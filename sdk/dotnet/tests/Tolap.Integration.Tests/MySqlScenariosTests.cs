using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using MySqlConnector;
using Tolap.Core;
using Tolap.Mcp;

namespace Tolap.Integration.Tests;

/// <summary>
/// Cross-SDK scenarios executed against real MySQL.
/// Same shared scenario JSON the Postgres and Python/TypeScript suites use.
/// </summary>
public sealed class MySqlScenariosTests : IClassFixture<MySqlFixture>
{
    private const string SigningKey = "integration-test-signing-key";
    private static readonly HashSet<string> Reserved = new() { "status" };
    private readonly MySqlFixture _db;

    public MySqlScenariosTests(MySqlFixture db) { _db = db; }

    private static string Quote(string col) => Reserved.Contains(col) ? $"`{col}`" : col;

    public static IEnumerable<object[]> Healthcare => LoadCases("postgres-healthcare-analyst.json", true);
    public static IEnumerable<object[]> RowFilters => LoadCases("postgres-row-filters.json", false);
    public static IEnumerable<object[]> FieldRules => LoadCases("postgres-field-rules.json", false);
    public static IEnumerable<object[]> Permissions => LoadCases("permissions-and-limits.json", false);

    private static IEnumerable<object[]> LoadCases(string filename, bool hasBase)
    {
        var json = ScenarioHelpers.LoadScenarioFile(filename);
        using var doc = JsonDocument.Parse(json);
        string baseJson = hasBase ? doc.RootElement.GetProperty("basePolicy").GetRawText() : "";
        foreach (var s in doc.RootElement.GetProperty("scenarios").EnumerateArray())
        {
            yield return new object[] { s.GetProperty("name").GetString()!, baseJson, s.GetRawText() };
        }
    }

    [Theory]
    [MemberData(nameof(Healthcare))]
    public async Task Healthcare_Mysql(string name, string baseJson, string scenarioJson)
    {
        if (!_db.Ready) return;
        using var baseDoc = JsonDocument.Parse(baseJson);
        using var scenarioDoc = JsonDocument.Parse(scenarioJson);
        var scenario = scenarioDoc.RootElement;

        JsonElement? overrideElement = null;
        if (scenario.TryGetProperty("policyOverride", out var ov)) overrideElement = ov;
        var merged = ScenarioHelpers.MergePolicy(baseDoc.RootElement, overrideElement);
        var policy = ScenarioHelpers.PolicyFromJson(merged);
        var ctx = ScenarioHelpers.SignPolicy(policy, SigningKey);

        var query = scenario.GetProperty("query");
        var table = query.GetProperty("table").GetString()!;
        var columns = query.GetProperty("columns").EnumerateArray().Select(e => e.GetString()!).ToArray();
        var fields = columns.Select(c => $"{table}.{c}").ToArray();

        var wrapper = new SecureContextToolWrapper(new SecureContextWrapperOptions(SigningKey));
        var args = new PreExecuteArgs("mysql-query", ObjectName: table, Fields: fields);

        var expected = scenario.GetProperty("expected");
        if (!expected.GetProperty("pass").GetBoolean())
        {
            var ex = await Record.ExceptionAsync(() =>
                wrapper.ExecuteWithEnforcementAsync(ctx, args, () => RunQuery(table, columns)));
            ex.Should().NotBeNull(name);
            ex!.Message.Should().Contain(expected.GetProperty("errorContains").GetString()!);
            return;
        }

        var rows = await wrapper.ExecuteWithEnforcementAsync(ctx, args, () => RunQuery(table, columns));
        await AssertHealthcarePass(name, rows, expected, table);
    }

    [Theory]
    [MemberData(nameof(RowFilters))]
    public async Task RowFilters_Mysql(string name, string _, string scenarioJson)
    {
        if (!_db.Ready) return;
        using var doc = JsonDocument.Parse(scenarioJson);
        var scenario = doc.RootElement;
        var policy = ScenarioHelpers.PolicyFromJson(scenario.GetProperty("policy"));
        var ctx = ScenarioHelpers.SignPolicy(policy, SigningKey);
        var query = scenario.GetProperty("query");
        var table = query.GetProperty("table").GetString()!;
        var columns = query.GetProperty("columns").EnumerateArray().Select(e => e.GetString()!).ToArray();

        var wrapper = new SecureContextToolWrapper(new SecureContextWrapperOptions(SigningKey));
        var args = new PreExecuteArgs("mysql-query", ObjectName: table);
        var expected = scenario.GetProperty("expected");

        if (!expected.GetProperty("pass").GetBoolean())
        {
            var ex = await Record.ExceptionAsync(() =>
                wrapper.ExecuteWithEnforcementAsync(ctx, args, () => RunQuery(table, columns)));
            ex.Should().NotBeNull(name);
            ex!.Message.Should().Contain(expected.GetProperty("errorContains").GetString()!);
            return;
        }

        var rows = await wrapper.ExecuteWithEnforcementAsync(ctx, args, () => RunQuery(table, columns));
        if (expected.TryGetProperty("rowCount", out var rc)) rows.Count.Should().Be(rc.GetInt32(), name);
        if (expected.TryGetProperty("regions", out var regs))
        {
            var actual = rows.Select(r => (string)r["region"]!).OrderBy(s => s).ToArray();
            var want = regs.EnumerateArray().Select(e => e.GetString()!).OrderBy(s => s).ToArray();
            actual.Should().BeEquivalentTo(want, opts => opts.WithStrictOrdering());
        }
        if (expected.TryGetProperty("idsEqual", out var ids))
        {
            var actual = rows.Select(r => Convert.ToInt32(r["id"])).OrderBy(i => i).ToArray();
            var want = ids.EnumerateArray().Select(e => e.GetInt32()).OrderBy(i => i).ToArray();
            actual.Should().BeEquivalentTo(want, opts => opts.WithStrictOrdering());
        }
    }

    [Theory]
    [MemberData(nameof(FieldRules))]
    public async Task FieldRules_Mysql(string name, string _, string scenarioJson)
    {
        if (!_db.Ready) return;
        using var doc = JsonDocument.Parse(scenarioJson);
        var scenario = doc.RootElement;
        var policy = ScenarioHelpers.PolicyFromJson(scenario.GetProperty("policy"));
        var ctx = ScenarioHelpers.SignPolicy(policy, SigningKey);
        var query = scenario.GetProperty("query");
        var table = query.GetProperty("table").GetString()!;
        var columns = query.GetProperty("columns").EnumerateArray().Select(e => e.GetString()!).ToArray();
        string[]? fields = null;
        if (scenario.TryGetProperty("fields", out var f))
            fields = f.EnumerateArray().Select(e => e.GetString()!).ToArray();

        var wrapper = new SecureContextToolWrapper(new SecureContextWrapperOptions(SigningKey));
        var args = new PreExecuteArgs("mysql-query", ObjectName: table, Fields: fields);
        var expected = scenario.GetProperty("expected");

        if (!expected.GetProperty("pass").GetBoolean())
        {
            var ex = await Record.ExceptionAsync(() =>
                wrapper.ExecuteWithEnforcementAsync(ctx, args, () => RunQuery(table, columns)));
            ex.Should().NotBeNull(name);
            ex!.Message.Should().Contain(expected.GetProperty("errorContains").GetString()!);
            return;
        }
        var rows = await wrapper.ExecuteWithEnforcementAsync(ctx, args, () => RunQuery(table, columns));
        await AssertFieldRulePass(name, rows, expected, table);
    }

    [Theory]
    [MemberData(nameof(Permissions))]
    public async Task Permissions_Mysql(string name, string _, string scenarioJson)
    {
        if (!_db.Ready) return;
        using var doc = JsonDocument.Parse(scenarioJson);
        var scenario = doc.RootElement;
        var policy = ScenarioHelpers.PolicyFromJson(scenario.GetProperty("policy"));
        var ctx = ScenarioHelpers.SignPolicy(policy, SigningKey);
        var query = scenario.GetProperty("query");
        var table = query.GetProperty("table").GetString()!;
        var columns = query.GetProperty("columns").EnumerateArray().Select(e => e.GetString()!).ToArray();
        string[]? fields = null;
        if (scenario.TryGetProperty("fields", out var f))
            fields = f.EnumerateArray().Select(e => e.GetString()!).ToArray();

        var wrapper = new SecureContextToolWrapper(new SecureContextWrapperOptions(SigningKey));
        var args = new PreExecuteArgs("mysql-query", ObjectName: table, Fields: fields);
        var expected = scenario.GetProperty("expected");

        if (!expected.GetProperty("pass").GetBoolean())
        {
            var ex = await Record.ExceptionAsync(() =>
                wrapper.ExecuteWithEnforcementAsync(ctx, args, () => RunQuery(table, columns)));
            ex.Should().NotBeNull(name);
            ex!.Message.Should().Contain(expected.GetProperty("errorContains").GetString()!);
            return;
        }
        var rows = await wrapper.ExecuteWithEnforcementAsync(ctx, args, () => RunQuery(table, columns));
        if (expected.TryGetProperty("rowCount", out var rc)) rows.Count.Should().Be(rc.GetInt32(), name);
    }

    private async Task<IReadOnlyList<Dictionary<string, object?>>> RunQuery(string table, string[] columns)
    {
        var cols = string.Join(", ", columns.Select(Quote));
        var sql = $"SELECT {cols} FROM {table} ORDER BY id";
        await using var cmd = new MySqlCommand(sql, _db.Connection);
        await using var reader = await cmd.ExecuteReaderAsync();
        var rows = new List<Dictionary<string, object?>>();
        while (await reader.ReadAsync())
        {
            var row = new Dictionary<string, object?>();
            for (var i = 0; i < reader.FieldCount; i++)
            {
                row[reader.GetName(i)] = reader.IsDBNull(i) ? null : reader.GetValue(i);
            }
            rows.Add(row);
        }
        return rows;
    }

    private async Task AssertHealthcarePass(string name, IReadOnlyList<Dictionary<string, object?>> rows, JsonElement expected, string table)
    {
        if (expected.TryGetProperty("rowCount", out var rc)) rows.Count.Should().Be(rc.GetInt32(), name);
        if (expected.TryGetProperty("idsEqual", out var ids))
        {
            var actual = rows.Select(r => Convert.ToInt32(r["id"])).OrderBy(i => i).ToArray();
            var want = ids.EnumerateArray().Select(e => e.GetInt32()).OrderBy(i => i).ToArray();
            actual.Should().BeEquivalentTo(want, opts => opts.WithStrictOrdering());
        }
        if (expected.TryGetProperty("regions", out var regs))
        {
            var actual = rows.Select(r => (string)r["region"]!).OrderBy(s => s).ToArray();
            var want = regs.EnumerateArray().Select(e => e.GetString()!).OrderBy(s => s).ToArray();
            actual.Should().BeEquivalentTo(want, opts => opts.WithStrictOrdering());
        }
        if (expected.TryGetProperty("maskedField", out var spec))
        {
            await AssertMaskFromDb(rows, spec, table);
        }
    }

    private async Task AssertFieldRulePass(string name, IReadOnlyList<Dictionary<string, object?>> rows, JsonElement expected, string table)
    {
        if (expected.TryGetProperty("rowCount", out var rc)) rows.Count.Should().Be(rc.GetInt32(), name);
        if (expected.TryGetProperty("maskedField", out var spec))
        {
            await AssertMaskFromDb(rows, spec, table);
        }
        if (expected.TryGetProperty("everyRowField", out var per))
        {
            foreach (var row in rows)
            {
                foreach (var s in per.EnumerateArray())
                {
                    var f = s.GetProperty("field").GetString()!;
                    var eq = s.GetProperty("equals").GetString();
                    row[f].Should().Be(eq);
                }
            }
        }
    }

    private async Task AssertMaskFromDb(IReadOnlyList<Dictionary<string, object?>> rows, JsonElement spec, string table)
    {
        var field = spec.GetProperty("field").GetString()!;
        var mask = spec.GetProperty("mask").GetString()!;
        var ids = rows.Select(r => Convert.ToInt32(r["id"])).ToArray();
        if (ids.Length == 0) return;
        var placeholders = string.Join(", ", ids.Select((_, i) => $"@id{i}"));
        var sql = $"SELECT id, {Quote(field)} AS val FROM {table} WHERE id IN ({placeholders}) ORDER BY id";
        await using var cmd = new MySqlCommand(sql, _db.Connection);
        for (var i = 0; i < ids.Length; i++) cmd.Parameters.AddWithValue($"@id{i}", ids[i]);
        var originals = new Dictionary<int, object?>();
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
            originals[Convert.ToInt32(reader.GetValue(0))] = reader.IsDBNull(1) ? null : reader.GetValue(1);
        foreach (var row in rows)
        {
            var id = Convert.ToInt32(row["id"]);
            AssertMask(row[field], originals[id], mask);
        }
    }

    private static void AssertMask(object? actual, object? original, string mask)
    {
        switch (mask)
        {
            case "sha256-16":
            {
                var s = original?.ToString() ?? "";
                using var sha = SHA256.Create();
                var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(s));
                ((string)actual!).Should().Be(Convert.ToHexString(hash).ToLowerInvariant()[..16]);
                break;
            }
            case "redacted":
                actual.Should().Be("[REDACTED]");
                break;
            case "partial-first-1":
            {
                var s = original?.ToString() ?? "";
                var got = (string)actual!;
                got[0].Should().Be(s[0]);
                got[1..].Should().Be(new string('*', s.Length - 1));
                break;
            }
            case "full-stars":
            {
                var s = original?.ToString() ?? "";
                actual.Should().Be(new string('*', s.Length));
                break;
            }
            case "is-null":
                actual.Should().BeNull();
                break;
            case "partial-last-4":
            {
                var s = original?.ToString() ?? "";
                var got = (string)actual!;
                got[^4..].Should().Be(s[^4..]);
                got[..^4].Should().Be(new string('*', s.Length - 4));
                break;
            }
            case "partial-first-2-last-2":
            {
                var s = original?.ToString() ?? "";
                var got = (string)actual!;
                got[..2].Should().Be(s[..2]);
                got[^2..].Should().Be(s[^2..]);
                got[2..^2].Should().Be(new string('*', s.Length - 4));
                break;
            }
            case "unchanged":
                actual!.ToString().Should().Be(original!.ToString());
                break;
            case "partial-first-1-hash":
            {
                var s = original?.ToString() ?? "";
                var got = (string)actual!;
                got[0].Should().Be(s[0]);
                got[1..].Should().Be(new string('#', s.Length - 1));
                break;
            }
            default:
                throw new InvalidOperationException($"unknown mask {mask}");
        }
    }
}
