using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Npgsql;
using Tolap.Core;
using Tolap.Mcp;

namespace Tolap.Integration.Tests;

public sealed class PostgresHealthcareAnalystTests : IClassFixture<PostgresFixture>
{
    private const string SigningKey = "integration-test-signing-key";
    private readonly PostgresFixture _db;

    public PostgresHealthcareAnalystTests(PostgresFixture db) { _db = db; }

    public static IEnumerable<object[]> Scenarios
    {
        get
        {
            var json = ScenarioHelpers.LoadScenarioFile("postgres-healthcare-analyst.json");
            using var doc = JsonDocument.Parse(json);
            var basePolicy = doc.RootElement.GetProperty("basePolicy").GetRawText();
            foreach (var s in doc.RootElement.GetProperty("scenarios").EnumerateArray())
            {
                yield return new object[]
                {
                    s.GetProperty("name").GetString()!,
                    basePolicy,
                    s.GetRawText()
                };
            }
        }
    }

    [Theory]
    [MemberData(nameof(Scenarios))]
    public async Task HealthcareAnalystScenario(string name, string baseJson, string scenarioJson)
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
        var columns = query.GetProperty("columns")
            .EnumerateArray().Select(e => e.GetString()!).ToArray();
        var fields = columns.Select(c => $"{table}.{c}").ToArray();

        var wrapper = new SecureContextToolWrapper(new SecureContextWrapperOptions(SigningKey));
        var args = new PreExecuteArgs(ToolName: "pg-query", ObjectName: table, Fields: fields);

        var expected = scenario.GetProperty("expected");
        if (!expected.GetProperty("pass").GetBoolean())
        {
            var errorContains = expected.GetProperty("errorContains").GetString()!;
            var ex = await Record.ExceptionAsync(() =>
                wrapper.ExecuteWithEnforcementAsync(ctx, args, () => RunQuery(table, columns)));
            ex.Should().NotBeNull($"scenario {name}");
            ex!.Message.Should().Contain(errorContains);
            return;
        }

        var rows = await wrapper.ExecuteWithEnforcementAsync(ctx, args, () => RunQuery(table, columns));
        await AssertPass(rows, expected, table);
    }

    private async Task<IReadOnlyList<Dictionary<string, object?>>> RunQuery(string table, string[] columns)
    {
        var sql = $"SELECT {string.Join(", ", columns)} FROM {table} ORDER BY id";
        await using var cmd = new NpgsqlCommand(sql, _db.Connection);
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

    private async Task AssertPass(IReadOnlyList<Dictionary<string, object?>> rows, JsonElement expected, string table)
    {
        if (expected.TryGetProperty("rowCount", out var rowCount))
        {
            rows.Count.Should().Be(rowCount.GetInt32());
        }
        if (expected.TryGetProperty("idsEqual", out var idsEqual))
        {
            var actual = rows.Select(r => Convert.ToInt32(r["id"])).OrderBy(i => i).ToArray();
            var want = idsEqual.EnumerateArray().Select(e => e.GetInt32()).OrderBy(i => i).ToArray();
            actual.Should().BeEquivalentTo(want, opts => opts.WithStrictOrdering());
        }
        if (expected.TryGetProperty("regions", out var regions))
        {
            var actual = rows.Select(r => (string)r["region"]!).OrderBy(s => s).ToArray();
            var want = regions.EnumerateArray().Select(e => e.GetString()!).OrderBy(s => s).ToArray();
            actual.Should().BeEquivalentTo(want, opts => opts.WithStrictOrdering());
        }
        if (expected.TryGetProperty("maskedField", out var spec))
        {
            var field = spec.GetProperty("field").GetString()!;
            var mask = spec.GetProperty("mask").GetString()!;
            var ids = rows.Select(r => Convert.ToInt32(r["id"])).ToArray();
            var sql = $"SELECT id, {field} AS val FROM {table} WHERE id = ANY(@ids) ORDER BY id";
            var originals = new Dictionary<int, object?>();
            await using var cmd = new NpgsqlCommand(sql, _db.Connection);
            cmd.Parameters.AddWithValue("ids", ids);
            await using var reader = await cmd.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                originals[reader.GetInt32(0)] = reader.IsDBNull(1) ? null : reader.GetValue(1);
            }
            foreach (var row in rows)
            {
                var id = Convert.ToInt32(row["id"]);
                AssertMask(row[field], originals[id], mask);
            }
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
                var hex = Convert.ToHexString(hash).ToLowerInvariant()[..16];
                ((string)actual!).Should().Be(hex);
                break;
            }
            case "redacted":
                actual.Should().Be("[REDACTED]");
                break;
            case "partial-first-1":
            {
                var orig = original?.ToString() ?? "";
                var got = (string)actual!;
                got[0].Should().Be(orig[0]);
                got[1..].Should().Be(new string('*', orig.Length - 1));
                break;
            }
            default:
                throw new InvalidOperationException($"unknown mask kind {mask}");
        }
    }
}
