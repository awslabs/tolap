using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Npgsql;
using Tolap.Core;
using Tolap.Mcp;

namespace Tolap.Integration.Tests;

/// <summary>
/// Cross-SDK field-rule scenarios.
/// </summary>
[Collection(DatabaseCollection.Name)]
public sealed class PostgresFieldRulesTests : IClassFixture<PostgresFixture>
{
    private const string SigningKey = "integration-test-signing-key";
    private readonly PostgresFixture _db;
    public PostgresFieldRulesTests(PostgresFixture db) { _db = db; }

    public static IEnumerable<object[]> Scenarios
    {
        get
        {
            var json = ScenarioHelpers.LoadScenarioFile("postgres-field-rules.json");
            using var doc = JsonDocument.Parse(json);
            foreach (var s in doc.RootElement.GetProperty("scenarios").EnumerateArray())
            {
                yield return new object[] { s.GetProperty("name").GetString()!, s.GetRawText() };
            }
        }
    }

    [Theory]
    [MemberData(nameof(Scenarios))]
    public async Task FieldRuleScenario(string name, string scenarioJson)
    {
        ScenarioHelpers.RequireService(_db.Ready, "a local database", _db.SkipReason);
        using var doc = JsonDocument.Parse(scenarioJson);
        var scenario = doc.RootElement;

        var policy = ScenarioHelpers.PolicyFromJson(scenario.GetProperty("policy"));
        var ctx = ScenarioHelpers.SignPolicy(policy, SigningKey);

        var query = scenario.GetProperty("query");
        var table = query.GetProperty("table").GetString()!;
        var columns = query.GetProperty("columns")
            .EnumerateArray().Select(e => e.GetString()!).ToArray();
        string[]? fields = null;
        if (scenario.TryGetProperty("fields", out var fieldsEl))
        {
            fields = fieldsEl.EnumerateArray().Select(e => e.GetString()!).ToArray();
        }

        var wrapper = new SecureContextToolWrapper(new SecureContextWrapperOptions(SigningKey));
        var args = new PreExecuteArgs("pg-query", ObjectName: table, Fields: fields);
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
        await AssertPass(name, rows, expected, table);
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
                row[reader.GetName(i)] = reader.IsDBNull(i) ? null : reader.GetValue(i);
            rows.Add(row);
        }
        return rows;
    }

    private async Task AssertPass(string name, IReadOnlyList<Dictionary<string, object?>> rows, JsonElement expected, string table)
    {
        if (expected.TryGetProperty("rowCount", out var rc))
            rows.Count.Should().Be(rc.GetInt32(), name);

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
                originals[reader.GetInt32(0)] = reader.IsDBNull(1) ? null : reader.GetValue(1);
            foreach (var row in rows)
            {
                var id = Convert.ToInt32(row["id"]);
                AssertMask(row[field], originals[id], mask);
            }
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

    private static void AssertMask(object? actual, object? original, string mask)
    {
        switch (mask)
        {
            case "full-stars":
            {
                var s = original?.ToString() ?? "";
                actual.Should().Be(new string('*', s.Length));
                break;
            }
            case "is-null":
                actual.Should().BeNull();
                break;
            case "redacted":
                actual.Should().Be("[REDACTED]");
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
            case "sha256-16":
            {
                var s = original?.ToString() ?? "";
                using var sha = SHA256.Create();
                var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(s));
                ((string)actual!).Should().Be(Convert.ToHexString(hash).ToLowerInvariant()[..16]);
                break;
            }
            default:
                throw new InvalidOperationException($"unknown mask {mask}");
        }
    }
}
