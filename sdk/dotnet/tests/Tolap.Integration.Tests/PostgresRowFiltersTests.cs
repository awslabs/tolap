using System.Text.Json;
using FluentAssertions;
using Npgsql;
using Tolap.Core;
using Tolap.Mcp;

namespace Tolap.Integration.Tests;

/// <summary>
/// Cross-SDK row-filter scenarios, against real Postgres.
/// Cases come from fixtures/integration-scenarios/postgres-row-filters.json.
/// </summary>
public sealed class PostgresRowFiltersTests : IClassFixture<PostgresFixture>
{
    private const string SigningKey = "integration-test-signing-key";
    private readonly PostgresFixture _db;

    public PostgresRowFiltersTests(PostgresFixture db) { _db = db; }

    public static IEnumerable<object[]> Scenarios
    {
        get
        {
            var json = ScenarioHelpers.LoadScenarioFile("postgres-row-filters.json");
            using var doc = JsonDocument.Parse(json);
            foreach (var scenario in doc.RootElement.GetProperty("scenarios").EnumerateArray())
            {
                yield return new object[]
                {
                    scenario.GetProperty("name").GetString()!,
                    scenario.GetRawText()
                };
            }
        }
    }

    [Theory]
    [MemberData(nameof(Scenarios))]
    public async Task RowFilterScenario(string name, string scenarioJson)
    {
        if (!_db.Ready)
        {
            // Postgres not available; mirror Python's pytest.skip behavior.
            return;
        }

        using var doc = JsonDocument.Parse(scenarioJson);
        var scenario = doc.RootElement;

        var policy = ScenarioHelpers.PolicyFromJson(scenario.GetProperty("policy"));
        var ctx = ScenarioHelpers.SignPolicy(policy, SigningKey);

        var query = scenario.GetProperty("query");
        var table = query.GetProperty("table").GetString()!;
        var columns = query.GetProperty("columns")
            .EnumerateArray().Select(e => e.GetString()!).ToArray();

        var wrapper = new SecureContextToolWrapper(new SecureContextWrapperOptions(SigningKey));
        var args = new PreExecuteArgs(ToolName: "pg-query", ObjectName: table);

        var expected = scenario.GetProperty("expected");
        var passOk = expected.GetProperty("pass").GetBoolean();

        if (!passOk)
        {
            var errorContains = expected.GetProperty("errorContains").GetString()!;
            var ex = await Record.ExceptionAsync(() =>
                wrapper.ExecuteWithEnforcementAsync(ctx, args, () => RunQuery(table, columns)));
            ex.Should().NotBeNull($"scenario {name} should fail with {errorContains}");
            ex!.Message.Should().Contain(errorContains);
            return;
        }

        var rows = await wrapper.ExecuteWithEnforcementAsync(ctx, args, () => RunQuery(table, columns));
        AssertPass(name, rows, expected);
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

    private static void AssertPass(string name, IReadOnlyList<Dictionary<string, object?>> rows, JsonElement expected)
    {
        if (expected.TryGetProperty("rowCount", out var rowCount))
        {
            rows.Count.Should().Be(rowCount.GetInt32(), $"scenario {name}");
        }
        if (expected.TryGetProperty("regions", out var regions))
        {
            var actual = rows.Select(r => (string)r["region"]!).OrderBy(s => s).ToArray();
            var want = regions.EnumerateArray().Select(e => e.GetString()!).OrderBy(s => s).ToArray();
            actual.Should().BeEquivalentTo(want, opts => opts.WithStrictOrdering());
        }
        if (expected.TryGetProperty("idsEqual", out var idsEqual))
        {
            var actual = rows.Select(r => Convert.ToInt32(r["id"])).OrderBy(i => i).ToArray();
            var want = idsEqual.EnumerateArray().Select(e => e.GetInt32()).OrderBy(i => i).ToArray();
            actual.Should().BeEquivalentTo(want, opts => opts.WithStrictOrdering());
        }
        if (expected.TryGetProperty("idsIn", out var idsIn))
        {
            var allowed = idsIn.EnumerateArray().Select(e => e.GetInt32()).ToHashSet();
            foreach (var row in rows)
            {
                allowed.Contains(Convert.ToInt32(row["id"])).Should().BeTrue();
            }
        }
    }
}
