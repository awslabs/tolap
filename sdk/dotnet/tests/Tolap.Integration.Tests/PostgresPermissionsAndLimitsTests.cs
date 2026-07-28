using System.Text.Json;
using FluentAssertions;
using Npgsql;
using Tolap.Core;
using Tolap.Mcp;

namespace Tolap.Integration.Tests;

public sealed class PostgresPermissionsAndLimitsTests : IClassFixture<PostgresFixture>
{
    private const string SigningKey = "integration-test-signing-key";
    private readonly PostgresFixture _db;
    public PostgresPermissionsAndLimitsTests(PostgresFixture db) { _db = db; }

    public static IEnumerable<object[]> Scenarios
    {
        get
        {
            var json = ScenarioHelpers.LoadScenarioFile("permissions-and-limits.json");
            using var doc = JsonDocument.Parse(json);
            foreach (var s in doc.RootElement.GetProperty("scenarios").EnumerateArray())
            {
                yield return new object[] { s.GetProperty("name").GetString()!, s.GetRawText() };
            }
        }
    }

    [Theory]
    [MemberData(nameof(Scenarios))]
    public async Task Scenario(string name, string scenarioJson)
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
        {
            fields = f.EnumerateArray().Select(e => e.GetString()!).ToArray();
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
        if (expected.TryGetProperty("rowCount", out var rc))
            rows.Count.Should().Be(rc.GetInt32(), name);
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
}
