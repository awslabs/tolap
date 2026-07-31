using MySqlConnector;

namespace Tolap.Integration.Tests;

/// <summary>
/// MySQL fixture for the .NET integration tests. Connects to the same
/// `tolap_integration_test` database the Python and TypeScript tests use,
/// re-applies schema_mysql.sql once per test class.
/// </summary>
public sealed class MySqlFixture : IAsyncLifetime, IDisposable
{
    public MySqlConnection Connection { get; private set; } = null!;
    public bool Ready { get; private set; }

    public async Task InitializeAsync()
    {
        var host = Environment.GetEnvironmentVariable("TOLAP_TEST_MYSQL_HOST") ?? "127.0.0.1";
        var user = Environment.GetEnvironmentVariable("TOLAP_TEST_MYSQL_USER") ?? "root";
        var password = Environment.GetEnvironmentVariable("TOLAP_TEST_MYSQL_PASSWORD") ?? "";
        var database = Environment.GetEnvironmentVariable("TOLAP_TEST_MYSQL_DB") ?? "tolap_integration_test";
        var port = int.Parse(Environment.GetEnvironmentVariable("TOLAP_TEST_MYSQL_PORT") ?? "3306");

        var cs = $"Server={host};Port={port};User ID={user};Password={password};Database={database};AllowUserVariables=true;AllowLoadLocalInfile=true;ConnectionTimeout=2";
        try
        {
            Connection = new MySqlConnection(cs);
            await Connection.OpenAsync();

            var schemaPath = Path.Combine(ScenarioHelpers.RepoRoot, "sdk", "python", "tests", "integration", "schema_mysql.sql");
            var rawSql = await File.ReadAllTextAsync(schemaPath);
            // Strip line comments so we can split on ';' safely.
            var cleaned = string.Join('\n',
                rawSql.Split('\n').Where(line => !line.TrimStart().StartsWith("--")));
            foreach (var stmt in cleaned.Split(';'))
            {
                var trimmed = stmt.Trim();
                if (trimmed.Length == 0) continue;
                await using var cmd = new MySqlCommand(trimmed, Connection);
                await cmd.ExecuteNonQueryAsync();
            }
            Ready = true;
        }
        catch (Exception)
        {
            Ready = false;
        }
    }

    public async Task DisposeAsync()
    {
        if (Connection is not null)
        {
            await Connection.CloseAsync();
            await Connection.DisposeAsync();
        }
    }

    public void Dispose() => Connection?.Dispose();
}
