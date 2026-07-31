using Npgsql;

namespace Tolap.Integration.Tests;

/// <summary>
/// Shared Postgres fixture for the .NET integration tests.
///
/// Connects to the same `tolap_integration_test` DB used by Python and
/// TypeScript and re-applies the seed schema once per test class. If
/// Postgres is unreachable, sets `Ready = false` so individual tests can
/// short-circuit gracefully.
/// </summary>
public sealed class PostgresFixture : IAsyncLifetime, IDisposable
{
    public NpgsqlConnection Connection { get; private set; } = null!;
    public bool Ready { get; private set; }

    public async Task InitializeAsync()
    {
        var dsn = Environment.GetEnvironmentVariable("TOLAP_TEST_DB_DSN")
                  ?? "Host=localhost;Database=tolap_integration_test;Include Error Detail=true";
        try
        {
            Connection = new NpgsqlConnection(dsn);
            await Connection.OpenAsync();
            var schemaSql = await File.ReadAllTextAsync(ScenarioHelpers.SchemaSqlPath);
            await using var cmd = new NpgsqlCommand(schemaSql, Connection);
            await cmd.ExecuteNonQueryAsync();
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

    public void Dispose()
    {
        Connection?.Dispose();
    }
}
