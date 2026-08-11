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

    /// <summary>Why the service was unavailable, or null when Ready.</summary>
    /// <remarks>
    /// A bare <c>catch (Exception)</c> with no logging made a bad schema, a permissions
    /// error, and an unreachable server indistinguishable — and since the tests treated
    /// all three as a silent pass, there was nothing to read either. Recording the reason
    /// is what makes the failure actionable.
    /// </remarks>
    public string? SkipReason { get; private set; }

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
        catch (Exception ex)
        {
            Ready = false;
            SkipReason = $"{ex.GetType().Name}: {ex.Message}";
            Console.Error.WriteLine($"[PostgresFixture] unavailable — {SkipReason}");
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

/// <summary>
/// Groups every test class that touches a local database so they share ONE instance of each
/// fixture and do not run concurrently with each other.
/// </summary>
/// <remarks>
/// With <c>IClassFixture</c>, each class got its own instance and each instance re-ran
/// <c>schema.sql</c>'s DROP/CREATE against the same tables. xUnit runs classes in parallel,
/// so they raced: one won and the rest failed to seed. That was invisible because a failed
/// seed set <c>Ready = false</c> and the tests returned early — which xUnit records as a
/// pass. Seeding once per collection removes the race; <c>ScenarioHelpers.RequireService</c>
/// makes any remaining failure loud.
/// </remarks>
/// <remarks>
/// Both fixtures hang off one collection rather than one each, because
/// <c>LikeCollationPushdownTests</c> needs Postgres AND MySQL and a class can only belong to
/// a single xUnit collection. Serializing the two backends together costs a little
/// wall-clock and buys a seeding order that cannot race.
/// </remarks>
[CollectionDefinition(Name)]
public sealed class DatabaseCollection
    : ICollectionFixture<PostgresFixture>, ICollectionFixture<MySqlFixture>
{
    public const string Name = "databases";
}
