using FluentAssertions;
using MySqlConnector;
using Npgsql;
using Tolap.Core;
using Xunit;

namespace Tolap.Integration.Tests;

/// <summary>
/// <c>like</c>/<c>notLike</c> pushdown and the column's collation, proven against live
/// Postgres AND live MySQL.
/// </summary>
/// <remarks>
/// <para>
/// A <b>measured</b> defect of the same class as the MySQL backtick one, and a worse one. The
/// post-execution pass compares case-SENSITIVELY and is engine-independent, but a pushed-down
/// <c>LIKE</c> inherits the <i>column's</i> collation:
/// </para>
/// <code>
/// postgres:  SELECT 'ALICE JONES' LIKE 'alice%'   ->  f     (case-sensitive)
/// mysql:     SELECT 'ALICE JONES' LIKE 'alice%'   ->  1     (utf8mb4_0900_ai_ci)
/// </code>
/// <para>
/// Run over the shared three-row corpus:
/// </para>
/// <code>
/// postgres  WHERE (name NOT LIKE 'alice%' OR name IS NULL)  -> mid, high, nullish
/// mysql     WHERE (name NOT LIKE 'alice%' OR name IS NULL)  -> high, nullish
/// </code>
/// <para>
/// The <c>mid</c> row is <c>'ALICE JONES'</c>. Its disappearing on MySQL is not a fail-closed
/// quoting mistake but a change in which <b>real records</b> a user sees. So <c>MySql</c>,
/// <c>SqlServer</c> and <c>Ansi</c> decline the operator and report it unpushable, while
/// <c>Postgres</c> and <c>Trino</c> may push it (canonical-enforcement-spec.md section 4).
/// </para>
/// <para>
/// Asserting the emitted text cannot catch this: the text was well-formed and meant something
/// different in the other engine. Only executing it against both engines can, which is why this
/// suite exists alongside the unit tests. Each engine short-circuits independently when
/// unreachable.
/// </para>
/// </remarks>
[Collection(DatabaseCollection.Name)]
public class LikeCollationPushdownTests
    : IClassFixture<PostgresFixture>, IClassFixture<MySqlFixture>, IAsyncLifetime
{
    private readonly PostgresFixture _pg;
    private readonly MySqlFixture _mysql;

    private readonly SqlQueryRewriter _mysqlRewriter = new(dialect: SqlDialect.MySql);
    private readonly SqlQueryRewriter _pgRewriter = new(dialect: SqlDialect.Postgres);
    private readonly SqlQueryRewriter _rewriter = new();

    public LikeCollationPushdownTests(PostgresFixture pg, MySqlFixture mysql)
    {
        _pg = pg;
        _mysql = mysql;
    }

    private const string Query = "SELECT id, name FROM collation_probe ORDER BY id";

    /// <summary>
    /// The three-row set from the shared operator corpus
    /// (<c>fixtures/enforcement/apply-row-filters-all-operators.json</c>), which is where the
    /// expectations below come from rather than from any implementation. <c>mid</c> is the row
    /// the two paths disagreed about.
    /// </summary>
    private static readonly (string Id, string? Name)[] CollationRows =
    [
        ("mid", "ALICE JONES"),
        ("high", "bob stone"),
        ("nullish", null)
    ];

    /// <summary>The policy filter that exposed it.</summary>
    private static RowFilter NotLikeAlice => new("name", FilterOperator.NotLike, Value: "alice%");

    /// <summary>
    /// What the case-sensitive post-execution pass selects: <c>'ALICE JONES'</c> does not match
    /// the lowercase pattern so <c>mid</c> is kept, and <c>nullish</c> is kept because its field
    /// is present with a null value (spec section 7).
    /// </summary>
    /// <remarks>
    /// Compared without regard to order, because <c>ORDER BY id</c> sorts these ids lexically
    /// while the corpus lists them in record order. Which rows survive is the claim; their order
    /// is the database's business.
    /// </remarks>
    private static readonly string[] NotLikeAliceExpected = ["mid", "high", "nullish"];

    /// <summary>Seeds the probe table in whichever engines are reachable.</summary>
    public async Task InitializeAsync()
    {
        if (_pg.Ready)
        {
            await ExecutePgAsync("DROP TABLE IF EXISTS collation_probe");
            await ExecutePgAsync("CREATE TABLE collation_probe (id TEXT, name TEXT)");
            foreach (var (id, name) in CollationRows)
            {
                await using var cmd = new NpgsqlCommand(
                    "INSERT INTO collation_probe VALUES (@id, @name)", _pg.Connection);
                cmd.Parameters.AddWithValue("id", id);
                cmd.Parameters.AddWithValue("name", (object?)name ?? DBNull.Value);
                await cmd.ExecuteNonQueryAsync();
            }
        }

        if (_mysql.Ready)
        {
            await ExecuteMySqlAsync("DROP TABLE IF EXISTS collation_probe");
            // No explicit COLLATE: the table takes the server default, which is what an
            // integrator's real table has and is the whole point of the case.
            await ExecuteMySqlAsync(
                "CREATE TABLE collation_probe (id VARCHAR(32), name VARCHAR(255)) "
                + "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
            foreach (var (id, name) in CollationRows)
            {
                await using var cmd = new MySqlCommand(
                    "INSERT INTO collation_probe VALUES (@id, @name)", _mysql.Connection);
                cmd.Parameters.AddWithValue("id", id);
                cmd.Parameters.AddWithValue("name", (object?)name ?? DBNull.Value);
                await cmd.ExecuteNonQueryAsync();
            }
        }
    }

    public async Task DisposeAsync()
    {
        if (_pg.Ready) await ExecutePgAsync("DROP TABLE IF EXISTS collation_probe");
        if (_mysql.Ready) await ExecuteMySqlAsync("DROP TABLE IF EXISTS collation_probe");
    }

    private async Task ExecutePgAsync(string sql)
    {
        await using var cmd = new NpgsqlCommand(sql, _pg.Connection);
        await cmd.ExecuteNonQueryAsync();
    }

    private async Task ExecuteMySqlAsync(string sql)
    {
        await using var cmd = new MySqlCommand(sql, _mysql.Connection);
        await cmd.ExecuteNonQueryAsync();
    }

    private static EffectivePolicy Policy(params RowFilter[] rowFilters)
        => new(
            Version: "1.0",
            UserId: "u",
            TenantId: "t",
            SourceConnectionId: "db:collation:main",
            ResolvedAt: DateTimeOffset.UtcNow,
            ExpiresAt: DateTimeOffset.UtcNow.AddHours(1),
            SourceProfiles: ["collation"],
            Permissions: new PolicyPermissions(CanQuery: true),
            ObjectRules: new ObjectRules(RowFilters: rowFilters));

    private async Task<List<Dictionary<string, object?>>> PgRowsAsync(string sql)
    {
        var rows = new List<Dictionary<string, object?>>();
        await using var cmd = new NpgsqlCommand(sql, _pg.Connection);
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            var row = new Dictionary<string, object?>();
            for (var i = 0; i < reader.FieldCount; i++)
                row[reader.GetName(i)] = await reader.IsDBNullAsync(i) ? null : reader.GetValue(i);
            rows.Add(row);
        }
        return rows;
    }

    private async Task<List<Dictionary<string, object?>>> MySqlRowsAsync(string sql)
    {
        var rows = new List<Dictionary<string, object?>>();
        await using var cmd = new MySqlCommand(sql, _mysql.Connection);
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            var row = new Dictionary<string, object?>();
            for (var i = 0; i < reader.FieldCount; i++)
                row[reader.GetName(i)] = await reader.IsDBNullAsync(i) ? null : reader.GetValue(i);
            rows.Add(row);
        }
        return rows;
    }

    private static string[] IdsOf(IEnumerable<Dictionary<string, object?>> rows)
        => rows.Select(r => (string)r["id"]!).ToArray();

    // =======================================================================
    // The engines genuinely disagree about the comparison
    // =======================================================================

    /// <remarks>
    /// The mechanism, measured directly — the premise everything below rests on. If it ever
    /// stops holding (a MySQL configured with a case-sensitive default collation, say), the rest
    /// of this class is testing a hazard that is no longer present, and that should be noticed
    /// here rather than inferred.
    /// </remarks>
    [Fact]
    public async Task PostgresLike_IsCaseSensitive()
    {
        ScenarioHelpers.RequireService(_pg.Ready, "a local database");

        var rows = await PgRowsAsync("SELECT ('ALICE JONES' LIKE 'alice%') AS cmp");

        Convert.ToBoolean(rows[0]["cmp"]).Should().BeFalse();
    }

    [Fact]
    public async Task MySqlLike_IsNot_UnderItsDefaultCollation()
    {
        ScenarioHelpers.RequireService(_mysql.Ready, "a local database");

        var rows = await MySqlRowsAsync("SELECT ('ALICE JONES' LIKE 'alice%') AS cmp");

        Convert.ToInt32(rows[0]["cmp"]).Should().Be(1);
    }

    // =======================================================================
    // MySQL does not push, and the row survives
    // =======================================================================

    /// <remarks>
    /// The SQL the rewriter used to emit for <c>mysql</c>. Run against the corpus it drops
    /// <c>mid</c> — <c>'ALICE JONES'</c> — which the post-execution pass keeps. Pinned so the
    /// effect is on record independently of whether the rewriter happens to emit it.
    /// </remarks>
    [Fact]
    public async Task TheBareMySqlPredicate_WouldDropARealRow()
    {
        ScenarioHelpers.RequireService(_mysql.Ready, "a local database");

        var dropped = await MySqlRowsAsync(
            "SELECT id, name FROM collation_probe "
            + "WHERE (`name` NOT LIKE 'alice%' OR `name` IS NULL) ORDER BY id");

        IdsOf(dropped).Should().BeEquivalentTo(["high", "nullish"]);
        IdsOf(dropped).Should().NotContain("mid");
        // ...while every row is present to begin with.
        (await MySqlRowsAsync(Query)).Should().HaveCount(CollationRows.Length);
    }

    /// <remarks>
    /// <b>The regression guard.</b> <c>'ALICE JONES'</c> surviving is the assertion. The filter
    /// is not pushed, the database returns every row, and the case-sensitive post-execution pass
    /// produces the corpus answer — including <c>mid</c>, which the pushed-down form dropped.
    /// </remarks>
    [Fact]
    public async Task MySql_DoesNotPush_AndThePostPassKeepsTheRow()
    {
        ScenarioHelpers.RequireService(_mysql.Ready, "a local database");

        var policy = Policy(NotLikeAlice);

        var rewritten = _mysqlRewriter.RewriteQuery(Query, policy);

        // Nothing pushed, and the decline is reported rather than silent.
        rewritten.Should().Be(Query);
        rewritten.Should().NotContainEquivalentOf("LIKE");
        _mysqlRewriter.UnpushableFilters(policy).Should().BeEquivalentTo(new[] { NotLikeAlice });

        var raw = await MySqlRowsAsync(rewritten);
        raw.Should().HaveCount(CollationRows.Length);

        var enforced = EnforcementEngine.ApplyRowFilters(raw, policy);

        IdsOf(enforced).Should().BeEquivalentTo(NotLikeAliceExpected);
        // Said the other way round, because this row is the whole point:
        enforced.Select(r => r["name"] as string).Should().Contain("ALICE JONES");
    }

    /// <remarks>
    /// <c>like</c> and not only <c>notLike</c>. The rule is about the comparison, not the
    /// negation, so the positive operator is declined on the same profiles — and the post pass
    /// gives the case-sensitive answer, which excludes <c>'ALICE JONES'</c>.
    /// </remarks>
    [Fact]
    public async Task APositiveLike_IsDeclinedOnMySql_AndStillCorrect()
    {
        ScenarioHelpers.RequireService(_mysql.Ready, "a local database");

        var like = new RowFilter("name", FilterOperator.Like, Value: "alice%");
        var policy = Policy(like);

        var rewritten = _mysqlRewriter.RewriteQuery(Query, policy);

        rewritten.Should().Be(Query);
        _mysqlRewriter.UnpushableFilters(policy).Should().BeEquivalentTo(new[] { like });

        // No corpus row matches lowercase 'alice%' case-sensitively.
        EnforcementEngine.ApplyRowFilters(await MySqlRowsAsync(rewritten), policy)
            .Should().BeEmpty();

        // Proof the pushed-down form would have differed.
        var wouldHaveMatched = await MySqlRowsAsync(
            "SELECT id FROM collation_probe WHERE `name` LIKE 'alice%' ORDER BY id");
        IdsOf(wouldHaveMatched).Should().BeEquivalentTo(["mid"]);
    }

    // =======================================================================
    // Postgres still pushes
    // =======================================================================

    /// <remarks>
    /// Declining on MySQL must not cost Postgres its optimization — and the pushed-down answer
    /// must equal the post-fetch answer, which is the equivalence the whole rule exists to
    /// protect.
    /// </remarks>
    [Fact]
    public async Task Postgres_StillPushes_AndStillAgreesWithThePostPass()
    {
        ScenarioHelpers.RequireService(_pg.Ready, "a local database");

        var policy = Policy(NotLikeAlice);

        var rewritten = _pgRewriter.RewriteQuery(Query, policy);

        rewritten.Should().NotBe(Query);
        rewritten.Should().Contain("NOT LIKE 'alice%'");
        _pgRewriter.UnpushableFilters(policy).Should().BeEmpty();

        var pushedDown = IdsOf(await PgRowsAsync(rewritten));
        var postFetch = IdsOf(EnforcementEngine.ApplyRowFilters(await PgRowsAsync(Query), policy));

        pushedDown.Should().BeEquivalentTo(NotLikeAliceExpected);
        postFetch.Should().BeEquivalentTo(NotLikeAliceExpected);
        pushedDown.Should().BeEquivalentTo(postFetch);
    }

    // =======================================================================
    // One policy, one row set, two engines
    // =======================================================================

    /// <remarks>
    /// The claim the fix is for. Postgres reaches it by pushing the filter down; MySQL reaches
    /// it by declining and letting the post pass do the work. Different <i>mechanisms</i>,
    /// identical <i>result</i> — which is what connector-spec.md section 5.1 promises and what
    /// the defect broke.
    /// </remarks>
    [Fact]
    public async Task TheSamePolicy_AdmitsTheSameRows_OnBothEngines()
    {
        if (!_pg.Ready || !_mysql.Ready) return;

        var policy = Policy(NotLikeAlice);

        var pgQuery = _pgRewriter.RewriteQuery(Query, policy);
        var mysqlQuery = _mysqlRewriter.RewriteQuery(Query, policy);

        var pgResult = IdsOf(
            EnforcementEngine.ApplyRowFilters(await PgRowsAsync(pgQuery), policy));
        var mysqlResult = IdsOf(
            EnforcementEngine.ApplyRowFilters(await MySqlRowsAsync(mysqlQuery), policy));

        pgResult.Should().BeEquivalentTo(mysqlResult);
        pgResult.Should().BeEquivalentTo(NotLikeAliceExpected);
    }

    // =======================================================================
    // No COLLATE clause is ever emitted
    // =======================================================================

    /// <remarks>
    /// <c>... LIKE 'alice%' COLLATE utf8mb4_0900_as_cs</c> and <c>BINARY ...</c> both force
    /// case-sensitivity on MySQL, so this IS technically emittable. It is deliberately not
    /// emitted: the right collation name depends on the column's character set, which a rewriter
    /// holding only a policy and a query string does not know, and guessing wrong either fails
    /// the query or silently changes the comparison again.
    /// </remarks>
    [Theory]
    [InlineData(SqlDialect.MySql, FilterOperator.Like)]
    [InlineData(SqlDialect.MySql, FilterOperator.NotLike)]
    [InlineData(SqlDialect.SqlServer, FilterOperator.Like)]
    [InlineData(SqlDialect.SqlServer, FilterOperator.NotLike)]
    [InlineData(SqlDialect.Ansi, FilterOperator.Like)]
    [InlineData(SqlDialect.Ansi, FilterOperator.NotLike)]
    public void NoCollateOrBinary_IsEmittedForADecliningProfile(
        SqlDialect dialect, FilterOperator op)
    {
        var rewritten = _rewriter.RewriteQuery(
            Query, Policy(new RowFilter("name", op, Value: "alice%")), dialect);

        rewritten.Should().NotContainEquivalentOf("COLLATE");
        rewritten.Should().NotContainEquivalentOf("BINARY");
        rewritten.Should().Be(Query);
    }

    /// <remarks>
    /// Direct evidence that this is a deliberate refusal and not a capability gap: the forced
    /// form does work on MySQL.
    /// </remarks>
    [Fact]
    public async Task TheMySqlCollateForm_WouldHaveWorked()
    {
        ScenarioHelpers.RequireService(_mysql.Ready, "a local database");

        var forced = await MySqlRowsAsync(
            "SELECT ('ALICE JONES' LIKE 'alice%' COLLATE utf8mb4_0900_as_cs) AS cmp");

        Convert.ToInt32(forced[0]["cmp"]).Should().Be(0);
    }
}
