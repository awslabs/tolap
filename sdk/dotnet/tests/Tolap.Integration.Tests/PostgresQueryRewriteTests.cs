using FluentAssertions;
using Npgsql;
using Tolap.Core;
using Tolap.Mcp;

namespace Tolap.Integration.Tests;

/// <summary>
/// Proves that a rewritten query is enforced by Postgres rather than after the fetch.
/// </summary>
/// <remarks>
/// <para>
/// The distinction these tests exist to establish is not whether the caller ends up with the
/// right rows — the post-fetch pipeline already guarantees that, and a test asserting only the
/// final row set passes whether or not the rewrite did anything. What is asserted here is that
/// <b>the database itself never produced the excluded rows</b>, which is the resource claim
/// (threat-model D2) the rewriter is for.
/// </para>
/// <para>
/// The evidence is taken three ways, because each alone is weak: the rewritten SQL is executed
/// raw and its row count compared against the unrestricted count; Postgres' own
/// <c>EXPLAIN</c> output is inspected for the injected predicate; and <c>pg_stat_statements</c>
/// -style row accounting is approximated by comparing what the reader returned against what
/// the table holds. A post-fetch-only implementation fails the first two.
/// </para>
/// </remarks>
public sealed class PostgresQueryRewriteTests : IClassFixture<PostgresFixture>
{
    private const string SigningKey = "integration-test-signing-key";

    private readonly PostgresFixture _db;

    /// <summary>
    /// Names Postgres explicitly, because every statement here runs against Postgres.
    /// </summary>
    /// <remarks>
    /// Load-bearing for <c>like</c>/<c>notLike</c>: a pushed-down <c>LIKE</c> inherits the
    /// column's collation, so only a dialect that promises a case-sensitive comparison may
    /// push it, and the default dialect makes no such promise.
    /// </remarks>
    private readonly SqlQueryRewriter _rewriter = new(dialect: SqlDialect.Postgres);

    public PostgresQueryRewriteTests(PostgresFixture db) { _db = db; }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private static EffectivePolicy Policy(
        string[]? allowedFields = null,
        string[]? hiddenFields = null,
        MaskingRule[]? maskedFields = null,
        RowFilter[]? rowFilters = null,
        int? maxResults = null) => new(
        Version: "1.0",
        UserId: "integration-user",
        TenantId: "integration-tenant",
        SourceConnectionId: "db:pg:tolap_integration_test",
        ResolvedAt: DateTimeOffset.UtcNow,
        ExpiresAt: DateTimeOffset.UtcNow.AddHours(1),
        SourceProfiles: new[] { "integration" },
        Permissions: new PolicyPermissions(CanQuery: true),
        ObjectRules: new ObjectRules(
            FieldRules: allowedFields is not null || hiddenFields is not null || maskedFields is not null
                ? new FieldRules(allowedFields, hiddenFields, maskedFields)
                : null,
            RowFilters: rowFilters),
        Limits: maxResults is not null ? new PolicyLimits(MaxResults: maxResults) : null);

    /// <summary>Executes SQL exactly as given and returns every row the database produced.</summary>
    private async Task<List<Dictionary<string, object?>>> RunRawAsync(string sql)
    {
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

    private async Task<long> ScalarCountAsync(string sql)
    {
        await using var cmd = new NpgsqlCommand(sql, _db.Connection);
        return Convert.ToInt64(await cmd.ExecuteScalarAsync());
    }

    /// <summary>The plan Postgres chose, as one string.</summary>
    private async Task<string> ExplainAsync(string sql)
    {
        await using var cmd = new NpgsqlCommand($"EXPLAIN {sql}", _db.Connection);
        await using var reader = await cmd.ExecuteReaderAsync();

        var lines = new List<string>();
        while (await reader.ReadAsync())
        {
            lines.Add(reader.GetString(0));
        }
        return string.Join("\n", lines);
    }

    private static SecurityContext Sign(EffectivePolicy policy)
        => ScenarioHelpers.SignPolicy(policy, SigningKey);

    private static SecureContextToolWrapper Wrapper()
        => new(new SecureContextWrapperOptions(SigningKey));

    // =======================================================================
    // The central claim: the filter reached the database
    // =======================================================================

    [Fact]
    public async Task RewrittenQuery_MakesPostgresReturnOnlyPermittedRows()
    {
        if (!_db.Ready) return;

        var policy = Policy(rowFilters: new[] { new RowFilter("region", FilterOperator.Equals, "us-east") });
        const string original = "SELECT id, region FROM patients ORDER BY id";

        // Baseline: unrestricted, the table produces every region.
        var unrestricted = await RunRawAsync(original);
        unrestricted.Should().HaveCountGreaterThan(2);
        unrestricted.Select(r => (string)r["region"]!).Distinct()
            .Should().HaveCountGreaterThan(1, "the fixture must contain more than one region");

        var rewritten = _rewriter.RewriteQuery(original, policy);
        rewritten.Should().Contain("WHERE \"region\" = 'us-east'");

        // Executed raw, with no post-fetch pass anywhere in the path: whatever comes back is
        // what Postgres itself decided to produce.
        var rows = await RunRawAsync(rewritten);

        rows.Should().NotBeEmpty();
        rows.Select(r => (string)r["region"]!).Should().AllBe("us-east");
        rows.Count.Should().BeLessThan(
            unrestricted.Count,
            "the database must have produced fewer rows, not the same rows filtered afterwards");
    }

    [Fact]
    public async Task Postgres_PlansTheInjectedPredicate_ProvingItIsNotAppliedAfterTheFetch()
    {
        if (!_db.Ready) return;

        var policy = Policy(rowFilters: new[] { new RowFilter("region", FilterOperator.Equals, "us-east") });
        var rewritten = _rewriter.RewriteQuery("SELECT id, region FROM patients", policy);

        // Postgres reports the predicate as a Filter or Index Cond on its own scan node. A
        // post-fetch implementation cannot produce this: the plan would carry no predicate at
        // all. This is the strongest available evidence that the restriction is the database's
        // and not the SDK's.
        var plan = await ExplainAsync(rewritten);

        plan.Should().Contain("patients");
        plan.Should().MatchRegex(@"(?i)(filter|cond).*region",
            "the injected predicate must appear in the plan Postgres chose");
        plan.Should().Contain("us-east");
    }

    [Fact]
    public async Task InjectedLimit_BoundsWhatPostgresProduces()
    {
        if (!_db.Ready) return;

        var total = await ScalarCountAsync("SELECT count(*) FROM patients");
        total.Should().BeGreaterThan(2);

        var policy = Policy(maxResults: 2);
        var rewritten = _rewriter.RewriteQuery("SELECT id FROM patients ORDER BY id", policy);

        rewritten.Should().EndWith("LIMIT 2");

        var rows = await RunRawAsync(rewritten);
        rows.Should().HaveCount(2);

        // The plan carries the bound, so the rows beyond it were never materialized.
        var plan = await ExplainAsync(rewritten);
        plan.Should().Contain("Limit");
    }

    [Fact]
    public async Task InjectedLimit_ClampsToTheSmallerOfExistingAndPolicy()
    {
        if (!_db.Ready) return;

        var policy = Policy(maxResults: 3);

        var clamped = _rewriter.RewriteQuery("SELECT id FROM patients ORDER BY id LIMIT 100", policy);
        (await RunRawAsync(clamped)).Should().HaveCount(3);

        var preserved = _rewriter.RewriteQuery("SELECT id FROM patients ORDER BY id LIMIT 1", policy);
        (await RunRawAsync(preserved)).Should().HaveCount(1);
    }

    [Fact]
    public async Task HiddenField_NeverLeavesTheDatabase()
    {
        if (!_db.Ready) return;

        var policy = Policy(hiddenFields: new[] { "ssn" });
        var rewritten = _rewriter.RewriteQuery(
            "SELECT id, full_name, ssn FROM patients ORDER BY id", policy);

        var rows = await RunRawAsync(rewritten);

        rows.Should().NotBeEmpty();
        // Not merely absent from the returned dictionaries: the column is absent from the
        // result set Postgres produced, so the values never crossed the wire.
        rows.Should().AllSatisfy(r => r.Keys.Should().NotContain("ssn"));
        rows.Should().AllSatisfy(r => r.Keys.Should().Contain("full_name"));
    }

    [Fact]
    public async Task SelectStar_ExpandsToAllowedMinusHidden_AgainstTheRealTable()
    {
        if (!_db.Ready) return;

        var policy = Policy(
            allowedFields: new[] { "id", "full_name", "ssn", "region" },
            hiddenFields: new[] { "ssn" });

        var rewritten = _rewriter.RewriteQuery("SELECT * FROM patients ORDER BY id", policy);
        var rows = await RunRawAsync(rewritten);

        rows.Should().NotBeEmpty();
        rows[0].Keys.Should().BeEquivalentTo(new[] { "id", "full_name", "region" });
        // email and date_of_birth are real columns the allow-list omits; a "SELECT *" that
        // reached the database would have returned them.
        rows[0].Keys.Should().NotContain("email");
        rows[0].Keys.Should().NotContain("date_of_birth");
    }

    [Fact]
    public async Task MaskedField_SurvivesIntoTheExecutedQuery_SoMaskingCanApply()
    {
        if (!_db.Ready) return;

        // The failure this guards against: dropping a masked column from the rewritten SELECT
        // means the post-fetch masker has nothing to act on, and the field vanishes from the
        // result instead of appearing masked.
        var policy = Policy(
            maskedFields: new[] { new MaskingRule("email", MaskType.Redact) },
            rowFilters: new[] { new RowFilter("region", FilterOperator.Equals, "us-east") });

        // region is projected deliberately: the post-fetch pass drops a row whose filtered
        // field is absent (spec section 7), so a query that omits the filter's field returns
        // nothing regardless of what the database matched. See
        // RowFilterField_MustBeProjected_OrThePostFetchPassDropsEveryRow below.
        var rewritten = _rewriter.RewriteQuery(
            "SELECT id, email, region FROM patients ORDER BY id", policy);

        var raw = await RunRawAsync(rewritten);
        raw.Should().NotBeEmpty();
        raw.Should().AllSatisfy(r => r.Keys.Should().Contain("email"));
        raw.Should().AllSatisfy(r => r["email"].Should().NotBeNull());

        // And after the mandatory post-fetch pass, the value is masked rather than missing.
        var masked = EnforcementEngine.ApplyRecordPipeline(raw, policy);
        masked.Should().NotBeEmpty();
        masked.Should().AllSatisfy(r => r["email"].Should().Be("[REDACTED]"));
    }

    // =======================================================================
    // Each added operator, executed by Postgres
    // =======================================================================

    [Fact]
    public async Task Like_PushedToPostgres()
    {
        if (!_db.Ready) return;

        var policy = Policy(rowFilters: new[] { new RowFilter("region", FilterOperator.Like, "us-%") });
        var rewritten = _rewriter.RewriteQuery("SELECT id, region FROM patients ORDER BY id", policy);

        rewritten.Should().Contain("LIKE 'us-%'");

        var rows = await RunRawAsync(rewritten);

        rows.Should().NotBeEmpty();
        rows.Select(r => (string)r["region"]!).Should().AllSatisfy(r => r.Should().StartWith("us-"));
        // eu-west is in the fixture and must not have been produced.
        rows.Select(r => (string)r["region"]!).Should().NotContain("eu-west");
    }

    [Fact]
    public async Task NotLike_PushedToPostgres()
    {
        if (!_db.Ready) return;

        var policy = Policy(rowFilters: new[] { new RowFilter("region", FilterOperator.NotLike, "us-%") });
        var rewritten = _rewriter.RewriteQuery("SELECT id, region FROM patients ORDER BY id", policy);

        var rows = await RunRawAsync(rewritten);

        rows.Should().NotBeEmpty();
        rows.Select(r => (string)r["region"]!).Should().AllSatisfy(r => r.Should().NotStartWith("us-"));
    }

    [Fact]
    public async Task Between_PushedToPostgres()
    {
        if (!_db.Ready) return;

        var policy = Policy(rowFilters: new[]
        {
            new RowFilter("id", FilterOperator.Between, Values: new object[] { 2, 4 })
        });
        var rewritten = _rewriter.RewriteQuery("SELECT id FROM patients ORDER BY id", policy);

        rewritten.Should().Contain("BETWEEN 2 AND 4");

        var rows = await RunRawAsync(rewritten);

        rows.Select(r => Convert.ToInt32(r["id"])).Should().BeEquivalentTo(new[] { 2, 3, 4 });
    }

    [Fact]
    public async Task GreaterThanOrEqualAndLessThanOrEqual_PushedToPostgres()
    {
        if (!_db.Ready) return;

        var policy = Policy(rowFilters: new[]
        {
            new RowFilter("id", FilterOperator.GreaterThanOrEqual, 3),
            new RowFilter("id", FilterOperator.LessThanOrEqual, 5)
        });
        var rewritten = _rewriter.RewriteQuery("SELECT id FROM patients ORDER BY id", policy);

        rewritten.Should().Contain("\"id\" >= 3");
        rewritten.Should().Contain("\"id\" <= 5");

        var rows = await RunRawAsync(rewritten);

        rows.Select(r => Convert.ToInt32(r["id"])).Should().BeEquivalentTo(new[] { 3, 4, 5 });
    }

    [Fact]
    public async Task IsNullAndIsNotNull_PushedToPostgres()
    {
        if (!_db.Ready) return;

        // patient_id is nullable in billing_internal only by reference; encounters.patient_id
        // is populated for every seeded row, so IS NOT NULL keeps all and IS NULL keeps none.
        var notNull = _rewriter.RewriteQuery(
            "SELECT id FROM encounters ORDER BY id",
            Policy(rowFilters: new[] { new RowFilter("patient_id", FilterOperator.IsNotNull) }));
        notNull.Should().Contain("\"patient_id\" IS NOT NULL");
        (await RunRawAsync(notNull)).Should().NotBeEmpty();

        var isNull = _rewriter.RewriteQuery(
            "SELECT id FROM encounters ORDER BY id",
            Policy(rowFilters: new[] { new RowFilter("patient_id", FilterOperator.IsNull) }));
        isNull.Should().Contain("\"patient_id\" IS NULL");
        (await RunRawAsync(isNull)).Should().BeEmpty();
    }

    [Fact]
    public async Task NotEquals_KeepsANullValuedRow_MatchingThePostFetchPass()
    {
        if (!_db.Ready) return;

        // The three-valued-logic case. A plain "col <> 'x'" drops a null-valued row, but the
        // post-fetch pass keeps it, so pushing the filter down would change the result. The
        // injected "OR col IS NULL" is what keeps the two paths agreeing -- asserted here
        // against the real engine rather than only against generated text.
        await using (var setup = new NpgsqlCommand(
            "DROP TABLE IF EXISTS rewrite_null_probe; "
            + "CREATE TABLE rewrite_null_probe (id INT, region TEXT); "
            + "INSERT INTO rewrite_null_probe VALUES (1, 'eu-west'), (2, 'us-east'), (3, NULL);",
            _db.Connection))
        {
            await setup.ExecuteNonQueryAsync();
        }

        var policy = Policy(rowFilters: new[] { new RowFilter("region", FilterOperator.NotEquals, "eu-west") });
        var rewritten = _rewriter.RewriteQuery(
            "SELECT id, region FROM rewrite_null_probe ORDER BY id", policy);

        var fromDatabase = await RunRawAsync(rewritten);

        // Row 3 (region NULL) is kept, row 1 (eu-west) is not.
        fromDatabase.Select(r => Convert.ToInt32(r["id"])).Should().BeEquivalentTo(new[] { 2, 3 });

        // And the post-fetch pass over the unrestricted rows agrees exactly.
        var unrestricted = await RunRawAsync("SELECT id, region FROM rewrite_null_probe ORDER BY id");
        var postFetch = EnforcementEngine.ApplyRowFilters(unrestricted, policy);

        postFetch.Select(r => Convert.ToInt32(r["id"]))
            .Should().BeEquivalentTo(fromDatabase.Select(r => Convert.ToInt32(r["id"])),
                "pushing a filter down must not change which rows the caller sees");

        await using var cleanup = new NpgsqlCommand("DROP TABLE rewrite_null_probe;", _db.Connection);
        await cleanup.ExecuteNonQueryAsync();
    }

    [Fact]
    public async Task NotIn_KeepsANullValuedRow_MatchingThePostFetchPass()
    {
        if (!_db.Ready) return;

        await using (var setup = new NpgsqlCommand(
            "DROP TABLE IF EXISTS rewrite_notin_probe; "
            + "CREATE TABLE rewrite_notin_probe (id INT, region TEXT); "
            + "INSERT INTO rewrite_notin_probe VALUES (1, 'eu-west'), (2, 'us-east'), (3, NULL);",
            _db.Connection))
        {
            await setup.ExecuteNonQueryAsync();
        }

        var policy = Policy(rowFilters: new[]
        {
            new RowFilter("region", FilterOperator.NotIn, Values: new object[] { "eu-west", "apac" })
        });
        var rewritten = _rewriter.RewriteQuery(
            "SELECT id, region FROM rewrite_notin_probe ORDER BY id", policy);

        var fromDatabase = await RunRawAsync(rewritten);
        var unrestricted = await RunRawAsync("SELECT id, region FROM rewrite_notin_probe ORDER BY id");
        var postFetch = EnforcementEngine.ApplyRowFilters(unrestricted, policy);

        fromDatabase.Select(r => Convert.ToInt32(r["id"])).Should().BeEquivalentTo(new[] { 2, 3 });
        postFetch.Select(r => Convert.ToInt32(r["id"]))
            .Should().BeEquivalentTo(fromDatabase.Select(r => Convert.ToInt32(r["id"])));

        await using var cleanup = new NpgsqlCommand("DROP TABLE rewrite_notin_probe;", _db.Connection);
        await cleanup.ExecuteNonQueryAsync();
    }

    /// <summary>
    /// <c>notLike</c>'s <c>IS NULL</c> arm, proven against a real engine like the other two.
    /// </summary>
    /// <remarks>
    /// <c>NULL NOT LIKE 'x'</c> is unknown — therefore not true — for exactly the same reason
    /// <c>NULL &lt;&gt; 'x'</c> is, so the bare form drops the null-valued row while the
    /// post-fetch pass keeps it. Postgres only, deliberately: a pushed-down <c>LIKE</c>
    /// inherits the column's collation and MySQL's default is case-insensitive, so the same
    /// comparison is engine-dependent there. That is separate from the null handling proven
    /// here.
    /// </remarks>
    [Fact]
    public async Task NotLike_KeepsANullValuedRow_MatchingThePostFetchPass()
    {
        if (!_db.Ready) return;

        await using (var setup = new NpgsqlCommand(
            "DROP TABLE IF EXISTS rewrite_notlike_probe; "
            + "CREATE TABLE rewrite_notlike_probe (id INT, name TEXT); "
            + "INSERT INTO rewrite_notlike_probe VALUES "
            + "(1, 'alice smith'), (2, 'ALICE JONES'), (3, 'bob stone'), (4, NULL);",
            _db.Connection))
        {
            await setup.ExecuteNonQueryAsync();
        }

        var policy = Policy(rowFilters: new[]
        {
            new RowFilter("name", FilterOperator.NotLike, "alice%")
        });
        const string original = "SELECT id, name FROM rewrite_notlike_probe ORDER BY id";
        var rewritten = _rewriter.RewriteQuery(original, policy);

        rewritten.Should().Contain("IS NULL");

        var fromDatabase = await RunRawAsync(rewritten);
        var postFetch = EnforcementEngine.ApplyRowFilters(await RunRawAsync(original), policy);

        // id 4 is NULL and is kept by BOTH paths; id 2 survives because Postgres LIKE is
        // case-sensitive, so 'ALICE JONES' does not match 'alice%'.
        fromDatabase.Select(r => Convert.ToInt32(r["id"])).Should().BeEquivalentTo(new[] { 2, 3, 4 });
        postFetch.Select(r => Convert.ToInt32(r["id"]))
            .Should().BeEquivalentTo(fromDatabase.Select(r => Convert.ToInt32(r["id"])));

        await using var cleanup = new NpgsqlCommand(
            "DROP TABLE rewrite_notlike_probe;", _db.Connection);
        await cleanup.ExecuteNonQueryAsync();
    }

    /// <summary>
    /// The three negative operators must select the same rows as each other, and each must
    /// agree across the pushed-down and post-fetch paths.
    /// </summary>
    /// <remarks>
    /// Regression guard for the asymmetry: <c>notLike</c> omitted the <c>IS NULL</c> arm that
    /// <c>notEquals</c> and <c>notIn</c> carried, so the same policy's row set depended on
    /// which negative operator the author happened to choose. Each filter below excludes
    /// exactly <c>'us-east'</c>.
    /// </remarks>
    [Fact]
    public async Task EveryNegativeOperator_SelectsTheSameRows_InBothPaths()
    {
        if (!_db.Ready) return;

        await using (var setup = new NpgsqlCommand(
            "DROP TABLE IF EXISTS rewrite_negatives_probe; "
            + "CREATE TABLE rewrite_negatives_probe (id INT, region TEXT); "
            + "INSERT INTO rewrite_negatives_probe VALUES "
            + "(1, 'us-east'), (2, 'eu-west'), (3, NULL);",
            _db.Connection))
        {
            await setup.ExecuteNonQueryAsync();
        }

        const string original = "SELECT id, region FROM rewrite_negatives_probe ORDER BY id";
        var negatives = new[]
        {
            new RowFilter("region", FilterOperator.NotEquals, "us-east"),
            new RowFilter("region", FilterOperator.NotIn, Values: new object[] { "us-east" }),
            new RowFilter("region", FilterOperator.NotLike, "us-eas_")
        };

        foreach (var filter in negatives)
        {
            var policy = Policy(rowFilters: new[] { filter });
            var rewritten = _rewriter.RewriteQuery(original, policy);

            // Every negative carries the arm, so the database keeps the null row too.
            rewritten.Should().Contain("IS NULL", filter.Operator.ToString());

            var fromDatabase = await RunRawAsync(rewritten);
            var postFetch = EnforcementEngine.ApplyRowFilters(await RunRawAsync(original), policy);

            // The null row is kept and the matching row dropped, identically in both paths
            // and identically for all three operators.
            fromDatabase.Select(r => Convert.ToInt32(r["id"])).OrderBy(i => i)
                .Should().BeEquivalentTo(new[] { 2, 3 }, filter.Operator.ToString());
            postFetch.Select(r => Convert.ToInt32(r["id"])).OrderBy(i => i)
                .Should().BeEquivalentTo(new[] { 2, 3 }, filter.Operator.ToString());
        }

        await using var cleanup = new NpgsqlCommand(
            "DROP TABLE rewrite_negatives_probe;", _db.Connection);
        await cleanup.ExecuteNonQueryAsync();
    }

    // =======================================================================
    // Rewrite and post-fetch must agree, over the whole fixture
    // =======================================================================

    public static IEnumerable<object[]> EquivalenceCases()
    {
        yield return new object[] { "equals", new RowFilter("region", FilterOperator.Equals, "us-east") };
        yield return new object[] { "notEquals", new RowFilter("region", FilterOperator.NotEquals, "us-east") };
        yield return new object[]
        {
            "in", new RowFilter("region", FilterOperator.In, Values: new object[] { "us-east", "eu-west" })
        };
        yield return new object[]
        {
            "notIn", new RowFilter("region", FilterOperator.NotIn, Values: new object[] { "us-east" })
        };
        yield return new object[] { "greaterThan", new RowFilter("id", FilterOperator.GreaterThan, 2) };
        yield return new object[] { "greaterThanOrEqual", new RowFilter("id", FilterOperator.GreaterThanOrEqual, 2) };
        yield return new object[] { "lessThan", new RowFilter("id", FilterOperator.LessThan, 4) };
        yield return new object[] { "lessThanOrEqual", new RowFilter("id", FilterOperator.LessThanOrEqual, 4) };
        yield return new object[] { "like", new RowFilter("region", FilterOperator.Like, "us-%") };
        yield return new object[] { "notLike", new RowFilter("region", FilterOperator.NotLike, "us-%") };
        yield return new object[] { "isNotNull", new RowFilter("region", FilterOperator.IsNotNull) };
        yield return new object[]
        {
            "between", new RowFilter("id", FilterOperator.Between, Values: new object[] { 2, 4 })
        };
    }

    [Theory]
    [MemberData(nameof(EquivalenceCases))]
    public async Task PushedDownAndPostFetch_SelectTheSameRows(string name, RowFilter filter)
    {
        if (!_db.Ready) return;

        var policy = Policy(rowFilters: new[] { filter });
        const string original = "SELECT id, region FROM patients ORDER BY id";

        // Path A: the database applies the filter.
        var pushedDown = await RunRawAsync(_rewriter.RewriteQuery(original, policy));

        // Path B: the database applies nothing and the pipeline filters afterwards.
        var postFetch = EnforcementEngine.ApplyRowFilters(await RunRawAsync(original), policy);

        pushedDown.Select(r => Convert.ToInt32(r["id"])).OrderBy(i => i)
            .Should().BeEquivalentTo(
                postFetch.Select(r => Convert.ToInt32(r["id"])).OrderBy(i => i),
                $"operator {name} must select the same rows whichever path enforces it");
    }

    // =======================================================================
    // Through the wrapper
    // =======================================================================

    [Fact]
    public async Task ExecuteSqlWithEnforcementAsync_RunsTheRewrittenQueryAndStillAppliesThePipeline()
    {
        if (!_db.Ready) return;

        var policy = Policy(
            hiddenFields: new[] { "ssn" },
            maskedFields: new[] { new MaskingRule("email", MaskType.Redact) },
            rowFilters: new[] { new RowFilter("region", FilterOperator.Like, "us-%") },
            maxResults: 10);

        var executed = new List<string>();

        var rows = await Wrapper().ExecuteSqlWithEnforcementAsync(
            Sign(policy),
            new PreExecuteArgs("pg-query"),
            "SELECT id, full_name, email, region FROM patients ORDER BY id",
            // Postgres LIKE is case-sensitive, so `like` is pushable here. The default
            // `ansi` profile declines it because it promises no collation (spec section 4).
            dialect: SqlDialect.Postgres,
            execute: async sql =>
            {
                executed.Add(sql);
                return await RunRawAsync(sql);
            });

        // The delegate received the rewritten text, not the caller's.
        executed.Should().ContainSingle();
        executed[0].Should().Contain("LIKE 'us-%'");
        executed[0].Should().Contain("LIMIT 10");

        rows.Should().NotBeEmpty();
        rows.Select(r => (string)r["region"]!).Should().AllSatisfy(r => r.Should().StartWith("us-"));
        // The post-fetch pass still ran: masking has no SQL form and could only have been
        // applied afterwards.
        rows.Should().AllSatisfy(r => r["email"].Should().Be("[REDACTED]"));
    }

    [Fact]
    public async Task PrepareSqlQuery_ResolvesTheObjectFromTheQuery_AndDeniesAHiddenTable()
    {
        if (!_db.Ready) return;

        // The caller names no object, so the table comes from the FROM clause. audit_log is
        // hidden, and a caller that simply omitted ObjectName must not thereby bypass the
        // check.
        var policy = Policy() with
        {
            ObjectRules = new ObjectRules(HiddenObjects: new[] { "audit_log" })
        };

        var prep = Wrapper().PrepareSqlQuery(
            Sign(policy), new PreExecuteArgs("pg-query"), "SELECT id FROM audit_log");

        prep.Allowed.Should().BeFalse();
        prep.DenialReason.Should().Be("object is hidden");
    }

    [Fact]
    public async Task PrepareSqlQuery_DeniesAQueryReferencingAHiddenField()
    {
        if (!_db.Ready) return;

        var prep = Wrapper().PrepareSqlQuery(
            Sign(Policy(hiddenFields: new[] { "ssn" })),
            new PreExecuteArgs("pg-query"),
            "SELECT id FROM patients WHERE ssn = '111-22-3333'");

        prep.Allowed.Should().BeFalse();
        prep.DenialReason.Should().Contain("permission");
    }

    [Fact]
    public async Task PrepareSqlQuery_ReportsFiltersItCouldNotPushDown()
    {
        if (!_db.Ready) return;

        // "matches" compiles as ^(?:pattern)$ (spec section 7), so the pattern must describe
        // the whole value: a bare "^J" would become "^(?:^J)$" and match nothing.
        var policy = Policy(rowFilters: new[]
        {
            new RowFilter("region", FilterOperator.Like, "us-%"),
            new RowFilter("full_name", FilterOperator.Matches, "J.*")
        });

        var prep = Wrapper().PrepareSqlQuery(
            Sign(policy), new PreExecuteArgs("pg-query"),
            "SELECT id, region, full_name FROM patients ORDER BY id",
            dialect: SqlDialect.Postgres);

        prep.Allowed.Should().BeTrue();
        prep.Rewritten.Should().BeTrue();
        prep.FullyPushedDown.Should().BeFalse();
        prep.UnpushableFilters.Should().ContainSingle().Which.Field.Should().Be("full_name");

        // The unpushable filter is still enforced, by the post-fetch pass.
        var rows = EnforcementEngine.ApplyRecordPipeline(await RunRawAsync(prep.Query), policy);
        rows.Should().NotBeEmpty();
        rows.Should().AllSatisfy(r => ((string)r["full_name"]!).Should().StartWith("J"));
        rows.Should().AllSatisfy(r => ((string)r["region"]!).Should().StartWith("us-"));
    }

    [Fact]
    public async Task PrepareSqlQuery_ReportsFullPushDown_WhenEveryFilterIsExpressible()
    {
        if (!_db.Ready) return;

        var prep = Wrapper().PrepareSqlQuery(
            Sign(Policy(rowFilters: new[] { new RowFilter("region", FilterOperator.Like, "us-%") })),
            new PreExecuteArgs("pg-query"),
            "SELECT id, region FROM patients",
            dialect: SqlDialect.Postgres);

        prep.Allowed.Should().BeTrue();
        prep.FullyPushedDown.Should().BeTrue();

        // Nothing is left for the post-fetch pass to drop.
        var raw = await RunRawAsync(prep.Query);
        EnforcementEngine.ApplyRowFilters(raw, Sign(Policy()).Policies[0]).Should().HaveCount(raw.Count);
    }

    [Fact]
    public async Task PrepareSqlQuery_LeavesAnUnrestrictedQueryUnchanged()
    {
        if (!_db.Ready) return;

        const string sql = "SELECT id, region FROM patients ORDER BY id";

        var prep = Wrapper().PrepareSqlQuery(Sign(Policy()), new PreExecuteArgs("pg-query"), sql);

        prep.Allowed.Should().BeTrue();
        prep.Rewritten.Should().BeFalse();
        prep.Query.Should().Be(sql);
    }

    [Fact]
    public async Task PrepareSqlQuery_DeniesAnEmptyQuery()
    {
        if (!_db.Ready) return;

        var prep = Wrapper().PrepareSqlQuery(Sign(Policy()), new PreExecuteArgs("pg-query"), "   ");

        prep.Allowed.Should().BeFalse();
        prep.DenialReason.Should().Be("query is empty");
    }

    [Fact]
    public async Task PrepareSqlQuery_DeniesAnUnsignedContext()
    {
        if (!_db.Ready) return;

        // The signature check must run before any rewriting: a tampered context's policy must
        // not be the one pushed into the query.
        var unsigned = SecurityContextBuilder.Build(
            "integration-user", "integration-tenant", new[] { Policy() });

        var prep = Wrapper().PrepareSqlQuery(
            unsigned, new PreExecuteArgs("pg-query"), "SELECT id FROM patients");

        prep.Allowed.Should().BeFalse();
        prep.DenialReason.Should().Be("invalid signature");
    }

    // =======================================================================
    // The interaction between pushing a filter down and the fail-closed post-fetch pass
    // =======================================================================

    [Fact]
    public async Task RowFilterField_MustBeProjected_OrThePostFetchPassDropsEveryRow()
    {
        if (!_db.Ready) return;

        // A sharp edge worth pinning, and not a rewrite defect: the two halves of enforcement
        // are individually correct and compose into a surprise.
        //
        // The rewriter pushes "WHERE region = 'us-east'" into the query, and Postgres returns
        // exactly the right rows. But if the projection does not include region, those rows
        // arrive without the field, and spec section 7 requires the post-fetch pass to drop a
        // row whose filtered field is absent. The caller gets nothing.
        //
        // This is the fail-closed direction, so it is not a security bug -- but an integrator
        // who reads "row filters are now pushed into SQL" and stops projecting the filter
        // field will see empty result sets, so the behaviour is asserted rather than left to be
        // rediscovered.
        var policy = Policy(rowFilters: new[] { new RowFilter("region", FilterOperator.Equals, "us-east") });

        var withoutField = _rewriter.RewriteQuery("SELECT id FROM patients ORDER BY id", policy);
        var rawWithoutField = await RunRawAsync(withoutField);

        // The database did its part.
        rawWithoutField.Should().NotBeEmpty("Postgres applied the injected predicate");
        rawWithoutField.Should().AllSatisfy(r => r.Keys.Should().NotContain("region"));

        // The post-fetch pass then drops every row, because it cannot confirm any of them.
        EnforcementEngine.ApplyRecordPipeline(rawWithoutField, policy)
            .Should().BeEmpty("a row missing the filtered field fails closed");

        // Projecting the field makes both halves agree.
        var withField = _rewriter.RewriteQuery("SELECT id, region FROM patients ORDER BY id", policy);
        var rawWithField = await RunRawAsync(withField);

        EnforcementEngine.ApplyRecordPipeline(rawWithField, policy)
            .Should().HaveCount(rawWithField.Count)
            .And.NotBeEmpty();
    }

    [Fact]
    public async Task AHiddenFilterField_StillDropsEveryRow_BecauseHiddenRemovalPrecedesNothing()
    {
        if (!_db.Ready) return;

        // The same edge, reached a second way: hiddenFields strips the field from every record
        // at step 5, but row filtering is step 1, so the filter sees the field and the caller
        // does not. Ordering saves this case -- asserted because reordering the pipeline would
        // silently turn it into the empty-result case above.
        var policy = Policy(
            hiddenFields: new[] { "region" },
            rowFilters: new[] { new RowFilter("region", FilterOperator.Equals, "us-east") });

        var rewritten = _rewriter.RewriteQuery("SELECT id, region FROM patients ORDER BY id", policy);

        // region is removed from the projection because it is hidden.
        rewritten.Should().Be("SELECT id FROM patients WHERE \"region\" = 'us-east' ORDER BY id");

        // So the rows come back without it, and the post-fetch filter drops them all. The
        // pushed-down predicate was correct and the outcome is still empty: a policy that both
        // hides a field and filters on it can only be enforced pre-execution.
        var raw = await RunRawAsync(rewritten);
        raw.Should().NotBeEmpty();
        EnforcementEngine.ApplyRecordPipeline(raw, policy).Should().BeEmpty();
    }

    // =======================================================================
    // A value that tries to escape the literal
    // =======================================================================

    [Fact]
    public async Task AQuoteInAPolicyValue_CannotBreakOutOfTheLiteral()
    {
        if (!_db.Ready) return;

        // Postgres is the arbiter here, not an assertion about generated text: if the escaping
        // were wrong this either raises a syntax error or returns every row.
        var policy = Policy(rowFilters: new[]
        {
            new RowFilter("region", FilterOperator.Equals, "us-east' OR '1'='1")
        });

        var rewritten = _rewriter.RewriteQuery("SELECT id FROM patients", policy);
        var rows = await RunRawAsync(rewritten);

        rows.Should().BeEmpty("no region equals the literal text \"us-east' OR '1'='1\"");
    }

    [Fact]
    public async Task ABackslashInAPolicyValue_IsNotPushedAndIsEnforcedAfterTheFetch()
    {
        if (!_db.Ready) return;

        // Refused as a literal because MySQL and Postgres disagree on backslash escaping. The
        // query is therefore unfiltered and the post-fetch pass must do the work.
        var policy = Policy(rowFilters: new[]
        {
            new RowFilter("region", FilterOperator.Equals, @"us-east\")
        });

        var prep = Wrapper().PrepareSqlQuery(
            Sign(policy), new PreExecuteArgs("pg-query"), "SELECT id, region FROM patients");

        prep.Allowed.Should().BeTrue();
        prep.FullyPushedDown.Should().BeFalse();

        var rows = EnforcementEngine.ApplyRecordPipeline(await RunRawAsync(prep.Query), policy);
        rows.Should().BeEmpty("no region equals \"us-east\\\", so every row is dropped post-fetch");
    }

    [Fact]
    public async Task ADroppedTableAttemptInAPolicyValue_IsInert()
    {
        if (!_db.Ready) return;

        var policy = Policy(rowFilters: new[]
        {
            new RowFilter("region", FilterOperator.Equals, "x'; DROP TABLE patients; --")
        });

        var rewritten = _rewriter.RewriteQuery("SELECT id FROM patients", policy);
        (await RunRawAsync(rewritten)).Should().BeEmpty();

        // The table is still there.
        (await ScalarCountAsync("SELECT count(*) FROM patients")).Should().BeGreaterThan(0);
    }
}
