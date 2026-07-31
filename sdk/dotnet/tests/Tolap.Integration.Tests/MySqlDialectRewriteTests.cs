using FluentAssertions;
using MySqlConnector;
using Tolap.Core;
using Xunit;

namespace Tolap.Integration.Tests;

/// <summary>
/// The dialect profiles, proven against a live MySQL.
/// </summary>
/// <remarks>
/// <para>
/// This is the regression suite for a <b>measured</b> defect. The rewriter emitted
/// Postgres-style double-quoted identifiers for every engine:
/// </para>
/// <code>
/// SELECT COUNT(*) FROM patients WHERE "region" = 'us-east'   ->  0   &lt;-- wrong
/// SELECT COUNT(*) FROM patients WHERE `region` = 'us-east'   ->  2   &lt;-- correct
/// SELECT COUNT(*) FROM patients                              ->  6
/// </code>
/// <para>
/// MySQL without <c>ANSI_QUOTES</c> reads <c>"region"</c> as a <i>string literal</i>, so it
/// evaluated <c>'region' = 'us-east'</c> — false for every row. <b>The engine reported no error
/// either way</b>, which is what made this silent: an integrator on MySQL saw empty results and
/// concluded the product was broken.
/// </para>
/// <para>
/// The failure direction matters: it fails <b>closed</b> — the policy-filtered query returned
/// <i>fewer</i> rows, never more — so this was a correctness and availability defect rather than
/// a disclosure. The post-execution pass remained the security boundary throughout
/// (canonical-enforcement-spec.md section 4).
/// </para>
/// <para>
/// Asserting the emitted SQL <i>text</i> cannot catch this class of bug, because the text was
/// well-formed — it just meant something different in the other engine. Only executing it can.
/// </para>
/// </remarks>
public class MySqlDialectRewriteTests : IClassFixture<MySqlFixture>
{
    private readonly MySqlFixture _fixture;
    private readonly SqlQueryRewriter _rewriter = new();

    /// <summary>The seeded <c>patients</c> table holds 6 rows, 2 of them in us-east.</summary>
    private const int TotalPatients = 6;
    private const int UsEastPatients = 2;

    public MySqlDialectRewriteTests(MySqlFixture fixture) => _fixture = fixture;

    private static EffectivePolicy Policy(
        RowFilter[]? rowFilters = null,
        int? maxResults = null,
        string[]? allowedFields = null,
        string[]? hiddenFields = null)
    {
        var hasFieldRules = allowedFields is not null || hiddenFields is not null;

        return new EffectivePolicy(
            Version: "1.0",
            UserId: "u",
            TenantId: "t",
            SourceConnectionId: "db:mysql:main",
            ResolvedAt: DateTimeOffset.UtcNow,
            ExpiresAt: DateTimeOffset.UtcNow.AddHours(1),
            SourceProfiles: ["dialect-integration"],
            Permissions: new PolicyPermissions(CanQuery: true),
            ObjectRules: hasFieldRules || rowFilters is not null
                ? new ObjectRules(
                    FieldRules: hasFieldRules
                        ? new FieldRules(AllowedFields: allowedFields, HiddenFields: hiddenFields)
                        : null,
                    RowFilters: rowFilters)
                : null,
            Limits: maxResults is not null ? new PolicyLimits(MaxResults: maxResults) : null);
    }

    /// <summary>The policy filter from the measured bug report: region = 'us-east'.</summary>
    private static RowFilter UsEast => new("region", FilterOperator.Equals, Value: "us-east");

    private async Task<List<Dictionary<string, object?>>> RowsAsync(string sql)
    {
        var rows = new List<Dictionary<string, object?>>();
        await using var cmd = new MySqlCommand(sql, _fixture.Connection);
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            var row = new Dictionary<string, object?>();
            for (var i = 0; i < reader.FieldCount; i++)
            {
                row[reader.GetName(i)] = await reader.IsDBNullAsync(i) ? null : reader.GetValue(i);
            }
            rows.Add(row);
        }
        return rows;
    }

    // =======================================================================
    // The measured defect, pinned so it cannot come back
    // =======================================================================

    [Fact]
    public async Task TheMySqlProfile_ReturnsTheCorrectRows()
    {
        if (!_fixture.Ready) return;

        var sql = _rewriter.RewriteQuery(
            "SELECT id, region FROM patients", Policy(rowFilters: [UsEast]), SqlDialect.MySql);

        sql.Should().Contain("`region`");

        var rows = await RowsAsync(sql);

        rows.Should().HaveCount(UsEastPatients);
        rows.Should().OnlyContain(r => (string)r["region"]! == "us-east");
    }

    /// <remarks>
    /// <b>This is the regression.</b> The ansi/postgres profile emits <c>"region"</c>, which
    /// MySQL reads as the string literal 'region', so the predicate is
    /// <c>'region' = 'us-east'</c> — false for every row. Pinned deliberately: if someone makes
    /// the default emit double quotes for MySQL again, this fails and names the reason. Note the
    /// engine raises nothing; the only symptom is the empty result.
    /// </remarks>
    [Fact]
    public async Task TheWrongProfile_SilentlyReturnsNothing()
    {
        if (!_fixture.Ready) return;

        var policy = Policy(rowFilters: [UsEast]);

        var wrongSql = _rewriter.RewriteQuery(
            "SELECT id, region FROM patients", policy, SqlDialect.Postgres);

        wrongSql.Should().Contain("\"region\"");
        (await RowsAsync(wrongSql)).Should().BeEmpty();

        // ...and the same policy with the right profile finds the rows.
        var rightSql = _rewriter.RewriteQuery(
            "SELECT id, region FROM patients", policy, SqlDialect.MySql);
        (await RowsAsync(rightSql)).Should().HaveCount(UsEastPatients);
    }

    [Fact]
    public async Task TheEngine_ReportsNoError_ForEitherForm()
    {
        if (!_fixture.Ready) return;

        // Why this was silent: both statements execute successfully.
        (await RowsAsync("SELECT COUNT(*) AS n FROM patients"))[0]["n"]
            .Should().Be(TotalPatients);
        (await RowsAsync("SELECT COUNT(*) AS n FROM patients WHERE \"region\" = 'us-east'"))[0]["n"]
            .Should().Be(0L);
        (await RowsAsync("SELECT COUNT(*) AS n FROM patients WHERE `region` = 'us-east'"))[0]["n"]
            .Should().Be((long)UsEastPatients);
    }

    [Fact]
    public async Task TheDoubleQuotedForm_IsAStringComparison()
    {
        if (!_fixture.Ready) return;

        // Direct proof of the mechanism, not just its effect.
        var rows = await RowsAsync("SELECT \"region\" = 'us-east' AS cmp");

        Convert.ToInt64(rows[0]["cmp"]).Should().Be(0);
    }

    [Fact]
    public async Task TheFailureDirection_IsClosedNotOpen()
    {
        if (!_fixture.Ready) return;

        // The wrong profile returned FEWER rows, never more. That is what makes this a
        // correctness/availability defect rather than a disclosure.
        var policy = Policy(rowFilters: [UsEast]);

        var wrong = await RowsAsync(
            _rewriter.RewriteQuery("SELECT id FROM patients", policy, SqlDialect.Postgres));
        var right = await RowsAsync(
            _rewriter.RewriteQuery("SELECT id FROM patients", policy, SqlDialect.MySql));

        wrong.Count.Should().BeLessThan(right.Count);
        wrong.Should().BeEmpty();
    }

    // =======================================================================
    // The profile's other pushdowns execute correctly
    // =======================================================================

    [Fact]
    public async Task TheLimitIsPushed_AndExecutes()
    {
        if (!_fixture.Ready) return;

        var sql = _rewriter.RewriteQuery(
            "SELECT id FROM patients", Policy(maxResults: 3), SqlDialect.MySql);

        sql.Should().EndWith("LIMIT 3");
        (await RowsAsync(sql)).Should().HaveCount(3);
    }

    [Fact]
    public async Task TheProjectionIsPushed_AndTheHiddenColumnNeverLeavesTheDatabase()
    {
        if (!_fixture.Ready) return;

        var sql = _rewriter.RewriteQuery(
            "SELECT * FROM patients",
            Policy(allowedFields: ["id", "region"], hiddenFields: ["ssn"]),
            SqlDialect.MySql);

        sql.Should().Be("SELECT `id`, `region` FROM patients");

        var rows = await RowsAsync(sql);

        rows[0].Keys.Should().BeEquivalentTo(["id", "region"]);
        rows[0].Should().NotContainKey("ssn");
    }

    [Fact]
    public async Task AnExistingWhereIsParenthesised_AndTheStatementParses()
    {
        if (!_fixture.Ready) return;

        // Both sides must be grouped, AND the trailing clauses must stay OUTSIDE the
        // parentheses -- MySQL rejects `WHERE (f) AND (status = 'active' ORDER BY id)` as a
        // syntax error, which is a bug this suite would have caught.
        var sql = _rewriter.RewriteQuery(
            "SELECT id, region FROM patients WHERE status = 'active' ORDER BY id",
            Policy(rowFilters: [UsEast]),
            SqlDialect.MySql);

        sql.Should().Be(
            "SELECT id, region FROM patients WHERE (`region` = 'us-east') AND "
            + "(status = 'active') ORDER BY id");

        var rows = await RowsAsync(sql);

        rows.Should().HaveCount(UsEastPatients);
    }

    // =======================================================================
    // Declining to rewrite is safe, because the post pass is the boundary
    // =======================================================================

    [Fact]
    public async Task RewritingDeclined_StillReturnsTheRightRows()
    {
        if (!_fixture.Ready) return;

        // The load-bearing claim behind rule 2: declining is only acceptable because the
        // post-execution pass was always the enforcement boundary. Asserted end to end.
        var policy = Policy(rowFilters: [UsEast]);

        var sql = _rewriter.RewriteQuery(
            "SELECT id, region FROM patients", policy, (SqlDialect)99);

        sql.Should().Be("SELECT id, region FROM patients");
        _rewriter.UnpushableFilters(policy, (SqlDialect)99).Should().HaveCount(1);

        // The database returns every row...
        var raw = await RowsAsync(sql);
        raw.Should().HaveCount(TotalPatients);

        // ...and the post pass produces exactly the right ones.
        var enforced = EnforcementEngine.ApplyRecordPipeline(raw, policy);

        enforced.Should().HaveCount(UsEastPatients);
        enforced.Should().OnlyContain(r => (string)r["region"]! == "us-east");
    }

    [Fact]
    public async Task ADeclinedLimit_IsStillAppliedAfterTheFetch()
    {
        if (!_fixture.Ready) return;

        var policy = Policy(maxResults: 2);

        var sql = _rewriter.RewriteQuery("SELECT id FROM patients", policy, (SqlDialect)99);

        var raw = await RowsAsync(sql);
        raw.Should().HaveCount(TotalPatients);
        EnforcementEngine.ApplyRecordPipeline(raw, policy).Should().HaveCount(2);
    }

    // =======================================================================
    // Refusals hold against the live engine
    // =======================================================================

    [Fact]
    public async Task ABackslashValue_NeverReachesTheStatement()
    {
        if (!_fixture.Ready) return;

        // Executing this is the point: asserting a value was refused proves the refusal;
        // running the query proves the RESULT is still right.
        var policy = Policy(rowFilters:
            [new("region", FilterOperator.Equals, Value: @"us-east\' OR 1=1 --")]);

        var sql = _rewriter.RewriteQuery(
            "SELECT id, region FROM patients", policy, SqlDialect.MySql);

        sql.Should().Be("SELECT id, region FROM patients");
        sql.Should().NotContain("\\");

        // The refused filter is enforced after the fetch instead, and admits no row.
        var raw = await RowsAsync(sql);
        raw.Should().HaveCount(TotalPatients);
        EnforcementEngine.ApplyRecordPipeline(raw, policy).Should().BeEmpty();
    }

    [Fact]
    public async Task AQuotedValue_IsEscapedAndExecutes()
    {
        if (!_fixture.Ready) return;

        // An ordinary apostrophe is doubled, not refused, and MySQL accepts it.
        var sql = _rewriter.RewriteQuery(
            "SELECT id FROM patients",
            Policy(rowFilters: [new("region", FilterOperator.Equals, Value: "it's-not-a-region")]),
            SqlDialect.MySql);

        sql.Should().Contain("'it''s-not-a-region'");
        (await RowsAsync(sql)).Should().BeEmpty();
    }
}
