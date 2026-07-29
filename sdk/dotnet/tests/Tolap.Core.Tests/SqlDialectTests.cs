using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// Dialect profiles for <see cref="SqlQueryRewriter"/> (connector-spec.md section 5.1).
/// </summary>
/// <remarks>
/// The bug these fix was measured, not theorised: the rewriter emitted Postgres-style
/// <c>WHERE "region" = 'us-east'</c> for every engine, and MySQL without <c>ANSI_QUOTES</c>
/// reads <c>"region"</c> as a <i>string literal</i>, so it evaluated
/// <c>'region' = 'us-east'</c> — false for every row, with no error reported. Against the
/// six-row integration fixture the policy-filtered query returned 0 rows where backticks
/// return 2. See <c>MySqlQueryRewriteTests</c> for the live proof against both engines.
/// </remarks>
public class SqlDialectTests
{
    private readonly SqlQueryRewriter _rewriter = new();

    /// <summary>An unrecognized dialect, reachable because a cast from an int is legal C#.</summary>
    private const SqlDialect Unrecognized = (SqlDialect)99;

    private static readonly SqlDialect[] EveryProfile =
    [
        SqlDialect.Ansi,
        SqlDialect.Postgres,
        SqlDialect.Trino,
        SqlDialect.MySql,
        SqlDialect.SqlServer
    ];

    private static EffectivePolicy Policy(
        RowFilter[]? rowFilters = null,
        int? maxResults = null,
        string[]? allowedFields = null,
        string[]? hiddenFields = null)
    {
        var hasFieldRules = allowedFields is not null || hiddenFields is not null;

        return new EffectivePolicy(
            Version: "1.0",
            UserId: "u1",
            TenantId: "t1",
            SourceConnectionId: "db:pg:main",
            ResolvedAt: DateTimeOffset.UtcNow,
            ExpiresAt: DateTimeOffset.UtcNow.AddHours(1),
            SourceProfiles: ["test"],
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

    /// <summary>The <c>region = 'US'</c> filter these tests push, in every profile.</summary>
    private static RowFilter UsFilter => new("region", FilterOperator.Equals, Value: "US");

    // =======================================================================
    // Per-profile emitted text
    // =======================================================================

    [Theory]
    [InlineData(SqlDialect.Ansi, "\"region\"")]
    [InlineData(SqlDialect.Postgres, "\"region\"")]
    [InlineData(SqlDialect.Trino, "\"region\"")]
    [InlineData(SqlDialect.MySql, "`region`")]
    [InlineData(SqlDialect.SqlServer, "[region]")]
    public void RewriteQuery_QuotesIdentifiers_ThePofilesOwnWay(SqlDialect dialect, string expected)
    {
        var result = _rewriter.RewriteQuery(
            "SELECT a FROM t", Policy(rowFilters: [UsFilter]), dialect);

        result.Should().Be($"SELECT a FROM t WHERE {expected} = 'US'");
    }

    [Theory]
    [InlineData(SqlDialect.Ansi, "SELECT a FROM t WHERE \"region\" = 'US' LIMIT 10")]
    [InlineData(SqlDialect.Postgres, "SELECT a FROM t WHERE \"region\" = 'US' LIMIT 10")]
    [InlineData(SqlDialect.Trino, "SELECT a FROM t WHERE \"region\" = 'US' LIMIT 10")]
    [InlineData(SqlDialect.MySql, "SELECT a FROM t WHERE `region` = 'US' LIMIT 10")]
    [InlineData(SqlDialect.SqlServer, "SELECT TOP 10 a FROM t WHERE [region] = 'US'")]
    public void RewriteQuery_SpellsTheRowLimit_ThePofilesOwnWay(SqlDialect dialect, string expected)
    {
        var result = _rewriter.RewriteQuery(
            "SELECT a FROM t", Policy(rowFilters: [UsFilter], maxResults: 10), dialect);

        result.Should().Be(expected);
    }

    [Fact]
    public void RewriteQuery_SelectsAnsi_WhenTheDialectIsOmitted()
    {
        // Not a guess at the engine -- the subset most engines accept.
        var policy = Policy(rowFilters: [UsFilter], maxResults: 10);

        _rewriter.RewriteQuery("SELECT a FROM t", policy)
            .Should().Be(_rewriter.RewriteQuery("SELECT a FROM t", policy, SqlDialect.Ansi));
    }

    [Fact]
    public void RewriteQuery_TakesTheDialect_FromTheConstructor()
    {
        var rewriter = new SqlQueryRewriter(dialect: SqlDialect.MySql);

        var result = rewriter.RewriteQuery("SELECT a FROM t", Policy(rowFilters: [UsFilter]));

        result.Should().Be("SELECT a FROM t WHERE `region` = 'US'");
    }

    [Fact]
    public void RewriteQuery_LetsAPerCallDialect_OverrideTheConstructors()
    {
        var rewriter = new SqlQueryRewriter(dialect: SqlDialect.MySql);

        var result = rewriter.RewriteQuery(
            "SELECT a FROM t", Policy(rowFilters: [UsFilter]), SqlDialect.SqlServer);

        result.Should().Be("SELECT a FROM t WHERE [region] = 'US'");
    }

    [Fact]
    public void RewriteQuery_QuotesAnExpandedSelectStar_ForTheProfile()
    {
        var result = _rewriter.RewriteQuery(
            "SELECT * FROM patients",
            Policy(allowedFields: ["id", "region"], hiddenFields: ["ssn"]),
            SqlDialect.MySql);

        result.Should().Be("SELECT `id`, `region` FROM patients");
    }

    // =======================================================================
    // Rule 2: an unrecognized dialect declines entirely
    // =======================================================================

    /// <remarks>
    /// Guessing a profile is how the MySQL backtick defect happened. Throwing would turn a
    /// deployment typo into an outage on a path that is only ever an optimization, so the query
    /// is returned untouched and the post-fetch pass — which was always the enforcement
    /// boundary (canonical-enforcement-spec.md section 4) — does the whole job.
    /// </remarks>
    [Fact]
    public void RewriteQuery_RewritesNothing_ForAnUnrecognizedDialect()
    {
        const string query = "SELECT a FROM t";

        var result = _rewriter.RewriteQuery(
            query, Policy(rowFilters: [UsFilter], maxResults: 10), Unrecognized);

        result.Should().Be(query);
    }

    [Fact]
    public void BuildWhereClause_IsEmpty_ForAnUnrecognizedDialect()
    {
        _rewriter.BuildWhereClause([UsFilter], Unrecognized).Should().BeEmpty();
    }

    [Fact]
    public void UnpushableFilters_ReportsEveryFilter_ForAnUnrecognizedDialect()
    {
        RowFilter[] filters =
        [
            UsFilter,
            new("status", FilterOperator.NotEquals, Value: "deleted")
        ];
        var policy = Policy(rowFilters: filters);

        _rewriter.UnpushableFilters(policy, Unrecognized).Should().BeEquivalentTo(filters);
        // ...where a recognized profile pushes both.
        _rewriter.UnpushableFilters(policy, SqlDialect.MySql).Should().BeEmpty();
    }

    [Fact]
    public void RewriteQuery_DoesNotThrow_ForAnUnrecognizedDialect()
    {
        var act = () => _rewriter.RewriteQuery(
            "SELECT a FROM t", Policy(rowFilters: [UsFilter]), Unrecognized);

        act.Should().NotThrow();
    }

    [Fact]
    public void RewriteQuery_ExplainsItself_ForAnUnrecognizedDialect()
    {
        var messages = new List<string>();
        var rewriter = new SqlQueryRewriter(messages.Add);

        rewriter.RewriteQuery("SELECT a FROM t", Policy(rowFilters: [UsFilter]), Unrecognized);

        messages.Should().Contain(m => m.Contains("unrecognized SQL dialect"));
    }

    [Fact]
    public void ThePostPass_StillEnforcesTheDeclinedFilters()
    {
        // The whole reason declining is safe: rewriting was only ever an optimization, so the
        // rows a caller ends up with are still correct.
        var policy = Policy(rowFilters: [UsFilter]);

        _rewriter.RewriteQuery("SELECT id, region FROM t", policy, Unrecognized)
            .Should().Be("SELECT id, region FROM t");

        List<Dictionary<string, object?>> rows =
        [
            new() { ["id"] = 1, ["region"] = "US" },
            new() { ["id"] = 2, ["region"] = "EU" },
            new() { ["id"] = 3, ["region"] = "US" }
        ];

        var enforced = EnforcementEngine.ApplyRecordPipeline(rows, policy);

        enforced.Should().HaveCount(2);
        enforced.Select(r => r["id"]).Should().BeEquivalentTo(new object?[] { 1, 3 });
    }

    // =======================================================================
    // Rule 4: an identifier carrying the profile's own quote is declined
    // =======================================================================

    /// <remarks>
    /// Declined, never escaped by doubling. Declining costs an optimization; mis-escaping emits
    /// author-controlled text into the statement, and the doubling rule is not even the same in
    /// every engine.
    /// </remarks>
    [Theory]
    [InlineData(SqlDialect.Ansi, "reg\"ion")]
    [InlineData(SqlDialect.Postgres, "reg\"ion")]
    [InlineData(SqlDialect.Trino, "reg\"ion")]
    [InlineData(SqlDialect.MySql, "reg`ion")]
    [InlineData(SqlDialect.SqlServer, "reg[ion")]
    [InlineData(SqlDialect.SqlServer, "reg]ion")]
    public void RewriteQuery_DeclinesAnIdentifier_CarryingTheProfilesOwnQuote(
        SqlDialect dialect, string field)
    {
        var policy = Policy(rowFilters: [new(field, FilterOperator.Equals, Value: "x")]);

        var result = _rewriter.RewriteQuery("SELECT a FROM t", policy, dialect);

        result.Should().Be("SELECT a FROM t");
        result.Should().NotContain("WHERE");
        _rewriter.UnpushableFilters(policy, dialect).Should().HaveCount(1);
    }

    [Fact]
    public void RewriteQuery_EmitsNoDoubledQuote_ForAnIdentifierCarryingOne()
    {
        var policy = Policy(rowFilters: [new("reg\"ion", FilterOperator.Equals, Value: "x")]);

        var result = _rewriter.RewriteQuery("SELECT a FROM t", policy, SqlDialect.Ansi);

        result.Should().NotContain("\"\"");
    }

    [Theory]
    [InlineData(SqlDialect.SqlServer, "[region]")]
    [InlineData(SqlDialect.MySql, "`region`")]
    public void RewriteQuery_StillUnwrapsAWrappingQuote_AndAcceptsTheName(
        SqlDialect dialect, string expected)
    {
        // The delimiters a policy wrote *around* a name are not part of it. Only a quote
        // character surviving *inside* the name is a decline.
        var policy = Policy(rowFilters: [new("[region]", FilterOperator.Equals, Value: "x")]);

        var result = _rewriter.RewriteQuery("SELECT a FROM t", policy, dialect);

        result.Should().Be($"SELECT a FROM t WHERE {expected} = 'x'");
    }

    // =======================================================================
    // Rule 5: a backslash value is refused under EVERY profile
    // =======================================================================

    /// <remarks>
    /// Uniform, so a policy behaves identically across engines. MySQL treats <c>\</c> as a
    /// string escape by default and Postgres does not, so the same text would mean different
    /// things in the two engines. Refusing everywhere keeps a filter unpushable on one engine
    /// unpushable on all of them — and one profile treating <c>\</c> as an escape is enough to
    /// make escaping unsafe to generalize.
    /// </remarks>
    public static TheoryData<SqlDialect> AllProfiles()
    {
        var data = new TheoryData<SqlDialect>();
        foreach (var dialect in EveryProfile) data.Add(dialect);
        return data;
    }

    [Theory]
    [MemberData(nameof(AllProfiles))]
    public void RewriteQuery_RefusesABackslashValue_UnderEveryProfile(SqlDialect dialect)
    {
        var policy = Policy(rowFilters:
            [new("region", FilterOperator.Equals, Value: @"us-east\' OR 1=1 --")]);

        var result = _rewriter.RewriteQuery("SELECT a FROM t", policy, dialect);

        result.Should().Be("SELECT a FROM t");
        result.Should().NotContain("\\");
        _rewriter.UnpushableFilters(policy, dialect).Should().HaveCount(1);
    }

    [Theory]
    [MemberData(nameof(AllProfiles))]
    public void RewriteQuery_RefusesAControlCharacterValue_UnderEveryProfile(SqlDialect dialect)
    {
        var policy = Policy(rowFilters:
            [new("region", FilterOperator.Equals, Value: "us\0east")]);

        var result = _rewriter.RewriteQuery("SELECT a FROM t", policy, dialect);

        result.Should().Be("SELECT a FROM t");
        _rewriter.UnpushableFilters(policy, dialect).Should().HaveCount(1);
    }

    [Theory]
    [MemberData(nameof(AllProfiles))]
    public void RewriteQuery_StillDoublesAPlainSingleQuote_UnderEveryProfile(SqlDialect dialect)
    {
        // The refusal is specific to backslashes and control characters. Ordinary ANSI quote
        // doubling is correct in every profile and stays.
        var policy = Policy(rowFilters:
            [new("region", FilterOperator.Equals, Value: "it's")]);

        var result = _rewriter.RewriteQuery("SELECT a FROM t", policy, dialect);

        result.Should().Contain("'it''s'");
        _rewriter.UnpushableFilters(policy, dialect).Should().BeEmpty();
    }

    // =======================================================================
    // Rule 3: sqlserver TOP placement is never approximated
    // =======================================================================

    /// <remarks>
    /// <c>TOP n</c> goes after <c>SELECT</c> (and after <c>DISTINCT</c>/<c>ALL</c>), not at the
    /// end, so this is a structural placement rather than a token swap. Where it cannot be
    /// placed correctly the limit is simply <b>not pushed</b> — never rendered as
    /// <c>LIMIT n</c> instead. An unpushed limit costs a transfer that
    /// <see cref="EnforcementEngine.ApplyResultLimit"/> trims; a misplaced one is a broken
    /// statement or a wrong row count.
    /// </remarks>
    private string SqlServer(string query, int maxResults = 10)
        => _rewriter.RewriteQuery(query, Policy(maxResults: maxResults), SqlDialect.SqlServer);

    [Fact]
    public void ClampLimit_PlacesTopAfterSelect_NotAtTheEnd()
    {
        var result = SqlServer("SELECT a FROM t");

        result.Should().Be("SELECT TOP 10 a FROM t");
        result.Should().NotContain("LIMIT");
    }

    [Fact]
    public void ClampLimit_PlacesTopAfterDistinct()
    {
        // "SELECT DISTINCT TOP 5" is a syntax error, and "SELECT TOP 5 DISTINCT" would count
        // rows before duplicates are removed.
        SqlServer("SELECT DISTINCT a FROM t").Should().Be("SELECT DISTINCT TOP 10 a FROM t");
    }

    [Fact]
    public void ClampLimit_PlacesTopAfterAll()
    {
        SqlServer("SELECT ALL a FROM t").Should().Be("SELECT ALL TOP 10 a FROM t");
    }

    [Fact]
    public void ClampLimit_ClampsAnExistingLargerTop()
    {
        SqlServer("SELECT TOP 50 a FROM t").Should().Be("SELECT TOP 10 a FROM t");
    }

    [Fact]
    public void ClampLimit_KeepsAnExistingSmallerTop()
    {
        SqlServer("SELECT TOP 3 a FROM t").Should().Be("SELECT TOP 3 a FROM t");
    }

    [Fact]
    public void ClampLimit_ClampsTheParenthesisedTopForm()
    {
        SqlServer("SELECT TOP (50) a FROM t").Should().Be("SELECT TOP 10 a FROM t");
    }

    [Theory]
    // A TOP on the first operand limits that operand, not the union, so the caller would
    // receive MORE rows than the policy allows.
    [InlineData("SELECT a FROM t UNION SELECT b FROM u")]
    [InlineData("SELECT a FROM t INTERSECT SELECT b FROM u")]
    [InlineData("SELECT a FROM t EXCEPT SELECT b FROM u")]
    // T-SQL forbids TOP alongside OFFSET ... FETCH.
    [InlineData("SELECT a FROM t ORDER BY a OFFSET 5 ROWS")]
    [InlineData("SELECT a FROM t ORDER BY a FETCH FIRST 5 ROWS ONLY")]
    // A percentage is not a row count; WITH TIES returns more rows than given.
    [InlineData("SELECT TOP 5 PERCENT a FROM t")]
    [InlineData("SELECT TOP 5 WITH TIES a FROM t ORDER BY a")]
    // Already not valid T-SQL; clamping around a clause this profile does not emit would be
    // guessing at what the caller meant.
    [InlineData("SELECT a FROM t LIMIT 50")]
    public void ClampLimit_DeclinesRatherThanApproximating(string query)
    {
        var result = SqlServer(query);

        result.Should().Be(query);
        result.Should().NotContain("TOP 10");
        result.Should().NotContain("LIMIT 10");
    }

    [Fact]
    public void ADeclinedLimit_IsStillEnforcedAfterTheFetch()
    {
        // The limit not reaching the statement costs transfer, not correctness.
        var policy = Policy(maxResults: 2);
        const string query = "SELECT a FROM t UNION SELECT b FROM u";

        _rewriter.RewriteQuery(query, policy, SqlDialect.SqlServer).Should().Be(query);

        List<Dictionary<string, object?>> rows =
        [
            new() { ["a"] = 1 }, new() { ["a"] = 2 }, new() { ["a"] = 3 }, new() { ["a"] = 4 }
        ];

        EnforcementEngine.ApplyRecordPipeline(rows, policy).Should().HaveCount(2);
    }

    [Theory]
    [InlineData("DELETE FROM t")]
    [InlineData("UPDATE t SET a = 1")]
    public void ClampLimit_DeclinesAStatementWithNoTopLevelSelect(string query)
    {
        // There is nowhere to place a TOP. A non-SELECT statement should not reach a read-path
        // rewriter at all -- readOnly blocks it earlier (connector-spec.md section 4) -- but if
        // one does, it is returned untouched rather than mangled.
        SqlServer(query).Should().Be(query);
    }

    [Fact]
    public void ARowFilter_IsStillPushed_WhenTheLimitIsDeclined()
    {
        // The two pushdowns are independent: declining the limit must not cost the WHERE.
        var result = _rewriter.RewriteQuery(
            "SELECT a FROM t LIMIT 50",
            Policy(rowFilters: [UsFilter], maxResults: 10),
            SqlDialect.SqlServer);

        result.Should().Be("SELECT a FROM t WHERE [region] = 'US' LIMIT 50");
    }
}
