using FluentAssertions;
using Tolap.Core;
using Xunit;

namespace Tolap.Mcp.Tests;

/// <summary>
/// <see cref="SqlEnforcementMode"/>: the two enforcement points must agree on what the caller
/// sees.
/// </summary>
/// <remarks>
/// <para>
/// The mode decides how much data the database produces — <c>RewriteAndPost</c> pushes filters,
/// the limit and the projection into the SQL; <c>PostOnly</c> leaves the query untouched — and if
/// the two ever returned <i>different rows</i>, the mode would be an access-control setting
/// wearing a performance setting's clothes. That is the divergence class
/// canonical-enforcement-spec.md section 4 exists to prevent.
/// </para>
/// <para>
/// So these assert equality <i>between</i> the modes rather than correctness of each alone. A
/// per-mode test would pass if <c>PostOnly</c> quietly returned an extra row, because nothing
/// would compare the two. The live-database version is Python's
/// <c>test_enforcement_mode_parity.py</c>; the fake execute here stands in for an engine so the
/// contract is pinned without a container.
/// </para>
/// </remarks>
public class SqlEnforcementModeTests
{
    private const string Sql = "SELECT id, full_name, email, region, status FROM patients ORDER BY id";

    private const string SigningKey = "mode-parity-test-key";

    private static readonly SecureContextToolWrapper Wrapper =
        new(new SecureContextWrapperOptions(SigningKey));

    /// <summary>The rows an engine would hold. PostOnly sees all of these; a rewrite sees fewer.</summary>
    private static List<Dictionary<string, object?>> Rows() =>
    [
        new() { ["id"] = 1, ["full_name"] = "John Smith", ["email"] = "j@x.com", ["region"] = "us-east", ["status"] = "active" },
        new() { ["id"] = 2, ["full_name"] = "Jane Doe", ["email"] = "jane@x.com", ["region"] = "us-west", ["status"] = "active" },
        new() { ["id"] = 3, ["full_name"] = "Mary Johnson", ["email"] = "m@x.com", ["region"] = "us-east", ["status"] = "active" },
        new() { ["id"] = 4, ["full_name"] = "Carl Davis", ["email"] = "c@x.com", ["region"] = "us-west", ["status"] = "deleted" },
    ];

    /// <summary>
    /// Stand in for the database: apply only what the emitted SQL would have applied.
    /// </summary>
    /// <remarks>
    /// Crude on purpose — it honours a pushed equality/inequality predicate and a pushed
    /// <c>LIMIT</c>, which is the subset rewriting pushes for these cases. The point is to feed
    /// the post pass a <i>different</i> input per mode, so equality of the final output is a real
    /// claim rather than a tautology.
    /// </remarks>
    private static Task<IReadOnlyList<Dictionary<string, object?>>> FakeDatabase(string query)
    {
        IEnumerable<Dictionary<string, object?>> rows = Rows();

        var eq = System.Text.RegularExpressions.Regex.Match(query, "\"(\\w+)\" = '([^']*)'");
        if (eq.Success)
            rows = rows.Where(r => Convert.ToString(r[eq.Groups[1].Value]) == eq.Groups[2].Value);

        var ne = System.Text.RegularExpressions.Regex.Match(query, "\\(\"(\\w+)\" <> '([^']*)' OR \"\\w+\" IS NULL\\)");
        if (ne.Success)
            rows = rows.Where(r => Convert.ToString(r[ne.Groups[1].Value]) != ne.Groups[2].Value);

        var limit = System.Text.RegularExpressions.Regex.Match(query, "LIMIT (\\d+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        if (limit.Success)
            rows = rows.Take(int.Parse(limit.Groups[1].Value));

        return Task.FromResult<IReadOnlyList<Dictionary<string, object?>>>(rows.ToList());
    }

    private static EffectivePolicy Policy(
        string[]? hiddenFields = null,
        MaskingRule[]? maskedFields = null,
        RowFilter[]? rowFilters = null,
        int? maxResults = null,
        bool canQuery = true)
    {
        var hasFieldRules = hiddenFields is not null || maskedFields is not null;

        return new EffectivePolicy(
            Version: "1.0",
            UserId: "u1",
            TenantId: "t1",
            SourceConnectionId: "db:pg:main",
            ResolvedAt: DateTimeOffset.UtcNow,
            ExpiresAt: DateTimeOffset.UtcNow.AddHours(1),
            SourceProfiles: ["mode-parity"],
            Permissions: new PolicyPermissions(CanQuery: canQuery),
            ObjectRules: new ObjectRules(
                AllowedObjects: ["patients"],
                FieldRules: hasFieldRules
                    ? new FieldRules(HiddenFields: hiddenFields, MaskedFields: maskedFields)
                    : null,
                RowFilters: rowFilters),
            Limits: maxResults is not null ? new PolicyLimits(MaxResults: maxResults) : null);
    }

    /// <summary>A signed context, since the wrapper verifies the signature before enforcing.</summary>
    private static SecurityContext Context(EffectivePolicy policy) =>
        SecurityContextSigner.Sign(
            SecurityContextBuilder.Build("u1", "t1", [policy]), SigningKey);

    public static TheoryData<string, EffectivePolicy> ParityCases() => new()
    {
        { "pushable equals", Policy(rowFilters: [new RowFilter("region", FilterOperator.Equals, Value: "us-east")]) },
        // No portable SQL form, so neither mode pushes it and the post pass does the work.
        { "unpushable startsWith", Policy(rowFilters: [new RowFilter("full_name", FilterOperator.StartsWith, Value: "J")]) },
        // Half pushed, half not: the engine applies one, the post pass the other, and the
        // result must equal post-only applying both.
        { "mixed", Policy(rowFilters: [
            new RowFilter("region", FilterOperator.Equals, Value: "us-east"),
            new RowFilter("full_name", FilterOperator.StartsWith, Value: "J")]) },
        // Needs the IS NULL arm when pushed, or the engine drops a row the post pass keeps.
        { "negative operator", Policy(rowFilters: [new RowFilter("status", FilterOperator.NotEquals, Value: "deleted")]) },
        // Masking has no SQL form at all, so it is post-pass work in both modes.
        { "masked field", Policy(maskedFields: [new MaskingRule("email", MaskType.Redact)]) },
        { "result limit", Policy(maxResults: 2) },
        { "combined", Policy(
            maskedFields: [new MaskingRule("email", MaskType.Redact)],
            rowFilters: [new RowFilter("region", FilterOperator.Equals, Value: "us-east")],
            maxResults: 2) },
    };

    [Theory]
    [MemberData(nameof(ParityCases))]
    public async Task BothModes_ReturnIdenticalResults(string name, EffectivePolicy policy)
    {
        var context = Context(policy);
        var args = new PreExecuteArgs("pg-query");

        var rewritten = await Wrapper.ExecuteSqlWithEnforcementAsync(
            context, args, Sql, FakeDatabase, dialect: SqlDialect.Postgres,
            mode: SqlEnforcementMode.RewriteAndPost);
        var postOnly = await Wrapper.ExecuteSqlWithEnforcementAsync(
            context, args, Sql, FakeDatabase, dialect: SqlDialect.Postgres,
            mode: SqlEnforcementMode.PostOnly);

        postOnly.Should().BeEquivalentTo(rewritten,
            $"{name}: the mode must not change what the caller sees (spec section 4)");
    }

    [Fact]
    public void TheModes_ReallyDoDifferInWhatTheyAskTheDatabase()
    {
        // Guards the guard: every equality assertion above would also pass if `mode` were
        // ignored and both calls took the same path.
        var context = Context(Policy(rowFilters: [new RowFilter("region", FilterOperator.Equals, Value: "us-east")], maxResults: 2));
        var args = new PreExecuteArgs("pg-query");

        var rewritten = Wrapper.PrepareSqlQuery(context, args, Sql, dialect: SqlDialect.Postgres, mode: SqlEnforcementMode.RewriteAndPost);
        var postOnly = Wrapper.PrepareSqlQuery(context, args, Sql, dialect: SqlDialect.Postgres, mode: SqlEnforcementMode.PostOnly);

        rewritten.Rewritten.Should().BeTrue();
        rewritten.Query.Should().Contain("WHERE").And.Contain("LIMIT");

        postOnly.Rewritten.Should().BeFalse();
        // A caller choosing PostOnly is choosing "the query that ran is the query I wrote".
        // A rewrite of any size, including a cosmetic one, breaks that promise.
        postOnly.Query.Should().Be(Sql);
    }

    [Fact]
    public void PostOnly_ReportsEveryFilterAsUnpushed()
    {
        // FullyPushedDown is what a caller checks before running a query whose result set may
        // be large. Reporting only the inexpressible operators would tell a PostOnly caller
        // their filters were pushed when the database never saw them.
        var policy = Policy(rowFilters: [
            new RowFilter("region", FilterOperator.Equals, Value: "us-east"),
            new RowFilter("status", FilterOperator.NotEquals, Value: "deleted")]);

        var prep = Wrapper.PrepareSqlQuery(Context(policy), new PreExecuteArgs("pg-query"), Sql,
            dialect: SqlDialect.Postgres, mode: SqlEnforcementMode.PostOnly);

        prep.UnpushableFilters.Should().HaveCount(2);
        prep.FullyPushedDown.Should().BeFalse();
    }

    [Theory]
    [InlineData(SqlEnforcementMode.RewriteAndPost)]
    [InlineData(SqlEnforcementMode.PostOnly)]
    public void PostOnly_SkipsTheRewrite_NotTheChecks_HiddenField(SqlEnforcementMode mode)
    {
        // The property that makes PostOnly safe to offer. If this refusal only lived on the
        // rewrite path, choosing PostOnly would hand the agent a column the policy hides.
        var prep = Wrapper.PrepareSqlQuery(
            Context(Policy(hiddenFields: ["ssn"])), new PreExecuteArgs("pg-query"),
            "SELECT id, ssn FROM patients", dialect: SqlDialect.Postgres, mode: mode);

        prep.Allowed.Should().BeFalse();
        prep.DenialReason.Should().Contain("permission");
    }

    [Theory]
    [InlineData(SqlEnforcementMode.RewriteAndPost)]
    [InlineData(SqlEnforcementMode.PostOnly)]
    public void PostOnly_SkipsTheRewrite_NotTheChecks_DisallowedObject(SqlEnforcementMode mode)
    {
        var prep = Wrapper.PrepareSqlQuery(
            Context(Policy()), new PreExecuteArgs("pg-query"),
            "SELECT id FROM encounters", dialect: SqlDialect.Postgres, mode: mode);

        prep.Allowed.Should().BeFalse();
    }

    [Theory]
    [InlineData(SqlEnforcementMode.RewriteAndPost)]
    [InlineData(SqlEnforcementMode.PostOnly)]
    public void PostOnly_SkipsTheRewrite_NotTheChecks_CanQueryFalse(SqlEnforcementMode mode)
    {
        var prep = Wrapper.PrepareSqlQuery(
            Context(Policy(canQuery: false)), new PreExecuteArgs("pg-query"), Sql,
            dialect: SqlDialect.Postgres, mode: mode);

        prep.Allowed.Should().BeFalse();
    }

    [Fact]
    public void DefaultMode_Rewrites()
    {
        // Not a tautology: it pins the cross-SDK contract. This SDK has always rewritten by
        // default and Python did not rewrite unless asked, which is the divergence the mode
        // exists to close. A change to the default has to break this test.
        SqlEnforcementModes.Default.Should().Be(SqlEnforcementMode.RewriteAndPost);
        SqlEnforcementModes.Resolve(null).Should().Be(SqlEnforcementMode.RewriteAndPost);

        var context = Context(Policy(rowFilters: [new RowFilter("region", FilterOperator.Equals, Value: "us-east")]));
        var omitted = Wrapper.PrepareSqlQuery(context, new PreExecuteArgs("pg-query"), Sql, dialect: SqlDialect.Postgres);

        omitted.Rewritten.Should().BeTrue();
    }

    [Fact]
    public void AnUndefinedMode_Throws_RatherThanDefaulting()
    {
        // A cast from an out-of-range int is legal C#, and 0 is RewriteAndPost -- so an
        // undefined member silently rewriting is the failure to prevent. This is the opposite
        // of dialect resolution, which declines to rewrite; see SqlEnforcementModes.Resolve.
        var act = () => SqlEnforcementModes.Resolve((SqlEnforcementMode)99);
        act.Should().Throw<ArgumentOutOfRangeException>()
            .WithMessage("*unrecognized SQL enforcement mode*");
    }
}
