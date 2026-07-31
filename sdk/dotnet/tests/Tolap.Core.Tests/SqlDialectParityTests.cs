using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// Cross-SDK emitted-SQL parity for the dialect profiles.
/// </summary>
/// <remarks>
/// <para>
/// <b>The same query + policy + profile must produce the SAME SQL text in Python,
/// TypeScript, and .NET.</b> This corpus is duplicated verbatim in all three SDKs:
/// <c>sdk/python/tests/test_sql_dialect_parity.py</c>,
/// <c>sdk/typescript/packages/core/tests/sql-dialect-parity.test.ts</c>, and this file.
/// </para>
/// <para>
/// Every row is the exact string all three emit. A change to any one SDK's output fails that
/// SDK's copy and names the case, which is the point: three implementations of one spec drift
/// silently otherwise, and drift here means the same policy behaves differently depending on
/// which SDK an integrator picked.
/// </para>
/// <para>
/// Building this corpus found two real divergences the per-SDK suites had missed, both in the
/// WHERE-injection path and both since fixed:
/// </para>
/// <list type="bullet">
///   <item><description>
///     <b>.NET</b> left the original WHERE body unparenthesised, emitting
///     <c>WHERE (filters) AND a = 1 OR b = 2</c>. AND binds tighter than OR, so that parses as
///     <c>((filters) AND a = 1) OR b = 2</c> and admits every row matching <c>b</c> — the prior implementation's
///     fail-open, which .NET's own test had <i>pinned</i> as expected.
///   </description></item>
///   <item><description>
///     <b>TypeScript</b> took the WHERE body to the end of the statement, pulling trailing
///     clauses inside the added parentheses and emitting
///     <c>WHERE (f) AND (status = 'active' ORDER BY a)</c> — rejected outright as a syntax error
///     by both Postgres and MySQL.
///   </description></item>
/// </list>
/// <para>
/// Neither was a dialect bug. Both were found only because parity was asserted across SDKs on a
/// shared corpus.
/// </para>
/// <para>
/// There are two corpora here, and both must agree across SDKs: <see cref="ParityCorpus"/>
/// fixes the emitted SQL text, and <see cref="UnpushableParityCorpus"/> fixes how many filters
/// each SDK reports as unpushable. The second exists because <c>like</c>/<c>notLike</c> are
/// <i>declined</i> on the profiles whose collation could make <c>LIKE</c> case-insensitive, and
/// a decline is only correct if it is also reported — text parity alone cannot tell "not pushed,
/// and the post pass is carrying it" apart from "silently dropped".
/// </para>
/// </remarks>
public class SqlDialectParityTests
{
    /// <summary>The policy each corpus row names, built identically in all three SDKs.</summary>
    private static EffectivePolicy PolicyFor(string spec)
    {
        RowFilter[]? rowFilters = null;
        int? maxResults = null;
        FieldRules? fieldRules = null;

        static RowFilter[] Eq(string field, object? value)
            => [new(field, FilterOperator.Equals, Value: value)];

        switch (spec)
        {
            case "us_filter":
                rowFilters = Eq("region", "us-east");
                break;
            case "limit10":
                maxResults = 10;
                break;
            case "us_filter_limit10":
                rowFilters = Eq("region", "us-east");
                maxResults = 10;
                break;
            case "fields":
                fieldRules = new FieldRules(
                    AllowedFields: ["id", "region"], HiddenFields: ["ssn"]);
                break;
            case "not_deleted":
                rowFilters = [new("status", FilterOperator.NotEquals, Value: "deleted")];
                break;
            case "in_regions":
                rowFilters = [new("region", FilterOperator.In, Values: ["us-east", "us-west"])];
                break;
            case "notin_regions":
                rowFilters = [new("region", FilterOperator.NotIn, Values: ["eu-west"])];
                break;
            case "between":
                rowFilters = [new("age", FilterOperator.Between, Values: [18, 65])];
                break;
            case "isnull":
                rowFilters = [new("deleted_at", FilterOperator.IsNull)];
                break;
            case "like":
                rowFilters = [new("region", FilterOperator.Like, Value: "us-%")];
                break;
            case "notlike":
                rowFilters = [new("region", FilterOperator.NotLike, Value: "us-%")];
                break;
            case "backslash":
                rowFilters = Eq("region", @"us\' OR 1=1 --");
                break;
            case "quote_in_field_backtick":
                rowFilters = Eq("reg`ion", "x");
                break;
            case "quote_in_field_dquote":
                rowFilters = Eq(@"reg""ion", "x");
                break;
            case "quote_in_field_bracket":
                rowFilters = Eq("reg[ion", "x");
                break;
            case "apostrophe":
                rowFilters = Eq("region", "it's");
                break;
            case "wrapped_field":
                rowFilters = Eq("[region]", "x");
                break;
            case "dotted_field":
                rowFilters = Eq("patients.region", "x");
                break;
            case "contains":
                rowFilters = [new("region", FilterOperator.Contains, Value: "us")];
                break;
            default:
                throw new ArgumentException($"unknown policy spec: {spec}", nameof(spec));
        }

        return new EffectivePolicy(
            Version: "1.0",
            UserId: "u",
            TenantId: "t",
            SourceConnectionId: "db:parity:main",
            ResolvedAt: DateTimeOffset.UtcNow,
            ExpiresAt: DateTimeOffset.UtcNow.AddHours(1),
            SourceProfiles: ["parity"],
            Permissions: new PolicyPermissions(CanQuery: true),
            ObjectRules: fieldRules is not null || rowFilters is not null
                ? new ObjectRules(FieldRules: fieldRules, RowFilters: rowFilters)
                : null,
            Limits: maxResults is not null ? new PolicyLimits(MaxResults: maxResults) : null);
    }

    /// <summary>
    /// The dialect a corpus row names. An unrecognized name maps to an out-of-range member,
    /// which is the decline path rule 2 requires.
    /// </summary>
    private static SqlDialect Dialect(string name) => name switch
    {
        "ansi" => SqlDialect.Ansi,
        "postgres" => SqlDialect.Postgres,
        "trino" => SqlDialect.Trino,
        "mysql" => SqlDialect.MySql,
        "sqlserver" => SqlDialect.SqlServer,
        _ => (SqlDialect)99
    };

    /// <summary>
    /// (case id, query, policy spec, dialect, the SQL all three SDKs must emit).
    /// </summary>
    public static TheoryData<string, string, string, string, string> ParityCorpus()
    {
        var data = new TheoryData<string, string, string, string, string>();
        data.Add(@"filter-ansi", @"SELECT id, region FROM patients", @"us_filter", @"ansi", @"SELECT id, region FROM patients WHERE ""region"" = 'us-east'");
        data.Add(@"filter-postgres", @"SELECT id, region FROM patients", @"us_filter", @"postgres", @"SELECT id, region FROM patients WHERE ""region"" = 'us-east'");
        data.Add(@"filter-trino", @"SELECT id, region FROM patients", @"us_filter", @"trino", @"SELECT id, region FROM patients WHERE ""region"" = 'us-east'");
        data.Add(@"filter-mysql", @"SELECT id, region FROM patients", @"us_filter", @"mysql", @"SELECT id, region FROM patients WHERE `region` = 'us-east'");
        data.Add(@"filter-sqlserver", @"SELECT id, region FROM patients", @"us_filter", @"sqlserver", @"SELECT id, region FROM patients WHERE [region] = 'us-east'");
        data.Add(@"filter-unknown", @"SELECT id, region FROM patients", @"us_filter", @"oracle", @"SELECT id, region FROM patients");
        data.Add(@"limit-ansi", @"SELECT a FROM t", @"limit10", @"ansi", @"SELECT a FROM t LIMIT 10");
        data.Add(@"limit-mysql", @"SELECT a FROM t", @"limit10", @"mysql", @"SELECT a FROM t LIMIT 10");
        data.Add(@"limit-sqlserver", @"SELECT a FROM t", @"limit10", @"sqlserver", @"SELECT TOP 10 a FROM t");
        data.Add(@"limit-clamp-ansi", @"SELECT a FROM t LIMIT 900", @"limit10", @"ansi", @"SELECT a FROM t LIMIT 10");
        data.Add(@"limit-clamp-mysql", @"SELECT a FROM t LIMIT 900", @"limit10", @"mysql", @"SELECT a FROM t LIMIT 10");
        data.Add(@"both-ansi", @"SELECT a FROM t", @"us_filter_limit10", @"ansi", @"SELECT a FROM t WHERE ""region"" = 'us-east' LIMIT 10");
        data.Add(@"both-mysql", @"SELECT a FROM t", @"us_filter_limit10", @"mysql", @"SELECT a FROM t WHERE `region` = 'us-east' LIMIT 10");
        data.Add(@"both-sqlserver", @"SELECT a FROM t", @"us_filter_limit10", @"sqlserver", @"SELECT TOP 10 a FROM t WHERE [region] = 'us-east'");
        data.Add(@"star-ansi", @"SELECT * FROM patients", @"fields", @"ansi", @"SELECT ""id"", ""region"" FROM patients");
        data.Add(@"star-mysql", @"SELECT * FROM patients", @"fields", @"mysql", @"SELECT `id`, `region` FROM patients");
        data.Add(@"star-sqlserver", @"SELECT * FROM patients", @"fields", @"sqlserver", @"SELECT [id], [region] FROM patients");
        data.Add(@"existing-where-ansi", @"SELECT a FROM t WHERE x = 1 OR y = 2", @"us_filter", @"ansi", @"SELECT a FROM t WHERE (""region"" = 'us-east') AND (x = 1 OR y = 2)");
        data.Add(@"existing-where-mysql", @"SELECT a FROM t WHERE x = 1 OR y = 2", @"us_filter", @"mysql", @"SELECT a FROM t WHERE (`region` = 'us-east') AND (x = 1 OR y = 2)");
        data.Add(@"existing-where-orderby-mysql", @"SELECT a FROM t WHERE status = 'active' ORDER BY a", @"us_filter_limit10", @"mysql", @"SELECT a FROM t WHERE (`region` = 'us-east') AND (status = 'active') ORDER BY a LIMIT 10");
        data.Add(@"distinct-sqlserver", @"SELECT DISTINCT a FROM t", @"limit10", @"sqlserver", @"SELECT DISTINCT TOP 10 a FROM t");
        data.Add(@"all-sqlserver", @"SELECT ALL a FROM t", @"limit10", @"sqlserver", @"SELECT ALL TOP 10 a FROM t");
        data.Add(@"existing-top-sqlserver", @"SELECT TOP 50 a FROM t", @"limit10", @"sqlserver", @"SELECT TOP 10 a FROM t");
        data.Add(@"existing-top-paren-sqlserver", @"SELECT TOP (50) a FROM t", @"limit10", @"sqlserver", @"SELECT TOP 10 a FROM t");
        data.Add(@"existing-top-smaller-sqlserver", @"SELECT TOP 3 a FROM t", @"limit10", @"sqlserver", @"SELECT TOP 3 a FROM t");
        data.Add(@"top-percent-sqlserver", @"SELECT TOP 5 PERCENT a FROM t", @"limit10", @"sqlserver", @"SELECT TOP 5 PERCENT a FROM t");
        data.Add(@"top-withties-sqlserver", @"SELECT TOP 5 WITH TIES a FROM t ORDER BY a", @"limit10", @"sqlserver", @"SELECT TOP 5 WITH TIES a FROM t ORDER BY a");
        data.Add(@"union-sqlserver", @"SELECT a FROM t UNION SELECT b FROM u", @"limit10", @"sqlserver", @"SELECT a FROM t UNION SELECT b FROM u");
        data.Add(@"offset-sqlserver", @"SELECT a FROM t ORDER BY a OFFSET 5 ROWS", @"limit10", @"sqlserver", @"SELECT a FROM t ORDER BY a OFFSET 5 ROWS");
        data.Add(@"limitkw-sqlserver", @"SELECT a FROM t LIMIT 50", @"limit10", @"sqlserver", @"SELECT a FROM t LIMIT 50");
        data.Add(@"nonselect-sqlserver", @"DELETE FROM t", @"limit10", @"sqlserver", @"DELETE FROM t");
        data.Add(@"groupby-mysql", @"SELECT region, count(*) FROM t GROUP BY region", @"us_filter", @"mysql", @"SELECT region, count(*) FROM t WHERE `region` = 'us-east' GROUP BY region");
        data.Add(@"subquery-mysql", @"SELECT a FROM t WHERE id IN (SELECT id FROM u WHERE x = 1)", @"us_filter", @"mysql", @"SELECT a FROM t WHERE (`region` = 'us-east') AND (id IN (SELECT id FROM u WHERE x = 1))");
        data.Add(@"notequals-mysql", @"SELECT a FROM t", @"not_deleted", @"mysql", @"SELECT a FROM t WHERE (`status` <> 'deleted' OR `status` IS NULL)");
        data.Add(@"notequals-sqlserver", @"SELECT a FROM t", @"not_deleted", @"sqlserver", @"SELECT a FROM t WHERE ([status] <> 'deleted' OR [status] IS NULL)");
        data.Add(@"in-mysql", @"SELECT a FROM t", @"in_regions", @"mysql", @"SELECT a FROM t WHERE `region` IN ('us-east', 'us-west')");
        data.Add(@"notin-mysql", @"SELECT a FROM t", @"notin_regions", @"mysql", @"SELECT a FROM t WHERE (`region` NOT IN ('eu-west') OR `region` IS NULL)");
        data.Add(@"between-mysql", @"SELECT a FROM t", @"between", @"mysql", @"SELECT a FROM t WHERE `age` BETWEEN 18 AND 65");
        data.Add(@"isnull-mysql", @"SELECT a FROM t", @"isnull", @"mysql", @"SELECT a FROM t WHERE `deleted_at` IS NULL");
        // like/notLike, every profile x both operators. The emitted text is the whole point
        // of the case: `postgres`/`trino` push a real LIKE, and `mysql`, `sqlserver` and
        // `ansi` emit the query untouched because their collation could make the comparison
        // case-insensitive, which would select different rows than the case-sensitive
        // post-execution pass (spec section 4). A declined filter is reported unpushable
        // and enforced post-fetch.
        data.Add(@"like-postgres", @"SELECT a FROM t", @"like", @"postgres", @"SELECT a FROM t WHERE ""region"" LIKE 'us-%'");
        data.Add(@"like-trino", @"SELECT a FROM t", @"like", @"trino", @"SELECT a FROM t WHERE ""region"" LIKE 'us-%'");
        data.Add(@"like-mysql", @"SELECT a FROM t", @"like", @"mysql", @"SELECT a FROM t");
        data.Add(@"like-sqlserver", @"SELECT a FROM t", @"like", @"sqlserver", @"SELECT a FROM t");
        data.Add(@"like-ansi", @"SELECT a FROM t", @"like", @"ansi", @"SELECT a FROM t");
        data.Add(@"notlike-postgres", @"SELECT a FROM t", @"notlike", @"postgres", @"SELECT a FROM t WHERE (""region"" NOT LIKE 'us-%' OR ""region"" IS NULL)");
        data.Add(@"notlike-trino", @"SELECT a FROM t", @"notlike", @"trino", @"SELECT a FROM t WHERE (""region"" NOT LIKE 'us-%' OR ""region"" IS NULL)");
        data.Add(@"notlike-mysql", @"SELECT a FROM t", @"notlike", @"mysql", @"SELECT a FROM t");
        data.Add(@"notlike-sqlserver", @"SELECT a FROM t", @"notlike", @"sqlserver", @"SELECT a FROM t");
        data.Add(@"notlike-ansi", @"SELECT a FROM t", @"notlike", @"ansi", @"SELECT a FROM t");
        data.Add(@"backslash-mysql", @"SELECT a FROM t", @"backslash", @"mysql", @"SELECT a FROM t");
        data.Add(@"backslash-ansi", @"SELECT a FROM t", @"backslash", @"ansi", @"SELECT a FROM t");
        data.Add(@"backslash-sqlserver", @"SELECT a FROM t", @"backslash", @"sqlserver", @"SELECT a FROM t");
        data.Add(@"quotefield-mysql", @"SELECT a FROM t", @"quote_in_field_backtick", @"mysql", @"SELECT a FROM t");
        data.Add(@"quotefield-ansi", @"SELECT a FROM t", @"quote_in_field_dquote", @"ansi", @"SELECT a FROM t");
        data.Add(@"quotefield-sqlserver", @"SELECT a FROM t", @"quote_in_field_bracket", @"sqlserver", @"SELECT a FROM t");
        data.Add(@"apostrophe-mysql", @"SELECT a FROM t", @"apostrophe", @"mysql", @"SELECT a FROM t WHERE `region` = 'it''s'");
        data.Add(@"wrapped-field-mysql", @"SELECT a FROM t", @"wrapped_field", @"mysql", @"SELECT a FROM t WHERE `region` = 'x'");
        data.Add(@"wrapped-field-sqlserver", @"SELECT a FROM t", @"wrapped_field", @"sqlserver", @"SELECT a FROM t WHERE [region] = 'x'");
        data.Add(@"dotted-field-mysql", @"SELECT a FROM t", @"dotted_field", @"mysql", @"SELECT a FROM t WHERE `region` = 'x'");
        data.Add(@"unpushable-op-mysql", @"SELECT a FROM t", @"contains", @"mysql", @"SELECT a FROM t");
        return data;
    }

    [Theory]
    [MemberData(nameof(ParityCorpus))]
    public void TheEmittedSql_MatchesTheCrossSdkCorpus(
        string caseId, string query, string spec, string dialect, string expected)
    {
        var rewriter = new SqlQueryRewriter();

        rewriter.RewriteQuery(query, PolicyFor(spec), Dialect(dialect))
            .Should().Be(expected, $"case {caseId} must match the cross-SDK corpus");
    }

    /// <summary>
    /// (case id, policy spec, dialect, how many filters all three SDKs must report as
    /// unpushable).
    /// </summary>
    /// <remarks>
    /// The emitted text and this report are two halves of one contract: a filter that
    /// vanishes from the SQL without being reported would be a silent loss of the
    /// optimization at best, and at worst an integrator's "fully pushed down" assertion
    /// passing while the database returns unfiltered rows. Duplicated verbatim in all three
    /// SDKs alongside <see cref="ParityCorpus"/>.
    /// </remarks>
    public static TheoryData<string, string, string, int> UnpushableParityCorpus()
    {
        var data = new TheoryData<string, string, string, int>();
        // like/notLike: pushed on the case-sensitive profiles, reported on the others.
        data.Add(@"like-postgres", @"like", @"postgres", 0);
        data.Add(@"like-trino", @"like", @"trino", 0);
        data.Add(@"like-mysql", @"like", @"mysql", 1);
        data.Add(@"like-sqlserver", @"like", @"sqlserver", 1);
        data.Add(@"like-ansi", @"like", @"ansi", 1);
        data.Add(@"notlike-postgres", @"notlike", @"postgres", 0);
        data.Add(@"notlike-trino", @"notlike", @"trino", 0);
        data.Add(@"notlike-mysql", @"notlike", @"mysql", 1);
        data.Add(@"notlike-sqlserver", @"notlike", @"sqlserver", 1);
        data.Add(@"notlike-ansi", @"notlike", @"ansi", 1);
        // The decline paths that were already dialect-independent, held here so the two
        // kinds of decline are asserted by the same mechanism.
        data.Add(@"contains-mysql", @"contains", @"mysql", 1);
        data.Add(@"contains-postgres", @"contains", @"postgres", 1);
        data.Add(@"backslash-postgres", @"backslash", @"postgres", 1);
        data.Add(@"backslash-mysql", @"backslash", @"mysql", 1);
        data.Add(@"equals-postgres", @"us_filter", @"postgres", 0);
        data.Add(@"equals-mysql", @"us_filter", @"mysql", 0);
        // An unrecognized dialect rewrites nothing, so every filter is reported.
        data.Add(@"like-unknown", @"like", @"oracle", 1);
        data.Add(@"equals-unknown", @"us_filter", @"oracle", 1);
        return data;
    }

    [Theory]
    [MemberData(nameof(UnpushableParityCorpus))]
    public void TheUnpushableReport_MatchesTheCrossSdkCorpus(
        string caseId, string spec, string dialect, int expectedCount)
    {
        var rewriter = new SqlQueryRewriter();

        rewriter.UnpushableFilters(PolicyFor(spec), Dialect(dialect))
            .Should().HaveCount(expectedCount, $"case {caseId} must match the cross-SDK corpus");
    }

    [Fact]
    public void TheCorpus_CoversEveryProfile_AndBothDeclinePaths()
    {
        // A guard on the corpus itself, so it cannot quietly stop covering a profile.
        var dialects = ParityCorpus().Select(row => (string)row[3]!).ToHashSet();

        dialects.Should().Contain(["ansi", "postgres", "trino", "mysql", "sqlserver"]);
        // The unrecognized-dialect path is part of the contract and must stay covered.
        dialects.Should().Contain("oracle");
    }

    [Fact]
    public void TheLikeGate_IsCoveredForEveryProfile_AndBothOperators()
    {
        // like/notLike are the one operator pair whose *pushability* depends on the
        // dialect, so the corpus must state an answer for all five profiles rather than
        // sampling one or two.
        string[] every = ["ansi", "postgres", "trino", "mysql", "sqlserver"];

        foreach (var spec in new[] { "like", "notlike" })
        {
            var emitted = ParityCorpus()
                .Where(row => (string)row[2]! == spec && (string)row[3]! != "oracle")
                .Select(row => (string)row[3]!)
                .ToHashSet();
            var reported = UnpushableParityCorpus()
                .Where(row => (string)row[1]! == spec && (string)row[2]! != "oracle")
                .Select(row => (string)row[2]!)
                .ToHashSet();

            emitted.Should().Contain(every, $"{spec} text must cover every profile");
            reported.Should().Contain(every, $"{spec} report must cover every profile");
        }
    }

    [Fact]
    public void EveryCaseId_IsUnique()
    {
        var ids = ParityCorpus().Select(row => (string)row[0]!).ToList();

        ids.Should().OnlyHaveUniqueItems();

        var unpushableIds = UnpushableParityCorpus().Select(row => (string)row[0]!).ToList();

        unpushableIds.Should().OnlyHaveUniqueItems();
    }
}
