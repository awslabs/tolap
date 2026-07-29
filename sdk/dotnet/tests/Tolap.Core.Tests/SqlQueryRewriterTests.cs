using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// Behavioural suite for <see cref="SqlQueryRewriter"/>.
/// </summary>
/// <remarks>
/// The first section ports the reference implementation's suite one-for-one onto TOLAP's
/// models, so the pushed-down behaviour is the behaviour that was already proven in
/// production. Later sections cover what the reference implementation did not: the seven
/// operators TOLAP adds, the three-valued-logic cases where naive SQL and the post-fetch pass
/// disagree, and the identifier/literal refusals that keep a policy value from escaping into
/// statement text.
/// </remarks>
public class SqlQueryRewriterTests
{
    private readonly SqlQueryRewriter _rewriter = new();

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private static EffectivePolicy Policy(
        string[]? allowedFields = null,
        string[]? hiddenFields = null,
        MaskingRule[]? maskedFields = null,
        RowFilter[]? rowFilters = null,
        int? maxResults = null,
        bool canQuery = true)
    {
        var hasFieldRules = allowedFields is not null || hiddenFields is not null || maskedFields is not null;

        return new EffectivePolicy(
            Version: "1.0",
            UserId: "u1",
            TenantId: "t1",
            SourceConnectionId: "db:pg:main",
            ResolvedAt: DateTimeOffset.UtcNow,
            ExpiresAt: DateTimeOffset.UtcNow.AddHours(1),
            SourceProfiles: new[] { "test" },
            Permissions: new PolicyPermissions(CanQuery: canQuery),
            ObjectRules: hasFieldRules || rowFilters is not null
                ? new ObjectRules(
                    FieldRules: hasFieldRules
                        ? new FieldRules(
                            AllowedFields: allowedFields,
                            HiddenFields: hiddenFields,
                            MaskedFields: maskedFields)
                        : null,
                    RowFilters: rowFilters)
                : null,
            Limits: maxResults is not null ? new PolicyLimits(MaxResults: maxResults) : null);
    }

    private static RowFilter Eq(string field, object? value)
        => new(field, FilterOperator.Equals, Value: value);

    // =======================================================================
    // Ported reference suite
    // =======================================================================

    // -- 1: a row filter becomes a WHERE clause --

    [Fact]
    public void RewriteQuery_AddsWhereClause_ForRowFilter()
    {
        var result = _rewriter.RewriteQuery(
            "SELECT id, name FROM patients",
            Policy(rowFilters: new[] { Eq("region", "US") }));

        result.Should().Contain("WHERE");
        result.Should().Contain("\"region\"");
        result.Should().Contain("'US'");
    }

    // -- 2: hidden fields leave the select list --

    [Fact]
    public void RewriteQuery_RemovesHiddenFields_FromSelect()
    {
        var result = _rewriter.RewriteQuery(
            "SELECT id, name, ssn, date_of_birth FROM patients",
            Policy(hiddenFields: new[] { "ssn", "date_of_birth" }));

        result.Should().NotContainEquivalentOf("ssn");
        result.Should().NotContainEquivalentOf("date_of_birth");
        result.Should().Contain("id");
        result.Should().Contain("name");
    }

    // -- 3: masked fields must SURVIVE the rewrite --
    //
    // The single easiest behaviour to get wrong. Masking has no SQL form here, so a masked
    // field removed from the projection is not masked in the result, it is absent from it --
    // and the post-fetch masking pass then has nothing to act on. The field must reach the
    // database so that ApplyFieldMasking can mask the value it returns.

    [Fact]
    public void RewriteQuery_DoesNotRemoveMaskedFields_FromSelect()
    {
        var result = _rewriter.RewriteQuery(
            "SELECT id, name, email, phone FROM patients",
            Policy(maskedFields: new[]
            {
                new MaskingRule("email", MaskType.Partial),
                new MaskingRule("phone", MaskType.Full)
            }));

        result.Should().Contain("email");
        result.Should().Contain("phone");
        result.Should().Contain("id");
        result.Should().Contain("name");
    }

    [Fact]
    public void RewriteQuery_KeepsMaskedField_EvenWhenItIsAlsoAllowed()
    {
        // The allow-list path is a separate branch from the untouched-list path above, and
        // must not drop a masked field either.
        var result = _rewriter.RewriteQuery(
            "SELECT id, email, phone FROM patients",
            Policy(
                allowedFields: new[] { "id", "email", "phone" },
                maskedFields: new[] { new MaskingRule("email", MaskType.Redact) }));

        result.Should().Contain("email");
    }

    [Fact]
    public void RewriteQuery_SelectStarExpansion_KeepsMaskedField()
    {
        var result = _rewriter.RewriteQuery(
            "SELECT * FROM patients",
            Policy(
                allowedFields: new[] { "id", "email" },
                maskedFields: new[] { new MaskingRule("email", MaskType.Hash) }));

        result.Should().Contain("\"email\"");
    }

    [Fact]
    public void RewriteQuery_HiddenBeatsMasked_WhenFieldIsBoth()
    {
        // Spec section 4 orders hidden-field removal before masking so a field that is both
        // is removed rather than returned masked. The rewriter must agree.
        var result = _rewriter.RewriteQuery(
            "SELECT id, ssn FROM patients",
            Policy(
                hiddenFields: new[] { "ssn" },
                maskedFields: new[] { new MaskingRule("ssn", MaskType.Partial) }));

        result.Should().NotContainEquivalentOf("ssn");
    }

    // -- 4: SELECT * expands to allowed minus hidden --

    [Fact]
    public void RewriteQuery_HandlesSelectStar_ByExpandingToExplicitFieldsMinusHidden()
    {
        var result = _rewriter.RewriteQuery(
            "SELECT * FROM patients",
            Policy(
                allowedFields: new[] { "id", "name", "ssn", "email" },
                hiddenFields: new[] { "ssn" }));

        result.Should().NotContain("*");
        result.Should().Contain("\"id\"");
        result.Should().Contain("\"name\"");
        result.Should().Contain("\"email\"");
        result.Should().NotContain("\"ssn\"");
    }

    // -- 5: an unrestricted policy leaves the query byte-identical --

    [Fact]
    public void RewriteQuery_WithNoRestrictions_ReturnsOriginalQuery()
    {
        const string query = "SELECT id, name, email FROM patients";

        _rewriter.RewriteQuery(query, Policy()).Should().Be(query);
    }

    // -- 6: joins --

    [Fact]
    public void RewriteQuery_HandlesMultipleTables_FiltersFieldsCorrectly()
    {
        var result = _rewriter.RewriteQuery(
            "SELECT p.id, p.name, p.ssn, d.diagnosis FROM patients p JOIN diagnoses d ON p.id = d.patient_id",
            Policy(hiddenFields: new[] { "ssn" }));

        result.Should().NotContain("p.ssn");
        result.Should().Contain("p.id");
        result.Should().Contain("p.name");
        result.Should().Contain("d.diagnosis");
    }

    // -- 7: an existing WHERE survives --

    [Fact]
    public void RewriteQuery_PreservesExistingWhereConditions()
    {
        var result = _rewriter.RewriteQuery(
            "SELECT id, name FROM patients WHERE status = 'active'",
            Policy(rowFilters: new[] { Eq("region", "US") }));

        result.Should().Contain("\"region\"");
        result.Should().Contain("'US'");
        result.Should().Contain("status = 'active'");
        result.Should().Contain("AND");
    }

    [Fact]
    public void RewriteQuery_ParenthesizesBothSides_SoAnExistingOrCannotWidenThem()
    {
        // BOTH sides must be grouped. Parenthesising only the injected half emits
        // "WHERE (region = 'US') AND a = 1 OR b = 2", which binds as
        // "((region = 'US') AND a = 1) OR b = 2" -- every row matching b comes back
        // regardless of region, and the security filter is bypassed entirely. This is the
        // known fail-open, and .NET reproduced it (the assertion here used to pin the
        // unparenthesised original) while Python and TypeScript did not.
        var result = _rewriter.RewriteQuery(
            "SELECT id FROM patients WHERE a = 1 OR b = 2",
            Policy(rowFilters: new[] { Eq("region", "US") }));

        result.Should().Be(
            "SELECT id FROM patients WHERE (\"region\" = 'US') AND (a = 1 OR b = 2)");
    }

    // -- null/empty input --

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void RewriteQuery_ReturnsOriginal_ForNullOrEmptyInput(string? query)
    {
        var result = _rewriter.RewriteQuery(query!, Policy(rowFilters: new[] { Eq("col", "val") }));

        result.Should().Be(query);
    }

    // -- LIMIT --

    [Fact]
    public void RewriteQuery_EnforcesMaxResultsLimit_WhenNoExistingLimit()
    {
        _rewriter.RewriteQuery("SELECT id, name FROM patients", Policy(maxResults: 500))
            .Should().Contain("LIMIT 500");
    }

    [Fact]
    public void RewriteQuery_EnforcesMaxResultsLimit_UsesMinimumWhenExistingLimitIsLarger()
    {
        var result = _rewriter.RewriteQuery(
            "SELECT id, name FROM patients LIMIT 10000", Policy(maxResults: 500));

        result.Should().Contain("LIMIT 500");
        result.Should().NotContain("LIMIT 10000");
    }

    [Fact]
    public void RewriteQuery_PreservesExistingLimit_WhenSmallerThanMaxResults()
    {
        _rewriter.RewriteQuery("SELECT id, name FROM patients LIMIT 100", Policy(maxResults: 500))
            .Should().Contain("LIMIT 100");
    }

    // -- ValidateQuery --

    [Fact]
    public void ValidateQuery_ReturnsFalse_WhenQueryReferencesHiddenField()
    {
        _rewriter.ValidateQuery("SELECT id, ssn FROM patients", Policy(hiddenFields: new[] { "ssn" }))
            .Should().BeFalse();
    }

    [Fact]
    public void ValidateQuery_ReturnsTrue_WhenQueryReferencesOnlyAllowedFields()
    {
        _rewriter.ValidateQuery(
            "SELECT id, name FROM patients",
            Policy(allowedFields: new[] { "id", "name", "email" }))
            .Should().BeTrue();
    }

    [Fact]
    public void ValidateQuery_ReturnsFalse_ForNullOrEmptyQuery()
    {
        var policy = Policy();

        _rewriter.ValidateQuery(null!, policy).Should().BeFalse();
        _rewriter.ValidateQuery("", policy).Should().BeFalse();
        _rewriter.ValidateQuery("   ", policy).Should().BeFalse();
    }

    // -- ExtractTableName --

    [Theory]
    [InlineData("SELECT * FROM patients", "patients")]
    [InlineData("SELECT * FROM public.patients", "patients")]
    [InlineData("SELECT * FROM \"my_schema.my_table\"", "my_table")]
    [InlineData("SELECT * FROM \"public\".\"patients\"", "patients")]
    public void ExtractTableName_ReturnsCorrectTableName(string query, string expected)
    {
        _rewriter.ExtractTableName(query).Should().Be(expected);
    }

    [Fact]
    public void ExtractTableName_ReturnsNull_WhenNoFromClause()
    {
        _rewriter.ExtractTableName("SHOW TABLES").Should().BeNull();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ExtractTableName_ReturnsNull_ForNullOrEmptyQuery(string? query)
    {
        _rewriter.ExtractTableName(query!).Should().BeNull();
    }

    // -- BuildWhereClause --

    [Fact]
    public void BuildWhereClause_GeneratesCorrectEqualsCondition()
    {
        var clause = _rewriter.BuildWhereClause(new[] { Eq("department", "cardiology") });

        clause.Should().Contain("\"department\"");
        clause.Should().Contain("'cardiology'");
    }

    [Fact]
    public void BuildWhereClause_CombinesMultipleFiltersWithAnd()
    {
        var clause = _rewriter.BuildWhereClause(new[] { Eq("region", "US"), Eq("active", "true") });

        clause.Should().Contain("AND");
        clause.Should().Contain("\"region\"");
        clause.Should().Contain("\"active\"");
    }

    [Fact]
    public void BuildWhereClause_ReturnsEmptyString_ForNoFilters()
    {
        _rewriter.BuildWhereClause(Array.Empty<RowFilter>()).Should().BeEmpty();
    }

    // -- IN --

    [Fact]
    public void RewriteQuery_HandlesInOperatorRowFilter()
    {
        var result = _rewriter.RewriteQuery(
            "SELECT id, name FROM patients",
            Policy(rowFilters: new[]
            {
                new RowFilter("region", FilterOperator.In, Values: new object[] { "US", "CA", "UK" })
            }));

        result.Should().Contain("IN");
        result.Should().Contain("'US'");
        result.Should().Contain("'CA'");
        result.Should().Contain("'UK'");
    }

    // -- SELECT * with hidden but no allowed --

    [Fact]
    public void RewriteQuery_SelectStar_WithHiddenFieldsOnly_LeavesStarForThePostFetchPass()
    {
        // Without an allowedFields list the table's column set is unknown, so '*' cannot be
        // expanded to "everything except ssn". StripHiddenFields removes ssn after the fetch;
        // the disclosure outcome is identical, only the transfer cost differs.
        var result = _rewriter.RewriteQuery(
            "SELECT * FROM patients", Policy(hiddenFields: new[] { "ssn" }));

        result.Should().Contain("SELECT");
        result.Should().Contain("FROM patients");
        result.Should().Contain("*");
    }

    // -- WHERE placement --

    [Fact]
    public void RewriteQuery_InsertsWhereBeforeOrderBy_WhenNoExistingWhere()
    {
        var result = _rewriter.RewriteQuery(
            "SELECT id, name FROM patients ORDER BY name",
            Policy(rowFilters: new[] { Eq("active", "true") }));

        result.IndexOf("WHERE", StringComparison.OrdinalIgnoreCase)
            .Should().BeLessThan(result.IndexOf("ORDER BY", StringComparison.OrdinalIgnoreCase));
    }

    // -- allowedFields narrows an explicit select list --

    [Fact]
    public void RewriteQuery_AllowedFieldsRestrict_ExplicitSelectFields()
    {
        var result = _rewriter.RewriteQuery(
            "SELECT id, name, email, phone FROM patients",
            Policy(allowedFields: new[] { "id", "name" }));

        result.Should().Contain("id");
        result.Should().Contain("name");
        result.Should().NotContain("email");
        result.Should().NotContain("phone");
    }

    // =======================================================================
    // WHERE placement, beyond the ported suite
    // =======================================================================

    [Theory]
    [InlineData("SELECT id FROM t GROUP BY id", "GROUP BY")]
    [InlineData("SELECT id FROM t HAVING count(*) > 1", "HAVING")]
    [InlineData("SELECT id FROM t ORDER BY id", "ORDER BY")]
    [InlineData("SELECT id FROM t LIMIT 5", "LIMIT")]
    [InlineData("SELECT id FROM t OFFSET 5", "OFFSET")]
    [InlineData("SELECT id FROM t WINDOW w AS (PARTITION BY id)", "WINDOW")]
    public void RewriteQuery_InsertsWhereBefore_EachTrailingClause(string query, string clause)
    {
        var result = _rewriter.RewriteQuery(query, Policy(rowFilters: new[] { Eq("region", "US") }));

        result.IndexOf("WHERE", StringComparison.OrdinalIgnoreCase)
            .Should().BeLessThan(result.IndexOf(clause, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RewriteQuery_InsertsWhereBeforeTheEarliestTrailingClause_NotTheFirstPatternToMatch()
    {
        // GROUP BY precedes ORDER BY in the query but ORDER BY is the earlier pattern in a
        // naive scan order; taking the first pattern to match would emit
        // "GROUP BY region WHERE ... ORDER BY id", which does not parse.
        var result = _rewriter.RewriteQuery(
            "SELECT region, count(*) FROM patients GROUP BY region ORDER BY region",
            Policy(rowFilters: new[] { Eq("region", "US") }));

        result.Should().Be(
            "SELECT region, count(*) FROM patients WHERE \"region\" = 'US' "
            + "GROUP BY region ORDER BY region");
    }

    [Fact]
    public void RewriteQuery_InsertsWhereBeforeTrailingSemicolon()
    {
        var result = _rewriter.RewriteQuery(
            "SELECT id FROM patients;", Policy(rowFilters: new[] { Eq("region", "US") }));

        result.Should().Be("SELECT id FROM patients WHERE \"region\" = 'US';");
    }

    [Fact]
    public void RewriteQuery_TargetsTheOuterWhere_NotASubqueryWhere()
    {
        // The subquery's WHERE appears first in the text. Injecting there would filter the
        // subquery's rows and leave the outer result unrestricted.
        var result = _rewriter.RewriteQuery(
            "SELECT id FROM patients WHERE id IN (SELECT patient_id FROM encounters WHERE status = 'active')",
            Policy(rowFilters: new[] { Eq("region", "US") }));

        result.Should().Be(
            "SELECT id FROM patients WHERE (\"region\" = 'US') AND (id IN "
            + "(SELECT patient_id FROM encounters WHERE status = 'active'))");
    }

    [Fact]
    public void RewriteQuery_AddsWhere_WhenTheOnlyWhereIsInsideASubquery()
    {
        var result = _rewriter.RewriteQuery(
            "SELECT id FROM patients WHERE id IN (SELECT patient_id FROM encounters WHERE status = 'active') "
            + "AND 1 = 1",
            Policy(rowFilters: new[] { Eq("region", "US") }));

        // The outer WHERE is still the one rewritten.
        result.Should().StartWith("SELECT id FROM patients WHERE (\"region\" = 'US') AND (id IN");
    }

    [Fact]
    public void RewriteQuery_IgnoresTheWordWhereInsideAStringLiteral()
    {
        var result = _rewriter.RewriteQuery(
            "SELECT id, 'where do we go' AS note FROM patients",
            Policy(rowFilters: new[] { Eq("region", "US") }));

        result.Should().Be(
            "SELECT id, 'where do we go' AS note FROM patients WHERE \"region\" = 'US'");
    }

    [Fact]
    public void RewriteQuery_IgnoresTheWordLimitInsideAStringLiteral()
    {
        var result = _rewriter.RewriteQuery(
            "SELECT id, 'limit 5' AS note FROM patients", Policy(maxResults: 10));

        result.Should().Be("SELECT id, 'limit 5' AS note FROM patients LIMIT 10");
    }

    // =======================================================================
    // LIMIT, beyond the ported suite
    // =======================================================================

    [Fact]
    public void RewriteQuery_AppendsLimitBeforeTrailingSemicolon()
    {
        _rewriter.RewriteQuery("SELECT id FROM patients;", Policy(maxResults: 10))
            .Should().Be("SELECT id FROM patients LIMIT 10;");
    }

    [Fact]
    public void RewriteQuery_ClampsTheStatementsOwnLimit_NotASetOperandsLimit()
    {
        // Clamping the first LIMIT would change which rows the first operand contributes,
        // rather than how many rows the caller receives.
        var result = _rewriter.RewriteQuery(
            "SELECT id FROM a LIMIT 5 UNION SELECT id FROM b LIMIT 900", Policy(maxResults: 100));

        result.Should().Be("SELECT id FROM a LIMIT 5 UNION SELECT id FROM b LIMIT 100");
    }

    [Fact]
    public void RewriteQuery_IgnoresASubqueryLimit_WhenAddingTheStatementsOwn()
    {
        var result = _rewriter.RewriteQuery(
            "SELECT id FROM patients WHERE id IN (SELECT id FROM vip LIMIT 3)", Policy(maxResults: 50));

        result.Should().Be(
            "SELECT id FROM patients WHERE id IN (SELECT id FROM vip LIMIT 3) LIMIT 50");
    }

    [Fact]
    public void RewriteQuery_ClampsALimitTooLargeToParse()
    {
        // long.Parse would throw on this literal; a value beyond long is certainly larger
        // than any policy limit.
        var result = _rewriter.RewriteQuery(
            "SELECT id FROM patients LIMIT 999999999999999999999999", Policy(maxResults: 25));

        result.Should().Be("SELECT id FROM patients LIMIT 25");
    }

    [Fact]
    public void RewriteQuery_MaxResultsZero_EmitsLimitZero()
    {
        // maxResults 0 is a real deny-everything limit, not an absent one.
        _rewriter.RewriteQuery("SELECT id FROM patients", Policy(maxResults: 0))
            .Should().Be("SELECT id FROM patients LIMIT 0");
    }

    [Fact]
    public void RewriteQuery_NegativeMaxResults_LeavesTheQueryAlone()
    {
        // "LIMIT -1" is a syntax error in Postgres and means "no limit" in some engines;
        // neither is what a negative policy value should produce.
        const string query = "SELECT id FROM patients LIMIT 10";

        _rewriter.RewriteQuery(query, Policy(maxResults: -1)).Should().Be(query);
    }

    // =======================================================================
    // Select-list handling, beyond the ported suite
    // =======================================================================

    [Fact]
    public void RewriteQuery_DoesNotSplitAFunctionCallOnItsOwnCommas()
    {
        var result = _rewriter.RewriteQuery(
            "SELECT id, coalesce(a, b, c) AS x, ssn FROM patients",
            Policy(hiddenFields: new[] { "ssn" }));

        result.Should().Contain("coalesce(a, b, c) AS x");
        result.Should().NotContainEquivalentOf("ssn");
    }

    [Fact]
    public void RewriteQuery_MatchesAnAliasedFieldByItsUnderlyingName()
    {
        var result = _rewriter.RewriteQuery(
            "SELECT id, ssn AS social FROM patients", Policy(hiddenFields: new[] { "ssn" }));

        result.Should().NotContainEquivalentOf("ssn");
        result.Should().NotContain("social");
    }

    [Fact]
    public void RewriteQuery_ProjectsAConstant_WhenEveryFieldIsRemoved()
    {
        // An empty projection is not valid SQL, and the fetch must still happen so the
        // post-fetch pass sees the right number of rows. "SELECT 1" preserves both.
        var result = _rewriter.RewriteQuery(
            "SELECT ssn FROM patients", Policy(hiddenFields: new[] { "ssn" }));

        result.Should().Be("SELECT 1 FROM patients");
    }

    [Fact]
    public void RewriteQuery_SelectStar_ProjectsAConstant_WhenEveryAllowedFieldIsHidden()
    {
        var result = _rewriter.RewriteQuery(
            "SELECT * FROM patients",
            Policy(allowedFields: new[] { "ssn" }, hiddenFields: new[] { "ssn" }));

        result.Should().Be("SELECT 1 FROM patients");
    }

    [Fact]
    public void RewriteQuery_SelectStar_EmptyAllowedFields_ProjectsAConstant()
    {
        // Spec section 3: an empty allow-list denies every field, and must not be read as
        // "unrestricted".
        var result = _rewriter.RewriteQuery(
            "SELECT * FROM patients", Policy(allowedFields: Array.Empty<string>()));

        result.Should().Be("SELECT 1 FROM patients");
    }

    [Fact]
    public void RewriteQuery_EmptyAllowedFields_RemovesEveryExplicitField()
    {
        var result = _rewriter.RewriteQuery(
            "SELECT id, name FROM patients", Policy(allowedFields: Array.Empty<string>()));

        result.Should().Be("SELECT 1 FROM patients");
    }

    [Fact]
    public void RewriteQuery_SelectStar_NotExpanded_WhenAllowedFieldsContainsAWildcard()
    {
        // "patients.*" has no column list to expand to, and dropping it would project less
        // than the policy grants.
        var result = _rewriter.RewriteQuery(
            "SELECT * FROM patients", Policy(allowedFields: new[] { "patients.*" }));

        result.Should().Be("SELECT * FROM patients");
    }

    [Fact]
    public void RewriteQuery_SelectStar_ExpansionQualifiesAndDeduplicates()
    {
        var result = _rewriter.RewriteQuery(
            "SELECT * FROM patients",
            Policy(allowedFields: new[] { "patients.id", "id", "name" }));

        result.Should().Be("SELECT \"id\", \"name\" FROM patients");
    }

    [Fact]
    public void RewriteQuery_SelectStar_SkipsAnAllowedFieldThatIsNotAPlainIdentifier()
    {
        var result = _rewriter.RewriteQuery(
            "SELECT * FROM patients",
            Policy(allowedFields: new[] { "id", "not a column" }));

        result.Should().Be("SELECT \"id\" FROM patients");
    }

    [Fact]
    public void RewriteQuery_LeavesTheSelectListAlone_WhenNoFieldIsRemoved()
    {
        // Byte-identical, not merely equivalent: an unnecessary reflow of the projection
        // would break an integrator diffing generated SQL.
        const string query = "SELECT  id ,  name  FROM patients";

        _rewriter.RewriteQuery(query, Policy(hiddenFields: new[] { "ssn" })).Should().Be(query);
    }

    [Fact]
    public void RewriteQuery_LeavesTheQueryAlone_WhenTheSelectListCannotBeLocated()
    {
        const string query = "SHOW COLUMNS IN patients";

        _rewriter.RewriteQuery(query, Policy(hiddenFields: new[] { "ssn" })).Should().Be(query);
    }

    [Fact]
    public void RewriteQuery_LeavesTheQueryAlone_WhenThereIsNoFromClause()
    {
        const string query = "SELECT 1";

        _rewriter.RewriteQuery(query, Policy(hiddenFields: new[] { "ssn" })).Should().Be(query);
    }

    [Fact]
    public void RewriteQuery_LeavesTheQueryAlone_WhenTheSelectListIsEmpty()
    {
        const string query = "SELECT FROM patients";

        _rewriter.RewriteQuery(query, Policy(hiddenFields: new[] { "ssn" })).Should().Be(query);
    }

    [Fact]
    public void RewriteQuery_RemovesAQualifiedHiddenField_MatchedByItsBareName()
    {
        var result = _rewriter.RewriteQuery(
            "SELECT p.id, p.ssn FROM patients p", Policy(hiddenFields: new[] { "patients.ssn" }));

        result.Should().Be("SELECT p.id FROM patients p");
    }

    [Fact]
    public void RewriteQuery_AppliesEveryStageTogether()
    {
        var result = _rewriter.RewriteQuery(
            "SELECT id, name, ssn FROM patients WHERE status = 'active' ORDER BY name LIMIT 5000",
            Policy(
                hiddenFields: new[] { "ssn" },
                rowFilters: new[] { Eq("region", "us-east") },
                maxResults: 100));

        // ORDER BY stays OUTSIDE the parenthesised original: the WHERE body ends at the next
        // top-level clause, not at the end of the statement, or the trailing clauses would be
        // pulled inside the parentheses and the statement would not parse.
        result.Should().Be(
            "SELECT id, name FROM patients WHERE (\"region\" = 'us-east') AND (status = 'active') "
            + "ORDER BY name LIMIT 100");
    }

    // =======================================================================
    // The seven added operators, as SQL
    // =======================================================================

    [Fact]
    public void BuildWhereClause_GreaterThanOrEqual()
    {
        _rewriter.BuildWhereClause(new[] { new RowFilter("age", FilterOperator.GreaterThanOrEqual, 18) })
            .Should().Be("\"age\" >= 18");
    }

    [Fact]
    public void BuildWhereClause_LessThanOrEqual()
    {
        _rewriter.BuildWhereClause(new[] { new RowFilter("age", FilterOperator.LessThanOrEqual, 65) })
            .Should().Be("\"age\" <= 65");
    }

    [Fact]
    public void BuildWhereClause_GreaterThan()
    {
        _rewriter.BuildWhereClause(new[] { new RowFilter("age", FilterOperator.GreaterThan, 18) })
            .Should().Be("\"age\" > 18");
    }

    [Fact]
    public void BuildWhereClause_LessThan()
    {
        _rewriter.BuildWhereClause(new[] { new RowFilter("age", FilterOperator.LessThan, 65) })
            .Should().Be("\"age\" < 65");
    }

    [Fact]
    public void BuildWhereClause_Like()
    {
        _rewriter.BuildWhereClause(new[] { new RowFilter("region", FilterOperator.Like, "us-%") })
            .Should().Be("\"region\" LIKE 'us-%'");
    }

    [Fact]
    public void BuildWhereClause_NotLike()
    {
        // No IS NULL arm: SQL NOT LIKE and the post-fetch pass both drop a null-valued row.
        _rewriter.BuildWhereClause(new[] { new RowFilter("region", FilterOperator.NotLike, "eu-%") })
            .Should().Be("\"region\" NOT LIKE 'eu-%'");
    }

    [Fact]
    public void BuildWhereClause_IsNull()
    {
        _rewriter.BuildWhereClause(new[] { new RowFilter("deleted_at", FilterOperator.IsNull) })
            .Should().Be("\"deleted_at\" IS NULL");
    }

    [Fact]
    public void BuildWhereClause_IsNotNull()
    {
        _rewriter.BuildWhereClause(new[] { new RowFilter("region", FilterOperator.IsNotNull) })
            .Should().Be("\"region\" IS NOT NULL");
    }

    [Fact]
    public void BuildWhereClause_Between()
    {
        _rewriter.BuildWhereClause(new[]
        {
            new RowFilter("age", FilterOperator.Between, Values: new object[] { 18, 65 })
        }).Should().Be("\"age\" BETWEEN 18 AND 65");
    }

    [Fact]
    public void BuildWhereClause_Between_UsesOnlyTheFirstTwoBounds()
    {
        _rewriter.BuildWhereClause(new[]
        {
            new RowFilter("age", FilterOperator.Between, Values: new object[] { 18, 65, 99 })
        }).Should().Be("\"age\" BETWEEN 18 AND 65");
    }

    [Fact]
    public void BuildWhereClause_Between_DoesNotReorderAnInvertedRange()
    {
        // BETWEEN 65 AND 18 matches nothing, in SQL and post-fetch alike. Reordering it would
        // turn a policy author's typo into a wider grant than the policy states.
        _rewriter.BuildWhereClause(new[]
        {
            new RowFilter("age", FilterOperator.Between, Values: new object[] { 65, 18 })
        }).Should().Be("\"age\" BETWEEN 65 AND 18");
    }

    [Theory]
    [InlineData(null)]
    [InlineData(0)]
    [InlineData(1)]
    public void BuildWhereClause_Between_WithFewerThanTwoBounds_AdmitsNoRow(int? boundCount)
    {
        var values = boundCount is null
            ? null
            : Enumerable.Range(0, boundCount.Value).Select(i => (object)i).ToArray();

        _rewriter.BuildWhereClause(new[] { new RowFilter("age", FilterOperator.Between, Values: values) })
            .Should().Be("1 = 0");
    }

    [Fact]
    public void BuildWhereClause_Between_WithANullBound_AdmitsNoRow()
    {
        _rewriter.BuildWhereClause(new[]
        {
            new RowFilter("age", FilterOperator.Between, Values: new object?[] { null, 65 }!)
        }).Should().Be("1 = 0");
    }

    [Fact]
    public void BuildWhereClause_Between_WithAnUnrenderableBound_IsNotPushed()
    {
        _rewriter.BuildWhereClause(new[]
        {
            new RowFilter("age", FilterOperator.Between, Values: new object[] { 1, new Uri("https://x") })
        }).Should().BeEmpty();
    }

    // =======================================================================
    // Three-valued logic: the SQL condition must mean what the post-fetch pass means
    // =======================================================================

    [Fact]
    public void BuildWhereClause_NotEquals_AlsoAdmitsANullValuedRow()
    {
        // Post-fetch, a field present with a null value satisfies notEquals 'x' and the row is
        // kept. Plain SQL "col <> 'x'" evaluates to NULL for that row and drops it, so pushing
        // the filter down would remove rows the post-fetch pass keeps.
        _rewriter.BuildWhereClause(new[] { new RowFilter("region", FilterOperator.NotEquals, "eu") })
            .Should().Be("(\"region\" <> 'eu' OR \"region\" IS NULL)");
    }

    [Fact]
    public void BuildWhereClause_NotIn_AlsoAdmitsANullValuedRow()
    {
        _rewriter.BuildWhereClause(new[]
        {
            new RowFilter("region", FilterOperator.NotIn, Values: new object[] { "eu", "apac" })
        }).Should().Be("(\"region\" NOT IN ('eu', 'apac') OR \"region\" IS NULL)");
    }

    [Fact]
    public void BuildWhereClause_EqualsNull_BecomesIsNull()
    {
        // "col = NULL" is NULL for every row, so it would admit nothing; post-fetch, an
        // equals filter with a null value matches a null-valued field.
        _rewriter.BuildWhereClause(new[] { Eq("region", null) })
            .Should().Be("\"region\" IS NULL");
    }

    [Fact]
    public void BuildWhereClause_NotEqualsNull_BecomesIsNotNull()
    {
        _rewriter.BuildWhereClause(new[] { new RowFilter("region", FilterOperator.NotEquals, null) })
            .Should().Be("\"region\" IS NOT NULL");
    }

    [Theory]
    [InlineData(FilterOperator.GreaterThan)]
    [InlineData(FilterOperator.GreaterThanOrEqual)]
    [InlineData(FilterOperator.LessThan)]
    [InlineData(FilterOperator.LessThanOrEqual)]
    public void BuildWhereClause_OrderingAgainstNull_AdmitsNoRow(FilterOperator op)
    {
        // CompareNullable returns null for a null operand post-fetch, so no row passes.
        _rewriter.BuildWhereClause(new[] { new RowFilter("age", op, null) }).Should().Be("1 = 0");
    }

    [Theory]
    [InlineData(FilterOperator.Like)]
    [InlineData(FilterOperator.NotLike)]
    public void BuildWhereClause_LikeAgainstNullPattern_AdmitsNoRow(FilterOperator op)
    {
        _rewriter.BuildWhereClause(new[] { new RowFilter("region", op, null) }).Should().Be("1 = 0");
    }

    [Fact]
    public void BuildWhereClause_In_WithNullValues_AdmitsNoRow()
    {
        // Post-fetch, "if (rf.Values is null) return false" drops every row.
        _rewriter.BuildWhereClause(new[] { new RowFilter("region", FilterOperator.In) })
            .Should().Be("1 = 0");
    }

    [Fact]
    public void BuildWhereClause_NotIn_WithNullValues_AdmitsNoRow()
    {
        // Post-fetch, notIn with a null values array also returns false. Not "1 = 1".
        _rewriter.BuildWhereClause(new[] { new RowFilter("region", FilterOperator.NotIn) })
            .Should().Be("1 = 0");
    }

    [Fact]
    public void BuildWhereClause_In_WithEmptyValues_AdmitsNoRow()
    {
        _rewriter.BuildWhereClause(new[]
        {
            new RowFilter("region", FilterOperator.In, Values: Array.Empty<object>())
        }).Should().Be("1 = 0");
    }

    [Fact]
    public void BuildWhereClause_NotIn_WithEmptyValues_AdmitsEveryRow()
    {
        // Nothing is excluded, so every row qualifies -- and SQL "NOT IN ()" is a syntax error.
        _rewriter.BuildWhereClause(new[]
        {
            new RowFilter("region", FilterOperator.NotIn, Values: Array.Empty<object>())
        }).Should().Be("1 = 1");
    }

    [Fact]
    public void BuildWhereClause_In_WithANullEntry_IsNotPushed()
    {
        // SQL "NOT IN (NULL, 'x')" is never true, so it would drop rows the post-fetch pass
        // keeps. Declining leaves the post-fetch pass to enforce it.
        _rewriter.BuildWhereClause(new[]
        {
            new RowFilter("region", FilterOperator.In, Values: new object?[] { "us", null }!)
        }).Should().BeEmpty();
    }

    // =======================================================================
    // Operators with no portable SQL form
    // =======================================================================

    [Theory]
    [InlineData(FilterOperator.Contains)]
    [InlineData(FilterOperator.StartsWith)]
    [InlineData(FilterOperator.Matches)]
    public void BuildWhereClause_OperatorsWithNoPortableForm_AreNotPushed(FilterOperator op)
    {
        _rewriter.BuildWhereClause(new[] { new RowFilter("region", op, "us") }).Should().BeEmpty();
    }

    [Fact]
    public void BuildWhereClause_UnrecognizedOperator_IsNotPushed()
    {
        _rewriter.BuildWhereClause(new[] { new RowFilter("region", (FilterOperator)9999, "us") })
            .Should().BeEmpty();
    }

    [Fact]
    public void RewriteQuery_InjectsOnlyThePushableFilters()
    {
        var result = _rewriter.RewriteQuery(
            "SELECT id FROM patients",
            Policy(rowFilters: new[]
            {
                Eq("region", "us-east"),
                new RowFilter("notes", FilterOperator.Matches, "^public")
            }));

        result.Should().Be("SELECT id FROM patients WHERE \"region\" = 'us-east'");
    }

    [Fact]
    public void RewriteQuery_LeavesTheQueryAlone_WhenNoFilterIsPushable()
    {
        const string query = "SELECT id FROM patients";

        var result = _rewriter.RewriteQuery(
            query,
            Policy(rowFilters: new[] { new RowFilter("notes", FilterOperator.Matches, "^public") }));

        result.Should().Be(query);
    }

    [Fact]
    public void UnpushableFilters_NamesTheFiltersLeftToThePostFetchPass()
    {
        var policy = Policy(rowFilters: new[]
        {
            Eq("region", "us-east"),
            new RowFilter("notes", FilterOperator.Matches, "^public"),
            new RowFilter("code", FilterOperator.Contains, "x")
        });

        var unpushable = _rewriter.UnpushableFilters(policy);

        unpushable.Select(f => f.Field).Should().BeEquivalentTo(new[] { "notes", "code" });
    }

    [Fact]
    public void UnpushableFilters_IsEmpty_WhenEveryFilterIsPushed()
    {
        var policy = Policy(rowFilters: new[] { Eq("region", "us-east") });

        _rewriter.UnpushableFilters(policy).Should().BeEmpty();
    }

    [Fact]
    public void UnpushableFilters_IsEmpty_ForAPolicyWithNoFilters()
    {
        _rewriter.UnpushableFilters(Policy()).Should().BeEmpty();
        _rewriter.UnpushableFilters(Policy(rowFilters: Array.Empty<RowFilter>())).Should().BeEmpty();
    }

    // =======================================================================
    // Injection resistance
    // =======================================================================

    [Fact]
    public void BuildWhereClause_DoublesASingleQuoteInAValue()
    {
        var clause = _rewriter.BuildWhereClause(new[] { Eq("name", "O'Brien") });

        clause.Should().Be("\"name\" = 'O''Brien'");
    }

    [Fact]
    public void BuildWhereClause_ClassicQuoteBreakoutIsNeutralized()
    {
        var clause = _rewriter.BuildWhereClause(new[] { Eq("region", "us' OR '1'='1") });

        clause.Should().Be("\"region\" = 'us'' OR ''1''=''1'");
        // The value stays one literal: no unescaped quote can end it early.
        clause.Count(c => c == '\'').Should().Be(10);
    }

    [Fact]
    public void BuildWhereClause_ValueWithABackslash_IsNotPushed()
    {
        // MySQL treats \ as an escape inside a string literal by default and Postgres does
        // not, so "\'" would leave the literal open on MySQL. Refused rather than escaped
        // per-dialect.
        _rewriter.BuildWhereClause(new[] { Eq("region", @"us\' OR 1=1 -- ") }).Should().BeEmpty();
    }

    [Theory]
    [InlineData("us\0east")]
    [InlineData("us\neast")]
    [InlineData("us\reast")]
    [InlineData("us\teast")]
    public void BuildWhereClause_ValueWithAControlCharacter_IsNotPushed(string value)
    {
        // NUL truncates the statement for some client libraries and a newline ends a
        // "--" comment, either of which changes what the database executes.
        _rewriter.BuildWhereClause(new[] { Eq("region", value) }).Should().BeEmpty();
    }

    [Theory]
    [InlineData("region\"; DROP TABLE patients; --")]
    [InlineData("region OR 1=1")]
    [InlineData("region--comment")]
    [InlineData("region;")]
    [InlineData("region name")]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("1region")]
    [InlineData("*")]
    public void BuildWhereClause_UnsafeFieldName_IsNotPushed(string field)
    {
        _rewriter.BuildWhereClause(new[] { Eq(field, "x") }).Should().BeEmpty();
    }

    [Fact]
    public void BuildWhereClause_AcceptsAQualifiedFieldName_ByItsLeaf()
    {
        // The qualifier is dropped rather than emitted: TOLAP already treats
        // "patients.region" and "region" as the same field, and a table qualifier would not
        // resolve against "FROM patients p".
        _rewriter.BuildWhereClause(new[] { Eq("patients.region", "us") })
            .Should().Be("\"region\" = 'us'");
    }

    [Fact]
    public void BuildWhereClause_AcceptsAQuotedFieldName()
    {
        _rewriter.BuildWhereClause(new[] { Eq("\"region\"", "us") }).Should().Be("\"region\" = 'us'");
    }

    [Fact]
    public void BuildWhereClause_AcceptsANonAsciiFieldName()
    {
        _rewriter.BuildWhereClause(new[] { Eq("región", "us") }).Should().Be("\"región\" = 'us'");
    }

    // =======================================================================
    // Literal formatting
    // =======================================================================

    [Fact]
    public void BuildWhereClause_FormatsBooleans()
    {
        _rewriter.BuildWhereClause(new[] { Eq("active", true) }).Should().Be("\"active\" = TRUE");
        _rewriter.BuildWhereClause(new[] { Eq("active", false) }).Should().Be("\"active\" = FALSE");
    }

    [Fact]
    public void BuildWhereClause_FormatsIntegralTypes()
    {
        _rewriter.BuildWhereClause(new[] { Eq("a", (short)1) }).Should().Be("\"a\" = 1");
        _rewriter.BuildWhereClause(new[] { Eq("a", 2) }).Should().Be("\"a\" = 2");
        _rewriter.BuildWhereClause(new[] { Eq("a", 3L) }).Should().Be("\"a\" = 3");
        _rewriter.BuildWhereClause(new[] { Eq("a", (byte)4) }).Should().Be("\"a\" = 4");
        _rewriter.BuildWhereClause(new[] { Eq("a", (uint)5) }).Should().Be("\"a\" = 5");
    }

    [Fact]
    public void BuildWhereClause_FormatsDecimalsInvariantly()
    {
        // Under a comma-decimal culture the ambient form of 1.5 is "1,5", which inside an IN
        // list silently becomes two values.
        _rewriter.BuildWhereClause(new[] { Eq("a", 1.5m) }).Should().Be("\"a\" = 1.5");
        _rewriter.BuildWhereClause(new[] { Eq("a", 1.5d) }).Should().Be("\"a\" = 1.5");
        _rewriter.BuildWhereClause(new[] { Eq("a", 1.5f) }).Should().Be("\"a\" = 1.5");
    }

    [Theory]
    [InlineData(double.NaN)]
    [InlineData(double.PositiveInfinity)]
    [InlineData(double.NegativeInfinity)]
    public void BuildWhereClause_NonFiniteNumber_IsNotPushed(double value)
    {
        _rewriter.BuildWhereClause(new[] { Eq("a", value) }).Should().BeEmpty();
    }

    [Fact]
    public void BuildWhereClause_FormatsDateAndTimeTypes()
    {
        _rewriter.BuildWhereClause(new[] { Eq("at", new DateTime(2026, 3, 4, 5, 6, 7, DateTimeKind.Utc)) })
            .Should().Be("\"at\" = '2026-03-04 05:06:07'");

        // The offset is preserved rather than normalized away: "05:06:07" with no zone is
        // interpreted in the session's time zone by Postgres, so dropping "+00:00" would shift
        // the boundary of a time-based row filter by the server's UTC offset.
        _rewriter.BuildWhereClause(new[] { Eq("at", new DateTimeOffset(2026, 3, 4, 5, 6, 7, TimeSpan.Zero)) })
            .Should().Be("\"at\" = '2026-03-04 05:06:07+00:00'");

        _rewriter.BuildWhereClause(
            new[] { Eq("at", new DateTimeOffset(2026, 3, 4, 5, 6, 7, TimeSpan.FromHours(-5))) })
            .Should().Be("\"at\" = '2026-03-04 05:06:07-05:00'");

        _rewriter.BuildWhereClause(new[] { Eq("on", new DateOnly(2026, 3, 4)) })
            .Should().Be("\"on\" = '2026-03-04'");
    }

    [Fact]
    public void BuildWhereClause_FormatsAChar()
    {
        _rewriter.BuildWhereClause(new[] { Eq("grade", 'A') }).Should().Be("\"grade\" = 'A'");
    }

    [Fact]
    public void BuildWhereClause_UnknownClrType_IsNotPushed()
    {
        // A driver-specific type's ToString form is not known to be a valid literal in any
        // dialect, so it is not guessed at.
        _rewriter.BuildWhereClause(new[] { Eq("a", new Uri("https://example.com")) })
            .Should().BeEmpty();
    }

    // -- JSON-sourced values, as a deserialized policy supplies them --

    [Fact]
    public void BuildWhereClause_FormatsJsonScalars()
    {
        _rewriter.BuildWhereClause(new[] { Eq("a", Json("\"us\"")) }).Should().Be("\"a\" = 'us'");
        _rewriter.BuildWhereClause(new[] { Eq("a", Json("42")) }).Should().Be("\"a\" = 42");
        _rewriter.BuildWhereClause(new[] { Eq("a", Json("1.5")) }).Should().Be("\"a\" = 1.5");
        _rewriter.BuildWhereClause(new[] { Eq("a", Json("true")) }).Should().Be("\"a\" = TRUE");
        _rewriter.BuildWhereClause(new[] { Eq("a", Json("false")) }).Should().Be("\"a\" = FALSE");
    }

    [Fact]
    public void BuildWhereClause_JsonNull_BecomesIsNull()
    {
        _rewriter.BuildWhereClause(new[] { Eq("a", Json("null")) }).Should().Be("\"a\" IS NULL");
    }

    [Fact]
    public void BuildWhereClause_JsonNull_UnderNotEquals_BecomesIsNotNull()
    {
        _rewriter.BuildWhereClause(new[] { new RowFilter("a", FilterOperator.NotEquals, Json("null")) })
            .Should().Be("\"a\" IS NOT NULL");
    }

    [Fact]
    public void BuildWhereClause_JsonNull_UnderOrdering_AdmitsNoRow()
    {
        _rewriter.BuildWhereClause(new[] { new RowFilter("a", FilterOperator.GreaterThan, Json("null")) })
            .Should().Be("1 = 0");
    }

    [Fact]
    public void BuildWhereClause_JsonNull_InAValuesList_IsNotPushed()
    {
        _rewriter.BuildWhereClause(new[]
        {
            new RowFilter("a", FilterOperator.In, Values: new object[] { Json("\"us\""), Json("null") })
        }).Should().BeEmpty();
    }

    [Fact]
    public void BuildWhereClause_JsonNull_AsABetweenBound_AdmitsNoRow()
    {
        _rewriter.BuildWhereClause(new[]
        {
            new RowFilter("a", FilterOperator.Between, Values: new object[] { Json("null"), Json("9") })
        }).Should().Be("1 = 0");
    }

    [Theory]
    [InlineData("[1,2]")]
    [InlineData("{\"a\":1}")]
    public void BuildWhereClause_NonScalarJson_IsNotPushed(string raw)
    {
        _rewriter.BuildWhereClause(new[] { Eq("a", Json(raw)) }).Should().BeEmpty();
    }

    [Fact]
    public void BuildWhereClause_EscapesAQuoteInsideAJsonString()
    {
        _rewriter.BuildWhereClause(new[] { Eq("a", Json("\"O'Brien\"")) })
            .Should().Be("\"a\" = 'O''Brien'");
    }

    private static System.Text.Json.JsonElement Json(string raw)
        => System.Text.Json.JsonDocument.Parse(raw).RootElement.Clone();

    [Fact]
    public void BuildWhereClause_JsonStringNull_IsTreatedAsEmpty()
    {
        // JsonElement.GetString() on a JSON string is non-null in practice; the null-coalesce
        // exists so a future JsonElement shape cannot dereference null. Reached here through a
        // JSON empty string, which is the closest observable case.
        _rewriter.BuildWhereClause(new[] { Eq("a", Json("\"\"")) }).Should().Be("\"a\" = ''");
    }

    [Fact]
    public void BuildWhereClause_UnrenderableValue_IsNotPushed_ForEveryOperatorFamily()
    {
        // Each operator family formats its operand through a different call site, so a type
        // with no literal form must be declined by each of them and not only by equals.
        var bad = new Uri("https://example.com");

        _rewriter.BuildWhereClause(new[] { Eq("a", bad) }).Should().BeEmpty();
        _rewriter.BuildWhereClause(new[] { new RowFilter("a", FilterOperator.NotEquals, bad) })
            .Should().BeEmpty();
        _rewriter.BuildWhereClause(new[] { new RowFilter("a", FilterOperator.GreaterThan, bad) })
            .Should().BeEmpty();
        _rewriter.BuildWhereClause(new[] { new RowFilter("a", FilterOperator.Like, bad) })
            .Should().BeEmpty();
        _rewriter.BuildWhereClause(new[] { new RowFilter("a", FilterOperator.NotLike, bad) })
            .Should().BeEmpty();
        _rewriter.BuildWhereClause(new[]
        {
            new RowFilter("a", FilterOperator.In, Values: new object[] { bad })
        }).Should().BeEmpty();
        _rewriter.BuildWhereClause(new[]
        {
            new RowFilter("a", FilterOperator.NotIn, Values: new object[] { bad })
        }).Should().BeEmpty();
        _rewriter.BuildWhereClause(new[]
        {
            new RowFilter("a", FilterOperator.Between, Values: new object[] { bad, bad })
        }).Should().BeEmpty();
    }

    [Fact]
    public void BuildWhereClause_ANullValueUnderNotEquals_DoesNotReachTheComparePath()
    {
        // Distinguishes the two ways NotEquals can produce no condition: a null value becomes
        // IS NOT NULL (a real condition), while an unrenderable value declines entirely.
        _rewriter.BuildWhereClause(new[] { new RowFilter("a", FilterOperator.NotEquals, null) })
            .Should().Be("\"a\" IS NOT NULL");
    }

    // =======================================================================
    // ValidateQuery, beyond the ported suite
    // =======================================================================

    [Fact]
    public void ValidateQuery_RejectsAHiddenFieldInTheWhereClause()
    {
        // A hidden field is unreadable, and inferring its value through a predicate is a
        // disclosure even though it never appears in the projection.
        _rewriter.ValidateQuery(
            "SELECT id FROM patients WHERE ssn = '111-22-3333'",
            Policy(hiddenFields: new[] { "ssn" }))
            .Should().BeFalse();
    }

    [Fact]
    public void ValidateQuery_RejectsAHiddenFieldInAQualifiedWhereClause()
    {
        _rewriter.ValidateQuery(
            "SELECT id FROM patients p WHERE p.ssn = '111-22-3333'",
            Policy(hiddenFields: new[] { "ssn" }))
            .Should().BeFalse();
    }

    [Fact]
    public void ValidateQuery_RejectsAHiddenFieldInAQuotedQualifiedWhereClause()
    {
        _rewriter.ValidateQuery(
            "SELECT id FROM patients p WHERE p.\"ssn\" = '111-22-3333'",
            Policy(hiddenFields: new[] { "ssn" }))
            .Should().BeFalse();
    }

    [Fact]
    public void ValidateQuery_RejectsAHiddenFieldInOrderBy()
    {
        // ORDER BY on a hidden field discloses its ordering across the visible rows.
        _rewriter.ValidateQuery(
            "SELECT id FROM patients ORDER BY ssn DESC", Policy(hiddenFields: new[] { "ssn" }))
            .Should().BeFalse();
    }

    [Fact]
    public void ValidateQuery_RejectsAHiddenFieldInOrderByWithNullsSuffix()
    {
        _rewriter.ValidateQuery(
            "SELECT id FROM patients ORDER BY ssn ASC NULLS LAST", Policy(hiddenFields: new[] { "ssn" }))
            .Should().BeFalse();
    }

    [Fact]
    public void ValidateQuery_RejectsAHiddenFieldInGroupBy()
    {
        _rewriter.ValidateQuery(
            "SELECT count(*) FROM patients GROUP BY ssn", Policy(hiddenFields: new[] { "ssn" }))
            .Should().BeFalse();
    }

    [Fact]
    public void ValidateQuery_RejectsAHiddenFieldInHaving()
    {
        _rewriter.ValidateQuery(
            "SELECT region FROM patients GROUP BY region HAVING max(ssn) > '1'",
            Policy(hiddenFields: new[] { "ssn" }))
            .Should().BeFalse();
    }

    [Fact]
    public void ValidateQuery_RejectsANonAllowedFieldInTheWhereClause()
    {
        _rewriter.ValidateQuery(
            "SELECT id FROM patients WHERE salary > 100",
            Policy(allowedFields: new[] { "id", "name" }))
            .Should().BeFalse();
    }

    [Fact]
    public void ValidateQuery_EmptyAllowedFields_RejectsEveryFieldReference()
    {
        _rewriter.ValidateQuery(
            "SELECT id FROM patients", Policy(allowedFields: Array.Empty<string>()))
            .Should().BeFalse();
    }

    [Fact]
    public void ValidateQuery_AllowsSelectStar_UnderAnAllowList()
    {
        // '*' names no field on its own; the projection is settled by the rewrite and the
        // post-fetch pass, so refusing every SELECT * here would reject ordinary queries.
        _rewriter.ValidateQuery("SELECT * FROM patients", Policy(allowedFields: new[] { "id" }))
            .Should().BeTrue();
    }

    [Fact]
    public void ValidateQuery_AllowsAnAggregate_UnderAnAllowList()
    {
        _rewriter.ValidateQuery(
            "SELECT count(*) FROM patients", Policy(allowedFields: new[] { "id" }))
            .Should().BeTrue();
    }

    [Fact]
    public void ValidateQuery_MatchesAQualifiedAllowedFieldAgainstABareReference()
    {
        _rewriter.ValidateQuery(
            "SELECT region FROM patients", Policy(allowedFields: new[] { "patients.region" }))
            .Should().BeTrue();
    }

    [Fact]
    public void ValidateQuery_IsCaseInsensitive()
    {
        _rewriter.ValidateQuery("SELECT SSN FROM patients", Policy(hiddenFields: new[] { "ssn" }))
            .Should().BeFalse();
    }

    [Fact]
    public void ValidateQuery_HonoursAWildcardHiddenPattern()
    {
        _rewriter.ValidateQuery(
            "SELECT internal_notes FROM patients", Policy(hiddenFields: new[] { "internal_*" }))
            .Should().BeFalse();
    }

    [Fact]
    public void ValidateQuery_ReturnsTrue_ForAnUnrestrictedPolicy()
    {
        _rewriter.ValidateQuery("SELECT id, ssn FROM patients", Policy()).Should().BeTrue();
    }

    [Fact]
    public void ValidateQuery_ReturnsTrue_WhenNoClauseYieldsAFieldName()
    {
        _rewriter.ValidateQuery("SHOW TABLES", Policy(hiddenFields: new[] { "ssn" }))
            .Should().BeTrue();
    }

    [Fact]
    public void ValidateQuery_RejectsAHiddenFieldInsideASelectAggregate()
    {
        // The token left of any operator is ")", so the comparison patterns find nothing; the
        // field is only reachable by looking inside the argument list.
        _rewriter.ValidateQuery(
            "SELECT max(ssn) FROM patients", Policy(hiddenFields: new[] { "ssn" }))
            .Should().BeFalse();
    }

    [Fact]
    public void ValidateQuery_RejectsAHiddenFieldInsideANestedFunctionCall()
    {
        _rewriter.ValidateQuery(
            "SELECT id FROM patients WHERE upper(trim(ssn)) = 'X'",
            Policy(hiddenFields: new[] { "ssn" }))
            .Should().BeFalse();
    }

    [Fact]
    public void ValidateQuery_DoesNotTreatAStringLiteralAsAFieldName()
    {
        // "ssn" appears only as a value here, so the query references no hidden field.
        _rewriter.ValidateQuery(
            "SELECT id FROM patients WHERE label = concat('ssn', 'x')",
            Policy(hiddenFields: new[] { "ssn" }))
            .Should().BeTrue();
    }

    [Fact]
    public void ValidateQuery_DoesNotTreatANumericArgumentAsAFieldName()
    {
        _rewriter.ValidateQuery(
            "SELECT round(1.5) FROM patients", Policy(allowedFields: new[] { "id" }))
            .Should().BeTrue();
    }

    [Fact]
    public void ValidateQuery_IgnoresKeywordsInsideAFunctionCall()
    {
        _rewriter.ValidateQuery(
            "SELECT cast(id AS text) FROM patients", Policy(allowedFields: new[] { "id" }))
            .Should().BeTrue();
    }

    [Fact]
    public void ValidateQuery_IgnoresAKeywordOnTheLeftOfAQualifiedComparison()
    {
        // "t.end = 1" yields the keyword "end", which must not be reported as a field.
        _rewriter.ValidateQuery(
            "SELECT id FROM spans t WHERE t.end = 1", Policy(allowedFields: new[] { "id", "end" }))
            .Should().BeTrue();
    }

    [Fact]
    public void ValidateQuery_ToleratesAnEmptyOrderByEntry()
    {
        _rewriter.ValidateQuery(
            "SELECT id FROM patients ORDER BY id, ", Policy(hiddenFields: new[] { "ssn" }))
            .Should().BeTrue();
    }

    [Fact]
    public void ValidateQuery_ToleratesAnEmptyGroupByEntry()
    {
        _rewriter.ValidateQuery(
            "SELECT id FROM patients GROUP BY id, ", Policy(hiddenFields: new[] { "ssn" }))
            .Should().BeTrue();
    }

    // =======================================================================
    // Diagnostics callback
    // =======================================================================

    [Fact]
    public void Diagnostics_ReceiveAMessage_WhenAFilterCannotBePushed()
    {
        var messages = new List<string>();
        var rewriter = new SqlQueryRewriter(messages.Add);

        rewriter.RewriteQuery(
            "SELECT id FROM patients",
            Policy(rowFilters: new[] { new RowFilter("notes", FilterOperator.Matches, "^x") }));

        messages.Should().ContainSingle()
            .Which.Should().Contain("notes").And.Contain("portable SQL form");
    }

    [Fact]
    public void Diagnostics_ReceiveAMessage_WhenSelectStarCannotBeExpanded()
    {
        var messages = new List<string>();
        var rewriter = new SqlQueryRewriter(messages.Add);

        rewriter.RewriteQuery("SELECT * FROM patients", Policy(hiddenFields: new[] { "ssn" }));

        messages.Should().ContainSingle().Which.Should().Contain("allowedFields");
    }

    [Fact]
    public void Diagnostics_ReceiveAMessage_WhenAFieldIsRemovedFromTheSelectList()
    {
        var messages = new List<string>();
        var rewriter = new SqlQueryRewriter(messages.Add);

        rewriter.RewriteQuery("SELECT id, ssn FROM patients", Policy(hiddenFields: new[] { "ssn" }));

        messages.Should().ContainSingle().Which.Should().Contain("hidden field").And.Contain("ssn");
    }

    [Fact]
    public void Diagnostics_AreOptional()
    {
        // The parameterless constructor must not throw on a path that would diagnose.
        var act = () => new SqlQueryRewriter().RewriteQuery(
            "SELECT * FROM patients", Policy(hiddenFields: new[] { "ssn" }));

        act.Should().NotThrow();
    }

    // =======================================================================
    // Structural scanning edge cases
    // =======================================================================

    [Fact]
    public void RewriteQuery_HandlesAnUnbalancedParenthesis_WithoutMisplacingTheWhere()
    {
        // An unbalanced ')' must not drive the depth negative and make a later inner keyword
        // look top-level.
        var result = _rewriter.RewriteQuery(
            "SELECT id) FROM patients", Policy(rowFilters: new[] { Eq("region", "US") }));

        result.Should().EndWith("WHERE \"region\" = 'US'");
    }

    [Fact]
    public void RewriteQuery_HandlesAnEscapedQuoteInsideALiteral()
    {
        var result = _rewriter.RewriteQuery(
            "SELECT id FROM patients WHERE note = 'it''s fine'",
            Policy(rowFilters: new[] { Eq("region", "US") }));

        result.Should().Be(
            "SELECT id FROM patients WHERE (\"region\" = 'US') AND (note = 'it''s fine')");
    }

    [Fact]
    public void RewriteQuery_HandlesAnUnterminatedLiteral_WithoutThrowing()
    {
        var act = () => _rewriter.RewriteQuery(
            "SELECT id FROM patients WHERE note = 'unterminated",
            Policy(rowFilters: new[] { Eq("region", "US") }, maxResults: 5));

        act.Should().NotThrow();
    }

    [Fact]
    public void RewriteQuery_HandlesADoubledQuoteInsideAQuotedIdentifier()
    {
        var result = _rewriter.RewriteQuery(
            "SELECT \"od''d\" FROM patients", Policy(rowFilters: new[] { Eq("region", "US") }));

        result.Should().EndWith("WHERE \"region\" = 'US'");
    }

    [Fact]
    public void RewriteQuery_HandlesAQuotedIdentifierContainingTheWordFrom()
    {
        var result = _rewriter.RewriteQuery(
            "SELECT \"from\", ssn FROM patients", Policy(hiddenFields: new[] { "ssn" }));

        result.Should().Be("SELECT \"from\" FROM patients");
    }

    [Fact]
    public void RewriteQuery_HandlesAMultilineQuery()
    {
        var result = _rewriter.RewriteQuery(
            "SELECT id,\n       ssn\n  FROM patients\n ORDER BY id",
            Policy(hiddenFields: new[] { "ssn" }, rowFilters: new[] { Eq("region", "US") }));

        result.Should().Contain("WHERE \"region\" = 'US'");
        result.Should().NotContainEquivalentOf("ssn");
        result.IndexOf("WHERE", StringComparison.Ordinal)
            .Should().BeLessThan(result.IndexOf("ORDER BY", StringComparison.Ordinal));
    }

    [Fact]
    public void RewriteQuery_IsCaseInsensitiveOnKeywords()
    {
        var result = _rewriter.RewriteQuery(
            "select id, ssn from patients where status = 'active' limit 900",
            Policy(hiddenFields: new[] { "ssn" }, rowFilters: new[] { Eq("region", "US") }, maxResults: 10));

        result.Should().Be(
            "select id from patients WHERE (\"region\" = 'US') AND (status = 'active') LIMIT 10");
    }

    [Fact]
    public void RewriteQuery_TrimsLeadingAndTrailingWhitespace()
    {
        _rewriter.RewriteQuery("  SELECT id FROM patients  ", Policy(maxResults: 5))
            .Should().Be("SELECT id FROM patients LIMIT 5");
    }
}
