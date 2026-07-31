using System.Text.Json;
using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// Post-fetch semantics for the seven operators TOLAP adds beyond its original nine, as
/// applied by <see cref="EnforcementEngine.ApplyRowFilters"/>.
/// </summary>
/// <remarks>
/// The post-fetch pass is the normative enforcement point (canonical-enforcement-spec.md
/// section 4), so these tests define what each operator means and
/// <see cref="SqlQueryRewriterTests"/> asserts that the pushed-down SQL agrees. Three rules
/// from spec section 7 get a case per operator: a row missing the field is dropped for every
/// operator including the negative ones, a type mismatch is a non-match rather than an
/// exception, and no comparison conflates a boolean with a number.
/// </remarks>
public class RowFilterOperatorTests
{
    private static EffectivePolicy Policy(params RowFilter[] filters) => new(
        Version: "1.0",
        UserId: "u1",
        TenantId: "t1",
        SourceConnectionId: "db:pg:main",
        ResolvedAt: DateTimeOffset.UtcNow,
        ExpiresAt: DateTimeOffset.UtcNow.AddHours(1),
        SourceProfiles: new[] { "test" },
        Permissions: new PolicyPermissions(CanQuery: true),
        ObjectRules: new ObjectRules(RowFilters: filters));

    /// <summary>Whether a one-field row survives a single filter.</summary>
    private static bool Passes(string field, object? value, RowFilter filter)
    {
        var rows = new List<Dictionary<string, object?>>
        {
            new() { [field] = value }
        };
        return EnforcementEngine.ApplyRowFilters(rows, Policy(filter)).Count == 1;
    }

    /// <summary>Whether a row lacking the referenced field survives a filter.</summary>
    private static bool PassesWithFieldAbsent(RowFilter filter)
    {
        var rows = new List<Dictionary<string, object?>>
        {
            new() { ["unrelated"] = "x" }
        };
        return EnforcementEngine.ApplyRowFilters(rows, Policy(filter)).Count == 1;
    }

    private static JsonElement Json(string raw) => JsonDocument.Parse(raw).RootElement.Clone();

    // =======================================================================
    // Fail closed on a missing field, for every added operator
    // =======================================================================

    [Theory]
    [InlineData(FilterOperator.GreaterThanOrEqual)]
    [InlineData(FilterOperator.LessThanOrEqual)]
    [InlineData(FilterOperator.Like)]
    [InlineData(FilterOperator.NotLike)]
    [InlineData(FilterOperator.IsNull)]
    [InlineData(FilterOperator.IsNotNull)]
    [InlineData(FilterOperator.Between)]
    public void MissingField_DropsTheRow_ForEveryAddedOperator(FilterOperator op)
    {
        // Spec section 7. notLike is the operator this most easily gets wrong: reading a
        // missing field as "not like the pattern" retains every row that simply lacks the
        // column, which is the same fail-open bug the spec records for notEquals/notIn.
        var filter = new RowFilter("region", op, Value: "us-%", Values: new object[] { 1, 10 });

        PassesWithFieldAbsent(filter).Should().BeFalse();
    }

    // =======================================================================
    // The three negative operators must not diverge from each other
    // =======================================================================

    /// <summary>
    /// The three negative operators, each phrased so a present, non-null, non-matching
    /// value passes. Written against one field so the three are directly comparable.
    /// </summary>
    /// <remarks>
    /// Regression guard. <c>notLike</c> used to drop a present-null row while
    /// <c>notEquals</c> and <c>notIn</c> kept it, and the rewriter emitted the
    /// <c>IS NULL</c> arm for those two while omitting it for <c>notLike</c> — so the same
    /// policy's row set depended on which negative operator the author happened to choose,
    /// which is not a distinction the policy expresses. A per-operator assertion cannot
    /// see that; only comparing the three can.
    /// </remarks>
    public static IEnumerable<object[]> NegativeOperators()
    {
        yield return new object[] { new RowFilter("region", FilterOperator.NotEquals, "us-east") };
        yield return new object[]
        {
            new RowFilter("region", FilterOperator.NotIn, Values: new object[] { "us-east" })
        };
        yield return new object[] { new RowFilter("region", FilterOperator.NotLike, "us-eas_") };
    }

    [Theory]
    [MemberData(nameof(NegativeOperators))]
    public void EveryNegativeOperator_KeepsAPresentNullValue(RowFilter filter)
    {
        // Keeping present-null is what preserves pushdown/post-fetch equivalence.
        Passes("region", null, filter).Should().BeTrue(filter.Operator.ToString());
        Passes("region", Json("null"), filter).Should().BeTrue(filter.Operator.ToString());
    }

    [Theory]
    [MemberData(nameof(NegativeOperators))]
    public void EveryNegativeOperator_DropsAnAbsentField(RowFilter filter)
    {
        // The separate, unchanged fail-closed rule: a value that cannot be established
        // cannot be shown to satisfy the filter.
        PassesWithFieldAbsent(filter).Should().BeFalse(filter.Operator.ToString());
    }

    [Theory]
    [MemberData(nameof(NegativeOperators))]
    public void EveryNegativeOperator_Discriminates(RowFilter filter)
    {
        // Guards the guard: the filters above must actually distinguish rows, or the two
        // assertions would hold vacuously.
        Passes("region", "eu-west", filter).Should().BeTrue(filter.Operator.ToString());
        Passes("region", "us-east", filter).Should().BeFalse(filter.Operator.ToString());
    }

    [Fact]
    public void IsNull_DropsARowMissingTheField_NotOnlyANonNullOne()
    {
        // The distinction this pins: "absent" and "present and null" are different states, and
        // isNull means the second. A row that never had the column cannot be shown to satisfy
        // the filter, so it is dropped -- the same fail-closed reading the spec applies to an
        // unscored record under a relevance floor. An integrator wanting "absent or null"
        // must say so with two policies, because collapsing the two here would make isNull
        // silently match rows from a differently-shaped result set.
        PassesWithFieldAbsent(new RowFilter("deleted_at", FilterOperator.IsNull)).Should().BeFalse();
        Passes("deleted_at", null, new RowFilter("deleted_at", FilterOperator.IsNull)).Should().BeTrue();
    }

    // =======================================================================
    // greaterThanOrEqual / lessThanOrEqual
    // =======================================================================

    [Theory]
    [InlineData(17, false)]
    [InlineData(18, true)]
    [InlineData(19, true)]
    public void GreaterThanOrEqual_IsInclusiveAtTheBoundary(int age, bool expected)
    {
        Passes("age", age, new RowFilter("age", FilterOperator.GreaterThanOrEqual, 18))
            .Should().Be(expected);
    }

    [Theory]
    [InlineData(64, true)]
    [InlineData(65, true)]
    [InlineData(66, false)]
    public void LessThanOrEqual_IsInclusiveAtTheBoundary(int age, bool expected)
    {
        Passes("age", age, new RowFilter("age", FilterOperator.LessThanOrEqual, 65))
            .Should().Be(expected);
    }

    [Fact]
    public void OrderingOperators_CompareAcrossNumericTypes()
    {
        // A driver may hand back long where the policy JSON carried int, or double where it
        // carried a whole number.
        Passes("age", 18L, new RowFilter("age", FilterOperator.GreaterThanOrEqual, 18)).Should().BeTrue();
        Passes("age", 18.0, new RowFilter("age", FilterOperator.GreaterThanOrEqual, 18)).Should().BeTrue();
        Passes("age", 18m, new RowFilter("age", FilterOperator.LessThanOrEqual, 18L)).Should().BeTrue();
    }

    [Fact]
    public void OrderingOperators_CompareStrings()
    {
        Passes("region", "us-east", new RowFilter("region", FilterOperator.GreaterThanOrEqual, "us-east"))
            .Should().BeTrue();
        Passes("region", "eu-west", new RowFilter("region", FilterOperator.GreaterThanOrEqual, "us-east"))
            .Should().BeFalse();
    }

    [Theory]
    [InlineData(FilterOperator.GreaterThanOrEqual)]
    [InlineData(FilterOperator.LessThanOrEqual)]
    public void OrderingOperators_TypeMismatchIsANonMatch(FilterOperator op)
    {
        // Never an exception that aborts the whole result pass (spec section 7).
        Passes("age", "notanumber", new RowFilter("age", op, 30)).Should().BeFalse();
        Passes("age", 30, new RowFilter("age", op, "notanumber")).Should().BeFalse();
    }

    [Theory]
    [InlineData(FilterOperator.GreaterThanOrEqual)]
    [InlineData(FilterOperator.LessThanOrEqual)]
    public void OrderingOperators_DoNotOrderBooleans(FilterOperator op)
    {
        Passes("active", true, new RowFilter("active", op, 1)).Should().BeFalse();
        Passes("active", true, new RowFilter("active", op, true)).Should().BeFalse();
    }

    [Theory]
    [InlineData(FilterOperator.GreaterThanOrEqual)]
    [InlineData(FilterOperator.LessThanOrEqual)]
    public void OrderingOperators_AgainstNull_AreNonMatches(FilterOperator op)
    {
        Passes("age", null, new RowFilter("age", op, 18)).Should().BeFalse();
        Passes("age", 18, new RowFilter("age", op, null)).Should().BeFalse();
    }

    [Fact]
    public void OrderingOperators_ComparePastAJsonElement()
    {
        Passes("age", 20, new RowFilter("age", FilterOperator.GreaterThanOrEqual, Json("18")))
            .Should().BeTrue();
        Passes("age", Json("20"), new RowFilter("age", FilterOperator.LessThanOrEqual, 18))
            .Should().BeFalse();
    }

    // =======================================================================
    // like / notLike
    // =======================================================================

    [Theory]
    [InlineData("us-east", "us-%", true)]
    [InlineData("eu-west", "us-%", false)]
    [InlineData("us-east", "%east", true)]
    [InlineData("us-east", "%-%", true)]
    [InlineData("us-east", "us-east", true)]
    [InlineData("us-east", "us-eas", false)]
    [InlineData("us", "%", true)]
    [InlineData("", "%", true)]
    public void Like_HandlesPercentWildcards(string value, string pattern, bool expected)
    {
        Passes("region", value, new RowFilter("region", FilterOperator.Like, pattern))
            .Should().Be(expected);
    }

    [Theory]
    [InlineData("us1", "us_", true)]
    [InlineData("us", "us_", false)]
    [InlineData("us12", "us_", false)]
    [InlineData("us12", "us__", true)]
    public void Like_UnderscoreMatchesExactlyOneCharacter(string value, string pattern, bool expected)
    {
        Passes("region", value, new RowFilter("region", FilterOperator.Like, pattern))
            .Should().Be(expected);
    }

    [Fact]
    public void Like_IsAnchored()
    {
        // "us" as a pattern is an equality test, not a substring test; that is what
        // "contains" is for.
        Passes("region", "us-east", new RowFilter("region", FilterOperator.Like, "us")).Should().BeFalse();
    }

    [Fact]
    public void Like_IsCaseSensitive()
    {
        // Matches Postgres LIKE. MySQL's default collation is case-insensitive, so pushing
        // the same filter there matches more rows; the post-fetch pass then removes the
        // extras, which is the fail-closed direction.
        Passes("region", "US-EAST", new RowFilter("region", FilterOperator.Like, "us-%"))
            .Should().BeFalse();
    }

    [Fact]
    public void Like_TreatsRegexMetacharactersLiterally()
    {
        // A LIKE pattern is not a regex. Were the pattern passed through to the regex engine
        // unescaped, "." would match any character and "a|b" would become an alternation.
        Passes("code", "a.b", new RowFilter("code", FilterOperator.Like, "a.b")).Should().BeTrue();
        Passes("code", "axb", new RowFilter("code", FilterOperator.Like, "a.b")).Should().BeFalse();
        Passes("code", "a", new RowFilter("code", FilterOperator.Like, "a|b")).Should().BeFalse();
        Passes("code", "a+", new RowFilter("code", FilterOperator.Like, "a+")).Should().BeTrue();
        Passes("code", "aaa", new RowFilter("code", FilterOperator.Like, "a+")).Should().BeFalse();
        Passes("code", "(a)", new RowFilter("code", FilterOperator.Like, "(a)")).Should().BeTrue();
        Passes("code", "a$", new RowFilter("code", FilterOperator.Like, "a$")).Should().BeTrue();
    }

    [Fact]
    public void Like_BackslashEscapesAWildcard()
    {
        Passes("code", "100%", new RowFilter("code", FilterOperator.Like, @"100\%")).Should().BeTrue();
        Passes("code", "100x", new RowFilter("code", FilterOperator.Like, @"100\%")).Should().BeFalse();
        Passes("code", "a_b", new RowFilter("code", FilterOperator.Like, @"a\_b")).Should().BeTrue();
        Passes("code", "axb", new RowFilter("code", FilterOperator.Like, @"a\_b")).Should().BeFalse();
    }

    [Fact]
    public void Like_TrailingBackslashIsLiteral()
    {
        // Nothing follows it to escape, so it must not read past the end of the pattern.
        Passes("code", @"a\", new RowFilter("code", FilterOperator.Like, @"a\")).Should().BeTrue();
    }

    [Theory]
    [InlineData("us-east", "eu-%", true)]
    [InlineData("eu-west", "eu-%", false)]
    public void NotLike_IsTheNegationOfLike(string value, string pattern, bool expected)
    {
        Passes("region", value, new RowFilter("region", FilterOperator.NotLike, pattern))
            .Should().Be(expected);
    }

    [Fact]
    public void Like_AgainstANullFieldValue_IsANonMatch()
    {
        // A null value cannot be shown to match a pattern, so `like` drops the row.
        Passes("region", null, new RowFilter("region", FilterOperator.Like, "us-%"))
            .Should().BeFalse();
    }

    [Fact]
    public void NotLike_AgainstAPresentNullFieldValue_KeepsTheRow()
    {
        // NotLike is a negative operator and keeps a present-and-null value, exactly as
        // NotEquals and NotIn do. Bare SQL "NULL NOT LIKE 'x'" is unknown and would drop
        // the row, which is why the rewriter emits (col NOT LIKE 'x' OR col IS NULL) --
        // so the pushed-down query and the post-fetch pass select the same rows.
        //
        // Distinct from the ABSENT-field rule, which still drops the row; see
        // MissingField_DropsTheRow_ForEveryAddedOperator.
        Passes("region", null, new RowFilter("region", FilterOperator.NotLike, "us-%"))
            .Should().BeTrue();
    }

    [Fact]
    public void NotLike_AgainstAJsonNullFieldValue_KeepsTheRow()
    {
        // A JSON null arrives as a JsonElement of kind Null, which is NOT a CLR null and
        // whose ToString() is the empty string. Testing only for a CLR null would compare
        // "" against the pattern instead of taking the null path, so this pins the shape a
        // policy and a result set actually arrive in over the wire.
        Passes("region", Json("null"), new RowFilter("region", FilterOperator.NotLike, "us-%"))
            .Should().BeTrue();
    }

    [Fact]
    public void Like_AgainstAJsonNullFieldValue_IsANonMatch()
    {
        // The same JsonElement-vs-CLR-null distinction, in the positive direction: a
        // null-valued row must not match `like '%'` by way of an empty string.
        Passes("region", Json("null"), new RowFilter("region", FilterOperator.Like, "%"))
            .Should().BeFalse();
    }

    [Theory]
    [InlineData(FilterOperator.Like)]
    [InlineData(FilterOperator.NotLike)]
    public void LikeOperators_AgainstANullPattern_AreNonMatches(FilterOperator op)
    {
        Passes("region", "us-east", new RowFilter("region", op, null)).Should().BeFalse();
    }

    [Fact]
    public void Like_CoercesANonStringFieldValueToItsStringForm()
    {
        Passes("code", 12345, new RowFilter("code", FilterOperator.Like, "123%")).Should().BeTrue();
    }

    [Fact]
    public void Like_AcceptsAJsonPattern()
    {
        Passes("region", "us-east", new RowFilter("region", FilterOperator.Like, Json("\"us-%\"")))
            .Should().BeTrue();
    }

    // =======================================================================
    // isNull / isNotNull
    // =======================================================================

    [Fact]
    public void IsNull_MatchesOnlyAPresentNullValue()
    {
        Passes("deleted_at", null, new RowFilter("deleted_at", FilterOperator.IsNull)).Should().BeTrue();
        Passes("deleted_at", "2026-01-01", new RowFilter("deleted_at", FilterOperator.IsNull)).Should().BeFalse();
    }

    [Fact]
    public void IsNotNull_MatchesOnlyAPresentNonNullValue()
    {
        Passes("region", "us-east", new RowFilter("region", FilterOperator.IsNotNull)).Should().BeTrue();
        Passes("region", null, new RowFilter("region", FilterOperator.IsNotNull)).Should().BeFalse();
    }

    [Fact]
    public void NullOperators_TreatAJsonNullAsNull()
    {
        // A policy round-tripped through JSON carries JsonValueKind.Null, not a CLR null; the
        // two must not behave differently.
        Passes("deleted_at", Json("null"), new RowFilter("deleted_at", FilterOperator.IsNull))
            .Should().BeTrue();
        Passes("deleted_at", Json("null"), new RowFilter("deleted_at", FilterOperator.IsNotNull))
            .Should().BeFalse();
    }

    [Fact]
    public void NullOperators_IgnoreTheValueField()
    {
        // isNull takes no operand; a stray value must not change the outcome.
        Passes("deleted_at", null, new RowFilter("deleted_at", FilterOperator.IsNull, "ignored"))
            .Should().BeTrue();
    }

    [Fact]
    public void IsNotNull_DoesNotTreatEmptyStringAsNull()
    {
        Passes("region", "", new RowFilter("region", FilterOperator.IsNotNull)).Should().BeTrue();
    }

    [Fact]
    public void IsNotNull_DoesNotTreatFalseOrZeroAsNull()
    {
        // A truthiness check rather than a null check would drop both of these.
        Passes("active", false, new RowFilter("active", FilterOperator.IsNotNull)).Should().BeTrue();
        Passes("count", 0, new RowFilter("count", FilterOperator.IsNotNull)).Should().BeTrue();
    }

    // =======================================================================
    // between
    // =======================================================================

    [Theory]
    [InlineData(17, false)]
    [InlineData(18, true)]
    [InlineData(40, true)]
    [InlineData(65, true)]
    [InlineData(66, false)]
    public void Between_IsInclusiveAtBothBounds(int age, bool expected)
    {
        Passes("age", age, new RowFilter("age", FilterOperator.Between, Values: new object[] { 18, 65 }))
            .Should().Be(expected);
    }

    [Fact]
    public void Between_UsesOnlyTheFirstTwoBounds()
    {
        var filter = new RowFilter("age", FilterOperator.Between, Values: new object[] { 18, 65, 0 });

        Passes("age", 40, filter).Should().BeTrue();
    }

    [Fact]
    public void Between_AnInvertedRangeMatchesNothing()
    {
        // As SQL "BETWEEN 65 AND 18" does. Reordering the bounds would turn a policy author's
        // typo into a wider grant than the policy states.
        var filter = new RowFilter("age", FilterOperator.Between, Values: new object[] { 65, 18 });

        Passes("age", 40, filter).Should().BeFalse();
        Passes("age", 65, filter).Should().BeFalse();
    }

    [Fact]
    public void Between_ADegenerateRangeMatchesOnlyThatValue()
    {
        var filter = new RowFilter("age", FilterOperator.Between, Values: new object[] { 40, 40 });

        Passes("age", 40, filter).Should().BeTrue();
        Passes("age", 41, filter).Should().BeFalse();
    }

    [Theory]
    [InlineData(null)]
    [InlineData(0)]
    [InlineData(1)]
    public void Between_WithFewerThanTwoBounds_DropsEveryRow(int? boundCount)
    {
        var values = boundCount is null
            ? null
            : Enumerable.Range(0, boundCount.Value).Select(i => (object)i).ToArray();

        Passes("age", 40, new RowFilter("age", FilterOperator.Between, Values: values)).Should().BeFalse();
    }

    [Fact]
    public void Between_WithANullBound_DropsEveryRow()
    {
        Passes("age", 40, new RowFilter("age", FilterOperator.Between, Values: new object?[] { null, 65 }!))
            .Should().BeFalse();
        Passes("age", 40, new RowFilter("age", FilterOperator.Between, Values: new object?[] { 18, null }!))
            .Should().BeFalse();
    }

    [Fact]
    public void Between_TypeMismatchIsANonMatch()
    {
        Passes("age", "notanumber", new RowFilter("age", FilterOperator.Between, Values: new object[] { 18, 65 }))
            .Should().BeFalse();
    }

    [Fact]
    public void Between_ComparesStrings()
    {
        var filter = new RowFilter("region", FilterOperator.Between, Values: new object[] { "a", "m" });

        Passes("region", "eu-west", filter).Should().BeTrue();
        Passes("region", "us-east", filter).Should().BeFalse();
    }

    [Fact]
    public void Between_ComparesAcrossNumericTypes()
    {
        var filter = new RowFilter("age", FilterOperator.Between, Values: new object[] { 18L, 65.0 });

        Passes("age", 40, filter).Should().BeTrue();
    }

    [Fact]
    public void Between_AcceptsJsonBounds()
    {
        var filter = new RowFilter(
            "age", FilterOperator.Between, Values: new object[] { Json("18"), Json("65") });

        Passes("age", 40, filter).Should().BeTrue();
        Passes("age", 66, filter).Should().BeFalse();
    }

    [Fact]
    public void Between_DoesNotOrderBooleans()
    {
        Passes("active", true, new RowFilter("active", FilterOperator.Between, Values: new object[] { 0, 2 }))
            .Should().BeFalse();
    }

    // =======================================================================
    // The added operators inside the whole pipeline
    // =======================================================================

    [Fact]
    public void AddedOperators_AndTogetherWithTheOriginalNine()
    {
        var rows = new List<Dictionary<string, object?>>
        {
            new() { ["id"] = 1, ["region"] = "us-east", ["age"] = 40, ["deleted_at"] = null },
            new() { ["id"] = 2, ["region"] = "us-west", ["age"] = 70, ["deleted_at"] = null },
            new() { ["id"] = 3, ["region"] = "eu-west", ["age"] = 40, ["deleted_at"] = null },
            new() { ["id"] = 4, ["region"] = "us-east", ["age"] = 40, ["deleted_at"] = "2026-01-01" }
        };

        var policy = Policy(
            new RowFilter("region", FilterOperator.Like, "us-%"),
            new RowFilter("age", FilterOperator.Between, Values: new object[] { 18, 65 }),
            new RowFilter("deleted_at", FilterOperator.IsNull));

        var kept = EnforcementEngine.ApplyRowFilters(rows, policy);

        kept.Select(r => r["id"]).Should().BeEquivalentTo(new object[] { 1 });
    }

    [Fact]
    public void AddedOperators_RunAsStepOneOfTheFullPipeline()
    {
        // Confirms the operators are reached through ApplyRecordPipeline, not only through the
        // row-filter method directly, and that a row they drop is gone before masking.
        var rows = new List<Dictionary<string, object?>>
        {
            new() { ["region"] = "us-east", ["ssn"] = "111-22-3333" },
            new() { ["region"] = "eu-west", ["ssn"] = "222-33-4444" }
        };

        var policy = new EffectivePolicy(
            Version: "1.0",
            UserId: "u1",
            TenantId: "t1",
            SourceConnectionId: "db:pg:main",
            ResolvedAt: DateTimeOffset.UtcNow,
            ExpiresAt: DateTimeOffset.UtcNow.AddHours(1),
            SourceProfiles: new[] { "test" },
            Permissions: new PolicyPermissions(CanQuery: true),
            ObjectRules: new ObjectRules(
                FieldRules: new FieldRules(
                    MaskedFields: new[] { new MaskingRule("ssn", MaskType.Redact) }),
                RowFilters: new[] { new RowFilter("region", FilterOperator.Like, "us-%") }));

        var result = EnforcementEngine.ApplyRecordPipeline(rows, policy);

        result.Should().HaveCount(1);
        result[0]["region"].Should().Be("us-east");
        result[0]["ssn"].Should().Be("[REDACTED]");
    }

    // =======================================================================
    // Wire form
    // =======================================================================

    [Theory]
    [InlineData(FilterOperator.GreaterThanOrEqual, "greaterThanOrEqual")]
    [InlineData(FilterOperator.LessThanOrEqual, "lessThanOrEqual")]
    [InlineData(FilterOperator.Like, "like")]
    [InlineData(FilterOperator.NotLike, "notLike")]
    [InlineData(FilterOperator.IsNull, "isNull")]
    [InlineData(FilterOperator.IsNotNull, "isNotNull")]
    [InlineData(FilterOperator.Between, "between")]
    public void AddedOperators_RoundTripThroughTheirSchemaNames(FilterOperator op, string wireName)
    {
        // These names must match schema/v1.0/policy-definition.schema.json exactly: a
        // mismatch makes a schema-valid policy fail to deserialize, and the wrapper then
        // denies every call rather than enforcing the intended filter.
        var filter = new RowFilter("f", op);

        var json = TolapJsonOptions.Serialize(filter);

        json.Should().Contain($"\"operator\":\"{wireName}\"");
        TolapJsonOptions.Deserialize<RowFilter>(json).Operator.Should().Be(op);
    }

    [Theory]
    [InlineData("greaterThanOrEqual", FilterOperator.GreaterThanOrEqual)]
    [InlineData("lessThanOrEqual", FilterOperator.LessThanOrEqual)]
    [InlineData("like", FilterOperator.Like)]
    [InlineData("notLike", FilterOperator.NotLike)]
    [InlineData("isNull", FilterOperator.IsNull)]
    [InlineData("isNotNull", FilterOperator.IsNotNull)]
    [InlineData("between", FilterOperator.Between)]
    public void AddedOperators_DeserializeFromTheirSchemaNames(string wireName, FilterOperator expected)
    {
        var json = $"{{\"field\":\"f\",\"operator\":\"{wireName}\"}}";

        TolapJsonOptions.Deserialize<RowFilter>(json).Operator.Should().Be(expected);
    }

    [Fact]
    public void AddedOperators_DoNotChangeTheOrdinalOfAnExistingOperator()
    {
        // The wire form is the camelCase string, but an ordinal leaking into a persisted
        // policy or an interop boundary would silently repoint a filter at a different
        // operator if the members were reordered.
        ((int)FilterOperator.Equals).Should().Be(0);
        ((int)FilterOperator.NotEquals).Should().Be(1);
        ((int)FilterOperator.In).Should().Be(2);
        ((int)FilterOperator.NotIn).Should().Be(3);
        ((int)FilterOperator.GreaterThan).Should().Be(4);
        ((int)FilterOperator.LessThan).Should().Be(5);
        ((int)FilterOperator.Contains).Should().Be(6);
        ((int)FilterOperator.StartsWith).Should().Be(7);
        ((int)FilterOperator.Matches).Should().Be(8);
    }

    [Fact]
    public void AnUnknownOperatorName_IsRejected()
    {
        var act = () => TolapJsonOptions.Deserialize<RowFilter>(
            "{\"field\":\"f\",\"operator\":\"isNotNullish\"}");

        act.Should().Throw<JsonException>();
    }

    [Fact]
    public void AnUnrecognizedOperator_DropsEveryRow()
    {
        // An operator from a newer schema version reaches the default arm, which must fail
        // closed rather than admitting the row.
        Passes("region", "us-east", new RowFilter("region", (FilterOperator)9999, "us-east"))
            .Should().BeFalse();
    }
}
