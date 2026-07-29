using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// Regression tests for the enforcement defects closed against
/// docs/canonical-enforcement-spec.md. Each test fails on the pre-fix code.
/// </summary>
public class EnforcementRegressionTests
{
    private static EffectivePolicy Policy(
        ObjectRules? objectRules = null,
        PolicyLimits? limits = null)
        => new(
            Version: "1.0", UserId: null, TenantId: null, SourceConnectionId: null,
            ResolvedAt: null, ExpiresAt: null,
            SourceProfiles: Array.Empty<string>(),
            Permissions: new PolicyPermissions(CanQuery: true),
            ObjectRules: objectRules,
            Limits: limits);

    // -- Defect 1: hiddenFields never stripped from results --

    [Fact]
    public void StripHiddenFields_RemovesHiddenKeysFromRecord()
    {
        var policy = Policy(new ObjectRules(
            FieldRules: new FieldRules(HiddenFields: new[] { "patients.ssn" })));

        var record = new Dictionary<string, object?>
        {
            ["id"] = 1,
            ["ssn"] = "123-45-6789"
        };

        var stripped = EnforcementEngine.StripHiddenFields(record, policy);

        // Bare<->dotted matching in both directions: the rule "patients.ssn" must
        // reach the bare key "ssn".
        stripped.Should().NotContainKey("ssn");
        stripped.Should().ContainKey("id");
        // The caller's record is left intact.
        record.Should().ContainKey("ssn");
    }

    [Fact]
    public void StripHiddenFields_MatchesBareRuleAgainstQualifiedKey()
    {
        var policy = Policy(new ObjectRules(
            FieldRules: new FieldRules(HiddenFields: new[] { "SSN" })));

        var record = new Dictionary<string, object?> { ["patients.ssn"] = "123-45-6789" };

        EnforcementEngine.StripHiddenFields(record, policy).Should().BeEmpty();
    }

    [Fact]
    public void StripHiddenFields_RecursesIntoNestedStructures()
    {
        var policy = Policy(new ObjectRules(
            FieldRules: new FieldRules(HiddenFields: new[] { "ssn" })));

        var record = new Dictionary<string, object?>
        {
            ["patient"] = new Dictionary<string, object?> { ["ssn"] = "111-11-1111" },
            ["contacts"] = new List<object?>
            {
                new Dictionary<string, object?> { ["ssn"] = "222-22-2222", ["name"] = "Ann" }
            }
        };

        var stripped = EnforcementEngine.StripHiddenFields(record, policy);

        ((Dictionary<string, object?>)stripped["patient"]!).Should().NotContainKey("ssn");
        var contacts = (List<object?>)stripped["contacts"]!;
        ((Dictionary<string, object?>)contacts[0]!).Should().NotContainKey("ssn");
        ((Dictionary<string, object?>)contacts[0]!).Should().ContainKey("name");
    }

    [Fact]
    public void ApplyRecordPipeline_HiddenBeatsMasked_FieldIsRemovedNotMasked()
    {
        // Ordering rationale from spec section 4: hidden removal precedes masking so a
        // field that is both hidden and masked is removed rather than returned masked.
        var policy = Policy(new ObjectRules(
            FieldRules: new FieldRules(
                HiddenFields: new[] { "ssn" },
                MaskedFields: new[] { new MaskingRule("ssn", MaskType.Hash) })));

        var rows = new List<Dictionary<string, object?>>
        {
            new() { ["id"] = 1, ["ssn"] = "123-45-6789" }
        };

        var result = EnforcementEngine.ApplyRecordPipeline(rows, policy);

        result[0].Should().NotContainKey("ssn");
    }

    // -- Defect 2: allowedFields never enforced on results --

    [Fact]
    public void ProjectAllowedFields_DropsUndeclaredColumns()
    {
        // A pre-execution field check only inspects the fields a caller volunteers, so a
        // tool returning undeclared columns (SELECT *) would otherwise leak them.
        var policy = Policy(new ObjectRules(
            FieldRules: new FieldRules(AllowedFields: new[] { "patients.id", "patients.region" })));

        var record = new Dictionary<string, object?>
        {
            ["id"] = 1,
            ["region"] = "us-east",
            ["ssn"] = "123-45-6789",
            ["email"] = "a@example.com"
        };

        var projected = EnforcementEngine.ProjectAllowedFields(record, policy);

        projected.Keys.Should().BeEquivalentTo(new[] { "id", "region" });
    }

    [Fact]
    public void ProjectAllowedFields_NullAllowListIsUnrestricted()
    {
        var policy = Policy(new ObjectRules(FieldRules: new FieldRules(AllowedFields: null)));
        var record = new Dictionary<string, object?> { ["ssn"] = "123-45-6789" };

        EnforcementEngine.ProjectAllowedFields(record, policy).Should().ContainKey("ssn");
    }

    [Fact]
    public void ProjectAllowedFields_EmptyAllowListDeniesEveryField()
    {
        // Spec section 3: [] is "deny everything", not "no restriction".
        var policy = Policy(new ObjectRules(
            FieldRules: new FieldRules(AllowedFields: Array.Empty<string>())));
        var record = new Dictionary<string, object?> { ["ssn"] = "123-45-6789" };

        EnforcementEngine.ProjectAllowedFields(record, policy).Should().BeEmpty();
    }

    // -- Defect 3: result-shape bypass --

    [Theory]
    [InlineData("a scalar string")]
    [InlineData(42)]
    [InlineData(true)]
    public void ClassifyResultShape_Scalars_AreUnenforceable(object scalar)
    {
        EnforcementEngine.ClassifyResultShape(scalar).Should().Be(ResultShape.Unenforceable);
    }

    [Fact]
    public void ClassifyResultShape_Poco_IsUnenforceable()
    {
        EnforcementEngine.ClassifyResultShape(new PatientDto("1", "123-45-6789"))
            .Should().Be(ResultShape.Unenforceable);
    }

    [Fact]
    public void ClassifyResultShape_UnmaterializedEnumerable_IsUnenforceable()
    {
        // A lazy sequence cannot be enforced: enumerating it here is a side effect and
        // the caller could enumerate the unfiltered original again.
        IEnumerable<Dictionary<string, object?>> lazy = LazyRows();

        EnforcementEngine.ClassifyResultShape(lazy).Should().Be(ResultShape.Unenforceable);
    }

    [Fact]
    public void ClassifyResultShape_RecordAndRecordList_AreEnforceable()
    {
        EnforcementEngine.ClassifyResultShape(new Dictionary<string, object?>())
            .Should().Be(ResultShape.Record);
        EnforcementEngine.ClassifyResultShape(new List<Dictionary<string, object?>>())
            .Should().Be(ResultShape.RecordList);
    }

    [Fact]
    public void ApplyResultPipeline_UnenforceableShape_ThrowsWithActionableMessage()
    {
        var act = () => EnforcementEngine.ApplyResultPipeline(
            new PatientDto("1", "123-45-6789"), Policy());

        act.Should().Throw<UnenforceableResultException>()
            .WithMessage("*PatientDto*")
            .WithMessage("*AllowUnenforceableShapes*");
    }

    [Fact]
    public void ApplyResultPipeline_SingleRecord_RunsRowFiltersNotJustMasking()
    {
        // Spec section 4 "Single records": a get-by-id tool must not skip row filters.
        var policy = Policy(new ObjectRules(
            RowFilters: new[] { new RowFilter("region", FilterOperator.Equals, "us-east") }));

        var excluded = new Dictionary<string, object?> { ["id"] = 1, ["region"] = "eu-west" };

        EnforcementEngine.ApplyResultPipeline(excluded, policy).Should().BeNull();
    }

    [Fact]
    public void ApplyResultPipeline_SingleRecord_RunsTagFilters()
    {
        // A deniedTags record returned by a get-by-id tool must not be disclosed.
        var policy = Policy(new ObjectRules(
            TagRules: new TagRules(DeniedTags: new[] { "classified" })));

        var classified = new Dictionary<string, object?>
        {
            ["id"] = 1,
            ["tags"] = new[] { "classified" }
        };

        EnforcementEngine.ApplyResultPipeline(classified, policy).Should().BeNull();
    }

    [Fact]
    public void ApplyResultPipeline_SingleRecord_StripsHiddenAndProjectsAllowed()
    {
        var policy = Policy(new ObjectRules(
            FieldRules: new FieldRules(
                AllowedFields: new[] { "id", "region", "ssn" },
                HiddenFields: new[] { "ssn" })));

        var record = new Dictionary<string, object?>
        {
            ["id"] = 1,
            ["region"] = "us-east",
            ["ssn"] = "123-45-6789",
            ["email"] = "a@example.com"
        };

        var result = (Dictionary<string, object?>)EnforcementEngine.ApplyResultPipeline(record, policy)!;

        result.Keys.Should().BeEquivalentTo(new[] { "id", "region" });
    }

    [Fact]
    public void ApplyResultPipeline_ObjectArrayOfRecords_IsEnforced()
    {
        // object[] never reached the old exact-type checks and passed through unfiltered.
        var policy = Policy(new ObjectRules(
            FieldRules: new FieldRules(HiddenFields: new[] { "ssn" })));

        object?[] rows =
        {
            new Dictionary<string, object?> { ["id"] = 1, ["ssn"] = "123-45-6789" }
        };

        var result = (IReadOnlyList<Dictionary<string, object?>>)
            EnforcementEngine.ApplyResultPipeline(rows, policy)!;

        result[0].Should().NotContainKey("ssn");
    }

    // -- Defect 6: mask restrictiveness ranking --

    [Fact]
    public void MaskRestrictiveness_NullAndRedactBeatPartialAndHash()
    {
        // Ranked by how much of the original value is disclosed (spec section 6).
        MaskType.Null.Restrictiveness().Should().BeGreaterThan(MaskType.Redact.Restrictiveness());
        MaskType.Redact.Restrictiveness().Should().BeGreaterThan(MaskType.Full.Restrictiveness());
        MaskType.Full.Restrictiveness().Should().BeGreaterThan(MaskType.Hash.Restrictiveness());
        MaskType.Hash.Restrictiveness().Should().BeGreaterThan(MaskType.Partial.Restrictiveness());
    }

    [Fact]
    public void ApplyFieldMasking_OverlappingRules_MostRestrictiveWins()
    {
        var policy = Policy(new ObjectRules(
            FieldRules: new FieldRules(MaskedFields: new[]
            {
                new MaskingRule("ssn", MaskType.Partial, new MaskingParameters(ShowLast: 4)),
                new MaskingRule("ssn", MaskType.Null)
            })));

        var masked = EnforcementEngine.ApplyFieldMasking(
            new Dictionary<string, object?> { ["ssn"] = "123-45-6789" }, policy);

        masked["ssn"].Should().BeNull();
    }

    // -- Defect 7: unknown maskType / partial-mask degradation --

    [Fact]
    public void ApplyMask_UnknownMaskType_RedactsInsteadOfReturningRawValue()
    {
        // A typo or a mask type from a newer schema version must not silently disable
        // masking (spec section 6).
        var rule = new MaskingRule("ssn", (MaskType)999);

        EnforcementEngine.ApplyMask("123-45-6789", rule).Should().Be("[REDACTED]");
    }

    [Fact]
    public void ApplyPartialMask_ShowFirstPlusShowLastCoversValue_DegradesToFullMask()
    {
        var policy = Policy(new ObjectRules(
            FieldRules: new FieldRules(MaskedFields: new[]
            {
                new MaskingRule("region", MaskType.Partial,
                    new MaskingParameters(ShowFirst: 100, ShowLast: 100))
            })));

        var masked = EnforcementEngine.ApplyFieldMasking(
            new Dictionary<string, object?> { ["region"] = "us-east" }, policy);

        masked["region"].Should().Be("*******");
    }

    // -- Defect 8: notEquals/notIn fail open on a missing field --

    [Fact]
    public void ApplyRowFilters_NotEqualsOnMissingField_DropsRow()
    {
        // Previously "undefined != x" was true, so a filter written to exclude
        // classified rows retained every row that simply lacked the column.
        var policy = Policy(new ObjectRules(
            RowFilters: new[] { new RowFilter("classification", FilterOperator.NotEquals, "secret") }));

        var rows = new List<Dictionary<string, object?>> { new() { ["id"] = 1 } };

        EnforcementEngine.ApplyRowFilters(rows, policy).Should().BeEmpty();
    }

    [Fact]
    public void ApplyRowFilters_NotInOnMissingField_DropsRow()
    {
        var policy = Policy(new ObjectRules(
            RowFilters: new[]
            {
                new RowFilter("classification", FilterOperator.NotIn, Values: new object[] { "secret" })
            }));

        var rows = new List<Dictionary<string, object?>> { new() { ["id"] = 1 } };

        EnforcementEngine.ApplyRowFilters(rows, policy).Should().BeEmpty();
    }

    [Fact]
    public void ApplyRowFilters_NotEqualsOnPresentNull_IsStillComparable()
    {
        // "Field absent" fails closed, but an explicit null is a real value that the
        // negative operators must still be able to compare against.
        var policy = Policy(new ObjectRules(
            RowFilters: new[] { new RowFilter("classification", FilterOperator.NotEquals, "secret") }));

        var rows = new List<Dictionary<string, object?>>
        {
            new() { ["id"] = 1, ["classification"] = null }
        };

        EnforcementEngine.ApplyRowFilters(rows, policy).Should().HaveCount(1);
    }

    // -- Defect 10: ReDoS timeout and non-capturing anchor group --

    [Fact]
    public void ApplyRowFilters_MatchesAnchorsWithNonCapturingGroup()
    {
        // "^hr|finance$" would otherwise bind ^ to "hr" alone and match
        // "hr_secret_internal" (spec section 7).
        var policy = Policy(new ObjectRules(
            RowFilters: new[] { new RowFilter("dept", FilterOperator.Matches, "hr|finance") }));

        var rows = new List<Dictionary<string, object?>>
        {
            new() { ["id"] = 1, ["dept"] = "hr_secret_internal" },
            new() { ["id"] = 2, ["dept"] = "hr" }
        };

        var kept = EnforcementEngine.ApplyRowFilters(rows, policy);

        kept.Should().HaveCount(1);
        kept[0]["id"].Should().Be(2);
    }

    [Fact]
    public void ApplyRowFilters_CatastrophicRegex_IsNonMatchNotAnException()
    {
        // A pathological pattern must be bounded and treated as a non-match; it must
        // never throw out of the result pass.
        var policy = Policy(new ObjectRules(
            RowFilters: new[]
            {
                new RowFilter("dept", FilterOperator.Matches, "(a+)+$")
            }));

        var rows = new List<Dictionary<string, object?>>
        {
            new() { ["id"] = 1, ["dept"] = new string('a', 40) + "!" }
        };

        var act = () => EnforcementEngine.ApplyRowFilters(rows, policy);

        act.Should().NotThrow();
        act().Should().BeEmpty();
    }

    [Fact]
    public void ApplyRowFilters_InvalidRegex_IsNonMatchNotAnException()
    {
        var policy = Policy(new ObjectRules(
            RowFilters: new[] { new RowFilter("dept", FilterOperator.Matches, "([unclosed") }));

        var rows = new List<Dictionary<string, object?>> { new() { ["dept"] = "hr" } };

        var act = () => EnforcementEngine.ApplyRowFilters(rows, policy);

        act.Should().NotThrow();
        act().Should().BeEmpty();
    }

    // -- Defect 12: numeric comparison type mismatch --

    [Fact]
    public void ApplyRowFilters_GreaterThanWithNonComparableOperands_DropsRowWithoutThrowing()
    {
        var policy = Policy(new ObjectRules(
            RowFilters: new[] { new RowFilter("age", FilterOperator.GreaterThan, 30) }));

        var rows = new List<Dictionary<string, object?>>
        {
            new() { ["id"] = 1, ["age"] = "notanumber" }
        };

        var act = () => EnforcementEngine.ApplyRowFilters(rows, policy);

        act.Should().NotThrow();
        act().Should().BeEmpty();
    }

    [Fact]
    public void ApplyRowFilters_EqualsDoesNotConflateBoolWithNumber()
    {
        // 1 != true (spec section 7).
        var policy = Policy(new ObjectRules(
            RowFilters: new[] { new RowFilter("flag", FilterOperator.Equals, 1) }));

        var rows = new List<Dictionary<string, object?>>
        {
            new() { ["id"] = 1, ["flag"] = true },
            new() { ["id"] = 2, ["flag"] = 1 }
        };

        var kept = EnforcementEngine.ApplyRowFilters(rows, policy);

        kept.Should().HaveCount(1);
        kept[0]["id"].Should().Be(2);
    }

    [Fact]
    public void ApplyRowFilters_LessThanWithBooleanOperand_DropsRow()
    {
        var policy = Policy(new ObjectRules(
            RowFilters: new[] { new RowFilter("flag", FilterOperator.LessThan, 5) }));

        var rows = new List<Dictionary<string, object?>> { new() { ["flag"] = true } };

        EnforcementEngine.ApplyRowFilters(rows, policy).Should().BeEmpty();
    }

    // -- Full pipeline ordering --

    [Fact]
    public void ApplyRecordPipeline_LimitAppliesAfterFiltering()
    {
        // The limit runs last so filtering never yields fewer rows than maxResults when
        // more qualifying rows exist (spec section 4).
        var policy = Policy(
            new ObjectRules(
                RowFilters: new[] { new RowFilter("region", FilterOperator.Equals, "us-east") }),
            new PolicyLimits(MaxResults: 2));

        var rows = new List<Dictionary<string, object?>>
        {
            new() { ["id"] = 1, ["region"] = "eu-west" },
            new() { ["id"] = 2, ["region"] = "us-east" },
            new() { ["id"] = 3, ["region"] = "eu-west" },
            new() { ["id"] = 4, ["region"] = "us-east" },
            new() { ["id"] = 5, ["region"] = "us-east" }
        };

        var result = EnforcementEngine.ApplyRecordPipeline(rows, policy);

        result.Should().HaveCount(2);
        result.Select(r => r["id"]).Should().BeEquivalentTo(new object[] { 2, 4 });
    }

    private static IEnumerable<Dictionary<string, object?>> LazyRows()
    {
        yield return new Dictionary<string, object?> { ["ssn"] = "123-45-6789" };
    }

    private sealed record PatientDto(string Id, string Ssn);
}
