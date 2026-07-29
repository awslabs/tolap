using System.Text.Json;
using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

public class PolicyMergerTests
{
    private static PolicyDefinition[] LoadMergeInputs(string fixturePath)
    {
        var root = FixtureHelper.ReadFixtureAsJson(fixturePath);
        var inputsJson = root.GetProperty("inputs").ToString();
        return TolapJsonOptions.Deserialize<PolicyDefinition[]>(inputsJson);
    }

    private static JsonElement LoadExpected(string fixturePath)
    {
        var root = FixtureHelper.ReadFixtureAsJson(fixturePath);
        return root.GetProperty("expected");
    }

    [Fact]
    public void Merge_EmptyList_ProducesDenyAll()
    {
        var inputs = LoadMergeInputs("merge-scenarios/empty-produces-deny-all.json");
        var expected = LoadExpected("merge-scenarios/empty-produces-deny-all.json");

        var result = PolicyMerger.Merge(inputs);

        result.SourceProfiles.Should().BeEmpty();
        result.Permissions.CanQuery.Should().BeFalse();
        result.Permissions.CanExport.Should().BeFalse();
        result.Permissions.ReadOnly.Should().BeTrue();
    }

    [Fact]
    public void Merge_SinglePolicy_PassesThrough()
    {
        var inputs = LoadMergeInputs("merge-scenarios/single-policy-passthrough.json");
        var expected = LoadExpected("merge-scenarios/single-policy-passthrough.json");

        var result = PolicyMerger.Merge(inputs);

        result.SourceProfiles.Should().BeEquivalentTo(new[] { "only-policy" });
        result.Permissions.CanQuery.Should().BeTrue();
        result.Permissions.CanExport.Should().BeTrue();
        result.Permissions.ReadOnly.Should().BeFalse();

        // Object rules
        result.ObjectRules.Should().NotBeNull();
        result.ObjectRules!.AllowedObjects.Should().BeEquivalentTo(new[] { "patients", "encounters" });
        result.ObjectRules.HiddenObjects.Should().BeEquivalentTo(new[] { "admin" });

        // Field rules
        result.ObjectRules.FieldRules.Should().NotBeNull();
        result.ObjectRules.FieldRules!.AllowedFields.Should().BeEquivalentTo(new[] { "name", "age" });
        result.ObjectRules.FieldRules.HiddenFields.Should().BeEquivalentTo(new[] { "ssn" });
        result.ObjectRules.FieldRules.MaskedFields.Should().HaveCount(1);
        result.ObjectRules.FieldRules.MaskedFields![0].Field.Should().Be("email");
        result.ObjectRules.FieldRules.MaskedFields[0].MaskType.Should().Be(MaskType.Hash);

        // Row filters
        result.ObjectRules.RowFilters.Should().HaveCount(1);
        result.ObjectRules.RowFilters![0].Field.Should().Be("region");

        // Tag rules
        result.ObjectRules.TagRules.Should().NotBeNull();
        result.ObjectRules.TagRules!.AllowedTags.Should().Contain("public");
        result.ObjectRules.TagRules.DeniedTags.Should().Contain("classified");

        // Endpoint rules
        result.ObjectRules.EndpointRules.Should().NotBeNull();
        result.ObjectRules.EndpointRules!.AllowedEndpoints.Should().Contain("/api/v1/patients");
        result.ObjectRules.EndpointRules.HiddenEndpoints.Should().Contain("/api/v1/admin/*");
        result.ObjectRules.EndpointRules.AllowedMethods.Should().BeEquivalentTo(new[] { "GET", "HEAD" });

        // Limits
        result.Limits.Should().NotBeNull();
        result.Limits!.MaxResults.Should().Be(1000);
        result.Limits.MaxQueryTimeSeconds.Should().Be(30);
        result.Limits.MinSimilarityScore.Should().Be(0.7);
        result.Limits.MaxObjectSizeBytes.Should().Be(52428800);
    }

    [Fact]
    public void Merge_CanQueryFalseWins_AndProducesFalse()
    {
        var inputs = LoadMergeInputs("merge-scenarios/can-query-false-wins.json");

        var result = PolicyMerger.Merge(inputs);

        result.SourceProfiles.Should().BeEquivalentTo(new[] { "policy-allows", "policy-denies" });
        result.Permissions.CanQuery.Should().BeFalse();
        result.Permissions.CanExport.Should().BeTrue();
        result.Permissions.ReadOnly.Should().BeFalse();
    }

    [Fact]
    public void Merge_IntersectionAllowedFields_ProducesCommonSubset()
    {
        var inputs = LoadMergeInputs("merge-scenarios/intersection-allowed-fields.json");

        var result = PolicyMerger.Merge(inputs);

        result.SourceProfiles.Should().BeEquivalentTo(new[] { "policy-a", "policy-b" });
        result.Permissions.CanQuery.Should().BeTrue();
        result.Permissions.CanExport.Should().BeFalse();
        result.Permissions.ReadOnly.Should().BeTrue();

        result.ObjectRules.Should().NotBeNull();
        result.ObjectRules!.AllowedObjects.Should().BeEquivalentTo(new[] { "patients", "medications" });
        result.ObjectRules.FieldRules.Should().NotBeNull();
        result.ObjectRules.FieldRules!.AllowedFields.Should().BeEquivalentTo(new[] { "name", "region", "diagnosis" });

        result.Limits!.MaxResults.Should().Be(1000);
    }

    [Fact]
    public void Merge_MaskedFieldsMostRestrictive_PicksHighestMaskType()
    {
        var inputs = LoadMergeInputs("merge-scenarios/masked-fields-most-restrictive.json");
        var expected = LoadExpected("merge-scenarios/masked-fields-most-restrictive.json");

        var result = PolicyMerger.Merge(inputs);

        result.SourceProfiles.Should().BeEquivalentTo(new[] { "policy-partial-mask", "policy-hash-mask" });
        result.ObjectRules.Should().NotBeNull();
        result.ObjectRules!.FieldRules.Should().NotBeNull();

        var maskedFields = result.ObjectRules.FieldRules!.MaskedFields!;
        maskedFields.Should().HaveCount(3);

        // Ranked by disclosure, most-restrictive-wins (canonical-enforcement-spec.md
        // section 6): null (5) > redact (4) > full (3) > hash (2) > partial (1). The
        // previous ranking placed null and redact *lowest*, so these assertions used to
        // expect partial to beat both -- disclosing real characters that one policy had
        // demanded be erased entirely.

        // email: hash (2) > partial (1) -> hash wins
        var emailMask = maskedFields.First(m => m.Field == "email");
        emailMask.MaskType.Should().Be(MaskType.Hash);
        emailMask.Parameters!.Algorithm.Should().Be("sha256");

        // phone: redact (4) > partial (1) -> redact wins
        var phoneMask = maskedFields.First(m => m.Field == "phone");
        phoneMask.MaskType.Should().Be(MaskType.Redact);

        // name: null (5) > partial (1) -> null wins
        var nameMask = maskedFields.First(m => m.Field == "name");
        nameMask.MaskType.Should().Be(MaskType.Null);
    }

    [Fact]
    public void Merge_MinMaxLimits_PicksMostRestrictive()
    {
        var inputs = LoadMergeInputs("merge-scenarios/min-max-limits.json");

        var result = PolicyMerger.Merge(inputs);

        result.SourceProfiles.Should().BeEquivalentTo(new[] { "policy-generous", "policy-strict" });
        result.Limits.Should().NotBeNull();
        result.Limits!.MaxResults.Should().Be(500); // min
        result.Limits.MaxQueryTimeSeconds.Should().Be(15); // min
        result.Limits.MinSimilarityScore.Should().Be(0.8); // max
        result.Limits.MaxObjectSizeBytes.Should().Be(52428800); // min
    }

    [Fact]
    public void Merge_RowFiltersConcatenate_AllPresent()
    {
        var inputs = LoadMergeInputs("merge-scenarios/row-filters-concatenate.json");

        var result = PolicyMerger.Merge(inputs);

        result.SourceProfiles.Should().BeEquivalentTo(new[] { "policy-region", "policy-status" });
        result.ObjectRules.Should().NotBeNull();
        result.ObjectRules!.RowFilters.Should().HaveCount(3);

        result.ObjectRules.RowFilters![0].Field.Should().Be("region");
        result.ObjectRules.RowFilters[0].Operator.Should().Be(FilterOperator.In);

        result.ObjectRules.RowFilters[1].Field.Should().Be("status");
        result.ObjectRules.RowFilters[1].Operator.Should().Be(FilterOperator.NotEquals);

        result.ObjectRules.RowFilters[2].Field.Should().Be("created_at");
        result.ObjectRules.RowFilters[2].Operator.Should().Be(FilterOperator.GreaterThan);
    }

    [Fact]
    public void Merge_HiddenWinsOverAllowed_UnionOfHiddenSets()
    {
        var inputs = LoadMergeInputs("merge-scenarios/hidden-wins-over-allowed.json");

        var result = PolicyMerger.Merge(inputs);

        result.SourceProfiles.Should().BeEquivalentTo(new[] { "policy-permissive", "policy-restrictive" });
        result.ObjectRules.Should().NotBeNull();
        result.ObjectRules!.HiddenObjects.Should().BeEquivalentTo(new[] { "audit_log" });

        // allowedFields is from the only policy that specifies them
        result.ObjectRules.FieldRules.Should().NotBeNull();
        result.ObjectRules.FieldRules!.AllowedFields.Should()
            .BeEquivalentTo(new[] { "name", "email", "ssn", "region" });

        // hiddenFields is the union from the policy that specifies them
        result.ObjectRules.FieldRules.HiddenFields.Should()
            .BeEquivalentTo(new[] { "ssn", "date_of_birth" });
    }
}
