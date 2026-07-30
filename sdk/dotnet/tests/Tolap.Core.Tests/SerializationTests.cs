using System.Text.Json;
using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

public class SerializationTests
{
    [Theory]
    [InlineData("policies/healthcare-analyst.json")]
    [InlineData("policies/api-readonly.json")]
    [InlineData("policies/kb-researcher.json")]
    [InlineData("policies/storage-analyst.json")]
    public void Deserialize_ValidPolicyFixture_ProducesValidPolicyDefinition(string fixturePath)
    {
        // Arrange
        var json = FixtureHelper.ReadFixture(fixturePath);

        // Act
        var policy = TolapJsonOptions.Deserialize<PolicyDefinition>(json);

        // Assert
        policy.Should().NotBeNull();
        policy.Version.Should().Be("1.0");
        policy.Name.Should().NotBeNullOrEmpty();
        policy.Permissions.Should().NotBeNull();
    }

    [Fact]
    public void Deserialize_HealthcareAnalyst_HasCorrectFields()
    {
        var policy = FixtureHelper.ReadFixtureAs<PolicyDefinition>("policies/healthcare-analyst.json");

        policy.Name.Should().Be("healthcare-analyst-db");
        policy.Priority.Should().Be(10);
        policy.Permissions.CanQuery.Should().BeTrue();
        policy.Permissions.ReadOnly.Should().BeTrue();
        policy.SourcePatterns.Should().Contain("db:production:patient_*");
        policy.ObjectRules.Should().NotBeNull();
        policy.ObjectRules!.AllowedObjects.Should().Contain("patients");
        policy.ObjectRules.HiddenObjects.Should().Contain("billing_internal");
        policy.ObjectRules.FieldRules.Should().NotBeNull();
        policy.ObjectRules.FieldRules!.MaskedFields.Should().HaveCount(2);
        policy.ObjectRules.FieldRules.MaskedFields![0].Field.Should().Be("patients.full_name");
        policy.ObjectRules.FieldRules.MaskedFields[0].MaskType.Should().Be(MaskType.Partial);
        policy.ObjectRules.FieldRules.MaskedFields[1].MaskType.Should().Be(MaskType.Hash);
        policy.ObjectRules.RowFilters.Should().HaveCount(2);
        policy.Limits.Should().NotBeNull();
        policy.Limits!.MaxResults.Should().Be(5000);
    }

    [Fact]
    public void Deserialize_ApiReadonly_HasEndpointRules()
    {
        var policy = FixtureHelper.ReadFixtureAs<PolicyDefinition>("policies/api-readonly.json");

        policy.Name.Should().Be("internal-api-readonly");
        policy.ObjectRules!.EndpointRules.Should().NotBeNull();
        policy.ObjectRules.EndpointRules!.AllowedEndpoints.Should().HaveCount(4);
        policy.ObjectRules.EndpointRules.HiddenEndpoints.Should().Contain("/api/v1/admin/*");
        policy.ObjectRules.EndpointRules.AllowedMethods.Should().Contain("GET");
    }

    [Fact]
    public void Deserialize_KbResearcher_HasTagRules()
    {
        var policy = FixtureHelper.ReadFixtureAs<PolicyDefinition>("policies/kb-researcher.json");

        policy.Name.Should().Be("research-kb-access");
        policy.ObjectRules!.TagRules.Should().NotBeNull();
        policy.ObjectRules.TagRules!.AllowedTags.Should().Contain("public");
        policy.ObjectRules.TagRules.DeniedTags.Should().Contain("classified");
        policy.Limits!.MinSimilarityScore.Should().Be(0.75);
    }

    [Fact]
    public void Deserialize_StorageAnalyst_HasObjectSizeLimit()
    {
        var policy = FixtureHelper.ReadFixtureAs<PolicyDefinition>("policies/storage-analyst.json");

        policy.Name.Should().Be("data-lake-analyst");
        policy.Limits!.MaxObjectSizeBytes.Should().Be(104857600);
    }

    [Fact]
    public void Deserialize_InvalidBadMaskType_ThrowsJsonException()
    {
        var json = FixtureHelper.ReadFixture("policies/invalid-bad-mask-type.json");

        var act = () => TolapJsonOptions.Deserialize<PolicyDefinition>(json);

        act.Should().Throw<JsonException>();
    }

    [Fact]
    public void Deserialize_InvalidMissingName_ProducesNullName()
    {
        // The JSON has no "name" field. Since PolicyDefinition requires Name in the constructor,
        // System.Text.Json will deserialize it with null (since Name is a string, not string?)
        // Actually, records with required constructor params will get default values
        var json = FixtureHelper.ReadFixture("policies/invalid-missing-name.json");

        // This should either throw or produce a policy with null/empty name
        var policy = TolapJsonOptions.Deserialize<PolicyDefinition>(json);
        policy.Name.Should().BeNullOrEmpty();
    }

    [Theory]
    [InlineData("policies/healthcare-analyst.json")]
    [InlineData("policies/api-readonly.json")]
    [InlineData("policies/kb-researcher.json")]
    [InlineData("policies/storage-analyst.json")]
    public void RoundTrip_SerializeDeserialize_PreservesStructure(string fixturePath)
    {
        // Arrange
        var original = FixtureHelper.ReadFixtureAs<PolicyDefinition>(fixturePath);

        // Act
        var json = TolapJsonOptions.Serialize(original);
        var roundTripped = TolapJsonOptions.Deserialize<PolicyDefinition>(json);

        // Assert
        roundTripped.Name.Should().Be(original.Name);
        roundTripped.Version.Should().Be(original.Version);
        roundTripped.Permissions.Should().Be(original.Permissions);
        roundTripped.Priority.Should().Be(original.Priority);
    }

    [Fact]
    public void Serialize_FilterOperator_ProducesSchemaValues()
    {
        var filter = new RowFilter("status", FilterOperator.NotEquals, "deleted");
        var json = TolapJsonOptions.Serialize(filter);

        json.Should().Contain("\"notEquals\"");
        json.Should().Contain("\"status\"");
    }

    [Fact]
    public void Serialize_MaskType_ProducesSchemaValues()
    {
        var rule = new MaskingRule("email", MaskType.Hash, new MaskingParameters(Algorithm: "sha256"));
        var json = TolapJsonOptions.Serialize(rule);

        json.Should().Contain("\"hash\"");
        json.Should().Contain("\"sha256\"");
    }

    [Fact]
    public void Deserialize_PolicyAssignment_FromFixture()
    {
        var assignment = FixtureHelper.ReadFixtureAs<PolicyAssignment>("assignments/user-direct.json");

        assignment.PolicyName.Should().Be("healthcare-analyst-db");
        assignment.Assignee.Type.Should().Be(AssigneeType.User);
        assignment.Assignee.Identifier.Should().Be("user-001");
        assignment.Scope.TenantId.Should().Be("tenant-midwest-health");
        assignment.Active.Should().BeTrue();
    }

    [Fact]
    public void Deserialize_GroupAssignment_FromFixture()
    {
        var assignment = FixtureHelper.ReadFixtureAs<PolicyAssignment>("assignments/group-assignment.json");

        assignment.Assignee.Type.Should().Be(AssigneeType.Group);
        assignment.Assignee.Identifier.Should().Be("research-analysts");
    }

    [Fact]
    public void Deserialize_TimeBoundAssignment_HasExpiresAt()
    {
        var assignment = FixtureHelper.ReadFixtureAs<PolicyAssignment>("assignments/time-bound.json");

        assignment.ExpiresAt.Should().NotBeNull();
        assignment.ExpiresAt!.Value.Year.Should().Be(2026);
    }

    [Fact]
    public void Deserialize_MultiScopeAssignment_HasSourceConnectionId()
    {
        var assignment = FixtureHelper.ReadFixtureAs<PolicyAssignment>("assignments/multi-scope.json");

        assignment.Scope.SourceConnectionId.Should().Be("ds-s3-datalake-prod");
        assignment.Assignee.Type.Should().Be(AssigneeType.Role);
    }
}
