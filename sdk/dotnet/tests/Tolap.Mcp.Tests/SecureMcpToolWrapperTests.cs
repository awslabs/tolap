using FluentAssertions;
using Tolap.Core;
using Tolap.Store;
using Xunit;

namespace Tolap.Mcp.Tests;

public class SecureMcpToolWrapperTests
{
    private static async Task<(InMemoryPolicyStore Store, SecureMcpToolWrapper Wrapper)> CreateTestSetup(
        EnforcementMode mode = EnforcementMode.Strict)
    {
        var store = new InMemoryPolicyStore();
        await store.CreatePolicyAsync(new PolicyDefinition(
            Version: "1.0",
            Name: "test-policy",
            Permissions: new PolicyPermissions(CanQuery: true, ReadOnly: true),
            Priority: 10,
            AppliesToAll: true,
            ObjectRules: new ObjectRules(
                AllowedObjects: new[] { "patients", "encounters" },
                HiddenObjects: new[] { "audit_log" },
                FieldRules: new FieldRules(
                    MaskedFields: new[]
                    {
                        new MaskingRule("ssn", MaskType.Null),
                        new MaskingRule("name", MaskType.Partial,
                            new MaskingParameters(ShowFirst: 1, ShowLast: 0))
                    }),
                TagRules: new TagRules(
                    AllowedTags: new[] { "public" },
                    DeniedTags: new[] { "classified" })),
            Limits: new PolicyLimits(MaxResults: 2)));

        await store.AssignPolicyAsync(new PolicyAssignment(
            Version: "1.0",
            PolicyName: "test-policy",
            Assignee: new Assignee(AssigneeType.User, "user-001"),
            Scope: new AssignmentScope(TenantId: "tenant-001"),
            Active: true,
            Audit: new AuditInfo("admin", DateTimeOffset.UtcNow, "Test")));

        var identityResolver = new StaticIdentityResolver();
        var options = new SecureMcpServerOptions(
            PolicyStore: store,
            IdentityResolver: identityResolver,
            IdentityExtractor: new HeaderIdentityExtractor(),
            SigningKey: "test-key",
            EnforcementMode: mode);

        var wrapper = new SecureMcpToolWrapper(options);
        return (store, wrapper);
    }

    private static Dictionary<string, string> CreateHeaders(
        string userId = "user-001",
        string tenantId = "tenant-001")
    {
        return new Dictionary<string, string>
        {
            ["X-Tolap-User-Id"] = userId,
            ["X-Tolap-Tenant-Id"] = tenantId
        };
    }

    [Fact]
    public async Task ExecuteWithEnforcement_AllowedObject_Succeeds()
    {
        var (_, wrapper) = await CreateTestSetup();
        var headers = CreateHeaders();

        // The test policy sets allowedTags: ["public"], and the single-record path runs
        // the same tag filter as the list path, so the record must carry an allowed tag.
        var result = await wrapper.ExecuteWithEnforcementAsync(
            headers, "query", "patients", "any-source",
            () => Task.FromResult<object?>(new Dictionary<string, object?>
            {
                ["id"] = "1",
                ["tags"] = new[] { "public" }
            }));

        result.Allowed.Should().BeTrue();
        result.Result.Should().NotBeNull();
    }

    [Fact]
    public async Task ExecuteWithEnforcement_HiddenObject_Denied()
    {
        var (_, wrapper) = await CreateTestSetup();
        var headers = CreateHeaders();

        var result = await wrapper.ExecuteWithEnforcementAsync(
            headers, "query", "audit_log", "any-source",
            () => Task.FromResult<object?>("should not execute"));

        result.Allowed.Should().BeFalse();
        result.DenialReason.Should().Contain("hidden");
    }

    [Fact]
    public async Task ExecuteWithEnforcement_NoPermission_Denied()
    {
        var (_, wrapper) = await CreateTestSetup();
        // Unknown user has no assignments -> deny-all
        var headers = CreateHeaders(userId: "unknown-user");

        var result = await wrapper.ExecuteWithEnforcementAsync(
            headers, "query", "patients", "any-source",
            () => Task.FromResult<object?>("should not execute"));

        result.Allowed.Should().BeFalse();
        result.DenialReason.Should().Contain("permission denied");
    }

    [Fact]
    public async Task ExecuteWithEnforcement_PermissiveMode_AllowsWithWarning()
    {
        var (_, wrapper) = await CreateTestSetup(EnforcementMode.Permissive);
        var headers = CreateHeaders();

        var result = await wrapper.ExecuteWithEnforcementAsync(
            headers, "query", "audit_log", "any-source",
            () => Task.FromResult<object?>("executed anyway"));

        result.Allowed.Should().BeTrue();
        result.DenialReason.Should().Contain("[permissive]");
    }

    [Fact]
    public async Task ExecuteWithEnforcement_RecordMasking_Applied()
    {
        var (_, wrapper) = await CreateTestSetup();
        var headers = CreateHeaders();

        var record = new Dictionary<string, object?>
        {
            ["name"] = "John Smith",
            ["ssn"] = "123-45-6789",
            ["region"] = "us-east",
            // The test policy sets allowedTags: ["public"]; the single-record path runs
            // the tag filter too, so an untagged record would be dropped.
            ["tags"] = new[] { "public" }
        };

        var result = await wrapper.ExecuteWithEnforcementAsync(
            headers, "query", "patients", "any-source",
            () => Task.FromResult<object?>(record));

        result.Allowed.Should().BeTrue();
        var maskedRecord = result.Result as Dictionary<string, object?>;
        maskedRecord.Should().NotBeNull();
        maskedRecord!["ssn"].Should().BeNull(); // null mask
        maskedRecord["name"].Should().NotBe("John Smith"); // partial mask
        maskedRecord["region"].Should().Be("us-east"); // untouched
    }

    [Fact]
    public async Task ValidateFieldsAsync_ReturnsCorrectResult()
    {
        var (_, wrapper) = await CreateTestSetup();
        var headers = CreateHeaders();

        // The test policy does not have allowedFields/hiddenFields explicitly,
        // so all fields should be allowed
        var result = await wrapper.ValidateFieldsAsync(
            headers, "any-source",
            new[] { "name", "region" });

        result.Allowed.Should().Contain("name");
        result.Allowed.Should().Contain("region");
    }
}
