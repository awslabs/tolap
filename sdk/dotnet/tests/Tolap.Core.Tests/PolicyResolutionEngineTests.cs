using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

public class PolicyResolutionEngineTests
{
    private static readonly PolicyDefinition HealthcarePolicy = new(
        Version: "1.0",
        Name: "healthcare-analyst-db",
        Permissions: new PolicyPermissions(CanQuery: true, ReadOnly: true),
        Priority: 10,
        AppliesToAll: false,
        SourcePatterns: new[] { "db:production:patient_*", "db:production:encounter_*" },
        ObjectRules: new ObjectRules(
            AllowedObjects: new[] { "patients", "encounters" },
            HiddenObjects: new[] { "audit_log" }));

    private static readonly PolicyDefinition ApiPolicy = new(
        Version: "1.0",
        Name: "internal-api-readonly",
        Permissions: new PolicyPermissions(CanQuery: true, ReadOnly: true),
        Priority: 20,
        AppliesToAll: false,
        SourcePatterns: new[] { "api:internal:*" });

    [Fact]
    public void Resolve_DirectUserAssignment_ProducesEffectivePolicy()
    {
        var assignments = new[]
        {
            new PolicyAssignment(
                Version: "1.0",
                PolicyName: "healthcare-analyst-db",
                Assignee: new Assignee(AssigneeType.User, "user-001"),
                Scope: new AssignmentScope(TenantId: "tenant-midwest-health"),
                Active: true,
                Audit: new AuditInfo("admin", DateTimeOffset.UtcNow, "Test"))
        };

        var definitions = new[] { HealthcarePolicy, ApiPolicy };

        var result = PolicyResolutionEngine.Resolve(
            userId: "user-001",
            tenantId: "tenant-midwest-health",
            sourceConnectionId: "db:production:patient_records",
            assignments: assignments,
            definitions: definitions,
            getGroups: _ => Array.Empty<string>(),
            getRoles: _ => Array.Empty<string>());

        result.Permissions.CanQuery.Should().BeTrue();
        result.SourceProfiles.Should().Contain("healthcare-analyst-db");
        result.UserId.Should().Be("user-001");
        result.TenantId.Should().Be("tenant-midwest-health");
        result.SourceConnectionId.Should().Be("db:production:patient_records");
    }

    [Fact]
    public void Resolve_GroupAssignment_MatchesGroupMember()
    {
        var assignments = new[]
        {
            new PolicyAssignment(
                Version: "1.0",
                PolicyName: "internal-api-readonly",
                Assignee: new Assignee(AssigneeType.Group, "research-analysts"),
                Scope: new AssignmentScope(TenantId: "tenant-midwest-health"),
                Active: true,
                Audit: new AuditInfo("admin", DateTimeOffset.UtcNow, "Test"))
        };

        var definitions = new[] { HealthcarePolicy, ApiPolicy };

        var result = PolicyResolutionEngine.Resolve(
            userId: "user-001",
            tenantId: "tenant-midwest-health",
            sourceConnectionId: "api:internal:patient-api",
            assignments: assignments,
            definitions: definitions,
            getGroups: _ => new[] { "research-analysts" },
            getRoles: _ => Array.Empty<string>());

        result.Permissions.CanQuery.Should().BeTrue();
        result.SourceProfiles.Should().Contain("internal-api-readonly");
    }

    [Fact]
    public void Resolve_RoleAssignment_MatchesRoleHolder()
    {
        var assignments = new[]
        {
            new PolicyAssignment(
                Version: "1.0",
                PolicyName: "healthcare-analyst-db",
                Assignee: new Assignee(AssigneeType.Role, "data-analyst"),
                Scope: new AssignmentScope(TenantId: "tenant-midwest-health"),
                Active: true,
                Audit: new AuditInfo("admin", DateTimeOffset.UtcNow, "Test"))
        };

        var definitions = new[] { HealthcarePolicy };

        var result = PolicyResolutionEngine.Resolve(
            userId: "user-001",
            tenantId: "tenant-midwest-health",
            sourceConnectionId: "db:production:patient_records",
            assignments: assignments,
            definitions: definitions,
            getGroups: _ => Array.Empty<string>(),
            getRoles: _ => new[] { "data-analyst" });

        result.Permissions.CanQuery.Should().BeTrue();
        result.SourceProfiles.Should().Contain("healthcare-analyst-db");
    }

    [Fact]
    public void Resolve_InactiveAssignment_IsIgnored()
    {
        var assignments = new[]
        {
            new PolicyAssignment(
                Version: "1.0",
                PolicyName: "healthcare-analyst-db",
                Assignee: new Assignee(AssigneeType.User, "user-001"),
                Scope: new AssignmentScope(TenantId: "tenant-midwest-health"),
                Active: false,
                Audit: new AuditInfo("admin", DateTimeOffset.UtcNow, "Deactivated"))
        };

        var definitions = new[] { HealthcarePolicy };

        var result = PolicyResolutionEngine.Resolve(
            userId: "user-001",
            tenantId: "tenant-midwest-health",
            sourceConnectionId: "db:production:patient_records",
            assignments: assignments,
            definitions: definitions,
            getGroups: _ => Array.Empty<string>(),
            getRoles: _ => Array.Empty<string>());

        result.Permissions.CanQuery.Should().BeFalse();
        result.SourceProfiles.Should().BeEmpty();
    }

    [Fact]
    public void Resolve_ExpiredAssignment_IsIgnored()
    {
        var assignments = new[]
        {
            new PolicyAssignment(
                Version: "1.0",
                PolicyName: "healthcare-analyst-db",
                Assignee: new Assignee(AssigneeType.User, "user-001"),
                Scope: new AssignmentScope(TenantId: "tenant-midwest-health"),
                Active: true,
                Audit: new AuditInfo("admin", DateTimeOffset.UtcNow, "Expired"),
                ExpiresAt: DateTimeOffset.UtcNow - TimeSpan.FromHours(1))
        };

        var definitions = new[] { HealthcarePolicy };

        var result = PolicyResolutionEngine.Resolve(
            userId: "user-001",
            tenantId: "tenant-midwest-health",
            sourceConnectionId: "db:production:patient_records",
            assignments: assignments,
            definitions: definitions,
            getGroups: _ => Array.Empty<string>(),
            getRoles: _ => Array.Empty<string>());

        result.Permissions.CanQuery.Should().BeFalse();
        result.SourceProfiles.Should().BeEmpty();
    }

    [Fact]
    public void Resolve_WrongTenant_IsIgnored()
    {
        var assignments = new[]
        {
            new PolicyAssignment(
                Version: "1.0",
                PolicyName: "healthcare-analyst-db",
                Assignee: new Assignee(AssigneeType.User, "user-001"),
                Scope: new AssignmentScope(TenantId: "tenant-other"),
                Active: true,
                Audit: new AuditInfo("admin", DateTimeOffset.UtcNow, "Test"))
        };

        var definitions = new[] { HealthcarePolicy };

        var result = PolicyResolutionEngine.Resolve(
            userId: "user-001",
            tenantId: "tenant-midwest-health",
            sourceConnectionId: "db:production:patient_records",
            assignments: assignments,
            definitions: definitions,
            getGroups: _ => Array.Empty<string>(),
            getRoles: _ => Array.Empty<string>());

        result.Permissions.CanQuery.Should().BeFalse();
    }

    [Fact]
    public void Resolve_SourcePatternMismatch_IsIgnored()
    {
        var assignments = new[]
        {
            new PolicyAssignment(
                Version: "1.0",
                PolicyName: "healthcare-analyst-db",
                Assignee: new Assignee(AssigneeType.User, "user-001"),
                Scope: new AssignmentScope(TenantId: "tenant-midwest-health"),
                Active: true,
                Audit: new AuditInfo("admin", DateTimeOffset.UtcNow, "Test"))
        };

        var definitions = new[] { HealthcarePolicy };

        // Source doesn't match the policy's source patterns
        var result = PolicyResolutionEngine.Resolve(
            userId: "user-001",
            tenantId: "tenant-midwest-health",
            sourceConnectionId: "api:internal:some-api",
            assignments: assignments,
            definitions: definitions,
            getGroups: _ => Array.Empty<string>(),
            getRoles: _ => Array.Empty<string>());

        result.Permissions.CanQuery.Should().BeFalse();
    }

    [Fact]
    public void Resolve_NoAssignments_ProducesDenyAll()
    {
        var result = PolicyResolutionEngine.Resolve(
            userId: "user-001",
            tenantId: "tenant-midwest-health",
            sourceConnectionId: "db:production:patient_records",
            assignments: Array.Empty<PolicyAssignment>(),
            definitions: new[] { HealthcarePolicy },
            getGroups: _ => Array.Empty<string>(),
            getRoles: _ => Array.Empty<string>());

        result.Permissions.CanQuery.Should().BeFalse();
        result.SourceProfiles.Should().BeEmpty();
    }

    [Fact]
    public void Resolve_MultipleMatchingPolicies_MergesCorrectly()
    {
        var exportPolicy = new PolicyDefinition(
            Version: "1.0",
            Name: "export-allowed",
            Permissions: new PolicyPermissions(CanQuery: true, ReadOnly: true),
            Priority: 20,
            AppliesToAll: true);

        var assignments = new[]
        {
            new PolicyAssignment(
                Version: "1.0",
                PolicyName: "healthcare-analyst-db",
                Assignee: new Assignee(AssigneeType.User, "user-001"),
                Scope: new AssignmentScope(TenantId: "tenant-midwest-health"),
                Active: true,
                Audit: new AuditInfo("admin", DateTimeOffset.UtcNow, "Test")),
            new PolicyAssignment(
                Version: "1.0",
                PolicyName: "export-allowed",
                Assignee: new Assignee(AssigneeType.User, "user-001"),
                Scope: new AssignmentScope(TenantId: "tenant-midwest-health"),
                Active: true,
                Audit: new AuditInfo("admin", DateTimeOffset.UtcNow, "Test"))
        };

        var definitions = new[] { HealthcarePolicy, exportPolicy };

        var result = PolicyResolutionEngine.Resolve(
            userId: "user-001",
            tenantId: "tenant-midwest-health",
            sourceConnectionId: "db:production:patient_records",
            assignments: assignments,
            definitions: definitions,
            getGroups: _ => Array.Empty<string>(),
            getRoles: _ => Array.Empty<string>());

        result.SourceProfiles.Should().HaveCount(2);
        result.Permissions.CanQuery.Should().BeTrue();
    }

    [Fact]
    public void GlobMatch_WildcardPattern_MatchesCorrectly()
    {
        PolicyResolutionEngine.GlobMatch("db:production:patient_*", "db:production:patient_records")
            .Should().BeTrue();

        PolicyResolutionEngine.GlobMatch("db:production:patient_*", "db:production:encounter_records")
            .Should().BeFalse();

        PolicyResolutionEngine.GlobMatch("api:internal:*", "api:internal:patient-api")
            .Should().BeTrue();

        PolicyResolutionEngine.GlobMatch("api:internal:*", "api:external:patient-api")
            .Should().BeFalse();
    }
}
