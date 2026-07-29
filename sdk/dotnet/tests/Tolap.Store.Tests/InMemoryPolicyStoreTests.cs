using FluentAssertions;
using Tolap.Core;
using Xunit;

namespace Tolap.Store.Tests;

public class InMemoryPolicyStoreTests
{
    private static PolicyDefinition CreateTestPolicy(string name = "test-policy")
    {
        return new PolicyDefinition(
            Version: "1.0",
            Name: name,
            Permissions: new PolicyPermissions(CanQuery: true, CanExport: false, ReadOnly: true),
            Priority: 10,
            AppliesToAll: true);
    }

    private static PolicyAssignment CreateTestAssignment(
        string policyName = "test-policy",
        AssigneeType assigneeType = AssigneeType.User,
        string identifier = "user-001",
        string tenantId = "tenant-001")
    {
        return new PolicyAssignment(
            Version: "1.0",
            PolicyName: policyName,
            Assignee: new Assignee(assigneeType, identifier),
            Scope: new AssignmentScope(TenantId: tenantId),
            Active: true,
            Audit: new AuditInfo("admin", DateTimeOffset.UtcNow, "Test assignment"));
    }

    // -- CRUD Operations --

    [Fact]
    public async Task CreatePolicy_Success()
    {
        var store = new InMemoryPolicyStore();
        var policy = CreateTestPolicy();

        var result = await store.CreatePolicyAsync(policy);

        result.Should().Be(policy);
    }

    [Fact]
    public async Task CreatePolicy_Duplicate_Throws()
    {
        var store = new InMemoryPolicyStore();
        var policy = CreateTestPolicy();
        await store.CreatePolicyAsync(policy);

        var act = () => store.CreatePolicyAsync(policy);

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*already exists*");
    }

    [Fact]
    public async Task GetPolicy_Existing_ReturnsPolicy()
    {
        var store = new InMemoryPolicyStore();
        var policy = CreateTestPolicy();
        await store.CreatePolicyAsync(policy);

        var result = await store.GetPolicyAsync("test-policy");

        result.Should().Be(policy);
    }

    [Fact]
    public async Task GetPolicy_NonExistent_ReturnsNull()
    {
        var store = new InMemoryPolicyStore();

        var result = await store.GetPolicyAsync("nonexistent");

        result.Should().BeNull();
    }

    [Fact]
    public async Task UpdatePolicy_Existing_UpdatesSuccessfully()
    {
        var store = new InMemoryPolicyStore();
        var policy = CreateTestPolicy();
        await store.CreatePolicyAsync(policy);

        var updated = policy with { Description = "Updated description" };
        var result = await store.UpdatePolicyAsync(updated);

        result.Description.Should().Be("Updated description");

        var fetched = await store.GetPolicyAsync("test-policy");
        fetched!.Description.Should().Be("Updated description");
    }

    [Fact]
    public async Task UpdatePolicy_NonExistent_Throws()
    {
        var store = new InMemoryPolicyStore();
        var policy = CreateTestPolicy();

        var act = () => store.UpdatePolicyAsync(policy);

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*not found*");
    }

    [Fact]
    public async Task DeletePolicy_Existing_ReturnsTrue()
    {
        var store = new InMemoryPolicyStore();
        await store.CreatePolicyAsync(CreateTestPolicy());

        var result = await store.DeletePolicyAsync("test-policy");

        result.Should().BeTrue();

        var fetched = await store.GetPolicyAsync("test-policy");
        fetched.Should().BeNull();
    }

    [Fact]
    public async Task DeletePolicy_NonExistent_ReturnsFalse()
    {
        var store = new InMemoryPolicyStore();

        var result = await store.DeletePolicyAsync("nonexistent");

        result.Should().BeFalse();
    }

    [Fact]
    public async Task ListPolicies_ReturnsAll()
    {
        var store = new InMemoryPolicyStore();
        await store.CreatePolicyAsync(CreateTestPolicy("policy-a"));
        await store.CreatePolicyAsync(CreateTestPolicy("policy-b"));

        var result = await store.ListPoliciesAsync();

        result.Should().HaveCount(2);
    }

    // -- Assignment Management --

    [Fact]
    public async Task AssignPolicy_Success()
    {
        var store = new InMemoryPolicyStore();
        var assignment = CreateTestAssignment();

        var result = await store.AssignPolicyAsync(assignment);

        result.Should().Be(assignment);
    }

    [Fact]
    public async Task GetAssignmentsForUser_ReturnsMatching()
    {
        var store = new InMemoryPolicyStore();
        await store.AssignPolicyAsync(CreateTestAssignment(identifier: "user-001"));
        await store.AssignPolicyAsync(CreateTestAssignment(identifier: "user-002"));

        var result = await store.GetAssignmentsForUserAsync("user-001");

        result.Should().HaveCount(1);
        result[0].Assignee.Identifier.Should().Be("user-001");
    }

    [Fact]
    public async Task GetAssignmentsForGroup_ReturnsMatching()
    {
        var store = new InMemoryPolicyStore();
        await store.AssignPolicyAsync(CreateTestAssignment(
            assigneeType: AssigneeType.Group, identifier: "research-analysts"));

        var result = await store.GetAssignmentsForGroupAsync("research-analysts");

        result.Should().HaveCount(1);
    }

    [Fact]
    public async Task GetAssignmentsForSource_ReturnsMatching()
    {
        var store = new InMemoryPolicyStore();
        var assignment = new PolicyAssignment(
            Version: "1.0",
            PolicyName: "test-policy",
            Assignee: new Assignee(AssigneeType.User, "user-001"),
            Scope: new AssignmentScope(TenantId: "tenant-001", SourceConnectionId: "ds-postgres"),
            Active: true,
            Audit: new AuditInfo("admin", DateTimeOffset.UtcNow, "Test"));
        await store.AssignPolicyAsync(assignment);

        var result = await store.GetAssignmentsForSourceAsync("ds-postgres");

        result.Should().HaveCount(1);
    }

    [Fact]
    public async Task ListAssignments_ReturnsAll()
    {
        var store = new InMemoryPolicyStore();
        await store.AssignPolicyAsync(CreateTestAssignment(identifier: "user-001"));
        await store.AssignPolicyAsync(CreateTestAssignment(identifier: "user-002"));

        var result = await store.ListAssignmentsAsync();

        result.Should().HaveCount(2);
    }

    // -- Resolution --

    [Fact]
    public async Task ResolveEffectivePolicy_WithMatchingAssignment_ReturnsPolicy()
    {
        var store = new InMemoryPolicyStore();
        await store.CreatePolicyAsync(CreateTestPolicy());
        await store.AssignPolicyAsync(CreateTestAssignment());

        var result = await store.ResolveEffectivePolicyAsync(
            userId: "user-001",
            tenantId: "tenant-001",
            sourceConnectionId: "any-source",
            getGroups: _ => Array.Empty<string>(),
            getRoles: _ => Array.Empty<string>());

        result.Permissions.CanQuery.Should().BeTrue();
        result.SourceProfiles.Should().Contain("test-policy");
    }

    [Fact]
    public async Task ResolveEffectivePolicy_NoMatchingAssignment_ReturnsDenyAll()
    {
        var store = new InMemoryPolicyStore();
        await store.CreatePolicyAsync(CreateTestPolicy());

        var result = await store.ResolveEffectivePolicyAsync(
            userId: "unknown-user",
            tenantId: "tenant-001",
            sourceConnectionId: "any-source",
            getGroups: _ => Array.Empty<string>(),
            getRoles: _ => Array.Empty<string>());

        result.Permissions.CanQuery.Should().BeFalse();
    }

    [Fact]
    public async Task ResolveAllEffectivePolicies_MultipleSourcesResolved()
    {
        var store = new InMemoryPolicyStore();
        await store.CreatePolicyAsync(CreateTestPolicy());
        await store.AssignPolicyAsync(CreateTestAssignment());

        var result = await store.ResolveAllEffectivePoliciesAsync(
            userId: "user-001",
            tenantId: "tenant-001",
            sourceConnectionIds: new[] { "source-a", "source-b" },
            getGroups: _ => Array.Empty<string>(),
            getRoles: _ => Array.Empty<string>());

        result.Should().HaveCount(2);
    }

    // -- Audit Events --

    [Fact]
    public async Task AuditEvents_FiredOnPolicyCreation()
    {
        var store = new InMemoryPolicyStore();
        var events = new List<PolicyAuditEvent>();
        store.OnAuditEvent(events.Add);

        await store.CreatePolicyAsync(CreateTestPolicy());

        events.Should().HaveCount(1);
        events[0].EventType.Should().Be(PolicyAuditEventType.PolicyCreated);
        events[0].Target.Identifier.Should().Be("test-policy");
    }

    [Fact]
    public async Task AuditEvents_FiredOnPolicyUpdate()
    {
        var store = new InMemoryPolicyStore();
        await store.CreatePolicyAsync(CreateTestPolicy());

        var events = new List<PolicyAuditEvent>();
        store.OnAuditEvent(events.Add);

        await store.UpdatePolicyAsync(CreateTestPolicy() with { Description = "Updated" });

        events.Should().HaveCount(1);
        events[0].EventType.Should().Be(PolicyAuditEventType.PolicyUpdated);
    }

    [Fact]
    public async Task AuditEvents_FiredOnPolicyDeletion()
    {
        var store = new InMemoryPolicyStore();
        await store.CreatePolicyAsync(CreateTestPolicy());

        var events = new List<PolicyAuditEvent>();
        store.OnAuditEvent(events.Add);

        await store.DeletePolicyAsync("test-policy");

        events.Should().HaveCount(1);
        events[0].EventType.Should().Be(PolicyAuditEventType.PolicyDeleted);
    }

    [Fact]
    public async Task AuditEvents_FiredOnPolicyAssignment()
    {
        var store = new InMemoryPolicyStore();
        var events = new List<PolicyAuditEvent>();
        store.OnAuditEvent(events.Add);

        await store.AssignPolicyAsync(CreateTestAssignment());

        events.Should().HaveCount(1);
        events[0].EventType.Should().Be(PolicyAuditEventType.PolicyAssigned);
    }

    [Fact]
    public async Task AuditEvents_FiredOnPolicyRevocation()
    {
        var store = new InMemoryPolicyStore();
        var assignment = CreateTestAssignment();
        await store.AssignPolicyAsync(assignment);

        var events = new List<PolicyAuditEvent>();
        store.OnAuditEvent(events.Add);

        await store.RevokePolicyAsync(
            assignment.PolicyName,
            assignment.Assignee,
            assignment.Scope);

        events.Should().HaveCount(1);
        events[0].EventType.Should().Be(PolicyAuditEventType.PolicyRevoked);

        // Asserting only the audit event let a fail-open revocation pass: the event fired
        // while the assignment stayed active. Per canonical-enforcement-spec.md section 9
        // the assignment must actually stop resolving.
        var remaining = await store.GetAssignmentsForUserAsync(assignment.Assignee.Identifier);
        remaining.Should().BeEmpty();
    }

    // -- Revocation (canonical-enforcement-spec.md section 9) --

    [Fact]
    public async Task RevokePolicy_RemovesTheAssignment()
    {
        var store = new InMemoryPolicyStore();
        var assignment = CreateTestAssignment();
        await store.AssignPolicyAsync(assignment);

        (await store.ListAssignmentsAsync()).Should().HaveCount(1);

        var revoked = await store.RevokePolicyAsync(
            assignment.PolicyName, assignment.Assignee, assignment.Scope);

        revoked.Should().BeTrue();
        (await store.ListAssignmentsAsync()).Should().BeEmpty();
        (await store.GetAssignmentsForUserAsync("user-001")).Should().BeEmpty();
    }

    [Fact]
    public async Task RevokePolicy_AccessIsGoneAfterRevocation()
    {
        // The fail-open bug's real consequence: a revoked user kept resolving the policy.
        var store = new InMemoryPolicyStore();
        await store.CreatePolicyAsync(CreateTestPolicy());
        var assignment = CreateTestAssignment();
        await store.AssignPolicyAsync(assignment);

        var before = await store.ResolveEffectivePolicyAsync(
            "user-001", "tenant-001", "ds-1", _ => Array.Empty<string>(), _ => Array.Empty<string>());
        before.Permissions.CanQuery.Should().BeTrue();
        before.SourceProfiles.Should().Contain("test-policy");

        await store.RevokePolicyAsync(assignment.PolicyName, assignment.Assignee, assignment.Scope);

        var after = await store.ResolveEffectivePolicyAsync(
            "user-001", "tenant-001", "ds-1", _ => Array.Empty<string>(), _ => Array.Empty<string>());
        after.Permissions.CanQuery.Should().BeFalse();
        after.SourceProfiles.Should().BeEmpty();
    }

    [Fact]
    public async Task RevokePolicy_LeavesNonMatchingAssignmentsIntact()
    {
        var store = new InMemoryPolicyStore();
        var target = CreateTestAssignment(identifier: "user-001");
        var other = CreateTestAssignment(identifier: "user-002");
        await store.AssignPolicyAsync(target);
        await store.AssignPolicyAsync(other);

        await store.RevokePolicyAsync(target.PolicyName, target.Assignee, target.Scope);

        (await store.GetAssignmentsForUserAsync("user-001")).Should().BeEmpty();
        (await store.GetAssignmentsForUserAsync("user-002")).Should().HaveCount(1);
    }

    [Fact]
    public async Task RevokePolicy_NoMatchingAssignment_ReturnsFalseAndEmitsNoEvent()
    {
        var store = new InMemoryPolicyStore();
        var events = new List<PolicyAuditEvent>();
        store.OnAuditEvent(events.Add);

        var revoked = await store.RevokePolicyAsync(
            "test-policy",
            new Assignee(AssigneeType.User, "nobody"),
            new AssignmentScope(TenantId: "tenant-001"));

        revoked.Should().BeFalse();
        events.Should().BeEmpty();
    }
}
