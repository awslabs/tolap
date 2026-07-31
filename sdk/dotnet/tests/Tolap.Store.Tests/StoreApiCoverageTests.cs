using FluentAssertions;
using Tolap.Core;
using Xunit;

namespace Tolap.Store.Tests;

/// <summary>
/// Covers the <see cref="StaticIdentityResolver"/> surface and the
/// <see cref="InMemoryPolicyStore"/> branches the behavioural suite leaves one-sided.
/// </summary>
public class StoreApiCoverageTests
{
    // -- StaticIdentityResolver --

    [Fact]
    public async Task StaticIdentityResolver_UnknownUser_ResolvesToNoGroupsOrRoles()
    {
        // No memberships must be an empty set, never null: a null would make a caller's
        // Contains check throw rather than simply failing to match.
        var resolver = new StaticIdentityResolver();

        (await resolver.GetGroupsForUserAsync("nobody")).Should().BeEmpty();
        (await resolver.GetRolesForUserAsync("nobody")).Should().BeEmpty();
    }

    [Fact]
    public async Task StaticIdentityResolver_RegistersGroupsAndRolesPerUser()
    {
        var resolver = new StaticIdentityResolver()
            .AddUserToGroups("alice", "analysts", "clinicians")
            .AddUserToRoles("alice", "auditor");

        (await resolver.GetGroupsForUserAsync("alice")).Should().BeEquivalentTo("analysts", "clinicians");
        (await resolver.GetRolesForUserAsync("alice")).Should().BeEquivalentTo("auditor");

        // Memberships are per-user, so one user's grants must not leak to another.
        (await resolver.GetGroupsForUserAsync("bob")).Should().BeEmpty();
        (await resolver.GetRolesForUserAsync("alice")).Should().NotContain("analysts");
    }

    [Fact]
    public async Task StaticIdentityResolver_RepeatedRegistrationAccumulates()
    {
        // The second call takes the "key already present" branch and must add to the
        // existing memberships rather than replacing them.
        var resolver = new StaticIdentityResolver()
            .AddUserToGroups("alice", "analysts")
            .AddUserToGroups("alice", "clinicians")
            .AddUserToRoles("alice", "auditor")
            .AddUserToRoles("alice", "reviewer");

        (await resolver.GetGroupsForUserAsync("alice")).Should().BeEquivalentTo("analysts", "clinicians");
        (await resolver.GetRolesForUserAsync("alice")).Should().BeEquivalentTo("auditor", "reviewer");
    }

    [Fact]
    public void StaticIdentityResolver_RegistrationIsChainable()
    {
        var resolver = new StaticIdentityResolver();

        resolver.AddUserToGroups("alice", "g").Should().BeSameAs(resolver);
        resolver.AddUserToRoles("alice", "r").Should().BeSameAs(resolver);
    }

    [Fact]
    public async Task StaticIdentityResolver_ReturnsASnapshotNotTheLiveList()
    {
        // A caller mutating the returned array must not be editing the resolver's state.
        var resolver = new StaticIdentityResolver().AddUserToGroups("alice", "analysts");

        var groups = await resolver.GetGroupsForUserAsync("alice");
        groups[0] = "admins";

        (await resolver.GetGroupsForUserAsync("alice")).Should().BeEquivalentTo("analysts");
    }

    [Fact]
    public async Task StaticIdentityResolver_DrivesResolutionThroughTheStore()
    {
        // End-to-end: a group membership registered here must actually satisfy a
        // group-scoped assignment, or the resolver is only nominally wired up.
        var store = new InMemoryPolicyStore();
        await store.CreatePolicyAsync(Definition("analyst"));
        await store.AssignPolicyAsync(Assignment("analyst", new Assignee(AssigneeType.Group, "analysts")));

        var resolver = new StaticIdentityResolver().AddUserToGroups("alice", "analysts");

        var policy = await store.ResolveEffectivePolicyAsync(
            "alice", "t", "db:prod",
            userId => resolver.GetGroupsForUserAsync(userId).GetAwaiter().GetResult(),
            userId => resolver.GetRolesForUserAsync(userId).GetAwaiter().GetResult());

        policy.Permissions.CanQuery.Should().BeTrue();
        policy.SourceProfiles.Should().BeEquivalentTo("analyst");
    }

    // -- InMemoryPolicyStore: assignment lookups by non-matching assignee type --

    [Fact]
    public async Task GetAssignmentsForUser_IgnoresGroupAssignmentsWithTheSameIdentifier()
    {
        // The lookup filters on assignee *type* as well as identifier. Without the type
        // check a group named "alice" would surface as a user assignment.
        var store = new InMemoryPolicyStore();
        await store.CreatePolicyAsync(Definition("p"));
        await store.AssignPolicyAsync(Assignment("p", new Assignee(AssigneeType.Group, "alice")));

        (await store.GetAssignmentsForUserAsync("alice")).Should().BeEmpty();
    }

    [Fact]
    public async Task GetAssignmentsForGroup_IgnoresUserAssignmentsWithTheSameIdentifier()
    {
        var store = new InMemoryPolicyStore();
        await store.CreatePolicyAsync(Definition("p"));
        await store.AssignPolicyAsync(Assignment("p", new Assignee(AssigneeType.User, "analysts")));

        (await store.GetAssignmentsForGroupAsync("analysts")).Should().BeEmpty();
    }

    [Fact]
    public async Task GetAssignmentsForSource_IgnoresAssignmentsScopedToAnotherSource()
    {
        var store = new InMemoryPolicyStore();
        await store.CreatePolicyAsync(Definition("p"));
        await store.AssignPolicyAsync(Assignment("p",
            scope: new AssignmentScope(SourceConnectionId: "db:dev")));

        (await store.GetAssignmentsForSourceAsync("db:prod")).Should().BeEmpty();
        (await store.GetAssignmentsForSourceAsync("db:dev")).Should().HaveCount(1);
    }

    [Fact]
    public async Task RevokePolicy_RequiresPolicyNameAssigneeAndScopeToAllMatch()
    {
        // Revocation is keyed on all three. A partial match must not revoke, or an
        // operator revoking one tenant's grant would silently revoke another's — and
        // conversely a near-miss must not report success while leaving access in place
        // (spec section 10).
        var store = new InMemoryPolicyStore();
        await store.CreatePolicyAsync(Definition("p"));
        var assignee = new Assignee(AssigneeType.User, "alice");
        var scope = new AssignmentScope(TenantId: "t", SourceConnectionId: "db:prod");
        await store.AssignPolicyAsync(Assignment("p", assignee, scope));

        (await store.RevokePolicyAsync("other-policy", assignee, scope)).Should().BeFalse();
        (await store.RevokePolicyAsync("p", new Assignee(AssigneeType.User, "bob"), scope)).Should().BeFalse();
        (await store.RevokePolicyAsync("p", assignee, new AssignmentScope(TenantId: "other"))).Should().BeFalse();

        // None of the near misses removed anything.
        (await store.ListAssignmentsAsync()).Should().HaveCount(1);

        // The exact match revokes, and access is gone afterwards.
        (await store.RevokePolicyAsync("p", assignee, scope)).Should().BeTrue();
        (await store.ListAssignmentsAsync()).Should().BeEmpty();
        (await store.ResolveEffectivePolicyAsync("alice", "t", "db:prod",
            _ => Array.Empty<string>(), _ => Array.Empty<string>()))
            .Permissions.CanQuery.Should().BeFalse();
    }

    [Fact]
    public async Task RevokePolicy_RemovesEveryDuplicateMatchingAssignment()
    {
        // Two identical grants must both go: leaving one behind would keep access alive
        // while reporting a successful revocation (spec section 10).
        var store = new InMemoryPolicyStore();
        await store.CreatePolicyAsync(Definition("p"));
        var assignee = new Assignee(AssigneeType.User, "alice");
        var scope = new AssignmentScope();
        await store.AssignPolicyAsync(Assignment("p", assignee, scope));
        await store.AssignPolicyAsync(Assignment("p", assignee, scope));

        (await store.RevokePolicyAsync("p", assignee, scope)).Should().BeTrue();

        (await store.ListAssignmentsAsync()).Should().BeEmpty();
    }

    [Fact]
    public async Task ListAssignments_ReturnsASnapshotNotTheLiveCollection()
    {
        // A caller iterating the result while another thread assigns must not observe a
        // mutation, and must not be able to mutate the store through the returned list.
        var store = new InMemoryPolicyStore();
        await store.CreatePolicyAsync(Definition("p"));
        await store.AssignPolicyAsync(Assignment("p"));

        var snapshot = await store.ListAssignmentsAsync();
        await store.AssignPolicyAsync(Assignment("p", new Assignee(AssigneeType.User, "bob")));

        snapshot.Should().HaveCount(1);
        (await store.ListAssignmentsAsync()).Should().HaveCount(2);
    }

    [Fact]
    public async Task OnAuditEvent_EveryRegisteredHandlerReceivesEveryEvent()
    {
        // Multiple subscribers is the normal deployment shape (a logger plus a SIEM
        // forwarder); a store that only invoked the first would silently drop the
        // audit trail one of them is responsible for.
        var store = new InMemoryPolicyStore();
        var first = new List<PolicyAuditEvent>();
        var second = new List<PolicyAuditEvent>();
        store.OnAuditEvent(first.Add);
        store.OnAuditEvent(second.Add);

        await store.CreatePolicyAsync(Definition("p"));

        first.Should().HaveCount(1);
        second.Should().HaveCount(1);
        first[0].EventType.Should().Be(PolicyAuditEventType.PolicyCreated);
    }

    [Fact]
    public async Task AuditEvent_CarriesActorTargetAndTimestamp()
    {
        var store = new InMemoryPolicyStore();
        var events = new List<PolicyAuditEvent>();
        store.OnAuditEvent(events.Add);
        var before = DateTimeOffset.UtcNow;

        await store.CreatePolicyAsync(Definition("p"));
        await store.AssignPolicyAsync(Assignment("p", new Assignee(AssigneeType.Group, "analysts")));

        var created = events[0];
        created.Actor.Should().Be("system");
        created.Target.Should().Be(new AuditTarget("policy", "p"));
        created.Details.Should().Contain("p");
        created.Timestamp.Should().BeOnOrAfter(before);

        // The assignment event is attributed to the granting operator, not to "system":
        // an audit trail that cannot name who granted access is not an audit trail.
        var assigned = events[1];
        assigned.EventType.Should().Be(PolicyAuditEventType.PolicyAssigned);
        assigned.Actor.Should().Be("admin");
        assigned.Target.Should().Be(new AuditTarget("Group", "analysts"));
    }

    [Fact]
    public async Task DeletePolicy_MissingPolicyEmitsNoAuditEvent()
    {
        // A no-op must not fabricate an audit record; a PolicyDeleted event for a policy
        // that never existed makes the trail unusable as evidence.
        var store = new InMemoryPolicyStore();
        var events = new List<PolicyAuditEvent>();
        store.OnAuditEvent(events.Add);

        (await store.DeletePolicyAsync("never-existed")).Should().BeFalse();

        events.Should().BeEmpty();
    }

    [Fact]
    public async Task ResolveAllEffectivePolicies_ResolvesPerSourceAndDeniesUnscopedOnes()
    {
        // Both outcomes in one call: the scoped source resolves the grant while the
        // other resolves to deny-all, in the order the caller asked for them.
        var store = new InMemoryPolicyStore();
        await store.CreatePolicyAsync(Definition("p"));
        await store.AssignPolicyAsync(Assignment("p",
            scope: new AssignmentScope(SourceConnectionId: "db:prod")));

        var policies = await store.ResolveAllEffectivePoliciesAsync(
            "alice", "t", new[] { "db:prod", "db:dev" },
            _ => Array.Empty<string>(), _ => Array.Empty<string>());

        policies.Should().HaveCount(2);
        policies[0].Permissions.CanQuery.Should().BeTrue();
        policies[0].SourceConnectionId.Should().Be("db:prod");
        policies[1].Permissions.CanQuery.Should().BeFalse();
    }

    [Fact]
    public async Task ResolveAllEffectivePolicies_NoSources_ReturnsNothing()
    {
        var store = new InMemoryPolicyStore();

        (await store.ResolveAllEffectivePoliciesAsync("alice", "t", Array.Empty<string>(),
            _ => Array.Empty<string>(), _ => Array.Empty<string>()))
            .Should().BeEmpty();
    }

    [Fact]
    public async Task UpdatePolicy_ChangesWhatResolutionReturns()
    {
        // An update that does not affect resolution would make the store's write path
        // decorative.
        var store = new InMemoryPolicyStore();
        await store.CreatePolicyAsync(Definition("p"));
        await store.AssignPolicyAsync(Assignment("p"));

        await store.UpdatePolicyAsync(Definition("p", canQuery: false));

        (await store.ResolveEffectivePolicyAsync("alice", "t", "db:prod",
            _ => Array.Empty<string>(), _ => Array.Empty<string>()))
            .Permissions.CanQuery.Should().BeFalse();
    }

    [Fact]
    public async Task DeletePolicy_RemovesItFromResolution()
    {
        var store = new InMemoryPolicyStore();
        await store.CreatePolicyAsync(Definition("p"));
        await store.AssignPolicyAsync(Assignment("p"));

        await store.DeletePolicyAsync("p");

        // The assignment survives but references nothing, which must resolve to deny-all
        // rather than to an unrestricted policy.
        (await store.ResolveEffectivePolicyAsync("alice", "t", "db:prod",
            _ => Array.Empty<string>(), _ => Array.Empty<string>()))
            .Permissions.CanQuery.Should().BeFalse();
    }

    [Fact]
    public async Task ListPolicies_EmptyStoreReturnsNothing()
    {
        (await new InMemoryPolicyStore().ListPoliciesAsync()).Should().BeEmpty();
    }

    [Fact]
    public async Task ConcurrentAssignAndRevoke_LeaveTheStoreConsistent()
    {
        // The assignment list is lock-guarded rather than a ConcurrentBag precisely so
        // revocation can remove entries; concurrent mutation must not corrupt it or throw.
        var store = new InMemoryPolicyStore();
        await store.CreatePolicyAsync(Definition("p"));

        var assignees = Enumerable.Range(0, 50)
            .Select(i => new Assignee(AssigneeType.User, $"user-{i}"))
            .ToArray();

        await Task.WhenAll(assignees.Select(a => store.AssignPolicyAsync(Assignment("p", a))));
        (await store.ListAssignmentsAsync()).Should().HaveCount(50);

        await Task.WhenAll(assignees.Select(a =>
            store.RevokePolicyAsync("p", a, new AssignmentScope())));

        (await store.ListAssignmentsAsync()).Should().BeEmpty();
    }

    // -- Audit model --

    [Fact]
    public void PolicyAuditEvent_ExposesItsMembers()
    {
        var timestamp = DateTimeOffset.Parse("2026-01-15T10:00:00Z");
        var target = new AuditTarget("policy", "analyst");
        var evt = new PolicyAuditEvent(
            PolicyAuditEventType.PolicyRevoked, timestamp, "admin@example.com", target, "revoked");

        evt.EventType.Should().Be(PolicyAuditEventType.PolicyRevoked);
        evt.Timestamp.Should().Be(timestamp);
        evt.Actor.Should().Be("admin@example.com");
        evt.Target.Should().BeSameAs(target);
        evt.Details.Should().Be("revoked");

        target.Type.Should().Be("policy");
        target.Identifier.Should().Be("analyst");
    }

    // -- Helpers --

    private static PolicyDefinition Definition(string name, bool canQuery = true) =>
        new(Version: "1.0",
            Name: name,
            Permissions: new PolicyPermissions(CanQuery: canQuery),
            AppliesToAll: true);

    private static PolicyAssignment Assignment(
        string policyName,
        Assignee? assignee = null,
        AssignmentScope? scope = null) =>
        new(Version: "1.0",
            PolicyName: policyName,
            Assignee: assignee ?? new Assignee(AssigneeType.User, "alice"),
            Scope: scope ?? new AssignmentScope(),
            Active: true,
            Audit: new AuditInfo("admin", DateTimeOffset.UtcNow, "test"));
}
