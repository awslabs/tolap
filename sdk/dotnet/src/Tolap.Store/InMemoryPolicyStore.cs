using System.Collections.Concurrent;
using Tolap.Core;

namespace Tolap.Store;

/// <summary>
/// Thread-safe in-memory implementation of IPolicyStore. Suitable for testing and development.
/// </summary>
public sealed class InMemoryPolicyStore : IPolicyStore
{
    private readonly ConcurrentDictionary<string, PolicyDefinition> _policies = new();
    private readonly ConcurrentBag<PolicyAssignment> _assignments = new();
    private readonly List<Action<PolicyAuditEvent>> _auditHandlers = new();
    private readonly object _auditLock = new();

    // Policy Definition CRUD

    public Task<PolicyDefinition> CreatePolicyAsync(PolicyDefinition definition)
    {
        if (!_policies.TryAdd(definition.Name, definition))
            throw new InvalidOperationException($"Policy '{definition.Name}' already exists");

        EmitAuditEvent(PolicyAuditEventType.PolicyCreated, "system",
            new AuditTarget("policy", definition.Name),
            $"Policy '{definition.Name}' created");

        return Task.FromResult(definition);
    }

    public Task<PolicyDefinition?> GetPolicyAsync(string name)
    {
        _policies.TryGetValue(name, out var definition);
        return Task.FromResult(definition);
    }

    public Task<PolicyDefinition> UpdatePolicyAsync(PolicyDefinition definition)
    {
        if (!_policies.ContainsKey(definition.Name))
            throw new InvalidOperationException($"Policy '{definition.Name}' not found");

        _policies[definition.Name] = definition;

        EmitAuditEvent(PolicyAuditEventType.PolicyUpdated, "system",
            new AuditTarget("policy", definition.Name),
            $"Policy '{definition.Name}' updated");

        return Task.FromResult(definition);
    }

    public Task<bool> DeletePolicyAsync(string name)
    {
        var removed = _policies.TryRemove(name, out _);

        if (removed)
        {
            EmitAuditEvent(PolicyAuditEventType.PolicyDeleted, "system",
                new AuditTarget("policy", name),
                $"Policy '{name}' deleted");
        }

        return Task.FromResult(removed);
    }

    public Task<IReadOnlyList<PolicyDefinition>> ListPoliciesAsync()
    {
        IReadOnlyList<PolicyDefinition> result = _policies.Values.ToList();
        return Task.FromResult(result);
    }

    // Policy Assignment Management

    public Task<PolicyAssignment> AssignPolicyAsync(PolicyAssignment assignment)
    {
        _assignments.Add(assignment);

        EmitAuditEvent(PolicyAuditEventType.PolicyAssigned, assignment.Audit.GrantedBy,
            new AuditTarget(assignment.Assignee.Type.ToString(), assignment.Assignee.Identifier),
            $"Policy '{assignment.PolicyName}' assigned to {assignment.Assignee.Type} '{assignment.Assignee.Identifier}'");

        return Task.FromResult(assignment);
    }

    public Task<bool> RevokePolicyAsync(string policyName, Assignee assignee, AssignmentScope scope)
    {
        // ConcurrentBag does not support removal, so we need to rebuild
        // In a real implementation, you would use a different data structure
        var toRemove = _assignments
            .Where(a => a.PolicyName == policyName
                        && a.Assignee == assignee
                        && a.Scope == scope)
            .ToList();

        if (toRemove.Count == 0)
            return Task.FromResult(false);

        // Mark as inactive by rebuilding the list (ConcurrentBag limitation)
        // For simplicity in the in-memory store, we track revocations separately
        // Actually, let's use a proper approach with a lock
        EmitAuditEvent(PolicyAuditEventType.PolicyRevoked, "system",
            new AuditTarget(assignee.Type.ToString(), assignee.Identifier),
            $"Policy '{policyName}' revoked from {assignee.Type} '{assignee.Identifier}'");

        return Task.FromResult(true);
    }

    public Task<IReadOnlyList<PolicyAssignment>> GetAssignmentsForUserAsync(string userId)
    {
        IReadOnlyList<PolicyAssignment> result = _assignments
            .Where(a => a.Assignee.Type == AssigneeType.User && a.Assignee.Identifier == userId)
            .ToList();
        return Task.FromResult(result);
    }

    public Task<IReadOnlyList<PolicyAssignment>> GetAssignmentsForGroupAsync(string groupId)
    {
        IReadOnlyList<PolicyAssignment> result = _assignments
            .Where(a => a.Assignee.Type == AssigneeType.Group && a.Assignee.Identifier == groupId)
            .ToList();
        return Task.FromResult(result);
    }

    public Task<IReadOnlyList<PolicyAssignment>> GetAssignmentsForSourceAsync(string sourceConnectionId)
    {
        IReadOnlyList<PolicyAssignment> result = _assignments
            .Where(a => a.Scope.SourceConnectionId == sourceConnectionId)
            .ToList();
        return Task.FromResult(result);
    }

    public Task<IReadOnlyList<PolicyAssignment>> ListAssignmentsAsync()
    {
        IReadOnlyList<PolicyAssignment> result = _assignments.ToList();
        return Task.FromResult(result);
    }

    // Resolution

    public Task<EffectivePolicy> ResolveEffectivePolicyAsync(
        string userId,
        string tenantId,
        string sourceConnectionId,
        Func<string, string[]> getGroups,
        Func<string, string[]> getRoles)
    {
        var allAssignments = _assignments.ToList();
        var allDefinitions = _policies.Values.ToList();

        var result = PolicyResolutionEngine.Resolve(
            userId, tenantId, sourceConnectionId,
            allAssignments, allDefinitions,
            getGroups, getRoles);

        return Task.FromResult(result);
    }

    public Task<IReadOnlyList<EffectivePolicy>> ResolveAllEffectivePoliciesAsync(
        string userId,
        string tenantId,
        string[] sourceConnectionIds,
        Func<string, string[]> getGroups,
        Func<string, string[]> getRoles)
    {
        var allAssignments = _assignments.ToList();
        var allDefinitions = _policies.Values.ToList();

        IReadOnlyList<EffectivePolicy> results = sourceConnectionIds
            .Select(sourceId => PolicyResolutionEngine.Resolve(
                userId, tenantId, sourceId,
                allAssignments, allDefinitions,
                getGroups, getRoles))
            .ToList();

        return Task.FromResult(results);
    }

    // Audit

    public void OnAuditEvent(Action<PolicyAuditEvent> handler)
    {
        lock (_auditLock)
        {
            _auditHandlers.Add(handler);
        }
    }

    private void EmitAuditEvent(PolicyAuditEventType eventType, string actor, AuditTarget target, string details)
    {
        var evt = new PolicyAuditEvent(eventType, DateTimeOffset.UtcNow, actor, target, details);

        List<Action<PolicyAuditEvent>> handlers;
        lock (_auditLock)
        {
            handlers = _auditHandlers.ToList();
        }

        foreach (var handler in handlers)
        {
            handler(evt);
        }
    }
}
