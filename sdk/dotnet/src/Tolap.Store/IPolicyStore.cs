using Tolap.Core;

namespace Tolap.Store;

/// <summary>
/// Interface for TOLAP policy storage and management.
/// </summary>
public interface IPolicyStore
{
    // Policy Definition CRUD
    Task<PolicyDefinition> CreatePolicyAsync(PolicyDefinition definition);
    Task<PolicyDefinition?> GetPolicyAsync(string name);
    Task<PolicyDefinition> UpdatePolicyAsync(PolicyDefinition definition);
    Task<bool> DeletePolicyAsync(string name);
    Task<IReadOnlyList<PolicyDefinition>> ListPoliciesAsync();

    // Policy Assignment Management
    Task<PolicyAssignment> AssignPolicyAsync(PolicyAssignment assignment);
    Task<bool> RevokePolicyAsync(string policyName, Assignee assignee, AssignmentScope scope);
    Task<IReadOnlyList<PolicyAssignment>> GetAssignmentsForUserAsync(string userId);
    Task<IReadOnlyList<PolicyAssignment>> GetAssignmentsForGroupAsync(string groupId);
    Task<IReadOnlyList<PolicyAssignment>> GetAssignmentsForSourceAsync(string sourceConnectionId);
    Task<IReadOnlyList<PolicyAssignment>> ListAssignmentsAsync();

    // Convenience: Resolution
    Task<EffectivePolicy> ResolveEffectivePolicyAsync(
        string userId,
        string tenantId,
        string sourceConnectionId,
        Func<string, string[]> getGroups,
        Func<string, string[]> getRoles);

    Task<IReadOnlyList<EffectivePolicy>> ResolveAllEffectivePoliciesAsync(
        string userId,
        string tenantId,
        string[] sourceConnectionIds,
        Func<string, string[]> getGroups,
        Func<string, string[]> getRoles);

    // Audit
    void OnAuditEvent(Action<PolicyAuditEvent> handler);
}
