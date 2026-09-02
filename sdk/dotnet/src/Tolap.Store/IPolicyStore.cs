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
    //
    // `declaredPurpose` is threaded through rather than left to the caller to apply
    // afterwards, because purpose filtering has to happen BEFORE the merge: a policy scoped to
    // a purpose the caller did not declare must not fold its rules into the effective policy at
    // all (canonical-enforcement-spec.md section 15.1). A store that dropped the parameter
    // would resolve a policy nobody asked for and there would be no later point at which to
    // undo it.
    //
    // Optional with a default so every existing call site keeps compiling and keeps its
    // meaning. An external implementor of this interface does have to add the parameter; there
    // is no way to extend a resolution contract without that, and silently ignoring a declared
    // purpose is the outcome worth breaking a build over.

    /// <param name="declaredPurpose">
    /// The purpose the caller declares, or null to declare none. Null resolves exactly the
    /// policies it did before purpose binding existed.
    /// </param>
    Task<EffectivePolicy> ResolveEffectivePolicyAsync(
        string userId,
        string tenantId,
        string sourceConnectionId,
        Func<string, string[]> getGroups,
        Func<string, string[]> getRoles,
        string? declaredPurpose = null);

    /// <param name="declaredPurpose">
    /// Applied to every source in <paramref name="sourceConnectionIds"/>. One purpose per call:
    /// a caller resolving several sources under different purposes is doing several things and
    /// should say so in several calls.
    /// </param>
    Task<IReadOnlyList<EffectivePolicy>> ResolveAllEffectivePoliciesAsync(
        string userId,
        string tenantId,
        string[] sourceConnectionIds,
        Func<string, string[]> getGroups,
        Func<string, string[]> getRoles,
        string? declaredPurpose = null);

    // Audit
    void OnAuditEvent(Action<PolicyAuditEvent> handler);
}
