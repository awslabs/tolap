using System.Diagnostics;
using Tolap.Core;
using Tolap.Store;

namespace Tolap.Mcp;

/// <summary>
/// Result of a tool execution with security enforcement applied.
/// </summary>
public sealed record ToolExecutionResult(
    bool Allowed,
    string? DenialReason,
    object? Result);

/// <summary>
/// Wraps an MCP tool call with pre-execution validation and post-execution
/// masking/filtering using the TOLAP EnforcementEngine.
/// </summary>
public sealed class SecureMcpToolWrapper
{
    private readonly SecureMcpServerOptions _options;

    /// <summary>
    /// Constructs the wrapper, warning loudly when it is configured in a mode that
    /// cannot deny.
    /// </summary>
    /// <remarks>
    /// Threat-model remediation R-6: <see cref="EnforcementMode.Permissive"/> turns every
    /// denial into an allow, so a deployment that reaches production still carrying it has
    /// no enforcement at all while continuing to look configured. The warning fires at
    /// construction rather than on the first denial, because a service whose policies
    /// happen not to deny anything during a smoke test would otherwise ship silently.
    /// <see cref="SecureMcpServerOptions.AllowUnenforceableShapes"/> already warns on the
    /// same channel when it passes a result through.
    /// </remarks>
    public SecureMcpToolWrapper(SecureMcpServerOptions options)
    {
        _options = options;
        WarnIfEnforcementDisabled(options.EnforcementMode);
    }

    /// <summary>
    /// Emits the startup warning once per wrapper when a non-denying mode is active.
    /// </summary>
    /// <remarks>
    /// Warned once at construction rather than on every denial: a per-denial warning is
    /// both noisy enough to be filtered out and absent from a service that simply has not
    /// denied anything yet.
    /// </remarks>
    public static void WarnIfEnforcementDisabled(EnforcementMode mode)
    {
        if (mode != EnforcementMode.Permissive)
            return;

        Trace.TraceWarning(
            "TOLAP enforcement is NOT enforcing: EnforcementMode.Permissive turns every "
            + "policy denial into an allow, so access is granted regardless of policy. "
            + "This is intended for migration only and MUST NOT be used in production. "
            + "Set EnforcementMode.Strict to enforce policy.");
    }

    /// <summary>
    /// Executes a tool call with TOLAP security enforcement.
    /// </summary>
    /// <param name="mcpRequest">The MCP request containing identity information.</param>
    /// <param name="toolName">The name of the tool being called.</param>
    /// <param name="objectName">The data object being accessed.</param>
    /// <param name="sourceConnectionId">The data source connection identifier.</param>
    /// <param name="execute">The actual tool execution function.</param>
    /// <returns>The execution result with enforcement applied.</returns>
    public async Task<ToolExecutionResult> ExecuteWithEnforcementAsync(
        object mcpRequest,
        string toolName,
        string objectName,
        string sourceConnectionId,
        Func<Task<object?>> execute)
    {
        // Extract identity
        var (userId, tenantId) = _options.IdentityExtractor.ExtractIdentity(mcpRequest);

        // Resolve source connection ID from mapping if available
        var resolvedSourceId = ResolveSourceConnectionId(sourceConnectionId);

        // Get identity groups and roles
        var groups = await _options.IdentityResolver.GetGroupsForUserAsync(userId);
        var roles = await _options.IdentityResolver.GetRolesForUserAsync(userId);

        // Resolve effective policy
        var policy = await _options.PolicyStore.ResolveEffectivePolicyAsync(
            userId, tenantId, resolvedSourceId,
            _ => groups,
            _ => roles);

        // Pre-execution: validate query permission
        if (!policy.Permissions.CanQuery)
        {
            return HandleDenial("query permission denied");
        }

        // Pre-execution: validate object access
        var accessResult = EnforcementEngine.ValidateAccess(objectName, policy);
        if (!accessResult.Allowed)
        {
            return HandleDenial(accessResult.Reason ?? "access denied");
        }

        // Execute the tool
        var result = await execute();

        // Post-execution: the canonical six-step pipeline
        // (row filters -> tag filters -> hidden fields -> allowed fields ->
        //  masking -> result limit), applied identically to a single record and to a
        //  list of records. A shape the policy cannot be applied to is denied.
        return new ToolExecutionResult(true, null, EnforceResult(result, policy));
    }

    /// <summary>
    /// Applies the post-execution pipeline, honouring the opt-out for unenforceable shapes.
    /// </summary>
    private object? EnforceResult(object? result, EffectivePolicy policy)
    {
        if (EnforcementEngine.ClassifyResultShape(result) == ResultShape.Unenforceable
            && _options.AllowUnenforceableShapes)
        {
            Trace.TraceWarning(
                "TOLAP enforcement bypassed: AllowUnenforceableShapes is enabled and the tool "
                + $"returned {EnforcementEngine.DescribeResultShape(result)}, which is passed "
                + "through unfiltered.");
            return result;
        }

        return EnforcementEngine.ApplyResultPipeline(result, policy);
    }

    /// <summary>
    /// Validates field access for a query before execution.
    /// </summary>
    public async Task<FieldAccessResult> ValidateFieldsAsync(
        object mcpRequest,
        string sourceConnectionId,
        string[] fields)
    {
        var (userId, tenantId) = _options.IdentityExtractor.ExtractIdentity(mcpRequest);
        var resolvedSourceId = ResolveSourceConnectionId(sourceConnectionId);
        var groups = await _options.IdentityResolver.GetGroupsForUserAsync(userId);
        var roles = await _options.IdentityResolver.GetRolesForUserAsync(userId);

        var policy = await _options.PolicyStore.ResolveEffectivePolicyAsync(
            userId, tenantId, resolvedSourceId,
            _ => groups,
            _ => roles);

        return EnforcementEngine.ValidateFieldAccess(fields, policy);
    }

    /// <summary>
    /// Validates endpoint access before execution.
    /// </summary>
    public async Task<AccessResult> ValidateEndpointAsync(
        object mcpRequest,
        string sourceConnectionId,
        string path,
        string method)
    {
        var (userId, tenantId) = _options.IdentityExtractor.ExtractIdentity(mcpRequest);
        var resolvedSourceId = ResolveSourceConnectionId(sourceConnectionId);
        var groups = await _options.IdentityResolver.GetGroupsForUserAsync(userId);
        var roles = await _options.IdentityResolver.GetRolesForUserAsync(userId);

        var policy = await _options.PolicyStore.ResolveEffectivePolicyAsync(
            userId, tenantId, resolvedSourceId,
            _ => groups,
            _ => roles);

        return EnforcementEngine.ValidateEndpoint(path, method, policy);
    }

    private string ResolveSourceConnectionId(string sourceConnectionId)
    {
        if (_options.SourceMapping is not null
            && _options.SourceMapping.TryGetValue(sourceConnectionId, out var mapped))
        {
            return mapped;
        }
        return sourceConnectionId;
    }

    private ToolExecutionResult HandleDenial(string reason)
    {
        if (_options.EnforcementMode == EnforcementMode.Permissive)
        {
            // In permissive mode, log but allow
            return new ToolExecutionResult(true, $"[permissive] {reason}", null);
        }

        return new ToolExecutionResult(false, reason, null);
    }
}
