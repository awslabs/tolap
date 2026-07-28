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

    public SecureMcpToolWrapper(SecureMcpServerOptions options)
    {
        _options = options;
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

        // Post-execution: apply masking and filtering
        if (result is Dictionary<string, object?> record)
        {
            result = EnforcementEngine.ApplyFieldMasking(record, policy);
        }

        if (result is IReadOnlyList<Dictionary<string, object?>> records)
        {
            // Order: row filters -> tag filters -> masking -> result limit
            // (mirrors Python and TypeScript SDK ordering)
            records = EnforcementEngine.ApplyRowFilters(records, policy);
            records = EnforcementEngine.FilterByTags(records, policy);

            var maskedRecords = new List<Dictionary<string, object?>>();
            foreach (var r in records)
            {
                maskedRecords.Add(EnforcementEngine.ApplyFieldMasking(r, policy));
            }
            records = maskedRecords;

            records = EnforcementEngine.ApplyResultLimit(records, policy);
            result = records;
        }

        return new ToolExecutionResult(true, null, result);
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
