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

        return EnforcementEngine.ApplyResultPipeline(result, policy, _options.HashSalt);
    }

    /// <summary>
    /// Resolves the caller's policy, runs the pre-execution checks, and rewrites a SQL query so
    /// the policy's restrictions reach the database.
    /// </summary>
    /// <remarks>
    /// <para>
    /// An optional step that never replaces the post-execution pipeline, which stays mandatory
    /// and stays the enforcement point (canonical-enforcement-spec.md section 4). What it adds
    /// is that a row the policy excludes is not fetched and materialized before being discarded
    /// (threat-model D2).
    /// </para>
    /// <para>
    /// The object name comes from the query's own <c>FROM</c> clause when
    /// <paramref name="objectName"/> is null, so an <c>allowedObjects</c> rule applies to the
    /// table the query actually reads. Pair with
    /// <see cref="ExecuteWithEnforcementAsync"/> — which still applies the pipeline — or with
    /// <see cref="EnforcementEngine.ApplyRecordPipeline"/> directly.
    /// </para>
    /// </remarks>
    /// <param name="mcpRequest">The inbound request carrying the caller's identity.</param>
    /// <param name="sourceConnectionId">The source the policy is resolved against.</param>
    /// <param name="sql">The query to check and rewrite.</param>
    /// <param name="objectName">
    /// The target object, or null to take it from the query's own <c>FROM</c> clause.
    /// </param>
    /// <param name="rewriter">The rewriter to use, or null for a default instance.</param>
    /// <param name="dialect">
    /// The engine <paramref name="sql"/> will run against (connector-spec.md section 5.1) —
    /// yours to supply, since only you know which connection this is for. Null selects the
    /// rewriter's own dialect, or <see cref="SqlDialect.Ansi"/>. An unrecognized value rewrites
    /// nothing and reports every filter, leaving the post-execution pass to enforce them.
    /// </param>
    public async Task<SqlQueryPreparation> PrepareSqlQueryAsync(
        object mcpRequest,
        string sourceConnectionId,
        string sql,
        string? objectName = null,
        ISqlQueryRewriter? rewriter = null,
        SqlDialect? dialect = null)
    {
        rewriter ??= new SqlQueryRewriter();

        if (string.IsNullOrWhiteSpace(sql))
        {
            return SqlQueryPreparation.Denied("query is empty", sql);
        }

        var policy = await ResolvePolicyAsync(mcpRequest, sourceConnectionId).ConfigureAwait(false);

        if (!policy.Permissions.CanQuery)
        {
            return Refuse("query permission denied", sql);
        }

        var target = objectName ?? rewriter.ExtractTableName(sql);
        if (target is not null)
        {
            var access = EnforcementEngine.ValidateAccess(target, policy);
            if (!access.Allowed)
            {
                return Refuse(access.Reason ?? "access denied", sql);
            }
        }

        if (!rewriter.ValidateQuery(sql, policy))
        {
            return Refuse("query references fields you do not have permission to access", sql);
        }

        var rewritten = rewriter.RewriteQuery(sql, policy, dialect);

        return new SqlQueryPreparation(
            Allowed: true,
            DenialReason: null,
            Query: rewritten,
            Rewritten: !string.Equals(rewritten, sql, StringComparison.Ordinal),
            UnpushableFilters: rewriter.UnpushableFilters(policy, dialect));

        // Permissive mode allows the call, as it does for every other denial here, but the
        // query is deliberately returned unrewritten: a mode whose contract is "log, do not
        // block" must not narrow a result set either, or a migration would see rows disappear
        // from a configuration documented as non-enforcing.
        SqlQueryPreparation Refuse(string reason, string original)
            => _options.EnforcementMode == EnforcementMode.Permissive
                ? new SqlQueryPreparation(
                    true, $"[permissive] {reason}", original, false, Array.Empty<RowFilter>())
                : SqlQueryPreparation.Denied(reason, original);
    }

    /// <summary>
    /// Resolves the effective policy for a request.
    /// </summary>
    private async Task<EffectivePolicy> ResolvePolicyAsync(object mcpRequest, string sourceConnectionId)
    {
        var (userId, tenantId) = _options.IdentityExtractor.ExtractIdentity(mcpRequest);
        var resolvedSourceId = ResolveSourceConnectionId(sourceConnectionId);
        var groups = await _options.IdentityResolver.GetGroupsForUserAsync(userId);
        var roles = await _options.IdentityResolver.GetRolesForUserAsync(userId);

        return await _options.PolicyStore.ResolveEffectivePolicyAsync(
            userId, tenantId, resolvedSourceId,
            _ => groups,
            _ => roles);
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
