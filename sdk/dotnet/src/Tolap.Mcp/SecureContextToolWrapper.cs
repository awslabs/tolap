using System.Diagnostics;
using Tolap.Core;

namespace Tolap.Mcp;

/// <summary>
/// Configuration for the context-driven secure tool wrapper.
/// </summary>
/// <param name="AllowUnenforceableShapes">
/// Pass through tool results the policy cannot be applied to. Off by default; see
/// canonical-enforcement-spec.md section 5.
/// </param>
public sealed record SecureContextWrapperOptions(
    string SigningKey,
    bool EnforceSignatures = true,
    bool EnforceExpiry = true,
    string[]? AllowedTools = null,
    bool AllowUnenforceableShapes = false);

/// <summary>
/// Pre-execution arguments describing what the tool is about to do.
/// </summary>
public sealed record PreExecuteArgs(
    string ToolName,
    string? ObjectName = null,
    string[]? Fields = null,
    string? EndpointPath = null,
    string? EndpointMethod = null);

/// <summary>
/// Context-driven secure tool wrapper. Mirrors Python's
/// SecureMcpToolWrapper.execute_with_enforcement and TypeScript's
/// SecureContextToolWrapper.
///
/// Use this when you already hold a signed SecurityContext (rather than the
/// MCP-style SecureMcpToolWrapper which resolves identity to a policy via
/// IdentityExtractor + PolicyStore).
/// </summary>
public sealed class SecureContextToolWrapper
{
    private readonly SecureContextWrapperOptions _options;

    public SecureContextToolWrapper(SecureContextWrapperOptions options)
    {
        _options = options;
    }

    /// <summary>
    /// Validates signature then expiry. Signature first, so a tampered context reports a
    /// signature failure rather than revealing whether a valid context merely expired.
    /// </summary>
    public AccessResult ValidateSecurityContext(SecurityContext context)
    {
        if (_options.EnforceSignatures
            && !SecurityContextSigner.Validate(context, _options.SigningKey))
        {
            return new AccessResult(false, "invalid signature");
        }

        if (_options.EnforceExpiry)
        {
            // A missing expiry is a denial, never a skipped check.
            var expiryReason = SecurityContextSigner.ValidateExpiry(context);
            if (expiryReason is not null)
            {
                return new AccessResult(false, expiryReason);
            }
        }

        return new AccessResult(true);
    }

    public AccessResult PreExecute(SecurityContext context, PreExecuteArgs args)
    {
        var ctxResult = ValidateSecurityContext(context);
        if (!ctxResult.Allowed) return ctxResult;

        if (_options.AllowedTools is not null
            && _options.AllowedTools.Length > 0
            && !_options.AllowedTools.Contains(args.ToolName))
        {
            return new AccessResult(false, "tool not in allowed list");
        }

        var policy = context.Policies.FirstOrDefault();
        if (policy is null)
        {
            return new AccessResult(false, "no policy in context");
        }

        if (!policy.Permissions.CanQuery)
        {
            return new AccessResult(false, "query not permitted");
        }

        if (args.ObjectName is not null)
        {
            var r = EnforcementEngine.ValidateAccess(args.ObjectName, policy);
            if (!r.Allowed) return r;
        }

        if (args.Fields is not null && args.Fields.Length > 0)
        {
            var r = EnforcementEngine.ValidateFieldAccess(args.Fields, policy);
            if (r.Denied.Length > 0)
            {
                return new AccessResult(false, $"denied fields: {string.Join(", ", r.Denied)}");
            }
        }

        if (args.EndpointPath is not null)
        {
            var method = args.EndpointMethod ?? "GET";
            var r = EnforcementEngine.ValidateEndpoint(args.EndpointPath, method, policy);
            if (!r.Allowed) return r;
        }

        return new AccessResult(true);
    }

    /// <summary>
    /// Applies the canonical post-execution pipeline to a result set.
    /// </summary>
    /// <remarks>
    /// Order (canonical-enforcement-spec.md section 4): row filters -> tag filters ->
    /// hidden fields -> allowed fields -> masking -> result limit. Hidden-field removal
    /// and allowed-field projection are mandatory here: the pre-execution field check
    /// only inspects the fields a caller volunteers, so a tool returning undeclared
    /// columns (<c>SELECT *</c>) would otherwise leak them.
    /// </remarks>
    public IReadOnlyList<Dictionary<string, object?>> PostExecute(
        SecurityContext context,
        IReadOnlyList<Dictionary<string, object?>> rows)
    {
        var policy = context.Policies.FirstOrDefault()
                     ?? throw new InvalidOperationException("no policy in context");

        return EnforcementEngine.ApplyRecordPipeline(rows, policy);
    }

    /// <summary>
    /// Applies the canonical post-execution pipeline to an arbitrary tool result.
    /// </summary>
    /// <remarks>
    /// A single record runs the identical pipeline (a get-by-id tool must not skip row
    /// or tag filters). Any other shape is denied unless the wrapper was configured with
    /// <see cref="SecureContextWrapperOptions.AllowUnenforceableShapes"/>.
    /// </remarks>
    /// <exception cref="UnenforceableResultException">
    /// Thrown for a shape the policy cannot be applied to.
    /// </exception>
    public object? PostExecuteResult(SecurityContext context, object? result)
    {
        var policy = context.Policies.FirstOrDefault()
                     ?? throw new InvalidOperationException("no policy in context");

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

    public async Task<IReadOnlyList<Dictionary<string, object?>>> ExecuteWithEnforcementAsync(
        SecurityContext context,
        PreExecuteArgs args,
        Func<Task<IReadOnlyList<Dictionary<string, object?>>>> toolFn)
    {
        var pre = PreExecute(context, args);
        if (!pre.Allowed)
        {
            throw new UnauthorizedAccessException($"Access denied: {pre.Reason}");
        }
        var raw = await toolFn().ConfigureAwait(false);
        return PostExecute(context, raw);
    }

    /// <summary>
    /// Executes a tool whose result shape is not statically known and applies full
    /// pre/post enforcement.
    /// </summary>
    /// <exception cref="UnauthorizedAccessException">
    /// Thrown when the pre-execution check denies the call, or when the tool returns a
    /// shape the policy cannot be applied to.
    /// </exception>
    public async Task<object?> ExecuteWithEnforcementAsync(
        SecurityContext context,
        PreExecuteArgs args,
        Func<Task<object?>> toolFn)
    {
        var pre = PreExecute(context, args);
        if (!pre.Allowed)
        {
            throw new UnauthorizedAccessException($"Access denied: {pre.Reason}");
        }
        var raw = await toolFn().ConfigureAwait(false);
        return PostExecuteResult(context, raw);
    }
}
