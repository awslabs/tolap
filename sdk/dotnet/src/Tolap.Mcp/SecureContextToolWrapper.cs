using Tolap.Core;

namespace Tolap.Mcp;

/// <summary>
/// Configuration for the context-driven secure tool wrapper.
/// </summary>
public sealed record SecureContextWrapperOptions(
    string SigningKey,
    bool EnforceSignatures = true,
    bool EnforceExpiry = true,
    string[]? AllowedTools = null);

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

    public AccessResult ValidateSecurityContext(SecurityContext context)
    {
        if (_options.EnforceSignatures
            && !SecurityContextSigner.Validate(context, _options.SigningKey))
        {
            return new AccessResult(false, "invalid signature");
        }

        if (_options.EnforceExpiry && context.ExpiresAt < DateTimeOffset.UtcNow)
        {
            return new AccessResult(false, "security context expired");
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

    public IReadOnlyList<Dictionary<string, object?>> PostExecute(
        SecurityContext context,
        IReadOnlyList<Dictionary<string, object?>> rows)
    {
        var policy = context.Policies.FirstOrDefault()
                     ?? throw new InvalidOperationException("no policy in context");

        var filtered = EnforcementEngine.ApplyRowFilters(rows, policy);
        filtered = EnforcementEngine.FilterByTags(filtered, policy);

        var masked = new List<Dictionary<string, object?>>(filtered.Count);
        foreach (var row in filtered)
        {
            masked.Add(EnforcementEngine.ApplyFieldMasking(row, policy));
        }

        return EnforcementEngine.ApplyResultLimit(masked, policy);
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
}
