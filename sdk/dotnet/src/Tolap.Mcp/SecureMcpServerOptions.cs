using Tolap.Store;

namespace Tolap.Mcp;

/// <summary>
/// Enforcement mode for the secure MCP server wrapper.
/// </summary>
public enum EnforcementMode
{
    /// <summary>
    /// Strict mode: all policy violations result in denied access.
    /// </summary>
    Strict,

    /// <summary>
    /// Permissive mode: policy violations are logged but access is allowed.
    /// </summary>
    Permissive
}

/// <summary>
/// Configuration options for the secure MCP server wrapper.
/// </summary>
/// <param name="AllowUnenforceableShapes">
/// Pass through tool results the policy cannot be applied to.
/// <para>
/// Off by default: a POCO/DTO, a scalar, a stream, or an unmaterialized iterator is
/// denied rather than returned unfiltered (canonical-enforcement-spec.md section 5).
/// Integrators mid-migration may opt in per wrapper, which is logged every time it
/// lets a result through.
/// </para>
/// </param>
public sealed record SecureMcpServerOptions(
    IPolicyStore PolicyStore,
    IIdentityResolver IdentityResolver,
    IRequestIdentityExtractor IdentityExtractor,
    string SigningKey,
    TimeSpan? ContextTtl = null,
    Dictionary<string, string>? SourceMapping = null,
    EnforcementMode EnforcementMode = EnforcementMode.Strict,
    bool AllowUnenforceableShapes = false);
