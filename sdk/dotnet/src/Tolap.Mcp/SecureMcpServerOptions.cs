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
public sealed record SecureMcpServerOptions(
    IPolicyStore PolicyStore,
    IIdentityResolver IdentityResolver,
    IRequestIdentityExtractor IdentityExtractor,
    string SigningKey,
    TimeSpan? ContextTtl = null,
    Dictionary<string, string>? SourceMapping = null,
    EnforcementMode EnforcementMode = EnforcementMode.Strict);
