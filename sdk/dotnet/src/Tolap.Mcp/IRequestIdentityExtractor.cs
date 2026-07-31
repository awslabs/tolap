namespace Tolap.Mcp;

/// <summary>
/// Extracts user identity from an MCP request.
/// </summary>
public interface IRequestIdentityExtractor
{
    /// <summary>
    /// Extracts the user ID and tenant ID from an MCP request object.
    /// </summary>
    /// <param name="mcpRequest">The MCP request to extract identity from.</param>
    /// <returns>A tuple of (UserId, TenantId).</returns>
    (string UserId, string TenantId) ExtractIdentity(object mcpRequest);
}
