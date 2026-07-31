namespace Tolap.Mcp;

/// <summary>
/// Extracts user identity from request headers.
/// Expects headers to contain userId and tenantId values.
/// </summary>
public sealed class HeaderIdentityExtractor : IRequestIdentityExtractor
{
    private readonly string _userIdHeader;
    private readonly string _tenantIdHeader;

    /// <summary>
    /// Creates a new HeaderIdentityExtractor with custom header names.
    /// </summary>
    /// <param name="userIdHeader">Header name containing the user ID.</param>
    /// <param name="tenantIdHeader">Header name containing the tenant ID.</param>
    public HeaderIdentityExtractor(
        string userIdHeader = "X-Tolap-User-Id",
        string tenantIdHeader = "X-Tolap-Tenant-Id")
    {
        _userIdHeader = userIdHeader;
        _tenantIdHeader = tenantIdHeader;
    }

    public (string UserId, string TenantId) ExtractIdentity(object mcpRequest)
    {
        if (mcpRequest is IDictionary<string, string> headers)
        {
            var userId = headers.TryGetValue(_userIdHeader, out var uid)
                ? uid
                : throw new InvalidOperationException($"Missing header: {_userIdHeader}");

            var tenantId = headers.TryGetValue(_tenantIdHeader, out var tid)
                ? tid
                : throw new InvalidOperationException($"Missing header: {_tenantIdHeader}");

            return (userId, tenantId);
        }

        if (mcpRequest is IDictionary<string, object> objectHeaders)
        {
            var userId = objectHeaders.TryGetValue(_userIdHeader, out var uid)
                ? uid?.ToString() ?? throw new InvalidOperationException($"Null value for header: {_userIdHeader}")
                : throw new InvalidOperationException($"Missing header: {_userIdHeader}");

            var tenantId = objectHeaders.TryGetValue(_tenantIdHeader, out var tid)
                ? tid?.ToString() ?? throw new InvalidOperationException($"Null value for header: {_tenantIdHeader}")
                : throw new InvalidOperationException($"Missing header: {_tenantIdHeader}");

            return (userId, tenantId);
        }

        throw new InvalidOperationException(
            "HeaderIdentityExtractor requires a dictionary of headers. " +
            $"Received: {mcpRequest.GetType().Name}");
    }
}
