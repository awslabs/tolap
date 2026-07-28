namespace Tolap.Core;

/// <summary>
/// Builds SecurityContext instances from effective policies.
/// </summary>
public static class SecurityContextBuilder
{
    private static readonly TimeSpan DefaultTtl = TimeSpan.FromHours(1);

    /// <summary>
    /// Builds a security context containing the given effective policies.
    /// </summary>
    /// <param name="userId">The user's unique identifier.</param>
    /// <param name="tenantId">The tenant context.</param>
    /// <param name="policies">The resolved effective policies.</param>
    /// <param name="ttl">Time-to-live for the context. Defaults to 1 hour.</param>
    /// <returns>An unsigned security context ready for signing.</returns>
    public static SecurityContext Build(
        string userId,
        string tenantId,
        EffectivePolicy[] policies,
        TimeSpan? ttl = null)
    {
        var now = DateTimeOffset.UtcNow;
        var effectiveTtl = ttl ?? DefaultTtl;

        return new SecurityContext(
            Version: "1.0",
            UserId: userId,
            TenantId: tenantId,
            IssuedAt: now,
            ExpiresAt: now + effectiveTtl,
            Policies: policies);
    }
}
