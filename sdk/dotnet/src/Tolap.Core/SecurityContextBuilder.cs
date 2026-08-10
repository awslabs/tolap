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
    /// <param name="jti">
    /// Unique context identifier for replay detection (spec section 13). Defaults to a
    /// fresh GUID so contexts are replay-checkable without the caller having to remember
    /// to ask; pass your own value to supply one, or <see cref="string.Empty"/> to omit it
    /// and reproduce the pre-<c>jti</c> canonical bytes. The id is inside the signed
    /// payload, so it cannot be stripped or swapped without invalidating the signature.
    /// </param>
    /// <returns>An unsigned security context ready for signing.</returns>
    public static SecurityContext Build(
        string userId,
        string tenantId,
        EffectivePolicy[] policies,
        TimeSpan? ttl = null,
        string? jti = null)
    {
        var now = DateTimeOffset.UtcNow;
        var effectiveTtl = ttl ?? DefaultTtl;

        return new SecurityContext(
            Version: "1.0",
            UserId: userId,
            TenantId: tenantId,
            IssuedAt: now,
            ExpiresAt: now + effectiveTtl,
            Policies: policies,
            Jti: jti switch
            {
                null => Guid.NewGuid().ToString(),
                "" => null,
                _ => jti
            });
    }
}
