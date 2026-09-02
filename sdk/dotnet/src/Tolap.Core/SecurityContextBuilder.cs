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
    /// <param name="declaredPurpose">
    /// The purpose this context was resolved for (spec section 15). Pass the same value
    /// given to <see cref="PolicyResolutionEngine.Resolve"/>, so the artifact records which
    /// purpose produced it. Signed when present; an empty string normalizes to absent so
    /// <c>""</c> and omitted cannot yield two different signatures.
    /// </param>
    /// <param name="delegationChain">
    /// The chain of principals this authority passed through, oldest hop first. Signed hop
    /// for hop when present. This method <i>records</i> the chain and does not check it,
    /// because a builder that silently dropped an invalid chain would produce a context that
    /// looked delegated and was not.
    /// <para>
    /// The check happens on the consuming side, where the chain is inside the signed bytes:
    /// every wrapper's context validation calls
    /// <see cref="DelegationChainValidator.Validate"/> before permitting a call. Issuers may
    /// call it here too to fail early, but a context that widens will be refused at use even
    /// if they do not.
    /// </para>
    /// </param>
    /// <returns>An unsigned security context ready for signing.</returns>
    /// <remarks>
    /// The two purpose parameters are appended after <paramref name="jti"/> rather than
    /// inserted beside <paramref name="policies"/>, so every existing positional call site
    /// keeps compiling and keeps meaning what it did. This is how <paramref name="jti"/> was
    /// added for the same reason.
    /// </remarks>
    public static SecurityContext Build(
        string userId,
        string tenantId,
        EffectivePolicy[] policies,
        TimeSpan? ttl = null,
        string? jti = null,
        string? declaredPurpose = null,
        DelegationHop[]? delegationChain = null)
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
            },
            // Normalized here as well as in the signing projection. Doing it here keeps the
            // model's own value and its signed value the same thing, so a caller inspecting
            // the context cannot see a purpose the signature does not cover.
            DeclaredPurpose: string.IsNullOrEmpty(declaredPurpose) ? null : declaredPurpose,
            DelegationChain: delegationChain);
    }
}
