using System.Security.Cryptography;
using System.Text;

namespace Tolap.Core;

/// <summary>
/// Signs and validates SecurityContext instances using HMAC-based algorithms.
/// </summary>
public static class SecurityContextSigner
{
    /// <summary>
    /// The canonical signing projection defined by canonical-enforcement-spec.md section 2.
    /// </summary>
    /// <remarks>
    /// The projection — not the public <see cref="SecurityContext"/> model — defines the
    /// signed bytes, so the .NET, Python and TypeScript SDKs keep their own public APIs
    /// while producing identical signatures. <c>issuedAt</c> and <c>expiresAt</c> are
    /// inside the payload, so rewriting an expiry on a captured context invalidates the
    /// signature instead of extending its life.
    /// </remarks>
    private sealed record CanonicalSigningPayload(
        string Version,
        string UserId,
        string TenantId,
        DateTimeOffset IssuedAt,
        DateTimeOffset ExpiresAt,
        EffectivePolicy[] Policies);

    /// <summary>
    /// Signs a security context by computing an HMAC over its canonical projection and
    /// attaching the integrity block.
    /// </summary>
    /// <param name="context">The security context to sign.</param>
    /// <param name="secretKey">The secret key for signing.</param>
    /// <param name="algorithm">The signing algorithm to use.</param>
    /// <returns>A new security context with the Integrity block populated.</returns>
    public static SecurityContext Sign(
        SecurityContext context,
        string secretKey,
        SigningAlgorithm algorithm = SigningAlgorithm.HmacSha256)
    {
        var payload = BuildCanonicalPayload(context);
        var signature = ComputeSignature(payload, secretKey, algorithm);

        return context with
        {
            Integrity = new IntegrityBlock(algorithm, signature)
        };
    }

    /// <summary>
    /// Validates the signature on a security context using constant-time comparison.
    /// </summary>
    /// <param name="context">The security context to validate.</param>
    /// <param name="secretKey">The secret key used for signing.</param>
    /// <returns>True if the signature is valid.</returns>
    public static bool Validate(SecurityContext context, string secretKey)
    {
        if (context.Integrity is null)
            return false;

        var payload = BuildCanonicalPayload(context);
        var expectedSignature = ComputeSignature(payload, secretKey, context.Integrity.Algorithm);

        // The provided signature is attacker-controlled: malformed Base64 is an invalid
        // signature, not a FormatException escaping to the caller.
        if (!TryDecodeBase64(context.Integrity.Signature, out var actualBytes))
            return false;

        var expectedBytes = Convert.FromBase64String(expectedSignature);

        return CryptographicOperations.FixedTimeEquals(expectedBytes, actualBytes);
    }

    /// <summary>
    /// Builds the canonical signing payload for a context: the whole envelope, in
    /// canonical JSON form, with every integrity block stripped.
    /// </summary>
    /// <remarks>
    /// A signature cannot cover itself, so the integrity block is removed from the
    /// envelope <b>and</b> from every policy inside it (spec section 2 rule 1). Exposed so
    /// cross-SDK conformance failures can be diagnosed by comparing bytes rather than
    /// signatures.
    /// </remarks>
    public static string BuildCanonicalPayload(SecurityContext context)
    {
        var policies = (context.Policies ?? Array.Empty<EffectivePolicy>())
            .Select(p => p with { Integrity = null })
            .ToArray();

        var payload = new CanonicalSigningPayload(
            Version: context.Version,
            UserId: context.UserId,
            TenantId: context.TenantId,
            IssuedAt: context.IssuedAt,
            ExpiresAt: context.ExpiresAt,
            Policies: policies);

        return CanonicalJson.Serialize(payload);
    }

    /// <summary>
    /// Checks a security context's expiry, returning a denial reason or null when valid.
    /// </summary>
    /// <remarks>
    /// Fails closed at both ends: a context whose <c>expiresAt</c> was absent from the
    /// transport JSON deserializes to <see cref="DateTimeOffset.MinValue"/> and is
    /// rejected rather than treated as "never expires". The comparison is
    /// <c>expiresAt &lt;= now</c> in UTC.
    /// </remarks>
    public static string? ValidateExpiry(SecurityContext context)
    {
        if (context.ExpiresAt == default)
            return "security context has no expiry";

        if (context.ExpiresAt.ToUniversalTime() <= DateTimeOffset.UtcNow)
            return "security context has expired";

        return null;
    }

    /// <summary>
    /// Serializes a security context to a Base64-encoded JSON string for transport.
    /// </summary>
    public static string Serialize(SecurityContext context)
    {
        var json = TolapJsonOptions.Serialize(context);
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(json));
    }

    /// <summary>
    /// Deserializes a Base64-encoded security context, validates its signature and expiry,
    /// and returns the context.
    /// </summary>
    /// <param name="serialized">Base64-encoded JSON security context.</param>
    /// <param name="secretKey">The secret key used for signing.</param>
    /// <returns>The validated security context.</returns>
    /// <exception cref="SecurityException">Thrown if signature is invalid or context has expired.</exception>
    public static SecurityContext Deserialize(string serialized, string secretKey)
    {
        if (!TryDecodeBase64(serialized, out var jsonBytes))
            throw new SecurityException("Security context is not valid Base64");

        var json = Encoding.UTF8.GetString(jsonBytes);
        var context = TolapJsonOptions.Deserialize<SecurityContext>(json);

        // Signature first, so a tampered context reports a signature failure rather
        // than leaking whether a valid context had merely expired.
        if (!Validate(context, secretKey))
            throw new SecurityException("Invalid signature on security context");

        var expiryReason = ValidateExpiry(context);
        if (expiryReason is not null)
            throw new SecurityException($"Security context rejected: {expiryReason}");

        return context;
    }

    private static bool TryDecodeBase64(string value, out byte[] bytes)
    {
        try
        {
            bytes = Convert.FromBase64String(value);
            return true;
        }
        catch (FormatException)
        {
            bytes = Array.Empty<byte>();
            return false;
        }
    }

    private static string ComputeSignature(string payload, string secretKey, SigningAlgorithm algorithm)
    {
        var keyBytes = Encoding.UTF8.GetBytes(secretKey);
        var payloadBytes = Encoding.UTF8.GetBytes(payload);

        byte[] hash;
        switch (algorithm)
        {
            case SigningAlgorithm.HmacSha256:
                using (var hmac = new HMACSHA256(keyBytes))
                {
                    hash = hmac.ComputeHash(payloadBytes);
                }
                break;

            case SigningAlgorithm.HmacSha512:
                using (var hmac = new HMACSHA512(keyBytes))
                {
                    hash = hmac.ComputeHash(payloadBytes);
                }
                break;

            case SigningAlgorithm.Ed25519:
                throw new NotSupportedException("Ed25519 signing is not yet implemented");

            default:
                throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Unsupported signing algorithm");
        }

        return Convert.ToBase64String(hash);
    }
}

/// <summary>
/// Exception thrown when security validation fails.
/// </summary>
public class SecurityException : Exception
{
    public SecurityException(string message) : base(message) { }
    public SecurityException(string message, Exception innerException) : base(message, innerException) { }
}
