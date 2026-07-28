using System.Security.Cryptography;
using System.Text;

namespace Tolap.Core;

/// <summary>
/// Signs and validates SecurityContext instances using HMAC-based algorithms.
/// </summary>
public static class SecurityContextSigner
{
    /// <summary>
    /// Signs a security context by computing an HMAC over its content and attaching the integrity block.
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
        // Remove existing integrity before signing
        var contextWithoutIntegrity = context with { Integrity = null };
        var payload = TolapJsonOptions.Serialize(contextWithoutIntegrity);
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

        var contextWithoutIntegrity = context with { Integrity = null };
        var payload = TolapJsonOptions.Serialize(contextWithoutIntegrity);
        var expectedSignature = ComputeSignature(payload, secretKey, context.Integrity.Algorithm);

        var expectedBytes = Convert.FromBase64String(expectedSignature);
        var actualBytes = Convert.FromBase64String(context.Integrity.Signature);

        return CryptographicOperations.FixedTimeEquals(expectedBytes, actualBytes);
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
        var json = Encoding.UTF8.GetString(Convert.FromBase64String(serialized));
        var context = TolapJsonOptions.Deserialize<SecurityContext>(json);

        if (!Validate(context, secretKey))
            throw new SecurityException("Invalid signature on security context");

        if (context.ExpiresAt < DateTimeOffset.UtcNow)
            throw new SecurityException("Security context has expired");

        return context;
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
