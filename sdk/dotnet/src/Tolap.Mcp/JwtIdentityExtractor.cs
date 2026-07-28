using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Tolap.Core;

namespace Tolap.Mcp;

/// <summary>
/// Extracts user identity from a JWT after verifying its signature.
/// </summary>
/// <remarks>
/// By default this extractor <b>verifies the JWT signature</b> (HMAC /
/// HS256-384-512) and the <c>exp</c> claim before trusting any identity claim.
/// A token that fails verification throws <see cref="SecurityException"/> so the
/// caller fails closed rather than resolving an attacker-supplied identity. The
/// <c>none</c> algorithm and any algorithm outside the allow-list are rejected,
/// defeating <c>alg</c>-confusion and unsigned-token attacks.
///
/// Use the unverified constructor (<see cref="CreateUnverified"/>) only when a
/// trusted upstream layer has already verified the signature.
/// </remarks>
public sealed class JwtIdentityExtractor : IRequestIdentityExtractor
{
    private static readonly string[] DefaultAlgorithms = { "HS256" };

    private readonly string _userIdClaim;
    private readonly string _tenantIdClaim;
    private readonly byte[]? _secret;
    private readonly HashSet<string> _algorithms;
    private readonly bool _allowUnverified;
    private readonly int _leewaySeconds;

    /// <summary>
    /// Creates a verifying extractor. The <paramref name="secret"/> is the
    /// shared HMAC key the issuer signed with.
    /// </summary>
    public JwtIdentityExtractor(
        string secret,
        string userIdClaim = "sub",
        string tenantIdClaim = "tenant_id",
        IEnumerable<string>? algorithms = null,
        int leewaySeconds = 0)
        : this(
            Encoding.UTF8.GetBytes(secret ?? throw new ArgumentNullException(nameof(secret))),
            userIdClaim, tenantIdClaim, algorithms, allowUnverified: false, leewaySeconds)
    {
    }

    private JwtIdentityExtractor(
        byte[]? secret,
        string userIdClaim,
        string tenantIdClaim,
        IEnumerable<string>? algorithms,
        bool allowUnverified,
        int leewaySeconds)
    {
        _secret = secret;
        _userIdClaim = userIdClaim;
        _tenantIdClaim = tenantIdClaim;
        _algorithms = new HashSet<string>(algorithms ?? DefaultAlgorithms, StringComparer.Ordinal);
        _allowUnverified = allowUnverified;
        _leewaySeconds = leewaySeconds;
    }

    /// <summary>
    /// Creates an extractor that trusts an already-verified token without
    /// re-checking the signature. Only safe when a trusted upstream layer has
    /// already validated the JWT before it reaches this tool.
    /// </summary>
    public static JwtIdentityExtractor CreateUnverified(
        string userIdClaim = "sub",
        string tenantIdClaim = "tenant_id",
        int leewaySeconds = 0)
        => new(null, userIdClaim, tenantIdClaim, algorithms: null, allowUnverified: true, leewaySeconds);

    public (string UserId, string TenantId) ExtractIdentity(object mcpRequest)
    {
        var token = mcpRequest as string
            ?? throw new InvalidOperationException(
                "JwtIdentityExtractor requires a JWT token string. " +
                $"Received: {mcpRequest.GetType().Name}");

        var parts = token.Split('.');
        if (parts.Length != 3)
            throw new InvalidOperationException("Invalid JWT format: expected 3 dot-separated parts");

        if (!_allowUnverified)
            VerifySignature(parts);

        var payloadJson = DecodeBase64Url(parts[1]);
        using var payload = JsonDocument.Parse(payloadJson);

        VerifyExpiry(payload.RootElement);

        var userId = GetRequiredClaim(payload.RootElement, _userIdClaim);
        var tenantId = GetRequiredClaim(payload.RootElement, _tenantIdClaim);
        return (userId, tenantId);
    }

    private void VerifySignature(string[] parts)
    {
        using var header = JsonDocument.Parse(DecodeBase64Url(parts[0]));
        var alg = header.RootElement.TryGetProperty("alg", out var algElement)
            ? algElement.GetString()
            : null;

        // Reject "none" and any algorithm outside the caller's allow-list.
        if (alg is null || !_algorithms.Contains(alg))
            throw new SecurityException($"JWT algorithm not allowed: {alg ?? "(none)"}");
        if (_secret is null)
            throw new SecurityException("No signing secret configured for JWT verification");

        var signingInput = Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}");
        byte[] expected;
        switch (alg)
        {
            case "HS256":
                using (var h = new HMACSHA256(_secret)) expected = h.ComputeHash(signingInput);
                break;
            case "HS384":
                using (var h = new HMACSHA384(_secret)) expected = h.ComputeHash(signingInput);
                break;
            case "HS512":
                using (var h = new HMACSHA512(_secret)) expected = h.ComputeHash(signingInput);
                break;
            default:
                throw new SecurityException($"JWT algorithm not supported: {alg}");
        }

        byte[] provided;
        try
        {
            provided = DecodeBase64UrlBytes(parts[2]);
        }
        catch (FormatException)
        {
            throw new SecurityException("Invalid JWT signature encoding");
        }

        if (expected.Length != provided.Length
            || !CryptographicOperations.FixedTimeEquals(expected, provided))
        {
            throw new SecurityException("Invalid JWT signature");
        }
    }

    private void VerifyExpiry(JsonElement payload)
    {
        if (payload.TryGetProperty("exp", out var expElement)
            && expElement.TryGetInt64(out var exp))
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (now > exp + _leewaySeconds)
                throw new SecurityException("JWT has expired");
        }
    }

    private static string GetRequiredClaim(JsonElement payload, string claim)
        => payload.TryGetProperty(claim, out var element)
            ? element.GetString() ?? throw new InvalidOperationException($"Null value for claim: {claim}")
            : throw new InvalidOperationException($"Missing claim: {claim}");

    private static string DecodeBase64Url(string base64Url)
        => Encoding.UTF8.GetString(DecodeBase64UrlBytes(base64Url));

    private static byte[] DecodeBase64UrlBytes(string base64Url)
    {
        var base64 = base64Url
            .Replace('-', '+')
            .Replace('_', '/');

        switch (base64.Length % 4)
        {
            case 2: base64 += "=="; break;
            case 3: base64 += "="; break;
        }

        return Convert.FromBase64String(base64);
    }
}
