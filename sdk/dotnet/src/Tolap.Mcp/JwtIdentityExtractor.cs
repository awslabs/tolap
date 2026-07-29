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
/// HS256-384-512) and the <c>exp</c>/<c>nbf</c> claims before trusting any identity
/// claim. The <c>none</c> algorithm and any algorithm outside the allow-list are
/// rejected, defeating <c>alg</c>-confusion and unsigned-token attacks.
///
/// <para>
/// Failure semantics follow canonical-enforcement-spec.md section 9 and are
/// identical in all three SDKs: a credential that is <b>presented but invalid</b>
/// — malformed, non-allowlisted algorithm, <c>alg=none</c>, bad signature, expired
/// (<c>exp</c>), not-yet-valid (<c>nbf</c>), or missing a required claim — throws
/// <see cref="SecurityException"/>. Returning "no identity" instead would convert an
/// authentication failure into an authorization decision, letting the request resolve
/// whatever an anonymous or default assignment grants.
/// </para>
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

    /// <summary>
    /// Extracts the identity from a presented JWT.
    /// </summary>
    /// <exception cref="SecurityException">
    /// Thrown when a credential is presented but invalid (spec section 9).
    /// </exception>
    public (string UserId, string TenantId) ExtractIdentity(object mcpRequest)
    {
        var token = mcpRequest as string
            ?? throw new InvalidOperationException(
                "JwtIdentityExtractor requires a JWT token string. " +
                $"Received: {mcpRequest.GetType().Name}");

        var parts = token.Split('.');
        if (parts.Length != 3)
            throw new SecurityException("Invalid JWT format: expected 3 dot-separated parts");

        if (!_allowUnverified)
            VerifySignature(parts);

        JsonDocument payload;
        try
        {
            payload = JsonDocument.Parse(DecodeBase64Url(parts[1]));
        }
        catch (Exception exception) when (exception is FormatException or JsonException)
        {
            // The token was presented, so a payload we cannot even parse is an invalid
            // credential rather than a decoding detail that escapes to the caller.
            throw new SecurityException("Malformed JWT encoding", exception);
        }

        using (payload)
        {
            VerifyTemporalClaims(payload.RootElement);

            var userId = GetRequiredClaim(payload.RootElement, _userIdClaim);
            var tenantId = GetRequiredClaim(payload.RootElement, _tenantIdClaim);
            return (userId, tenantId);
        }
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

    /// <summary>
    /// Enforces the <c>exp</c> and <c>nbf</c> claims when present, with the same leeway.
    /// </summary>
    /// <remarks>
    /// RFC 7519 defines both as NumericDate, which may carry a fractional part, and
    /// issuers do emit <c>1699999999.0</c>. Checking only the integer form let a
    /// floating-point value skip the check entirely, so an expired token was accepted;
    /// both forms are now enforced.
    ///
    /// <para>
    /// <c>nbf</c> is validated because a token presented before it becomes valid is
    /// invalid, not anonymous (spec section 9). Leaving it unchecked let a post-dated
    /// token — one an issuer minted for a future window — be used immediately.
    /// </para>
    /// </remarks>
    private void VerifyTemporalClaims(JsonElement payload)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        if (TryGetNumericDate(payload, "exp", out var exp) && now > exp + _leewaySeconds)
            throw new SecurityException("JWT has expired");

        if (TryGetNumericDate(payload, "nbf", out var nbf) && now < nbf - _leewaySeconds)
            throw new SecurityException("JWT is not yet valid");
    }

    /// <summary>
    /// Reads a NumericDate claim, accepting both integral and fractional forms.
    /// </summary>
    private static bool TryGetNumericDate(JsonElement payload, string claim, out double value)
    {
        value = 0;
        if (!payload.TryGetProperty(claim, out var element)
            || element.ValueKind != JsonValueKind.Number)
        {
            return false;
        }

        if (element.TryGetInt64(out var seconds))
        {
            value = seconds;
            return true;
        }
        if (element.TryGetDouble(out value))
        {
            return true;
        }

        throw new SecurityException($"JWT {claim} claim is not a valid NumericDate");
    }

    /// <summary>
    /// Reads a required identity claim.
    /// </summary>
    /// <remarks>
    /// A verified token missing a required claim throws <see cref="SecurityException"/>:
    /// the issuer authenticated someone the policy engine cannot identify, which is an
    /// invalid credential rather than an anonymous request (spec section 9).
    /// </remarks>
    private static string GetRequiredClaim(JsonElement payload, string claim)
    {
        if (!payload.TryGetProperty(claim, out var element)
            || element.ValueKind != JsonValueKind.String)
        {
            throw new SecurityException($"Missing claim: {claim}");
        }

        var value = element.GetString();
        return string.IsNullOrEmpty(value)
            ? throw new SecurityException($"Missing claim: {claim}")
            : value;
    }

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
