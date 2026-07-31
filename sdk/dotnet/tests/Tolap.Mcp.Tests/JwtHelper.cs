using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Tolap.Mcp.Tests;

/// <summary>
/// Mints JWTs for the identity-extractor tests, including deliberately malformed ones.
/// </summary>
/// <remarks>
/// Hand-rolled rather than taken from a JWT library on purpose: the extractor's job is to
/// reject tokens a well-behaved library would never produce (<c>alg=none</c>, a wrong
/// digest, a truncated signature), and a library that refuses to emit them cannot be used
/// to test that rejection.
/// </remarks>
internal static class JwtHelper
{
    /// <summary>
    /// Base64url-encodes a UTF-8 string, stripping the padding a JWT omits.
    /// </summary>
    public static string Encode(string value) => Encode(Encoding.UTF8.GetBytes(value));

    /// <summary>
    /// Base64url-encodes raw bytes, stripping padding.
    /// </summary>
    public static string Encode(byte[] value) => Convert.ToBase64String(value)
        .TrimEnd('=')
        .Replace('+', '-')
        .Replace('/', '_');

    /// <summary>
    /// Joins three already-encoded segments into a token, valid or not.
    /// </summary>
    public static string Compose(string header, string payload, string signature)
        => $"{header}.{payload}.{signature}";

    /// <summary>
    /// Mints a correctly signed HMAC token for the given algorithm and claims.
    /// </summary>
    public static string Signed(string secret, string algorithm, Dictionary<string, object> claims)
    {
        var header = Encode($"{{\"alg\":\"{algorithm}\",\"typ\":\"JWT\"}}");
        var payload = Encode(JsonSerializer.Serialize(claims));
        var signingInput = Encoding.ASCII.GetBytes($"{header}.{payload}");

        using HMAC hmac = algorithm switch
        {
            "HS256" => new HMACSHA256(Encoding.UTF8.GetBytes(secret)),
            "HS384" => new HMACSHA384(Encoding.UTF8.GetBytes(secret)),
            "HS512" => new HMACSHA512(Encoding.UTF8.GetBytes(secret)),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Unsupported test algorithm")
        };

        return Compose(header, payload, Encode(hmac.ComputeHash(signingInput)));
    }
}
