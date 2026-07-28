using System.Text;
using System.Text.Json;
using FluentAssertions;
using Tolap.Core;
using Xunit;

namespace Tolap.Mcp.Tests;

public class IdentityExtractorTests
{
    // -- HeaderIdentityExtractor --

    [Fact]
    public void HeaderExtractor_StringDictionary_ExtractsIdentity()
    {
        var extractor = new HeaderIdentityExtractor();
        var headers = new Dictionary<string, string>
        {
            ["X-Tolap-User-Id"] = "user-001",
            ["X-Tolap-Tenant-Id"] = "tenant-001"
        };

        var (userId, tenantId) = extractor.ExtractIdentity(headers);

        userId.Should().Be("user-001");
        tenantId.Should().Be("tenant-001");
    }

    [Fact]
    public void HeaderExtractor_CustomHeaders_ExtractsIdentity()
    {
        var extractor = new HeaderIdentityExtractor("X-User", "X-Tenant");
        var headers = new Dictionary<string, string>
        {
            ["X-User"] = "custom-user",
            ["X-Tenant"] = "custom-tenant"
        };

        var (userId, tenantId) = extractor.ExtractIdentity(headers);

        userId.Should().Be("custom-user");
        tenantId.Should().Be("custom-tenant");
    }

    [Fact]
    public void HeaderExtractor_MissingHeader_Throws()
    {
        var extractor = new HeaderIdentityExtractor();
        var headers = new Dictionary<string, string>
        {
            ["X-Tolap-User-Id"] = "user-001"
        };

        var act = () => extractor.ExtractIdentity(headers);

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*Missing header*");
    }

    [Fact]
    public void HeaderExtractor_WrongType_Throws()
    {
        var extractor = new HeaderIdentityExtractor();

        var act = () => extractor.ExtractIdentity("not a dictionary");

        act.Should().Throw<InvalidOperationException>();
    }

    // -- JwtIdentityExtractor --

    private const string Secret = "test-signing-secret-value";

    [Fact]
    public void JwtExtractor_ValidSignedToken_ExtractsIdentity()
    {
        var extractor = new JwtIdentityExtractor(Secret);
        var token = CreateSignedJwt(new { sub = "user-001", tenant_id = "tenant-001" }, Secret);

        var (userId, tenantId) = extractor.ExtractIdentity(token);

        userId.Should().Be("user-001");
        tenantId.Should().Be("tenant-001");
    }

    [Fact]
    public void JwtExtractor_CustomClaims_ExtractsIdentity()
    {
        var extractor = new JwtIdentityExtractor(Secret, "user_id", "org_id");
        var token = CreateSignedJwt(new { user_id = "custom-user", org_id = "custom-org" }, Secret);

        var (userId, tenantId) = extractor.ExtractIdentity(token);

        userId.Should().Be("custom-user");
        tenantId.Should().Be("custom-org");
    }

    [Fact]
    public void JwtExtractor_ConstructedWithoutSecret_ThrowsArgumentNull()
    {
        var act = () => new JwtIdentityExtractor(null!);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void JwtExtractor_TamperedSignature_ThrowsSecurity()
    {
        var extractor = new JwtIdentityExtractor(Secret);
        // Signed with a different key -> signature will not match.
        var token = CreateSignedJwt(new { sub = "attacker", tenant_id = "victim" }, "wrong-secret");

        var act = () => extractor.ExtractIdentity(token);

        act.Should().Throw<SecurityException>().WithMessage("*signature*");
    }

    [Fact]
    public void JwtExtractor_NoneAlgorithm_IsRejected()
    {
        var extractor = new JwtIdentityExtractor(Secret);
        var header = Base64UrlEncode(JsonSerializer.Serialize(new { alg = "none", typ = "JWT" }));
        var body = Base64UrlEncode(JsonSerializer.Serialize(new { sub = "attacker", tenant_id = "victim" }));
        var token = $"{header}.{body}.";

        var act = () => extractor.ExtractIdentity(token);

        act.Should().Throw<SecurityException>();
    }

    [Fact]
    public void JwtExtractor_ExpiredToken_ThrowsSecurity()
    {
        var extractor = new JwtIdentityExtractor(Secret);
        var past = DateTimeOffset.UtcNow.AddMinutes(-5).ToUnixTimeSeconds();
        var token = CreateSignedJwt(new { sub = "user-001", tenant_id = "tenant-001", exp = past }, Secret);

        var act = () => extractor.ExtractIdentity(token);

        act.Should().Throw<SecurityException>().WithMessage("*expired*");
    }

    [Fact]
    public void JwtExtractor_MissingClaim_Throws()
    {
        var extractor = new JwtIdentityExtractor(Secret);
        var token = CreateSignedJwt(new { sub = "user-001" }, Secret); // missing tenant_id

        var act = () => extractor.ExtractIdentity(token);

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*Missing claim*");
    }

    [Fact]
    public void JwtExtractor_Unverified_SkipsSignatureCheck()
    {
        var extractor = JwtIdentityExtractor.CreateUnverified();
        // Any signature is accepted in unverified mode (upstream is trusted).
        var token = CreateSignedJwt(new { sub = "user-001", tenant_id = "tenant-001" }, "any-key");

        var (userId, tenantId) = extractor.ExtractIdentity(token);

        userId.Should().Be("user-001");
        tenantId.Should().Be("tenant-001");
    }

    [Fact]
    public void JwtExtractor_InvalidFormat_Throws()
    {
        var extractor = new JwtIdentityExtractor(Secret);

        var act = () => extractor.ExtractIdentity("not.a.jwt.token.at.all");

        act.Should().Throw<Exception>();
    }

    [Fact]
    public void JwtExtractor_NonStringInput_Throws()
    {
        var extractor = new JwtIdentityExtractor(Secret);

        var act = () => extractor.ExtractIdentity(42);

        act.Should().Throw<InvalidOperationException>();
    }

    private static string CreateSignedJwt(object payload, string secret)
    {
        var header = Base64UrlEncode(JsonSerializer.Serialize(new { alg = "HS256", typ = "JWT" }));
        var body = Base64UrlEncode(JsonSerializer.Serialize(payload));
        var signingInput = $"{header}.{body}";
        using var hmac = new System.Security.Cryptography.HMACSHA256(Encoding.UTF8.GetBytes(secret));
        var signature = hmac.ComputeHash(Encoding.ASCII.GetBytes(signingInput));
        return $"{signingInput}.{Base64UrlEncodeBytes(signature)}";
    }

    private static string Base64UrlEncode(string value)
        => Base64UrlEncodeBytes(Encoding.UTF8.GetBytes(value));

    private static string Base64UrlEncodeBytes(byte[] bytes)
        => Convert.ToBase64String(bytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
}
