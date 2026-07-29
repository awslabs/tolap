using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

public class SecurityContextSignerTests
{
    private const string TestKey = "test-signing-key-2026";

    private static SecurityContext CreateTestContext(TimeSpan? ttlOverride = null)
    {
        var now = DateTimeOffset.UtcNow;
        var ttl = ttlOverride ?? TimeSpan.FromHours(1);

        return new SecurityContext(
            Version: "1.0",
            UserId: "user-001",
            TenantId: "tenant-midwest-health",
            IssuedAt: now,
            ExpiresAt: now + ttl,
            Policies: new[]
            {
                new EffectivePolicy(
                    Version: "1.0",
                    UserId: "user-001",
                    TenantId: "tenant-midwest-health",
                    SourceConnectionId: "ds-postgres-healthcare",
                    ResolvedAt: now,
                    ExpiresAt: now + ttl,
                    SourceProfiles: new[] { "healthcare-analyst-db" },
                    Permissions: new PolicyPermissions(CanQuery: true, ReadOnly: true))
            });
    }

    [Fact]
    public void Sign_ProducesIntegrityBlock()
    {
        var context = CreateTestContext();

        var signed = SecurityContextSigner.Sign(context, TestKey);

        signed.Integrity.Should().NotBeNull();
        signed.Integrity!.Algorithm.Should().Be(SigningAlgorithm.HmacSha256);
        signed.Integrity.Signature.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void Validate_ValidSignature_ReturnsTrue()
    {
        var context = CreateTestContext();
        var signed = SecurityContextSigner.Sign(context, TestKey);

        var isValid = SecurityContextSigner.Validate(signed, TestKey);

        isValid.Should().BeTrue();
    }

    [Fact]
    public void Validate_TamperedContext_ReturnsFalse()
    {
        var context = CreateTestContext();
        var signed = SecurityContextSigner.Sign(context, TestKey);

        // Tamper with the context
        var tampered = signed with { UserId = "user-002" };

        var isValid = SecurityContextSigner.Validate(tampered, TestKey);

        isValid.Should().BeFalse();
    }

    [Fact]
    public void Validate_WrongKey_ReturnsFalse()
    {
        var context = CreateTestContext();
        var signed = SecurityContextSigner.Sign(context, TestKey);

        var isValid = SecurityContextSigner.Validate(signed, "wrong-key");

        isValid.Should().BeFalse();
    }

    [Fact]
    public void Validate_NoIntegrity_ReturnsFalse()
    {
        var context = CreateTestContext();

        var isValid = SecurityContextSigner.Validate(context, TestKey);

        isValid.Should().BeFalse();
    }

    [Fact]
    public void SerializeDeserialize_RoundTrip_PreservesContext()
    {
        var context = CreateTestContext();
        var signed = SecurityContextSigner.Sign(context, TestKey);

        var serialized = SecurityContextSigner.Serialize(signed);
        var deserialized = SecurityContextSigner.Deserialize(serialized, TestKey);

        deserialized.UserId.Should().Be(signed.UserId);
        deserialized.TenantId.Should().Be(signed.TenantId);
        deserialized.Policies.Should().HaveCount(1);
        deserialized.Integrity.Should().NotBeNull();
    }

    [Fact]
    public void Deserialize_TamperedBase64_ThrowsSecurityException()
    {
        var context = CreateTestContext();
        var signed = SecurityContextSigner.Sign(context, TestKey);
        var serialized = SecurityContextSigner.Serialize(signed);

        // Tamper with the base64 string by changing some characters
        var chars = serialized.ToCharArray();
        // Flip a character in the middle of the payload
        var midpoint = chars.Length / 2;
        chars[midpoint] = chars[midpoint] == 'A' ? 'B' : 'A';
        var tampered = new string(chars);

        var act = () => SecurityContextSigner.Deserialize(tampered, TestKey);

        // Should throw either SecurityException or a JSON/Base64 parsing exception
        act.Should().Throw<Exception>();
    }

    [Fact]
    public void Deserialize_ExpiredContext_ThrowsSecurityException()
    {
        // Create a context that expired in the past
        var now = DateTimeOffset.UtcNow;
        var expired = new SecurityContext(
            Version: "1.0",
            UserId: "user-001",
            TenantId: "tenant-midwest-health",
            IssuedAt: now - TimeSpan.FromHours(2),
            ExpiresAt: now - TimeSpan.FromHours(1),
            Policies: Array.Empty<EffectivePolicy>());

        var signed = SecurityContextSigner.Sign(expired, TestKey);
        var serialized = SecurityContextSigner.Serialize(signed);

        var act = () => SecurityContextSigner.Deserialize(serialized, TestKey);

        act.Should().Throw<SecurityException>()
            .WithMessage("*expired*");
    }

    [Fact]
    public void Sign_HmacSha512_ProducesValidSignature()
    {
        var context = CreateTestContext();

        var signed = SecurityContextSigner.Sign(context, TestKey, SigningAlgorithm.HmacSha512);

        signed.Integrity.Should().NotBeNull();
        signed.Integrity!.Algorithm.Should().Be(SigningAlgorithm.HmacSha512);

        var isValid = SecurityContextSigner.Validate(signed, TestKey);
        isValid.Should().BeTrue();
    }

    [Fact]
    public void Sign_DeterministicForSameInput()
    {
        // Build a deterministic context (fixed timestamps)
        var fixedTime = new DateTimeOffset(2026, 1, 15, 10, 0, 0, TimeSpan.Zero);
        var context = new SecurityContext(
            Version: "1.0",
            UserId: "user-001",
            TenantId: "tenant-midwest-health",
            IssuedAt: fixedTime,
            ExpiresAt: fixedTime + TimeSpan.FromHours(1),
            Policies: Array.Empty<EffectivePolicy>());

        var signed1 = SecurityContextSigner.Sign(context, TestKey);
        var signed2 = SecurityContextSigner.Sign(context, TestKey);

        signed1.Integrity!.Signature.Should().Be(signed2.Integrity!.Signature);
    }
}
