using System.Text.Json;
using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// Cross-SDK signing conformance and canonical-form regression tests
/// (docs/canonical-enforcement-spec.md sections 1, 2 and 11).
/// </summary>
public class SigningConformanceTests
{
    /// <summary>
    /// The cross-SDK HMAC-SHA256 over the shared fixture payload, computed per the
    /// canonical spec. Asserted literally rather than only for self-consistency: a
    /// determinism-only assertion (sign twice, compare to itself) passes even when all
    /// three SDKs disagree with each other, which is exactly how the signing divergence
    /// went unnoticed (spec section 11).
    /// </summary>
    private const string ExpectedHmacSha256 = "mpKFMZqD3NvddMUZJMIJBcvDF28Q/WRwDzpDLe4pHGY=";

    private const string ExpectedHmacSha512 =
        "EZ1/QbixgohMFZsmI+K0Xq50T0lGtFToJlEkVi+uCf8SvHYJSj2/ShmpI/3XsJ5pu4DlUcwMjXI0JGipY46SpA==";

    /// <summary>
    /// The canonical signing bytes for the fixture payload: recursively key-sorted,
    /// compact, nulls omitted, integrity stripped, timestamps normalized to "Z".
    /// </summary>
    private const string ExpectedCanonicalPayload =
        """
        {"expiresAt":"2026-01-15T11:00:00Z","issuedAt":"2026-01-15T10:00:00Z","policies":[{"expiresAt":"2026-01-15T11:00:00Z","permissions":{"canExport":false,"canQuery":true,"readOnly":true},"resolvedAt":"2026-01-15T10:00:00Z","sourceConnectionId":"ds-postgres-healthcare","sourceProfiles":["healthcare-analyst-db"],"tenantId":"tenant-midwest-health","userId":"user-001","version":"1.0"}],"tenantId":"tenant-midwest-health","userId":"user-001","version":"1.0"}
        """;

    private const string FixturePath = "signing/hmac-sha256-known-answer.json";

    /// <summary>
    /// Projects the fixture payload into the canonical envelope shape, taking
    /// issuedAt/expiresAt from the policy's resolvedAt/expiresAt so all three SDKs sign
    /// the same instants.
    /// </summary>
    private static (SecurityContext Context, string SecretKey) LoadFixtureContext(
        string fixturePath = FixturePath)
    {
        var root = FixtureHelper.ReadFixtureAsJson(fixturePath);
        var secretKey = root.GetProperty("secretKey").GetString()!;
        var policy = TolapJsonOptions.Deserialize<EffectivePolicy>(
            root.GetProperty("payload").GetRawText());

        var context = new SecurityContext(
            Version: policy.Version,
            UserId: policy.UserId!,
            TenantId: policy.TenantId!,
            IssuedAt: policy.ResolvedAt!.Value,
            ExpiresAt: policy.ExpiresAt!.Value,
            Policies: new[] { policy });

        return (context, secretKey);
    }

    [Fact]
    public void CanonicalPayload_MatchesCrossSdkBytes()
    {
        var (context, _) = LoadFixtureContext();

        SecurityContextSigner.BuildCanonicalPayload(context)
            .Should().Be(ExpectedCanonicalPayload);
    }

    [Fact]
    public void Sign_HmacSha256_MatchesCrossSdkKnownAnswer()
    {
        var (context, secretKey) = LoadFixtureContext();

        var signed = SecurityContextSigner.Sign(context, secretKey, SigningAlgorithm.HmacSha256);

        signed.Integrity!.Signature.Should().Be(ExpectedHmacSha256);
    }

    [Fact]
    public void Sign_HmacSha512_MatchesCrossSdkKnownAnswer()
    {
        var (context, secretKey) = LoadFixtureContext();

        var signed = SecurityContextSigner.Sign(context, secretKey, SigningAlgorithm.HmacSha512);

        signed.Integrity!.Signature.Should().Be(ExpectedHmacSha512);
    }

    [Fact]
    public void Sign_MatchesFixtureExpectedSignature()
    {
        // The shared fixture is the cross-SDK authority: all three SDKs assert against it.
        // This test deliberately FAILS if expectedSignature is missing rather than skipping.
        // A conditional pass is how the original divergence went unnoticed -- the fixture
        // claimed all languages produced the same signature while carrying no value to
        // check, and the .NET suite never loaded it at all. See spec section 11.
        var root = FixtureHelper.ReadFixtureAsJson(FixturePath);

        root.TryGetProperty("expectedSignature", out var expected).Should().BeTrue(
            "the cross-SDK known-answer fixture must carry an expectedSignature");
        expected.ValueKind.Should().Be(JsonValueKind.String);

        var (context, secretKey) = LoadFixtureContext();

        SecurityContextSigner.Sign(context, secretKey, SigningAlgorithm.HmacSha256)
            .Integrity!.Signature.Should().Be(expected.GetString());
    }

    [Fact]
    public void Sign_MatchesFixtureCanonicalPayload()
    {
        // Same reasoning: assert the canonical byte string from the fixture, unconditionally,
        // so a cross-SDK mismatch is diagnosable by comparing bytes rather than only digests.
        var root = FixtureHelper.ReadFixtureAsJson(FixturePath);

        root.TryGetProperty("canonicalPayload", out var expected).Should().BeTrue(
            "the cross-SDK known-answer fixture must carry a canonicalPayload");

        var (context, _) = LoadFixtureContext();

        SecurityContextSigner.BuildCanonicalPayload(context)
            .Should().Be(expected.GetString());
    }

    // -- Sub-second conformance (spec section 2 rule 5) --

    /// <summary>
    /// The sub-second conformance fixture. Its <i>input</i> timestamps carry microseconds
    /// (<c>.123456Z</c> / <c>.987654Z</c>) which MUST canonicalize to milliseconds
    /// (<c>.123Z</c> / <c>.987Z</c>).
    /// </summary>
    /// <remarks>
    /// The whole-second fixture cannot detect a precision mismatch — every runtime renders
    /// <c>10:00:00</c> identically. Python and .NET natively serialize microseconds while
    /// JavaScript's <c>Date</c> cannot represent them at all, so without a mandated
    /// precision the same instant signed in different languages produced different bytes
    /// and failed to verify cross-SDK.
    /// </remarks>
    private const string SubSecondFixturePath = "signing/hmac-sha256-subsecond.json";

    private const string ExpectedSubSecondHmacSha256 = "Dgage1Y2tjqQVNXn9O3y90riPpfnOZFe6R2TsWDr/xc=";

    private const string ExpectedSubSecondHmacSha512 =
        "IKX8zYAeX3BxET3/gOouAJA707WETb1+ki1uUjMZXRhojlTnyJ+ICBSutgHN+XFtxoA7pH92Mpm8blSYMbsXLg==";

    [Fact]
    public void SubSecond_CanonicalPayload_TruncatesMicrosecondsToMilliseconds()
    {
        // Asserted as bytes so a precision regression names the offending field rather
        // than surfacing as an opaque HMAC mismatch. The envelope's issuedAt/expiresAt are
        // not the only instants in the signed bytes: each policy repeats its own
        // resolvedAt/expiresAt, and both must truncate.
        var root = FixtureHelper.ReadFixtureAsJson(SubSecondFixturePath);
        root.TryGetProperty("canonicalPayload", out var expected).Should().BeTrue(
            "the sub-second conformance fixture must carry a canonicalPayload");

        var (context, _) = LoadFixtureContext(SubSecondFixturePath);
        var payload = SecurityContextSigner.BuildCanonicalPayload(context);

        payload.Should().Be(expected.GetString());
        // The microsecond input must not survive into the signed bytes anywhere.
        payload.Should().NotContain(".123456Z");
        payload.Should().NotContain(".987654Z");
        payload.Should().Contain("\"issuedAt\":\"2026-03-01T08:30:15.123Z\"");
        payload.Should().Contain("\"expiresAt\":\"2026-03-01T09:30:15.987Z\"");
        payload.Should().Contain("\"resolvedAt\":\"2026-03-01T08:30:15.123Z\"");
    }

    [Fact]
    public void SubSecond_SignHmacSha256_MatchesCrossSdkKnownAnswer()
    {
        // Unconditional: a fixture that lost its expected value would otherwise silently
        // stop verifying anything, which is the blind spot spec section 11 exists to close.
        var root = FixtureHelper.ReadFixtureAsJson(SubSecondFixturePath);
        root.TryGetProperty("expectedSignature", out var expected).Should().BeTrue(
            "the sub-second conformance fixture must carry an expectedSignature");
        expected.ValueKind.Should().Be(JsonValueKind.String);
        expected.GetString().Should().Be(ExpectedSubSecondHmacSha256);

        var (context, secretKey) = LoadFixtureContext(SubSecondFixturePath);

        SecurityContextSigner.Sign(context, secretKey, SigningAlgorithm.HmacSha256)
            .Integrity!.Signature.Should().Be(ExpectedSubSecondHmacSha256);
    }

    [Fact]
    public void SubSecond_SignHmacSha512_MatchesCrossSdkKnownAnswer()
    {
        var root = FixtureHelper.ReadFixtureAsJson(SubSecondFixturePath);
        root.TryGetProperty("expectedSignatureSha512", out var expected).Should().BeTrue(
            "the sub-second conformance fixture must carry an expectedSignatureSha512");
        expected.GetString().Should().Be(ExpectedSubSecondHmacSha512);

        var (context, secretKey) = LoadFixtureContext(SubSecondFixturePath);

        SecurityContextSigner.Sign(context, secretKey, SigningAlgorithm.HmacSha512)
            .Integrity!.Signature.Should().Be(ExpectedSubSecondHmacSha512);
    }

    [Fact]
    public void SubSecond_MicrosecondAndMillisecondContexts_SignIdentically()
    {
        // The instants are equal at millisecond precision, so the SDKs must agree on their
        // bytes regardless of which precision the issuer transported.
        var micro = BuildContext(new DateTimeOffset(2026, 3, 1, 8, 30, 15, TimeSpan.Zero)
            .AddTicks(1234560));
        var milli = BuildContext(new DateTimeOffset(2026, 3, 1, 8, 30, 15, 123, TimeSpan.Zero));

        SecurityContextSigner.BuildCanonicalPayload(micro)
            .Should().Be(SecurityContextSigner.BuildCanonicalPayload(milli));
    }

    // -- Timestamp normalization table (spec section 2 rule 5) --

    /// <summary>
    /// The normalization table, asserted directly.
    /// </summary>
    /// <remarks>
    /// These seven cases are identical in all three SDKs. Asserting them here rather than
    /// only through a signature means a precision regression reports "expected .123Z, got
    /// .1234560Z" instead of an opaque HMAC mismatch that cannot distinguish a truncation
    /// bug from a key-ordering bug.
    /// </remarks>
    [Theory]
    // Whole seconds: no fractional part is emitted at all.
    [InlineData("2026-01-15T10:00:00Z", "2026-01-15T10:00:00Z")]
    // "+00:00" and "Z" are the same instant and must fold to the same bytes.
    [InlineData("2026-01-15T10:00:00+00:00", "2026-01-15T10:00:00Z")]
    // A zero fraction is dropped rather than rendered as ".000".
    [InlineData("2026-01-15T10:00:00.000Z", "2026-01-15T10:00:00Z")]
    // Exactly three digits pass through unchanged.
    [InlineData("2026-01-15T10:00:00.123Z", "2026-01-15T10:00:00.123Z")]
    // Microseconds truncate to milliseconds.
    [InlineData("2026-01-15T10:00:00.123456Z", "2026-01-15T10:00:00.123Z")]
    // Truncation, never rounding: .1239 -> .123, not .124.
    [InlineData("2026-01-15T10:00:00.1239Z", "2026-01-15T10:00:00.123Z")]
    // Truncation must not carry into the next second.
    [InlineData("2026-01-15T10:00:00.999999Z", "2026-01-15T10:00:00.999Z")]
    public void NormalizeTimestamp_MatchesTheCrossSdkTable(string input, string expected)
    {
        var parsed = DateTimeOffset.Parse(
            input, System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.RoundtripKind);

        CanonicalJson.NormalizeTimestamp(parsed).Should().Be(expected);
    }

    [Fact]
    public void NormalizeTimestamp_TruncatesRatherThanRounding()
    {
        // Rounding could move an expiry later than the issuer intended.
        var value = DateTimeOffset.Parse(
            "2026-01-15T10:00:00.9999Z", System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.RoundtripKind);

        CanonicalJson.NormalizeTimestamp(value).Should().Be("2026-01-15T10:00:00.999Z");
    }

    [Fact]
    public void NormalizeTimestamp_ConvertsNonUtcOffsetRatherThanRelabelling()
    {
        var value = DateTimeOffset.Parse(
            "2026-01-15T05:00:00.123456-05:00", System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.RoundtripKind);

        CanonicalJson.NormalizeTimestamp(value).Should().Be("2026-01-15T10:00:00.123Z");
    }

    // -- Canonical form properties (spec section 1) --

    [Fact]
    public void CanonicalPayload_SortsKeysRecursively()
    {
        var (context, _) = LoadFixtureContext();

        var payload = SecurityContextSigner.BuildCanonicalPayload(context);

        // Top level: expiresAt < issuedAt < policies < tenantId < userId < version.
        payload.IndexOf("\"expiresAt\"", StringComparison.Ordinal)
            .Should().BeLessThan(payload.IndexOf("\"issuedAt\"", StringComparison.Ordinal));
        // Nested permissions object is sorted too.
        payload.Should().Contain("\"permissions\":{\"canExport\":false,\"canQuery\":true,\"readOnly\":true}");
    }

    [Fact]
    public void CanonicalJson_DoesNotHtmlEscapeOrEscapeNonAscii()
    {
        // System.Text.Json's default encoder escapes '<', '&', '+' and every non-ASCII
        // rune, which breaks agreement with Python's ensure_ascii=False output.
        var policy = new PolicyDefinition(
            Version: "1.0",
            Name: "tenant <a&b> Ünïcøde +1",
            Permissions: new PolicyPermissions(CanQuery: true));

        var canonical = CanonicalJson.Serialize(policy);

        canonical.Should().Contain("tenant <a&b> Ünïcøde +1");
        canonical.Should().NotContain("\\u");
    }

    [Fact]
    public void CanonicalJson_OmitsNullsAndPreservesEmptyArrays()
    {
        // Spec section 1/3: a null field is indistinguishable from absent, but [] is
        // semantically distinct from absent ("deny everything").
        var policy = new EffectivePolicy(
            Version: "1.0", UserId: "u", TenantId: "t", SourceConnectionId: null,
            ResolvedAt: null, ExpiresAt: null,
            SourceProfiles: Array.Empty<string>(),
            Permissions: new PolicyPermissions(CanQuery: true),
            ObjectRules: new ObjectRules(AllowedObjects: Array.Empty<string>()));

        var canonical = CanonicalJson.Serialize(policy);

        canonical.Should().NotContain("sourceConnectionId");
        canonical.Should().NotContain("null");
        canonical.Should().Contain("\"allowedObjects\":[]");
        canonical.Should().Contain("\"sourceProfiles\":[]");
    }

    [Fact]
    public void CanonicalJson_DoesNotElideDefaultValuedMaskChar()
    {
        // The transport converter omits maskChar when it equals '*'. Default-value elision
        // is forbidden in the signed form: it makes the bytes depend on a C# default the
        // other SDKs do not share.
        var rule = new MaskingRule("ssn", MaskType.Full, new MaskingParameters(MaskChar: '*'));

        CanonicalJson.Serialize(rule).Should().Contain("\"maskChar\":\"*\"");
        // Confirms the transport form still elides it, so this is a signing-only change.
        TolapJsonOptions.Serialize(rule).Should().NotContain("maskChar");
    }

    [Fact]
    public void CanonicalPayload_NormalizesOffsetTimestampsToUtcZ()
    {
        // "+00:00" and "Z" must not produce different bytes (spec section 2 rule 4), and
        // a non-UTC offset must be converted rather than signed verbatim.
        var utc = new DateTimeOffset(2026, 1, 15, 10, 0, 0, TimeSpan.Zero);
        var offset = new DateTimeOffset(2026, 1, 15, 5, 0, 0, TimeSpan.FromHours(-5));

        var fromUtc = SecurityContextSigner.BuildCanonicalPayload(BuildContext(utc));
        var fromOffset = SecurityContextSigner.BuildCanonicalPayload(BuildContext(offset));

        fromOffset.Should().Be(fromUtc);
        fromUtc.Should().Contain("\"issuedAt\":\"2026-01-15T10:00:00Z\"");
    }

    // -- Envelope coverage (spec section 2) --

    [Fact]
    public void Validate_RewrittenExpiry_FailsSignature()
    {
        // expiresAt is inside the signed payload, so extending it on a captured context
        // invalidates the signature instead of extending its life.
        var (context, secretKey) = LoadFixtureContext();
        var signed = SecurityContextSigner.Sign(context, secretKey);

        var replayed = signed with { ExpiresAt = signed.ExpiresAt.AddYears(10) };

        SecurityContextSigner.Validate(replayed, secretKey).Should().BeFalse();
    }

    [Fact]
    public void Validate_RewrittenIssuedAt_FailsSignature()
    {
        var (context, secretKey) = LoadFixtureContext();
        var signed = SecurityContextSigner.Sign(context, secretKey);

        var tampered = signed with { IssuedAt = signed.IssuedAt.AddHours(-5) };

        SecurityContextSigner.Validate(tampered, secretKey).Should().BeFalse();
    }

    [Fact]
    public void Validate_TamperedPolicyRule_FailsSignature()
    {
        var (context, secretKey) = LoadFixtureContext();
        var signed = SecurityContextSigner.Sign(context, secretKey);

        var escalated = signed with
        {
            Policies = new[]
            {
                signed.Policies[0] with
                {
                    Permissions = new PolicyPermissions(CanQuery: true, CanExport: true, ReadOnly: false)
                }
            }
        };

        SecurityContextSigner.Validate(escalated, secretKey).Should().BeFalse();
    }

    [Fact]
    public void Validate_IgnoresPolicyIntegrityBlock()
    {
        // A signature cannot cover itself, so a per-policy integrity block must be
        // stripped from the signed bytes rather than changing them.
        var (context, secretKey) = LoadFixtureContext();
        var signed = SecurityContextSigner.Sign(context, secretKey);

        var withPolicyIntegrity = signed with
        {
            Policies = new[]
            {
                signed.Policies[0] with
                {
                    Integrity = new IntegrityBlock(SigningAlgorithm.HmacSha256, "irrelevant")
                }
            }
        };

        SecurityContextSigner.Validate(withPolicyIntegrity, secretKey).Should().BeTrue();
    }

    // -- Defect 11: malformed Base64 signature --

    [Fact]
    public void Validate_MalformedBase64Signature_ReturnsFalseWithoutFormatException()
    {
        var (context, secretKey) = LoadFixtureContext();
        var tampered = context with
        {
            Integrity = new IntegrityBlock(SigningAlgorithm.HmacSha256, "!!!not-base64!!!")
        };

        var act = () => SecurityContextSigner.Validate(tampered, secretKey);

        act.Should().NotThrow<FormatException>();
        act().Should().BeFalse();
    }

    [Fact]
    public void Deserialize_MalformedBase64Envelope_ThrowsSecurityExceptionNotFormatException()
    {
        var act = () => SecurityContextSigner.Deserialize("!!!not-base64!!!", "any-key");

        act.Should().Throw<SecurityException>();
        act.Should().NotThrow<FormatException>();
    }

    [Fact]
    public void Deserialize_MalformedSignatureInsideEnvelope_ThrowsSecurityException()
    {
        var (context, secretKey) = LoadFixtureContext();
        var tampered = context with
        {
            Integrity = new IntegrityBlock(SigningAlgorithm.HmacSha256, "%%%%")
        };
        var serialized = SecurityContextSigner.Serialize(tampered);

        var act = () => SecurityContextSigner.Deserialize(serialized, secretKey);

        act.Should().Throw<SecurityException>().WithMessage("*signature*");
    }

    // -- Expiry validation (spec section 2) --

    [Fact]
    public void ValidateExpiry_MissingExpiresAt_IsRejected()
    {
        // Never treat absent expiry as "never expires". A context whose expiresAt was
        // absent from the transport JSON deserializes to DateTimeOffset.MinValue.
        var context = new SecurityContext(
            Version: "1.0",
            UserId: "u",
            TenantId: "t",
            IssuedAt: DateTimeOffset.UtcNow,
            ExpiresAt: default,
            Policies: Array.Empty<EffectivePolicy>());

        SecurityContextSigner.ValidateExpiry(context).Should().Contain("no expiry");
    }

    [Fact]
    public void ValidateExpiry_ExpiryExactlyNow_IsRejected()
    {
        // Comparison is expiresAt <= now.
        var context = new SecurityContext(
            Version: "1.0", UserId: "u", TenantId: "t",
            IssuedAt: DateTimeOffset.UtcNow.AddHours(-1),
            ExpiresAt: DateTimeOffset.UtcNow,
            Policies: Array.Empty<EffectivePolicy>());

        SecurityContextSigner.ValidateExpiry(context).Should().NotBeNull();
    }

    [Fact]
    public void Deserialize_TamperedAndExpired_ReportsSignatureFailureFirst()
    {
        // Signature is verified before expiry so a tampered context does not leak whether
        // a valid context had merely expired.
        var (context, secretKey) = LoadFixtureContext();
        var expired = context with
        {
            IssuedAt = DateTimeOffset.UtcNow.AddHours(-2),
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(-1)
        };
        var signed = SecurityContextSigner.Sign(expired, secretKey);
        var tampered = signed with { UserId = "attacker" };

        var act = () => SecurityContextSigner.Deserialize(
            SecurityContextSigner.Serialize(tampered), secretKey);

        act.Should().Throw<SecurityException>().WithMessage("*signature*");
    }

    private static SecurityContext BuildContext(DateTimeOffset issuedAt) => new(
        Version: "1.0",
        UserId: "user-001",
        TenantId: "tenant-midwest-health",
        IssuedAt: issuedAt,
        ExpiresAt: issuedAt.AddHours(1),
        Policies: Array.Empty<EffectivePolicy>());
}
