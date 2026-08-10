using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// Salted <c>hash</c> masking (spec section 6).
/// </summary>
/// <remarks>
/// <para>The <c>hash</c> mask was an unsalted, truncated digest. That is fine as a
/// pseudonymous join key and <b>not</b> fine as confidentiality: the input spaces that
/// matter here are small enough to enumerate. There are ~10^9 SSNs and ~4x10^4 plausible
/// dates of birth, so a masked column of either is recoverable with a rainbow table in
/// seconds, while the output still looks like an opaque token.</para>
///
/// <para>An optional secret salt turns the digest into a keyed HMAC. The join-key property
/// survives — the same salt over the same value yields the same pseudonym everywhere — but
/// recovery now needs the salt, which is a deployment secret.</para>
///
/// <para>The recovery test below is the point of this file: it demonstrates the actual
/// attack against the unsalted form and then shows the salt defeating it. Asserting only
/// "salted differs from unsalted" would pass against a broken implementation that merely
/// appended the salt to the output.</para>
/// </remarks>
public class HashSaltTests
{
    private const string Salt = "deployment-secret-salt-from-kms";
    private const string Ssn = "123-45-6789";

    private static EffectivePolicy Policy(string? algorithm = null) => new(
        Version: "1.0",
        UserId: null,
        TenantId: null,
        SourceConnectionId: null,
        ResolvedAt: null,
        ExpiresAt: null,
        SourceProfiles: Array.Empty<string>(),
        Permissions: new PolicyPermissions(CanQuery: true, ReadOnly: true),
        ObjectRules: new ObjectRules(
            FieldRules: new FieldRules(
                MaskedFields: new[]
                {
                    new MaskingRule(
                        Field: "ssn",
                        MaskType: MaskType.Hash,
                        Parameters: algorithm is null
                            ? null
                            : new MaskingParameters(Algorithm: algorithm))
                })));

    private static string Mask(string value, string? salt = null, string? algorithm = null)
    {
        var record = new Dictionary<string, object?> { ["ssn"] = value };
        return (string)EnforcementEngine.ApplyFieldMasking(record, Policy(algorithm), salt)["ssn"]!;
    }

    private static string Sha256Of(string value)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)))
            .ToLowerInvariant()[..16];

    // -- The salt defeats brute force --------------------------------------

    [Fact]
    public void UnsaltedHash_IsRecoverableByRainbowTable()
    {
        // The vulnerability, demonstrated rather than asserted abstractly.
        var masked = Mask(Ssn);

        // An attacker who knows the format enumerates candidates and matches the digest.
        // Only the last four digits are unknown here, which is a 10^4 search — the full
        // 10^9 SSN space is minutes of CPU.
        string? recovered = null;
        for (var candidate = 6780; candidate < 6800; candidate++)
        {
            var guess = $"123-45-{candidate}";
            if (Sha256Of(guess) == masked)
            {
                recovered = guess;
                break;
            }
        }

        recovered.Should().Be(Ssn, "an unsalted digest is trivially reversible");
    }

    [Fact]
    public void SaltedHash_ResistsTheSameAttack()
    {
        var masked = Mask(Ssn, Salt);

        for (var candidate = 6780; candidate < 6800; candidate++)
        {
            Sha256Of($"123-45-{candidate}").Should().NotBe(masked);
        }

        masked.Should().NotBe(Ssn);
    }

    [Fact]
    public void SaltedValue_IsNeitherPlaintextNorPlainDigest()
    {
        var masked = Mask(Ssn, Salt);

        masked.Should().NotBe(Ssn);
        masked.Should().NotBe(Mask(Ssn));
        // Not merely the digest with the salt glued on, which would leak the digest.
        masked.Should().NotContain(Mask(Ssn));
    }

    // -- Cross-language agreement ------------------------------------------

    [Theory]
    // Pinned from the Python and TypeScript SDKs, which agree with each other. A salted
    // pseudonym is only usable as a join key if all three compute the same bytes, and a
    // determinism-only assertion (mask twice, compare to itself) passes even when every
    // implementation disagrees with the others.
    [InlineData(null, "dce7edba05c55d1b")]
    [InlineData("sha256", "dce7edba05c55d1b")]
    [InlineData("sha512", "e6ebbe7ba1c748e4")]
    [InlineData("blake2b", "8ec2eb016a655de4")]
    public void SaltedDigest_MatchesTheOtherSdks(string? algorithm, string expected)
    {
        Mask(Ssn, Salt, algorithm).Should().Be(expected);
    }

    [Fact]
    public void UnsaltedDigest_StillMatchesTheOtherSdks()
    {
        Mask(Ssn).Should().Be("01a54629efb95228");
    }

    // -- The join-key property ---------------------------------------------

    [Fact]
    public void SameValueAndSalt_YieldTheSamePseudonym()
    {
        Mask(Ssn, Salt).Should().Be(Mask(Ssn, Salt));
    }

    [Fact]
    public void DifferentValues_YieldDifferentPseudonyms()
    {
        Mask(Ssn, Salt).Should().NotBe(Mask("987-65-4321", Salt));
    }

    [Fact]
    public void DifferentSalts_YieldDifferentPseudonyms()
    {
        // Why the salt must match everywhere the pseudonym is joined.
        Mask(Ssn, "salt-a").Should().NotBe(Mask(Ssn, "salt-b"));
    }

    [Fact]
    public void Output_KeepsThe16HexCharShape()
    {
        // The wire contract does not change, so a fixed-width column still fits.
        Mask(Ssn, Salt).Should().MatchRegex("^[0-9a-f]{16}$");
    }

    // -- Backward compatibility --------------------------------------------

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void NoSalt_PreservesTheExistingDigest(string? empty)
    {
        // Existing join keys must not change for integrators who do not opt in.
        Mask(Ssn, empty).Should().Be(Sha256Of(Ssn));
    }

    // -- Algorithms --------------------------------------------------------

    [Theory]
    [InlineData("sha256")]
    [InlineData("sha512")]
    [InlineData("blake2b")]
    public void EveryPermittedAlgorithm_HonoursTheSalt(string algorithm)
    {
        var salted = Mask(Ssn, Salt, algorithm);

        salted.Should().NotBe(Mask(Ssn, null, algorithm));
        salted.Should().MatchRegex("^[0-9a-f]{16}$");
    }

    [Theory]
    [InlineData("sha512")]
    [InlineData("blake2b")]
    public void SaltedAlgorithms_DoNotCollapseOntoSaltedSha256(string algorithm)
    {
        Mask(Ssn, Salt, algorithm).Should().NotBe(Mask(Ssn, Salt, "sha256"));
    }

    [Fact]
    public void UnsupportedAlgorithm_StillFailsClosedWhenSalted()
    {
        // Salting must not turn a redact-on-unknown-algorithm into a disclosure.
        Mask(Ssn, Salt, "md5").Should().Be("[REDACTED]");
    }

    [Fact]
    public void LongSalt_IsHashedDownPerRfc2104()
    {
        // A key longer than the block size must be reduced, not truncated or rejected.
        var longSalt = new string('k', 200);

        Mask(Ssn, longSalt).Should().MatchRegex("^[0-9a-f]{16}$");
        Mask(Ssn, longSalt).Should().NotBe(Mask(Ssn));
    }

    // -- Nested shapes -----------------------------------------------------

    [Fact]
    public void NestedRecords_AreSalted()
    {
        var body = new Dictionary<string, object?>
        {
            ["results"] = new List<object?>
            {
                new Dictionary<string, object?>
                {
                    ["patient"] = new Dictionary<string, object?> { ["ssn"] = Ssn }
                }
            }
        };

        var salted = EnforcementEngine.ApplyFieldMasking(body, Policy(), Salt);
        var unsalted = EnforcementEngine.ApplyFieldMasking(body, Policy());

        static string Extract(Dictionary<string, object?> tree)
        {
            var results = (List<object?>)tree["results"]!;
            var first = (Dictionary<string, object?>)results[0]!;
            var patient = (Dictionary<string, object?>)first["patient"]!;
            return (string)patient["ssn"]!;
        }

        Extract(salted).Should().NotBe(Ssn);
        Extract(salted).Should().NotBe(Extract(unsalted));
    }
}
