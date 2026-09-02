using System.Text.Json;
using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// Purpose and delegation chain inside the signed bytes (spec sections 2 and 15).
/// </summary>
/// <remarks>
/// <para>The point of signing them is narrow and load-bearing: a purpose-scoped policy is
/// only worth resolving if the purpose that selected it cannot then be swapped, and a
/// delegation chain that can be rewritten is decoration —
/// <see cref="DelegationChainValidator"/> would be validating the attacker's own arithmetic.
/// So the tests below assert tamper-detection, not merely that a signature is produced.</para>
/// <para>Every assertion here is unconditional. A test that skipped when the fixture lacked
/// an expected value is how the original cross-SDK signing divergence survived.</para>
/// </remarks>
public class PurposeSigningConformanceTests
{
    private const string FixturePath = "signing/hmac-sha256-purpose-bound.json";

    private static (SecurityContext Context, JsonElement Fixture, string SecretKey) LoadFixture()
    {
        var root = FixtureHelper.ReadFixtureAsJson(FixturePath);
        var secretKey = root.GetProperty("secretKey").GetString()!;
        var policy = TolapJsonOptions.Deserialize<EffectivePolicy>(
            root.GetProperty("payload").GetRawText());
        var chain = TolapJsonOptions.Deserialize<DelegationHop[]>(
            root.GetProperty("delegationChain").GetRawText());

        var context = new SecurityContext(
            Version: policy.Version,
            UserId: policy.UserId!,
            TenantId: policy.TenantId!,
            IssuedAt: policy.ResolvedAt!.Value,
            ExpiresAt: policy.ExpiresAt!.Value,
            Policies: new[] { policy },
            DeclaredPurpose: root.GetProperty("declaredPurpose").GetString(),
            DelegationChain: chain);

        return (context, root, secretKey);
    }

    [Fact]
    public void TheFixtureCarriesWhatTheseTestsAssume()
    {
        var (context, _, _) = LoadFixture();

        context.DeclaredPurpose.Should().Be("campaign-x-overlap");
        context.DelegationChain.Should().HaveCount(3);
        context.Policies[0].PurposeProfile.Should().NotBeNull(
            "the fixture exists to cover a purpose-bound policy");
    }

    [Fact]
    public void CanonicalPayload_MatchesTheFixtureBytes()
    {
        // Bytes, not signatures. When two SDKs disagree, comparing signatures says only
        // "different"; comparing the canonical string says where.
        var (context, fixture, _) = LoadFixture();

        SecurityContextSigner.BuildCanonicalPayload(context)
            .Should().Be(fixture.GetProperty("canonicalPayload").GetString());
    }

    [Fact]
    public void CanonicalPayload_TruncatesAHopTimestampToMilliseconds()
    {
        // The fixture's third hop carries microsecond input. Milliseconds are the greatest
        // precision all three runtimes represent exactly, and this is the only fixture that
        // exercises the rule for a timestamp nested inside an array of objects.
        var (context, _, _) = LoadFixture();

        var payload = SecurityContextSigner.BuildCanonicalPayload(context);

        payload.Should().Contain("2026-09-01T10:00:00.123Z");
        payload.Should().NotContain("123456", "sub-millisecond digits are truncated, never rounded");
    }

    [Fact]
    public void Sign_HmacSha256_MatchesTheSharedKnownAnswer()
    {
        var (context, fixture, secretKey) = LoadFixture();

        var signed = SecurityContextSigner.Sign(context, secretKey, SigningAlgorithm.HmacSha256);

        signed.Integrity!.Signature.Should()
            .Be(fixture.GetProperty("expectedSignature").GetString());
    }

    [Fact]
    public void Sign_HmacSha512_MatchesTheSharedKnownAnswer()
    {
        var (context, fixture, secretKey) = LoadFixture();

        var signed = SecurityContextSigner.Sign(context, secretKey, SigningAlgorithm.HmacSha512);

        signed.Integrity!.Signature.Should()
            .Be(fixture.GetProperty("expectedSignatureSha512").GetString());
    }

    [Fact]
    public void Validate_AcceptsTheSignedFixtureContext()
    {
        // The paired control for every tamper case below: without it, a Validate that always
        // returned false would satisfy all of them.
        var (context, _, secretKey) = LoadFixture();
        var signed = SecurityContextSigner.Sign(context, secretKey);

        SecurityContextSigner.Validate(signed, secretKey).Should().BeTrue();
    }

    [Fact]
    public void Validate_RejectsAStrippedDeclaredPurpose()
    {
        // The attack this field exists to stop: remove the purpose and a purpose-scoped
        // context becomes an unscoped one.
        var (context, _, secretKey) = LoadFixture();
        var signed = SecurityContextSigner.Sign(context, secretKey);

        var stripped = signed with { DeclaredPurpose = null };

        SecurityContextSigner.Validate(stripped, secretKey).Should().BeFalse();
    }

    [Fact]
    public void Validate_RejectsASwappedDeclaredPurpose()
    {
        var (context, _, secretKey) = LoadFixture();
        var signed = SecurityContextSigner.Sign(context, secretKey);

        var swapped = signed with { DeclaredPurpose = "fraud-detection" };

        SecurityContextSigner.Validate(swapped, secretKey).Should().BeFalse();
    }

    [Fact]
    public void Validate_RejectsAStrippedDelegationChain()
    {
        var (context, _, secretKey) = LoadFixture();
        var signed = SecurityContextSigner.Sign(context, secretKey);

        SecurityContextSigner.Validate(signed with { DelegationChain = null }, secretKey)
            .Should().BeFalse();
    }

    [Fact]
    public void Validate_RejectsAnAppendedHop()
    {
        // Appending is the interesting direction: it is how a sub-agent would grant itself a
        // hop claiming a wider purpose than its parent passed down.
        var (context, _, secretKey) = LoadFixture();
        var signed = SecurityContextSigner.Sign(context, secretKey);

        var widened = signed with
        {
            DelegationChain = signed.DelegationChain!
                .Append(new DelegationHop("agent-exfil", PrincipalType.Agent, "campaign-y-export"))
                .ToArray()
        };

        SecurityContextSigner.Validate(widened, secretKey).Should().BeFalse();
    }

    [Fact]
    public void Validate_RejectsAMutatedHopPurpose()
    {
        var (context, _, secretKey) = LoadFixture();
        var signed = SecurityContextSigner.Sign(context, secretKey);

        var chain = signed.DelegationChain!.ToArray();
        chain[2] = chain[2] with { DeclaredPurpose = "campaign-*" };

        SecurityContextSigner.Validate(signed with { DelegationChain = chain }, secretKey)
            .Should().BeFalse();
    }

    [Fact]
    public void Validate_RejectsAWidenedHopScope()
    {
        var (context, _, secretKey) = LoadFixture();
        var signed = SecurityContextSigner.Sign(context, secretKey);

        var chain = signed.DelegationChain!.ToArray();
        chain[2] = chain[2] with { ScopeNarrowing = new[] { "read", "write" } };

        SecurityContextSigner.Validate(signed with { DelegationChain = chain }, secretKey)
            .Should().BeFalse();
    }

    [Fact]
    public void Validate_RejectsReorderedHops()
    {
        // Order carries meaning: hop 0 is the delegator. Reversing the chain would make the
        // sub-agent the root and every narrowing check compare the wrong pair.
        var (context, _, secretKey) = LoadFixture();
        var signed = SecurityContextSigner.Sign(context, secretKey);

        var reversed = signed.DelegationChain!.Reverse().ToArray();

        SecurityContextSigner.Validate(signed with { DelegationChain = reversed }, secretKey)
            .Should().BeFalse();
    }

    [Fact]
    public void Validate_RejectsAMutatedPurposeProfileOnThePolicy()
    {
        // purposeProfile rides inside the signed policies[] array, so it is covered with no
        // change to the projection. Asserted rather than assumed, because "covered for free"
        // is exactly the kind of claim that silently stops being true.
        var (context, _, secretKey) = LoadFixture();
        var signed = SecurityContextSigner.Sign(context, secretKey);

        var policy = signed.Policies[0];
        var widened = policy with
        {
            PurposeProfile = policy.PurposeProfile! with { ProhibitedActions = Array.Empty<string>() }
        };

        SecurityContextSigner.Validate(signed with { Policies = new[] { widened } }, secretKey)
            .Should().BeFalse();
    }

    [Fact]
    public void AbsentPurposeAndChain_SignToThePreFeatureBytes()
    {
        // The backward-compatibility guarantee, asserted directly rather than inferred from
        // the older fixtures still passing. Two contexts identical but for fields set to
        // null must produce byte-identical payloads, or every previously-signed context
        // fails to verify after this upgrade.
        var (context, _, _) = LoadFixture();

        var without = context with { DeclaredPurpose = null, DelegationChain = null };
        var withEmpties = context with { DeclaredPurpose = "", DelegationChain = Array.Empty<DelegationHop>() };

        SecurityContextSigner.BuildCanonicalPayload(withEmpties)
            .Should().Be(SecurityContextSigner.BuildCanonicalPayload(without),
                "\"\" and [] normalize to absent, so one context cannot have two valid signatures");

        SecurityContextSigner.BuildCanonicalPayload(without)
            .Should().NotContain("declaredPurpose").And.NotContain("delegationChain");
    }

    [Fact]
    public void TheOlderSigningFixturesAreUnchangedByThisFeature()
    {
        // The regression that matters most: every context signed before purpose binding must
        // still verify. Pinned here as well as in SigningConformanceTests so a change to the
        // projection fails in the file that made it.
        var root = FixtureHelper.ReadFixtureAsJson("signing/hmac-sha256-known-answer.json");
        var policy = TolapJsonOptions.Deserialize<EffectivePolicy>(
            root.GetProperty("payload").GetRawText());

        var context = new SecurityContext(
            Version: policy.Version,
            UserId: policy.UserId!,
            TenantId: policy.TenantId!,
            IssuedAt: policy.ResolvedAt!.Value,
            ExpiresAt: policy.ExpiresAt!.Value,
            Policies: new[] { policy });

        var signed = SecurityContextSigner.Sign(
            context, root.GetProperty("secretKey").GetString()!, SigningAlgorithm.HmacSha256);

        signed.Integrity!.Signature.Should()
            .Be(root.GetProperty("expectedSignature").GetString());
    }

    [Fact]
    public void SerializeAndDeserialize_RoundTripsPurposeAndChain()
    {
        // Transport, as distinct from signing. A context whose chain survived signing but not
        // the base64 round-trip would verify and then arrive with no hops to validate.
        //
        // Built through SecurityContextBuilder rather than from the fixture, because
        // Deserialize checks expiry and the fixture's instants are fixed in the past -- which
        // is exactly what a known-answer fixture needs and exactly what a round-trip cannot
        // use.
        var (fixtureContext, _, secretKey) = LoadFixture();
        var context = SecurityContextBuilder.Build(
            userId: fixtureContext.UserId,
            tenantId: fixtureContext.TenantId,
            policies: fixtureContext.Policies,
            declaredPurpose: fixtureContext.DeclaredPurpose,
            delegationChain: fixtureContext.DelegationChain);
        var signed = SecurityContextSigner.Sign(context, secretKey);

        var restored = SecurityContextSigner.Deserialize(
            SecurityContextSigner.Serialize(signed), secretKey);

        restored.DeclaredPurpose.Should().Be("campaign-x-overlap");
        restored.DelegationChain.Should().HaveCount(3);
        restored.DelegationChain![2].PrincipalType.Should().Be(PrincipalType.Agent);
        restored.DelegationChain[2].ScopeNarrowing.Should().BeEquivalentTo(new[] { "read" });
        restored.Policies[0].PurposeProfile!.PurposeId.Should().Be("campaign-x-overlap");
    }

    [Fact]
    public void Deserialize_RefusesAnUnknownPrincipalType()
    {
        // Fail closed at the boundary, matching how an unknown mask type or filter operator is
        // treated. An unrecognized principal type must not reach chain validation as a value
        // no narrowing rule covers.
        const string json =
            """
            {"principalId":"agent-1","principalType":"daemon","declaredPurpose":"campaign-x"}
            """;

        var act = () => TolapJsonOptions.Deserialize<DelegationHop>(json);

        act.Should().Throw<JsonException>().WithMessage("*daemon*");
    }
}
