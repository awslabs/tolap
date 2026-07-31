using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// A SecurityContext carries exactly one effective policy (spec section 2 rule 3).
/// </summary>
/// <remarks>
/// <para>The <c>Policies</c> array is the wire shape, but every enforcement path reads
/// only the first element -- six call sites across the wrappers use
/// <c>FirstOrDefault()</c> or <c>Policies[0]</c>, and nothing iterates. A context
/// carrying two policies would therefore sign both and enforce one: a silent truncation
/// moved from construction time to enforcement time, which is harder to notice, not
/// easier.</para>
/// <para>Python and TypeScript refuse the same shape. TypeScript's case was the worst of
/// the three before the fix: passing an array stored it verbatim, signed a payload whose
/// <c>policies[0]</c> had keys "0" and "1", validated that signature as true, and then
/// failed during enforcement with an error naming neither the mistake nor the fix.</para>
/// </remarks>
public class SecurityContextPolicyCountTests
{
    private static EffectivePolicy Policy(string profile) =>
        new(Version: "1.0", UserId: "u", TenantId: "t", SourceConnectionId: null,
            ResolvedAt: null, ExpiresAt: null, SourceProfiles: [profile],
            Permissions: new PolicyPermissions(CanQuery: true));

    private static SecurityContext Build(params EffectivePolicy[] policies) =>
        new("1.0", "u", "t", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1), policies);

    [Fact]
    public void TwoPolicies_AreRefusedRatherThanSilentlyUnderEnforced()
    {
        var act = () => Build(Policy("db-policy"), Policy("api-policy"));

        act.Should().Throw<ArgumentException>()
            .WithMessage("*single effective policy*")
            .WithMessage("*one context per data source*");
    }

    [Fact]
    public void OnePolicy_IsAccepted()
    {
        Build(Policy("db-policy")).Policies.Should().HaveCount(1);
    }

    [Fact]
    public void NoPolicies_IsAccepted_BecauseCarryingNonePermitsNothing()
    {
        // Distinct from carrying two: an empty context grants nothing, so it is safe.
        // Refusing it would break deserializing a context that legitimately has none.
        Build().Policies.Should().BeEmpty();
    }

    [Fact]
    public void NullPolicies_StillProducesSignableBytes()
    {
        // A context deserialized without a "policies" key must not throw here; the
        // signing projection renders it as an empty array.
        var context = new SecurityContext("1.0", "u", "t",
            DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1), null!);

        SecurityContextSigner.BuildCanonicalPayload(context).Should().Contain("\"policies\":[]");
    }

    [Fact]
    public void WithExpression_StillWorks_SoTheSignerCanStripIntegrity()
    {
        // The signer relies on `context with { Integrity = null }`. Converting the record
        // from positional to explicit properties must not break that.
        var signed = Build(Policy("db-policy")) with { Integrity = new IntegrityBlock(SigningAlgorithm.HmacSha256, "sig") };

        (signed with { Integrity = null }).Integrity.Should().BeNull();
    }
}
