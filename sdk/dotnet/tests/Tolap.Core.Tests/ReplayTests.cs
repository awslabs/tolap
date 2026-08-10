using System.Security;
using System.Text;
using System.Text.Json.Nodes;
using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// Replay detection for signed security contexts (spec section 13).
/// </summary>
/// <remarks>
/// A signed context was previously a bearer credential replayable for its full TTL:
/// capture it and it worked until it expired. <c>Jti</c> plus an
/// <see cref="IReplayGuard"/> closes that. The two halves matter separately: the
/// identifier is <b>inside the signed payload</b> so it cannot be stripped or swapped
/// to dodge the check, and the guard is the state the SDK deliberately does not assume.
///
/// A test that only asserted "the same context twice is rejected" would pass against an
/// implementation that left the id outside the signature — where an attacker simply
/// removes it. The stripping and swapping cases below are the ones that distinguish a
/// real fix.
/// </remarks>
public class ReplayTests
{
    private const string Key = "test-signing-key-do-not-use-in-production";

    private static EffectivePolicy Policy() => new(
        Version: "1.0",
        UserId: "user-001",
        TenantId: "tenant-001",
        SourceConnectionId: "ds-postgres-001",
        ResolvedAt: DateTimeOffset.UtcNow,
        ExpiresAt: DateTimeOffset.UtcNow.AddHours(1),
        SourceProfiles: Array.Empty<string>(),
        Permissions: new PolicyPermissions(CanQuery: true, ReadOnly: true));

    private static string Signed(string? jti = null)
    {
        var context = SecurityContextBuilder.Build(
            "user-001", "tenant-001", new[] { Policy() }, TimeSpan.FromHours(1), jti);
        return SecurityContextSigner.Serialize(SecurityContextSigner.Sign(context, Key));
    }

    private static JsonObject Decode(string serialized)
    {
        var json = Encoding.UTF8.GetString(Convert.FromBase64String(serialized));
        return JsonNode.Parse(json)!.AsObject();
    }

    private static string Encode(JsonObject payload)
        => Convert.ToBase64String(Encoding.UTF8.GetBytes(payload.ToJsonString()));

    // -- The jti is minted -------------------------------------------------

    [Fact]
    public void Build_MintsAJtiByDefault()
    {
        var context = SecurityContextBuilder.Build(
            "user-001", "tenant-001", new[] { Policy() });

        context.Jti.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void Build_GivesEachContextADistinctJti()
    {
        var first = SecurityContextBuilder.Build("user-001", "tenant-001", new[] { Policy() });
        var second = SecurityContextBuilder.Build("user-001", "tenant-001", new[] { Policy() });

        first.Jti.Should().NotBe(second.Jti);
    }

    [Fact]
    public void Build_HonoursAnExplicitJti()
    {
        var context = SecurityContextBuilder.Build(
            "user-001", "tenant-001", new[] { Policy() }, jti: "ctx-abc");

        context.Jti.Should().Be("ctx-abc");
    }

    [Fact]
    public void Build_TreatsEmptyStringAsOptingOut()
    {
        var context = SecurityContextBuilder.Build(
            "user-001", "tenant-001", new[] { Policy() }, jti: "");

        context.Jti.Should().BeNull();
    }

    // -- The jti is signed -------------------------------------------------

    [Fact]
    public void Jti_IsInsideTheSignedPayload()
    {
        var context = SecurityContextBuilder.Build(
            "user-001", "tenant-001", new[] { Policy() }, jti: "ctx-abc");

        SecurityContextSigner.BuildCanonicalPayload(context)
            .Should().Contain("\"jti\":\"ctx-abc\"");
    }

    [Fact]
    public void StrippingTheJti_InvalidatesTheSignature()
    {
        // The attack a guard alone would not stop.
        var signed = SecurityContextSigner.Sign(
            SecurityContextBuilder.Build(
                "user-001", "tenant-001", new[] { Policy() }, jti: "ctx-abc"),
            Key);

        SecurityContextSigner.Validate(signed, Key).Should().BeTrue();

        SecurityContextSigner.Validate(signed with { Jti = null }, Key).Should().BeFalse();
    }

    [Fact]
    public void SwappingTheJti_InvalidatesTheSignature()
    {
        // Otherwise a replayer just mints a fresh id per replay.
        var signed = SecurityContextSigner.Sign(
            SecurityContextBuilder.Build(
                "user-001", "tenant-001", new[] { Policy() }, jti: "ctx-abc"),
            Key);

        SecurityContextSigner.Validate(signed with { Jti = "ctx-xyz" }, Key)
            .Should().BeFalse();
    }

    [Fact]
    public void AbsentJti_ProducesThePreJtiCanonicalBytes()
    {
        // Backward compatibility: emitting the key unconditionally would change the
        // signed bytes for every existing context and break the known-answer fixtures.
        var context = SecurityContextBuilder.Build(
            "user-001", "tenant-001", new[] { Policy() }, jti: "");

        var payload = SecurityContextSigner.BuildCanonicalPayload(context);

        payload.Should().NotContain("jti");
    }

    [Fact]
    public void EmptyAndAbsentJti_SignIdentically()
    {
        // "" and absent are semantically the same context; they must not yield two
        // different signatures.
        var built = SecurityContextBuilder.Build(
            "user-001", "tenant-001", new[] { Policy() }, TimeSpan.FromHours(1), "");

        var withEmpty = built with { Jti = "" };
        var withNull = built with { Jti = null };

        SecurityContextSigner.BuildCanonicalPayload(withEmpty)
            .Should().Be(SecurityContextSigner.BuildCanonicalPayload(withNull));
    }

    // -- The guard rejects reuse -------------------------------------------

    [Fact]
    public void FirstUse_IsAccepted()
    {
        var guard = new InMemoryReplayGuard();

        var context = SecurityContextSigner.Deserialize(Signed(), Key, guard);

        context.Policies[0].Permissions.CanQuery.Should().BeTrue();
    }

    [Fact]
    public void SecondUseOfTheSameContext_IsRejected()
    {
        var guard = new InMemoryReplayGuard();
        var serialized = Signed();

        SecurityContextSigner.Deserialize(serialized, Key, guard);

        var replay = () => SecurityContextSigner.Deserialize(serialized, Key, guard);

        replay.Should().Throw<SecurityException>().WithMessage("*replay*");
    }

    [Fact]
    public void TwoDistinctContexts_BothSucceed()
    {
        // The guard must not reject merely because a user appeared twice.
        var guard = new InMemoryReplayGuard();

        var act = () =>
        {
            SecurityContextSigner.Deserialize(Signed(), Key, guard);
            SecurityContextSigner.Deserialize(Signed(), Key, guard);
        };

        act.Should().NotThrow();
    }

    [Fact]
    public void WithoutAGuard_ReplayIsAllowed()
    {
        // Documents the default: TTL-bounded replay, as specified.
        var serialized = Signed();

        var act = () =>
        {
            SecurityContextSigner.Deserialize(serialized, Key);
            SecurityContextSigner.Deserialize(serialized, Key);
        };

        act.Should().NotThrow();
    }

    [Fact]
    public void SeparateGuards_DoNotShareState()
    {
        // Pins the documented limitation of the in-memory guard.
        var serialized = Signed();

        var act = () =>
        {
            SecurityContextSigner.Deserialize(serialized, Key, new InMemoryReplayGuard());
            SecurityContextSigner.Deserialize(serialized, Key, new InMemoryReplayGuard());
        };

        act.Should().NotThrow();
    }

    // -- The guard requires a jti ------------------------------------------

    [Fact]
    public void ContextWithoutAJti_IsRejectedWhenGuarding()
    {
        // Skipping the check for a jti-less context is the failure mode to avoid.
        var act = () => SecurityContextSigner.Deserialize(
            Signed(jti: ""), Key, new InMemoryReplayGuard());

        act.Should().Throw<SecurityException>().WithMessage("*requires a 'jti'*");
    }

    [Fact]
    public void ForgedJti_IsRejectedBeforeTheGuardSeesIt()
    {
        // Adding a jti to a context signed without one changes the signed bytes, so it
        // fails on signature and never reaches the guard.
        var payload = Decode(Signed(jti: ""));
        payload["jti"] = "attacker-chosen";

        var act = () => SecurityContextSigner.Deserialize(
            Encode(payload), Key, new InMemoryReplayGuard());

        act.Should().Throw<SecurityException>().WithMessage("*signature*");
    }

    // -- Ordering ----------------------------------------------------------

    [Fact]
    public void ExpiredContext_DoesNotConsumeItsJti()
    {
        // If the guard ran before expiry validation, an attacker could pre-register the
        // id of a context that had not been used yet, and the legitimate holder would
        // then be refused.
        var guard = new InMemoryReplayGuard();
        var expired = SecurityContextSigner.Serialize(SecurityContextSigner.Sign(
            SecurityContextBuilder.Build(
                "user-001", "tenant-001", new[] { Policy() },
                TimeSpan.FromHours(-1), "ctx-abc"),
            Key));

        var act = () => SecurityContextSigner.Deserialize(expired, Key, guard);
        act.Should().Throw<SecurityException>().WithMessage("*expired*");

        // The id was never consumed, so a fresh context using it still works.
        guard.CheckAndRegister("ctx-abc", null).Should().BeTrue();
    }

    [Fact]
    public void BadlySignedContext_DoesNotConsumeItsJti()
    {
        var guard = new InMemoryReplayGuard();
        var payload = Decode(Signed(jti: "ctx-abc"));
        payload["integrity"]!["signature"] = Convert.ToBase64String(Encoding.UTF8.GetBytes("wrong"));

        var act = () => SecurityContextSigner.Deserialize(Encode(payload), Key, guard);
        act.Should().Throw<SecurityException>();

        guard.CheckAndRegister("ctx-abc", null).Should().BeTrue();
    }

    // -- InMemoryReplayGuard ----------------------------------------------

    [Fact]
    public void Guard_IsFirstWins()
    {
        var guard = new InMemoryReplayGuard();

        guard.CheckAndRegister("a", null).Should().BeTrue();
        guard.CheckAndRegister("a", null).Should().BeFalse();
    }

    [Fact]
    public void Guard_TreatsDistinctIdsIndependently()
    {
        var guard = new InMemoryReplayGuard();

        guard.CheckAndRegister("a", null).Should().BeTrue();
        guard.CheckAndRegister("b", null).Should().BeTrue();
    }

    [Fact]
    public void Guard_DropsEntriesOnceExpired()
    {
        // Memory is bounded by one TTL's worth of contexts, not unbounded.
        var guard = new InMemoryReplayGuard();
        guard.CheckAndRegister("a", DateTimeOffset.UtcNow.AddHours(-1)).Should().BeTrue();

        // A later call sweeps the expired entry; the id becomes reusable, which is safe
        // because a context carrying it would now fail the expiry check.
        guard.CheckAndRegister("b", null).Should().BeTrue();
        guard.CheckAndRegister("a", null).Should().BeTrue();
    }

    [Fact]
    public void Guard_IsSafeUnderConcurrentUse()
    {
        // Exactly one caller may win a race for the same id; check-then-register as two
        // steps would let several through.
        var guard = new InMemoryReplayGuard();
        var wins = 0;

        Parallel.For(0, 64, _ =>
        {
            if (guard.CheckAndRegister("contended", DateTimeOffset.UtcNow.AddHours(1)))
                Interlocked.Increment(ref wins);
        });

        wins.Should().Be(1, "exactly one caller may register a given jti");
    }
}
