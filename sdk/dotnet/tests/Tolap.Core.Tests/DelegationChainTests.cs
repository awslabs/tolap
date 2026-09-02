using System.Text.Json;
using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// Delegation chain narrowing (canonical-enforcement-spec.md section 15.3).
/// </summary>
/// <remarks>
/// The shared fixture is the contract; the hand-written cases add what it cannot express —
/// that the substring hole is closed for every shape of near-miss, and that an unusable
/// pattern denies rather than throwing.
/// </remarks>
public class DelegationChainTests
{
    private const string Fixture = "purpose-binding/delegation-chains.json";

    public static TheoryData<string> FixtureCases()
    {
        var cases = FixtureHelper.ReadFixtureAsJson(Fixture).GetProperty("cases");
        var data = new TheoryData<string>();
        foreach (var testCase in cases.EnumerateArray())
            data.Add(testCase.GetProperty("name").GetString()!);
        return data;
    }

    private static JsonElement CaseNamed(string name) =>
        FixtureHelper.ReadFixtureAsJson(Fixture).GetProperty("cases")
            .EnumerateArray()
            .Single(c => c.GetProperty("name").GetString() == name);

    [Theory]
    [MemberData(nameof(FixtureCases))]
    public void Validate_MatchesTheSharedFixture(string name)
    {
        var testCase = CaseNamed(name);
        var chainJson = testCase.GetProperty("chain");
        var chain = chainJson.ValueKind == JsonValueKind.Null
            ? null
            : TolapJsonOptions.Deserialize<DelegationHop[]>(chainJson.GetRawText());
        var expected = testCase.GetProperty("expected");

        var result = DelegationChainValidator.Validate(chain);

        result.Allowed.Should().Be(expected.GetProperty("allowed").GetBoolean(), "case '{0}'", name);

        if (expected.TryGetProperty("reason", out var reason))
            result.Reason.Should().Be(reason.GetString(), "case '{0}'", name);
        else
            result.Reason.Should().BeNull("an allow carries no reason");
    }

    [Fact]
    public void FixtureCases_CoverBothOutcomes()
    {
        // Blocking every chain would satisfy the denial cases and prove nothing.
        var outcomes = FixtureHelper.ReadFixtureAsJson(Fixture).GetProperty("cases")
            .EnumerateArray()
            .Select(c => c.GetProperty("expected").GetProperty("allowed").GetBoolean())
            .ToList();

        outcomes.Should().Contain(true).And.Contain(false);
    }

    private static DelegationHop Hop(string id, string? purpose = null, string[]? scopes = null) =>
        new(id, PrincipalType.Agent, DeclaredPurpose: purpose, ScopeNarrowing: scopes);

    [Fact]
    public void Validate_NullChain_IsAllowed()
    {
        // Absent is not suspicious: delegation is opt-in, so every context predating this
        // feature carries no chain and must keep resolving.
        DelegationChainValidator.Validate(null).Allowed.Should().BeTrue();
    }

    [Fact]
    public void Validate_EmptyChain_IsAllowed()
    {
        DelegationChainValidator.Validate(Array.Empty<DelegationHop>()).Allowed.Should().BeTrue();
    }

    [Fact]
    public void Validate_SingleHop_IsAllowed()
    {
        // No parent to widen against, so there is nothing to check -- however implausible the
        // purpose. A single hop declaring '*' is still just one hop.
        DelegationChainValidator.Validate(new[] { Hop("user-1", "*") })
            .Allowed.Should().BeTrue();
    }

    [Theory]
    // The hole a plain prefix test leaves open, in every shape it takes. Each of these
    // merely starts with the parent's characters and names an unrelated purpose.
    [InlineData("campaign-x", "campaign-xyz-evil")]
    [InlineData("campaign-x", "campaign-xx")]
    [InlineData("campaign-x", "campaign-x2")]
    [InlineData("campaign", "campaigns-all")]
    [InlineData("fraud", "fraudulent-export")]
    public void Validate_MidSegmentExtension_IsDenied(string parent, string child)
    {
        var result = DelegationChainValidator.Validate(new[] { Hop("p", parent), Hop("c", child) });

        result.Allowed.Should().BeFalse(
            "'{0}' only starts with '{1}'; it is not a narrowing of it", child, parent);
        result.Reason.Should().Be(
            $"delegation hop 1 purpose '{child}' is not within parent scope '{parent}'");
    }

    [Theory]
    // The paired direction: extension ON the boundary is the whole point of the rule, so a
    // validator that denied everything would fail here.
    [InlineData("campaign-x", "campaign-x-overlap")]
    [InlineData("campaign-x", "campaign-x-overlap-eu")]
    [InlineData("campaign", "campaign-x")]
    public void Validate_SegmentBoundaryExtension_IsAllowed(string parent, string child)
    {
        DelegationChainValidator.Validate(new[] { Hop("p", parent), Hop("c", child) })
            .Allowed.Should().BeTrue();
    }

    [Theory]
    [InlineData("campaign-*", "campaign-x-overlap")]
    [InlineData("campaign-*", "campaign-x")]
    [InlineData("*", "anything-at-all")]
    [InlineData("campaign-x-*", "campaign-x-overlap")]
    public void Validate_ParentGlob_AdmitsWhatItMatches(string parent, string child)
    {
        DelegationChainValidator.Validate(new[] { Hop("p", parent), Hop("c", child) })
            .Allowed.Should().BeTrue();
    }

    [Theory]
    [InlineData("campaign-*", "fraud-detection")]
    [InlineData("campaign-x-*", "campaign-y-overlap")]
    public void Validate_ParentGlob_RefusesWhatItDoesNotMatch(string parent, string child)
    {
        DelegationChainValidator.Validate(new[] { Hop("p", parent), Hop("c", child) })
            .Allowed.Should().BeFalse();
    }

    [Theory]
    [InlineData("campaign-x", "Campaign-X")]
    [InlineData("campaign-x", "CAMPAIGN-X-OVERLAP")]
    [InlineData("campaign-*", "Campaign-X-Overlap")]
    public void Validate_PurposeComparison_IsCaseSensitive(string parent, string child)
    {
        // Case-sensitive to match the purposeId comparison at resolution, and unlike the two
        // glob helpers this borrows nothing from. Both existing helpers are
        // case-INsensitive, so a validator built on either would admit these.
        DelegationChainValidator.Validate(new[] { Hop("p", parent), Hop("c", child) })
            .Allowed.Should().BeFalse();
    }

    [Fact]
    public void Validate_ExactMatchAcrossEveryHop_IsAllowed()
    {
        var chain = new[]
        {
            Hop("user-1", "campaign-x-overlap"),
            Hop("orch-1", "campaign-x-overlap"),
            Hop("agent-1", "campaign-x-overlap")
        };

        DelegationChainValidator.Validate(chain).Allowed.Should().BeTrue();
    }

    [Fact]
    public void Validate_ScopeSubset_IsAllowedAndWideningIsNot()
    {
        var narrowing = new[] { Hop("p", scopes: new[] { "read", "aggregate" }), Hop("c", scopes: new[] { "read" }) };
        var widening = new[] { Hop("p", scopes: new[] { "read" }), Hop("c", scopes: new[] { "read", "write" }) };

        DelegationChainValidator.Validate(narrowing).Allowed.Should().BeTrue();

        var denied = DelegationChainValidator.Validate(widening);
        denied.Allowed.Should().BeFalse();
        denied.Reason.Should().Be("delegation hop 1 scopes exceed parent delegation");
    }

    [Fact]
    public void Validate_EmptyParentScope_LeavesNothingForAChildToClaim()
    {
        // scopeNarrowing lists the scopes still IN FORCE, not the ones removed, so an empty
        // parent set means nothing remains to pass on. Reading it the other way round would
        // make this the most permissive case rather than the strictest.
        var chain = new[] { Hop("p", scopes: Array.Empty<string>()), Hop("c", scopes: new[] { "read" }) };

        DelegationChainValidator.Validate(chain).Allowed.Should().BeFalse();
    }

    [Fact]
    public void Validate_EmptyChildScope_IsAllowed()
    {
        // The paired direction: a child may hold nothing. Only widening is refused.
        var chain = new[] { Hop("p", scopes: new[] { "read" }), Hop("c", scopes: Array.Empty<string>()) };

        DelegationChainValidator.Validate(chain).Allowed.Should().BeTrue();
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void Validate_ScopeAbsentOnEitherSide_AddsNoConstraint(bool parentHasScopes, bool childHasScopes)
    {
        var chain = new[]
        {
            Hop("p", scopes: parentHasScopes ? new[] { "read" } : null),
            Hop("c", scopes: childHasScopes ? new[] { "read", "write", "admin" } : null)
        };

        DelegationChainValidator.Validate(chain).Allowed.Should().BeTrue();
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(false, false)]
    public void Validate_PurposeAbsentOnEitherSide_AddsNoConstraint(bool parentHasPurpose, bool childHasPurpose)
    {
        // A hop declaring no purpose is not claiming one, so there is nothing to exceed.
        // Refusing an undeclared purpose is resolution's job (section 15.1), and doing it
        // here as well would deny every legitimate partial chain.
        var chain = new[]
        {
            Hop("p", parentHasPurpose ? "campaign-x" : null),
            Hop("c", childHasPurpose ? "fraud-detection" : null)
        };

        DelegationChainValidator.Validate(chain).Allowed.Should().BeTrue();
    }

    [Theory]
    [InlineData("")]
    public void Validate_EmptyPurposeString_IsTreatedAsAbsent(string childPurpose)
    {
        // "" and omitted must not behave as two different declarations, matching how the
        // signing projection normalizes them.
        var chain = new[] { Hop("p", "campaign-x"), Hop("c", childPurpose) };

        DelegationChainValidator.Validate(chain).Allowed.Should().BeTrue();
    }

    [Fact]
    public void Validate_DeniesAtTheFirstOffendingHop_AndNamesIt()
    {
        // The index is part of the reason string so an operator can find the hop. Asserted on
        // a chain where an earlier hop is fine, or a validator that always reported hop 1
        // would pass.
        var chain = new[]
        {
            Hop("user-1", "campaign-*"),
            Hop("orch-1", "campaign-x-*"),
            Hop("agent-1", "campaign-x-overlap"),
            Hop("agent-2", "campaign-y-export")
        };

        var result = DelegationChainValidator.Validate(chain);

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be(
            "delegation hop 3 purpose 'campaign-y-export' is not within parent scope 'campaign-x-overlap'");
    }

    [Fact]
    public void Validate_ChecksPurposeBeforeScope_SoTheMoreSpecificReasonWins()
    {
        // Both rules are violated at the same hop. The purpose message names the offending
        // value; the scope message cannot, so purpose is reported.
        var chain = new[]
        {
            new DelegationHop("p", PrincipalType.User, "campaign-x", ScopeNarrowing: new[] { "read" }),
            new DelegationHop("c", PrincipalType.Agent, "fraud-detection", ScopeNarrowing: new[] { "read", "write" })
        };

        DelegationChainValidator.Validate(chain).Reason.Should().Contain("purpose");
    }

    [Fact]
    public void Validate_APatternThatCannotBeEvaluatedInTime_DeniesRatherThanThrowing()
    {
        // Fail closed under the regex match timeout, as PolicyResolutionEngine.GlobMatch and the
        // row-filter patterns do. A pattern that cannot be evaluated must not become an escaping
        // exception in the middle of an authorization decision -- nor a pass.
        //
        // Catastrophic backtracking needs a match that FAILS: the trailing "-x" is absent from
        // the child purpose, so the engine explores every way the wildcards could split the input
        // before giving up. A pattern that merely contains many wildcards and succeeds returns in
        // microseconds and would leave this path untested.
        var pathological = string.Concat(Enumerable.Repeat("*a", 40)) + "-x";
        var chain = new[] { Hop("p", pathological), Hop("c", new string('a', 200)) };

        var act = () => DelegationChainValidator.Validate(chain);

        act.Should().NotThrow();
        act().Allowed.Should().BeFalse();
    }

    [Fact]
    public void Validate_IgnoresPrincipalTypeAndTimestamps()
    {
        // Narrowing is about purpose and scope. Whether a hop is a user, an agent or a
        // service does not change whether it widened, and neither does when it happened --
        // those fields exist for the audit trail. Pinned so a future rule keyed on principal
        // type is a deliberate change rather than a surprise.
        var chain = new[]
        {
            new DelegationHop("agent-1", PrincipalType.Agent, "campaign-x",
                DelegatedAt: DateTimeOffset.Parse("2026-09-01T12:00:00Z")),
            new DelegationHop("user-1", PrincipalType.User, "campaign-x-overlap",
                DelegatedAt: DateTimeOffset.Parse("2020-01-01T00:00:00Z"))
        };

        DelegationChainValidator.Validate(chain).Allowed.Should().BeTrue();
    }
}
