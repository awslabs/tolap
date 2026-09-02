using System.Text.Json;
using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// Action validation against a purpose profile (canonical-enforcement-spec.md section 15.2).
/// </summary>
/// <remarks>
/// Driven from <c>fixtures/enforcement/validate-action.json</c> so the three SDKs are held to
/// one table rather than three readings of it. The hand-written cases below cover what a
/// shared fixture cannot: the null-versus-empty distinction asserted on the model directly,
/// and the reason strings as literals.
/// </remarks>
public class ActionValidationTests
{
    private const string Fixture = "enforcement/validate-action.json";

    public static TheoryData<int> FixtureCases()
    {
        var cases = FixtureHelper.ReadFixtureAsJson(Fixture).GetProperty("cases");
        var data = new TheoryData<int>();
        for (var i = 0; i < cases.GetArrayLength(); i++)
            data.Add(i);
        return data;
    }

    [Theory]
    [MemberData(nameof(FixtureCases))]
    public void ValidateAction_MatchesTheSharedFixture(int index)
    {
        var testCase = FixtureHelper.ReadFixtureAsJson(Fixture).GetProperty("cases")[index];
        var actionCategory = testCase.GetProperty("actionCategory").GetString()!;
        var policy = TolapJsonOptions.Deserialize<EffectivePolicy>(
            testCase.GetProperty("policy").GetRawText());
        var expected = testCase.GetProperty("expected");

        // Asserted rather than assumed: a fixture whose policy lost its purposeProfile in
        // deserialization would make every case below pass vacuously against a null profile.
        policy.PurposeProfile.Should().NotBeNull(
            "case {0} exists to exercise a purpose profile", index);

        var result = EnforcementEngine.ValidateAction(actionCategory, policy.PurposeProfile!);

        result.Allowed.Should().Be(expected.GetProperty("allowed").GetBoolean(),
            "fixture case {0} (action '{1}')", index, actionCategory);

        if (expected.TryGetProperty("reason", out var reason))
            result.Reason.Should().Be(reason.GetString());
        else
            result.Reason.Should().BeNull("an allow carries no reason");
    }

    [Fact]
    public void FixtureCases_CoverBothOutcomes()
    {
        // A fixture that drifted into all-denials would still pass every case above while
        // proving nothing: blocking everything is trivially "correct". Spec section 14 and
        // testing-antipatterns.md both call this out, so the corpus itself is asserted.
        var cases = FixtureHelper.ReadFixtureAsJson(Fixture).GetProperty("cases");
        var outcomes = cases.EnumerateArray()
            .Select(c => c.GetProperty("expected").GetProperty("allowed").GetBoolean())
            .ToList();

        outcomes.Should().Contain(true).And.Contain(false);
    }

    [Fact]
    public void ValidateAction_NullAllowedActions_PermitsAnything()
    {
        // Null is unrestricted (spec section 3). Unlike allowedMethods, absence here is a
        // real grant rather than an oversight: a purpose may constrain only what is
        // forbidden.
        var profile = new PurposeProfile("campaign-x-overlap");

        EnforcementEngine.ValidateAction("anything-at-all", profile).Allowed.Should().BeTrue();
    }

    [Fact]
    public void ValidateAction_EmptyAllowedActions_DeniesEverything()
    {
        // The other half of section 3, and the one a truthiness check breaks: an empty
        // allow-list is the most restrictive value the model can express, so reading it as
        // falsy turns the strictest possible policy into no policy at all.
        var profile = new PurposeProfile(
            "campaign-x-overlap",
            AllowedActions: Array.Empty<string>());

        var result = EnforcementEngine.ValidateAction("aggregate_overlap", profile);

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be(
            "action 'aggregate_overlap' not in allowed actions for purpose 'campaign-x-overlap'");
    }

    [Fact]
    public void ValidateAction_EmptyProhibitedActions_RestrictsNothing()
    {
        // The mirror of the case above: [] on a DENY-list forbids nothing, because the list
        // enumerates what is refused rather than what is permitted. Paired with it so the
        // asymmetry is pinned rather than inferred.
        var profile = new PurposeProfile(
            "campaign-x-overlap",
            ProhibitedActions: Array.Empty<string>());

        EnforcementEngine.ValidateAction("export_pii", profile).Allowed.Should().BeTrue();
    }

    [Fact]
    public void ValidateAction_ProhibitedWins_WhenACategoryIsInBothLists()
    {
        var profile = new PurposeProfile(
            "campaign-x-overlap",
            AllowedActions: new[] { "export_pii", "aggregate_overlap" },
            ProhibitedActions: new[] { "export_pii" });

        var denied = EnforcementEngine.ValidateAction("export_pii", profile);
        var allowed = EnforcementEngine.ValidateAction("aggregate_overlap", profile);

        denied.Allowed.Should().BeFalse();
        denied.Reason.Should().Be(
            "action 'export_pii' is prohibited under purpose 'campaign-x-overlap'");

        // The paired control. Without it, an implementation that denied unconditionally
        // would satisfy the assertion above.
        allowed.Allowed.Should().BeTrue();
    }

    [Theory]
    [InlineData("EXPORT_PII")]
    [InlineData("Export_Pii")]
    [InlineData("export_PII")]
    public void ValidateAction_ProhibitionCatchesAnyCasing(string actionCategory)
    {
        // Case-insensitive deliberately, and in the opposite direction to the purposeId
        // comparison at resolution. Both choices deny: a mis-cased purpose resolves nothing,
        // and a mis-cased category is still caught. A case-sensitive test here would let
        // 'EXPORT_PII' walk straight past a prohibition on 'export_pii'.
        var profile = new PurposeProfile(
            "campaign-x-overlap",
            ProhibitedActions: new[] { "export_pii" });

        var result = EnforcementEngine.ValidateAction(actionCategory, profile);

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be(
            $"action '{actionCategory}' is prohibited under purpose 'campaign-x-overlap'",
            "the reason echoes the category as supplied, so the log shows what was attempted");
    }

    [Theory]
    [InlineData("AGGREGATE_OVERLAP")]
    [InlineData("Aggregate_Overlap")]
    public void ValidateAction_AllowListAlsoMatchesAnyCasing(string actionCategory)
    {
        // The paired direction: case-insensitivity must not be implemented only on the deny
        // path, or a correctly-configured tool is refused for its capitalization.
        var profile = new PurposeProfile(
            "campaign-x-overlap",
            AllowedActions: new[] { "aggregate_overlap" });

        EnforcementEngine.ValidateAction(actionCategory, profile).Allowed.Should().BeTrue();
    }

    [Fact]
    public void ValidateAction_EmptyCategory_IsDeniedAgainstAnAllowList()
    {
        // A wrapper that could not determine a category must not get a free pass by handing
        // over "". The empty string is not in any allow-list, so it is refused.
        var profile = new PurposeProfile(
            "campaign-x-overlap",
            AllowedActions: new[] { "aggregate_overlap" });

        var result = EnforcementEngine.ValidateAction("", profile);

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be(
            "action '' not in allowed actions for purpose 'campaign-x-overlap'");
    }

    [Fact]
    public void ValidateAction_ReasonNamesThePurpose_NotJustTheAction()
    {
        // Two purposes can forbid the same category for different reasons, so the purpose is
        // in the message. Integrators log and branch on these strings.
        var first = new PurposeProfile("campaign-x-overlap", ProhibitedActions: new[] { "export_pii" });
        var second = new PurposeProfile("fraud-detection", ProhibitedActions: new[] { "export_pii" });

        EnforcementEngine.ValidateAction("export_pii", first).Reason
            .Should().Contain("campaign-x-overlap");
        EnforcementEngine.ValidateAction("export_pii", second).Reason
            .Should().Contain("fraud-detection");
    }

    [Fact]
    public void ValidateAction_DoesNotConsultObjectRulesOrPermissions()
    {
        // ValidateAction answers one question. The read gate, object rules and endpoint
        // rules are separate checks that the wrapper sequences around it, and folding any of
        // them in here would mean a purpose-agnostic policy silently changed behaviour when
        // this function was added.
        var profile = new PurposeProfile(
            "campaign-x-overlap",
            AllowedActions: new[] { "aggregate_overlap" });

        EnforcementEngine.ValidateAction("aggregate_overlap", profile).Allowed.Should().BeTrue();
    }
}
