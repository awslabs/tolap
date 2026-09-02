using System.Text.Json;
using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// Merging purpose profiles into an effective policy (spec section 15.2).
/// </summary>
/// <remarks>
/// The profile is carried through the merge rather than consumed at resolution because every
/// enforcement entry point takes an <see cref="EffectivePolicy"/>. Without that, a
/// <c>purposeProfile</c> would be authorable and unenforceable — and it also means the purpose
/// rides inside the signed bytes with no change to the signing projection.
/// </remarks>
public class PurposeMergeTests
{
    private static readonly string[] Scenarios =
    {
        "purpose-profile-carried-through",
        "purpose-profile-actions-merge",
        "purpose-profile-conflicting-ids-deny-all",
        "purpose-profile-disjoint-allowed-denies-every-action"
    };

    public static TheoryData<string> ScenarioNames()
    {
        var data = new TheoryData<string>();
        foreach (var name in Scenarios)
            data.Add(name);
        return data;
    }

    [Theory]
    [MemberData(nameof(ScenarioNames))]
    public void Merge_MatchesTheSharedScenario(string name)
    {
        var fixture = FixtureHelper.ReadFixtureAsJson($"merge-scenarios/{name}.json");
        var inputs = fixture.GetProperty("inputs").EnumerateArray()
            .Select(p => TolapJsonOptions.Deserialize<PolicyDefinition>(p.GetRawText()))
            .ToList();
        var expected = fixture.GetProperty("expected");

        var result = PolicyMerger.Merge(inputs);

        result.SourceProfiles.Should().BeEquivalentTo(
            expected.GetProperty("sourceProfiles").EnumerateArray().Select(v => v.GetString()));
        result.Permissions.CanQuery.Should()
            .Be(expected.GetProperty("permissions").GetProperty("canQuery").GetBoolean());

        if (!expected.TryGetProperty("purposeProfile", out var expectedProfile))
        {
            result.PurposeProfile.Should().BeNull("scenario '{0}' expects no profile", name);
            return;
        }

        result.PurposeProfile.Should().NotBeNull("scenario '{0}'", name);
        result.PurposeProfile!.PurposeId.Should()
            .Be(expectedProfile.GetProperty("purposeId").GetString());

        AssertStringArray(expectedProfile, "allowedActions", result.PurposeProfile.AllowedActions, name);
        AssertStringArray(expectedProfile, "prohibitedActions", result.PurposeProfile.ProhibitedActions, name);

        if (expectedProfile.TryGetProperty("judge", out var expectedJudge))
        {
            result.PurposeProfile.Judge.Should().NotBeNull("scenario '{0}'", name);
            var judge = result.PurposeProfile.Judge!;
            judge.Enabled.Should().Be(expectedJudge.GetProperty("enabled").GetBoolean());
            judge.Model.Should().Be(expectedJudge.GetProperty("model").GetString());
            judge.HistoryWindow.Should().Be(expectedJudge.GetProperty("historyWindow").GetInt32());
            judge.ConfidenceThreshold.Should().Be(expectedJudge.GetProperty("confidenceThreshold").GetDouble());
            judge.EscalationThreshold.Should().Be(expectedJudge.GetProperty("escalationThreshold").GetDouble());
            judge.MaxLatencyMs.Should().Be(expectedJudge.GetProperty("maxLatencyMs").GetInt32());
        }
        else
        {
            result.PurposeProfile.Judge.Should().BeNull("scenario '{0}'", name);
        }
    }

    /// <remarks>
    /// Compared as a set, since union and intersection are unordered. Absent and empty are
    /// distinguished, because that is the distinction spec section 3 makes load-bearing.
    /// </remarks>
    private static void AssertStringArray(
        JsonElement expectedProfile, string property, string[]? actual, string scenario)
    {
        if (!expectedProfile.TryGetProperty(property, out var expected))
        {
            actual.Should().BeNull("scenario '{0}' expects no {1}", scenario, property);
            return;
        }

        actual.Should().NotBeNull("scenario '{0}' expects a {1}", scenario, property);
        actual.Should().BeEquivalentTo(expected.EnumerateArray().Select(v => v.GetString()));
    }

    private static PolicyDefinition WithProfile(string name, PurposeProfile? profile, int priority = 10) =>
        new(
            Version: "1.0",
            Name: name,
            Permissions: new PolicyPermissions(CanQuery: true, ReadOnly: true),
            Priority: priority,
            PurposeProfile: profile);

    [Fact]
    public void Merge_NoPolicyCarriesAProfile_LeavesTheEffectivePolicyUnscoped()
    {
        // The backward-compatibility case: a purpose-agnostic policy set must produce exactly
        // what it did before this field existed, including a null rather than an empty profile.
        var result = PolicyMerger.Merge(new[] { WithProfile("a", null), WithProfile("b", null) });

        result.PurposeProfile.Should().BeNull();
        result.Permissions.CanQuery.Should().BeTrue();
    }

    [Fact]
    public void Merge_ConflictingPurposeIds_IsDenyAll()
    {
        // Not "pick one" and not "drop the profile". Picking one applies rules authored for a
        // purpose the caller did not declare; dropping the profile turns a purpose-scoped
        // policy into an unscoped one. Both are worse than refusing.
        var result = PolicyMerger.Merge(new[]
        {
            WithProfile("a", new PurposeProfile("campaign-x-overlap")),
            WithProfile("b", new PurposeProfile("fraud-detection"))
        });

        result.Permissions.CanQuery.Should().BeFalse();
        result.SourceProfiles.Should().BeEmpty();
        result.PurposeProfile.Should().BeNull();
    }

    [Fact]
    public void Merge_PurposeIdComparisonIsCaseSensitive()
    {
        // Two spellings are two purposes, consistent with resolution. Collapsing them would
        // merge rules across what the SDK elsewhere treats as distinct purposes.
        var result = PolicyMerger.Merge(new[]
        {
            WithProfile("a", new PurposeProfile("campaign-x-overlap")),
            WithProfile("b", new PurposeProfile("Campaign-X-Overlap"))
        });

        result.Permissions.CanQuery.Should().BeFalse();
    }

    [Fact]
    public void Merge_AgreeingPurposeIds_Succeeds()
    {
        // The paired control for both cases above.
        var result = PolicyMerger.Merge(new[]
        {
            WithProfile("a", new PurposeProfile("campaign-x-overlap")),
            WithProfile("b", new PurposeProfile("campaign-x-overlap"))
        });

        result.Permissions.CanQuery.Should().BeTrue();
        result.PurposeProfile!.PurposeId.Should().Be("campaign-x-overlap");
    }

    [Fact]
    public void Merge_DisjointAllowedActions_YieldsEmptyRatherThanNull()
    {
        // The intersection is [] which denies every action. Collapsing it to null would mean
        // the opposite -- unrestricted -- so the assertion is on emptiness AND non-nullness.
        var result = PolicyMerger.Merge(new[]
        {
            WithProfile("a", new PurposeProfile("p-x", AllowedActions: new[] { "aggregate_overlap" })),
            WithProfile("b", new PurposeProfile("p-x", AllowedActions: new[] { "inspect_account" }))
        });

        result.PurposeProfile!.AllowedActions.Should().NotBeNull().And.BeEmpty();

        // And the consequence is real, not cosmetic: every action is now refused.
        EnforcementEngine.ValidateAction("aggregate_overlap", result.PurposeProfile!)
            .Allowed.Should().BeFalse();
    }

    [Fact]
    public void Merge_OneNullAllowList_DoesNotWidenTheOther()
    {
        // Null means "adds no restriction", so intersecting it with a list must yield the
        // list. An implementation that treated null as "everything" and intersected against a
        // universe would produce the same answer here; one that treated null as a reset to
        // unrestricted would widen, which is the failure worth pinning.
        var result = PolicyMerger.Merge(new[]
        {
            WithProfile("a", new PurposeProfile("p-x", AllowedActions: new[] { "aggregate_overlap" })),
            WithProfile("b", new PurposeProfile("p-x", AllowedActions: null))
        });

        result.PurposeProfile!.AllowedActions.Should().BeEquivalentTo(new[] { "aggregate_overlap" });
    }

    [Fact]
    public void Merge_ProhibitedActionsUnion_KeepsEveryPolicysDenials()
    {
        var result = PolicyMerger.Merge(new[]
        {
            WithProfile("a", new PurposeProfile("p-x", ProhibitedActions: new[] { "export_pii" })),
            WithProfile("b", new PurposeProfile("p-x", ProhibitedActions: new[] { "train_model" }))
        });

        result.PurposeProfile!.ProhibitedActions.Should()
            .BeEquivalentTo(new[] { "export_pii", "train_model" });
    }

    [Fact]
    public void Merge_AgnosticPlusScoped_CarriesTheScopedProfile()
    {
        var result = PolicyMerger.Merge(new[]
        {
            WithProfile("scoped", new PurposeProfile("p-x", AllowedActions: new[] { "aggregate_overlap" })),
            WithProfile("agnostic", null)
        });

        result.PurposeProfile!.PurposeId.Should().Be("p-x");
        result.PurposeProfile.AllowedActions.Should().BeEquivalentTo(new[] { "aggregate_overlap" },
            "a policy with no profile contributes no action restriction, and must not erase one");
    }

    [Fact]
    public void Merge_JudgeEnabledIsOred()
    {
        var result = PolicyMerger.Merge(new[]
        {
            WithProfile("a", new PurposeProfile("p-x", Judge: new JudgeConfig(Enabled: false))),
            WithProfile("b", new PurposeProfile("p-x", Judge: new JudgeConfig(Enabled: true)))
        });

        result.PurposeProfile!.Judge!.Enabled.Should().BeTrue("any policy may switch the judge on");
    }

    [Fact]
    public void Merge_JudgeEnabledFalseEverywhere_StaysExplicitlyFalse()
    {
        // Not null. The policies said "no judge" rather than saying nothing, and collapsing the
        // two would lose an author's explicit decision -- and, because absent fields are omitted
        // from the canonical form, would change the signed bytes as well.
        var result = PolicyMerger.Merge(new[]
        {
            WithProfile("a", new PurposeProfile("p-x", Judge: new JudgeConfig(Enabled: false))),
            WithProfile("b", new PurposeProfile("p-x", Judge: new JudgeConfig(Enabled: false)))
        });

        result.PurposeProfile!.Judge!.Enabled.Should().BeFalse();
    }

    [Fact]
    public void Merge_JudgeEnabledAbsentEverywhere_StaysAbsent()
    {
        // The third state. A judge block configuring only a threshold has not said whether the
        // judge is on, and inventing a false would be as wrong as inventing a true.
        var result = PolicyMerger.Merge(new[]
        {
            WithProfile("a", new PurposeProfile("p-x", Judge: new JudgeConfig(HistoryWindow: 5))),
            WithProfile("b", new PurposeProfile("p-x", Judge: new JudgeConfig(HistoryWindow: 7)))
        });

        result.PurposeProfile!.Judge!.Enabled.Should().BeNull();
        result.PurposeProfile.Judge.HistoryWindow.Should().Be(7);
    }

    [Fact]
    public void Merge_JudgeThresholdsTakeTheMaximum()
    {
        // Both maxima, and both for the same reason: a higher bar sends more calls to human
        // review rather than letting them through.
        var result = PolicyMerger.Merge(new[]
        {
            WithProfile("a", new PurposeProfile("p-x", Judge: new JudgeConfig(
                ConfidenceThreshold: 0.8, EscalationThreshold: 0.5, HistoryWindow: 5, MaxLatencyMs: 2500))),
            WithProfile("b", new PurposeProfile("p-x", Judge: new JudgeConfig(
                ConfidenceThreshold: 0.9, EscalationThreshold: 0.7, HistoryWindow: 12, MaxLatencyMs: 1500)))
        });

        var judge = result.PurposeProfile!.Judge!;
        judge.ConfidenceThreshold.Should().Be(0.9);
        judge.EscalationThreshold.Should().Be(0.7);
        judge.HistoryWindow.Should().Be(12, "more context helps a judge notice drift");
        judge.MaxLatencyMs.Should().Be(1500, "the tighter budget wins");
    }

    [Fact]
    public void Merge_DifferentJudgeModels_IsDenyAll()
    {
        // A verdict is only meaningful against the model that produced it, so there is no
        // most-restrictive combination of two models.
        var result = PolicyMerger.Merge(new[]
        {
            WithProfile("a", new PurposeProfile("p-x", Judge: new JudgeConfig(Model: "claude-sonnet"))),
            WithProfile("b", new PurposeProfile("p-x", Judge: new JudgeConfig(Model: "some-other-model")))
        });

        result.Permissions.CanQuery.Should().BeFalse();
        result.PurposeProfile.Should().BeNull();
    }

    [Fact]
    public void Merge_OneJudgeNamesAModelAndTheOtherDoesNot_KeepsTheNamedOne()
    {
        // The paired control: only a genuine disagreement refuses.
        var result = PolicyMerger.Merge(new[]
        {
            WithProfile("a", new PurposeProfile("p-x", Judge: new JudgeConfig(Model: "claude-sonnet"))),
            WithProfile("b", new PurposeProfile("p-x", Judge: new JudgeConfig(Enabled: true)))
        });

        result.PurposeProfile!.Judge!.Model.Should().Be("claude-sonnet");
    }

    [Fact]
    public void Merge_NoJudgeConfigured_LeavesJudgeNull()
    {
        var result = PolicyMerger.Merge(new[]
        {
            WithProfile("a", new PurposeProfile("p-x")),
            WithProfile("b", new PurposeProfile("p-x"))
        });

        result.PurposeProfile!.Judge.Should().BeNull(
            "an absent judge must stay absent, or every purpose-bound policy grows a judge block "
            + "and the canonical bytes change");
    }

    [Fact]
    public void Merge_JudgeFieldsAbsentOnBothSides_StayAbsent()
    {
        // Nullable rather than defaulted, so an unset threshold serializes as absent. Value
        // defaults would be written unconditionally by the canonical writer, which does no
        // default-value elision -- changing the signed bytes of every purpose-bound policy.
        var result = PolicyMerger.Merge(new[]
        {
            WithProfile("a", new PurposeProfile("p-x", Judge: new JudgeConfig(Enabled: true))),
            WithProfile("b", new PurposeProfile("p-x", Judge: new JudgeConfig(Enabled: true)))
        });

        var judge = result.PurposeProfile!.Judge!;
        judge.ConfidenceThreshold.Should().BeNull();
        judge.EscalationThreshold.Should().BeNull();
        judge.HistoryWindow.Should().BeNull();
        judge.MaxLatencyMs.Should().BeNull();
        judge.Model.Should().BeNull();
    }

    [Fact]
    public void Merge_SinglePolicy_PassesItsProfileThroughUnchanged()
    {
        var profile = new PurposeProfile(
            "campaign-x-overlap",
            Description: "Identify overlapping segments.",
            AllowedActions: new[] { "aggregate_overlap" },
            ProhibitedActions: new[] { "export_pii" },
            Judge: new JudgeConfig(Enabled: true, Model: "claude-sonnet"));

        var result = PolicyMerger.Merge(new[] { WithProfile("only", profile) });

        result.PurposeProfile.Should().BeEquivalentTo(profile);
    }

    [Fact]
    public void Merge_Description_ComesFromTheFirstPolicyThatHasOne()
    {
        // Merge is called with the list already ordered by ascending priority, so this is the
        // most specific policy's description.
        var result = PolicyMerger.Merge(new[]
        {
            WithProfile("a", new PurposeProfile("p-x"), priority: 10),
            WithProfile("b", new PurposeProfile("p-x", Description: "the only description"), priority: 20)
        });

        result.PurposeProfile!.Description.Should().Be("the only description");
    }
}
