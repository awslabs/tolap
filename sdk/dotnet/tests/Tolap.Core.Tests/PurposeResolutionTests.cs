using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// Resolution-time purpose filtering (canonical-enforcement-spec.md section 15.1).
/// </summary>
/// <remarks>
/// <para>The definitions and assignments come from the shared fixture corpus rather than
/// being restated here, so the same four policies drive the Python and TypeScript suites and
/// a divergence in the filter shows up as a fixture disagreement rather than three
/// independently-plausible test files.</para>
/// <para>Every denial has a paired allow. A filter that excluded everything would satisfy
/// the deny-all cases on its own, which is the failure mode testing-antipatterns.md
/// section 3 describes.</para>
/// </remarks>
public class PurposeResolutionTests
{
    private const string Tenant = "tenant-acme-retail";
    private const string User = "user-marketing-001";
    private const string Source = "db:marketing:customer_segments";
    private const string CampaignPurpose = "campaign-x-overlap";

    private static PolicyDefinition Definition(string name) =>
        FixtureHelper.ReadFixtureAs<PolicyDefinition>($"policies/{name}.json");

    private static PolicyAssignment Assignment(string name) =>
        FixtureHelper.ReadFixtureAs<PolicyAssignment>($"assignments/{name}.json");

    private static readonly PolicyDefinition Scoped = Definition("purpose-campaign-overlap");
    private static readonly PolicyDefinition Fraud = Definition("purpose-fraud-detection");
    private static readonly PolicyDefinition Agnostic = Definition("purpose-agnostic-baseline");
    private static readonly PolicyDefinition Judged = Definition("purpose-judge-enabled");

    private static EffectivePolicy Resolve(
        IReadOnlyList<PolicyDefinition> definitions,
        IReadOnlyList<PolicyAssignment> assignments,
        string? declaredPurpose)
        => PolicyResolutionEngine.Resolve(
            userId: User,
            tenantId: Tenant,
            sourceConnectionId: Source,
            assignments: assignments,
            definitions: definitions,
            getGroups: _ => Array.Empty<string>(),
            getRoles: _ => Array.Empty<string>(),
            declaredPurpose: declaredPurpose);

    [Fact]
    public void TheFixturesAreWhatTheseTestsAssume()
    {
        // Guards every case below. If the fixtures were edited so that, say, the scoped
        // policy lost its profile, the filtering assertions would pass against a policy set
        // that no longer exercises filtering at all.
        Scoped.PurposeProfile!.PurposeId.Should().Be(CampaignPurpose);
        Fraud.PurposeProfile!.PurposeId.Should().Be("fraud-detection");
        Judged.PurposeProfile!.PurposeId.Should().Be(CampaignPurpose);
        Agnostic.PurposeProfile.Should().BeNull();

        // All four must cover the source under test, or a case would "pass" because
        // sourcePatterns excluded the policy rather than because the purpose filter did.
        foreach (var definition in new[] { Scoped, Fraud, Agnostic, Judged })
        {
            definition.SourcePatterns.Should().Contain("db:marketing:*",
                "{0} must reach the source these tests resolve", definition.Name);
        }
    }

    [Fact]
    public void Resolve_WithoutAPurpose_KeepsOnlyThePurposeAgnosticPolicy()
    {
        var result = Resolve(
            new[] { Scoped, Agnostic },
            new[] { Assignment("purpose-campaign-overlap"), Assignment("purpose-agnostic-baseline") },
            declaredPurpose: null);

        result.SourceProfiles.Should().BeEquivalentTo(new[] { "marketing-baseline" });
        result.PurposeProfile.Should().BeNull("no purpose-scoped policy resolved");

        // The scoped policy's rules must not have leaked in. Asserting the profile is absent
        // is not enough on its own -- the rules could still have merged while the profile was
        // dropped, which is the specific failure filtering-after-merge produces.
        result.ObjectRules!.FieldRules!.HiddenFields
            .Should().NotContain("customer_segments.ssn is masked only by the scoped policy");
        result.Limits!.MaxResults.Should().Be(2000, "only the baseline's limit applies");
    }

    [Fact]
    public void Resolve_WithAMatchingPurpose_IncludesTheScopedPolicy()
    {
        var result = Resolve(
            new[] { Scoped, Agnostic },
            new[] { Assignment("purpose-campaign-overlap"), Assignment("purpose-agnostic-baseline") },
            declaredPurpose: CampaignPurpose);

        result.SourceProfiles.Should().BeEquivalentTo(
            new[] { "campaign-x-overlap-agent", "marketing-baseline" });
        result.PurposeProfile!.PurposeId.Should().Be(CampaignPurpose);
        result.PurposeProfile.ProhibitedActions.Should().Contain("export_pii");

        // The merge ran across both, so the more restrictive limit wins.
        result.Limits!.MaxResults.Should().Be(2000);
    }

    [Fact]
    public void Resolve_WithAWrongPurpose_ExcludesTheNonMatchingScopedPolicy()
    {
        var result = Resolve(
            new[] { Scoped, Fraud },
            new[] { Assignment("purpose-campaign-overlap"), Assignment("purpose-fraud-detection") },
            declaredPurpose: CampaignPurpose);

        result.SourceProfiles.Should().BeEquivalentTo(new[] { "campaign-x-overlap-agent" });
        result.PurposeProfile!.PurposeId.Should().Be(CampaignPurpose);

        // The fraud policy permits enumerate_individuals, which the campaign purpose
        // forbids. If it had merged, that grant would be present -- and this is the case that
        // shows purpose filtering changes the *access*, not just the label.
        result.PurposeProfile.AllowedActions.Should().NotContain("inspect_account");
        result.Limits!.MaxResults.Should().Be(10000,
            "the fraud policy's tighter limit of 500 must not apply");
    }

    [Fact]
    public void Resolve_TheOtherPurpose_ResolvesTheOtherPolicy()
    {
        // The paired control for the case above. Without it, a filter that dropped every
        // scoped policy except the first would still pass.
        var result = Resolve(
            new[] { Scoped, Fraud },
            new[] { Assignment("purpose-campaign-overlap"), Assignment("purpose-fraud-detection") },
            declaredPurpose: "fraud-detection");

        result.SourceProfiles.Should().BeEquivalentTo(new[] { "fraud-detection-agent" });
        result.Limits!.MaxResults.Should().Be(500);
    }

    [Fact]
    public void Resolve_AllPoliciesPurposeScopedAndNoPurposeDeclared_IsDenyAll()
    {
        var result = Resolve(
            new[] { Scoped, Fraud },
            new[] { Assignment("purpose-campaign-overlap"), Assignment("purpose-fraud-detection") },
            declaredPurpose: null);

        result.Permissions.CanQuery.Should().BeFalse();
        result.Permissions.ReadOnly.Should().BeTrue();
        result.SourceProfiles.Should().BeEmpty();
        result.PurposeProfile.Should().BeNull();
    }

    [Fact]
    public void Resolve_PurposeDeclaredButNoPolicyIsScoped_ResolvesNormally()
    {
        // Declaring a purpose must not restrict a purpose-agnostic policy set. Otherwise
        // switching a caller to declare its purpose would silently reduce its access, and
        // integrators would learn to leave the field off.
        var result = Resolve(
            new[] { Agnostic },
            new[] { Assignment("purpose-agnostic-baseline") },
            declaredPurpose: "some-purpose-nothing-declares");

        result.Permissions.CanQuery.Should().BeTrue();
        result.SourceProfiles.Should().BeEquivalentTo(new[] { "marketing-baseline" });
    }

    [Theory]
    [InlineData("Campaign-X-Overlap")]
    [InlineData("CAMPAIGN-X-OVERLAP")]
    [InlineData("campaign-X-overlap")]
    public void Resolve_PurposeMatchingIsCaseSensitive(string declaredPurpose)
    {
        // Exact and ordinal, deliberately unlike sourcePatterns and the chain-narrowing
        // globs, which are both case-insensitive. A case-insensitive comparison here would
        // let a caller resolve a policy written for a different spelling of the purpose.
        var result = Resolve(
            new[] { Scoped },
            new[] { Assignment("purpose-campaign-overlap") },
            declaredPurpose);

        result.Permissions.CanQuery.Should().BeFalse("'{0}' is not 'campaign-x-overlap'", declaredPurpose);
    }

    [Fact]
    public void Resolve_ExactPurpose_Resolves()
    {
        // Paired with the casing theory above: the exact spelling must work, or that theory
        // would pass against a filter that rejected everything.
        Resolve(new[] { Scoped }, new[] { Assignment("purpose-campaign-overlap") }, CampaignPurpose)
            .Permissions.CanQuery.Should().BeTrue();
    }

    [Fact]
    public void Resolve_EmptyPurposeString_IsTreatedAsNoPurpose()
    {
        // "" and omitted must not behave as two different declarations, matching how the
        // signing projection normalizes them. A truthiness-free comparison would treat "" as
        // a purpose that simply matches nothing -- the same outcome here, but for a reason
        // that would diverge from the signed bytes.
        var result = Resolve(
            new[] { Scoped, Agnostic },
            new[] { Assignment("purpose-campaign-overlap"), Assignment("purpose-agnostic-baseline") },
            declaredPurpose: "");

        result.SourceProfiles.Should().BeEquivalentTo(new[] { "marketing-baseline" });
    }

    [Fact]
    public void Resolve_PurposeIsNotAGlob()
    {
        // Declaring '*' must not resolve every purpose-scoped policy. This is why the
        // comparison is equality rather than a reuse of GlobMatch, and it is the case that
        // makes the difference security-relevant rather than stylistic.
        var result = Resolve(
            new[] { Scoped, Fraud },
            new[] { Assignment("purpose-campaign-overlap"), Assignment("purpose-fraud-detection") },
            declaredPurpose: "*");

        result.Permissions.CanQuery.Should().BeFalse();
        result.SourceProfiles.Should().BeEmpty();
    }

    [Fact]
    public void Resolve_TwoPoliciesSharingAPurpose_BothResolveAndMerge()
    {
        var result = Resolve(
            new[] { Scoped, Judged },
            new[] { Assignment("purpose-campaign-overlap"), Assignment("purpose-judged") },
            declaredPurpose: CampaignPurpose);

        result.SourceProfiles.Should().BeEquivalentTo(
            new[] { "campaign-x-overlap-agent", "campaign-x-overlap-judged" });

        // Intersected allow-list, unioned deny-list.
        result.PurposeProfile!.AllowedActions.Should().BeEquivalentTo(
            new[] { "aggregate_overlap", "count_segments" });
        result.PurposeProfile.ProhibitedActions.Should().Contain("export_pii").And.Contain("train_model");

        // The judge config came from one policy only and survives the merge.
        result.PurposeProfile.Judge!.Enabled.Should().BeTrue();
        result.PurposeProfile.Judge.Model.Should().Be("claude-sonnet");
    }

    [Fact]
    public void Resolve_TheSameDefinitionReachedByTwoAssignments_IsFilteredPerOccurrence()
    {
        // Resolution appends one definition per matching assignment, so the same policy can
        // appear twice. The filter must be a per-element predicate rather than a set
        // operation, or de-duplication changes which rules merge.
        var twice = new[]
        {
            Assignment("purpose-campaign-overlap"),
            Assignment("purpose-campaign-overlap") with
            {
                Assignee = new Assignee(AssigneeType.Group, "marketing-team")
            }
        };

        EffectivePolicy ResolveWithGroup(string? declaredPurpose) =>
            PolicyResolutionEngine.Resolve(
                userId: User,
                tenantId: Tenant,
                sourceConnectionId: Source,
                assignments: twice,
                definitions: new[] { Scoped },
                // Both assignments have to match, or this exercises de-duplication of one
                // entry rather than of two.
                getGroups: _ => new[] { "marketing-team" },
                getRoles: _ => Array.Empty<string>(),
                declaredPurpose: declaredPurpose);

        var matched = ResolveWithGroup(CampaignPurpose);
        var excluded = ResolveWithGroup(declaredPurpose: null);

        matched.SourceProfiles.Should().HaveCount(2, "one entry per matching assignment");
        matched.Permissions.CanQuery.Should().BeTrue();

        excluded.SourceProfiles.Should().BeEmpty();
        excluded.Permissions.CanQuery.Should().BeFalse();
    }

    [Fact]
    public void Resolve_PurposeFilteringComposesWithSourcePatterns()
    {
        // Both filters run before the merge and neither substitutes for the other. A matching
        // purpose must not rescue a policy scoped to a different source.
        var result = Resolve(
            new[] { Scoped },
            new[] { Assignment("purpose-campaign-overlap") },
            CampaignPurpose);

        var wrongSource = PolicyResolutionEngine.Resolve(
            userId: User,
            tenantId: Tenant,
            sourceConnectionId: "db:production:patient_records",
            assignments: new[] { Assignment("purpose-campaign-overlap") },
            definitions: new[] { Scoped },
            getGroups: _ => Array.Empty<string>(),
            getRoles: _ => Array.Empty<string>(),
            declaredPurpose: CampaignPurpose);

        result.Permissions.CanQuery.Should().BeTrue();
        wrongSource.Permissions.CanQuery.Should().BeFalse();
    }

    [Fact]
    public void Resolve_PurposeFilteringDoesNotRescueARevokedAssignment()
    {
        // Revocation is checked before definitions are even loaded (spec section 12), so a
        // declared purpose cannot reach a revoked grant. Asserted because purpose filtering
        // was inserted into the same pipeline.
        var revoked = Assignment("purpose-campaign-overlap") with
        {
            RevokedAt = DateTimeOffset.UtcNow.AddDays(-1)
        };

        Resolve(new[] { Scoped }, new[] { revoked }, CampaignPurpose)
            .Permissions.CanQuery.Should().BeFalse();
    }

    [Fact]
    public void Resolve_WithoutTheParameter_BehavesAsBeforeThisFeature()
    {
        // The backward-compatibility assertion, made against the seven-argument overload
        // rather than by passing null. Existing callers do not pass a purpose at all, and
        // this is the call they make.
        var result = PolicyResolutionEngine.Resolve(
            userId: User,
            tenantId: Tenant,
            sourceConnectionId: Source,
            assignments: new[] { Assignment("purpose-agnostic-baseline") },
            definitions: new[] { Agnostic },
            getGroups: _ => Array.Empty<string>(),
            getRoles: _ => Array.Empty<string>());

        result.Permissions.CanQuery.Should().BeTrue();
        result.PurposeProfile.Should().BeNull();
    }
}
