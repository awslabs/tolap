using Tolap.Core;
using Tolap.Mcp;
using FluentAssertions;
using Microsoft.SemanticKernel;
using Xunit;

namespace Tolap.Examples;

/// <summary>
/// Asserts both .NET framework examples enforce, not merely that they compile.
/// </summary>
/// <remarks>
/// <para>
/// Parametrised across frameworks on purpose. A per-framework test would pass if one integration
/// quietly returned the raw rows, because nothing would compare it to the other. Here both must
/// produce the <i>same</i> enforced output.
/// </para>
/// <para>
/// <see cref="Expected"/> is identical to the Python and TypeScript suites', which is the point:
/// the examples across all three languages make one claim, so a cross-language divergence shows up
/// as a different result rather than hiding behind separately-written expectations.
/// </para>
/// </remarks>
public class ExamplesTests
{
    /// <summary>
    /// What the policy must produce from <see cref="TolapSetup.FakeRows"/>: the region filter drops
    /// eu-west (4 -> 3), MaxResults caps at 2, ssn is hidden, dob is redacted.
    /// </summary>
    private static readonly List<Dictionary<string, object?>> Expected = new()
    {
        new() { ["id"] = 1, ["name"] = "Alice Nguyen", ["region"] = "us-east", ["dob"] = "[REDACTED]" },
        new() { ["id"] = 2, ["name"] = "Bruno Sato", ["region"] = "us-east", ["dob"] = "[REDACTED]" },
    };

    /// <summary>Each framework driven through its own registered entry point.</summary>
    private static List<Dictionary<string, object?>> Invoke(string framework, string table)
        => framework switch
        {
            "mcp-server" => McpServerExample.QueryPatients(table),
            "semantic-kernel" => new SemanticKernelExample().QueryPatients(table),
            _ => throw new ArgumentOutOfRangeException(nameof(framework)),
        };

    [Theory]
    [InlineData("mcp-server")]
    [InlineData("semantic-kernel")]
    public void PermittedTable_ReturnsTheEnforcedRows(string framework)
    {
        Invoke(framework, "patients").Should().BeEquivalentTo(Expected);
    }

    [Fact]
    public void Control_TheFakeSourceReallyReturnsMore()
    {
        // Without this, the assertion above could pass against an empty source.
        TolapSetup.FakeRows.Count.Should().BeGreaterThan(Expected.Count);
        TolapSetup.FakeRows.Should().Contain(r => r.ContainsKey("ssn"));
    }

    [Theory]
    [InlineData("mcp-server")]
    [InlineData("semantic-kernel")]
    public void HiddenField_NeverReachesTheCaller(string framework)
    {
        Invoke(framework, "patients").Should().OnlyContain(r => !r.ContainsKey("ssn"));
    }

    [Theory]
    [InlineData("mcp-server")]
    [InlineData("semantic-kernel")]
    public void MaskedField_IsRedacted(string framework)
    {
        var originals = TolapSetup.FakeRows.Select(r => (string?)r["dob"]).ToHashSet();

        Invoke(framework, "patients").Should().OnlyContain(r => !originals.Contains((string?)r["dob"]));
    }

    [Theory]
    [InlineData("mcp-server")]
    [InlineData("semantic-kernel")]
    public void RowFilterAndLimit_AreApplied(string framework)
    {
        var rows = Invoke(framework, "patients");

        rows.Should().OnlyContain(r => (string?)r["region"] == "us-east");
        rows.Should().HaveCount(2);
    }

    [Theory]
    [InlineData("mcp-server")]
    [InlineData("semantic-kernel")]
    public void DeniedTable_ThrowsRatherThanReturningData(string framework)
    {
        // A denial must be distinguishable from an empty result: an agent that cannot tell "no
        // rows matched" from "you may not read this" will retry forever, and an audit trail that
        // conflates them cannot answer what was refused.
        var act = () => Invoke(framework, "encounters");

        act.Should().Throw<UnauthorizedAccessException>();
    }

    [Fact]
    public void SemanticKernel_RegistersTheFunctionWithTheKernel()
    {
        // Proves the attribute wiring works, not just the method body: a plugin whose function is
        // never discovered would pass every assertion above while being invisible to the planner.
        var kernel = Kernel.CreateBuilder().Build();
        kernel.Plugins.AddFromType<SemanticKernelExample>("patients");

        kernel.Plugins.GetFunction("patients", "query_patients").Should().NotBeNull();
    }
}

/// <summary>
/// The enforcement-mode example, executed rather than trusted.
/// </summary>
/// <remarks>
/// An example nothing runs will drift; one that mis-wires enforcement teaches people to bypass it.
/// These run the example's own methods and assert the property it claims — that the two modes agree
/// — so a regression in either path fails here rather than in a reader's terminal.
/// </remarks>
public class EnforcementModeExampleTests
{
    [Fact]
    public async Task BothModes_ReturnIdenticalRows()
    {
        var rewritten = await EnforcementModeExample.RunAsync(SqlEnforcementMode.RewriteAndPost);
        var postOnly = await EnforcementModeExample.RunAsync(SqlEnforcementMode.PostOnly);

        postOnly.Final.Should().BeEquivalentTo(rewritten.Final);

        // And the modes really did ask the database for different things — otherwise the
        // equality above would hold trivially.
        rewritten.Prep.Rewritten.Should().BeTrue();
        postOnly.Prep.Rewritten.Should().BeFalse();
        postOnly.Prep.Query.Should().Be(EnforcementModeExample.Query);
        rewritten.FromDatabase.Count.Should().BeLessThan(postOnly.FromDatabase.Count);
    }

    [Fact]
    public async Task MatchesThePythonAndTypeScriptExamples()
    {
        // All three languages state the same expectation on purpose. A per-language expectation
        // would let one SDK quietly return something else, because nothing would compare them.
        var run = await EnforcementModeExample.RunAsync(SqlEnforcementMode.RewriteAndPost);

        run.Final.Should().HaveCount(1);
        run.Final[0]["id"].Should().Be(1);
        run.Final[0]["name"].Should().Be("Alice Nguyen");
        run.Final[0]["region"].Should().Be("us-east");
        run.Final[0]["dob"].Should().Be("[REDACTED]");
    }

    [Theory]
    [InlineData(SqlEnforcementMode.RewriteAndPost)]
    [InlineData(SqlEnforcementMode.PostOnly)]
    public async Task HidesSsnAndRedactsDob_InBothModes(SqlEnforcementMode mode)
    {
        var run = await EnforcementModeExample.RunAsync(mode);

        // The fake database really did return ssn, so its absence is enforcement rather than a
        // fixture that never had it.
        run.FromDatabase.Should().Contain(r => r.ContainsKey("ssn"));
        run.Final.Should().OnlyContain(r => !r.ContainsKey("ssn"));
        run.Final.Should().OnlyContain(r => Equals(r["dob"], "[REDACTED]"));
    }

    [Fact]
    public async Task TheExampleRunsCleanAndAgrees()
    {
        // RunExampleAsync throws if the modes disagree, so this covers that path too.
        var act = async () => await EnforcementModeExample.RunExampleAsync();

        await act.Should().NotThrowAsync();
    }
}

/// <summary>
/// The purpose-binding example, executed rather than trusted.
/// </summary>
/// <remarks>
/// <para>
/// Each test asserts an <i>outcome</i> — which policy resolved, which action was refused, the
/// reason string — rather than that the example ran without throwing. An example that printed
/// plausible-looking verdicts while enforcing nothing is worse than no example.
/// </para>
/// <para>
/// The expectations here are byte-identical to
/// <c>examples/python/test_examples.py</c> and <c>examples/typescript/examples.test.ts</c>, for the
/// same reason the framework suites share one <c>Expected</c> value: one signed policy must behave
/// the same in all three SDKs, so a divergence surfaces as a different result.
/// </para>
/// </remarks>
public class PurposeBindingExampleTests
{
    // ---------------------------------------------------------------- resolution filtering (15.1)

    [Fact]
    public void NoDeclaredPurpose_ResolvesDenyAll_WhenEveryCandidateIsPurposeScoped()
    {
        var policy = PurposeBindingExample.ResolveFor(
            [PurposeBindingExample.CampaignDefinition(), PurposeBindingExample.FraudDefinition()],
            declaredPurpose: null);

        policy.SourceProfiles.Should().BeEmpty();
        policy.Permissions.CanQuery.Should().BeFalse();
        policy.PurposeProfile.Should().BeNull();
    }

    [Fact]
    public void DeclaredPurpose_ResolvesOnlyTheMatchingPolicy()
    {
        var policy = PurposeBindingExample.ResolveFor(
            [PurposeBindingExample.CampaignDefinition(), PurposeBindingExample.FraudDefinition()],
            PurposeBindingExample.CampaignPurpose);

        // The other purpose's rules were never merged, which is the point of filtering before
        // the merge rather than after it.
        policy.SourceProfiles.Should().Equal("campaign-x-overlap-agent");
        policy.PurposeProfile!.PurposeId.Should().Be("campaign-x-overlap");
        policy.Limits!.MaxResults.Should().Be(10000);
        policy.ObjectRules!.AllowedObjects.Should().NotContain("flagged_accounts");
    }

    [Fact]
    public void PurposeComparison_IsCaseSensitive()
    {
        var policy = PurposeBindingExample.ResolveFor(
            [PurposeBindingExample.CampaignDefinition(), PurposeBindingExample.FraudDefinition()],
            "Campaign-X-Overlap");

        policy.SourceProfiles.Should().BeEmpty();
        policy.Permissions.CanQuery.Should().BeFalse();
    }

    [Fact]
    public void APurposeAgnosticPolicy_StillResolvesWithoutAPurpose()
    {
        // The paired allow: purpose binding is additive, so a policy carrying no profile behaves
        // exactly as it did before the feature existed.
        var policy = PurposeBindingExample.ResolveFor(
            [
                PurposeBindingExample.CampaignDefinition(),
                PurposeBindingExample.FraudDefinition(),
                PurposeBindingExample.BaselineDefinition(),
            ],
            declaredPurpose: null);

        policy.SourceProfiles.Should().Equal("marketing-baseline");
        policy.Permissions.CanQuery.Should().BeTrue();
        policy.PurposeProfile.Should().BeNull();
    }

    // ------------------------------------------------------------------- delegation chain (15.3)

    [Fact]
    public void AThreeHopNarrowingChain_IsAllowed()
    {
        var result = DelegationChainValidator.Validate(PurposeBindingExample.NarrowingChain());

        result.Allowed.Should().BeTrue();
        result.Reason.Should().BeNull();
    }

    [Fact]
    public void AFourthHopThatWidens_IsRefused()
    {
        var chain = PurposeBindingExample.NarrowingChain();

        var result = DelegationChainValidator.Validate(
            [.. chain, PurposeBindingExample.WideningHop()]);

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be(
            "delegation hop 3 purpose 'campaign-y-export' is not within parent scope 'campaign-x-overlap'");
    }

    [Fact]
    public void SegmentBoundaryExtension_IsANarrowing()
    {
        DelegationChainValidator
            .Validate(PurposeBindingExample.TwoHop("campaign-x", "campaign-x-overlap"))
            .Allowed.Should().BeTrue();
    }

    [Fact]
    public void MidSegmentExtension_IsNot()
    {
        // The sharp case. A plain prefix test accepts this; 'campaign-x' and 'campaign-xyz-evil'
        // are unrelated purposes, one of which merely begins with the other's characters.
        var result = DelegationChainValidator.Validate(
            PurposeBindingExample.TwoHop("campaign-x", "campaign-xyz-evil"));

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be(
            "delegation hop 1 purpose 'campaign-xyz-evil' is not within parent scope 'campaign-x'");
    }

    [Fact]
    public void NarrowingScopes_AreAllowed_AndWideningOnesAreNot()
    {
        DelegationChainValidator
            .Validate(PurposeBindingExample.ScopeHops(["read", "aggregate"], ["read"]))
            .Allowed.Should().BeTrue();

        var widened = DelegationChainValidator.Validate(
            PurposeBindingExample.ScopeHops(["read"], ["read", "write"]));

        widened.Allowed.Should().BeFalse();
        widened.Reason.Should().Be("delegation hop 1 scopes exceed parent delegation");
    }

    // -------------------------------------------------------------------- action validation (15.2)

    private static AccessResult Check(string toolName)
    {
        var wrapper = new SecureContextToolWrapper(new SecureContextWrapperOptions(
            PurposeBindingExample.SigningKey,
            ToolActionCategories: PurposeBindingExample.ToolActionCategories));

        return wrapper.PreExecute(PurposeBindingExample.SignedContext(), new PreExecuteArgs(toolName));
    }

    [Fact]
    public void APermittedCategory_IsAllowed()
    {
        var result = Check("segment_overlap");

        result.Allowed.Should().BeTrue();
        result.Reason.Should().BeNull();
    }

    [Fact]
    public void AProhibitedCategory_IsDenied()
    {
        var result = Check("export_customers");

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be(
            "action 'export_pii' is prohibited under purpose 'campaign-x-overlap'");
    }

    [Fact]
    public void ACategoryOutsideTheAllowedList_IsDenied()
    {
        var result = Check("inspect_account");

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be(
            "action 'inspect_account' not in allowed actions for purpose 'campaign-x-overlap'");
    }

    [Fact]
    public void AnUnmappedTool_IsDenied_AsAConfigurationFault()
    {
        var result = Check("join_external");

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be("action category not declared for tool");
        result.Reason.Should().Be(PurposeActionResolver.UndeclaredCategoryReason);
    }

    // ----------------------------------------------------------------------------- judge (15.4)

    [Theory]
    [InlineData(true, 0.95, JudgeDisposition.Allow)]
    [InlineData(false, 0.95, JudgeDisposition.Block)]
    [InlineData(true, 0.70, JudgeDisposition.Escalate)]
    public async Task TheStubJudgesVerdict_MapsToTheDocumentedDisposition(
        bool aligned, double confidence, JudgeDisposition expected)
    {
        var judge = new PurposeBindingExample.StubJudge(
            new JudgeResult(aligned, confidence, "stub"));

        var outcome = await JudgeGate.EvaluateAsync(
            PurposeBindingExample.JudgedPolicy(), judge, "segment_overlap(campaign_x)");

        outcome.Disposition.Should().Be(expected);
        // escalate is NOT an allow. A wrapper with no review handler denies.
        outcome.Allowed.Should().Be(expected == JudgeDisposition.Allow);
    }

    // ------------------------------------------------------- purpose and chain inside the signature

    [Fact]
    public void TheSignedContext_Verifies()
    {
        var context = PurposeBindingExample.SignedContext();

        SecurityContextSigner.Validate(context, PurposeBindingExample.SigningKey).Should().BeTrue();
        context.DeclaredPurpose.Should().Be("campaign-x-overlap");
        context.DelegationChain.Should().HaveCount(3);
    }

    [Fact]
    public void MutatingThePurposeOrTheChain_BreaksTheSignature()
    {
        // Without this the validator above would be checking the attacker's own arithmetic.
        SecurityContextSigner
            .Validate(PurposeBindingExample.Repurposed(), PurposeBindingExample.SigningKey)
            .Should().BeFalse();
        SecurityContextSigner
            .Validate(PurposeBindingExample.Rechained(), PurposeBindingExample.SigningKey)
            .Should().BeFalse();
        SecurityContextSigner
            .Validate(PurposeBindingExample.Appended(), PurposeBindingExample.SigningKey)
            .Should().BeFalse();
        // Reordering included: hop 0 is the delegator, so reversing a chain makes the sub-agent
        // the root.
        SecurityContextSigner
            .Validate(PurposeBindingExample.Reordered(), PurposeBindingExample.SigningKey)
            .Should().BeFalse();
    }

    [Fact]
    public async Task TheExampleRunsClean_AndPrintsTheConclusionTheOtherTwoLanguagesPrint()
    {
        // RunExampleAsync throws if a mutated context still verifies, so this covers that path.
        // The captured lines are asserted rather than merely produced: the three languages print
        // byte-identical output, so these strings appear verbatim in the Python and TypeScript
        // suites too, and a divergence in any SDK fails here.
        var original = Console.Out;
        var captured = new StringWriter();
        try
        {
            Console.SetOut(captured);
            await PurposeBindingExample.RunExampleAsync();
        }
        finally
        {
            Console.SetOut(original);
        }

        var output = captured.ToString();

        output.Should().Contain(
            "  (no purpose)                      DENY      deny-all: 0 policies resolved, canQuery=false");
        output.Should().Contain(
            "  'campaign-x-overlap'              ALLOW     campaign-x-overlap-agent (maxResults=10000)");
        output.Should().Contain(
            "  campaign-x -> campaign-xyz-evil   DENY      delegation hop 1 purpose 'campaign-xyz-evil' is not within parent scope 'campaign-x'");
        output.Should().Contain(
            "  join_external                     DENY      action category not declared for tool");
        output.Should().Contain("  aligned, confidence 0.70          escalate  ");
        output.Should().Contain("  declared purpose swapped          BROKEN    to 'fraud-detection'");
        output.Should().Contain("the judge can only withdraw an allowance, never grant one");
    }
}

