using FluentAssertions;
using Tolap.Core;
using Tolap.Mcp;
using Xunit;

namespace Tolap.Mcp.Tests;

/// <summary>
/// The semantic judge as the wrapper actually runs it (spec section 15.4).
/// </summary>
/// <remarks>
/// <para><c>JudgeGateTests</c> covers the decision. This covers the wiring, which is the part
/// that silently does not exist if it is wrong: a gate nobody calls passes all of its own tests
/// while a policy's <c>judge</c> block quietly governs nothing. Every case here goes through
/// <c>PreExecuteAsync</c> — the call an integrator makes.</para>
/// <para>The ordering assertions are the ones worth reading. A judge that ran <i>before</i> the
/// deterministic checks, or that could turn a denial into an allow, would be a privilege
/// escalation dressed as a safety feature.</para>
/// </remarks>
public class JudgeWrapperTests
{
    private const string Key = "judge-wrapper-key";
    private const string Model = "test-model-1";

    /// <summary>A judge returning a fixed verdict, with a call counter.</summary>
    private sealed class StubJudge : IJudge
    {
        private readonly JudgeResult _result;
        public int Calls { get; private set; }
        public string? LastToolCall { get; private set; }
        public string[]? LastHistory { get; private set; }

        public StubJudge(JudgeResult result, string modelId = Model)
        {
            _result = result;
            ModelId = modelId;
        }

        public string ModelId { get; }

        public Task<JudgeResult> EvaluateAsync(JudgeRequest request, CancellationToken ct = default)
        {
            Calls++;
            LastToolCall = request.CurrentToolCall;
            LastHistory = request.RecentHistory;
            return Task.FromResult(_result);
        }
    }

    private static JudgeResult Verdict(bool aligned, double confidence) =>
        new(Aligned: aligned, Confidence: confidence, Reasoning: "stub");

    private static PurposeProfile Purpose(bool judgeEnabled) => new(
        PurposeId: "campaign-x-overlap",
        Description: "Aggregate overlap only.",
        AllowedActions: new[] { "aggregate_overlap" },
        Judge: judgeEnabled ? new JudgeConfig(Enabled: true, Model: Model) : null);

    private static EffectivePolicy PolicyWith(PurposeProfile? profile, bool canQuery = true)
    {
        var now = DateTimeOffset.UtcNow;
        return new EffectivePolicy(
            Version: "1.0",
            UserId: "judge-user",
            TenantId: "judge-tenant",
            SourceConnectionId: "db:marketing:segments",
            ResolvedAt: now,
            ExpiresAt: now.AddHours(1),
            SourceProfiles: new[] { "judge-wrapper" },
            Permissions: new PolicyPermissions(CanQuery: canQuery, ReadOnly: true),
            PurposeProfile: profile);
    }

    private static SecurityContext Signed(EffectivePolicy policy) =>
        SecurityContextSigner.Sign(
            SecurityContextBuilder.Build(
                "judge-user", "judge-tenant", new[] { policy },
                declaredPurpose: policy.PurposeProfile?.PurposeId),
            Key);

    private static readonly Dictionary<string, string> ToolMap = new()
    {
        ["segment_overlap"] = "aggregate_overlap",
        ["export_csv"] = "export_pii"
    };

    private static SecureContextToolWrapper Wrapper(
        IJudge? judge,
        ToolCallHistory? history = null,
        Func<JudgeOutcome, Task<bool>>? escalation = null) =>
        new(new SecureContextWrapperOptions(
            Key,
            ToolActionCategories: ToolMap,
            Judge: judge,
            ToolCallHistory: history,
            EscalationHandler: escalation));

    // -- The judge runs, and can subtract -----------------------------------

    [Fact]
    public async Task AConfidentlyAlignedCall_IsAllowed()
    {
        var judge = new StubJudge(Verdict(aligned: true, confidence: 0.95));

        var result = await Wrapper(judge).PreExecuteAsync(
            Signed(PolicyWith(Purpose(judgeEnabled: true))),
            new PreExecuteArgs("segment_overlap"));

        result.Allowed.Should().BeTrue();
        judge.Calls.Should().Be(1, "the policy asked for a judge, so one must have been consulted");
    }

    [Fact]
    public async Task AConfidentlyMisalignedCall_IsDenied()
    {
        // The whole reason the judge exists: a call the deterministic rules permit, refused
        // because it does not serve the declared purpose.
        var judge = new StubJudge(Verdict(aligned: false, confidence: 0.95));

        var result = await Wrapper(judge).PreExecuteAsync(
            Signed(PolicyWith(Purpose(judgeEnabled: true))),
            new PreExecuteArgs("segment_overlap"));

        result.Allowed.Should().BeFalse();
        result.Reason.Should().NotBeNullOrWhiteSpace();
    }

    // -- The judge can only ever subtract -----------------------------------

    [Fact]
    public async Task ADeterministicDenial_IsNotSentToTheJudgeAtAll()
    {
        // The load-bearing assertion. If a denial reached the judge, a confidently-aligned
        // verdict could overturn it -- and a persuasive prompt would become a privilege
        // escalation. Asserted on the judge having been left uncalled, not on the outcome,
        // because the outcome is the same either way.
        var judge = new StubJudge(Verdict(aligned: true, confidence: 1.0));

        var result = await Wrapper(judge).PreExecuteAsync(
            Signed(PolicyWith(Purpose(judgeEnabled: true))),
            new PreExecuteArgs("export_csv"));

        result.Allowed.Should().BeFalse("export_pii is not in the purpose's allowed actions");
        judge.Calls.Should().Be(0, "a refused call must never be offered to the judge");
    }

    [Fact]
    public async Task ACanQueryDenial_IsNotSentToTheJudgeEither()
    {
        var judge = new StubJudge(Verdict(aligned: true, confidence: 1.0));

        var result = await Wrapper(judge).PreExecuteAsync(
            Signed(PolicyWith(Purpose(judgeEnabled: true), canQuery: false)),
            new PreExecuteArgs("segment_overlap"));

        result.Reason.Should().Be("query not permitted");
        judge.Calls.Should().Be(0);
    }

    // -- Escalation is a denial unless a handler exists ----------------------

    [Fact]
    public async Task Escalation_WithNoHandler_Denies()
    {
        // A low-confidence verdict escalates. With no review path that must deny, or
        // "escalate to human review" means "permit" wherever review was never built.
        var judge = new StubJudge(Verdict(aligned: true, confidence: 0.4));

        var result = await Wrapper(judge).PreExecuteAsync(
            Signed(PolicyWith(Purpose(judgeEnabled: true))),
            new PreExecuteArgs("segment_overlap"));

        result.Allowed.Should().BeFalse("escalate is a denial without a review handler");
    }

    [Fact]
    public async Task Escalation_WithAHandlerThatApproves_Allows()
    {
        var judge = new StubJudge(Verdict(aligned: true, confidence: 0.4));
        JudgeOutcome? seen = null;

        var result = await Wrapper(judge, escalation: outcome =>
        {
            seen = outcome;
            return Task.FromResult(true);
        }).PreExecuteAsync(
            Signed(PolicyWith(Purpose(judgeEnabled: true))),
            new PreExecuteArgs("segment_overlap"));

        result.Allowed.Should().BeTrue();
        seen.Should().NotBeNull("the handler receives the outcome, including its reason");
        seen!.Disposition.Should().Be(JudgeDisposition.Escalate);
    }

    [Fact]
    public async Task Escalation_WithAHandlerThatRefuses_Denies()
    {
        // The paired control: a handler that is consulted and says no must still deny.
        var judge = new StubJudge(Verdict(aligned: true, confidence: 0.4));

        var result = await Wrapper(judge, escalation: _ => Task.FromResult(false))
            .PreExecuteAsync(
                Signed(PolicyWith(Purpose(judgeEnabled: true))),
                new PreExecuteArgs("segment_overlap"));

        result.Allowed.Should().BeFalse();
    }

    [Fact]
    public async Task ABlockingVerdict_IgnoresTheEscalationHandler()
    {
        // A review handler is for the ambiguous case. Routing a confident block through it
        // would let a deployment approve away the judge's clearest refusals.
        var judge = new StubJudge(Verdict(aligned: false, confidence: 0.99));
        var handlerCalled = false;

        var result = await Wrapper(judge, escalation: _ =>
        {
            handlerCalled = true;
            return Task.FromResult(true);
        }).PreExecuteAsync(
            Signed(PolicyWith(Purpose(judgeEnabled: true))),
            new PreExecuteArgs("segment_overlap"));

        result.Allowed.Should().BeFalse();
        handlerCalled.Should().BeFalse("only Escalate consults the review handler");
    }

    // -- Model verification --------------------------------------------------

    [Fact]
    public async Task AModelMismatch_EscalatesBeforeTheCallIsIssued()
    {
        // Spending tokens on the wrong model and noticing afterwards has already produced a
        // verdict that reads as authoritative in an audit log.
        var judge = new StubJudge(Verdict(aligned: true, confidence: 1.0), modelId: "some-other-model");

        var result = await Wrapper(judge).PreExecuteAsync(
            Signed(PolicyWith(Purpose(judgeEnabled: true))),
            new PreExecuteArgs("segment_overlap"));

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Contain(JudgeGate.ModelMismatchReason);
        judge.Calls.Should().Be(0, "the mismatch is caught before the model is invoked");
    }

    // -- Opting out, and backward compatibility -----------------------------

    [Fact]
    public async Task NoJudgeConfigured_BehavesExactlyLikePreExecute()
    {
        // A policy asking for a judge with none wired is not an error: the deterministic
        // checks have run, and the judge could only have subtracted.
        var context = Signed(PolicyWith(Purpose(judgeEnabled: true)));
        var wrapper = Wrapper(judge: null);

        var async = await wrapper.PreExecuteAsync(context, new PreExecuteArgs("segment_overlap"));
        var sync = wrapper.PreExecute(context, new PreExecuteArgs("segment_overlap"));

        async.Allowed.Should().Be(sync.Allowed).And.BeTrue();
    }

    [Fact]
    public async Task APolicyWithNoJudgeBlock_DoesNotConsultTheJudge()
    {
        // A judge wired at the composition root must not start judging policies that never
        // asked for one -- otherwise enabling it for one policy changes every other.
        var judge = new StubJudge(Verdict(aligned: false, confidence: 1.0));

        var result = await Wrapper(judge).PreExecuteAsync(
            Signed(PolicyWith(Purpose(judgeEnabled: false))),
            new PreExecuteArgs("segment_overlap"));

        result.Allowed.Should().BeTrue();
        judge.Calls.Should().Be(0);
    }

    // -- History -------------------------------------------------------------

    [Fact]
    public async Task TheTrajectoryReachesTheJudge_AndRefusedCallsAreKept()
    {
        // Drift is a property of the sequence, not of one call, so the history has to arrive.
        // Refused calls are recorded too: an agent probing for what it can reach is exactly
        // the pattern the judge is meant to notice, and keeping only successes would hide it.
        var history = new ToolCallHistory(maxSize: 8);
        var judge = new StubJudge(Verdict(aligned: true, confidence: 0.95));
        var wrapper = Wrapper(judge, history);
        var context = Signed(PolicyWith(Purpose(judgeEnabled: true)));

        await wrapper.PreExecuteAsync(context, new PreExecuteArgs("export_csv"));   // refused
        await wrapper.PreExecuteAsync(context, new PreExecuteArgs("segment_overlap"));

        judge.LastHistory.Should().Contain(h => h.Contains("export_csv"),
            "a refused probe is part of the trajectory");
        history.Count.Should().Be(2);
    }

    [Fact]
    public void TheRenderedCallCarriesFieldNamesButNoValues()
    {
        // Field names are most of what makes a read on-purpose. Values never reach the
        // renderer, so this path cannot send row data to a model.
        var rendered = SecureContextToolWrapper.RenderToolCall(
            new PreExecuteArgs("export_csv", ObjectName: "customers",
                Fields: new[] { "email", "ssn" }));

        rendered.Should().Be("export_csv(object=customers fields=[email,ssn])");
    }

    /// <summary>
    /// The rendering is a cross-SDK contract, not a formatting detail: the same call must
    /// render identically in all three, or a policy's judge sees different text depending on
    /// which SDK the wrapper came from — and a verdict is only comparable against one
    /// rendering. The Python and TypeScript suites assert these same four strings.
    /// </summary>
    [Theory]
    [InlineData("ping", null, null, null, null, "ping()")]
    [InlineData("fetch", null, null, "/segments/overlap", null,
        "fetch(endpoint=GET /segments/overlap)")]
    [InlineData("fetch", null, null, "/export/all.csv", "POST",
        "fetch(endpoint=POST /export/all.csv)")]
    [InlineData("read", "customers", "email", "/c", "PUT",
        "read(object=customers fields=[email] endpoint=PUT /c)")]
    public void TheRenderingIsACrossSdkContract(
        string toolName, string? objectName, string? field,
        string? endpointPath, string? endpointMethod, string expected)
    {
        SecureContextToolWrapper.RenderToolCall(new PreExecuteArgs(
            toolName,
            ObjectName: objectName,
            Fields: field is null ? null : new[] { field },
            EndpointPath: endpointPath,
            EndpointMethod: endpointMethod))
            .Should().Be(expected);
    }
}
