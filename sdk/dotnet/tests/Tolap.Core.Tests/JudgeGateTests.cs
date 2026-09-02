using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// Turning a policy's judge configuration into an actual invocation (spec section 15.4).
/// </summary>
/// <remarks>
/// This is the seam that makes <c>purposeProfile.judge</c> mean something. Before it existed a
/// policy could name a model, a history window, two thresholds and a latency budget, and a
/// deployment would honour none of them — the judge ran with whatever the integrator's own glue
/// happened to pass. Every test here is about a policy field actually taking effect, or about
/// what happens when it cannot.
/// </remarks>
public class JudgeGateTests
{
    private sealed class StubJudge : IJudge
    {
        private readonly JudgeResult _result;

        public StubJudge(JudgeResult result, string modelId = "claude-sonnet")
        {
            _result = result;
            ModelId = modelId;
        }

        public string ModelId { get; }
        public int Calls { get; private set; }
        public JudgeRequest? LastRequest { get; private set; }

        public Task<JudgeResult> EvaluateAsync(JudgeRequest request, CancellationToken ct = default)
        {
            Calls++;
            LastRequest = request;
            return Task.FromResult(_result);
        }
    }

    private static readonly JudgeResult ConfidentlyAligned = new(true, 0.95, "on task");
    private static readonly JudgeResult ConfidentlyMisaligned = new(false, 0.95, "off task");

    private static EffectivePolicy PolicyWith(PurposeProfile? profile)
    {
        var now = DateTimeOffset.UtcNow;
        return new EffectivePolicy(
            Version: "1.0",
            UserId: "u",
            TenantId: "t",
            SourceConnectionId: "db:marketing:customer_segments",
            ResolvedAt: now,
            ExpiresAt: now.AddHours(1),
            SourceProfiles: new[] { "p" },
            Permissions: new PolicyPermissions(CanQuery: true, ReadOnly: true),
            PurposeProfile: profile);
    }

    private static PurposeProfile WithJudge(JudgeConfig? judge) =>
        new("campaign-x-overlap", Description: "Aggregate overlap only.", Judge: judge);

    // -- Whether the judge runs at all ------------------------------------

    [Fact]
    public void IsEnabled_RequiresAnExplicitTrue()
    {
        // Checked against `== true` rather than for truthiness, because Enabled is nullable:
        // absent means "not configured", which is a different statement from an explicit false
        // even though both mean no judge today.
        JudgeGate.IsEnabled(PolicyWith(null)).Should().BeFalse("no purpose profile at all");
        JudgeGate.IsEnabled(PolicyWith(WithJudge(null))).Should().BeFalse("no judge block");
        JudgeGate.IsEnabled(PolicyWith(WithJudge(new JudgeConfig()))).Should().BeFalse("enabled absent");
        JudgeGate.IsEnabled(PolicyWith(WithJudge(new JudgeConfig(Enabled: false)))).Should().BeFalse();
        JudgeGate.IsEnabled(PolicyWith(WithJudge(new JudgeConfig(Enabled: true)))).Should().BeTrue();
    }

    [Fact]
    public async Task Evaluate_NoJudgeEnabled_AllowsWithoutCallingTheJudge()
    {
        // A judge that is not asked for must not be invoked -- both because it costs a model
        // call and because a verdict nobody asked for should not be able to deny a call the
        // deterministic checks allowed.
        var judge = new StubJudge(ConfidentlyMisaligned);

        var outcome = await JudgeGate.EvaluateAsync(
            PolicyWith(WithJudge(new JudgeConfig(Enabled: false))), judge, "aggregate_overlap()");

        outcome.Disposition.Should().Be(JudgeDisposition.Allow);
        outcome.Result.Should().BeNull("no model was consulted");
        judge.Calls.Should().Be(0);
    }

    [Fact]
    public async Task Evaluate_APurposeAgnosticPolicy_AllowsWithoutCallingTheJudge()
    {
        var judge = new StubJudge(ConfidentlyMisaligned);

        var outcome = await JudgeGate.EvaluateAsync(PolicyWith(null), judge, "anything()");

        outcome.Disposition.Should().Be(JudgeDisposition.Allow);
        outcome.Result.Should().BeNull("no model was consulted");
        judge.Calls.Should().Be(0);
    }

    [Fact]
    public void RequestFor_NoJudgeEnabled_IsNull()
    {
        JudgeGate.RequestFor(PolicyWith(null), "x").Should().BeNull();
        JudgeGate.RequestFor(PolicyWith(WithJudge(new JudgeConfig())), "x").Should().BeNull();
    }

    // -- The model check --------------------------------------------------

    [Fact]
    public async Task Evaluate_AModelMismatch_EscalatesWithoutCallingTheJudge()
    {
        // The gap this class was written to close. A policy demanding one model must not be
        // silently judged by another -- a verdict is only meaningful against the model that
        // produced it. Checked BEFORE the call, so the wrong model is never invoked and no
        // authoritative-looking verdict lands in the audit log.
        var judge = new StubJudge(ConfidentlyAligned, modelId: "global.anthropic.claude-sonnet-5");
        var policy = PolicyWith(WithJudge(new JudgeConfig(Enabled: true, Model: "claude-opus")));

        var outcome = await JudgeGate.EvaluateAsync(policy, judge, "aggregate_overlap()");

        outcome.Disposition.Should().Be(JudgeDisposition.Escalate);
        judge.Calls.Should().Be(0, "the wrong model is not invoked at all");

        // The reason is what makes this escalation actionable. Returning the disposition alone
        // left an integrator unable to tell a misconfigured deployment from a genuinely
        // uncertain verdict -- the same escalation, two entirely different responses.
        outcome.Reason.Should().Contain(JudgeGate.ModelMismatchReason);
        outcome.Reason.Should().Contain("claude-opus").And.Contain("claude-sonnet-5");
        outcome.Result.Should().BeNull("the model was never consulted");
    }

    [Fact]
    public async Task Evaluate_AMatchingModel_ProceedsToTheJudge()
    {
        // The paired control. Without it, a gate that escalated on every configured model would
        // satisfy the mismatch test and disable the judge entirely.
        var judge = new StubJudge(ConfidentlyAligned, modelId: "claude-sonnet");
        var policy = PolicyWith(WithJudge(new JudgeConfig(Enabled: true, Model: "claude-sonnet")));

        var outcome = await JudgeGate.EvaluateAsync(policy, judge, "aggregate_overlap()");

        outcome.Disposition.Should().Be(JudgeDisposition.Allow);
        judge.Calls.Should().Be(1);
        outcome.Result.Should().BeSameAs(ConfidentlyAligned, "the verdict is carried out");
        outcome.Reason.Should().Be("on task", "the judge's own reasoning becomes the reason");
    }

    [Fact]
    public async Task Evaluate_APolicyNamingNoModel_AcceptsAnyJudge()
    {
        // The field is optional. Requiring it would make every judge-enabled policy fail until
        // someone pinned a model id, and those differ per account and region.
        var judge = new StubJudge(ConfidentlyAligned, modelId: "whatever-is-deployed");
        var policy = PolicyWith(WithJudge(new JudgeConfig(Enabled: true)));

        (await JudgeGate.EvaluateAsync(policy, judge, "x")).Disposition.Should().Be(JudgeDisposition.Allow);
        judge.Calls.Should().Be(1);
    }

    [Theory]
    [InlineData("Claude-Sonnet")]
    [InlineData("claude-sonnet-5")]
    [InlineData("claude-sonne")]
    [InlineData("anthropic.claude-sonnet")]
    public async Task Evaluate_ModelComparisonIsExactAndCaseSensitive(string deployedModel)
    {
        // Not a prefix or substring rule. `claude-sonnet` and `claude-sonnet-5` are different
        // models, and a prefix match would let a deployment satisfy a policy demanding one by
        // wiring the other. An identifier is matched, not a pattern -- the same reasoning as the
        // purposeId comparison.
        var judge = new StubJudge(ConfidentlyAligned, modelId: deployedModel);
        var policy = PolicyWith(WithJudge(new JudgeConfig(Enabled: true, Model: "claude-sonnet")));

        (await JudgeGate.EvaluateAsync(policy, judge, "x")).Disposition.Should().Be(JudgeDisposition.Escalate);
    }

    [Fact]
    public void TheModelMismatchReasonIsPartOfTheContract()
    {
        JudgeGate.ModelMismatchReason.Should().Be("judge model mismatch");
    }

    // -- The policy's history window --------------------------------------

    [Fact]
    public void HistoryWindowFor_ComesFromThePolicyOrTheDocumentedDefault()
    {
        JudgeGate.HistoryWindowFor(PolicyWith(WithJudge(new JudgeConfig(HistoryWindow: 3))))
            .Should().Be(3);
        JudgeGate.HistoryWindowFor(PolicyWith(WithJudge(new JudgeConfig())))
            .Should().Be(JudgeDispositions.DefaultHistoryWindow, "judge block with no window");
        JudgeGate.HistoryWindowFor(PolicyWith(WithJudge(null)))
            .Should().Be(JudgeDispositions.DefaultHistoryWindow, "purpose profile with no judge");
        JudgeGate.HistoryWindowFor(PolicyWith(null))
            .Should().Be(JudgeDispositions.DefaultHistoryWindow, "no purpose profile at all");
    }

    [Fact]
    public void RequestFor_TrimsHistoryToThePolicysWindow()
    {
        // An oversized buffer must not quietly widen what the policy chose to send. Trimmed to
        // the MOST RECENT entries, because a window of three means the last three calls, not the
        // first three.
        var policy = PolicyWith(WithJudge(new JudgeConfig(Enabled: true, HistoryWindow: 2)));
        var history = new ToolCallHistory(maxSize: 10);
        history.Record("a");
        history.Record("b");
        history.Record("c");

        var request = JudgeGate.RequestFor(policy, "d", history);

        request!.RecentHistory.Should().Equal("b", "c");
    }

    [Fact]
    public void RequestFor_AHistoryShorterThanTheWindow_IsPassedWhole()
    {
        var policy = PolicyWith(WithJudge(new JudgeConfig(Enabled: true, HistoryWindow: 10)));
        var history = new ToolCallHistory(maxSize: 10);
        history.Record("a");

        JudgeGate.RequestFor(policy, "b", history)!.RecentHistory.Should().Equal("a");
    }

    [Fact]
    public void RequestFor_NoHistorySupplied_SendsAnEmptyTrajectory()
    {
        var policy = PolicyWith(WithJudge(new JudgeConfig(Enabled: true)));

        JudgeGate.RequestFor(policy, "a")!.RecentHistory.Should().BeEmpty();
    }

    [Fact]
    public void RequestFor_RefusesANullToolCall()
    {
        var act = () => JudgeGate.RequestFor(
            PolicyWith(WithJudge(new JudgeConfig(Enabled: true))), null!);

        act.Should().Throw<ArgumentNullException>();
    }

    // -- The policy's latency budget and thresholds ------------------------

    [Fact]
    public void RequestFor_TakesTheLatencyBudgetFromThePolicy()
    {
        // maxLatencyMs is a policy field, so it comes from the policy. A caller passing its own
        // value would make the policy's advisory.
        var policy = PolicyWith(WithJudge(new JudgeConfig(Enabled: true, MaxLatencyMs: 750)));

        JudgeGate.RequestFor(policy, "x")!.MaxLatencyMs.Should().Be(750);
    }

    [Fact]
    public void RequestFor_AnAbsentLatencyBudget_UsesTheDocumentedDefault()
    {
        var policy = PolicyWith(WithJudge(new JudgeConfig(Enabled: true)));

        JudgeGate.RequestFor(policy, "x")!.MaxLatencyMs
            .Should().Be(JudgeDispositions.DefaultMaxLatencyMs);
    }

    [Fact]
    public void RequestFor_PassesThePolicysPurposeToTheJudge()
    {
        // The purpose description is what the judge compares the call against, so it has to be
        // the resolved policy's rather than anything the caller supplies.
        var profile = new PurposeProfile(
            "campaign-x-overlap",
            Description: "Aggregate overlap only.",
            AllowedActions: new[] { "aggregate_overlap" },
            Judge: new JudgeConfig(Enabled: true));

        var request = JudgeGate.RequestFor(PolicyWith(profile), "x");

        request!.Purpose.Should().BeSameAs(profile);
    }

    [Fact]
    public async Task Evaluate_AppliesThePolicysThresholds()
    {
        // The same verdict, two policies, two outcomes -- which is what proves the thresholds are
        // read from the policy rather than from the defaults.
        var judge = new StubJudge(new JudgeResult(true, 0.88, "fairly sure"));

        var lenient = PolicyWith(WithJudge(new JudgeConfig(
            Enabled: true, ConfidenceThreshold: 0.85, EscalationThreshold: 0.6)));
        var strict = PolicyWith(WithJudge(new JudgeConfig(
            Enabled: true, ConfidenceThreshold: 0.95, EscalationThreshold: 0.6)));

        (await JudgeGate.EvaluateAsync(lenient, judge, "x")).Disposition.Should().Be(JudgeDisposition.Allow);
        (await JudgeGate.EvaluateAsync(strict, judge, "x")).Disposition.Should().Be(JudgeDisposition.Escalate);
    }

    [Fact]
    public async Task Evaluate_AConfidentlyMisalignedVerdict_Blocks()
    {
        var policy = PolicyWith(WithJudge(new JudgeConfig(Enabled: true)));

        (await JudgeGate.EvaluateAsync(policy, new StubJudge(ConfidentlyMisaligned), "x")).Disposition.Should().Be(JudgeDisposition.Block);
    }

    [Fact]
    public async Task Evaluate_AnUnavailableJudge_Escalates()
    {
        // What BedrockJudge returns when the model could not be reached. Escalation, not allow --
        // a judge that could not answer has not approved anything.
        var unavailable = new JudgeResult(false, 0.0, "judge timed out", new[] { "judge-unavailable" });
        var policy = PolicyWith(WithJudge(new JudgeConfig(Enabled: true)));

        (await JudgeGate.EvaluateAsync(policy, new StubJudge(unavailable), "x")).Disposition.Should().Be(JudgeDisposition.Escalate);
    }

    [Fact]
    public async Task Evaluate_RefusesANullJudge()
    {
        var policy = PolicyWith(WithJudge(new JudgeConfig(Enabled: true)));

        var act = () => JudgeGate.EvaluateAsync(policy, null!, "x");

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task Evaluate_PassesCallerCancellationThrough()
    {
        // A caller's cancellation is distinct from the policy's latency budget, and must not be
        // swallowed into an escalation that looks like a judge failure.
        var policy = PolicyWith(WithJudge(new JudgeConfig(Enabled: true)));
        var judge = new CancellationObservingJudge();
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        var act = () => JudgeGate.EvaluateAsync(policy, judge, "x", null, cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    private sealed class CancellationObservingJudge : IJudge
    {
        public string ModelId => "stub-model";

        public Task<JudgeResult> EvaluateAsync(JudgeRequest request, CancellationToken ct = default)
        {
            ct.ThrowIfCancellationRequested();
            return Task.FromResult(new JudgeResult(true, 1.0, "unreachable"));
        }
    }

    // -- JudgeOutcome.Allowed ---------------------------------------------

    [Fact]
    public void Outcome_TreatsEscalateAsNotAllowed()
    {
        // The single most likely route to "escalate to human review" quietly meaning "permit"
        // is a convenience property that reads escalate as allowed. All three dispositions are
        // asserted, not just the escalate one, so a property inverted in either direction fails.
        new JudgeOutcome(JudgeDisposition.Allow, "confident and aligned").Allowed
            .Should().BeTrue();
        new JudgeOutcome(JudgeDisposition.Block, "confident and misaligned").Allowed
            .Should().BeFalse();
        new JudgeOutcome(JudgeDisposition.Escalate, "uncertain").Allowed
            .Should().BeFalse("escalate is a denial unless a review handler is wired");
    }

    [Fact]
    public async Task Evaluate_AnEscalatingOutcome_IsNotAllowed()
    {
        // The same claim through the gate rather than on a hand-built record, since that is the
        // path an integrator takes.
        var policy = PolicyWith(WithJudge(new JudgeConfig(Enabled: true)));
        var unsure = new JudgeResult(true, 0.3, "cannot tell");

        var outcome = await JudgeGate.EvaluateAsync(policy, new StubJudge(unsure), "x");

        outcome.Disposition.Should().Be(JudgeDisposition.Escalate);
        outcome.Allowed.Should().BeFalse();
        outcome.Reason.Should().Be("cannot tell");
    }

    // -- A throwing judge must not reach the authorization path ------------

    private sealed class ThrowingJudge : IJudge
    {
        public string ModelId => "stub-model";

        public Task<JudgeResult> EvaluateAsync(JudgeRequest request, CancellationToken ct = default)
            => throw new InvalidOperationException("no credentials");
    }

    [Fact]
    public async Task Evaluate_AJudgeThatThrows_EscalatesRatherThanPropagating()
    {
        // Section 15.4 requires a timeout, a transport failure and an unparseable response to
        // escalate rather than raise. BedrockJudge honours that internally, but IJudge is a
        // public interface — so a custom implementation can throw, and the natural fix for an
        // exception on the authorization path is a `catch` at the call site returning "allow".
        // That is the failure mode this guard designs out.
        var policy = PolicyWith(WithJudge(new JudgeConfig(Enabled: true)));

        var act = async () => await JudgeGate.EvaluateAsync(policy, new ThrowingJudge(), "x");

        await act.Should().NotThrowAsync();

        var outcome = await JudgeGate.EvaluateAsync(policy, new ThrowingJudge(), "x");
        outcome.Disposition.Should().Be(JudgeDisposition.Escalate);
        outcome.Allowed.Should().BeFalse();
        outcome.Reason.Should().StartWith(JudgeGate.JudgeFailedReason);
        outcome.Reason.Should().Contain("InvalidOperationException",
            "the exception type is named so an operator can find the faulty implementation");
        outcome.Result.Should().BeNull("no verdict was obtained");
    }

    [Fact]
    public async Task Evaluate_ACallerCancellation_StillPropagates()
    {
        // The paired direction. A caller's own cancellation is not a judge failure, and
        // swallowing it into an escalation would make a cancelled request indistinguishable
        // from a broken judge.
        var policy = PolicyWith(WithJudge(new JudgeConfig(Enabled: true)));
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        var act = () => JudgeGate.EvaluateAsync(
            policy, new CancellationObservingJudge(), "x", null, cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public void TheJudgeFailedReasonIsPartOfTheContract()
    {
        JudgeGate.JudgeFailedReason.Should().Be("judge invocation failed");
    }
}
