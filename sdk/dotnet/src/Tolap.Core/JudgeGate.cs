namespace Tolap.Core;

/// <summary>
/// A judge gate's decision, and the reason for it.
/// </summary>
/// <param name="Disposition">What to do. <c>Escalate</c> is a denial without a review handler.</param>
/// <param name="Reason">
/// Why, in a form fit for an audit log. This is the field that distinguishes the several
/// routes to <see cref="JudgeDisposition.Escalate"/> from each other: a model mismatch, a
/// low-confidence verdict, and an unusable one are the same disposition and very different
/// operational problems. Returning the disposition alone made the mandated
/// <see cref="JudgeGate.ModelMismatchReason"/> unreachable from the call — an integrator could
/// only rediscover it by re-checking <see cref="IJudge.ModelId"/> themselves, which is asking
/// the caller to re-implement the check it just delegated.
/// </param>
/// <param name="Result">
/// The judge's verdict, or <c>null</c> when no call was made — because no judge was configured,
/// or because the model did not match and the call was refused before being issued. Null
/// therefore means "no model was consulted", which is worth being able to tell apart from a
/// verdict that happened to be unhelpful.
/// </param>
public sealed record JudgeOutcome(
    JudgeDisposition Disposition,
    string Reason,
    JudgeResult? Result = null)
{
    /// <summary>
    /// Whether the call may proceed on the judge's account.
    /// </summary>
    /// <remarks>
    /// <c>Escalate</c> reads as <b>not</b> allowed here deliberately. A property that treated it
    /// as permitted would be the single most likely way for "escalate to human review" to become
    /// "permit" in a deployment with no review path, and the whole point of the disposition is
    /// that the ambiguous case does not proceed silently. A caller with a review handler
    /// switches on <see cref="Disposition"/> instead.
    /// </remarks>
    public bool Allowed => Disposition == JudgeDisposition.Allow;
}

/// <summary>
/// Turns a policy's <c>purposeProfile.judge</c> block into an actual judge invocation
/// (canonical-enforcement-spec.md section 15.4).
/// </summary>
/// <remarks>
/// <para>This exists because a policy can configure a judge in full — a model, a history window,
/// two thresholds, a latency budget — and none of it takes effect unless something reads those
/// values and applies them. Left to each integrator, the predictable outcome is a deployment
/// where the judge runs with a window and thresholds nobody chose, and where the policy's
/// <c>model</c> is quietly ignored. That is a control the configuration implies and that never
/// runs.</para>
/// <para>The wrappers call this for you when a judge is configured:
/// <see cref="SecureContextToolWrapper.PreExecuteAsync"/> runs the deterministic checks and
/// then this, so a policy's judge block applies without any glue of yours. Call it directly
/// only if you are not using a wrapper — and use
/// <see cref="SecureContextToolWrapper.RenderToolCall"/> for the call string if you do, so your
/// history and a wrapper's remain comparable.</para>
/// <para>Strictly subtractive, like the judge itself. Every path returns
/// <see cref="JudgeDisposition.Allow"/> only when the policy asked for a judge and the judge
/// confidently agreed; everything else denies or escalates. It never permits a call the
/// deterministic checks refused, because it is never consulted about one.</para>
/// </remarks>
public static class JudgeGate
{
    /// <summary>
    /// The escalation reason when the judge is not the model the policy asked for.
    /// </summary>
    /// <remarks>
    /// Part of the contract. Escalation rather than a hard block: the call may be perfectly
    /// legitimate, and the fault is in the deployment, so a human is the right destination. What
    /// it must never be is a silent substitution.
    /// </remarks>
    public const string ModelMismatchReason = "judge model mismatch";

    /// <summary>
    /// The reason on an allow that no judge was asked for.
    /// </summary>
    /// <remarks>
    /// Named rather than inlined, and byte-identical to Python's and TypeScript's, because
    /// <see cref="JudgeOutcome.Reason"/> is a contract field an integrator logs and branches
    /// on. It was an inline literal here and a named constant in TypeScript, spelled two
    /// different ways — the kind of drift that is invisible until an operator greps one
    /// deployment's logs for a string another deployment never emits.
    /// </remarks>
    public const string NoJudgeConfiguredReason = "no judge configured";

    /// <summary>
    /// The escalation reason when the judge itself threw.
    /// </summary>
    /// <remarks>
    /// Spec section 15.4 requires a timeout, a transport failure and an unparseable response to
    /// "produce escalation rather than an exception". <see cref="Tolap.Mcp"/>'s Bedrock judge
    /// honours that internally, but <see cref="IJudge"/> is a public interface and a custom
    /// implementation can throw — which would put an exception on the authorization path, and
    /// the natural fix for that at a call site is a <c>catch</c> that returns "allow". Caught
    /// here so the safe reading is the default rather than something each integrator has to
    /// remember.
    /// </remarks>
    public const string JudgeFailedReason = "judge invocation failed";

    /// <summary>
    /// Whether this policy asks for a judge at all.
    /// </summary>
    /// <remarks>
    /// Checked against <c>Enabled == true</c> rather than for truthiness, because
    /// <see cref="JudgeConfig.Enabled"/> is nullable: absent means "not configured", which is
    /// not the same statement as an explicit <c>false</c> even though both mean no judge today.
    /// </remarks>
    public static bool IsEnabled(EffectivePolicy policy) =>
        policy.PurposeProfile?.Judge?.Enabled == true;

    /// <summary>
    /// How many preceding calls the policy wants the judge to see.
    /// </summary>
    /// <remarks>
    /// Read this to size a <see cref="ToolCallHistory"/>, so the window is the policy author's
    /// choice rather than the integrator's default. A window smaller than the policy asked for
    /// hides exactly the trajectory the judge was enabled to notice.
    /// </remarks>
    public static int HistoryWindowFor(EffectivePolicy policy) =>
        policy.PurposeProfile?.Judge?.HistoryWindow ?? JudgeDispositions.DefaultHistoryWindow;

    /// <summary>
    /// Builds the request for a call, from the policy's judge configuration.
    /// </summary>
    /// <returns>
    /// The request, or <c>null</c> when this policy has no judge enabled — in which case there
    /// is nothing to ask and the deterministic decision stands.
    /// </returns>
    /// <remarks>
    /// The latency budget comes from the policy rather than from the caller, which is the whole
    /// point: <c>maxLatencyMs</c> is a policy field and a caller passing its own value would make
    /// it advisory.
    /// </remarks>
    public static JudgeRequest? RequestFor(
        EffectivePolicy policy,
        string currentToolCall,
        ToolCallHistory? history = null)
    {
        ArgumentNullException.ThrowIfNull(currentToolCall);

        if (!IsEnabled(policy))
            return null;

        var profile = policy.PurposeProfile!;
        var judge = profile.Judge!;

        // Trimmed to the policy's window even when the caller's history is larger, so an
        // oversized buffer cannot quietly widen what the policy chose to send.
        var window = judge.HistoryWindow ?? JudgeDispositions.DefaultHistoryWindow;
        var recent = history?.GetRecent() ?? Array.Empty<string>();
        if (recent.Length > window)
            recent = recent[^window..];

        return new JudgeRequest(
            Purpose: profile,
            CurrentToolCall: currentToolCall,
            RecentHistory: recent,
            MaxLatencyMs: judge.MaxLatencyMs ?? JudgeDispositions.DefaultMaxLatencyMs);
    }

    /// <summary>
    /// Runs the judge for a call and maps the verdict to a disposition.
    /// </summary>
    /// <param name="policy">The resolved policy. No judge enabled means <see cref="JudgeDisposition.Allow"/>.</param>
    /// <param name="judge">The judge. Its <see cref="IJudge.ModelId"/> is verified first.</param>
    /// <param name="currentToolCall">A rendering of the call under consideration.</param>
    /// <param name="history">Preceding calls; trimmed to the policy's window.</param>
    /// <param name="ct">Caller cancellation. Distinct from the policy's latency budget.</param>
    /// <returns>
    /// What to do, and why. <see cref="JudgeDisposition.Escalate"/> is <b>not</b> an allow: treat
    /// it as a denial unless a human review path exists, or "escalate to review" means "permit"
    /// in every deployment that never built one.
    /// </returns>
    /// <remarks>
    /// The model check runs before the call, not after. Invoking the wrong model and then
    /// noticing would have spent the tokens and, worse, produced a verdict that reads as
    /// authoritative in an audit log.
    /// </remarks>
    public static async Task<JudgeOutcome> EvaluateAsync(
        EffectivePolicy policy,
        IJudge judge,
        string currentToolCall,
        ToolCallHistory? history = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(judge);

        var request = RequestFor(policy, currentToolCall, history);
        if (request is null)
            return new JudgeOutcome(JudgeDisposition.Allow, NoJudgeConfiguredReason);

        var config = policy.PurposeProfile!.Judge!;

        if (!ModelMatches(config.Model, judge.ModelId))
        {
            return new JudgeOutcome(
                JudgeDisposition.Escalate,
                $"{ModelMismatchReason}: policy asked for '{config.Model}', " +
                $"judge reports '{judge.ModelId}'");
        }

        JudgeResult result;
        try
        {
            result = await judge.EvaluateAsync(request, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // The caller's own cancellation, not a judge failure. Propagated so it stays
            // distinguishable from an escalation the judge caused.
            throw;
        }
        catch (Exception ex)
        {
            // Deliberately broad: `IJudge` is public, so the exception taxonomy is whatever an
            // implementation happens to raise, and every one of them means the same thing here.
            // No result, because no verdict was obtained.
            return new JudgeOutcome(
                JudgeDisposition.Escalate,
                $"{JudgeFailedReason}: {ex.GetType().Name}");
        }

        return new JudgeOutcome(JudgeDispositions.For(result, config), result.Reasoning, result);
    }

    /// <summary>
    /// Whether the judge in hand is the one the policy asked for.
    /// </summary>
    /// <remarks>
    /// <para>A policy naming no model accepts any judge: the field is optional, and requiring it
    /// would make every judge-enabled policy fail until someone pinned a model id that differs
    /// per account and region.</para>
    /// <para>When a policy does name one, the comparison is case-sensitive and exact. Not a
    /// prefix or substring match: <c>claude-sonnet</c> and <c>claude-sonnet-5</c> are different
    /// models, and a prefix rule would let a deployment satisfy a policy demanding one by wiring
    /// the other. This mirrors the purposeId comparison — an identifier is matched, not a
    /// pattern.</para>
    /// </remarks>
    private static bool ModelMatches(string? configured, string? actual) =>
        configured is null || string.Equals(configured, actual, StringComparison.Ordinal);
}
