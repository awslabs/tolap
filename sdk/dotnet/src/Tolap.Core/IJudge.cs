namespace Tolap.Core;

/// <summary>
/// What a judge is asked to decide.
/// </summary>
/// <param name="Purpose">
/// The profile from the resolved policy. Its <see cref="PurposeProfile.Description"/> is
/// what gives the judge something to compare the call against, which is why an author who
/// enables the judge should write one.
/// </param>
/// <param name="CurrentToolCall">A rendering of the call under consideration.</param>
/// <param name="RecentHistory">
/// Preceding calls, oldest first, bounded by <see cref="JudgeConfig.HistoryWindow"/>. Drift
/// is a property of a sequence rather than of one call: an agent asking for one more column
/// each turn looks reasonable at every single step.
/// </param>
/// <param name="MaxLatencyMs">
/// The wall-clock budget. Exceeding it escalates rather than allowing.
/// </param>
public record JudgeRequest(
    PurposeProfile Purpose,
    string CurrentToolCall,
    string[] RecentHistory,
    int MaxLatencyMs);

/// <summary>
/// A judge's verdict.
/// </summary>
/// <param name="Aligned">Whether the call serves the declared purpose.</param>
/// <param name="Confidence">
/// How sure the judge is, in <c>[0, 1]</c>. A value outside that range is unusable and
/// escalates — see <see cref="JudgeDispositions.For"/>.
/// </param>
/// <param name="Reasoning">The judge's explanation, for the audit trail.</param>
/// <param name="Flags">Optional machine-readable markers for downstream triage.</param>
public record JudgeResult(
    bool Aligned,
    double Confidence,
    string Reasoning,
    string[]? Flags = null);

/// <summary>
/// What to do with a judge's verdict.
/// </summary>
public enum JudgeDisposition
{
    /// <summary>Proceed. The deterministic checks already passed.</summary>
    Allow,

    /// <summary>Refuse. The judge is confident the call does not serve the purpose.</summary>
    Block,

    /// <summary>
    /// Refer to a human. <b>Not</b> an allow: a wrapper with no escalation handler must deny,
    /// or "escalate to review" silently means "permit" wherever the review step was never
    /// built.
    /// </summary>
    Escalate
}

/// <summary>
/// A semantic check on whether a tool call serves the purpose it was authorized for
/// (canonical-enforcement-spec.md section 15.4).
/// </summary>
/// <remarks>
/// <para>Advisory and strictly subtractive. A judge runs only after the three deterministic
/// checks have allowed a call, and can only take that allowance away. It can never permit
/// something purpose filtering, action validation, or chain validation denied — a
/// non-deterministic component must not be able to widen access, because then a prompt that
/// talks the model round becomes a privilege escalation.</para>
/// <para>The interface lives in <c>Tolap.Core</c> and every implementation that calls a
/// model lives in <c>Tolap.Mcp</c>, which already carries external dependencies. Core ships
/// with none, and a judge needs a network client.</para>
/// </remarks>
public interface IJudge
{
    /// <summary>
    /// The model this judge actually invokes.
    /// </summary>
    /// <remarks>
    /// <para>Declared so that <see cref="JudgeGate"/> can check it against the
    /// <see cref="JudgeConfig.Model"/> the policy asked for. Without it, a policy demanding one
    /// model would be silently judged by whatever the deployment happened to wire up — the
    /// policy field would look like a control and be decoration. A verdict is only meaningful
    /// against the model that produced it, which is also why two policies naming different
    /// models refuse to merge.</para>
    /// <para>Reported by the implementation rather than configured alongside it, so the value
    /// comes from whatever really issues the call.</para>
    /// </remarks>
    string ModelId { get; }

    /// <summary>
    /// Evaluates a call against its purpose.
    /// </summary>
    /// <remarks>
    /// Implementations should surface a timeout or a transport failure as an exception or a
    /// low-confidence result rather than a confident <c>Aligned: true</c>. The caller maps
    /// either to <see cref="JudgeDisposition.Escalate"/>; a fabricated confident alignment
    /// is the one response that cannot be recovered from.
    /// </remarks>
    Task<JudgeResult> EvaluateAsync(JudgeRequest request, CancellationToken ct = default);
}

/// <summary>
/// Maps a <see cref="JudgeResult"/> onto a <see cref="JudgeDisposition"/>.
/// </summary>
public static class JudgeDispositions
{
    /// <summary>Confidence at or above which a verdict is final, when unconfigured.</summary>
    public const double DefaultConfidenceThreshold = 0.85;

    /// <summary>Confidence below which a call escalates, when unconfigured.</summary>
    public const double DefaultEscalationThreshold = 0.60;

    /// <summary>Wall-clock budget for one evaluation, when unconfigured.</summary>
    public const int DefaultMaxLatencyMs = 2000;

    /// <summary>Number of preceding calls to supply, when unconfigured.</summary>
    public const int DefaultHistoryWindow = 10;

    /// <summary>
    /// Decides what to do with a verdict.
    /// </summary>
    /// <remarks>
    /// <para>Every path that is not a confident verdict escalates, and escalation denies
    /// unless a handler is wired. The ordering matters: the unusable-input checks come
    /// first, so a malformed result cannot reach the threshold comparisons and win one.</para>
    /// <para>Three unusable-input cases, each of which would otherwise produce a confident
    /// allow:</para>
    /// <list type="bullet">
    /// <item>A confidence outside <c>[0, 1]</c>. A judge reporting <c>1.5</c> has
    /// malfunctioned, and comparing it against a threshold would grant it more authority
    /// than a correct answer.</item>
    /// <item>Thresholds inverted, with escalation above confidence. There is no reading of
    /// that configuration to act on, so it escalates rather than picking whichever bound
    /// happens to be checked first.</item>
    /// <item><see cref="double.NaN"/>, which fails every comparison and would otherwise
    /// fall through to whatever the last branch happened to be.</item>
    /// </list>
    /// </remarks>
    public static JudgeDisposition For(JudgeResult result, JudgeConfig? config)
    {
        var confidenceThreshold = config?.ConfidenceThreshold ?? DefaultConfidenceThreshold;
        var escalationThreshold = config?.EscalationThreshold ?? DefaultEscalationThreshold;

        if (double.IsNaN(result.Confidence) || result.Confidence < 0.0 || result.Confidence > 1.0)
            return JudgeDisposition.Escalate;

        if (escalationThreshold > confidenceThreshold)
            return JudgeDisposition.Escalate;

        if (result.Confidence < escalationThreshold)
            return JudgeDisposition.Escalate;

        if (result.Confidence < confidenceThreshold)
            return JudgeDisposition.Escalate;

        return result.Aligned ? JudgeDisposition.Allow : JudgeDisposition.Block;
    }
}
