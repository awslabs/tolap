/**
 * TOLAP Semantic Judge (canonical spec §15.4)
 *
 * A semantic check on whether a tool call serves the purpose it was authorized for,
 * plus the gate that turns a policy's `purposeProfile.judge` block into an actual
 * invocation.
 *
 * **Advisory and strictly subtractive.** A judge runs only after the three
 * deterministic checks — purpose filtering at resolution, action validation, chain
 * validation — have allowed a call, and it can only take that allowance away. It can
 * never permit something they denied, because a non-deterministic component must not
 * be able to widen access: otherwise a prompt that talks the model round becomes a
 * privilege escalation.
 *
 * The gate exists because a policy can configure a judge in full — a model, a
 * history window, two thresholds, a latency budget — and none of it takes effect
 * unless something reads those values and applies them. Left to each integrator, the
 * predictable outcome is a deployment where the judge runs with a window and
 * thresholds nobody chose and where the policy's `model` is quietly ignored: a
 * control the configuration implies and that never runs.
 *
 * The wrappers call `evaluateJudge` for you when a judge is configured: `preExecuteAsync`
 * runs the deterministic checks and then the gate, so a policy's judge block applies
 * without glue of yours. Call it directly only if you are not using a wrapper — and render
 * the call with `renderToolCall` if you do, so your history and a wrapper's stay
 * comparable. An implementation that calls a model lives in `@aws/tolap-mcp` (see
 * `BedrockJudge`); `@aws/tolap-core` ships with no runtime dependencies and a judge needs a
 * transport.
 */

import type {
  EffectivePolicy,
  JudgeConfig,
  PurposeProfile,
} from "./types.js";
import type { ToolCallHistory } from "./history.js";

// ---------------------------------------------------------------------------
// Documented defaults (applied at READ time, never stored on a JudgeConfig)
// ---------------------------------------------------------------------------
//
// `JudgeConfig`'s fields are all optional and these are applied when a field is
// read. Storing them on the object instead would serialize values the author never
// wrote, changing the canonical bytes -- and so the signature -- of every
// purpose-bound policy. The numbers match `schema/v1.0/*.schema.json`'s `default`
// keywords, and `schema-conformance`-style tests pin that agreement.

/** Confidence at or above which a verdict is final, when unconfigured. */
export const DEFAULT_CONFIDENCE_THRESHOLD = 0.85;

/** Confidence below which a call escalates, when unconfigured. */
export const DEFAULT_ESCALATION_THRESHOLD = 0.6;

/** Wall-clock budget for one evaluation, when unconfigured. */
export const DEFAULT_MAX_LATENCY_MS = 2000;

/** Number of preceding calls to supply, when unconfigured. */
export const DEFAULT_HISTORY_WINDOW = 10;

/**
 * The escalation reason when the judge is not the model the policy asked for.
 *
 * Part of the contract; integrators log and branch on it. Escalation rather than a
 * hard block: the call may be perfectly legitimate and the fault is in the
 * deployment, so a human is the right destination. What it must never be is a silent
 * substitution.
 *
 * `JudgeOutcome.reason` carries this as a **prefix**, followed by the two model ids —
 * a mismatch is a configuration fault and the only useful log line names both sides.
 * Branch with `reason.startsWith(JUDGE_MODEL_MISMATCH_REASON)`, never on equality.
 */
export const JUDGE_MODEL_MISMATCH_REASON = "judge model mismatch";

/** The reason a policy that asked for no judge reports. */
export const NO_JUDGE_CONFIGURED_REASON = "no judge configured";

/**
 * The escalation reason when the judge itself threw.
 *
 * §15.4 requires a timeout, a transport failure and an unparseable response to "produce
 * escalation rather than an exception". `BedrockJudge` honours that internally, but {@link Judge}
 * is a public interface and a custom implementation can throw — which would put an exception on
 * the authorization path, and the natural fix for that at a call site is a `catch` that returns
 * "allow". Caught in {@link evaluateJudge} so the safe reading is the default rather than
 * something each integrator has to remember. Byte-identical to .NET's
 * `JudgeGate.JudgeFailedReason` and Python's `JUDGE_FAILED_REASON`.
 */
export const JUDGE_FAILED_REASON = "judge invocation failed";

// ---------------------------------------------------------------------------
// The judge contract
// ---------------------------------------------------------------------------

/** What a judge is asked to decide. */
export interface JudgeRequest {
  /**
   * The profile from the resolved policy. Its `description` is what gives the judge
   * something to compare the call against, which is why an author who enables the
   * judge should write one.
   */
  purpose: PurposeProfile;
  /** A rendering of the call under consideration. */
  currentToolCall: string;
  /**
   * Preceding calls, **oldest first**, bounded by `JudgeConfig.historyWindow`.
   * Drift is a property of a sequence rather than of one call: an agent asking for
   * one more column each turn looks reasonable at every single step.
   */
  recentHistory: string[];
  /** The wall-clock budget. Exceeding it escalates rather than allowing. */
  maxLatencyMs: number;
}

/** A judge's verdict. */
export interface JudgeResult {
  /** Whether the call serves the declared purpose. */
  aligned: boolean;
  /**
   * How sure the judge is, in `[0, 1]`. A value outside that range is unusable and
   * escalates — see {@link getDisposition}.
   */
  confidence: number;
  /** The judge's explanation, for the audit trail. */
  reasoning: string;
  /** Optional machine-readable markers for downstream triage. */
  flags?: string[];
}

/** What to do with a judge's verdict. */
export enum JudgeDisposition {
  /** Proceed. The deterministic checks already passed. */
  Allow = "allow",
  /** Refuse. The judge is confident the call does not serve the purpose. */
  Block = "block",
  /**
   * Refer to a human. **Not** an allow: a wrapper with no escalation handler must
   * deny, or "escalate to review" silently means "permit" wherever the review step
   * was never built.
   */
  Escalate = "escalate",
}

/**
 * What {@link evaluateJudge} decided, and why.
 *
 * A bare {@link JudgeDisposition} is not enough. `escalate` is returned both when the
 * deployment wired up the wrong model and when the judge genuinely could not tell, and
 * those call for entirely different responses — fix the configuration versus route to a
 * reviewer. Returning only the disposition left {@link JUDGE_MODEL_MISMATCH_REASON}
 * unreachable from the call site, which made a mandated reason string decoration.
 */
export interface JudgeOutcome {
  disposition: JudgeDisposition;
  /**
   * Why. The judge's own `reasoning` on a real verdict; otherwise a reason this module
   * owns — {@link NO_JUDGE_CONFIGURED_REASON}, or a string beginning with
   * {@link JUDGE_MODEL_MISMATCH_REASON}.
   */
  reason: string;
  /**
   * The verdict, or **absent when no model was consulted** — either because the policy
   * asked for no judge, or because the model did not match and the call was refused
   * before being issued. Absent is therefore a positive statement: no tokens were
   * spent and nothing a model said is being reported.
   */
  result?: JudgeResult;
  /**
   * Whether the call may proceed. **`escalate` is not allowed.**
   *
   * Precomputed rather than left to the caller, because a caller writing
   * `disposition !== Block` is the most likely route to "escalate to human review"
   * quietly meaning "permit" in a deployment that never built the review step.
   */
  allowed: boolean;
}

/** Build a {@link JudgeOutcome}, deriving `allowed` so no caller has to. */
function outcome(
  disposition: JudgeDisposition,
  reason: string,
  result?: JudgeResult,
): JudgeOutcome {
  return {
    disposition,
    reason,
    ...(result === undefined ? {} : { result }),
    // The one place `escalate` is turned into a boolean, so there is one place to read
    // when asking whether it counts as permission. It does not.
    allowed: disposition === JudgeDisposition.Allow,
  };
}

/**
 * A semantic judge.
 *
 * Named `Judge` rather than `IJudge` to match this SDK's convention — `PolicyStore`
 * and `ReplayGuard` are the TypeScript spellings of .NET's `IPolicyStore` and
 * `IReplayGuard`. The .NET counterpart is `Tolap.Core.IJudge`.
 */
export interface Judge {
  /**
   * The model this judge actually invokes.
   *
   * Declared so {@link evaluateJudge} can check it against the
   * `JudgeConfig.model` the policy asked for. Without it, a policy demanding one
   * model would be silently judged by whatever the deployment happened to wire up
   * — the policy field would look like a control and be decoration. A verdict is
   * only meaningful against the model that produced it, which is also why two
   * policies naming different models refuse to merge.
   *
   * Reported by the implementation rather than configured alongside it, so the
   * value comes from whatever really issues the call.
   */
  readonly modelId: string;

  /**
   * Evaluate a call against its purpose.
   *
   * Implementations should surface a timeout or a transport failure as a
   * low-confidence result (or, for caller cancellation, by rejecting) rather than
   * a confident `aligned: true`. The caller maps either to
   * {@link JudgeDisposition.Escalate}; a fabricated confident alignment is the one
   * response that cannot be recovered from.
   *
   * @param signal Caller cancellation, distinct from the policy's latency budget.
   */
  evaluate(request: JudgeRequest, signal?: AbortSignal): Promise<JudgeResult>;
}

// ---------------------------------------------------------------------------
// Verdict -> disposition
// ---------------------------------------------------------------------------

/**
 * Decide what to do with a verdict.
 *
 * Every path that is not a confident verdict escalates, and escalation denies
 * unless a handler is wired. The ordering matters: the unusable-input checks come
 * **first**, so a malformed result cannot reach the threshold comparisons and win
 * one.
 *
 * Three unusable-input cases, each of which would otherwise produce a confident
 * allow:
 *
 * - A confidence outside `[0, 1]`. A judge reporting `1.5` has malfunctioned, and
 *   comparing it against a threshold would grant it more authority than a correct
 *   answer.
 * - Thresholds **inverted**, with escalation above confidence. There is no reading
 *   of that configuration to act on, so it escalates rather than picking whichever
 *   bound happens to be checked first.
 * - `NaN`, which fails every comparison and would otherwise fall through to
 *   whatever the last branch happened to be. In JavaScript this matters more than
 *   elsewhere: `NaN < 0.6` and `NaN > 1` are both false, so a bare comparison chain
 *   ends at the confident arm.
 */
export function getDisposition(
  result: JudgeResult,
  config?: JudgeConfig,
): JudgeDisposition {
  const confidenceThreshold =
    config?.confidenceThreshold ?? DEFAULT_CONFIDENCE_THRESHOLD;
  const escalationThreshold =
    config?.escalationThreshold ?? DEFAULT_ESCALATION_THRESHOLD;

  if (
    Number.isNaN(result.confidence) ||
    result.confidence < 0 ||
    result.confidence > 1
  ) {
    return JudgeDisposition.Escalate;
  }

  if (escalationThreshold > confidenceThreshold) {
    return JudgeDisposition.Escalate;
  }

  if (result.confidence < escalationThreshold) {
    return JudgeDisposition.Escalate;
  }

  if (result.confidence < confidenceThreshold) {
    return JudgeDisposition.Escalate;
  }

  return result.aligned ? JudgeDisposition.Allow : JudgeDisposition.Block;
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

/**
 * Whether this policy asks for a judge at all.
 *
 * Checked against `=== true` rather than for truthiness, because
 * `JudgeConfig.enabled` is optional: absent means "not configured", which is not
 * the same statement as an explicit `false` even though both mean no judge today.
 */
export function judgeEnabled(policy: EffectivePolicy): boolean {
  return policy.purposeProfile?.judge?.enabled === true;
}

/**
 * How many preceding calls the policy wants the judge to see.
 *
 * Read this to size a `ToolCallHistory`, so the window is the policy author's
 * choice rather than the integrator's default. A window smaller than the policy
 * asked for hides exactly the trajectory the judge was enabled to notice.
 */
export function judgeHistoryWindow(policy: EffectivePolicy): number {
  return policy.purposeProfile?.judge?.historyWindow ?? DEFAULT_HISTORY_WINDOW;
}

/**
 * Build the judge request for a call, from the policy's judge configuration.
 *
 * @returns
 * The request, or `undefined` when this policy has no judge enabled — in which case
 * there is nothing to ask and the deterministic decision stands.
 *
 * The latency budget comes from the policy rather than from the caller, which is
 * the whole point: `maxLatencyMs` is a policy field and a caller passing its own
 * value would make it advisory.
 *
 * @throws Error when `currentToolCall` is not a string. Guarded at runtime because
 * the alternative is a prompt in which the call under review reads as the literal
 * `undefined`, and a judge cannot report that as suspicious.
 */
export function buildJudgeRequest(
  policy: EffectivePolicy,
  currentToolCall: string,
  history?: ToolCallHistory,
): JudgeRequest | undefined {
  if (typeof currentToolCall !== "string") {
    throw new Error(
      `buildJudgeRequest requires a string rendering of the call, received ` +
        `${currentToolCall === null ? "null" : typeof currentToolCall}`,
    );
  }

  if (!judgeEnabled(policy)) return undefined;

  // Non-null after `judgeEnabled`: it is exactly the assertion that both are set.
  const profile = policy.purposeProfile as PurposeProfile;
  const judge = profile.judge as JudgeConfig;

  // Trimmed to the policy's window even when the caller's history is larger, so an
  // oversized buffer cannot quietly widen what the policy chose to send.
  const window = judge.historyWindow ?? DEFAULT_HISTORY_WINDOW;
  const recorded = history?.getRecent() ?? [];
  const recentHistory =
    recorded.length > window ? recorded.slice(recorded.length - window) : recorded;

  return {
    purpose: profile,
    currentToolCall,
    recentHistory,
    maxLatencyMs: judge.maxLatencyMs ?? DEFAULT_MAX_LATENCY_MS,
  };
}

/**
 * Whether the judge in hand is the one the policy asked for.
 *
 * A policy naming no model accepts any judge: the field is optional, and requiring
 * it would make every judge-enabled policy fail until someone pinned a model id
 * that differs per account and region.
 *
 * When a policy does name one, the comparison is **exact and case-sensitive**. Not
 * a prefix or substring match: `claude-sonnet` and `claude-sonnet-5` are different
 * models, and a prefix rule would let a deployment satisfy a policy demanding one
 * by wiring the other. This mirrors the `purposeId` comparison — an identifier is
 * matched, not a pattern.
 */
function modelMatches(configured: string | undefined, actual: string): boolean {
  return configured === undefined || configured === actual;
}

/**
 * Run the judge for a call and map the verdict to a disposition.
 *
 * @param policy The resolved policy. No judge enabled means
 * {@link JudgeDisposition.Allow}.
 * @param judge The judge. Its `modelId` is verified **first**.
 * @param currentToolCall A rendering of the call under consideration.
 * @param history Preceding calls; trimmed to the policy's window.
 * @param signal Caller cancellation. Distinct from the policy's latency budget.
 *
 * @returns
 * A {@link JudgeOutcome}: what to do, why, and the verdict when one was obtained.
 * `JudgeDisposition.Escalate` is **not** an allow — read `outcome.allowed`, which
 * says so — or "escalate to review" means "permit" in every deployment that never
 * built one.
 *
 * The model check runs before the call, not after. Invoking the wrong model and
 * then noticing would have spent the tokens and, worse, produced a verdict that
 * reads as authoritative in an audit log. That escalation's reason begins with
 * {@link JUDGE_MODEL_MISMATCH_REASON} and names both models, and its `result` is
 * absent because nothing was asked.
 *
 * @throws Error when `judge` is nullish.
 */
export async function evaluateJudge(
  policy: EffectivePolicy,
  judge: Judge,
  currentToolCall: string,
  history?: ToolCallHistory,
  signal?: AbortSignal,
): Promise<JudgeOutcome> {
  if (judge === null || judge === undefined) {
    throw new Error("evaluateJudge requires a judge; received none");
  }

  const request = buildJudgeRequest(policy, currentToolCall, history);
  if (request === undefined) {
    return outcome(JudgeDisposition.Allow, NO_JUDGE_CONFIGURED_REASON);
  }

  const config = (policy.purposeProfile as PurposeProfile).judge as JudgeConfig;

  if (!modelMatches(config.model, judge.modelId)) {
    return outcome(
      JudgeDisposition.Escalate,
      // Both sides named. A log line saying only "judge model mismatch" tells an
      // operator that something is misconfigured and nothing about what to change.
      `${JUDGE_MODEL_MISMATCH_REASON}: policy requires '${config.model}', ` +
        `judge reports '${judge.modelId}'`,
    );
  }

  let result: JudgeResult;
  try {
    result = await judge.evaluate(request, signal);
  } catch (error) {
    // Deliberately broad: `Judge` is a public interface, so the thrown value is whatever an
    // implementation produces, and every one of them means the same thing here — no verdict.
    // A caller's own abort is re-thrown so it stays distinguishable from a judge failure.
    if (signal?.aborted) throw error;
    const name = error instanceof Error ? error.constructor.name : typeof error;
    return outcome(JudgeDisposition.Escalate, `${JUDGE_FAILED_REASON}: ${name}`);
  }

  // The judge's own words become the reason, so a `block` or an ambiguous `escalate`
  // carries the explanation the model gave rather than a reason this module invented.
  return outcome(getDisposition(result, config), result.reasoning, result);
}
