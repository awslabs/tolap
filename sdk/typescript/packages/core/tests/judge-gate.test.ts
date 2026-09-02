/**
 * The judge gate — turning a policy's `purposeProfile.judge` block into an actual
 * invocation (canonical spec §15.4).
 *
 * This exists because a policy can configure a judge in full — a model, a history
 * window, two thresholds, a latency budget — and none of it takes effect unless
 * something reads those values and applies them. So the assertions here are about the
 * policy's configuration *being obeyed*, not merely being readable: a control that a
 * configuration implies and that never runs is the shape
 * `docs/testing-antipatterns.md` §4 warns about.
 *
 * The model check is the sharpest of them. Without it, a policy demanding one model
 * would be silently judged by whatever the deployment happened to wire up, and the
 * policy field would look like a control and be decoration.
 */

import { describe, expect, it } from "vitest";
import {
  DEFAULT_HISTORY_WINDOW,
  DEFAULT_MAX_LATENCY_MS,
  JUDGE_FAILED_REASON,
  JUDGE_MODEL_MISMATCH_REASON,
  NO_JUDGE_CONFIGURED_REASON,
  JudgeDisposition,
  buildJudgeRequest,
  evaluateJudge,
  judgeEnabled,
  judgeHistoryWindow,
  type Judge,
  type JudgeRequest,
  type JudgeResult,
} from "../src/judge.js";
import { ToolCallHistory } from "../src/history.js";
import type {
  EffectivePolicy,
  JudgeConfig,
  PurposeProfile,
} from "../src/types.js";

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

/** A judge returning a fixed verdict, counting its invocations. */
class StubJudge implements Judge {
  calls = 0;
  lastRequest: JudgeRequest | undefined;

  constructor(
    private readonly result: JudgeResult,
    readonly modelId: string = "claude-sonnet",
  ) {}

  async evaluate(request: JudgeRequest): Promise<JudgeResult> {
    this.calls += 1;
    this.lastRequest = request;
    return this.result;
  }
}

/** A judge that observes the caller's cancellation signal. */
class CancellationObservingJudge implements Judge {
  readonly modelId = "stub-model";

  async evaluate(_request: JudgeRequest, signal?: AbortSignal): Promise<JudgeResult> {
    if (signal?.aborted === true) {
      throw new Error("cancelled");
    }
    return { aligned: true, confidence: 1, reasoning: "unreachable" };
  }
}

const CONFIDENTLY_ALIGNED: JudgeResult = {
  aligned: true,
  confidence: 0.95,
  reasoning: "on task",
};
const CONFIDENTLY_MISALIGNED: JudgeResult = {
  aligned: false,
  confidence: 0.95,
  reasoning: "off task",
};

function policyWith(profile?: PurposeProfile): EffectivePolicy {
  return {
    version: "1.0",
    userId: "u",
    tenantId: "t",
    sourceConnectionId: "db:marketing:customer_segments",
    resolvedAt: "2026-09-01T10:00:00Z",
    expiresAt: "2026-09-01T11:00:00Z",
    sourceProfiles: ["p"],
    permissions: { canQuery: true, readOnly: true },
    ...(profile === undefined ? {} : { purposeProfile: profile }),
    integrity: { algorithm: "none", signature: "" },
  };
}

function withJudge(judge?: JudgeConfig): PurposeProfile {
  return {
    purposeId: "campaign-x-overlap",
    description: "Aggregate overlap only.",
    ...(judge === undefined ? {} : { judge }),
  };
}

// ---------------------------------------------------------------------------
// Is a judge asked for at all?
// ---------------------------------------------------------------------------

describe("judgeEnabled requires an explicit true", () => {
  it("no purpose profile at all", () => {
    expect(judgeEnabled(policyWith())).toBe(false);
  });

  it("a profile with no judge block", () => {
    expect(judgeEnabled(policyWith(withJudge()))).toBe(false);
  });

  it("a judge block with `enabled` absent", () => {
    // Absent means "not configured", which is not the same statement as an explicit
    // false even though both mean no judge today. Checked against `=== true` rather
    // than for truthiness so the three states stay three.
    expect(judgeEnabled(policyWith(withJudge({})))).toBe(false);
  });

  it("an explicit false", () => {
    expect(judgeEnabled(policyWith(withJudge({ enabled: false })))).toBe(false);
  });

  it("an explicit true", () => {
    expect(judgeEnabled(policyWith(withJudge({ enabled: true })))).toBe(true);
  });

  it("a judge configured in full but switched off is still off", () => {
    // A populated block is not consent. An integrator staging a rollout leaves the
    // thresholds in place and flips `enabled`.
    expect(
      judgeEnabled(
        policyWith(
          withJudge({
            enabled: false,
            model: "claude-sonnet",
            historyWindow: 5,
            confidenceThreshold: 0.9,
            escalationThreshold: 0.7,
            maxLatencyMs: 1500,
          }),
        ),
      ),
    ).toBe(false);
  });
});

describe("no judge enabled means allow, without invoking anything", () => {
  it("a disabled judge allows and does not call the judge", async () => {
    // The judge is consulted only about calls the deterministic checks already allowed,
    // so "no judge" is an allow. Asserting `calls === 0` is what proves the misaligned
    // verdict below was never consulted rather than consulted and ignored.
    const judge = new StubJudge(CONFIDENTLY_MISALIGNED);
    const policy = policyWith(withJudge({ enabled: false }));

    expect((await evaluateJudge(policy, judge, "aggregate_overlap()")).disposition).toBe(
      JudgeDisposition.Allow,
    );
    expect(judge.calls).toBe(0);
  });

  it("a purpose-agnostic policy allows and does not call the judge", async () => {
    const judge = new StubJudge(CONFIDENTLY_MISALIGNED);

    expect((await evaluateJudge(policyWith(), judge, "anything()")).disposition).toBe(
      JudgeDisposition.Allow,
    );
    expect(judge.calls).toBe(0);
  });

  it("buildJudgeRequest returns undefined when there is nothing to ask", () => {
    expect(buildJudgeRequest(policyWith(), "x")).toBeUndefined();
    expect(buildJudgeRequest(policyWith(withJudge({})), "x")).toBeUndefined();
    expect(buildJudgeRequest(policyWith(withJudge({ enabled: false })), "x")).toBeUndefined();
  });

  it("an enabled judge does produce a request", async () => {
    // The paired control for the block above.
    const judge = new StubJudge(CONFIDENTLY_MISALIGNED);
    const policy = policyWith(withJudge({ enabled: true }));

    expect(buildJudgeRequest(policy, "x")).toBeDefined();
    expect((await evaluateJudge(policy, judge, "x")).disposition).toBe(
      JudgeDisposition.Block,
    );
    expect(judge.calls).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// The model check
// ---------------------------------------------------------------------------

describe("the policy's model is verified before the judge is invoked", () => {
  it("a mismatch escalates and spends no tokens", async () => {
    // Before the call, not after. Invoking the wrong model and then noticing would have
    // spent the tokens and, worse, produced a verdict that reads as authoritative in an
    // audit log.
    const judge = new StubJudge(CONFIDENTLY_ALIGNED, "global.anthropic.claude-sonnet-5");
    const policy = policyWith(withJudge({ enabled: true, model: "claude-opus" }));

    expect(
      (await evaluateJudge(policy, judge, "aggregate_overlap()")).disposition,
    ).toBe(JudgeDisposition.Escalate);
    expect(judge.calls).toBe(0);
  });

  it("a matching model proceeds to the judge", async () => {
    const judge = new StubJudge(CONFIDENTLY_ALIGNED, "claude-sonnet");
    const policy = policyWith(withJudge({ enabled: true, model: "claude-sonnet" }));

    expect((await evaluateJudge(policy, judge, "aggregate_overlap()")).disposition).toBe(
      JudgeDisposition.Allow,
    );
    expect(judge.calls).toBe(1);
  });

  it("a policy naming no model accepts any judge", async () => {
    // The field is optional, and requiring it would make every judge-enabled policy
    // fail until someone pinned a model id that differs per account and region.
    const judge = new StubJudge(CONFIDENTLY_ALIGNED, "whatever-is-deployed");
    const policy = policyWith(withJudge({ enabled: true }));

    expect((await evaluateJudge(policy, judge, "x")).disposition).toBe(
        JudgeDisposition.Allow,
      );
    expect(judge.calls).toBe(1);
  });

  const nearMisses = [
    "Claude-Sonnet",
    "claude-sonnet-5",
    "claude-sonne",
    "anthropic.claude-sonnet",
    "",
  ];

  for (const deployed of nearMisses) {
    it(`'${deployed}' does not satisfy a policy demanding 'claude-sonnet'`, async () => {
      // Exact and case-sensitive, not a prefix or substring match: `claude-sonnet` and
      // `claude-sonnet-5` are different models, and a prefix rule would let a
      // deployment satisfy a policy demanding one by wiring the other.
      const judge = new StubJudge(CONFIDENTLY_ALIGNED, deployed);
      const policy = policyWith(withJudge({ enabled: true, model: "claude-sonnet" }));

      expect((await evaluateJudge(policy, judge, "x")).disposition).toBe(
        JudgeDisposition.Escalate,
      );
      expect(judge.calls).toBe(0);
    });
  }

  it("the mismatch reason is part of the contract", () => {
    // Escalation rather than a hard block: the call may be perfectly legitimate and the
    // fault is in the deployment, so a human is the right destination. What it must
    // never be is a silent substitution.
    expect(JUDGE_MODEL_MISMATCH_REASON).toBe("judge model mismatch");
  });
});

// ---------------------------------------------------------------------------
// The history window
// ---------------------------------------------------------------------------

describe("the history window comes from the policy", () => {
  it("reads the policy's value, or the documented default", () => {
    // Read this to size a `ToolCallHistory`, so the window is the policy author's
    // choice rather than the integrator's default. A window smaller than the policy
    // asked for hides exactly the trajectory the judge was enabled to notice.
    expect(judgeHistoryWindow(policyWith(withJudge({ historyWindow: 3 })))).toBe(3);
    expect(judgeHistoryWindow(policyWith(withJudge({})))).toBe(DEFAULT_HISTORY_WINDOW);
    expect(judgeHistoryWindow(policyWith(withJudge()))).toBe(DEFAULT_HISTORY_WINDOW);
    expect(judgeHistoryWindow(policyWith())).toBe(DEFAULT_HISTORY_WINDOW);
  });

  it("trims a larger history to the policy's window, keeping the most recent", () => {
    // An oversized buffer must not quietly widen what the policy chose to send.
    const policy = policyWith(withJudge({ enabled: true, historyWindow: 2 }));
    const history = new ToolCallHistory(10);
    history.record("a");
    history.record("b");
    history.record("c");

    expect(buildJudgeRequest(policy, "d", history)?.recentHistory).toEqual(["b", "c"]);
  });

  it("passes a shorter history whole", () => {
    const policy = policyWith(withJudge({ enabled: true, historyWindow: 10 }));
    const history = new ToolCallHistory(10);
    history.record("a");

    expect(buildJudgeRequest(policy, "b", history)?.recentHistory).toEqual(["a"]);
  });

  it("passes a history exactly at the window whole", () => {
    const policy = policyWith(withJudge({ enabled: true, historyWindow: 2 }));
    const history = new ToolCallHistory(10);
    history.record("a");
    history.record("b");

    expect(buildJudgeRequest(policy, "c", history)?.recentHistory).toEqual(["a", "b"]);
  });

  it("no history supplied sends an empty trajectory, not undefined", () => {
    // The optional-argument case: called without a history at all. A judge receiving
    // `undefined` where it expected an array is how a prompt builder ends up rendering
    // the literal "undefined" as a preceding call.
    const request = buildJudgeRequest(
      policyWith(withJudge({ enabled: true })),
      "aggregate_overlap()",
    );

    expect(request?.recentHistory).toEqual([]);
  });

  it("an empty history sends an empty trajectory", () => {
    const request = buildJudgeRequest(
      policyWith(withJudge({ enabled: true })),
      "x",
      new ToolCallHistory(5),
    );

    expect(request?.recentHistory).toEqual([]);
  });

  it("trims using the DEFAULT window when the policy names none", () => {
    // The `?? DEFAULT_HISTORY_WINDOW` arm inside the trim, which a policy that always
    // names a window would never reach.
    const policy = policyWith(withJudge({ enabled: true }));
    const history = new ToolCallHistory(20);
    for (let i = 0; i < 15; i++) history.record(`call-${i}`);

    const request = buildJudgeRequest(policy, "x", history);
    expect(request?.recentHistory).toHaveLength(DEFAULT_HISTORY_WINDOW);
    expect(request?.recentHistory[0]).toBe("call-5");
  });
});

// ---------------------------------------------------------------------------
// The rest of the request
// ---------------------------------------------------------------------------

describe("the request carries the policy's own values", () => {
  it("takes the latency budget from the policy", () => {
    // `maxLatencyMs` is a policy field. A caller passing its own value would make it
    // advisory, which is the whole thing this gate exists to prevent.
    expect(
      buildJudgeRequest(policyWith(withJudge({ enabled: true, maxLatencyMs: 750 })), "x")
        ?.maxLatencyMs,
    ).toBe(750);
  });

  it("uses the documented default when the policy names no budget", () => {
    expect(
      buildJudgeRequest(policyWith(withJudge({ enabled: true })), "x")?.maxLatencyMs,
    ).toBe(DEFAULT_MAX_LATENCY_MS);
  });

  it("passes the policy's own profile object, not a copy", () => {
    // The judge is shown the administrator's description and action lists verbatim. A
    // reconstructed profile is a second place for the prompt's idea of the purpose to
    // drift from the policy's.
    const profile: PurposeProfile = {
      purposeId: "campaign-x-overlap",
      description: "Aggregate overlap only.",
      allowedActions: ["aggregate_overlap"],
      judge: { enabled: true },
    };

    expect(buildJudgeRequest(policyWith(profile), "x")?.purpose).toBe(profile);
  });

  it("passes the tool call through verbatim", () => {
    const request = buildJudgeRequest(
      policyWith(withJudge({ enabled: true })),
      "export_csv(customer_segments, format='raw')",
    );

    expect(request?.currentToolCall).toBe("export_csv(customer_segments, format='raw')");
  });

  it("an empty tool call is passed through rather than refused", () => {
    // `""` is a poor rendering but it is a string, and refusing it would be a denial
    // the caller cannot act on. The guard below is for a non-string.
    expect(
      buildJudgeRequest(policyWith(withJudge({ enabled: true })), "")?.currentToolCall,
    ).toBe("");
  });

  it("refuses a non-string tool call", () => {
    // TypeScript's types are erased, so a JavaScript caller reaches this. The
    // alternative is a prompt in which the call under review reads as the literal
    // `undefined`, and a judge cannot report that as suspicious.
    const policy = policyWith(withJudge({ enabled: true }));

    expect(() =>
      buildJudgeRequest(policy, undefined as unknown as string),
    ).toThrow(/requires a string rendering of the call/);
    expect(() => buildJudgeRequest(policy, null as unknown as string)).toThrow(/null/);
    expect(() => buildJudgeRequest(policy, 42 as unknown as string)).toThrow(/number/);
  });

  it("refuses a non-string tool call even when no judge is enabled", () => {
    // The guard runs before the enabled check, so a latent bug in a caller does not
    // hide until someone switches the judge on.
    expect(() =>
      buildJudgeRequest(policyWith(), undefined as unknown as string),
    ).toThrow(/requires a string rendering of the call/);
  });
});

// ---------------------------------------------------------------------------
// The verdict is mapped with the policy's thresholds
// ---------------------------------------------------------------------------

describe("the policy's thresholds are applied to the verdict", () => {
  it("the same verdict allows under a lenient bar and escalates under a strict one", () => {
    // Two configurations, one verdict, asserted against each other. Pinning each in
    // isolation cannot show that the thresholds are what moved the answer.
    const verdict: JudgeResult = { aligned: true, confidence: 0.88, reasoning: "fairly sure" };
    const lenient = policyWith(
      withJudge({ enabled: true, confidenceThreshold: 0.85, escalationThreshold: 0.6 }),
    );
    const strict = policyWith(
      withJudge({ enabled: true, confidenceThreshold: 0.95, escalationThreshold: 0.6 }),
    );

    return Promise.all([
      evaluateJudge(lenient, new StubJudge(verdict), "x"),
      evaluateJudge(strict, new StubJudge(verdict), "x"),
    ]).then(([lenientResult, strictResult]) => {
      expect(lenientResult.disposition).toBe(JudgeDisposition.Allow);
      expect(strictResult.disposition).toBe(JudgeDisposition.Escalate);
      // Same verdict either way, so the reason is the judge's own words in both cases
      // and only the disposition moved.
      expect(lenientResult.reason).toBe("fairly sure");
      expect(strictResult.reason).toBe("fairly sure");
    });
  });

  it("a confidently misaligned verdict blocks", async () => {
    expect(
      (
        await evaluateJudge(
          policyWith(withJudge({ enabled: true })),
          new StubJudge(CONFIDENTLY_MISALIGNED),
          "x",
        )
      ).disposition,
    ).toBe(JudgeDisposition.Block);
  });

  it("an unavailable judge escalates", async () => {
    // The shape every failure path in a judge implementation reports: zero confidence
    // and a flag. It must escalate rather than block, because there was no verdict.
    const unavailable: JudgeResult = {
      aligned: false,
      confidence: 0,
      reasoning: "judge timed out",
      flags: ["judge-unavailable"],
    };

    expect(
      (
        await evaluateJudge(
          policyWith(withJudge({ enabled: true })),
          new StubJudge(unavailable),
          "x",
        )
      ).disposition,
    ).toBe(JudgeDisposition.Escalate);
  });

  it("an inverted threshold pair on the policy escalates", async () => {
    expect(
      (
        await evaluateJudge(
          policyWith(
            withJudge({ enabled: true, confidenceThreshold: 0.6, escalationThreshold: 0.9 }),
          ),
          new StubJudge(CONFIDENTLY_ALIGNED),
          "x",
        )
      ).disposition,
    ).toBe(JudgeDisposition.Escalate);
  });
});

// ---------------------------------------------------------------------------
// The outcome carries WHY, not only what
// ---------------------------------------------------------------------------

describe("the outcome distinguishes a misconfiguration from an uncertain verdict", () => {
  it("both are `escalate`, so the disposition alone cannot tell them apart", async () => {
    // The reason this whole shape exists, stated as an assertion: two situations calling
    // for entirely different responses — fix the deployment versus route to a reviewer —
    // and one disposition between them.
    const mismatch = await evaluateJudge(
      policyWith(withJudge({ enabled: true, model: "claude-sonnet" })),
      new StubJudge(CONFIDENTLY_ALIGNED, "claude-opus"),
      "x",
    );
    const uncertain = await evaluateJudge(
      policyWith(withJudge({ enabled: true })),
      new StubJudge({ aligned: true, confidence: 0.7, reasoning: "cannot tell" }),
      "x",
    );

    expect(mismatch.disposition).toBe(JudgeDisposition.Escalate);
    expect(uncertain.disposition).toBe(JudgeDisposition.Escalate);
    expect(mismatch.reason).not.toBe(uncertain.reason);
  });

  it("a model mismatch reports the mandated reason and names both models", async () => {
    // The constant is a PREFIX contract: it is present so an integrator can branch, and
    // the two model ids follow because a log line saying only "judge model mismatch"
    // tells an operator that something is misconfigured and nothing about what to change.
    const outcome = await evaluateJudge(
      policyWith(withJudge({ enabled: true, model: "claude-sonnet" })),
      new StubJudge(CONFIDENTLY_ALIGNED, "global.anthropic.claude-sonnet-5"),
      "x",
    );

    expect(outcome.reason.startsWith(JUDGE_MODEL_MISMATCH_REASON)).toBe(true);
    expect(outcome.reason).toContain("claude-sonnet");
    expect(outcome.reason).toContain("global.anthropic.claude-sonnet-5");
  });

  it("a model mismatch carries NO result, because no model was consulted", async () => {
    // Absent is a positive statement: no tokens were spent and nothing a model said is
    // being reported. A `result` here would read as a verdict the deployment's wrong
    // model had actually produced.
    const judge = new StubJudge(CONFIDENTLY_ALIGNED, "claude-opus");
    const outcome = await evaluateJudge(
      policyWith(withJudge({ enabled: true, model: "claude-sonnet" })),
      judge,
      "x",
    );

    expect(outcome.result).toBeUndefined();
    expect("result" in outcome).toBe(false);
    expect(judge.calls).toBe(0);
  });

  it("no judge configured carries no result either, and says so", async () => {
    const judge = new StubJudge(CONFIDENTLY_MISALIGNED);
    const outcome = await evaluateJudge(policyWith(), judge, "x");

    expect(outcome.disposition).toBe(JudgeDisposition.Allow);
    expect(outcome.reason).toBe(NO_JUDGE_CONFIGURED_REASON);
    expect(outcome.result).toBeUndefined();
    expect(judge.calls).toBe(0);
  });

  it("the two no-model reasons are distinguishable from each other", async () => {
    // "the policy asked for no judge" and "the deployment wired the wrong model" both
    // yield an absent result. They are not the same finding.
    const noJudge = await evaluateJudge(policyWith(), new StubJudge(CONFIDENTLY_ALIGNED), "x");
    const mismatch = await evaluateJudge(
      policyWith(withJudge({ enabled: true, model: "claude-sonnet" })),
      new StubJudge(CONFIDENTLY_ALIGNED, "claude-opus"),
      "x",
    );

    expect(noJudge.reason).not.toBe(mismatch.reason);
    expect(noJudge.allowed).toBe(true);
    expect(mismatch.allowed).toBe(false);
  });

  it("a real verdict carries the judge's own reasoning and the result itself", async () => {
    // Not a reason this module invented: the model's explanation is what an audit trail
    // needs, and reconstructing it from the disposition is impossible.
    const verdict: JudgeResult = {
      aligned: false,
      confidence: 0.95,
      reasoning: "row-level export of customer identifiers",
      flags: ["pii"],
    };
    const outcome = await evaluateJudge(
      policyWith(withJudge({ enabled: true })),
      new StubJudge(verdict),
      "export_csv()",
    );

    expect(outcome.disposition).toBe(JudgeDisposition.Block);
    expect(outcome.reason).toBe("row-level export of customer identifiers");
    expect(outcome.result).toBe(verdict);
    expect(outcome.result?.flags).toEqual(["pii"]);
  });

  it("an allow carries the reasoning too, so a permit is as auditable as a refusal", async () => {
    const outcome = await evaluateJudge(
      policyWith(withJudge({ enabled: true })),
      new StubJudge(CONFIDENTLY_ALIGNED),
      "x",
    );

    expect(outcome.disposition).toBe(JudgeDisposition.Allow);
    expect(outcome.reason).toBe("on task");
    expect(outcome.result).toBe(CONFIDENTLY_ALIGNED);
  });
});

describe("`allowed` treats escalate as NOT allowed", () => {
  it("allow -> true", async () => {
    expect(
      (
        await evaluateJudge(
          policyWith(withJudge({ enabled: true })),
          new StubJudge(CONFIDENTLY_ALIGNED),
          "x",
        )
      ).allowed,
    ).toBe(true);
  });

  it("block -> false", async () => {
    expect(
      (
        await evaluateJudge(
          policyWith(withJudge({ enabled: true })),
          new StubJudge(CONFIDENTLY_MISALIGNED),
          "x",
        )
      ).allowed,
    ).toBe(false);
  });

  it("escalate -> false", async () => {
    // The assertion the whole field exists for. A caller writing
    // `disposition !== Block` is the most likely route to "escalate to human review"
    // quietly meaning "permit" in a deployment that never built the review step, so the
    // boolean is computed in one place and says no.
    const outcome = await evaluateJudge(
      policyWith(withJudge({ enabled: true })),
      new StubJudge({ aligned: true, confidence: 0.7, reasoning: "cannot tell" }),
      "x",
    );

    expect(outcome.disposition).toBe(JudgeDisposition.Escalate);
    expect(outcome.allowed).toBe(false);
  });

  it("a model mismatch is not allowed", async () => {
    expect(
      (
        await evaluateJudge(
          policyWith(withJudge({ enabled: true, model: "claude-sonnet" })),
          new StubJudge(CONFIDENTLY_ALIGNED, "claude-opus"),
          "x",
        )
      ).allowed,
    ).toBe(false);
  });

  it("`allowed` agrees with the disposition on every path", async () => {
    // Cross-checked rather than pinned per case, so a future disposition added without a
    // corresponding `allowed` rule fails here.
    const outcomes = [
      await evaluateJudge(policyWith(), new StubJudge(CONFIDENTLY_ALIGNED), "x"),
      await evaluateJudge(
        policyWith(withJudge({ enabled: true })),
        new StubJudge(CONFIDENTLY_ALIGNED),
        "x",
      ),
      await evaluateJudge(
        policyWith(withJudge({ enabled: true })),
        new StubJudge(CONFIDENTLY_MISALIGNED),
        "x",
      ),
      await evaluateJudge(
        policyWith(withJudge({ enabled: true })),
        new StubJudge({ aligned: true, confidence: 0.7, reasoning: "unsure" }),
        "x",
      ),
      await evaluateJudge(
        policyWith(withJudge({ enabled: true, model: "a" })),
        new StubJudge(CONFIDENTLY_ALIGNED, "b"),
        "x",
      ),
    ];

    // All three dispositions are exercised, so the agreement below is not vacuous.
    expect(new Set(outcomes.map((o) => o.disposition)).size).toBe(3);
    for (const o of outcomes) {
      expect(o.allowed, o.reason).toBe(o.disposition === JudgeDisposition.Allow);
    }
  });

  it("every outcome carries a non-empty reason", async () => {
    // A reason field that is sometimes blank is a reason field a caller learns to
    // ignore.
    const outcomes = [
      await evaluateJudge(policyWith(), new StubJudge(CONFIDENTLY_ALIGNED), "x"),
      await evaluateJudge(
        policyWith(withJudge({ enabled: true })),
        new StubJudge(CONFIDENTLY_ALIGNED),
        "x",
      ),
      await evaluateJudge(
        policyWith(withJudge({ enabled: true, model: "a" })),
        new StubJudge(CONFIDENTLY_ALIGNED, "b"),
        "x",
      ),
    ];

    for (const o of outcomes) expect(o.reason.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// Argument guards and cancellation
// ---------------------------------------------------------------------------

describe("argument guards", () => {
  it("refuses a missing judge", async () => {
    const policy = policyWith(withJudge({ enabled: true }));

    await expect(
      evaluateJudge(policy, undefined as unknown as Judge, "x"),
    ).rejects.toThrow(/requires a judge/);
    await expect(
      evaluateJudge(policy, null as unknown as Judge, "x"),
    ).rejects.toThrow(/requires a judge/);
  });

  it("refuses a missing judge even for a policy that would not use it", async () => {
    // Checked before the enabled test, so a caller's bug does not lie dormant until the
    // day a purpose-bound policy resolves.
    await expect(
      evaluateJudge(policyWith(), undefined as unknown as Judge, "x"),
    ).rejects.toThrow(/requires a judge/);
  });

  it("passes the caller's cancellation signal through to the judge", async () => {
    // Distinct from the policy's latency budget: one is the deployment's own
    // shutdown/abort, the other is a policy field.
    const controller = new AbortController();
    controller.abort();

    await expect(
      evaluateJudge(
        policyWith(withJudge({ enabled: true })),
        new CancellationObservingJudge(),
        "x",
        undefined,
        controller.signal,
      ),
    ).rejects.toThrow(/cancelled/);
  });

  it("an un-aborted signal does not disturb the evaluation", async () => {
    // Paired control: the signal is forwarded, not merely present.
    const controller = new AbortController();

    expect(
      (
        await evaluateJudge(
          policyWith(withJudge({ enabled: true })),
          new CancellationObservingJudge(),
          "x",
          undefined,
          controller.signal,
        )
      ).disposition,
    ).toBe(JudgeDisposition.Allow);
  });
});

describe("a throwing judge does not reach the authorization path", () => {
  // §15.4 requires every judge failure to escalate rather than throw. `BedrockJudge` honours
  // that internally, but `Judge` is a public interface — so a custom implementation can throw,
  // and the natural fix for an exception on the authorization path is a `catch` at the call site
  // returning "allow". That is the failure mode this guard designs out.
  const throwing: Judge = {
    modelId: "stub-model",
    evaluate: () => {
      throw new TypeError("no credentials");
    },
  };

  it("escalates rather than propagating", async () => {
    const policy = policyWith(withJudge({ enabled: true }));

    const outcome = await evaluateJudge(policy, throwing, "x");

    expect(outcome.disposition).toBe(JudgeDisposition.Escalate);
    expect(outcome.allowed).toBe(false);
    expect(outcome.reason.startsWith(JUDGE_FAILED_REASON)).toBe(true);
    expect(outcome.reason).toContain(
      "TypeError",
      // The exception type is named so an operator can find the faulty implementation.
    );
    expect(outcome.result).toBeUndefined();
  });

  it("re-throws a caller's own abort", async () => {
    // The paired direction. A caller's abort is not a judge failure, and swallowing it into an
    // escalation would make a cancelled request indistinguishable from a broken judge.
    const controller = new AbortController();
    controller.abort();
    const policy = policyWith(withJudge({ enabled: true }));

    await expect(
      evaluateJudge(policy, throwing, "x", undefined, controller.signal),
    ).rejects.toThrow();
  });

  it("handles a thrown non-Error", async () => {
    // JavaScript lets you throw anything, and `Judge` is a public interface, so an
    // implementation doing `throw "boom"` is reachable. Without this arm the reason would read
    // `undefined` — losing the only clue an operator has about which implementation failed —
    // and the `instanceof` guard would be an untested branch in a fail-closed path.
    const throwsAString: Judge = {
      modelId: "stub-model",
      evaluate: () => {
        // eslint-disable-next-line @typescript-eslint/only-throw-error
        throw "boom";
      },
    };
    const policy = policyWith(withJudge({ enabled: true }));

    const outcome = await evaluateJudge(policy, throwsAString, "x");

    expect(outcome.disposition).toBe(JudgeDisposition.Escalate);
    expect(outcome.allowed).toBe(false);
    expect(outcome.reason).toBe(`${JUDGE_FAILED_REASON}: string`);
    expect(outcome.result).toBeUndefined();
  });

  it("uses the reason string the other SDKs use", () => {
    expect(JUDGE_FAILED_REASON).toBe("judge invocation failed");
  });
});

