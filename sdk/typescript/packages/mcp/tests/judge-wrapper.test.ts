/**
 * The semantic judge as the wrapper actually runs it (canonical spec §15.4).
 *
 * `judge-gate.test.ts` covers the decision. This covers the wiring, which is the part that
 * silently does not exist if it is wrong: a gate nobody calls passes all of its own tests while a
 * policy's `judge` block quietly governs nothing. Every case here goes through
 * `preExecuteAsync` — the call an integrator makes.
 *
 * The ordering assertions are the ones worth reading. A judge that ran *before* the deterministic
 * checks, or that could turn a denial into an allow, would be a privilege escalation dressed as a
 * safety feature.
 */

import { describe, expect, it } from "vitest";

import {
  JUDGE_MODEL_MISMATCH_REASON,
  JudgeDisposition,
  ToolCallHistory,
  buildSecurityContext,
  signContext,
  type ActionCategoryMap,
  type EffectivePolicy,
  type Judge,
  type JudgeOutcome,
  type JudgeRequest,
  type JudgeResult,
  type PurposeProfile,
  type SecurityContext,
} from "@aws/tolap-core";
import { SecureContextToolWrapper } from "../src/context-wrapper.js";
import { renderToolCall } from "../src/tool-call.js";

const KEY = "judge-wrapper-key";
const MODEL = "test-model-1";
const TOOL_MAP: ActionCategoryMap = {
  segment_overlap: "aggregate_overlap",
  export_csv: "export_pii",
};

/** A judge returning a fixed verdict, with a call counter. */
class StubJudge implements Judge {
  calls = 0;
  lastToolCall: string | undefined;
  lastHistory: string[] | undefined;

  constructor(
    private readonly result: JudgeResult,
    readonly modelId: string = MODEL,
  ) {}

  async evaluate(request: JudgeRequest): Promise<JudgeResult> {
    this.calls += 1;
    this.lastToolCall = request.currentToolCall;
    this.lastHistory = [...request.recentHistory];
    return this.result;
  }
}

const verdict = (aligned: boolean, confidence: number): JudgeResult => ({
  aligned,
  confidence,
  reasoning: "stub",
});

function purpose(judgeEnabled: boolean): PurposeProfile {
  return {
    purposeId: "campaign-x-overlap",
    description: "Aggregate overlap only.",
    allowedActions: ["aggregate_overlap"],
    ...(judgeEnabled ? { judge: { enabled: true, model: MODEL } } : {}),
  };
}

function policyWith(profile: PurposeProfile, canQuery = true): EffectivePolicy {
  const now = new Date();
  return {
    version: "1.0",
    userId: "judge-user",
    tenantId: "judge-tenant",
    sourceConnectionId: "db:marketing:segments",
    resolvedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 3_600_000).toISOString(),
    sourceProfiles: ["judge-wrapper"],
    permissions: { canQuery, readOnly: true },
    purposeProfile: profile,
    integrity: { algorithm: "none", signature: "" },
  };
}

function signed(policy: EffectivePolicy): SecurityContext {
  return signContext(
    buildSecurityContext(
      policy.userId,
      policy.tenantId,
      policy,
      3_600_000,
      undefined,
      policy.purposeProfile?.purposeId,
    ),
    KEY,
  );
}

function wrapper(
  judge: Judge | undefined,
  toolCallHistory?: ToolCallHistory,
  escalationHandler?: (o: JudgeOutcome) => boolean | Promise<boolean>,
): SecureContextToolWrapper {
  return new SecureContextToolWrapper({
    signingKey: KEY,
    toolActionCategories: TOOL_MAP,
    ...(judge === undefined ? {} : { judge }),
    ...(toolCallHistory === undefined ? {} : { toolCallHistory }),
    ...(escalationHandler === undefined ? {} : { escalationHandler }),
  });
}

describe("the judge runs, and can subtract", () => {
  it("allows a confidently aligned call", async () => {
    const judge = new StubJudge(verdict(true, 0.95));

    const result = await wrapper(judge).preExecuteAsync(signed(policyWith(purpose(true))), {
      toolName: "segment_overlap",
    });

    expect(result.allowed).toBe(true);
    expect(judge.calls).toBe(1);
  });

  it("denies a confidently misaligned call", async () => {
    // The whole reason the judge exists: a call the deterministic rules permit, refused
    // because it does not serve the declared purpose.
    const judge = new StubJudge(verdict(false, 0.95));

    const result = await wrapper(judge).preExecuteAsync(signed(policyWith(purpose(true))), {
      toolName: "segment_overlap",
    });

    expect(result.allowed).toBe(false);
    expect(result.reason).toBeTruthy();
  });
});

describe("the judge can only ever subtract", () => {
  it("never offers a deterministic denial to the judge", async () => {
    // The load-bearing assertion. If a denial reached the judge, a confidently-aligned verdict
    // could overturn it — and a persuasive prompt would become a privilege escalation. Asserted
    // on the judge having been left uncalled, not on the outcome, which is the same either way.
    const judge = new StubJudge(verdict(true, 1.0));

    const result = await wrapper(judge).preExecuteAsync(signed(policyWith(purpose(true))), {
      toolName: "export_csv",
    });

    expect(result.allowed).toBe(false);
    expect(judge.calls).toBe(0);
  });

  it("never offers a canQuery denial to the judge either", async () => {
    const judge = new StubJudge(verdict(true, 1.0));

    const result = await wrapper(judge).preExecuteAsync(
      signed(policyWith(purpose(true), false)),
      { toolName: "segment_overlap" },
    );

    expect(result.reason).toBe("query not permitted");
    expect(judge.calls).toBe(0);
  });
});

describe("escalation is a denial without a handler", () => {
  it("denies when no handler is wired", async () => {
    const judge = new StubJudge(verdict(true, 0.4));

    const result = await wrapper(judge).preExecuteAsync(signed(policyWith(purpose(true))), {
      toolName: "segment_overlap",
    });

    expect(result.allowed).toBe(false);
  });

  it("allows when a handler approves", async () => {
    const judge = new StubJudge(verdict(true, 0.4));
    const seen: JudgeOutcome[] = [];

    const result = await wrapper(judge, undefined, (o) => {
      seen.push(o);
      return true;
    }).preExecuteAsync(signed(policyWith(purpose(true))), { toolName: "segment_overlap" });

    expect(result.allowed).toBe(true);
    expect(seen[0]?.disposition).toBe(JudgeDisposition.Escalate);
  });

  it("denies when a handler refuses", async () => {
    // The paired control: a handler consulted and saying no must still deny.
    const judge = new StubJudge(verdict(true, 0.4));

    const result = await wrapper(judge, undefined, () => false).preExecuteAsync(
      signed(policyWith(purpose(true))),
      { toolName: "segment_overlap" },
    );

    expect(result.allowed).toBe(false);
  });

  it("does not route a confident block through the handler", async () => {
    // A review handler is for the ambiguous case. Routing a confident block through it would
    // let a deployment approve away the judge's clearest refusals.
    const judge = new StubJudge(verdict(false, 0.99));
    let called = false;

    const result = await wrapper(judge, undefined, () => {
      called = true;
      return true;
    }).preExecuteAsync(signed(policyWith(purpose(true))), { toolName: "segment_overlap" });

    expect(result.allowed).toBe(false);
    expect(called).toBe(false);
  });
});

describe("model verification", () => {
  it("escalates a model mismatch before the call is issued", async () => {
    const judge = new StubJudge(verdict(true, 1.0), "other-model");

    const result = await wrapper(judge).preExecuteAsync(signed(policyWith(purpose(true))), {
      toolName: "segment_overlap",
    });

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain(JUDGE_MODEL_MISMATCH_REASON);
    expect(judge.calls).toBe(0);
  });
});

describe("opting out", () => {
  it("matches preExecute when no judge is configured", async () => {
    // A policy asking for a judge with none wired is not an error: the deterministic checks
    // have run, and the judge could only have subtracted.
    const context = signed(policyWith(purpose(true)));
    const w = wrapper(undefined);

    const async_ = await w.preExecuteAsync(context, { toolName: "segment_overlap" });
    const sync = w.preExecute(context, { toolName: "segment_overlap" });

    expect(async_.allowed).toBe(sync.allowed);
    expect(async_.allowed).toBe(true);
  });

  it("does not consult the judge for a policy with no judge block", async () => {
    // A judge wired at the composition root must not start judging policies that never asked
    // for one — otherwise enabling it for one policy changes every other.
    const judge = new StubJudge(verdict(false, 1.0));

    const result = await wrapper(judge).preExecuteAsync(signed(policyWith(purpose(false))), {
      toolName: "segment_overlap",
    });

    expect(result.allowed).toBe(true);
    expect(judge.calls).toBe(0);
  });
});

describe("history", () => {
  it("sends the trajectory to the judge, refused calls included", async () => {
    // Drift is a property of the sequence, not of one call, so the history has to arrive.
    // Refused calls are recorded too: an agent probing for what it can reach is exactly the
    // pattern the judge is meant to notice.
    const history = new ToolCallHistory(8);
    const judge = new StubJudge(verdict(true, 0.95));
    const w = wrapper(judge, history);
    const context = signed(policyWith(purpose(true)));

    await w.preExecuteAsync(context, { toolName: "export_csv" }); // refused
    await w.preExecuteAsync(context, { toolName: "segment_overlap" });

    expect(judge.lastHistory?.some((h) => h.includes("export_csv"))).toBe(true);
    expect(history.getRecent()).toHaveLength(2);
  });

  it("renders field names but never values", () => {
    // Field names are most of what makes a read on-purpose. Values never reach the renderer,
    // so this path cannot send row data to a model.
    expect(
      renderToolCall({
        toolName: "export_csv",
        objectName: "customers",
        fields: ["email", "ssn"],
      }),
    ).toBe("export_csv(object=customers fields=[email,ssn])");
  });

  // The rendering is a cross-SDK contract, not a formatting detail: the same call has to
  // render identically in all three, or a policy's judge sees different text depending on
  // which SDK the wrapper came from — and a verdict is only comparable against one rendering.
  // The .NET and Python suites assert these same four strings.
  it.each([
    [{ toolName: "ping" }, "ping()"],
    [
      { toolName: "fetch", endpointPath: "/segments/overlap" },
      "fetch(endpoint=GET /segments/overlap)",
    ],
    [
      { toolName: "fetch", endpointPath: "/export/all.csv", endpointMethod: "POST" },
      "fetch(endpoint=POST /export/all.csv)",
    ],
    [
      {
        toolName: "read",
        objectName: "customers",
        fields: ["email"],
        endpointPath: "/c",
        endpointMethod: "PUT",
      },
      "read(object=customers fields=[email] endpoint=PUT /c)",
    ],
  ])("renders %j as %s", (args, expected) => {
    expect(renderToolCall(args)).toBe(expected);
  });
});
