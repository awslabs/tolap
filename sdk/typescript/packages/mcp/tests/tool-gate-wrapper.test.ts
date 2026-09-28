/**
 * objectRules.toolRules on the MCP wrappers (canonical spec §16).
 *
 * Driven from fixtures/enforcement/tool-gate-wrapper.json so all three SDKs agree on order
 * and filtering. There is no option to set: the policy alone decides. The tamper, judge,
 * history, factory, store-wrapper and concurrency cases are hand-written because they are
 * about signing, wiring and state, which a table can't say.
 */

import fs from "node:fs";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";

import {
  ToolCallHistory,
  buildSecurityContext,
  signContext,
  type EffectivePolicy,
  type Judge,
  type JudgeRequest,
  type JudgeResult,
  type SecurityContext,
} from "@aws/tolap-core";
import { SecureContextToolWrapper } from "../src/context-wrapper.js";
import { SecureToolFactory } from "../src/factory.js";
import { HeaderIdentityExtractor } from "../src/extractors.js";
import { renderToolCall } from "../src/tool-call.js";
import { SecureMcpToolWrapper } from "../src/wrapper.js";
import { EnforcementMode } from "../src/types.js";
import type {
  EnforcementDecision,
  McpRequestContext,
  McpToolDefinition,
} from "../src/types.js";

const KEY = "tool-gate-key";
const WRONG_KEY = "tolap-fixture-wrong-key-000000000000";

interface FixtureCase {
  name: string;
  staticAllowedTools: string[];
  toolName: string;
  contextOverride?: "expired" | "wrongKey";
  object?: string;
  fields?: string[];
  toolActionCategories?: Record<string, string>;
  policy: Record<string, unknown>;
  expected: { allowed: boolean; reason?: string; reasonFamily?: string };
}

interface FixtureFilterCase {
  name: string;
  staticAllowedTools: string[];
  contextOverride?: "expired" | "wrongKey";
  toolActionCategories?: Record<string, string>;
  toolNames: string[];
  policy: Record<string, unknown>;
  expected: string[];
}

interface FixtureWriteCase {
  name: string;
  staticAllowedTools: string[];
  toolName?: string;
  contextOverride?: "expired" | "wrongKey";
  operation: string;
  object?: string;
  payload?: Record<string, unknown>;
  policy: Record<string, unknown>;
  expected: { allowed: boolean; reason?: string; reasonFamily?: string };
}

const fixture = JSON.parse(
  fs.readFileSync(
    path.resolve(__dirname, "../../../../../fixtures/enforcement/tool-gate-wrapper.json"),
    "utf-8",
  ),
) as {
  reasonFamilies: Record<string, { typescript: string }>;
  cases: FixtureCase[];
  filterCases: FixtureFilterCase[];
  writeCases: FixtureWriteCase[];
};

const HIDDEN_EXPORT = {
  permissions: { canQuery: true },
  objectRules: { toolRules: { hiddenTools: ["export_segment_csv"] } },
};

function policyFrom(fragment: Record<string, unknown>): EffectivePolicy {
  const now = Date.now();
  return {
    version: "1.0",
    userId: "tool-user",
    tenantId: "tool-tenant",
    sourceConnectionId: "db:tool:test",
    resolvedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + 3_600_000).toISOString(),
    sourceProfiles: ["tool-gate"],
    integrity: { algorithm: "none", signature: "" },
    // Cloned so a tamper test mutating the context cannot reach the shared constants.
    ...structuredClone(fragment),
  } as EffectivePolicy;
}

function signed(
  fragment: Record<string, unknown>,
  override?: "expired" | "wrongKey",
): SecurityContext {
  const policy = policyFrom(fragment);
  const ttl = override === "expired" ? -3_600_000 : 3_600_000;
  return signContext(
    buildSecurityContext(
      policy.userId,
      policy.tenantId,
      policy,
      ttl,
      undefined,
      policy.purposeProfile?.purposeId,
    ),
    override === "wrongKey" ? WRONG_KEY : KEY,
  );
}

function wrapper(c: {
  staticAllowedTools: string[];
  toolActionCategories?: Record<string, string>;
}): SecureContextToolWrapper {
  return new SecureContextToolWrapper({
    signingKey: KEY,
    allowedTools: c.staticAllowedTools,
    ...(c.toolActionCategories ? { toolActionCategories: c.toolActionCategories } : {}),
  });
}

function expectedReason(expected: FixtureCase["expected"]): string | undefined {
  if (expected.reasonFamily !== undefined) {
    return fixture.reasonFamilies[expected.reasonFamily].typescript;
  }
  return expected.reason;
}

// ---------------------------------------------------------------------------
// The shared fixture: B1-B11 and C1-C6, plus the named rows
// ---------------------------------------------------------------------------

describe("tool-gate-wrapper.json: preExecute", () => {
  for (const c of fixture.cases) {
    it(c.name, () => {
      const result = wrapper(c).preExecute(signed(c.policy, c.contextOverride), {
        toolName: c.toolName,
        ...(c.object !== undefined ? { objectName: c.object } : {}),
        ...(c.fields !== undefined ? { fields: c.fields } : {}),
      });
      expect(result.allowed).toBe(c.expected.allowed);
      expect(result.reason).toBe(expectedReason(c.expected));
    });
  }
});

describe("tool-gate-wrapper.json: filterTools", () => {
  for (const c of fixture.filterCases) {
    it(c.name, () => {
      expect(
        wrapper(c).filterTools(signed(c.policy, c.contextOverride), c.toolNames),
      ).toEqual(c.expected);
    });
  }
});

describe("tool-gate-wrapper.json: preWrite", () => {
  for (const c of fixture.writeCases) {
    it(c.name, () => {
      // A row with no toolName key omits the option entirely, not { toolName: undefined }.
      const options = "toolName" in c ? { toolName: c.toolName } : {};
      const result = wrapper(c).preWrite(
        signed(c.policy, c.contextOverride),
        c.operation,
        c.object,
        c.payload,
        options,
      );
      expect(result.allowed).toBe(c.expected.allowed);
      expect(result.reason).toBe(expectedReason(c.expected));
    });
  }
});

describe("tool-gate-wrapper.json: executeWriteWithEnforcement", () => {
  for (const c of fixture.writeCases) {
    it(c.name, async () => {
      // The helper must thread toolName through: a denied row never reaches the write.
      const options = "toolName" in c ? { toolName: c.toolName } : {};
      const writeFn = vi.fn(() => undefined);
      const run = wrapper(c).executeWriteWithEnforcement(
        signed(c.policy, c.contextOverride),
        c.operation,
        writeFn,
        c.object,
        c.payload,
        options,
      );
      if (c.expected.allowed) {
        await expect(run).resolves.toBeUndefined();
        expect(writeFn).toHaveBeenCalledTimes(1);
      } else {
        await expect(run).rejects.toThrow(`Access denied: ${expectedReason(c.expected)}`);
        expect(writeFn).not.toHaveBeenCalled();
      }
    });
  }
});

describe("the write gate: what the rows cannot say", () => {
  const WRITE_ONLY_HIDDEN = {
    permissions: { canQuery: false, canInsert: true, readOnly: false },
    objectRules: { toolRules: { hiddenTools: ["delete_patient"] } },
  };
  const w = () => new SecureContextToolWrapper({ signingKey: KEY });

  it("the write denial matches the read denial exactly", () => {
    const ctx = signed({
      permissions: { canQuery: true, canInsert: true, readOnly: false },
      objectRules: {
        toolRules: { allowedTools: ["write_note"], hiddenTools: ["delete_patient"] },
      },
    });
    for (const name of ["delete_patient", "DELETE_patient", "export_csv", "bad name", "\u212Aill"]) {
      const read = w().preExecute(ctx, { toolName: name });
      const write = w().preWrite(ctx, "insert", "notes", { body: "x" }, { toolName: name });
      expect(read.allowed, name).toBe(false);
      expect(write, name).toEqual(read);
    }
  });

  it("an empty-string name is gated, not treated as omitted", () => {
    expect(
      w().preWrite(signed(WRITE_ONLY_HIDDEN), "insert", "notes", { body: "x" }, { toolName: "" }),
    ).toEqual({ allowed: false, reason: "invalid tool name" });
  });

  it("toolName is not forwarded to validateWrite as a write option", () => {
    // With a full replace and a readOnlyFields entry, the existing write options still apply.
    const ctx = signed({
      permissions: { canQuery: false, canUpdate: true, readOnly: false },
      objectRules: {
        fieldRules: { readOnlyFields: ["id"] },
        toolRules: { allowedTools: ["update_note"] },
      },
    });
    expect(
      w().preWrite(ctx, "update", "notes", { body: "x" }, {
        toolName: "update_note",
        fullReplace: true,
      }),
    ).toEqual({ allowed: false, reason: "field is read-only: id" });
    // Paired control: the same call without fullReplace is allowed, so the denial above
    // came from the write option and not from the tool gate.
    expect(
      w().preWrite(ctx, "update", "notes", { body: "x" }, { toolName: "update_note" }),
    ).toEqual({ allowed: true });
  });

  it("a tampered context is refused before the tool gate", () => {
    const ctx = signed(WRITE_ONLY_HIDDEN);
    ctx.effectivePolicy.objectRules!.toolRules!.hiddenTools = [];
    expect(
      w().preWrite(ctx, "insert", "notes", { body: "x" }, { toolName: "delete_patient" }),
    ).toEqual({ allowed: false, reason: "invalid signature" });
  });
});

describe("M3: filterTools drops null and non-string names", () => {
  const w = () => new SecureContextToolWrapper({ signingKey: KEY });
  for (const [label, fragment] of [
    ["no toolRules", { permissions: { canQuery: true } }],
    ["with toolRules", HIDDEN_EXPORT],
  ] as const) {
    it(label, () => {
      const names = [
        null,
        "query_patients",
        5,
        undefined,
        ["x"],
        { n: 1 },
        "count_patients",
      ] as unknown as string[];
      expect(w().filterTools(signed(fragment), names)).toEqual([
        "query_patients",
        "count_patients",
      ]);
    });
  }
});

describe("tool-gate-wrapper.json: the runner covers every row", () => {
  it("every owned row is present", () => {
    // A fixture edit that drops a row would otherwise just run fewer cases, silently.
    const caseNames = new Set(fixture.cases.map((c) => c.name));
    const filterNames = new Set(fixture.filterCases.map((c) => c.name));
    for (let i = 1; i <= 11; i++) expect(caseNames).toContain(`B${i}`);
    for (let i = 1; i <= 6; i++) expect(filterNames).toContain(`C${i}`);
    for (const name of [
      "no-tool-rules-unchanged",
      "hidden",
      "not-in-allowed-set",
      "allowed",
      "tools-only-policy",
      "static-list-wins-first",
      "static-empty-policy-empty",
      "static-and-policy-intersect",
      "tool-rules-before-can-query",
      "allowed-tool-still-needs-can-query",
      "kelvin-sign-invalid-name",
      "mis-cased-not-in-allowed-set",
    ]) {
      expect(caseNames).toContain(name);
    }
    for (const name of [
      "filter-tool-rules",
      "filter-no-tool-rules-lists-everything",
      "filter-static-list-applies",
      "filter-ignores-can-query",
      "filter-purpose-action-applies",
      "filter-no-tool-rules-no-grammar",
      "filter-mis-cased-dropped",
    ]) {
      expect(filterNames).toContain(name);
    }
    for (const name of [
      "filter-deny-all-lists-nothing",
      "filter-deny-all-explicit-false-lists-nothing",
      "filter-write-only-subject-to-tool-rules",
      "filter-update-only-lists",
      "filter-delete-only-lists",
    ]) {
      expect(filterNames).toContain(name);
    }
    const writePrefixes = new Set(fixture.writeCases.map((c) => c.name.split("-")[0]));
    for (let i = 1; i <= 12; i++) expect(writePrefixes).toContain(`W${i}`);
    expect(fixture.writeCases.some((c) => !("toolName" in c))).toBe(true);
    expect(fixture.writeCases.some((c) => "toolName" in c)).toBe(true);
    expect(fixture.cases).toHaveLength(23);
    expect(fixture.filterCases).toHaveLength(18);
    expect(fixture.writeCases).toHaveLength(12);
  });

  it("every override the runner reads is exercised", () => {
    // Pins that contextOverride, object, fields and toolActionCategories are each used,
    // so a runner that ignored one could not pass by the fixture never using it.
    const all = [...fixture.cases, ...fixture.filterCases, ...fixture.writeCases];
    const overrides = new Set(all.map((c) => c.contextOverride));
    expect(overrides).toContain("expired");
    expect(overrides).toContain("wrongKey");
    expect(fixture.cases.some((c) => c.object !== undefined)).toBe(true);
    expect(fixture.cases.some((c) => c.fields !== undefined)).toBe(true);
    expect(fixture.cases.some((c) => c.toolActionCategories !== undefined)).toBe(true);
    expect(fixture.filterCases.some((c) => c.toolActionCategories !== undefined)).toBe(true);
  });

  it("every reasonFamily resolves to a TypeScript reason", () => {
    for (const c of fixture.cases) {
      if (c.expected.reasonFamily !== undefined) {
        expect(typeof fixture.reasonFamilies[c.expected.reasonFamily]?.typescript).toBe(
          "string",
        );
      }
    }
  });
});

// ---------------------------------------------------------------------------
// C10: filterTools agrees with preExecute
// ---------------------------------------------------------------------------

describe("C10: filterTools agrees with preExecute over every filterCases row", () => {
  for (const c of fixture.filterCases) {
    it(c.name, () => {
      const w = wrapper(c);
      const ctx = signed(c.policy, c.contextOverride);
      const kept = w.filterTools(ctx, c.toolNames);
      for (const name of c.toolNames) {
        const result = w.preExecute(ctx, { toolName: name });
        if (kept.includes(name)) {
          // The only denial a kept name may still meet, with no call arguments, is the
          // read gate filterTools deliberately does not apply -- never a tool-name reason.
          expect(result.allowed || result.reason === "query not permitted", name).toBe(true);
        } else {
          expect(result.allowed, name).toBe(false);
        }
      }
    });
  }

  it("the property is not vacuous", () => {
    // At least one row drops a name and at least one keeps a name preExecute still
    // denies for canQuery -- otherwise both branches above could be dead.
    let dropped = 0;
    let keptButDenied = 0;
    for (const c of fixture.filterCases) {
      const w = wrapper(c);
      const ctx = signed(c.policy, c.contextOverride);
      const kept = w.filterTools(ctx, c.toolNames);
      dropped += c.toolNames.filter((n) => !kept.includes(n)).length;
      keptButDenied += kept.filter((n) => !w.preExecute(ctx, { toolName: n }).allowed).length;
    }
    expect(dropped).toBeGreaterThan(0);
    expect(keptButDenied).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// F1-F4: every edit to toolRules after signing breaks the seal
// ---------------------------------------------------------------------------

describe("F1-F4: tamper", () => {
  const w = () => new SecureContextToolWrapper({ signingKey: KEY });
  const INVALID = { allowed: false, reason: "invalid signature" };

  it("control: the untampered context is valid", () => {
    // Without this, a wrapper that rejected every context would pass the rows below.
    expect(w().preExecute(signed(HIDDEN_EXPORT), { toolName: "export_segment_csv" })).toEqual({
      allowed: false,
      reason: "tool is hidden",
    });
    expect(w().filterTools(signed(HIDDEN_EXPORT), ["query_patients"])).toEqual([
      "query_patients",
    ]);
  });

  it("F1: clearing hiddenTools", () => {
    const ctx = signed(HIDDEN_EXPORT);
    ctx.effectivePolicy.objectRules!.toolRules!.hiddenTools = [];
    expect(w().preExecute(ctx, { toolName: "export_segment_csv" })).toEqual(INVALID);
    expect(w().filterTools(ctx, ["query_patients"])).toEqual([]);
  });

  it("F2: removing toolRules", () => {
    const ctx = signed(HIDDEN_EXPORT);
    delete ctx.effectivePolicy.objectRules!.toolRules;
    expect(w().preExecute(ctx, { toolName: "export_segment_csv" })).toEqual(INVALID);
    expect(w().filterTools(ctx, ["export_segment_csv"])).toEqual([]);
  });

  it("F3: appending to allowedTools", () => {
    const ctx = signed({
      permissions: { canQuery: true },
      objectRules: { toolRules: { allowedTools: ["query_patients"] } },
    });
    ctx.effectivePolicy.objectRules!.toolRules!.allowedTools!.push("export_segment_csv");
    expect(w().preExecute(ctx, { toolName: "export_segment_csv" })).toEqual(INVALID);
    expect(w().filterTools(ctx, ["query_patients"])).toEqual([]);
  });

  it("F4: adding toolRules, even a narrowing edit", () => {
    const ctx = signed({ permissions: { canQuery: true } });
    ctx.effectivePolicy.objectRules = {
      ...(ctx.effectivePolicy.objectRules ?? {}),
      toolRules: { hiddenTools: ["export_segment_csv"] },
    };
    expect(w().preExecute(ctx, { toolName: "query_patients" })).toEqual(INVALID);
    expect(w().filterTools(ctx, ["query_patients"])).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// B12 / C9: the judge never sees a tool denial
// ---------------------------------------------------------------------------

const JUDGE_MODEL = "tool-gate-judge-model";
const JUDGE_TOOL_MAP = {
  query_patients: "aggregate_overlap",
  export_segment_csv: "aggregate_overlap",
};
const JUDGE_POLICY = {
  permissions: { canQuery: true },
  objectRules: { toolRules: { hiddenTools: ["export_segment_csv"] } },
  purposeProfile: {
    purposeId: "campaign-x-overlap",
    description: "Aggregate overlap only.",
    allowedActions: ["aggregate_overlap"],
    judge: { enabled: true, model: JUDGE_MODEL },
  },
};

/** Always aligned and confident, so any call that reaches it would be allowed. */
class CountingJudge implements Judge {
  calls = 0;
  readonly modelId = JUDGE_MODEL;

  async evaluate(_request: JudgeRequest): Promise<JudgeResult> {
    this.calls += 1;
    return { aligned: true, confidence: 1, reasoning: "stub" };
  }
}

function judgeWrapper(judge: Judge, history?: ToolCallHistory): SecureContextToolWrapper {
  return new SecureContextToolWrapper({
    signingKey: KEY,
    toolActionCategories: JUDGE_TOOL_MAP,
    judge,
    ...(history ? { toolCallHistory: history } : {}),
  });
}

describe("B12/C9: the judge never sees a tool denial", () => {
  it("control: an allowed tool reaches the judge", async () => {
    // Proves the stub is wired: otherwise zero calls below would be meaningless.
    const judge = new CountingJudge();
    const result = await judgeWrapper(judge).preExecuteAsync(signed(JUDGE_POLICY), {
      toolName: "query_patients",
    });
    expect(result).toEqual({ allowed: true });
    expect(judge.calls).toBe(1);
  });

  it("B12: a hidden tool is denied without the judge", async () => {
    // The stub would allow anything it saw, so reaching it would turn the hide into an
    // allow. Asserted on the call count, not only the outcome.
    const judge = new CountingJudge();
    const result = await judgeWrapper(judge).preExecuteAsync(signed(JUDGE_POLICY), {
      toolName: "export_segment_csv",
    });
    expect(result).toEqual({ allowed: false, reason: "tool is hidden" });
    expect(judge.calls).toBe(0);
  });

  it("B12: a name outside the allowed set is denied without the judge", async () => {
    const judge = new CountingJudge();
    const result = await judgeWrapper(judge).preExecuteAsync(
      signed({
        ...JUDGE_POLICY,
        objectRules: { toolRules: { allowedTools: ["query_patients"] } },
      }),
      { toolName: "export_segment_csv" },
    );
    expect(result).toEqual({ allowed: false, reason: "tool not in allowed set" });
    expect(judge.calls).toBe(0);
  });

  it("C9: filterTools never calls the judge", () => {
    const judge = new CountingJudge();
    const kept = judgeWrapper(judge).filterTools(signed(JUDGE_POLICY), [
      "query_patients",
      "export_segment_csv",
    ]);
    expect(kept).toEqual(["query_patients"]);
    expect(judge.calls).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// B13 / C8: history
// ---------------------------------------------------------------------------

describe("B13/C8: history", () => {
  const w = (history: ToolCallHistory) =>
    new SecureContextToolWrapper({ signingKey: KEY, toolCallHistory: history });

  it("B13: a hidden-tool denial is recorded by preExecuteAsync", async () => {
    const history = new ToolCallHistory();
    const result = await w(history).preExecuteAsync(signed(HIDDEN_EXPORT), {
      toolName: "export_segment_csv",
    });
    expect(result).toEqual({ allowed: false, reason: "tool is hidden" });
    expect(history.getRecent()).toEqual([renderToolCall({ toolName: "export_segment_csv" })]);
  });

  it("B13: recorded exactly like an existing (canQuery) denial", async () => {
    // A canQuery denial on the same tool records the same entry, so the judge sees a
    // refused tool the same way it sees any other refused call.
    const toolHistory = new ToolCallHistory();
    const queryHistory = new ToolCallHistory();
    const args = { toolName: "export_segment_csv", objectName: "patients" };
    const toolDenial = await w(toolHistory).preExecuteAsync(signed(HIDDEN_EXPORT), args);
    const queryDenial = await w(queryHistory).preExecuteAsync(
      signed({ permissions: { canQuery: false } }),
      args,
    );
    expect(toolDenial.reason).toBe("tool is hidden");
    expect(queryDenial.reason).toBe("query not permitted");
    expect(toolHistory.getRecent()).toEqual(queryHistory.getRecent());
    expect(toolHistory.count).toBe(1);
  });

  it("B13: sync preExecute records neither denial, as today", () => {
    const toolHistory = new ToolCallHistory();
    const queryHistory = new ToolCallHistory();
    w(toolHistory).preExecute(signed(HIDDEN_EXPORT), { toolName: "export_segment_csv" });
    w(queryHistory).preExecute(signed({ permissions: { canQuery: false } }), {
      toolName: "export_segment_csv",
    });
    expect(toolHistory.count).toBe(0);
    expect(queryHistory.count).toBe(0);
  });

  it("C8: filterTools records nothing", () => {
    const history = new ToolCallHistory();
    history.record("earlier-call");
    const before = history.getRecent();
    const kept = w(history).filterTools(signed(HIDDEN_EXPORT), [
      "query_patients",
      "export_segment_csv",
    ]);
    expect(kept).toEqual(["query_patients"]);
    expect(history.getRecent()).toEqual(before);
  });
});

// ---------------------------------------------------------------------------
// C7 and ordering of filterTools
// ---------------------------------------------------------------------------

describe("filterTools input and output", () => {
  const w = () => new SecureContextToolWrapper({ signingKey: KEY });

  it("C7: the input list is not mutated", () => {
    const names = ["query_patients", "export_segment_csv", "EXPORT_SEGMENT_CSV", "bad name"];
    const snapshot = [...names];
    const kept = w().filterTools(signed(HIDDEN_EXPORT), names);
    expect(names).toEqual(snapshot);
    expect(kept).toEqual(["query_patients"]);
    expect(kept).not.toBe(names);
  });

  it("C7: the result is a new array even when nothing is dropped", () => {
    const names = ["a", "b"];
    const kept = w().filterTools(signed({ permissions: { canQuery: true } }), names);
    expect(kept).not.toBe(names);
    kept.push("c");
    expect(names).toEqual(["a", "b"]);
  });

  it("C7: an invalid context returns a fresh empty array and leaves the input alone", () => {
    const names = ["query_patients"];
    const kept = w().filterTools(signed(HIDDEN_EXPORT, "wrongKey"), names);
    expect(kept).toEqual([]);
    expect(names).toEqual(["query_patients"]);
  });

  it("preserves input order", () => {
    expect(
      w().filterTools(signed({ permissions: { canQuery: true } }), ["zeta", "alpha", "mid"]),
    ).toEqual(["zeta", "alpha", "mid"]);
  });

  it("preserves order while dropping", () => {
    expect(
      w().filterTools(signed(HIDDEN_EXPORT), [
        "zeta",
        "export_segment_csv",
        "alpha",
        "Export_Segment_Csv",
        "mid",
      ]),
    ).toEqual(["zeta", "alpha", "mid"]);
  });

  it("applies no grammar when the policy has no toolRules", () => {
    // A name the grammar would refuse is listed, exactly as preExecute allows it (B11).
    const ctx = signed({ permissions: { canQuery: true } });
    expect(w().filterTools(ctx, ["export_segment_csv "])).toEqual(["export_segment_csv "]);
    expect(w().preExecute(ctx, { toolName: "export_segment_csv " })).toEqual({ allowed: true });
  });

  it("does not apply object, field or endpoint rules", () => {
    // Listing is by name. A policy whose data rules deny everything still lists tools.
    const ctx = signed({
      permissions: { canQuery: true },
      objectRules: {
        allowedObjects: [],
        fieldRules: { allowedFields: [] },
        endpointRules: { allowedEndpoints: [], allowedMethods: [] },
      },
    });
    expect(w().filterTools(ctx, ["query_patients"])).toEqual(["query_patients"]);
    // Paired control: the same policy's data rules do deny once a call names an object.
    expect(
      w().preExecute(ctx, { toolName: "query_patients", objectName: "patients" }).allowed,
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Mis-cased names: allowedTools is exact, so folding the name would fail open
// ---------------------------------------------------------------------------

const ALLOW_QUERY = {
  permissions: { canQuery: true },
  objectRules: { toolRules: { allowedTools: ["query_patients"] } },
};

describe("a mis-cased name is not in the allowed set", () => {
  const w = () => new SecureContextToolWrapper({ signingKey: KEY });

  it("preExecute denies Query_Patients against allowedTools [query_patients]", () => {
    expect(w().preExecute(signed(ALLOW_QUERY), { toolName: "Query_Patients" })).toEqual({
      allowed: false,
      reason: "tool not in allowed set",
    });
    // Paired control: the exact name is allowed.
    expect(w().preExecute(signed(ALLOW_QUERY), { toolName: "query_patients" })).toEqual({
      allowed: true,
    });
  });

  it("filterTools drops Query_Patients and keeps query_patients", () => {
    expect(w().filterTools(signed(ALLOW_QUERY), ["Query_Patients", "query_patients"])).toEqual([
      "query_patients",
    ]);
  });

  it("the store wrapper denies Query_Patients", async () => {
    const wrapper = strictWrapper(policyFrom(ALLOW_QUERY), {}, storeTool({ name: "Query_Patients" }));
    await expect(wrapper.executeTool(request({ toolName: "Query_Patients" }))).rejects.toThrow(
      'Access denied for tool "Query_Patients": tool not in allowed set',
    );
    // Paired control: the exact name runs under the same policy.
    const exact = strictWrapper(
      policyFrom(ALLOW_QUERY),
      {},
      storeTool({ name: "query_patients", execute: async () => [{ id: 1 }] }),
    );
    expect(await exact.executeTool(request({ toolName: "query_patients" }))).toEqual([{ id: 1 }]);
  });
});

// ---------------------------------------------------------------------------
// Execution paths that go through preExecute inherit the gate
// ---------------------------------------------------------------------------

describe("the gate holds on every execution path of the context wrapper", () => {
  const w = () => new SecureContextToolWrapper({ signingKey: KEY });

  it("executeWithEnforcement never invokes a hidden tool", async () => {
    let invoked = 0;
    await expect(
      w().executeWithEnforcement(signed(HIDDEN_EXPORT), { toolName: "export_segment_csv" }, () => {
        invoked += 1;
        return [];
      }),
    ).rejects.toThrow("Access denied: tool is hidden");
    expect(invoked).toBe(0);
  });

  it("prepareSqlQuery refuses a hidden tool", () => {
    const prep = w().prepareSqlQuery(
      signed(HIDDEN_EXPORT),
      { toolName: "export_segment_csv" },
      "SELECT name FROM patients",
    );
    expect(prep.allowed).toBe(false);
    expect(prep.denialReason).toBe("tool is hidden");
  });

  it("the reason never echoes the tool name", () => {
    for (const [policy, name] of [
      [HIDDEN_EXPORT, "export_segment_csv"],
      [{ permissions: { canQuery: true }, objectRules: { toolRules: { allowedTools: [] } } }, "secret_tool_x"],
      [{ permissions: { canQuery: true }, objectRules: { toolRules: {} } }, "secret tool"],
    ] as const) {
      const result = w().preExecute(signed(policy), { toolName: name });
      expect(result.allowed).toBe(false);
      expect(result.reason).not.toContain(name);
    }
  });
});

// ---------------------------------------------------------------------------
// B17: the factory with default options
// ---------------------------------------------------------------------------

describe("B17: SecureToolFactory with default options", () => {
  it("a context tool denies a hidden tool", () => {
    const factory = new SecureToolFactory({ signingKey: KEY });
    const ctx = signed(HIDDEN_EXPORT);
    const tool = factory.createContextTool();
    expect(tool.preExecute(ctx, { toolName: "export_segment_csv" })).toEqual({
      allowed: false,
      reason: "tool is hidden",
    });
    // Paired control: the same tool allows one the rules do not touch.
    expect(tool.preExecute(ctx, { toolName: "query_patients" })).toEqual({ allowed: true });
    expect(tool.filterTools(ctx, ["export_segment_csv", "query_patients"])).toEqual([
      "query_patients",
    ]);
  });

  it("createTool for a db source produces a wrapper that denies a hidden tool", () => {
    const factory = new SecureToolFactory({ signingKey: KEY });
    const ctx = signed({ ...HIDDEN_EXPORT, sourceConnectionId: "db:clinical:patients" });
    const tool = factory.createTool(ctx);
    expect(tool).toBeInstanceOf(SecureContextToolWrapper);
    expect(
      (tool as SecureContextToolWrapper).preExecute(ctx, { toolName: "export_segment_csv" }),
    ).toEqual({ allowed: false, reason: "tool is hidden" });
  });
});

// ---------------------------------------------------------------------------
// B18: concurrency
// ---------------------------------------------------------------------------

describe("B18: 50 concurrent calls each get their own decision", () => {
  const names = Array.from({ length: 50 }, (_, i) =>
    i % 2 === 0 ? "query_patients" : "export_segment_csv",
  );

  const check = (results: Array<{ allowed: boolean; reason?: string }>) => {
    expect(results).toHaveLength(50);
    results.forEach((result, i) => {
      if (names[i] === "query_patients") {
        expect(result).toEqual({ allowed: true });
      } else {
        expect(result).toEqual({ allowed: false, reason: "tool is hidden" });
      }
    });
  };

  it("preExecuteAsync through Promise.all, with a judge and history on one wrapper", async () => {
    const judge = new CountingJudge();
    const history = new ToolCallHistory(100);
    const w = judgeWrapper(judge, history);
    const ctx = signed(JUDGE_POLICY);
    const results = await Promise.all(
      names.map((toolName) => w.preExecuteAsync(ctx, { toolName })),
    );
    check(results);
    expect(judge.calls).toBe(25);
    expect(history.count).toBe(50);
  });

  it("preExecute through Promise.all on one wrapper", async () => {
    const w = new SecureContextToolWrapper({ signingKey: KEY });
    const ctx = signed(HIDDEN_EXPORT);
    const results = await Promise.all(
      names.map(async (toolName) => w.preExecute(ctx, { toolName })),
    );
    check(results);
  });
});

// ---------------------------------------------------------------------------
// B14 / B16: the store-resolving SecureMcpToolWrapper, with no new option
// ---------------------------------------------------------------------------

const IDENTITY_HEADERS = { "x-user-id": "tool-user", "x-tenant-id": "tool-tenant" };

function request(overrides: Partial<McpRequestContext> = {}): McpRequestContext {
  return { toolName: "export_segment_csv", headers: { ...IDENTITY_HEADERS }, ...overrides };
}

function storeTool(overrides: Partial<McpToolDefinition> = {}): McpToolDefinition {
  return {
    name: "export_segment_csv",
    objectName: "test-object",
    execute: async (args) => args,
    ...overrides,
  };
}

function strictWrapper(
  resolved: EffectivePolicy,
  options: Partial<ConstructorParameters<typeof SecureMcpToolWrapper>[0]> = {},
  toolDef: McpToolDefinition = storeTool(),
) {
  const wrapper = new SecureMcpToolWrapper({
    mode: EnforcementMode.Strict,
    identityExtractor: new HeaderIdentityExtractor(),
    resolvePolicy: async () => resolved,
    ...options,
  });
  wrapper.registerTool(toolDef);
  return wrapper;
}

function collect() {
  const decisions: EnforcementDecision[] = [];
  return { decisions, onEnforcementDecision: (d: EnforcementDecision) => decisions.push(d) };
}

const STORE_HIDDEN = {
  permissions: { canQuery: false },
  objectRules: { toolRules: { hiddenTools: ["export_segment_csv"] } },
};

describe("B14/B16: the store-resolving wrapper", () => {
  it("B14: a hidden tool is denied 'tool is hidden', ahead of canQuery", async () => {
    const { decisions, onEnforcementDecision } = collect();
    let invoked = 0;
    const wrapper = strictWrapper(
      policyFrom(STORE_HIDDEN),
      { onEnforcementDecision },
      storeTool({
        execute: async () => {
          invoked += 1;
          return [];
        },
      }),
    );
    await expect(wrapper.executeTool(request())).rejects.toThrow(
      'Access denied for tool "export_segment_csv": tool is hidden',
    );
    expect(invoked).toBe(0);
    expect(decisions).toHaveLength(1);
    expect(decisions[0]).toMatchObject({ allowed: false, reason: "tool is hidden" });
  });

  it("B16: the same policy without toolRules gives the canQuery denial it gives today", async () => {
    const { decisions, onEnforcementDecision } = collect();
    const wrapper = strictWrapper(policyFrom({ permissions: { canQuery: false } }), {
      onEnforcementDecision,
    });
    await expect(wrapper.executeTool(request())).rejects.toThrow(
      'Access denied for tool "export_segment_csv": query not permitted',
    );
    expect(decisions).toHaveLength(1);
    expect(decisions[0]).toMatchObject({
      toolName: "export_segment_csv",
      userId: "tool-user",
      tenantId: "tool-tenant",
      allowed: false,
      reason: "query not permitted",
      mode: EnforcementMode.Strict,
    });
  });

  it("B16: a policy without toolRules still allows and filters as today", async () => {
    const { decisions, onEnforcementDecision } = collect();
    const wrapper = strictWrapper(
      policyFrom({
        permissions: { canQuery: true },
        objectRules: { fieldRules: { hiddenFields: ["ssn"] } },
      }),
      { onEnforcementDecision },
      storeTool({
        name: "export_segment_csv ",
        execute: async () => [{ name: "a", ssn: "111-22-3333" }],
      }),
    );
    // A name the grammar would refuse, but with no toolRules no grammar applies (B11).
    expect(await wrapper.executeTool(request({ toolName: "export_segment_csv " }))).toEqual([
      { name: "a" },
    ]);
    expect(decisions.map((d) => d.allowed)).toEqual([true]);
  });

  it("the tool check runs before the purpose action", async () => {
    const wrapper = strictWrapper(
      policyFrom({
        permissions: { canQuery: true },
        objectRules: { toolRules: { hiddenTools: ["export_csv"] } },
        purposeProfile: {
          purposeId: "campaign-x-overlap",
          allowedActions: ["aggregate_overlap"],
          prohibitedActions: ["export_pii"],
        },
      }),
      { toolActionCategories: { export_csv: "export_pii" } },
      storeTool({ name: "export_csv" }),
    );
    await expect(wrapper.executeTool(request({ toolName: "export_csv" }))).rejects.toThrow(
      'Access denied for tool "export_csv": tool is hidden',
    );
  });

  it("an allowed tool still meets the purpose action and the data rules", async () => {
    const purposeBound = strictWrapper(
      policyFrom({
        permissions: { canQuery: true },
        objectRules: { toolRules: { allowedTools: ["export_csv"] } },
        purposeProfile: {
          purposeId: "campaign-x-overlap",
          allowedActions: ["aggregate_overlap"],
          prohibitedActions: ["export_pii"],
        },
      }),
      { toolActionCategories: { export_csv: "export_pii" } },
      storeTool({ name: "export_csv" }),
    );
    await expect(purposeBound.executeTool(request({ toolName: "export_csv" }))).rejects.toThrow(
      "action 'export_pii' is prohibited under purpose 'campaign-x-overlap'",
    );

    const objectBound = strictWrapper(
      policyFrom({
        permissions: { canQuery: true },
        objectRules: {
          allowedObjects: ["patients"],
          toolRules: { allowedTools: ["export_segment_csv"] },
        },
      }),
    );
    await expect(objectBound.executeTool(request())).rejects.toThrow(
      "object not in allowed set",
    );
  });

  it("not in the allowed set, and an invalid name, are denied", async () => {
    await expect(
      strictWrapper(
        policyFrom({
          permissions: { canQuery: true },
          objectRules: { toolRules: { allowedTools: ["query_patients"] } },
        }),
      ).executeTool(request()),
    ).rejects.toThrow('Access denied for tool "export_segment_csv": tool not in allowed set');

    await expect(
      strictWrapper(
        policyFrom({ permissions: { canQuery: true }, objectRules: { toolRules: {} } }),
        {},
        storeTool({ name: "export_segment_csv " }),
      ).executeTool(request({ toolName: "export_segment_csv " })),
    ).rejects.toThrow("invalid tool name");
  });

  it("an allowed tool runs", async () => {
    const wrapper = strictWrapper(
      policyFrom({
        permissions: { canQuery: true },
        objectRules: { toolRules: { allowedTools: ["export_segment_csv"] } },
      }),
      {},
      storeTool({ execute: async () => [{ id: 1 }] }),
    );
    expect(await wrapper.executeTool(request())).toEqual([{ id: 1 }]);
  });

  it("AuditOnly denies a hidden tool exactly like Strict", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const { decisions, onEnforcementDecision } = collect();
    const wrapper = strictWrapper(policyFrom(STORE_HIDDEN), {
      mode: EnforcementMode.AuditOnly,
      onEnforcementDecision,
    });
    await expect(wrapper.executeTool(request())).rejects.toThrow("tool is hidden");
    expect(decisions[0]).toMatchObject({
      allowed: false,
      reason: "tool is hidden",
      mode: EnforcementMode.AuditOnly,
    });
    warn.mockRestore();
  });

  it("listTools is unchanged: it lists every registered tool regardless of policy", () => {
    const wrapper = strictWrapper(policyFrom(STORE_HIDDEN));
    wrapper.registerTool(storeTool({ name: "query_patients" }));
    expect(wrapper.listTools().map((t) => t.name)).toEqual([
      "export_segment_csv",
      "query_patients",
    ]);
  });
});

// ---------------------------------------------------------------------------
// No option was added
// ---------------------------------------------------------------------------

it("no wrapper exposes a tool-rules option", async () => {
  const sources = await Promise.all(
    ["context-wrapper.ts", "types.ts", "factory.ts"].map((f) =>
      fs.promises.readFile(path.resolve(__dirname, "../src", f), "utf8"),
    ),
  );
  for (const source of sources) {
    expect(source).not.toMatch(/^\s*(enforce)?[tT]oolRules\??:/m);
  }
});
