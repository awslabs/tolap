/**
 * Asserts every TypeScript framework example enforces, not merely that it compiles.
 *
 * Parametrised across frameworks on purpose. A per-framework test would pass if one integration
 * quietly returned the raw rows, because nothing would compare it to the others. Here all five
 * must produce the *same* enforced output, so a broken wiring stands out against four correct
 * ones.
 *
 * `EXPECTED` is byte-identical to the Python suite's, which is the point: twelve examples across
 * three languages make one claim, so a cross-language divergence shows up as a different result
 * rather than hiding behind separately-written expectations.
 */

import { describe, expect, it } from "vitest";

import { FAKE_ROWS } from "./tolap-setup.js";
import { queryPatients as mcpQuery } from "./mcp-server-example.js";
import { queryPatients as langchainTool } from "./langchain-example.js";
import { queryPatients as vercelTool } from "./vercel-ai-example.js";
import { queryPatients as mastraTool } from "./mastra-example.js";
import { queryPatients as openaiTool } from "./openai-agents-example.js";

/**
 * What the policy must produce from FAKE_ROWS, whatever the framework: the region filter drops
 * eu-west (4 -> 3), maxResults caps at 2, ssn is hidden, dob is redacted.
 */
const EXPECTED = [
  { id: 1, name: "Alice Nguyen", region: "us-east", dob: "[REDACTED]" },
  { id: 2, name: "Bruno Sato", region: "us-east", dob: "[REDACTED]" },
];

type Invoke = (table: string) => Promise<unknown> | unknown;

/** Each framework driven through its OWN invocation path, not a shared shortcut. */
const FRAMEWORKS: Record<string, Invoke> = {
  "mcp-server": (table) => mcpQuery(table),
  langchain: (table) => langchainTool.invoke({ table }),
  // Both SDKs pass an options/context argument to `execute` that a real run supplies. Only the
  // fields these tools actually read matter here, so the rest is stubbed with `as never` rather
  // than reconstructed -- reconstructing it would couple this test to internals that change
  // between minors without testing anything about TOLAP.
  "vercel-ai": (table) =>
    vercelTool.execute!({ table }, { toolCallId: "t", messages: [], context: undefined } as never),
  mastra: (table) => mastraTool.execute!({ table } as never, {} as never),
  "openai-agents": (table) => openaiTool.invoke({} as never, JSON.stringify({ table })),
};

async function rowsFrom(invoke: Invoke, table: string): Promise<Record<string, unknown>[]> {
  const result = await invoke(table);
  // OpenAI Agents stringifies tool results; the others return the array.
  return typeof result === "string" ? JSON.parse(result) : (result as Record<string, unknown>[]);
}

describe.each(Object.keys(FRAMEWORKS).sort())("%s", (name) => {
  const invoke = FRAMEWORKS[name]!;

  it("returns the enforced rows for a permitted table", async () => {
    expect(await rowsFrom(invoke, "patients")).toEqual(EXPECTED);
  });

  it("CONTROL: the fake source really returns more", () => {
    // Without this, the assertion above could pass against an empty source.
    expect(FAKE_ROWS.length).toBeGreaterThan(EXPECTED.length);
    expect(FAKE_ROWS.some((r) => "ssn" in r)).toBe(true);
  });

  it("never leaks the hidden field", async () => {
    const rows = await rowsFrom(invoke, "patients");
    expect(rows.every((r) => !("ssn" in r))).toBe(true);
  });

  it("redacts the masked field", async () => {
    const rows = await rowsFrom(invoke, "patients");
    const originals = new Set(FAKE_ROWS.map((r) => r["dob"]));
    expect(rows.every((r) => !originals.has(r["dob"]))).toBe(true);
  });

  it("applies the row filter and the limit", async () => {
    const rows = await rowsFrom(invoke, "patients");
    expect(rows.every((r) => r["region"] === "us-east")).toBe(true);
    expect(rows).toHaveLength(2);
  });

  it("raises on a denied table rather than returning data", async () => {
    // A denial must be distinguishable from an empty result: an agent that cannot tell "no rows
    // matched" from "you may not read this" will retry forever, and an audit trail that
    // conflates them cannot answer what was refused.
    await expect(async () => rowsFrom(invoke, "encounters")).rejects.toThrow();
  });
});

describe("enforcement-mode example", () => {
  // An example nothing runs will drift; one that mis-wires enforcement teaches people to
  // bypass it. This exercises the example's own functions and asserts the property it claims
  // -- that the two modes agree -- so a regression in either path fails here rather than in a
  // reader's terminal.

  it("returns identical rows in both modes", async () => {
    const mode = await import("./enforcement-mode-example.js");
    const { SqlEnforcementMode } = await import("@aws/tolap-core");
    const policy = mode.buildPolicy();

    const rewritten = mode.run(policy, SqlEnforcementMode.RewriteAndPost);
    const postOnly = mode.run(policy, SqlEnforcementMode.PostOnly);

    expect(postOnly.final).toEqual(rewritten.final);

    // And the modes really did ask the database for different things -- otherwise the equality
    // above would hold trivially.
    expect(rewritten.prep.rewritten).toBe(true);
    expect(postOnly.prep.rewritten).toBe(false);
    expect(postOnly.prep.query).toBe(mode.QUERY);
    expect(rewritten.fromDatabase.length).toBeLessThan(postOnly.fromDatabase.length);
  });

  it("matches the Python example's enforced result", async () => {
    // The two languages state the same expectation on purpose. A per-language expectation
    // would let one SDK quietly return something else, because nothing would compare them.
    const mode = await import("./enforcement-mode-example.js");
    const { SqlEnforcementMode } = await import("@aws/tolap-core");

    const { final } = mode.run(mode.buildPolicy(), SqlEnforcementMode.RewriteAndPost);

    expect(final).toEqual([
      { id: 1, name: "Alice Nguyen", region: "us-east", dob: "[REDACTED]" },
    ]);
  });

  it("hides ssn and redacts dob in both modes", async () => {
    const mode = await import("./enforcement-mode-example.js");
    const { SqlEnforcementMode } = await import("@aws/tolap-core");
    const policy = mode.buildPolicy();

    for (const m of [SqlEnforcementMode.RewriteAndPost, SqlEnforcementMode.PostOnly]) {
      const { final, fromDatabase } = mode.run(policy, m);
      // The fake database really did return ssn, so its absence is enforcement rather than a
      // fixture that never had it.
      expect(fromDatabase.some((r) => "ssn" in r)).toBe(true);
      expect(final.every((r) => !("ssn" in r))).toBe(true);
      expect(final.every((r) => r["dob"] === "[REDACTED]")).toBe(true);
    }
  });
});

/**
 * The lines the purpose-binding example must print, byte for byte.
 *
 * Written out in full rather than matched loosely, and repeated verbatim in the Python and .NET
 * suites, for the same reason `EXPECTED` above is: the three SDKs must agree, so a divergence has
 * to surface as a *different line* rather than hiding behind three separately written substring
 * matches. Each one is an outcome — which policy resolved, which action was refused, the reason
 * string — not evidence that the script ran.
 */
const PURPOSE_EXPECTED_LINES = [
  // §15.1 — resolution filtering. Deny-all without a purpose, the scoped policy with one.
  "  (no purpose)                      DENY      deny-all: 0 policies resolved, canQuery=false",
  "  'campaign-x-overlap'              ALLOW     campaign-x-overlap-agent (maxResults=10000)",
  "  'fraud-detection'                 ALLOW     fraud-detection-agent (maxResults=500)",
  "  'Campaign-X-Overlap'              DENY      deny-all: 0 policies resolved, canQuery=false",
  "  (no purpose)                      ALLOW     marketing-baseline (maxResults=2000)",
  // §15.3 — the chain narrows, and the sharp mid-segment case.
  "  three narrowing hops              ALLOW",
  "  + a fourth, wider hop             DENY      delegation hop 3 purpose 'campaign-y-export' is not within parent scope 'campaign-x-overlap'",
  "  campaign-x -> campaign-x-overlap  ALLOW     extends on a '-' segment boundary",
  "  campaign-x -> campaign-xyz-evil   DENY      delegation hop 1 purpose 'campaign-xyz-evil' is not within parent scope 'campaign-x'",
  "  [read, aggregate] -> [read]       ALLOW     a subset of the parent",
  "  [read] -> [read, write]           DENY      delegation hop 1 scopes exceed parent delegation",
  // §15.2 — the three action outcomes, plus the permitted one.
  "  segment_overlap                   ALLOW     category 'aggregate_overlap' is allowed",
  "  export_customers                  DENY      action 'export_pii' is prohibited under purpose 'campaign-x-overlap'",
  "  inspect_account                   DENY      action 'inspect_account' not in allowed actions for purpose 'campaign-x-overlap'",
  "  join_external                     DENY      action category not declared for tool",
  // §15.4 — the disposition mapping.
  "  aligned, confidence 0.95          allow     the deterministic allowance stands",
  "  misaligned, confidence 0.95       block     the allowance is withdrawn",
  "  aligned, confidence 0.70          escalate  a DENIAL unless a review handler is wired",
  // The purpose and the chain are inside the signature.
  "  as signed                         VALID     purpose 'campaign-x-overlap', 3 hops",
  "  declared purpose swapped          BROKEN    to 'fraud-detection'",
  "  last hop repurposed               BROKEN    to 'campaign-y-export'",
  "  a fourth hop appended             BROKEN    agent-exfil, 'campaign-y-export'",
  "  hops reordered                    BROKEN    hop 0 is the delegator; reversing inverts it",
];

describe("purpose-binding example", () => {
  // Every assertion below is an *outcome*: which policy resolved, which action was allowed or
  // refused, the verbatim reason string. An example that printed plausible-looking verdicts while
  // enforcing nothing would teach a wiring pattern nobody has checked.

  it("resolves deny-all when no purpose is declared and every candidate is purpose-scoped", async () => {
    // The control with teeth. A purpose-scoped policy is not a default grant.
    const ex = await import("./purpose-binding-example.js");

    const policy = await ex.resolveFor([ex.campaignDefinition(), ex.fraudDefinition()], undefined);

    expect(policy.sourceProfiles).toEqual([]);
    expect(policy.permissions.canQuery).toBe(false);
    expect(policy.purposeProfile).toBeUndefined();
  });

  it("resolves only the matching policy when the purpose is declared", async () => {
    const ex = await import("./purpose-binding-example.js");

    const policy = await ex.resolveFor(
      [ex.campaignDefinition(), ex.fraudDefinition()],
      ex.CAMPAIGN_PURPOSE,
    );

    // The other purpose's rules were never merged — which is why the filter runs before the merge
    // rather than after it.
    expect(policy.sourceProfiles).toEqual(["campaign-x-overlap-agent"]);
    expect(policy.purposeProfile?.purposeId).toBe("campaign-x-overlap");
    expect(policy.limits?.maxResults).toBe(10000);
    expect(policy.objectRules?.allowedObjects).not.toContain("flagged_accounts");
  });

  it("compares the purpose case-sensitively", async () => {
    const ex = await import("./purpose-binding-example.js");

    const policy = await ex.resolveFor(
      [ex.campaignDefinition(), ex.fraudDefinition()],
      "Campaign-X-Overlap",
    );

    expect(policy.sourceProfiles).toEqual([]);
    expect(policy.permissions.canQuery).toBe(false);
  });

  it("CONTROL: a purpose-agnostic policy still resolves without a purpose", async () => {
    // Purpose binding is additive, so every pre-purpose policy is untouched.
    const ex = await import("./purpose-binding-example.js");

    const policy = await ex.resolveFor(
      [ex.campaignDefinition(), ex.fraudDefinition(), ex.baselineDefinition()],
      undefined,
    );

    expect(policy.sourceProfiles).toEqual(["marketing-baseline"]);
    expect(policy.permissions.canQuery).toBe(true);
    expect(policy.purposeProfile).toBeUndefined();
  });

  it("allows a narrowing chain and refuses a widening fourth hop", async () => {
    const ex = await import("./purpose-binding-example.js");
    const { validateDelegationChain } = await import("@aws/tolap-core");

    const chain = ex.narrowingChain();
    expect(validateDelegationChain(chain).allowed).toBe(true);

    const widened = validateDelegationChain([...chain, ex.wideningHop()]);
    expect(widened.allowed).toBe(false);
    expect(widened.reason).toBe(
      "delegation hop 3 purpose 'campaign-y-export' is not within parent scope 'campaign-x-overlap'",
    );
  });

  it("narrows on a segment boundary but not mid-segment", async () => {
    // The case a plain `startsWith` gets wrong, which is why it is in the example.
    const ex = await import("./purpose-binding-example.js");
    const { validateDelegationChain } = await import("@aws/tolap-core");

    expect(validateDelegationChain(ex.twoHop("campaign-x", "campaign-x-overlap")).allowed).toBe(
      true,
    );

    const evil = validateDelegationChain(ex.twoHop("campaign-x", "campaign-xyz-evil"));
    expect(evil.allowed).toBe(false);
    expect(evil.reason).toBe(
      "delegation hop 1 purpose 'campaign-xyz-evil' is not within parent scope 'campaign-x'",
    );
  });

  it("lets scopes narrow but not widen", async () => {
    const ex = await import("./purpose-binding-example.js");
    const { validateDelegationChain } = await import("@aws/tolap-core");

    expect(validateDelegationChain(ex.scopeHops(["read", "aggregate"], ["read"])).allowed).toBe(
      true,
    );

    const widened = validateDelegationChain(ex.scopeHops(["read"], ["read", "write"]));
    expect(widened.allowed).toBe(false);
    expect(widened.reason).toBe("delegation hop 1 scopes exceed parent delegation");
  });

  it.each([
    ["segment_overlap", undefined],
    [
      "export_customers",
      "action 'export_pii' is prohibited under purpose 'campaign-x-overlap'",
    ],
    [
      "inspect_account",
      "action 'inspect_account' not in allowed actions for purpose 'campaign-x-overlap'",
    ],
    ["join_external", "action category not declared for tool"],
  ])("the action-category map decides for %s", async (toolName, expectedReason) => {
    // A permitted category passes; a prohibited one, an unlisted one and an *unmapped* one each
    // fail, with their own reason. The map is deployment configuration on the wrapper, never a
    // caller argument — so this goes through the wrapper's own pre-execute.
    const ex = await import("./purpose-binding-example.js");
    const { SecureContextToolWrapper } = await import("@aws/tolap-mcp");

    const wrapper = new SecureContextToolWrapper({
      signingKey: ex.SIGNING_KEY,
      toolActionCategories: ex.TOOL_ACTION_CATEGORIES,
    });

    const result = wrapper.preExecute(await ex.signedContext(), { toolName: toolName as string });

    expect(result.allowed).toBe(expectedReason === undefined);
    expect(result.reason).toBe(expectedReason);
  });

  it.each([
    [true, 0.95, "allow"],
    [false, 0.95, "block"],
    [true, 0.7, "escalate"],
  ])("maps aligned=%s confidence=%s to %s", async (aligned, confidence, expected) => {
    const ex = await import("./purpose-binding-example.js");
    const { evaluateJudge } = await import("@aws/tolap-core");

    const outcome = await evaluateJudge(
      await ex.judgedPolicy(),
      new ex.StubJudge({
        aligned: aligned as boolean,
        confidence: confidence as number,
        reasoning: "stub",
      }),
      "segment_overlap(campaign_x)",
    );

    expect(outcome.disposition).toBe(expected);
    // escalate is NOT an allow. A wrapper with no review handler denies.
    expect(outcome.allowed).toBe(expected === "allow");
  });

  it("breaks the signature when the purpose or the chain is mutated", async () => {
    // Without this, the chain validation above would check the attacker's own arithmetic.
    const ex = await import("./purpose-binding-example.js");
    const { validateContext } = await import("@aws/tolap-core");

    const original = await ex.signedContext();
    expect(validateContext(original, ex.SIGNING_KEY)).toBe(true);
    expect(original.declaredPurpose).toBe("campaign-x-overlap");
    expect(original.delegationChain).toHaveLength(3);

    const repurposed = await ex.signedContext();
    repurposed.declaredPurpose = ex.FRAUD_PURPOSE;
    expect(validateContext(repurposed, ex.SIGNING_KEY)).toBe(false);

    const rechained = await ex.signedContext();
    rechained.delegationChain![2]!.declaredPurpose = "campaign-y-export";
    expect(validateContext(rechained, ex.SIGNING_KEY)).toBe(false);

    const appended = await ex.signedContext();
    appended.delegationChain!.push(ex.wideningHop());
    expect(validateContext(appended, ex.SIGNING_KEY)).toBe(false);

    // Reordering included: hop 0 is the delegator, so reversing a chain makes the sub-agent the
    // root.
    const reordered = await ex.signedContext();
    reordered.delegationChain!.reverse();
    expect(validateContext(reordered, ex.SIGNING_KEY)).toBe(false);
  });

  it("prints every expected line", async () => {
    // The example itself throws if a mutated context still verifies, so this covers that path.
    // Nothing runs this file standalone in CI — the TypeScript job typechecks and tests — so the
    // run has to happen here or the script would only ever be compiled, never executed.
    const ex = await import("./purpose-binding-example.js");

    const lines: string[] = [];
    const original = console.log;
    console.log = (...args: unknown[]) => {
      lines.push(args.map(String).join(" "));
    };
    try {
      await ex.main();
    } finally {
      console.log = original;
    }

    for (const expected of PURPOSE_EXPECTED_LINES) {
      expect(lines, `missing line: ${expected}`).toContain(expected);
    }
  });
});
