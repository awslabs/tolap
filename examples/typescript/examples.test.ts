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
