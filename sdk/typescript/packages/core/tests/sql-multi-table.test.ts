/**
 * Cross-SDK conformance: the SQL pre-checks validate every table a query references.
 *
 * Driven by `fixtures/enforcement/sql-multi-table.json`. The counterparts read the
 * same file, case for case:
 *
 * - Python: `tests/test_sql_multi_table.py`
 * - TypeScript MCP: `packages/mcp/tests/sql-multi-table.test.ts`
 * - .NET: `tests/Tolap.Core.Tests/SqlMultiTableTests.cs` and
 *   `tests/Tolap.Mcp.Tests/SqlMultiTableTests.cs`
 *
 * Each case runs {@link prepareSqlQuery}, the full pre-execution path, and pins
 * whether the query may run and, when it may not, the reason given.
 */

import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { prepareSqlQuery } from "../src/sql-rewriter.js";
import type { EffectivePolicy } from "../src/types.js";

const FIXTURE_PATH = path.resolve(
  __dirname,
  "../../../../../fixtures/enforcement/sql-multi-table.json",
);

/** Asserted so that a dropped case fails the suite rather than shrinking it quietly. */
const EXPECTED_CASE_COUNT = 322;

interface MultiTableCase {
  name: string;
  notes?: string;
  query: string;
  objectName?: string;
  policy: Partial<EffectivePolicy>;
  expected: { allowed: boolean; reason?: string };
}

const CASES = (
  JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf-8")) as { cases: MultiTableCase[] }
).cases;

/** Fill the envelope fields a fixture policy omits, as the operator corpus does. */
function toEffectivePolicy(partial: Partial<EffectivePolicy>): EffectivePolicy {
  return {
    userId: "corpus-user",
    tenantId: "corpus-tenant",
    sourceConnectionId: "db:corpus:sql-multi-table",
    resolvedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    sourceProfiles: ["sql-multi-table"],
    integrity: { algorithm: "none", signature: "" },
    ...partial,
  } as EffectivePolicy;
}

describe("the multi-table SQL corpus is intact", () => {
  it(`carries ${EXPECTED_CASE_COUNT} cases`, () => {
    expect(CASES).toHaveLength(EXPECTED_CASE_COUNT);
  });

  it("has a unique name per case", () => {
    const names = CASES.map((c) => c.name);

    expect(new Set(names).size).toBe(names.length);
  });

  it("names the reason for every refusal", () => {
    for (const c of CASES) if (!c.expected.allowed) expect(c.expected.reason, c.name).toBeDefined();
  });
});

describe("prepareSqlQuery matches the multi-table SQL corpus", () => {
  it.each(CASES.map((c) => [c.name, c] as const))("%s", (_name, testCase) => {
    const prep = prepareSqlQuery(testCase.query, toEffectivePolicy(testCase.policy), {
      ...(testCase.objectName !== undefined ? { objectName: testCase.objectName } : {}),
    });
    const actual: Record<string, unknown> = { allowed: prep.allowed };
    if ("reason" in testCase.expected) actual["reason"] = prep.denialReason;

    expect(actual).toEqual(testCase.expected);
  });
});
