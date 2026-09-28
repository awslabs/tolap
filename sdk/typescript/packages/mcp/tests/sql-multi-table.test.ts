/**
 * Cross-SDK conformance: the context wrapper's SQL pre-checks validate every table
 * a query references.
 *
 * Driven by `fixtures/enforcement/sql-multi-table.json`, the corpus the core
 * `prepareSqlQuery` runner and the Python and .NET runners also read. Each case
 * runs {@link SecureContextToolWrapper.prepareSqlQuery} against a signed context
 * carrying the case's policy.
 */

import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import {
  buildSecurityContext,
  signContext,
  type EffectivePolicy,
} from "@aws/tolap-core";
import { SecureContextToolWrapper } from "../src/context-wrapper.js";

const FIXTURE_PATH = path.resolve(
  __dirname,
  "../../../../../fixtures/enforcement/sql-multi-table.json",
);

/** Asserted so that a dropped case fails the suite rather than shrinking it quietly. */
const EXPECTED_CASE_COUNT = 322;

const SIGNING_KEY = "sql-multi-table-signing-key";

interface MultiTableCase {
  name: string;
  query: string;
  objectName?: string;
  policy: Partial<EffectivePolicy>;
  expected: { allowed: boolean; reason?: string };
}

const CASES = (
  JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf-8")) as { cases: MultiTableCase[] }
).cases;

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
});

describe("SecureContextToolWrapper.prepareSqlQuery matches the multi-table SQL corpus", () => {
  const wrapper = new SecureContextToolWrapper({ signingKey: SIGNING_KEY });

  it.each(CASES.map((c) => [c.name, c] as const))("%s", (_name, testCase) => {
    const policy = toEffectivePolicy(testCase.policy);
    const context = signContext(
      buildSecurityContext(policy.userId, policy.tenantId, policy, 3_600_000),
      SIGNING_KEY,
    );
    const prep = wrapper.prepareSqlQuery(
      context,
      {
        toolName: "sql-query",
        ...(testCase.objectName !== undefined ? { objectName: testCase.objectName } : {}),
      },
      testCase.query,
    );
    const actual: Record<string, unknown> = { allowed: prep.allowed };
    if ("reason" in testCase.expected) actual["reason"] = prep.denialReason;

    expect(actual).toEqual(testCase.expected);
  });
});
