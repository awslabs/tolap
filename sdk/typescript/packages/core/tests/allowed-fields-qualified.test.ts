/**
 * Cross-SDK conformance for how allowedFields treats object qualifiers (issue #36).
 *
 * Driven by `fixtures/enforcement/allowed-fields-qualified.json`. The
 * counterparts read the same file, case for case:
 *
 * - Python: `tests/test_allowed_fields_qualified.py`
 * - .NET: `tests/Tolap.Core.Tests/AllowedFieldsQualifiedTests.cs`
 *
 * allowedFields used the field-name matcher, which drops qualifiers, so an entry
 * `patients.name` also allowed `encounters.name`: the read projection kept a
 * column the policy never listed, and the write path accepted it. The
 * expectations live only in the fixture, so the three SDKs cannot drift apart.
 *
 * Each case carries its own records or payload because key order is part of
 * what is being tested. `JSON.parse` keeps the order the fixture writes for
 * non-integer keys, which every key in this fixture is.
 */

import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import {
  applyResultPipeline,
  projectAllowedFields,
  validateWrite,
} from "../src/enforcement.js";
import type { EffectivePolicy } from "../src/types.js";

const FIXTURE_PATH = path.resolve(
  __dirname,
  "../../../../../fixtures/enforcement/allowed-fields-qualified.json",
);

/** Asserted so that a dropped case fails the suite rather than shrinking it quietly. */
const EXPECTED_CASE_COUNT = 36;

const ACTIONS = ["projectAllowedFields", "applyResultPipeline", "validateWrite"];

interface AllowedCase {
  name: string;
  notes?: string;
  action: string;
  records?: Array<Record<string, unknown>>;
  operation?: string;
  objectName?: string;
  payload?: Record<string, unknown>;
  policy: Partial<EffectivePolicy>;
  expected: unknown;
}

const CASES = (
  JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf-8")) as { cases: AllowedCase[] }
).cases;

/** Fill the envelope fields a fixture policy omits, as the operator corpus does. */
function toEffectivePolicy(partial: Partial<EffectivePolicy>): EffectivePolicy {
  return {
    version: "1.0",
    userId: "corpus-user",
    tenantId: "corpus-tenant",
    sourceConnectionId: "db:corpus:allowed-fields-qualified",
    resolvedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    sourceProfiles: ["allowed-fields-qualified"],
    integrity: { algorithm: "none", signature: "" },
    ...partial,
  } as EffectivePolicy;
}

function run(testCase: AllowedCase): unknown {
  const policy = toEffectivePolicy(testCase.policy);
  switch (testCase.action) {
    case "projectAllowedFields":
      return projectAllowedFields(testCase.records, policy);
    case "applyResultPipeline":
      return applyResultPipeline(testCase.records, policy);
    default: {
      const result = validateWrite(
        testCase.operation!,
        testCase.objectName,
        testCase.payload,
        policy,
      );
      const actual: Record<string, unknown> = { allowed: result.allowed };
      if ("reason" in (testCase.expected as object)) actual["reason"] = result.reason;
      return actual;
    }
  }
}

describe("the allowed-fields qualifier corpus is intact", () => {
  it(`carries ${EXPECTED_CASE_COUNT} cases`, () => {
    expect(CASES).toHaveLength(EXPECTED_CASE_COUNT);
  });

  it("has a unique name per case", () => {
    const names = CASES.map((c) => c.name);

    expect(new Set(names).size).toBe(names.length);
  });

  it("names only known actions, and exercises every one", () => {
    for (const testCase of CASES) expect(ACTIONS, testCase.name).toContain(testCase.action);
    expect(new Set(CASES.map((c) => c.action))).toEqual(new Set(ACTIONS));
  });
});

describe("allowedFields matches the qualifier corpus", () => {
  it.each(CASES.map((c) => [c.name, c] as const))("%s", (_name, testCase) => {
    expect(run(testCase)).toStrictEqual(testCase.expected);
  });
});
