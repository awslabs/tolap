/**
 * Cross-SDK conformance for how a row filter finds its field on a row (issue #32).
 *
 * Driven by `fixtures/enforcement/row-filter-qualified-lookup.json`. The
 * counterparts read the same file, case for case:
 *
 * - Python: `tests/test_row_filter_qualified_lookup.py`
 * - .NET: `tests/Tolap.Core.Tests/RowFilterQualifiedLookupTests.cs`
 *
 * The lookup used to fall back to the field-name matcher. That matcher drops
 * qualifiers, so a filter on `patients.region` read `encounters.region` when the
 * row had no `patients` column, and a bare filter matching several qualified keys
 * used whichever key came first. The expectations live only in the fixture, as
 * they do for the operator corpus, so the three SDKs cannot drift apart.
 *
 * Each case carries its own records because key order is part of what is being
 * tested. `JSON.parse` keeps the order the fixture writes for non-integer keys,
 * which every key in this fixture is.
 */

import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { applyRowFilters } from "../src/enforcement.js";
import type { EffectivePolicy, RowFilter } from "../src/types.js";

const FIXTURE_PATH = path.resolve(
  __dirname,
  "../../../../../fixtures/enforcement/row-filter-qualified-lookup.json",
);

/** Asserted so that a dropped case fails the suite rather than shrinking it quietly. */
const EXPECTED_CASE_COUNT = 23;

interface LookupCase {
  name: string;
  notes?: string;
  records: Array<Record<string, unknown>>;
  expected: string[];
  policy: Partial<EffectivePolicy>;
}

const CASES = (
  JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf-8")) as { cases: LookupCase[] }
).cases;

function caseFilters(testCase: LookupCase): RowFilter[] {
  return (testCase.policy.objectRules?.rowFilters ?? []) as RowFilter[];
}

/** Fill the envelope fields a fixture policy omits, as the operator corpus does. */
function toEffectivePolicy(partial: Partial<EffectivePolicy>): EffectivePolicy {
  return {
    version: "1.0",
    userId: "corpus-user",
    tenantId: "corpus-tenant",
    sourceConnectionId: "db:corpus:qualified-lookup",
    resolvedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    sourceProfiles: ["row-filter-qualified-lookup"],
    integrity: { algorithm: "none", signature: "" },
    ...partial,
  } as EffectivePolicy;
}

function survivingIds(testCase: LookupCase): unknown[] {
  return applyRowFilters(testCase.records, toEffectivePolicy(testCase.policy)).map(
    (row) => row["id"],
  );
}

describe("the qualified-lookup corpus is intact", () => {
  it(`carries ${EXPECTED_CASE_COUNT} cases`, () => {
    expect(CASES).toHaveLength(EXPECTED_CASE_COUNT);
  });

  it("has a unique name per case", () => {
    const names = CASES.map((c) => c.name);

    expect(new Set(names).size).toBe(names.length);
  });

  it("gives every case records and a policy carrying row filters", () => {
    for (const testCase of CASES) {
      expect(testCase.records.length, testCase.name).toBeGreaterThan(0);
      expect(caseFilters(testCase).length, testCase.name).toBeGreaterThan(0);
    }
  });
});

describe("applyRowFilters matches the qualified-lookup corpus", () => {
  it.each(CASES.map((c) => [c.name, c] as const))("%s", (_name, testCase) => {
    expect(survivingIds(testCase)).toEqual(testCase.expected);
  });
});
