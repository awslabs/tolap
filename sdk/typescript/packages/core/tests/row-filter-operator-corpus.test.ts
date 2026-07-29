/**
 * Cross-SDK conformance for all 16 row-filter operators, from the shared corpus.
 *
 * Driven by `fixtures/enforcement/apply-row-filters-all-operators.json`. The
 * counterparts read the same file, case for case:
 *
 *   - Python: `sdk/python/tests/test_row_filter_operator_corpus.py`
 *   - .NET: `tests/Tolap.Core.Tests/RowFilterOperatorCorpusTests.cs`
 *
 * `row-filter-operators.test.ts` already pins each operator's semantics *in this
 * SDK*. That is not the same guarantee: a per-SDK unit test asserts whatever that
 * SDK happens to implement, so three suites can all pass while three
 * implementations disagree. The corpus previously covered 9 of the schema's 16
 * operators, and the seven it left out -- `between`, `greaterThanOrEqual`,
 * `lessThanOrEqual`, `isNull`, `isNotNull`, `like`, `notLike` -- are exactly the
 * ones that diverged: a schema-valid `{"operator":"between"}` policy crashed Python
 * with a `KeyError`, silently dropped every row here, and enforced correctly in
 * .NET, while the signature verified in all three. Nothing forced agreement because
 * nothing compared them.
 *
 * So the expectations live in the fixture and only in the fixture. Restating them
 * here would create a second copy free to drift the same way the first one did,
 * which is the whole failure mode being closed.
 *
 * Two properties this file deliberately does NOT soften:
 *
 *   - **No skips.** A missing fixture throws while the module loads, and an operator
 *     string with no {@link FilterOperator} member fails its own assertion. An
 *     operator this SDK cannot express IS the divergence, not a reason to stand
 *     down. This matters more here than in the other two SDKs: `RowFilter.operator`
 *     is typed `FilterOperator | string`, so an unrecognized operator is not a type
 *     error and would otherwise reach `rowPassesFilter`'s default arm and silently
 *     drop every row -- indistinguishable from a filter that is working.
 *   - **One test per case.** A single loop reports the first mismatch and hides the
 *     rest; 21 named cases report which *operator* disagrees, which is the fact
 *     worth having.
 */

import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { applyRowFilters } from "../src/enforcement.js";
import { FilterOperator } from "../src/types.js";
import type { EffectivePolicy, RowFilter } from "../src/types.js";

const FIXTURE_PATH = path.resolve(
  __dirname,
  "../../../../../fixtures/enforcement/apply-row-filters-all-operators.json",
);

/**
 * The number of cases the corpus is expected to carry. Asserted below so a future
 * edit that silently drops a case cannot look like a shrinking-but-passing suite.
 */
const EXPECTED_CASE_COUNT = 21;

interface CorpusCase {
  name: string;
  expected: string[];
  notes?: string;
  /** A complete policy, so the shared corpus walk can schema-validate the case. */
  policy: Partial<EffectivePolicy>;
}

interface Corpus {
  records: Array<Record<string, unknown>>;
  cases: CorpusCase[];
}

/**
 * Read the corpus, failing the whole file if it is absent.
 *
 * `readFileSync` throwing at module load is the intended behaviour: a fixture that
 * cannot be found must not degrade into a suite that quietly asserts nothing.
 */
function loadCorpus(): Corpus {
  return JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf-8")) as Corpus;
}

const corpus = loadCorpus();
const RECORDS = corpus.records;
const CASES = corpus.cases;

/** The raw filter objects a case's policy carries, as written in the fixture. */
function caseFilters(testCase: CorpusCase): RowFilter[] {
  return (testCase.policy.objectRules?.rowFilters ?? []) as RowFilter[];
}

/**
 * Complete a fixture policy into an `EffectivePolicy`.
 *
 * The fixture carries the fields that bear on the decision -- `version`,
 * `permissions`, `objectRules` -- and the envelope fields are filled in here.
 * Nothing under `objectRules` is touched, so the filters reaching the engine are
 * verbatim the schema-valid ones the corpus declares.
 */
function toEffectivePolicy(partial: Partial<EffectivePolicy>): EffectivePolicy {
  return {
    version: "1.0",
    userId: "corpus-user",
    tenantId: "corpus-tenant",
    sourceConnectionId: "db:corpus:operators",
    resolvedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    sourceProfiles: ["row-filter-operator-corpus"],
    integrity: { algorithm: "none", signature: "" },
    ...partial,
  } as EffectivePolicy;
}

/** Run a case's policy over the shared records and return the surviving ids. */
function survivingIds(testCase: CorpusCase): unknown[] {
  const kept = applyRowFilters(RECORDS, toEffectivePolicy(testCase.policy));
  return kept.map((row) => row["id"]);
}

// ---------------------------------------------------------------------------
// Guards on the corpus itself, before any operator is evaluated
// ---------------------------------------------------------------------------

describe("the shared row-filter corpus is intact", () => {
  it(`carries ${EXPECTED_CASE_COUNT} cases`, () => {
    expect(CASES).toHaveLength(EXPECTED_CASE_COUNT);
  });

  it("carries the expected shared records", () => {
    expect(RECORDS.map((row) => row["id"])).toEqual([
      "low",
      "mid",
      "high",
      "nullish",
      "missing",
    ]);
  });

  it("has a unique name per case", () => {
    // Duplicated names would let one case mask another in the report.
    const names = CASES.map((c) => c.name);

    expect(new Set(names).size).toBe(names.length);
  });

  it("gives every case a policy carrying row filters", () => {
    // A case that cannot be mapped is a failure, never a skip.
    for (const testCase of CASES) {
      expect(caseFilters(testCase).length, testCase.name).toBeGreaterThan(0);
    }
  });

  it("uses only operators this SDK can express", () => {
    // An operator string with no enum member IS the divergence. Asserted on its own
    // so the message names the offending value rather than surfacing as 21 identical
    // deny-everything failures below.
    const expressible = new Set<string>(Object.values(FilterOperator));
    const used = new Set<string>(
      CASES.flatMap((c) => caseFilters(c).map((f) => String(f.operator))),
    );

    expect([...used].filter((op) => !expressible.has(op))).toEqual([]);
  });

  it("exercises every operator the schema declares", () => {
    // The point of the fixture: 16 of 16, not 9 of 16.
    const used = new Set<string>(
      CASES.flatMap((c) => caseFilters(c).map((f) => String(f.operator))),
    );

    expect([...used].sort()).toEqual([...Object.values(FilterOperator)].sort());
  });
});

// ---------------------------------------------------------------------------
// One test per case, so a failure names the operator that disagreed
// ---------------------------------------------------------------------------

describe("applyRowFilters matches the shared corpus", () => {
  it.each(CASES.map((c) => [c.name, c] as const))(
    "%s",
    (_name, testCase) => {
      expect(survivingIds(testCase)).toEqual(testCase.expected);
    },
  );
});
