/**
 * Enforcement of minSimilarityScore and maxObjectSizeBytes
 * (docs/canonical-enforcement-spec.md §4, steps 3 and 4).
 *
 * Both limits were parsed, validated, and merged most-restrictively -- and then
 * never applied to any result. The merge and round-trip paths *were* tested, so
 * branch coverage reached ~100% while neither control did anything: coverage
 * measures whether written code runs, never whether required code was written.
 *
 * `minSimilarityScore` is documented as a confidentiality control ("similarity
 * score thresholds prevent low-relevance results from surfacing sensitive
 * content"), so these tests assert it fails closed rather than filtering only
 * when a score happens to be present.
 */

import { describe, it, expect } from "vitest";
import {
  applyObjectSizeCeiling,
  applyResultPipeline,
  applySimilarityFloor,
} from "../src/enforcement.js";
import type { EffectivePolicy } from "../src/types.js";

function policy(limits: Record<string, unknown>): EffectivePolicy {
  return {
    version: "1.0",
    sourceProfiles: ["p"],
    permissions: { canQuery: true, canExport: false, readOnly: true },
    limits,
  } as unknown as EffectivePolicy;
}

const ids = (records: unknown[]): unknown[] =>
  (records as Array<Record<string, unknown>>).map((r) => r["id"]);

describe("similarity floor (spec §4 step 3)", () => {
  it("drops records scoring below the floor", () => {
    const kept = applySimilarityFloor(
      [
        { id: "high", score: 0.95 },
        { id: "low", score: 0.1 },
      ],
      policy({ minSimilarityScore: 0.9 }),
    );

    expect(ids(kept)).toEqual(["high"]);
  });

  it("keeps a score exactly at the floor", () => {
    const kept = applySimilarityFloor(
      [{ id: "exact", score: 0.9 }],
      policy({ minSimilarityScore: 0.9 }),
    );

    expect(ids(kept)).toEqual(["exact"]);
  });

  it("drops an unscored record", () => {
    // Fail closed: relevance that cannot be established cannot satisfy a floor.
    const kept = applySimilarityFloor(
      [{ id: "no-score-field" }],
      policy({ minSimilarityScore: 0.5 }),
    );

    expect(kept).toEqual([]);
  });

  it.each([
    ["a non-numeric string", "not-a-number"],
    ["an empty string", ""],
    ["null", null],
    ["undefined", undefined],
    // `Number(true)` is 1, so a boolean must be rejected by type rather than coerced.
    ["a boolean", true],
    ["NaN", Number.NaN],
    ["Infinity", Number.POSITIVE_INFINITY],
  ])("drops a record whose score is %s", (_label, score) => {
    const kept = applySimilarityFloor(
      [{ id: "bad", score }],
      policy({ minSimilarityScore: 0.5 }),
    );

    expect(kept).toEqual([]);
  });

  it("honours a numeric string score", () => {
    const kept = applySimilarityFloor(
      [
        { id: "pass", score: "0.75" },
        { id: "fail", score: "0.25" },
      ],
      policy({ minSimilarityScore: 0.5 }),
    );

    expect(ids(kept)).toEqual(["pass"]);
  });

  it.each(["similarity", "similarityScore", "_score", "SCORE"])(
    "recognizes the alternate score field %s",
    (key) => {
      const kept = applySimilarityFloor(
        [{ id: "a", [key]: 0.9 }],
        policy({ minSimilarityScore: 0.5 }),
      );

      expect(ids(kept)).toEqual(["a"]);
    },
  );

  it("is a passthrough when no floor is configured", () => {
    const records = [{ id: "a" }, { id: "b", score: 0.01 }];

    expect(applySimilarityFloor(records, policy({}))).toBe(records);
  });
});

describe("object size ceiling (spec §4 step 4)", () => {
  it("drops records above the ceiling", () => {
    const kept = applyObjectSizeCeiling(
      [
        { id: "small", size: 500 },
        { id: "huge", size: 999_999_999 },
      ],
      policy({ maxObjectSizeBytes: 1024 }),
    );

    expect(ids(kept)).toEqual(["small"]);
  });

  it("keeps a size exactly at the ceiling", () => {
    const kept = applyObjectSizeCeiling(
      [{ id: "exact", size: 1024 }],
      policy({ maxObjectSizeBytes: 1024 }),
    );

    expect(ids(kept)).toEqual(["exact"]);
  });

  it("drops an unsized record", () => {
    const kept = applyObjectSizeCeiling(
      [{ id: "no-size-field" }],
      policy({ maxObjectSizeBytes: 1024 }),
    );

    expect(kept).toEqual([]);
  });

  it("drops a non-numeric size", () => {
    const kept = applyObjectSizeCeiling(
      [{ id: "a", size: "big" }],
      policy({ maxObjectSizeBytes: 1024 }),
    );

    expect(kept).toEqual([]);
  });

  it.each(["sizeBytes", "contentLength", "objectSize", "SIZE"])(
    "recognizes the alternate size field %s",
    (key) => {
      const kept = applyObjectSizeCeiling(
        [{ id: "a", [key]: 10 }],
        policy({ maxObjectSizeBytes: 1024 }),
      );

      expect(ids(kept)).toEqual(["a"]);
    },
  );

  it("is a passthrough when no ceiling is configured", () => {
    const records = [{ id: "a" }, { id: "b", size: 10 ** 12 }];

    expect(applyObjectSizeCeiling(records, policy({}))).toBe(records);
  });
});

describe("pipeline integration", () => {
  it("applies both limits, matching Python and .NET", () => {
    // The identical input and expectation are asserted in the Python and .NET
    // suites. Divergence here means one SDK enforces a policy the others do not.
    const out = applyResultPipeline(
      [
        { id: "ok", score: 0.9, size: 100 },
        { id: "low", score: 0.1, size: 100 },
        { id: "big", score: 0.9, size: 99_999 },
        { id: "noscore", size: 100 },
        { id: "exact", score: 0.5, size: 1000 },
        { id: "boolscore", score: true, size: 10 },
      ],
      policy({ minSimilarityScore: 0.5, maxObjectSizeBytes: 1000 }),
    );

    expect(ids(out as unknown[])).toEqual(["ok", "exact"]);
  });

  it("drops a single record that fails the floor, rather than returning an empty record", () => {
    const out = applyResultPipeline(
      { id: "low", score: 0.1 },
      policy({ minSimilarityScore: 0.9 }),
    );

    // `null`, not `undefined` and not `{}`: an empty record would imply the row
    // existed but had no fields. Python returns None and .NET returns null, so the
    // three SDKs agree on the denial value (spec §4, "Single records").
    expect(out).toBeNull();
  });

  it("drops records before masking them", () => {
    // Spec §4 ordering: no work is spent masking a record about to be discarded.
    const withMask = {
      version: "1.0",
      sourceProfiles: ["p"],
      permissions: { canQuery: true, canExport: false, readOnly: true },
      objectRules: {
        fieldRules: { maskedFields: [{ field: "secret", maskType: "redact" }] },
      },
      limits: { minSimilarityScore: 0.5 },
    } as unknown as EffectivePolicy;

    const out = applyResultPipeline(
      [
        { id: "keep", score: 0.9, secret: "s1" },
        { id: "drop", score: 0.1, secret: "s2" },
      ],
      withMask,
    ) as Array<Record<string, unknown>>;

    expect(out).toHaveLength(1);
    expect(out[0]["id"]).toBe("keep");
    expect(out[0]["secret"]).toBe("[REDACTED]");
  });

  it("applies the limits before maxResults", () => {
    // maxResults must count only records that survived the floor: had the limit run
    // first, "a" would consume a slot and only "b" would remain.
    const out = applyResultPipeline(
      [
        { id: "a", score: 0.1 },
        { id: "b", score: 0.9 },
        { id: "c", score: 0.9 },
      ],
      policy({ minSimilarityScore: 0.5, maxResults: 2 }),
    );

    expect(ids(out as unknown[])).toEqual(["b", "c"]);
  });
});
