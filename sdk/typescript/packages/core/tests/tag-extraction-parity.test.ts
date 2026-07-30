/**
 * Cross-SDK parity for tag extraction (connector spec §7).
 *
 * One record corpus, one policy set, one outcome table, asserted with identical
 * expected outcomes in all three SDKs. The counterparts are:
 *
 *   - Python: `sdk/python/tests/test_tag_extraction_parity.py`
 *   - .NET: `tests/Tolap.Core.Tests/TagExtractionParityTests.cs`
 *
 * Tag filtering is the whole knowledge-base confidentiality control: a
 * classification level **is** a tag and there is no separate classification
 * construct, so a gap here is a disclosure rather than a cosmetic difference. The
 * corpus is the set of shapes real providers emit -- a lower-case `tags` array, a
 * differently-cased key, tags nested in a metadata object, an alternate key name, a
 * scalar instead of an array, and a tag key inside an array of chunks -- because a
 * literal lower-case `tags` lookup found exactly one of them and disclosed the
 * other four.
 *
 * Each shape is run against five policies rather than one, so the two halves of the
 * control are separable: a denylist must *drop* the carrier and an allow-list must
 * *not admit* it, and an SDK that extracts a tag for one purpose but not the other
 * fails a specific cell rather than passing on average.
 *
 * The corpus also pins the boundaries the fix must not move: `categories` is
 * outside the recognized key set and is therefore ordinary data (an over-broad set
 * fails open, because an unrelated field whose value appears in `allowedTags` would
 * admit a record the allow-list would otherwise have dropped), a non-string tag
 * value contributes no tag, and an untagged record is dropped under an allow-list
 * but kept under a denylist alone.
 */

import { describe, expect, it } from "vitest";
import { filterByTags } from "../src/enforcement.js";
import type { EffectivePolicy, TagRules } from "../src/types.js";

/**
 * The shared record corpus, keyed by case id. Identical field-for-field in all
 * three SDKs.
 */
const PARITY_RECORDS: Record<string, Record<string, unknown>> = {
  // The five shapes measured as leaking: only "tags-list" was enforced.
  "tags-list": { tags: ["secret"] },
  "cased-key": { Tags: ["secret"] },
  "nested-metadata": { metadata: { tags: ["secret"] } },
  "labels-key": { labels: ["secret"] },
  "scalar-classification": { classification: "secret" },
  // Further provider shapes and case variants.
  "scalar-tags": { tags: "secret" },
  "upper-value": { tags: ["SECRET"] },
  "cased-key-and-value": { CLASSIFICATION: "Secret" },
  "nested-labels": { metadata: { labels: ["secret"] } },
  "in-array": { chunks: [{ tags: ["secret"] }] },
  // Boundaries the fix must not move.
  "public-tag": { tags: ["public"] },
  untagged: { note: "no tags at all" },
  "empty-tags": { tags: [] },
  "non-string-tags": { tags: 42 },
  "unrecognized-key": { categories: ["secret"] },
};

/** The shared policy set, keyed by policy id. Identical in all three SDKs. */
const PARITY_TAG_RULES: Record<string, TagRules> = {
  "deny-secret": { deniedTags: ["secret"] },
  "deny-Secret-cased": { deniedTags: ["Secret"] },
  "allow-public": { allowedTags: ["public"] },
  "allow-secret": { allowedTags: ["secret"] },
  "allow-public-deny-secret": { allowedTags: ["public"], deniedTags: ["secret"] },
};

/** Every shape carrying "secret" behaves the same way under every policy. */
const SECRET_CARRIERS = [
  "tags-list",
  "cased-key",
  "nested-metadata",
  "labels-key",
  "scalar-classification",
  "scalar-tags",
  "upper-value",
  "cased-key-and-value",
  "nested-labels",
  "in-array",
];

/**
 * The shapes with no recognizable tags. No tags means dropped under an allow-list,
 * kept under a denylist (canonical spec §4).
 */
const UNTAGGED_EQUIVALENTS = [
  "untagged",
  "empty-tags",
  "non-string-tags",
  "unrecognized-key",
];

/**
 * [record id, policy id, kept] -- the canonical table. `true` means the record
 * survives the filter; `false` means it is dropped.
 */
const PARITY_TABLE: Array<[string, string, boolean]> = [
  ...SECRET_CARRIERS.flatMap(
    (recordId): Array<[string, string, boolean]> => [
      [recordId, "deny-secret", false],
      [recordId, "deny-Secret-cased", false],
      [recordId, "allow-public", false],
      [recordId, "allow-secret", true],
      [recordId, "allow-public-deny-secret", false],
    ],
  ),
  // A record carrying only an allowed tag.
  ["public-tag", "deny-secret", true],
  ["public-tag", "deny-Secret-cased", true],
  ["public-tag", "allow-public", true],
  ["public-tag", "allow-secret", false],
  ["public-tag", "allow-public-deny-secret", true],
  ...UNTAGGED_EQUIVALENTS.flatMap(
    (recordId): Array<[string, string, boolean]> => [
      [recordId, "deny-secret", true],
      [recordId, "deny-Secret-cased", true],
      [recordId, "allow-public", false],
      [recordId, "allow-secret", false],
      [recordId, "allow-public-deny-secret", false],
    ],
  ),
];

function parityPolicy(tagRules: TagRules): EffectivePolicy {
  return {
    version: "1.0",
    userId: "parity-user",
    tenantId: "parity-tenant",
    sourceConnectionId: "kb:internal:parity",
    resolvedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    sourceProfiles: ["tag-extraction-parity"],
    permissions: { canQuery: true, readOnly: true },
    objectRules: { tagRules },
    integrity: { algorithm: "none", signature: "" },
  };
}

describe("tag extraction: cross-SDK parity table", () => {
  for (const [recordId, policyId, kept] of PARITY_TABLE) {
    it(`${recordId} under ${policyId} -> ${kept ? "kept" : "dropped"}`, () => {
      const record = PARITY_RECORDS[recordId]!;

      const filtered = filterByTags([record], parityPolicy(PARITY_TAG_RULES[policyId]!));

      expect(filtered).toEqual(kept ? [record] : []);
    });
  }

  it("the corpus and table stay in step", () => {
    // A shape silently dropped from the table would look like a passing parity run
    // while enforcing nothing, which is the failure mode this file exists to catch.
    const covered = new Set(
      PARITY_TABLE.map(([recordId, policyId]) => `${recordId}|${policyId}`),
    );
    const expected = new Set(
      Object.keys(PARITY_RECORDS).flatMap((recordId) =>
        Object.keys(PARITY_TAG_RULES).map((policyId) => `${recordId}|${policyId}`),
      ),
    );

    expect([...covered].sort()).toEqual([...expected].sort());
  });
});
