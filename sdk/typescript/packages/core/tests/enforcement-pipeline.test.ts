/**
 * Regression tests for the post-execution enforcement pipeline.
 *
 * One describe block per confirmed defect in docs/canonical-enforcement-spec.md.
 * Every test here fails against the pre-hardening implementation.
 */

import { describe, it, expect } from "vitest";
import {
  applyFieldMasking,
  applyResultPipeline,
  applyRowFilters,
  classifyResultShape,
  describeResultShape,
  filterByTags,
  projectAllowedFields,
  stripHiddenFields,
  UnenforceableResultError,
} from "../src/enforcement.js";
import {
  MASK_RESTRICTIVENESS,
  maskRestrictiveness,
  type EffectivePolicy,
  type FieldRules,
  type MaskingRule,
  type RowFilter,
  type TagRules,
} from "../src/types.js";

interface PolicyParts {
  hiddenFields?: string[];
  allowedFields?: string[];
  maskedFields?: MaskingRule[];
  rowFilters?: RowFilter[];
  tagRules?: TagRules;
  maxResults?: number;
}

function policy(parts: PolicyParts = {}): EffectivePolicy {
  const fieldRules: FieldRules = {};
  if (parts.hiddenFields !== undefined) fieldRules.hiddenFields = parts.hiddenFields;
  if (parts.allowedFields !== undefined) fieldRules.allowedFields = parts.allowedFields;
  if (parts.maskedFields !== undefined) fieldRules.maskedFields = parts.maskedFields;

  return {
    version: "1.0",
    userId: "user-001",
    tenantId: "tenant-001",
    sourceConnectionId: "ds-test",
    resolvedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    sourceProfiles: ["pipeline-test"],
    permissions: { canQuery: true, canExport: false, readOnly: true },
    objectRules: {
      ...(Object.keys(fieldRules).length > 0 ? { fieldRules } : {}),
      ...(parts.rowFilters !== undefined ? { rowFilters: parts.rowFilters } : {}),
      ...(parts.tagRules !== undefined ? { tagRules: parts.tagRules } : {}),
    },
    ...(parts.maxResults !== undefined ? { limits: { maxResults: parts.maxResults } } : {}),
    integrity: { algorithm: "none", signature: "" },
  };
}

// ---------------------------------------------------------------------------
// Defect 1: hiddenFields were never stripped from results
// ---------------------------------------------------------------------------

describe("defect 1: hiddenFields are removed from results", () => {
  it("LEAK: an undeclared column matching hiddenFields is stripped", () => {
    // The tool declared only `name` but its SELECT * returned `ssn` too. The
    // pre-execution field check never saw `ssn`, so nothing removed it.
    const result = applyResultPipeline(
      [{ id: 1, name: "John Smith", ssn: "111-22-3333" }],
      policy({ hiddenFields: ["ssn"] }),
    ) as Array<Record<string, unknown>>;

    expect(result[0]).toEqual({ id: 1, name: "John Smith" });
    expect("ssn" in result[0]).toBe(false);
  });

  it("a qualified hidden rule matches a bare key", () => {
    const result = stripHiddenFields(
      [{ id: 1, ssn: "111-22-3333" }],
      policy({ hiddenFields: ["patients.ssn"] }),
    );

    expect(result[0]).toEqual({ id: 1 });
  });

  it("a bare hidden rule matches a qualified key", () => {
    const result = stripHiddenFields(
      [{ id: 1, "patients.ssn": "111-22-3333" }],
      policy({ hiddenFields: ["ssn"] }),
    );

    expect(result[0]).toEqual({ id: 1 });
  });

  it("matching is case-insensitive", () => {
    const result = stripHiddenFields(
      [{ id: 1, SSN: "111-22-3333" }],
      policy({ hiddenFields: ["ssn"] }),
    );

    expect(result[0]).toEqual({ id: 1 });
  });

  it("hidden-field removal recurses into nested records and arrays", () => {
    const result = stripHiddenFields(
      [{ id: 1, patient: { name: "J", ssn: "x" }, notes: [{ ssn: "y", text: "t" }] }],
      policy({ hiddenFields: ["ssn"] }),
    );

    expect(result[0]).toEqual({
      id: 1,
      patient: { name: "J" },
      notes: [{ text: "t" }],
    });
  });

  it("hidden wins over masked for the same field", () => {
    // Ordering rationale (spec §4): removal precedes masking, so a field that is
    // both hidden and masked is removed rather than returned in masked form.
    const result = applyResultPipeline(
      [{ id: 1, ssn: "111-22-3333" }],
      policy({
        hiddenFields: ["ssn"],
        maskedFields: [{ field: "ssn", maskType: "hash" }],
      }),
    ) as Array<Record<string, unknown>>;

    expect(result[0]).toEqual({ id: 1 });
  });

  it("does not mutate the caller's records", () => {
    const rows = [{ id: 1, ssn: "111-22-3333" }];
    stripHiddenFields(rows, policy({ hiddenFields: ["ssn"] }));

    expect(rows[0].ssn).toBe("111-22-3333");
  });
});

// ---------------------------------------------------------------------------
// Defect 2: allowedFields were never enforced on results
// ---------------------------------------------------------------------------

describe("defect 2: results are projected to allowedFields", () => {
  it("LEAK: a column the policy never listed is dropped from the result", () => {
    const result = applyResultPipeline(
      [{ id: 1, name: "John", ssn: "111-22-3333", salary: 90_000 }],
      policy({ allowedFields: ["id", "name"] }),
    ) as Array<Record<string, unknown>>;

    expect(result[0]).toEqual({ id: 1, name: "John" });
  });

  it("a qualified allow-list matches bare keys", () => {
    const result = projectAllowedFields(
      [{ id: 1, name: "John", ssn: "x" }],
      policy({ allowedFields: ["patients.id", "patients.name"] }),
    );

    expect(result[0]).toEqual({ id: 1, name: "John" });
  });

  it("a glob allow-list is honoured", () => {
    const result = projectAllowedFields(
      [{ id: 1, name: "John", ssn: "x" }],
      policy({ allowedFields: ["patients.*"] }),
    );

    expect(result[0]).toEqual({ id: 1, name: "John", ssn: "x" });
  });

  it("an empty allow-list denies every field", () => {
    // [] is deny-all, not "unrestricted" (spec §3).
    const result = projectAllowedFields(
      [{ id: 1, name: "John" }],
      policy({ allowedFields: [] }),
    );

    expect(result[0]).toEqual({});
  });

  it("an absent allow-list is unrestricted", () => {
    const result = projectAllowedFields([{ id: 1, name: "John" }], policy({}));

    expect(result[0]).toEqual({ id: 1, name: "John" });
  });
});

// ---------------------------------------------------------------------------
// Defect 3: a single (non-array) record skipped row and tag filters
// ---------------------------------------------------------------------------

describe("defect 3: a single record runs the full pipeline", () => {
  it("LEAK: a get-by-id record carrying a denied tag is denied, not returned", () => {
    // The single-record branch previously applied masking only, so a
    // deniedTags record returned by a get-by-id tool was disclosed verbatim.
    const result = applyResultPipeline(
      { id: 1, title: "Classified Report", tags: ["classified"] },
      policy({ tagRules: { deniedTags: ["classified"] } }),
    );

    expect(result).toBeNull();
  });

  it("a single record is row-filtered", () => {
    const result = applyResultPipeline(
      { id: 1, region: "eu-west" },
      policy({
        rowFilters: [{ field: "region", operator: "equals", value: "us-east" }],
      }),
    );

    expect(result).toBeNull();
  });

  it("a single record that survives filtering is stripped and masked", () => {
    const result = applyResultPipeline(
      { id: 1, region: "us-east", ssn: "111-22-3333", email: "a@b.c" },
      policy({
        rowFilters: [{ field: "region", operator: "equals", value: "us-east" }],
        hiddenFields: ["ssn"],
        maskedFields: [{ field: "email", maskType: "redact" }],
      }),
    );

    expect(result).toEqual({ id: 1, region: "us-east", email: "[REDACTED]" });
  });

  it("a single record with an allowed tag survives", () => {
    const result = applyResultPipeline(
      { id: 1, tags: ["public"] },
      policy({ tagRules: { allowedTags: ["public"] } }),
    );

    expect(result).toEqual({ id: 1, tags: ["public"] });
  });
});

// ---------------------------------------------------------------------------
// Defect 6: unknown maskType failed open
// ---------------------------------------------------------------------------

describe("defect 6: an unknown maskType fails closed", () => {
  it("LEAK: an unrecognized mask type redacts rather than returning the raw value", () => {
    const result = applyFieldMasking(
      { ssn: "111-22-3333" },
      policy({ maskedFields: [{ field: "ssn", maskType: "tokenize-v2" }] }),
    );

    expect(result.ssn).toBe("[REDACTED]");
    expect(result.ssn).not.toBe("111-22-3333");
  });

  it("a typo'd mask type does not silently disable masking", () => {
    const result = applyFieldMasking(
      { ssn: "111-22-3333" },
      policy({ maskedFields: [{ field: "ssn", maskType: "redcat" }] }),
    );

    expect(result.ssn).toBe("[REDACTED]");
  });

  it("an unknown mask type ranks most-restrictive so a weaker known type cannot beat it", () => {
    expect(maskRestrictiveness("tokenize-v2")).toBeGreaterThan(
      maskRestrictiveness("null"),
    );
  });
});

// ---------------------------------------------------------------------------
// Defect 7: mask restrictiveness ranking was inverted
// ---------------------------------------------------------------------------

describe("defect 7: mask restrictiveness ranks by disclosure", () => {
  it("null and redact outrank partial, hash, and full", () => {
    // The previous ranking was null=1 .. full=5, so merging `ssn: null` with
    // `ssn: partial` produced `partial` -- disclosing real SSN digits that one
    // policy had demanded be erased entirely.
    expect(MASK_RESTRICTIVENESS["null"]).toBeGreaterThan(
      MASK_RESTRICTIVENESS["redact"],
    );
    expect(MASK_RESTRICTIVENESS["redact"]).toBeGreaterThan(
      MASK_RESTRICTIVENESS["full"],
    );
    expect(MASK_RESTRICTIVENESS["full"]).toBeGreaterThan(
      MASK_RESTRICTIVENESS["hash"],
    );
    expect(MASK_RESTRICTIVENESS["hash"]).toBeGreaterThan(
      MASK_RESTRICTIVENESS["partial"],
    );
  });

  it("the most restrictive matching rule wins when two rules hit one key", () => {
    const result = applyFieldMasking(
      { ssn: "111-22-3333" },
      policy({
        maskedFields: [
          { field: "ssn", maskType: "partial", parameters: { showLast: 4 } },
          { field: "ssn", maskType: "null" },
        ],
      }),
    );

    expect(result.ssn).toBeNull();
  });

  it("EXPLOIT: partial masking that would show everything degrades to a full mask", () => {
    const result = applyFieldMasking(
      { region: "us-east" },
      policy({
        maskedFields: [
          {
            field: "region",
            maskType: "partial",
            parameters: { showFirst: 100, showLast: 100 },
          },
        ],
      }),
    );

    expect(result.region).toBe("*******");
    expect(result.region).not.toBe("us-east");
  });

  it("showFirst + showLast exactly equal to the length degrades to a full mask", () => {
    const result = applyFieldMasking(
      { region: "us-east" },
      policy({
        maskedFields: [
          {
            field: "region",
            maskType: "partial",
            parameters: { showFirst: 3, showLast: 4, maskChar: "#" },
          },
        ],
      }),
    );

    expect(result.region).toBe("#######");
  });
});

// ---------------------------------------------------------------------------
// Defect 8: row-filter negative operators failed OPEN
// ---------------------------------------------------------------------------

describe("defect 8: row filters fail closed on a missing field", () => {
  it("LEAK: notEquals drops a row that is missing the referenced field", () => {
    // `undefined !== "classified"` is true, so a filter written to exclude
    // classified rows previously retained every row that lacked the column.
    const rows = [
      { id: 1, classification: "public" },
      { id: 2 }, // no classification column at all
    ];

    const kept = applyRowFilters(
      rows,
      policy({
        rowFilters: [
          { field: "classification", operator: "notEquals", value: "classified" },
        ],
      }),
    );

    expect(kept.map((r) => r.id)).toEqual([1]);
  });

  it("LEAK: notIn drops a row that is missing the referenced field", () => {
    const rows = [{ id: 1, region: "us-east" }, { id: 2 }];

    const kept = applyRowFilters(
      rows,
      policy({
        rowFilters: [
          { field: "region", operator: "notIn", values: ["eu-west"] },
        ],
      }),
    );

    expect(kept.map((r) => r.id)).toEqual([1]);
  });

  it("every operator drops a row missing the field", () => {
    const operators: RowFilter[] = [
      { field: "x", operator: "equals", value: 1 },
      { field: "x", operator: "notEquals", value: 1 },
      { field: "x", operator: "in", values: [1] },
      { field: "x", operator: "notIn", values: [1] },
      { field: "x", operator: "greaterThan", value: 1 },
      { field: "x", operator: "lessThan", value: 1 },
      { field: "x", operator: "contains", value: "1" },
      { field: "x", operator: "startsWith", value: "1" },
      { field: "x", operator: "matches", value: ".*" },
    ];

    for (const filter of operators) {
      const kept = applyRowFilters([{ id: 1 }], policy({ rowFilters: [filter] }));
      expect(kept, `operator ${filter.operator} must drop a field-less row`).toEqual([]);
    }
  });

  it("an explicitly null value is still compared, not treated as missing", () => {
    const rows = [{ id: 1, region: null }];

    const equalsNull = applyRowFilters(
      rows,
      policy({ rowFilters: [{ field: "region", operator: "equals", value: null }] }),
    );
    const notEqualsUsEast = applyRowFilters(
      rows,
      policy({
        rowFilters: [{ field: "region", operator: "notEquals", value: "us-east" }],
      }),
    );

    expect(equalsNull.map((r) => r.id)).toEqual([1]);
    expect(notEqualsUsEast.map((r) => r.id)).toEqual([1]);
  });

  it("a non-comparable value drops the row instead of throwing", () => {
    const rows = [{ id: 1, age: "notanumber" }];

    expect(
      applyRowFilters(
        rows,
        policy({ rowFilters: [{ field: "age", operator: "greaterThan", value: 30 }] }),
      ),
    ).toEqual([]);
    expect(
      applyRowFilters(
        rows,
        policy({ rowFilters: [{ field: "age", operator: "lessThan", value: 30 }] }),
      ),
    ).toEqual([]);
  });

  it("equals does not conflate booleans with numbers", () => {
    expect(
      applyRowFilters(
        [{ id: 1, flag: true }],
        policy({ rowFilters: [{ field: "flag", operator: "equals", value: 1 }] }),
      ),
    ).toEqual([]);
    expect(
      applyRowFilters(
        [{ id: 1, flag: 1 }],
        policy({ rowFilters: [{ field: "flag", operator: "equals", value: true }] }),
      ),
    ).toEqual([]);
  });

  it("in does not conflate booleans with numbers", () => {
    expect(
      applyRowFilters(
        [{ id: 1, flag: true }],
        policy({ rowFilters: [{ field: "flag", operator: "in", values: [1] }] }),
      ),
    ).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Defect 9: `matches` was unanchored-alternation + unbounded (ReDoS)
// ---------------------------------------------------------------------------

describe("defect 9: matches is anchored with a non-capturing group and bounded", () => {
  it("EXPLOIT: an alternation pattern no longer matches a longer string", () => {
    // `^hr|finance$` binds `^` to `hr` only, so "hr_secret_internal" matched an
    // allow-filter written to permit exactly "hr" or "finance".
    const rows = [
      { id: 1, dept: "hr" },
      { id: 2, dept: "finance" },
      { id: 3, dept: "hr_secret_internal" },
      { id: 4, dept: "corporate_finance" },
    ];

    const kept = applyRowFilters(
      rows,
      policy({
        rowFilters: [{ field: "dept", operator: "matches", value: "hr|finance" }],
      }),
    );

    expect(kept.map((r) => r.id)).toEqual([1, 2]);
  });

  it("an invalid regex is a non-match, not a thrown error", () => {
    const rows = [{ id: 1, dept: "hr" }];

    expect(() =>
      applyRowFilters(
        rows,
        policy({
          rowFilters: [{ field: "dept", operator: "matches", value: "([unclosed" }],
        }),
      ),
    ).not.toThrow();
    expect(
      applyRowFilters(
        rows,
        policy({
          rowFilters: [{ field: "dept", operator: "matches", value: "([unclosed" }],
        }),
      ),
    ).toEqual([]);
  });

  it("ReDoS GUARD: a pattern over the length bound is refused, not evaluated", () => {
    // JavaScript's RegExp has no evaluation timeout, so the bound is on input
    // size: an over-long pattern is refused rather than handed to the engine.
    // This pattern *would* match, so a refusal (row dropped) is the only way to
    // observe the guard -- an unbounded implementation keeps the row.
    const rows = [{ id: 1, dept: "a" }];
    const oversized = `${"a|".repeat(600)}a`;
    expect(oversized.length).toBeGreaterThan(1024);
    expect(new RegExp(`^(?:${oversized})$`).test("a")).toBe(true);

    const kept = applyRowFilters(
      rows,
      policy({
        rowFilters: [{ field: "dept", operator: "matches", value: oversized }],
      }),
    );

    expect(kept).toEqual([]);
  });

  it("ReDoS GUARD: a catastrophic-backtracking pattern does not hang the pass", () => {
    const rows = [{ id: 1, dept: "a".repeat(64) }];
    const evil = `${"(a+)+".repeat(300)}b`;

    const start = Date.now();
    const kept = applyRowFilters(
      rows,
      policy({ rowFilters: [{ field: "dept", operator: "matches", value: evil }] }),
    );

    expect(kept).toEqual([]);
    expect(Date.now() - start).toBeLessThan(1000);
  });

  it("ReDoS GUARD: an oversized subject value is a non-match", () => {
    const rows = [{ id: 1, dept: "a".repeat(5000) }];

    const kept = applyRowFilters(
      rows,
      policy({ rowFilters: [{ field: "dept", operator: "matches", value: "a*" }] }),
    );

    expect(kept).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Defect 10: the field pre-check depended on static accessedFields
// ---------------------------------------------------------------------------

describe("defect 10: undeclared columns cannot leak past the pre-check", () => {
  it("LEAK: a tool declaring only 'name' but returning ssn has ssn stripped", () => {
    // The pre-check inspects the field list the caller volunteers, so a tool
    // declaring accessedFields: ["name"] passes it while returning {name, ssn}.
    // Post-execution stripping is what closes the leak.
    const result = applyResultPipeline(
      [{ name: "John Smith", ssn: "111-22-3333" }],
      policy({ hiddenFields: ["ssn"] }),
    ) as Array<Record<string, unknown>>;

    expect(result).toEqual([{ name: "John Smith" }]);
  });
});

// ---------------------------------------------------------------------------
// Defect 11: filterByTags dropped untagged records for denylist-only policies
// ---------------------------------------------------------------------------

describe("defect 11: a pure denylist does not drop untagged records", () => {
  it("an untagged record survives a deniedTags-only policy", () => {
    // An untagged record matches no denied tag, so dropping it enforced a
    // restriction the policy never stated.
    const results = [
      { id: "doc1", tags: ["public"] },
      { id: "doc2" }, // no tags key at all
      { id: "doc3", tags: [] },
      { id: "doc4", tags: ["classified"] },
    ];

    const kept = filterByTags(
      results,
      policy({ tagRules: { deniedTags: ["classified"] } }),
    );

    expect(kept.map((r) => r.id)).toEqual(["doc1", "doc2", "doc3"]);
  });

  it("an untagged record is still dropped when allowedTags is specified", () => {
    const results = [{ id: "doc1", tags: ["public"] }, { id: "doc2" }];

    const kept = filterByTags(
      results,
      policy({ tagRules: { allowedTags: ["public"] } }),
    );

    expect(kept.map((r) => r.id)).toEqual(["doc1"]);
  });

  it("denied still takes precedence over allowed", () => {
    const results = [{ id: "doc6", tags: ["confidential", "public"] }];

    const kept = filterByTags(
      results,
      policy({
        tagRules: { allowedTags: ["public"], deniedTags: ["confidential"] },
      }),
    );

    expect(kept).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Defect 12: prototype pollution surface while walking result trees
// ---------------------------------------------------------------------------

describe("defect 12: dangerous keys are never walked or assigned through", () => {
  it("a __proto__ key in a result body does not reach Object.prototype", () => {
    const hostile = JSON.parse(
      '{"id":1,"__proto__":{"polluted":"yes"},"ssn":"x"}',
    ) as Record<string, unknown>;

    const stripped = stripHiddenFields([hostile], policy({ hiddenFields: ["ssn"] }));
    const masked = applyFieldMasking(
      hostile,
      policy({ maskedFields: [{ field: "id", maskType: "redact" }] }),
    );

    expect(({} as Record<string, unknown>)["polluted"]).toBeUndefined();
    expect(Object.prototype).not.toHaveProperty("polluted");
    // The hostile key is dropped entirely rather than assigned through (a bare
    // `node["__proto__"] = ...` would reassign the object's prototype).
    expect(Object.prototype.hasOwnProperty.call(stripped[0], "__proto__")).toBe(
      false,
    );
    expect(Object.keys(masked)).not.toContain("__proto__");
  });

  it("a constructor key is skipped rather than reassigned", () => {
    const hostile = JSON.parse('{"id":1,"constructor":{"x":1}}') as Record<
      string,
      unknown
    >;

    expect(() =>
      applyFieldMasking(
        hostile,
        policy({ maskedFields: [{ field: "constructor", maskType: "redact" }] }),
      ),
    ).not.toThrow();
    expect(({} as Record<string, unknown>).constructor).toBe(Object);
  });
});

// ---------------------------------------------------------------------------
// Defect 13: result shapes fail closed
// ---------------------------------------------------------------------------

describe("defect 13: unenforceable result shapes are denied", () => {
  const badResults: Array<[string, unknown]> = [
    ["scalar-string", "a string"],
    ["scalar-number", 42],
    ["scalar-boolean", true],
    ["null", null],
    ["undefined", undefined],
    ["generator", (function* () { yield { a: 1 }; })()],
    ["arbitrary-class", new (class Poco { x = 1; })()],
    ["mixed-array", [{ a: 1 }, "not a record"]],
    ["array-of-scalars", [1, 2, 3]],
  ];

  for (const [label, bad] of badResults) {
    it(`${label} is denied`, () => {
      expect(() => applyResultPipeline(bad, policy({ hiddenFields: ["ssn"] }))).toThrow(
        UnenforceableResultError,
      );
      expect(() => applyResultPipeline(bad, policy({ hiddenFields: ["ssn"] }))).toThrow(
        /cannot be policy-enforced/,
      );
    });
  }

  it("the denial message names the observed shape", () => {
    expect(() => applyResultPipeline("a string", policy())).toThrow(/string/);
    expect(() => applyResultPipeline([1, 2], policy())).toThrow(
      /array containing number/,
    );
  });

  it("a record and an array of records are enforceable", () => {
    expect(classifyResultShape({ id: 1 })).toBe("record");
    expect(classifyResultShape([{ id: 1 }])).toBe("records");
    expect(classifyResultShape([])).toBe("records");
  });

  it("an empty array is enforceable and passes through", () => {
    expect(applyResultPipeline([], policy({ hiddenFields: ["ssn"] }))).toEqual([]);
  });

  it("describeResultShape names the observed type", () => {
    class Poco {
      x = 1;
    }
    // A class instance is denied by name: enforcing over accessors and
    // prototype methods the pipeline cannot see would be a false guarantee.
    expect(describeResultShape(new Poco())).toContain("Poco");
    expect(describeResultShape(Symbol("s"))).toContain("symbol");
    expect(describeResultShape({ id: 1 })).toBe("object (record)");
  });
});

// ---------------------------------------------------------------------------
// Pipeline ordering (canonical spec §4)
// ---------------------------------------------------------------------------

describe("pipeline runs the six steps in canonical order", () => {
  it("row -> tag -> hidden -> allowed -> mask -> limit", () => {
    const rows = [
      { id: 1, region: "us-east", tags: ["public"], ssn: "a", email: "a@x", extra: "drop-me" },
      { id: 2, region: "eu-west", tags: ["public"], ssn: "b", email: "b@x", extra: "drop-me" },
      { id: 3, region: "us-east", tags: ["classified"], ssn: "c", email: "c@x", extra: "drop-me" },
      { id: 4, region: "us-east", tags: ["public"], ssn: "d", email: "d@x", extra: "drop-me" },
      { id: 5, region: "us-east", tags: ["public"], ssn: "e", email: "e@x", extra: "drop-me" },
    ];

    const result = applyResultPipeline(
      rows,
      policy({
        rowFilters: [{ field: "region", operator: "equals", value: "us-east" }],
        tagRules: { deniedTags: ["classified"] },
        hiddenFields: ["ssn"],
        allowedFields: ["id", "region", "tags", "email"],
        maskedFields: [{ field: "email", maskType: "redact" }],
        maxResults: 2,
      }),
    ) as Array<Record<string, unknown>>;

    // rows 2 (region) and 3 (tag) are dropped; ssn hidden; extra not allowed;
    // email masked; limit truncates the surviving 1/4/5 to 1/4.
    expect(result).toEqual([
      { id: 1, region: "us-east", tags: ["public"], email: "[REDACTED]" },
      { id: 4, region: "us-east", tags: ["public"], email: "[REDACTED]" },
    ]);
  });

  it("the limit applies after filtering, not before", () => {
    const rows = [
      { id: 1, region: "eu-west" },
      { id: 2, region: "eu-west" },
      { id: 3, region: "us-east" },
      { id: 4, region: "us-east" },
    ];

    const result = applyResultPipeline(
      rows,
      policy({
        rowFilters: [{ field: "region", operator: "equals", value: "us-east" }],
        maxResults: 2,
      }),
    ) as Array<Record<string, unknown>>;

    // Limiting first would have yielded zero rows.
    expect(result.map((r) => r.id)).toEqual([3, 4]);
  });

  it("does not mutate the caller's records", () => {
    const rows = [{ id: 1, ssn: "111-22-3333", nested: { email: "a@x" } }];

    applyResultPipeline(
      rows,
      policy({
        hiddenFields: ["ssn"],
        maskedFields: [{ field: "email", maskType: "redact" }],
      }),
    );

    expect(rows[0].ssn).toBe("111-22-3333");
    expect(rows[0].nested.email).toBe("a@x");
  });
});

// ---------------------------------------------------------------------------
// Nested / bidirectional field matching (canonical spec §4)
// ---------------------------------------------------------------------------

describe("field matching is bidirectional, case-insensitive, and recursive", () => {
  it("a dotted rule masks a nested leaf", () => {
    const result = applyFieldMasking(
      { patient: { ssn: "111-22-3333" } },
      policy({ maskedFields: [{ field: "patient.ssn", maskType: "redact" }] }),
    );

    expect(result).toEqual({ patient: { ssn: "[REDACTED]" } });
  });

  it("a bare rule masks a qualified key", () => {
    const result = applyFieldMasking(
      { "patients.ssn": "111-22-3333" },
      policy({ maskedFields: [{ field: "ssn", maskType: "redact" }] }),
    );

    expect(result).toEqual({ "patients.ssn": "[REDACTED]" });
  });

  it("a qualified rule masks a bare key", () => {
    const result = applyFieldMasking(
      { ssn: "111-22-3333" },
      policy({ maskedFields: [{ field: "patients.ssn", maskType: "redact" }] }),
    );

    expect(result).toEqual({ ssn: "[REDACTED]" });
  });

  it("matching is case-insensitive", () => {
    const result = applyFieldMasking(
      { SSN: "111-22-3333" },
      policy({ maskedFields: [{ field: "ssn", maskType: "redact" }] }),
    );

    expect(result).toEqual({ SSN: "[REDACTED]" });
  });

  it("masking recurses into arrays of records", () => {
    const result = applyFieldMasking(
      { reactions: [{ name: "a" }, { name: "b" }] },
      policy({ maskedFields: [{ field: "name", maskType: "redact" }] }),
    );

    expect(result).toEqual({
      reactions: [{ name: "[REDACTED]" }, { name: "[REDACTED]" }],
    });
  });

  it("Date values survive the pipeline as dates", () => {
    // pg returns Date objects for DATE/TIMESTAMP columns; the pipeline must not
    // flatten them into {} while cloning.
    const dob = new Date("1980-03-12T00:00:00Z");
    const result = applyResultPipeline(
      [{ id: 1, dateOfBirth: dob, ssn: "x" }],
      policy({ hiddenFields: ["ssn"] }),
    ) as Array<Record<string, unknown>>;

    expect(result[0].dateOfBirth).toBeInstanceOf(Date);
    expect((result[0].dateOfBirth as Date).toISOString()).toBe(dob.toISOString());
  });
});
