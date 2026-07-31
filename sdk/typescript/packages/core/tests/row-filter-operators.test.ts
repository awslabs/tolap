/**
 * The seven operators added so the SDK covers the shared schema's full operator
 * set: greaterThanOrEqual, lessThanOrEqual, like, notLike, isNull, isNotNull,
 * between.
 *
 * They exist because the schema advertised sixteen operators while this SDK
 * implemented nine, so a schema-VALID policy such as
 * `{"field":"age","operator":"between","values":[18,65]}` verified its signature,
 * fell through `rowPassesFilter`'s default arm, and dropped every row -- a silent
 * deny-all here while .NET enforced the same filter correctly. Each case below
 * asserts both outcomes (keep and drop) so an operator implemented as a constant
 * cannot pass, and each fail-closed edge names the spec rule it enforces.
 */

import { describe, expect, it, vi } from "vitest";
import { applyRowFilters } from "../src/enforcement.js";
import { FilterOperator } from "../src/types.js";
import type {
  EffectivePolicy,
  ObjectRules,
  RowFilter,
} from "../src/types.js";

function policy(objectRules: ObjectRules): EffectivePolicy {
  return {
    version: "1.0",
    userId: "user-001",
    tenantId: "tenant-001",
    sourceConnectionId: "db:production:test",
    resolvedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    sourceProfiles: ["operators"],
    permissions: { canQuery: true, readOnly: true },
    objectRules,
    integrity: { algorithm: "none", signature: "" },
  };
}

function rows(filters: RowFilter[], data: Array<Record<string, unknown>>) {
  return applyRowFilters(data, policy({ rowFilters: filters }));
}

/** Whether a single-field row survives one filter. */
function passes(
  field: string,
  value: unknown,
  filter: RowFilter,
): boolean {
  return rows([filter], [{ [field]: value }]).length === 1;
}

// ---------------------------------------------------------------------------
// greaterThanOrEqual / lessThanOrEqual
// ---------------------------------------------------------------------------

describe("greaterThanOrEqual / lessThanOrEqual", () => {
  const gte = (value: unknown): RowFilter => ({
    field: "a",
    operator: FilterOperator.GreaterThanOrEqual,
    value,
  });
  const lte = (value: unknown): RowFilter => ({
    field: "a",
    operator: FilterOperator.LessThanOrEqual,
    value,
  });

  it("include the boundary, unlike their strict counterparts", () => {
    // The whole reason these operators exist: `greaterThan 18` excludes an
    // 18-year-old, which is not what a policy saying "adults" means.
    expect(passes("a", 18, gte(18))).toBe(true);
    expect(passes("a", 18, { field: "a", operator: FilterOperator.GreaterThan, value: 18 }))
      .toBe(false);
    expect(passes("a", 65, lte(65))).toBe(true);
    expect(passes("a", 65, { field: "a", operator: FilterOperator.LessThan, value: 65 }))
      .toBe(false);
  });

  it("order numbers on both sides of the boundary", () => {
    expect(passes("a", 19, gte(18))).toBe(true);
    expect(passes("a", 17, gte(18))).toBe(false);
    expect(passes("a", 64, lte(65))).toBe(true);
    expect(passes("a", 66, lte(65))).toBe(false);
  });

  it("order strings lexicographically", () => {
    expect(passes("a", "m", gte("m"))).toBe(true);
    expect(passes("a", "z", gte("m"))).toBe(true);
    expect(passes("a", "a", gte("m"))).toBe(false);
    expect(passes("a", "m", lte("m"))).toBe(true);
    expect(passes("a", "z", lte("m"))).toBe(false);
  });

  it("order Dates by instant, boundary included", () => {
    const cutoff = new Date("2026-01-01T00:00:00Z");
    expect(passes("a", new Date(cutoff), gte(cutoff))).toBe(true);
    expect(passes("a", new Date("2026-06-01T00:00:00Z"), gte(cutoff))).toBe(true);
    expect(passes("a", new Date("2025-06-01T00:00:00Z"), gte(cutoff))).toBe(false);
    expect(passes("a", new Date(cutoff), lte(cutoff))).toBe(true);
  });

  it("order bigints, boundary included", () => {
    expect(passes("a", 10n, gte(10n))).toBe(true);
    expect(passes("a", 9n, gte(10n))).toBe(false);
    expect(passes("a", 10n, lte(10n))).toBe(true);
    expect(passes("a", 11n, lte(10n))).toBe(false);
  });

  it("a non-comparable pair drops the row and never throws (spec §7)", () => {
    // Fail closed: the author asked for a bound and it cannot be shown to hold.
    // The bigint/number pair also THROWS under a bare `>=` in JS, so this guard is
    // what keeps one bad row from aborting the whole result pass.
    const mixed: Array<[unknown, unknown]> = [
      ["notanumber", 30],
      [30, "notanumber"],
      [10n, 5],
      [5, 10n],
      [new Date(), 5],
      [true, 1],
      [{ nested: 1 }, 5],
      [[1, 2], 5],
      [Number.NaN, 30],
      [30, Number.NaN],
    ];

    for (const [rowValue, filterValue] of mixed) {
      expect(() => passes("a", rowValue, gte(filterValue))).not.toThrow();
      expect(
        passes("a", rowValue, gte(filterValue)),
        `gte ${String(rowValue)} vs ${String(filterValue)}`,
      ).toBe(false);
      expect(passes("a", rowValue, lte(filterValue))).toBe(false);
    }
  });

  it("a stored null or an absent/null filter value is a non-match", () => {
    // An ordering comparison against null is not satisfiable, in SQL or here.
    expect(passes("a", null, gte(30))).toBe(false);
    expect(passes("a", null, lte(30))).toBe(false);
    expect(passes("a", 30, gte(null))).toBe(false);
    expect(passes("a", 30, lte(null))).toBe(false);
    expect(
      passes("a", 30, { field: "a", operator: FilterOperator.GreaterThanOrEqual }),
    ).toBe(false);
    expect(
      passes("a", 30, { field: "a", operator: FilterOperator.LessThanOrEqual }),
    ).toBe(false);
  });

  it("a row missing the field is dropped (spec §7)", () => {
    expect(rows([gte(1)], [{ other: 1 }])).toEqual([]);
    expect(rows([lte(1)], [{ other: 1 }])).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// like / notLike
// ---------------------------------------------------------------------------

describe("like", () => {
  const like = (pattern: unknown): RowFilter => ({
    field: "a",
    operator: FilterOperator.Like,
    value: pattern,
  });

  it("% matches any run of characters, including none", () => {
    expect(passes("a", "us-east", like("us-%"))).toBe(true);
    expect(passes("a", "us-", like("us-%"))).toBe(true);
    expect(passes("a", "eu-west", like("us-%"))).toBe(false);
    expect(passes("a", "us-east-1", like("%east%"))).toBe(true);
    expect(passes("a", "anything", like("%"))).toBe(true);
    expect(passes("a", "", like("%"))).toBe(true);
  });

  it("_ matches exactly one character", () => {
    expect(passes("a", "us1", like("us_"))).toBe(true);
    expect(passes("a", "us", like("us_"))).toBe(false);
    expect(passes("a", "us12", like("us_"))).toBe(false);
    expect(passes("a", "us12", like("us__"))).toBe(true);
  });

  it("is anchored: a full-value match, not a substring search", () => {
    // The distinction from `contains`. A pattern with no wildcards must match the
    // whole value, or a policy `like 'us'` would admit every us-* region.
    expect(passes("a", "us-east", like("us"))).toBe(false);
    expect(passes("a", "us", like("us"))).toBe(true);
    expect(passes("a", "us-east", like("east"))).toBe(false);
  });

  it("is case-sensitive, matching Postgres LIKE", () => {
    // Load-bearing: sql-rewriter pushes this operator down as a real LIKE, and
    // Postgres/Athena/Trino all evaluate it case-sensitively. Were the post-fetch
    // pass lenient here, pushing the filter down would change which rows a caller
    // sees, and no post-fetch leniency could recover rows the DB already dropped.
    expect(passes("a", "US-EAST", like("us-%"))).toBe(false);
    expect(passes("a", "us-east", like("US-%"))).toBe(false);
    expect(passes("a", "us-east", like("us-%"))).toBe(true);
  });

  it("treats regex metacharacters literally -- a LIKE pattern is not a regex", () => {
    // Passing the pattern through to the regex engine unescaped would make `.`
    // match any character and `|` an alternation, widening the filter well past
    // what the author wrote.
    expect(passes("a", "a.b", like("a.b"))).toBe(true);
    expect(passes("a", "axb", like("a.b"))).toBe(false);
    expect(passes("a", "a", like("a|b"))).toBe(false);
    expect(passes("a", "a|b", like("a|b"))).toBe(true);
    expect(passes("a", "a+", like("a+"))).toBe(true);
    expect(passes("a", "aaa", like("a+"))).toBe(false);
    expect(passes("a", "(a)", like("(a)"))).toBe(true);
    expect(passes("a", "a$", like("a$"))).toBe(true);
    expect(passes("a", "a^b", like("a^b"))).toBe(true);
    expect(passes("a", "a{2}", like("a{2}"))).toBe(true);
    expect(passes("a", "aa", like("a{2}"))).toBe(false);
    expect(passes("a", "a[b]", like("a[b]"))).toBe(true);
  });

  it("an alternation-looking pattern cannot escape the anchors", () => {
    // The `matches` analogue of spec §7's `^(?:pattern)$` requirement: without the
    // non-capturing group, `^a|b$` binds `^` to `a` alone. LIKE has no alternation
    // at all, so a literal `|` must simply be a literal.
    expect(passes("a", "b-suffix", like("a|b"))).toBe(false);
    expect(passes("a", "prefix-a", like("a|b"))).toBe(false);
  });

  it("a backslash escapes a wildcard so it can be matched literally", () => {
    expect(passes("a", "100%", like("100\\%"))).toBe(true);
    expect(passes("a", "100x", like("100\\%"))).toBe(false);
    expect(passes("a", "a_b", like("a\\_b"))).toBe(true);
    expect(passes("a", "axb", like("a\\_b"))).toBe(false);
    expect(passes("a", "a\\b", like("a\\\\b"))).toBe(true);
  });

  it("a trailing backslash has nothing to escape and is literal", () => {
    // Guards the `i + 1 < pattern.length` bound: consuming past the end would
    // either throw or silently drop the character.
    expect(passes("a", "a\\", like("a\\"))).toBe(true);
    expect(passes("a", "a", like("a\\"))).toBe(false);
  });

  it("wildcards span a newline, as SQL LIKE's do", () => {
    // SQL LIKE has no line semantics, so `%` must not stop at a \n. Without the `s`
    // flag `.` would not cross one and a multi-line value would escape the filter.
    expect(passes("a", "us\neast", like("us%east"))).toBe(true);
    expect(passes("a", "a\nb", like("a_b"))).toBe(true);
  });

  it("coerces a non-string field value rather than throwing", () => {
    expect(passes("a", 12345, like("123%"))).toBe(true);
    expect(passes("a", 12345, like("9%"))).toBe(false);
    expect(passes("a", true, like("tru_"))).toBe(true);
  });

  it("a stored null or an absent/null pattern is a non-match", () => {
    // Without the guard, String(null) = "null" would satisfy like('nu%').
    expect(passes("a", null, like("nu%"))).toBe(false);
    expect(passes("a", null, like("%"))).toBe(false);
    expect(passes("a", "hello", like(null))).toBe(false);
    expect(passes("a", "hello", { field: "a", operator: FilterOperator.Like })).toBe(false);
  });

  it("a row missing the field is dropped (spec §7)", () => {
    expect(rows([like("%")], [{ other: "x" }])).toEqual([]);
  });

  it("an over-long pattern or value is a non-match, not unbounded work", () => {
    // ReDoS guard, consistent with `matches`. The LIKE translation emits only
    // `.*`, `.`, and escaped literals -- there is no nesting to backtrack over --
    // but the bound is kept so the two operators refuse the same inputs.
    const longPattern = "%".repeat(2000);
    expect(passes("a", "x", like(longPattern))).toBe(false);
    const longValue = "x".repeat(5000);
    expect(passes("a", longValue, like("%"))).toBe(false);
  });

  it("caches compiled patterns without unbounded growth", () => {
    // Bounded like the `matches` cache: a varied policy stream must not grow it
    // forever, and eviction must not turn a valid pattern into a silent non-match.
    for (let i = 0; i < 300; i++) {
      expect(passes("a", `bounded-${i}`, like(`bounded-${i}`))).toBe(true);
    }
    expect(passes("a", "bounded-0", like("bounded-0"))).toBe(true);
  });
});

describe("notLike", () => {
  const notLike = (pattern: unknown): RowFilter => ({
    field: "a",
    operator: FilterOperator.NotLike,
    value: pattern,
  });

  it("is the exact negation of like for a present, non-null value", () => {
    expect(passes("a", "eu-west", notLike("us-%"))).toBe(true);
    expect(passes("a", "us-east", notLike("us-%"))).toBe(false);
  });

  it("a stored null is KEPT, exactly as notEquals and notIn keep it (spec §7)", () => {
    // Bare SQL `NULL NOT LIKE 'x'` is unknown and would drop the row, which is
    // precisely why the rewriter emits `(col NOT LIKE 'x' OR col IS NULL)` -- so the
    // pushed-down query and this pass select the same rows (spec §4). Dropping the
    // row here is the divergence: it would make `notLike` disagree with its two
    // sibling negatives for no reason the policy expresses.
    //
    // Distinct from the ABSENT-field rule asserted in the next case, which drops.
    expect(passes("a", null, notLike("internal-%"))).toBe(true);
  });

  it("a row missing the field is dropped, not retained (spec §7)", () => {
    expect(rows([notLike("internal-%")], [{ other: "x" }])).toEqual([]);
  });

  it("an absent or null pattern is a non-match", () => {
    expect(passes("a", "hello", notLike(null))).toBe(false);
    expect(passes("a", "hello", { field: "a", operator: FilterOperator.NotLike })).toBe(
      false,
    );
  });

  it("treats regex metacharacters literally, like its positive counterpart", () => {
    expect(passes("a", "axb", notLike("a.b"))).toBe(true);
    expect(passes("a", "a.b", notLike("a.b"))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// isNull / isNotNull
// ---------------------------------------------------------------------------

describe("isNull / isNotNull", () => {
  const isNull: RowFilter = { field: "a", operator: FilterOperator.IsNull };
  const isNotNull: RowFilter = { field: "a", operator: FilterOperator.IsNotNull };

  it("isNull keeps a present-and-null field and drops a valued one", () => {
    expect(passes("a", null, isNull)).toBe(true);
    expect(passes("a", "value", isNull)).toBe(false);
  });

  it("isNotNull is the exact complement for a present field", () => {
    expect(passes("a", "value", isNotNull)).toBe(true);
    expect(passes("a", null, isNotNull)).toBe(false);
  });

  it("a MISSING field does NOT satisfy isNull -- the row is dropped (spec §7)", () => {
    // The deliberate decision. "Absent" and "present and null" are different
    // statements: the first says the tool returned no such column, the second says
    // the column exists and holds no value. Only the second is what an author
    // writing `isNull` asked about, and the fail-closed reading of the first is a
    // drop -- consistent with spec §7's rule that a missing field drops the row for
    // EVERY operator, with no carve-outs. A carve-out here would also be
    // self-defeating: `SELECT region` omitted from a projection would start
    // satisfying an isNull filter, so narrowing a query could widen a result.
    expect(rows([isNull], [{ other: 1 }])).toEqual([]);
    expect(rows([isNotNull], [{ other: 1 }])).toEqual([]);
  });

  it("both ignore `value` and `values` entirely", () => {
    // They take no operand; a stray one must not change the outcome.
    expect(
      passes("a", null, { field: "a", operator: FilterOperator.IsNull, value: "ignored" }),
    ).toBe(true);
    expect(
      passes("a", null, { field: "a", operator: FilterOperator.IsNull, values: [1, 2] }),
    ).toBe(true);
  });

  it("a key holding undefined counts as null", () => {
    // hasOwnProperty makes the key present, so it reaches the operator rather than
    // being dropped as missing. A driver or caller writing `undefined` means the
    // same thing a JSON null does.
    expect(rows([isNull], [{ a: undefined }])).toHaveLength(1);
    expect(rows([isNotNull], [{ a: undefined }])).toEqual([]);
  });

  it("falsy-but-present values are NOT null", () => {
    // The classic bug: a `!value` test would report 0, "", and false as null.
    for (const value of [0, "", false, Number.NaN]) {
      expect(passes("a", value, isNull), `${String(value)} is not null`).toBe(false);
      expect(passes("a", value, isNotNull), `${String(value)} is not null`).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// between
// ---------------------------------------------------------------------------

describe("between", () => {
  const between = (values: unknown[] | undefined): RowFilter => ({
    field: "a",
    operator: FilterOperator.Between,
    ...(values === undefined ? {} : { values }),
  });

  it("is inclusive at both bounds", () => {
    expect(passes("a", 18, between([18, 65]))).toBe(true);
    expect(passes("a", 65, between([18, 65]))).toBe(true);
    expect(passes("a", 40, between([18, 65]))).toBe(true);
  });

  it("excludes values outside the range", () => {
    expect(passes("a", 17, between([18, 65]))).toBe(false);
    expect(passes("a", 66, between([18, 65]))).toBe(false);
  });

  it("ranges over strings and Dates, not just numbers", () => {
    expect(passes("a", "m", between(["a", "z"]))).toBe(true);
    expect(passes("a", "Z", between(["a", "z"]))).toBe(false); // uppercase sorts before "a"
    const low = new Date("2026-01-01T00:00:00Z");
    const high = new Date("2026-12-31T00:00:00Z");
    expect(passes("a", new Date("2026-06-01T00:00:00Z"), between([low, high]))).toBe(true);
    expect(passes("a", new Date("2025-06-01T00:00:00Z"), between([low, high]))).toBe(false);
  });

  it("an inverted range matches nothing and is NOT silently reordered", () => {
    // SQL `BETWEEN 10 AND 1` matches nothing. Reordering the bounds would turn a
    // policy author's typo into a WIDER grant than the policy states, which is the
    // wrong direction for a security control to guess in.
    expect(passes("a", 5, between([10, 1]))).toBe(false);
    expect(passes("a", 1, between([10, 1]))).toBe(false);
    expect(passes("a", 10, between([10, 1]))).toBe(false);
  });

  it("a degenerate range matches only its single value", () => {
    expect(passes("a", 5, between([5, 5]))).toBe(true);
    expect(passes("a", 6, between([5, 5]))).toBe(false);
  });

  it("fewer than two bounds drops the row (spec §7: fail closed)", () => {
    expect(passes("a", 5, between(undefined))).toBe(false);
    expect(passes("a", 5, between([]))).toBe(false);
    expect(passes("a", 5, between([1]))).toBe(false);
  });

  it("ignores extra bounds beyond the first two", () => {
    expect(passes("a", 5, between([1, 10, 999]))).toBe(true);
    expect(passes("a", 50, between([1, 10, 999]))).toBe(false);
  });

  it("a null bound or a null field value drops the row", () => {
    expect(passes("a", 5, between([null, 10]))).toBe(false);
    expect(passes("a", 5, between([1, null]))).toBe(false);
    expect(passes("a", 5, between([undefined, 10]))).toBe(false);
    expect(passes("a", 5, between([1, undefined]))).toBe(false);
    expect(passes("a", null, between([1, 10]))).toBe(false);
  });

  it("a bound not ordered against the value drops the row, never throws", () => {
    const unordered: unknown[][] = [
      ["notanumber", 10],
      [1, "notanumber"],
      [1n, 10],
      [new Date(), 10],
      [true, 10],
      [{ x: 1 }, 10],
    ];
    for (const bounds of unordered) {
      expect(() => passes("a", 5, between(bounds))).not.toThrow();
      expect(passes("a", 5, between(bounds)), JSON.stringify(String(bounds))).toBe(false);
    }
  });

  it("a row missing the field is dropped (spec §7)", () => {
    expect(rows([between([1, 10])], [{ other: 5 }])).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// The unknown-operator arm
// ---------------------------------------------------------------------------

describe("unrecognized operator: fail closed, and say so", () => {
  it("drops every row rather than passing them through", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      // A distinct spelling per call, so the once-per-operator dedupe does not
      // make a later assertion depend on an earlier test having run.
      expect(rows([{ field: "a", operator: "gte-typo-1", value: 1 }], [{ a: 1 }])).toEqual(
        [],
      );
    } finally {
      warn.mockRestore();
    }
  });

  it("warns, so a silent deny-all is distinguishable from a working filter", () => {
    // Fail-closed alone is not enough operationally: dropping every row looks
    // exactly like a filter that is working, so an integrator whose policy uses an
    // operator this SDK does not implement gets no signal. Warning rather than
    // throwing matches how an unknown maskType degrades to `redact` (spec §6)
    // instead of aborting the result pass -- one malformed filter must not take
    // down an entire tool call. Deliberately NOT fail-open.
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      rows([{ field: "a", operator: "not-an-operator-xyz", value: 1 }], [{ a: 1 }]);
      expect(warn).toHaveBeenCalledTimes(1);
      const message = String(warn.mock.calls[0]?.[0]);
      expect(message).toContain("not-an-operator-xyz");
      expect(message).toContain("dropped");
      // The message lists what IS supported, so the fix is actionable.
      expect(message).toContain("between");
    } finally {
      warn.mockRestore();
    }
  });

  it("warns once per distinct operator, not once per row", () => {
    // A filter evaluated over a large result set must not emit one message per row.
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const data = Array.from({ length: 50 }, (_, i) => ({ a: i }));
      rows([{ field: "a", operator: "repeated-unknown-op", value: 1 }], data);
      rows([{ field: "a", operator: "repeated-unknown-op", value: 1 }], data);
      expect(warn).toHaveBeenCalledTimes(1);
    } finally {
      warn.mockRestore();
    }
  });

  it("the warned-operator set is bounded", () => {
    // A varied or hostile policy stream must not grow it without limit. Eviction
    // may re-warn, which is harmless; unbounded memory growth is not.
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      for (let i = 0; i < 200; i++) {
        expect(
          rows([{ field: "a", operator: `bounded-unknown-${i}`, value: 1 }], [{ a: 1 }]),
        ).toEqual([]);
      }
    } finally {
      warn.mockRestore();
    }
  });
});

// ---------------------------------------------------------------------------
// Cross-operator: the new operators compose with the old ones
// ---------------------------------------------------------------------------

describe("the new operators AND together with the existing ones", () => {
  it("a row must satisfy every filter, old and new alike", () => {
    const data = [
      { id: 1, age: 30, region: "us-east", deleted_at: null },
      { id: 2, age: 17, region: "us-east", deleted_at: null },
      { id: 3, age: 30, region: "eu-west", deleted_at: null },
      { id: 4, age: 30, region: "us-east", deleted_at: "2026-01-01" },
    ];

    const kept = rows(
      [
        { field: "age", operator: FilterOperator.Between, values: [18, 65] },
        { field: "region", operator: FilterOperator.Like, value: "us-%" },
        { field: "deleted_at", operator: FilterOperator.IsNull },
      ],
      data,
    );

    expect(kept.map((r) => r.id)).toEqual([1]);
  });
});
