/**
 * Branch coverage for enforcement.ts, asserting the SPEC-mandated outcome of each
 * conditional rather than merely reaching it.
 *
 * Every one of TOLAP's recent critical vulnerabilities was an untested branch --
 * `notEquals` failing open on a missing field, an unknown `maskType` returning the
 * raw value -- so each case here pins the fail-closed side of a decision the
 * canonical spec makes normative. Where a branch is a fail-open risk the test says
 * which spec section forbids it.
 */

import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  applyMask,
  applyObjectSizeCeiling,
  applyResultLimit,
  applySimilarityFloor,
  applyResultPipeline,
  applyRowFilters,
  applyFieldMasking,
  applyMaskingToTree,
  classifyResultShape,
  describeResultShape,
  filterByTags,
  projectAllowedFields,
  stripHiddenFields,
  validateAccess,
  validateEndpoint,
  validateFieldAccess,
} from "../src/enforcement.js";
import type {
  EffectivePolicy,
  MaskingRule,
  ObjectRules,
  PolicyLimits,
  PolicyPermissions,
  RowFilter,
} from "../src/types.js";

function policy(
  objectRules?: ObjectRules,
  limits?: PolicyLimits,
  permissions: PolicyPermissions = { canQuery: true, readOnly: true },
): EffectivePolicy {
  return {
    version: "1.0",
    userId: "user-001",
    tenantId: "tenant-001",
    sourceConnectionId: "db:production:test",
    resolvedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    sourceProfiles: ["branches"],
    permissions,
    ...(objectRules !== undefined ? { objectRules } : {}),
    ...(limits !== undefined ? { limits } : {}),
    integrity: { algorithm: "none", signature: "" },
  };
}

function rows(filters: RowFilter[], data: Array<Record<string, unknown>>) {
  return applyRowFilters(data, policy({ rowFilters: filters }));
}

// ---------------------------------------------------------------------------
// validateAccess -- both sides of every guard
// ---------------------------------------------------------------------------

describe("validateAccess: both outcomes of each conditional", () => {
  it("denies when canQuery is false, before any rule is consulted", () => {
    // canQuery is checked first, so even an explicitly allowed object is denied.
    const result = validateAccess(
      "patients",
      policy({ allowedObjects: ["patients"] }, undefined, { canQuery: false }),
    );

    expect(result).toEqual({ allowed: false, reason: "query not permitted" });
  });

  it("allows when there are no objectRules at all", () => {
    expect(validateAccess("patients", policy())).toEqual({ allowed: true });
  });

  it("allows when objectRules exist but constrain nothing", () => {
    expect(validateAccess("patients", policy({}))).toEqual({ allowed: true });
  });

  it("hidden wins over allowed for the same object", () => {
    const result = validateAccess(
      "patients",
      policy({ allowedObjects: ["patients"], hiddenObjects: ["patients"] }),
    );

    expect(result).toEqual({ allowed: false, reason: "object is hidden" });
  });

  it("a non-matching hiddenObjects entry does not deny", () => {
    expect(
      validateAccess("patients", policy({ hiddenObjects: ["billing"] })),
    ).toEqual({ allowed: true });
  });

  it("an empty allowedObjects denies every object", () => {
    // [] is deny-all, not unrestricted (spec §3).
    expect(validateAccess("patients", policy({ allowedObjects: [] }))).toEqual({
      allowed: false,
      reason: "object not in allowed set",
    });
  });

  it("an empty hiddenObjects hides nothing", () => {
    expect(validateAccess("patients", policy({ hiddenObjects: [] }))).toEqual({
      allowed: true,
    });
  });

  it("a glob allowedObjects entry matches", () => {
    expect(
      validateAccess("patient_records", policy({ allowedObjects: ["patient_*"] })),
    ).toEqual({ allowed: true });
  });
});

// ---------------------------------------------------------------------------
// validateFieldAccess -- the three exits of the per-field loop
// ---------------------------------------------------------------------------

describe("validateFieldAccess: each loop exit", () => {
  it("hidden takes precedence over an allow-list naming the same field", () => {
    const result = validateFieldAccess(
      ["ssn"],
      policy({ fieldRules: { allowedFields: ["ssn"], hiddenFields: ["ssn"] } }),
    );

    expect(result).toEqual({ allowed: [], denied: ["ssn"] });
  });

  it("with no fieldRules at all, every field is allowed", () => {
    expect(validateFieldAccess(["a", "b"], policy())).toEqual({
      allowed: ["a", "b"],
      denied: [],
    });
  });

  it("with fieldRules but no field constraints, every field is allowed", () => {
    expect(validateFieldAccess(["a"], policy({ fieldRules: {} }))).toEqual({
      allowed: ["a"],
      denied: [],
    });
  });

  it("splits a field list across allowed and denied", () => {
    const result = validateFieldAccess(
      ["id", "name", "ssn"],
      policy({ fieldRules: { allowedFields: ["id", "name"] } }),
    );

    expect(result).toEqual({ allowed: ["id", "name"], denied: ["ssn"] });
  });

  it("an empty allowedFields denies every field", () => {
    expect(
      validateFieldAccess(["id"], policy({ fieldRules: { allowedFields: [] } })),
    ).toEqual({ allowed: [], denied: ["id"] });
  });

  it("an empty field list yields two empty lists", () => {
    expect(
      validateFieldAccess([], policy({ fieldRules: { allowedFields: ["id"] } })),
    ).toEqual({ allowed: [], denied: [] });
  });

  it("hiddenFields alone denies a match and allows a non-match", () => {
    expect(
      validateFieldAccess(["ssn", "id"], policy({ fieldRules: { hiddenFields: ["ssn"] } })),
    ).toEqual({ allowed: ["id"], denied: ["ssn"] });
  });
});

// ---------------------------------------------------------------------------
// applyMask -- every switch arm and parameter default
// ---------------------------------------------------------------------------

describe("applyMask: every arm and parameter default", () => {
  const rule = (maskType: string, parameters?: MaskingRule["parameters"]): MaskingRule => ({
    field: "f",
    maskType,
    ...(parameters !== undefined ? { parameters } : {}),
  });

  it("null and undefined inputs both mask to null, disclosing nothing", () => {
    expect(applyMask(null, rule("full"))).toBeNull();
    expect(applyMask(undefined, rule("partial"))).toBeNull();
    // Even a mask type that would otherwise stringify cannot turn a null into the
    // literal "null" and thereby leak that the field existed.
    expect(applyMask(null, rule("hash"))).toBeNull();
  });

  it("full uses the default mask char and honours an override", () => {
    expect(applyMask("abcd", rule("full"))).toBe("****");
    expect(applyMask("abcd", rule("full", { maskChar: "#" }))).toBe("####");
  });

  it("full leaks length only, and coerces a non-string first", () => {
    expect(applyMask(12345, rule("full"))).toBe("*****");
    expect(applyMask(true, rule("full"))).toBe("****");
  });

  it("partial with no parameters degrades to a full mask", () => {
    // showFirst and showLast both default to 0, so 0 + 0 < length holds and the
    // whole value is masked -- never returned raw.
    expect(applyMask("abcdef", rule("partial"))).toBe("******");
  });

  it("partial reveals only the requested prefix and suffix", () => {
    expect(applyMask("1234567890", rule("partial", { showFirst: 2, showLast: 2 }))).toBe(
      "12******90",
    );
    expect(applyMask("1234567890", rule("partial", { showFirst: 3 }))).toBe(
      "123*******",
    );
    expect(applyMask("1234567890", rule("partial", { showLast: 4 }))).toBe(
      "******7890",
    );
  });

  it("partial with a negative parameter degrades to a full mask", () => {
    // A negative slice would otherwise produce a nonsensical -- and potentially
    // disclosing -- result (spec §6).
    expect(applyMask("abcdef", rule("partial", { showFirst: -1 }))).toBe("******");
    expect(applyMask("abcdef", rule("partial", { showLast: -3 }))).toBe("******");
  });

  it("partial that would reveal the whole value degrades to a full mask", () => {
    expect(applyMask("abcd", rule("partial", { showFirst: 2, showLast: 2 }))).toBe(
      "****",
    );
    expect(applyMask("abcd", rule("partial", { showFirst: 99 }))).toBe("****");
  });

  it("partial honours a custom mask char", () => {
    expect(
      applyMask("1234567890", rule("partial", { showLast: 2, maskChar: "x" })),
    ).toBe("xxxxxxxx90");
  });

  it("hash is 16 lowercase hex chars, stable, and not the original", () => {
    const first = applyMask("111-22-3333", rule("hash"));
    const second = applyMask("111-22-3333", rule("hash"));

    expect(first).toMatch(/^[a-f0-9]{16}$/);
    expect(first).toBe(second); // stable, so it works as a join key
    expect(first).not.toBe("111-22-3333");
    expect(applyMask("111-22-3334", rule("hash"))).not.toBe(first);
  });

  // -- hash algorithm: the cross-language join key (spec §6) --
  //
  // Masked value of "123-45-6789" per algorithm. These are known-answers shared with
  // the Python and .NET suites: the same literals appear in
  // test_enforcement_branches.py and EnforcementBranchCoverageTests.cs, so a change
  // that makes one SDK disagree fails in that SDK's own suite rather than only in a
  // cross-language integration test nobody runs.
  const KNOWN_ANSWERS: Record<string, string> = {
    sha256: "01a54629efb95228",
    sha512: "fbe47783b1d59d46",
    blake2b: "ddefd0f544edbef0",
  };

  const hashMask = (value: unknown, algorithm?: string): unknown =>
    applyMask(value, rule("hash", algorithm === undefined ? undefined : { algorithm }));

  it.each(Object.entries(KNOWN_ANSWERS))(
    "hash with %s matches the cross-SDK known answer",
    (algorithm, expected) => {
      expect(hashMask("123-45-6789", algorithm)).toBe(expected);
    },
  );

  it("hash defaults to sha256 when algorithm is absent", () => {
    expect(hashMask("123-45-6789")).toBe(KNOWN_ANSWERS.sha256);
  });

  it("blake2b means BLAKE2b-512, which Node spells blake2b512", () => {
    // The schema value is mapped to the runtime's name rather than passed through:
    // `createHash("blake2b")` throws. Pinning the mapping keeps the pseudonym equal to
    // Python's hashlib.blake2b(digest_size=64) -- a different digest size is a
    // different hash.
    expect(hashMask("123-45-6789", "blake2b")).toBe(
      createHash("blake2b512").update("123-45-6789").digest("hex").slice(0, 16),
    );
  });

  it("each algorithm yields a distinct digest", () => {
    // Guards the defect directly: the parameter must actually be read. Python and .NET
    // ignored it and produced three identical digests, which is what this table would
    // look like if it were dropped again and the expectations regenerated from the
    // broken implementation.
    const digests = new Set(
      Object.keys(KNOWN_ANSWERS).map((a) => hashMask("123-45-6789", a)),
    );
    expect(digests.size).toBe(3);
  });

  it("an unpermitted hash algorithm redacts rather than leaking or substituting", () => {
    // Fails closed as `redact` (spec §6). It must not throw -- that would abort the
    // whole result pass -- and must not return the original. It must also not fall back
    // to sha256, which this used to do: a substituted digest looks like a valid
    // pseudonym while silently failing to join against a service that computed the
    // algorithm the policy actually asked for.
    //
    // Note `md5` and `sha1` are rejected despite OpenSSL providing them: passing the
    // parameter straight to `createHash` accepted every digest Node knows, plus
    // spellings (`blake2b512`) that Python and .NET reject -- the same cross-SDK
    // divergence in a new form.
    for (const algorithm of [
      "md5",
      "sha1",
      "blake2b512",
      "SHA256",
      "sha-256",
      "not-a-real-algorithm",
      "",
      " sha256",
    ]) {
      let masked: unknown;
      expect(() => {
        masked = hashMask("123-45-6789", algorithm);
      }).not.toThrow();
      expect(masked).toBe("[REDACTED]");
    }
  });

  it("hash of a non-string coerces before hashing, for every algorithm", () => {
    for (const algorithm of Object.keys(KNOWN_ANSWERS)) {
      expect(hashMask(12345, algorithm)).toMatch(/^[a-f0-9]{16}$/);
    }
  });

  it("null mask returns null and redact returns the fixed placeholder", () => {
    expect(applyMask("secret", rule("null"))).toBeNull();
    expect(applyMask("secret", rule("redact"))).toBe("[REDACTED]");
  });

  it("an unknown mask type redacts (spec §6: it must not return the raw value)", () => {
    for (const unknown of ["tokenize-v2", "REDACT", "", "Full", "hash "]) {
      expect(applyMask("111-22-3333", rule(unknown))).toBe("[REDACTED]");
    }
  });
});

// ---------------------------------------------------------------------------
// applyFieldMasking / applyMaskingToTree -- the no-rules short-circuit
// ---------------------------------------------------------------------------

describe("masking walkers: short-circuit and recursion", () => {
  it("with no masking rules the record is returned as an unmutated copy", () => {
    const record = { id: 1, nested: { a: 1 } };
    const out = applyFieldMasking(record, policy({ fieldRules: {} }));

    expect(out).toEqual(record);
    expect(out).not.toBe(record);
    expect(out.nested).not.toBe(record.nested);
  });

  it("with an empty maskedFields array the record is unchanged", () => {
    expect(
      applyFieldMasking({ ssn: "x" }, policy({ fieldRules: { maskedFields: [] } })),
    ).toEqual({ ssn: "x" });
  });

  it("a non-matching rule leaves every key alone", () => {
    expect(
      applyFieldMasking(
        { id: 1 },
        policy({ fieldRules: { maskedFields: [{ field: "ssn", maskType: "null" }] } }),
      ),
    ).toEqual({ id: 1 });
  });

  it("applyMaskingToTree masks an array of records at the top level", () => {
    const out = applyMaskingToTree(
      [{ ssn: "a" }, { ssn: "b" }],
      policy({ fieldRules: { maskedFields: [{ field: "ssn", maskType: "redact" }] } }),
    );

    expect(out).toEqual([{ ssn: "[REDACTED]" }, { ssn: "[REDACTED]" }]);
  });

  it("applyMaskingToTree reaches a bare rule's nested key", () => {
    // The property the HTTP wrapper's own walker lacked: a bare `ssn` rule must
    // reach `demographics.ssn` (spec §4 -- matching recurses).
    const out = applyMaskingToTree(
      { results: [{ demographics: { ssn: "111-22-3333", name: "A" } }] },
      policy({ fieldRules: { maskedFields: [{ field: "ssn", maskType: "redact" }] } }),
    );

    expect(out).toEqual({
      results: [{ demographics: { ssn: "[REDACTED]", name: "A" } }],
    });
  });

  it("applyMaskingToTree passes a scalar through untouched", () => {
    expect(
      applyMaskingToTree(
        "just a string",
        policy({ fieldRules: { maskedFields: [{ field: "ssn", maskType: "null" }] } }),
      ),
    ).toBe("just a string");
  });

  it("the SECOND of two matching rules loses when it is weaker", () => {
    // Drives the "incumbent stays" side of the restrictiveness comparison: rule
    // order must not decide disclosure, only restrictiveness may (spec §6).
    const strictFirst = applyFieldMasking(
      { ssn: "111-22-3333" },
      policy({
        fieldRules: {
          maskedFields: [
            { field: "ssn", maskType: "null" },
            { field: "ssn", maskType: "partial", parameters: { showLast: 4 } },
          ],
        },
      }),
    );
    const weakFirst = applyFieldMasking(
      { ssn: "111-22-3333" },
      policy({
        fieldRules: {
          maskedFields: [
            { field: "ssn", maskType: "partial", parameters: { showLast: 4 } },
            { field: "ssn", maskType: "null" },
          ],
        },
      }),
    );

    expect(strictFirst.ssn).toBeNull();
    expect(weakFirst.ssn).toBeNull();
  });

  it("two EQUALLY restrictive matching rules keep the first", () => {
    const out = applyFieldMasking(
      { ssn: "12345" },
      policy({
        fieldRules: {
          maskedFields: [
            { field: "ssn", maskType: "full", parameters: { maskChar: "#" } },
            { field: "ssn", maskType: "full", parameters: { maskChar: "@" } },
          ],
        },
      }),
    );

    expect(out.ssn).toBe("#####");
  });

  it("three matching rules select the strictest regardless of position", () => {
    for (const order of [
      ["partial", "hash", "null"],
      ["null", "partial", "hash"],
      ["hash", "null", "partial"],
    ]) {
      const out = applyFieldMasking(
        { ssn: "12345" },
        policy({
          fieldRules: {
            maskedFields: order.map((maskType) => ({ field: "ssn", maskType })),
          },
        }),
      );
      expect(out.ssn, order.join(">")).toBeNull();
    }
  });

  it("a masked key is not recursed into after being masked", () => {
    // When a rule matches an object-valued key, the whole subtree is replaced --
    // masking the container must not leave its children visible.
    const out = applyFieldMasking(
      { patient: { ssn: "111-22-3333" } },
      policy({ fieldRules: { maskedFields: [{ field: "patient", maskType: "null" }] } }),
    );

    expect(out).toEqual({ patient: null });
  });
});

// ---------------------------------------------------------------------------
// stripHiddenFields / projectAllowedFields -- short-circuits and shapes
// ---------------------------------------------------------------------------

describe("stripHiddenFields: short-circuit and shapes", () => {
  it("with no hiddenFields the input is returned as an unmutated deep copy", () => {
    const input = [{ id: 1, nested: { a: 1 } }];
    const out = stripHiddenFields(input, policy({ fieldRules: {} }));

    expect(out).toEqual(input);
    expect(out[0].nested).not.toBe(input[0].nested);
  });

  it("an empty hiddenFields array removes nothing", () => {
    expect(
      stripHiddenFields([{ ssn: "x" }], policy({ fieldRules: { hiddenFields: [] } })),
    ).toEqual([{ ssn: "x" }]);
  });

  it("a scalar passes through both with and without patterns", () => {
    expect(stripHiddenFields(42, policy({ fieldRules: { hiddenFields: ["ssn"] } }))).toBe(
      42,
    );
    expect(stripHiddenFields(42, policy({ fieldRules: {} }))).toBe(42);
  });

  it("a bare pattern removes a key nested under an array of records", () => {
    expect(
      stripHiddenFields(
        { results: [{ inner: { ssn: "x", id: 1 } }] },
        policy({ fieldRules: { hiddenFields: ["ssn"] } }),
      ),
    ).toEqual({ results: [{ inner: { id: 1 } }] });
  });

  it("a non-matching pattern removes nothing", () => {
    expect(
      stripHiddenFields(
        [{ id: 1 }],
        policy({ fieldRules: { hiddenFields: ["ssn"] } }),
      ),
    ).toEqual([{ id: 1 }]);
  });
});

describe("projectAllowedFields: short-circuit and shapes", () => {
  it("an undefined allow-list is unrestricted and returns a deep copy", () => {
    const input = [{ id: 1, nested: { a: 1 } }];
    const out = projectAllowedFields(input, policy({ fieldRules: {} }));

    expect(out).toEqual(input);
    expect(out[0].nested).not.toBe(input[0].nested);
  });

  it("an array containing a non-record leaves that entry as-is", () => {
    // projectAllowedFields is reachable directly (not only via the pipeline, which
    // classifies shapes first), so a mixed array must not throw.
    const out = projectAllowedFields(
      [{ id: 1, ssn: "x" }, 42] as unknown[],
      policy({ fieldRules: { allowedFields: ["id"] } }),
    );

    expect(out).toEqual([{ id: 1 }, 42]);
  });

  it("a single record is projected", () => {
    expect(
      projectAllowedFields(
        { id: 1, ssn: "x" },
        policy({ fieldRules: { allowedFields: ["id"] } }),
      ),
    ).toEqual({ id: 1 });
  });

  it("a scalar with an allow-list set passes through rather than throwing", () => {
    expect(
      projectAllowedFields("scalar", policy({ fieldRules: { allowedFields: ["id"] } })),
    ).toBe("scalar");
    expect(
      projectAllowedFields(null, policy({ fieldRules: { allowedFields: ["id"] } })),
    ).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// applyResultLimit -- both sides of the bound
// ---------------------------------------------------------------------------

describe("applyResultLimit: both sides of the bound", () => {
  it("no limits object at all leaves the list intact", () => {
    expect(applyResultLimit([1, 2, 3], policy())).toEqual([1, 2, 3]);
  });

  it("a limits object without maxResults leaves the list intact", () => {
    expect(applyResultLimit([1, 2, 3], policy(undefined, {}))).toEqual([1, 2, 3]);
  });

  it("a length exactly equal to maxResults is not truncated", () => {
    expect(applyResultLimit([1, 2], policy(undefined, { maxResults: 2 }))).toEqual([
      1, 2,
    ]);
  });

  it("maxResults 0 truncates to nothing", () => {
    // 0 is falsy; a truthiness check here would have ignored the limit entirely.
    expect(applyResultLimit([1, 2], policy(undefined, { maxResults: 0 }))).toEqual([]);
  });

  it("an empty list under a limit stays empty", () => {
    expect(applyResultLimit([], policy(undefined, { maxResults: 5 }))).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Relevance floor / size ceiling -- the non-record guard
// ---------------------------------------------------------------------------

describe("relevance floor and size ceiling: a NON-RECORD entry fails closed", () => {
  it("a scalar in the list is dropped when a floor or ceiling is set", () => {
    // A scalar has no score or size field, so its value cannot be established --
    // and the documented purpose of both limits is to stop unqualified records
    // surfacing, so an unevaluable entry must not slip through (spec §4 steps 3-4).
    const mixed = [{ score: 0.9, size: 10 }, "a string", 42, null, [1]] as unknown[];

    expect(
      applySimilarityFloor(mixed, policy(undefined, { minSimilarityScore: 0.5 })),
    ).toEqual([{ score: 0.9, size: 10 }]);
    expect(
      applyObjectSizeCeiling(mixed, policy(undefined, { maxObjectSizeBytes: 100 })),
    ).toEqual([{ score: 0.9, size: 10 }]);
  });

  it("a class instance is not a record, so it is dropped too", () => {
    // A class instance may carry a `score` accessor the walker cannot see, so
    // treating it as scored would be a false guarantee (spec §5).
    class Hit {
      score = 0.99;
    }
    expect(
      applySimilarityFloor([new Hit()] as unknown[], policy(undefined, { minSimilarityScore: 0.5 })),
    ).toEqual([]);
  });

  it("with neither limit set, non-records pass through untouched", () => {
    const mixed = ["a string", 42] as unknown[];
    expect(applySimilarityFloor(mixed, policy())).toBe(mixed);
    expect(applyObjectSizeCeiling(mixed, policy())).toBe(mixed);
  });
});

// ---------------------------------------------------------------------------
// Row filters -- every operator, both outcomes, and each type-guard exit
// ---------------------------------------------------------------------------

describe("row filters: no-op short-circuits", () => {
  it("absent rowFilters keeps every row", () => {
    expect(applyRowFilters([{ id: 1 }], policy({}))).toEqual([{ id: 1 }]);
  });

  it("an empty rowFilters array keeps every row", () => {
    expect(applyRowFilters([{ id: 1 }], policy({ rowFilters: [] }))).toEqual([
      { id: 1 },
    ]);
  });

  it("filters AND together: failing any one drops the row", () => {
    const data = [
      { id: 1, region: "us-east", status: "active" },
      { id: 2, region: "us-east", status: "deleted" },
      { id: 3, region: "eu-west", status: "active" },
    ];

    expect(
      rows(
        [
          { field: "region", operator: "equals", value: "us-east" },
          { field: "status", operator: "equals", value: "active" },
        ],
        data,
      ).map((r) => r.id),
    ).toEqual([1]);
  });
});

describe("row filters: equals / notEquals", () => {
  it("equals keeps a match and drops a non-match", () => {
    expect(rows([{ field: "a", operator: "equals", value: 1 }], [{ a: 1 }])).toHaveLength(
      1,
    );
    expect(rows([{ field: "a", operator: "equals", value: 1 }], [{ a: 2 }])).toEqual([]);
  });

  it("notEquals drops a match and keeps a non-match", () => {
    expect(
      rows([{ field: "a", operator: "notEquals", value: 1 }], [{ a: 1 }]),
    ).toEqual([]);
    expect(
      rows([{ field: "a", operator: "notEquals", value: 1 }], [{ a: 2 }]),
    ).toHaveLength(1);
  });

  it("neither conflates a boolean with a number, in either direction", () => {
    expect(rows([{ field: "a", operator: "equals", value: 1 }], [{ a: true }])).toEqual(
      [],
    );
    // notEquals must therefore say "not equal" -- the row is KEPT, because the
    // field is present and genuinely holds a different value.
    expect(
      rows([{ field: "a", operator: "notEquals", value: 1 }], [{ a: true }]),
    ).toHaveLength(1);
    expect(
      rows([{ field: "a", operator: "equals", value: true }], [{ a: 1 }]),
    ).toEqual([]);
  });

  it("two booleans still compare normally", () => {
    expect(
      rows([{ field: "a", operator: "equals", value: true }], [{ a: true }]),
    ).toHaveLength(1);
    expect(
      rows([{ field: "a", operator: "equals", value: false }], [{ a: true }]),
    ).toEqual([]);
  });

  it("an absent rf.value compares against undefined rather than matching anything", () => {
    expect(rows([{ field: "a", operator: "equals" }], [{ a: 1 }])).toEqual([]);
    expect(rows([{ field: "a", operator: "notEquals" }], [{ a: 1 }])).toHaveLength(1);
  });
});

describe("row filters: in / notIn", () => {
  it("in keeps a listed value and drops an unlisted one", () => {
    expect(
      rows([{ field: "a", operator: "in", values: [1, 2] }], [{ a: 2 }]),
    ).toHaveLength(1);
    expect(rows([{ field: "a", operator: "in", values: [1, 2] }], [{ a: 3 }])).toEqual(
      [],
    );
  });

  it("notIn drops a listed value and keeps an unlisted one", () => {
    expect(
      rows([{ field: "a", operator: "notIn", values: [1] }], [{ a: 1 }]),
    ).toEqual([]);
    expect(
      rows([{ field: "a", operator: "notIn", values: [1] }], [{ a: 2 }]),
    ).toHaveLength(1);
  });

  it("an absent values list makes `in` deny and `notIn` allow", () => {
    // `in` against nothing matches nothing; `notIn` nothing excludes nothing.
    expect(rows([{ field: "a", operator: "in" }], [{ a: 1 }])).toEqual([]);
    expect(rows([{ field: "a", operator: "notIn" }], [{ a: 1 }])).toHaveLength(1);
  });

  it("an empty values list behaves the same as an absent one", () => {
    expect(rows([{ field: "a", operator: "in", values: [] }], [{ a: 1 }])).toEqual([]);
    expect(
      rows([{ field: "a", operator: "notIn", values: [] }], [{ a: 1 }]),
    ).toHaveLength(1);
  });
});

describe("row filters: greaterThan / lessThan and every compareValues exit", () => {
  const gt = (value: unknown, field = "a") =>
    ({ field, operator: "greaterThan", value }) satisfies RowFilter;
  const lt = (value: unknown, field = "a") =>
    ({ field, operator: "lessThan", value }) satisfies RowFilter;

  it("numbers compare in both directions and at equality", () => {
    expect(rows([gt(30)], [{ a: 31 }])).toHaveLength(1);
    expect(rows([gt(30)], [{ a: 29 }])).toEqual([]);
    expect(rows([gt(30)], [{ a: 30 }])).toEqual([]); // strict
    expect(rows([lt(30)], [{ a: 29 }])).toHaveLength(1);
    expect(rows([lt(30)], [{ a: 31 }])).toEqual([]);
    expect(rows([lt(30)], [{ a: 30 }])).toEqual([]); // strict
  });

  it("strings compare lexicographically in both directions", () => {
    expect(rows([gt("m")], [{ a: "z" }])).toHaveLength(1);
    expect(rows([gt("m")], [{ a: "a" }])).toEqual([]);
    expect(rows([gt("m")], [{ a: "m" }])).toEqual([]);
    expect(rows([lt("m")], [{ a: "a" }])).toHaveLength(1);
    expect(rows([lt("m")], [{ a: "z" }])).toEqual([]);
  });

  it("Dates compare by instant in both directions", () => {
    const cutoff = new Date("2026-01-01T00:00:00Z");
    expect(rows([gt(cutoff)], [{ a: new Date("2026-06-01T00:00:00Z") }])).toHaveLength(1);
    expect(rows([gt(cutoff)], [{ a: new Date("2025-06-01T00:00:00Z") }])).toEqual([]);
    expect(rows([gt(cutoff)], [{ a: new Date(cutoff) }])).toEqual([]);
    expect(rows([lt(cutoff)], [{ a: new Date("2025-06-01T00:00:00Z") }])).toHaveLength(1);
  });

  it("an Invalid Date on either side is a non-match, never a throw", () => {
    const invalid = new Date("not-a-date");
    expect(rows([gt(new Date("2026-01-01T00:00:00Z"))], [{ a: invalid }])).toEqual([]);
    expect(rows([gt(invalid)], [{ a: new Date("2026-01-01T00:00:00Z") }])).toEqual([]);
    expect(rows([lt(invalid)], [{ a: invalid }])).toEqual([]);
  });

  it("NaN on either side is a non-match", () => {
    expect(rows([gt(30)], [{ a: Number.NaN }])).toEqual([]);
    expect(rows([gt(Number.NaN)], [{ a: 30 }])).toEqual([]);
    expect(rows([lt(Number.NaN)], [{ a: 30 }])).toEqual([]);
  });

  it("bigints compare in both directions and at equality", () => {
    expect(rows([gt(10n)], [{ a: 20n }])).toHaveLength(1);
    expect(rows([gt(10n)], [{ a: 5n }])).toEqual([]);
    expect(rows([gt(10n)], [{ a: 10n }])).toEqual([]);
    expect(rows([lt(10n)], [{ a: 5n }])).toHaveLength(1);
    expect(rows([lt(10n)], [{ a: 20n }])).toEqual([]);
  });

  it("MIXED types are non-comparable and drop the row, never throw", () => {
    // Fail closed: the policy author asked for a bound and we cannot prove it
    // holds (spec §7). A bigint/number pair also THROWS under a bare `>` in JS,
    // so this is the guard that keeps the whole result pass alive.
    const mixed: Array<[unknown, unknown]> = [
      ["notanumber", 30],
      [30, "notanumber"],
      [10n, 5],
      [5, 10n],
      [new Date(), 5],
      [5, new Date()],
      [true, 1],
      [{ nested: 1 }, 5],
      [[1, 2], 5],
    ];

    for (const [rowValue, filterValue] of mixed) {
      expect(() => rows([gt(filterValue)], [{ a: rowValue }])).not.toThrow();
      expect(
        rows([gt(filterValue)], [{ a: rowValue }]),
        `greaterThan ${String(rowValue)} vs ${String(filterValue)}`,
      ).toEqual([]);
      expect(rows([lt(filterValue)], [{ a: rowValue }])).toEqual([]);
    }
  });

  it("a stored null and an absent/null filter value are all non-matches", () => {
    expect(rows([gt(30)], [{ a: null }])).toEqual([]);
    expect(rows([lt(30)], [{ a: null }])).toEqual([]);
    expect(rows([gt(null)], [{ a: 30 }])).toEqual([]);
    expect(rows([lt(null)], [{ a: 30 }])).toEqual([]);
    expect(rows([{ field: "a", operator: "greaterThan" }], [{ a: 30 }])).toEqual([]);
    expect(rows([{ field: "a", operator: "lessThan" }], [{ a: 30 }])).toEqual([]);
  });
});

describe("row filters: contains / startsWith", () => {
  it("contains keeps a substring match and drops a non-match", () => {
    expect(
      rows([{ field: "a", operator: "contains", value: "ell" }], [{ a: "hello" }]),
    ).toHaveLength(1);
    expect(
      rows([{ field: "a", operator: "contains", value: "zzz" }], [{ a: "hello" }]),
    ).toEqual([]);
  });

  it("startsWith keeps a prefix match and drops a mid-string match", () => {
    expect(
      rows([{ field: "a", operator: "startsWith", value: "he" }], [{ a: "hello" }]),
    ).toHaveLength(1);
    expect(
      rows([{ field: "a", operator: "startsWith", value: "ell" }], [{ a: "hello" }]),
    ).toEqual([]);
  });

  it("both coerce non-strings rather than throwing", () => {
    expect(
      rows([{ field: "a", operator: "contains", value: 23 }], [{ a: 12345 }]),
    ).toHaveLength(1);
    expect(
      rows([{ field: "a", operator: "startsWith", value: 1 }], [{ a: 12345 }]),
    ).toHaveLength(1);
  });

  it("a stored null and an absent/null filter value are all non-matches", () => {
    // Without the null guards, String(null) would make "null".includes("ul") true
    // and a row with no value would satisfy a substring filter.
    expect(
      rows([{ field: "a", operator: "contains", value: "ul" }], [{ a: null }]),
    ).toEqual([]);
    expect(rows([{ field: "a", operator: "contains" }], [{ a: "hello" }])).toEqual([]);
    expect(
      rows([{ field: "a", operator: "contains", value: null }], [{ a: "hello" }]),
    ).toEqual([]);
    expect(
      rows([{ field: "a", operator: "startsWith", value: "nu" }], [{ a: null }]),
    ).toEqual([]);
    expect(rows([{ field: "a", operator: "startsWith" }], [{ a: "hello" }])).toEqual([]);
    expect(
      rows([{ field: "a", operator: "startsWith", value: null }], [{ a: "hello" }]),
    ).toEqual([]);
  });
});

describe("row filters: matches", () => {
  it("an anchored pattern matches the whole value only", () => {
    expect(
      rows([{ field: "a", operator: "matches", value: "hr" }], [{ a: "hr" }]),
    ).toHaveLength(1);
    expect(
      rows([{ field: "a", operator: "matches", value: "hr" }], [{ a: "hr_secret" }]),
    ).toEqual([]);
  });

  it("a stored null and an absent/null pattern are all non-matches", () => {
    expect(
      rows([{ field: "a", operator: "matches", value: ".*" }], [{ a: null }]),
    ).toEqual([]);
    expect(rows([{ field: "a", operator: "matches" }], [{ a: "x" }])).toEqual([]);
    expect(
      rows([{ field: "a", operator: "matches", value: null }], [{ a: "x" }]),
    ).toEqual([]);
  });

  it("a non-string value is coerced and matched", () => {
    expect(
      rows([{ field: "a", operator: "matches", value: "\\d+" }], [{ a: 12345 }]),
    ).toHaveLength(1);
  });

  it("a value exactly at the length bound is still evaluated", () => {
    // The bound is 4096; 4096 is allowed and 4097 is refused, so this pins the
    // boundary rather than only the far side of it.
    expect(
      rows(
        [{ field: "a", operator: "matches", value: "a*" }],
        [{ a: "a".repeat(4096) }],
      ),
    ).toHaveLength(1);
    expect(
      rows(
        [{ field: "a", operator: "matches", value: "a*" }],
        [{ a: "a".repeat(4097) }],
      ),
    ).toEqual([]);
  });

  it("a pattern exactly at the length bound is still compiled", () => {
    const atBound = "a".repeat(1024);
    expect(atBound.length).toBe(1024);
    expect(
      rows([{ field: "a", operator: "matches", value: atBound }], [{ a: atBound }]),
    ).toHaveLength(1);
    expect(
      rows(
        [{ field: "a", operator: "matches", value: `${atBound}a` }],
        [{ a: `${atBound}a` }],
      ),
    ).toEqual([]);
  });

  it("the compiled-pattern cache returns the same verdict on a second use", () => {
    // Compilation is cached, so the second evaluation takes the cache-hit branch.
    // A cache that returned a stale or wrong entry would silently change a policy
    // decision, so assert the verdict twice rather than just calling twice.
    const filter: RowFilter = { field: "a", operator: "matches", value: "cache-probe" };
    expect(rows([filter], [{ a: "cache-probe" }])).toHaveLength(1);
    expect(rows([filter], [{ a: "cache-probe" }])).toHaveLength(1);
    expect(rows([filter], [{ a: "other" }])).toEqual([]);
  });

  it("an invalid pattern is cached as a non-match and stays a non-match", () => {
    const filter: RowFilter = { field: "a", operator: "matches", value: "([unclosed" };
    expect(rows([filter], [{ a: "anything" }])).toEqual([]);
    expect(rows([filter], [{ a: "anything" }])).toEqual([]);
  });

  it("the cache is bounded and keeps evaluating correctly past its limit", () => {
    // A hostile policy stream must not grow the cache without limit; after the
    // clear, patterns must still compile and match correctly rather than the
    // eviction turning into a silent non-match for a valid rule.
    for (let i = 0; i < 300; i++) {
      const value = `bounded-${i}`;
      expect(
        rows([{ field: "a", operator: "matches", value }], [{ a: value }]),
      ).toHaveLength(1);
    }
    expect(
      rows([{ field: "a", operator: "matches", value: "bounded-0" }], [{ a: "bounded-0" }]),
    ).toHaveLength(1);
  });
});

describe("row filters: unknown operator and field lookup", () => {
  it("an unrecognized operator drops the row (spec §7: fail closed)", () => {
    // A typo or an operator from a newer schema version must not become
    // "no restriction" -- that is the same failure mode as an unknown maskType.
    for (const operator of ["regex", "EQUALS", "", "notEqual", "gte"]) {
      expect(
        rows([{ field: "a", operator, value: 1 }], [{ a: 1 }]),
        `operator ${operator} must not silently pass the row`,
      ).toEqual([]);
    }
  });

  it("an exact key wins over a fuzzy match", () => {
    const data = [{ region: "us-east", "patients.region": "eu-west" }];
    expect(
      rows([{ field: "region", operator: "equals", value: "us-east" }], data),
    ).toHaveLength(1);
  });

  it("a dotted filter field resolves against a bare key, and vice versa", () => {
    expect(
      rows(
        [{ field: "patients.region", operator: "equals", value: "us-east" }],
        [{ region: "us-east" }],
      ),
    ).toHaveLength(1);
    expect(
      rows(
        [{ field: "region", operator: "equals", value: "us-east" }],
        [{ "patients.region": "us-east" }],
      ),
    ).toHaveLength(1);
  });

  it("field lookup is case-insensitive", () => {
    expect(
      rows([{ field: "region", operator: "equals", value: "us-east" }], [{ REGION: "us-east" }]),
    ).toHaveLength(1);
  });

  it("a genuinely absent field drops the row for EVERY operator", () => {
    // The original notEquals/notIn fail-open (spec §7).
    const operators: RowFilter[] = [
      { field: "missing", operator: "equals", value: 1 },
      { field: "missing", operator: "notEquals", value: 1 },
      { field: "missing", operator: "in", values: [1] },
      { field: "missing", operator: "notIn", values: [1] },
      { field: "missing", operator: "greaterThan", value: 1 },
      { field: "missing", operator: "lessThan", value: 1 },
      { field: "missing", operator: "contains", value: "1" },
      { field: "missing", operator: "startsWith", value: "1" },
      { field: "missing", operator: "matches", value: ".*" },
      { field: "missing", operator: "unknown-op", value: 1 },
    ];

    for (const filter of operators) {
      expect(rows([filter], [{ id: 1 }]), `operator ${filter.operator}`).toEqual([]);
    }
  });

  it("a key holding undefined is present, so it is compared not dropped", () => {
    // hasOwnProperty distinguishes "present but undefined" from absent.
    expect(
      rows([{ field: "a", operator: "notEquals", value: 1 }], [{ a: undefined }]),
    ).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// filterByTags -- every combination of the two lists
// ---------------------------------------------------------------------------

describe("filterByTags: every combination of allow/deny", () => {
  const tagged = [
    { id: "public", tags: ["public"] },
    { id: "confidential", tags: ["confidential"] },
    { id: "both", tags: ["public", "confidential"] },
    { id: "untagged" },
    { id: "empty-tags", tags: [] },
    // A scalar in the tags slot is ONE tag, not a malformed list: providers emit
    // both `{tags: "secret"}` and `{tags: ["secret"]}` and connector spec §7
    // requires the two to behave identically.
    { id: "scalar-tags", tags: "public" },
  ];

  const ids = (tagRules: Record<string, string[]> | undefined) =>
    filterByTags(tagged, policy(tagRules === undefined ? {} : { tagRules })).map(
      (r) => r.id,
    );

  it("absent tagRules keeps everything", () => {
    expect(ids(undefined)).toEqual(tagged.map((r) => r.id));
  });

  it("an empty tagRules object keeps everything", () => {
    expect(filterByTags(tagged, policy({ tagRules: {} }))).toHaveLength(tagged.length);
  });

  it("a denylist drops only carriers and keeps untagged records", () => {
    expect(ids({ deniedTags: ["confidential"] })).toEqual([
      "public",
      "untagged",
      "empty-tags",
      "scalar-tags",
    ]);
  });

  it("an EMPTY denylist denies nothing", () => {
    expect(ids({ deniedTags: [] })).toEqual(tagged.map((r) => r.id));
  });

  it("an allow-list drops untagged and empty-tagged records", () => {
    // No tag means no proof of allowance (spec §4). "scalar-tags" DOES carry a tag
    // -- the scalar "public" is a one-element tag list per connector spec §7 -- so
    // it satisfies the allow-list.
    expect(ids({ allowedTags: ["public"] })).toEqual([
      "public",
      "both",
      "scalar-tags",
    ]);
  });

  it("an EMPTY allow-list denies every record (spec §3)", () => {
    expect(ids({ allowedTags: [] })).toEqual([]);
  });

  it("denied beats allowed when a record carries both", () => {
    expect(ids({ allowedTags: ["public"], deniedTags: ["confidential"] })).toEqual([
      "public",
      "scalar-tags",
    ]);
  });

  it("a scalar tags value is ONE tag, not an untagged record", () => {
    // Connector spec §7: "A scalar value counts as a single tag." Treating
    // `tags: "secret"` as untagged is the fail-open half of the KB control -- a
    // denylist stopped dropping the record, because classification IS tags and this
    // is one of the shapes providers emit. Previously this test asserted the
    // opposite and was corrected against §7.
    const only = [{ id: 1, tags: "public" }];
    expect(filterByTags(only, policy({ tagRules: { allowedTags: ["public"] } }))).toEqual(
      only,
    );
    expect(filterByTags(only, policy({ tagRules: { deniedTags: ["public"] } }))).toEqual(
      [],
    );
  });

  it("a non-string tags value contributes no tag and fails closed", () => {
    // `allowedTags`/`deniedTags` hold strings, so a number could only match after a
    // stringification whose result differs per language. It therefore contributes no
    // tag: an allow-list drops the record, a denylist has nothing to match.
    const only = [{ id: 1, tags: 42 }];
    expect(filterByTags(only, policy({ tagRules: { allowedTags: ["42"] } }))).toEqual([]);
    expect(filterByTags(only, policy({ tagRules: { deniedTags: ["42"] } }))).toEqual(only);
  });

  it("an empty result list stays empty", () => {
    expect(filterByTags([], policy({ tagRules: { allowedTags: ["public"] } }))).toEqual(
      [],
    );
  });
});

// ---------------------------------------------------------------------------
// Result-shape classification -- every branch of both functions
// ---------------------------------------------------------------------------

describe("classifyResultShape / describeResultShape: every branch", () => {
  it("classifies records, arrays of records, and an empty array", () => {
    expect(classifyResultShape({ id: 1 })).toBe("record");
    expect(classifyResultShape(Object.create(null) as object)).toBe("record");
    expect(classifyResultShape([{ id: 1 }])).toBe("records");
    expect(classifyResultShape([])).toBe("records");
  });

  it("refuses every non-record shape", () => {
    const unenforceable: unknown[] = [
      null,
      undefined,
      "s",
      42,
      true,
      0n,
      Symbol("s"),
      new Date(),
      new Map(),
      Buffer.from("x"),
      new (class Poco {})(),
      (function* () {})(),
      [1],
      [{ a: 1 }, "x"],
      [null],
      [[{ a: 1 }]],
    ];

    for (const value of unenforceable) {
      expect(classifyResultShape(value), String(value)).toBeUndefined();
    }
  });

  it("describes null and undefined by name", () => {
    expect(describeResultShape(null)).toBe("null");
    expect(describeResultShape(undefined)).toBe("undefined");
  });

  it("describes an all-records array and an empty array as records", () => {
    expect(describeResultShape([{ a: 1 }])).toBe("array of records");
    expect(describeResultShape([])).toBe("array of records");
  });

  it("names, de-duplicates, and sorts the offenders in a mixed array", () => {
    expect(describeResultShape([1, "x", 2])).toBe(
      "array containing number, string (not records)",
    );
    expect(describeResultShape([null, null])).toBe(
      "array containing null (not records)",
    );
    expect(describeResultShape([[1]])).toBe("array containing array (not records)");
  });

  it("names a class instance and a null-prototype object in an array", () => {
    class Poco {}
    expect(describeResultShape([new Poco()])).toBe(
      "array containing Poco (not records)",
    );
    // Object.create(null) has no constructor, so the "object" fallback applies --
    // but it also IS a record, so it is only reachable as a nested value.
    expect(describeResultShape([[Object.create(null)]])).toContain("array");
  });

  it("describes a record and each scalar type", () => {
    expect(describeResultShape({ id: 1 })).toBe("object (record)");
    expect(describeResultShape("s")).toBe("string (not a record or array of records)");
    expect(describeResultShape(42)).toBe("number (not a record or array of records)");
    expect(describeResultShape(true)).toBe("boolean (not a record or array of records)");
    expect(describeResultShape(Symbol("s"))).toBe(
      "symbol (not a record or array of records)",
    );
    expect(describeResultShape(new Date())).toBe(
      "Date (not a record or array of records)",
    );
  });
});

// ---------------------------------------------------------------------------
// applyResultPipeline -- the single-record vs array exits
// ---------------------------------------------------------------------------

describe("applyResultPipeline: shape-dependent exits", () => {
  it("a surviving single record is returned as a record, not wrapped", () => {
    expect(applyResultPipeline({ id: 1 }, policy({}))).toEqual({ id: 1 });
  });

  it("a dropped single record is null, not an empty object", () => {
    // Returning {} would imply the row existed but had no fields.
    expect(
      applyResultPipeline(
        { id: 1, region: "eu" },
        policy({ rowFilters: [{ field: "region", operator: "equals", value: "us" }] }),
      ),
    ).toBeNull();
  });

  it("an array result stays an array even when emptied", () => {
    expect(
      applyResultPipeline(
        [{ region: "eu" }],
        policy({ rowFilters: [{ field: "region", operator: "equals", value: "us" }] }),
      ),
    ).toEqual([]);
  });

  it("a single record is subject to maxResults like any other", () => {
    expect(applyResultPipeline({ id: 1 }, policy({}, { maxResults: 0 }))).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// validateEndpoint -- both sides of all four guards
// ---------------------------------------------------------------------------

describe("validateEndpoint: both outcomes of each guard", () => {
  it("denies when canQuery is false regardless of the endpoint rules", () => {
    expect(
      validateEndpoint(
        "/x",
        "GET",
        policy({ endpointRules: { allowedEndpoints: ["/x"] } }, undefined, {
          canQuery: false,
        }),
      ),
    ).toEqual({ allowed: false, reason: "query not permitted" });
  });

  it("allows when there are no endpointRules, and when they are empty", () => {
    expect(validateEndpoint("/x", "GET", policy())).toEqual({ allowed: true });
    expect(validateEndpoint("/x", "GET", policy({}))).toEqual({ allowed: true });
    expect(validateEndpoint("/x", "GET", policy({ endpointRules: {} }))).toEqual({
      allowed: true,
    });
  });

  it("hidden wins over an allow-list naming the same endpoint", () => {
    expect(
      validateEndpoint(
        "/admin/audit",
        "GET",
        policy({
          endpointRules: {
            allowedEndpoints: ["/admin/*"],
            hiddenEndpoints: ["/admin/*"],
          },
        }),
      ),
    ).toEqual({ allowed: false, reason: "endpoint is hidden" });
  });

  it("a non-matching hiddenEndpoints entry does not deny", () => {
    expect(
      validateEndpoint("/patients", "GET", policy({ endpointRules: { hiddenEndpoints: ["/admin/*"] } })),
    ).toEqual({ allowed: true });
  });

  it("an empty hiddenEndpoints hides nothing; an empty allowedEndpoints denies all", () => {
    expect(
      validateEndpoint("/x", "GET", policy({ endpointRules: { hiddenEndpoints: [] } })),
    ).toEqual({ allowed: true });
    expect(
      validateEndpoint("/x", "GET", policy({ endpointRules: { allowedEndpoints: [] } })),
    ).toEqual({ allowed: false, reason: "endpoint not in allowed set" });
  });

  it("an allowed path with a disallowed method is denied on the method", () => {
    expect(
      validateEndpoint(
        "/patients",
        "DELETE",
        policy({
          endpointRules: { allowedEndpoints: ["/patients"], allowedMethods: ["GET"] },
        }),
      ),
    ).toEqual({ allowed: false, reason: "method not allowed" });
  });

  it("method comparison upper-cases the caller's method", () => {
    expect(
      validateEndpoint("/x", "get", policy({ endpointRules: { allowedMethods: ["GET"] } })),
    ).toEqual({ allowed: true });
  });

  it("an empty allowedMethods denies every method", () => {
    expect(
      validateEndpoint("/x", "GET", policy({ endpointRules: { allowedMethods: [] } })),
    ).toEqual({ allowed: false, reason: "method not allowed" });
  });

  it("passes when path and method both match", () => {
    expect(
      validateEndpoint(
        "/patients/123",
        "GET",
        policy({
          endpointRules: {
            allowedEndpoints: ["/patients/*"],
            hiddenEndpoints: ["/admin/*"],
            allowedMethods: ["GET", "HEAD"],
          },
        }),
      ),
    ).toEqual({ allowed: true });
  });

  // -- Spec §9: write protection. Both controls previously failed OPEN. --

  it("an omitted allowedMethods defaults to the read methods, not to unrestricted", () => {
    // The schema documents the default: "If omitted, defaults to read-only methods:
    // GET, HEAD, OPTIONS". Treating omitted as unrestricted told a policy author
    // writes were already blocked while permitting DELETE/POST/PUT/PATCH.
    const p = policy({ endpointRules: { allowedEndpoints: ["/api/*"] } }, undefined, {
      canQuery: true,
      readOnly: false,
    });

    for (const method of ["GET", "HEAD", "OPTIONS"]) {
      expect(validateEndpoint("/api/x", method, p)).toEqual({ allowed: true });
    }
    for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
      expect(validateEndpoint("/api/x", method, p)).toEqual({
        allowed: false,
        reason: "method not allowed",
      });
    }
  });

  it("readOnly denies every write method it was explicitly granted", () => {
    // readOnly was merged (OR-folded) and then never consulted by any decision, so
    // an administrator could set it, watch it survive resolution, and still have
    // DELETE permitted. readOnly is a ceiling: allowedMethods cannot lift it.
    const p = policy({
      endpointRules: { allowedMethods: ["GET", "POST", "PUT", "PATCH", "DELETE"] },
    });

    for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
      expect(validateEndpoint("/api/x", method, p)).toEqual({
        allowed: false,
        reason: "method not allowed on a read-only policy",
      });
    }
  });

  it("readOnly still permits every read method", () => {
    const p = policy({
      endpointRules: { allowedMethods: ["GET", "HEAD", "OPTIONS", "DELETE"] },
    });

    for (const method of ["GET", "HEAD", "OPTIONS"]) {
      expect(validateEndpoint("/api/x", method, p)).toEqual({ allowed: true });
    }
  });

  it("an absent readOnly takes its restrictive schema default of true", () => {
    // Spec §8: absent booleans take their schema default BEFORE folding. Excluding
    // an absent readOnly from the decision would invert it, letting a policy silent
    // on the flag permit writes.
    const p = policy({ endpointRules: { allowedMethods: ["POST"] } }, undefined, {
      canQuery: true,
    });

    expect(validateEndpoint("/api/x", "POST", p)).toEqual({
      allowed: false,
      reason: "method not allowed on a read-only policy",
    });
  });

  it("an allowedMethods denial keeps its own reason, distinct from the readOnly gate", () => {
    // The two reasons must be distinguishable so an integrator can tell which rule
    // denied them: widening allowedMethods fixes one and not the other.
    const p = policy({ endpointRules: { allowedMethods: ["GET"] } });

    expect(validateEndpoint("/api/x", "DELETE", p).reason).toBe("method not allowed");
  });

  it("an empty allowedMethods denies everything including GET, even when writable", () => {
    // §3: [] is deny-all for an allow-list, and that is unaffected by readOnly.
    const p = policy({ endpointRules: { allowedMethods: [] } }, undefined, {
      canQuery: true,
      readOnly: false,
    });

    for (const method of ["GET", "HEAD", "OPTIONS", "POST", "DELETE"]) {
      expect(validateEndpoint("/api/x", method, p)).toEqual({
        allowed: false,
        reason: "method not allowed",
      });
    }
  });

  it("method comparison is case-insensitive on both sides of the pair", () => {
    const writable = policy(
      { endpointRules: { allowedMethods: ["delete"] } },
      undefined,
      { canQuery: true, readOnly: false },
    );

    // Lower-case policy entry, upper-case request, and the reverse.
    expect(validateEndpoint("/api/x", "DELETE", writable)).toEqual({ allowed: true });
    expect(validateEndpoint("/api/x", "delete", writable)).toEqual({ allowed: true });
    // The readOnly ceiling is likewise case-insensitive: lower-case "delete" must
    // not slip past a read-method set spelled in upper case.
    expect(
      validateEndpoint("/api/x", "delete", policy({ endpointRules: { allowedMethods: ["delete"] } })),
    ).toEqual({ allowed: false, reason: "method not allowed on a read-only policy" });
  });

  it("an absent path constraint does not make the method unconstrained", () => {
    // With no endpointRules at all, the method still defaults to the read methods:
    // the path being unconstrained is not a grant of DELETE.
    const p = policy(undefined, undefined, {
      canQuery: true,
      readOnly: false,
    });

    expect(validateEndpoint("/anything", "GET", p)).toEqual({ allowed: true });
    expect(validateEndpoint("/anything", "DELETE", p)).toEqual({
      allowed: false,
      reason: "method not allowed",
    });
  });
});

// ---------------------------------------------------------------------------
// Prototype-pollution guards on every walker
// ---------------------------------------------------------------------------

describe("prototype-pollution guards on every walker", () => {
  // JSON.parse is the only way to get a real own "__proto__" key, which is
  // exactly how such a key arrives in practice: from a parsed response body.
  const hostile = () =>
    JSON.parse('{"id":1,"__proto__":{"polluted":"yes"},"constructor":{"x":1},"ssn":"s"}');

  it("masking, stripping, and projecting all refuse to walk dangerous keys", () => {
    const maskRules = policy({
      fieldRules: {
        maskedFields: [
          { field: "__proto__", maskType: "redact" },
          { field: "constructor", maskType: "redact" },
          { field: "prototype", maskType: "redact" },
        ],
      },
    });

    expect(() => applyFieldMasking(hostile(), maskRules)).not.toThrow();
    expect(() =>
      stripHiddenFields([hostile()], policy({ fieldRules: { hiddenFields: ["__proto__"] } })),
    ).not.toThrow();
    expect(() =>
      projectAllowedFields([hostile()], policy({ fieldRules: { allowedFields: ["*"] } })),
    ).not.toThrow();

    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(Object.prototype).not.toHaveProperty("polluted");
    expect(({} as Record<string, unknown>).constructor).toBe(Object);
  });

  it("a dangerous key is dropped from the projection rather than copied", () => {
    const out = projectAllowedFields(
      [hostile()],
      policy({ fieldRules: { allowedFields: ["*"] } }),
    ) as Array<Record<string, unknown>>;

    expect(Object.keys(out[0])).toEqual(["id", "ssn"]);
  });

  it("the pipeline as a whole survives a hostile body and still enforces", () => {
    const out = applyResultPipeline(
      [hostile()],
      policy({ fieldRules: { hiddenFields: ["ssn"] } }),
    ) as Array<Record<string, unknown>>;

    expect("ssn" in out[0]).toBe(false);
    expect(Object.keys(out[0])).not.toContain("__proto__");
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it("a row filter naming a dangerous key does not reach the prototype", () => {
    expect(() =>
      rows([{ field: "__proto__", operator: "equals", value: "x" }], [hostile()]),
    ).not.toThrow();
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Leaf-value preservation while cloning
// ---------------------------------------------------------------------------

describe("cloning preserves data-carrying leaf values", () => {
  it("Date, Map, and Buffer survive as themselves rather than becoming {}", () => {
    // pg returns Date for DATE/TIMESTAMP columns; flattening them into {} during
    // the clone would corrupt every timestamp the pipeline touches.
    const date = new Date("1980-03-12T00:00:00Z");
    const map = new Map([["k", "v"]]);
    const buffer = Buffer.from("bytes");

    const out = applyResultPipeline(
      [{ id: 1, date, map, buffer, ssn: "x" }],
      policy({ fieldRules: { hiddenFields: ["ssn"] } }),
    ) as Array<Record<string, unknown>>;

    expect(out[0].date).toBeInstanceOf(Date);
    expect((out[0].date as Date).toISOString()).toBe(date.toISOString());
    expect(out[0].map).toBeInstanceOf(Map);
    expect((out[0].map as Map<string, string>).get("k")).toBe("v");
    expect(Buffer.isBuffer(out[0].buffer)).toBe(true);
  });

  it("a nested array of scalars is cloned, not shared", () => {
    const input = [{ id: 1, tags: ["a", "b"], ssn: "x" }];
    const out = stripHiddenFields(input, policy({ fieldRules: { hiddenFields: ["ssn"] } }));

    expect(out[0].tags).toEqual(["a", "b"]);
    expect(out[0].tags).not.toBe(input[0].tags);
  });
});
