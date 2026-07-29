/**
 * Coverage for the exported helpers in types.ts.
 *
 * `createDenyAllPolicy` is the value every fail-closed path is supposed to fall
 * back to, so an error in it would quietly grant access at exactly the moment
 * something else already went wrong. `maskRestrictiveness` decides which of two
 * competing masks survives a merge.
 */

import { readFileSync } from "node:fs";
import { resolve as resolvePath } from "node:path";
import { describe, expect, it } from "vitest";
import {
  AssigneeType,
  createDenyAllPolicy,
  FilterOperator,
  maskRestrictiveness,
  MASK_RESTRICTIVENESS,
  MaskType,
  SigningAlgorithm,
  UNKNOWN_MASK_RESTRICTIVENESS,
} from "../src/types.js";
import {
  applyResultPipeline,
  applyRowFilters,
  validateAccess,
  validateEndpoint,
} from "../src/enforcement.js";
import { validateExpiry } from "../src/context.js";
import { resolve } from "../src/resolution.js";
import type { EffectivePolicy, PolicyAssignment, PolicyDefinition, RowFilter } from "../src/types.js";

describe("createDenyAllPolicy", () => {
  it("carries the caller's identity and denies every permission", () => {
    const policy = createDenyAllPolicy("user-001", "tenant-001", "db:production:x");

    expect(policy.userId).toBe("user-001");
    expect(policy.tenantId).toBe("tenant-001");
    expect(policy.sourceConnectionId).toBe("db:production:x");
    expect(policy.version).toBe("1.0");
    expect(policy.permissions).toEqual({
      canQuery: false,
      canExport: false,
      readOnly: true,
    });
    expect(policy.sourceProfiles).toEqual([]);
    expect(policy.integrity).toEqual({ algorithm: "none", signature: "" });
  });

  it("is already expired, so it cannot be replayed as a valid grant", () => {
    // resolvedAt === expiresAt === now, and the expiry comparison is `<=`, so a
    // deny-all policy is expired the instant it is created.
    const policy = createDenyAllPolicy("u", "t", "s");
    expect(policy.expiresAt).toBe(policy.resolvedAt);
    expect(
      validateExpiry({
        effectivePolicy: policy,
        resolvedAt: policy.resolvedAt,
        expiresAt: policy.expiresAt,
      }),
    ).toBe("security context expired");
  });

  it("actually denies through the enforcement entry points", () => {
    // The point of the helper is the DECISION it produces, not its field values.
    const policy = createDenyAllPolicy("u", "t", "s");

    expect(validateAccess("patients", policy)).toEqual({
      allowed: false,
      reason: "query not permitted",
    });
    expect(validateEndpoint("/patients", "GET", policy)).toEqual({
      allowed: false,
      reason: "query not permitted",
    });
  });

  it("sets no objectRules or limits, so nothing can be mistaken for a grant", () => {
    const policy = createDenyAllPolicy("u", "t", "s");
    expect(policy.objectRules).toBeUndefined();
    expect(policy.limits).toBeUndefined();
  });

  it("still runs the result pipeline without throwing if a caller reaches it", () => {
    // canQuery is checked before execution, so the pipeline should never see a
    // result under a deny-all policy -- but if a wrapper calls it anyway, it must
    // behave rather than crash.
    const policy = createDenyAllPolicy("u", "t", "s");
    expect(applyResultPipeline([{ id: 1 }], policy)).toEqual([{ id: 1 }]);
  });

  it("returns a fresh object each call", () => {
    const first = createDenyAllPolicy("a", "t", "s");
    const second = createDenyAllPolicy("b", "t", "s");
    expect(first).not.toBe(second);
    expect(first.userId).toBe("a");
  });
});

describe("maskRestrictiveness", () => {
  it("ranks every known type by how little it discloses", () => {
    expect(maskRestrictiveness(MaskType.Partial)).toBe(1);
    expect(maskRestrictiveness(MaskType.Hash)).toBe(2);
    expect(maskRestrictiveness(MaskType.Full)).toBe(3);
    expect(maskRestrictiveness(MaskType.Redact)).toBe(4);
    expect(maskRestrictiveness(MaskType.Null)).toBe(5);
  });

  it("ranks anything unrecognized above every known type", () => {
    // So a typo or a newer-schema type can never be downgraded into a weaker known
    // one during a merge (spec §6).
    for (const unknown of ["tokenize-v2", "", "REDACT", "Null", "hash "]) {
      expect(maskRestrictiveness(unknown), unknown).toBe(UNKNOWN_MASK_RESTRICTIVENESS);
      expect(maskRestrictiveness(unknown)).toBeGreaterThan(
        Math.max(...Object.values(MASK_RESTRICTIVENESS)),
      );
    }
  });

  it("the exported table and the unknown rank stay in step", () => {
    expect(UNKNOWN_MASK_RESTRICTIVENESS).toBe(
      Math.max(...Object.values(MASK_RESTRICTIVENESS)) + 1,
    );
  });

  it("the MaskType enum values match the table's keys", () => {
    // A drift here would make a legitimate enum value rank as "unknown".
    for (const value of Object.values(MaskType)) {
      expect(MASK_RESTRICTIVENESS[value], value).toBeDefined();
      expect(maskRestrictiveness(value)).toBeLessThan(UNKNOWN_MASK_RESTRICTIVENESS);
    }
  });
});

// ---------------------------------------------------------------------------
// The exported enums are wire values, so their spellings are load-bearing
// ---------------------------------------------------------------------------

function policy(objectRules?: EffectivePolicy["objectRules"]): EffectivePolicy {
  return {
    version: "1.0",
    userId: "user-001",
    tenantId: "tenant-001",
    sourceConnectionId: "db:production:x",
    resolvedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    sourceProfiles: [],
    permissions: { canQuery: true, canExport: false, readOnly: true },
    ...(objectRules !== undefined ? { objectRules } : {}),
    integrity: { algorithm: "none", signature: "" },
  };
}

describe("FilterOperator: every member is an operator the engine implements", () => {
  it("no enum member falls through to the unknown-operator default", () => {
    // The enum is the public spelling of the wire format, so a member the switch in
    // rowPassesFilter does not handle would silently drop every row -- a mismatch
    // between what the API advertises and what enforcement can evaluate. Each case
    // below is a row that SATISFIES its filter, so the unknown-operator default
    // (which returns false and drops the row) is detectable as a failure.
    const satisfying: Array<[FilterOperator, RowFilter, Record<string, unknown>]> = [
      [FilterOperator.Equals, { field: "f", operator: FilterOperator.Equals, value: "x" }, { f: "x" }],
      [FilterOperator.NotEquals, { field: "f", operator: FilterOperator.NotEquals, value: "x" }, { f: "y" }],
      [FilterOperator.In, { field: "f", operator: FilterOperator.In, values: ["x"] }, { f: "x" }],
      [FilterOperator.NotIn, { field: "f", operator: FilterOperator.NotIn, values: ["x"] }, { f: "y" }],
      [FilterOperator.GreaterThan, { field: "f", operator: FilterOperator.GreaterThan, value: 10 }, { f: 50 }],
      [FilterOperator.LessThan, { field: "f", operator: FilterOperator.LessThan, value: 100 }, { f: 50 }],
      [FilterOperator.Contains, { field: "f", operator: FilterOperator.Contains, value: "el" }, { f: "hello" }],
      [FilterOperator.StartsWith, { field: "f", operator: FilterOperator.StartsWith, value: "he" }, { f: "hello" }],
      [FilterOperator.Matches, { field: "f", operator: FilterOperator.Matches, value: "h.*o" }, { f: "hello" }],
      [FilterOperator.GreaterThanOrEqual, { field: "f", operator: FilterOperator.GreaterThanOrEqual, value: 50 }, { f: 50 }],
      [FilterOperator.LessThanOrEqual, { field: "f", operator: FilterOperator.LessThanOrEqual, value: 50 }, { f: 50 }],
      [FilterOperator.Like, { field: "f", operator: FilterOperator.Like, value: "he%" }, { f: "hello" }],
      [FilterOperator.NotLike, { field: "f", operator: FilterOperator.NotLike, value: "zz%" }, { f: "hello" }],
      [FilterOperator.IsNull, { field: "f", operator: FilterOperator.IsNull }, { f: null }],
      [FilterOperator.IsNotNull, { field: "f", operator: FilterOperator.IsNotNull }, { f: "hello" }],
      [FilterOperator.Between, { field: "f", operator: FilterOperator.Between, values: [1, 100] }, { f: 50 }],
    ];

    // Every enum member is covered, so adding one without handling it fails here.
    expect(satisfying.map(([op]) => op).sort()).toEqual(Object.values(FilterOperator).sort());

    for (const [operator, filter, row] of satisfying) {
      expect(
        applyRowFilters([row], policy({ rowFilters: [filter] })),
        `operator ${operator} must keep a row that satisfies it`,
      ).toEqual([row]);
    }
  });

  it("each member also DROPS a row that violates it", () => {
    // The complementary side: an operator that always returned true would pass the
    // test above while enforcing nothing.
    const violating: Array<[FilterOperator, RowFilter, Record<string, unknown>]> = [
      [FilterOperator.Equals, { field: "f", operator: FilterOperator.Equals, value: "x" }, { f: "y" }],
      [FilterOperator.NotEquals, { field: "f", operator: FilterOperator.NotEquals, value: "x" }, { f: "x" }],
      [FilterOperator.In, { field: "f", operator: FilterOperator.In, values: ["x"] }, { f: "y" }],
      [FilterOperator.NotIn, { field: "f", operator: FilterOperator.NotIn, values: ["x"] }, { f: "x" }],
      [FilterOperator.GreaterThan, { field: "f", operator: FilterOperator.GreaterThan, value: 10 }, { f: 5 }],
      [FilterOperator.LessThan, { field: "f", operator: FilterOperator.LessThan, value: 10 }, { f: 50 }],
      [FilterOperator.Contains, { field: "f", operator: FilterOperator.Contains, value: "zz" }, { f: "hello" }],
      [FilterOperator.StartsWith, { field: "f", operator: FilterOperator.StartsWith, value: "zz" }, { f: "hello" }],
      [FilterOperator.Matches, { field: "f", operator: FilterOperator.Matches, value: "z.*z" }, { f: "hello" }],
      [FilterOperator.GreaterThanOrEqual, { field: "f", operator: FilterOperator.GreaterThanOrEqual, value: 50 }, { f: 49 }],
      [FilterOperator.LessThanOrEqual, { field: "f", operator: FilterOperator.LessThanOrEqual, value: 50 }, { f: 51 }],
      [FilterOperator.Like, { field: "f", operator: FilterOperator.Like, value: "zz%" }, { f: "hello" }],
      [FilterOperator.NotLike, { field: "f", operator: FilterOperator.NotLike, value: "he%" }, { f: "hello" }],
      [FilterOperator.IsNull, { field: "f", operator: FilterOperator.IsNull }, { f: "hello" }],
      [FilterOperator.IsNotNull, { field: "f", operator: FilterOperator.IsNotNull }, { f: null }],
      [FilterOperator.Between, { field: "f", operator: FilterOperator.Between, values: [1, 10] }, { f: 50 }],
    ];

    // The violating table must also cover every member: an operator present only in
    // the satisfying table could be implemented as "always true" and pass.
    expect([...new Set(violating.map(([op]) => op))].sort()).toEqual(
      Object.values(FilterOperator).sort(),
    );

    for (const [operator, filter, row] of violating) {
      expect(
        applyRowFilters([row], policy({ rowFilters: [filter] })),
        `operator ${operator} must drop a row that violates it`,
      ).toEqual([]);
    }
  });

  it("the enum's string values are the camelCase wire spellings", () => {
    // A renamed value would silently stop matching policies already in the store.
    expect(FilterOperator.Equals).toBe("equals");
    expect(FilterOperator.NotEquals).toBe("notEquals");
    expect(FilterOperator.In).toBe("in");
    expect(FilterOperator.NotIn).toBe("notIn");
    expect(FilterOperator.GreaterThan).toBe("greaterThan");
    expect(FilterOperator.LessThan).toBe("lessThan");
    expect(FilterOperator.Contains).toBe("contains");
    expect(FilterOperator.StartsWith).toBe("startsWith");
    expect(FilterOperator.Matches).toBe("matches");
    expect(FilterOperator.GreaterThanOrEqual).toBe("greaterThanOrEqual");
    expect(FilterOperator.LessThanOrEqual).toBe("lessThanOrEqual");
    expect(FilterOperator.Like).toBe("like");
    expect(FilterOperator.NotLike).toBe("notLike");
    expect(FilterOperator.IsNull).toBe("isNull");
    expect(FilterOperator.IsNotNull).toBe("isNotNull");
    expect(FilterOperator.Between).toBe("between");
  });

  it("the enum matches the shared policy schema's operator enum exactly", () => {
    // The divergence this pins: the schema was widened to 16 operators ahead of the
    // implementations, so a schema-VALID policy using `between` passed signature
    // verification and then hit the unknown-operator default -- dropping every row
    // in TypeScript while .NET enforced the filter correctly. Reading the schema
    // rather than restating the list means the two cannot drift again silently.
    //
    // The full five-enum conformance suite -- MaskType, AssigneeType,
    // SigningAlgorithm and mask `parameters.algorithm` alongside this one, each in
    // both directions -- lives in `schema-conformance.test.ts`, held in the same
    // shape as its Python and .NET counterparts. This assertion is kept here
    // because the tests above establish that every member is *enforceable*, and the
    // pairing of "enforceable" with "matches the schema" is what makes either
    // meaningful: an enum that matched the schema but fell through the switch, or
    // one that handled every member of a list the schema no longer agreed with,
    // would each pass half of this file.
    const schemaPath = resolvePath(
      __dirname,
      "..","..","..","..","..",
      "schema","v1.0","policy-definition.schema.json",
    );
    const schema = JSON.parse(readFileSync(schemaPath, "utf8"));
    const schemaOperators: string[] =
      schema.$defs.filterRule.properties.operator.enum;

    expect([...schemaOperators].sort()).toEqual(Object.values(FilterOperator).sort());
  });
});

describe("AssigneeType: every member resolves through the assignee switch", () => {
  const definition: PolicyDefinition = {
    version: "1.0",
    name: "policy-a",
    permissions: { canQuery: true, canExport: false, readOnly: true },
  };

  function assignment(type: string, identifier: string): PolicyAssignment {
    return {
      version: "1.0",
      policyName: "policy-a",
      assignee: { type, identifier },
      scope: {},
      active: true,
      audit: { grantedBy: "admin", grantedAt: "2026-01-01T00:00:00Z", reason: "t" },
    };
  }

  it("no enum member falls through to the fail-closed default", () => {
    // A member the switch does not handle would never match, so an administrator's
    // grant would silently do nothing.
    const cases: Array<[AssigneeType, string, { groups?: string[]; roles?: string[] }]> = [
      [AssigneeType.User, "user-001", {}],
      [AssigneeType.ServiceAccount, "user-001", {}],
      [AssigneeType.Group, "analysts", { groups: ["analysts"] }],
      [AssigneeType.Role, "data-analyst", { roles: ["data-analyst"] }],
    ];

    expect(cases.map(([t]) => t).sort()).toEqual(Object.values(AssigneeType).sort());

    return Promise.all(
      cases.map(async ([type, identifier, identity]) => {
        const result = await resolve(
          "user-001",
          "tenant-001",
          "db:production:x",
          [assignment(type, identifier)],
          { "policy-a": definition },
          () => identity.groups ?? [],
          () => identity.roles ?? [],
        );
        expect(result.sourceProfiles, `assignee type ${type}`).toEqual(["policy-a"]);
      }),
    );
  });

  it("the enum's string values are the wire spellings", () => {
    expect(AssigneeType.User).toBe("user");
    expect(AssigneeType.Group).toBe("group");
    expect(AssigneeType.Role).toBe("role");
    expect(AssigneeType.ServiceAccount).toBe("serviceAccount");
  });

  it("the enum matches the shared assignment schema's type enum exactly", () => {
    // Read from disk for the same reason as the operator enum above: an assignee
    // type the schema permits but this switch cannot resolve means an
    // administrator's grant silently does nothing, and the literals asserted just
    // above would keep passing while the schema moved. Both directions, so an enum
    // that gained a value the schema forbids also fails.
    const schemaPath = resolvePath(
      __dirname,
      "..","..","..","..","..",
      "schema","v1.0","policy-assignment.schema.json",
    );
    const schema = JSON.parse(readFileSync(schemaPath, "utf8"));
    const schemaTypes: string[] = schema.properties.assignee.properties.type.enum;

    expect([...schemaTypes].sort()).toEqual(Object.values(AssigneeType).sort());
  });
});

describe("SigningAlgorithm carries the wire spellings", () => {
  it("the values match the schema's algorithm enum", () => {
    expect(SigningAlgorithm.HmacSha256).toBe("hmac-sha256");
    expect(SigningAlgorithm.HmacSha512).toBe("hmac-sha512");
    // ed25519 is in the schema enum but unimplemented in this SDK, which is why
    // validateContext/validatePolicy must DENY rather than throw when they see it.
    // The member must stay: dropping it would replace a refusal that names the
    // algorithm with an unrecognized-value path. Asserted against the schema file
    // in `schema-conformance.test.ts`.
    expect(SigningAlgorithm.Ed25519).toBe("ed25519");
  });

  it("the enum matches the shared effective-policy schema's algorithm enum exactly", () => {
    const schemaPath = resolvePath(
      __dirname,
      "..","..","..","..","..",
      "schema","v1.0","effective-policy.schema.json",
    );
    const schema = JSON.parse(readFileSync(schemaPath, "utf8"));
    const schemaAlgorithms: string[] =
      schema.properties.integrity.properties.algorithm.enum;

    expect([...schemaAlgorithms].sort()).toEqual(Object.values(SigningAlgorithm).sort());
  });
});

describe("MaskType matches the shared policy schema's maskType enum", () => {
  it("matches exactly, in both directions", () => {
    // The `maskRestrictiveness` tests above prove every member is ranked; this
    // proves the members are the right ones. A schema-valid mask type missing from
    // the enum would rank as "unknown" and win every merge it should have lost.
    const schemaPath = resolvePath(
      __dirname,
      "..","..","..","..","..",
      "schema","v1.0","policy-definition.schema.json",
    );
    const schema = JSON.parse(readFileSync(schemaPath, "utf8"));
    const schemaMaskTypes: string[] =
      schema.$defs.maskingRule.properties.maskType.enum;

    expect([...schemaMaskTypes].sort()).toEqual(Object.values(MaskType).sort());
  });
});
