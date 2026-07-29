/**
 * Cross-SDK parity for enforcement glob matching (connector spec §3.1).
 *
 * One case corpus, one outcome table, asserted with identical expected allow/deny
 * outcomes **and** identical denial reasons in all three SDKs. Every expectation in
 * this file was produced by running Python's `validate_access`,
 * `validate_field_access` and `validate_endpoint` over the same rules and subjects,
 * and independently confirmed against .NET's `EnforcementEngine.GlobMatch` compiled
 * and executed rather than read.
 *
 * §3.1 states two rules for the enforcement dialect — objects, fields, endpoints and
 * storage prefixes — and TypeScript diverged on both, in opposite directions:
 *
 *   1. **Case-insensitivity**, and this half FAILED OPEN. `globToRegex` compiled a
 *      case-sensitive RegExp, so `hiddenObjects: ["patients"]` did not hide an
 *      object named `PATIENTS`. A table Python and .NET both denied was reachable in
 *      TypeScript purely by case — not a cosmetic difference but a reachable hidden
 *      table on every path object rules take, database and MCP alike.
 *   2. **`*` crossing every separator.** `*` compiled to `[^/]*`, so
 *      `allowedEndpoints: ["/api/*"]` denied `/api/v1/x` that the same signed policy
 *      allowed under Python. Over-restrictive rather than a hole, but it means one
 *      signed policy grants different access per language: an integrator who tests
 *      on Python and deploys on TypeScript silently loses access.
 *
 * The corpus deliberately pins the boundaries the fix must not move — a `.` and a
 * `+` stay literal, a bare collection is NOT granted by a `prefix/*` rule, an empty
 * allow-list still denies — because the cheap way to make the crossing cases pass is
 * to widen `*` into something that also swallows the literals, and that fails open.
 *
 * Two glob behaviors that §3.1 does NOT unify are covered elsewhere and must stay
 * separate: `sourcePatterns` resolution keeps `*` inside a `:` segment
 * (`sourcePatternMatch`, pinned in resolution-source-patterns.test.ts and by a
 * regression case at the bottom of this file).
 */

import { describe, expect, it } from "vitest";
import {
  validateAccess,
  validateEndpoint,
  validateFieldAccess,
} from "../src/enforcement.js";
import { globMatch, sourcePatternMatch } from "../src/resolution.js";
import type {
  EffectivePolicy,
  EndpointRules,
  FieldRules,
  ObjectRules,
} from "../src/types.js";

/**
 * A minimal queryable policy carrying only the rules under test.
 *
 * `canQuery` is true throughout so a denial can only have come from glob matching:
 * a false `canQuery` short-circuits with "query not permitted" before any pattern is
 * consulted, which would make every row pass for the wrong reason.
 */
function policy(objectRules: ObjectRules): EffectivePolicy {
  return {
    version: "1.0",
    userId: "u",
    tenantId: "t",
    sourceConnectionId: "db:production:x",
    resolvedAt: "2026-01-01T00:00:00Z",
    expiresAt: "2027-01-01T00:00:00Z",
    sourceProfiles: [],
    permissions: { canQuery: true, canExport: false, readOnly: true },
    objectRules,
    integrity: { algorithm: "none", signature: "" },
  };
}

// ---------------------------------------------------------------------------
// validateAccess -- objects and storage prefixes
// ---------------------------------------------------------------------------

interface AccessCase {
  id: string;
  allowedObjects?: string[];
  hiddenObjects?: string[];
  objectName: string;
  /** Measured under Python `validate_access`. */
  allowed: boolean;
  /** Measured under Python; `undefined` where Python reports no reason. */
  reason?: string;
}

const ACCESS_CORPUS: AccessCase[] = [
  // Case-insensitivity on hiddenObjects: the fail-open direction, both ways round.
  { id: "hidden-lower-rule-upper-name", hiddenObjects: ["patients"], objectName: "PATIENTS", allowed: false, reason: "object is hidden" },
  { id: "hidden-upper-rule-lower-name", hiddenObjects: ["PATIENTS"], objectName: "patients", allowed: false, reason: "object is hidden" },
  { id: "hidden-mixed-rule-mixed-name", hiddenObjects: ["PaTiEnTs"], objectName: "pAtIeNtS", allowed: false, reason: "object is hidden" },
  { id: "hidden-glob-cased", hiddenObjects: ["Patient*"], objectName: "PATIENT_RECORDS", allowed: false, reason: "object is hidden" },
  // Case-insensitivity must not become case-blindness: a genuinely different name
  // is still allowed, so the hidden rows above are not passing vacuously.
  { id: "hidden-cased-no-match", hiddenObjects: ["patients"], objectName: "ENCOUNTERS", allowed: true },

  // Case-insensitivity on allowedObjects, both ways round.
  { id: "allow-lower-rule-upper-name", allowedObjects: ["patients"], objectName: "PATIENTS", allowed: true },
  { id: "allow-upper-rule-lower-name", allowedObjects: ["PATIENTS"], objectName: "patients", allowed: true },
  { id: "allow-cased-glob", allowedObjects: ["Reports.*"], objectName: "REPORTS.Q1", allowed: true },
  { id: "allow-cased-no-match", allowedObjects: ["patients"], objectName: "BILLING", allowed: false, reason: "object not in allowed set" },

  // Hidden still wins over allowed once both match case-insensitively.
  { id: "hidden-beats-allow-cased", allowedObjects: ["PATIENTS"], hiddenObjects: ["patients"], objectName: "Patients", allowed: false, reason: "object is hidden" },

  // Storage prefixes -- §3.1's second worked example, verbatim.
  { id: "prefix-flat", allowedObjects: ["exports/public/*"], objectName: "exports/public/a.csv", allowed: true },
  { id: "prefix-deep", allowedObjects: ["exports/public/*"], objectName: "exports/public/sub/deep.csv", allowed: true },
  { id: "prefix-deeper", allowedObjects: ["exports/public/*"], objectName: "exports/public/a/b/c/d.csv", allowed: true },
  { id: "prefix-sibling-denied", allowedObjects: ["exports/public/*"], objectName: "exports/private/a.csv", allowed: false, reason: "object not in allowed set" },
  // The boundary that makes "descends arbitrarily" safe to state: the prefix itself
  // is NOT granted, exactly as the endpoint collection is not.
  { id: "prefix-bare-collection", allowedObjects: ["exports/public/*"], objectName: "exports/public", allowed: false, reason: "object not in allowed set" },
  { id: "prefix-cased", allowedObjects: ["Exports/Public/*"], objectName: "exports/public/SUB/deep.csv", allowed: true },
  { id: "hidden-prefix-deep", hiddenObjects: ["exports/private/*"], objectName: "exports/private/sub/x.csv", allowed: false, reason: "object is hidden" },

  // `*` crosses `.` too, which is what schema-qualified object names need.
  { id: "dotted-star-crosses", allowedObjects: ["public.*"], objectName: "public.patients", allowed: true },
  { id: "dotted-star-crosses-twice", allowedObjects: ["public.*"], objectName: "public.schema.patients", allowed: true },
  { id: "dotted-bare", allowedObjects: ["public.*"], objectName: "public", allowed: false, reason: "object not in allowed set" },

  // `**` is accepted and means exactly what `*` means.
  { id: "double-star-alias", allowedObjects: ["exports/public/**"], objectName: "exports/public/sub/deep.csv", allowed: true },
  { id: "double-star-alias-single-lvl", allowedObjects: ["exports/public/**"], objectName: "exports/public/a.csv", allowed: true },

  // Boundaries the widening must not cross: a glob is a glob, not a regex.
  { id: "dot-is-literal", allowedObjects: ["a.c"], objectName: "axc", allowed: false, reason: "object not in allowed set" },
  { id: "dot-matches-itself", allowedObjects: ["a.c"], objectName: "a.c", allowed: true },
  { id: "plus-is-literal", allowedObjects: ["a+c"], objectName: "aac", allowed: false, reason: "object not in allowed set" },

  { id: "bare-star-everything", allowedObjects: ["*"], objectName: "any/deep.name/here", allowed: true },
  // An empty allow-list denies everything (spec §3), unchanged by the widening.
  { id: "empty-allow-list", allowedObjects: [], objectName: "patients", allowed: false, reason: "object not in allowed set" },
];

describe("spec §3.1 parity: validateAccess matches Python outcome and reason", () => {
  for (const testCase of ACCESS_CORPUS) {
    it(`${testCase.id} matches the shared expectation`, () => {
      const result = validateAccess(
        testCase.objectName,
        policy({
          ...(testCase.allowedObjects !== undefined
            ? { allowedObjects: testCase.allowedObjects }
            : {}),
          ...(testCase.hiddenObjects !== undefined
            ? { hiddenObjects: testCase.hiddenObjects }
            : {}),
        }),
      );

      expect(result.allowed).toBe(testCase.allowed);
      expect(result.reason).toBe(testCase.reason);
    });
  }
});

// ---------------------------------------------------------------------------
// validateFieldAccess -- fields
// ---------------------------------------------------------------------------

interface FieldCase {
  id: string;
  allowedFields?: string[];
  hiddenFields?: string[];
  fields: string[];
  /** Measured under Python `validate_field_access`. Order is part of the contract. */
  allowed: string[];
  denied: string[];
}

const FIELD_CORPUS: FieldCase[] = [
  // Case-insensitivity on hiddenFields: an upper-case field against a lower-case
  // rule and vice versa. The denied list carries the field as the CALLER spelled
  // it, not as the rule did, so a caller can correlate the denial with its request.
  { id: "hidden-lower-rule-upper-field", hiddenFields: ["ssn"], fields: ["SSN", "name"], allowed: ["name"], denied: ["SSN"] },
  { id: "hidden-upper-rule-lower-field", hiddenFields: ["SSN"], fields: ["ssn", "name"], allowed: ["name"], denied: ["ssn"] },

  // Case-insensitivity on allowedFields, both ways round.
  { id: "allow-lower-rule-upper-field", allowedFields: ["name"], fields: ["NAME", "ssn"], allowed: ["NAME"], denied: ["ssn"] },
  { id: "allow-upper-rule-lower-field", allowedFields: ["NAME"], fields: ["name", "ssn"], allowed: ["name"], denied: ["ssn"] },
  { id: "hidden-glob-cased", hiddenFields: ["Patients.*"], fields: ["PATIENTS.SSN", "other.ssn"], allowed: ["other.ssn"], denied: ["PATIENTS.SSN"] },

  // `*` crosses `.`: a table-scoped rule reaches a nested field, not just a leaf.
  { id: "hidden-star-crosses-dot", hiddenFields: ["patients.*"], fields: ["patients.address.zip"], allowed: [], denied: ["patients.address.zip"] },
  { id: "allow-star-crosses-dot", allowedFields: ["patients.*"], fields: ["patients.address.zip", "billing.amt"], allowed: ["patients.address.zip"], denied: ["billing.amt"] },
  { id: "hidden-leading-star-dot", hiddenFields: ["*.ssn"], fields: ["patients.ssn", "patients.name"], allowed: ["patients.name"], denied: ["patients.ssn"] },

  { id: "hidden-bare-star", hiddenFields: ["*"], fields: ["anything", "a.b.c"], allowed: [], denied: ["anything", "a.b.c"] },
  { id: "empty-allow-list", allowedFields: [], fields: ["name"], allowed: [], denied: ["name"] },
];

describe("spec §3.1 parity: validateFieldAccess matches Python allow/deny split", () => {
  for (const testCase of FIELD_CORPUS) {
    it(`${testCase.id} matches the shared expectation`, () => {
      const fieldRules: FieldRules = {
        ...(testCase.allowedFields !== undefined
          ? { allowedFields: testCase.allowedFields }
          : {}),
        ...(testCase.hiddenFields !== undefined
          ? { hiddenFields: testCase.hiddenFields }
          : {}),
      };

      const result = validateFieldAccess(testCase.fields, policy({ fieldRules }));

      expect(result.allowed).toEqual(testCase.allowed);
      expect(result.denied).toEqual(testCase.denied);
    });
  }
});

// ---------------------------------------------------------------------------
// validateEndpoint -- paths
// ---------------------------------------------------------------------------

interface EndpointCase {
  id: string;
  allowedEndpoints?: string[];
  hiddenEndpoints?: string[];
  path: string;
  method: string;
  /** Measured under Python `validate_endpoint`. */
  allowed: boolean;
  reason?: string;
}

const ENDPOINT_CORPUS: EndpointCase[] = [
  // §3.1's first worked example, verbatim: the nested resource is granted, the
  // collection itself is not, and listing both is how an author gets both.
  { id: "spec-example-member", allowedEndpoints: ["/api/v1/patients/*"], path: "/api/v1/patients/123", method: "GET", allowed: true },
  { id: "spec-example-nested", allowedEndpoints: ["/api/v1/patients/*"], path: "/api/v1/patients/123/labs", method: "GET", allowed: true },
  { id: "spec-example-collection", allowedEndpoints: ["/api/v1/patients/*"], path: "/api/v1/patients", method: "GET", allowed: false, reason: "endpoint not in allowed set" },
  { id: "spec-example-both-listed", allowedEndpoints: ["/api/v1/patients", "/api/v1/patients/*"], path: "/api/v1/patients", method: "GET", allowed: true },

  // The measured divergence: TS denied this row, Python allowed it.
  { id: "shallow-star-crosses", allowedEndpoints: ["/api/*"], path: "/api/v1/x", method: "GET", allowed: true },
  { id: "shallow-star-one-level", allowedEndpoints: ["/api/*"], path: "/api/x", method: "GET", allowed: true },
  { id: "shallow-star-other-root", allowedEndpoints: ["/api/*"], path: "/admin/x", method: "GET", allowed: false, reason: "endpoint not in allowed set" },

  // Case-insensitivity on hiddenEndpoints: the fail-open direction, both ways.
  { id: "hidden-lower-rule-upper-path", hiddenEndpoints: ["/admin/*"], path: "/ADMIN/users", method: "GET", allowed: false, reason: "endpoint is hidden" },
  { id: "hidden-upper-rule-lower-path", hiddenEndpoints: ["/ADMIN/*"], path: "/admin/users", method: "GET", allowed: false, reason: "endpoint is hidden" },
  { id: "hidden-cased-nested", hiddenEndpoints: ["/Admin/*"], path: "/admin/users/1/roles", method: "GET", allowed: false, reason: "endpoint is hidden" },
  { id: "hidden-cased-no-match", hiddenEndpoints: ["/admin/*"], path: "/api/users", method: "GET", allowed: true },

  // Case-insensitivity on allowedEndpoints, both ways round.
  { id: "allow-lower-rule-upper-path", allowedEndpoints: ["/api/v1/*"], path: "/API/V1/patients", method: "GET", allowed: true },
  { id: "allow-upper-rule-lower-path", allowedEndpoints: ["/API/V1/*"], path: "/api/v1/patients", method: "GET", allowed: true },

  { id: "hidden-beats-allow-cased", allowedEndpoints: ["/API/*"], hiddenEndpoints: ["/api/v1/*"], path: "/Api/V1/patients", method: "GET", allowed: false, reason: "endpoint is hidden" },
  { id: "double-star-alias", allowedEndpoints: ["/api/**"], path: "/api/v1/patients/123", method: "GET", allowed: true },
  { id: "dotted-path", allowedEndpoints: ["/drug/*"], path: "/drug/event.json", method: "GET", allowed: true },

  // Reason precedence survives the change: the path rule is consulted before the
  // method rule, so a hidden path reports "endpoint is hidden" even for a write...
  { id: "hidden-path-beats-method", hiddenEndpoints: ["/admin/*"], path: "/ADMIN/x", method: "POST", allowed: false, reason: "endpoint is hidden" },
  // ...and a path that now matches case-insensitively reports the METHOD denial
  // rather than the path one. This row would have reported "endpoint not in
  // allowed set" before the fix -- same deny, different reason, and the reason is
  // part of the contract (§3.3).
  { id: "method-denied-cased-path", allowedEndpoints: ["/API/*"], path: "/api/x", method: "DELETE", allowed: false, reason: "method not allowed" },
];

describe("spec §3.1 parity: validateEndpoint matches Python outcome and reason", () => {
  for (const testCase of ENDPOINT_CORPUS) {
    it(`${testCase.id} matches the shared expectation`, () => {
      const endpointRules: EndpointRules = {
        ...(testCase.allowedEndpoints !== undefined
          ? { allowedEndpoints: testCase.allowedEndpoints }
          : {}),
        ...(testCase.hiddenEndpoints !== undefined
          ? { hiddenEndpoints: testCase.hiddenEndpoints }
          : {}),
      };

      const result = validateEndpoint(
        testCase.path,
        testCase.method,
        policy({ endpointRules }),
      );

      expect(result.allowed).toBe(testCase.allowed);
      expect(result.reason).toBe(testCase.reason);
    });
  }
});

// ---------------------------------------------------------------------------
// The two dialects stay apart
// ---------------------------------------------------------------------------

describe("spec §3.1: `sourcePatterns` matching still does NOT cross `:`", () => {
  // The behavior the enforcement widening must not break. §3.1 tabulates the split
  // deliberately: `sourcePatterns` keeps `*` inside a `:` segment while enforcement
  // globs cross everything. Unifying on the enforcement dialect would let a policy
  // scoped to `db:*` govern every database source in every namespace -- silently
  // widening every source-scoped policy that was never authored for them.
  it("`db:*` does not match `db:production:patients`", () => {
    expect(sourcePatternMatch("db:*", "db:production:patients")).toBe(false);
    expect(sourcePatternMatch("db:*", "db:production")).toBe(true);
  });

  it("the enforcement dialect DOES cross `:`, which is why they are separate", () => {
    // Both halves asserted together, so a future unification fails here rather
    // than passing by making both sides agree on the wrong answer.
    expect(globMatch("db:*", "db:production:patients")).toBe(true);
    expect(sourcePatternMatch("db:*", "db:production:patients")).toBe(false);
  });

  it("a segment-scoped source pattern still reaches its own segment", () => {
    expect(sourcePatternMatch("db:production:*", "db:production:patients")).toBe(true);
    expect(sourcePatternMatch("db:production:*", "db:staging:patients")).toBe(false);
  });
});
