/**
 * The native enums must match the published schema's enums, set for set.
 *
 * `schema/v1.0/*.json` is the published contract. This SDK re-declares parts of it
 * as TypeScript `enum`s, and those declarations drift silently unless something
 * compares them (canonical spec §14).
 *
 * Two drifts had already happened by the time the spec mandated this check:
 *
 * - The schema's row-filter operator enum grew to 16 values while this SDK and
 *   Python declared 9. A schema-valid `{"operator":"between"}` policy fell through
 *   `rowPassesFilter`'s default arm here and dropped every row, raised an uncaught
 *   `KeyError` in Python, and enforced correctly in .NET. The signature verified in
 *   all three -- the canonical payload covers the policy verbatim -- so the policy
 *   passed every integrity check while producing three different access outcomes.
 * - The mask `parameters.algorithm` enum permits `sha256|sha512|blake2b`; Python and
 *   .NET hardcoded SHA-256 and ignored it, so one policy produced a different
 *   pseudonym per language and every cross-service join on a hashed column silently
 *   failed while each side looked correct alone.
 *
 * Three properties make this able to catch the next one:
 *
 * - The expected values are **read from the schema file on disk**, never restated
 *   here. A copy in the test is a second thing free to drift.
 * - Both directions are asserted. Schema→SDK alone misses an SDK that accepts what
 *   the schema forbids; SDK→schema alone misses the `between` case above.
 * - The assertions are unconditional: each enum is located by keyword path and the
 *   locator throws when the path is absent, so a schema reorganization fails loudly
 *   instead of skipping. A skip restores the blind spot rather than reporting it.
 *
 * `ed25519` is a deliberate special case. It is schema-valid and this SDK's
 * `SigningAlgorithm` MUST carry it, because a policy naming it is a policy this SDK
 * has to *recognize in order to refuse*. Dropping the member to make a set
 * comparison pass would turn a loud refusal into an unrecognized-value path, so it
 * is asserted present in the enum and, separately, asserted to fail closed.
 *
 * This file is the TypeScript half of a trio held in the same shape:
 * `sdk/python/tests/test_schema_conformance.py` and
 * `sdk/dotnet/tests/Tolap.Core.Tests/SchemaConformanceTests.cs`.
 */

import { readFileSync } from "node:fs";
import { resolve as resolvePath } from "node:path";
import { describe, expect, it } from "vitest";
import {
  AssigneeType,
  FilterOperator,
  MASK_RESTRICTIVENESS,
  maskRestrictiveness,
  MaskType,
  SigningAlgorithm,
  UNKNOWN_MASK_RESTRICTIVENESS,
} from "../src/types.js";
import { applyMask, writeOperationForMethod } from "../src/enforcement.js";
import {
  buildSecurityContext,
  signContext,
  validateContext,
} from "../src/context.js";
import type { EffectivePolicy } from "../src/types.js";

const SCHEMA_DIR = resolvePath(__dirname, "..", "..", "..", "..", "..", "schema", "v1.0");

/**
 * Load a published schema by bare name.
 *
 * Throws rather than skipping when the file is absent: schema conformance that
 * silently does not run is the blind spot §14 exists to close.
 */
function loadSchema(name: string): Record<string, unknown> {
  const path = resolvePath(SCHEMA_DIR, `${name}.schema.json`);
  let contents: string;
  try {
    contents = readFileSync(path, "utf8");
  } catch {
    throw new Error(
      `published schema ${path} is missing; schema conformance cannot be checked ` +
        "and MUST NOT be skipped (canonical spec §14)",
    );
  }
  return JSON.parse(contents);
}

/**
 * Read the `enum` list at a keyword path inside a loaded schema.
 *
 * Throws when the path is absent. A missing path means the published enum moved or
 * was renamed, which is itself the finding -- returning `[]` instead would make
 * every comparison against it pass while checking nothing.
 */
function schemaEnumAt(schemaName: string, ...path: string[]): string[] {
  let node: unknown = loadSchema(schemaName);

  for (const [index, key] of path.entries()) {
    if (typeof node !== "object" || node === null || !(key in node)) {
      throw new Error(
        `schema path ${path.join(".")} is missing at segment '${key}' ` +
          `(position ${index}) in ${schemaName}.schema.json; this SDK's native enum ` +
          "is no longer being compared to anything (canonical spec §14)",
      );
    }
    node = (node as Record<string, unknown>)[key];
  }

  if (!Array.isArray(node) || node.length === 0) {
    throw new Error(
      `schema path ${path.join(".")} in ${schemaName}.schema.json is not a ` +
        "non-empty enum list",
    );
  }
  return node as string[];
}

// The keyword path to each enum, held as data so a missing path names the enum that
// moved rather than failing somewhere anonymous.
const OPERATOR_PATH = ["$defs", "filterRule", "properties", "operator", "enum"];
const MASK_TYPE_PATH = ["$defs", "maskingRule", "properties", "maskType", "enum"];
const MASK_ALGORITHM_PATH = [
  "$defs", "maskingRule", "properties", "parameters", "properties", "algorithm", "enum",
];
const ASSIGNEE_TYPE_PATH = ["properties", "assignee", "properties", "type", "enum"];
const SIGNING_ALGORITHM_PATH = [
  "properties", "integrity", "properties", "algorithm", "enum",
];
const ALLOWED_METHODS_PATH = [
  "properties", "objectRules", "properties", "endpointRules", "properties",
  "allowedMethods", "items", "enum",
];

// The effective-policy schema restates the operator and mask enums inline rather
// than through $defs, so its paths differ from the definition schema's.
const EFFECTIVE_OPERATOR_PATH = [
  "properties", "objectRules", "properties", "rowFilters", "items",
  "properties", "operator", "enum",
];
const EFFECTIVE_MASK_TYPE_PATH = [
  "properties", "objectRules", "properties", "fieldRules", "properties",
  "maskedFields", "items", "properties", "maskType", "enum",
];
const EFFECTIVE_MASK_ALGORITHM_PATH = [
  "properties", "objectRules", "properties", "fieldRules", "properties",
  "maskedFields", "items", "properties", "parameters", "properties", "algorithm", "enum",
];

/** The JSON spellings this SDK accepts, not the member names. */
function wireValues(enumObject: Record<string, string>): string[] {
  return Object.values(enumObject).sort();
}

function sorted(values: readonly string[]): string[] {
  return [...values].sort();
}

// ---------------------------------------------------------------------------
// The locator must fail rather than skip, or the whole file proves nothing
// ---------------------------------------------------------------------------

describe("the schema locator fails loudly", () => {
  it("throws on a missing path instead of returning an empty enum", () => {
    expect(() => schemaEnumAt("policy-definition", "$defs", "notARule", "enum")).toThrow(
      /is missing at segment 'notARule'/,
    );
  });

  it("throws when the path is not a non-empty enum list", () => {
    expect(() => schemaEnumAt("policy-definition", "$defs", "filterRule")).toThrow(
      /not a non-empty enum list/,
    );
  });

  it("throws on a missing schema file instead of skipping", () => {
    expect(() => loadSchema("no-such-schema")).toThrow(/MUST NOT be skipped/);
  });
});

// ---------------------------------------------------------------------------
// FilterOperator -- 16 operators, the drift this file exists for
// ---------------------------------------------------------------------------

describe("FilterOperator matches the schema", () => {
  it("matches exactly, in both directions", () => {
    // Schema→SDK: an operator the schema permits but this SDK cannot express falls
    // through rowPassesFilter's default arm and drops every row, so an
    // administrator's working filter becomes a silent deny-all here while another
    // SDK enforces it. SDK→schema: an operator this SDK accepts but the schema
    // forbids would be rejected by a schema-validating peer.
    expect(wireValues(FilterOperator)).toEqual(
      sorted(schemaEnumAt("policy-definition", ...OPERATOR_PATH)),
    );
  });

  it("the two schemas declare the same operator enum", () => {
    // An effective policy is the merged product of definitions, so every operator a
    // definition can express has to survive resolution. The enum is duplicated in
    // the two schema files and a reviewer noticing is otherwise the only guard.
    const definition = schemaEnumAt("policy-definition", ...OPERATOR_PATH);
    const effective = schemaEnumAt("effective-policy", ...EFFECTIVE_OPERATOR_PATH);

    expect(effective).toEqual(definition);
  });
});

// ---------------------------------------------------------------------------
// MaskType
// ---------------------------------------------------------------------------

describe("MaskType matches the schema", () => {
  it("matches exactly, in both directions", () => {
    expect(wireValues(MaskType)).toEqual(
      sorted(schemaEnumAt("policy-definition", ...MASK_TYPE_PATH)),
    );
  });

  it("the two schemas declare the same mask type enum", () => {
    const definition = schemaEnumAt("policy-definition", ...MASK_TYPE_PATH);
    const effective = schemaEnumAt("effective-policy", ...EFFECTIVE_MASK_TYPE_PATH);

    expect(effective).toEqual(definition);
  });

  it("every schema value ranks below the unknown rank", () => {
    // Unknown types rank most-restrictive so a typo cannot be downgraded into a
    // weaker known type during a merge (spec §6). That safety net becomes a bug if
    // it catches a LEGITIMATE value: the mask would win every merge it should have
    // lost.
    for (const value of schemaEnumAt("policy-definition", ...MASK_TYPE_PATH)) {
      expect(MASK_RESTRICTIVENESS[value], value).toBeDefined();
      expect(maskRestrictiveness(value), value).toBeLessThan(
        UNKNOWN_MASK_RESTRICTIVENESS,
      );
    }
  });
});

// ---------------------------------------------------------------------------
// Mask parameters.algorithm -- not a native enum, so it needs its own check
// ---------------------------------------------------------------------------

/**
 * Apply a `hash` mask with the given `algorithm` parameter.
 *
 * The hash mask exists to be a cross-service join key, which only holds if every
 * SDK computes the same digest for the same policy. Python and .NET previously
 * hardcoded SHA-256 and ignored this parameter while this SDK honoured it, so a
 * policy asking for `sha512` produced two different pseudonyms for one value. The
 * schema's enum -- read from disk -- is the authority for what must work.
 */
function hashed(algorithm?: string): unknown {
  return applyMask("john.smith@example.com", {
    field: "email",
    maskType: MaskType.Hash,
    ...(algorithm !== undefined ? { parameters: { algorithm } } : {}),
  });
}

describe("mask parameters.algorithm matches the schema", () => {
  it("every schema-permitted algorithm actually hashes", () => {
    // Schema→SDK. Redacting is the correct response to an algorithm the runtime
    // cannot provide, but applying it to a value the schema permits silently
    // destroys data the policy author asked to have pseudonymized.
    for (const algorithm of schemaEnumAt("policy-definition", ...MASK_ALGORITHM_PATH)) {
      const result = hashed(algorithm);

      expect(result, `${algorithm} is schema-valid but was redacted`).not.toBe(
        "[REDACTED]",
      );
      // Lower-case hex truncated to 16 characters (spec §6): the rendering is part
      // of the join-key contract, so a differently-rendered digest is still a
      // divergence.
      expect(result, algorithm).toMatch(/^[0-9a-f]{16}$/);
    }
  });

  it("the schema-permitted algorithms produce distinct digests", () => {
    // A substituted algorithm is worse than a refusal: the field would look like a
    // valid pseudonym while failing to join against a service that honoured the
    // parameter as written.
    const algorithms = schemaEnumAt("policy-definition", ...MASK_ALGORITHM_PATH);
    const digests = algorithms.map((algorithm) => hashed(algorithm));

    expect(new Set(digests).size).toBe(algorithms.length);
  });

  it("an algorithm outside the schema enum fails closed", () => {
    // SDK→schema. Passing the parameter straight to createHash would accept anything
    // OpenSSL knows -- md5 included -- plus spellings the other two SDKs reject,
    // which is the original divergence in a new form.
    const permitted = schemaEnumAt("policy-definition", ...MASK_ALGORITHM_PATH);

    for (const algorithm of ["md5", "sha1", "sha3-256", "sha384", "blake2s", "SHA256", ""]) {
      expect(permitted, "test case is no longer out-of-schema").not.toContain(algorithm);
      expect(hashed(algorithm), algorithm).toBe("[REDACTED]");
    }
  });

  it("the default when absent is sha256", () => {
    // Spec §6 fixes the default, so all three SDKs agree when it is omitted.
    expect(hashed(undefined)).toBe(hashed("sha256"));
  });

  it("the two schemas declare the same algorithm enum", () => {
    const definition = schemaEnumAt("policy-definition", ...MASK_ALGORITHM_PATH);
    const effective = schemaEnumAt("effective-policy", ...EFFECTIVE_MASK_ALGORITHM_PATH);

    expect(effective).toEqual(definition);
  });
});

// ---------------------------------------------------------------------------
// AssigneeType
// ---------------------------------------------------------------------------

describe("AssigneeType matches the schema", () => {
  it("matches exactly, in both directions", () => {
    // Schema→SDK: an assignee type the schema permits but this SDK cannot express
    // means an administrator's grant silently resolves to nothing.
    expect(wireValues(AssigneeType)).toEqual(
      sorted(schemaEnumAt("policy-assignment", ...ASSIGNEE_TYPE_PATH)),
    );
  });
});

// ---------------------------------------------------------------------------
// SigningAlgorithm, including the deliberate ed25519 case
// ---------------------------------------------------------------------------

function policy(): EffectivePolicy {
  const now = new Date();
  return {
    version: "1.0",
    userId: "user-001",
    tenantId: "tenant-001",
    sourceConnectionId: "db:production:x",
    resolvedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 3_600_000).toISOString(),
    sourceProfiles: ["schema-conformance"],
    permissions: { canQuery: true, canExport: false, readOnly: true },
    integrity: { algorithm: "none", signature: "" },
  };
}

describe("SigningAlgorithm matches the schema", () => {
  it("matches exactly, in both directions", () => {
    // Including ed25519, which this SDK carries in order to REFUSE it: an algorithm
    // this SDK cannot name is an algorithm it cannot refuse by name.
    expect(wireValues(SigningAlgorithm)).toEqual(
      sorted(schemaEnumAt("effective-policy", ...SIGNING_ALGORITHM_PATH)),
    );
  });

  it("ed25519 is present in the enum rather than omitted", () => {
    // Asserted explicitly, not just as a by-product of the set comparison above.
    // Removing the member would make that comparison pass by narrowing the enum
    // instead of by fixing anything, and would replace an explicit refusal with an
    // unrecognized-value path.
    expect(SigningAlgorithm.Ed25519).toBe("ed25519");
    expect(schemaEnumAt("effective-policy", ...SIGNING_ALGORITHM_PATH)).toContain(
      "ed25519",
    );
  });

  it("ed25519 fails closed at signing time", () => {
    // Present in the enum, refused at use: two separate claims. Being nameable is
    // what lets the refusal name the algorithm it refused; the refusal itself is
    // what stops an unsigned context being treated as signed.
    const context = buildSecurityContext("user-001", "tenant-001", policy());

    expect(() => signContext(context, "key", SigningAlgorithm.Ed25519)).toThrow(
      /ed25519/,
    );
  });

  it("ed25519 on validation denies rather than throwing", () => {
    // ed25519 is schema-valid, so a signed context naming it is reachable without
    // malformed input. Verification must DENY -- spec §5 requires unenforceable
    // inputs to be refused, not to abort the pass with an exception escaping an
    // enforcement check. This SDK gets it right; .NET currently throws here, which
    // its own conformance test now reports.
    const signed = signContext(buildSecurityContext("u", "t", policy()), "key");
    signed.algorithm = SigningAlgorithm.Ed25519;

    expect(() => validateContext(signed, "key")).not.toThrow();
    expect(validateContext(signed, "key")).toBe(false);
  });

  it("the hmac algorithms are the ones that do work", () => {
    // The complement: the refusal above must not be the behaviour for all three.
    for (const algorithm of [SigningAlgorithm.HmacSha256, SigningAlgorithm.HmacSha512]) {
      const signed = signContext(
        buildSecurityContext("user-001", "tenant-001", policy()),
        "key",
        algorithm,
      );

      expect(signed.signature).toBeTruthy();
      expect(signed.algorithm).toBe(algorithm);
      expect(validateContext(signed, "key")).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// allowedMethods -- duplicated the same way, same reasoning
// ---------------------------------------------------------------------------

describe("allowedMethods matches the schema", () => {
  it("the two schemas declare the same method enum", () => {
    const definition = schemaEnumAt("policy-definition", ...ALLOWED_METHODS_PATH);
    const effective = schemaEnumAt("effective-policy", ...ALLOWED_METHODS_PATH);

    expect(effective).toEqual(definition);
  });

  it("every schema method is classified by the write mapping", () => {
    // allowedMethods is a string array rather than a native enum, so the drift shows
    // up as a method the schema permits that the write-classification switch does
    // not recognize -- which would decide a write's permission by falling through
    // rather than by the policy.
    const methods = schemaEnumAt("policy-definition", ...ALLOWED_METHODS_PATH);

    expect(sorted(methods)).toEqual(
      sorted(["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]),
    );

    for (const method of ["GET", "HEAD", "OPTIONS"]) {
      expect(methods).toContain(method);
      expect(writeOperationForMethod(method), method).toBeUndefined();
    }

    for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
      expect(methods).toContain(method);
      expect(writeOperationForMethod(method), method).toBeDefined();
    }
  });
});
