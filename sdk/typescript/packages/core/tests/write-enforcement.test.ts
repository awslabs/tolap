/**
 * Write-path enforcement beyond the cross-SDK corpus (connector spec §4).
 *
 * `write-path-parity.test.ts` carries the decision table the three SDKs assert
 * identically. This file covers what is either TypeScript-specific or too
 * shape-dependent to express in a shared table:
 *
 * - the `TARGET_ROW_UNKNOWN` sentinel and non-record targets
 * - `payloadWriteFields`'s tree walk
 * - the HTTP method-to-permission mapping and the `PUT` full-replace rule
 * - §4.3: `readOnlyFields` is a write control and has no effect on reads
 *
 * The Python counterpart is `tests/test_write_enforcement.py`; the wrapper-level
 * cases live in `packages/mcp/tests/write-wrapper.test.ts`.
 */

import { describe, expect, it } from "vitest";
import {
  TARGET_ROW_UNKNOWN,
  applyResultPipeline,
  payloadWriteFields,
  validateFieldAccess,
  validateHttpWrite,
  validateWrite,
  writeOperationForMethod,
  type WriteTargetRow,
} from "../src/enforcement.js";
import {
  FilterOperator,
  WriteOperation,
  type EffectivePolicy,
  type ObjectRules,
  type PolicyPermissions,
} from "../src/types.js";

/**
 * A policy granting reads, with every write permission absent unless asked for.
 *
 * `readOnly` defaults to false here so a denial reports the specific permission it
 * lacked rather than the `read-only policy` ceiling, which would mask every other
 * reason under test.
 */
function policy(
  permissions: Partial<PolicyPermissions> = {},
  objectRules?: ObjectRules,
): EffectivePolicy {
  return {
    version: "1.0",
    userId: "u",
    tenantId: "t",
    sourceConnectionId: "db:write-enforcement:patients",
    resolvedAt: "2026-01-15T10:00:00Z",
    expiresAt: "2026-01-15T11:00:00Z",
    sourceProfiles: ["write-enforcement"],
    permissions: {
      canQuery: true,
      readOnly: false,
      ...permissions,
    },
    ...(objectRules !== undefined ? { objectRules } : {}),
    integrity: { algorithm: "none", signature: "" },
  };
}

// ---------------------------------------------------------------------------
// Operation resolution
// ---------------------------------------------------------------------------

describe("validateWrite: the operation argument accepts an enum or its string value", () => {
  it.each([
    ["insert", "insert not permitted"],
    ["INSERT", "insert not permitted"],
    ["update", "update not permitted"],
    ["delete", "delete not permitted"],
    ["upsert", "insert not permitted"],
  ])("resolves %s case-insensitively", (value, expectedReason) => {
    const result = validateWrite(value, "patients", { a: 1 }, policy());

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe(expectedReason);
  });

  it("denies an unrecognized operation instead of admitting it", () => {
    // There is no permission to consult, so there is no grant to rely on. A write
    // whose kind this SDK cannot classify must not fall through to the field and row
    // checks and be allowed by them: the operation *is* what selects the permission,
    // so an unclassifiable operation has no grant behind it.
    const grantsEverything = policy({
      canInsert: true,
      canUpdate: true,
      canDelete: true,
    });

    const result = validateWrite("truncate", "patients", null, grantsEverything);

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("unknown write operation");
  });
});

// ---------------------------------------------------------------------------
// The target-row sentinel (§4.2)
// ---------------------------------------------------------------------------

describe("validateWrite: an unverifiable target is a denial, never an allow", () => {
  const FILTERED = policy(
    { canUpdate: true, canDelete: true },
    {
      rowFilters: [
        { field: "region", operator: FilterOperator.Equals, value: "us-east" },
      ],
    },
  );

  it("treats an omitted targetRow as unverifiable", () => {
    // The load-bearing default: an integrator who calls validateWrite without
    // thinking about the target row gets a denial, not a pass.
    const result = validateWrite(
      WriteOperation.Update,
      "patients",
      { a: 1 },
      FILTERED,
    );

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("write target unverifiable");
  });

  it("denies identically when the sentinel is passed explicitly", () => {
    const result = validateWrite(WriteOperation.Update, "patients", { a: 1 }, FILTERED, {
      targetRow: TARGET_ROW_UNKNOWN,
    });

    expect(result.reason).toBe("write target unverifiable");
  });

  it.each([
    ["undefined", undefined],
    ["a string", "us-east"],
    ["a number", 42],
    ["an array", ["us-east"]],
  ])("treats %s as unverifiable rather than as a passing row", (_label, target) => {
    // A target the filters cannot be evaluated against is unverifiable. The
    // alternative -- treating a value we cannot inspect as satisfying the filters --
    // is the fail-open this whole check exists to prevent. A bare string or an array
    // is not a row, so there is nothing to compare `region` against.
    const result = validateWrite(WriteOperation.Delete, "patients", null, FILTERED, {
      targetRow: target as WriteTargetRow,
    });

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("write target unverifiable");
  });

  it("treats a CLASS INSTANCE target as unverifiable, not as a row", () => {
    // TypeScript-specific, and the reason `isRecord` inspects the prototype rather
    // than settling for `typeof === "object"`. A class instance's data may live in
    // accessors and prototype methods this engine cannot enumerate, so the filters
    // cannot be shown to hold over it -- an ORM entity passed here must fail closed
    // even though it looks like it carries the field the filter names.
    class PatientRow {
      readonly region = "us-east";
    }

    const result = validateWrite(
      WriteOperation.Update,
      "patients",
      { a: 1 },
      FILTERED,
      { targetRow: new PatientRow() as unknown as WriteTargetRow },
    );

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("write target unverifiable");
  });

  it("accepts a null-prototype bag as a row", () => {
    // The TypeScript counterpart to Python accepting any Mapping: a driver or a
    // hand-built lookup that uses `Object.create(null)` to avoid prototype
    // collisions is still a row, so the filters run and this one matches.
    const bag = Object.create(null) as Record<string, unknown>;
    bag["region"] = "us-east";

    const result = validateWrite(WriteOperation.Update, "patients", { a: 1 }, FILTERED, {
      targetRow: bag,
    });

    expect(result.allowed).toBe(true);
  });

  it("evaluates an empty record target and fails closed on the filters", () => {
    // `{}` is a row, not an absent target, so the filters run and drop it. The
    // distinction matters: an empty row is missing the filtered field, which
    // canonical spec §7 drops -- so the reason is the row denial, not the
    // unverifiable one. An integrator seeing "target row not permitted" knows the
    // row was checked; "write target unverifiable" means it was not.
    const result = validateWrite(WriteOperation.Update, "patients", { a: 1 }, FILTERED, {
      targetRow: {},
    });

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("target row not permitted");
  });

  it.each([WriteOperation.Update, WriteOperation.Delete, WriteOperation.Upsert])(
    "has nothing to verify for %s when the policy carries no objectRules",
    (operation) => {
      // No objectRules block at all means no row filters, so nothing is
      // unverifiable. The check is vacuous rather than fail-closed: a policy that
      // never expressed a row constraint cannot have one violated. Distinct from a
      // filtered policy with no target row, which denies.
      const unfiltered = policy({
        canInsert: true,
        canUpdate: true,
        canDelete: true,
      });

      const result = validateWrite(operation, "patients", { a: 1 }, unfiltered);

      expect(result.allowed).toBe(true);
      expect(result.reason).toBeUndefined();
    },
  );
});

// ---------------------------------------------------------------------------
// payloadWriteFields
// ---------------------------------------------------------------------------

describe("payloadWriteFields: the tree walk that decides which fields a payload names", () => {
  it("collects keys at every depth", () => {
    expect(payloadWriteFields({ outer: { inner: { ssn: "1" } }, sibling: 2 })).toEqual([
      "outer",
      "inner",
      "ssn",
      "sibling",
    ]);
  });

  it("collects the keys of every record in a list", () => {
    // A bulk insert names the fields of every record it carries.
    expect(payloadWriteFields([{ a: 1 }, { b: 2 }])).toEqual(["a", "b"]);
  });

  it("walks a list nested under a key", () => {
    expect(payloadWriteFields({ encounters: [{ ssn: "1" }] })).toEqual([
      "encounters",
      "ssn",
    ]);
  });

  it("reports a duplicate key once", () => {
    // Deduplicated so a denial names a field once, not per occurrence.
    expect(payloadWriteFields([{ a: 1 }, { a: 2 }])).toEqual(["a"]);
  });

  it.each([
    ["null", null],
    ["undefined", undefined],
    ["a string", "a string"],
    ["a number", 42],
    ["a boolean", true],
  ])("names no fields for %s", (_label, payload) => {
    // Only a record names fields; a scalar body has none to check. Not a fail-open:
    // a scalar payload cannot carry a hidden field, and the permission, object and
    // row checks all still run.
    expect(payloadWriteFields(payload)).toEqual([]);
  });

  it("treats a Date value as a leaf rather than walking its shape", () => {
    // `pg` returns Date objects for DATE/TIMESTAMP columns, so a payload built from
    // a previously-read row carries them. A Date is a value, not a record naming
    // fields, so the key is collected and the object is not descended into -- which
    // is what keeps a policy rule from being matched against `getTime`.
    expect(payloadWriteFields({ created_at: new Date("2026-01-15T10:00:00Z") })).toEqual(
      ["created_at"],
    );
  });

  it("collects a numeric key as its string form", () => {
    // A JSON body cannot produce these, but a hand-built object can, and the field
    // matcher only compares strings.
    expect(payloadWriteFields({ 1: "a", ssn: "b" })).toEqual(["1", "ssn"]);
  });

  it("extends the set with resourceFields without duplicating", () => {
    expect(payloadWriteFields({ a: 1 }, ["a", "b"])).toEqual(["a", "b"]);
  });
});

// ---------------------------------------------------------------------------
// HTTP method mapping (connector spec §6)
// ---------------------------------------------------------------------------

describe("writeOperationForMethod: method-to-permission mapping", () => {
  it.each([
    ["POST", WriteOperation.Insert],
    ["PUT", WriteOperation.Update],
    ["PATCH", WriteOperation.Update],
    ["DELETE", WriteOperation.Delete],
    ["post", WriteOperation.Insert],
    ["Delete", WriteOperation.Delete],
  ])("maps %s to its operation", (method, operation) => {
    expect(writeOperationForMethod(method)).toBe(operation);
  });

  it.each(["GET", "HEAD", "OPTIONS", "get"])("maps %s to no operation", (method) => {
    // A read is governed by canQuery, which validateEndpoint already gates.
    expect(writeOperationForMethod(method)).toBeUndefined();
  });

  it("maps an unknown method to no operation without admitting the verb", () => {
    // Returning undefined here does not let TRACE through -- validateEndpoint
    // refuses it because an omitted allowedMethods defaults to GET/HEAD/OPTIONS and
    // an explicit list would have to name TRACE for it to pass.
    expect(writeOperationForMethod("TRACE")).toBeUndefined();

    const p = policy(
      { canInsert: true, canUpdate: true, canDelete: true },
      { endpointRules: { allowedEndpoints: ["/*"] } },
    );

    const result = validateHttpWrite("TRACE", "/patients", null, p);

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("method not allowed");
  });
});

// ---------------------------------------------------------------------------
// validateHttpWrite
// ---------------------------------------------------------------------------

describe("validateHttpWrite: endpoint rules and the write checks both run", () => {
  const ALLOW_WRITE_METHODS: ObjectRules = {
    endpointRules: {
      allowedEndpoints: ["/patients", "/patients/*"],
      allowedMethods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
    },
    fieldRules: { readOnlyFields: ["patients.created_at"] },
  };

  it("returns the endpoint decision unchanged for a read method", () => {
    // A GET is not a write, so no write permission is invented for it.
    const p = policy({ readOnly: true }, ALLOW_WRITE_METHODS);

    expect(validateHttpWrite("GET", "/patients", null, p).allowed).toBe(true);
  });

  it("does not treat an allowed method as a write grant", () => {
    // POST in allowedMethods says nothing about canInsert. The two controls are
    // independent by design (connector spec §6): one says which verbs reach which
    // paths, the other says which operations the principal may perform.
    const result = validateHttpWrite(
      "POST",
      "/patients",
      { a: 1 },
      policy({}, ALLOW_WRITE_METHODS),
    );

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("insert not permitted");
  });

  it("does not treat a write permission as making a path reachable", () => {
    // The converse: canInsert says nothing about which endpoints exist.
    const p = policy(
      { canInsert: true },
      {
        endpointRules: {
          allowedEndpoints: ["/patients", "/patients/*"],
          allowedMethods: ["POST"],
        },
      },
    );

    const result = validateHttpWrite("POST", "/admin/audit", { a: 1 }, p);

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("endpoint not in allowed set");
  });

  it("runs the endpoint check before the write checks", () => {
    // Both would deny; the endpoint reason wins because it runs first, so an
    // integrator is told the path is unreachable rather than sent to edit
    // readOnlyFields for a call that would fail anyway.
    const result = validateHttpWrite(
      "POST",
      "/admin/audit",
      { created_at: "x" },
      policy({}, ALLOW_WRITE_METHODS),
    );

    expect(result.reason).toBe("endpoint not in allowed set");
  });

  it("validates only the keys a PATCH body carries", () => {
    // A PATCH is a partial update, so an unmentioned field is not written.
    const p = policy({ canUpdate: true }, ALLOW_WRITE_METHODS);

    expect(validateHttpWrite("PATCH", "/patients/1", { full_name: "x" }, p).allowed).toBe(
      true,
    );
  });

  it("treats a field a PUT omits as written", () => {
    // The full-replace rule (connector spec §6). A PUT replaces the whole resource,
    // so omitting `created_at` is not "leaving it alone" -- it is an attempt to
    // overwrite it with absent. The identical body through PATCH is permitted
    // (above); the only difference is the method's replace semantics.
    const p = policy({ canUpdate: true }, ALLOW_WRITE_METHODS);

    const result = validateHttpWrite("PUT", "/patients/1", { full_name: "x" }, p);

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("field is read-only: patients.created_at");
  });

  it("permits a PUT when the policy protects no fields", () => {
    // A replace adds nothing when there is nothing to protect.
    const p = policy(
      { canUpdate: true },
      {
        endpointRules: {
          allowedEndpoints: ["/patients", "/patients/*"],
          allowedMethods: ["PUT"],
        },
      },
    );

    expect(validateHttpWrite("PUT", "/patients/1", { full_name: "x" }, p).allowed).toBe(
      true,
    );
  });

  it("needs resourceFields to extend a PUT to an allowedFields allow-list", () => {
    // The policy alone cannot say which resource fields an allow-list omits -- that
    // is knowable only from the resource's shape -- so an integrator combining
    // allowedFields with full-resource replaces supplies it.
    const p = policy(
      { canUpdate: true },
      {
        endpointRules: {
          allowedEndpoints: ["/patients", "/patients/*"],
          allowedMethods: ["PUT"],
        },
        fieldRules: { allowedFields: ["full_name"] },
      },
    );

    const without = validateHttpWrite("PUT", "/patients/1", { full_name: "x" }, p);
    const withResource = validateHttpWrite("PUT", "/patients/1", { full_name: "x" }, p, {
      resourceFields: ["ssn"],
    });

    expect(without.allowed).toBe(true);
    expect(withResource.allowed).toBe(false);
    expect(withResource.reason).toBe("field not in allowed set: ssn");
  });

  it("checks the object name when one is supplied", () => {
    const p = policy(
      { canInsert: true },
      {
        hiddenObjects: ["audit_log"],
        endpointRules: { allowedEndpoints: ["/*"], allowedMethods: ["POST"] },
      },
    );

    const result = validateHttpWrite("POST", "/anything", { a: 1 }, p, {
      objectName: "audit_log",
    });

    expect(result.reason).toBe("object is hidden");
  });

  it("passes the target row through to the row check", () => {
    const p = policy(
      { canDelete: true },
      {
        rowFilters: [
          { field: "region", operator: FilterOperator.Equals, value: "us-east" },
        ],
        endpointRules: {
          allowedEndpoints: ["/patients/*"],
          allowedMethods: ["DELETE"],
        },
      },
    );

    expect(
      validateHttpWrite("DELETE", "/patients/1", null, p, {
        targetRow: { region: "us-east" },
      }).allowed,
    ).toBe(true);
    expect(
      validateHttpWrite("DELETE", "/patients/1", null, p, {
        targetRow: { region: "eu-west" },
      }).reason,
    ).toBe("target row not permitted");
  });
});

// ---------------------------------------------------------------------------
// §4.3 -- readOnlyFields is a write control only
// ---------------------------------------------------------------------------

describe("readOnlyFields has no effect on reads (§4.3)", () => {
  // A field listed there is returned normally, subject to hidden/allowed/masking
  // rules like any other. Two doc comments in a prior implementation contradicted
  // each other on this point, so it is pinned here from both sides.
  const READ_ONLY_FIELDS = policy(
    { canUpdate: true },
    { fieldRules: { readOnlyFields: ["created_at", "id"] } },
  );

  it("returns a read-only field from the result pipeline", () => {
    const rows = applyResultPipeline(
      [{ id: 1, created_at: "2026-01-01", full_name: "Alice" }],
      READ_ONLY_FIELDS,
    );

    expect(rows).toEqual([{ id: 1, created_at: "2026-01-01", full_name: "Alice" }]);
  });

  it("does not deny a read-only field on the read field check", () => {
    const result = validateFieldAccess(["id", "created_at"], READ_ONLY_FIELDS);

    expect(result.denied).toEqual([]);
    expect(result.allowed).toEqual(["id", "created_at"]);
  });

  it("denies the same field on the write path", () => {
    // The asymmetry is the whole feature: readable, not writable.
    const result = validateWrite(
      WriteOperation.Update,
      undefined,
      { created_at: "x" },
      READ_ONLY_FIELDS,
    );

    expect(result.reason).toBe("field is read-only: created_at");
  });
});
