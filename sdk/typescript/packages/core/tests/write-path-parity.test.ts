/**
 * Cross-SDK parity for the write path (connector spec §4).
 *
 * One case corpus — operation × policy × payload × target row -> allowed + reason —
 * asserted with byte-identical expected outcomes in all three SDKs. The counterparts
 * are:
 *
 * - Python: `tests/test_write_path_parity.py` (the reference ordering)
 * - .NET: `tests/Tolap.Core.Tests/WritePathParityTests.cs`
 *
 * The three tables must stay identical case-for-case, and this file follows the
 * Python ordering row for row so a diff of the three is readable.
 *
 * **The reason strings are asserted, not just the boolean.** They are the contract
 * integrators log and branch on, and each one names a different policy edit that
 * would unblock the caller: `insert not permitted` is fixed by granting `canInsert`,
 * `read-only policy` by clearing `readOnly`, `field is read-only: x` by removing `x`
 * from `readOnlyFields`, and `write target unverifiable` by reading the target row
 * first. An integrator who cannot tell them apart cannot tell which edit to make.
 *
 * A corpus of this shape is what catches divergence: a prior cross-SDK table exposed
 * a real fail-open that no single-SDK test had found, because every SDK's own suite
 * asserted the behaviour that SDK happened to implement.
 */

import { describe, it, expect } from "vitest";
import { validateWrite } from "../src/enforcement.js";
import {
  FilterOperator,
  MaskType,
  WriteOperation,
  type EffectivePolicy,
  type ObjectRules,
  type PolicyPermissions,
} from "../src/types.js";

function policy(
  permissions: PolicyPermissions,
  objectRules?: ObjectRules,
): EffectivePolicy {
  return {
    version: "1.0",
    userId: "parity-user",
    tenantId: "parity-tenant",
    sourceConnectionId: "db:parity:patients",
    resolvedAt: "2026-01-15T10:00:00Z",
    expiresAt: "2026-01-15T11:00:00Z",
    sourceProfiles: ["write-path-parity"],
    permissions,
    ...(objectRules ? { objectRules } : {}),
    integrity: { algorithm: "none", signature: "" },
  };
}

// -- The shared parity policies. Identical field-for-field in all three SDKs. --

/** Every write granted, with object rules, field rules and a row filter. */
const FULL_WRITE = policy(
  {
    canQuery: true,
    canInsert: true,
    canUpdate: true,
    canDelete: true,
    canExport: false,
    readOnly: false,
  },
  {
    allowedObjects: ["patients", "encounters"],
    hiddenObjects: ["audit_log"],
    fieldRules: {
      hiddenFields: ["patients.ssn"],
      readOnlyFields: ["patients.created_at"],
      maskedFields: [{ field: "patients.email", maskType: MaskType.Hash }],
    },
    rowFilters: [
      { field: "region", operator: FilterOperator.In, values: ["us-east"] },
    ],
  },
);

/**
 * A policy authored before writes existed: it grants reads and says nothing about
 * writes. Every write must be denied, which is the whole point of the false default.
 */
const SILENT = policy({ canQuery: true });

/**
 * Contradictory on purpose: all three write permissions granted *and* readOnly set.
 * The ceiling has to win (connector spec §4.1).
 */
const READ_ONLY_CEILING = policy({
  canQuery: true,
  canInsert: true,
  canUpdate: true,
  canDelete: true,
  canExport: false,
  readOnly: true,
});

/**
 * Insert and update granted, delete omitted; an allowedFields allow-list and no row
 * filters, so the row check has nothing to verify and must not deny.
 */
const ALLOW_LIST = policy(
  { canQuery: true, canInsert: true, canUpdate: true, canExport: false, readOnly: false },
  { fieldRules: { allowedFields: ["full_name", "status"] } },
);

/**
 * An EMPTY allowedFields, which denies every field (canonical spec §3) rather than
 * lifting the restriction. The most restrictive possible field rule.
 */
const EMPTY_ALLOW_LIST = policy(
  { canQuery: true, canInsert: true, canExport: false, readOnly: false },
  { fieldRules: { allowedFields: [] } },
);

/**
 * canInsert without canUpdate, so an upsert — which needs both — is denied on the
 * half it lacks (connector spec §8's safe intersection).
 */
const INSERT_ONLY = policy({
  canQuery: true,
  canInsert: true,
  canExport: false,
  readOnly: false,
});

const POLICIES: Record<string, EffectivePolicy> = {
  "full-write": FULL_WRITE,
  silent: SILENT,
  "read-only-ceiling": READ_ONLY_CEILING,
  "allow-list": ALLOW_LIST,
  "empty-allow-list": EMPTY_ALLOW_LIST,
  "insert-only": INSERT_ONLY,
};

interface ParityCase {
  id: string;
  policy: string;
  operation: WriteOperation;
  objectName?: string;
  payload?: unknown;
  /** Absent means the caller supplied no target row, by omission. */
  targetRow?: Record<string, unknown>;
  /**
   * Marks a row whose target is an EXPLICIT null rather than absent.
   *
   * The distinction is not cosmetic. "Absent" reaches the code through
   * `validateWrite`'s own `?? TARGET_ROW_UNKNOWN` default, while an explicit null
   * reaches the separate "this is not a row I can evaluate filters against" guard.
   * Both MUST deny with `write target unverifiable`, but they are different branches,
   * and a corpus that only ever spelled it one way left the other unexercised: with
   * only the null spelling in the table, deleting the sentinel branch outright — a
   * textbook fail-open, "no target row supplied means nothing to check" — kept every
   * case green, because null happened to be caught downstream by the non-record guard.
   * Both spellings are now in the table so neither branch can be removed silently.
   */
  explicitNullTarget?: boolean;
  fullReplace?: boolean;
  allowed: boolean;
  reason?: string;
}

/** The corpus, in the same order as the Python and .NET tables. */
const PARITY_CORPUS: ParityCase[] = [
  // -- Check 1: operation permission, then the readOnly ceiling --
  { id: "silent-insert", policy: "silent", operation: WriteOperation.Insert, objectName: "patients", payload: { full_name: "x" }, allowed: false, reason: "insert not permitted" },
  { id: "silent-update", policy: "silent", operation: WriteOperation.Update, objectName: "patients", payload: { full_name: "x" }, allowed: false, reason: "update not permitted" },
  { id: "silent-delete", policy: "silent", operation: WriteOperation.Delete, objectName: "patients", allowed: false, reason: "delete not permitted" },
  // An upsert reports the first permission it lacks, so the reason names insert.
  { id: "silent-upsert", policy: "silent", operation: WriteOperation.Upsert, objectName: "patients", payload: { full_name: "x" }, allowed: false, reason: "insert not permitted" },
  // The ceiling overrides all three grants, and reports itself rather than a
  // permission -- clearing readOnly is the edit that unblocks the caller.
  { id: "ceiling-insert", policy: "read-only-ceiling", operation: WriteOperation.Insert, objectName: "patients", payload: { full_name: "x" }, allowed: false, reason: "read-only policy" },
  { id: "ceiling-update", policy: "read-only-ceiling", operation: WriteOperation.Update, objectName: "patients", payload: { full_name: "x" }, allowed: false, reason: "read-only policy" },
  { id: "ceiling-delete", policy: "read-only-ceiling", operation: WriteOperation.Delete, objectName: "patients", allowed: false, reason: "read-only policy" },
  { id: "ceiling-upsert", policy: "read-only-ceiling", operation: WriteOperation.Upsert, objectName: "patients", payload: { full_name: "x" }, allowed: false, reason: "read-only policy" },
  // The safe intersection: insert alone is not enough for an upsert.
  { id: "insert-only-upsert", policy: "insert-only", operation: WriteOperation.Upsert, objectName: "patients", payload: { full_name: "x" }, allowed: false, reason: "update not permitted" },
  { id: "insert-only-insert", policy: "insert-only", operation: WriteOperation.Insert, objectName: "patients", payload: { full_name: "x" }, allowed: true },
  { id: "allow-list-delete", policy: "allow-list", operation: WriteOperation.Delete, objectName: "patients", allowed: false, reason: "delete not permitted" },

  // -- Check 2: the target object --
  { id: "hidden-object", policy: "full-write", operation: WriteOperation.Insert, objectName: "audit_log", payload: { full_name: "x" }, allowed: false, reason: "object is hidden" },
  { id: "object-not-allowed", policy: "full-write", operation: WriteOperation.Insert, objectName: "billing_internal", payload: { full_name: "x" }, allowed: false, reason: "object not in allowed set" },
  // A hidden object is not writable even for a delete whose target row would pass.
  { id: "hidden-object-delete", policy: "full-write", operation: WriteOperation.Delete, objectName: "audit_log", targetRow: { region: "us-east" }, allowed: false, reason: "object is hidden" },
  { id: "allowed-object", policy: "full-write", operation: WriteOperation.Insert, objectName: "encounters", payload: { full_name: "x" }, allowed: true },
  // No object supplied skips the check rather than denying: an integrator who cannot
  // name the object still gets the other three checks.
  { id: "no-object-name", policy: "full-write", operation: WriteOperation.Insert, payload: { full_name: "x" }, allowed: true },

  // -- Check 3: every field in the payload --
  { id: "insert-plain-field", policy: "full-write", operation: WriteOperation.Insert, objectName: "patients", payload: { full_name: "x" }, allowed: true },
  // A field the caller cannot read, it cannot write. The reason names the payload key
  // as the caller spelled it -- safe, since the caller supplied it.
  { id: "hidden-field-bare", policy: "full-write", operation: WriteOperation.Insert, objectName: "patients", payload: { ssn: "1" }, allowed: false, reason: "field is hidden: ssn" },
  // Bidirectional, case-insensitive matching: a rule of patients.ssn blocks a key of
  // PATIENTS.SSN and of ssn alike (connector spec §3.2).
  { id: "hidden-field-qualified-upper", policy: "full-write", operation: WriteOperation.Insert, objectName: "patients", payload: { "PATIENTS.SSN": "1" }, allowed: false, reason: "field is hidden: PATIENTS.SSN" },
  // The readOnlyFields rule is written qualified; the payload key is bare.
  { id: "read-only-field", policy: "full-write", operation: WriteOperation.Insert, objectName: "patients", payload: { created_at: "2026-01-01" }, allowed: false, reason: "field is read-only: created_at" },
  // Nested keys are reached at every depth, and the walk records the container key
  // first -- so the reported field is the offending leaf, not its parent.
  { id: "nested-hidden-field", policy: "full-write", operation: WriteOperation.Insert, objectName: "patients", payload: { demographics: { ssn: "1" } }, allowed: false, reason: "field is hidden: ssn" },
  // Fail closed on the WHOLE write: a payload mixing a writable and an unwritable
  // field is rejected outright, never stripped down to the writable part.
  { id: "mixed-payload-rejected-whole", policy: "full-write", operation: WriteOperation.Update, objectName: "patients", payload: { status: "active", ssn: "1" }, targetRow: { region: "us-east" }, allowed: false, reason: "field is hidden: ssn" },
  // readOnlyFields has NO effect on reads: a masked field is still writable here, and
  // this row exists to pin that maskedFields is not a write restriction.
  { id: "masked-field-is-writable", policy: "full-write", operation: WriteOperation.Insert, objectName: "patients", payload: { email: "a@b.c" }, allowed: true },
  { id: "allow-list-permits-listed", policy: "allow-list", operation: WriteOperation.Insert, objectName: "patients", payload: { full_name: "x" }, allowed: true },
  { id: "allow-list-denies-unlisted", policy: "allow-list", operation: WriteOperation.Insert, objectName: "patients", payload: { full_name: "x", region: "us-east" }, allowed: false, reason: "field not in allowed set: region" },
  // [] denies every field rather than lifting the restriction.
  { id: "empty-allow-list-denies", policy: "empty-allow-list", operation: WriteOperation.Insert, objectName: "patients", payload: { full_name: "x" }, allowed: false, reason: "field not in allowed set: full_name" },
  // An empty payload names no fields, so the field check has nothing to reject. The
  // permission and object checks still ran and passed.
  { id: "empty-payload-under-empty-allow-list", policy: "empty-allow-list", operation: WriteOperation.Insert, objectName: "patients", payload: {}, allowed: true },

  // -- Check 4: row filters against the update/delete target --
  { id: "update-matching-row", policy: "full-write", operation: WriteOperation.Update, objectName: "patients", payload: { full_name: "x" }, targetRow: { region: "us-east" }, allowed: true },
  // A caller must not modify a row it could not have selected. The reason names no
  // value -- §4.4 permits naming a payload field, never a row value.
  { id: "update-non-matching-row", policy: "full-write", operation: WriteOperation.Update, objectName: "patients", payload: { full_name: "x" }, targetRow: { region: "eu-west" }, allowed: false, reason: "target row not permitted" },
  // A row missing the filtered field fails closed, exactly as it would on a read.
  { id: "update-row-missing-field", policy: "full-write", operation: WriteOperation.Update, objectName: "patients", payload: { full_name: "x" }, targetRow: { id: 1 }, allowed: false, reason: "target row not permitted" },
  // No target row and filters present is UNVERIFIABLE, not an allow. This is the
  // fail-open a naive implementation reaches by treating "nothing to check" as pass.
  { id: "update-no-target-row", policy: "full-write", operation: WriteOperation.Update, objectName: "patients", payload: { full_name: "x" }, allowed: false, reason: "write target unverifiable" },
  { id: "delete-no-target-row", policy: "full-write", operation: WriteOperation.Delete, objectName: "patients", allowed: false, reason: "write target unverifiable" },
  // An EXPLICIT null target is a different code path from an omitted one (see
  // ParityCase.explicitNullTarget) and must deny identically. A caller who passes the
  // row they failed to read must not do better than one who passed nothing.
  { id: "update-explicit-null-target", policy: "full-write", operation: WriteOperation.Update, objectName: "patients", payload: { full_name: "x" }, explicitNullTarget: true, allowed: false, reason: "write target unverifiable" },
  { id: "delete-explicit-null-target", policy: "full-write", operation: WriteOperation.Delete, objectName: "patients", explicitNullTarget: true, allowed: false, reason: "write target unverifiable" },
  { id: "delete-matching-row", policy: "full-write", operation: WriteOperation.Delete, objectName: "patients", targetRow: { region: "us-east" }, allowed: true },
  { id: "delete-non-matching-row", policy: "full-write", operation: WriteOperation.Delete, objectName: "patients", targetRow: { region: "eu-west" }, allowed: false, reason: "target row not permitted" },
  { id: "upsert-matching-row", policy: "full-write", operation: WriteOperation.Upsert, objectName: "patients", payload: { full_name: "x" }, targetRow: { region: "us-east" }, allowed: true },
  { id: "upsert-no-target-row", policy: "full-write", operation: WriteOperation.Upsert, objectName: "patients", payload: { full_name: "x" }, allowed: false, reason: "write target unverifiable" },
  // An insert has no pre-existing target, so the row check does not apply to it --
  // this is why insert-plain-field above passes with no target row.
  { id: "insert-ignores-target-row", policy: "full-write", operation: WriteOperation.Insert, objectName: "patients", payload: { full_name: "x" }, allowed: true },
  // A policy with no row filters has nothing to verify, so an absent target row is not
  // unverifiable -- the check is vacuous rather than fail-closed.
  { id: "no-filters-no-target-row", policy: "allow-list", operation: WriteOperation.Update, objectName: "patients", payload: { status: "active" }, allowed: true },

  // -- Ordering: the field check precedes the row check --
  // Both would deny; the field reason wins because check 3 runs before check 4.
  { id: "field-denial-precedes-row-denial", policy: "full-write", operation: WriteOperation.Update, objectName: "patients", payload: { created_at: "x" }, targetRow: { region: "eu-west" }, allowed: false, reason: "field is read-only: created_at" },
  // And the permission check precedes everything: this payload and object would both
  // deny under full-write, but under `silent` the permission reason is reported.
  { id: "permission-denial-precedes-all", policy: "silent", operation: WriteOperation.Insert, objectName: "audit_log", payload: { ssn: "1" }, allowed: false, reason: "insert not permitted" },

  // -- The full-resource-replace rule (connector spec §6) --
  // Identical payload, identical policy, identical target row: the ONLY difference is
  // that a replace overwrites every field of the resource, so omitting a protected
  // field is still an attempt to overwrite it with absent.
  { id: "partial-update-omitting-protected-field", policy: "full-write", operation: WriteOperation.Update, objectName: "patients", payload: { full_name: "x" }, targetRow: { region: "us-east" }, allowed: true },
  { id: "full-replace-omitting-protected-field", policy: "full-write", operation: WriteOperation.Update, objectName: "patients", payload: { full_name: "x" }, targetRow: { region: "us-east" }, fullReplace: true, allowed: false, reason: "field is hidden: patients.ssn" },
  // A replace under a policy with no protected fields adds nothing, so it behaves
  // exactly like a partial update.
  { id: "full-replace-with-no-protected-fields", policy: "insert-only", operation: WriteOperation.Insert, objectName: "patients", payload: { full_name: "x" }, fullReplace: true, allowed: true },
];

describe("write path cross-SDK parity", () => {
  it.each(PARITY_CORPUS)("$id", (testCase) => {
    // An omitted targetRow goes through validateWrite's own default, so the sentinel
    // branch is exercised; explicitNullTarget goes through the null path instead.
    // Spelling both as undefined would leave the sentinel branch untested -- see
    // ParityCase.explicitNullTarget.
    const result = validateWrite(
      testCase.operation,
      testCase.objectName,
      testCase.payload,
      POLICIES[testCase.policy]!,
      {
        ...(testCase.explicitNullTarget === true
          ? { targetRow: null as unknown as undefined }
          : testCase.targetRow !== undefined
            ? { targetRow: testCase.targetRow }
            : {}),
        fullReplace: testCase.fullReplace ?? false,
      },
    );

    expect(result.allowed, `${testCase.id}: ${result.reason}`).toBe(testCase.allowed);
    expect(result.reason, testCase.id).toBe(testCase.reason);
  });

  it("the corpus covers every documented write denial reason", () => {
    // Without this, a reason could be dropped from the implementation *and* from the
    // table together and the parity suite would keep passing -- the corpus would agree
    // with itself across three SDKs while none of them enforced the rule.
    const documented = [
      "insert not permitted",
      "update not permitted",
      "delete not permitted",
      "read-only policy",
      "field is hidden",
      "field is read-only",
      "field not in allowed set",
      "target row not permitted",
      "write target unverifiable",
      // Not from §4.4 but part of the same contract: the object rules' reasons (§3.3)
      // are reachable on the write path too.
      "object is hidden",
      "object not in allowed set",
    ];
    // A parameterized reason is compared on its prefix; the field name after the colon
    // is the caller's own payload key.
    const seen = new Set(
      PARITY_CORPUS.map((c) => c.reason?.split(":")[0]).filter((r) => r !== undefined),
    );

    for (const reason of documented) {
      expect(seen.has(reason), `corpus never produces "${reason}"`).toBe(true);
    }
  });

  it("case ids are unique", () => {
    // Duplicate ids would make a cross-SDK diff of the three tables unreadable.
    const ids = PARITY_CORPUS.map((c) => c.id);

    expect(new Set(ids).size).toBe(ids.length);
  });
});
