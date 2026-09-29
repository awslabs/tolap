/**
 * The policy tour, executed rather than trusted.
 *
 * Each assertion is an outcome — a masked value, a refusal and its reason, the ids a filter kept,
 * what a merge produced — so a tour that printed plausible lines while enforcing nothing would
 * fail here. `EXPECTED_LINES` is byte-identical to the Python and .NET suites'.
 */

import { describe, expect, it } from "vitest";

import { MaskType, WriteOperation } from "@aws/tolap-core";

import * as ex from "./policy-tour-example.js";

/** Every line of the tour that carries a result, in order. */
const EXPECTED_LINES = [
  "--- Masks: one rule per mask type ------------------------------------",
  "  id         no rule                 7                       7",
  "  name       partial showFirst 1     Alice Nguyen            A***********",
  "  phone      partial showLast 4 '#'  555-867-5309            ########5309",
  "  card       partial first 4 last 4  4111111111111111        4111********1111",
  "  address    full                    12 Elm Street           *************",
  "  email      hash sha256             alice@example.com       ff8d9819fc0e12bf",
  "  mrn        hash sha512             MRN-00417               972f27e06cb47c3e",
  "  member_id  hash blake2b            M-99812                 eeeb704b805ffb7c",
  "  notes      null                    allergic to penicillin  null",
  "  dob        redact                  1979-04-12              [REDACTED]",
  "  ssn        hiddenFields            111-22-3333             (dropped)",
  "--- Fields: allowedFields next to hiddenFields -----------------------",
  "  the source returns    id, name, region, dob, notes, ssn",
  "  allowedFields [id, name, region]",
  "    returns             id, name, region",
  "      asks for [id, ssn]            DENY    denied fields: ssn",
  "  hiddenFields [ssn, notes]",
  "    returns             id, name, region, dob",
  "      asks for [id, ssn]            DENY    denied fields: ssn",
  "--- Objects: allowedObjects [patients, encounters, billing_*] --------",
  "                       hiddenObjects [billing_internal]",
  "  patients                          ALLOW",
  "  encounters                        ALLOW",
  "  billing_invoices                  ALLOW",
  "  billing_internal                  DENY    object is hidden",
  "  audit_log                         DENY    object not in allowed set",
  "--- Row filters: one operator at a time over rows 1-6 ----------------",
  "  region equals us-east             ids 1, 4, 6",
  "  region notEquals us-east          ids 2, 3, 5",
  "  region in [us-east, us-west]      ids 1, 2, 4, 6",
  "  region notIn [us-east, us-west]   ids 3, 5",
  "  age greaterThan 40                ids 3, 4, 5",
  "  age lessThanOrEqual 29            ids 2, 6",
  "  age between [30, 52]              ids 1, 3, 5",
  "  email contains @clinic.           ids 1, 2, 4, 6",
  "  ward startsWith cardio            ids 1, 3, 6",
  "  email like %@partner.net          ids 3, 5",
  "  code matches PT-[0-9]{3}          ids 1, 2, 5",
  "  discharged_at isNull              ids 1, 3, 5",
  "  discharged_at isNotNull           ids 2, 4",
  "--- Permissions ------------------------------------------------------",
  "  canQuery false",
  "      query patients                DENY    query not permitted",
  "  canInsert true, readOnly true",
  "      insert                        DENY    read-only policy",
  "  canInsert, canUpdate, readOnly false; mrn read-only; region us-east",
  "      insert                        ALLOW",
  "      insert setting mrn            DENY    field is read-only: mrn",
  "      update a us-east row          ALLOW",
  "      update an eu-west row         DENY    target row not permitted",
  "      delete                        DENY    delete not permitted",
  "--- Limits over seven search hits ------------------------------------",
  "  scores  d1 0.92  d2 0.75  d3 0.60  d4 0.88  d5 0.81  d6 none  d7 0.99",
  "  sizes   d1 1200  d2 4096  d3 800   d4 2048  d5 none  d6 500   d7 100",
  "  minSimilarityScore 0.75           d1, d2, d4, d5, d7",
  "  maxObjectSizeBytes 2048           d1, d3, d4, d6, d7",
  "  maxResults 2                      d1, d2",
  "  all three                         d1, d4",
  "--- Merging: a user policy and a group policy ------------------------",
  "  resolved from    analyst-direct, clinicians-group",
  "  allowedObjects   intersected",
  "    analyst-direct     encounters, labs, patients",
  "    clinicians-group   billing, encounters, patients",
  "    merged             encounters, patients",
  "  hiddenFields     unioned",
  "    analyst-direct     ssn",
  "    clinicians-group   notes",
  "    merged             notes, ssn",
  "  phone mask       the most restrictive",
  "    analyst-direct     partial",
  "    clinicians-group   redact",
  "    merged             redact",
  "  rowFilters       all of them apply",
  "    analyst-direct     region in",
  "    clinicians-group   age greaterThanOrEqual",
  "    merged             region in, age greaterThanOrEqual",
  "  maxResults       the lowest",
  "    analyst-direct     100",
  "    clinicians-group   25",
  "    merged             25",
  "  canInsert        only if every policy grants it",
  "    analyst-direct     no",
  "    clinicians-group   yes",
  "    merged             no",
  "  readOnly         if any policy sets it",
  "    analyst-direct     yes",
  "    clinicians-group   no",
  "    merged             yes",
  "    id=1  region=us-east  age=34  phone=[REDACTED]",
  "    id=4  region=us-east  age=65  phone=[REDACTED]",
  "  labs                              DENY    object not in allowed set",
  "  billing                           DENY    object not in allowed set",
  "  insert                            DENY    insert not permitted",
];

function byLabel<T extends { label: string }>(entries: T[], label: string): T {
  const found = entries.find((e) => e.label === label);
  if (found === undefined) throw new Error(`no entry ${label}`);
  return found;
}

describe("policy tour example", () => {
  it("changes the value for every mask type and drops a hidden field", () => {
    const masked = ex.enforce(ex.maskPolicy(), [ex.PATIENT])[0];

    expect(masked).toEqual({
      id: 7,
      name: "A***********",
      phone: "########5309",
      card: "4111********1111",
      address: "*************",
      email: "ff8d9819fc0e12bf",
      mrn: "972f27e06cb47c3e",
      member_id: "eeeb704b805ffb7c",
      notes: null,
      dob: "[REDACTED]",
    });
  });

  it("keeps only allowedFields and drops only hiddenFields", () => {
    const source = { id: 1, name: "n", region: "r", dob: "d", notes: "x", ssn: "s" };

    expect(Object.keys(ex.enforce(ex.allowedFieldsPolicy(), [source])[0]).sort()).toEqual([
      "id",
      "name",
      "region",
    ]);
    expect(Object.keys(ex.enforce(ex.hiddenFieldsPolicy(), [source])[0]).sort()).toEqual([
      "dob",
      "id",
      "name",
      "region",
    ]);
  });

  it.each([
    ["patients", true, undefined],
    ["billing_invoices", true, undefined],
    ["billing_internal", false, "object is hidden"],
    ["audit_log", false, "object not in allowed set"],
  ])("lets hiddenObjects win over allowedObjects for %s", (name, allowed, reason) => {
    const result = ex.check(ex.objectPolicy(), name);

    expect(result.allowed).toBe(allowed);
    if (reason !== undefined) expect(result.reason).toBe(reason);
  });

  it.each([
    ["region equals us-east", [1, 4, 6]],
    ["region notEquals us-east", [2, 3, 5]],
    ["region in [us-east, us-west]", [1, 2, 4, 6]],
    ["region notIn [us-east, us-west]", [3, 5]],
    ["age greaterThan 40", [3, 4, 5]],
    ["age lessThanOrEqual 29", [2, 6]],
    ["age between [30, 52]", [1, 3, 5]],
    ["email contains @clinic.", [1, 2, 4, 6]],
    ["ward startsWith cardio", [1, 3, 6]],
    ["email like %@partner.net", [3, 5]],
    ["code matches PT-[0-9]{3}", [1, 2, 5]],
    ["discharged_at isNull", [1, 3, 5]],
    ["discharged_at isNotNull", [2, 4]],
  ])("keeps the expected rows for %s", (label, ids) => {
    const { rule } = byLabel(ex.FILTERS, label as string);

    expect(ex.enforce(ex.filterPolicy(rule), ex.ROWS).map((r) => r.id)).toEqual(ids);
  });

  it("refuses under canQuery false and readOnly true", () => {
    const query = ex.check(ex.queryDeniedPolicy(), "patients");
    expect(query.allowed).toBe(false);
    expect(query.reason).toBe("query not permitted");

    const insert = ex.checkWrite(ex.readOnlyPolicy(), WriteOperation.Insert, { name: "Bo" });
    expect(insert.allowed).toBe(false);
    expect(insert.reason).toBe("read-only policy");
  });

  it("still applies the field and row rules to a granted write", () => {
    const writer = ex.writerPolicy();
    const east = { id: 1, region: "us-east" };
    const west = { id: 3, region: "eu-west" };

    expect(
      ex.checkWrite(writer, WriteOperation.Insert, { name: "Bo", region: "us-east" }).allowed,
    ).toBe(true);
    expect(ex.checkWrite(writer, WriteOperation.Insert, { mrn: "MRN-1" }).reason).toBe(
      "field is read-only: mrn",
    );
    expect(ex.checkWrite(writer, WriteOperation.Update, { name: "Bo" }, east).allowed).toBe(true);
    expect(ex.checkWrite(writer, WriteOperation.Update, { name: "Bo" }, west).reason).toBe(
      "target row not permitted",
    );
    expect(ex.checkWrite(writer, WriteOperation.Delete, {}, east).reason).toBe(
      "delete not permitted",
    );
  });

  it.each([
    ["minSimilarityScore 0.75", ["d1", "d2", "d4", "d5", "d7"]],
    ["maxObjectSizeBytes 2048", ["d1", "d3", "d4", "d6", "d7"]],
    ["maxResults 2", ["d1", "d2"]],
    ["all three", ["d1", "d4"]],
  ])("keeps the expected hits under %s", (label, ids) => {
    const { limits } = byLabel(ex.LIMITS, label as string);

    expect(ex.enforce(ex.policy({ limits }), ex.DOCUMENTS).map((r) => r.id)).toEqual(ids);
  });

  it("merges a user and a group policy so the most restrictive rule wins", async () => {
    const merged = await ex.mergedPolicy();
    const rules = merged.objectRules!;

    expect(merged.sourceProfiles).toEqual(["analyst-direct", "clinicians-group"]);
    expect([...(rules.allowedObjects ?? [])].sort()).toEqual(["encounters", "patients"]);
    expect([...(rules.fieldRules?.hiddenFields ?? [])].sort()).toEqual(["notes", "ssn"]);
    expect(rules.fieldRules?.maskedFields?.find((m) => m.field === "phone")?.maskType).toBe(
      MaskType.Redact,
    );
    expect(rules.rowFilters).toHaveLength(2);
    expect(merged.limits?.maxResults).toBe(25);
    expect(merged.permissions.canInsert).not.toBe(true);
    expect(merged.permissions.readOnly).toBe(true);

    const rows = ex.enforce(merged, ex.MERGE_ROWS);
    expect(rows.map((r) => r.id)).toEqual([1, 4]);
    for (const row of rows) {
      expect(row).not.toHaveProperty("ssn");
      expect(row).not.toHaveProperty("notes");
      expect(row.phone).toBe("[REDACTED]");
    }
  });

  it("runs clean and prints the lines the other two languages print", async () => {
    // main() throws if a mask or the merge lets a hidden field through, so this covers those
    // paths too.
    const lines: string[] = [];
    const original = console.log;
    console.log = (...args: unknown[]) => {
      lines.push(...args.map(String).join(" ").split("\n"));
    };
    try {
      await ex.main();
    } finally {
      console.log = original;
    }

    const results = lines.filter((l) => l.startsWith("  ") || l.startsWith("---"));
    expect(results).toEqual(EXPECTED_LINES);
  });
});
