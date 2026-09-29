/**
 * A tour of every policy rule the SDK enforces, one section per rule.
 *
 * The framework examples all hold the same small policy, because their point is the
 * integration. This one holds the integration constant instead and changes the policy, so each
 * rule is seen on its own against data that shows what it did:
 *
 * - **Masks** — `full`, `partial` (`showFirst`/`showLast`/`maskChar`), `hash` (`sha256`,
 *   `sha512`, `blake2b`), `null` and `redact`, raw value next to masked value.
 * - **Fields** — `allowedFields` (keep only these) next to `hiddenFields` (drop only these).
 * - **Objects** — `allowedObjects` next to `hiddenObjects`, and a refused call for each.
 * - **Row filters** — every operator family, each on its own, over the same six rows.
 * - **Permissions** — `canQuery: false`, `readOnly: true` refusing a write, and the write checks
 *   that still run once writes are granted.
 * - **Limits** — `minSimilarityScore`, `maxObjectSizeBytes` and `maxResults`.
 * - **Merging** — a user policy and a group policy resolved into one, where the most restrictive
 *   rule wins.
 *
 * Every verdict and every masked value below comes from the SDK; the script only prints. Where a
 * rule refuses something, the reason is the SDK's own string.
 *
 *     npx tsx policy-tour-example.ts
 *
 * Deliberately mirrors `examples/python/policy_tour_example.py` and
 * `examples/dotnet/PolicyTourExample.cs` — same policies, same rows, byte-identical printed
 * output. A divergence between the languages then shows up as a different result rather than
 * hiding behind separately-written expectations.
 */

import {
  AssigneeType,
  FilterOperator,
  MaskType,
  WriteOperation,
  buildSecurityContext,
  resolve,
  signContext,
  type AccessResult,
  type EffectivePolicy,
  type FieldRules,
  type ObjectRules,
  type PolicyAssignment,
  type PolicyDefinition,
  type PolicyLimits,
  type PolicyPermissions,
  type RowFilter,
  type SecurityContext,
} from "@aws/tolap-core";
import { SecureContextToolWrapper } from "@aws/tolap-mcp";

export const SIGNING_KEY = "example-signing-key-do-not-use-in-production";

export const TENANT = "hospital-001";

export const SOURCE = "db:clinical:patients";

export const USER = "analyst-001";

type Row = Record<string, unknown>;

// ---------------------------------------------------------------------------------------------
// The data. Each "database" returns more than any policy below permits.
// ---------------------------------------------------------------------------------------------

/** One patient, with a column for every mask type. */
export const PATIENT: Row = {
  id: 7,
  name: "Alice Nguyen",
  phone: "555-867-5309",
  card: "4111111111111111",
  address: "12 Elm Street",
  email: "alice@example.com",
  mrn: "MRN-00417",
  member_id: "M-99812",
  notes: "allergic to penicillin",
  dob: "1979-04-12",
  ssn: "111-22-3333",
};

/** Rows for the row-filter section. Row 6 has no `discharged_at` key at all. */
export const ROWS: Row[] = [
  { id: 1, region: "us-east", age: 34, ward: "cardiology", email: "alice@clinic.org", code: "PT-101", discharged_at: null },
  { id: 2, region: "us-west", age: 17, ward: "pediatrics", email: "bruno@clinic.org", code: "PT-102", discharged_at: "2026-08-01" },
  { id: 3, region: "eu-west", age: 52, ward: "cardiology", email: "carol@partner.net", code: "PT-10A", discharged_at: null },
  { id: 4, region: "us-east", age: 65, ward: "oncology", email: "dan@clinic.org", code: "XX-104", discharged_at: "2026-07-15" },
  { id: 5, region: "ap-south", age: 41, ward: "neurology", email: "erin@partner.net", code: "PT-105", discharged_at: null },
  { id: 6, region: "us-east", age: 29, ward: "cardiology-icu", email: "fay@clinic.org", code: "pt-106" },
];

/** Search hits for the limits section. d5 carries no size and d6 no score. */
export const DOCUMENTS: Row[] = [
  { id: "d1", score: 0.92, size: 1200 },
  { id: "d2", score: 0.75, size: 4096 },
  { id: "d3", score: 0.6, size: 800 },
  { id: "d4", score: 0.88, size: 2048 },
  { id: "d5", score: 0.81 },
  { id: "d6", size: 500 },
  { id: "d7", score: 0.99, size: 100 },
];

/** Rows for the merge section. */
export const MERGE_ROWS: Row[] = [
  { id: 1, region: "us-east", age: 34, phone: "555-867-5309", ssn: "111-22-3333", notes: "stable" },
  { id: 2, region: "us-west", age: 17, phone: "555-201-4471", ssn: "222-33-4444", notes: "minor" },
  { id: 3, region: "eu-west", age: 52, phone: "555-310-9920", ssn: "333-44-5555", notes: "transfer" },
  { id: 4, region: "us-east", age: 65, phone: "555-448-1062", ssn: "444-55-6666", notes: "follow-up" },
];

/** The order columns are printed in, so the output does not depend on a runtime's map ordering. */
const PATIENT_COLUMNS = ["id", "name", "phone", "card", "address", "email", "mrn", "member_id", "notes", "dob", "ssn"];
const FIELD_COLUMNS = ["id", "name", "region", "dob", "notes", "ssn"];
const MERGE_COLUMNS = ["id", "region", "age", "phone", "notes", "ssn"];

// ---------------------------------------------------------------------------------------------
// Policies. Each one is written inline so the rule under test is visible where it is used; in a
// real deployment they come from `store.resolvePolicy(...)`.
// ---------------------------------------------------------------------------------------------

/** An effective policy holding only the rule a section is about. */
export function policy(
  rules: { permissions?: PolicyPermissions; objectRules?: ObjectRules; limits?: PolicyLimits } = {},
): EffectivePolicy {
  const now = new Date();
  return {
    version: "1.0",
    userId: USER,
    tenantId: TENANT,
    sourceConnectionId: SOURCE,
    sourceProfiles: ["policy-tour"],
    resolvedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 3_600_000).toISOString(),
    integrity: { algorithm: "none", signature: "" },
    permissions: rules.permissions ?? { canQuery: true, readOnly: true },
    ...(rules.objectRules ? { objectRules: rules.objectRules } : {}),
    ...(rules.limits ? { limits: rules.limits } : {}),
  };
}

/** One rule per mask type, and `ssn` hidden outright for contrast. */
export function maskPolicy(): EffectivePolicy {
  return policy({
    objectRules: {
      fieldRules: {
        hiddenFields: ["ssn"],
        maskedFields: [
          { field: "name", maskType: MaskType.Partial, parameters: { showFirst: 1 } },
          { field: "phone", maskType: MaskType.Partial, parameters: { showLast: 4, maskChar: "#" } },
          { field: "card", maskType: MaskType.Partial, parameters: { showFirst: 4, showLast: 4 } },
          { field: "address", maskType: MaskType.Full },
          { field: "email", maskType: MaskType.Hash, parameters: { algorithm: "sha256" } },
          { field: "mrn", maskType: MaskType.Hash, parameters: { algorithm: "sha512" } },
          { field: "member_id", maskType: MaskType.Hash, parameters: { algorithm: "blake2b" } },
          { field: "notes", maskType: MaskType.Null },
          { field: "dob", maskType: MaskType.Redact },
        ],
      },
    },
  });
}

/** Label shown for each mask rule, in PATIENT_COLUMNS order. */
const MASK_LABELS: Record<string, string> = {
  id: "no rule",
  name: "partial showFirst 1",
  phone: "partial showLast 4 '#'",
  card: "partial first 4 last 4",
  address: "full",
  email: "hash sha256",
  mrn: "hash sha512",
  member_id: "hash blake2b",
  notes: "null",
  dob: "redact",
  ssn: "hiddenFields",
};

/** An allow-list of fields: anything not named is dropped, including columns added later. */
export function allowedFieldsPolicy(): EffectivePolicy {
  return policy({ objectRules: { fieldRules: { allowedFields: ["id", "name", "region"] } } });
}

/** A deny-list of fields: only the named ones are dropped. */
export function hiddenFieldsPolicy(): EffectivePolicy {
  return policy({ objectRules: { fieldRules: { hiddenFields: ["ssn", "notes"] } } });
}

/** `billing_*` is allowed, and `billing_internal` is hidden anyway: hidden wins. */
export function objectPolicy(): EffectivePolicy {
  return policy({
    objectRules: {
      allowedObjects: ["patients", "encounters", "billing_*"],
      hiddenObjects: ["billing_internal"],
    },
  });
}

export const OBJECT_PROBES = ["patients", "encounters", "billing_invoices", "billing_internal", "audit_log"];

export interface Filter {
  label: string;
  rule: RowFilter;
}

export const FILTERS: Filter[] = [
  { label: "region equals us-east", rule: { field: "region", operator: FilterOperator.Equals, value: "us-east" } },
  { label: "region notEquals us-east", rule: { field: "region", operator: FilterOperator.NotEquals, value: "us-east" } },
  { label: "region in [us-east, us-west]", rule: { field: "region", operator: FilterOperator.In, values: ["us-east", "us-west"] } },
  { label: "region notIn [us-east, us-west]", rule: { field: "region", operator: FilterOperator.NotIn, values: ["us-east", "us-west"] } },
  { label: "age greaterThan 40", rule: { field: "age", operator: FilterOperator.GreaterThan, value: 40 } },
  { label: "age lessThanOrEqual 29", rule: { field: "age", operator: FilterOperator.LessThanOrEqual, value: 29 } },
  { label: "age between [30, 52]", rule: { field: "age", operator: FilterOperator.Between, values: [30, 52] } },
  { label: "email contains @clinic.", rule: { field: "email", operator: FilterOperator.Contains, value: "@clinic." } },
  { label: "ward startsWith cardio", rule: { field: "ward", operator: FilterOperator.StartsWith, value: "cardio" } },
  { label: "email like %@partner.net", rule: { field: "email", operator: FilterOperator.Like, value: "%@partner.net" } },
  { label: "code matches PT-[0-9]{3}", rule: { field: "code", operator: FilterOperator.Matches, value: "PT-[0-9]{3}" } },
  { label: "discharged_at isNull", rule: { field: "discharged_at", operator: FilterOperator.IsNull } },
  { label: "discharged_at isNotNull", rule: { field: "discharged_at", operator: FilterOperator.IsNotNull } },
];

export function filterPolicy(rule: RowFilter): EffectivePolicy {
  return policy({ objectRules: { rowFilters: [rule] } });
}

/** Holds object rules, but no reads at all: `canQuery` is checked before any of them. */
export function queryDeniedPolicy(): EffectivePolicy {
  return policy({ permissions: { canQuery: false }, objectRules: { allowedObjects: ["patients"] } });
}

/** Grants inserts, and is read-only anyway: `readOnly` is a ceiling over the grants. */
export function readOnlyPolicy(): EffectivePolicy {
  return policy({ permissions: { canQuery: true, canInsert: true, readOnly: true } });
}

/** Inserts and updates granted, but only on us-east rows and never to `mrn`. */
export function writerPolicy(): EffectivePolicy {
  return policy({
    permissions: { canQuery: true, canInsert: true, canUpdate: true, readOnly: false },
    objectRules: {
      fieldRules: { readOnlyFields: ["mrn"] },
      rowFilters: [{ field: "region", operator: FilterOperator.Equals, value: "us-east" }],
    },
  });
}

export interface Limit {
  label: string;
  limits: PolicyLimits;
}

export const LIMITS: Limit[] = [
  { label: "minSimilarityScore 0.75", limits: { minSimilarityScore: 0.75 } },
  { label: "maxObjectSizeBytes 2048", limits: { maxObjectSizeBytes: 2048 } },
  { label: "maxResults 2", limits: { maxResults: 2 } },
  { label: "all three", limits: { maxResults: 2, minSimilarityScore: 0.75, maxObjectSizeBytes: 2048 } },
];

// ---------------------------------------------------------------------------------------------
// Merging: two policy definitions, one granted to the user and one to a group they belong to.
// ---------------------------------------------------------------------------------------------

export const GROUP = "clinicians";

function audit(reason: string) {
  return { grantedBy: "admin-jane-doe", grantedAt: "2026-09-01T09:00:00Z", reason };
}

/** Assigned to the analyst directly. Read-only, the wider row cap, a partial phone mask. */
export function userDefinition(): PolicyDefinition {
  return {
    version: "1.0",
    name: "analyst-direct",
    permissions: { canQuery: true, readOnly: true },
    priority: 10,
    sourcePatterns: ["db:clinical:*"],
    objectRules: {
      allowedObjects: ["patients", "encounters", "labs"],
      fieldRules: {
        hiddenFields: ["ssn"],
        maskedFields: [{ field: "phone", maskType: MaskType.Partial, parameters: { showLast: 4 } }],
      },
      rowFilters: [{ field: "region", operator: FilterOperator.In, values: ["us-east", "us-west"] }],
    },
    limits: { maxResults: 100 },
  };
}

/** Assigned to the clinicians group. Grants inserts, a lower row cap, redacts the phone. */
export function groupDefinition(): PolicyDefinition {
  return {
    version: "1.0",
    name: "clinicians-group",
    permissions: { canQuery: true, canInsert: true, readOnly: false },
    priority: 50,
    sourcePatterns: ["db:clinical:*"],
    objectRules: {
      allowedObjects: ["patients", "encounters", "billing"],
      fieldRules: {
        hiddenFields: ["notes"],
        maskedFields: [{ field: "phone", maskType: MaskType.Redact }],
      },
      rowFilters: [{ field: "age", operator: FilterOperator.GreaterThanOrEqual, value: 18 }],
    },
    limits: { maxResults: 25 },
  };
}

export function mergeAssignments(): PolicyAssignment[] {
  return [
    {
      version: "1.0",
      policyName: "analyst-direct",
      assignee: { type: AssigneeType.User, identifier: USER },
      scope: { tenantId: TENANT },
      active: true,
      audit: audit("policy tour: the user's own grant"),
    },
    {
      version: "1.0",
      policyName: "clinicians-group",
      assignee: { type: AssigneeType.Group, identifier: GROUP },
      scope: { tenantId: TENANT },
      active: true,
      audit: audit("policy tour: the group's grant"),
    },
  ];
}

/** Resolved exactly as a store would: both assignments match, so both definitions merge. */
export async function mergedPolicy(): Promise<EffectivePolicy> {
  const definitions = [userDefinition(), groupDefinition()];
  return resolve(
    USER,
    TENANT,
    SOURCE,
    mergeAssignments(),
    Object.fromEntries(definitions.map((d) => [d.name, d])),
    () => [GROUP],
    () => [],
  );
}

// ---------------------------------------------------------------------------------------------
// Enforcement. The same wrapper and the same three calls for every section.
// ---------------------------------------------------------------------------------------------

/** Signed, so the policy cannot be edited in transit by the agent it constrains. */
export function signedContext(effective: EffectivePolicy): SecurityContext {
  return signContext(buildSecurityContext(USER, TENANT, effective), SIGNING_KEY);
}

export function wrapper(): SecureContextToolWrapper {
  return new SecureContextToolWrapper({ signingKey: SIGNING_KEY });
}

/** The post-execution pipeline over copies of `rows`, so the source data is never touched. */
export function enforce(effective: EffectivePolicy, rows: Row[]): Row[] {
  return wrapper().postExecute(
    signedContext(effective),
    rows.map((row) => ({ ...row })),
  ) as Row[];
}

export function check(
  effective: EffectivePolicy,
  objectName?: string,
  fields?: string[],
): AccessResult {
  return wrapper().preExecute(signedContext(effective), {
    toolName: "query_patients",
    objectName,
    fields,
  });
}

export function checkWrite(
  effective: EffectivePolicy,
  operation: WriteOperation,
  payload: Row,
  targetRow?: Row,
): AccessResult {
  return wrapper().preWrite(
    signedContext(effective),
    operation,
    "patients",
    payload,
    targetRow === undefined ? {} : { targetRow },
  );
}

// ---------------------------------------------------------------------------------------------
// Printing. Every line below is byte-identical to the Python and .NET examples.
// ---------------------------------------------------------------------------------------------

const LABEL_WIDTH = 34;
const VERDICT_WIDTH = 8;

function access(label: string, result: AccessResult): string {
  const verdict = result.allowed ? "ALLOW" : "DENY";
  return `  ${label.padEnd(LABEL_WIDTH)}${verdict.padEnd(VERDICT_WIDTH)}${result.reason ?? ""}`.replace(
    /\s+$/,
    "",
  );
}

function rule(title: string): string {
  return `--- ${title} ` + "-".repeat(Math.max(0, 70 - 5 - title.length));
}

function value(v: unknown): string {
  return v === null || v === undefined ? "null" : String(v);
}

function columns(row: Row, order: string[]): string {
  return order.filter((column) => column in row).join(", ");
}

function formatRow(row: Row, order: string[]): string {
  return order
    .filter((column) => column in row)
    .map((column) => `${column}=${value(row[column])}`)
    .join("  ");
}

function ids(rows: Row[]): string {
  return rows.map((row) => String(row.id)).join(", ") || "(none)";
}

type Source = PolicyDefinition | EffectivePolicy;

function rulesOf(source: Source): ObjectRules {
  return source.objectRules ?? {};
}

function fieldsOf(source: Source): FieldRules {
  return rulesOf(source).fieldRules ?? {};
}

function yes(flag: boolean | undefined): string {
  return flag ? "yes" : "no";
}

function sorted(values: string[] | undefined): string {
  return [...(values ?? [])].sort().join(", ");
}

/**
 * Each merged rule, how the merge combines it, and how to read it off a definition or a policy.
 * Lists are printed sorted, so the output does not depend on the order a merge emits them in.
 */
const MERGE_TABLE: [string, string, (s: Source) => string][] = [
  ["allowedObjects", "intersected", (s) => sorted(rulesOf(s).allowedObjects)],
  ["hiddenFields", "unioned", (s) => sorted(fieldsOf(s).hiddenFields)],
  [
    "phone mask",
    "the most restrictive",
    (s) =>
      (fieldsOf(s).maskedFields ?? [])
        .filter((m) => m.field === "phone")
        .map((m) => String(m.maskType))
        .join(", "),
  ],
  [
    "rowFilters",
    "all of them apply",
    (s) => (rulesOf(s).rowFilters ?? []).map((f) => `${f.field} ${f.operator}`).join(", "),
  ],
  ["maxResults", "the lowest", (s) => value(s.limits?.maxResults)],
  ["canInsert", "only if every policy grants it", (s) => yes(s.permissions.canInsert)],
  ["readOnly", "if any policy sets it", (s) => yes(s.permissions.readOnly)],
];

export async function main(): Promise<void> {
  console.log("=".repeat(70));
  console.log("Policy tour: every rule the SDK enforces, one section each");
  console.log("=".repeat(70));
  console.log();
  console.log("Every section below uses the same signed context, the same wrapper and the same");
  console.log("calls. Only the policy changes, and the source returns everything each time, so");
  console.log("what is missing or masked in the output is enforcement.");

  // -- Masks ----------------------------------------------------------------------------------
  console.log();
  console.log(rule("Masks: one rule per mask type"));
  const masked = enforce(maskPolicy(), [PATIENT])[0];
  for (const column of PATIENT_COLUMNS) {
    const after = column in masked ? value(masked[column]) : "(dropped)";
    console.log(
      `  ${column.padEnd(11)}${MASK_LABELS[column].padEnd(24)}${value(PATIENT[column]).padEnd(24)}${after}`,
    );
  }
  if ("ssn" in masked || masked.dob !== "[REDACTED]") {
    throw new Error("MASKING FAILED. ssn must be dropped and dob redacted.");
  }
  console.log();
  console.log("Hashes are the first 16 hex characters of the digest, so the same input always");
  console.log("gives the same token: rows still join and group on email without revealing it.");

  // -- Fields ---------------------------------------------------------------------------------
  console.log();
  console.log(rule("Fields: allowedFields next to hiddenFields"));
  const source: Row = { id: 1, name: "Alice Nguyen", region: "us-east", dob: "1979-04-12", notes: "stable", ssn: "111-22-3333" };
  console.log("  the source returns    " + columns(source, FIELD_COLUMNS));
  for (const [label, effective] of [
    ["allowedFields [id, name, region]", allowedFieldsPolicy()],
    ["hiddenFields [ssn, notes]", hiddenFieldsPolicy()],
  ] as const) {
    const kept = enforce(effective, [source])[0];
    console.log();
    console.log(`  ${label}`);
    console.log("    returns             " + columns(kept, FIELD_COLUMNS));
    console.log(access("    asks for [id, ssn]", check(effective, undefined, ["id", "ssn"])));
  }
  console.log();
  console.log("An allow-list also drops a column the source adds tomorrow; a deny-list keeps it.");

  // -- Objects --------------------------------------------------------------------------------
  console.log();
  console.log(rule("Objects: allowedObjects [patients, encounters, billing_*]"));
  console.log("                       hiddenObjects [billing_internal]");
  for (const name of OBJECT_PROBES) console.log(access(name, check(objectPolicy(), name)));
  console.log();
  console.log("billing_internal matches the billing_* allow and is refused anyway: a hide wins.");

  // -- Row filters ----------------------------------------------------------------------------
  console.log();
  console.log(rule("Row filters: one operator at a time over rows 1-6"));
  for (const entry of FILTERS) {
    console.log(`  ${entry.label.padEnd(LABEL_WIDTH)}ids ${ids(enforce(filterPolicy(entry.rule), ROWS))}`);
  }
  console.log();
  console.log("Row 6 has no discharged_at key, so it fails isNull and isNotNull alike: a missing");
  console.log("field never passes a filter. matches is anchored and case-sensitive, so PT-10A");
  console.log("and pt-106 fail it; between is inclusive, so age 52 is kept.");

  // -- Permissions ----------------------------------------------------------------------------
  console.log();
  console.log(rule("Permissions"));
  console.log("  canQuery false");
  console.log(access("    query patients", check(queryDeniedPolicy(), "patients")));
  console.log("  canInsert true, readOnly true");
  console.log(access("    insert", checkWrite(readOnlyPolicy(), WriteOperation.Insert, { name: "Bo" })));
  console.log("  canInsert, canUpdate, readOnly false; mrn read-only; region us-east");
  const writer = writerPolicy();
  const east: Row = { id: 1, region: "us-east" };
  const west: Row = { id: 3, region: "eu-west" };
  console.log(access("    insert", checkWrite(writer, WriteOperation.Insert, { name: "Bo", region: "us-east" })));
  console.log(access("    insert setting mrn", checkWrite(writer, WriteOperation.Insert, { name: "Bo", mrn: "MRN-1" })));
  console.log(access("    update a us-east row", checkWrite(writer, WriteOperation.Update, { name: "Bo" }, east)));
  console.log(access("    update an eu-west row", checkWrite(writer, WriteOperation.Update, { name: "Bo" }, west)));
  console.log(access("    delete", checkWrite(writer, WriteOperation.Delete, {}, east)));
  console.log();
  console.log("readOnly is a ceiling over the grants, not a default beside them. Once writes are");
  console.log("granted, the field and row rules still apply to what a write touches.");

  // -- Limits ---------------------------------------------------------------------------------
  console.log();
  console.log(rule("Limits over seven search hits"));
  console.log("  scores  d1 0.92  d2 0.75  d3 0.60  d4 0.88  d5 0.81  d6 none  d7 0.99");
  console.log("  sizes   d1 1200  d2 4096  d3 800   d4 2048  d5 none  d6 500   d7 100");
  console.log();
  for (const limit of LIMITS) {
    console.log(`  ${limit.label.padEnd(LABEL_WIDTH)}${ids(enforce(policy({ limits: limit.limits }), DOCUMENTS))}`);
  }
  console.log();
  console.log("Both bounds are inclusive, and a hit with no score or no size is dropped rather");
  console.log("than let through. maxResults applies last, to what the other rules kept.");

  // -- Merging --------------------------------------------------------------------------------
  console.log();
  console.log(rule("Merging: a user policy and a group policy"));
  const merged = await mergedPolicy();
  console.log("  resolved from    " + merged.sourceProfiles.join(", "));
  const user = userDefinition();
  const group = groupDefinition();
  for (const [title, how, pick] of MERGE_TABLE) {
    console.log();
    console.log(`  ${title.padEnd(17)}${how}`);
    for (const [name, from] of [
      [user.name, user],
      [group.name, group],
      ["merged", merged],
    ] as const) {
      console.log(`    ${name.padEnd(19)}${pick(from)}`);
    }
  }
  console.log();
  console.log("The merged policy, enforced:");
  const mergedRows = enforce(merged, MERGE_ROWS);
  if (mergedRows.some((row) => "ssn" in row || "notes" in row)) {
    throw new Error("A HIDDEN FIELD LEAKED. The merge must union both policies' hidden fields.");
  }
  for (const row of mergedRows) console.log("    " + formatRow(row, MERGE_COLUMNS));
  console.log(access("labs", check(merged, "labs")));
  console.log(access("billing", check(merged, "billing")));
  console.log(access("insert", checkWrite(merged, WriteOperation.Insert, { name: "Bo" })));
  console.log();
  console.log("Most restrictive wins: allowed sets intersect, hidden fields union, the stronger");
  console.log("mask and the lower cap apply, every row filter holds, and a grant survives only if");
  console.log("every policy makes it. The group's insert grant is outvoted by the user's policy.");

  console.log();
  console.log("=".repeat(70));
  console.log("One wrapper, one set of calls; the policy alone decided every line above.");
  console.log("=".repeat(70));
}

// Run directly, not on import, so the test file can call the exports above.
if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) {
  await main();
}
