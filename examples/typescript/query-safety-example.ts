/**
 * What 1.2.0 changed about queries that span tables, and about results enforced twice.
 *
 * The other examples read one table through one tool. Real agents join, and real data layers
 * sometimes enforce before TOLAP sees the rows. Three things behave differently from 1.1.0, and
 * each section below shows one of them with the SDK's own decisions:
 *
 * 1. **The SQL pre-check reads every table.** A joined, comma-joined or derived table is checked
 *    against `allowedObjects`/`hiddenObjects` like the `FROM` table, every column is resolved
 *    through its alias to the table it belongs to, and a construct the check cannot resolve is
 *    refused rather than guessed at. A refused query never reaches the source.
 * 2. **Qualified names stay with their object.** A row filter on `patients.region` reads
 *    `patients.region`, never `encounters.region`, and `allowedFields` entry `patients.name` no
 *    longer lets `encounters.name` through.
 * 3. **A tool can declare its result already enforced.** A data layer that already ran the
 *    result pipeline returns `EnforcedResult.forContext(rows, context)`, and the wrapper stops
 *    hashing hashed fields a second time. Only a marker bound to this exact signed context is
 *    honoured.
 *
 * One identity, one signed policy, one wrapper. Specified in docs/canonical-enforcement-spec.md
 * §4 and §7 and docs/connector-spec.md §5.
 *
 *     npx tsx query-safety-example.ts
 *
 * Deliberately mirrors `examples/python/query_safety_example.py` and
 * `examples/dotnet/QuerySafetyExample.cs` — same policy, same queries, same rows, byte-identical
 * printed output. A divergence between the languages then shows up as a different result rather
 * than hiding behind separately-written expectations.
 */

import {
  applyResultPipeline,
  buildSecurityContext,
  EnforcedResult,
  signContext,
  FilterOperator,
  MaskType,
  type EffectivePolicy,
  type SecurityContext,
} from "@aws/tolap-core";
import { SecureContextToolWrapper } from "@aws/tolap-mcp";

export const SIGNING_KEY = "example-signing-key-do-not-use-in-production";

/**
 * The salt `hash` masking uses. The data layer in section 3 must use the wrapper's salt, or its
 * hashes would not match the wrapper's and the marker would be a lie.
 */
export const HASH_SALT = "example-hash-salt-do-not-use-in-production";

export const TENANT = "hospital-001";

export const USER = "analyst-001";

export interface Query {
  label: string;
  sql: string;
}

/** Section 1. The first query is the one the policy permits; every other one is refused. */
export const QUERIES: Query[] = [
  {
    label: "join an allowed table",
    sql: "SELECT p.id, p.name, e.code FROM patients p JOIN encounters e ON e.patient_id = p.id",
  },
  {
    label: "join a hidden table",
    sql: "SELECT p.id, b.amount FROM patients p JOIN billing_internal b ON b.patient_id = p.id",
  },
  { label: "comma join", sql: "SELECT p.id FROM patients p, billing_internal b" },
  {
    label: "derived table",
    sql: "SELECT x.id FROM (SELECT patient_id AS id FROM billing_internal) x",
  },
  {
    label: "subquery in WHERE",
    sql: "SELECT p.id FROM patients p WHERE p.id IN (SELECT patient_id FROM billing_internal)",
  },
  {
    label: "hidden field via alias",
    sql: "SELECT p.ssn FROM patients p JOIN encounters e ON e.patient_id = p.id",
  },
  {
    label: "other object's column",
    sql: "SELECT e.name FROM patients p JOIN encounters e ON e.patient_id = p.id",
  },
  {
    label: "bare column in a join",
    sql: "SELECT id FROM patients p JOIN encounters e ON e.patient_id = p.id",
  },
];

/**
 * Section 2. What the join returns, keyed by object. Each row carries two `region` columns and
 * two `name` columns, one per table, so a rule that ignores the qualifier reads the wrong one.
 */
export const JOIN_ROWS: Record<string, unknown>[] = [
  {
    "patients.id": 1,
    "patients.name": "Alice Nguyen",
    "patients.region": "eu-west",
    "patients.ssn": "111-22-3333",
    "encounters.region": "us-east",
    "encounters.name": "Dr Okafor",
    "encounters.code": "E11.9",
  },
  {
    "patients.id": 2,
    "patients.name": "Bruno Sato",
    "patients.region": "us-east",
    "patients.ssn": "222-33-4444",
    "encounters.region": "eu-west",
    "encounters.name": "Dr Lindqvist",
    "encounters.code": "I10",
  },
];

const JOIN_COLUMNS = [
  "patients.id",
  "patients.name",
  "patients.region",
  "patients.ssn",
  "encounters.region",
  "encounters.name",
  "encounters.code",
];

/** Section 2. The field pre-check, told which object a bare field belongs to. */
export const FIELD_CHECKS: [string, string][] = [
  ["patients", "name"],
  ["encounters", "name"],
  ["encounters", "code"],
];

/** Section 3. What the `patients` table holds. */
export const PATIENT_ROWS: Record<string, unknown>[] = [
  { id: 1, name: "Alice Nguyen", email: "alice@example.com", region: "us-east", ssn: "111-22-3333" },
  { id: 2, name: "Dan Meyer", email: "dan@example.com", region: "eu-west", ssn: "444-55-6666" },
];

const PATIENT_COLUMNS = ["id", "name", "email", "region", "ssn"];

/**
 * Two objects the analyst may read, one they may not, and field rules on both.
 *
 * `allowedFields` names each object's columns with its qualifier, which is what makes the
 * qualifier matter: `patients.name` is listed, `encounters.name` is not. In a real deployment
 * this comes from `store.resolvePolicy(...)`; it is written inline here so the rules under test
 * are visible in one place.
 */
export function buildPolicy(userId: string): EffectivePolicy {
  const now = new Date();
  return {
    version: "1.0",
    userId,
    tenantId: TENANT,
    sourceConnectionId: "db:analytics:clinical",
    sourceProfiles: ["clinical-analyst"],
    resolvedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 3_600_000).toISOString(),
    integrity: { algorithm: "none", signature: "" },
    permissions: { canQuery: true, readOnly: true },
    objectRules: {
      allowedObjects: ["patients", "encounters"],
      hiddenObjects: ["billing_internal"],
      fieldRules: {
        hiddenFields: ["ssn"],
        allowedFields: [
          "patients.id",
          "patients.name",
          "patients.email",
          "patients.region",
          "encounters.id",
          "encounters.patient_id",
          "encounters.code",
        ],
        maskedFields: [{ field: "email", maskType: MaskType.Hash }],
      },
      rowFilters: [
        { field: "patients.region", operator: FilterOperator.Equals, value: "us-east" },
      ],
    },
    limits: { maxResults: 10 },
  };
}

export function signedContext(userId: string = USER): SecurityContext {
  return signContext(buildSecurityContext(userId, TENANT, buildPolicy(userId)), SIGNING_KEY);
}

export function wrapper(): SecureContextToolWrapper {
  return new SecureContextToolWrapper({ signingKey: SIGNING_KEY, hashSalt: HASH_SALT });
}

export interface QueryOutcome {
  /** `undefined` when the query ran. */
  reason?: string;
  reached: boolean;
}

/**
 * Section 1: run one query through the SQL path. Returns the denial reason, and whether the
 * source was reached. The fake source records the call and returns the join's rows.
 */
export async function runQuery(context: SecurityContext, sql: string): Promise<QueryOutcome> {
  const reached: string[] = [];
  const source = (query: string): Record<string, unknown>[] => {
    reached.push(query);
    return JOIN_ROWS.map((row) => ({ ...row }));
  };
  try {
    await wrapper().executeSqlWithEnforcement(context, { toolName: "query_patients" }, sql, source);
  } catch (denied) {
    const message = (denied as Error).message.replace(/^Access denied: /, "");
    return { reason: message, reached: reached.length > 0 };
  }
  return { reached: reached.length > 0 };
}

export interface Tool {
  label: string;
  note: string;
  /** Builds the tool's return value from the signed context of the call. */
  returns: (context: SecurityContext) => unknown;
}

/** Stands in for the database. Returns everything, so enforcement is visible. */
export function rawRows(): Record<string, unknown>[] {
  return PATIENT_ROWS.map((row) => ({ ...row }));
}

/** An ORM adapter that runs the result pipeline itself, with the wrapper's salt. */
export function dataLayerRows(context: SecurityContext): unknown {
  return applyResultPipeline(rawRows(), context.effectivePolicy, HASH_SALT);
}

/** Section 3. Five tools, one call each through `executeWithEnforcement`. */
export const TOOLS: Tool[] = [
  { label: "plain rows", note: "the wrapper enforces", returns: () => rawRows() },
  { label: "enforced, unmarked", note: "hashed twice", returns: dataLayerRows },
  {
    label: "enforced, marked",
    note: "marker honoured",
    returns: (ctx) => EnforcedResult.forContext(dataLayerRows(ctx), ctx),
  },
  {
    label: "marked for another user",
    note: "marker ignored",
    returns: () => EnforcedResult.forContext(rawRows(), signedContext("analyst-002")),
  },
  {
    label: "marked, not enforced",
    note: "a false claim",
    returns: (ctx) => EnforcedResult.forContext(rawRows(), ctx),
  },
];

export async function callTool(
  context: SecurityContext,
  tool: Tool,
): Promise<Record<string, unknown>[]> {
  return (await wrapper().executeWithEnforcement(
    context,
    { toolName: "query_patients", objectName: "patients" },
    () => tool.returns(context),
  )) as Record<string, unknown>[];
}

// ---------------------------------------------------------------------------------------------
// Printing. Every line below is byte-identical to the Python and .NET examples.
// ---------------------------------------------------------------------------------------------

const LABEL_WIDTH = 25;
const VERDICT_WIDTH = 8;

function access(label: string, allowed: boolean, detail = ""): string {
  const verdict = allowed ? "ALLOW" : "DENY";
  return `  ${label.padEnd(LABEL_WIDTH)}${verdict.padEnd(VERDICT_WIDTH)}${detail}`.replace(
    /\s+$/,
    "",
  );
}

function rule(title: string): string {
  return `--- ${title} ` + "-".repeat(Math.max(0, 70 - 5 - title.length));
}

function formatRow(row: Record<string, unknown>, columns: string[]): string {
  return columns
    .filter((column) => column in row)
    .map((column) => `${column}=${String(row[column])}`)
    .join("  ");
}

export async function main(): Promise<void> {
  const context = signedContext();
  console.log("=".repeat(70));
  console.log("Query safety: every table checked, every name resolved, one enforcement");
  console.log("=".repeat(70));
  console.log();
  console.log("One analyst, one signed policy:");
  console.log("    allowedObjects  patients, encounters      hiddenObjects  billing_internal");
  console.log(
    "    allowedFields   patients.{id,name,email,region}, encounters.{id,patient_id,code}",
  );
  console.log("    hiddenFields    ssn        maskedFields  email (hash)");
  console.log("    rowFilters      patients.region = us-east");

  // 1. ---------------------------------------------------------------------------------------
  console.log();
  console.log(rule("1. the SQL pre-check reads every table"));
  console.log("Each query goes through the wrapper's SQL path. The source records whether it was");
  console.log("reached; a refused query never is.");
  console.log();
  for (const query of QUERIES) {
    const { reason, reached } = await runQuery(context, query.sql);
    if (reason !== undefined && reached) {
      throw new Error(`A REFUSED QUERY REACHED THE SOURCE: ${query.sql}`);
    }
    console.log("    " + query.sql);
    console.log(access(query.label, reason === undefined, reason ?? "the source ran"));
  }
  console.log();
  console.log("Before 1.2.0 the check did not resolve joined, comma-joined or derived tables, so");
  console.log("the three queries that reach billing_internal that way were not refused by it.");

  // 2. ---------------------------------------------------------------------------------------
  console.log();
  console.log(rule("2. qualified names stay with their object"));
  console.log("The allowed join returns both tables' columns, keyed by object:");
  for (const row of JOIN_ROWS) console.log("    " + formatRow(row, JOIN_COLUMNS));
  console.log();
  console.log("After the result pipeline:");
  const enforced = wrapper().postExecute(
    context,
    JOIN_ROWS.map((row) => ({ ...row })),
  ) as Record<string, unknown>[];
  for (const row of enforced) console.log("    " + formatRow(row, JOIN_COLUMNS));
  if (enforced.some((row) => "patients.ssn" in row || "encounters.name" in row)) {
    throw new Error("A COLUMN THE POLICY DOES NOT ALLOW CAME BACK.");
  }
  console.log();
  console.log("Alice's row is dropped: her patients.region is eu-west. The filter no longer falls");
  console.log("back to encounters.region, whose us-east used to keep her row. encounters.name and");
  console.log("encounters.region are projected out: patients.name does not allow encounters.name.");
  console.log();
  console.log("The field pre-check, told which object a bare field is read from:");
  for (const [objectName, field] of FIELD_CHECKS) {
    const decision = wrapper().preExecute(context, {
      toolName: "query_patients",
      objectName,
      fields: [field],
    });
    console.log(access(`${field} from ${objectName}`, decision.allowed, decision.reason ?? ""));
  }

  // 3. ---------------------------------------------------------------------------------------
  console.log();
  console.log(rule("3. a tool can declare its result already enforced"));
  console.log("Each tool is called through the wrapper's tool path. email is hash-masked, and hash");
  console.log("masking is not idempotent: enforce twice and the value is hashed twice.");
  console.log();
  const reference = await callTool(context, TOOLS[0]);
  for (const tool of TOOLS) {
    const rows = await callTool(context, tool);
    console.log(`  ${tool.label.padEnd(LABEL_WIDTH)}${tool.note}`);
    for (const row of rows) console.log("    " + formatRow(row, PATIENT_COLUMNS));
    if (rows.some((row) => "ssn" in row)) {
      throw new Error("ssn LEAKED. Hidden-field removal runs even for an honoured marker.");
    }
  }
  if (JSON.stringify(await callTool(context, TOOLS[2])) !== JSON.stringify(reference)) {
    throw new Error("AN HONOURED MARKER DID NOT MATCH THE WRAPPER'S OWN ENFORCEMENT.");
  }
  console.log();
  console.log("An honoured marker skips masking and the size ceiling, nothing else: ssn is still");
  console.log("removed and the region filter still runs, which is why the last tool's raw email");
  console.log("comes back while its ssn and Dan's eu-west row do not. The marker is the tool's");
  console.log("claim, not proof, so return one only when the data layer really ran this context's");
  console.log("pipeline. A marker bound to another context is unwrapped and its rows get the full");
  console.log("pipeline, as before 1.2.0. Only the tool path honours a marker; the SQL path and a");
  console.log("direct post-execute call unwrap it and enforce in full.");

  console.log();
  console.log("=".repeat(70));
  console.log("Every decision above is the SDK's. A refused query never reached the source, a");
  console.log("qualified rule read only its own object, and a result was enforced exactly once.");
  console.log("=".repeat(70));
}

// Run directly, not on import, so the test file can call the exports above.
if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) {
  await main();
}
