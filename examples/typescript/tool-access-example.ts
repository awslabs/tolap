/**
 * Gating which MCP tools an identity may call, not just what those tools return.
 *
 * Your MCP host or gateway already decides whether an agent may reach a server, and it decides
 * once, for everyone behind that agent: every user sees the same tool list. The other examples
 * here are about the second question — what a permitted call may return. This one is about the
 * layer in between. A policy that carries `objectRules.toolRules` gives each identity its own
 * answer to "which of these tools may I call at all?":
 *
 * - `allowedTools` — the only tools this identity may call. Matched exactly.
 * - `hiddenTools` — tools this identity may never call. Matched case-insensitively, so a
 *   mis-cased name cannot slip past a hide.
 *
 * One server registers four tools. Three identities hold three signed policies, and for each the
 * script prints what a `tools/list` handler would show, what happens when a client calls every
 * tool anyway, and what a permitted call returns — because the data rules still apply to it.
 *
 * There is no switch in the code. The same wrapper and the same calls run for all three
 * identities; the policy alone decides, and a policy without `toolRules` leaves tool gating with
 * the host exactly as before. Specified in docs/canonical-enforcement-spec.md §16.
 *
 *     npx tsx tool-access-example.ts
 *
 * Deliberately mirrors `examples/python/tool_access_example.py` and
 * `examples/dotnet/ToolAccessExample.cs` — same tools, same policies, same rows, byte-identical
 * printed output. A divergence between the languages then shows up as a different result rather
 * than hiding behind separately-written expectations.
 */

import {
  buildSecurityContext,
  signContext,
  FilterOperator,
  MaskType,
  type AccessResult,
  type EffectivePolicy,
  type SecurityContext,
  type ToolRules,
} from "@aws/tolap-core";
import { SecureContextToolWrapper } from "@aws/tolap-mcp";

export const SIGNING_KEY = "example-signing-key-do-not-use-in-production";

export const TENANT = "hospital-001";

/** What the agent server registers. The host shows this list to every user. */
export const TOOLS = ["query_patients", "count_patients", "export_segment_csv", "delete_patient"];

/** What the "database" holds: more rows and more columns than the data rules permit. */
export const FAKE_ROWS: Record<string, unknown>[] = [
  { id: 1, name: "Alice Nguyen", region: "us-east", ssn: "111-22-3333", dob: "1979-04-12" },
  { id: 2, name: "Bruno Sato", region: "us-east", ssn: "222-33-4444", dob: "1985-11-02" },
  { id: 3, name: "Carol Diaz", region: "us-east", ssn: "333-44-5555", dob: "1990-01-30" },
  { id: 4, name: "Dan Meyer", region: "eu-west", ssn: "444-55-6666", dob: "1972-08-19" },
];

/** The order columns are printed in, so the output does not depend on a runtime's map ordering. */
const COLUMNS = ["id", "name", "region", "ssn", "dob"];

export interface Identity {
  userId: string;
  profile: string;
  /** `undefined` is the data-only case: no tool gating in the policy at all. */
  toolRules?: ToolRules;
  /** A mis-cased name to try as well. */
  misCased?: string;
}

export const IDENTITIES: Identity[] = [
  {
    userId: "analyst-001",
    profile: "patients-analyst",
    toolRules: { allowedTools: ["query_patients", "count_patients"] },
    misCased: "Query_Patients",
  },
  {
    userId: "support-001",
    profile: "patients-support",
    toolRules: { hiddenTools: ["export_segment_csv", "delete_patient"] },
    misCased: "Delete_Patient",
  },
  { userId: "auditor-001", profile: "patients-data-only" },
];

/**
 * The same data rules for everyone; only `toolRules` differs.
 *
 * Holding the data rules constant is what makes the tool layer the only variable: every
 * difference in the output below is `toolRules` at work. In a real deployment each policy comes
 * from `store.resolvePolicy(...)`; it is written inline here so the rules under test are visible
 * in one place.
 */
export function buildPolicy(identity: Identity): EffectivePolicy {
  const now = new Date();
  return {
    version: "1.0",
    userId: identity.userId,
    tenantId: TENANT,
    sourceConnectionId: "db:analytics:patients",
    sourceProfiles: [identity.profile],
    resolvedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 3_600_000).toISOString(),
    integrity: { algorithm: "none", signature: "" },
    permissions: { canQuery: true, readOnly: true },
    objectRules: {
      allowedObjects: ["patients"],
      fieldRules: {
        hiddenFields: ["ssn"],
        maskedFields: [{ field: "dob", maskType: MaskType.Redact }],
      },
      rowFilters: [{ field: "region", operator: FilterOperator.Equals, value: "us-east" }],
      // Absent rather than `undefined`, so the data-only policy signs the bytes it always did.
      ...(identity.toolRules ? { toolRules: identity.toolRules } : {}),
    },
    limits: { maxResults: 2 },
  };
}

/** Signed, so the tool rules cannot be edited in transit by the agent they constrain. */
export function signedContext(identity: Identity): SecurityContext {
  return signContext(
    buildSecurityContext(identity.userId, TENANT, buildPolicy(identity)),
    SIGNING_KEY,
  );
}

/** One wrapper for every identity. There is no tool-rules option to set on it. */
export function wrapper(): SecureContextToolWrapper {
  return new SecureContextToolWrapper({ signingKey: SIGNING_KEY });
}

/** Stands in for the database. Returns everything, so enforcement is visible. */
export function fakeSource(): Record<string, unknown>[] {
  return FAKE_ROWS.map((row) => ({ ...row }));
}

export interface ToolCall {
  decision: AccessResult;
  rows?: Record<string, unknown>[];
}

/**
 * What a `tools/call` handler does: check the tool, then fetch, then enforce on the rows.
 *
 * The tool check runs before `canQuery` and every data check, so a refused tool never reaches
 * the source. Every tool reads `patients` here; that keeps the demo about the tool name rather
 * than about which table each tool happens to touch.
 */
export function callTool(context: SecurityContext, toolName: string): ToolCall {
  const decision = wrapper().preExecute(context, { toolName, objectName: "patients" });
  if (!decision.allowed) return { decision };
  const rows = wrapper().postExecute(context, fakeSource()) as Record<string, unknown>[];
  return { decision, rows };
}

// ---------------------------------------------------------------------------------------------
// Printing. Every line below is byte-identical to the Python and .NET examples.
// ---------------------------------------------------------------------------------------------

const LABEL_WIDTH = 22;
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

function describe(rules: ToolRules | undefined): string {
  if (rules === undefined) return "no toolRules";
  if (rules.allowedTools !== undefined) return `allowedTools [${rules.allowedTools.join(", ")}]`;
  return `hiddenTools [${(rules.hiddenTools ?? []).join(", ")}]`;
}

function formatRow(row: Record<string, unknown>): string {
  return COLUMNS.filter((column) => column in row)
    .map((column) => `${column}=${String(row[column])}`)
    .join("  ");
}

const NOTES: Record<string, string[]> = {
  "analyst-001": [
    "An allow-list: two tools listed, the other two refused when called anyway. The",
    "match is exact, so 'Query_Patients' is not 'query_patients' and is refused too.",
  ],
  "support-001": [
    "A deny-list, landing on the analyst's list from the other side. The difference shows",
    "when the server adds a tool: an allow-list will not list it, a deny-list will. The",
    "hide is case-insensitive, so 'Delete_Patient' is refused rather than slipping past.",
  ],
  "auditor-001": [
    "No toolRules, so TOLAP does not gate tools at all: every tool is listed and",
    "callable, and the decision stays with the host, exactly as before. The data rules",
    "still apply, which is all this policy asks for.",
  ],
};

export function main(): void {
  console.log("=".repeat(70));
  console.log("Tool access: one server, one tool list, a different answer per identity");
  console.log("=".repeat(70));
  console.log();
  console.log("The server registers four tools, and the host shows every user the same list:");
  console.log("    " + TOOLS.join(", "));
  console.log();
  console.log(
    `The database holds ${FAKE_ROWS.length} rows. Every policy below carries the same data rules -- ssn`,
  );
  console.log("hidden, dob redacted, region us-east, at most 2 rows -- so the only thing that");
  console.log("differs between the three identities is objectRules.toolRules.");

  for (const identity of IDENTITIES) {
    const context = signedContext(identity);
    const listed = wrapper().filterTools(context, TOOLS);

    console.log();
    console.log(rule(`${identity.userId}  ${describe(identity.toolRules)}`));
    console.log("tools/list shows: " + listed.join(", "));
    console.log();
    console.log("Every tool called anyway, as a client that ignores the list might:");

    const calledThrough: string[] = [];
    for (const tool of [...TOOLS, ...(identity.misCased ? [identity.misCased] : [])]) {
      const { decision } = callTool(context, tool);
      console.log(access(tool, decision.allowed, decision.reason ?? ""));
      if (decision.allowed && TOOLS.includes(tool)) calledThrough.push(tool);
    }

    if (JSON.stringify(calledThrough) !== JSON.stringify(listed)) {
      throw new Error(
        "THE LIST AND THE CALLS DISAGREED. A tools/list handler must show exactly the tools a " +
          `call would not refuse by name.\n  listed: ${listed}\n  callable: ${calledThrough}`,
      );
    }

    const { rows } = callTool(context, "query_patients");
    if (rows === undefined) throw new Error("query_patients was refused");
    if (rows.some((row) => "ssn" in row)) {
      throw new Error("ssn LEAKED. A permitted tool must still meet the data rules.");
    }

    console.log();
    console.log("query_patients is permitted, and still meets the data rules:");
    for (const row of rows) console.log("    " + formatRow(row));
    console.log();
    for (const line of NOTES[identity.userId]) console.log(line);
  }

  console.log();
  console.log("=".repeat(70));
  console.log("Three identities, one server, one wrapper, no code change between them.");
  console.log("The policy alone picks the combination:");
  console.log("  no toolRules              data access only; tool gating stays with the host");
  console.log("  toolRules and data rules  both layers narrow (the analyst and support above)");
  console.log("  toolRules, no data rules  tool access only");
  console.log();
  console.log("Listing is not permission. Every call is re-checked, which is why the tools the");
  console.log("list never showed were refused when called, before any query was built. And");
  console.log("allowedTools [] is not 'unrestricted': it denies every tool.");
  console.log("=".repeat(70));
}

// Run directly, not on import, so the test file can call the exports above.
if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) {
  main();
}
