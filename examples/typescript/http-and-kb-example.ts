/**
 * HTTP endpoints and knowledge bases: the two non-SQL sources, and policies scoped to a source.
 *
 * The framework examples all read a table. Two other kinds of source get their own rules, and
 * this script shows both, enforced by the SDK rather than described:
 *
 * - **An HTTP API**, called through `SecureHttpToolWrapper`. `objectRules.endpointRules` decides
 *   which paths and methods may be requested, *before* the request leaves the process, and the
 *   field and row rules still apply to the JSON that comes back.
 * - **A knowledge base.** `tagRules` are turned into a metadata filter the provider applies at
 *   retrieval (`buildKbFilter` / `renderKbFilter`), and the post pass then re-applies them,
 *   together with `minSimilarityScore`, over whatever the provider returned. The pushdown is an
 *   optimisation; the post pass is the enforcement.
 *
 * Both policies carry `sourcePatterns`, so each applies only to the sources it names. One
 * identity holds both, and resolution picks per source: the API policy for the API, the KB
 * policy for the KB, and nothing at all — deny-all — for a source neither names.
 *
 *     npx tsx http-and-kb-example.ts
 *
 * Deliberately mirrors `examples/python/http_and_kb_example.py` and
 * `examples/dotnet/HttpAndKbExample.cs` — same policies, same fake API, same chunks,
 * byte-identical printed output. A divergence between the languages then shows up as a different
 * result rather than hiding behind separately-written expectations.
 */

import {
  FilterOperator,
  KbFilterOp,
  KbProvider,
  MaskType,
  buildKbFilter,
  buildSecurityContext,
  renderKbFilter,
  resolve,
  signContext,
  type EffectivePolicy,
  type KbFilterClause,
  type PolicyAssignment,
  type PolicyDefinition,
  type SecurityContext,
} from "@aws/tolap-core";
import { SecureContextToolWrapper, SecureHttpToolWrapper, type FetchLike } from "@aws/tolap-mcp";

export const SIGNING_KEY = "example-signing-key-do-not-use-in-production";

export const USER = "analyst-001";
export const TENANT = "hospital-001";

export const API_SOURCE = "api:clinical:patients";
export const KB_SOURCE = "kb:clinical:guidelines";
/** An API source neither policy names. Same category, same endpoint, different namespace. */
export const UNMATCHED_SOURCE = "api:research:patients";

export const BASE_URL = "https://clinical-api.example";

/** What the API returns for `GET /patients`: more rows and more fields than the policy permits. */
export const FAKE_ROWS: Record<string, unknown>[] = [
  { id: 1, name: "Alice Nguyen", region: "us-east", ssn: "111-22-3333", dob: "1979-04-12" },
  { id: 2, name: "Bruno Sato", region: "us-east", ssn: "222-33-4444", dob: "1985-11-02" },
  { id: 3, name: "Carol Diaz", region: "us-east", ssn: "333-44-5555", dob: "1990-01-30" },
  { id: 4, name: "Dan Meyer", region: "eu-west", ssn: "444-55-6666", dob: "1972-08-19" },
];

/** The order columns are printed in, so the output does not depend on map ordering. */
const COLUMNS = ["id", "name", "region", "ssn", "dob"];

export interface Chunk {
  id: string;
  title: string;
  tags: string[];
  /** A second classification the provider does not index; `undefined` when absent. */
  classification?: string;
  score: number;
}

/**
 * What the knowledge base holds. The provider indexes `tags` only; `classification` is metadata
 * it stores but was never asked to filter on.
 */
export const CHUNKS: Chunk[] = [
  { id: "doc-1", title: "Sepsis screening protocol", tags: ["clinical"], score: 0.91 },
  { id: "doc-2", title: "Ward 4 incident review", tags: ["clinical", "restricted"], score: 0.88 },
  { id: "doc-3", title: "Visitor hours", tags: ["public"], score: 0.42 },
  { id: "doc-4", title: "Staff rota, week 39", tags: ["hr"], score: 0.8 },
  {
    id: "doc-5",
    title: "Medication error log",
    tags: ["clinical"],
    classification: "restricted",
    score: 0.86,
  },
  { id: "doc-6", title: "Hand hygiene guideline", tags: ["public"], score: 0.77 },
];

/**
 * The API policy. Applies only to `api:clinical:*`.
 *
 * `allowedMethods` admits GET and POST, and `readOnly` is false, so a POST passes the endpoint
 * check — and is still refused, because no `canInsert` is granted. An endpoint allow-list is not
 * a write grant.
 */
export function apiDefinition(): PolicyDefinition {
  return {
    version: "1.0",
    name: "patients-api-reader",
    priority: 10,
    sourcePatterns: ["api:clinical:*"],
    permissions: { canQuery: true, readOnly: false },
    objectRules: {
      endpointRules: {
        allowedEndpoints: ["/patients", "/patients/*"],
        hiddenEndpoints: ["/patients/*/notes"],
        allowedMethods: ["GET", "POST"],
      },
      fieldRules: {
        hiddenFields: ["ssn"],
        maskedFields: [{ field: "dob", maskType: MaskType.Redact }],
      },
      rowFilters: [{ field: "region", operator: FilterOperator.Equals, value: "us-east" }],
    },
    limits: { maxResults: 2 },
  };
}

/** The KB policy. Applies only to `kb:clinical:*`. */
export function kbDefinition(): PolicyDefinition {
  return {
    version: "1.0",
    name: "clinical-kb-reader",
    priority: 10,
    sourcePatterns: ["kb:clinical:*"],
    permissions: { canQuery: true, readOnly: true },
    objectRules: {
      tagRules: { allowedTags: ["clinical", "public"], deniedTags: ["restricted"] },
    },
    limits: { maxResults: 5, minSimilarityScore: 0.5 },
  };
}

export const DEFINITIONS = [apiDefinition(), kbDefinition()];

/**
 * Resolve exactly as a store would: the same identity and assignments, one source.
 *
 * `sourcePatterns` is applied before the merge, so a definition that does not name the source
 * contributes nothing. When none does, the set is empty and resolution returns deny-all.
 */
export async function resolveFor(source: string): Promise<EffectivePolicy> {
  const assignments: PolicyAssignment[] = DEFINITIONS.map((d) => ({
    version: "1.0",
    policyName: d.name,
    assignee: { type: "user", identifier: USER },
    scope: { tenantId: TENANT },
    active: true,
    audit: {
      grantedBy: "admin-jane-doe",
      grantedAt: "2026-09-01T09:00:00Z",
      reason: `granted for the HTTP and KB example: ${d.name}`,
    },
  }));
  return resolve(
    USER,
    TENANT,
    source,
    assignments,
    Object.fromEntries(DEFINITIONS.map((d) => [d.name, d])),
    () => [],
    () => [],
  );
}

export async function signedContext(source: string): Promise<SecurityContext> {
  return signContext(buildSecurityContext(USER, TENANT, await resolveFor(source)), SIGNING_KEY);
}

// ---------------------------------------------------------------------------------------------
// The HTTP API.
// ---------------------------------------------------------------------------------------------

/** Stands in for the clinical API. Returns everything, and counts what reached it. */
export class FakeApi {
  hits: string[] = [];

  fetch: FetchLike = async (input) => {
    const path = new URL(input.url).pathname;
    this.hits.push(`${input.method} ${path}`);
    const results =
      input.method === "GET" && path === "/patients" ? FAKE_ROWS.map((row) => ({ ...row })) : [];
    return { ok: true, status: 200, json: async () => ({ results }) };
  };
}

export interface HttpCall {
  allowed: boolean;
  reason: string;
  rows?: Record<string, unknown>[];
}

/** One request through the wrapper. A refusal is raised before the request is sent. */
export async function callApi(
  api: FakeApi,
  context: SecurityContext,
  method: string,
  path: string,
): Promise<HttpCall> {
  const http = new SecureHttpToolWrapper({ signingKey: SIGNING_KEY, baseUrl: BASE_URL }, api.fetch);
  const body = method === "POST" ? { name: "Eve Park", region: "us-east" } : undefined;
  try {
    const response = (await http.request(context, {
      method,
      path,
      body,
      collectionPath: "results",
    })) as { results: Record<string, unknown>[] };
    return { allowed: true, reason: "", rows: response.results };
  } catch (denied) {
    const message = (denied as Error).message;
    if (!message.startsWith("Access denied: ")) throw denied;
    return { allowed: false, reason: message.slice("Access denied: ".length) };
  }
}

/** The requests the agent makes, in order. */
export const REQUESTS: [string, string][] = [
  ["GET", "/patients"],
  ["GET", "/patients/1/notes"],
  ["GET", "/billing/invoices"],
  ["DELETE", "/patients/1"],
  ["POST", "/patients"],
];

// ---------------------------------------------------------------------------------------------
// The knowledge base.
// ---------------------------------------------------------------------------------------------

/**
 * Stands in for the provider. Applies the pushed-down clauses to `tags`, and only there.
 *
 * A chunk passes `notIn` when none of its tags is listed, and `in` when at least one is — the
 * list-attribute semantics of the providers the renderers target. It never looks at
 * `classification`, because it was never asked to.
 */
export function fakeKbRetrieve(clauses: KbFilterClause[]): Record<string, unknown>[] {
  const retrieved: Record<string, unknown>[] = [];
  for (const chunk of CHUNKS) {
    const tags = chunk.tags.map((tag) => tag.toLowerCase());
    let keep = true;
    for (const clause of clauses) {
      const listed = tags.some((tag) => clause.values.includes(tag));
      if ((clause.op === KbFilterOp.In && !listed) || (clause.op === KbFilterOp.NotIn && listed)) {
        keep = false;
      }
    }
    if (keep) {
      const record: Record<string, unknown> = { id: chunk.id, title: chunk.title, tags: [...chunk.tags] };
      if (chunk.classification !== undefined) record.classification = chunk.classification;
      record.score = chunk.score;
      retrieved.push(record);
    }
  }
  return retrieved;
}

/** Compact JSON, written out by hand so every language prints the same bytes. */
export function toJson(value: unknown): string {
  if (Array.isArray(value)) return "[" + value.map(toJson).join(",") + "]";
  if (typeof value === "object" && value !== null) {
    return (
      "{" +
      Object.entries(value)
        .map(([k, v]) => `"${k}":${toJson(v)}`)
        .join(",") +
      "}"
    );
  }
  return `"${String(value)}"`;
}

// ---------------------------------------------------------------------------------------------
// Printing. Every line below is byte-identical to the Python and .NET examples.
// ---------------------------------------------------------------------------------------------

const LABEL_WIDTH = 24;
const VERDICT_WIDTH = 8;
const SOURCE_WIDTH = 26;
const PROFILE_WIDTH = 22;

function access(label: string, allowed: boolean, detail = ""): string {
  const verdict = allowed ? "ALLOW" : "DENY";
  return `  ${label.padEnd(LABEL_WIDTH)}${verdict.padEnd(VERDICT_WIDTH)}${detail}`.trimEnd();
}

function rule(title: string): string {
  return `--- ${title} ` + "-".repeat(Math.max(0, 70 - 5 - title.length));
}

function formatRow(row: Record<string, unknown>): string {
  return COLUMNS.filter((column) => column in row)
    .map((column) => `${column}=${String(row[column])}`)
    .join("  ");
}

function op(value: KbFilterOp): string {
  return value === KbFilterOp.In ? "in" : "notIn";
}

/**
 * Why the post pass dropped a chunk the provider returned. Printed only for a chunk the SDK
 * actually dropped; `main` refuses to run if the SDK's drops differ from these.
 */
export const POST_PASS_DROPS: Record<string, string> = {
  "doc-3": "score 0.42 is below minSimilarityScore 0.5",
  "doc-5": "classification restricted, a key the provider never saw",
};

export async function main(): Promise<void> {
  console.log("=".repeat(70));
  console.log("HTTP endpoints and knowledge bases: one identity, three sources");
  console.log("=".repeat(70));
  console.log();
  console.log(`${USER} holds two policy definitions. Each carries sourcePatterns, so it`);
  console.log("applies only to the sources it names:");
  for (const definition of DEFINITIONS) {
    const patterns = (definition.sourcePatterns ?? []).join(", ");
    console.log(`    ${definition.name.padEnd(PROFILE_WIDTH)}sourcePatterns [${patterns}]`);
  }

  // -------------------------------------------------------------- sourcePatterns
  console.log();
  console.log(rule("sourcePatterns: one identity resolved for three sources"));
  for (const source of [API_SOURCE, KB_SOURCE, UNMATCHED_SOURCE]) {
    const policy = await resolveFor(source);
    const profiles = policy.sourceProfiles.join(", ") || "(none)";
    const canQuery = policy.permissions.canQuery ? "true" : "false";
    console.log(`  ${source.padEnd(SOURCE_WIDTH)}${profiles.padEnd(PROFILE_WIDTH)}canQuery=${canQuery}`);
  }
  console.log();
  console.log(`${UNMATCHED_SOURCE} matches neither pattern, so nothing resolves and the`);
  console.log("result is deny-all -- not the API policy borrowed from a similar name.");

  // -------------------------------------------------------------- HTTP
  const api = new FakeApi();
  const context = await signedContext(API_SOURCE);

  console.log();
  console.log(rule(`endpointRules through the HTTP wrapper (${API_SOURCE})`));
  console.log(
    `The fake API returns all ${FAKE_ROWS.length} patients, with ssn and dob, for GET /patients.`,
  );
  console.log("allowedEndpoints [/patients, /patients/*], hiddenEndpoints [/patients/*/notes],");
  console.log("allowedMethods [GET, POST], no canInsert:");
  console.log();

  let rows: Record<string, unknown>[] | undefined;
  for (const [method, path] of REQUESTS) {
    const call = await callApi(api, context, method, path);
    console.log(access(`${method} ${path}`, call.allowed, call.reason));
    if (call.allowed) rows = call.rows;
  }

  if (api.hits.length !== 1 || api.hits[0] !== "GET /patients") {
    throw new Error(`A REFUSED REQUEST REACHED THE API. It saw: ${api.hits.join(", ")}`);
  }
  if (rows === undefined || rows.some((row) => "ssn" in row)) {
    throw new Error("ssn LEAKED. A permitted request must still meet the field rules.");
  }

  console.log();
  console.log(`The fake API was reached ${api.hits.length} time. The four refused requests never`);
  console.log("left the process. POST passed the endpoint rules and was refused by the");
  console.log("missing canInsert: an endpoint allow-list is not a write grant.");
  console.log();
  console.log("GET /patients, after the row, field and limit rules:");
  for (const row of rows) console.log("    " + formatRow(row));

  console.log();
  console.log(`The same GET /patients under a context resolved for ${UNMATCHED_SOURCE}:`);
  const unmatched = await callApi(api, await signedContext(UNMATCHED_SOURCE), "GET", "/patients");
  console.log(access("GET /patients", unmatched.allowed, unmatched.reason));
  if (unmatched.allowed || api.hits.length !== 1) {
    throw new Error("THE UNMATCHED SOURCE WAS SERVED. sourcePatterns must scope the policy.");
  }

  // -------------------------------------------------------------- KB
  const kbPolicy = await resolveFor(KB_SOURCE);
  const kbFilter = buildKbFilter(kbPolicy, { metadataKeys: ["tags"] });
  const rendered = renderKbFilter(kbFilter, KbProvider.Bedrock);

  console.log();
  console.log(rule(`tagRules on a knowledge base (${KB_SOURCE})`));
  console.log("allowedTags [clinical, public], deniedTags [restricted], minSimilarityScore 0.5.");
  console.log();
  console.log('The filter built from the policy for the metadata key "tags":');
  for (const clause of kbFilter.clauses) {
    console.log(`    ${clause.key} ${op(clause.op)} [${clause.values.join(", ")}]`);
  }
  console.log("Rendered for Bedrock:");
  console.log("    " + toJson(rendered.filter));
  const unpushed = kbFilter.unpushedRules.map((r) => r.rule).join(", ") || "none";
  console.log(`Unpushed rules: ${unpushed}`);

  console.log();
  console.log(`The fake KB holds ${CHUNKS.length} chunks and filters on tags only:`);
  for (const chunk of CHUNKS) {
    const extra = chunk.classification ? `  classification=${chunk.classification}` : "";
    console.log(
      `  ${chunk.id}  ${chunk.title.padEnd(28)}score=${chunk.score.toFixed(2)}  tags=${chunk.tags.join(",")}${extra}`,
    );
  }

  const retrieved = fakeKbRetrieve(kbFilter.clauses);
  const retrievedIds = retrieved.map((record) => String(record.id));
  console.log();
  console.log(`The provider returned ${retrieved.length} of ${CHUNKS.length}: ${retrievedIds.join(", ")}`);

  const kbContext = await signedContext(KB_SOURCE);
  const wrapper = new SecureContextToolWrapper({ signingKey: SIGNING_KEY });
  const decision = wrapper.preExecute(kbContext, { toolName: "search_guidelines" });
  if (!decision.allowed) throw new Error(`THE KB SEARCH WAS REFUSED: ${decision.reason}`);
  const enforced = wrapper.postExecute(kbContext, retrieved) as Record<string, unknown>[];
  const keptIds = enforced.map((record) => String(record.id));

  const dropped = retrievedIds.filter((id) => !keptIds.includes(id));
  const expectedDrops = Object.keys(POST_PASS_DROPS).sort();
  if ([...dropped].sort().join(",") !== expectedDrops.join(",")) {
    throw new Error(`THE POST PASS DROPPED ${dropped.join(", ")}, expected ${expectedDrops.join(", ")}.`);
  }

  console.log("The post pass, over what the provider returned:");
  for (const id of retrievedIds) {
    console.log(keptIds.includes(id) ? `  ${id}  KEEP` : `  ${id}  DROP  ${POST_PASS_DROPS[id]}`);
  }

  console.log();
  console.log("The pushdown removed doc-2 (restricted) and doc-4 (hr) at the provider, so");
  console.log("they were never retrieved. doc-5 carries restricted under a key the provider");
  console.log("does not filter on, and the post pass caught it. The pushdown is an");
  console.log("optimisation; the post pass is the enforcement.");

  console.log();
  console.log("=".repeat(70));
  console.log("One identity, one set of assignments. sourcePatterns picked the policy per");
  console.log("source, endpointRules refused requests before they were sent, and tagRules");
  console.log("filtered the knowledge base twice: at the provider, then in the SDK.");
  console.log("=".repeat(70));
}

if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) {
  void main();
}
