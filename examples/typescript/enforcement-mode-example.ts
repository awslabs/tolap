/**
 * Choosing where a database policy is applied: in the SQL, or only in the results.
 *
 * The other examples here wrap a framework's tool call. This one is about SQL specifically,
 * and shows the one knob an integrator has over *where* enforcement happens:
 *
 * - `RewriteAndPost` (the default) — TOLAP edits the query so the database returns less data,
 *   then enforces on what comes back.
 * - `PostOnly` — your query runs byte for byte as written, and enforcement happens entirely
 *   on the rows returned.
 *
 * **Both print the same rows.** That is the point, and it is why the choice is safe to offer:
 * the mode is a resource decision, not an access-control one. If it changed what the caller
 * saw it would be a security setting wearing a performance setting's clothes.
 *
 * Deliberately mirrors `examples/python/enforcement_mode_example.py` — same policy, same fake
 * rows, same printed conclusion. A divergence between the languages then shows up as a
 * different result rather than hiding behind separately-written expectations.
 *
 *     npx tsx enforcement-mode-example.ts
 *
 * There is no third "rewrite only" mode. Masking has no SQL form (no `SELECT` returns
 * `[REDACTED]`) and `contains` / `startsWith` / `matches` are not portably expressible, so
 * skipping the post pass would return unmasked values *and* rows the policy excludes.
 */

import {
  applyResultPipeline,
  buildSecurityContext,
  prepareSqlQuery,
  signContext,
  FilterOperator,
  MaskType,
  SqlDialect,
  SqlEnforcementMode,
  type EffectivePolicy,
  type SecurityContext,
  type SqlQueryPreparation,
} from "@aws/tolap-core";

export const SIGNING_KEY = "example-signing-key-do-not-use-in-production";

export const QUERY = "SELECT id, name, region, dob FROM patients ORDER BY id";

/** What the "database" holds: more rows and more columns than the policy permits. */
export const FAKE_ROWS: Record<string, unknown>[] = [
  { id: 1, name: "Alice Nguyen", region: "us-east", dob: "1980-04-01", ssn: "111-22-3333" },
  { id: 2, name: "Bruno Sato", region: "us-east", dob: "1975-09-12", ssn: "222-33-4444" },
  { id: 3, name: "Chidi Okonkwo", region: "us-east", dob: "1990-01-30", ssn: "333-44-5555" },
  { id: 4, name: "Dana Petrova", region: "eu-west", dob: "1988-07-19", ssn: "444-55-6666" },
];

/**
 * A policy whose every rule is observable in the output.
 *
 * Note the mix on purpose: `region` is an `equals` filter the rewriter CAN push into SQL, while
 * `name` is a `startsWith` it cannot. So even in `RewriteAndPost` the post pass is doing real
 * work — which is the whole reason it is never optional.
 */
export function buildPolicy(): EffectivePolicy {
  return {
    version: "1.0",
    userId: "user-123",
    tenantId: "tenant-acme",
    sourceConnectionId: "db:analytics:patients",
    sourceProfiles: ["enforcement-mode-example"],
    permissions: { canQuery: true, readOnly: true },
    objectRules: {
      allowedObjects: ["patients"],
      rowFilters: [
        // Pushable: becomes WHERE "region" = 'us-east'.
        { field: "region", operator: FilterOperator.Equals, value: "us-east" },
        // NOT pushable: no portable SQL form, so the post pass enforces it.
        { field: "name", operator: FilterOperator.StartsWith, value: "A" },
      ],
      fieldRules: {
        hiddenFields: ["ssn"],
        maskedFields: [{ field: "dob", maskType: MaskType.Redact }],
      },
    },
    limits: { maxResults: 2 },
  } as unknown as EffectivePolicy;
}

export function buildContext(): SecurityContext {
  return signContext(
    buildSecurityContext("user-123", "tenant-acme", [buildPolicy()]),
    SIGNING_KEY,
  );
}

/**
 * Stand in for an engine: honour a pushed WHERE and LIMIT, ignore the rest.
 *
 * Crude, and that is the point — it responds differently to the two modes, so the equality of
 * the final output below is a real result rather than a coincidence.
 */
export function fakeDatabase(query: string): Record<string, unknown>[] {
  let rows = [...FAKE_ROWS];
  const eq = /"(\w+)" = '([^']*)'/.exec(query);
  if (eq) rows = rows.filter((r) => String(r[eq[1]]) === eq[2]);
  const limit = /LIMIT (\d+)/i.exec(query);
  if (limit) rows = rows.slice(0, Number(limit[1]));
  return rows;
}

export interface ModeRun {
  prep: SqlQueryPreparation;
  fromDatabase: Record<string, unknown>[];
  final: Record<string, unknown>[];
}

/** Prepare in `mode`, execute, then run the mandatory post pass. */
export function run(policy: EffectivePolicy, mode: SqlEnforcementMode): ModeRun {
  const prep = prepareSqlQuery(QUERY, policy, { dialect: SqlDialect.Postgres, mode });
  if (!prep.allowed) throw new Error(`Access denied: ${prep.denialReason}`);

  const fromDatabase = fakeDatabase(prep.query);
  // Mandatory in BOTH modes. This is the enforcement boundary.
  const final = applyResultPipeline(fromDatabase, policy) as Record<string, unknown>[];
  return { prep, fromDatabase, final };
}

export function main(): void {
  const policy = buildPolicy();

  console.log("The query the agent asked for:");
  console.log(`  ${QUERY}`);
  console.log(`\nThe database holds ${FAKE_ROWS.length} rows and 5 columns.\n`);

  const results = new Map<SqlEnforcementMode, Record<string, unknown>[]>();

  for (const mode of [SqlEnforcementMode.RewriteAndPost, SqlEnforcementMode.PostOnly]) {
    const { prep, fromDatabase, final } = run(policy, mode);
    results.set(mode, final);

    console.log(`--- mode: ${mode} ${"-".repeat(Math.max(0, 52 - mode.length))}`);
    console.log("  SQL sent to the database:");
    console.log(`    ${prep.query}`);
    console.log(`  query was edited: ${prep.rewritten}`);
    console.log(`  rows the database returned: ${fromDatabase.length}`);
    console.log(
      `  filters the database did NOT apply: ${JSON.stringify(prep.unpushableFilters.map((f) => f.field))}`,
    );
    console.log(`  rows after enforcement: ${final.length}`);
    for (const row of final) console.log(`    ${JSON.stringify(row)}`);
    console.log();
  }

  const rewritten = results.get(SqlEnforcementMode.RewriteAndPost)!;
  const postOnly = results.get(SqlEnforcementMode.PostOnly)!;

  console.log("=".repeat(70));
  if (JSON.stringify(rewritten) !== JSON.stringify(postOnly)) {
    throw new Error(
      "MODES DISAGREED. Rewriting is a resource optimization and must never change the " +
        `result.\n  RewriteAndPost: ${JSON.stringify(rewritten)}\n  PostOnly: ${JSON.stringify(postOnly)}`,
    );
  }

  const pushedRowCount = run(policy, SqlEnforcementMode.RewriteAndPost).fromDatabase.length;
  console.log("Both modes returned the SAME rows, as they must.");
  console.log(
    `The mode changed how much data the database produced — ${pushedRowCount} rows versus ` +
      `${FAKE_ROWS.length} — and nothing about what the caller may see.`,
  );
  console.log();
  console.log("Note what enforcement did that no SQL could have:");
  console.log("  * `ssn` is absent, though the database returned it");
  console.log("  * `dob` reads [REDACTED] — there is no SELECT that produces that");
  console.log("  * the `name startsWith A` filter was applied after the fetch, because it has");
  console.log("    no portable SQL form — which is why the post pass is never optional");
}

// Run directly, not on import, so the test file can call the exports above.
if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) {
  main();
}
