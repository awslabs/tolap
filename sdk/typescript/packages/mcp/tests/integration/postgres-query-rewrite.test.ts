/**
 * SQL query rewriting, against real Postgres.
 *
 * The unit tests assert what the rewriter EMITS. These assert what the database
 * DOES with it, which is the only way to know the pushed-down filter is real:
 *
 *  - The rewritten query returns already-filtered rows, and the unfiltered one
 *    returns strictly more. That is the whole claim -- the excluded rows never cross
 *    the wire.
 *  - The pushed-down path and the post-fetch path select the IDENTICAL rows, for
 *    every operator including the null-valued cases where SQL's three-valued logic
 *    diverges from the post pass unless the rewriter compensates.
 *  - Every emitted statement actually parses. A rewriter that emits invalid SQL
 *    fails as an outage rather than a leak, and a unit test comparing strings cannot
 *    tell the difference.
 *
 * Skips (with a warning) when Postgres is unreachable, matching the other
 * integration suites.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client } from "pg";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  SqlQueryRewriter,
  applyResultPipeline,
  applyRowFilters,
  buildSecurityContext,
  signContext,
  FilterOperator,
  SqlDialect,
  type EffectivePolicy,
  type ObjectRules,
  type PolicyLimits,
  type RowFilter,
} from "@tolap/core";
import { SecureContextToolWrapper } from "../../src/context-wrapper.js";

const SCHEMA_PATH = resolve(
  __dirname,
  "..", "..", "..", "..", "..",
  "python", "tests", "integration", "schema.sql",
);
const DSN = process.env.TOLAP_TEST_DB_DSN ?? "postgresql:///tolap_integration_test";

let client: Client;
let dbReady = false;

beforeAll(async () => {
  client = new Client({ connectionString: DSN });
  try {
    await client.connect();
    await client.query(readFileSync(SCHEMA_PATH, "utf8"));
    // A nullable column, so the null-handling cases have something to exercise.
    // The negative operators are exactly where SQL and the post pass diverge.
    await client.query(`ALTER TABLE patients ADD COLUMN IF NOT EXISTS nickname TEXT`);
    await client.query(`UPDATE patients SET nickname = 'Johnny' WHERE id = 1`);
    await client.query(`UPDATE patients SET nickname = 'Janey'  WHERE id = 2`);
    // ids 3-6 keep nickname NULL.
    dbReady = true;
  } catch (err) {
    console.warn(`Postgres not reachable at ${DSN}; skipping rewrite tests.`, err);
  }
});

afterAll(async () => {
  if (client) await client.end().catch(() => {});
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function policyOf(opts: {
  rowFilters?: RowFilter[];
  allowedFields?: string[];
  hiddenFields?: string[];
  maxResults?: number;
}): EffectivePolicy {
  const objectRules: ObjectRules = {};
  if (opts.rowFilters !== undefined) objectRules.rowFilters = opts.rowFilters;
  if (opts.allowedFields !== undefined || opts.hiddenFields !== undefined) {
    objectRules.fieldRules = {
      ...(opts.allowedFields !== undefined ? { allowedFields: opts.allowedFields } : {}),
      ...(opts.hiddenFields !== undefined ? { hiddenFields: opts.hiddenFields } : {}),
    };
  }
  const limits: PolicyLimits = {};
  if (opts.maxResults !== undefined) limits.maxResults = opts.maxResults;

  return {
    version: "1.0",
    userId: "rewrite-user",
    tenantId: "rewrite-tenant",
    sourceConnectionId: "db:production:patients",
    resolvedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    sourceProfiles: ["rewrite"],
    permissions: { canQuery: true, canExport: false, readOnly: true },
    ...(Object.keys(objectRules).length > 0 ? { objectRules } : {}),
    ...(Object.keys(limits).length > 0 ? { limits } : {}),
    integrity: { algorithm: "none", signature: "" },
  };
}

const rewriter = new SqlQueryRewriter();

async function rows(sql: string): Promise<Array<Record<string, unknown>>> {
  const result = await client.query(sql);
  return result.rows as Array<Record<string, unknown>>;
}

function ids(records: Array<Record<string, unknown>>): number[] {
  return records.map((r) => Number(r.id)).sort((a, b) => a - b);
}

// ---------------------------------------------------------------------------
// The filter reaches the database
// ---------------------------------------------------------------------------

describe("the pushed-down filter reaches the database", () => {
  it("the rewritten query returns fewer rows than the unfiltered one", async () => {
    if (!dbReady) return;

    const original = "SELECT id, region FROM patients ORDER BY id";
    const policy = policyOf({
      rowFilters: [
        { field: "region", operator: FilterOperator.Equals, value: "us-east" },
      ],
    });

    const { query, unpushableFilters } = rewriter.rewriteQuery(original, policy);
    expect(unpushableFilters).toEqual([]);

    const unfiltered = await rows(original);
    const filtered = await rows(query);

    // The claim: the database itself did the filtering.
    expect(filtered.length).toBeLessThan(unfiltered.length);
    expect(ids(filtered)).toEqual([1, 3]);
    expect(unfiltered.length).toBe(6);

    // And the post pass -- which still runs, always -- finds nothing left to drop,
    // because the excluded rows never arrived.
    expect(ids(applyRowFilters(filtered, policy) )).toEqual([1, 3]);
  });

  it("the post-fetch path reaches the SAME rows the slow way", async () => {
    if (!dbReady) return;

    const original = "SELECT id, region FROM patients ORDER BY id";
    const policy = policyOf({
      rowFilters: [
        { field: "region", operator: FilterOperator.Equals, value: "us-east" },
      ],
    });

    // Both halves of enforcement must agree, or turning the optimization on changes
    // what the caller sees.
    const pushedDown = await rows(rewriter.rewriteQuery(original, policy).query);
    const postFetch = applyRowFilters(await rows(original), policy);

    expect(ids(pushedDown)).toEqual(ids(postFetch));
  });

  it("LIMIT is enforced by the database, not just by truncation", async () => {
    if (!dbReady) return;

    const original = "SELECT id FROM patients ORDER BY id";
    const policy = policyOf({ maxResults: 2 });

    const { query } = rewriter.rewriteQuery(original, policy);
    expect(query).toContain("LIMIT 2");

    const limited = await rows(query);
    expect(limited).toHaveLength(2);
    expect(await rows(original)).toHaveLength(6);
  });

  it("hidden columns are projected out by the database", async () => {
    if (!dbReady) return;

    const original = "SELECT id, full_name, ssn FROM patients ORDER BY id";
    const policy = policyOf({ hiddenFields: ["ssn"] });

    const { query } = rewriter.rewriteQuery(original, policy);
    const result = await rows(query);

    // The column is absent from the RESULT SET, not merely stripped afterwards --
    // the ssn values never left the database.
    expect(Object.keys(result[0]!)).toEqual(["id", "full_name"]);
    expect(Object.keys(await rows(original))).not.toEqual(["id", "full_name"]);
  });

  it("SELECT * expands to the allowed columns at the database", async () => {
    if (!dbReady) return;

    const policy = policyOf({
      allowedFields: ["id", "full_name", "region", "ssn"],
      hiddenFields: ["ssn"],
    });

    const { query } = rewriter.rewriteQuery(
      "SELECT * FROM patients ORDER BY id",
      policy,
    );
    const result = await rows(query);

    expect(Object.keys(result[0]!).sort()).toEqual(["full_name", "id", "region"]);
  });

  it("SELECT * with hiddenFields but no allowedFields still returns the hidden column", async () => {
    if (!dbReady) return;

    // The documented limitation, proved rather than asserted: the rewriter cannot
    // subtract a hidden column from `*` without schema knowledge, so ssn DOES cross
    // the wire...
    const policy = policyOf({ hiddenFields: ["ssn"] });
    const { query } = rewriter.rewriteQuery("SELECT * FROM patients ORDER BY id", policy);

    const raw = await rows(query);
    expect(Object.keys(raw[0]!)).toContain("ssn");

    // ...and the post pass is what keeps it from the agent. Disclosure outcome
    // identical; transfer cost is not.
    const enforced = applyResultPipeline(raw, policy) as Array<Record<string, unknown>>;
    expect(Object.keys(enforced[0]!)).not.toContain("ssn");
  });
});

// ---------------------------------------------------------------------------
// The two paths agree, operator by operator
// ---------------------------------------------------------------------------

describe("pushed-down and post-fetch paths select identical rows", () => {
  // Every case runs the same policy both ways against live Postgres. Any operator
  // whose SQL rendering disagrees with `applyRowFilters` shows up here as a
  // mismatch, which is exactly the divergence class the IS NULL arms exist to stop.
  const cases: Array<{ name: string; filter: RowFilter; columns: string }> = [
    {
      name: "equals",
      filter: { field: "region", operator: FilterOperator.Equals, value: "us-east" },
      columns: "id, region",
    },
    {
      name: "notEquals over a NON-null column",
      filter: { field: "region", operator: FilterOperator.NotEquals, value: "us-east" },
      columns: "id, region",
    },
    {
      name: "notEquals over a NULLABLE column (the IS NULL arm)",
      // The important one. SQL `nickname <> 'Johnny'` is unknown for the four
      // null-nickname rows and drops them; the post pass KEEPS them (spec §7 drops
      // rows whose field is ABSENT, not null-valued ones). Only the injected
      // `OR nickname IS NULL` makes the two agree.
      filter: { field: "nickname", operator: FilterOperator.NotEquals, value: "Johnny" },
      columns: "id, nickname",
    },
    {
      name: "in",
      filter: {
        field: "region",
        operator: FilterOperator.In,
        values: ["us-east", "us-west"],
      },
      columns: "id, region",
    },
    {
      name: "notIn over a NULLABLE column (the IS NULL arm)",
      filter: {
        field: "nickname",
        operator: FilterOperator.NotIn,
        values: ["Johnny"],
      },
      columns: "id, nickname",
    },
    {
      name: "greaterThan",
      filter: { field: "id", operator: FilterOperator.GreaterThan, value: 3 },
      columns: "id",
    },
    {
      name: "greaterThanOrEqual includes the boundary",
      filter: { field: "id", operator: FilterOperator.GreaterThanOrEqual, value: 3 },
      columns: "id",
    },
    {
      name: "lessThan",
      filter: { field: "id", operator: FilterOperator.LessThan, value: 3 },
      columns: "id",
    },
    {
      name: "lessThanOrEqual includes the boundary",
      filter: { field: "id", operator: FilterOperator.LessThanOrEqual, value: 3 },
      columns: "id",
    },
    {
      name: "between is inclusive at both ends",
      filter: { field: "id", operator: FilterOperator.Between, values: [2, 4] },
      columns: "id",
    },
    {
      name: "like with a % wildcard",
      filter: { field: "region", operator: FilterOperator.Like, value: "us-%" },
      columns: "id, region",
    },
    {
      name: "like with an _ wildcard",
      filter: { field: "region", operator: FilterOperator.Like, value: "us-eas_" },
      columns: "id, region",
    },
    {
      name: "notLike over a NULLABLE column (no IS NULL arm -- both drop the nulls)",
      filter: { field: "nickname", operator: FilterOperator.NotLike, value: "J%" },
      columns: "id, nickname",
    },
    {
      name: "isNull",
      filter: { field: "nickname", operator: FilterOperator.IsNull },
      columns: "id, nickname",
    },
    {
      name: "isNotNull",
      filter: { field: "nickname", operator: FilterOperator.IsNotNull },
      columns: "id, nickname",
    },
  ];

  for (const { name, filter, columns } of cases) {
    it(name, async () => {
      if (!dbReady) return;

      const policy = policyOf({ rowFilters: [filter] });
      const original = `SELECT ${columns} FROM patients ORDER BY id`;

      const { query, unpushableFilters } = rewriter.rewriteQuery(original, policy);
      // Every operator here has a portable SQL form, so all of them push down.
      expect(unpushableFilters, `${name} should be pushable`).toEqual([]);
      expect(query, `${name} should have been rewritten`).not.toBe(original);

      // The database's answer and the in-memory answer must be the same set.
      const pushedDown = await rows(query);
      const postFetch = applyRowFilters(await rows(original), policy);

      expect(ids(pushedDown), `${name}: pushed-down vs post-fetch`).toEqual(
        ids(postFetch),
      );

      // Running the post pass over the already-filtered rows is idempotent: it must
      // not drop rows the database correctly kept.
      expect(ids(applyRowFilters(pushedDown, policy)), `${name}: idempotent`).toEqual(
        ids(pushedDown),
      );
    });
  }

  it("the nullable-column cases genuinely exercise nulls", async () => {
    if (!dbReady) return;
    // Guards the guard: if the fixture stopped having null nicknames, the IS NULL
    // cases above would pass vacuously.
    const nulls = await rows(
      "SELECT id FROM patients WHERE nickname IS NULL ORDER BY id",
    );
    expect(nulls.length).toBeGreaterThan(0);
    const nonNulls = await rows(
      "SELECT id FROM patients WHERE nickname IS NOT NULL ORDER BY id",
    );
    expect(nonNulls.length).toBeGreaterThan(0);
  });

  it("notEquals on a nullable column returns MORE rows than bare SQL would", async () => {
    if (!dbReady) return;

    // The concrete demonstration of the prior implementation's defect. Bare `<>` loses the
    // null-nickname rows; the rewritten form keeps them, matching the post pass.
    const bare = await rows(
      "SELECT id FROM patients WHERE nickname <> 'Johnny' ORDER BY id",
    );
    const { query } = rewriter.rewriteQuery(
      "SELECT id, nickname FROM patients ORDER BY id",
      policyOf({
        rowFilters: [
          { field: "nickname", operator: FilterOperator.NotEquals, value: "Johnny" },
        ],
      }),
    );
    const rewritten = await rows(query);

    expect(rewritten.length).toBeGreaterThan(bare.length);
  });
});

// ---------------------------------------------------------------------------
// Every emitted statement parses
// ---------------------------------------------------------------------------

describe("every emitted statement is valid SQL", () => {
  const policy = policyOf({
    rowFilters: [
      { field: "region", operator: FilterOperator.Equals, value: "us-east" },
      { field: "status", operator: FilterOperator.NotEquals, value: "deleted" },
      { field: "id", operator: FilterOperator.Between, values: [1, 100] },
    ],
    hiddenFields: ["ssn"],
    maxResults: 10,
  });

  // Shapes that between them hit every injection and clamping path: no WHERE, an
  // existing WHERE, an OR'd WHERE (the parenthesisation defect), each trailing
  // clause, a subquery (the wrong-WHERE defect), a join, and a semicolon.
  const shapes = [
    "SELECT id, region, status FROM patients",
    "SELECT id, region, status FROM patients WHERE full_name IS NOT NULL",
    "SELECT id, region, status FROM patients WHERE id = 1 OR id = 2",
    "SELECT id, region, status FROM patients ORDER BY id",
    "SELECT id, region, status FROM patients ORDER BY id DESC LIMIT 1000",
    "SELECT region, status, count(*) AS n, min(id) AS id FROM patients GROUP BY region, status",
    "SELECT region, status, count(*) AS n, min(id) AS id FROM patients GROUP BY region, status ORDER BY n",
    "SELECT region, status, count(*) AS n, min(id) AS id FROM patients GROUP BY region, status HAVING count(*) > 0",
    "SELECT id, region, status FROM patients WHERE id IN (SELECT patient_id FROM encounters WHERE status = 'active')",
    "SELECT id, region, status FROM patients;",
    "SELECT id, region, status FROM patients LIMIT 5 OFFSET 1",
  ];

  for (const original of shapes) {
    it(`parses and runs: ${original.slice(0, 62)}`, async () => {
      if (!dbReady) return;

      const { query } = rewriter.rewriteQuery(original, policy);

      // Postgres is the parser. A rewriter that emits invalid SQL is an outage, and
      // a unit test comparing strings cannot detect it -- a prior implementation's insert-point defect
      // emitted `GROUP BY x WHERE ... ORDER BY y`, which only fails here.
      await expect(rows(query), `emitted: ${query}`).resolves.toBeDefined();

      // The rewrite must not have widened the result: whatever came back still
      // satisfies the policy, so the post pass has nothing to remove.
      const returned = await rows(query);
      expect(applyRowFilters(returned, policy)).toHaveLength(returned.length);
      // And the hidden column never arrived.
      for (const row of returned) {
        expect(Object.keys(row)).not.toContain("ssn");
      }
    });
  }

  it("a JOIN whose tables share the filtered column ERRORS rather than guessing", async () => {
    if (!dbReady) return;

    // A deliberate, documented consequence of emitting a BARE column name. Both
    // `patients` and `encounters` have `region`, so `WHERE "region" = 'us-east'` is
    // ambiguous and Postgres refuses the statement.
    //
    // This is the correct trade. The alternative -- emitting `"patients"."region"` --
    // would break the far more common case of an aliased table (`FROM patients p`
    // makes `patients.region` unresolvable), and guessing which side of a join a
    // policy field belongs to could silently filter the WRONG table's column, which
    // is a disclosure. An error is loud, immediate, and fixable by qualifying the
    // query; a silently-wrong filter is neither.
    const policy2 = policyOf({
      rowFilters: [
        { field: "region", operator: FilterOperator.Equals, value: "us-east" },
      ],
    });
    const { query } = rewriter.rewriteQuery(
      "SELECT p.id, p.region FROM patients p JOIN encounters e ON p.id = e.patient_id",
      policy2,
    );

    await expect(rows(query)).rejects.toThrow(/ambiguous/i);

    // A join that does NOT share the column is unaffected.
    const unambiguous = rewriter.rewriteQuery(
      "SELECT p.id, p.region FROM patients p JOIN audit_log a ON a.id = p.id",
      policy2,
    ).query;
    await expect(rows(unambiguous)).resolves.toBeDefined();
  });

  it("a refused injection value leaves a query that still runs", async () => {
    if (!dbReady) return;

    // A value with a backslash is declined rather than escaped, so the filter falls
    // to the post pass. The emitted query must still be valid, and the post pass
    // must still enforce the filter.
    const nasty = policyOf({
      rowFilters: [
        { field: "region", operator: FilterOperator.Equals, value: "us-east\\' OR 1=1 --" },
      ],
    });
    const { query, unpushableFilters } = rewriter.rewriteQuery(
      "SELECT id, region FROM patients ORDER BY id",
      nasty,
    );

    expect(unpushableFilters).toHaveLength(1);
    expect(query).toBe("SELECT id, region FROM patients ORDER BY id");

    // The query runs and returns everything...
    const returned = await rows(query);
    expect(returned).toHaveLength(6);
    // ...and the post pass drops every row, because no region equals that value.
    expect(applyRowFilters(returned, nasty)).toEqual([]);
  });

  it("an escaped-but-pushed injection payload is data, not syntax", async () => {
    if (!dbReady) return;

    // No backslash, so this one IS pushed down -- with the quote doubled. If the
    // escaping were wrong, Postgres would either error or return every row.
    const payload = "us-east' OR 1=1 --";
    const policy2 = policyOf({
      rowFilters: [{ field: "region", operator: FilterOperator.Equals, value: payload }],
    });
    const { query } = rewriter.rewriteQuery(
      "SELECT id, region FROM patients ORDER BY id",
      policy2,
    );

    const returned = await rows(query);
    // No region has that literal value, so the injection matched nothing rather than
    // everything. `OR 1=1` never became a predicate.
    expect(returned).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// The wrapper-level API an integrator actually calls
// ---------------------------------------------------------------------------

const SIGNING_KEY = "rewrite-integration-signing-key";

function contextFor(policy: EffectivePolicy) {
  return signContext(
    buildSecurityContext(policy.userId, policy.tenantId, policy, 3_600_000),
    SIGNING_KEY,
  );
}

describe("prepareSqlQuery / executeSqlWithEnforcement", () => {
  const wrapper = new SecureContextToolWrapper({ signingKey: SIGNING_KEY });

  it("prepares, executes, and post-processes in one call", async () => {
    if (!dbReady) return;

    const policy = policyOf({
      rowFilters: [
        { field: "region", operator: FilterOperator.Equals, value: "us-east" },
      ],
      hiddenFields: ["ssn"],
      maxResults: 10,
    });

    const result = await wrapper.executeSqlWithEnforcement(
      contextFor(policy),
      { toolName: "pg-query" },
      "SELECT id, region, full_name FROM patients ORDER BY id",
      (query) => rows(query),
    );

    expect(ids(result)).toEqual([1, 3]);
    for (const row of result) expect(Object.keys(row)).not.toContain("ssn");
  });

  it("passes the dialect through to the rewriter", async () => {
    if (!dbReady) return;

    // The dialect is the integrator's to supply; the wrapper must plumb it, not
    // infer it (connector spec §5.1). `postgres` here matches the live connection.
    const policy = policyOf({
      rowFilters: [
        { field: "region", operator: FilterOperator.Equals, value: "us-east" },
      ],
    });

    const prep = wrapper.prepareSqlQuery(
      contextFor(policy),
      { toolName: "pg-query" },
      "SELECT id, region FROM patients ORDER BY id",
      undefined,
      SqlDialect.Postgres,
    );

    expect(prep.query).toContain('"region"');
    expect(ids(await rows(prep.query))).toEqual([1, 3]);
  });

  it("emits mysql quoting when the mysql dialect is passed through", () => {
    if (!dbReady) return;

    // Not executed against Postgres -- backticks are a syntax error there, which is
    // exactly why the profile has to be the caller's choice.
    const prep = wrapper.prepareSqlQuery(
      contextFor(
        policyOf({
          rowFilters: [
            { field: "region", operator: FilterOperator.Equals, value: "us-east" },
          ],
        }),
      ),
      { toolName: "mysql-query" },
      "SELECT id, region FROM patients",
      undefined,
      SqlDialect.MySql,
    );

    expect(prep.query).toBe("SELECT id, region FROM patients WHERE `region` = 'us-east'");
  });

  it("declines to rewrite for an unrecognized dialect, and the post pass still works", async () => {
    if (!dbReady) return;

    const policy = policyOf({
      rowFilters: [
        { field: "region", operator: FilterOperator.Equals, value: "us-east" },
      ],
    });
    const ctx = contextFor(policy);

    const prep = wrapper.prepareSqlQuery(
      ctx,
      { toolName: "pg-query" },
      "SELECT id, region FROM patients ORDER BY id",
      undefined,
      "oracle",
    );

    // Nothing pushed down, every filter reported...
    expect(prep.allowed).toBe(true);
    expect(prep.rewritten).toBe(false);
    expect(prep.fullyPushedDown).toBe(false);

    // ...the database returns every row...
    const raw = await rows(prep.query);
    expect(raw.length).toBe(6);

    // ...and the post pass still produces exactly the right ones.
    expect(ids(wrapper.postExecute(ctx, raw))).toEqual([1, 3]);
  });

  it("passes the dialect through executeSqlWithEnforcement too", async () => {
    if (!dbReady) return;

    const policy = policyOf({
      rowFilters: [
        { field: "region", operator: FilterOperator.Equals, value: "us-east" },
      ],
    });

    const seen: string[] = [];
    const result = await wrapper.executeSqlWithEnforcement(
      contextFor(policy),
      { toolName: "pg-query" },
      "SELECT id, region FROM patients ORDER BY id",
      (query) => {
        seen.push(query);
        return rows(query);
      },
      undefined,
      SqlDialect.Postgres,
    );

    expect(seen[0]).toContain('"region"');
    expect(ids(result)).toEqual([1, 3]);
  });

  it("reports fullyPushedDown when every filter reached the database", async () => {
    if (!dbReady) return;

    const prep = wrapper.prepareSqlQuery(
      contextFor(
        policyOf({
          rowFilters: [
            { field: "region", operator: FilterOperator.Equals, value: "us-east" },
          ],
        }),
      ),
      { toolName: "pg-query" },
      "SELECT id, region FROM patients ORDER BY id",
    );

    expect(prep.allowed).toBe(true);
    expect(prep.rewritten).toBe(true);
    expect(prep.fullyPushedDown).toBe(true);
    expect(ids(await rows(prep.query))).toEqual([1, 3]);
  });

  it("reports the unpushable filters, and the post pass still enforces them", async () => {
    if (!dbReady) return;

    // `contains` has no portable SQL form, so the database returns extra rows and the
    // post pass is what removes them. The integrator can SEE that from the result.
    const policy = policyOf({
      rowFilters: [{ field: "region", operator: FilterOperator.Contains, value: "east" }],
    });
    const ctx = contextFor(policy);

    const prep = wrapper.prepareSqlQuery(
      ctx,
      { toolName: "pg-query" },
      "SELECT id, region FROM patients ORDER BY id",
    );

    expect(prep.allowed).toBe(true);
    expect(prep.fullyPushedDown).toBe(false);
    expect(prep.unpushableFilters).toHaveLength(1);

    // The DB returned everything...
    const returned = await rows(prep.query);
    expect(returned).toHaveLength(6);
    // ...and postExecute enforced the filter anyway.
    expect(ids(wrapper.postExecute(ctx, returned))).toEqual([1, 3]);
  });

  it("resolves the object name from the query when the caller omits it", async () => {
    if (!dbReady) return;

    // An allowedObjects rule must apply to the table the query READS, not to a
    // declaration the query is free to contradict.
    const policy = policyOf({});
    policy.objectRules = { ...policy.objectRules, allowedObjects: ["encounters"] };

    const prep = wrapper.prepareSqlQuery(
      contextFor(policy),
      { toolName: "pg-query" },
      "SELECT id FROM patients",
    );

    expect(prep.allowed).toBe(false);
    expect(prep.denialReason).toContain("not in allowed set");
    // The caller's query is returned unchanged and must not be executed.
    expect(prep.query).toBe("SELECT id FROM patients");
  });

  it("refuses a query naming a hidden field rather than silently narrowing it", async () => {
    if (!dbReady) return;

    const prep = wrapper.prepareSqlQuery(
      contextFor(policyOf({ hiddenFields: ["ssn"] })),
      { toolName: "pg-query" },
      "SELECT id, ssn FROM patients",
    );

    expect(prep.allowed).toBe(false);
    expect(prep.denialReason).toContain("do not have permission");
  });

  it("refuses an empty query", () => {
    const prep = wrapper.prepareSqlQuery(
      contextFor(policyOf({})),
      { toolName: "pg-query" },
      "   ",
    );
    expect(prep.allowed).toBe(false);
    expect(prep.denialReason).toBe("query is empty");
  });

  it("executeSqlWithEnforcement throws without invoking the callback when refused", async () => {
    let invoked = false;
    await expect(
      wrapper.executeSqlWithEnforcement(
        contextFor(policyOf({ hiddenFields: ["ssn"] })),
        { toolName: "pg-query" },
        "SELECT ssn FROM patients",
        () => {
          invoked = true;
          return [];
        },
      ),
    ).rejects.toThrow(/Access denied/);
    expect(invoked).toBe(false);
  });

  it("honours an explicitly supplied objectName over the query's table", async () => {
    // The caller may be wrapping a tool whose "object" is not the SQL table -- a
    // view name, a logical dataset. An explicit objectName is authoritative and the
    // query is not consulted for it.
    const policy = policyOf({});
    policy.objectRules = { ...policy.objectRules, allowedObjects: ["patients"] };
    const ctx = contextFor(policy);

    // Explicit name is in the allow-list, so this passes even though the query reads
    // a table that is not.
    expect(
      wrapper.prepareSqlQuery(
        ctx,
        { toolName: "pg-query", objectName: "patients" },
        "SELECT id FROM encounters",
      ).allowed,
    ).toBe(true);

    // And an explicit name that is NOT allowed is refused even though the query's
    // own table would have been.
    const refused = wrapper.prepareSqlQuery(
      ctx,
      { toolName: "pg-query", objectName: "billing_internal" },
      "SELECT id FROM patients",
    );
    expect(refused.allowed).toBe(false);
    expect(refused.denialReason).toContain("not in allowed set");
  });

  it("executeSqlWithEnforcement runs the callback with the REWRITTEN query", async () => {
    // Asserted without a database so the contract is pinned even where Postgres is
    // unavailable: the callback must receive the rewritten text, not the original.
    const policy = policyOf({
      rowFilters: [
        { field: "region", operator: FilterOperator.Equals, value: "us-east" },
      ],
      maxResults: 5,
    });

    let seen: string | undefined;
    const result = await wrapper.executeSqlWithEnforcement(
      contextFor(policy),
      { toolName: "pg-query", objectName: "patients" },
      "SELECT id, region FROM patients",
      (query) => {
        seen = query;
        return [
          { id: 1, region: "us-east" },
          { id: 2, region: "eu-west" },
        ];
      },
    );

    expect(seen).toBe(
      `SELECT id, region FROM patients WHERE "region" = 'us-east' LIMIT 5`,
    );
    // And the post pass still ran over what the callback returned -- the eu-west row
    // is gone even though this fake "database" ignored the WHERE clause. That is the
    // property that makes rewriting an optimization rather than the boundary.
    expect(result).toEqual([{ id: 1, region: "us-east" }]);
  });

  it("an invalid context is refused before any rewriting happens", () => {
    const policy = policyOf({});
    const ctx = contextFor(policy);
    const tampered = { ...ctx, signature: "deadbeef" };

    const prep = wrapper.prepareSqlQuery(
      tampered,
      { toolName: "pg-query" },
      "SELECT id FROM patients",
    );
    expect(prep.allowed).toBe(false);
    expect(prep.denialReason).toContain("signature");
  });

  it("passes a supplied rewriter through, so diagnostics reach the caller", () => {
    const messages: string[] = [];
    const prep = wrapper.prepareSqlQuery(
      contextFor(
        policyOf({
          rowFilters: [
            { field: "region", operator: FilterOperator.Matches, value: ".*east" },
          ],
        }),
      ),
      { toolName: "pg-query" },
      "SELECT id, region FROM patients",
      new SqlQueryRewriter({ diagnostics: (m) => messages.push(m) }),
    );

    expect(prep.allowed).toBe(true);
    expect(messages.join("\n")).toContain("no portable SQL form");
  });
});

// ---------------------------------------------------------------------------
// The footgun, against a real database
// ---------------------------------------------------------------------------

describe("footgun: filtering on an unprojected column returns zero rows", () => {
  it("the database filters correctly, then the post pass drops everything", async () => {
    if (!dbReady) return;

    // Fail-closed, not a leak, but surprising enough to pin against a live DB. The
    // query projects only `id`, so the rows carry no `region` key and spec §7 drops
    // every one.
    const policy = policyOf({
      rowFilters: [
        { field: "region", operator: FilterOperator.Equals, value: "us-east" },
      ],
    });

    const { query } = rewriter.rewriteQuery("SELECT id FROM patients ORDER BY id", policy);
    const returned = await rows(query);

    // The database did the right thing.
    expect(ids(returned)).toEqual([1, 3]);
    // The post pass then drops them all, because `region` is not in the result.
    expect(applyRowFilters(returned, policy)).toEqual([]);

    // Projecting the filtered column is the fix.
    const fixed = await rows(
      rewriter.rewriteQuery("SELECT id, region FROM patients ORDER BY id", policy).query,
    );
    expect(ids(applyRowFilters(fixed, policy))).toEqual([1, 3]);
  });
});
