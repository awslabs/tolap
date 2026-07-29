/**
 * `like`/`notLike` pushdown and the column's collation, against live Postgres AND
 * live MySQL.
 *
 * A **measured** defect of the same class as the MySQL backtick one, and a worse
 * one. The post-execution pass compares case-SENSITIVELY and is engine-independent,
 * but a pushed-down `LIKE` inherits the *column's* collation:
 *
 * ```
 * postgres:  SELECT 'ALICE JONES' LIKE 'alice%'   ->  f     (case-sensitive)
 * mysql:     SELECT 'ALICE JONES' LIKE 'alice%'   ->  1     (utf8mb4_0900_ai_ci)
 * ```
 *
 * Run over the shared three-row corpus:
 *
 * ```
 * postgres  WHERE (name NOT LIKE 'alice%' OR name IS NULL)  -> mid, high, nullish
 * mysql     WHERE (name NOT LIKE 'alice%' OR name IS NULL)  -> high, nullish
 * ```
 *
 * The `mid` row is `'ALICE JONES'`. Its disappearing on MySQL is not a fail-closed
 * quoting mistake but a change in which **real records** a user sees. So `mysql`,
 * `sqlserver` and `ansi` decline the operator and report it unpushable, while
 * `postgres` and `trino` may push it (canonical spec §4).
 *
 * Asserting the emitted text cannot catch this: the text was well-formed and meant
 * something different in the other engine. Only executing it against both engines
 * can, which is why this suite exists alongside the unit tests.
 *
 * Skips (with a warning) when an engine is unreachable, matching the other
 * integration suites. Each engine is checked independently.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client } from "pg";
import { createConnection, type Connection } from "mysql2/promise";

import {
  SqlQueryRewriter,
  applyRowFilters,
  FilterOperator,
  SqlDialect,
  type EffectivePolicy,
  type RowFilter,
} from "@tolap/core";

const DSN = process.env.TOLAP_TEST_DB_DSN ?? "postgresql:///tolap_integration_test";

/**
 * The three-row set from the shared operator corpus
 * (`fixtures/enforcement/apply-row-filters-all-operators.json`), which is where the
 * expectations below come from rather than from any implementation. `mid` is the row
 * the two paths disagreed about.
 */
const COLLATION_ROWS: ReadonlyArray<readonly [string, string | null]> = [
  ["mid", "ALICE JONES"],
  ["high", "bob stone"],
  ["nullish", null],
];

/** The policy filter that exposed it. */
const NOT_LIKE_ALICE: RowFilter = {
  field: "name",
  operator: FilterOperator.NotLike,
  value: "alice%",
};

/**
 * What the case-sensitive post-fetch pass selects: `'ALICE JONES'` does not match the
 * lowercase pattern so `mid` is kept, and `nullish` is kept because its field is
 * present with a null value (spec §7).
 *
 * Compared as a sorted set, because `ORDER BY id` sorts these ids lexically while the
 * corpus lists them in record order. Which rows survive is the claim; their order is
 * the database's business.
 */
const NOT_LIKE_ALICE_EXPECTED = ["high", "mid", "nullish"];

let pg: Client;
let pgReady = false;
let my: Connection | null = null;
let myReady = false;

beforeAll(async () => {
  pg = new Client({ connectionString: DSN });
  try {
    await pg.connect();
    await pg.query("DROP TABLE IF EXISTS collation_probe");
    await pg.query("CREATE TABLE collation_probe (id TEXT, name TEXT)");
    for (const [id, name] of COLLATION_ROWS) {
      await pg.query("INSERT INTO collation_probe VALUES ($1, $2)", [id, name]);
    }
    pgReady = true;
  } catch (err) {
    console.warn(`Postgres not reachable at ${DSN}; skipping.`, err);
  }

  try {
    my = await createConnection({
      host: process.env.TOLAP_TEST_MYSQL_HOST ?? "127.0.0.1",
      user: process.env.TOLAP_TEST_MYSQL_USER ?? "root",
      password: process.env.TOLAP_TEST_MYSQL_PASSWORD ?? "",
      database: process.env.TOLAP_TEST_MYSQL_DB ?? "tolap_integration_test",
      port: Number(process.env.TOLAP_TEST_MYSQL_PORT ?? 3306),
    });
    await my.query("DROP TABLE IF EXISTS collation_probe");
    // No explicit COLLATE: the table takes the server default, which is what an
    // integrator's real table has and is the whole point of the case.
    await my.query(
      "CREATE TABLE collation_probe (id VARCHAR(32), name VARCHAR(255)) " +
        "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
    );
    for (const [id, name] of COLLATION_ROWS) {
      await my.query("INSERT INTO collation_probe VALUES (?, ?)", [id, name]);
    }
    myReady = true;
  } catch (err) {
    console.warn("MySQL not reachable; skipping.", err);
  }
});

afterAll(async () => {
  if (pg) {
    await pg.query("DROP TABLE IF EXISTS collation_probe").catch(() => {});
    await pg.end().catch(() => {});
  }
  if (my) {
    await my.query("DROP TABLE IF EXISTS collation_probe").catch(() => {});
    await my.end().catch(() => {});
  }
});

const QUERY = "SELECT id, name FROM collation_probe ORDER BY id";

function policyOf(filters: RowFilter[]): EffectivePolicy {
  return {
    version: "1.0",
    userId: "collation-user",
    tenantId: "collation-tenant",
    sourceConnectionId: "db:production:collation",
    resolvedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    sourceProfiles: ["collation"],
    permissions: { canQuery: true, canExport: false, readOnly: true },
    objectRules: { rowFilters: filters },
    integrity: { algorithm: "none", signature: "" },
  };
}

async function pgRows(sql: string): Promise<Array<Record<string, unknown>>> {
  return (await pg.query(sql)).rows as Array<Record<string, unknown>>;
}

async function myRows(sql: string): Promise<Array<Record<string, unknown>>> {
  const [rows] = await my!.query(sql);
  return rows as Array<Record<string, unknown>>;
}

function idsOf(records: Array<Record<string, unknown>>): string[] {
  return records.map((r) => String(r.id)).sort();
}

const mysqlRewriter = new SqlQueryRewriter({ dialect: SqlDialect.MySql });
const pgRewriter = new SqlQueryRewriter({ dialect: SqlDialect.Postgres });

describe("the engines genuinely disagree about the comparison", () => {
  /**
   * The mechanism, measured directly -- the premise everything below rests on. If it
   * ever stops holding (a MySQL configured with a case-sensitive default collation,
   * say), the rest of this file is testing a hazard that is no longer present, and
   * that should be noticed here rather than inferred.
   */
  it("postgres LIKE is case-sensitive", async () => {
    if (!pgReady) return;

    const rows = await pgRows("SELECT ('ALICE JONES' LIKE 'alice%') AS cmp");

    expect(rows[0]?.cmp).toBe(false);
  });

  it("mysql LIKE is not, under its default collation", async () => {
    if (!myReady) return;

    const rows = await myRows("SELECT ('ALICE JONES' LIKE 'alice%') AS cmp");

    expect(Number(rows[0]?.cmp)).toBe(1);
  });
});

describe("mysql does not push like/notLike, and the row survives", () => {
  it("the bare mysql predicate would drop a real row", async () => {
    if (!myReady) return;

    // The SQL the rewriter used to emit for `mysql`. Run against the corpus it drops
    // `mid` -- 'ALICE JONES' -- which the post-fetch pass keeps. Pinned so the effect
    // is on record independently of whether the rewriter happens to emit it.
    const dropped = await myRows(
      "SELECT id, name FROM collation_probe " +
        "WHERE (`name` NOT LIKE 'alice%' OR `name` IS NULL) ORDER BY id",
    );

    expect(idsOf(dropped)).toEqual(["high", "nullish"]);
    expect(idsOf(dropped)).not.toContain("mid");
    // ...while every row is present to begin with.
    expect(await myRows(QUERY)).toHaveLength(COLLATION_ROWS.length);
  });

  it("the filter is not pushed and the post pass keeps 'ALICE JONES'", async () => {
    if (!myReady) return;

    // **The regression guard.** 'ALICE JONES' surviving is the assertion.
    const policy = policyOf([NOT_LIKE_ALICE]);

    const { query, rewritten, unpushableFilters } = mysqlRewriter.rewriteQuery(
      QUERY,
      policy,
    );

    // Nothing pushed, and the decline is reported rather than silent.
    expect(query).toBe(QUERY);
    expect(query.toUpperCase()).not.toContain("LIKE");
    expect(rewritten).toBe(false);
    expect(unpushableFilters).toEqual([NOT_LIKE_ALICE]);

    const raw = await myRows(query);
    expect(raw).toHaveLength(COLLATION_ROWS.length);

    const enforced = applyRowFilters(raw, policy);

    expect(idsOf(enforced)).toEqual(NOT_LIKE_ALICE_EXPECTED);
    // Said the other way round, because this row is the whole point:
    expect(enforced.map((r) => r.name)).toContain("ALICE JONES");
  });

  it("a positive like is declined on mysql and still correct", async () => {
    if (!myReady) return;

    // `like` and not only `notLike`. The rule is about the comparison, not the
    // negation, so the positive operator is declined on the same profiles -- and the
    // post pass gives the case-sensitive answer, which excludes 'ALICE JONES'.
    const like: RowFilter = {
      field: "name",
      operator: FilterOperator.Like,
      value: "alice%",
    };
    const policy = policyOf([like]);

    const { query, unpushableFilters } = mysqlRewriter.rewriteQuery(QUERY, policy);

    expect(query).toBe(QUERY);
    expect(unpushableFilters).toEqual([like]);

    // No corpus row matches lowercase 'alice%' case-sensitively.
    expect(applyRowFilters(await myRows(query), policy)).toEqual([]);
    // Proof the pushed-down form would have differed.
    const wouldHaveMatched = await myRows(
      "SELECT id FROM collation_probe WHERE `name` LIKE 'alice%' ORDER BY id",
    );
    expect(idsOf(wouldHaveMatched)).toEqual(["mid"]);
  });
});

describe("postgres still pushes like/notLike", () => {
  it("the pushed-down answer equals the post-fetch answer", async () => {
    if (!pgReady) return;

    // Declining on MySQL must not cost Postgres its optimization -- and the
    // pushed-down answer must equal the post-fetch answer, which is the equivalence
    // the whole rule exists to protect.
    const policy = policyOf([NOT_LIKE_ALICE]);

    const { query, rewritten, unpushableFilters } = pgRewriter.rewriteQuery(
      QUERY,
      policy,
    );

    expect(rewritten).toBe(true);
    expect(query).toContain("NOT LIKE 'alice%'");
    expect(unpushableFilters).toEqual([]);

    const pushedDown = idsOf(await pgRows(query));
    const postFetch = idsOf(applyRowFilters(await pgRows(QUERY), policy));

    expect(pushedDown).toEqual(NOT_LIKE_ALICE_EXPECTED);
    expect(postFetch).toEqual(NOT_LIKE_ALICE_EXPECTED);
    expect(pushedDown).toEqual(postFetch);
  });
});

describe("the same policy admits the same rows on both engines", () => {
  it("postgres by pushing, mysql by declining, identical result", async () => {
    if (!pgReady || !myReady) return;

    // The claim the fix is for. Different *mechanisms*, identical *result* -- which is
    // what connector spec §5.1 promises and what the defect broke.
    const policy = policyOf([NOT_LIKE_ALICE]);

    const pgQuery = pgRewriter.rewriteQuery(QUERY, policy).query;
    const myQuery = mysqlRewriter.rewriteQuery(QUERY, policy).query;

    const pgResult = idsOf(applyRowFilters(await pgRows(pgQuery), policy));
    const myResult = idsOf(applyRowFilters(await myRows(myQuery), policy));

    expect(pgResult).toEqual(myResult);
    expect(pgResult).toEqual(NOT_LIKE_ALICE_EXPECTED);
  });
});

describe("no COLLATE clause is ever emitted", () => {
  /**
   * `... LIKE 'alice%' COLLATE utf8mb4_0900_as_cs` and `BINARY ...` both force
   * case-sensitivity on MySQL, so this IS technically emittable. It is deliberately
   * not emitted: the right collation name depends on the column's character set,
   * which a rewriter holding only a policy and a query string does not know, and
   * guessing wrong either fails the query or silently changes the comparison again.
   */
  const declining = [SqlDialect.MySql, SqlDialect.SqlServer, SqlDialect.Ansi];
  const operators = [FilterOperator.Like, FilterOperator.NotLike];

  const cases = declining.flatMap((dialect) =>
    operators.map((operator) => [dialect, operator] as const),
  );

  it.each(cases)("%s does not emit COLLATE or BINARY for %s", (dialect, operator) => {
    const rewriter = new SqlQueryRewriter({ dialect });

    const { query } = rewriter.rewriteQuery(
      QUERY,
      policyOf([{ field: "name", operator, value: "alice%" }]),
    );

    expect(query.toUpperCase()).not.toContain("COLLATE");
    expect(query.toUpperCase()).not.toContain("BINARY");
    expect(query).toBe(QUERY);
  });

  it("the mysql COLLATE form would have worked, which is why refusing is a choice", async () => {
    if (!myReady) return;

    // Direct evidence that this is a deliberate refusal and not a capability gap.
    const forced = await myRows(
      "SELECT ('ALICE JONES' LIKE 'alice%' COLLATE utf8mb4_0900_as_cs) AS cmp",
    );

    expect(Number(forced[0]?.cmp)).toBe(0);
  });
});
