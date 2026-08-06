/**
 * Test database helper.
 *
 * Store tests run against a real PostgreSQL instance because the things they
 * assert are properties *of* the persistence layer -- whether `[]` survives a
 * round trip, whether a partial unique index behaves, whether a revoked row
 * really stops resolving. A fake would assert the fake.
 *
 * Set `TOLAP_TEST_DB_DSN` to point at a database. The suites skip when it is
 * unset, and each suite carries a guard test that is deliberately *not* behind the
 * skip -- this repo has shipped gates that silently disabled whole suites (see
 * CHANGELOG "Test-reporting defects"), and a gate that is also the thing being
 * gated cannot catch itself.
 *
 * ## Isolation
 *
 * Vitest runs test files in parallel, and every file that called `applySchema`
 * plus `TRUNCATE` against one shared database deadlocked against its siblings --
 * two concurrent transactions each taking locks on the same six tables in an
 * order Postgres could not reconcile. Sharing a database and serializing the
 * files would fix the deadlock but leave the suites able to truncate each other's
 * fixtures mid-run.
 *
 * So each caller gets its **own schema** (a Postgres namespace) with `search_path`
 * pinned to it. Files then touch disjoint objects, run genuinely in parallel, and
 * cannot see one another's rows. `dropSchema` cleans up.
 */

import { Pool } from "pg";
import { schemaSql } from "../../src/db/migrate.ts";

export const TEST_DSN = process.env.TOLAP_TEST_DB_DSN;
export const HAVE_DB = TEST_DSN !== undefined && TEST_DSN.trim() !== "";

/** Tables the fixtures reset between tests, in dependency order. */
export const TABLES = [
  "tolap_audit",
  "tolap_assignments",
  "tolap_policy_versions",
  "tolap_policies",
  "tolap_sources",
  "tolap_installs",
];

export interface TestDb {
  readonly pool: Pool;
  readonly schema: string;
  /** Empty every table. Safe to call between tests. */
  reset(): Promise<void>;
  /** Drop the schema and close the pool. */
  close(): Promise<void>;
}

let counter = 0;

/**
 * Create an isolated schema and apply the DDL into it.
 *
 * @param label A short name for the calling suite, used in the schema name so a
 *              leftover schema is traceable to its test.
 */
export async function testDb(label: string): Promise<TestDb> {
  // Unique per call: the pid keeps parallel vitest workers apart, the counter
  // keeps repeat calls within one worker apart.
  const safeLabel = label.replace(/[^a-z0-9]+/gi, "_").toLowerCase();
  counter += 1;
  const schema = `tolap_test_${safeLabel}_${process.pid}_${counter}`;

  const pool = new Pool({ connectionString: TEST_DSN });

  // Pin search_path on every connection the pool opens, including ones created
  // later to satisfy concurrency -- setting it once on a single client would
  // silently apply the DDL to `public` on any subsequent connection.
  pool.on("connect", (client) => {
    void client.query(`SET search_path TO ${schema}`);
  });

  const client = await pool.connect();
  try {
    await client.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await client.query(`CREATE SCHEMA ${schema}`);
    await client.query(`SET search_path TO ${schema}`);
    // gen_random_uuid() lives in public (pgcrypto or PG13+ builtin), so keep
    // public on the path behind our schema for function resolution.
    await client.query(`SET search_path TO ${schema}, public`);
    await client.query(schemaSql());
  } finally {
    client.release();
  }

  return {
    pool,
    schema,
    async reset() {
      await pool.query(
        `TRUNCATE ${TABLES.map((t) => `${schema}.${t}`).join(", ")} RESTART IDENTITY CASCADE`,
      );
    },
    async close() {
      try {
        await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
      } finally {
        await pool.end();
      }
    },
  };
}

/** An identity resolver with fixed group and role membership. */
export function staticIdentity(
  groups: Record<string, string[]> = {},
  roles: Record<string, string[]> = {},
) {
  return {
    getGroups: async (userId: string) => groups[userId] ?? [],
    getRoles: async (userId: string) => roles[userId] ?? [],
  };
}

export const ADMIN = { id: "admin-1", kind: "admin" as const };
