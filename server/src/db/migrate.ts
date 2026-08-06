/**
 * Schema application.
 *
 * `schema.sql` is written to be idempotent (`CREATE TABLE IF NOT EXISTS`,
 * `CREATE INDEX IF NOT EXISTS`), so applying it repeatedly is safe and this
 * runner stays a single statement. When the schema starts needing genuine
 * migrations -- a column type change, a backfill -- this is where a numbered
 * migration table goes; it is deliberately not built ahead of that need, because
 * an unused migration framework is one more thing to get wrong.
 *
 * Applied inside a transaction so a partial schema is never left behind.
 */

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { Pool } from "pg";

const HERE = path.dirname(fileURLToPath(import.meta.url));

export function schemaSql(): string {
  return readFileSync(path.join(HERE, "schema.sql"), "utf8");
}

export async function applySchema(pool: Pool): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(schemaSql());
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

// Run directly: `npm run migrate`.
if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) {
  const { Pool } = await import("pg");
  const url = process.env.DATABASE_URL;
  if (!url) {
    console.error("DATABASE_URL is required");
    process.exit(1);
  }
  const pool = new Pool({ connectionString: url });
  try {
    await applySchema(pool);
    console.log("schema applied");
  } finally {
    await pool.end();
  }
}
