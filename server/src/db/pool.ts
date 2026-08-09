/**
 * Build the connection pool from either database configuration form.
 *
 * The `secret` form is the one that matters in a deployment: the password is read
 * from Secrets Manager when a connection is opened rather than baked into the
 * environment at task start, so a rotated credential is picked up by the next
 * connection without a restart.
 *
 * `pg` takes the *password* as a function it calls per client, but the user, host and
 * port are read once at pool construction. So those are resolved from the secret
 * before the pool is built, and only the password stays dynamic — which is the field
 * rotation actually changes.
 */

import { readFileSync } from "node:fs";
import { Pool } from "pg";
import type { DatabaseConfig } from "../config.ts";
import {
  CredentialsError,
  DatabaseSecretReader,
  onAuthFailureInvalidate,
  secretPasswordProvider,
} from "./credentials.ts";

export interface BuiltPool {
  readonly pool: Pool;
  /** How the password is obtained, for the startup log. */
  readonly source: "url" | "secret";
  /** Present only for the secret-backed form. */
  readonly secretReader?: DatabaseSecretReader;
}

/**
 * Build the pool.
 *
 * Async because the secret-backed form must read the secret once up front to learn
 * the username and, when not configured, the host.
 */
/**
 * Per-task connection limits, bounded because the pool is now multiplied by task count.
 *
 * The service runs more than one task and autoscales, and every task opens its own pool.
 * `pg` defaults to 10 clients, so N tasks is up to 10N connections against one Aurora
 * cluster -- and Serverless v2 at the 0.5 ACU floor this cluster starts from allows on
 * the order of 90. An unbounded pool therefore trades a latency problem for connection
 * exhaustion, which fails worse: a task that cannot get a connection cannot resolve
 * policy at all, so the symptom is a denial rather than a delay.
 *
 * `connectionTimeoutMillis` matters as much as the ceiling. `pg` defaults to no timeout,
 * so a request that arrives with the pool saturated waits **forever** -- it consumes a
 * socket and a Fastify handler and never returns, which is how a busy service becomes an
 * unresponsive one. Failing in 5 seconds gives the caller an error it can retry and lets
 * the 5xx alarm see it.
 */
function poolLimits(): { max: number; connectionTimeoutMillis: number; idleTimeoutMillis: number } {
  const max = Number(process.env.DATABASE_POOL_MAX ?? 10);
  if (!Number.isInteger(max) || max < 1) {
    throw new Error(
      `DATABASE_POOL_MAX must be a positive integer, got ${JSON.stringify(process.env.DATABASE_POOL_MAX)}`,
    );
  }
  return {
    max,
    connectionTimeoutMillis: 5_000,
    // Return connections to Aurora rather than holding the full pool open at idle, so a
    // scaled-out fleet is not sitting on its whole allocation between requests.
    idleTimeoutMillis: 30_000,
  };
}

export async function buildPool(config: DatabaseConfig): Promise<BuiltPool> {
  if (config.kind === "url") {
    // Local development: the password is in the string and there is no rotation to
    // absorb.
    return {
      pool: new Pool({ connectionString: config.url, ...poolLimits() }),
      source: "url",
    };
  }

  const reader = new DatabaseSecretReader({
    secretId: config.secretId,
    cacheTtlMs: config.cacheTtlMs,
  });

  // Read once for the fields pg cannot take dynamically. RDS- and Aurora-managed
  // secrets carry `username` and `host` alongside the password, so a deployment need
  // only name the secret.
  const secret = await reader.read();
  const host = config.host !== "" ? config.host : secret.host;
  if (host === undefined || host === "") {
    throw new CredentialsError(
      `no database host: set DATABASE_HOST, or use a secret that carries 'host' (secret ${config.secretId})`,
    );
  }

  // `verify-full` needs a CA that can vouch for the server certificate. Aurora
  // chains to an Amazon RDS CA that is not in Node's default trust store, so the
  // bundle is read from disk and passed explicitly. Without it the only options
  // would be to disable verification or fail to connect.
  const ssl =
    config.sslMode === "disable"
      ? false
      : {
          // `rejectUnauthorized: false` here would make the whole TLS setup
          // decorative, so only an explicit `no-verify` relaxes it.
          rejectUnauthorized: config.sslMode !== "no-verify",
          ...(config.sslRootCert !== undefined
            ? { ca: readFileSync(config.sslRootCert, "utf8") }
            : {}),
        };

  const pool = new Pool({
    host,
    port: secret.port ?? config.port,
    database: config.database,
    user: secret.username,
    // The one dynamic field. `pg` calls this per new client
    // (pg/lib/client.js:269), which is the hook that makes rotation work without a
    // restart.
    password: secretPasswordProvider(reader),
    ssl,
    ...poolLimits(),
  });

  // A stale password surfaces as an authentication error. Clearing the cache on one
  // means the next connection re-reads the secret rather than failing until the TTL
  // expires.
  onAuthFailureInvalidate(pool, reader);

  return { pool, source: "secret", secretReader: reader };
}
