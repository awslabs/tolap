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
export async function buildPool(config: DatabaseConfig): Promise<BuiltPool> {
  if (config.kind === "url") {
    // Local development: the password is in the string and there is no rotation to
    // absorb.
    return {
      pool: new Pool({ connectionString: config.url }),
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
  });

  // A stale password surfaces as an authentication error. Clearing the cache on one
  // means the next connection re-reads the secret rather than failing until the TTL
  // expires.
  onAuthFailureInvalidate(pool, reader);

  return { pool, source: "secret", secretReader: reader };
}
