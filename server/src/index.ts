/**
 * Composition root.
 *
 * Two listeners, deliberately: the admin API and console on one, `/v1/resolve` on
 * the other, so an operator can bind the policy-authoring surface to a private
 * interface while remote installs reach only the resolve port. That is defense in
 * depth -- the route guards are the actual control, and a single-interface
 * deployment is still safe. See docs/policy-server.md.
 */

import { Pool } from "pg";
import { CognitoVerifier } from "./auth/cognito.ts";
import { loadConfig, type ServerConfig } from "./config.ts";
import { PostgresPolicyStore } from "./db/store.ts";
import { buildAdminApp } from "./routes/admin.ts";
import { buildResolveApp } from "./routes/resolve.ts";

/**
 * Group and role membership for policy resolution.
 *
 * Deliberately empty by default rather than guessed. A resolver that invented
 * group membership would silently widen or narrow what every group-scoped
 * assignment grants, and getting that wrong is an access-control bug rather than a
 * configuration inconvenience. Point this at the directory that owns the answer --
 * Cognito groups, an LDAP query, an internal service -- when wiring up a
 * deployment.
 */
export interface IdentitySource {
  getGroups(userId: string): Promise<string[]>;
  getRoles(userId: string): Promise<string[]>;
}

const emptyIdentitySource: IdentitySource = {
  getGroups: async () => [],
  getRoles: async () => [],
};

export interface StartedServer {
  readonly adminUrl: string;
  readonly resolveUrl: string;
  close(): Promise<void>;
}

export async function start(
  config: ServerConfig = loadConfig(),
  identitySource: IdentitySource = emptyIdentitySource,
): Promise<StartedServer> {
  const pool = new Pool({ connectionString: config.databaseUrl });
  const store = new PostgresPolicyStore(pool, identitySource);

  const verifier = new CognitoVerifier({
    issuer: config.cognitoIssuer,
    audience: config.cognitoAudience,
    adminGroup: config.adminGroup,
    auditorGroup: config.auditorGroup,
  });

  const admin = buildAdminApp({
    store,
    verifier,
    signingKey: config.signingKey,
    ttlSeconds: config.ttlSeconds,
  });
  const resolve = buildResolveApp({
    store,
    signingKey: config.signingKey,
    ttlSeconds: config.ttlSeconds,
  });

  const adminUrl = await admin.listen({
    port: config.port,
    host: config.host,
  });
  const resolveUrl = await resolve.listen({
    port: config.resolvePort,
    host: config.resolveHost,
  });

  return {
    adminUrl,
    resolveUrl,
    async close() {
      // Stop accepting requests before closing the pool, so an in-flight query
      // cannot fail against a pool that has already gone away.
      await Promise.all([admin.close(), resolve.close()]);
      await pool.end();
    },
  };
}

// Run directly: `npm run dev`.
if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) {
  try {
    const config = loadConfig();
    const server = await start(config);
    console.log(`admin API + console  ${server.adminUrl}`);
    console.log(`resolve API          ${server.resolveUrl}`);

    for (const signal of ["SIGINT", "SIGTERM"] as const) {
      process.once(signal, () => {
        void server.close().then(() => process.exit(0));
      });
    }
  } catch (error) {
    // Configuration and startup failures are fatal by design: a policy server
    // that boots with a bad signing key issues artifacts nobody can verify, and
    // the failure would surface at some other service's enforcement boundary
    // rather than here.
    console.error(`failed to start: ${(error as Error).message}`);
    process.exit(1);
  }
}
