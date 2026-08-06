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
import {
  CognitoIdentitySource,
  NoIdentitySource,
  StaticIdentitySource,
  type IdentitySource,
} from "./auth/identity-source.ts";
import { loadConfig, type ServerConfig } from "./config.ts";
import { PostgresPolicyStore } from "./db/store.ts";
import { buildAdminApp } from "./routes/admin.ts";
import { buildResolveApp } from "./routes/resolve.ts";

/**
 * Build the identity source the configuration asks for.
 *
 * Group and role membership decides whether a group-scoped assignment applies, so
 * getting it wrong is an access-control bug rather than a configuration
 * inconvenience. The `none` case is a deliberate, named choice rather than a
 * default nobody notices -- and the server logs which one it chose at startup, so
 * "why did that group grant do nothing" is answerable from the log.
 */
function buildIdentitySource(config: ServerConfig): IdentitySource {
  switch (config.identity.kind) {
    case "cognito":
      return new CognitoIdentitySource({
        userPoolId: config.identity.userPoolId,
        ...(config.identity.rolePrefix !== undefined
          ? { rolePrefix: config.identity.rolePrefix }
          : {}),
        cacheTtlSeconds: config.identity.cacheTtlSeconds,
      });
    case "static":
      return StaticIdentitySource.parse(config.identity.spec);
    case "none":
      return new NoIdentitySource();
  }
}

export interface StartedServer {
  readonly adminUrl: string;
  readonly resolveUrl: string;
  close(): Promise<void>;
}

export async function start(
  config: ServerConfig = loadConfig(),
  identitySource: IdentitySource = buildIdentitySource(config),
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
    keyring: config.keyring,
    ttlSeconds: config.ttlSeconds,
  });
  const resolve = buildResolveApp({
    store,
    keyring: config.keyring,
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
    // Logged because both are silent-failure surfaces: a `none` identity source
    // makes group-scoped assignments resolve to nothing, and knowing which key is
    // active is the first question during a rotation.
    console.log(
      `identity source      ${config.identity.kind}` +
        (config.identity.kind === "none"
          ? "  (group- and role-scoped assignments will NOT resolve)"
          : ""),
    );
    console.log(
      `signing keys         active=${config.keyring.active.kid}` +
        (config.keyring.size > 1
          ? `  also verifying: ${config.keyring.kids.filter((k) => k !== config.keyring.active.kid).join(", ")}`
          : ""),
    );

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
