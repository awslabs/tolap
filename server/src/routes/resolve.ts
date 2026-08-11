/**
 * The resolve port: `GET /v1/resolve`.
 *
 * This is the endpoint remote TOLAP installs call, and the only one on its
 * listener. It resolves the caller's effective policy for one data source and
 * returns it signed.
 *
 * Kept deliberately small. Everything an attacker can reach without an admin
 * credential is here, so there is value in it being short enough to read in one
 * sitting.
 */

import type { FastifyInstance, FastifyPluginAsync } from "fastify";
import Fastify from "fastify";
import { parseSourceIdentity } from "@aws/tolap-core";
import { AuthorizationError, requireInstall } from "../auth/guards.ts";
import { IdentityLookupError } from "../auth/identity-source.ts";
import type { Keyring } from "../signing/keyring.ts";
import type { PostgresPolicyStore } from "../db/store.ts";
import { loggerOptions, type LogLevel } from "../logging.ts";
import { buildSignedArtifact } from "../signing/artifact.ts";

export interface ResolveDeps {
  readonly store: PostgresPolicyStore;
  /** Signs with the active key and stamps its kid. */
  readonly keyring: Keyring;
  readonly ttlSeconds: number;
  /**
   * Request log verbosity. Omitted means `silent`, for the tests. The composition root
   * passes the configured level.
   *
   * Note what the serializer drops on this port specifically: the query string names the
   * user and tenant being resolved for, which the audit log already records under access
   * control. See src/logging.ts.
   */
  readonly logLevel?: LogLevel;
}

interface ResolveQuery {
  userId?: string;
  tenantId?: string;
  sourceConnectionId?: string;
}

export const resolveRoutes =
  (deps: ResolveDeps): FastifyPluginAsync =>
  async (app) => {
    app.get<{ Querystring: ResolveQuery }>("/v1/resolve", async (request, reply) => {
      const install = await requireInstall(
        request.headers.authorization,
        deps.store,
      );

      const { userId, tenantId, sourceConnectionId } = request.query;

      // All three are required. Defaulting any of them would resolve a policy for
      // a principal or a source the caller did not name -- and since resolution
      // returns deny-all rather than an error when nothing matches, the mistake
      // would look like a working request that simply grants nothing.
      const missing = (
        [
          ["userId", userId],
          ["tenantId", tenantId],
          ["sourceConnectionId", sourceConnectionId],
        ] as const
      )
        .filter(([, value]) => value === undefined || value.trim() === "")
        .map(([name]) => name);

      if (missing.length > 0) {
        return reply
          .code(400)
          .send({ error: `missing required query parameters: ${missing.join(", ")}` });
      }

      // The identifier must parse as `category:namespace:name`. The category
      // decides which wrapper enforces the policy downstream and is read from the
      // *signed* identifier, so an unparseable one cannot be signed and shipped
      // for something else to interpret loosely.
      //
      // Checked with `== null` deliberately: the TypeScript SDK returns
      // `undefined` for an unparseable identifier while the Python one returns
      // `None`, and the docstrings describe both as "None". A `=== null` test here
      // silently never matched, so every malformed identifier was accepted and
      // signed -- caught by the request-validation tests below.
      if (parseSourceIdentity(sourceConnectionId!) == null) {
        return reply.code(400).send({
          error:
            "sourceConnectionId must be 'category:namespace:name' with category one of db, api, kb, storage",
        });
      }

      const policy = await deps.store.resolvePolicy(
        userId!,
        tenantId!,
        sourceConnectionId!,
      );

      const artifact = buildSignedArtifact(
        policy,
        deps.keyring.active,
        deps.ttlSeconds * 1000,
      );

      // Record who pulled what. This is the row that answers "which install has
      // this policy?" during an incident, so it is written before the response
      // rather than fire-and-forget.
      await deps.store.record(
        { id: install.id, kind: "install" },
        "policy.resolve",
        { kind: "source", id: sourceConnectionId! },
        { userId, tenantId, canQuery: policy.permissions.canQuery },
      );
      await deps.store.touchInstall(install.id);

      // No-store: a signed artifact is a bearer credential for its whole TTL
      // (spec section 13), and a proxy or browser cache holding it would widen the
      // replay window beyond the expiry the server chose.
      return reply
        .header("cache-control", "no-store")
        .code(200)
        .send(artifact);
    });

    app.get("/health", async () => ({ status: "ok" }));
  };

/**
 * Build the resolve listener.
 *
 * A separate Fastify instance from the admin app so the two can bind different
 * interfaces -- see docs/policy-server.md on the two-port topology.
 */
export function buildResolveApp(deps: ResolveDeps): FastifyInstance {
  const app = Fastify({
    logger: loggerOptions({ level: deps.logLevel ?? "silent", app: "resolve" }),
  });

  app.setErrorHandler((error, _request, reply) => {
    if (error instanceof IdentityLookupError) {
      // The server could not learn the user's group membership. Returning a policy
      // anyway would silently drop every group-scoped grant -- a denial that looks
      // like a working request, which is the hardest kind to debug. 503 says
      // "ask again", and the cause is logged.
      app.log.error(error);
      return reply
        .code(503)
        .send({ error: "identity lookup unavailable; policy not resolved" });
    }
    if (error instanceof AuthorizationError) {
      // Every resolve-side authorization failure is a flat 401 with an
      // identical body: whether an install exists, whether it was revoked, and
      // whether the secret was wrong must be indistinguishable, or this endpoint
      // becomes an oracle for enumerating installs.
      return reply.code(error.status).send({ error: error.message });
    }

    // Anything else is ours, not the caller's. Log it and say nothing: a stack
    // trace or a database error string in the response body tells an
    // unauthenticated caller about the server's internals.
    app.log.error(error);
    return reply.code(500).send({ error: "internal error" });
  });

  void app.register(resolveRoutes(deps));
  return app;
}
