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
import rateLimit from "@fastify/rate-limit";
import { parseSourceIdentity } from "@aws/tolap-core";
import { AuthorizationError, requireInstall } from "../auth/guards.ts";
import {
  isValidationError,
  normalizeDeclaredPurpose,
  validationErrorBody,
} from "./purpose-query.ts";
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
  /**
   * Per-IP requests per window, applied in-process. Omitted disables it, which is what
   * the tests want -- they issue many requests from one address.
   *
   * This exists alongside the edge WAF rate-based rule rather than instead of it,
   * because the two fail differently. WAF sheds a flood before it reaches this process;
   * in-process limiting cannot, since by the time Fastify counts a request it has
   * already cost a connection and an event-loop turn. But WAF only protects a
   * deployment that has WAF, and this server is meant to run behind any ingress --
   * including none. Without a bound here, those deployments have none.
   *
   * It matters more on this port than on the admin one. Every artifact this endpoint
   * returns is replayable for its whole TTL unless the consuming SDK configures a
   * replay guard, which this server can neither enforce nor observe. The rate at which
   * a stolen install credential can harvest signed policy is bounded here or nowhere.
   */
  readonly rateLimit?: number;
  readonly rateLimitWindowSeconds?: number;
}

interface ResolveQuery {
  userId?: string;
  tenantId?: string;
  sourceConnectionId?: string;
  /**
   * The purpose the caller declares for this resolution (canonical-enforcement-spec §15.1).
   *
   * Optional, and omitting it is not the same as declaring nothing went wrong: a policy
   * carrying a `purposeProfile` will not resolve, and a policy set that is entirely
   * purpose-scoped resolves to deny-all. That is the specified behaviour, not a fault, which
   * is why it is not an error to omit -- but it is why a caller that means to use a
   * purpose-bound policy has to send this.
   */
  declaredPurpose?: string;
}

/**
 * The `purposeId` pattern from `schema/v1.0/policy-definition.schema.json`.
 *
 * Restated here rather than read from the schema because this port is deliberately small and
 * has no schema loader; `src/validation.ts` owns document validation and a declared purpose is
 * a query parameter, not a document. Kept in step by
 * `tests/resolve-purpose.test.ts`, which reads the schema and asserts the two agree.
 */

export const resolveRoutes =
  (deps: ResolveDeps): FastifyPluginAsync =>
  async (app) => {
    // A querystring schema, so Fastify hands the handler strings rather than whatever the
    // default parser inferred. Without it a REPEATED key yields an ARRAY, and the handler's
    // `.trim()` throws a TypeError before any validation runs -- turning
    // `?declaredPurpose=a&declaredPurpose=b` into a 500. Contained (the catch-all returns a
    // flat error and logs the cause, and `requireInstall` gates the route first) but wrong:
    // a malformed request is a 400. Declared for all four parameters, because the pattern
    // pre-dated `declaredPurpose` for the other three and fixing one would have left three.
    //
    // The schema alone was not enough, and the 400 this comment asserted was not what the
    // port returned: a validation error reaches `setErrorHandler`, which had no branch for
    // it and fell through to the catch-all. The schema rejected the request correctly and
    // the response blamed the server. `isValidationError` in the handler is the other half,
    // and there is now a test for the status code rather than a comment claiming it.
    const querystring = {
      type: "object",
      additionalProperties: false,
      properties: {
        userId: { type: "string" },
        tenantId: { type: "string" },
        sourceConnectionId: { type: "string" },
        declaredPurpose: { type: "string" },
      },
    } as const;

    app.get<{ Querystring: ResolveQuery }>("/v1/resolve", { schema: { querystring } }, async (request, reply) => {
      const install = await requireInstall(
        request.headers.authorization,
        deps.store,
      );

      const { userId, tenantId, sourceConnectionId, declaredPurpose } = request.query;

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

      // A malformed purpose is rejected rather than ignored, and an empty one normalizes to
      // absent. Both rules live in `purpose-query.ts` so this route and
      // `GET /v1/resolve/preview` cannot disagree about them -- they already did once, which
      // is why the helper exists.
      const { purpose, error: purposeError } = normalizeDeclaredPurpose(declaredPurpose);
      if (purposeError !== undefined) {
        return reply.code(400).send({ error: purposeError });
      }

      const policy = await deps.store.resolvePolicy(
        userId!,
        tenantId!,
        sourceConnectionId!,
        purpose,
      );

      const artifact = buildSignedArtifact(
        policy,
        deps.keyring.active,
        deps.ttlSeconds * 1000,
      );

      // Record who pulled what. This is the row that answers "which install has
      // this policy?" during an incident, so it is written before the response
      // rather than fire-and-forget.
      // The declared purpose is recorded because it is half of what was authorized: the same
      // user and source under two purposes are two different grants, and an incident review
      // that cannot tell them apart cannot answer what an agent was permitted to do. Recorded
      // as resolved (empty normalized to absent) rather than as sent, so the log matches the
      // artifact.
      await deps.store.record(
        { id: install.id, kind: "install" },
        "policy.resolve",
        { kind: "source", id: sourceConnectionId! },
        {
          userId,
          tenantId,
          canQuery: policy.permissions.canQuery,
          declaredPurpose: purpose ?? null,
          purposeId: policy.purposeProfile?.purposeId ?? null,
        },
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
    // Unknown query/body properties are REJECTED, not silently stripped. Fastify's ajv
    // defaults to `removeAdditional: true`, which deletes anything a schema's
    // `additionalProperties: false` does not allow and then proceeds -- so a typo'd
    // `declaredPurposes` was dropped and the request resolved as though no purpose had been
    // declared. Against a purpose-scoped policy set that is deny-all: a request that looks
    // like it worked and simply granted nothing, which is the failure this port already
    // rejects a *malformed* purpose to avoid. Stripping and denying is the same mistake
    // wearing a 200.
    ajv: { customOptions: { removeAdditional: false } },
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

    // A schema-validation failure is the caller's fault, not the server's. Without this
    // branch the querystring schema below works and reports itself as a 500, because
    // `setErrorHandler` replaces the default 400 response wholesale.
    if (isValidationError(error)) {
      return reply.code(400).send(validationErrorBody(error));
    }

    // The rate limiter signals a refusal by throwing, so without this the catch-all
    // below rewrites every 429 into a 500 -- the limiter would work and report itself
    // as a server fault. Found by the test that asserts the status code rather than
    // asserting the plugin is registered.
    // Narrowed rather than cast: the handler's `error` is `unknown`, and reaching
    // into it without a check is how a non-error throw becomes a crash in the
    // handler that exists to prevent crashes.
    if (
      typeof error === "object" &&
      error !== null &&
      (error as { statusCode?: unknown }).statusCode === 429
    ) {
      return reply.code(429).send({ error: "too many requests" });
    }

    // Anything else is ours, not the caller's. Log it and say nothing: a stack
    // trace or a database error string in the response body tells an
    // unauthenticated caller about the server's internals.
    app.log.error(error);
    return reply.code(500).send({ error: "internal error" });
  });

  if (deps.rateLimit !== undefined) {
    void app.register(rateLimit, {
      max: deps.rateLimit,
      timeWindow: (deps.rateLimitWindowSeconds ?? 60) * 1000,
      allowList: (request) => request.url === "/health",
      // No `errorResponseBuilder` here, deliberately. It replaces the thrown error
      // with a plain object carrying no `statusCode`, which the error handler below
      // then cannot recognise as a 429 and rewrites to 500. The handler already owns
      // response shaping on this port, so the flat body is built there instead.
    });
  }

  void app.register(resolveRoutes(deps));
  return app;
}
