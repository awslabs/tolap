/**
 * The admin API: policy authoring, assignments, installs, catalog, audit.
 *
 * Every route requires a Cognito-authenticated principal. Reads accept `auditor`;
 * anything that writes requires `admin`. The split exists so a compliance reviewer
 * can inspect policy without holding the ability to change it -- see
 * docs/policy-server.md.
 *
 * This listener is separate from the resolve one so an operator can bind it to a
 * private interface. That is defense in depth; the guards below are the control.
 *
 * Every list route is paginated and bounded. Not for tidiness: this listener
 * shares one Node process and one connection pool with `/v1/resolve`, so a listing
 * that serializes a whole table delays policy resolution for every install, and an
 * install that cannot resolve gets no access at all. `db/pagination.ts` states the
 * bounds and why an over-large `limit` is refused rather than quietly clamped.
 */

import type { FastifyInstance, FastifyPluginAsync, FastifyRequest } from "fastify";
import Fastify from "fastify";
import { parseSourceIdentity, type PolicyAssignment, type PolicyDefinition } from "@aws/tolap-core";
import { AdminAuthError, type AdminPrincipal } from "../auth/cognito.ts";
import { IdentityLookupError } from "../auth/identity-source.ts";
import {
  AuthorizationError,
  requireAdmin,
  type TokenVerifier,
} from "../auth/guards.ts";
import { issueCredential } from "../auth/install-credential.ts";
import type { Actor, PostgresPolicyStore } from "../db/store.ts";
import {
  PaginationError,
  parseLimit,
  type Page,
  type PageQuery,
  type PageRequest,
} from "../db/pagination.ts";
import type { Keyring } from "../signing/keyring.ts";
import {
  SchemaValidationError,
  validateSchema,
} from "../validation.ts";
import { parseManifest, ManifestError } from "../catalog/manifest.ts";
import { importOpenApi } from "../catalog/import-openapi.ts";
import { importSqlDdl } from "../catalog/import-sql.ts";
import { loggerOptions, type LogLevel } from "../logging.ts";

export interface AdminDeps {
  readonly store: PostgresPolicyStore;
  readonly verifier: TokenVerifier;
  readonly keyring: Keyring;
  readonly ttlSeconds: number;
  /**
   * Request log verbosity. Omitted means `silent`, which is what the tests want:
   * hundreds of requests per file, and a log line per request buries the failure.
   * The composition root passes the configured level.
   */
  readonly logLevel?: LogLevel;
}

const actorOf = (principal: AdminPrincipal): Actor => ({
  // The audit row records the Cognito subject, which is stable, rather than the
  // email, which can change.
  id: principal.subject,
  kind: "admin",
});

/**
 * Read `?limit=` and `?cursor=` off a request.
 *
 * Throws `PaginationError`, which the error handler turns into a 400. Deliberately
 * not "fall back to the default on nonsense": a caller who asked for 100000000
 * rows and received 200 with no error would read that as the table being small.
 */
const pageOf = (query: PageQuery): PageRequest => {
  const limit = parseLimit(query.limit);
  return {
    ...(limit !== undefined ? { limit } : {}),
    ...(query.cursor !== undefined ? { cursor: query.cursor } : {}),
  };
};

/**
 * Wrap a page in the response envelope every list route shares.
 *
 * One shape across endpoints so a client writes the paging loop once: the items
 * under the route's own key, and `nextCursor` always present -- `null` on the last
 * page rather than omitted, so "no more pages" is a value the caller can test
 * instead of a missing key that also means "this endpoint does not paginate".
 */
const paged = <T>(key: string, page: Page<T>): Record<string, unknown> => ({
  [key]: page.items,
  nextCursor: page.nextCursor,
});

export const adminRoutes =
  (deps: AdminDeps): FastifyPluginAsync =>
  async (app) => {
    const { store } = deps;

    /** Authenticate and require a role. Throws AuthorizationError otherwise. */
    const auth = (
      request: FastifyRequest,
      role: "admin" | "auditor" = "admin",
    ): Promise<AdminPrincipal> =>
      requireAdmin(request.headers.authorization, deps.verifier, role);

    // -- Session -----------------------------------------------------------

    app.get("/v1/me", async (request) => {
      // The console calls this after the OIDC redirect to learn which role it
      // should render. Requires only `auditor`, so both roles can ask.
      const principal = await auth(request, "auditor");
      return {
        subject: principal.subject,
        email: principal.email,
        role: principal.role,
      };
    });

    // -- Policies ----------------------------------------------------------

    app.get<{ Querystring: PageQuery }>("/v1/policies", async (request) => {
      await auth(request, "auditor");
      // A caller that passes neither parameter still gets a usable first page, so
      // the console keeps working unchanged -- it just stops being the whole table.
      return paged("policies", await store.pageDefinitions(pageOf(request.query)));
    });

    app.get<{ Params: { name: string } }>(
      "/v1/policies/:name",
      async (request, reply) => {
        await auth(request, "auditor");
        const policy = await store.getDefinition(request.params.name);
        if (!policy) return reply.code(404).send({ error: "policy not found" });
        return policy;
      },
    );

    app.post<{ Body: unknown; Querystring: { fragment?: string } }>(
      "/v1/policies/validate",
      async (request) => {
        // Read-only: validating a candidate policy changes nothing, so an auditor
        // may do it. Used for live feedback in the editor.
        await auth(request, "auditor");
        return validateSchema(request.body, "policy-definition", {
          fragment: request.query.fragment === "true",
        });
      },
    );

    app.put<{ Params: { name: string }; Body: PolicyDefinition }>(
      "/v1/policies/:name",
      async (request, reply) => {
        const principal = await auth(request);
        const body = request.body;

        if (body?.name !== request.params.name) {
          // A mismatch means the caller is confused about which policy they are
          // editing; guessing which one they meant is how the wrong policy gets
          // overwritten.
          return reply
            .code(400)
            .send({ error: "policy name in body must match the URL" });
        }

        // Full document validation on the write path: a partial policy must not
        // reach the datastore, where it would resolve and be enforced.
        const result = validateSchema(body, "policy-definition");
        if (!result.valid) {
          return reply.code(422).send({ error: "validation failed", errors: result.errors });
        }

        await store.putDefinitionAs(body, actorOf(principal));
        return reply.code(200).send(body);
      },
    );

    app.delete<{ Params: { name: string } }>(
      "/v1/policies/:name",
      async (request, reply) => {
        const principal = await auth(request);
        const deleted = await store.deleteDefinitionAs(
          request.params.name,
          actorOf(principal),
        );
        if (!deleted) return reply.code(404).send({ error: "policy not found" });
        return reply.code(204).send();
      },
    );

    // -- Versions ----------------------------------------------------------

    app.get<{ Params: { name: string }; Querystring: PageQuery }>(
      "/v1/policies/:name/versions",
      async (request) => {
        await auth(request, "auditor");
        // Bounded even though it is scoped to one policy: each row carries a full
        // policy body, so a long-lived policy's history is one of the biggest
        // payloads this API can build.
        return paged(
          "versions",
          await store.pageVersions(request.params.name, pageOf(request.query)),
        );
      },
    );

    app.post<{
      Params: { name: string };
      Body: { policy: PolicyDefinition; note?: string };
    }>("/v1/policies/:name/versions", async (request, reply) => {
      const principal = await auth(request);
      const { policy, note } = request.body ?? {};

      if (policy?.name !== request.params.name) {
        return reply
          .code(400)
          .send({ error: "policy name in body must match the URL" });
      }

      // Drafts are validated as documents too. A draft is a candidate for
      // publishing, and validating only at publish time means the error arrives
      // when someone is trying to ship.
      const result = validateSchema(policy, "policy-definition");
      if (!result.valid) {
        return reply.code(422).send({ error: "validation failed", errors: result.errors });
      }

      const versionNo = await store.saveDraft(policy, actorOf(principal), note);
      return reply.code(201).send({ name: policy.name, versionNo });
    });

    app.post<{ Params: { name: string; versionNo: string } }>(
      "/v1/policies/:name/versions/:versionNo/publish",
      async (request, reply) => {
        const principal = await auth(request);
        const versionNo = Number(request.params.versionNo);
        if (!Number.isInteger(versionNo)) {
          return reply.code(400).send({ error: "versionNo must be an integer" });
        }
        try {
          const policy = await store.publish(
            request.params.name,
            versionNo,
            actorOf(principal),
          );
          return { published: policy };
        } catch (error) {
          return reply.code(404).send({ error: (error as Error).message });
        }
      },
    );

    app.post<{ Params: { name: string; versionNo: string } }>(
      "/v1/policies/:name/versions/:versionNo/rollback",
      async (request, reply) => {
        const principal = await auth(request);
        const versionNo = Number(request.params.versionNo);
        if (!Number.isInteger(versionNo)) {
          return reply.code(400).send({ error: "versionNo must be an integer" });
        }
        try {
          const newVersionNo = await store.rollback(
            request.params.name,
            versionNo,
            actorOf(principal),
          );
          return { newVersionNo };
        } catch (error) {
          return reply.code(404).send({ error: (error as Error).message });
        }
      },
    );

    // -- Assignments -------------------------------------------------------

    app.get<{ Querystring: PageQuery & { assignee?: string } }>(
      "/v1/assignments",
      async (request) => {
        await auth(request, "auditor");
        return paged(
          "assignments",
          await store.pageAssignments(
            request.query.assignee,
            pageOf(request.query),
          ),
        );
      },
    );

    app.post<{ Body: PolicyAssignment }>("/v1/assignments", async (request, reply) => {
      const principal = await auth(request);

      const result = validateSchema(request.body, "policy-assignment");
      if (!result.valid) {
        return reply.code(422).send({ error: "validation failed", errors: result.errors });
      }

      // An assignment naming a policy that does not exist would sit in the table
      // contributing nothing while appearing, in the UI, to grant access.
      if (!(await store.getDefinition(request.body.policyName))) {
        return reply
          .code(422)
          .send({ error: `policy '${request.body.policyName}' does not exist` });
      }

      await store.putAssignmentAs(request.body, actorOf(principal));
      return reply.code(201).send(request.body);
    });

    app.delete<{ Querystring: { policyName?: string; assignee?: string } }>(
      "/v1/assignments",
      async (request, reply) => {
        const principal = await auth(request);
        const { policyName, assignee } = request.query;
        if (!policyName || !assignee) {
          return reply
            .code(400)
            .send({ error: "policyName and assignee are required" });
        }
        const revoked = await store.revokeAssignment(
          policyName,
          assignee,
          actorOf(principal),
        );
        if (!revoked) return reply.code(404).send({ error: "no live assignment" });
        return reply.code(204).send();
      },
    );

    // -- Resolve preview ---------------------------------------------------

    app.get<{
      Querystring: { userId?: string; tenantId?: string; sourceConnectionId?: string };
    }>("/v1/resolve/preview", async (request, reply) => {
      await auth(request, "auditor");
      const { userId, tenantId, sourceConnectionId } = request.query;

      if (!userId || !tenantId || !sourceConnectionId) {
        return reply.code(400).send({
          error: "userId, tenantId and sourceConnectionId are required",
        });
      }
      if (parseSourceIdentity(sourceConnectionId) == null) {
        return reply
          .code(400)
          .send({ error: "sourceConnectionId must be 'category:namespace:name'" });
      }

      const policy = await store.resolvePolicy(userId, tenantId, sourceConnectionId);

      // Returned UNSIGNED, deliberately. A preview is for a human to read in the
      // console; signing it would produce a usable credential on a route an
      // auditor can reach, turning a read-only inspection tool into a way to mint
      // access.
      return {
        effectivePolicy: policy,
        contributingPolicies: policy.sourceProfiles,
      };
    });

    // -- Installs ----------------------------------------------------------

    app.get<{ Querystring: PageQuery }>("/v1/installs", async (request) => {
      await auth(request, "auditor");
      return paged("installs", await store.pageInstalls(pageOf(request.query)));
    });

    app.post<{ Body: { id?: string; name?: string } }>(
      "/v1/installs",
      async (request, reply) => {
        const principal = await auth(request);
        const { id, name } = request.body ?? {};

        if (!id || !name) {
          return reply.code(400).send({ error: "id and name are required" });
        }
        // The id is embedded in the credential and used as a lookup key, so keep
        // it to a conservative character set rather than discovering later what a
        // colon or a slash does to the parsing.
        if (!/^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$/.test(id)) {
          return reply.code(400).send({
            error: "id must be lowercase alphanumeric with hyphens, 2-64 chars",
          });
        }
        if (await store.getInstall(id)) {
          return reply.code(409).send({ error: "install id already registered" });
        }

        const issued = issueCredential(id);
        await store.createInstall(id, name, issued.hash, actorOf(principal));

        // The secret is returned exactly once and never recoverable: only its hash
        // is stored. Said plainly in the response so a caller that discards it
        // knows to re-register rather than going looking for it.
        return reply.code(201).send({
          id,
          name,
          credential: issued.secret,
          notice:
            "Store this credential now. It is not recoverable -- only its hash is kept.",
        });
      },
    );

    app.delete<{ Params: { id: string } }>(
      "/v1/installs/:id",
      async (request, reply) => {
        const principal = await auth(request);
        const revoked = await store.revokeInstall(
          request.params.id,
          actorOf(principal),
        );
        if (!revoked) {
          return reply.code(404).send({ error: "no live install with that id" });
        }
        return reply.code(204).send();
      },
    );

    // -- Source catalog ----------------------------------------------------

    app.get<{ Querystring: PageQuery }>("/v1/catalog", async (request) => {
      await auth(request, "auditor");
      // Few rows, large rows: one manifest can be megabytes, so the bound here is
      // about response size rather than row count.
      return paged("sources", await store.pageSources(pageOf(request.query)));
    });

    app.get<{ Params: { id: string } }>("/v1/catalog/:id", async (request, reply) => {
      await auth(request, "auditor");
      const source = await store.getSource(request.params.id);
      if (!source) return reply.code(404).send({ error: "source not found" });
      return source;
    });

    app.put<{ Body: unknown }>("/v1/catalog", async (request, reply) => {
      const principal = await auth(request);
      try {
        const manifest = parseManifest(request.body);
        await store.putSourceAs(manifest, "manifest", actorOf(principal));
        return reply.code(200).send(manifest);
      } catch (error) {
        if (error instanceof ManifestError) {
          return reply.code(422).send({ error: error.message });
        }
        throw error;
      }
    });

    app.post<{
      Body: { sourceConnectionId?: string; spec?: unknown };
    }>("/v1/catalog/import/openapi", async (request, reply) => {
      const principal = await auth(request);
      const { sourceConnectionId, spec } = request.body ?? {};
      if (!sourceConnectionId || spec === undefined) {
        return reply
          .code(400)
          .send({ error: "sourceConnectionId and spec are required" });
      }
      try {
        const manifest = importOpenApi(sourceConnectionId, spec);
        await store.putSourceAs(manifest, "openapi", actorOf(principal));
        return reply.code(200).send(manifest);
      } catch (error) {
        if (error instanceof ManifestError) {
          return reply.code(422).send({ error: error.message });
        }
        throw error;
      }
    });

    app.post<{
      Body: { sourceConnectionId?: string; ddl?: string };
    }>("/v1/catalog/import/sql", async (request, reply) => {
      const principal = await auth(request);
      const { sourceConnectionId, ddl } = request.body ?? {};
      if (!sourceConnectionId || typeof ddl !== "string") {
        return reply
          .code(400)
          .send({ error: "sourceConnectionId and ddl are required" });
      }
      try {
        const manifest = importSqlDdl(sourceConnectionId, ddl);
        await store.putSourceAs(manifest, "sql", actorOf(principal));
        return reply.code(200).send(manifest);
      } catch (error) {
        if (error instanceof ManifestError) {
          return reply.code(422).send({ error: error.message });
        }
        throw error;
      }
    });

    app.delete<{ Params: { id: string } }>(
      "/v1/catalog/:id",
      async (request, reply) => {
        const principal = await auth(request);
        const deleted = await store.deleteSourceAs(
          request.params.id,
          actorOf(principal),
        );
        if (!deleted) return reply.code(404).send({ error: "source not found" });
        return reply.code(204).send();
      },
    );

    // -- Audit -------------------------------------------------------------

    app.get<{ Querystring: PageQuery }>("/v1/audit", async (request) => {
      // Readable by an auditor: reading the audit log is the auditor's job.
      await auth(request, "auditor");
      // This route previously accepted any integer, so `?limit=100000000` read the
      // whole log into one response. The parse now refuses anything that is not a
      // plain integer inside the ceiling instead of coercing it -- a reviewer who
      // asks for more entries than exist must not be told, by silence, that there
      // were only 500 events.
      return paged("entries", await store.pageAudit(pageOf(request.query)));
    });

    app.get("/health", async () => ({ status: "ok" }));
  };

export function buildAdminApp(deps: AdminDeps): FastifyInstance {
  const app = Fastify({
    logger: loggerOptions({ level: deps.logLevel ?? "silent", app: "admin" }),
    // Stated rather than inherited. Fastify defaults to 1 MB, which is already the
    // bound on how much work an uploaded OpenAPI document or SQL dump can ask the
    // importers to do -- so it is a security parameter here and belongs where it can
    // be seen and changed. 2 MB because a real `pg_dump --schema-only` of a wide
    // schema exceeds 1 MB and being unable to import it is a worse failure than the
    // extra megabyte.
    //
    // The importers are linear in input size. Treat that as a property under test rather
    // than an obvious one: six separate super-linear paths have been found and fixed in
    // `catalog/`, and the sixth survived a sweep of the other five because the test
    // guarding its function fed it input that never reached the offending loop. A
    // quadratic parser turns any body limit into an event-loop stall, and this task also
    // serves policy resolution -- so the cost lands on every install as a denial.
    bodyLimit: 2 * 1024 * 1024,
  });

  app.setErrorHandler((error, _request, reply) => {
    if (error instanceof AuthorizationError) {
      // 401 versus 403 is preserved here, unlike on the resolve port: the console
      // needs to distinguish "log in again" from "your role cannot do this", and
      // the caller is already authenticated for the 403 case.
      return reply.code(error.status).send({ error: error.message });
    }
    if (error instanceof AdminAuthError) {
      return reply.code(401).send({ error: error.message });
    }
    if (error instanceof IdentityLookupError) {
      // Same reasoning as the resolve port: a preview computed without knowing the
      // user's groups would show narrower access than they really have, and an
      // administrator would take that at face value.
      app.log.error(error);
      return reply
        .code(503)
        .send({ error: "identity lookup unavailable; policy not resolved" });
    }
    if (error instanceof PaginationError) {
      // 400, not 422: a bad `?limit=` or `?cursor=` is a malformed request line,
      // not a document that failed schema validation, and the console renders the
      // two differently.
      return reply.code(error.status).send({ error: error.message });
    }
    if (error instanceof SchemaValidationError) {
      return reply
        .code(422)
        .send({ error: "validation failed", errors: error.errors });
    }
    app.log.error(error);
    return reply.code(500).send({ error: "internal error" });
  });

  void app.register(adminRoutes(deps));
  return app;
}
