/**
 * The admin API.
 *
 * The recurring question is authorization: for every route, can an auditor reach
 * it, and does an unauthenticated caller get nothing? Those are asserted
 * route-by-route rather than once, because a missing guard on a single write route
 * is the whole compromise and a spot check would not find it.
 */

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import type { AdminPrincipal } from "../src/auth/cognito.ts";
import { AdminAuthError } from "../src/auth/cognito.ts";
import { PostgresPolicyStore } from "../src/db/store.ts";
import { buildAdminApp } from "../src/routes/admin.ts";
import { HAVE_DB, staticIdentity, testDb, type TestDb } from "./helpers/db.ts";

const KEY = "admin-endpoint-test-key-not-for-production";

const ADMIN_PRINCIPAL: AdminPrincipal = {
  subject: "cognito-sub-admin",
  email: "admin@example.com",
  role: "admin",
};
const AUDITOR_PRINCIPAL: AdminPrincipal = {
  subject: "cognito-sub-auditor",
  role: "auditor",
};

/** Verifier that trusts a token naming a role, so tests need no real Cognito. */
const verifier = {
  verify: async (token: string): Promise<AdminPrincipal> => {
    if (token === "admin-token") return ADMIN_PRINCIPAL;
    if (token === "auditor-token") return AUDITOR_PRINCIPAL;
    throw new AdminAuthError("unrecognized test token");
  },
};

const POLICY = {
  version: "1.0",
  name: "analyst",
  description: "test policy",
  permissions: { canQuery: true, readOnly: true },
  objectRules: { allowedObjects: ["patients"] },
} as const;

const asAdmin = { authorization: "Bearer admin-token" };
const asAuditor = { authorization: "Bearer auditor-token" };

describe("admin API", () => {
  it("guard: the skip condition is a real boolean", () => {
    expect(typeof HAVE_DB).toBe("boolean");
  });

  describe.skipIf(!HAVE_DB)("against PostgreSQL", () => {
    let db: TestDb;
    let store: PostgresPolicyStore;
    let app: FastifyInstance;

    beforeAll(async () => {
      db = await testDb("admin_endpoint");
    });

    afterAll(async () => {
      await app?.close();
      await db?.close();
    });

    beforeEach(async () => {
      await db.reset();
      store = new PostgresPolicyStore(db.pool, staticIdentity());
      await app?.close();
      app = buildAdminApp({ store, verifier, signingKey: KEY, ttlSeconds: 900 });
    });

    const put = (policy: unknown = POLICY, headers = asAdmin) =>
      app.inject({
        method: "PUT",
        url: `/v1/policies/${(policy as { name: string }).name}`,
        headers,
        payload: policy as object,
      });

    // -- Authorization matrix ---------------------------------------------

    describe("authorization", () => {
      /** Every route, with the role it should demand. */
      const routes = [
        { method: "GET", url: "/v1/me", role: "auditor" },
        { method: "GET", url: "/v1/policies", role: "auditor" },
        { method: "GET", url: "/v1/policies/analyst", role: "auditor" },
        { method: "POST", url: "/v1/policies/validate", role: "auditor" },
        { method: "GET", url: "/v1/policies/analyst/versions", role: "auditor" },
        { method: "GET", url: "/v1/assignments", role: "auditor" },
        { method: "GET", url: "/v1/resolve/preview", role: "auditor" },
        { method: "GET", url: "/v1/installs", role: "auditor" },
        { method: "GET", url: "/v1/catalog", role: "auditor" },
        { method: "GET", url: "/v1/audit", role: "auditor" },
        { method: "PUT", url: "/v1/policies/analyst", role: "admin" },
        { method: "DELETE", url: "/v1/policies/analyst", role: "admin" },
        { method: "POST", url: "/v1/policies/analyst/versions", role: "admin" },
        {
          method: "POST",
          url: "/v1/policies/analyst/versions/1/publish",
          role: "admin",
        },
        {
          method: "POST",
          url: "/v1/policies/analyst/versions/1/rollback",
          role: "admin",
        },
        { method: "POST", url: "/v1/assignments", role: "admin" },
        { method: "DELETE", url: "/v1/assignments", role: "admin" },
        { method: "POST", url: "/v1/installs", role: "admin" },
        { method: "DELETE", url: "/v1/installs/x", role: "admin" },
        { method: "PUT", url: "/v1/catalog", role: "admin" },
        { method: "POST", url: "/v1/catalog/import/openapi", role: "admin" },
        { method: "POST", url: "/v1/catalog/import/sql", role: "admin" },
        { method: "DELETE", url: "/v1/catalog/x", role: "admin" },
      ] as const;

      it.each(routes)(
        "$method $url rejects an unauthenticated caller",
        async ({ method, url }) => {
          const response = await app.inject({ method, url, payload: {} });
          expect(response.statusCode).toBe(401);
        },
      );

      it.each(routes)(
        "$method $url rejects an unrecognized token",
        async ({ method, url }) => {
          const response = await app.inject({
            method,
            url,
            headers: { authorization: "Bearer forged" },
            payload: {},
          });
          expect(response.statusCode).toBe(401);
        },
      );

      it.each(routes.filter((r) => r.role === "admin"))(
        "$method $url forbids an auditor with 403",
        async ({ method, url }) => {
          const response = await app.inject({
            method,
            url,
            headers: asAuditor,
            payload: {},
          });
          // 403 rather than 401: the identity is fine, the role is not. A 401 would
          // send the console through a login that cannot fix anything.
          expect(response.statusCode).toBe(403);
        },
      );

      it.each(routes.filter((r) => r.role === "auditor"))(
        "$method $url admits an auditor",
        async ({ method, url }) => {
          const response = await app.inject({
            method,
            url,
            headers: asAuditor,
            payload: {},
          });
          // Not 401 or 403. A 400 for a missing query parameter is fine here --
          // the point is the guard let them through.
          expect([401, 403]).not.toContain(response.statusCode);
        },
      );
    });

    // -- Policies ----------------------------------------------------------

    describe("policies", () => {
      it("creates, reads and lists a policy", async () => {
        expect((await put()).statusCode).toBe(200);

        const read = await app.inject({
          method: "GET",
          url: "/v1/policies/analyst",
          headers: asAuditor,
        });
        expect(read.json().name).toBe("analyst");

        const list = await app.inject({
          method: "GET",
          url: "/v1/policies",
          headers: asAuditor,
        });
        expect(list.json().policies).toHaveLength(1);
      });

      it("404s an unknown policy", async () => {
        const response = await app.inject({
          method: "GET",
          url: "/v1/policies/nope",
          headers: asAuditor,
        });
        expect(response.statusCode).toBe(404);
      });

      it("rejects a body whose name disagrees with the URL", async () => {
        // Guessing which policy the caller meant is how the wrong one gets
        // overwritten.
        const response = await app.inject({
          method: "PUT",
          url: "/v1/policies/analyst",
          headers: asAdmin,
          payload: { ...POLICY, name: "something-else" },
        });
        expect(response.statusCode).toBe(400);
      });

      it("rejects an invalid policy with every error listed", async () => {
        const response = await put({
          version: "2.0",
          name: "Bad Name",
          permissions: {},
        });
        expect(response.statusCode).toBe(422);
        const body = response.json();
        expect(body.errors.length).toBeGreaterThan(1);
        expect(body.errors.map((e: { path: string }) => e.path)).toContain(
          "/version",
        );
      });

      it("never persists a policy that failed validation", async () => {
        await put({ name: "half-written" });
        const list = await app.inject({
          method: "GET",
          url: "/v1/policies",
          headers: asAuditor,
        });
        expect(list.json().policies).toEqual([]);
      });

      it("deletes a policy", async () => {
        await put();
        expect(
          (
            await app.inject({
              method: "DELETE",
              url: "/v1/policies/analyst",
              headers: asAdmin,
            })
          ).statusCode,
        ).toBe(204);
        expect(
          (
            await app.inject({
              method: "DELETE",
              url: "/v1/policies/analyst",
              headers: asAdmin,
            })
          ).statusCode,
        ).toBe(404);
      });

      it("validates without saving", async () => {
        const response = await app.inject({
          method: "POST",
          url: "/v1/policies/validate",
          headers: asAuditor,
          payload: POLICY,
        });
        expect(response.json()).toEqual({ valid: true, errors: [] });

        const list = await app.inject({
          method: "GET",
          url: "/v1/policies",
          headers: asAuditor,
        });
        expect(list.json().policies).toEqual([]);
      });

      it("validates a draft in fragment mode", async () => {
        const partial = { name: "draft-policy" };
        const strict = await app.inject({
          method: "POST",
          url: "/v1/policies/validate",
          headers: asAuditor,
          payload: partial,
        });
        expect(strict.json().valid).toBe(false);

        const lenient = await app.inject({
          method: "POST",
          url: "/v1/policies/validate?fragment=true",
          headers: asAuditor,
          payload: partial,
        });
        expect(lenient.json().valid).toBe(true);
      });
    });

    // -- Versions ----------------------------------------------------------

    describe("versions", () => {
      const draft = (policy: unknown = POLICY, note = "note") =>
        app.inject({
          method: "POST",
          url: `/v1/policies/${(policy as { name: string }).name}/versions`,
          headers: asAdmin,
          payload: { policy, note },
        });

      it("drafts, publishes, and rolls back", async () => {
        const first = await draft(POLICY);
        expect(first.statusCode).toBe(201);
        expect(first.json().versionNo).toBe(1);

        await app.inject({
          method: "POST",
          url: "/v1/policies/analyst/versions/1/publish",
          headers: asAdmin,
        });

        // A second version that widens access, then a rollback to the first.
        const widened = {
          ...POLICY,
          objectRules: { allowedObjects: ["patients", "billing"] },
        };
        const second = await draft(widened);
        expect(second.json().versionNo).toBe(2);
        await app.inject({
          method: "POST",
          url: "/v1/policies/analyst/versions/2/publish",
          headers: asAdmin,
        });

        expect(
          (
            await app.inject({
              method: "GET",
              url: "/v1/policies/analyst",
              headers: asAuditor,
            })
          ).json().objectRules.allowedObjects,
        ).toEqual(["patients", "billing"]);

        const rollback = await app.inject({
          method: "POST",
          url: "/v1/policies/analyst/versions/1/rollback",
          headers: asAdmin,
        });
        // Rollback appends a new version rather than mutating history, so "we
        // rolled back" is its own event instead of looking like v1 was always live.
        expect(rollback.json().newVersionNo).toBe(3);

        expect(
          (
            await app.inject({
              method: "GET",
              url: "/v1/policies/analyst",
              headers: asAuditor,
            })
          ).json().objectRules.allowedObjects,
        ).toEqual(["patients"]);
      });

      it("keeps exactly one published version", async () => {
        await draft(POLICY);
        await draft({ ...POLICY, description: "v2" });
        await app.inject({
          method: "POST",
          url: "/v1/policies/analyst/versions/1/publish",
          headers: asAdmin,
        });
        await app.inject({
          method: "POST",
          url: "/v1/policies/analyst/versions/2/publish",
          headers: asAdmin,
        });

        const versions = (
          await app.inject({
            method: "GET",
            url: "/v1/policies/analyst/versions",
            headers: asAuditor,
          })
        ).json().versions as Array<{ versionNo: number; state: string }>;

        expect(versions.filter((v) => v.state === "published")).toHaveLength(1);
        expect(versions.find((v) => v.state === "published")!.versionNo).toBe(2);
        expect(versions.find((v) => v.versionNo === 1)!.state).toBe("superseded");
      });

      it("validates a draft as a full document", async () => {
        // Validating only at publish time means the error arrives when someone is
        // trying to ship.
        const response = await draft({ name: "half-written" });
        expect(response.statusCode).toBe(422);
      });

      it("404s publishing or rolling back a version that does not exist", async () => {
        await put();
        for (const action of ["publish", "rollback"]) {
          const response = await app.inject({
            method: "POST",
            url: `/v1/policies/analyst/versions/99/${action}`,
            headers: asAdmin,
          });
          expect(response.statusCode).toBe(404);
        }
      });

      it("400s a non-numeric version", async () => {
        const response = await app.inject({
          method: "POST",
          url: "/v1/policies/analyst/versions/abc/publish",
          headers: asAdmin,
        });
        expect(response.statusCode).toBe(400);
      });
    });

    // -- Assignments -------------------------------------------------------

    describe("assignments", () => {
      const ASSIGNMENT = {
        version: "1.0",
        policyName: "analyst",
        assignee: { type: "user", identifier: "alice" },
        scope: { tenantId: "t1" },
        active: true,
        audit: {
          grantedBy: "admin",
          grantedAt: "2026-01-01T00:00:00Z",
          reason: "test",
        },
      };

      it("creates, lists and revokes", async () => {
        await put();
        expect(
          (
            await app.inject({
              method: "POST",
              url: "/v1/assignments",
              headers: asAdmin,
              payload: ASSIGNMENT,
            })
          ).statusCode,
        ).toBe(201);

        expect(
          (
            await app.inject({
              method: "GET",
              url: "/v1/assignments",
              headers: asAuditor,
            })
          ).json().assignments,
        ).toHaveLength(1);

        expect(
          (
            await app.inject({
              method: "DELETE",
              url: "/v1/assignments?policyName=analyst&assignee=alice",
              headers: asAdmin,
            })
          ).statusCode,
        ).toBe(204);

        // Revoked assignments disappear from the live listing.
        expect(
          (
            await app.inject({
              method: "GET",
              url: "/v1/assignments",
              headers: asAuditor,
            })
          ).json().assignments,
        ).toEqual([]);
      });

      it("refuses an assignment naming a policy that does not exist", async () => {
        // Such a row would sit in the table contributing nothing while appearing,
        // in the UI, to grant access.
        const response = await app.inject({
          method: "POST",
          url: "/v1/assignments",
          headers: asAdmin,
          payload: ASSIGNMENT,
        });
        expect(response.statusCode).toBe(422);
        expect(response.json().error).toContain("does not exist");
      });

      it("rejects a schema-invalid assignment", async () => {
        await put();
        const response = await app.inject({
          method: "POST",
          url: "/v1/assignments",
          headers: asAdmin,
          payload: { version: "1.0", policyName: "analyst" },
        });
        expect(response.statusCode).toBe(422);
      });

      it("400s a revoke missing its parameters", async () => {
        const response = await app.inject({
          method: "DELETE",
          url: "/v1/assignments?policyName=analyst",
          headers: asAdmin,
        });
        expect(response.statusCode).toBe(400);
      });
    });

    // -- Resolve preview ---------------------------------------------------

    describe("resolve preview", () => {
      it("returns the merged policy UNSIGNED", async () => {
        await put();
        await app.inject({
          method: "POST",
          url: "/v1/assignments",
          headers: asAdmin,
          payload: {
            version: "1.0",
            policyName: "analyst",
            assignee: { type: "user", identifier: "alice" },
            scope: { tenantId: "t1" },
            active: true,
            audit: {
              grantedBy: "admin",
              grantedAt: "2026-01-01T00:00:00Z",
              reason: "test",
            },
          },
        });

        const response = await app.inject({
          method: "GET",
          url: "/v1/resolve/preview?userId=alice&tenantId=t1&sourceConnectionId=db:analytics:patients",
          headers: asAuditor,
        });

        expect(response.statusCode).toBe(200);
        const body = response.json();
        expect(body.effectivePolicy.permissions.canQuery).toBe(true);
        expect(body.contributingPolicies).toContain("analyst");

        // No signature anywhere: signing a preview would mint a usable credential
        // on a route an auditor can reach.
        expect(body.signature).toBeUndefined();
        expect(body.effectivePolicy.integrity?.signature).toBeFalsy();
      });

      it("validates its parameters", async () => {
        for (const url of [
          "/v1/resolve/preview",
          "/v1/resolve/preview?userId=a&tenantId=t",
          "/v1/resolve/preview?userId=a&tenantId=t&sourceConnectionId=bogus",
        ]) {
          const response = await app.inject({ method: "GET", url, headers: asAuditor });
          expect(response.statusCode).toBe(400);
        }
      });
    });

    // -- Installs ----------------------------------------------------------

    describe("installs", () => {
      it("issues a credential exactly once", async () => {
        const created = await app.inject({
          method: "POST",
          url: "/v1/installs",
          headers: asAdmin,
          payload: { id: "install-1", name: "worker" },
        });
        expect(created.statusCode).toBe(201);
        const credential = created.json().credential;
        expect(credential).toMatch(/^tolap_ik_install-1\./);

        // The listing must never carry the secret or its hash.
        const listed = await app.inject({
          method: "GET",
          url: "/v1/installs",
          headers: asAuditor,
        });
        const body = listed.body;
        expect(body).not.toContain(credential);
        expect(body).not.toContain("credentialHash");
        expect(body).not.toContain("credential_hash");
      });

      it("refuses a duplicate id", async () => {
        const payload = { id: "install-1", name: "worker" };
        await app.inject({ method: "POST", url: "/v1/installs", headers: asAdmin, payload });
        const second = await app.inject({
          method: "POST",
          url: "/v1/installs",
          headers: asAdmin,
          payload,
        });
        expect(second.statusCode).toBe(409);
      });

      it.each(["Install_1", "in stall", "a", "x".repeat(65), "in:stall", "../etc"])(
        "rejects id '%s'",
        async (id) => {
          const response = await app.inject({
            method: "POST",
            url: "/v1/installs",
            headers: asAdmin,
            payload: { id, name: "worker" },
          });
          expect(response.statusCode).toBe(400);
        },
      );

      it("revokes an install once", async () => {
        await app.inject({
          method: "POST",
          url: "/v1/installs",
          headers: asAdmin,
          payload: { id: "install-1", name: "worker" },
        });
        expect(
          (
            await app.inject({
              method: "DELETE",
              url: "/v1/installs/install-1",
              headers: asAdmin,
            })
          ).statusCode,
        ).toBe(204);
        expect(
          (
            await app.inject({
              method: "DELETE",
              url: "/v1/installs/install-1",
              headers: asAdmin,
            })
          ).statusCode,
        ).toBe(404);
      });
    });

    // -- Catalog -----------------------------------------------------------

    describe("catalog", () => {
      it("stores and reads a manifest", async () => {
        const manifest = {
          sourceConnectionId: "db:analytics:patients",
          objects: [{ name: "patients", fields: ["id", "ssn"] }],
        };
        expect(
          (
            await app.inject({
              method: "PUT",
              url: "/v1/catalog",
              headers: asAdmin,
              payload: manifest,
            })
          ).statusCode,
        ).toBe(200);

        const read = await app.inject({
          method: "GET",
          url: "/v1/catalog/db:analytics:patients",
          headers: asAuditor,
        });
        expect(read.json().objects[0].fields).toEqual(["id", "ssn"]);
      });

      it("imports SQL DDL", async () => {
        const response = await app.inject({
          method: "POST",
          url: "/v1/catalog/import/sql",
          headers: asAdmin,
          payload: {
            sourceConnectionId: "db:analytics:patients",
            ddl: "CREATE TABLE patients (id uuid, ssn text);",
          },
        });
        expect(response.statusCode).toBe(200);
        expect(response.json().objects[0].name).toBe("patients");
      });

      it("imports an OpenAPI spec", async () => {
        const response = await app.inject({
          method: "POST",
          url: "/v1/catalog/import/openapi",
          headers: asAdmin,
          payload: {
            sourceConnectionId: "api:internal:clinical",
            spec: { paths: { "/patients/{id}": { get: { responses: { "200": {} } } } } },
          },
        });
        expect(response.statusCode).toBe(200);
        expect(response.json().endpoints[0].path).toBe("/patients/*");
      });

      it("422s a malformed manifest or import", async () => {
        expect(
          (
            await app.inject({
              method: "PUT",
              url: "/v1/catalog",
              headers: asAdmin,
              payload: { sourceConnectionId: "nonsense" },
            })
          ).statusCode,
        ).toBe(422);

        expect(
          (
            await app.inject({
              method: "POST",
              url: "/v1/catalog/import/sql",
              headers: asAdmin,
              payload: { sourceConnectionId: "db:a:b", ddl: "SELECT 1;" },
            })
          ).statusCode,
        ).toBe(422);
      });

      it("400s an import missing its arguments", async () => {
        expect(
          (
            await app.inject({
              method: "POST",
              url: "/v1/catalog/import/sql",
              headers: asAdmin,
              payload: { sourceConnectionId: "db:a:b" },
            })
          ).statusCode,
        ).toBe(400);
      });

      it("deletes a source", async () => {
        await app.inject({
          method: "PUT",
          url: "/v1/catalog",
          headers: asAdmin,
          payload: { sourceConnectionId: "db:a:b" },
        });
        expect(
          (
            await app.inject({
              method: "DELETE",
              url: "/v1/catalog/db:a:b",
              headers: asAdmin,
            })
          ).statusCode,
        ).toBe(204);
      });
    });

    // -- Audit -------------------------------------------------------------

    describe("audit", () => {
      it("records the Cognito subject as the actor", async () => {
        await put();
        const entries = (
          await app.inject({ method: "GET", url: "/v1/audit", headers: asAuditor })
        ).json().entries as Array<{ actor: string; action: string }>;

        const entry = entries.find((e) => e.action === "definition.put");
        expect(entry).toBeDefined();
        // The stable subject, not the email, which can change.
        expect(entry!.actor).toBe("cognito-sub-admin");
      });

      it("records nothing for a rejected write", async () => {
        await put(POLICY, asAuditor);
        const entries = (
          await app.inject({ method: "GET", url: "/v1/audit", headers: asAuditor })
        ).json().entries as unknown[];
        expect(entries).toEqual([]);
      });
    });

    it("reports the caller's role", async () => {
      const response = await app.inject({
        method: "GET",
        url: "/v1/me",
        headers: asAuditor,
      });
      expect(response.json()).toEqual({
        subject: "cognito-sub-auditor",
        role: "auditor",
      });
    });
  });
});
