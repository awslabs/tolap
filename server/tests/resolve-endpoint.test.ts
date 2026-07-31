/**
 * The resolve endpoint, end to end.
 *
 * Exercised through Fastify's `inject` against a real Postgres schema, so the
 * whole path runs: credential check, resolution, merge, signing, audit write. The
 * final test carries the artifact all the way into Python's enforcement engine,
 * because "the endpoint returned 200" and "a remote install can actually enforce
 * what it received" are different claims.
 */

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { FastifyInstance } from "fastify";
import type { PolicyAssignment, PolicyDefinition } from "@tolap/core";
import { validateContext, validatePolicy } from "@tolap/core";
import { PostgresPolicyStore } from "../src/db/store.ts";
import { Keyring } from "../src/signing/keyring.ts";
import { buildResolveApp } from "../src/routes/resolve.ts";
import { issueCredential } from "../src/auth/install-credential.ts";
import { ADMIN, HAVE_DB, staticIdentity, testDb, type TestDb } from "./helpers/db.ts";

const KEY = "resolve-endpoint-test-key-not-for-production";
const SOURCE = "db:analytics:patients";
const REPO = path.resolve(__dirname, "../..");

const POLICY = {
  version: "1.0",
  name: "analyst",
  permissions: { canQuery: true, readOnly: true },
  objectRules: {
    allowedObjects: ["patients"],
    fieldRules: { hiddenFields: ["ssn"] },
    rowFilters: [{ field: "region", operator: "equals", value: "us-east" }],
  },
  limits: { maxResults: 2 },
} as unknown as PolicyDefinition;

const ASSIGNMENT = {
  version: "1.0",
  policyName: "analyst",
  assignee: { type: "user", identifier: "alice" },
  scope: { tenantId: "t1" },
  active: true,
  audit: { grantedBy: "admin-1", grantedAt: "2026-01-01T00:00:00Z", reason: "test" },
} as unknown as PolicyAssignment;

function havePython(): boolean {
  try {
    execFileSync("which", ["python3"], { stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
}

describe("GET /v1/resolve", () => {
  it("guard: the skip condition is a real boolean", () => {
    expect(typeof HAVE_DB).toBe("boolean");
  });

  describe.skipIf(!HAVE_DB)("against PostgreSQL", () => {
    let db: TestDb;
    let store: PostgresPolicyStore;
    let app: FastifyInstance;
    let secret: string;

    const url = (
      params: Record<string, string> = {},
    ): string => {
      const query = new URLSearchParams({
        userId: "alice",
        tenantId: "t1",
        sourceConnectionId: SOURCE,
        ...params,
      });
      return `/v1/resolve?${query.toString()}`;
    };

    beforeAll(async () => {
      db = await testDb("resolve_endpoint");
    });

    afterAll(async () => {
      await app?.close();
      await db?.close();
    });

    beforeEach(async () => {
      await db.reset();
      store = new PostgresPolicyStore(
        db.pool,
        staticIdentity({ alice: ["analysts"] }),
      );
      await store.putDefinitionAs(POLICY, ADMIN);
      await store.putAssignmentAs(ASSIGNMENT, ADMIN);

      const issued = issueCredential("install-1");
      secret = issued.secret;
      await store.createInstall("install-1", "test install", issued.hash, ADMIN);

      await app?.close();
      app = buildResolveApp({ store, keyring: new Keyring([{ kid: "test-key", secret: KEY }], "test-key"), ttlSeconds: 900 });
    });

    const auth = () => ({ authorization: `Bearer ${secret}` });

    it("returns a signed artifact both verification paths accept", async () => {
      const response = await app.inject({ method: "GET", url: url(), headers: auth() });

      expect(response.statusCode).toBe(200);
      const artifact = response.json();

      // Both signatures, because Python/.NET verify the envelope and TypeScript
      // verifies the bare policy.
      expect(validateContext(artifact, KEY)).toBe(true);
      expect(validatePolicy(artifact.effectivePolicy, KEY)).toBe(true);

      expect(artifact.effectivePolicy.sourceConnectionId).toBe(SOURCE);
      expect(artifact.effectivePolicy.permissions.canQuery).toBe(true);
      expect(artifact.issuedAt).toBe(artifact.resolvedAt);
    });

    it("honors the configured TTL", async () => {
      const shortLived = buildResolveApp({
        store,
        keyring: new Keyring([{ kid: "test-key", secret: KEY }], "test-key"),
        ttlSeconds: 60,
      });
      try {
        const response = await shortLived.inject({
          method: "GET",
          url: url(),
          headers: auth(),
        });
        const artifact = response.json();
        const lifetime =
          new Date(artifact.expiresAt).getTime() -
          new Date(artifact.issuedAt).getTime();
        expect(lifetime).toBe(60_000);
      } finally {
        await shortLived.close();
      }
    });

    it("forbids caching of the artifact", async () => {
      // The artifact is a bearer credential until it expires; a cache holding it
      // widens the replay window past the expiry the server chose.
      const response = await app.inject({ method: "GET", url: url(), headers: auth() });
      expect(response.headers["cache-control"]).toBe("no-store");
    });

    it("returns a deny-all policy when nothing is assigned", async () => {
      const response = await app.inject({
        method: "GET",
        url: url({ userId: "stranger" }),
        headers: auth(),
      });

      // Not a 404: "no policy" is a legitimate answer meaning "grants nothing",
      // and it is still signed so the install can tell it apart from a forgery.
      expect(response.statusCode).toBe(200);
      const artifact = response.json();
      expect(artifact.effectivePolicy.permissions.canQuery).toBe(false);
      expect(validateContext(artifact, KEY)).toBe(true);
    });

    it("resolves per source, not per user", async () => {
      // The policy's allowedObjects are scoped to a db source; asking for an
      // unrelated api source must not return the db rules.
      const response = await app.inject({
        method: "GET",
        url: url({ sourceConnectionId: "api:internal:billing" }),
        headers: auth(),
      });
      expect(response.statusCode).toBe(200);
      expect(response.json().effectivePolicy.sourceConnectionId).toBe(
        "api:internal:billing",
      );
    });

    describe("authentication", () => {
      it("rejects a request with no credential", async () => {
        const response = await app.inject({ method: "GET", url: url() });
        expect(response.statusCode).toBe(401);
      });

      it("rejects a malformed credential", async () => {
        const response = await app.inject({
          method: "GET",
          url: url(),
          headers: { authorization: "Bearer nonsense" },
        });
        expect(response.statusCode).toBe(401);
      });

      it("rejects a credential for an unknown install", async () => {
        const response = await app.inject({
          method: "GET",
          url: url(),
          headers: { authorization: `Bearer ${issueCredential("ghost").secret}` },
        });
        expect(response.statusCode).toBe(401);
      });

      it("rejects a revoked install", async () => {
        await store.revokeInstall("install-1", ADMIN);
        const response = await app.inject({
          method: "GET",
          url: url(),
          headers: auth(),
        });
        // Revocation denies rather than merely being recorded.
        expect(response.statusCode).toBe(401);
      });

      it("does not reveal which stage failed", async () => {
        const bodies = new Set<string>();
        for (const header of [
          { authorization: "Bearer nonsense" },
          { authorization: `Bearer ${issueCredential("ghost").secret}` },
          { authorization: "Basic abc" },
        ]) {
          const response = await app.inject({
            method: "GET",
            url: url(),
            headers: header,
          });
          bodies.add(response.body);
        }
        expect(bodies.size).toBe(1);
      });

      it("authenticates before validating parameters", async () => {
        // An unauthenticated caller must not learn which parameters the endpoint
        // wants, so the credential check comes first.
        const response = await app.inject({
          method: "GET",
          url: "/v1/resolve",
        });
        expect(response.statusCode).toBe(401);
      });
    });

    describe("request validation", () => {
      it.each(["userId", "tenantId", "sourceConnectionId"])(
        "rejects a missing %s",
        async (param) => {
          const query = new URLSearchParams({
            userId: "alice",
            tenantId: "t1",
            sourceConnectionId: SOURCE,
          });
          query.delete(param);
          const response = await app.inject({
            method: "GET",
            url: `/v1/resolve?${query.toString()}`,
            headers: auth(),
          });
          expect(response.statusCode).toBe(400);
          expect(response.json().error).toContain(param);
        },
      );

      it("rejects a blank parameter", async () => {
        const response = await app.inject({
          method: "GET",
          url: url({ userId: "   " }),
          headers: auth(),
        });
        expect(response.statusCode).toBe(400);
      });

      it.each([
        "not-three-parts",
        "db:only-two",
        "db:a:b:c",
        "bogus:a:b",
        "db::name",
      ])("rejects sourceConnectionId '%s'", async (bad) => {
        const response = await app.inject({
          method: "GET",
          url: url({ sourceConnectionId: bad }),
          headers: auth(),
        });
        expect(response.statusCode).toBe(400);
      });

      it.each(["db:a:b", "api:internal:x", "kb:corp:docs", "storage:data:bucket"])(
        "accepts category '%s'",
        async (good) => {
          const response = await app.inject({
            method: "GET",
            url: url({ sourceConnectionId: good }),
            headers: auth(),
          });
          expect(response.statusCode).toBe(200);
        },
      );
    });

    describe("audit", () => {
      it("records which install resolved what", async () => {
        await app.inject({ method: "GET", url: url(), headers: auth() });

        const audit = await store.listAudit();
        const entry = audit.find(
          (e) => e.action === "policy.resolve" && e.actorKind === "install",
        );
        expect(entry).toBeDefined();
        expect(entry!.actor).toBe("install-1");
        expect(entry!.targetId).toBe(SOURCE);
        expect((entry!.detail as { userId: string }).userId).toBe("alice");
      });

      it("updates the install's last-seen timestamp", async () => {
        const before = (await store.listInstalls())[0].lastSeenAt;
        expect(before).toBeNull();

        await app.inject({ method: "GET", url: url(), headers: auth() });

        expect((await store.listInstalls())[0].lastSeenAt).not.toBeNull();
      });

      it("does not record an audit row for a rejected request", async () => {
        await app.inject({
          method: "GET",
          url: url(),
          headers: { authorization: "Bearer nonsense" },
        });
        const audit = await store.listAudit();
        expect(audit.filter((e) => e.action === "policy.resolve")).toEqual([]);
      });
    });

    it("serves a health check without a credential", async () => {
      const response = await app.inject({ method: "GET", url: "/health" });
      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({ status: "ok" });
    });

    it.skipIf(!havePython())(
      "Python enforces the artifact this endpoint returned",
      async () => {
        const response = await app.inject({
          method: "GET",
          url: url(),
          headers: auth(),
        });
        const encoded = Buffer.from(response.body, "utf8").toString("base64");

        const dir = mkdtempSync(path.join(tmpdir(), "tolap-resolve-"));
        try {
          const file = path.join(dir, "artifact.b64");
          writeFileSync(file, encoded, "utf8");

          const script = `
import base64, json, sys
sys.path.insert(0, ${JSON.stringify(path.join(REPO, "sdk/python/tolap-core"))})
sys.path.insert(0, ${JSON.stringify(path.join(REPO, "sdk/python/tolap-mcp"))})
from tolap_core.context import deserialize_context
from tolap_mcp.wrapper import SecureMcpToolWrapper
from tolap_mcp.options import SecureMcpServerOptions

ctx = deserialize_context(open(sys.argv[1]).read().strip(), ${JSON.stringify(KEY)})
rows = [
    {"id": 1, "region": "us-east", "ssn": "111-22-3333"},
    {"id": 2, "region": "us-east", "ssn": "222-33-4444"},
    {"id": 3, "region": "us-east", "ssn": "333-44-5555"},
    {"id": 4, "region": "eu-west", "ssn": "444-55-6666"},
]
w = SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=${JSON.stringify(KEY)}))
out = w.execute_with_enforcement(
    context=ctx, tool_name="q", tool_fn=lambda table: list(rows),
    tool_args={"table": "patients"}, object_name="patients")
print(json.dumps(out))
`;
          const stdout = execFileSync("python3", ["-c", script, file], {
            encoding: "utf8",
            stdio: ["pipe", "pipe", "pipe"],
          });
          const enforced = JSON.parse(stdout.trim()) as Array<
            Record<string, unknown>
          >;

          // The policy came out of Postgres, was merged by the SDK, signed by the
          // server, shipped over HTTP, and enforced by a different language --
          // and every rule still bit: the row filter and limit cut 4 rows to 2,
          // and the hidden field is gone.
          expect(enforced).toHaveLength(2);
          for (const row of enforced) {
            expect(row).not.toHaveProperty("ssn");
            expect(row.region).toBe("us-east");
          }
        } finally {
          rmSync(dir, { recursive: true, force: true });
        }
      },
    );
  });
});
