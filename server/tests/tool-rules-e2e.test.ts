/**
 * Tool rules end to end (matrix row G7).
 *
 * One user, two assignments: one policy hides `export_segment_csv`, the other allows
 * exactly `[query_patients, export_segment_csv]`. Resolution intersects the allow-lists and
 * unions the hidden lists, so the merged rule allows only `query_patients`. What is
 * asserted is the decision a real MCP wrapper makes on the artifact this server signs --
 * not the merged JSON -- because "the policy looks right" and "the wrapper refuses the
 * tool" are different claims.
 *
 * Two arms:
 * - **Through the server** (DB-gated): definitions and assignments stored in PostgreSQL,
 *   artifact fetched from `GET /v1/resolve` with an install credential, the same path a
 *   deployed wrapper takes.
 * - **Without a database**: the same SDK `resolve()` the store delegates to, signed with
 *   the server's own `buildSignedArtifact`, so the property is still checked on a machine
 *   with no PostgreSQL.
 *
 * The wrapper is imported from the TypeScript MCP package's source, the way these tests
 * already take the core package from source (see the aliases in `vitest.config.ts`).
 */

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import {
  resolve,
  type EffectivePolicy,
  type PolicyAssignment,
  type PolicyDefinition,
  type SecurityContext,
} from "@aws/tolap-core";
import { SecureContextToolWrapper } from "../../sdk/typescript/packages/mcp/src/context-wrapper.ts";
import { PostgresPolicyStore } from "../src/db/store.ts";
import { Keyring } from "../src/signing/keyring.ts";
import { buildSignedArtifact } from "../src/signing/artifact.ts";
import { buildResolveApp } from "../src/routes/resolve.ts";
import { issueCredential } from "../src/auth/install-credential.ts";
import { ADMIN, HAVE_DB, staticIdentity, testDb, type TestDb } from "./helpers/db.ts";

const KEY = "tool-rules-e2e-test-key-not-for-production";
const SOURCE = "db:analytics:patients";

const HIDES_EXPORT = {
  version: "1.0",
  name: "hides-export",
  permissions: { canQuery: true, readOnly: true },
  objectRules: { toolRules: { hiddenTools: ["export_segment_csv"] } },
} as unknown as PolicyDefinition;

const ALLOWS_BOTH = {
  version: "1.0",
  name: "allows-query-and-export",
  permissions: { canQuery: true, readOnly: true },
  objectRules: {
    toolRules: { allowedTools: ["query_patients", "export_segment_csv"] },
  },
} as unknown as PolicyDefinition;

const assignment = (policyName: string): PolicyAssignment =>
  ({
    version: "1.0",
    policyName,
    assignee: { type: "user", identifier: "alice" },
    scope: { tenantId: "t1" },
    active: true,
    audit: { grantedBy: "admin-1", grantedAt: "2026-01-01T00:00:00Z", reason: "test" },
  }) as unknown as PolicyAssignment;

const ASSIGNMENTS = [assignment(HIDES_EXPORT.name), assignment(ALLOWS_BOTH.name)];

/** The G7 assertions, applied to whatever signed artifact an arm produced. */
function assertToolDecisions(artifact: unknown): void {
  const context = artifact as SecurityContext;
  const policy = (artifact as { effectivePolicy: EffectivePolicy }).effectivePolicy;

  // Both assignments contributed: the allow-list is B's, the hidden list is A's.
  expect(policy.objectRules?.toolRules).toEqual({
    allowedTools: ["query_patients", "export_segment_csv"],
    hiddenTools: ["export_segment_csv"],
  });

  const wrapper = new SecureContextToolWrapper({ signingKey: KEY });

  // Allowed by B, hidden by A: hidden wins, with the hidden reason, not the allowed one.
  expect(wrapper.preExecute(context, { toolName: "export_segment_csv" })).toEqual({
    allowed: false,
    reason: "tool is hidden",
  });
  // Mis-cased: still hidden (hiddenTools folds ASCII case).
  expect(wrapper.preExecute(context, { toolName: "Export_Segment_CSV" })).toEqual({
    allowed: false,
    reason: "tool is hidden",
  });
  expect(wrapper.preExecute(context, { toolName: "query_patients" })).toEqual({
    allowed: true,
  });
  // Not in B's allow-list: A's absent allow-list does not widen it.
  expect(wrapper.preExecute(context, { toolName: "list_cohorts" })).toEqual({
    allowed: false,
    reason: "tool not in allowed set",
  });

  expect(wrapper.filterTools(context, ["query_patients", "export_segment_csv"])).toEqual([
    "query_patients",
  ]);
  expect(
    wrapper.filterTools(context, [
      "export_segment_csv",
      "list_cohorts",
      "query_patients",
      "query_patients ",
    ]),
  ).toEqual(["query_patients"]);
}

/** Tampering with the signed tool rules must fail closed in both entry points. */
function assertTamperFailsClosed(artifact: unknown): void {
  const tampered = structuredClone(artifact) as {
    effectivePolicy: EffectivePolicy;
    policies: EffectivePolicy[];
  };
  // Lift the hide in both places a consumer might read it from.
  for (const policy of [tampered.effectivePolicy, ...tampered.policies]) {
    policy.objectRules!.toolRules!.hiddenTools = [];
  }
  const context = tampered as unknown as SecurityContext;
  const wrapper = new SecureContextToolWrapper({ signingKey: KEY });

  expect(wrapper.preExecute(context, { toolName: "export_segment_csv" })).toEqual({
    allowed: false,
    reason: "invalid signature",
  });
  expect(wrapper.filterTools(context, ["query_patients", "export_segment_csv"])).toEqual([]);
}

describe("G7: tool rules from two assignments, resolved, signed, enforced", () => {
  describe("without a database", () => {
    const artifact = async () => {
      const policy = await resolve(
        "alice",
        "t1",
        SOURCE,
        structuredClone(ASSIGNMENTS),
        new Map([
          [HIDES_EXPORT.name, structuredClone(HIDES_EXPORT)],
          [ALLOWS_BOTH.name, structuredClone(ALLOWS_BOTH)],
        ]),
      );
      return JSON.parse(
        JSON.stringify(buildSignedArtifact(policy, { kid: "test-key", secret: KEY }, 900_000)),
      ) as unknown;
    };

    it("export_segment_csv is hidden, query_patients is allowed, filterTools keeps only query_patients", async () => {
      assertToolDecisions(await artifact());
    });

    it("the same artifact with the hide lifted fails 'invalid signature' and lists no tools", async () => {
      assertTamperFailsClosed(await artifact());
    });

    it("control: either assignment alone decides differently", async () => {
      // Guards against the merged assertions passing because one policy was ignored.
      const wrapper = new SecureContextToolWrapper({ signingKey: KEY });
      for (const [definition, expected] of [
        [HIDES_EXPORT, ["query_patients", "list_cohorts"]],
        [ALLOWS_BOTH, ["query_patients", "export_segment_csv"]],
      ] as const) {
        const policy = await resolve(
          "alice",
          "t1",
          SOURCE,
          [assignment(definition.name)],
          new Map([[definition.name, structuredClone(definition)]]),
        );
        const signed = buildSignedArtifact(policy, { kid: "test-key", secret: KEY }, 900_000);
        expect(
          wrapper.filterTools(signed as unknown as SecurityContext, [
            "query_patients",
            "export_segment_csv",
            "list_cohorts",
          ]),
          definition.name,
        ).toEqual(expected);
      }
    });
  });

  it("guard: the skip condition is a real boolean", () => {
    expect(typeof HAVE_DB).toBe("boolean");
  });

  describe.skipIf(!HAVE_DB)("through the policy server, against PostgreSQL", () => {
    let db: TestDb;
    let app: FastifyInstance;
    let secret: string;

    beforeAll(async () => {
      db = await testDb("tool_rules_e2e");
    });

    afterAll(async () => {
      await app?.close();
      await db?.close();
    });

    beforeEach(async () => {
      await db.reset();
      const store = new PostgresPolicyStore(db.pool, staticIdentity());
      await store.putDefinitionAs(HIDES_EXPORT, ADMIN);
      await store.putDefinitionAs(ALLOWS_BOTH, ADMIN);
      for (const a of ASSIGNMENTS) await store.putAssignmentAs(a, ADMIN);

      const issued = issueCredential("install-1");
      secret = issued.secret;
      await store.createInstall("install-1", "tool rules e2e", issued.hash, ADMIN);

      await app?.close();
      app = buildResolveApp({
        store,
        keyring: new Keyring([{ kid: "test-key", secret: KEY }], "test-key"),
        ttlSeconds: 900,
      });
    });

    const fetchArtifact = async (): Promise<unknown> => {
      const query = new URLSearchParams({
        userId: "alice",
        tenantId: "t1",
        sourceConnectionId: SOURCE,
      });
      const response = await app.inject({
        method: "GET",
        url: `/v1/resolve?${query.toString()}`,
        headers: { authorization: `Bearer ${secret}` },
      });
      expect(response.statusCode).toBe(200);
      return response.json();
    };

    it("export_segment_csv is hidden, query_patients is allowed, filterTools keeps only query_patients", async () => {
      assertToolDecisions(await fetchArtifact());
    });

    it("the served artifact with the hide lifted fails 'invalid signature' and lists no tools", async () => {
      assertTamperFailsClosed(await fetchArtifact());
    });
  });
});
