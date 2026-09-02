/**
 * `GET /v1/resolve` with a declared purpose (canonical-enforcement-spec §15.1).
 *
 * Separate from `resolve-endpoint.test.ts` because the interesting cases here are about a
 * *parameter* changing which policies resolve, rather than about the endpoint's plumbing.
 *
 * The claim worth testing is not "the parameter is accepted" but "the parameter changes the
 * access". Every case therefore asserts the resolved policy's contents — whether the scoped
 * policy's rules are present — rather than only a status code. A purpose parameter that were
 * quietly dropped would still return 200 with a perfectly valid signed artifact granting the
 * wrong thing, which is exactly the failure a status-code assertion cannot see.
 */

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import path from "node:path";
import type { FastifyInstance } from "fastify";
import type { PolicyAssignment, PolicyDefinition } from "@aws/tolap-core";
import { validateContext } from "@aws/tolap-core";
import { PostgresPolicyStore } from "../src/db/store.ts";
import { Keyring } from "../src/signing/keyring.ts";
import { buildResolveApp } from "../src/routes/resolve.ts";
import { buildAdminApp } from "../src/routes/admin.ts";
import { AdminAuthError, type AdminPrincipal } from "../src/auth/cognito.ts";
import { issueCredential } from "../src/auth/install-credential.ts";
import { ADMIN, HAVE_DB, staticIdentity, testDb, type TestDb } from "./helpers/db.ts";

const KEY = "resolve-purpose-test-key-not-for-production";
const SOURCE = "db:marketing:customer_segments";
const REPO = path.resolve(__dirname, "../..");

/** The shared fixtures, so the server is held to the same policies as the three SDKs. */
function fixture<T>(relative: string): T {
  return JSON.parse(readFileSync(path.join(REPO, "fixtures", relative), "utf-8")) as T;
}

const SCOPED = fixture<PolicyDefinition>("policies/purpose-campaign-overlap.json");
const FRAUD = fixture<PolicyDefinition>("policies/purpose-fraud-detection.json");
const AGNOSTIC = fixture<PolicyDefinition>("policies/purpose-agnostic-baseline.json");

const SCOPED_ASSIGNMENT = fixture<PolicyAssignment>("assignments/purpose-campaign-overlap.json");
const FRAUD_ASSIGNMENT = fixture<PolicyAssignment>("assignments/purpose-fraud-detection.json");
const AGNOSTIC_ASSIGNMENT = fixture<PolicyAssignment>("assignments/purpose-agnostic-baseline.json");

const USER = SCOPED_ASSIGNMENT.assignee.identifier;
const TENANT = SCOPED_ASSIGNMENT.scope.tenantId!;
const PURPOSE = "campaign-x-overlap";

describe("GET /v1/resolve with a declared purpose", () => {
  it("guard: the skip condition is a real boolean", () => {
    expect(typeof HAVE_DB).toBe("boolean");
  });

  it("the endpoint's purposeId pattern matches the published schema", () => {
    // The server restates the pattern rather than loading the schema, because that port is
    // deliberately small and has no schema loader. This is what keeps the copy honest: if the
    // schema's pattern changed, the endpoints would start accepting or rejecting purposes the
    // rest of the system disagrees with, and nothing else would notice.
    //
    // Read from `purpose-query.ts` rather than from a route, because both `GET /v1/resolve`
    // and `GET /v1/resolve/preview` now share it. That is the point of the module: the two
    // routes disagreeing about purposes is the bug that created it.
    const schema = JSON.parse(
      readFileSync(path.join(REPO, "schema/v1.0/policy-definition.schema.json"), "utf-8"),
    ) as {
      properties: {
        purposeProfile: {
          properties: { purposeId: { pattern: string; maxLength: number } };
        };
      };
    };
    const declared = schema.properties.purposeProfile.properties.purposeId;

    const shared = readFileSync(
      path.join(REPO, "server/src/routes/purpose-query.ts"),
      "utf-8",
    );

    expect(shared).toContain(declared.pattern);
    expect(shared).toContain(`PURPOSE_ID_MAX_LENGTH = ${declared.maxLength}`);

    // And both routes actually go through it, so the parity check above is not verifying a
    // module nobody calls -- the exact failure mode that made the preview gap possible.
    for (const route of ["resolve.ts", "admin.ts"]) {
      expect(
        readFileSync(path.join(REPO, "server/src/routes", route), "utf-8"),
      ).toContain("normalizeDeclaredPurpose");
    }
  });

  it("the fixtures are what these tests assume", () => {
    // Guards every case below: if the scoped fixture lost its profile, the filtering
    // assertions would pass against a policy set that no longer exercises filtering.
    expect(SCOPED.purposeProfile?.purposeId).toBe(PURPOSE);
    expect(FRAUD.purposeProfile?.purposeId).toBe("fraud-detection");
    expect(AGNOSTIC.purposeProfile).toBeUndefined();
  });

  describe.skipIf(!HAVE_DB)("against PostgreSQL", () => {
    let db: TestDb;
    let store: PostgresPolicyStore;
    let app: FastifyInstance;
    let secret: string;

    const url = (params: Record<string, string> = {}): string => {
      const query = new URLSearchParams({
        userId: USER,
        tenantId: TENANT,
        sourceConnectionId: SOURCE,
        ...params,
      });
      return `/v1/resolve?${query.toString()}`;
    };

    beforeAll(async () => {
      db = await testDb("resolve_purpose");
    });

    afterAll(async () => {
      await app?.close();
      await db?.close();
    });

    beforeEach(async () => {
      await db.reset();
      store = new PostgresPolicyStore(db.pool, staticIdentity({ [USER]: [] }));

      for (const definition of [SCOPED, FRAUD, AGNOSTIC]) {
        await store.putDefinitionAs(definition, ADMIN);
      }
      for (const assignment of [SCOPED_ASSIGNMENT, FRAUD_ASSIGNMENT, AGNOSTIC_ASSIGNMENT]) {
        await store.putAssignmentAs(assignment, ADMIN);
      }

      const issued = issueCredential("install-1");
      secret = issued.secret;
      await store.createInstall("install-1", "test install", issued.hash, ADMIN);

      await app?.close();
      app = buildResolveApp({
        store,
        keyring: new Keyring([{ kid: "test-key", secret: KEY }], "test-key"),
        ttlSeconds: 900,
      });
    });

    const auth = () => ({ authorization: `Bearer ${secret}` });

    it("400s a repeated declaredPurpose instead of 500ing", async () => {
      // The querystring schema on this route was added to turn a repeated key into a 400,
      // and a comment said it did -- but a validation error reaches `setErrorHandler`, which
      // had no branch for it and fell through to the catch-all. So the schema rejected the
      // request correctly and the response blamed the server. Asserted on the status code,
      // because that is the thing the comment got wrong.
      const response = await app.inject({
        method: "GET",
        url:
          `/v1/resolve?userId=${USER}&tenantId=${TENANT}` +
          `&sourceConnectionId=${SOURCE}&declaredPurpose=a&declaredPurpose=b`,
        headers: auth(),
      });

      expect(response.statusCode).toBe(400);
      expect(response.json().error).toContain("malformed query parameters");
    });

    it("400s an unknown query parameter, rather than ignoring it", async () => {
      // `additionalProperties: false` on the schema. A typo'd `declaredPurposes` silently
      // ignored would resolve without a purpose -- deny-all here -- and look like a working
      // request that granted nothing.
      const response = await app.inject({
        method: "GET",
        url: url({ declaredPurposes: PURPOSE }),
        headers: auth(),
      });

      expect(response.statusCode).toBe(400);
    });

    it("without a purpose, resolves only the purpose-agnostic policy", async () => {
      const response = await app.inject({ method: "GET", url: url(), headers: auth() });

      expect(response.statusCode).toBe(200);
      const policy = response.json().effectivePolicy;

      expect(policy.sourceProfiles).toEqual(["marketing-baseline"]);
      expect(policy.purposeProfile).toBeUndefined();

      // The scoped policy's rules must not have leaked in. Asserting the profile is absent is
      // not enough: the rules could have merged while the profile was dropped, which is what
      // filtering-after-merge produces.
      expect(policy.limits.maxResults).toBe(2000);
    });

    it("with a matching purpose, resolves the scoped policy too", async () => {
      const response = await app.inject({
        method: "GET",
        url: url({ declaredPurpose: PURPOSE }),
        headers: auth(),
      });

      expect(response.statusCode).toBe(200);
      const artifact = response.json();
      const policy = artifact.effectivePolicy;

      expect(policy.sourceProfiles).toEqual(
        expect.arrayContaining(["campaign-x-overlap-agent", "marketing-baseline"]),
      );
      expect(policy.purposeProfile.purposeId).toBe(PURPOSE);
      expect(policy.purposeProfile.prohibitedActions).toContain("export_pii");

      // Still a properly signed artifact: the purpose rides inside the signed policy, so a
      // signing path that mishandled it would fail here rather than at the consumer.
      expect(validateContext(artifact, KEY)).toBe(true);
    });

    it("with a non-matching purpose, excludes the other scoped policy", async () => {
      const response = await app.inject({
        method: "GET",
        url: url({ declaredPurpose: PURPOSE }),
        headers: auth(),
      });

      const policy = response.json().effectivePolicy;

      // The fraud policy permits enumerate_individuals, which this purpose forbids, and caps
      // results at 500. Either appearing would mean it merged.
      expect(policy.sourceProfiles).not.toContain("fraud-detection-agent");
      expect(policy.purposeProfile.allowedActions).not.toContain("inspect_account");
    });

    it("with the other purpose, resolves the other scoped policy", async () => {
      // The paired control. Without it, a filter that dropped every scoped policy but the
      // first would satisfy the case above.
      const response = await app.inject({
        method: "GET",
        url: url({ declaredPurpose: "fraud-detection" }),
        headers: auth(),
      });

      const policy = response.json().effectivePolicy;

      expect(policy.sourceProfiles).toContain("fraud-detection-agent");
      expect(policy.sourceProfiles).not.toContain("campaign-x-overlap-agent");
      expect(policy.purposeProfile.purposeId).toBe("fraud-detection");
    });

    it("purpose matching is case-sensitive", async () => {
      const response = await app.inject({
        method: "GET",
        url: url({ declaredPurpose: "Campaign-X-Overlap" }),
        headers: auth(),
      });

      // 400, not a silent miss: the schema forbids uppercase, so this cannot be a purpose any
      // policy declares, and saying so beats resolving deny-all and letting the caller guess.
      expect(response.statusCode).toBe(400);
      expect(response.json().error).toContain("declaredPurpose");
    });

    it("an empty purpose is treated as absent rather than rejected", async () => {
      // "" and omitted must not behave as two different declarations, matching how the SDKs
      // normalize it for the signature.
      const response = await app.inject({
        method: "GET",
        url: url({ declaredPurpose: "" }),
        headers: auth(),
      });

      expect(response.statusCode).toBe(200);
      expect(response.json().effectivePolicy.sourceProfiles).toEqual(["marketing-baseline"]);
    });

    it.each([
      ["-leading-hyphen", "a leading hyphen"],
      ["trailing-hyphen-", "a trailing hyphen"],
      ["has space", "a space"],
      ["UPPER", "uppercase"],
      ["under_score", "an underscore"],
      ["a".repeat(129), "an over-length value"],
    ])("rejects %s rather than ignoring it (%s)", async (value) => {
      // Rejected rather than ignored, on the same reasoning as the required-parameter check:
      // ignoring it resolves without a purpose, which for a purpose-scoped policy set means
      // deny-all -- a request that looks like it worked and simply granted nothing.
      const response = await app.inject({
        method: "GET",
        url: url({ declaredPurpose: value }),
        headers: auth(),
      });

      expect(response.statusCode).toBe(400);
    });

    it("records the declared purpose in the audit trail", async () => {
      // Two grants for the same user and source under different purposes are different
      // grants. An incident review that cannot tell them apart cannot answer what the agent
      // was permitted to do.
      await app.inject({
        method: "GET",
        url: url({ declaredPurpose: PURPOSE }),
        headers: auth(),
      });

      const { rows } = await db.pool.query(
        "SELECT detail FROM tolap_audit WHERE action = 'policy.resolve' ORDER BY id DESC LIMIT 1",
      );

      expect(rows).toHaveLength(1);
      expect(rows[0].detail.declaredPurpose).toBe(PURPOSE);
      expect(rows[0].detail.purposeId).toBe(PURPOSE);
    });

    it("records a null purpose when none was declared", async () => {
      // The paired control, and the one that makes the field readable: an absent purpose is
      // recorded as null rather than omitted, so a reviewer can tell "no purpose was declared"
      // from "this row predates purpose binding".
      await app.inject({ method: "GET", url: url(), headers: auth() });

      const { rows } = await db.pool.query(
        "SELECT detail FROM tolap_audit WHERE action = 'policy.resolve' ORDER BY id DESC LIMIT 1",
      );

      expect(rows[0].detail.declaredPurpose).toBeNull();
      expect(rows[0].detail.purposeId).toBeNull();
    });

    it("a purpose nothing declares resolves the agnostic policy unchanged", async () => {
      // Declaring a purpose must not restrict a purpose-agnostic policy. Otherwise switching a
      // caller to declare its purpose would silently reduce its access, and integrators would
      // learn to leave the parameter off.
      const response = await app.inject({
        method: "GET",
        url: url({ declaredPurpose: "some-purpose-nothing-declares" }),
        headers: auth(),
      });

      expect(response.statusCode).toBe(200);
      const policy = response.json().effectivePolicy;
      expect(policy.sourceProfiles).toEqual(["marketing-baseline"]);
      expect(policy.permissions.canQuery).toBe(true);
    });
  });
});

// ---------------------------------------------------------------------------
// The preview route resolves for a purpose too
// ---------------------------------------------------------------------------

const AUDITOR: AdminPrincipal = { subject: "cognito-sub-auditor", role: "auditor" };
const ADMIN_PRINCIPAL: AdminPrincipal = {
  subject: "cognito-sub-admin",
  email: "admin@example.com",
  role: "admin",
};

/** Verifier that trusts a token naming a role, so these tests need no real Cognito. */
const previewVerifier = {
  verify: async (token: string): Promise<AdminPrincipal> => {
    if (token === "auditor-token") return AUDITOR;
    if (token === "admin-token") return ADMIN_PRINCIPAL;
    throw new AdminAuthError("unrecognized test token");
  },
};

describe("GET /v1/resolve/preview with a declared purpose", () => {
  it("guard: the skip condition is a real boolean", () => {
    expect(typeof HAVE_DB).toBe("boolean");
  });

  describe.skipIf(!HAVE_DB)("against PostgreSQL", () => {
    let db: TestDb;
    let store: PostgresPolicyStore;
    let app: FastifyInstance;

    const asAuditor = { authorization: "Bearer auditor-token" };

    const url = (params: Record<string, string> = {}): string => {
      const query = new URLSearchParams({
        userId: USER,
        tenantId: TENANT,
        sourceConnectionId: SOURCE,
        ...params,
      });
      return `/v1/resolve/preview?${query.toString()}`;
    };

    beforeAll(async () => {
      db = await testDb("preview_purpose");
    });

    afterAll(async () => {
      await app?.close();
      await db?.close();
    });

    beforeEach(async () => {
      await db.reset();
      store = new PostgresPolicyStore(db.pool, staticIdentity({ [USER]: [] }));

      // The same fixtures as the resolve cases above, so the two routes are held to one
      // policy set. That is what makes the agreement assertion below mean anything.
      for (const definition of [SCOPED, FRAUD, AGNOSTIC]) {
        await store.putDefinitionAs(definition, ADMIN);
      }
      for (const assignment of [SCOPED_ASSIGNMENT, FRAUD_ASSIGNMENT, AGNOSTIC_ASSIGNMENT]) {
        await store.putAssignmentAs(assignment, ADMIN);
      }

      await app?.close();
      app = buildAdminApp({
        store,
        verifier: previewVerifier,
        keyring: new Keyring([{ kid: "test-key", secret: KEY }], "test-key"),
        ttlSeconds: 900,
      });
    });

    it("with a matching purpose, the scoped policy is visible", async () => {
      // The defect: this route took no `declaredPurpose`, so it always resolved as though
      // none was declared -- and a purpose-scoped policy was therefore invisible in the
      // console's own preview. An administrator could author a `purposeProfile` in the
      // editor and then see a preview that did not contain it, which reads as "this policy
      // grants nothing" rather than as "this screen cannot see it".
      const response = await app.inject({
        method: "GET",
        url: url({ declaredPurpose: PURPOSE }),
        headers: asAuditor,
      });

      expect(response.statusCode).toBe(200);
      const body = response.json();
      expect(body.effectivePolicy.purposeProfile?.purposeId).toBe(PURPOSE);
      expect(body.contributingPolicies).toContain(SCOPED.name);
    });

    it("without a purpose, the scoped policy is absent", async () => {
      // The paired control, and the before-state of the bug. Asserted on the *contents*
      // rather than the status, because the broken route returned 200 here too.
      const response = await app.inject({ method: "GET", url: url(), headers: asAuditor });

      expect(response.statusCode).toBe(200);
      const body = response.json();
      expect(body.effectivePolicy.purposeProfile).toBeUndefined();
      expect(body.contributingPolicies).not.toContain(SCOPED.name);
    });

    it("a non-matching purpose does not reach the scoped policy", async () => {
      const response = await app.inject({
        method: "GET",
        url: url({ declaredPurpose: "fraud-detection" }),
        headers: asAuditor,
      });

      expect(response.statusCode).toBe(200);
      const body = response.json();
      expect(body.effectivePolicy.purposeProfile?.purposeId).toBe("fraud-detection");
      expect(body.contributingPolicies).not.toContain(SCOPED.name);
    });

    it("agrees with GET /v1/resolve about what the purpose resolves to", async () => {
      // The property that actually matters: a preview an administrator trusts has to show
      // the policy an agent will really get. Comparing the two routes catches a drift that
      // neither route's own tests would -- each would still be internally consistent.
      const issued = issueCredential("install-preview");
      await store.createInstall("install-preview", "test install", issued.hash, ADMIN);
      const resolveApp = buildResolveApp({
        store,
        keyring: new Keyring([{ kid: "test-key", secret: KEY }], "test-key"),
        ttlSeconds: 900,
      });

      try {
        const query = new URLSearchParams({
          userId: USER,
          tenantId: TENANT,
          sourceConnectionId: SOURCE,
          declaredPurpose: PURPOSE,
        }).toString();

        const preview = await app.inject({
          method: "GET",
          url: `/v1/resolve/preview?${query}`,
          headers: asAuditor,
        });
        const resolved = await resolveApp.inject({
          method: "GET",
          url: `/v1/resolve?${query}`,
          headers: { authorization: `Bearer ${issued.secret}` },
        });

        expect(preview.statusCode).toBe(200);
        expect(resolved.statusCode).toBe(200);

        const previewPolicy = preview.json().effectivePolicy;
        const resolvedPolicy = resolved.json().effectivePolicy;

        // Not a whole-object comparison: `resolvedAt`, `expiresAt` and `integrity` differ by
        // design, since the preview is deliberately unsigned and the two are computed at
        // different instants. The access-bearing fields are what must agree.
        expect(previewPolicy.purposeProfile).toEqual(resolvedPolicy.purposeProfile);
        expect(previewPolicy.permissions).toEqual(resolvedPolicy.permissions);
        expect(previewPolicy.objectRules).toEqual(resolvedPolicy.objectRules);
        expect(previewPolicy.sourceProfiles).toEqual(resolvedPolicy.sourceProfiles);
      } finally {
        await resolveApp.close();
      }
    });

    it("rejects a malformed purpose rather than ignoring it", async () => {
      // Ignoring it would preview without a purpose -- deny-all against this policy set --
      // and show an empty result for a typo. Same 400 and same message as `GET /v1/resolve`,
      // because both come from `normalizeDeclaredPurpose`.
      for (const bad of ["Campaign-X", "campaign_x", "-campaign", "a".repeat(129)]) {
        const response = await app.inject({
          method: "GET",
          url: url({ declaredPurpose: bad }),
          headers: asAuditor,
        });
        expect(response.statusCode, bad).toBe(400);
        expect(response.json().error).toContain("declaredPurpose must be");
      }
    });

    it("treats an empty purpose as absent, not as malformed", async () => {
      // Matching the SDKs' signing normalization: "" and omitted are one declaration.
      const response = await app.inject({
        method: "GET",
        url: url({ declaredPurpose: "" }),
        headers: asAuditor,
      });

      expect(response.statusCode).toBe(200);
      expect(response.json().effectivePolicy.purposeProfile).toBeUndefined();
    });

    it("400s a repeated purpose parameter instead of 500ing", async () => {
      // Without a querystring schema a repeated key arrives as an array and `.trim()` throws
      // a TypeError before any validation runs, which the catch-all turns into a 500. A
      // malformed request is a 400.
      const response = await app.inject({
        method: "GET",
        url:
          `/v1/resolve/preview?userId=${USER}&tenantId=${TENANT}` +
          `&sourceConnectionId=${SOURCE}&declaredPurpose=a&declaredPurpose=b`,
        headers: asAuditor,
      });

      expect(response.statusCode).toBe(400);
    });

    it("is still unsigned when a purpose is declared", async () => {
      // The preview's existing security property must survive the new parameter: signing it
      // would mint a usable purpose-bound credential on a route an auditor can reach.
      const response = await app.inject({
        method: "GET",
        url: url({ declaredPurpose: PURPOSE }),
        headers: asAuditor,
      });

      const body = response.json();
      expect(body.signature).toBeUndefined();
      expect(body.effectivePolicy.integrity?.signature).toBeFalsy();
    });
  });
});
