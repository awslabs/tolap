/**
 * Malformed `objectRules.toolRules` is refused at write time (matrix rows E1-E8, G2).
 *
 * The SDKs are the second line here, not the first. TypeScript has no deserializer, and
 * the Python and .NET deserializers read a typo'd key such as `{"allowedTool": [...]}` as
 * `toolRules: {}` -- present, so the grammar applies, but restricting nothing the author
 * meant it to. The only place that typo is caught is this server's schema check
 * (`additionalProperties: false`), so each malformed shape is asserted here, one test per
 * row, with the exact status, the exact error list, and a follow-up read proving nothing
 * reached the datastore.
 *
 * Status is 422, not 400. The matrix says "400", but every schema failure on these routes
 * has always been 422 (`admin.ts`, and `admin-endpoint.test.ts` pins it); 400 is reserved
 * for a request the server cannot interpret at all, such as a name that disagrees with
 * the URL. The rows assert the code the server actually sends so a regression to 200 --
 * the failure that matters -- is caught either way.
 *
 * E8 (`toolRules: null`) is rejected here too. The SDKs read a JSON null as absent, but the
 * schema types `toolRules` as an object, exactly like every other `objectRules` member, so
 * a stored policy never carries the null in the first place.
 */

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import type { AdminPrincipal } from "../src/auth/cognito.ts";
import { AdminAuthError } from "../src/auth/cognito.ts";
import { PostgresPolicyStore } from "../src/db/store.ts";
import { Keyring } from "../src/signing/keyring.ts";
import { buildAdminApp } from "../src/routes/admin.ts";
import { validateSchema, type ValidationError } from "../src/validation.ts";
import { HAVE_DB, staticIdentity, testDb, type TestDb } from "./helpers/db.ts";

const NAME_PATTERN = '"^[A-Za-z0-9_.-]{1,128}$"';

interface MalformedRow {
  readonly id: string;
  readonly toolRules: unknown;
  readonly errors: ValidationError[];
}

/** Every E row, with the exact error list the schema produces for it. */
const ROWS: readonly MalformedRow[] = [
  {
    id: "E1",
    toolRules: { allowedTools: "query_patients" },
    errors: [{ path: "/objectRules/toolRules/allowedTools", message: "must be array" }],
  },
  {
    id: "E2",
    toolRules: { allowedTools: [1] },
    errors: [{ path: "/objectRules/toolRules/allowedTools/0", message: "must be string" }],
  },
  {
    id: "E3",
    toolRules: { allowedTool: ["x"] },
    errors: [
      { path: "/objectRules/toolRules", message: "must NOT have additional properties" },
    ],
  },
  {
    id: "E4",
    toolRules: [],
    errors: [{ path: "/objectRules/toolRules", message: "must be object" }],
  },
  {
    id: "E5",
    toolRules: { allowedTools: ["query_patients", "query_patients"] },
    errors: [
      {
        path: "/objectRules/toolRules/allowedTools",
        message: "must NOT have duplicate items (items ## 1 and 0 are identical)",
      },
    ],
  },
  {
    id: "E6",
    toolRules: { hiddenTools: ["export segment"] },
    errors: [
      {
        path: "/objectRules/toolRules/hiddenTools/0",
        message: `must match pattern ${NAME_PATTERN}`,
      },
    ],
  },
  {
    id: "E7",
    toolRules: { hiddenTools: [""] },
    errors: [
      {
        path: "/objectRules/toolRules/hiddenTools/0",
        message: `must match pattern ${NAME_PATTERN}`,
      },
    ],
  },
  {
    id: "E8",
    toolRules: null,
    errors: [{ path: "/objectRules/toolRules", message: "must be object" }],
  },
];

const policyWith = (name: string, toolRules: unknown) => ({
  version: "1.0",
  name,
  permissions: { canQuery: true, readOnly: true },
  objectRules: { allowedObjects: ["patients"], toolRules },
});

const slug = (id: string) => `malformed-${id.toLowerCase()}`;

// -- Schema, no database -----------------------------------------------------

describe("toolRules schema (no database)", () => {
  it("guard: the table covers E1 through E8 exactly once", () => {
    expect(ROWS.map((row) => row.id)).toEqual([
      "E1", "E2", "E3", "E4", "E5", "E6", "E7", "E8",
    ]);
  });

  for (const row of ROWS) {
    it(`${row.id}: rejected as a document with exactly the toolRules error`, () => {
      expect(validateSchema(policyWith(slug(row.id), row.toolRules), "policy-definition")).toEqual({
        valid: false,
        errors: row.errors,
      });
    });

    it(`${row.id}: rejected in fragment mode too, so the console flags it while typing`, () => {
      // Fragment mode relaxes only the top-level `required`; nested constraints must hold.
      expect(
        validateSchema({ objectRules: { toolRules: row.toolRules } }, "policy-definition", {
          fragment: true,
        }),
      ).toEqual({ valid: false, errors: row.errors });
    });
  }

  it("control: the well-formed shapes next to the E rows are accepted", () => {
    // Without this, a schema that rejected every toolRules would pass every row above.
    for (const toolRules of [
      {},
      { allowedTools: [] },
      { hiddenTools: [] },
      { allowedTools: [], hiddenTools: [] },
      { allowedTools: ["query_patients"], hiddenTools: ["export_segment_csv"] },
      { allowedTools: ["tools.query-v2_x", "a".repeat(128)] },
    ]) {
      expect(
        validateSchema(policyWith("well-formed", toolRules), "policy-definition"),
        JSON.stringify(toolRules),
      ).toEqual({ valid: true, errors: [] });
    }
  });
});

// -- The write routes, against PostgreSQL ------------------------------------

const KEY = "tool-rules-write-test-key-not-for-production";

const ADMIN_PRINCIPAL: AdminPrincipal = {
  subject: "cognito-sub-admin",
  email: "admin@example.com",
  role: "admin",
};

const verifier = {
  verify: async (token: string): Promise<AdminPrincipal> => {
    if (token === "admin-token") return ADMIN_PRINCIPAL;
    throw new AdminAuthError("unrecognized test token");
  },
};

const asAdmin = { authorization: "Bearer admin-token" };

/** What was already stored under the name each malformed write targets. */
const EXISTING_TOOL_RULES = {
  allowedTools: ["query_patients"],
  hiddenTools: ["export_segment_csv"],
};

describe("toolRules on the policy write routes", () => {
  it("guard: the skip condition is a real boolean", () => {
    expect(typeof HAVE_DB).toBe("boolean");
  });

  describe.skipIf(!HAVE_DB)("against PostgreSQL", () => {
    let db: TestDb;
    let app: FastifyInstance;

    beforeAll(async () => {
      db = await testDb("tool_rules_write");
    });

    afterAll(async () => {
      await app?.close();
      await db?.close();
    });

    beforeEach(async () => {
      await db.reset();
      await app?.close();
      app = buildAdminApp({
        store: new PostgresPolicyStore(db.pool, staticIdentity()),
        verifier,
        keyring: new Keyring([{ kid: "test-key", secret: KEY }], "test-key"),
        ttlSeconds: 900,
      });
    });

    const put = (body: { name: string }) =>
      app.inject({
        method: "PUT",
        url: `/v1/policies/${body.name}`,
        headers: asAdmin,
        payload: body,
      });

    const draft = (body: { name: string }) =>
      app.inject({
        method: "POST",
        url: `/v1/policies/${body.name}/versions`,
        headers: asAdmin,
        payload: { policy: body, note: "malformed" },
      });

    const get = (name: string) =>
      app.inject({ method: "GET", url: `/v1/policies/${name}`, headers: asAdmin });

    const versions = (name: string) =>
      app.inject({ method: "GET", url: `/v1/policies/${name}/versions`, headers: asAdmin });

    const listNames = async (): Promise<string[]> => {
      const response = await app.inject({
        method: "GET",
        url: "/v1/policies",
        headers: asAdmin,
      });
      return (response.json().policies as Array<{ name: string }>).map((p) => p.name);
    };

    it("control: a well-formed toolRules is stored and read back exactly", async () => {
      // Proves the 422s below are about the shape, not about toolRules being refused
      // outright.
      const body = policyWith("well-formed", { allowedTools: [], hiddenTools: ["kill_switch"] });
      expect((await put(body)).statusCode).toBe(200);

      const read = await get("well-formed");
      expect(read.statusCode).toBe(200);
      expect(read.json().objectRules.toolRules).toEqual({
        allowedTools: [],
        hiddenTools: ["kill_switch"],
      });
    });

    for (const row of ROWS) {
      it(`G2/${row.id}: PUT is refused and nothing is written`, async () => {
        const name = slug(row.id);
        const response = await put(policyWith(name, row.toolRules));

        expect(response.statusCode).toBe(422);
        expect(response.json()).toEqual({ error: "validation failed", errors: row.errors });

        expect((await get(name)).statusCode).toBe(404);
        expect(await listNames()).toEqual([]);
        expect((await versions(name)).json()).toEqual({ versions: [], nextCursor: null });
      });

      it(`G2/${row.id}: PUT over an existing policy is refused and leaves it unchanged`, async () => {
        // The overwrite case: a refusal that still replaced the stored body -- or merged
        // part of it -- would be worse than one that created a new row.
        const name = slug(row.id);
        const original = policyWith(name, EXISTING_TOOL_RULES);
        expect((await put(original)).statusCode).toBe(200);

        const response = await put(policyWith(name, row.toolRules));
        expect(response.statusCode).toBe(422);
        expect(response.json()).toEqual({ error: "validation failed", errors: row.errors });

        const read = await get(name);
        expect(read.statusCode).toBe(200);
        expect(read.json()).toEqual(original);
        expect(await listNames()).toEqual([name]);
      });

      it(`G2/${row.id}: POST of a draft version is refused and no version is written`, async () => {
        const name = slug(row.id);
        const response = await draft(policyWith(name, row.toolRules));

        expect(response.statusCode).toBe(422);
        expect(response.json()).toEqual({ error: "validation failed", errors: row.errors });

        expect((await versions(name)).json()).toEqual({ versions: [], nextCursor: null });
        expect((await get(name)).statusCode).toBe(404);
        expect(await listNames()).toEqual([]);
      });
    }

    it("E3 in particular: the typo key is refused, not stored as an empty toolRules", async () => {
      // Spelled out separately because it is the one the SDKs cannot catch: they read it
      // as `toolRules: {}`. If the server ever stored it, the author's allow-list would be
      // silently dropped and every tool with a well-formed name would pass.
      const name = "typo-allowed-tool";
      const response = await put(policyWith(name, { allowedTool: ["query_patients"] }));
      expect(response.statusCode).toBe(422);
      expect(response.json().errors).toEqual([
        { path: "/objectRules/toolRules", message: "must NOT have additional properties" },
      ]);
      expect((await get(name)).statusCode).toBe(404);
    });
  });
});
