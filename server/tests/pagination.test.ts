/**
 * Bounded, keyset pagination on every list endpoint.
 *
 * Why this suite is more than a smoke test: the admin API and `/v1/resolve` share
 * one Node process, so an unbounded listing is not a slow request -- it is a stalled
 * event loop and a saturated pool for every install's policy resolution, and an
 * install that cannot resolve gets *no* access. The bound is an availability
 * control, so "the ceiling is actually enforced" is asserted per endpoint rather
 * than once.
 *
 * The paging assertions all cross a page boundary with more rows than the page
 * size, because a pagination test with fewer rows than a page proves only that
 * `LIMIT` accepts a number. Three specific failures are targeted, each of which
 * has shipped in real systems:
 *
 * - **A tied sort key.** `at` and `granted_at` are not unique. A keyset comparison
 *   on a non-unique key skips or repeats the tied rows, so the fixtures deliberately
 *   write every row with an *identical* timestamp and make the primary-key tiebreak
 *   carry the whole ordering.
 * - **A truncated cursor.** Postgres keeps microseconds; a JS `Date` keeps
 *   milliseconds. `skips a row when the cursor loses sub-millisecond precision`
 *   builds the exact interleaving where truncation drops a row.
 * - **An exactly-full last page.** Deciding "there is more" from a full page hands
 *   out a cursor to an empty page forever.
 *
 * And one correctness property, asserted here rather than assumed: paging must not
 * touch a policy body. Section 3 makes `[]` and `null` opposites for an allow-list,
 * so a listing that "tidied" an empty array would convert deny-everything into
 * unrestricted. See store-null-vs-empty.test.ts, which owns that property; this
 * suite only proves the new code path did not become an exception to it.
 */

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import type { PolicyDefinition } from "@aws/tolap-core";
import { validateFieldAccess } from "@aws/tolap-core";
import { PostgresPolicyStore } from "../src/db/store.ts";
import { Keyring } from "../src/signing/keyring.ts";
import { buildAdminApp } from "../src/routes/admin.ts";
import type { AdminPrincipal } from "../src/auth/cognito.ts";
import { AdminAuthError } from "../src/auth/cognito.ts";
import {
  DEFAULT_PAGE_LIMIT,
  MAX_INT4,
  MAX_PAGE_LIMIT,
  PaginationError,
  cursorInteger,
  decodeCursor,
  encodeCursor,
  normalizeLimit,
  parseLimit,
  toPage,
} from "../src/db/pagination.ts";
import { HAVE_DB, staticIdentity, testDb, type TestDb } from "./helpers/db.ts";

/** Comfortably more than one default page, so a boundary is always crossed. */
const ROWS = 250;

const verifier = {
  verify: async (token: string): Promise<AdminPrincipal> => {
    if (token === "auditor-token") {
      return { subject: "cognito-sub-auditor", role: "auditor" };
    }
    throw new AdminAuthError("unrecognized test token");
  },
};
const asAuditor = { authorization: "Bearer auditor-token" };

// -- The parsing and page-assembly rules, without a database ----------------

describe("pagination bounds", () => {
  it("guard: the skip condition is a real boolean", () => {
    expect(typeof HAVE_DB).toBe("boolean");
  });

  it("defaults to a page, not to everything", () => {
    expect(normalizeLimit(undefined)).toBe(DEFAULT_PAGE_LIMIT);
    expect(parseLimit(undefined)).toBeUndefined();
  });

  it("accepts a limit at the ceiling and refuses one above it", () => {
    expect(parseLimit(String(MAX_PAGE_LIMIT))).toBe(MAX_PAGE_LIMIT);
    // Refused, never clamped. Clamping returns fewer rows than asked for with no
    // signal, and on the audit log a reviewer reads that as "there were only 500
    // events".
    expect(() => parseLimit(String(MAX_PAGE_LIMIT + 1))).toThrow(PaginationError);
    expect(() => normalizeLimit(MAX_PAGE_LIMIT + 1)).toThrow(PaginationError);
    expect(() => parseLimit("100000000")).toThrow(PaginationError);
  });

  it.each([
    ["negative", "-1"],
    ["zero", "0"],
    ["non-numeric", "abc"],
    ["empty", ""],
    ["float", "1.5"],
    // Number("1e3") is 1000 and Number(" 5") is 5. Coercion here would let a caller
    // set the server's memory bound through a value it never validated.
    ["exponent", "1e3"],
    ["leading space", " 5"],
    ["hex", "0x10"],
    ["Infinity", "Infinity"],
    ["NaN", "NaN"],
  ])("rejects a %s limit", (_label, raw) => {
    expect(() => parseLimit(raw)).toThrow(PaginationError);
  });

  it("reports 400 for a bad limit, not 422", () => {
    // 400 is a malformed request line; 422 is a document that failed schema
    // validation. The console renders the two differently.
    try {
      parseLimit("-1");
      throw new Error("expected a PaginationError");
    } catch (error) {
      expect((error as PaginationError).status).toBe(400);
    }
  });

  it("round-trips a cursor and refuses a mangled one", () => {
    expect(decodeCursor(encodeCursor(["a", "b"]), 2)).toEqual(["a", "b"]);
    expect(decodeCursor(undefined, 1)).toBeUndefined();
    expect(() => decodeCursor("!!not base64!!", 1)).toThrow(PaginationError);
    // Wrong arity: a cursor minted by another endpoint would otherwise be
    // interpolated into the wrong comparison and page from nonsense.
    expect(() => decodeCursor(encodeCursor(["a"]), 2)).toThrow(PaginationError);
    expect(() => decodeCursor(Buffer.from('"a"').toString("base64url"), 1)).toThrow(
      PaginationError,
    );
  });

  it("refuses an integer cursor too large for its column", () => {
    // Shape alone was not enough. `/^\d+$/` accepted an arbitrarily long digit string,
    // which then reached a `::bigint` cast and made Postgres raise 22003 -- surfacing as
    // **500 {"error":"internal error"}** from a URL an auditor could type by hand. That is
    // exactly the "page an operator over a bad URL" outcome these validators exist to
    // prevent, so the validator has to reject what the target COLUMN cannot hold, not just
    // what does not look like a number.
    expect(() => cursorInteger("9".repeat(30))).toThrow(/not a valid pagination cursor/);
    // 2^63 -- one past what a bigint holds.
    expect(() => cursorInteger("9223372036854775808")).toThrow(/not a valid/);
    // The boundary itself is fine.
    expect(cursorInteger("9223372036854775807")).toBe("9223372036854775807");

    // `version_no` is an int4, so its ceiling is lower and is passed explicitly.
    expect(() => cursorInteger("2147483648", MAX_INT4)).toThrow(/not a valid/);
    expect(cursorInteger("2147483647", MAX_INT4)).toBe("2147483647");
  });

  it("uses base64url so a cursor survives a query string", () => {
    // A '+' in a cursor decodes as a space, and the next page silently starts from
    // the wrong row. 0xFF bytes force the characters base64 differs on.
    const cursor = encodeCursor([Buffer.from([0xff, 0xfe, 0xfd]).toString("latin1")]);
    expect(cursor).not.toMatch(/[+/=]/);
    expect(decodeCursor(cursor, 1)).toBeDefined();
  });

  it("reports no cursor when the last page is exactly full", () => {
    // limit + 1 rows are fetched; only the extra one means "there is more".
    const exact = toPage([1, 2], 2, (n) => n, String);
    expect(exact.items).toEqual([1, 2]);
    expect(exact.nextCursor).toBeNull();

    const more = toPage([1, 2, 3], 2, (n) => n, String);
    expect(more.items).toEqual([1, 2]);
    expect(more.nextCursor).toBe("2");

    expect(toPage([], 2, (n) => n, String).nextCursor).toBeNull();
  });
});

describe("paginated listings", () => {
  it("guard: the skip condition is a real boolean", () => {
    expect(typeof HAVE_DB).toBe("boolean");
  });

  describe.skipIf(!HAVE_DB)("against PostgreSQL", () => {
    let db: TestDb;
    let store: PostgresPolicyStore;
    let app: FastifyInstance;

    beforeAll(async () => {
      db = await testDb("pagination");
    });

    afterAll(async () => {
      await app?.close();
      await db?.close();
    });

    beforeEach(async () => {
      await db.reset();
      store = new PostgresPolicyStore(db.pool, staticIdentity());
      await app?.close();
      app = buildAdminApp({
        store,
        verifier,
        keyring: new Keyring(
          [{ kid: "test-key", secret: "pagination-test-key-not-for-production" }],
          "test-key",
        ),
        ttlSeconds: 900,
      });
    });

    // -- Fixtures ---------------------------------------------------------
    //
    // Written with raw SQL rather than through the store so the timestamps can be
    // pinned. Every timestamp in a batch is *identical* on purpose: that is what
    // forces the primary-key tiebreak to carry the ordering, which is the case a
    // keyset walk gets wrong when the key is not unique.

    const seedPolicies = async (count = ROWS) => {
      await db.pool.query(
        `INSERT INTO tolap_policies (name, policy_json)
         SELECT 'p-' || lpad(g::text, 4, '0'),
                jsonb_build_object(
                  'version', '1.0',
                  'name', 'p-' || lpad(g::text, 4, '0'),
                  'permissions', jsonb_build_object('canQuery', true))
         FROM generate_series(1, $1) g`,
        [count],
      );
    };

    const seedAudit = async (count = ROWS, at = "2026-01-01T00:00:00Z") => {
      await db.pool.query(
        `INSERT INTO tolap_audit (at, actor, actor_kind, action)
         SELECT $2::timestamptz, 'admin-1', 'admin', 'event-' || lpad(g::text, 4, '0')
         FROM generate_series(1, $1) g`,
        [count, at],
      );
    };

    const seedAssignments = async (count = ROWS) => {
      await db.pool.query(
        `INSERT INTO tolap_policies (name, policy_json)
         VALUES ('analyst', '{"version":"1.0","name":"analyst","permissions":{"canQuery":true}}'::jsonb)`,
      );
      await db.pool.query(
        `INSERT INTO tolap_assignments
           (policy_name, assignee_type, assignee_id, tenant_id, granted_by, granted_at)
         SELECT 'analyst', 'user', 'user-' || lpad(g::text, 4, '0'), 't1', 'admin-1',
                '2026-01-01T00:00:00Z'::timestamptz
         FROM generate_series(1, $1) g`,
        [count],
      );
    };

    const seedSources = async (count = ROWS) => {
      await db.pool.query(
        `INSERT INTO tolap_sources (source_connection_id, category, manifest_json)
         SELECT 'db:analytics:t' || lpad(g::text, 4, '0'), 'db',
                jsonb_build_object(
                  'sourceConnectionId', 'db:analytics:t' || lpad(g::text, 4, '0'),
                  'category', 'db', 'objects', '[]'::jsonb, 'endpoints', '[]'::jsonb,
                  'tags', '[]'::jsonb, 'prefixes', '[]'::jsonb)
         FROM generate_series(1, $1) g`,
        [count],
      );
    };

    const seedInstalls = async (count = ROWS) => {
      await db.pool.query(
        `INSERT INTO tolap_installs (id, name, credential_hash, created_by, created_at)
         SELECT 'i-' || lpad(g::text, 4, '0'), 'install ' || g, 'hash-' || g, 'admin-1',
                '2026-01-01T00:00:00Z'::timestamptz
         FROM generate_series(1, $1) g`,
        [count],
      );
    };

    const seedVersions = async (count = ROWS) => {
      await db.pool.query(
        `INSERT INTO tolap_policy_versions
           (name, version_no, policy_json, state, created_by)
         SELECT 'analyst', g,
                jsonb_build_object('version', '1.0', 'name', 'analyst',
                  'permissions', jsonb_build_object('canQuery', true)),
                'draft', 'admin-1'
         FROM generate_series(1, $1) g`,
        [count],
      );
    };

    /**
     * Walk every page and return the identities seen, in order.
     *
     * Returns the raw list rather than a set so the caller can assert on
     * duplicates: a keyset bug shows up as a repeated row, and a set would hide it.
     */
    async function walk<T>(
      fetch: (cursor: string | undefined) => Promise<{
        items: T[];
        nextCursor: string | null;
      }>,
      identify: (item: T) => string,
    ): Promise<string[]> {
      const seen: string[] = [];
      let cursor: string | undefined;
      // Bounded so a cursor that fails to advance fails the test instead of
      // hanging the suite.
      for (let page = 0; page < 100; page += 1) {
        const result = await fetch(cursor);
        seen.push(...result.items.map(identify));
        if (result.nextCursor === null) return seen;
        cursor = result.nextCursor;
      }
      throw new Error("pagination did not terminate within 100 pages");
    }

    // -- Definitions -------------------------------------------------------

    describe("policies", () => {
      it("returns one default-sized page and a cursor, not the table", async () => {
        await seedPolicies();
        const page = await store.pageDefinitions();

        expect(page.items).toHaveLength(DEFAULT_PAGE_LIMIT);
        expect(page.nextCursor).not.toBeNull();
        // The bound is the point: 250 rows exist and 200 came back.
        expect(page.items.length).toBeLessThan(ROWS);
      });

      it("walks every row exactly once across page boundaries", async () => {
        await seedPolicies();
        const seen = await walk(
          (cursor) =>
            store.pageDefinitions({ limit: 40, ...(cursor ? { cursor } : {}) }),
          (p) => p.name,
        );

        expect(seen).toHaveLength(ROWS);
        expect(new Set(seen).size).toBe(ROWS);
        // Ordered by name, so the walk must produce the sorted sequence -- no gaps.
        expect(seen).toEqual([...seen].sort());
        expect(seen[0]).toBe("p-0001");
        expect(seen[ROWS - 1]).toBe("p-0250");
      });

      it("reports no cursor when the last page is exactly full", async () => {
        // 250 rows in pages of 125: the second page fills exactly, and a naive
        // "full page means more" would hand out a cursor to an empty page.
        await seedPolicies();
        const first = await store.pageDefinitions({ limit: 125 });
        const second = await store.pageDefinitions({
          limit: 125,
          cursor: first.nextCursor!,
        });

        expect(second.items).toHaveLength(125);
        expect(second.nextCursor).toBeNull();
      });

      it("preserves an empty allowedFields array through a page", async () => {
        // Section 3: `[]` denies everything, absent is unrestricted. A listing that
        // rebuilt the body could collapse them, so this asserts the *decision* after
        // paging, not just the JSON. store-null-vs-empty.test.ts owns this property
        // on the single-read path; this proves paging is not an exception.
        const deny = {
          version: "1.0",
          name: "deny-all",
          permissions: { canQuery: true },
          objectRules: { fieldRules: { allowedFields: [] } },
        } as unknown as PolicyDefinition;
        const open = {
          version: "1.0",
          name: "unrestricted",
          permissions: { canQuery: true },
          objectRules: { fieldRules: { hiddenFields: ["ssn"] } },
        } as unknown as PolicyDefinition;
        await store.putDefinitionAs(deny, { id: "admin-1", kind: "admin" });
        await store.putDefinitionAs(open, { id: "admin-1", kind: "admin" });

        const page = await store.pageDefinitions();
        const listed = new Map(page.items.map((p) => [p.name, p]));

        expect(listed.get("deny-all")!.objectRules?.fieldRules?.allowedFields).toEqual(
          [],
        );
        expect(
          listed.get("unrestricted")!.objectRules?.fieldRules?.allowedFields,
        ).toBeUndefined();

        // Had paging coerced [] to null, every field would be allowed here.
        const denied = validateFieldAccess(["name", "email"], {
          objectRules: listed.get("deny-all")!.objectRules,
        } as never);
        expect(denied.allowed).toEqual([]);
      });
    });

    // -- Audit -------------------------------------------------------------

    describe("audit", () => {
      it("pages newest-first through rows sharing one timestamp", async () => {
        // Every row has an identical `at`, so the id tiebreak is the only thing
        // ordering them. A keyset walk on `at` alone would skip or repeat here.
        await seedAudit();
        const seen = await walk(
          (cursor) => store.pageAudit({ limit: 60, ...(cursor ? { cursor } : {}) }),
          (e) => e.action,
        );

        expect(seen).toHaveLength(ROWS);
        expect(new Set(seen).size).toBe(ROWS);
        // Newest first: the highest id was inserted last.
        expect(seen[0]).toBe("event-0250");
        expect(seen[ROWS - 1]).toBe("event-0001");
      });

      it("skips no row when the cursor loses sub-millisecond precision", async () => {
        // Two rows inside one millisecond, one microsecond apart. If the cursor were
        // rendered through a JS Date (millisecond resolution), the second row's `at`
        // would compare as *greater* than the truncated cursor and be dropped.
        await db.pool.query(
          `INSERT INTO tolap_audit (at, actor, actor_kind, action) VALUES
             ('2026-01-01T00:00:00.000501Z'::timestamptz, 'a', 'admin', 'newer'),
             ('2026-01-01T00:00:00.000500Z'::timestamptz, 'a', 'admin', 'older')`,
        );

        const seen = await walk(
          (cursor) => store.pageAudit({ limit: 1, ...(cursor ? { cursor } : {}) }),
          (e) => e.action,
        );
        expect(seen).toEqual(["newer", "older"]);
      });

      it("neither skips nor repeats when rows are appended mid-walk", async () => {
        // The reason this is keyset and not OFFSET. The audit log is append-only and
        // written constantly, so an OFFSET window shifts under a paged export and
        // silently drops an entry -- losing evidence, not losing tidiness.
        await seedAudit(ROWS, "2026-01-01T00:00:00Z");
        const first = await store.pageAudit({ limit: 100 });

        // 50 newer rows arrive between the two requests.
        await seedAudit(50, "2026-06-01T00:00:00Z");

        const second = await store.pageAudit({
          limit: 100,
          cursor: first.nextCursor!,
        });

        const overlap = second.items.filter((entry) =>
          first.items.some((seen) => seen.action === entry.action),
        );
        expect(overlap).toEqual([]);
        // The page continues from where the first left off rather than from the new
        // rows: the newest row on page 1 was event-0250, so page 2 starts at 0150.
        expect(second.items[0]!.action).toBe("event-0150");
      });

      it("enforces the ceiling on the audit limit too", async () => {
        await seedAudit(10);
        await expect(store.pageAudit({ limit: MAX_PAGE_LIMIT + 1 })).rejects.toThrow(
          PaginationError,
        );
        // listAudit shares the bound: a helper that could read the whole table
        // would reintroduce exactly what pagination is here to prevent.
        await expect(store.listAudit(100_000_000)).rejects.toThrow(PaginationError);
      });

      it("bounds listAudit's default", async () => {
        await seedAudit(ROWS);
        expect(await store.listAudit()).toHaveLength(DEFAULT_PAGE_LIMIT);
      });
    });

    // -- Assignments -------------------------------------------------------

    describe("assignments", () => {
      it("walks every live assignment exactly once", async () => {
        // All 250 share one granted_at, so the uuid primary key carries the order.
        await seedAssignments();
        const seen = await walk(
          (cursor) =>
            store.pageAssignments(undefined, {
              limit: 70,
              ...(cursor ? { cursor } : {}),
            }),
          (a) => a.assignee.identifier,
        );

        expect(seen).toHaveLength(ROWS);
        expect(new Set(seen).size).toBe(ROWS);
      });

      it("still hides revoked assignments on every page", async () => {
        // Section 12: revocation must make an assignment stop resolving, and a
        // listing that showed revoked rows as live would have an administrator
        // believe access exists that does not.
        await seedAssignments();
        await db.pool.query(
          `UPDATE tolap_assignments SET revoked_at = now()
           WHERE assignee_id < 'user-0051'`,
        );

        const seen = await walk(
          (cursor) =>
            store.pageAssignments(undefined, {
              limit: 40,
              ...(cursor ? { cursor } : {}),
            }),
          (a) => a.assignee.identifier,
        );
        expect(seen).toHaveLength(ROWS - 50);
        expect(seen).not.toContain("user-0001");
      });

      it("keeps the assignee filter across pages", async () => {
        await seedAssignments();
        const page = await store.pageAssignments("user-0007", { limit: 40 });
        expect(page.items.map((a) => a.assignee.identifier)).toEqual(["user-0007"]);
        expect(page.nextCursor).toBeNull();
      });

      it("rejects a cursor whose id is not a uuid", async () => {
        // Reaches a `::uuid` cast, so a hand-edited cursor must produce a 400 that
        // names the problem rather than a Postgres cast error surfacing as a 500.
        await seedAssignments(5);
        await expect(
          store.pageAssignments(undefined, {
            cursor: encodeCursor(["2026-01-01T00:00:00.000000Z", "not-a-uuid"]),
          }),
        ).rejects.toThrow(PaginationError);
      });
    });

    // -- Versions, catalog, installs ---------------------------------------

    describe("versions", () => {
      it("walks a policy's history newest-first", async () => {
        await seedVersions();
        const seen = await walk(
          (cursor) =>
            store.pageVersions("analyst", { limit: 45, ...(cursor ? { cursor } : {}) }),
          (v) => String(v.versionNo),
        );

        expect(seen).toHaveLength(ROWS);
        expect(new Set(seen).size).toBe(ROWS);
        expect(seen[0]).toBe(String(ROWS));
        expect(seen[ROWS - 1]).toBe("1");
      });

      it("bounds the default page", async () => {
        await seedVersions();
        const page = await store.pageVersions("analyst");
        expect(page.items).toHaveLength(DEFAULT_PAGE_LIMIT);
        expect(page.nextCursor).not.toBeNull();
      });
    });

    describe("catalog", () => {
      it("walks every source exactly once", async () => {
        await seedSources();
        const seen = await walk(
          (cursor) => store.pageSources({ limit: 55, ...(cursor ? { cursor } : {}) }),
          (s) => s.sourceConnectionId,
        );

        expect(seen).toHaveLength(ROWS);
        expect(new Set(seen).size).toBe(ROWS);
        expect(seen).toEqual([...seen].sort());
      });
    });

    describe("installs", () => {
      it("walks every install exactly once through a tied timestamp", async () => {
        await seedInstalls();
        const seen = await walk(
          (cursor) => store.pageInstalls({ limit: 65, ...(cursor ? { cursor } : {}) }),
          (i) => i.id,
        );

        expect(seen).toHaveLength(ROWS);
        expect(new Set(seen).size).toBe(ROWS);
      });

      it("never carries the credential hash on any page", async () => {
        await seedInstalls(3);
        const page = await store.pageInstalls();
        expect(JSON.stringify(page)).not.toContain("hash-");
      });
    });

    // -- Over HTTP ---------------------------------------------------------
    //
    // The store bound is the backstop; the route is the control. Asserted through
    // the real endpoints because that is the surface a caller reaches.

    describe("over HTTP", () => {
      const get = (url: string) =>
        app.inject({ method: "GET", url, headers: asAuditor });

      /** Each list route, its items key, and a fixture that overfills a page. */
      const endpoints = [
        { url: "/v1/policies", key: "policies", seed: seedPolicies },
        { url: "/v1/audit", key: "entries", seed: seedAudit },
        { url: "/v1/assignments", key: "assignments", seed: seedAssignments },
        { url: "/v1/catalog", key: "sources", seed: seedSources },
        { url: "/v1/installs", key: "installs", seed: seedInstalls },
        {
          url: "/v1/policies/analyst/versions",
          key: "versions",
          seed: seedVersions,
        },
      ] as const;

      it.each(endpoints)(
        "GET $url returns a default page and a cursor",
        async ({ url, key, seed }) => {
          await seed(ROWS);
          const body = (await get(url)).json();

          // A caller that passes no parameters -- which is every console call today
          // -- gets a sensible first page rather than an error.
          expect(body[key]).toHaveLength(DEFAULT_PAGE_LIMIT);
          expect(body.nextCursor).toEqual(expect.any(String));
        },
      );

      it("GET /v1/audit answers 400, not 500, for an oversized cursor", async () => {
        // The bug this pins produced `500 {"error":"internal error"}`: the integer cursor
        // validator checked shape but not magnitude, so a long digit string reached a
        // `::bigint` cast and Postgres raised 22003. A 500 from a hand-typed URL is the
        // exact "page an operator over nothing" outcome the validators exist to prevent,
        // and an auditor can trigger it by editing a link.
        await seedAudit(10);
        const cursor = encodeCursor(["2026-01-01T00:00:00.000000Z", "9".repeat(30)]);
        const response = await get(`/v1/audit?cursor=${cursor}`);

        expect(response.statusCode).toBe(400);
        expect(response.json().error).toMatch(/cursor/i);
      });

      it("GET versions answers 400 for a cursor beyond int4", async () => {
        // `version_no` is an `integer`, so its ceiling is lower than a bigint's -- a value
        // that fits one and not the other would still have surfaced as a 500.
        await seedVersions(10);
        const cursor = encodeCursor(["2147483648"]);
        const response = await get(`/v1/policies/analyst/versions?cursor=${cursor}`);

        expect(response.statusCode).toBe(400);
      });

      it.each(endpoints)(
        "GET $url rejects a limit above the ceiling with 400",
        async ({ url, seed }) => {
          await seed(10);
          const response = await get(`${url}?limit=${MAX_PAGE_LIMIT + 1}`);
          expect(response.statusCode).toBe(400);
          expect(response.json().error).toContain(String(MAX_PAGE_LIMIT));
        },
      );

      it.each(endpoints)(
        "GET $url rejects a non-numeric or negative limit with 400",
        async ({ url, seed }) => {
          await seed(10);
          for (const bad of ["abc", "-1", "0", "1e9", "100000000"]) {
            const response = await get(`${url}?limit=${bad}`);
            expect(
              response.statusCode,
              `${url}?limit=${bad} should be refused`,
            ).toBe(400);
          }
        },
      );

      it.each(endpoints)(
        "GET $url rejects a mangled cursor with 400",
        async ({ url, seed }) => {
          await seed(10);
          const response = await get(`${url}?cursor=not-a-cursor`);
          expect(response.statusCode).toBe(400);
        },
      );

      it.each(endpoints)(
        "GET $url pages to the end with no gaps and no duplicates",
        async ({ url, key, seed }) => {
          await seed(ROWS);

          const seen: string[] = [];
          let cursor: string | undefined;
          let pages = 0;
          do {
            const query = `limit=60${cursor !== undefined ? `&cursor=${encodeURIComponent(cursor)}` : ""}`;
            const body = (await get(`${url}?${query}`)).json();
            // Identity by the whole serialized row: every fixture row is distinct,
            // so a duplicate here is a real keyset defect rather than a naming
            // coincidence.
            seen.push(...body[key].map((item: unknown) => JSON.stringify(item)));
            cursor = body.nextCursor ?? undefined;
            pages += 1;
          } while (cursor !== undefined && pages < 20);

          expect(seen).toHaveLength(ROWS);
          expect(new Set(seen).size).toBe(ROWS);
          // The last page reported no further cursor, which is how a caller's loop
          // terminates.
          expect(cursor).toBeUndefined();
        },
      );

      it("uses the same envelope on every list endpoint", async () => {
        // One shape so a client writes the paging loop once. `nextCursor` is present
        // and null on the last page, not omitted -- an absent field would make "no
        // more pages" indistinguishable from "this endpoint does not paginate".
        for (const { url, key, seed } of endpoints) {
          await db.reset();
          await seed(2);
          const body = (await get(url)).json();
          expect(Object.keys(body).sort(), url).toEqual([key, "nextCursor"].sort());
          expect(body.nextCursor, url).toBeNull();
        }
      });

      it("accepts a limit of exactly the ceiling", async () => {
        await seedAudit(ROWS);
        const response = await get(`/v1/audit?limit=${MAX_PAGE_LIMIT}`);
        expect(response.statusCode).toBe(200);
        expect(response.json().entries).toHaveLength(ROWS);
      });
    });
  });
});
