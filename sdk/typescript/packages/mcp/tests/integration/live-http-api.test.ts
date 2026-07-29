/**
 * Enforcement over a REAL socket, against tools/test-api/server.py.
 *
 * Why a live server rather than another in-process `FetchLike` mock: the mocks
 * hand the wrapper a body that was never serialized, over a transport that never
 * produced a status line or a header. They cannot catch a wrapper that mishandles
 * a genuine non-2xx status, a nested JSON body parsed from bytes, or an envelope
 * shape it only ever saw hand-written. Everything asserted here is enforcement
 * behavior the canonical spec mandates; the socket is what makes the assertion
 * about the shipped code path rather than about the fixture.
 *
 * The server is started as a child process on a port distinct from the Python
 * suite's (8888). If it cannot bind or does not answer /healthz, every test here
 * skips rather than failing -- a missing local server is an environment gap, not
 * a policy regression.
 */

import { spawn, type ChildProcess } from "node:child_process";
import { resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  buildSecurityContext,
  signContext,
  type EffectivePolicy,
  type SecurityContext,
} from "@tolap/core";
import { SecureHttpToolWrapper, type FetchLike } from "../../src/http-wrapper.js";

const SIGNING_KEY = "live-http-api-key";
const PORT = Number(process.env.TOLAP_TS_TEST_API_PORT ?? 8889);
const BASE_URL = `http://127.0.0.1:${PORT}`;
const REPO_ROOT = resolve(__dirname, "..", "..", "..", "..", "..", "..");
const SERVER = resolve(REPO_ROOT, "tools", "test-api", "server.py");

let child: ChildProcess | undefined;
let available = false;
/** True when this process started the server and must therefore stop it. */
let ownsServer = false;

async function probe(): Promise<boolean> {
  try {
    const response = await fetch(`${BASE_URL}/healthz`, {
      signal: AbortSignal.timeout(1000),
    });
    if (!response.ok) return false;
    const body = (await response.json()) as { status?: string };
    return body.status === "ok";
  } catch {
    return false;
  }
}

beforeAll(async () => {
  // Reuse an already-running instance (a developer's, or a sibling suite's)
  // rather than fighting it for the port.
  if (await probe()) {
    available = true;
    return;
  }

  child = spawn("python3", [SERVER, "--port", String(PORT)], {
    cwd: REPO_ROOT,
    stdio: "ignore",
  });
  child.on("error", () => {
    available = false;
  });
  ownsServer = true;

  for (let attempt = 0; attempt < 40; attempt++) {
    if (child.exitCode !== null) break; // died on startup (port in use, no python3)
    if (await probe()) {
      available = true;
      return;
    }
    await new Promise((r) => setTimeout(r, 100));
  }
}, 20_000);

afterAll(() => {
  if (ownsServer && child && child.exitCode === null) child.kill("SIGTERM");
});

/** Real-socket transport. Deliberately does not paper over a non-2xx status. */
const liveFetch: FetchLike = async ({ method, url, body, headers }) => {
  const response = await fetch(url, {
    method,
    headers: {
      "User-Agent": "tolap-ts-tests/1.0",
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      ...(headers ?? {}),
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    signal: AbortSignal.timeout(10_000),
  });
  const parsed = await response.json();
  return { ok: response.ok, status: response.status, json: async () => parsed };
};

function policy(
  objectRules: EffectivePolicy["objectRules"],
  limits?: EffectivePolicy["limits"],
  permissions: EffectivePolicy["permissions"] = {
    canQuery: true,
    canExport: false,
    readOnly: true,
  },
): EffectivePolicy {
  const now = new Date();
  return {
    version: "1.0",
    userId: "live-user",
    tenantId: "live-tenant",
    sourceConnectionId: "api:internal:test",
    resolvedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 3_600_000).toISOString(),
    sourceProfiles: ["live-http-api"],
    permissions,
    ...(objectRules !== undefined ? { objectRules } : {}),
    ...(limits !== undefined ? { limits } : {}),
    integrity: { algorithm: "none", signature: "" },
  };
}

function signed(p: EffectivePolicy): SecurityContext {
  return signContext(buildSecurityContext(p.userId, p.tenantId, p, 3_600_000), SIGNING_KEY);
}

function wrapper(): SecureHttpToolWrapper {
  return new SecureHttpToolWrapper({ signingKey: SIGNING_KEY, baseUrl: BASE_URL }, liveFetch);
}

/** Every test in this file needs the server; skip cleanly when it is absent. */
function requireServer(ctx: { skip: (note?: string) => void }): void {
  if (!available) ctx.skip("local test API not reachable");
}

const ALLOW_ALL_PATIENTS = {
  endpointRules: { allowedEndpoints: ["/patients", "/patients/*"], allowedMethods: ["GET"] },
} satisfies EffectivePolicy["objectRules"];

// ---------------------------------------------------------------------------
// Pipeline steps 1 and 2 over HTTP (canonical spec §4)
// ---------------------------------------------------------------------------

describe("spec §4: the HTTP body runs row filters and tag filters", () => {
  it("LEAK: a row filter excludes records instead of being a silent no-op", async (ctx) => {
    requireServer(ctx);
    // /patients returns 5 records, one of them status="deleted". A policy that
    // constrains status to "active" must not return the deleted record. Before
    // the fix the HTTP wrapper never called applyRowFilters at all, so every
    // rowFilters entry in a policy was silently ignored on the API path while the
    // identical policy filtered correctly through the MCP and context wrappers.
    const body = (await wrapper().request(
      signed(
        policy({
          ...ALLOW_ALL_PATIENTS,
          rowFilters: [{ field: "status", operator: "equals", value: "active" }],
        }),
      ),
      { method: "GET", path: "/patients", collectionPath: "results" },
    )) as { results: Array<Record<string, unknown>> };

    expect(body.results.map((r) => r.id)).toEqual([1, 2, 3, 5]);
    expect(body.results.some((r) => r.status === "deleted")).toBe(false);
  });

  it("LEAK: a denied tag excludes the record it is on", async (ctx) => {
    requireServer(ctx);
    const body = (await wrapper().request(
      signed(
        policy({
          ...ALLOW_ALL_PATIENTS,
          tagRules: { deniedTags: ["confidential"] },
        }),
      ),
      { method: "GET", path: "/patients", collectionPath: "results" },
    )) as { results: Array<Record<string, unknown>> };

    // Record 3 carries "confidential" and is dropped. Record 5 has no `tags` key
    // at all and survives: an untagged record matches no denied tag, so dropping
    // it would enforce a restriction the policy never stated (spec §4).
    expect(body.results.map((r) => r.id)).toEqual([1, 2, 4, 5]);
  });

  it("LEAK: allowedTags: [] denies every record rather than lifting the rule", async (ctx) => {
    requireServer(ctx);
    // [] is deny-all, not "unrestricted" (spec §3). Treating it as falsy is the
    // single most dangerous version of this bug: the most restrictive possible
    // policy becomes no policy at all.
    const body = (await wrapper().request(
      signed(policy({ ...ALLOW_ALL_PATIENTS, tagRules: { allowedTags: [] } })),
      { method: "GET", path: "/patients", collectionPath: "results" },
    )) as { results: Array<Record<string, unknown>> };

    expect(body.results).toEqual([]);
  });

  it("a non-empty allowedTags keeps only matching records and drops untagged ones", async (ctx) => {
    requireServer(ctx);
    const body = (await wrapper().request(
      signed(
        policy({ ...ALLOW_ALL_PATIENTS, tagRules: { allowedTags: ["research"] } }),
      ),
      { method: "GET", path: "/patients", collectionPath: "results" },
    )) as { results: Array<Record<string, unknown>> };

    // Only record 2 carries "research"; record 5 is untagged, and an untagged
    // record has no proof of allowance, so it is dropped (spec §4).
    expect(body.results.map((r) => r.id)).toEqual([2]);
  });

  it("row and tag filters AND together with the rest of the pipeline", async (ctx) => {
    requireServer(ctx);
    const body = (await wrapper().request(
      signed(
        policy(
          {
            ...ALLOW_ALL_PATIENTS,
            rowFilters: [{ field: "status", operator: "equals", value: "active" }],
            tagRules: { deniedTags: ["confidential"] },
            fieldRules: {
              hiddenFields: ["ssn"],
              maskedFields: [{ field: "email", maskType: "redact" }],
            },
          },
          { maxResults: 1 },
        ),
      ),
      { method: "GET", path: "/patients", collectionPath: "results" },
    )) as { results: Array<Record<string, unknown>> };

    // status filter drops 4; deniedTags drops 3; ssn hidden; email redacted; the
    // limit runs LAST, so it truncates the two survivors (1, 5) to one.
    expect(body.results.length).toBe(1);
    expect(body.results[0].id).toBe(1);
    expect("ssn" in body.results[0]).toBe(false);
    expect(body.results[0].email).toBe("[REDACTED]");
  });

  it("a row filter drops a record missing the referenced field (fail closed)", async (ctx) => {
    requireServer(ctx);
    // Record 5 has no `tags` key. A filter referencing it must drop that record
    // for the negative operators too (spec §7).
    const body = (await wrapper().request(
      signed(
        policy({
          ...ALLOW_ALL_PATIENTS,
          rowFilters: [{ field: "tags", operator: "notEquals", value: "nope" }],
        }),
      ),
      { method: "GET", path: "/patients", collectionPath: "results" },
    )) as { results: Array<Record<string, unknown>> };

    expect(body.results.map((r) => r.id)).not.toContain(5);
  });

  it("filtering respects a nested collectionPath", async (ctx) => {
    requireServer(ctx);
    const body = (await wrapper().request(
      signed(
        policy({
          endpointRules: { allowedEndpoints: ["/patients/*"], allowedMethods: ["GET"] },
          rowFilters: [{ field: "region", operator: "equals", value: "us-east" }],
        }),
      ),
      { method: "GET", path: "/patients/envelope", collectionPath: "items" },
    )) as { items: Array<Record<string, unknown>>; total: number };

    expect(body.items.map((r) => r.id)).toEqual([1, 4]);
    // The transport envelope survives: filtering targets the records, not the
    // paging block.
    expect(body.total).toBe(5);
  });

  it("filtering leaves the body untouched when the policy sets no filters", async (ctx) => {
    requireServer(ctx);
    const body = (await wrapper().request(signed(policy(ALLOW_ALL_PATIENTS)), {
      method: "GET",
      path: "/patients",
      collectionPath: "results",
    })) as { results: unknown[] };

    expect(body.results.length).toBe(5);
  });

  it("the relevance floor drops unscored records over HTTP (spec §4 step 3)", async (ctx) => {
    requireServer(ctx);
    // /patients records carry no score field at all. A floor set on a source whose
    // records cannot be scored must drop them: a record whose relevance cannot be
    // established cannot be shown to satisfy the floor. Skipping the step over HTTP
    // returned every low-relevance hit instead.
    const body = (await wrapper().request(
      signed(policy(ALLOW_ALL_PATIENTS, { minSimilarityScore: 0.8 })),
      { method: "GET", path: "/patients", collectionPath: "results" },
    )) as { results: unknown[] };

    expect(body.results).toEqual([]);
  });

  it("the size ceiling drops unsized records over HTTP (spec §4 step 4)", async (ctx) => {
    requireServer(ctx);
    const body = (await wrapper().request(
      signed(policy(ALLOW_ALL_PATIENTS, { maxObjectSizeBytes: 1024 })),
      { method: "GET", path: "/patients", collectionPath: "results" },
    )) as { results: unknown[] };

    expect(body.results).toEqual([]);
  });

  it("both limits leave the body alone when the policy sets neither", async (ctx) => {
    requireServer(ctx);
    const body = (await wrapper().request(
      signed(policy(ALLOW_ALL_PATIENTS, { maxQueryTimeSeconds: 30 })),
      { method: "GET", path: "/patients", collectionPath: "results" },
    )) as { results: unknown[] };

    expect(body.results.length).toBe(5);
  });
});

// ---------------------------------------------------------------------------
// Masking must recurse (canonical spec §4)
// ---------------------------------------------------------------------------

describe("spec §4: HTTP masking recurses into nested records", () => {
  it("LEAK: a bare rule masks a nested key, in cleartext before the fix", async (ctx) => {
    requireServer(ctx);
    // /patients/nested puts ssn under demographics. The wrapper's own masking
    // walker split the rule on "." and walked that literal path from the root,
    // so a bare `ssn` rule matched nothing and the SSN was returned in cleartext
    // over HTTP -- while the very same rule masked it on the MCP path, which
    // delegates to the core walker.
    const body = (await wrapper().request(
      signed(
        policy({
          endpointRules: { allowedEndpoints: ["/patients/*"], allowedMethods: ["GET"] },
          fieldRules: { maskedFields: [{ field: "ssn", maskType: "redact" }] },
        }),
      ),
      { method: "GET", path: "/patients/nested", collectionPath: "results" },
    )) as { results: Array<{ demographics: Record<string, unknown> }> };

    expect(body.results[0].demographics.ssn).toBe("[REDACTED]");
    expect(body.results[0].demographics.ssn).not.toBe("111-22-3333");
    expect(body.results[1].demographics.ssn).toBe("[REDACTED]");
  });

  it("a two-level-deep bare rule is reached", async (ctx) => {
    requireServer(ctx);
    // demographics.contact.email: three levels down, addressed by leaf name only.
    const body = (await wrapper().request(
      signed(
        policy({
          endpointRules: { allowedEndpoints: ["/patients/*"], allowedMethods: ["GET"] },
          fieldRules: { maskedFields: [{ field: "email", maskType: "hash" }] },
        }),
      ),
      { method: "GET", path: "/patients/nested", collectionPath: "results" },
    )) as {
      results: Array<{ demographics: { contact: Record<string, unknown> } }>;
    };

    expect(body.results[0].demographics.contact.email).toMatch(/^[a-f0-9]{16}$/);
    // The sibling key is untouched: masking is targeted, not a blanket wipe.
    expect(body.results[0].demographics.contact.phone).toBe("555-0100");
  });

  it("a dotted rule still works (the pre-existing openFDA convention)", async (ctx) => {
    requireServer(ctx);
    const body = (await wrapper().request(
      signed(
        policy({
          endpointRules: { allowedEndpoints: ["/patients/*"], allowedMethods: ["GET"] },
          fieldRules: {
            maskedFields: [{ field: "demographics.full_name", maskType: "full" }],
          },
        }),
      ),
      { method: "GET", path: "/patients/nested", collectionPath: "results" },
    )) as { results: Array<{ demographics: Record<string, unknown> }> };

    expect(body.results[0].demographics.full_name).toBe("*".repeat("Alice Nguyen".length));
  });

  it("masking reaches inside a nested ARRAY of records", async (ctx) => {
    requireServer(ctx);
    // encounters[].billing.amount_cents: array, then two objects deep.
    const body = (await wrapper().request(
      signed(
        policy({
          endpointRules: { allowedEndpoints: ["/patients/*"], allowedMethods: ["GET"] },
          fieldRules: { maskedFields: [{ field: "amount_cents", maskType: "null" }] },
        }),
      ),
      { method: "GET", path: "/patients/nested", collectionPath: "results" },
    )) as {
      results: Array<{ encounters: Array<{ billing: Record<string, unknown> }> }>;
    };

    expect(body.results[0].encounters[0].billing.amount_cents).toBeNull();
  });

  it("hidden-field removal already recursed, and still does", async (ctx) => {
    requireServer(ctx);
    const body = (await wrapper().request(
      signed(
        policy({
          endpointRules: { allowedEndpoints: ["/patients/*"], allowedMethods: ["GET"] },
          fieldRules: { hiddenFields: ["ssn"] },
        }),
      ),
      { method: "GET", path: "/patients/nested", collectionPath: "results" },
    )) as { results: Array<{ demographics: Record<string, unknown> }> };

    expect("ssn" in body.results[0].demographics).toBe(false);
    expect(body.results[0].demographics.full_name).toBe("Alice Nguyen");
  });

  it("an unknown maskType redacts a nested value rather than disclosing it", async (ctx) => {
    requireServer(ctx);
    const body = (await wrapper().request(
      signed(
        policy({
          endpointRules: { allowedEndpoints: ["/patients/*"], allowedMethods: ["GET"] },
          fieldRules: { maskedFields: [{ field: "ssn", maskType: "tokenize-v9" }] },
        }),
      ),
      { method: "GET", path: "/patients/nested", collectionPath: "results" },
    )) as { results: Array<{ demographics: Record<string, unknown> }> };

    expect(body.results[0].demographics.ssn).toBe("[REDACTED]");
  });
});

// ---------------------------------------------------------------------------
// Real statuses and real headers -- what a mock cannot produce
// ---------------------------------------------------------------------------

describe("real HTTP statuses propagate as denials", () => {
  for (const status of [400, 401, 403, 404, 429, 500, 503]) {
    it(`${status} from the server is raised, not returned as a body`, async (ctx) => {
      requireServer(ctx);
      const p = policy({
        endpointRules: { allowedEndpoints: ["/status/*"], allowedMethods: ["GET"] },
      });

      await expect(
        wrapper().request(signed(p), { method: "GET", path: `/status/${status}` }),
      ).rejects.toThrow(new RegExp(`HTTP ${status}`));
    });
  }

  it("a 2xx body is enforced rather than raised", async (ctx) => {
    requireServer(ctx);
    const p = policy({
      endpointRules: { allowedEndpoints: ["/status/*"], allowedMethods: ["GET"] },
    });

    const body = await wrapper().request(signed(p), {
      method: "GET",
      path: "/status/200",
    });

    expect(body).toBeDefined();
  });
});

describe("request shaping over a real socket", () => {
  it("caller headers reach the server", async (ctx) => {
    requireServer(ctx);
    const p = policy({
      endpointRules: { allowedEndpoints: ["/echo"], allowedMethods: ["GET"] },
    });

    const body = (await wrapper().request(signed(p), {
      method: "GET",
      path: "/echo",
      headers: { "X-Tolap-Probe": "abc123" },
    })) as { headers: Record<string, string> };

    expect(body.headers["x-tolap-probe"]).toBe("abc123");
  });

  it("a query string is sent upstream but not used for policy matching", async (ctx) => {
    requireServer(ctx);
    // The allow-pattern is written against the path. Without query-stripping
    // before evaluation, "/echo?limit=3" would fail to match "/echo".
    const p = policy({
      endpointRules: { allowedEndpoints: ["/echo"], allowedMethods: ["GET"] },
    });

    const body = (await wrapper().request(signed(p), {
      method: "GET",
      path: "/echo?limit=3&region=us-east",
    })) as { query: Record<string, string[]> };

    expect(body.query.limit).toEqual(["3"]);
    expect(body.query.region).toEqual(["us-east"]);
  });

  it("a POST body is transmitted when the policy permits the method", async (ctx) => {
    requireServer(ctx);
    // Permitting a write takes BOTH allowedMethods and readOnly: false. readOnly is
    // a permission-level ceiling over the method (canonical spec §9), so a policy
    // still declaring itself read-only cannot POST however its allowedMethods reads.
    const p = policy(
      {
        endpointRules: {
          allowedEndpoints: ["/patients"],
          allowedMethods: ["GET", "POST"],
        },
      },
      undefined,
      { canQuery: true, canExport: false, readOnly: false },
    );

    const body = (await wrapper().request(signed(p), {
      method: "POST",
      path: "/patients",
      body: { full_name: "New Patient" },
    })) as { created: boolean; received: Record<string, unknown> };

    expect(body.created).toBe(true);
    expect(body.received.full_name).toBe("New Patient");
  });

  it("a GET-only policy denies the POST before it reaches the socket", async (ctx) => {
    requireServer(ctx);
    // The server accepts POST /patients by design: the denial has to come from
    // TOLAP, so this asserts enforcement rather than server-side hiding.
    const p = policy(
      { endpointRules: { allowedEndpoints: ["/patients"], allowedMethods: ["GET"] } },
      undefined,
      { canQuery: true, canExport: false, readOnly: false },
    );

    await expect(
      wrapper().request(signed(p), {
        method: "POST",
        path: "/patients",
        body: { full_name: "Should Not Land" },
      }),
    ).rejects.toThrow(/method not allowed/);
  });

  it("a still-read-only policy denies a POST its allowedMethods granted", async (ctx) => {
    requireServer(ctx);
    // The server would return 201, so the denial is the readOnly permission's work.
    // readOnly is a ceiling: listing POST does not lift it (canonical spec §9).
    const p = policy({
      endpointRules: { allowedEndpoints: ["/patients"], allowedMethods: ["GET", "POST"] },
    });

    await expect(
      wrapper().request(signed(p), {
        method: "POST",
        path: "/patients",
        body: { full_name: "Should Not Land" },
      }),
    ).rejects.toThrow(/read-only policy/);
  });

  it("an endpoint rule denies a reachable admin route", async (ctx) => {
    requireServer(ctx);
    // /admin/audit answers 200 to anyone; TOLAP is what must refuse it.
    const p = policy({
      endpointRules: {
        allowedEndpoints: ["/patients", "/patients/*"],
        hiddenEndpoints: ["/admin/*"],
        allowedMethods: ["GET"],
      },
    });

    await expect(
      wrapper().request(signed(p), { method: "GET", path: "/admin/audit" }),
    ).rejects.toThrow(/endpoint is hidden/);
  });

  it("a recorded openFDA route enforces identically over the socket", async (ctx) => {
    requireServer(ctx);
    const p = policy(
      {
        endpointRules: { allowedEndpoints: ["/drug/*"], allowedMethods: ["GET"] },
        fieldRules: { maskedFields: [{ field: "safetyreportid", maskType: "hash" }] },
      },
      { maxResults: 1 },
    );

    const body = (await wrapper().request(signed(p), {
      method: "GET",
      path: "/drug/event.json?limit=3",
      collectionPath: "results",
    })) as { results: Array<Record<string, unknown>> };

    expect(body.results.length).toBe(1);
    expect(body.results[0].safetyreportid).toMatch(/^[a-f0-9]{16}$/);
  });
});
