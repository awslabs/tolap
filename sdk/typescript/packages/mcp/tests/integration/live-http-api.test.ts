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
 * The server is started as a child process on a port the OS assigns (see
 * `freePort`), not a hard-coded one. A fixed port is a machine-wide resource: this
 * suite used to claim 8889, so a second copy of it or an orphan from a killed run
 * could not bind, and the whole file then skipped while still reporting green.
 *
 * Only an absent dependency skips -- no python3, or no server.py. A server that
 * should have started and did not throws, because a skip that reads as success is
 * how a suite silently stops testing anything.
 */

import { spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { createServer } from "node:net";
import { resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  buildSecurityContext,
  signContext,
  type EffectivePolicy,
  type SecurityContext,
} from "@aws/tolap-core";
import {
  MAX_REDIRECTS,
  SecureHttpToolWrapper,
  limitCollectionForTest,
  UpstreamHttpError,
  type FetchLike,
} from "../../src/http-wrapper.js";

const SIGNING_KEY = "live-http-api-key";
const REPO_ROOT = resolve(__dirname, "..", "..", "..", "..", "..", "..");
const SERVER = resolve(REPO_ROOT, "tools", "test-api", "server.py");

let child: ChildProcess | undefined;
let available = false;
/** Set once the OS has assigned a port; the wrapper's base URL derives from it. */
let baseUrl = "";

/**
 * Ask the OS for an unused loopback port by listening on port 0, then release it.
 *
 * Mirrors `_free_port()` in the Python suite's `test_live_http_api.py`. The port is
 * released before the child claims it, so another process could in principle take it
 * in between; the kernel does not reissue an ephemeral port that quickly, and a lost
 * race now fails loudly instead of skipping.
 */
function freePort(): Promise<number> {
  return new Promise((resolvePort, rejectPort) => {
    const server = createServer();
    server.once("error", rejectPort);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (address === null || typeof address === "string") {
        server.close(() => rejectPort(new Error("could not read the assigned port")));
        return;
      }
      const { port } = address;
      server.close(() => resolvePort(port));
    });
  });
}

async function probe(): Promise<boolean> {
  try {
    const response = await fetch(`${baseUrl}/healthz`, {
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
  // A missing checkout of the server script is an absent dependency, like a missing
  // python3: skip. Everything after this point is a real failure.
  if (!existsSync(SERVER)) return;

  const port = await freePort();
  baseUrl = `http://127.0.0.1:${port}`;

  // No probe for an already-running server: the port came from the OS moments ago,
  // so anything answering on it is not ours.
  child = spawn("python3", [SERVER, "--port", String(port)], {
    cwd: REPO_ROOT,
    stdio: "ignore",
  });

  // An absent python3 surfaces here as an `error` event rather than an exit code, and
  // it is the one failure that legitimately skips.
  let spawnError: Error | undefined;
  child.on("error", (error) => {
    spawnError = error;
  });

  for (let attempt = 0; attempt < 40; attempt++) {
    if (spawnError !== undefined) return; // leaves `available` false -> tests skip
    if (child.exitCode !== null) {
      throw new Error(
        `test API server exited with ${child.exitCode} on port ${port} before answering /healthz`,
      );
    }
    if (await probe()) {
      available = true;
      return;
    }
    await new Promise((r) => setTimeout(r, 100));
  }

  throw new Error(
    `test API server did not answer /healthz on port ${port} within 40 probes`,
  );
}, 20_000);

afterAll(() => {
  if (child && child.exitCode === null) child.kill("SIGTERM");
});

/**
 * Real-socket transport. Deliberately does not paper over a non-2xx status.
 *
 * `redirect` is forwarded straight to `fetch`, which is the whole point of the
 * parameter: `fetch` follows redirects by default, so without it a 302 to a denied
 * endpoint would be followed before the wrapper ever saw the hop (connector spec
 * §6). `headers` is surfaced so the wrapper can read `Location`, and `redirected`
 * so it can detect a transport that followed anyway.
 *
 * A 3xx body is not parsed: the wrapper is about to discard it in favour of the
 * hop it re-validates, and a bodiless 302 (the loop endpoint) has nothing to parse.
 */
const liveFetch: FetchLike = async ({ method, url, body, headers, redirect }) => {
  const response = await fetch(url, {
    method,
    redirect,
    headers: {
      "User-Agent": "tolap-ts-tests/1.0",
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      ...(headers ?? {}),
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    signal: AbortSignal.timeout(10_000),
  });
  const isRedirect = response.status >= 300 && response.status < 400;
  const parsed = isRedirect ? undefined : await response.json();
  return {
    ok: response.ok,
    status: response.status,
    json: async () => parsed,
    headers: response.headers,
    redirected: response.redirected,
    url: response.url,
  };
};

function policy(
  objectRules: EffectivePolicy["objectRules"],
  limits?: EffectivePolicy["limits"],
  permissions: EffectivePolicy["permissions"] = {
    canQuery: true,
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
  return new SecureHttpToolWrapper({ signingKey: SIGNING_KEY, baseUrl }, liveFetch);
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

  it("a maxResults above the result count leaves the body alone", async (ctx) => {
    requireServer(ctx);
    const body = (await wrapper().request(
      signed(policy(ALLOW_ALL_PATIENTS, { maxResults: 100 })),
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

    it(`the ${status} body runs the same pipeline as a success body`, async (ctx) => {
      requireServer(ctx);
      // LEAK: /status/<code> returns {"error": {"code": .., "message": ..}}, so
      // hiddenFields: ["error"] must empty it. The wrapper previously threw on
      // !response.ok before parsing, so the error payload was never enforced --
      // and the transport had already handed the caller a response object holding
      // it. Connector spec §6: "A 4xx/5xx payload carries the same fields as a
      // success payload."
      const p = policy({
        endpointRules: { allowedEndpoints: ["/status/*"], allowedMethods: ["GET"] },
        fieldRules: { hiddenFields: ["error"] },
      });

      const error = await wrapper()
        .request(signed(p), { method: "GET", path: `/status/${status}` })
        .then(
          () => undefined,
          (e: unknown) => e as UpstreamHttpError,
        );

      expect(error).toBeInstanceOf(UpstreamHttpError);
      expect(error!.status).toBe(status);
      expect(error!.body).toEqual({});
      expect(error!.message).not.toContain("synthetic");
    });
  }

  it("an error body is masked rather than returned in cleartext", async (ctx) => {
    requireServer(ctx);
    const p = policy({
      endpointRules: { allowedEndpoints: ["/status/*"], allowedMethods: ["GET"] },
      fieldRules: { maskedFields: [{ field: "message", maskType: "redact" }] },
    });

    const error = await wrapper()
      .request(signed(p), { method: "GET", path: "/status/400" })
      .then(
        () => undefined,
        (e: unknown) => e as UpstreamHttpError,
      );

    expect(error!.body).toEqual({ error: { code: 400, message: "[REDACTED]" } });
  });

  it("the record-dropping steps also reach an error body", async (ctx) => {
    requireServer(ctx);
    // The body {"error": {...}} is a single record (spec §4, "Single records"), and
    // a filter on a field it does not carry fails closed and drops it, so the
    // enforced body is null -- "the language's null value ... **not** an empty
    // record". Only observable if the record-dropping pass really ran -- a wrapper
    // that merely stripped fields from an error body would return the record.
    const p = policy({
      endpointRules: { allowedEndpoints: ["/status/*"], allowedMethods: ["GET"] },
      rowFilters: [{ field: "account", operator: "notEquals", value: "other" }],
    });

    const error = await wrapper()
      .request(signed(p), { method: "GET", path: "/status/404" })
      .then(
        () => undefined,
        (e: unknown) => e as UpstreamHttpError,
      );

    expect(error!.status).toBe(404);
    expect(error!.body).toBeNull();
  });

  it("the raised error exposes no route to the unenforced body", async (ctx) => {
    requireServer(ctx);
    // The point of enforcing an error body is defeated if the exception also ships
    // a handle on the raw one. UpstreamHttpError carries a status, an enforced body
    // and a URL, and nothing else.
    const p = policy({
      endpointRules: { allowedEndpoints: ["/status/*"], allowedMethods: ["GET"] },
      fieldRules: { hiddenFields: ["error"] },
    });

    const error = (await wrapper()
      .request(signed(p), { method: "GET", path: "/status/500" })
      .then(
        () => undefined,
        (e: unknown) => e,
      )) as UpstreamHttpError & Record<string, unknown>;

    expect(error.response).toBeUndefined();
    for (const value of Object.values(error)) {
      expect(JSON.stringify(value) ?? "").not.toContain("synthetic");
    }
  });

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
    // Permitting a write takes allowedMethods, readOnly: false, AND canInsert.
    // Three independent gates (canonical spec §9, connector spec §4 and §6):
    // allowedMethods makes the verb reachable on the path, readOnly is the ceiling
    // over every write, and canInsert is the permission for the operation POST
    // performs. None of the three implies another.
    const p = policy(
      {
        endpointRules: {
          allowedEndpoints: ["/patients"],
          allowedMethods: ["GET", "POST"],
        },
      },
      undefined,
      { canQuery: true, canInsert: true, readOnly: false },
    );

    const body = (await wrapper().request(signed(p), {
      method: "POST",
      path: "/patients",
      body: { full_name: "New Patient" },
    })) as { created: boolean; received: Record<string, unknown> };

    expect(body.created).toBe(true);
    expect(body.received.full_name).toBe("New Patient");
  });

  it("a POST is denied when canInsert is absent", async (ctx) => {
    requireServer(ctx);
    // The method is allowed and the policy is not read-only, so both of the older
    // gates open -- the only thing refusing this POST is the absent write
    // permission. Absent defaults to false (connector spec §4.1), deliberately
    // opposite to canQuery, so a policy authored before writes existed does not
    // silently acquire them. The server accepts POST /patients by design, so the
    // denial is TOLAP's work.
    const p = policy(
      {
        endpointRules: {
          allowedEndpoints: ["/patients"],
          allowedMethods: ["GET", "POST"],
        },
      },
      undefined,
      { canQuery: true, readOnly: false },
    );

    await expect(
      wrapper().request(signed(p), {
        method: "POST",
        path: "/patients",
        body: { full_name: "New Patient" },
      }),
    ).rejects.toThrow(/insert not permitted/);
  });

  it("a GET-only policy denies the POST before it reaches the socket", async (ctx) => {
    requireServer(ctx);
    // The server accepts POST /patients by design: the denial has to come from
    // TOLAP, so this asserts enforcement rather than server-side hiding.
    const p = policy(
      { endpointRules: { allowedEndpoints: ["/patients"], allowedMethods: ["GET"] } },
      undefined,
      { canQuery: true, readOnly: false },
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

// ---------------------------------------------------------------------------
// Redirects (connector spec §6) -- what a mock transport cannot catch
// ---------------------------------------------------------------------------

/**
 * `fetch` follows redirects by default, so this SDK was exposed right now: a
 * permitted endpoint that 302s to a denied one bypassed the endpoint check
 * entirely and the wrapper never saw the hop. Nothing in the wrapper configured
 * redirect behavior at all -- it inherited the transport's.
 *
 * These run over a real socket on purpose. A mock cannot reproduce the actual
 * failure mode, which is a client that follows a redirect before the wrapper's
 * code sees it.
 */
describe("spec §6: redirects are re-validated, never followed blind", () => {
  const REDIRECT_AND_ADMIN = {
    endpointRules: {
      allowedEndpoints: ["/redirect/*"],
      hiddenEndpoints: ["/admin/*"],
      allowedMethods: ["GET"],
    },
  } satisfies EffectivePolicy["objectRules"];

  it("LEAK: a redirect to a denied endpoint is refused, not followed", async (ctx) => {
    requireServer(ctx);
    // The server really serves /admin/audit, so a wrapper that followed the 302
    // handed back data the policy denies by name.
    await expect(
      wrapper().request(signed(policy(REDIRECT_AND_ADMIN)), {
        method: "GET",
        path: "/redirect/302",
      }),
    ).rejects.toThrow(/redirect target rejected: endpoint is hidden/);
  });

  it("the denial names the endpoint rule that refused the hop", async (ctx) => {
    requireServer(ctx);
    const p = policy({
      endpointRules: { allowedEndpoints: ["/redirect/*"], allowedMethods: ["GET"] },
    });

    await expect(
      wrapper().request(signed(p), { method: "GET", path: "/redirect/302" }),
    ).rejects.toThrow(/endpoint not in allowed set/);
  });

  for (const code of [301, 302, 307, 308]) {
    it(`a ${code} is re-validated like every other redirect`, async (ctx) => {
      requireServer(ctx);
      // 307/308 preserve the method and body; 301/302 downgrade to GET. Both
      // re-check, so neither shape is a way past the rules.
      await expect(
        wrapper().request(signed(policy(REDIRECT_AND_ADMIN)), {
          method: "GET",
          path: `/redirect/${code}`,
        }),
      ).rejects.toThrow(/endpoint is hidden/);
    });
  }

  it("a redirect to a permitted endpoint is followed and the body enforced", async (ctx) => {
    requireServer(ctx);
    // Re-validating is not refusing. And the followed hop's body still runs the
    // full pipeline, so a redirect is not a way around field rules either.
    const p = policy({
      endpointRules: {
        allowedEndpoints: ["/redirect/*", "/patients"],
        allowedMethods: ["GET"],
      },
      fieldRules: { hiddenFields: ["ssn"] },
    });

    const body = (await wrapper().request(signed(p), {
      method: "GET",
      path: "/redirect/302?to=%2Fpatients",
      collectionPath: "results",
    })) as { results: Array<Record<string, unknown>> };

    expect(body.results.length).toBeGreaterThan(0);
    for (const record of body.results) {
      expect(record.ssn).toBeUndefined();
    }
  });

  it("a cross-host redirect is refused rather than re-globbed", async (ctx) => {
    requireServer(ctx);
    // `allowedEndpoints: ["/*"]` describes paths on the source this policy was
    // resolved for. Matching that glob against a path on another host would
    // "permit" an origin the author never considered, so the hop is refused on the
    // host change rather than re-globbed on the path.
    const p = policy({
      endpointRules: { allowedEndpoints: ["/*", "/**"], allowedMethods: ["GET"] },
    });

    await expect(
      wrapper().request(signed(p), {
        method: "GET",
        path: "/redirect/302?to=http%3A%2F%2F127.0.0.1%3A9%2Fblocked",
      }),
    ).rejects.toThrow(/redirect crosses origin/);
  });

  it("a redirect loop is bounded rather than followed forever", async (ctx) => {
    requireServer(ctx);
    // /redirect-loop points at itself. The hop budget has to be ours, not the
    // transport's: every client's own limit differs (fetch 20, httpx 20, .NET 50).
    // The target is permitted at every hop, which makes this the bound's test
    // rather than the endpoint rules'.
    const p = policy({
      endpointRules: { allowedEndpoints: ["/redirect-loop"], allowedMethods: ["GET"] },
    });

    await expect(
      wrapper().request(signed(p), { method: "GET", path: "/redirect-loop" }),
    ).rejects.toThrow(/too many redirects \(limit 5\)/);
  });

  it("the hop budget permits a chain up to the limit and denies one past it", async (ctx) => {
    requireServer(ctx);
    // Pins the number rather than merely "some bound exists", so the three SDKs
    // can be asserted identical.
    expect(MAX_REDIRECTS).toBe(5);

    const p = policy({
      endpointRules: {
        allowedEndpoints: ["/redirect/*", "/patients"],
        allowedMethods: ["GET"],
      },
    });

    /** A chain of `hops` redirects ending at /patients. */
    const chain = (hops: number): string => {
      let target = "/patients";
      for (let i = 0; i < hops; i++) {
        target = `/redirect/302?to=${encodeURIComponent(target)}`;
      }
      return target;
    };

    const body = (await wrapper().request(signed(p), {
      method: "GET",
      path: chain(MAX_REDIRECTS),
      collectionPath: "results",
    })) as { results: unknown[] };
    expect(body.results.length).toBeGreaterThan(0);

    await expect(
      wrapper().request(signed(p), { method: "GET", path: chain(MAX_REDIRECTS + 1) }),
    ).rejects.toThrow(/too many redirects/);
  });

  it("a transport that follows a redirect anyway is refused, not enforced", async (ctx) => {
    requireServer(ctx);
    // The specific inheritance §6 forbids relying on. This transport ignores
    // `redirect: "manual"` and follows -- exactly what plain `fetch` does by
    // default. The body it returns came from a hop no check approved, so the
    // wrapper refuses it rather than enforcing it and calling that safe.
    const followingFetch: FetchLike = async ({ method, url, body, headers }) => {
      const response = await fetch(url, {
        method,
        redirect: "follow",
        headers: headers ?? {},
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
        signal: AbortSignal.timeout(10_000),
      });
      const parsed = await response.json();
      return {
        ok: response.ok,
        status: response.status,
        json: async () => parsed,
        headers: response.headers,
        redirected: response.redirected,
        url: response.url,
      };
    };
    const following = new SecureHttpToolWrapper(
      { signingKey: SIGNING_KEY, baseUrl },
      followingFetch,
    );

    await expect(
      following.request(signed(policy(REDIRECT_AND_ADMIN)), {
        method: "GET",
        path: "/redirect/302",
      }),
    ).rejects.toThrow(/transport followed a redirect that was not re-validated/);

    // The transport really does follow: used directly it lands on the audit log.
    const direct = await fetch(`${baseUrl}/redirect/302`);
    expect(new URL(direct.url).pathname).toBe("/admin/audit");
  });
});

// ---------------------------------------------------------------------------
// Object rules on the HTTP path (connector spec §6, last bullet)
// ---------------------------------------------------------------------------

/**
 * No resource name is derived from a path -- the spec is explicit that an author
 * "MUST express API restrictions as `endpointRules`", and inferring a resource from
 * a route is unspecified guesswork. But an integrator who names the object gets the
 * check, on every method rather than only on a write.
 */
describe("spec §6: allowedObjects/hiddenObjects are honoured when named", () => {
  const ALLOW_ALL_GET = {
    allowedEndpoints: ["/*", "/**"],
    allowedMethods: ["GET"],
  };

  it("a hidden object named by the caller denies a GET", async (ctx) => {
    requireServer(ctx);
    const p = policy({ endpointRules: ALLOW_ALL_GET, hiddenObjects: ["patients"] });

    await expect(
      wrapper().request(signed(p), {
        method: "GET",
        path: "/patients",
        objectName: "patients",
      }),
    ).rejects.toThrow(/object is hidden/);
  });

  it("an object outside the allow-list denies a GET", async (ctx) => {
    requireServer(ctx);
    const p = policy({ endpointRules: ALLOW_ALL_GET, allowedObjects: ["encounters"] });

    await expect(
      wrapper().request(signed(p), {
        method: "GET",
        path: "/patients",
        objectName: "patients",
      }),
    ).rejects.toThrow(/object not in allowed set/);
  });

  it("a permitted object name still returns an enforced body", async (ctx) => {
    requireServer(ctx);
    const p = policy({
      endpointRules: ALLOW_ALL_GET,
      allowedObjects: ["patients"],
      fieldRules: { hiddenFields: ["ssn"] },
    });

    const body = (await wrapper().request(signed(p), {
      method: "GET",
      path: "/patients",
      objectName: "patients",
      collectionPath: "results",
    })) as { results: Array<Record<string, unknown>> };

    expect(body.results.length).toBeGreaterThan(0);
    for (const record of body.results) expect(record.ssn).toBeUndefined();
  });

  it("omitting the object name skips the check rather than guessing", async (ctx) => {
    requireServer(ctx);
    // A wrapper that derived "patients" from /patients would deny this, which is
    // exactly the unspecified behaviour §6 marks with a warning.
    const p = policy({ endpointRules: ALLOW_ALL_GET, hiddenObjects: ["patients"] });

    const body = (await wrapper().request(signed(p), {
      method: "GET",
      path: "/patients",
      collectionPath: "results",
    })) as { results: unknown[] };

    expect(body.results.length).toBeGreaterThan(0);
  });

  it("a redirect hop re-checks the named object", async (ctx) => {
    requireServer(ctx);
    const p = policy({
      endpointRules: {
        allowedEndpoints: ["/redirect/*", "/patients"],
        allowedMethods: ["GET"],
      },
      hiddenObjects: ["patients"],
    });

    await expect(
      wrapper().request(signed(p), {
        method: "GET",
        path: "/redirect/302?to=%2Fpatients",
        objectName: "patients",
      }),
    ).rejects.toThrow(/object is hidden/);
  });
});

// ---------------------------------------------------------------------------
// The limit when the caller does not name the collection (spec §6)
// ---------------------------------------------------------------------------

/**
 * `maxResults` when the caller omits `collectionPath`.
 *
 * These exist because a fail-open shipped in all three SDKs and the `api` suites did not catch
 * it. Every existing `maxResults` test passed `collectionPath`, because that is what the
 * implementation wanted -- so the branch taken when it is *omitted* was never executed, and
 * `maxResults: 1` against an enveloped body returned every record the upstream sent.
 *
 * `collectionPath` is optional. An integrator reading "post-response: the full pipeline over the
 * body, walking nested structures" has no reason to pass it, gets no warning, and their limit
 * silently does nothing. That usage is what these tests encode.
 *
 * What made the omission dangerous rather than merely surprising is that the three record-level
 * controls disagreed on it: projection and row filtering fail-closed, only the limit failed open.
 */
describe("spec §6: maxResults without an explicit collectionPath", () => {
  it("REGRESSION: an enveloped body is limited (was: every record returned)", async (ctx) => {
    requireServer(ctx);
    // collectionPath deliberately NOT passed -- this is the integrator's call.
    const body = (await wrapper().request(signed(policy(ALLOW_ALL_PATIENTS, { maxResults: 1 })), {
      method: "GET",
      path: "/patients",
    })) as { results: unknown[] };

    expect(body.results.length).toBe(1);
  });

  it("CONTROL: the upstream really returns more than one record", async (ctx) => {
    requireServer(ctx);
    const raw = (await (await fetch(`${baseUrl}/patients`)).json()) as { results: unknown[] };

    expect(raw.results.length).toBeGreaterThan(1);
  });

  it("a differently-named collection is still enforced", async (ctx) => {
    requireServer(ctx);
    // The key is discovered, not assumed to be "results". openFDA uses `results`,
    // ClinicalTrials.gov uses `studies`, this endpoint uses `items` -- recognising only one of
    // them would be the same bug wearing a different hat.
    const body = (await wrapper().request(signed(policy(ALLOW_ALL_PATIENTS, { maxResults: 2 })), {
      method: "GET",
      path: "/patients/envelope",
    })) as { items: unknown[]; total: number };

    expect(body.items.length).toBe(2);
    expect(body.total, "a paging counter is not a record collection").toBe(5);
  });

  it("two candidate collections throw rather than guess", async (ctx) => {
    requireServer(ctx);
    // Guessing would be worse than the original bug: enforcing on the wrong array looks like
    // success.
    const p = policy(ALLOW_ALL_PATIENTS, { maxResults: 1 });
    const body = { results: [{ id: 1 }, { id: 2 }], studies: [{ id: 3 }, { id: 4 }] };

    expect(() => limitCollectionForTest(body, undefined, p)).toThrow(/collectionPath/);
  });

  it("a body with no record collection is left alone", async (ctx) => {
    requireServer(ctx);
    const p = policy(ALLOW_ALL_PATIENTS, { maxResults: 1 });

    expect(limitCollectionForTest({ meta: { count: 0 } }, undefined, p)).toEqual({
      meta: { count: 0 },
    });
  });

  it("the record-level controls agree when the path is omitted", async (ctx) => {
    requireServer(ctx);
    // The property whose absence let the fail-open through. Each control was tested alone, with
    // collectionPath supplied, so the disagreement between them was invisible.
    const raw = (await (await fetch(`${baseUrl}/patients`)).json()) as { results: unknown[] };
    const upstream = raw.results.length;
    expect(upstream).toBeGreaterThan(1);

    const limited = (await wrapper().request(
      signed(policy(ALLOW_ALL_PATIENTS, { maxResults: 1 })),
      { method: "GET", path: "/patients" },
    )) as { results: unknown[] };

    expect(limited.results.length).toBeLessThan(upstream);
  });
});
