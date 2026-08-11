/**
 * Branch coverage for http-wrapper.ts, using an in-process transport so every
 * conditional -- including the ones a real server would never produce -- can be
 * driven from both sides.
 *
 * The real-socket counterpart lives in tests/integration/live-http-api.test.ts; that
 * file proves the shipped code path works against genuine bytes, this one reaches
 * the collection-path and option edges a live server cannot be made to emit.
 * Everything asserted here is a spec-mandated outcome, not just a visited line.
 */

import { describe, expect, it, vi } from "vitest";

import {
  buildSecurityContext,
  signContext,
  type EffectivePolicy,
  type SecurityContext,
} from "@aws/tolap-core";
import { SecureHttpToolWrapper, type FetchLike } from "../src/http-wrapper.js";

const KEY = "http-branch-key";

function policy(
  objectRules?: EffectivePolicy["objectRules"],
  limits?: EffectivePolicy["limits"],
  permissions: EffectivePolicy["permissions"] = {
    canQuery: true,
    readOnly: true,
  },
): EffectivePolicy {
  const now = new Date();
  return {
    version: "1.0",
    userId: "user-001",
    tenantId: "tenant-001",
    sourceConnectionId: "api:internal:test",
    resolvedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 3_600_000).toISOString(),
    sourceProfiles: ["http-branches"],
    permissions,
    ...(objectRules !== undefined ? { objectRules } : {}),
    ...(limits !== undefined ? { limits } : {}),
    integrity: { algorithm: "none", signature: "" },
  };
}

function signed(p: EffectivePolicy, ttlMs = 3_600_000): SecurityContext {
  return signContext(buildSecurityContext(p.userId, p.tenantId, p, ttlMs), KEY);
}

/** A transport that always returns `body`, recording what it was asked for. */
function stubFetch(body: unknown, ok = true, status = 200) {
  const calls: Array<Parameters<FetchLike>[0]> = [];
  const fetchFn: FetchLike = async (input) => {
    calls.push(input);
    return { ok, status, json: async () => body };
  };
  return { fetchFn, calls };
}

function wrapper(
  body: unknown,
  options: Partial<ConstructorParameters<typeof SecureHttpToolWrapper>[0]> = {},
) {
  const { fetchFn, calls } = stubFetch(body);
  return {
    instance: new SecureHttpToolWrapper({ signingKey: KEY, ...options }, fetchFn),
    calls,
  };
}

const GET_ANY = {
  endpointRules: { allowedEndpoints: ["/*", "/**"], allowedMethods: ["GET"] },
} satisfies EffectivePolicy["objectRules"];

// ---------------------------------------------------------------------------
// validateSecurityContext -- all four combinations of the two toggles
// ---------------------------------------------------------------------------

describe("validateSecurityContext: both toggles, both ways", () => {
  const unsigned = (): SecurityContext =>
    buildSecurityContext("user-001", "tenant-001", policy(), 3_600_000);

  it("with both enforced, a valid context is allowed", () => {
    const { instance } = wrapper({});
    expect(instance.validateSecurityContext(signed(policy()))).toEqual({ allowed: true });
  });

  it("with both enforced, an unsigned context is denied on the signature", () => {
    const { instance } = wrapper({});
    expect(instance.validateSecurityContext(unsigned())).toEqual({
      allowed: false,
      reason: "invalid signature",
    });
  });

  it("enforceSignatures: false accepts an unsigned context (and is a real bypass)", () => {
    // Documented opt-out. Asserting it explicitly matters: this is the setting that
    // turns signature verification off entirely, so its behavior must be pinned
    // rather than assumed.
    const { instance } = wrapper({}, { enforceSignatures: false });
    expect(instance.validateSecurityContext(unsigned())).toEqual({ allowed: true });
  });

  it("enforceSignatures: false still enforces expiry", () => {
    const { instance } = wrapper({}, { enforceSignatures: false });
    const expired = buildSecurityContext("u", "t", policy(), -1000);
    expect(instance.validateSecurityContext(expired)).toEqual({
      allowed: false,
      reason: "security context expired",
    });
  });

  it("enforceExpiry: false accepts an expired but correctly signed context", () => {
    const { instance } = wrapper({}, { enforceExpiry: false });
    expect(instance.validateSecurityContext(signed(policy(), -1000))).toEqual({
      allowed: true,
    });
  });

  it("enforceExpiry: false still enforces the signature", () => {
    const { instance } = wrapper({}, { enforceExpiry: false });
    expect(instance.validateSecurityContext(unsigned())).toEqual({
      allowed: false,
      reason: "invalid signature",
    });
  });

  it("with both disabled, an unsigned expired context is allowed", () => {
    const { instance } = wrapper(
      {},
      { enforceSignatures: false, enforceExpiry: false },
    );
    expect(
      instance.validateSecurityContext(buildSecurityContext("u", "t", policy(), -1000)),
    ).toEqual({ allowed: true });
  });

  it("a missing expiry is a denial, never 'never expires' (spec §2)", () => {
    const { instance } = wrapper({});
    const ctx: SecurityContext = {
      effectivePolicy: policy(),
      resolvedAt: new Date().toISOString(),
      expiresAt: "",
    };
    signContext(ctx, KEY);

    expect(instance.validateSecurityContext(ctx)).toEqual({
      allowed: false,
      reason: "security context has no expiry",
    });
  });

  it("an unparseable expiry is a denial, not a skipped check", () => {
    const { instance } = wrapper({});
    const ctx: SecurityContext = {
      effectivePolicy: policy(),
      resolvedAt: new Date().toISOString(),
      expiresAt: "never",
    };
    signContext(ctx, KEY);

    expect(instance.validateSecurityContext(ctx)).toEqual({
      allowed: false,
      reason: "invalid expiry format",
    });
  });
});

// ---------------------------------------------------------------------------
// request(): the pre-call gates, each short-circuiting before the transport
// ---------------------------------------------------------------------------

describe("request: pre-call gates short-circuit before the transport", () => {
  it("a context denial throws and never calls fetch", async () => {
    const { instance, calls } = wrapper({ results: [] });
    await expect(
      instance.request(buildSecurityContext("u", "t", policy(GET_ANY), 3_600_000), {
        method: "GET",
        path: "/x",
      }),
    ).rejects.toThrow(/Access denied: invalid signature/);
    expect(calls).toEqual([]);
  });

  it("canQuery: false throws and never calls fetch", async () => {
    const p = policy(GET_ANY, undefined, { canQuery: false });
    const { instance, calls } = wrapper({ results: [] });

    await expect(
      instance.request(signed(p), { method: "GET", path: "/x" }),
    ).rejects.toThrow(/query not permitted/);
    expect(calls).toEqual([]);
  });

  it("an endpoint denial throws and never calls fetch", async () => {
    const p = policy({
      endpointRules: { allowedEndpoints: ["/allowed"], allowedMethods: ["GET"] },
    });
    const { instance, calls } = wrapper({ results: [] });

    await expect(
      instance.request(signed(p), { method: "GET", path: "/denied" }),
    ).rejects.toThrow(/endpoint not in allowed set/);
    expect(calls).toEqual([]);
  });

  it("a non-ok response throws with the status and the resolved url", async () => {
    const { fetchFn } = stubFetch({ error: "x" }, false, 503);
    const instance = new SecureHttpToolWrapper(
      { signingKey: KEY, baseUrl: "https://example.test" },
      fetchFn,
    );

    await expect(
      instance.request(signed(policy(GET_ANY)), { method: "GET", path: "/x" }),
    ).rejects.toThrow("HTTP 503 from https://example.test/x");
  });
});

describe("request: url assembly and query-string handling", () => {
  it("baseUrl is prefixed when set and omitted when absent", async () => {
    const withBase = wrapper({}, { baseUrl: "https://example.test" });
    await withBase.instance.request(signed(policy(GET_ANY)), { method: "GET", path: "/x" });
    expect(withBase.calls[0].url).toBe("https://example.test/x");

    const withoutBase = wrapper({});
    await withoutBase.instance.request(signed(policy(GET_ANY)), {
      method: "GET",
      path: "/x",
    });
    expect(withoutBase.calls[0].url).toBe("/x");
  });

  it("the query string is stripped for policy matching but kept on the wire", async () => {
    // Policy patterns are written against paths. Without stripping,
    // "/drug/event.json?limit=3" would not match an "/drug/*" allow-pattern.
    const p = policy({
      endpointRules: { allowedEndpoints: ["/drug/*"], allowedMethods: ["GET"] },
    });
    const { instance, calls } = wrapper({}, { baseUrl: "https://example.test" });

    await instance.request(signed(p), { method: "GET", path: "/drug/event.json?limit=3" });

    expect(calls[0].url).toBe("https://example.test/drug/event.json?limit=3");
  });

  it("a path with no query string takes the other branch and still matches", async () => {
    const p = policy({
      endpointRules: { allowedEndpoints: ["/drug/*"], allowedMethods: ["GET"] },
    });
    const { instance, calls } = wrapper({});

    await instance.request(signed(p), { method: "GET", path: "/drug/event.json" });
    expect(calls[0].url).toBe("/drug/event.json");
  });

  it("a query string cannot smuggle a denied path past the allow-list", async () => {
    // "/allowed?x=1" matches; "/denied?path=/allowed" must NOT.
    const p = policy({
      endpointRules: { allowedEndpoints: ["/allowed"], allowedMethods: ["GET"] },
    });
    const { instance, calls } = wrapper({});

    await expect(
      instance.request(signed(p), { method: "GET", path: "/denied?path=/allowed" }),
    ).rejects.toThrow(/endpoint not in allowed set/);
    expect(calls).toEqual([]);
  });

  it("method and headers are passed through to the transport", async () => {
    // Three gates have to open for a POST, and none implies another:
    // allowedMethods makes the verb reachable, readOnly: false lifts the ceiling
    // (canonical spec §9), and canInsert grants the operation POST performs
    // (connector spec §4.1 and §6). canInsert defaults to false when absent, so it
    // must be stated explicitly.
    const p = policy(
      { endpointRules: { allowedEndpoints: ["/x"], allowedMethods: ["GET", "POST"] } },
      undefined,
      { canQuery: true, canInsert: true, readOnly: false },
    );
    const { instance, calls } = wrapper({});

    await instance.request(signed(p), {
      method: "POST",
      path: "/x",
      body: { a: 1 },
      headers: { "X-Probe": "1" },
    });

    expect(calls[0].method).toBe("POST");
    expect(calls[0].body).toEqual({ a: 1 });
    expect(calls[0].headers).toEqual({ "X-Probe": "1" });
  });

  it("an absent body and absent headers are forwarded as undefined", async () => {
    const { instance, calls } = wrapper({});
    await instance.request(signed(policy(GET_ANY)), { method: "GET", path: "/x" });

    expect(calls[0].body).toBeUndefined();
    expect(calls[0].headers).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// The record-dropping steps and their collectionPath resolution
// ---------------------------------------------------------------------------

describe("record-dropping steps: collectionPath resolution", () => {
  const filterUsEast = {
    ...GET_ANY,
    rowFilters: [{ field: "region", operator: "equals", value: "us-east" }],
  } satisfies EffectivePolicy["objectRules"];

  const request = async (
    body: unknown,
    objectRules: EffectivePolicy["objectRules"],
    collectionPath?: string,
    limits?: EffectivePolicy["limits"],
  ) => {
    const { instance } = wrapper(body);
    return instance.request(signed(policy(objectRules, limits)), {
      method: "GET",
      path: "/x",
      ...(collectionPath !== undefined ? { collectionPath } : {}),
    });
  };

  it("with no collectionPath, a body that IS an array is filtered", async () => {
    const out = (await request(
      [{ id: 1, region: "us-east" }, { id: 2, region: "eu-west" }],
      filterUsEast,
    )) as Array<Record<string, unknown>>;

    expect(out.map((r) => r.id)).toEqual([1]);
  });

  it("with no collectionPath, a body that is a single RECORD is filtered", async () => {
    // A single record runs the identical filters and becomes `null` when dropped
    // (spec §4, "Single records"): "the result is the language's null value ... **not**
    // an empty record", because an empty collection implies the caller asked for a list.
    // This previously asserted `[]`, which was a third answer to the same body: Python
    // returned `None` and .NET returned the record unfiltered. All three now agree on
    // the spelling the spec names.
    expect(await request({ id: 1, region: "eu-west" }, filterUsEast)).toBeNull();
    expect(await request({ id: 1, region: "us-east" }, filterUsEast)).toEqual({
      id: 1,
      region: "us-east",
    });
  });

  it("with no collectionPath, a scalar body passes through unchanged", async () => {
    expect(await request("just a string", filterUsEast)).toBe("just a string");
    expect(await request(42, filterUsEast)).toBe(42);
    expect(await request(null, filterUsEast)).toBeNull();
  });

  it("a single-segment collectionPath filters the named array", async () => {
    const out = (await request(
      { results: [{ id: 1, region: "us-east" }, { id: 2, region: "eu-west" }], meta: { total: 2 } },
      filterUsEast,
      "results",
    )) as { results: Array<Record<string, unknown>>; meta: { total: number } };

    expect(out.results.map((r) => r.id)).toEqual([1]);
    // The envelope survives -- filtering targets records, not paging metadata.
    expect(out.meta).toEqual({ total: 2 });
  });

  it("a nested collectionPath walks each segment", async () => {
    const out = (await request(
      { data: { rows: [{ id: 1, region: "us-east" }, { id: 2, region: "eu-west" }] } },
      filterUsEast,
      "data.rows",
    )) as { data: { rows: Array<Record<string, unknown>> } };

    expect(out.data.rows.map((r) => r.id)).toEqual([1]);
  });

  it("a collectionPath whose intermediate segment is missing leaves the body alone", async () => {
    const body = { other: { rows: [{ id: 1, region: "eu-west" }] } };
    expect(await request(body, filterUsEast, "data.rows")).toEqual(body);
  });

  it("a collectionPath whose intermediate segment is not an object leaves the body alone", async () => {
    const body = { data: "not an object" };
    expect(await request(body, filterUsEast, "data.rows")).toEqual(body);
  });

  it("a collectionPath whose leaf is absent or not an array leaves the body alone", async () => {
    expect(await request({ results: "not an array" }, filterUsEast, "results")).toEqual({
      results: "not an array",
    });
    expect(await request({ other: [] }, filterUsEast, "results")).toEqual({ other: [] });
  });

  it("non-record entries inside the collection are dropped, not passed through", async () => {
    // A scalar cannot be evaluated against a field rule, so it fails closed.
    const out = (await request(
      { results: [{ id: 1, region: "us-east" }, "a string", 42, null] },
      filterUsEast,
      "results",
    )) as { results: Array<Record<string, unknown>> };

    expect(out.results).toEqual([{ id: 1, region: "us-east" }]);
  });

  it("with NO dropping rules at all the body is returned untouched", async () => {
    const body = { results: [{ id: 1 }, { id: 2 }] };
    expect(await request(body, GET_ANY, "results")).toEqual(body);
  });

  it("tagRules present but with empty arrays still constrains", async () => {
    // Presence, not truthiness: allowedTags: [] is deny-all (spec §3).
    const denyAll = { ...GET_ANY, tagRules: { allowedTags: [] } };
    const out = (await request(
      { results: [{ id: 1, tags: ["public"] }] },
      denyAll,
      "results",
    )) as { results: unknown[] };

    expect(out.results).toEqual([]);
  });

  it("an empty deniedTags list denies nothing", async () => {
    const out = (await request(
      { results: [{ id: 1, tags: ["public"] }] },
      { ...GET_ANY, tagRules: { deniedTags: [] } },
      "results",
    )) as { results: unknown[] };

    expect(out.results).toHaveLength(1);
  });

  it("the relevance floor keeps a scoring record and drops a low one", async () => {
    const out = (await request(
      { results: [{ id: 1, score: 0.9 }, { id: 2, score: 0.1 }, { id: 3 }] },
      GET_ANY,
      "results",
      { minSimilarityScore: 0.5 },
    )) as { results: Array<Record<string, unknown>> };

    // id 3 has no score, so its relevance cannot be established: dropped.
    expect(out.results.map((r) => r.id)).toEqual([1]);
  });

  it("the size ceiling keeps a small record and drops a large or unsized one", async () => {
    const out = (await request(
      { results: [{ id: 1, size: 100 }, { id: 2, size: 99_999 }, { id: 3 }] },
      GET_ANY,
      "results",
      { maxObjectSizeBytes: 1000 },
    )) as { results: Array<Record<string, unknown>> };

    expect(out.results.map((r) => r.id)).toEqual([1]);
  });

  it("the caller's body object is not mutated by filtering", async () => {
    const body = { results: [{ id: 1, region: "us-east" }, { id: 2, region: "eu-west" }] };
    await request(body, filterUsEast, "results");
    expect(body.results).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// projectAllowedFieldsInBody
// ---------------------------------------------------------------------------

describe("allowedFields projection in the body", () => {
  const project = (allowedFields: string[] | undefined) =>
    ({
      ...GET_ANY,
      ...(allowedFields !== undefined ? { fieldRules: { allowedFields } } : {}),
    }) satisfies EffectivePolicy["objectRules"];

  const request = async (
    body: unknown,
    allowedFields: string[] | undefined,
    collectionPath?: string,
  ) => {
    const { instance } = wrapper(body);
    return instance.request(signed(policy(project(allowedFields))), {
      method: "GET",
      path: "/x",
      ...(collectionPath !== undefined ? { collectionPath } : {}),
    });
  };

  it("an undefined allow-list leaves the body untouched", async () => {
    const body = { results: [{ id: 1, ssn: "x" }] };
    expect(await request(body, undefined, "results")).toEqual(body);
  });

  it("an allow-list trims the records but preserves the envelope", async () => {
    const out = (await request(
      { results: [{ id: 1, ssn: "x" }], meta: { total: 1 } },
      ["id"],
      "results",
    )) as { results: unknown[]; meta: unknown };

    expect(out.results).toEqual([{ id: 1 }]);
    expect(out.meta).toEqual({ total: 1 });
  });

  it("an EMPTY allow-list denies every field (spec §3)", async () => {
    const out = (await request({ results: [{ id: 1, ssn: "x" }] }, [], "results")) as {
      results: unknown[];
    };
    expect(out.results).toEqual([{}]);
  });

  it("with no collectionPath, an array body and a record body are both projected", async () => {
    expect(await request([{ id: 1, ssn: "x" }], ["id"])).toEqual([{ id: 1 }]);
    expect(await request({ id: 1, ssn: "x" }, ["id"])).toEqual({ id: 1 });
  });

  it("with no collectionPath, a scalar body passes through", async () => {
    expect(await request("scalar", ["id"])).toBe("scalar");
    expect(await request(42, ["id"])).toBe(42);
  });

  it("a nested collectionPath is walked", async () => {
    const out = (await request(
      { data: { rows: [{ id: 1, ssn: "x" }] } },
      ["id"],
      "data.rows",
    )) as { data: { rows: unknown[] } };
    expect(out.data.rows).toEqual([{ id: 1 }]);
  });

  it("a missing intermediate segment or non-array leaf leaves the body alone", async () => {
    expect(await request({ other: {} }, ["id"], "data.rows")).toEqual({ other: {} });
    expect(await request({ data: 1 }, ["id"], "data.rows")).toEqual({ data: 1 });
    expect(await request({ results: "no" }, ["id"], "results")).toEqual({ results: "no" });
  });
});

// ---------------------------------------------------------------------------
// limitCollection
// ---------------------------------------------------------------------------

describe("result limit in the body", () => {
  const request = async (
    body: unknown,
    maxResults: number | undefined,
    collectionPath?: string,
  ) => {
    const { instance } = wrapper(body);
    return instance.request(
      signed(policy(GET_ANY, maxResults === undefined ? {} : { maxResults })),
      {
        method: "GET",
        path: "/x",
        ...(collectionPath !== undefined ? { collectionPath } : {}),
      },
    );
  };

  it("an absent maxResults leaves the body untouched", async () => {
    const body = { results: [{ id: 1 }, { id: 2 }, { id: 3 }] };
    expect(await request(body, undefined, "results")).toEqual(body);
  });

  it("maxResults truncates the named collection", async () => {
    const out = (await request(
      { results: [{ id: 1 }, { id: 2 }, { id: 3 }] },
      2,
      "results",
    )) as { results: unknown[] };
    expect(out.results).toHaveLength(2);
  });

  it("maxResults 0 truncates to nothing rather than being ignored as falsy", async () => {
    const out = (await request({ results: [{ id: 1 }] }, 0, "results")) as {
      results: unknown[];
    };
    expect(out.results).toEqual([]);
  });

  it("with no collectionPath, an array body is limited and a record body is not", async () => {
    expect(await request([{ id: 1 }, { id: 2 }], 1)).toHaveLength(1);
    // A single record is not a collection, so there is nothing to truncate.
    expect(await request({ id: 1 }, 1)).toEqual({ id: 1 });
  });

  it("a nested collectionPath is walked", async () => {
    const out = (await request({ data: { rows: [{ id: 1 }, { id: 2 }] } }, 1, "data.rows")) as {
      data: { rows: unknown[] };
    };
    expect(out.data.rows).toHaveLength(1);
  });

  it("a missing intermediate segment or non-array leaf leaves the body alone", async () => {
    expect(await request({ other: {} }, 1, "data.rows")).toEqual({ other: {} });
    expect(await request({ data: "x" }, 1, "data.rows")).toEqual({ data: "x" });
    expect(await request({ results: "x" }, 1, "results")).toEqual({ results: "x" });
  });

  it("the limit runs LAST, after filtering", async () => {
    // Limiting first would yield zero rows here.
    const { instance } = wrapper({
      results: [
        { id: 1, region: "eu-west" },
        { id: 2, region: "eu-west" },
        { id: 3, region: "us-east" },
        { id: 4, region: "us-east" },
      ],
    });
    const out = (await instance.request(
      signed(
        policy(
          {
            ...GET_ANY,
            rowFilters: [{ field: "region", operator: "equals", value: "us-east" }],
          },
          { maxResults: 2 },
        ),
      ),
      { method: "GET", path: "/x", collectionPath: "results" },
    )) as { results: Array<Record<string, unknown>> };

    expect(out.results.map((r) => r.id)).toEqual([3, 4]);
  });
});

// ---------------------------------------------------------------------------
// Masking through the shared core walker
// ---------------------------------------------------------------------------

describe("masking delegates to the shared core walker", () => {
  const request = async (body: unknown, maskedFields: unknown[]) => {
    const { instance } = wrapper(body);
    return instance.request(
      signed(
        policy({
          ...GET_ANY,
          fieldRules: {
            maskedFields: maskedFields as NonNullable<
              NonNullable<EffectivePolicy["objectRules"]>["fieldRules"]
            >["maskedFields"],
          },
        }),
      ),
      { method: "GET", path: "/x", collectionPath: "results" },
    );
  };

  it("an absent or empty maskedFields list leaves the body untouched", async () => {
    const body = { results: [{ ssn: "111-22-3333" }] };
    const { instance } = wrapper(body);
    expect(
      await instance.request(signed(policy(GET_ANY)), {
        method: "GET",
        path: "/x",
        collectionPath: "results",
      }),
    ).toEqual(body);
    expect(await request(body, [])).toEqual(body);
  });

  it("a BARE rule reaches a nested key, matching the DB/MCP path", async () => {
    // The drift this closes: a wrapper-local path walker only matched the literal
    // dotted path from the root, so a bare `ssn` rule missed
    // `results[].demographics.ssn` and returned the SSN in cleartext over HTTP.
    const out = (await request(
      { results: [{ demographics: { ssn: "111-22-3333", name: "A" } }] },
      [{ field: "ssn", maskType: "redact" }],
    )) as { results: Array<{ demographics: Record<string, unknown> }> };

    expect(out.results[0].demographics.ssn).toBe("[REDACTED]");
    expect(out.results[0].demographics.name).toBe("A");
  });

  it("a dotted rule still works", async () => {
    const out = (await request(
      { results: [{ patient: { ssn: "x" } }] },
      [{ field: "patient.ssn", maskType: "null" }],
    )) as { results: Array<{ patient: Record<string, unknown> }> };

    expect(out.results[0].patient.ssn).toBeNull();
  });

  it("an unknown maskType redacts rather than returning the raw value", async () => {
    const out = (await request({ results: [{ ssn: "111-22-3333" }] }, [
      { field: "ssn", maskType: "tokenize-v2" },
    ])) as { results: Array<Record<string, unknown>> };

    expect(out.results[0].ssn).toBe("[REDACTED]");
  });

  it("hidden wins over masked for the same field", async () => {
    const { instance } = wrapper({ results: [{ id: 1, ssn: "x" }] });
    const out = (await instance.request(
      signed(
        policy({
          ...GET_ANY,
          fieldRules: {
            hiddenFields: ["ssn"],
            maskedFields: [{ field: "ssn", maskType: "hash" }],
          },
        }),
      ),
      { method: "GET", path: "/x", collectionPath: "results" },
    )) as { results: Array<Record<string, unknown>> };

    expect(out.results[0]).toEqual({ id: 1 });
  });

  it("a dangerous masking rule cannot pollute Object.prototype", async () => {
    const out = await request({ results: [{ id: 1 }] }, [
      { field: "__proto__", maskType: "redact" },
      { field: "constructor", maskType: "redact" },
    ]);

    expect(out).toBeDefined();
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(({} as Record<string, unknown>).constructor).toBe(Object);
  });

  it("a hostile __proto__ key in the RESPONSE body does not pollute Object.prototype", async () => {
    const hostile = JSON.parse('{"results":[{"id":1,"__proto__":{"polluted":"yes"}}]}');
    const { instance } = wrapper(hostile);

    await instance.request(
      signed(policy({ ...GET_ANY, fieldRules: { hiddenFields: ["nothing"] } })),
      { method: "GET", path: "/x", collectionPath: "results" },
    );

    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(Object.prototype).not.toHaveProperty("polluted");
  });
});

// ---------------------------------------------------------------------------
// Full-pipeline ordering over the body
// ---------------------------------------------------------------------------

describe("the body pipeline runs all eight steps in canonical order", () => {
  it("row -> tag -> floor -> ceiling -> hidden -> allowed -> mask -> limit", async () => {
    const { instance } = wrapper({
      meta: { total: 7 },
      results: [
        { id: 1, region: "us-east", tags: ["public"], score: 0.9, size: 10, ssn: "a", email: "a@x", extra: "drop" },
        { id: 2, region: "eu-west", tags: ["public"], score: 0.9, size: 10, ssn: "b", email: "b@x", extra: "drop" },
        { id: 3, region: "us-east", tags: ["secret"], score: 0.9, size: 10, ssn: "c", email: "c@x", extra: "drop" },
        { id: 4, region: "us-east", tags: ["public"], score: 0.1, size: 10, ssn: "d", email: "d@x", extra: "drop" },
        { id: 5, region: "us-east", tags: ["public"], score: 0.9, size: 99_999, ssn: "e", email: "e@x", extra: "drop" },
        { id: 6, region: "us-east", tags: ["public"], score: 0.9, size: 10, ssn: "f", email: "f@x", extra: "drop" },
        { id: 7, region: "us-east", tags: ["public"], score: 0.9, size: 10, ssn: "g", email: "g@x", extra: "drop" },
      ],
    });

    const out = (await instance.request(
      signed(
        policy(
          {
            ...GET_ANY,
            rowFilters: [{ field: "region", operator: "equals", value: "us-east" }],
            tagRules: { deniedTags: ["secret"] },
            fieldRules: {
              hiddenFields: ["ssn"],
              allowedFields: ["id", "region", "tags", "email", "score", "size"],
              maskedFields: [{ field: "email", maskType: "redact" }],
            },
          },
          { minSimilarityScore: 0.5, maxObjectSizeBytes: 1000, maxResults: 2 },
        ),
      ),
      { method: "GET", path: "/x", collectionPath: "results" },
    )) as { results: Array<Record<string, unknown>>; meta: unknown };

    // 2 dropped on region, 3 on tag, 4 on score, 5 on size; ssn hidden; extra not
    // allowed; email redacted; limit truncates survivors 1/6/7 to 1/6.
    expect(out.results.map((r) => r.id)).toEqual([1, 6]);
    for (const record of out.results) {
      expect("ssn" in record).toBe(false);
      expect("extra" in record).toBe(false);
      expect(record.email).toBe("[REDACTED]");
    }
    expect(out.meta).toEqual({ total: 7 });
  });
});
