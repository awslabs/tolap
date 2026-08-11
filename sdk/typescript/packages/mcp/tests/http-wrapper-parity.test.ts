/**
 * Cross-SDK parity for the HTTP wrapper's §6 category requirements.
 *
 * One case corpus -- status code x policy, and redirect shape x policy -> outcome --
 * asserted with byte-identical expected outcomes in all three SDKs. The counterparts
 * are:
 *
 *   - Python: `tests/test_http_wrapper_parity.py`
 *   - .NET:   `tests/Tolap.Mcp.Tests/HttpWrapperParityTests.cs`
 *
 * Python is the reference ordering; this file follows it row for row so a diff of the
 * three is readable.
 *
 * **The denial reasons are asserted, not just the outcome kind.** They are the
 * contract integrators log and branch on, and each names a different policy or client
 * edit that would unblock the caller: `endpoint is hidden` is fixed by editing
 * `hiddenEndpoints`, `redirect crosses origin` cannot be fixed by a policy edit at
 * all, and `too many redirects` points at the chain rather than the rules.
 *
 * A corpus of this shape is what catches divergence: three per-SDK suites each assert
 * the behaviour that SDK happens to implement, which is exactly how the single-record
 * body ended up with three different answers -- Python `None`, TypeScript `[]`, .NET
 * the record unfiltered -- while every suite stayed green.
 */

import { describe, expect, it } from "vitest";

import {
  buildSecurityContext,
  signContext,
  type EffectivePolicy,
  type SecurityContext,
} from "@aws/tolap-core";
import {
  MAX_REDIRECTS,
  SecureHttpToolWrapper,
  UpstreamHttpError,
  type FetchLike,
} from "../src/http-wrapper.js";

const KEY = "http-parity-key";
const BASE = "https://parity.test";

function policyOf(objectRules: EffectivePolicy["objectRules"]): EffectivePolicy {
  const now = new Date();
  return {
    version: "1.0",
    userId: "parity-user",
    tenantId: "parity-tenant",
    sourceConnectionId: "api:parity:test",
    resolvedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 3_600_000).toISOString(),
    sourceProfiles: ["http-wrapper-parity"],
    permissions: { canQuery: true, readOnly: true },
    objectRules,
    integrity: { algorithm: "none", signature: "" },
  };
}

// -- The shared parity policies. Identical field-for-field in all three SDKs. --

const ALL_GET = { allowedEndpoints: ["/*", "/**"], allowedMethods: ["GET"] };

/** Every path reachable by GET, no field rules: the control case. */
const OPEN = policyOf({ endpointRules: ALL_GET });

/** `error` hidden. The 4xx/5xx body is exactly {"error": {...}}, so enforced is {}. */
const HIDE_ERROR = policyOf({
  endpointRules: ALL_GET,
  fieldRules: { hiddenFields: ["error"] },
});

/** `message` redacted, proving masking reaches an error body's nested leaf. */
const MASK_MESSAGE = policyOf({
  endpointRules: ALL_GET,
  fieldRules: { maskedFields: [{ field: "message", maskType: "redact" }] },
});

/** A filter the error body cannot satisfy: fails closed, dropping it to null. */
const FILTER_DROPS_ERROR = policyOf({
  endpointRules: ALL_GET,
  rowFilters: [{ field: "account", operator: "notEquals", value: "other" }],
});

/** Redirect sources permitted, the redirect *target* hidden. */
const REDIRECT_TARGET_HIDDEN = policyOf({
  endpointRules: {
    allowedEndpoints: ["/redirect/*"],
    hiddenEndpoints: ["/admin/*"],
    allowedMethods: ["GET"],
  },
});

/** Redirect sources permitted and nothing else. */
const REDIRECT_ONLY = policyOf({
  endpointRules: { allowedEndpoints: ["/redirect/*"], allowedMethods: ["GET"] },
});

/** Both the redirect source and its target permitted. */
const REDIRECT_AND_TARGET = policyOf({
  endpointRules: {
    allowedEndpoints: ["/redirect/*", "/patients"],
    allowedMethods: ["GET"],
  },
});

/** The object named by the caller is hidden; endpoint rules allow everything. */
const OBJECT_HIDDEN = policyOf({
  endpointRules: ALL_GET,
  hiddenObjects: ["patients"],
});

/** An allow-list the named object is absent from. */
const OBJECT_NOT_ALLOWED = policyOf({
  endpointRules: ALL_GET,
  allowedObjects: ["encounters"],
});

// ---------------------------------------------------------------------------
// Table 1: status code x policy -> enforced error body (spec §6)
// ---------------------------------------------------------------------------

/**
 * A status of 200 is in the table on purpose: the success and error paths must run
 * the *same* pipeline, and a table that only listed error codes could not show that.
 */
interface ErrorBodyCase {
  id: string;
  policy: EffectivePolicy;
  status: number;
  expected: unknown;
}

const ERROR_BODY_CORPUS: ErrorBodyCase[] = [
  // -- No field rules: the payload survives, whatever the status. --
  { id: "open-200", policy: OPEN, status: 200, expected: { error: { code: 200, message: "synthetic" } } },
  { id: "open-400", policy: OPEN, status: 400, expected: { error: { code: 400, message: "synthetic" } } },
  { id: "open-401", policy: OPEN, status: 401, expected: { error: { code: 401, message: "synthetic" } } },
  { id: "open-403", policy: OPEN, status: 403, expected: { error: { code: 403, message: "synthetic" } } },
  { id: "open-404", policy: OPEN, status: 404, expected: { error: { code: 404, message: "synthetic" } } },
  { id: "open-422", policy: OPEN, status: 422, expected: { error: { code: 422, message: "synthetic" } } },
  { id: "open-429", policy: OPEN, status: 429, expected: { error: { code: 429, message: "synthetic" } } },
  { id: "open-500", policy: OPEN, status: 500, expected: { error: { code: 500, message: "synthetic" } } },
  { id: "open-503", policy: OPEN, status: 503, expected: { error: { code: 503, message: "synthetic" } } },

  // -- hiddenFields empties the body identically on every status. This is the row
  // -- that failed before the fix: the wrapper threw on !ok before parsing, so the
  // -- 4xx/5xx payload never reached the pipeline while the 200 twin was enforced.
  { id: "hide-error-200", policy: HIDE_ERROR, status: 200, expected: {} },
  { id: "hide-error-400", policy: HIDE_ERROR, status: 400, expected: {} },
  { id: "hide-error-401", policy: HIDE_ERROR, status: 401, expected: {} },
  { id: "hide-error-403", policy: HIDE_ERROR, status: 403, expected: {} },
  { id: "hide-error-404", policy: HIDE_ERROR, status: 404, expected: {} },
  { id: "hide-error-422", policy: HIDE_ERROR, status: 422, expected: {} },
  { id: "hide-error-429", policy: HIDE_ERROR, status: 429, expected: {} },
  { id: "hide-error-500", policy: HIDE_ERROR, status: 500, expected: {} },
  { id: "hide-error-503", policy: HIDE_ERROR, status: 503, expected: {} },

  // -- Masking reaches a nested leaf of an error body, not only a success one's.
  { id: "mask-200", policy: MASK_MESSAGE, status: 200, expected: { error: { code: 200, message: "[REDACTED]" } } },
  { id: "mask-400", policy: MASK_MESSAGE, status: 400, expected: { error: { code: 400, message: "[REDACTED]" } } },
  { id: "mask-500", policy: MASK_MESSAGE, status: 500, expected: { error: { code: 500, message: "[REDACTED]" } } },

  // -- The record-dropping steps reach an error body too. The body is a single
  // -- record, and a filter it cannot satisfy drops it to null (spec §4).
  { id: "filter-drops-200", policy: FILTER_DROPS_ERROR, status: 200, expected: null },
  { id: "filter-drops-400", policy: FILTER_DROPS_ERROR, status: 400, expected: null },
  { id: "filter-drops-500", policy: FILTER_DROPS_ERROR, status: 500, expected: null },
];

// ---------------------------------------------------------------------------
// Table 2: redirect shape x policy -> outcome (spec §6)
// ---------------------------------------------------------------------------

/** `hops` is how many 302s the transport serves before the final 200. */
interface RedirectCase {
  id: string;
  policy: EffectivePolicy;
  location: string;
  hops: number;
  /** Expected denial substring, or undefined for "followed and enforced". */
  denial?: string;
}

const REDIRECT_CORPUS: RedirectCase[] = [
  // -- A permitted source redirecting to a denied target: the whole point of §6. --
  {
    id: "hidden-target-relative",
    policy: REDIRECT_TARGET_HIDDEN,
    location: "/admin/audit",
    hops: 1,
    denial: "redirect target rejected: endpoint is hidden",
  },
  {
    id: "not-allowed-target",
    policy: REDIRECT_ONLY,
    location: "/admin/audit",
    hops: 1,
    denial: "redirect target rejected: endpoint not in allowed set",
  },
  // A relative Location that walks up: resolved against the request URL, then
  // re-globbed on the resulting path, so "../admin/audit" is denied like the absolute
  // spelling rather than matched literally.
  {
    id: "hidden-target-dot-dot",
    policy: REDIRECT_TARGET_HIDDEN,
    location: "../admin/audit",
    hops: 1,
    denial: "redirect target rejected: endpoint is hidden",
  },
  // An absolute Location on the SAME origin is re-globbed normally: it is the host
  // change, not the absoluteness, that takes a hop out of the policy's frame.
  {
    id: "hidden-target-absolute-same-origin",
    policy: REDIRECT_TARGET_HIDDEN,
    location: `${BASE}/admin/audit`,
    hops: 1,
    denial: "redirect target rejected: endpoint is hidden",
  },

  // -- A permitted target is followed: re-validating is not refusing. --
  { id: "permitted-target", policy: REDIRECT_AND_TARGET, location: "/patients", hops: 1 },
  {
    id: "permitted-target-absolute",
    policy: REDIRECT_AND_TARGET,
    location: `${BASE}/patients`,
    hops: 1,
  },
  // The Location's own query string is not policy-relevant (the path is), and it must
  // not be corrupted by re-appending the original request's params.
  {
    id: "permitted-target-with-query",
    policy: REDIRECT_AND_TARGET,
    location: "/patients?region=us-east",
    hops: 1,
  },

  // -- Cross-origin: refused on the host change, never re-globbed on the path. --
  // OPEN allows "/*" and "/**", so a wrapper that globbed the path would ALLOW every
  // one of these. That is what makes them the fail-open rows.
  {
    id: "cross-host",
    policy: OPEN,
    location: "https://attacker.test/patients",
    hops: 1,
    denial: "redirect crosses origin",
  },
  {
    id: "cross-port",
    policy: OPEN,
    location: "https://parity.test:8443/patients",
    hops: 1,
    denial: "redirect crosses origin",
  },
  {
    id: "cross-scheme-downgrade",
    policy: OPEN,
    location: "http://parity.test/patients",
    hops: 1,
    denial: "redirect crosses origin",
  },

  // -- The hop budget is the wrapper's, not the transport's. --
  { id: "chain-at-limit", policy: REDIRECT_AND_TARGET, location: "/patients", hops: MAX_REDIRECTS },
  {
    id: "chain-past-limit",
    policy: REDIRECT_AND_TARGET,
    location: "/patients",
    hops: MAX_REDIRECTS + 1,
    denial: `too many redirects (limit ${MAX_REDIRECTS})`,
  },

  // -- The object check is part of a hop, so a redirect cannot shed it. --
  { id: "object-hidden-on-hop", policy: OBJECT_HIDDEN, location: "/patients", hops: 1, denial: "object is hidden" },
];

// ---------------------------------------------------------------------------
// Table 3: object name x policy -> outcome (spec §6, last bullet)
// ---------------------------------------------------------------------------

/**
 * The rows with no object name pin "no inference": the identical policy that denies a
 * named object must ALLOW the same path when nothing is named, because deriving a
 * resource from a route is the unspecified behaviour §6 warns against.
 */
interface ObjectNameCase {
  id: string;
  policy: EffectivePolicy;
  objectName?: string;
  denial?: string;
}

const OBJECT_NAME_CORPUS: ObjectNameCase[] = [
  { id: "hidden-object-named", policy: OBJECT_HIDDEN, objectName: "patients", denial: "object is hidden" },
  { id: "hidden-object-not-named", policy: OBJECT_HIDDEN },
  {
    id: "object-not-in-allow-list",
    policy: OBJECT_NOT_ALLOWED,
    objectName: "patients",
    denial: "object not in allowed set",
  },
  { id: "object-in-allow-list", policy: OBJECT_NOT_ALLOWED, objectName: "encounters" },
  { id: "allow-list-not-named", policy: OBJECT_NOT_ALLOWED },
  { id: "no-object-rules-named", policy: OPEN, objectName: "patients" },
];

// A case-sensitivity row (`hiddenObjects: ["patients"]` against an object name of
// `PATIENTS`) is deliberately NOT in this table, and its absence was originally a
// finding: adding it exposed a divergence in `validateAccess` itself, not in the HTTP
// wrappers. Python's `_pattern_matches` and .NET's `GlobMatch` both matched
// case-insensitively, while TypeScript's `globToRegex` compiled a case-SENSITIVE
// regex, so the identical policy that hides `patients` from a caller naming
// `PATIENTS` denied in two SDKs and allowed in the third.
//
// RESOLVED: `globToRegex` now compiles with the `i` flag, per spec §3.1 ("All
// enforcement matching is case-insensitive and platform-independent"). The row still
// does not belong here — this table's subject is what the `api` wrapper adds on top
// of core enforcement, and its length is asserted identical in all three SDKs, so a
// core-matching case would have to land in three corpora to test one thing. Case
// folding for `validateAccess`, `validateFieldAccess` and `validateEndpoint` is
// pinned in core's `tests/glob-matching-parity.test.ts` against the same measured
// Python outcomes instead.

function signed(p: EffectivePolicy): SecurityContext {
  return signContext(buildSecurityContext(p.userId, p.tenantId, p, 3_600_000), KEY);
}

function wrapperOver(fetchFn: FetchLike): SecureHttpToolWrapper {
  return new SecureHttpToolWrapper({ signingKey: KEY, baseUrl: BASE }, fetchFn);
}

/** A transport returning one status and the shared error-shaped body. */
function statusFetch(status: number): FetchLike {
  const body = { error: { code: status, message: "synthetic" } };
  return async () => ({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    headers: { get: () => null },
  });
}

/**
 * A transport serving `hops` redirects then a 200 collection.
 *
 * The intermediate hops point back at a permitted /redirect/N so only the FINAL hop
 * exercises the case's Location.
 */
function redirectFetch(location: string, hops: number): FetchLike {
  let served = 0;
  return async () => {
    served++;
    if (served <= hops - 1) {
      const intermediate = `/redirect/${served}`;
      return {
        ok: false,
        status: 302,
        json: async () => undefined,
        headers: { get: (n: string) => (n.toLowerCase() === "location" ? intermediate : null) },
      };
    }
    if (served === hops) {
      return {
        ok: false,
        status: 302,
        json: async () => undefined,
        headers: { get: (n: string) => (n.toLowerCase() === "location" ? location : null) },
      };
    }
    return {
      ok: true,
      status: 200,
      json: async () => ({ results: [{ id: 1, region: "us-east" }] }),
      headers: { get: () => null },
    };
  };
}

describe("spec §6 parity: an error body carries the same enforcement as a success body", () => {
  for (const testCase of ERROR_BODY_CORPUS) {
    it(`${testCase.id} matches the shared expectation`, async () => {
      const wrapper = wrapperOver(statusFetch(testCase.status));

      if (testCase.status >= 200 && testCase.status < 300) {
        await expect(
          wrapper.request(signed(testCase.policy), { method: "GET", path: "/status" }),
        ).resolves.toEqual(testCase.expected);
        return;
      }

      const error = (await wrapper
        .request(signed(testCase.policy), { method: "GET", path: "/status" })
        .then(
          () => undefined,
          (e: unknown) => e,
        )) as UpstreamHttpError;

      expect(error).toBeInstanceOf(UpstreamHttpError);
      expect(error.status).toBe(testCase.status);
      expect(error.body).toEqual(testCase.expected);
    });
  }
});

describe("spec §6 parity: every hop is re-validated, bounded, and same-origin", () => {
  for (const testCase of REDIRECT_CORPUS) {
    it(`${testCase.id} matches the shared expectation`, async () => {
      const wrapper = wrapperOver(redirectFetch(testCase.location, testCase.hops));
      const args = {
        method: "GET",
        path: "/redirect/0",
        ...(testCase.policy === OBJECT_HIDDEN ? { objectName: "patients" } : {}),
      };

      if (testCase.denial === undefined) {
        const body = (await wrapper.request(signed(testCase.policy), {
          ...args,
          collectionPath: "results",
        })) as { results: unknown[] };
        expect(body.results).toEqual([{ id: 1, region: "us-east" }]);
        return;
      }

      await expect(wrapper.request(signed(testCase.policy), args)).rejects.toThrow(
        testCase.denial,
      );
    });
  }
});

describe("spec §6 parity: object rules are honoured when named, never inferred", () => {
  for (const testCase of OBJECT_NAME_CORPUS) {
    it(`${testCase.id} matches the shared expectation`, async () => {
      const fetchFn: FetchLike = async () => ({
        ok: true,
        status: 200,
        json: async () => ({ results: [{ id: 1 }] }),
        headers: { get: () => null },
      });
      const wrapper = wrapperOver(fetchFn);
      const args = {
        method: "GET",
        path: "/patients",
        ...(testCase.objectName !== undefined ? { objectName: testCase.objectName } : {}),
      };

      if (testCase.denial === undefined) {
        const body = (await wrapper.request(signed(testCase.policy), {
          ...args,
          collectionPath: "results",
        })) as { results: unknown[] };
        expect(body.results).toEqual([{ id: 1 }]);
        return;
      }

      await expect(wrapper.request(signed(testCase.policy), args)).rejects.toThrow(
        testCase.denial,
      );
    });
  }
});

/**
 * Table 4: request targets that are not host-relative paths.
 *
 * Every row is checked against {@link OPEN} — `allowedEndpoints: ["/*", "/**"]`, the
 * most permissive policy in the corpus — because the point is that the globs cannot
 * save you here. A glob decides *which paths* a policy reaches; by the time one runs,
 * the authority is already chosen. `//evil.example/x` matches `/*` on its leading
 * slash and then resolves as an authority, so the request left for a host the policy
 * author never named, carrying whatever auth headers the integrator configured on the
 * client. Confirmed reachable in .NET before this check existed.
 *
 * The transport must never be invoked: a denial that still made the request would
 * have already leaked the credentials, whatever it returned to the caller.
 */
const PATH_SHAPE_CORPUS: Array<{ id: string; path: string; denial: string }> = [
  { id: "protocol-relative", path: "//evil.example/x", denial: "request path is protocol-relative" },
  { id: "protocol-relative-backslash", path: "/\\evil.example/x", denial: "request path is protocol-relative" },
  { id: "absolute-https", path: "https://evil.example/x", denial: "request path is not host-relative" },
  { id: "absolute-http", path: "http://evil.example/x", denial: "request path is not host-relative" },
  { id: "leading-backslash", path: "\\\\evil.example\\x", denial: "request path is not host-relative" },
  { id: "schemeless-relative", path: "drug/event.json", denial: "request path is not host-relative" },
  { id: "dot-dot-escapes-prefix", path: "/drug/../../internal/admin", denial: "request path contains a '..' segment" },
  { id: "dot-dot-before-query", path: "/drug/..?x=1", denial: "request path contains a '..' segment" },
  { id: "empty", path: "", denial: "request path is empty" },
];

describe("path shape parity", () => {
  // Table 4: a request target that is not a host-relative path is refused.
  for (const testCase of PATH_SHAPE_CORPUS) {
    it(testCase.id, async () => {
      const served: string[] = [];
      const wrapper = wrapperOver(async (input) => {
        served.push(input.url);
        return {
          ok: true,
          status: 200,
          json: async () => ({ results: [] }),
          headers: { get: () => null },
        };
      });

      await expect(
        wrapper.request(signed(OPEN), { method: "GET", path: testCase.path }),
      ).rejects.toThrow(testCase.denial);
      // The credentials are on the transport, so a request that went out has
      // already leaked them regardless of what the wrapper returned.
      expect(served, `transport reached for ${JSON.stringify(testCase.path)}`).toEqual([]);
    });
  }

  it("an ordinary rooted path is still allowed", async () => {
    // The control: the check must not reject the paths policies are written for.
    const served: string[] = [];
    const wrapper = wrapperOver(async (input) => {
      served.push(input.url);
      return {
        ok: true,
        status: 200,
        json: async () => ({ results: [{ id: 1 }] }),
        headers: { get: () => null },
      };
    });

    const body = (await wrapper.request(signed(OPEN), {
      method: "GET",
      path: "/drug/event.json?limit=3",
      collectionPath: "results",
    })) as { results: unknown[] };

    expect(body.results).toEqual([{ id: 1 }]);
    expect(served).toEqual(["https://parity.test/drug/event.json?limit=3"]);
  });
});

describe("the corpus itself", () => {
  // A corpus that silently shrank would make every SDK agree by asserting nothing.
  it("the tables carry the expected number of cases", () => {
    expect(ERROR_BODY_CORPUS.length).toBe(24);
    expect(REDIRECT_CORPUS.length).toBe(13);
    expect(OBJECT_NAME_CORPUS.length).toBe(6);
    expect(PATH_SHAPE_CORPUS.length).toBe(9);
  });

  it("case ids are unique within each table", () => {
    for (const corpus of [
      ERROR_BODY_CORPUS,
      REDIRECT_CORPUS,
      OBJECT_NAME_CORPUS,
      PATH_SHAPE_CORPUS,
    ]) {
      const ids = corpus.map((c) => c.id);
      expect(new Set(ids).size).toBe(ids.length);
    }
  });

  it("the hop budget is the agreed number", () => {
    // All three SDKs state 5, independently of any client's own default.
    expect(MAX_REDIRECTS).toBe(5);
  });
});
