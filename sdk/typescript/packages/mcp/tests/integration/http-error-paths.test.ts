/**
 * HTTP error and short-circuit behavior for the TypeScript SecureHttpToolWrapper.
 * Mirrors sdk/python/tests/integration/test_http_error_paths.py.
 */

import { describe, expect, it } from "vitest";

import {
  buildSecurityContext,
  signContext,
  type EffectivePolicy,
} from "@aws/tolap-core";
import {
  SecureHttpToolWrapper,
  type FetchLike,
} from "../../src/http-wrapper.js";

const SIGNING_KEY = "openfda-integration-key";

function allowDrugPolicy(): EffectivePolicy {
  const now = new Date();
  return {
    version: "1.0",
    userId: "u",
    tenantId: "t",
    sourceConnectionId: "s",
    resolvedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 3_600_000).toISOString(),
    sourceProfiles: ["http-error-test"],
    permissions: { canQuery: true },
    objectRules: {
      endpointRules: {
        allowedEndpoints: ["/drug/*"],
        hiddenEndpoints: ["/food/*"],
        allowedMethods: ["GET"],
      },
    },
    integrity: { algorithm: "none", signature: "" },
  };
}

function signedCtx() {
  const policy = allowDrugPolicy();
  const ctx = buildSecurityContext(policy.userId, policy.tenantId, policy, 3_600_000);
  return signContext(ctx, SIGNING_KEY);
}

function makeStatusFetch(status: number, body: any = { error: "x" }): FetchLike {
  return async () => ({ ok: status >= 200 && status < 300, status, json: async () => body });
}

describe("upstream error propagation", () => {
  it("404 raises after policy passes", async () => {
    const wrapper = new SecureHttpToolWrapper(
      { signingKey: SIGNING_KEY, baseUrl: "https://api.fda.gov" },
      makeStatusFetch(404),
    );
    await expect(
      wrapper.request(signedCtx(), { method: "GET", path: "/drug/event.json" }),
    ).rejects.toThrow(/HTTP 404/);
  });

  it("429 propagates", async () => {
    const wrapper = new SecureHttpToolWrapper(
      { signingKey: SIGNING_KEY, baseUrl: "https://api.fda.gov" },
      makeStatusFetch(429),
    );
    await expect(
      wrapper.request(signedCtx(), { method: "GET", path: "/drug/event.json" }),
    ).rejects.toThrow(/HTTP 429/);
  });

  it("500 propagates", async () => {
    const wrapper = new SecureHttpToolWrapper(
      { signingKey: SIGNING_KEY, baseUrl: "https://api.fda.gov" },
      makeStatusFetch(500),
    );
    await expect(
      wrapper.request(signedCtx(), { method: "GET", path: "/drug/event.json" }),
    ).rejects.toThrow(/HTTP 500/);
  });
});

describe("policy short-circuits before transport", () => {
  it("hidden endpoint denial does not invoke transport", async () => {
    const calls: string[] = [];
    const fetchFn: FetchLike = async ({ url }) => {
      calls.push(url);
      return { ok: false, status: 500, json: async () => ({}) };
    };
    const wrapper = new SecureHttpToolWrapper(
      { signingKey: SIGNING_KEY, baseUrl: "https://api.fda.gov" },
      fetchFn,
    );
    await expect(
      wrapper.request(signedCtx(), { method: "GET", path: "/food/enforcement.json" }),
    ).rejects.toThrow(/endpoint is hidden/);
    expect(calls).toEqual([]);
  });

  it("method denial does not invoke transport", async () => {
    const calls: string[] = [];
    const fetchFn: FetchLike = async ({ method }) => {
      calls.push(method);
      return { ok: true, status: 200, json: async () => ({}) };
    };
    const wrapper = new SecureHttpToolWrapper(
      { signingKey: SIGNING_KEY, baseUrl: "https://api.fda.gov" },
      fetchFn,
    );
    await expect(
      wrapper.request(signedCtx(), { method: "DELETE", path: "/drug/event.json" }),
    ).rejects.toThrow(/method not allowed/);
    expect(calls).toEqual([]);
  });
});
