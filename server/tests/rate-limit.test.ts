/**
 * In-process rate limiting on both listeners.
 *
 * These tests exist because CodeQL raised `js/missing-rate-limiting` on all 24 admin
 * routes and the honest answer at the time was "the reference deployment has a WAF
 * rule" -- true, and in a different directory. A deployment behind some other ingress
 * had no bound at all, and nothing in the code said so.
 *
 * What is asserted here is the property, not the plugin: that the (N+1)th request from
 * one address is refused, that the refusal is a 429, that `/health` is exempt so a
 * load balancer cannot rate-limit a working server out of service, and that the
 * resolve port's refusal does not disclose the configured ceiling. A test that only
 * checked "the plugin is registered" would pass with the limit set to infinity.
 *
 * No database needed: every request here is refused before it reaches a route, which
 * is the point -- the limiter runs ahead of the credential check.
 */

import { afterEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { PostgresPolicyStore } from "../src/db/store.ts";
import { Keyring } from "../src/signing/keyring.ts";
import { buildResolveApp } from "../src/routes/resolve.ts";
import { buildAdminApp } from "../src/routes/admin.ts";
import { staticIdentity } from "./helpers/db.ts";

const KEY = "rate-limit-test-key-not-for-production";

/** Never reached: these tests never get past the limiter or the auth guard. */
const store = new PostgresPolicyStore(
  { query: async () => ({ rows: [] }) } as never,
  staticIdentity(),
);
const keyring = () => new Keyring([{ kid: "k1", secret: KEY }], "k1");

let app: FastifyInstance | undefined;
afterEach(async () => {
  await app?.close();
  app = undefined;
});

describe("resolve listener", () => {
  it("refuses the request after the ceiling and keeps refusing", async () => {
    app = buildResolveApp({ store, keyring: keyring(), ttlSeconds: 900, rateLimit: 3 });

    const codes: number[] = [];
    for (let i = 0; i < 5; i += 1) {
      const res = await app.inject({ method: "GET", url: "/v1/resolve" });
      codes.push(res.statusCode);
    }

    // The first three are let through to the auth guard, which refuses them for a
    // different reason (401, no credential). Only the count matters here: what
    // distinguishes limited from unlimited is that requests 4 and 5 never arrive.
    expect(codes.slice(0, 3).every((c) => c !== 429)).toBe(true);
    expect(codes.slice(3)).toEqual([429, 429]);
  });

  it("does not disclose the ceiling in the refusal body", async () => {
    app = buildResolveApp({ store, keyring: keyring(), ttlSeconds: 900, rateLimit: 1 });
    await app.inject({ method: "GET", url: "/v1/resolve" });
    const limited = await app.inject({ method: "GET", url: "/v1/resolve" });

    expect(limited.statusCode).toBe(429);
    // The plugin's default message is "Rate limit exceeded, retry in N ms" and names
    // the ceiling. On this port every other response is a flat, uninformative string
    // for the same reason: an unauthenticated caller learning how fast they may probe
    // without refusal is a small oracle, and this endpoint has no others.
    expect(limited.json()).toEqual({ error: "too many requests" });
    expect(limited.body).not.toMatch(/\d/);
  });

  it("exempts /health so a health check cannot exhaust the budget", async () => {
    app = buildResolveApp({ store, keyring: keyring(), ttlSeconds: 900, rateLimit: 1 });

    for (let i = 0; i < 10; i += 1) {
      const res = await app.inject({ method: "GET", url: "/health" });
      // A load balancer polls this every few seconds, at a frequency that has nothing
      // to do with abuse. Counting it means an over-eager check marks the task
      // unhealthy and removes a server that was working.
      expect(res.statusCode).toBe(200);
    }
  });

  it("applies no limit when none is configured", async () => {
    // Omission is what the other suites rely on: they issue hundreds of requests from
    // one address and would otherwise assert against a 429 instead of the behaviour
    // under test. Asserting it here keeps that contract visible rather than incidental.
    app = buildResolveApp({ store, keyring: keyring(), ttlSeconds: 900 });

    for (let i = 0; i < 20; i += 1) {
      const res = await app.inject({ method: "GET", url: "/v1/resolve" });
      expect(res.statusCode).not.toBe(429);
    }
  });
});

describe("admin listener", () => {
  const verifier = { verify: async () => { throw new Error("never reached"); } } as never;

  it("refuses the request after the ceiling", async () => {
    app = buildAdminApp({
      store,
      verifier,
      keyring: keyring(),
      ttlSeconds: 900,
      rateLimit: 2,
    });

    const codes: number[] = [];
    for (let i = 0; i < 4; i += 1) {
      const res = await app.inject({ method: "GET", url: "/v1/policies" });
      codes.push(res.statusCode);
    }

    expect(codes.slice(0, 2).every((c) => c !== 429)).toBe(true);
    expect(codes.slice(2)).toEqual([429, 429]);
  });

  it("limits before authentication, not after", async () => {
    // Ordering is the property worth pinning. If the guard ran first, an
    // unauthenticated flood would still cost a Cognito verification per request --
    // a network call to another service -- and the limiter would be protecting
    // nothing that matters.
    app = buildAdminApp({
      store,
      verifier,
      keyring: keyring(),
      ttlSeconds: 900,
      rateLimit: 1,
    });

    await app.inject({ method: "GET", url: "/v1/policies" });
    const limited = await app.inject({
      method: "GET",
      url: "/v1/policies",
      headers: { authorization: "Bearer whatever" },
    });

    // `verifier.verify` throws if called. A 429 rather than a 500 proves the limiter
    // short-circuited ahead of it.
    expect(limited.statusCode).toBe(429);
  });

  it("exempts /health", async () => {
    app = buildAdminApp({
      store,
      verifier,
      keyring: keyring(),
      ttlSeconds: 900,
      rateLimit: 1,
    });

    for (let i = 0; i < 5; i += 1) {
      expect((await app.inject({ method: "GET", url: "/health" })).statusCode).toBe(200);
    }
  });
});
