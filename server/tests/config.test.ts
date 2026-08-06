/**
 * Configuration validation.
 *
 * The point of these tests is that the server **refuses to start** on a bad
 * value. A policy server that boots with a weak or defaulted signing key answers
 * `/v1/resolve` with artifacts nobody can trust, and the failure surfaces at some
 * other service's enforcement boundary rather than here.
 */

import { describe, expect, it } from "vitest";
import {
  DEFAULT_TTL_SECONDS,
  MAX_TTL_SECONDS,
  MIN_SIGNING_KEY_LENGTH,
  loadConfig,
} from "../src/config.ts";

const KEY = "k".repeat(MIN_SIGNING_KEY_LENGTH);
const base = {
  DATABASE_URL: "postgres:///tolap",
  TOLAP_SIGNING_KEY: KEY,
} as NodeJS.ProcessEnv;

describe("loadConfig", () => {
  it("accepts a minimal valid environment", () => {
    const config = loadConfig({ ...base });
    expect(config.databaseUrl).toBe("postgres:///tolap");
    expect(config.signingKey).toBe(KEY);
    expect(config.ttlSeconds).toBe(DEFAULT_TTL_SECONDS);
    expect(config.port).toBe(8080);
    // Loopback by default: a policy server that binds 0.0.0.0 the moment it starts
    // is reachable before the operator has decided it should be.
    expect(config.host).toBe("127.0.0.1");
  });

  it("requires DATABASE_URL", () => {
    expect(() => loadConfig({ TOLAP_SIGNING_KEY: KEY })).toThrow(/DATABASE_URL/);
  });

  it("requires a signing key with no fallback", () => {
    // The absence of a development default is the point. A default key would be
    // shared by every deployment that forgot to set one.
    expect(() => loadConfig({ DATABASE_URL: "postgres:///t" })).toThrow(
      /TOLAP_SIGNING_KEY/,
    );
    expect(() =>
      loadConfig({ DATABASE_URL: "postgres:///t", TOLAP_SIGNING_KEY: "   " }),
    ).toThrow(/TOLAP_SIGNING_KEY/);
  });

  it("rejects a short signing key", () => {
    expect(() =>
      loadConfig({ ...base, TOLAP_SIGNING_KEY: "too-short" }),
    ).toThrow(new RegExp(`at least ${MIN_SIGNING_KEY_LENGTH}`));
  });

  it("accepts a TTL inside the allowed range", () => {
    expect(loadConfig({ ...base, TOLAP_TTL_SECONDS: "60" }).ttlSeconds).toBe(60);
    expect(
      loadConfig({ ...base, TOLAP_TTL_SECONDS: String(MAX_TTL_SECONDS) })
        .ttlSeconds,
    ).toBe(MAX_TTL_SECONDS);
  });

  it("rejects a TTL above the ceiling", () => {
    // A signed artifact is replayable until it expires (spec section 13), so the
    // ceiling is a control rather than a suggestion.
    expect(() =>
      loadConfig({ ...base, TOLAP_TTL_SECONDS: String(MAX_TTL_SECONDS + 1) }),
    ).toThrow(/TOLAP_TTL_SECONDS/);
    expect(() =>
      loadConfig({ ...base, TOLAP_TTL_SECONDS: "86400" }),
    ).toThrow(/replayable/);
  });

  it("rejects a zero or negative TTL", () => {
    expect(() => loadConfig({ ...base, TOLAP_TTL_SECONDS: "0" })).toThrow(
      /TOLAP_TTL_SECONDS/,
    );
    // "-5" is not digits, so it fails the integer shape check first.
    expect(() => loadConfig({ ...base, TOLAP_TTL_SECONDS: "-5" })).toThrow(
      /non-negative integer/,
    );
  });

  it("rejects numeric values that are not plain integers", () => {
    // Number() would accept all of these and parseInt would accept "900abc";
    // neither is what a TTL or a port means.
    for (const bad of ["1e3", "0x10", "9.5", "900abc", "abc"]) {
      expect(
        () => loadConfig({ ...base, TOLAP_TTL_SECONDS: bad }),
        `expected ${bad} to be rejected`,
      ).toThrow(/non-negative integer/);
    }
  });

  it("tolerates surrounding whitespace on numbers", () => {
    expect(loadConfig({ ...base, TOLAP_TTL_SECONDS: " 120 " }).ttlSeconds).toBe(
      120,
    );
  });

  it("falls back to the default when a number is empty", () => {
    expect(loadConfig({ ...base, TOLAP_TTL_SECONDS: "" }).ttlSeconds).toBe(
      DEFAULT_TTL_SECONDS,
    );
  });

  it("validates the port range", () => {
    expect(loadConfig({ ...base, PORT: "9000" }).port).toBe(9000);
    expect(() => loadConfig({ ...base, PORT: "0" })).toThrow(/PORT/);
    expect(() => loadConfig({ ...base, PORT: "70000" })).toThrow(/PORT/);
  });

  it("honors an explicit host", () => {
    expect(loadConfig({ ...base, HOST: "0.0.0.0" }).host).toBe("0.0.0.0");
  });
});
