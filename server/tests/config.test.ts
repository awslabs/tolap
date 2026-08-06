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
  COGNITO_ISSUER: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_test",
  COGNITO_AUDIENCE: "test-client-id",
} as NodeJS.ProcessEnv;

/** `base` minus one key, for asserting that key is required. */
const without = (key: string): NodeJS.ProcessEnv => {
  const env = { ...base };
  delete env[key];
  return env;
};

describe("loadConfig", () => {
  it("accepts a minimal valid environment", () => {
    const config = loadConfig({ ...base });
    expect(config.databaseUrl).toBe("postgres:///tolap");
    expect(config.signingKey).toBe(KEY);
    expect(config.ttlSeconds).toBe(DEFAULT_TTL_SECONDS);
    expect(config.port).toBe(8080);
    expect(config.resolvePort).toBe(8081);
    // Loopback by default: a policy server that binds 0.0.0.0 the moment it starts
    // is reachable before the operator has decided it should be.
    expect(config.host).toBe("127.0.0.1");
    expect(config.resolveHost).toBe("127.0.0.1");
    expect(config.adminGroup).toBe("tolap-admin");
    expect(config.auditorGroup).toBe("tolap-auditor");
  });

  it.each(["DATABASE_URL", "COGNITO_ISSUER", "COGNITO_AUDIENCE"])(
    "requires %s",
    (key) => {
      expect(() => loadConfig(without(key))).toThrow(new RegExp(key));
    },
  );

  it("requires a signing key with no fallback", () => {
    // The absence of a development default is the point. A default key would be
    // shared by every deployment that forgot to set one.
    expect(() => loadConfig(without("TOLAP_SIGNING_KEY"))).toThrow(
      /TOLAP_SIGNING_KEY/,
    );
    expect(() =>
      loadConfig({ ...base, TOLAP_SIGNING_KEY: "   " }),
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
    expect(() => loadConfig({ ...base, RESOLVE_PORT: "0" })).toThrow(
      /RESOLVE_PORT/,
    );
  });

  it("refuses to put both listeners on one port", () => {
    // Sharing a port collapses the two-listener split, putting the
    // policy-authoring surface on the interface meant for remote installs.
    expect(() =>
      loadConfig({ ...base, PORT: "8080", RESOLVE_PORT: "8080" }),
    ).toThrow(/must differ/);
  });

  it("honors an explicit host", () => {
    expect(loadConfig({ ...base, HOST: "0.0.0.0" }).host).toBe("0.0.0.0");
  });

  it("lets the resolve listener bind a different interface", () => {
    // The point of the split: expose resolve while keeping admin private.
    const config = loadConfig({
      ...base,
      HOST: "127.0.0.1",
      RESOLVE_HOST: "0.0.0.0",
    });
    expect(config.host).toBe("127.0.0.1");
    expect(config.resolveHost).toBe("0.0.0.0");
  });

  it("defaults the resolve host to HOST when only HOST is set", () => {
    expect(loadConfig({ ...base, HOST: "10.0.0.5" }).resolveHost).toBe("10.0.0.5");
  });

  it("honors custom Cognito group names", () => {
    const config = loadConfig({
      ...base,
      TOLAP_ADMIN_GROUP: "PolicyAdmins",
      TOLAP_AUDITOR_GROUP: "PolicyReviewers",
    });
    expect(config.adminGroup).toBe("PolicyAdmins");
    expect(config.auditorGroup).toBe("PolicyReviewers");
  });
});
