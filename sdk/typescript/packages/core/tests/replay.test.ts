/**
 * Replay detection for signed security contexts (spec §13).
 *
 * A signed context was previously a bearer credential replayable for its full
 * TTL: capture it and it worked until it expired. `jti` plus a `ReplayGuard`
 * closes that. The two halves matter separately:
 *
 * - the identifier is *inside the signed payload*, so it cannot be stripped or
 *   swapped to dodge the check without invalidating the signature;
 * - the guard is the state the SDK deliberately does not assume, supplied by the
 *   integrator.
 *
 * A test that only asserted "the same context twice is rejected" would pass
 * against an implementation that left `jti` outside the signature — where an
 * attacker simply removes it. The stripping and swapping cases below are the ones
 * that distinguish a real fix.
 */

import { describe, it, expect } from "vitest";
import {
  InMemoryReplayGuard,
  buildSecurityContext,
  deserializeContext,
  serializeContext,
  signContext,
  validateContext,
} from "../src/context.js";
import type { EffectivePolicy, SecurityContext } from "../src/types.js";

const KEY = "test-signing-key-do-not-use-in-production";

function policy(): EffectivePolicy {
  return {
    version: "1.0",
    userId: "user-001",
    tenantId: "tenant-001",
    resolvedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    sourceProfiles: [],
    permissions: { canQuery: true, readOnly: true },
    integrity: { algorithm: "none", signature: "" },
  };
}

function signed(jti?: string): string {
  const context = buildSecurityContext(
    "user-001",
    "tenant-001",
    policy(),
    3_600_000,
    jti,
  );
  return serializeContext(signContext(context, KEY));
}

function decode(serialized: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(serialized, "base64").toString("utf8"));
}

function encode(payload: Record<string, unknown>): string {
  return Buffer.from(JSON.stringify(payload), "utf8").toString("base64");
}

describe("§13: a jti is minted", () => {
  it("mints one by default", () => {
    const context = buildSecurityContext("user-001", "tenant-001", policy());
    expect(context.jti).toBeTruthy();
    expect(context.jti!.length).toBeGreaterThanOrEqual(32);
  });

  it("gives each context a distinct id", () => {
    const a = buildSecurityContext("user-001", "tenant-001", policy());
    const b = buildSecurityContext("user-001", "tenant-001", policy());
    expect(a.jti).not.toBe(b.jti);
  });

  it("honours an explicit id", () => {
    const context = buildSecurityContext(
      "user-001",
      "tenant-001",
      policy(),
      3_600_000,
      "ctx-abc",
    );
    expect(context.jti).toBe("ctx-abc");
  });

  it("treats an empty id as opting out", () => {
    const context = buildSecurityContext(
      "user-001",
      "tenant-001",
      policy(),
      3_600_000,
      "",
    );
    expect(context.jti).toBeUndefined();
  });
});

describe("§13: the jti is signed", () => {
  it("invalidates the signature when stripped", () => {
    // The attack a guard alone would not stop.
    const context = signContext(
      buildSecurityContext("user-001", "tenant-001", policy(), 3_600_000, "ctx-abc"),
      KEY,
    );
    expect(validateContext(context, KEY)).toBe(true);

    delete context.jti;
    expect(validateContext(context, KEY)).toBe(false);
  });

  it("invalidates the signature when swapped", () => {
    // Otherwise a replayer just mints a fresh id per replay.
    const context = signContext(
      buildSecurityContext("user-001", "tenant-001", policy(), 3_600_000, "ctx-abc"),
      KEY,
    );
    context.jti = "ctx-xyz";
    expect(validateContext(context, KEY)).toBe(false);
  });

  it("keeps the legacy signature when absent", () => {
    // Backward compatibility: no `jti` signs exactly as it did before.
    const shared = policy();
    const withoutJti: SecurityContext = {
      effectivePolicy: shared,
      resolvedAt: "2026-01-15T10:00:00Z",
      expiresAt: "2026-01-15T11:00:00Z",
    };
    const first = signContext({ ...withoutJti }, KEY).signature;
    const second = signContext(
      { ...withoutJti, jti: undefined },
      KEY,
    ).signature;
    expect(first).toBe(second);
  });
});

describe("§13: the guard rejects reuse", () => {
  it("accepts a first use", () => {
    const guard = new InMemoryReplayGuard();
    const context = deserializeContext(signed(), KEY, guard);
    expect(context.effectivePolicy.permissions.canQuery).toBe(true);
  });

  it("rejects a second use of the same context", () => {
    const guard = new InMemoryReplayGuard();
    const serialized = signed();

    deserializeContext(serialized, KEY, guard);

    expect(() => deserializeContext(serialized, KEY, guard)).toThrow(/replay/);
  });

  it("accepts two distinct contexts", () => {
    // The guard must not reject merely because a user appeared twice.
    const guard = new InMemoryReplayGuard();
    expect(() => {
      deserializeContext(signed(), KEY, guard);
      deserializeContext(signed(), KEY, guard);
    }).not.toThrow();
  });

  it("allows replay when no guard is supplied", () => {
    // Documents the default: TTL-bounded replay, as specified.
    const serialized = signed();
    expect(() => {
      deserializeContext(serialized, KEY);
      deserializeContext(serialized, KEY);
    }).not.toThrow();
  });

  it("does not share state between separate guards", () => {
    // Pins the documented limitation of the in-memory guard.
    const serialized = signed();
    expect(() => {
      deserializeContext(serialized, KEY, new InMemoryReplayGuard());
      deserializeContext(serialized, KEY, new InMemoryReplayGuard());
    }).not.toThrow();
  });
});

describe("§13: the guard requires a jti", () => {
  it("rejects a context with no jti", () => {
    // Skipping the check for a jti-less context is the failure mode to avoid.
    expect(() =>
      deserializeContext(signed(""), KEY, new InMemoryReplayGuard()),
    ).toThrow(/requires a 'jti'/);
  });

  it("rejects a forged jti before the guard sees it", () => {
    // Adding a `jti` to a context signed without one changes the signed bytes,
    // so it fails on signature and never reaches the guard.
    const payload = decode(signed(""));
    payload.jti = "attacker-chosen";

    expect(() =>
      deserializeContext(encode(payload), KEY, new InMemoryReplayGuard()),
    ).toThrow(/signature/);
  });
});

describe("§13: guard ordering", () => {
  it("does not consume the jti of an expired context", () => {
    // If the guard ran before expiry validation, an attacker could pre-register
    // the id of a context that had not been used yet, and the legitimate holder
    // would then be refused.
    const guard = new InMemoryReplayGuard();
    const context = buildSecurityContext(
      "user-001",
      "tenant-001",
      policy(),
      3_600_000,
      "ctx-abc",
    );
    context.resolvedAt = "2020-01-01T00:00:00Z";
    context.expiresAt = "2020-01-01T01:00:00Z";
    const expired = serializeContext(signContext(context, KEY));

    expect(() => deserializeContext(expired, KEY, guard)).toThrow(/expired/);

    // The id was never consumed, so a fresh context using it still works.
    expect(guard.checkAndRegister("ctx-abc")).toBe(true);
  });

  it("does not consume the jti of a badly signed context", () => {
    const guard = new InMemoryReplayGuard();
    const payload = decode(signed("ctx-abc"));
    payload.signature = Buffer.from("wrong").toString("base64");

    expect(() => deserializeContext(encode(payload), KEY, guard)).toThrow(
      /signature/,
    );

    expect(guard.checkAndRegister("ctx-abc")).toBe(true);
  });
});

describe("InMemoryReplayGuard", () => {
  it("is first-wins", () => {
    const guard = new InMemoryReplayGuard();
    expect(guard.checkAndRegister("a")).toBe(true);
    expect(guard.checkAndRegister("a")).toBe(false);
  });

  it("treats distinct ids independently", () => {
    const guard = new InMemoryReplayGuard();
    expect(guard.checkAndRegister("a")).toBe(true);
    expect(guard.checkAndRegister("b")).toBe(true);
  });

  it("drops entries once expired", () => {
    // Memory is bounded by one TTL's worth of contexts, not unbounded.
    const guard = new InMemoryReplayGuard();
    const past = new Date(Date.now() - 3_600_000).toISOString();
    expect(guard.checkAndRegister("a", past)).toBe(true);

    // A later call sweeps the expired entry; the id becomes reusable, which is
    // safe because a context carrying it would now fail the expiry check.
    expect(guard.checkAndRegister("b")).toBe(true);
    expect(guard.checkAndRegister("a")).toBe(true);
  });

  it("does not pin an entry forever on an unparseable expiry", () => {
    const guard = new InMemoryReplayGuard();
    expect(guard.checkAndRegister("a", "not-a-date")).toBe(true);
    // Still registered (bounded fallback), so a replay is caught.
    expect(guard.checkAndRegister("a", "not-a-date")).toBe(false);
  });
});
