/**
 * Install credentials: the resolve port's authentication.
 */

import { describe, expect, it } from "vitest";
import {
  CREDENTIAL_PREFIX,
  credentialMatches,
  hashCredential,
  installIdFromCredential,
  issueCredential,
} from "../src/auth/install-credential.ts";

describe("issueCredential", () => {
  it("returns a prefixed secret and a hash that is not the secret", () => {
    const issued = issueCredential("install-1");
    expect(issued.secret.startsWith(CREDENTIAL_PREFIX)).toBe(true);
    expect(issued.installId).toBe("install-1");
    // What lands in the database must not be usable as a credential.
    expect(issued.hash).not.toContain(issued.secret);
    expect(issued.hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("never repeats a secret", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 200; i += 1) {
      seen.add(issueCredential("install-1").secret);
    }
    // Same install id every time, so any collision here is the random component
    // failing rather than the id being reused.
    expect(seen.size).toBe(200);
  });

  it("produces a credential that validates against its own hash", () => {
    const issued = issueCredential("install-1");
    expect(credentialMatches(issued.secret, issued.hash)).toBe(true);
  });
});

describe("installIdFromCredential", () => {
  it("recovers the install id", () => {
    const issued = issueCredential("install-abc");
    expect(installIdFromCredential(issued.secret)).toBe("install-abc");
  });

  it("returns undefined for anything not shaped like a credential", () => {
    expect(installIdFromCredential("nope")).toBeUndefined();
    expect(installIdFromCredential(`${CREDENTIAL_PREFIX}no-dot`)).toBeUndefined();
    // Empty id or empty secret half are both unusable.
    expect(installIdFromCredential(`${CREDENTIAL_PREFIX}.secret`)).toBeUndefined();
    expect(installIdFromCredential(`${CREDENTIAL_PREFIX}id.`)).toBeUndefined();
  });
});

describe("credentialMatches", () => {
  it("rejects a wrong secret for a known install", () => {
    const real = issueCredential("install-1");
    const other = issueCredential("install-1");
    // Same install id, different secret: the id is a lookup key, not a
    // credential, so it must not be sufficient on its own.
    expect(credentialMatches(other.secret, real.hash)).toBe(false);
  });

  it("rejects a truncated secret", () => {
    const issued = issueCredential("install-1");
    expect(
      credentialMatches(issued.secret.slice(0, -4), issued.hash),
    ).toBe(false);
  });

  it("returns false rather than throwing on a malformed stored hash", () => {
    const issued = issueCredential("install-1");
    // A short or non-hex stored hash must be a non-match. timingSafeEqual throws
    // on a length mismatch, and an exception escaping an auth check is how a
    // deny turns into a crash -- or, wrapped in a careless try/catch, an allow.
    expect(credentialMatches(issued.secret, "abcd")).toBe(false);
    expect(credentialMatches(issued.secret, "")).toBe(false);
    expect(credentialMatches(issued.secret, "zz".repeat(32))).toBe(false);
  });

  it("hashing is stable", () => {
    const secret = `${CREDENTIAL_PREFIX}i.abc`;
    expect(hashCredential(secret)).toBe(hashCredential(secret));
    expect(hashCredential(secret)).not.toBe(hashCredential(`${secret}x`));
  });
});
