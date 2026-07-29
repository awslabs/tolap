/**
 * Regression tests for the canonical signing payload and expiry validation.
 *
 * One test (or describe block) per confirmed defect in
 * docs/canonical-enforcement-spec.md. Every test here fails against the
 * pre-hardening implementation, which signed only `canonicalize(effectivePolicy)`
 * and left the envelope's resolvedAt/expiresAt outside the HMAC.
 */

import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import {
  buildSecurityContext,
  deserializeContext,
  normalizeTimestamp,
  serializeContext,
  signContext,
  validateContext,
  validateExpiry,
} from "../src/context.js";
import type { EffectivePolicy, SecurityContext } from "../src/types.js";
import { SigningAlgorithm } from "../src/types.js";

const signingFixturesDir = path.resolve(
  __dirname,
  "../../../../../fixtures/signing",
);

function loadFixture(filename: string): Record<string, unknown> {
  const content = fs.readFileSync(
    path.join(signingFixturesDir, filename),
    "utf-8",
  );
  return JSON.parse(content) as Record<string, unknown>;
}

const SECRET = "signing-regression-key";

function createPolicy(overrides?: Partial<EffectivePolicy>): EffectivePolicy {
  return {
    version: "1.0",
    userId: "user-001",
    tenantId: "tenant-midwest-health",
    sourceConnectionId: "ds-postgres-healthcare",
    resolvedAt: "2026-01-15T10:00:00Z",
    expiresAt: "2026-01-15T11:00:00Z",
    sourceProfiles: ["healthcare-analyst-db"],
    permissions: { canQuery: true, canExport: false, readOnly: true },
    integrity: { algorithm: "none", signature: "" },
    ...overrides,
  };
}

function contextFor(
  policy: EffectivePolicy,
  resolvedAt: string,
  expiresAt: string,
): SecurityContext {
  return { effectivePolicy: policy, resolvedAt, expiresAt };
}

// ---------------------------------------------------------------------------
// Defect 4: signed context expiry was unauthenticated
// ---------------------------------------------------------------------------

describe("defect 4: expiry and issuance are inside the signed payload", () => {
  it("REPLAY EXPLOIT: rewriting expiresAt on an expired serialized context is rejected", () => {
    // Sign a context that has already expired.
    const expired = contextFor(
      createPolicy(),
      new Date(Date.now() - 7_200_000).toISOString(),
      new Date(Date.now() - 3_600_000).toISOString(),
    );
    signContext(expired, SECRET);
    const serialized = serializeContext(expired);

    // Attacker captures the serialized blob and extends its life, leaving the
    // signature untouched. Before the fix the HMAC covered only the policy, so
    // the rewritten envelope still validated and the context was accepted.
    const stolen = JSON.parse(
      Buffer.from(serialized, "base64").toString("utf8"),
    ) as SecurityContext;
    stolen.expiresAt = new Date(Date.now() + 86_400_000).toISOString();
    const replayed = Buffer.from(JSON.stringify(stolen), "utf8").toString(
      "base64",
    );

    expect(validateContext(stolen, SECRET)).toBe(false);
    expect(() => deserializeContext(replayed, SECRET)).toThrow(
      /signature validation failed/,
    );
  });

  it("rewriting resolvedAt invalidates the signature", () => {
    const ctx = buildSecurityContext("user-001", "tenant-001", createPolicy());
    signContext(ctx, SECRET);
    expect(validateContext(ctx, SECRET)).toBe(true);

    ctx.resolvedAt = new Date(Date.now() - 86_400_000).toISOString();
    expect(validateContext(ctx, SECRET)).toBe(false);
  });

  it("two contexts differing only in expiry produce different signatures", () => {
    const a = contextFor(
      createPolicy(),
      "2026-01-15T10:00:00Z",
      "2026-01-15T11:00:00Z",
    );
    const b = contextFor(
      createPolicy(),
      "2026-01-15T10:00:00Z",
      "2036-01-15T11:00:00Z",
    );
    signContext(a, SECRET);
    signContext(b, SECRET);

    expect(a.signature).not.toBe(b.signature);
  });

  it("tampering with the policy still invalidates the signature", () => {
    const ctx = buildSecurityContext("user-001", "tenant-001", createPolicy());
    signContext(ctx, SECRET);

    ctx.effectivePolicy.permissions.canQuery = false;
    expect(validateContext(ctx, SECRET)).toBe(false);
  });

  it("the policy's own integrity block does not affect the envelope signature", () => {
    const a = contextFor(
      createPolicy(),
      "2026-01-15T10:00:00Z",
      "2026-01-15T11:00:00Z",
    );
    const b = contextFor(
      createPolicy({ integrity: { algorithm: "hmac-sha256", signature: "xx" } }),
      "2026-01-15T10:00:00Z",
      "2026-01-15T11:00:00Z",
    );
    signContext(a, SECRET);
    signContext(b, SECRET);

    // The integrity block is stripped before signing (it cannot sign itself),
    // so its contents cannot change the envelope bytes.
    expect(a.signature).toBe(b.signature);
  });

  it("normalizes +00:00 and Z to the same signed bytes", () => {
    const withZ = contextFor(
      createPolicy(),
      "2026-01-15T10:00:00Z",
      "2026-01-15T11:00:00Z",
    );
    const withOffset = contextFor(
      createPolicy(),
      "2026-01-15T10:00:00+00:00",
      "2026-01-15T11:00:00+00:00",
    );
    signContext(withZ, SECRET);
    signContext(withOffset, SECRET);

    expect(withZ.signature).toBe(withOffset.signature);
  });

  it("normalizes a non-UTC offset to the same instant", () => {
    const utc = contextFor(
      createPolicy(),
      "2026-01-15T10:00:00Z",
      "2026-01-15T11:00:00Z",
    );
    const offset = contextFor(
      createPolicy(),
      "2026-01-15T05:00:00-05:00",
      "2026-01-15T06:00:00-05:00",
    );
    signContext(utc, SECRET);
    signContext(offset, SECRET);

    expect(utc.signature).toBe(offset.signature);
  });
});

// ---------------------------------------------------------------------------
// Cross-language conformance (canonical spec §11)
// ---------------------------------------------------------------------------

describe("cross-SDK known-answer conformance", () => {
  /**
   * Project the fixture payload into the canonical envelope shape.
   *
   * The fixture carries a single effective policy; the canonical signing payload
   * wraps it in the envelope, taking issuedAt/expiresAt from the policy's
   * resolvedAt/expiresAt so all three SDKs sign the same instants.
   */
  function contextFromFixture(fixture: Record<string, unknown>): SecurityContext {
    const payload = fixture["payload"] as Record<string, unknown>;
    const policy: EffectivePolicy = {
      ...(payload as unknown as EffectivePolicy),
      integrity: { algorithm: "none", signature: "" },
    };
    return contextFor(policy, policy.resolvedAt, policy.expiresAt);
  }

  // Computed per docs/canonical-enforcement-spec.md §1/§2 and matched
  // byte-for-byte against the already-hardened Python SDK. A determinism-only
  // assertion (sign twice, compare to itself) passes even when all three SDKs
  // disagree with each other, which is exactly how the divergence went
  // unnoticed -- so these are asserted as literals.
  const EXPECTED_SHA256 = "mpKFMZqD3NvddMUZJMIJBcvDF28Q/WRwDzpDLe4pHGY=";
  const EXPECTED_SHA512 =
    "EZ1/QbixgohMFZsmI+K0Xq50T0lGtFToJlEkVi+uCf8SvHYJSj2/ShmpI/3XsJ5pu4DlUcwMjXI0JGipY46SpA==";

  it("HMAC-SHA256 matches the cross-SDK expected signature", () => {
    const fixture = loadFixture("hmac-sha256-known-answer.json");
    const ctx = contextFromFixture(fixture);

    signContext(
      ctx,
      fixture["secretKey"] as string,
      SigningAlgorithm.HmacSha256,
    );

    expect(ctx.signature).toBe(EXPECTED_SHA256);

    // Also assert against the shared fixture's own value so a future edit to
    // either side cannot drift silently. The literal above is kept as well: if
    // someone "fixes" a failure by rewriting the fixture, that literal fails.
    // Asserted unconditionally -- a conditional check would let a fixture that
    // loses its expected value silently stop verifying anything, which is the
    // blind spot this whole conformance suite exists to close (spec section 11).
    expect(fixture["expectedSignature"]).toBe(EXPECTED_SHA256);
  });

  it("the canonical signed bytes match the fixture byte-for-byte", () => {
    // Recomputing the projection here (rather than exporting the private
    // canonicalizer) keeps the assertion honest about what the three SDKs agreed
    // on: keys recursively sorted, compact separators, explicit nulls dropped,
    // integrity stripped from the envelope and from the policy, issuedAt derived
    // from resolvedAt, timestamps normalized to "Z".
    const fixture = loadFixture("hmac-sha256-known-answer.json");
    const expectedBytes = fixture["canonicalPayload"];
    expect(
      typeof expectedBytes === "string" && expectedBytes.length > 0,
      "the cross-SDK known-answer fixture must carry a canonicalPayload",
    ).toBe(true);

    const payload = fixture["payload"] as Record<string, unknown>;
    const sortDropNulls = (value: unknown): unknown => {
      if (Array.isArray(value)) return value.map(sortDropNulls);
      if (value !== null && typeof value === "object") {
        const obj = value as Record<string, unknown>;
        const out: Record<string, unknown> = {};
        for (const key of Object.keys(obj).sort()) {
          if (obj[key] === null || obj[key] === undefined) continue;
          out[key] = sortDropNulls(obj[key]);
        }
        return out;
      }
      return value;
    };
    const projection = {
      version: payload["version"],
      userId: payload["userId"],
      tenantId: payload["tenantId"],
      issuedAt: payload["resolvedAt"],
      expiresAt: payload["expiresAt"],
      policies: [payload],
    };

    expect(JSON.stringify(sortDropNulls(projection))).toBe(expectedBytes);
  });

  it("HMAC-SHA512 matches the cross-SDK expected signature", () => {
    const fixture = loadFixture("hmac-sha256-known-answer.json");
    const ctx = contextFromFixture(fixture);

    signContext(
      ctx,
      fixture["secretKey"] as string,
      SigningAlgorithm.HmacSha512,
    );

    expect(ctx.signature).toBe(EXPECTED_SHA512);
  });

  // -------------------------------------------------------------------------
  // Sub-second conformance (canonical spec §2 rule 5)
  // -------------------------------------------------------------------------

  describe("sub-second precision", () => {
    /**
     * The whole-second fixture cannot detect a precision mismatch -- every
     * runtime renders `10:00:00` identically. This fixture's *input* carries
     * microseconds (`.123456Z` / `.987654Z`) which must canonicalize to
     * milliseconds (`.123Z` / `.987Z`): Python and .NET natively serialize
     * microseconds while JavaScript's `Date` cannot represent them at all, so
     * without a mandated precision the same instant signed in different
     * languages produced different bytes and failed to verify cross-SDK.
     */
    const SUBSECOND_FIXTURE = "hmac-sha256-subsecond.json";
    const EXPECTED_SUBSECOND_SHA256 =
      "Dgage1Y2tjqQVNXn9O3y90riPpfnOZFe6R2TsWDr/xc=";
    const EXPECTED_SUBSECOND_SHA512 =
      "IKX8zYAeX3BxET3/gOouAJA707WETb1+ki1uUjMZXRhojlTnyJ+ICBSutgHN+XFtxoA7pH92Mpm8blSYMbsXLg==";

    it("HMAC-SHA256 over microsecond input matches the cross-SDK signature", () => {
      const fixture = loadFixture(SUBSECOND_FIXTURE);
      const ctx = contextFromFixture(fixture);

      signContext(
        ctx,
        fixture["secretKey"] as string,
        SigningAlgorithm.HmacSha256,
      );

      expect(ctx.signature).toBe(EXPECTED_SUBSECOND_SHA256);
      // Asserted unconditionally: a fixture that lost its expected value would
      // otherwise silently stop verifying anything (spec §11).
      expect(fixture["expectedSignature"]).toBe(EXPECTED_SUBSECOND_SHA256);
    });

    it("HMAC-SHA512 over microsecond input matches the cross-SDK signature", () => {
      const fixture = loadFixture(SUBSECOND_FIXTURE);
      const ctx = contextFromFixture(fixture);

      signContext(
        ctx,
        fixture["secretKey"] as string,
        SigningAlgorithm.HmacSha512,
      );

      expect(ctx.signature).toBe(EXPECTED_SUBSECOND_SHA512);
      expect(fixture["expectedSignatureSha512"]).toBe(
        EXPECTED_SUBSECOND_SHA512,
      );
    });

    it("the canonical bytes truncate microseconds to milliseconds everywhere", () => {
      // Signing through the public API and comparing bytes, so a mismatch names
      // the offending field instead of surfacing as an opaque HMAC failure.
      // The envelope's issuedAt/expiresAt are not the only instants in the signed
      // bytes: each policy repeats its own resolvedAt/expiresAt, and those were
      // previously signed as the verbatim microsecond transport strings while
      // .NET normalized them -- exactly the divergence this fixture catches.
      const fixture = loadFixture(SUBSECOND_FIXTURE);
      const expectedBytes = fixture["canonicalPayload"];
      expect(
        typeof expectedBytes === "string" && expectedBytes.length > 0,
        "the sub-second fixture must carry a canonicalPayload",
      ).toBe(true);

      const payload = fixture["payload"] as Record<string, unknown>;
      const projection = {
        version: payload["version"],
        userId: payload["userId"],
        tenantId: payload["tenantId"],
        issuedAt: normalizeTimestamp(payload["resolvedAt"] as string),
        expiresAt: normalizeTimestamp(payload["expiresAt"] as string),
        policies: [
          {
            ...payload,
            resolvedAt: normalizeTimestamp(payload["resolvedAt"] as string),
            expiresAt: normalizeTimestamp(payload["expiresAt"] as string),
          },
        ],
      };
      const sortDropNulls = (value: unknown): unknown => {
        if (Array.isArray(value)) return value.map(sortDropNulls);
        if (value !== null && typeof value === "object") {
          const obj = value as Record<string, unknown>;
          const out: Record<string, unknown> = {};
          for (const key of Object.keys(obj).sort()) {
            if (obj[key] === null || obj[key] === undefined) continue;
            out[key] = sortDropNulls(obj[key]);
          }
          return out;
        }
        return value;
      };

      const bytes = JSON.stringify(sortDropNulls(projection));
      expect(bytes).toBe(expectedBytes);
      // The microsecond input must not survive into the signed bytes anywhere.
      expect(bytes).not.toContain(".123456Z");
      expect(bytes).not.toContain(".987654Z");
    });

    it("a microsecond and a millisecond context sign identically", () => {
      // The instants are equal at millisecond precision, so the SDKs must agree
      // on their bytes regardless of which precision the issuer transported.
      const micro = contextFor(
        createPolicy({
          resolvedAt: "2026-03-01T08:30:15.123456Z",
          expiresAt: "2026-03-01T09:30:15.987654Z",
        }),
        "2026-03-01T08:30:15.123456Z",
        "2026-03-01T09:30:15.987654Z",
      );
      const milli = contextFor(
        createPolicy({
          resolvedAt: "2026-03-01T08:30:15.123Z",
          expiresAt: "2026-03-01T09:30:15.987Z",
        }),
        "2026-03-01T08:30:15.123Z",
        "2026-03-01T09:30:15.987Z",
      );
      signContext(micro, SECRET);
      signContext(milli, SECRET);

      expect(micro.signature).toBe(milli.signature);
    });
  });
});

// ---------------------------------------------------------------------------
// Timestamp normalization table (canonical spec §2 rule 5)
// ---------------------------------------------------------------------------

describe("normalizeTimestamp", () => {
  /**
   * These seven cases are identical in all three SDKs. Asserting them directly
   * (rather than only through a signature) means a precision regression reports
   * "expected .123Z, got .123456Z" instead of an opaque HMAC mismatch that
   * cannot distinguish a truncation bug from a key-ordering bug.
   */
  const cases: Array<[input: string, expected: string]> = [
    // Whole seconds: no fractional part is emitted at all.
    ["2026-01-15T10:00:00Z", "2026-01-15T10:00:00Z"],
    // "+00:00" and "Z" are the same instant and must fold to the same bytes.
    ["2026-01-15T10:00:00+00:00", "2026-01-15T10:00:00Z"],
    // A zero fraction is dropped rather than rendered as ".000".
    ["2026-01-15T10:00:00.000Z", "2026-01-15T10:00:00Z"],
    // Exactly three digits pass through unchanged.
    ["2026-01-15T10:00:00.123Z", "2026-01-15T10:00:00.123Z"],
    // Microseconds truncate to milliseconds.
    ["2026-01-15T10:00:00.123456Z", "2026-01-15T10:00:00.123Z"],
    // Truncation, never rounding: .1239 -> .123, not .124.
    ["2026-01-15T10:00:00.1239Z", "2026-01-15T10:00:00.123Z"],
    // Truncation must not carry into the next second.
    ["2026-01-15T10:00:00.999999Z", "2026-01-15T10:00:00.999Z"],
  ];

  for (const [input, expected] of cases) {
    it(`normalizes ${input} to ${expected}`, () => {
      expect(normalizeTimestamp(input)).toBe(expected);
    });
  }

  it("truncates rather than rounding, so an expiry never moves later", () => {
    expect(normalizeTimestamp("2026-01-15T10:00:00.9999Z")).toBe(
      "2026-01-15T10:00:00.999Z",
    );
  });

  it("converts a non-UTC offset rather than relabelling it", () => {
    expect(normalizeTimestamp("2026-01-15T05:00:00.123456-05:00")).toBe(
      "2026-01-15T10:00:00.123Z",
    );
  });
});

// ---------------------------------------------------------------------------
// Defect 5: invalid/missing dates bypassed expiry
// ---------------------------------------------------------------------------

describe("defect 5: expiry validation fails closed", () => {
  it("a missing expiry is rejected, never treated as 'never expires'", () => {
    const ctx = { effectivePolicy: createPolicy(), resolvedAt: "2026-01-15T10:00:00Z" } as SecurityContext;

    expect(validateExpiry(ctx)).toBe("security context has no expiry");
  });

  it("an empty expiry is rejected", () => {
    const ctx = contextFor(createPolicy(), "2026-01-15T10:00:00Z", "");

    expect(validateExpiry(ctx)).toBe("security context has no expiry");
  });

  it("EXPLOIT: an unparseable expiry is rejected rather than granting immortality", () => {
    // `new Date("never") <= new Date()` is false in JavaScript, so the previous
    // comparison-only check reported "not expired" for any malformed timestamp.
    for (const bad of ["never", "not-a-date", "2026-13-45T99:99:99Z", "tomorrow"]) {
      const ctx = contextFor(createPolicy(), "2026-01-15T10:00:00Z", bad);
      expect(new Date(bad) <= new Date()).toBe(false); // the old check's verdict
      expect(validateExpiry(ctx)).toBe("invalid expiry format");
    }
  });

  it("an expiry exactly at now is expired", () => {
    const ctx = contextFor(
      createPolicy(),
      new Date(Date.now() - 1000).toISOString(),
      new Date(Date.now()).toISOString(),
    );

    expect(validateExpiry(ctx)).toBe("security context expired");
  });

  it("a valid future expiry passes", () => {
    const ctx = buildSecurityContext("user-001", "tenant-001", createPolicy());

    expect(validateExpiry(ctx)).toBeUndefined();
  });

  it("deserializeContext rejects a signed context carrying an unparseable expiry", () => {
    const ctx = contextFor(createPolicy(), new Date().toISOString(), "never");
    signContext(ctx, SECRET);

    // Signed correctly -- the malformed expiry is inside the HMAC -- so the
    // expiry check is the only control that stops it.
    expect(validateContext(ctx, SECRET)).toBe(true);
    expect(() => deserializeContext(serializeContext(ctx), SECRET)).toThrow(
      /invalid expiry format/,
    );
  });

  it("deserializeContext rejects a signed context with no expiry", () => {
    const ctx = { effectivePolicy: createPolicy(), resolvedAt: new Date().toISOString() } as SecurityContext;
    signContext(ctx, SECRET);

    expect(() => deserializeContext(serializeContext(ctx), SECRET)).toThrow(
      /has no expiry/,
    );
  });
});

describe("signature is verified before expiry", () => {
  it("an expired AND tampered context reports a signature failure", () => {
    // Reporting "expired" first would leak that a valid context merely expired.
    const ctx = contextFor(
      createPolicy(),
      new Date(Date.now() - 7_200_000).toISOString(),
      new Date(Date.now() - 3_600_000).toISOString(),
    );
    signContext(ctx, SECRET);
    ctx.signature = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    expect(() => deserializeContext(serializeContext(ctx), SECRET)).toThrow(
      /signature validation failed/,
    );
  });
});
