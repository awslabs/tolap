/**
 * Branch coverage for context.ts: the canonicalizer, the algorithm switch, and the
 * signature/expiry validators.
 *
 * Signing is the control that makes a policy tamper-evident across process and
 * account boundaries, so a wrong branch here either accepts a forged context or
 * throws out of an enforcement check. Both are asserted below rather than merely
 * executed.
 */

import { describe, expect, it } from "vitest";
import {
  buildSecurityContext,
  deserializeContext,
  serializeContext,
  signContext,
  signPolicy,
  validateContext,
  validateExpiry,
  validatePolicy,
} from "../src/context.js";
import { SigningAlgorithm } from "../src/types.js";
import type { EffectivePolicy, SecurityContext } from "../src/types.js";

const KEY = "context-branch-key";

function policy(overrides: Partial<EffectivePolicy> = {}): EffectivePolicy {
  const now = new Date();
  return {
    version: "1.0",
    userId: "user-001",
    tenantId: "tenant-001",
    sourceConnectionId: "db:production:x",
    resolvedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 3_600_000).toISOString(),
    sourceProfiles: ["context-branches"],
    permissions: { canQuery: true, canExport: false, readOnly: true },
    integrity: { algorithm: "none", signature: "" },
    ...overrides,
  };
}

function signedContext(
  overrides: Partial<EffectivePolicy> = {},
  ttlMs = 3_600_000,
  algorithm: string = SigningAlgorithm.HmacSha256,
): SecurityContext {
  const p = policy(overrides);
  return signContext(buildSecurityContext(p.userId, p.tenantId, p, ttlMs), KEY, algorithm);
}

// ---------------------------------------------------------------------------
// Canonicalization -- the branches that decide the signed bytes
// ---------------------------------------------------------------------------

describe("canonicalization: the value-shape branches", () => {
  it("a null field is dropped, so it signs the same as an absent one", () => {
    // Spec §1: a null field is indistinguishable from an absent one. If null were
    // passed through, two contexts the spec calls identical would produce different
    // signatures and cross-SDK verification would fail.
    const withNull = policy({ objectRules: null as unknown as undefined });
    const absent = policy();
    absent.resolvedAt = withNull.resolvedAt;
    absent.expiresAt = withNull.expiresAt;

    expect(signPolicy(withNull, KEY).integrity.signature).toBe(
      signPolicy(absent, KEY).integrity.signature,
    );
  });

  it("a null INSIDE AN ARRAY is preserved, not silently removed", () => {
    // Null-dropping applies to object PROPERTIES, where null and absent are
    // indistinguishable. Array elements are positional, so dropping one would
    // renumber the rest and change the meaning of the signed data -- e.g. a
    // rowFilters `values: [null, "x"]` list. So `deepSortKeys` returns a null array
    // element as-is, and two policies differing only in a null element must sign
    // differently.
    const base = { resolvedAt: "2026-01-15T10:00:00Z", expiresAt: "2026-01-15T11:00:00Z" };
    const withNullElement = policy({
      ...base,
      objectRules: {
        rowFilters: [{ field: "x", operator: "in", values: [null, "x"] }],
      },
    });
    const withoutNullElement = policy({
      ...base,
      objectRules: {
        rowFilters: [{ field: "x", operator: "in", values: ["x"] }],
      },
    });

    expect(signPolicy(withNullElement, KEY).integrity.signature).not.toBe(
      signPolicy(withoutNullElement, KEY).integrity.signature,
    );
    // And it still round-trips: the null survives canonicalization intact.
    expect(validatePolicy(signPolicy(withNullElement, KEY), KEY)).toBe(true);
  });

  it("a null NESTED field is dropped, leaving its parent object present", () => {
    // Dropping happens at every level, so `{objectRules: {allowedObjects: null}}`
    // signs as `{objectRules: {}}` -- distinct from omitting objectRules entirely,
    // which is correct: the parent object IS present in the transported policy.
    const nestedNull = policy({
      objectRules: { allowedObjects: null as unknown as string[] },
    });
    const emptyParent = policy({ objectRules: {} });
    emptyParent.resolvedAt = nestedNull.resolvedAt;
    emptyParent.expiresAt = nestedNull.expiresAt;

    expect(signPolicy(nestedNull, KEY).integrity.signature).toBe(
      signPolicy(emptyParent, KEY).integrity.signature,
    );
  });

  it("an EMPTY array is preserved and changes the signature", () => {
    // Spec §1/§3: `[]` is semantically distinct from absent -- it means deny-all --
    // so it must survive canonicalization.
    const empty = policy({ objectRules: { allowedObjects: [] } });
    const absent = policy();
    absent.resolvedAt = empty.resolvedAt;
    absent.expiresAt = empty.expiresAt;

    expect(signPolicy(empty, KEY).integrity.signature).not.toBe(
      signPolicy(absent, KEY).integrity.signature,
    );
  });

  it("key order in the input does not change the signature", () => {
    const shared = policy();
    const a = { ...shared, objectRules: { allowedObjects: ["x"], hiddenObjects: ["y"] } };
    const b = { ...shared, objectRules: { hiddenObjects: ["y"], allowedObjects: ["x"] } };

    expect(signPolicy(a, KEY).integrity.signature).toBe(
      signPolicy(b, KEY).integrity.signature,
    );
  });

  it("nested arrays and objects are both walked", () => {
    const withNested = policy({
      objectRules: {
        rowFilters: [{ field: "x", operator: "in", values: [1, 2, 3] }],
        fieldRules: { maskedFields: [{ field: "ssn", maskType: "null" }] },
      },
    });

    expect(() => signPolicy(withNested, KEY)).not.toThrow();
    expect(validatePolicy(signPolicy(withNested, KEY), KEY)).toBe(true);
  });

  it("scalar leaf types all survive canonicalization", () => {
    const withScalars = policy({
      objectRules: {
        rowFilters: [
          { field: "s", operator: "equals", value: "text" },
          { field: "n", operator: "equals", value: 42 },
          { field: "b", operator: "equals", value: true },
        ],
      },
    });

    expect(validatePolicy(signPolicy(withScalars, KEY), KEY)).toBe(true);
  });

  it("the integrity block is excluded, so signing is idempotent", () => {
    // A signature cannot sign itself: re-signing an already-signed policy must
    // produce the same bytes rather than folding the previous signature in.
    const p = policy();
    const first = signPolicy(p, KEY).integrity.signature;
    const second = signPolicy(p, KEY).integrity.signature;

    expect(second).toBe(first);
  });

  it("a policy-level timestamp is normalized before signing", () => {
    // resolvedAt/expiresAt inside the policy are normalized too, so `+00:00` and
    // `Z` -- and sub-millisecond precision -- do not produce different bytes than
    // the other SDKs would sign.
    const zSuffix = policy({
      resolvedAt: "2026-01-15T10:00:00Z",
      expiresAt: "2026-06-15T10:00:00Z",
    });
    const offset = policy({
      resolvedAt: "2026-01-15T10:00:00+00:00",
      expiresAt: "2026-06-15T10:00:00.000+00:00",
    });

    expect(signPolicy(offset, KEY).integrity.signature).toBe(
      signPolicy(zSuffix, KEY).integrity.signature,
    );
  });

  it("a non-string policy timestamp is left alone rather than crashing", () => {
    const weird = policy({ resolvedAt: 12345 as unknown as string });
    expect(() => signPolicy(weird, KEY)).not.toThrow();
  });

  it("policy-ALONE signing normalizes timestamps exactly as envelope signing does", () => {
    // Spec §1 ("all signature computation uses this form and only this form") plus
    // §2 rules 4-5. signPolicy previously skipped the normalization that the
    // envelope projection applied, so on the policy-alone path `+00:00` vs `Z`, an
    // explicit `.000`, and sub-millisecond precision each produced DIFFERENT bytes
    // for the same instant -- while the envelope path treated them as identical.
    // A policy whose timestamps were reformatted in transit then failed its own
    // integrity check with an error indistinguishable from tampering.
    const canonical = policy({
      resolvedAt: "2026-01-15T10:00:00Z",
      expiresAt: "2026-01-15T11:00:00Z",
    });
    const equivalents = [
      { resolvedAt: "2026-01-15T10:00:00+00:00", expiresAt: "2026-01-15T11:00:00+00:00" },
      { resolvedAt: "2026-01-15T10:00:00.000Z", expiresAt: "2026-01-15T11:00:00.000Z" },
      { resolvedAt: "2026-01-15T05:00:00-05:00", expiresAt: "2026-01-15T06:00:00-05:00" },
    ];

    const expected = signPolicy(canonical, KEY).integrity.signature;
    for (const form of equivalents) {
      expect(
        signPolicy(policy(form), KEY).integrity.signature,
        `${form.resolvedAt} must sign as ${canonical.resolvedAt}`,
      ).toBe(expected);
    }
  });

  it("policy-alone signing truncates sub-millisecond precision, not pads it", () => {
    // Milliseconds are the greatest precision all three runtimes represent exactly
    // (spec §2 rule 5), so `.123456Z` and `.1239Z` must both sign as `.123Z`.
    // Pin expiresAt too: the policy() helper derives it from the current clock, so
    // leaving it floating would make each signature differ for an unrelated reason.
    const at = (resolvedAt: string) =>
      signPolicy(policy({ resolvedAt, expiresAt: "2026-01-15T11:00:00Z" }), KEY)
        .integrity.signature;

    const truncated = at("2026-01-15T10:00:00.123Z");
    for (const precise of ["2026-01-15T10:00:00.123456Z", "2026-01-15T10:00:00.1239Z"]) {
      expect(at(precise), `${precise} must sign as .123Z`).toBe(truncated);
    }
    // And the truncated form is genuinely different from the whole second, so the
    // milliseconds are not simply being dropped.
    expect(at("2026-01-15T10:00:00Z")).not.toBe(truncated);
  });

  it("a DIFFERENT instant still signs differently after normalization", () => {
    // Normalization must not flatten genuinely different timestamps into one, or
    // rewriting an expiry would stop being detectable.
    const original = signPolicy(
      policy({ expiresAt: "2026-01-15T11:00:00Z" }),
      KEY,
    ).integrity.signature;
    const extended = signPolicy(
      policy({ expiresAt: "2027-01-15T11:00:00Z" }),
      KEY,
    ).integrity.signature;
    const oneMilli = signPolicy(
      policy({ expiresAt: "2026-01-15T11:00:00.001Z" }),
      KEY,
    ).integrity.signature;

    expect(extended).not.toBe(original);
    expect(oneMilli).not.toBe(original);
  });

  it("a policy signed with a reformatted-but-equivalent timestamp still validates", () => {
    // The end-to-end consequence: sign with `Z`, transport reformats to `+00:00`,
    // integrity check must still pass.
    const signed = signPolicy(
      policy({ resolvedAt: "2026-01-15T10:00:00Z", expiresAt: "2026-01-15T11:00:00Z" }),
      KEY,
    );
    const reformatted: EffectivePolicy = {
      ...signed,
      resolvedAt: "2026-01-15T10:00:00.000+00:00",
      expiresAt: "2026-01-15T11:00:00.000+00:00",
    };

    expect(validatePolicy(reformatted, KEY)).toBe(true);
  });

  it("an absent userId/tenantId canonicalizes to the empty string", () => {
    const bare = policy({
      userId: undefined as unknown as string,
      tenantId: undefined as unknown as string,
    });
    const ctx = buildSecurityContext("", "", bare, 3_600_000);

    expect(() => signContext(ctx, KEY)).not.toThrow();
    expect(validateContext(signContext(ctx, KEY), KEY)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// The algorithm switch -- both supported arms and the unsupported default
// ---------------------------------------------------------------------------

describe("the signing-algorithm switch", () => {
  it("hmac-sha256 and hmac-sha512 both sign and verify, and differ", () => {
    const p = policy();
    const sha256 = signPolicy({ ...p }, KEY, SigningAlgorithm.HmacSha256);
    const sha512 = signPolicy({ ...p }, KEY, SigningAlgorithm.HmacSha512);

    expect(validatePolicy(sha256, KEY)).toBe(true);
    expect(validatePolicy(sha512, KEY)).toBe(true);
    expect(sha256.integrity.signature).not.toBe(sha512.integrity.signature);
  });

  it("a sha512 context verifies through validateContext", () => {
    expect(validateContext(signedContext({}, 3_600_000, SigningAlgorithm.HmacSha512), KEY)).toBe(
      true,
    );
  });

  it("signing with an UNSUPPORTED algorithm throws at signing time", () => {
    // Loud at signing: the issuer is misconfigured and no usable signature exists.
    // ed25519 is in the schema enum but unimplemented in this SDK.
    expect(() => signPolicy(policy(), KEY, SigningAlgorithm.Ed25519)).toThrow(
      /Unsupported signing algorithm/,
    );
    expect(() =>
      signContext(buildSecurityContext("u", "t", policy(), 1000), KEY, "made-up"),
    ).toThrow(/Unsupported signing algorithm/);
  });

  it("VALIDATING an unsupported algorithm returns false rather than throwing", () => {
    // An attacker controls the algorithm field on a presented context, so an
    // unknown value must be a denial, not an exception escaping an enforcement
    // check. ed25519 is schema-valid, so this is reachable without a malformed
    // policy at all.
    const ctx = signedContext();
    ctx.algorithm = SigningAlgorithm.Ed25519;
    expect(() => validateContext(ctx, KEY)).not.toThrow();
    expect(validateContext(ctx, KEY)).toBe(false);

    const p = signPolicy(policy(), KEY);
    p.integrity.algorithm = SigningAlgorithm.Ed25519;
    expect(() => validatePolicy(p, KEY)).not.toThrow();
    expect(validatePolicy(p, KEY)).toBe(false);
  });

  it("an arbitrary attacker-chosen algorithm is also a denial, not a crash", () => {
    for (const algorithm of ["none", "", "HMAC-SHA256", "md5", "../../etc"]) {
      const ctx = signedContext();
      ctx.algorithm = algorithm;
      expect(() => validateContext(ctx, KEY)).not.toThrow();
      expect(validateContext(ctx, KEY), `algorithm ${algorithm}`).toBe(false);

      const p = signPolicy(policy(), KEY);
      p.integrity.algorithm = algorithm;
      expect(validatePolicy(p, KEY), `policy algorithm ${algorithm}`).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------
// validateContext -- every rejection path
// ---------------------------------------------------------------------------

describe("validateContext: every rejection path", () => {
  it("accepts a correctly signed context", () => {
    expect(validateContext(signedContext(), KEY)).toBe(true);
  });

  it("rejects a context with no signature or no algorithm", () => {
    const noSig = signedContext();
    delete noSig.signature;
    expect(validateContext(noSig, KEY)).toBe(false);

    const noAlgo = signedContext();
    delete noAlgo.algorithm;
    expect(validateContext(noAlgo, KEY)).toBe(false);

    const emptySig = signedContext();
    emptySig.signature = "";
    expect(validateContext(emptySig, KEY)).toBe(false);
  });

  it("rejects the wrong key", () => {
    expect(validateContext(signedContext(), "wrong-key")).toBe(false);
  });

  it("rejects a signature of a DIFFERENT LENGTH without throwing", () => {
    // timingSafeEqual throws on a length mismatch, so the length pre-check is what
    // keeps a truncated signature a denial rather than a crash.
    const ctx = signedContext();
    ctx.signature = "AAAA";
    expect(() => validateContext(ctx, KEY)).not.toThrow();
    expect(validateContext(ctx, KEY)).toBe(false);
  });

  it("rejects a same-length but wrong signature", () => {
    const ctx = signedContext();
    const flipped = ctx.signature!.startsWith("A") ? "B" : "A";
    ctx.signature = flipped + ctx.signature!.slice(1);
    expect(validateContext(ctx, KEY)).toBe(false);
  });

  it("EXPLOIT: rewriting expiresAt invalidates the signature", () => {
    // The expiry is INSIDE the signed payload (spec §2), so extending the life of a
    // captured context is detectable rather than free.
    const ctx = signedContext();
    ctx.expiresAt = new Date(Date.now() + 10 * 365 * 86_400_000).toISOString();
    expect(validateContext(ctx, KEY)).toBe(false);
  });

  it("EXPLOIT: rewriting resolvedAt invalidates the signature", () => {
    const ctx = signedContext();
    ctx.resolvedAt = new Date(0).toISOString();
    expect(validateContext(ctx, KEY)).toBe(false);
  });

  it("EXPLOIT: escalating the policy inside the envelope invalidates the signature", () => {
    const ctx = signedContext({ permissions: { canQuery: true, readOnly: true } });
    ctx.effectivePolicy.permissions.readOnly = false;
    ctx.effectivePolicy.permissions.canExport = true;
    expect(validateContext(ctx, KEY)).toBe(false);
  });

  it("EXPLOIT: swapping the userId invalidates the signature", () => {
    const ctx = signedContext();
    ctx.effectivePolicy.userId = "attacker";
    expect(validateContext(ctx, KEY)).toBe(false);
  });

  it("a rewritten policy integrity block does NOT affect the envelope signature", () => {
    // The integrity block is excluded from the envelope payload, so replacing it
    // must not invalidate the envelope -- the envelope signature covers the policy
    // content itself, which is what matters.
    const ctx = signedContext();
    ctx.effectivePolicy.integrity = { algorithm: "none", signature: "" };
    expect(validateContext(ctx, KEY)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// validatePolicy -- every rejection path
// ---------------------------------------------------------------------------

describe("validatePolicy: every rejection path", () => {
  it("accepts a correctly signed policy", () => {
    expect(validatePolicy(signPolicy(policy(), KEY), KEY)).toBe(true);
  });

  it("rejects an absent integrity block, signature, or algorithm", () => {
    expect(
      validatePolicy({ ...policy(), integrity: undefined } as unknown as EffectivePolicy, KEY),
    ).toBe(false);

    const noSig = signPolicy(policy(), KEY);
    noSig.integrity.signature = "";
    expect(validatePolicy(noSig, KEY)).toBe(false);

    const noAlgo = signPolicy(policy(), KEY);
    noAlgo.integrity.algorithm = "";
    expect(validatePolicy(noAlgo, KEY)).toBe(false);
  });

  it("rejects the wrong key and a tampered field", () => {
    expect(validatePolicy(signPolicy(policy(), KEY), "wrong")).toBe(false);

    const tampered = signPolicy(policy(), KEY);
    tampered.permissions.canExport = true;
    expect(validatePolicy(tampered, KEY)).toBe(false);
  });

  it("rejects a length-mismatched signature without throwing", () => {
    const p = signPolicy(policy(), KEY);
    p.integrity.signature = "AA";
    expect(() => validatePolicy(p, KEY)).not.toThrow();
    expect(validatePolicy(p, KEY)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// validateExpiry -- all four exits
// ---------------------------------------------------------------------------

describe("validateExpiry: all four exits", () => {
  const ctx = (expiresAt: string | undefined): SecurityContext => ({
    effectivePolicy: policy(),
    resolvedAt: new Date().toISOString(),
    expiresAt: expiresAt as string,
  });

  it("a future expiry is valid", () => {
    expect(validateExpiry(ctx(new Date(Date.now() + 60_000).toISOString()))).toBeUndefined();
  });

  it("an absent or empty expiry is a denial, never 'never expires'", () => {
    expect(validateExpiry(ctx(undefined))).toBe("security context has no expiry");
    expect(validateExpiry(ctx(""))).toBe("security context has no expiry");
  });

  it("an UNPARSEABLE expiry is a denial, not a skipped check", () => {
    // `new Date("never") <= new Date()` is `false` in JavaScript, which previously
    // granted an unbounded lifetime to any context carrying a malformed timestamp
    // (spec §2).
    for (const bad of ["never", "not-a-date", "2026-13-45T99:99:99Z", "tomorrow"]) {
      expect(new Date(bad) <= new Date()).toBe(false); // the old verdict
      expect(validateExpiry(ctx(bad)), `expiresAt=${bad}`).toBe("invalid expiry format");
    }
  });

  it("a past expiry, and one exactly at now, are both expired", () => {
    expect(validateExpiry(ctx(new Date(Date.now() - 1).toISOString()))).toBe(
      "security context expired",
    );
    // The comparison is `<=`, so the boundary instant is expired.
    expect(validateExpiry(ctx(new Date(Date.now()).toISOString()))).toBe(
      "security context expired",
    );
  });
});

// ---------------------------------------------------------------------------
// Serialization round-trip and its rejection paths
// ---------------------------------------------------------------------------

describe("serialize / deserialize", () => {
  it("round-trips a signed context", () => {
    const ctx = signedContext();
    const restored = deserializeContext(serializeContext(ctx), KEY);

    expect(restored.effectivePolicy.userId).toBe("user-001");
    expect(restored.signature).toBe(ctx.signature);
  });

  it("rejects non-base64 and non-JSON payloads", () => {
    expect(() => deserializeContext("!!!not base64!!!", KEY)).toThrow(
      /Failed to deserialize/,
    );
    expect(() =>
      deserializeContext(Buffer.from("not json").toString("base64"), KEY),
    ).toThrow(/Failed to deserialize/);
  });

  it("reports a SIGNATURE failure before an expiry failure", () => {
    // Spec §2: a tampered context must not leak whether a valid context had merely
    // expired. Here the context is BOTH tampered and expired; the reported error
    // must be the signature one.
    const ctx = signedContext({}, -1000);
    ctx.effectivePolicy.userId = "attacker";

    expect(() => deserializeContext(serializeContext(ctx), KEY)).toThrow(
      /signature validation failed/,
    );
  });

  it("rejects an expired but correctly signed context on expiry", () => {
    const expired = signedContext({}, -1000);
    expect(() => deserializeContext(serializeContext(expired), KEY)).toThrow(
      /rejected: security context expired/,
    );
  });

  it("rejects a signed context whose expiry is unparseable", () => {
    // Signed with the malformed value, so the signature is valid and expiry
    // validation is what has to catch it.
    const p = policy();
    const ctx: SecurityContext = {
      effectivePolicy: p,
      resolvedAt: new Date().toISOString(),
      expiresAt: "never",
    };
    signContext(ctx, KEY);

    expect(() => deserializeContext(serializeContext(ctx), KEY)).toThrow(
      /invalid expiry format/,
    );
  });

  it("rejects an unsigned context", () => {
    const unsigned = buildSecurityContext("u", "t", policy(), 3_600_000);
    expect(() => deserializeContext(serializeContext(unsigned), KEY)).toThrow(
      /signature validation failed/,
    );
  });
});

// ---------------------------------------------------------------------------
// buildSecurityContext
// ---------------------------------------------------------------------------

describe("buildSecurityContext", () => {
  it("derives expiresAt from the ttl and defaults to one hour", () => {
    const before = Date.now();
    const explicit = buildSecurityContext("u", "t", policy(), 60_000);
    const defaulted = buildSecurityContext("u", "t", policy());

    const explicitExpiry = new Date(explicit.expiresAt).getTime();
    expect(explicitExpiry).toBeGreaterThanOrEqual(before + 60_000);
    expect(explicitExpiry).toBeLessThan(before + 60_000 + 5_000);

    const defaultExpiry = new Date(defaulted.expiresAt).getTime();
    expect(defaultExpiry).toBeGreaterThanOrEqual(before + 3_600_000);
    expect(defaultExpiry).toBeLessThan(before + 3_600_000 + 5_000);
  });

  it("a negative ttl produces an already-expired context that fails validateExpiry", () => {
    expect(validateExpiry(buildSecurityContext("u", "t", policy(), -1))).toBe(
      "security context expired",
    );
  });

  it("carries the policy by reference and leaves it unsigned", () => {
    const p = policy();
    const ctx = buildSecurityContext("u", "t", p, 1000);

    expect(ctx.effectivePolicy).toBe(p);
    expect(ctx.signature).toBeUndefined();
    expect(ctx.algorithm).toBeUndefined();
  });

  it("rejects an array of policies instead of storing it", () => {
    // docs/architecture.md shows the context with a `policies` array, so a caller
    // reaching this through JS or `any` passes two policies. The type erases at
    // runtime: the array used to be stored verbatim, sign and validate cleanly, and
    // then crash enforcement with a bare "cannot read properties of undefined".
    const policies = [policy(), policy()] as unknown as ReturnType<typeof policy>;

    expect(() => buildSecurityContext("u", "t", policies)).toThrow(
      /expects a single effective policy, received an array of 2/,
    );
  });

  it("the array rejection names the remedy rather than only refusing", () => {
    const policies = [policy()] as unknown as ReturnType<typeof policy>;

    // Even a one-element array is refused: the caller believes the context is
    // multi-policy, and silently unwrapping would leave that belief intact.
    expect(() => buildSecurityContext("u", "t", policies)).toThrow(
      /one context per data source/,
    );
  });
});

// ---------------------------------------------------------------------------
// signContext side effects
// ---------------------------------------------------------------------------

describe("signContext sets both the envelope and policy signatures", () => {
  it("populates envelope signature/algorithm and the policy integrity block", () => {
    const ctx = buildSecurityContext("u", "t", policy(), 3_600_000);
    const signed = signContext(ctx, KEY);

    expect(signed).toBe(ctx); // mutates and returns the same object
    expect(signed.algorithm).toBe(SigningAlgorithm.HmacSha256);
    expect(signed.signature).toMatch(/^[A-Za-z0-9+/=]+$/);
    expect(signed.effectivePolicy.integrity.algorithm).toBe(SigningAlgorithm.HmacSha256);
    expect(signed.effectivePolicy.integrity.signature).not.toBe("");
  });

  it("the policy remains independently verifiable after being signed in an envelope", () => {
    // A policy extracted from an envelope must still verify on its own.
    const signed = signContext(buildSecurityContext("u", "t", policy(), 3_600_000), KEY);

    expect(validatePolicy(signed.effectivePolicy, KEY)).toBe(true);
    expect(validateContext(signed, KEY)).toBe(true);
  });

  it("the envelope and policy signatures are different values", () => {
    // They cover different payloads: the whole envelope vs the policy alone.
    const signed = signContext(buildSecurityContext("u", "t", policy(), 3_600_000), KEY);
    expect(signed.signature).not.toBe(signed.effectivePolicy.integrity.signature);
  });

  it("the default algorithm is hmac-sha256", () => {
    expect(signPolicy(policy(), KEY).integrity.algorithm).toBe(
      SigningAlgorithm.HmacSha256,
    );
  });
});
