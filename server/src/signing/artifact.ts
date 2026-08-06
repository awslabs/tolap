/**
 * The signed artifact `/v1/resolve` returns.
 *
 * This is the one place the server produces bytes that another process
 * cryptographically depends on, and it is the only genuinely new logic in the
 * server. Everything about the canonical form comes from `@tolap/core` -- this
 * module composes two SDK calls and adds one key. It does not serialize, sort,
 * or normalize anything itself, because
 * `docs/canonical-enforcement-spec.md` sections 1-2 are normative about the
 * exact bytes and any re-serialization through a generic JSON layer breaks
 * cross-SDK agreement.
 *
 * ## Why one artifact needs two signatures
 *
 * The three SDKs do not verify the same thing, and the differences are not
 * cosmetic:
 *
 * | SDK        | verifies                     | envelope instant | signature lives in |
 * | ---------- | ---------------------------- | ---------------- | ------------------ |
 * | Python     | the `SecurityContext`        | `issuedAt`       | flat `signature`   |
 * | TypeScript | the bare `EffectivePolicy`   | `resolvedAt`     | `integrity{}`      |
 * | .NET       | the `SecurityContext`        | `issuedAt`       | `Integrity{}`      |
 *
 * `SecureMcpToolWrapper` in TypeScript calls `validatePolicy(policy, key)` on the
 * policy its `resolvePolicy` hook returned -- it never sees an envelope. Python's
 * wrapper calls `validate_context` on an envelope. Those are HMACs over two
 * different byte strings (`canonicalize(policy)` versus
 * `canonicalPayload(envelope)`), so no single signature satisfies both.
 *
 * The artifact carries **both**, which works because the envelope projection
 * strips `integrity` from the policy before hashing (spec section 2 rule 1). The
 * policy-level signature is therefore invisible to the envelope signature, and
 * the two coexist without either invalidating the other. Emitting `issuedAt` and
 * `resolvedAt` with the same value covers the naming split -- the envelope has no
 * schema of its own, so the extra key is legal.
 *
 * `signContext` writes **both** signatures: the envelope's, and the policy's own
 * `integrity` block (`context.ts:233`), precisely so a policy lifted out of the
 * envelope stays independently verifiable. So one call is enough, and calling
 * `signPolicy` first would recompute the identical bytes and throw the result
 * away. An earlier draft of this file did exactly that; a mutation test that
 * removed the call and saw nothing fail is what surfaced it.
 *
 * Verified against all three real SDKs; `tests/cross-sdk-artifact.test.ts` keeps
 * it that way, and it is the test to look at first if this file is ever changed.
 */

import {
  buildSecurityContext,
  signContext,
  type EffectivePolicy,
} from "@tolap/core";

/**
 * The wire shape of a resolved, signed policy.
 *
 * Deliberately not the native `SecurityContext` of any one SDK: it is the union
 * of what all three accept. Consumers deserialize it with their own SDK's
 * function and never need to know it was produced by a TypeScript server.
 */
export interface SignedArtifact {
  /** The resolved policy, carrying its own `integrity` block. */
  readonly effectivePolicy: EffectivePolicy;
  /** Envelope issue instant. The spelling Python and .NET read. */
  readonly issuedAt: string;
  /** The same instant, spelled the way the TypeScript SDK reads it. */
  readonly resolvedAt: string;
  /** Envelope expiry. Inside the signed bytes, so it cannot be extended. */
  readonly expiresAt: string;
  /** Envelope signature, base64. */
  readonly signature: string;
  /** Signing algorithm, e.g. `hmac-sha256`. */
  readonly algorithm: string;
}

/**
 * Sign a resolved policy into an artifact every TOLAP SDK can verify.
 *
 * @param policy   A resolved `EffectivePolicy`. Mutated: both `signPolicy` and
 *                 `buildSecurityContext` write through in the SDK, so callers
 *                 should pass a policy they own rather than a cached one.
 * @param key      The HMAC signing key. Never leaves the server.
 * @param ttlMs    Artifact lifetime in milliseconds.
 */
export function buildSignedArtifact(
  policy: EffectivePolicy,
  key: string,
  ttlMs: number,
): SignedArtifact {
  const context = buildSecurityContext(
    policy.userId,
    policy.tenantId,
    policy,
    ttlMs,
  );

  // `buildSecurityContext` stamps its own `resolvedAt`/`expiresAt` from now +
  // ttl. The policy carries its own pair from resolution, which the TypeScript
  // resolver sets and the Python and .NET resolvers leave null -- so the
  // envelope's instants are the authoritative ones here and the caller is
  // responsible for the policy's.
  //
  // This single call produces the envelope signature *and* the policy's
  // integrity block, which is why both verification paths are satisfied.
  signContext(context, key);

  if (!context.signature || !context.algorithm) {
    // Unreachable via signContext, which always sets both. Asserted rather than
    // non-null-asserted so a future SDK change surfaces here instead of shipping
    // an unsigned artifact that fails at some integrator's enforcement boundary.
    throw new Error("signContext produced no signature");
  }

  const integrity = context.effectivePolicy.integrity;
  if (!integrity?.signature || integrity.algorithm === "none") {
    // The policy-level signature is what the TypeScript SecureMcpToolWrapper
    // verifies, and `resolve()` seeds this field with an `algorithm: "none"`
    // placeholder that is not even in the schema's algorithm enum. Shipping that
    // placeholder would fail every TypeScript integrator's enforcement check, so
    // assert it was overwritten rather than trusting the side effect.
    throw new Error(
      "signContext left the policy integrity block unsigned; " +
        "the TypeScript enforcement path would reject this artifact",
    );
  }

  return {
    effectivePolicy: context.effectivePolicy,
    issuedAt: context.resolvedAt,
    resolvedAt: context.resolvedAt,
    expiresAt: context.expiresAt,
    signature: context.signature,
    algorithm: context.algorithm,
  };
}

/**
 * Base64-encode an artifact for transports that want a single opaque string.
 *
 * This is the form Python's `deserialize_context` and .NET's
 * `SecurityContextSigner.Deserialize` take.
 */
export function encodeArtifact(artifact: SignedArtifact): string {
  return Buffer.from(JSON.stringify(artifact), "utf8").toString("base64");
}
