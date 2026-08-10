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
import type { SigningKey } from "./keyring.ts";

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
  /**
   * Unique artifact identifier for replay detection (spec section 13).
   *
   * **Inside the signed payload**, unlike `kid`: it cannot be stripped or swapped
   * without invalidating the signature, which is what makes a consumer-side
   * `ReplayGuard` non-bypassable. It must therefore be carried on the wire — the
   * server signs it, so an artifact that omitted it would fail verification in
   * every SDK.
   *
   * Replay detection remains opt-in at the consumer: the id alone records nothing,
   * and single-use enforcement needs state the SDK does not assume.
   */
  readonly jti: string;
  /**
   * Which key signed this, so a consumer holding several can pick one during a
   * rotation overlap.
   *
   * **Outside the signed payload, and therefore only a hint.** The canonical
   * projection is fixed to `{version,userId,tenantId,issuedAt,expiresAt,policies[]}`
   * (spec section 2), so this key cannot alter the signed bytes -- which is exactly
   * why it can be added without any SDK change, and exactly why it must never be
   * trusted. A forged `kid` selects a key under which the signature fails; that is
   * a denial. A consumer must not respond to an unknown `kid` by trying every key
   * it holds, which would turn this field into an oracle.
   */
  readonly kid: string;

  /**
   * Envelope-level fields, for SDKs that deserialize into their own
   * `SecurityContext` type rather than reading this shape field by field.
   *
   * Added because the artifact did not in fact deserialize in .NET. `SecurityContext`
   * there (`sdk/dotnet/src/Tolap.Core/Models.cs`) declares `Version`, `UserId`,
   * `TenantId`, `Policies[]` and `Integrity{}` at the envelope level, and the artifact
   * carried none of them -- so `TolapJsonOptions.Deserialize<SecurityContext>` produced
   * an object of nulls with an empty policy array, and `Validate` then signed those
   * nulls and rejected. A .NET consumer following the documented path could not use the
   * artifact at all.
   *
   * The tests missed it because both .NET arms hand-built the context from JSON fields
   * instead of calling `Deserialize`, so they proved .NET's HMAC arithmetic works rather
   * than that .NET can consume what this server emits. The lesson generalises: a claim
   * about another runtime has to be asserted through that runtime's real entry point.
   * The Python arm does exactly that, which is why the Python path was correct.
   *
   * Safe to add for the same reason `kid` is: the canonical projection is fixed to
   * `{version,userId,tenantId,issuedAt,expiresAt,policies[]}` (spec section 2), and it
   * reads these values rather than being widened by them -- so the signed bytes are
   * unchanged and `policies` here is the same object as `effectivePolicy`, not a copy
   * that could drift.
   */
  readonly version: string;
  readonly userId: string;
  readonly tenantId: string;
  readonly policies: readonly EffectivePolicy[];
  readonly integrity: { readonly algorithm: string; readonly signature: string };
}

/**
 * Sign a resolved policy into an artifact every TOLAP SDK can verify.
 *
 * @param policy   A resolved `EffectivePolicy`. Mutated: both `signPolicy` and
 *                 `buildSecurityContext` write through in the SDK, so callers
 *                 should pass a policy they own rather than a cached one.
 * @param key      The signing key. Never leaves the server. A `SigningKey`
 *                 contributes its `kid` to the artifact; a bare string is treated
 *                 as the key `default`, which keeps single-key deployments
 *                 byte-identical apart from the added hint.
 * @param ttlMs    Artifact lifetime in milliseconds.
 */
export function buildSignedArtifact(
  policy: EffectivePolicy,
  key: string | SigningKey,
  ttlMs: number,
): SignedArtifact {
  const { kid, secret } =
    typeof key === "string" ? { kid: "default", secret: key } : key;
  const context = buildSecurityContext(
    policy.userId,
    policy.tenantId,
    policy,
    ttlMs,
  );

  // The two expiries MUST agree, and making them agree is this function's job.
  //
  // They did not. `buildSecurityContext` stamps the envelope from now + ttlMs, while the
  // policy carried whatever the resolver put there -- and the SDK's `resolve()` defaults
  // `ttlMs` to one hour, which the store did not override. So an artifact shipped with an
  // envelope expiring at the configured TTL and a policy expiring an hour out.
  //
  // That is not cosmetic, because the two verification paths read different fields: the
  // Python and .NET wrappers validate the envelope, while the TypeScript wrapper reads
  // `policy.expiresAt` directly (`sdk/typescript/packages/mcp/src/wrapper.ts`) and never
  // sees the envelope at all. The effect was that `TOLAP_TTL_SECONDS` was silently
  // ignored on TypeScript installs, which always got an hour -- and `config.ts` caps that
  // variable at one hour *specifically* because spec section 13 makes expiry the only
  // bound on replay. An operator tightening the window to 15 minutes got 60 on a third of
  // their fleet with nothing to indicate it.
  //
  // Overwritten here rather than fixed at the `resolve()` call because this function
  // already owns both signatures: whatever it writes before signing is what every
  // verifier sees, so one assignment closes the gap for all three paths at once.
  policy.expiresAt = context.expiresAt;
  policy.resolvedAt = context.resolvedAt;

  //
  // This single call produces the envelope signature *and* the policy's
  // integrity block, which is why both verification paths are satisfied.
  signContext(context, secret);

  if (!context.jti) {
    // buildSecurityContext mints one by default. Asserted rather than defaulted so a
    // future SDK change cannot silently ship artifacts that no consumer can
    // replay-check, which would look identical to working ones.
    throw new Error("buildSecurityContext produced no jti");
  }

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
    kid,
    // Signed, unlike `kid`, so it has to travel with the artifact for the signature
    // to verify at all.
    jti: context.jti,

    // The envelope-level view of the same values -- see the interface. `policies` holds
    // the same object as `effectivePolicy` rather than a copy, so the two cannot drift.
    version: context.effectivePolicy.version,
    userId: context.effectivePolicy.userId,
    tenantId: context.effectivePolicy.tenantId,
    policies: [context.effectivePolicy],
    integrity: { algorithm: context.algorithm, signature: context.signature },
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
