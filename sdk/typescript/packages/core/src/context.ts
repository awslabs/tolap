/**
 * TOLAP Security Context
 *
 * Build, sign, validate, serialize, and deserialize security contexts
 * that carry effective policies to tool execution environments.
 */

import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import {
  type EffectivePolicy,
  type SecurityContext,
  SigningAlgorithm,
} from "./types.js";

// ---------------------------------------------------------------------------
// Canonical serialization
// ---------------------------------------------------------------------------

/**
 * Recursively sort all object keys and drop explicit nulls for deterministic
 * JSON output (canonical spec §1).
 *
 * Nulls must be dropped during the sort walk rather than passed through:
 * `null` and "absent" are indistinguishable in the canonical form, and the
 * three SDKs only agree on the signed bytes if each omits both.
 */
function deepSortKeys(value: unknown): unknown {
  if (value === null || value === undefined) return value;
  if (Array.isArray(value)) return value.map(deepSortKeys);
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(obj).sort()) {
      const child = obj[key];
      if (child === null || child === undefined) continue;
      sorted[key] = deepSortKeys(child);
    }
    return sorted;
  }
  return value;
}

/**
 * Normalize an RFC 3339 timestamp to UTC with a `Z` suffix.
 *
 * Signing must not distinguish `+00:00` from `Z`, so both forms fold to the
 * same bytes. Sub-second digits are **truncated to milliseconds** per spec §2
 * rule 5 — omitted entirely when zero, otherwise exactly three digits. An
 * unparseable value is passed through verbatim: the signature then covers
 * exactly what was transported, and `validateExpiry` (which rejects unparseable
 * values) is the control that stops it.
 *
 * Exported (but deliberately absent from the package's public index) so the
 * conformance suite can assert the normalization table directly rather than only
 * observing it through a signature, which cannot tell a precision bug from a key
 * mismatch.
 */
export function normalizeTimestamp(value: string | undefined): string {
  if (!value) return "";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;

  // Spec section 2 rule 5: truncate to milliseconds. `Date` already truncates
  // anything finer on parse, so `toISOString()` is exactly the canonical form
  // once a zero fractional part is dropped. Do NOT pad to six digits: Python and
  // .NET truncate to three, so padding would reintroduce a cross-SDK mismatch on
  // any timestamp carrying sub-second precision.
  const iso = parsed.toISOString(); // always "....sssZ"
  return parsed.getUTCMilliseconds() === 0
    ? iso.replace(/\.\d{3}Z$/, "Z")
    : iso;
}

/**
 * Produce a canonical JSON representation of a single policy for signing.
 *
 * Excludes the `integrity` block (it cannot sign itself) and uses compact JSON with
 * recursively sorted keys and explicit nulls dropped.
 *
 * Timestamps are normalized here for the same reason the envelope projection
 * normalizes them (spec §1: "All signature computation uses this form and only this
 * form", plus §2 rule 4/5): without it, `+00:00` and `Z` — and `.123456Z` versus
 * `.123Z` — signed to different bytes on the policy-alone path while agreeing on the
 * envelope path. A policy round-tripped through a transport that reformats its
 * timestamps then failed its own integrity check with a generic signature error
 * indistinguishable from tampering.
 */
function canonicalize(policy: EffectivePolicy): string {
  return JSON.stringify(
    deepSortKeys(normalizePolicyTimestamps(stripIntegrity(policy))),
  );
}

function stripIntegrity(policy: EffectivePolicy): Record<string, unknown> {
  const { integrity: _integrity, ...rest } = policy;
  return rest as Record<string, unknown>;
}

/** Timestamp-valued keys on a projected policy (canonical spec §2 rule 5). */
const POLICY_TIMESTAMP_KEYS = ["resolvedAt", "expiresAt"] as const;

/**
 * Normalize the timestamps carried *inside* a projected policy.
 *
 * The envelope's `issuedAt`/`expiresAt` are not the only instants in the signed
 * bytes: each policy repeats its own `resolvedAt`/`expiresAt`. .NET normalizes
 * those through a canonical `DateTimeOffset` converter, so leaving them as the
 * verbatim transport strings here made TypeScript sign `.123456Z` where .NET
 * signed `.123Z` — the same context, two different signatures, and a cross-SDK
 * verification failure the whole-second fixture could not detect.
 */
function normalizePolicyTimestamps(
  policy: Record<string, unknown>,
): Record<string, unknown> {
  const out: Record<string, unknown> = { ...policy };
  for (const key of POLICY_TIMESTAMP_KEYS) {
    const value = out[key];
    if (typeof value === "string") out[key] = normalizeTimestamp(value);
  }
  return out;
}

/**
 * Project a SecurityContext into the canonical signing shape and serialize it.
 *
 * The HMAC covers the whole envelope, not just the policy (canonical spec §2):
 *
 *     {version, userId, tenantId, issuedAt, expiresAt, policies[]}
 *
 * `issuedAt` and `expiresAt` are *inside* the signed bytes, so rewriting an
 * expiry on a captured context invalidates the signature instead of extending
 * its life. The TypeScript SecurityContext holds one policy and calls its issue
 * instant `resolvedAt`; both project into the canonical envelope so the bytes
 * match the multi-policy SDKs while the public model stays unchanged.
 */
function canonicalPayload(context: SecurityContext): string {
  const policy = context.effectivePolicy;
  const payload: Record<string, unknown> = {
    version: policy.version,
    userId: policy.userId ?? "",
    tenantId: policy.tenantId ?? "",
    issuedAt: normalizeTimestamp(context.resolvedAt),
    expiresAt: normalizeTimestamp(context.expiresAt),
    policies: [normalizePolicyTimestamps(stripIntegrity(policy))],
  };
  // `jti` joins the signed bytes only when present. Emitting it unconditionally
  // (as `null` or `""`) would change the canonical form for every existing
  // context and break the known-answer fixtures and cross-SDK agreement, so
  // absence is byte-identical to the pre-`jti` form. When present it is signed,
  // so a replay guard cannot be defeated by stripping or swapping the id.
  if (context.jti) {
    payload.jti = context.jti;
  }
  return JSON.stringify(deepSortKeys(payload));
}

// ---------------------------------------------------------------------------
// Replay detection
// ---------------------------------------------------------------------------

/**
 * Records which context identifiers have been seen (spec §13).
 *
 * A signed context is otherwise a bearer credential replayable until it expires.
 * Single-use enforcement needs state the SDK deliberately does not assume, so
 * this is the seam: implement it over whatever store the deployment already has
 * (Redis, DynamoDB, a database table) and pass it to {@link deserializeContext}.
 *
 * Implementations must be atomic — check-then-register as two separate steps lets
 * two concurrent replays of the same context both succeed, which defeats the
 * guard under exactly the load an attacker would generate.
 */
export interface ReplayGuard {
  /**
   * Atomically record `jti`; return `false` if it was already present.
   *
   * `expiresAt` is the context's expiry, supplied so implementations can expire
   * their own entries: an id can be forgotten once the context carrying it would
   * be rejected on expiry anyway.
   */
  checkAndRegister(jti: string, expiresAt?: string): boolean;
}

/**
 * Process-local {@link ReplayGuard}, suitable for a single-process tool.
 *
 * Not shared across processes or hosts: two workers behind a load balancer each
 * keep their own set, so a context replayed against a *different* worker is not
 * detected. Use a shared store for anything multi-process — this class exists so
 * single-process deployments and tests have a working guard rather than none.
 *
 * Entries are dropped once their context has expired, so memory is bounded by the
 * number of contexts issued within one TTL rather than growing without limit.
 */
export class InMemoryReplayGuard implements ReplayGuard {
  private seen = new Map<string, number>();

  checkAndRegister(jti: string, expiresAt?: string): boolean {
    const now = Date.now();
    // Fall back to a bounded retention when expiry is absent or unreadable, so a
    // malformed value cannot pin an entry in memory forever.
    const parsed = expiresAt === undefined ? NaN : new Date(expiresAt).getTime();
    const expiry = Number.isNaN(parsed) ? now + 3_600_000 : parsed;

    // Opportunistic sweep: an id is only worth remembering while a context
    // bearing it could still pass the expiry check.
    for (const [key, value] of this.seen) {
      if (value <= now) this.seen.delete(key);
    }

    if (this.seen.has(jti)) return false;
    this.seen.set(jti, expiry);
    return true;
  }
}

// ---------------------------------------------------------------------------
// HMAC helpers
// ---------------------------------------------------------------------------

function hmacAlgorithm(algo: string): string {
  switch (algo) {
    case SigningAlgorithm.HmacSha256:
      return "sha256";
    case SigningAlgorithm.HmacSha512:
      return "sha512";
    default:
      throw new Error(`Unsupported signing algorithm: ${algo}`);
  }
}

function computeHmac(data: string, key: string, algorithm: string): string {
  const hashAlgo = hmacAlgorithm(algorithm);
  return createHmac(hashAlgo, key).update(data, "utf8").digest("base64");
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Build a SecurityContext wrapping a single EffectivePolicy.
 *
 * `SecurityContext` carries exactly one policy, and every enforcement entry point
 * reads `context.effectivePolicy` without being told which data source the call is
 * aimed at. An array is therefore rejected here rather than stored.
 *
 * The type signature already says "one policy", but types are erased at runtime and
 * `docs/architecture.md` shows the context with a `policies` **array**, so a
 * JavaScript caller — or a TypeScript one reaching this through `any`/JSON — would
 * follow the docs and pass `[dbPolicy, apiPolicy]`. That array was stored verbatim,
 * signed, and validated successfully; enforcement then read
 * `policy.permissions.canQuery` off the array and crashed with a bare
 * `TypeError: Cannot read properties of undefined`, naming neither the real mistake
 * nor the fix. Failing here instead makes the mistake unmissable at the point it is
 * made. Build one context per data source; there is no per-source resolution rule
 * for this SDK to apply.
 *
 * @throws Error if `policy` is an array rather than a single policy.
 */
export function buildSecurityContext(
  userId: string,
  tenantId: string,
  policy: EffectivePolicy,
  ttlMs: number = 3_600_000,
  jti?: string,
): SecurityContext {
  if (Array.isArray(policy)) {
    throw new Error(
      `buildSecurityContext expects a single effective policy, received an array of ` +
        `${policy.length}; a SecurityContext carries one policy, so build one context ` +
        `per data source`,
    );
  }

  const now = new Date();
  const expiresAt = new Date(now.getTime() + ttlMs);
  // Defaults to a fresh UUID so contexts are replay-checkable without the caller
  // remembering to ask. Pass `""` to omit it and reproduce the pre-`jti` bytes.
  const contextId = jti === undefined ? randomUUID() : jti;
  return {
    effectivePolicy: policy,
    resolvedAt: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
    ...(contextId ? { jti: contextId } : {}),
  };
}

/**
 * Sign a SecurityContext using HMAC. Mutates and returns the context with
 * signature and algorithm fields set, and also sets the policy's integrity block.
 */
export function signContext(
  context: SecurityContext,
  secretKey: string,
  algorithm: string = SigningAlgorithm.HmacSha256,
): SecurityContext {
  const payload = canonicalPayload(context);
  const signature = computeHmac(payload, secretKey, algorithm);

  context.signature = signature;
  context.algorithm = algorithm;
  // The policy's own integrity block signs the policy alone, so that a policy
  // extracted from the envelope is still independently verifiable. It is
  // excluded from the envelope payload above and set after it is computed.
  context.effectivePolicy.integrity = {
    algorithm,
    signature: computeHmac(canonicalize(context.effectivePolicy), secretKey, algorithm),
  };

  return context;
}

/**
 * Validate the integrity signature of a SecurityContext.
 * Uses timing-safe comparison to prevent timing attacks.
 *
 * The signature covers the whole envelope, so rewriting `expiresAt` or
 * `resolvedAt` on a captured context invalidates it.
 */
export function validateContext(
  context: SecurityContext,
  secretKey: string,
): boolean {
  if (!context.signature || !context.algorithm) return false;

  let expected: string;
  try {
    expected = computeHmac(canonicalPayload(context), secretKey, context.algorithm);
  } catch {
    // Unknown algorithm on an attacker-supplied context: a validation failure,
    // never a thrown error that escapes an enforcement check.
    return false;
  }

  const sigBuf = Buffer.from(context.signature, "base64");
  const expectedBuf = Buffer.from(expected, "base64");

  if (sigBuf.length !== expectedBuf.length) return false;

  return timingSafeEqual(sigBuf, expectedBuf);
}

/**
 * Check a context's expiry, returning a denial reason or `undefined` when valid.
 *
 * Fails closed on both ends (canonical spec §2): a missing or empty expiry is
 * never "never expires", and an unparseable expiry is never a silently skipped
 * check. `new Date("never") <= new Date()` is `false` in JavaScript, which
 * previously granted an unbounded lifetime to any context carrying a malformed
 * timestamp.
 */
export function validateExpiry(context: SecurityContext): string | undefined {
  if (!context.expiresAt) return "security context has no expiry";
  const expires = new Date(context.expiresAt);
  if (Number.isNaN(expires.getTime())) return "invalid expiry format";
  if (expires.getTime() <= Date.now()) return "security context expired";
  return undefined;
}

/**
 * Serialize a SecurityContext to a base64-encoded string.
 */
export function serializeContext(context: SecurityContext): string {
  const json = JSON.stringify(context);
  return Buffer.from(json, "utf8").toString("base64");
}

/**
 * Deserialize a SecurityContext from a base64-encoded string.
 *
 * The signature is verified **before** expiry, so a tampered context reports a
 * signature failure rather than leaking whether a valid context merely expired.
 *
 * @throws Error if deserialization fails, the signature is invalid, or the
 * context is expired / carries a missing or unparseable expiry.
 */
export function deserializeContext(
  serialized: string,
  secretKey: string,
  replayGuard?: ReplayGuard,
): SecurityContext {
  let context: SecurityContext;
  try {
    const json = Buffer.from(serialized, "base64").toString("utf8");
    context = JSON.parse(json) as SecurityContext;
  } catch {
    throw new Error("Failed to deserialize security context");
  }

  // Validate signature first: expiry is inside the signed payload, so a
  // rewritten expiry surfaces here rather than passing an expiry check.
  if (!validateContext(context, secretKey)) {
    throw new Error("Security context signature validation failed");
  }

  const expiryReason = validateExpiry(context);
  if (expiryReason !== undefined) {
    throw new Error(`Security context rejected: ${expiryReason}`);
  }

  // Replay check runs last: it consumes the `jti`, so it must not fire for a
  // context that was going to be rejected anyway. Doing it earlier would let an
  // attacker burn a legitimate id by replaying an already-expired context.
  if (replayGuard !== undefined) {
    if (!context.jti) {
      throw new Error(
        "Security context rejected: replay checking requires a 'jti'; " +
          "this context carries none",
      );
    }
    if (!replayGuard.checkAndRegister(context.jti, context.expiresAt)) {
      throw new Error("Security context rejected: context already used (replay)");
    }
  }

  return context;
}

/**
 * Sign an EffectivePolicy directly (not wrapped in a SecurityContext).
 * Returns the EffectivePolicy with its integrity block populated.
 */
export function signPolicy(
  policy: EffectivePolicy,
  secretKey: string,
  algorithm: string = SigningAlgorithm.HmacSha256,
): EffectivePolicy {
  const payload = canonicalize(policy);
  const signature = computeHmac(payload, secretKey, algorithm);
  policy.integrity = { algorithm, signature };
  return policy;
}

/**
 * Validate an EffectivePolicy's integrity signature directly.
 */
export function validatePolicy(
  policy: EffectivePolicy,
  secretKey: string,
): boolean {
  if (!policy.integrity?.signature || !policy.integrity?.algorithm) return false;

  const { algorithm } = policy.integrity;
  const payload = canonicalize(policy);

  let expected: string;
  try {
    expected = computeHmac(payload, secretKey, algorithm);
  } catch {
    // An algorithm this SDK cannot verify is a validation FAILURE, never a thrown
    // error that escapes an enforcement check. `ed25519` is in the schema's
    // algorithm enum but unimplemented here, so a schema-valid policy reaches this
    // path -- and a wrapper calling validatePolicy inside a try-less enforcement
    // step would otherwise surface a crash instead of a denial. Mirrors
    // validateContext, which already fails closed the same way.
    return false;
  }

  const sigBuf = Buffer.from(policy.integrity.signature, "base64");
  const expectedBuf = Buffer.from(expected, "base64");

  if (sigBuf.length !== expectedBuf.length) return false;

  return timingSafeEqual(sigBuf, expectedBuf);
}
