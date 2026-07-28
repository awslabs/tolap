/**
 * TOLAP Security Context
 *
 * Build, sign, validate, serialize, and deserialize security contexts
 * that carry effective policies to tool execution environments.
 */

import { createHmac, timingSafeEqual } from "node:crypto";
import {
  type EffectivePolicy,
  type SecurityContext,
  SigningAlgorithm,
} from "./types.js";

// ---------------------------------------------------------------------------
// Canonical serialization
// ---------------------------------------------------------------------------

/**
 * Recursively sort all object keys for deterministic JSON output.
 */
function deepSortKeys(value: unknown): unknown {
  if (value === null || value === undefined) return value;
  if (Array.isArray(value)) return value.map(deepSortKeys);
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(obj).sort()) {
      sorted[key] = deepSortKeys(obj[key]);
    }
    return sorted;
  }
  return value;
}

/**
 * Produce a canonical JSON representation of the policy for signing.
 * This excludes the `integrity` block and uses compact JSON with
 * recursively sorted keys for deterministic output.
 */
function canonicalize(policy: EffectivePolicy): string {
  const { integrity: _integrity, ...rest } = policy;
  return JSON.stringify(deepSortKeys(rest));
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
 * Build a SecurityContext wrapping an EffectivePolicy.
 */
export function buildSecurityContext(
  userId: string,
  tenantId: string,
  policy: EffectivePolicy,
  ttlMs: number = 3_600_000,
): SecurityContext {
  const now = new Date();
  const expiresAt = new Date(now.getTime() + ttlMs);
  return {
    effectivePolicy: policy,
    resolvedAt: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
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
  const payload = canonicalize(context.effectivePolicy);
  const signature = computeHmac(payload, secretKey, algorithm);

  context.effectivePolicy.integrity = { algorithm, signature };
  context.signature = signature;
  context.algorithm = algorithm;

  return context;
}

/**
 * Validate the integrity signature of a SecurityContext.
 * Uses timing-safe comparison to prevent timing attacks.
 */
export function validateContext(
  context: SecurityContext,
  secretKey: string,
): boolean {
  if (!context.signature || !context.algorithm) return false;

  const payload = canonicalize(context.effectivePolicy);
  const expected = computeHmac(payload, secretKey, context.algorithm);

  const sigBuf = Buffer.from(context.signature, "base64");
  const expectedBuf = Buffer.from(expected, "base64");

  if (sigBuf.length !== expectedBuf.length) return false;

  return timingSafeEqual(sigBuf, expectedBuf);
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
 * Validates the signature if a secret key is provided.
 *
 * @throws Error if deserialization fails, the context is expired, or signature is invalid.
 */
export function deserializeContext(
  serialized: string,
  secretKey: string,
): SecurityContext {
  let context: SecurityContext;
  try {
    const json = Buffer.from(serialized, "base64").toString("utf8");
    context = JSON.parse(json) as SecurityContext;
  } catch {
    throw new Error("Failed to deserialize security context");
  }

  // Validate expiry
  if (context.expiresAt) {
    const expires = new Date(context.expiresAt);
    if (expires <= new Date()) {
      throw new Error("Security context has expired");
    }
  }

  // Validate signature
  if (!validateContext(context, secretKey)) {
    throw new Error("Security context signature validation failed");
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
  const expected = computeHmac(payload, secretKey, algorithm);

  const sigBuf = Buffer.from(policy.integrity.signature, "base64");
  const expectedBuf = Buffer.from(expected, "base64");

  if (sigBuf.length !== expectedBuf.length) return false;

  return timingSafeEqual(sigBuf, expectedBuf);
}
