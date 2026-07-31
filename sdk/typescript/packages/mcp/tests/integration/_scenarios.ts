/**
 * Cross-SDK scenario loader for the TypeScript SDK.
 * Mirrors sdk/python/tests/integration/_scenarios.py.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  buildSecurityContext,
  signContext,
  type EffectivePolicy,
  type SecurityContext,
} from "@tolap/core";

const REPO_ROOT = resolve(__dirname, "..", "..", "..", "..", "..", "..");
export const SCENARIOS_DIR = resolve(REPO_ROOT, "fixtures", "integration-scenarios");
export const OPENFDA_FIXTURES = resolve(REPO_ROOT, "fixtures", "api", "openfda");

export function loadScenarios(filename: string): {
  description: string;
  scenarios: any[];
  basePolicy?: any;
} {
  return JSON.parse(readFileSync(resolve(SCENARIOS_DIR, filename), "utf8"));
}

/** Shallow-merge an override dict into a base policy. */
export function mergePolicy(
  base: Record<string, unknown>,
  override?: Record<string, unknown>,
): Record<string, unknown> {
  if (!override) return base;
  return { ...base, ...override };
}

/**
 * Build a fully-populated EffectivePolicy from a scenario's partial JSON.
 * The TS type requires userId/tenantId/etc; the scenarios omit those.
 */
export function policyFromDict(
  partial: Record<string, unknown>,
  opts: { userId?: string; tenantId?: string } = {},
): EffectivePolicy {
  const now = new Date();
  const expires = new Date(now.getTime() + 3_600_000);
  return {
    version: (partial.version as string) ?? "1.0",
    userId: opts.userId ?? "scenario-user",
    tenantId: opts.tenantId ?? "scenario-tenant",
    sourceConnectionId: "scenario-source",
    resolvedAt: now.toISOString(),
    expiresAt: expires.toISOString(),
    sourceProfiles: ["scenario"],
    permissions: partial.permissions as EffectivePolicy["permissions"],
    objectRules: partial.objectRules as EffectivePolicy["objectRules"],
    limits: partial.limits as EffectivePolicy["limits"],
    integrity: { algorithm: "none", signature: "" },
  };
}

/** Build and sign a SecurityContext for the given policy. */
export function signPolicy(
  policy: EffectivePolicy,
  signingKey: string,
  ttlMs = 3_600_000,
): SecurityContext {
  const ctx = buildSecurityContext(policy.userId, policy.tenantId, policy, ttlMs);
  return signContext(ctx, signingKey);
}
