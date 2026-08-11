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

/**
 * Throws when a required backing service is unavailable.
 *
 * Tests previously wrote `if (!dbReady) return;`, and an early return from a test body is
 * a **PASS**, not a skip. Measured before this helper existed: with the databases pointed
 * at dead ports the integration suite reported `243 passed` — indistinguishable from a run
 * against live databases. For a policy-enforcement SDK that means a regression letting
 * `patients.ssn` through could ship behind a green build.
 *
 * There is deliberately no opt-out. The .NET counterpart tried one and removed it: an
 * escape hatch can suppress this call but not the dead connection the test uses two lines
 * later, so the tests failed anyway with a worse message. Start the services (see
 * `docs/local-testing.md`) or filter the run. Python's conftest reports an honest
 * `pytest.skip` for the same condition, which is the behaviour to match when a runner
 * offers it.
 */
export function requireService(ready: boolean, service: string, detail?: string): void {
  if (ready) return;
  const because = detail === undefined ? service : `${service} (${detail})`;
  throw new Error(
    `This integration test requires ${because}, which is unavailable. ` +
      "Start it (see docs/local-testing.md), or filter it out of the run. It must not be " +
      "skipped silently: an early return would be recorded as a pass.",
  );
}
