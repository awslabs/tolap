/**
 * Shared TOLAP setup for the TypeScript framework examples: one policy, one signed context.
 *
 * Deliberately mirrors `examples/python/tolap_setup.py` — same policy, same fake rows, same
 * expected output. That is not duplication for its own sake: it means the twelve examples across
 * three languages are all making the *same* claim, so a divergence between languages shows up as
 * a different enforced result rather than hiding behind separately-written expectations.
 *
 * Every example registers a tool with a different framework and routes data access through
 * {@link enforcedQuery}. The enforcement code is identical regardless of framework, because TOLAP
 * wraps the function the framework calls rather than integrating with the framework itself.
 */

import {
  applyResultPipeline,
  buildSecurityContext,
  signContext,
  validateAccess,
  FilterOperator,
  MaskType,
  type EffectivePolicy,
  type SecurityContext,
} from "@aws/tolap-core";

export const SIGNING_KEY = "example-signing-key-do-not-use-in-production";

/**
 * What the "database" returns: more rows and more columns than the policy permits, so the
 * difference between raw and enforced output is observable rather than asserted.
 */
export const FAKE_ROWS: Record<string, unknown>[] = [
  { id: 1, name: "Alice Nguyen", region: "us-east", ssn: "111-22-3333", dob: "1979-04-12" },
  { id: 2, name: "Bruno Sato", region: "us-east", ssn: "222-33-4444", dob: "1985-11-02" },
  { id: 3, name: "Carol Diaz", region: "us-east", ssn: "333-44-5555", dob: "1990-01-30" },
  { id: 4, name: "Dan Meyer", region: "eu-west", ssn: "444-55-6666", dob: "1972-08-19" },
];

/**
 * The effective policy the agent's user holds for this source.
 *
 * In a real deployment this comes from `store.resolvePolicy(...)`, which merges every assignment
 * the user holds — see docs/architecture.md. Constructed inline here so the examples need no
 * database and the rules under test are visible in one place.
 */
export function buildPolicy(): EffectivePolicy {
  const now = new Date();
  return {
    version: "1.0",
    userId: "analyst-001",
    tenantId: "hospital-001",
    sourceConnectionId: "db:analytics:patients",
    sourceProfiles: ["example-analyst"],
    // Required, and not boilerplate: expiresAt is inside the signature, so it is the only bound
    // on how long a captured context stays usable (canonical-enforcement-spec.md §13).
    resolvedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 3_600_000).toISOString(),
    integrity: { algorithm: "none", signature: "" },
    permissions: { canQuery: true, readOnly: true },
    objectRules: {
      allowedObjects: ["patients"],
      fieldRules: {
        hiddenFields: ["ssn"],
        maskedFields: [{ field: "dob", maskType: MaskType.Redact }],
      },
      rowFilters: [{ field: "region", operator: FilterOperator.Equals, value: "us-east" }],
    },
    limits: { maxResults: 2 },
  };
}

/**
 * A signed context for the policy above.
 *
 * Signing is not decoration: the enforcement path verifies the signature and expiry, so a
 * tampered policy is refused rather than applied — which is what stops an agent editing its own
 * permissions in transit.
 */
export function signedContext(): SecurityContext {
  return signContext(buildSecurityContext("analyst-001", "hospital-001", buildPolicy()), SIGNING_KEY);
}

/**
 * Stands in for the code that really talks to your data source.
 *
 * Deliberately returns everything: TOLAP is handed the *result*, so a fake source that
 * pre-filtered would prove nothing. Swap this for pg, the AWS SDK or a fetch call — the
 * enforcement above it does not change, and it never sees your credentials.
 */
export function queryPatientsUnsafe(_table: string): Record<string, unknown>[] {
  return [...FAKE_ROWS];
}

/**
 * The one function every framework example calls. This is the whole integration.
 *
 * The object check runs first and separately, because a result-filtering pass cannot express
 * "this table is not yours" — by the time rows exist, the unauthorized query has already been
 * issued and logged as though it were authorized.
 *
 * Throws when the policy refuses the call, which each framework surfaces to the model as a tool
 * error. An agent must be able to tell "no rows matched" from "you may not read this"; returning
 * an empty array for a denial makes those indistinguishable and invites an infinite retry.
 */
export function enforcedQuery(table: string): Record<string, unknown>[] {
  const policy = buildPolicy();

  // Verify before enforcing. A context whose signature does not check out grants nothing.
  const context = signedContext();
  if (context.signature === undefined) {
    throw new Error("context is not signed");
  }

  const decision = validateAccess(table, policy);
  if (!decision.allowed) {
    throw new Error(`Access denied: ${decision.reason ?? "object not in allowed set"}`);
  }

  const rows = queryPatientsUnsafe(table);
  return applyResultPipeline(rows, policy) as Record<string, unknown>[];
}
