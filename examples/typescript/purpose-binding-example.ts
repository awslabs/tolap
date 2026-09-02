/**
 * Binding a policy to a *reason*, not just an identity.
 *
 * Every other example here answers "what may this identity see?". This one answers "and for
 * what?". A signed context binds identity, tenant, source and expiry — but not the reason the
 * data is being read. So an agent holding a perfectly legitimate context may use it for anything
 * its policy happens to permit, and an agent that has drifted off-task is indistinguishable from
 * one that has not.
 *
 * Purpose binding makes the declared reason an input to resolution and part of the signed bytes.
 * It is specified in `docs/canonical-enforcement-spec.md` §15, as four controls. This script walks
 * them in the order a call meets them, and shows each one **both allowing and denying**:
 *
 * 1. *Resolution filtering* (§15.1) — the purpose selects which policies resolve at all.
 * 2. *Delegation chain* (§15.3) — authority may narrow at every hop and never widen.
 * 3. *Action validation* (§15.2) — a semantic action category, supplied by configuration.
 * 4. *The judge* (§15.4) — an optional model check that can only subtract.
 *
 * A demo that shows only denials teaches nothing about whether legitimate work still passes, so
 * every control below is paired. The last section shows the property the whole thing rests on:
 * the purpose and the chain are inside the signature, so a captured context is not repurposable.
 *
 *     npx tsx purpose-binding-example.ts
 *
 * Deliberately mirrors `examples/python/purpose_binding_example.py` and
 * `examples/dotnet/PurposeBindingExample.cs` — same policies, same chain, same stub verdicts,
 * byte-identical printed output. A divergence between the languages then shows up as a different
 * result rather than hiding behind separately-written expectations.
 *
 * The policies match `fixtures/policies/purpose-*.json`, which is what the conformance suites
 * pin. They are written inline so the rules under test are visible in one place.
 *
 * One asymmetry worth naming, because it bites when porting: the action-category map lives on
 * `SecureContextToolWrapper` here and in .NET, but on `SecureMcpToolWrapper` in Python. The
 * printed output is identical; only the wrapper the map hangs off differs.
 */

import {
  FilterOperator,
  MaskType,
  PrincipalType,
  buildSecurityContext,
  evaluateJudge,
  resolve,
  signContext,
  validateContext,
  validateDelegationChain,
  type ActionCategoryMap,
  type DelegationHop,
  type EffectivePolicy,
  type Judge,
  type JudgeRequest,
  type JudgeResult,
  type PolicyAssignment,
  type PolicyDefinition,
  type PurposeProfile,
  type SecurityContext,
} from "@aws/tolap-core";
import { SecureContextToolWrapper } from "@aws/tolap-mcp";

export const SIGNING_KEY = "example-signing-key-do-not-use-in-production";

export const USER = "user-marketing-001";
export const TENANT = "tenant-acme-retail";
export const SOURCE = "db:marketing:customer_segments";

export const CAMPAIGN_PURPOSE = "campaign-x-overlap";
export const FRAUD_PURPOSE = "fraud-detection";

/**
 * The purpose the campaign policy serves, and the actions it will and will not admit.
 *
 * `allowedActions` absent would mean *unrestricted* (§3); naming it is what makes
 * `inspect_account` — a category no prohibition mentions — still a denial below.
 */
export const CAMPAIGN_PROFILE: PurposeProfile = {
  purposeId: CAMPAIGN_PURPOSE,
  description: "Identify overlapping opted-in customer segments for Campaign X.",
  allowedActions: ["aggregate_overlap", "count_segments"],
  prohibitedActions: ["export_pii", "enumerate_individuals", "join_external_data"],
};

export const FRAUD_PROFILE: PurposeProfile = {
  purposeId: FRAUD_PURPOSE,
  description: "Review flagged accounts for payment fraud.",
  allowedActions: ["inspect_account", "enumerate_individuals"],
  prohibitedActions: ["export_pii"],
};

/**
 * The wrapper's action-category map: **deployment configuration**, supplied where the wrapper is
 * constructed, keyed by tool name and matched exactly.
 *
 * It is deliberately not a caller argument. An agent that can name its own action category names
 * a permitted one, and the check reduces to a formality. `join_external` is absent on purpose —
 * an unclassified tool under a constraining purpose is a configuration fault, and fails closed.
 */
export const TOOL_ACTION_CATEGORIES: ActionCategoryMap = {
  segment_overlap: "aggregate_overlap",
  count_segments: "count_segments",
  export_customers: "export_pii",
  inspect_account: "inspect_account",
};

/** Purpose-scoped: resolves only for a caller declaring `campaign-x-overlap`. */
export function campaignDefinition(): PolicyDefinition {
  return {
    version: "1.0",
    name: "campaign-x-overlap-agent",
    priority: 10,
    sourcePatterns: ["db:marketing:*"],
    permissions: { canQuery: true, readOnly: true },
    objectRules: {
      allowedObjects: ["customer_segments", "campaign_assignments"],
      fieldRules: {
        hiddenFields: ["customer_segments.ssn"],
        maskedFields: [{ field: "customer_segments.email", maskType: MaskType.Hash }],
      },
      rowFilters: [
        { field: "consent_status", operator: FilterOperator.Equals, value: "opted_in" },
      ],
    },
    limits: { maxResults: 10000 },
    purposeProfile: CAMPAIGN_PROFILE,
  };
}

/**
 * The same sources, a different purpose. Granted to the same user, so a purpose mismatch — not a
 * missing grant — is what excludes it.
 */
export function fraudDefinition(): PolicyDefinition {
  return {
    version: "1.0",
    name: "fraud-detection-agent",
    priority: 10,
    sourcePatterns: ["db:marketing:*"],
    permissions: { canQuery: true, readOnly: true },
    objectRules: { allowedObjects: ["flagged_accounts", "campaign_assignments"] },
    limits: { maxResults: 500 },
    purposeProfile: FRAUD_PROFILE,
  };
}

/**
 * No `purposeProfile` at all — the backward-compatibility half of every scenario here.
 *
 * Purpose binding is opt-in and additive: a policy carrying no profile resolves whether or not a
 * purpose is declared, down to the signed bytes it produced before §15 existed.
 */
export function baselineDefinition(): PolicyDefinition {
  return {
    version: "1.0",
    name: "marketing-baseline",
    priority: 50,
    sourcePatterns: ["db:marketing:*"],
    permissions: { canQuery: true, readOnly: true },
    objectRules: {
      fieldRules: {
        hiddenFields: ["customer_segments.ssn", "customer_segments.date_of_birth"],
      },
    },
    limits: { maxResults: 2000 },
  };
}

function assignments(definitions: PolicyDefinition[]): PolicyAssignment[] {
  return definitions.map((d) => ({
    version: "1.0",
    policyName: d.name,
    assignee: { type: "user", identifier: USER },
    scope: { tenantId: TENANT },
    active: true,
    audit: {
      grantedBy: "admin-jane-doe",
      grantedAt: "2026-09-01T09:00:00Z",
      reason: `granted for the purpose-binding example: ${d.name}`,
    },
  }));
}

/**
 * Resolve exactly as a store would, with the purpose as a filter (§15.1).
 *
 * The filter runs *before* the merge, alongside the `sourcePatterns` filter and for the same
 * reason: a definition that does not apply must not fold its rules into the effective policy at
 * all. When every candidate is purpose-scoped and no matching purpose is declared the filtered
 * set is empty, and resolution returns the same deny-all it returns for any empty set — there is
 * no separate deny path to drift.
 */
export async function resolveFor(
  definitions: PolicyDefinition[],
  declaredPurpose?: string,
): Promise<EffectivePolicy> {
  return resolve(
    USER,
    TENANT,
    SOURCE,
    assignments(definitions),
    Object.fromEntries(definitions.map((d) => [d.name, d])),
    () => [],
    () => [],
    3_600_000,
    declaredPurpose,
  );
}

// ---------------------------------------------------------------------------------------------
// The delegation chain: a human delegates to an orchestrator, which delegates to an agent.
// ---------------------------------------------------------------------------------------------

/** Three hops, each narrower than its parent, in both purpose and scope. */
export function narrowingChain(): DelegationHop[] {
  return [
    {
      principalId: USER,
      principalType: PrincipalType.User,
      declaredPurpose: "campaign-*",
      scopeNarrowing: ["read", "aggregate", "export"],
    },
    {
      principalId: "orchestrator-01",
      principalType: PrincipalType.Service,
      declaredPurpose: "campaign-x-*",
      scopeNarrowing: ["read", "aggregate"],
    },
    {
      principalId: "agent-overlap",
      principalType: PrincipalType.Agent,
      declaredPurpose: CAMPAIGN_PURPOSE,
      scopeNarrowing: ["read"],
    },
  ];
}

/** A fourth hop that steps sideways out of the family it was delegated within. */
export function wideningHop(): DelegationHop {
  return {
    principalId: "agent-exfil",
    principalType: PrincipalType.Agent,
    declaredPurpose: "campaign-y-export",
  };
}

export function twoHop(parent: string, child: string): DelegationHop[] {
  return [
    { principalId: USER, principalType: PrincipalType.User, declaredPurpose: parent },
    { principalId: "agent-overlap", principalType: PrincipalType.Agent, declaredPurpose: child },
  ];
}

export function scopeHops(parent: string[], child: string[]): DelegationHop[] {
  return [
    { principalId: USER, principalType: PrincipalType.User, scopeNarrowing: parent },
    { principalId: "agent-overlap", principalType: PrincipalType.Agent, scopeNarrowing: child },
  ];
}

// ---------------------------------------------------------------------------------------------
// The judge: stubbed on purpose. An example must not make a live model call.
// ---------------------------------------------------------------------------------------------

/**
 * A judge with a fixed verdict, so the *mapping* is what this section demonstrates.
 *
 * A real judge's answer is not a function of its input, which is why the conformance corpus pins
 * the verdict-to-disposition mapping rather than the verdict. An example that called a model
 * would be untestable and would need a credential to run.
 */
export class StubJudge implements Judge {
  constructor(
    private readonly result: JudgeResult,
    readonly modelId: string = "example-judge-model",
  ) {}

  async evaluate(_request: JudgeRequest): Promise<JudgeResult> {
    return this.result;
  }
}

/**
 * The campaign policy with semantic review switched on, and the thresholds named.
 *
 * Every judge field must be read from the resolved policy. Left to each integrator's glue, the
 * predictable outcome is a judge running with thresholds nobody chose while the policy's `model`
 * is quietly ignored — configuration implying a control that never runs.
 */
export async function judgedPolicy(): Promise<EffectivePolicy> {
  const base = await resolveFor([campaignDefinition()], CAMPAIGN_PURPOSE);
  return {
    ...base,
    purposeProfile: {
      purposeId: CAMPAIGN_PURPOSE,
      allowedActions: CAMPAIGN_PROFILE.allowedActions,
      prohibitedActions: CAMPAIGN_PROFILE.prohibitedActions,
      judge: {
        enabled: true,
        model: "example-judge-model",
        confidenceThreshold: 0.85,
        escalationThreshold: 0.6,
      },
    },
  };
}

// ---------------------------------------------------------------------------------------------
// Signing: the purpose and the chain are inside the signature.
// ---------------------------------------------------------------------------------------------

/**
 * A context carrying the declared purpose and the chain, then signed.
 *
 * `buildSecurityContext` records the chain; it does not validate it. Validation is a separate
 * call, because a chain arriving over the wire must be checked by the party that enforces rather
 * than by the party that assembled it.
 */
export async function signedContext(): Promise<SecurityContext> {
  const policy = await resolveFor([campaignDefinition(), fraudDefinition()], CAMPAIGN_PURPOSE);
  return signContext(
    buildSecurityContext(
      USER,
      TENANT,
      policy,
      3_600_000,
      undefined,
      CAMPAIGN_PURPOSE,
      narrowingChain(),
    ),
    SIGNING_KEY,
  );
}

// ---------------------------------------------------------------------------------------------
// Printing. Every line below is byte-identical to the Python and .NET examples.
// ---------------------------------------------------------------------------------------------

const LABEL_WIDTH = 34;
const VERDICT_WIDTH = 10;

function row(label: string, verdict: string, detail = ""): string {
  return `  ${label.padEnd(LABEL_WIDTH)}${verdict.padEnd(VERDICT_WIDTH)}${detail}`.replace(
    /\s+$/,
    "",
  );
}

function access(label: string, allowed: boolean, detail = ""): string {
  return row(label, allowed ? "ALLOW" : "DENY", detail);
}

function rule(title: string): string {
  return `--- ${title} ` + "-".repeat(Math.max(0, 70 - 5 - title.length));
}

function describe(policy: EffectivePolicy): string {
  if (policy.sourceProfiles.length === 0) {
    return "deny-all: 0 policies resolved, canQuery=false";
  }
  return `${policy.sourceProfiles.join(", ")} (maxResults=${policy.limits?.maxResults})`;
}

export async function main(): Promise<void> {
  console.log("=".repeat(70));
  console.log("Purpose binding: four controls, in the order a call meets them");
  console.log("=".repeat(70));

  // -------------------------------------------------------------- 1. resolution filtering
  console.log();
  console.log(rule("1. resolution filtering (spec 15.1)"));
  console.log("Two policies are granted to the same user over the same sources, and both are");
  console.log("purpose-scoped:");
  console.log("    campaign-x-overlap-agent  purposeId 'campaign-x-overlap'");
  console.log("    fraud-detection-agent     purposeId 'fraud-detection'");
  console.log();

  const scoped = [campaignDefinition(), fraudDefinition()];
  const scopedCases: [string, string | undefined][] = [
    ["(no purpose)", undefined],
    [`'${CAMPAIGN_PURPOSE}'`, CAMPAIGN_PURPOSE],
    [`'${FRAUD_PURPOSE}'`, FRAUD_PURPOSE],
    ["'Campaign-X-Overlap'", "Campaign-X-Overlap"],
  ];
  for (const [label, declared] of scopedCases) {
    const policy = await resolveFor(scoped, declared);
    console.log(access(label, policy.sourceProfiles.length > 0, describe(policy)));
  }

  console.log();
  console.log("The purpose selects the policy. Declaring none resolves nothing, because a");
  console.log("purpose-scoped policy is not a default grant; declaring one resolves that policy");
  console.log("and never the other's rules. The comparison is exact and case-sensitive, so");
  console.log("'Campaign-X-Overlap' resolves no more than a purpose nobody authored would.");
  console.log();
  console.log("Purpose binding is additive, though. Add a policy carrying no purposeProfile and");
  console.log("the no-purpose caller resolves again, exactly as it did before section 15 existed:");

  const withBaseline = [campaignDefinition(), fraudDefinition(), baselineDefinition()];
  const baselineCases: [string, string | undefined][] = [
    ["(no purpose)", undefined],
    [`'${CAMPAIGN_PURPOSE}'`, CAMPAIGN_PURPOSE],
  ];
  for (const [label, declared] of baselineCases) {
    const policy = await resolveFor(withBaseline, declared);
    console.log(access(label, policy.sourceProfiles.length > 0, describe(policy)));
  }

  // ------------------------------------------------------------------ 2. delegation chain
  console.log();
  console.log(rule("2. delegation chain (spec 15.3)"));
  console.log("Authority reaches the agent through three hops, narrowing at each one:");
  console.log("    user-marketing-001  user     'campaign-*'          scopes [read, aggregate, export]");
  console.log("    orchestrator-01     service  'campaign-x-*'        scopes [read, aggregate]");
  console.log("    agent-overlap       agent    'campaign-x-overlap'  scopes [read]");
  console.log();

  const chain = narrowingChain();
  const ok = validateDelegationChain(chain);
  console.log(access("three narrowing hops", ok.allowed, ok.reason ?? ""));

  const widened = validateDelegationChain([...chain, wideningHop()]);
  console.log(access("+ a fourth, wider hop", widened.allowed, widened.reason ?? ""));

  console.log();
  console.log("Now the case a plain prefix test gets wrong. Both children begin with the parent's");
  console.log("characters; only one of them is a narrowing:");
  for (const child of ["campaign-x-overlap", "campaign-xyz-evil"]) {
    const result = validateDelegationChain(twoHop("campaign-x", child));
    const note = result.allowed ? "extends on a '-' segment boundary" : (result.reason ?? "");
    console.log(access(`campaign-x -> ${child}`, result.allowed, note));
  }

  console.log();
  console.log("'campaign-x' and 'campaign-xyz-evil' are unrelated purposes; one merely begins with");
  console.log("the other's characters. Requiring the segment boundary makes the prefix mean what a");
  console.log("reader assumes it means.");
  console.log();
  console.log("Scopes narrow the same way. scopeNarrowing lists what is still IN FORCE at a hop,");
  console.log("not what the hop removed, so each set must be a subset of its parent's:");
  const scopeCases: [string[], string[]][] = [
    [["read", "aggregate"], ["read"]],
    [["read"], ["read", "write"]],
  ];
  for (const [parentScopes, childScopes] of scopeCases) {
    const result = validateDelegationChain(scopeHops(parentScopes, childScopes));
    const label = `[${parentScopes.join(", ")}] -> [${childScopes.join(", ")}]`;
    console.log(access(label, result.allowed, result.reason ?? "a subset of the parent"));
  }

  // ----------------------------------------------------------------- 3. action validation
  console.log();
  console.log(rule("3. action validation (spec 15.2)"));
  console.log("The action category comes from the wrapper's map -- deployment configuration, fixed");
  console.log("where the wrapper is constructed, keyed by tool name and matched exactly:");
  for (const [tool, category] of Object.entries(TOOL_ACTION_CATEGORIES)) {
    console.log(`    ${tool.padEnd(18)} -> ${category}`);
  }
  console.log("    join_external      -> (deliberately not in the map)");
  console.log();
  console.log("It is never a caller argument. An agent that can name its own action category names a");
  console.log("permitted one, and the check reduces to a formality.");
  console.log();
  console.log("Under purpose 'campaign-x-overlap':");
  console.log("    allowedActions     [aggregate_overlap, count_segments]");
  console.log("    prohibitedActions  [export_pii, enumerate_individuals, join_external_data]");
  console.log();

  const wrapper = new SecureContextToolWrapper({
    signingKey: SIGNING_KEY,
    toolActionCategories: TOOL_ACTION_CATEGORIES,
  });
  const context = await signedContext();
  for (const toolName of [
    "segment_overlap",
    "export_customers",
    "inspect_account",
    "join_external",
  ]) {
    const result = wrapper.preExecute(context, { toolName });
    console.log(
      access(toolName, result.allowed, result.reason ?? "category 'aggregate_overlap' is allowed"),
    );
  }

  console.log();
  console.log("Three different denials, and the third is the one worth dwelling on. An unclassified");
  console.log("tool under a purpose that constrains actions at all is refused, because a purpose");
  console.log("declaring only prohibitedActions means 'anything but these' -- and an unclassified");
  console.log("tool might be exactly one of them. The reason names a configuration fault because");
  console.log("that is what it is: the fix is to classify the tool, not to widen the policy.");

  // ----------------------------------------------------------------------- 4. the judge
  console.log();
  console.log(rule("4. the semantic judge (spec 15.4)"));
  console.log("Optional, and stubbed here: an example must not make a live model call. Three fixed");
  console.log("verdicts through the real gate, with the policy's own thresholds --");
  console.log("confidenceThreshold 0.85, escalationThreshold 0.60:");
  console.log();

  const policy = await judgedPolicy();
  const verdicts: [string, JudgeResult, string][] = [
    [
      "aligned, confidence 0.95",
      { aligned: true, confidence: 0.95, reasoning: "counts only" },
      "the deterministic allowance stands",
    ],
    [
      "misaligned, confidence 0.95",
      { aligned: false, confidence: 0.95, reasoning: "row-level export" },
      "the allowance is withdrawn",
    ],
    [
      "aligned, confidence 0.70",
      { aligned: true, confidence: 0.7, reasoning: "probably fine" },
      "a DENIAL unless a review handler is wired",
    ],
  ];
  for (const [label, result, note] of verdicts) {
    // `evaluateJudge` takes the *policy*, not loose thresholds: every judge field is read from
    // the resolved profile, including the model, which is checked before any call is issued. It
    // returns the disposition together with a reason, because escalate covers both "the judge
    // could not tell" and "this deployment wired the wrong model".
    const outcome = await evaluateJudge(
      policy,
      new StubJudge(result),
      "segment_overlap(campaign_x)",
    );
    console.log(row(label, outcome.disposition, note));
  }

  console.log();
  console.log("escalate is a DENIAL unless an escalation handler is wired. Otherwise 'escalate to");
  console.log("human review' silently means 'permit' in every deployment that never built the review");
  console.log("step -- a fail-open on precisely the ambiguous cases the judge exists to surface.");
  console.log();
  console.log("And the judge is strictly subtractive. It runs only after the three deterministic");
  console.log("checks have already allowed the call, and can only take that allowance away; it is");
  console.log("never consulted to permit something they denied. That is what makes a prompt");
  console.log("injection survivable rather than critical -- the worst a manipulated verdict achieves");
  console.log("is an allow the deterministic rules had already granted.");

  // -------------------------------------------------- the purpose is inside the signature
  console.log();
  console.log(rule("the purpose and the chain are inside the signature"));
  console.log("None of the above is worth running on a context the caller can rewrite. An unsigned");
  console.log("chain can be edited by the principal it constrains, so a validator would be checking");
  console.log("the attacker's own arithmetic.");
  console.log();

  const verify = (label: string, ctx: SecurityContext, detail: string): string =>
    row(label, validateContext(ctx, SIGNING_KEY) ? "VALID" : "BROKEN", detail);

  const original = await signedContext();
  console.log(verify("as signed", original, "purpose 'campaign-x-overlap', 3 hops"));

  const repurposed = await signedContext();
  repurposed.declaredPurpose = FRAUD_PURPOSE;
  console.log(verify("declared purpose swapped", repurposed, "to 'fraud-detection'"));

  const rechained = await signedContext();
  rechained.delegationChain![2]!.declaredPurpose = "campaign-y-export";
  console.log(verify("last hop repurposed", rechained, "to 'campaign-y-export'"));

  const appended = await signedContext();
  appended.delegationChain!.push(wideningHop());
  console.log(verify("a fourth hop appended", appended, "agent-exfil, 'campaign-y-export'"));

  const reordered = await signedContext();
  reordered.delegationChain!.reverse();
  console.log(
    verify("hops reordered", reordered, "hop 0 is the delegator; reversing inverts it"),
  );

  if (validateContext(repurposed, SIGNING_KEY) || validateContext(rechained, SIGNING_KEY)) {
    throw new Error(
      "A MUTATED CONTEXT STILL VERIFIED. The purpose and the chain must be inside the signed " +
        "bytes, or nothing above constrains anything.",
    );
  }

  // ------------------------------------------------------------------------- conclusion
  console.log();
  console.log("=".repeat(70));
  console.log("Four controls, each shown allowing legitimate work and refusing the rest:");
  console.log("  * the declared purpose selects which policies resolve at all");
  console.log("  * a delegation chain may narrow at every hop and never widen");
  console.log("  * the action category is configuration, so a caller cannot name its own");
  console.log("  * the judge can only withdraw an allowance, never grant one");
  console.log();
  console.log("What this does NOT do: purpose is *asserted* by the caller. TOLAP checks that the");
  console.log("assertion matches a policy and that a chain is internally consistent. It cannot");
  console.log("check that the caller was honest. This constrains a cooperative agent that drifts,");
  console.log("not an integrator that lies.");
  console.log("=".repeat(70));
}

// Run directly, not on import, so the test file can call the exports above.
if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) {
  void main();
}
