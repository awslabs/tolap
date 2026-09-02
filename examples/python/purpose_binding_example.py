"""Binding a policy to a *reason*, not just an identity.

Every other example here answers "what may this identity see?". This one answers "and for
what?". A signed context binds identity, tenant, source and expiry -- but not the reason the
data is being read. So an agent holding a perfectly legitimate context may use it for anything
its policy happens to permit, and an agent that has drifted off-task is indistinguishable from
one that has not.

Purpose binding makes the declared reason an input to resolution and part of the signed bytes.
It is specified in docs/canonical-enforcement-spec.md section 15, as four controls. This script
walks them in the order a call meets them, and shows each one **both allowing and denying**:

1. *Resolution filtering* (15.1) -- the purpose selects which policies resolve at all.
2. *Delegation chain* (15.3) -- authority may narrow at every hop and never widen.
3. *Action validation* (15.2) -- a semantic action category, supplied by configuration.
4. *The judge* (15.4) -- an optional model check that can only subtract.

A demo that shows only denials teaches nothing about whether legitimate work still passes, so
every control below is paired. The last section shows the property the whole thing rests on:
the purpose and the chain are inside the signature, so a captured context is not repurposable.

Run it::

    python3 examples/python/purpose_binding_example.py

Deliberately mirrors ``examples/typescript/purpose-binding-example.ts`` and
``examples/dotnet/PurposeBindingExample.cs`` -- same policies, same chain, same stub verdicts,
byte-identical printed output. A divergence between the languages then shows up as a different
result rather than hiding behind separately-written expectations.

The policies match ``fixtures/policies/purpose-*.json``, which is what the conformance suites
pin. They are written inline so the rules under test are visible in one place.
"""

from __future__ import annotations

from tolap_core import (
    Assignee,
    AssigneeType,
    AssignmentScope,
    AuditInfo,
    DelegationHop,
    EffectivePolicy,
    FieldRules,
    FilterOperator,
    Judge,
    JudgeConfig,
    JudgeRequest,
    JudgeResult,
    MaskType,
    MaskingRule,
    ObjectRules,
    PolicyAssignment,
    PolicyDefinition,
    PolicyLimits,
    PolicyPermissions,
    PrincipalType,
    PurposeProfile,
    RowFilter,
    SecurityContext,
    build_security_context,
    evaluate_judge,
    resolve,
    sign_context,
    validate_context,
    validate_delegation_chain,
)
from tolap_mcp.options import SecureMcpServerOptions
from tolap_mcp.wrapper import SecureMcpToolWrapper

SIGNING_KEY = "example-signing-key-do-not-use-in-production"

USER = "user-marketing-001"
TENANT = "tenant-acme-retail"
SOURCE = "db:marketing:customer_segments"

CAMPAIGN_PURPOSE = "campaign-x-overlap"
FRAUD_PURPOSE = "fraud-detection"

#: The purpose the campaign policy serves, and the actions it will and will not admit.
#:
#: ``allowedActions`` absent would mean *unrestricted* (spec section 3); naming it is what makes
#: `inspect_account` -- a category no prohibition mentions -- still a denial below.
CAMPAIGN_PROFILE = PurposeProfile(
    purpose_id=CAMPAIGN_PURPOSE,
    description="Identify overlapping opted-in customer segments for Campaign X.",
    allowed_actions=["aggregate_overlap", "count_segments"],
    prohibited_actions=["export_pii", "enumerate_individuals", "join_external_data"],
)

FRAUD_PROFILE = PurposeProfile(
    purpose_id=FRAUD_PURPOSE,
    description="Review flagged accounts for payment fraud.",
    allowed_actions=["inspect_account", "enumerate_individuals"],
    prohibited_actions=["export_pii"],
)

#: The wrapper's action-category map: **deployment configuration**, supplied where the wrapper is
#: constructed, keyed by tool name and matched exactly.
#:
#: It is deliberately not a caller argument. An agent that can name its own action category names
#: a permitted one, and the check reduces to a formality. ``join_external`` is absent on purpose --
#: an unclassified tool under a constraining purpose is a configuration fault, and fails closed.
TOOL_ACTION_CATEGORIES = {
    "segment_overlap": "aggregate_overlap",
    "count_segments": "count_segments",
    "export_customers": "export_pii",
    "inspect_account": "inspect_account",
}


def _audit(reason: str) -> AuditInfo:
    return AuditInfo(granted_by="admin-jane-doe", granted_at="2026-09-01T09:00:00Z", reason=reason)


def campaign_definition() -> PolicyDefinition:
    """Purpose-scoped: resolves only for a caller declaring ``campaign-x-overlap``."""
    return PolicyDefinition(
        version="1.0",
        name="campaign-x-overlap-agent",
        permissions=PolicyPermissions(can_query=True, read_only=True),
        priority=10,
        source_patterns=["db:marketing:*"],
        object_rules=ObjectRules(
            allowed_objects=["customer_segments", "campaign_assignments"],
            field_rules=FieldRules(
                hidden_fields=["customer_segments.ssn"],
                masked_fields=[
                    MaskingRule(field="customer_segments.email", mask_type=MaskType.hash)
                ],
            ),
            row_filters=[
                RowFilter(field="consent_status", operator=FilterOperator.equals, value="opted_in")
            ],
        ),
        limits=PolicyLimits(max_results=10000),
        purpose_profile=CAMPAIGN_PROFILE,
    )


def fraud_definition() -> PolicyDefinition:
    """The same sources, a different purpose. Granted to the same user, so a purpose mismatch --
    not a missing grant -- is what excludes it."""
    return PolicyDefinition(
        version="1.0",
        name="fraud-detection-agent",
        permissions=PolicyPermissions(can_query=True, read_only=True),
        priority=10,
        source_patterns=["db:marketing:*"],
        object_rules=ObjectRules(allowed_objects=["flagged_accounts", "campaign_assignments"]),
        limits=PolicyLimits(max_results=500),
        purpose_profile=FRAUD_PROFILE,
    )


def baseline_definition() -> PolicyDefinition:
    """No ``purposeProfile`` at all -- the backward-compatibility half of every scenario here.

    Purpose binding is opt-in and additive: a policy carrying no profile resolves whether or not
    a purpose is declared, down to the signed bytes it produced before section 15 existed.
    """
    return PolicyDefinition(
        version="1.0",
        name="marketing-baseline",
        permissions=PolicyPermissions(can_query=True, read_only=True),
        priority=50,
        source_patterns=["db:marketing:*"],
        object_rules=ObjectRules(
            field_rules=FieldRules(
                hidden_fields=["customer_segments.ssn", "customer_segments.date_of_birth"]
            )
        ),
        limits=PolicyLimits(max_results=2000),
    )


def _assignments(definitions: list[PolicyDefinition]) -> list[PolicyAssignment]:
    return [
        PolicyAssignment(
            version="1.0",
            policy_name=d.name,
            assignee=Assignee(type=AssigneeType.user, identifier=USER),
            scope=AssignmentScope(tenant_id=TENANT),
            active=True,
            audit=_audit(f"granted for the purpose-binding example: {d.name}"),
        )
        for d in definitions
    ]


def resolve_for(
    definitions: list[PolicyDefinition], declared_purpose: str | None
) -> EffectivePolicy:
    """Resolve exactly as a store would, with the purpose as a filter (spec 15.1).

    The filter runs *before* the merge, alongside the ``sourcePatterns`` filter and for the same
    reason: a definition that does not apply must not fold its rules into the effective policy at
    all. When every candidate is purpose-scoped and no matching purpose is declared the filtered
    set is empty, and resolution returns the same deny-all it returns for any empty set -- there
    is no separate deny path to drift.
    """
    return resolve(
        USER,
        TENANT,
        SOURCE,
        _assignments(definitions),
        {d.name: d for d in definitions},
        lambda _: [],
        lambda _: [],
        declared_purpose=declared_purpose,
    )


# --------------------------------------------------------------------------------------------
# The delegation chain: a human delegates to an orchestrator, which delegates to an agent.
# --------------------------------------------------------------------------------------------

def narrowing_chain() -> list[DelegationHop]:
    """Three hops, each narrower than its parent, in both purpose and scope."""
    return [
        DelegationHop(
            principal_id=USER,
            principal_type=PrincipalType.user,
            declared_purpose="campaign-*",
            scope_narrowing=["read", "aggregate", "export"],
        ),
        DelegationHop(
            principal_id="orchestrator-01",
            principal_type=PrincipalType.service,
            declared_purpose="campaign-x-*",
            scope_narrowing=["read", "aggregate"],
        ),
        DelegationHop(
            principal_id="agent-overlap",
            principal_type=PrincipalType.agent,
            declared_purpose=CAMPAIGN_PURPOSE,
            scope_narrowing=["read"],
        ),
    ]


def widening_hop() -> DelegationHop:
    """A fourth hop that steps sideways out of the family it was delegated within."""
    return DelegationHop(
        principal_id="agent-exfil",
        principal_type=PrincipalType.agent,
        declared_purpose="campaign-y-export",
    )


def two_hop(parent: str, child: str) -> list[DelegationHop]:
    return [
        DelegationHop(principal_id=USER, principal_type=PrincipalType.user, declared_purpose=parent),
        DelegationHop(
            principal_id="agent-overlap", principal_type=PrincipalType.agent, declared_purpose=child
        ),
    ]


def scope_hops(parent: list[str], child: list[str]) -> list[DelegationHop]:
    return [
        DelegationHop(principal_id=USER, principal_type=PrincipalType.user, scope_narrowing=parent),
        DelegationHop(
            principal_id="agent-overlap", principal_type=PrincipalType.agent, scope_narrowing=child
        ),
    ]


# --------------------------------------------------------------------------------------------
# The judge: stubbed on purpose. An example must not make a live model call.
# --------------------------------------------------------------------------------------------

class StubJudge(Judge):
    """A judge with a fixed verdict, so the *mapping* is what this section demonstrates.

    A real judge's answer is not a function of its input, which is why the conformance corpus
    pins the verdict-to-disposition mapping rather than the verdict. An example that called a
    model would be untestable and would need a credential to run.
    """

    def __init__(self, result: JudgeResult, model_id: str = "example-judge-model") -> None:
        self._result = result
        self._model_id = model_id

    @property
    def model_id(self) -> str:
        return self._model_id

    def evaluate(self, request: JudgeRequest) -> JudgeResult:  # noqa: D102
        return self._result


def judged_policy() -> EffectivePolicy:
    """The campaign policy with semantic review switched on, and the thresholds named.

    Every judge field must be read from the resolved policy. Left to each integrator's glue, the
    predictable outcome is a judge running with thresholds nobody chose while the policy's
    ``model`` is quietly ignored -- configuration implying a control that never runs.
    """
    profile = PurposeProfile(
        purpose_id=CAMPAIGN_PURPOSE,
        allowed_actions=CAMPAIGN_PROFILE.allowed_actions,
        prohibited_actions=CAMPAIGN_PROFILE.prohibited_actions,
        judge=JudgeConfig(
            enabled=True,
            model="example-judge-model",
            confidence_threshold=0.85,
            escalation_threshold=0.60,
        ),
    )
    base = resolve_for([campaign_definition()], CAMPAIGN_PURPOSE)
    base.purpose_profile = profile
    return base


# --------------------------------------------------------------------------------------------
# Signing: the purpose and the chain are inside the signature.
# --------------------------------------------------------------------------------------------

def signed_context() -> SecurityContext:
    """A context carrying the declared purpose and the chain, then signed.

    ``build_security_context`` records the chain; it does not validate it. Validation is a
    separate call, because a chain arriving over the wire must be checked by the party that
    enforces rather than by the party that assembled it.
    """
    return sign_context(
        build_security_context(
            USER,
            TENANT,
            [resolve_for([campaign_definition(), fraud_definition()], CAMPAIGN_PURPOSE)],
            declared_purpose=CAMPAIGN_PURPOSE,
            delegation_chain=narrowing_chain(),
        ),
        SIGNING_KEY,
    )


# --------------------------------------------------------------------------------------------
# Printing. Every line below is byte-identical to the TypeScript and .NET examples.
# --------------------------------------------------------------------------------------------

LABEL_WIDTH = 34
VERDICT_WIDTH = 10


def _row(label: str, verdict: str, detail: str = "") -> str:
    return f"  {label:<{LABEL_WIDTH}}{verdict:<{VERDICT_WIDTH}}{detail}".rstrip()


def _access(label: str, allowed: bool, detail: str = "") -> str:
    return _row(label, "ALLOW" if allowed else "DENY", detail)


def _rule(title: str) -> str:
    return f"--- {title} " + "-" * max(0, 70 - 5 - len(title))


def _describe(policy: EffectivePolicy) -> str:
    if not policy.source_profiles:
        return "deny-all: 0 policies resolved, canQuery=false"
    names = ", ".join(policy.source_profiles)
    limit = policy.limits.max_results if policy.limits else None
    return f"{names} (maxResults={limit})"


def main() -> None:
    print("=" * 70)
    print("Purpose binding: four controls, in the order a call meets them")
    print("=" * 70)

    # ---------------------------------------------------------------- 1. resolution filtering
    print()
    print(_rule("1. resolution filtering (spec 15.1)"))
    print("Two policies are granted to the same user over the same sources, and both are")
    print("purpose-scoped:")
    print("    campaign-x-overlap-agent  purposeId 'campaign-x-overlap'")
    print("    fraud-detection-agent     purposeId 'fraud-detection'")
    print()

    scoped = [campaign_definition(), fraud_definition()]
    for label, declared in (
        ("(no purpose)", None),
        (f"'{CAMPAIGN_PURPOSE}'", CAMPAIGN_PURPOSE),
        (f"'{FRAUD_PURPOSE}'", FRAUD_PURPOSE),
        ("'Campaign-X-Overlap'", "Campaign-X-Overlap"),
    ):
        policy = resolve_for(scoped, declared)
        print(_access(label, bool(policy.source_profiles), _describe(policy)))

    print()
    print("The purpose selects the policy. Declaring none resolves nothing, because a")
    print("purpose-scoped policy is not a default grant; declaring one resolves that policy")
    print("and never the other's rules. The comparison is exact and case-sensitive, so")
    print("'Campaign-X-Overlap' resolves no more than a purpose nobody authored would.")
    print()
    print("Purpose binding is additive, though. Add a policy carrying no purposeProfile and")
    print("the no-purpose caller resolves again, exactly as it did before section 15 existed:")

    with_baseline = [campaign_definition(), fraud_definition(), baseline_definition()]
    for label, declared in (("(no purpose)", None), (f"'{CAMPAIGN_PURPOSE}'", CAMPAIGN_PURPOSE)):
        policy = resolve_for(with_baseline, declared)
        print(_access(label, bool(policy.source_profiles), _describe(policy)))

    # ------------------------------------------------------------------- 2. delegation chain
    print()
    print(_rule("2. delegation chain (spec 15.3)"))
    print("Authority reaches the agent through three hops, narrowing at each one:")
    print("    user-marketing-001  user     'campaign-*'          scopes [read, aggregate, export]")
    print("    orchestrator-01     service  'campaign-x-*'        scopes [read, aggregate]")
    print("    agent-overlap       agent    'campaign-x-overlap'  scopes [read]")
    print()

    chain = narrowing_chain()
    ok = validate_delegation_chain(chain)
    print(_access("three narrowing hops", ok.allowed, ok.reason or ""))

    widened = validate_delegation_chain(chain + [widening_hop()])
    print(_access("+ a fourth, wider hop", widened.allowed, widened.reason or ""))

    print()
    print("Now the case a plain prefix test gets wrong. Both children begin with the parent's")
    print("characters; only one of them is a narrowing:")
    for child in ("campaign-x-overlap", "campaign-xyz-evil"):
        result = validate_delegation_chain(two_hop("campaign-x", child))
        note = "extends on a '-' segment boundary" if result.allowed else result.reason
        print(_access(f"campaign-x -> {child}", result.allowed, note or ""))

    print()
    print("'campaign-x' and 'campaign-xyz-evil' are unrelated purposes; one merely begins with")
    print("the other's characters. Requiring the segment boundary makes the prefix mean what a")
    print("reader assumes it means.")
    print()
    print("Scopes narrow the same way. scopeNarrowing lists what is still IN FORCE at a hop,")
    print("not what the hop removed, so each set must be a subset of its parent's:")
    for parent_scopes, child_scopes in (
        (["read", "aggregate"], ["read"]),
        (["read"], ["read", "write"]),
    ):
        result = validate_delegation_chain(scope_hops(parent_scopes, child_scopes))
        label = f"{parent_scopes} -> {child_scopes}".replace("'", "")
        print(_access(label, result.allowed, result.reason or "a subset of the parent"))

    # ------------------------------------------------------------------ 3. action validation
    print()
    print(_rule("3. action validation (spec 15.2)"))
    print("The action category comes from the wrapper's map -- deployment configuration, fixed")
    print("where the wrapper is constructed, keyed by tool name and matched exactly:")
    for tool, category in TOOL_ACTION_CATEGORIES.items():
        print(f"    {tool:<18} -> {category}")
    print("    join_external      -> (deliberately not in the map)")
    print()
    print("It is never a caller argument. An agent that can name its own action category names a")
    print("permitted one, and the check reduces to a formality.")
    print()
    print("Under purpose 'campaign-x-overlap':")
    print("    allowedActions     [aggregate_overlap, count_segments]")
    print("    prohibitedActions  [export_pii, enumerate_individuals, join_external_data]")
    print()

    wrapper = SecureMcpToolWrapper(
        SecureMcpServerOptions(
            signing_key=SIGNING_KEY, tool_action_categories=TOOL_ACTION_CATEGORIES
        )
    )
    context = signed_context()
    for tool in ("segment_overlap", "export_customers", "inspect_account", "join_external"):
        result = wrapper.pre_execute(context, tool)
        print(_access(tool, result.allowed, result.reason or "category 'aggregate_overlap' is allowed"))

    print()
    print("Three different denials, and the third is the one worth dwelling on. An unclassified")
    print("tool under a purpose that constrains actions at all is refused, because a purpose")
    print("declaring only prohibitedActions means 'anything but these' -- and an unclassified")
    print("tool might be exactly one of them. The reason names a configuration fault because")
    print("that is what it is: the fix is to classify the tool, not to widen the policy.")

    # ------------------------------------------------------------------------ 4. the judge
    print()
    print(_rule("4. the semantic judge (spec 15.4)"))
    print("Optional, and stubbed here: an example must not make a live model call. Three fixed")
    print("verdicts through the real gate, with the policy's own thresholds --")
    print("confidenceThreshold 0.85, escalationThreshold 0.60:")
    print()

    policy = judged_policy()
    for label, result, note in (
        (
            "aligned, confidence 0.95",
            JudgeResult(aligned=True, confidence=0.95, reasoning="counts only"),
            "the deterministic allowance stands",
        ),
        (
            "misaligned, confidence 0.95",
            JudgeResult(aligned=False, confidence=0.95, reasoning="row-level export"),
            "the allowance is withdrawn",
        ),
        (
            "aligned, confidence 0.70",
            JudgeResult(aligned=True, confidence=0.70, reasoning="probably fine"),
            "a DENIAL unless a review handler is wired",
        ),
    ):
        # `evaluate_judge` takes the *policy*, not loose thresholds: every judge field is read
        # from the resolved profile, including the model, which is checked before any call is
        # issued. It returns the disposition together with a reason, because escalate covers
        # both "the judge could not tell" and "this deployment wired the wrong model".
        outcome = evaluate_judge(policy, StubJudge(result), "segment_overlap(campaign_x)")
        print(_row(label, outcome.disposition.value, note))

    print()
    print("escalate is a DENIAL unless an escalation handler is wired. Otherwise 'escalate to")
    print("human review' silently means 'permit' in every deployment that never built the review")
    print("step -- a fail-open on precisely the ambiguous cases the judge exists to surface.")
    print()
    print("And the judge is strictly subtractive. It runs only after the three deterministic")
    print("checks have already allowed the call, and can only take that allowance away; it is")
    print("never consulted to permit something they denied. That is what makes a prompt")
    print("injection survivable rather than critical -- the worst a manipulated verdict achieves")
    print("is an allow the deterministic rules had already granted.")

    # --------------------------------------------------------- the purpose is inside the signature
    print()
    print(_rule("the purpose and the chain are inside the signature"))
    print("None of the above is worth running on a context the caller can rewrite. An unsigned")
    print("chain can be edited by the principal it constrains, so a validator would be checking")
    print("the attacker's own arithmetic.")
    print()

    def _verify(label: str, context: SecurityContext, detail: str) -> str:
        ok = validate_context(context, SIGNING_KEY)
        return _row(label, "VALID" if ok else "BROKEN", detail)

    original = signed_context()
    print(_verify("as signed", original, "purpose 'campaign-x-overlap', 3 hops"))

    repurposed = signed_context()
    repurposed.declared_purpose = FRAUD_PURPOSE
    print(_verify("declared purpose swapped", repurposed, "to 'fraud-detection'"))

    rechained = signed_context()
    assert rechained.delegation_chain is not None
    rechained.delegation_chain[-1].declared_purpose = "campaign-y-export"
    print(_verify("last hop repurposed", rechained, "to 'campaign-y-export'"))

    appended = signed_context()
    assert appended.delegation_chain is not None
    appended.delegation_chain.append(widening_hop())
    print(_verify("a fourth hop appended", appended, "agent-exfil, 'campaign-y-export'"))

    reversed_chain = signed_context()
    assert reversed_chain.delegation_chain is not None
    reversed_chain.delegation_chain.reverse()
    print(_verify("hops reordered", reversed_chain, "hop 0 is the delegator; reversing inverts it"))

    if validate_context(repurposed, SIGNING_KEY) or validate_context(rechained, SIGNING_KEY):
        raise SystemExit(
            "A MUTATED CONTEXT STILL VERIFIED. The purpose and the chain must be inside the "
            "signed bytes, or nothing above constrains anything."
        )

    # ------------------------------------------------------------------------------ conclusion
    print()
    print("=" * 70)
    print("Four controls, each shown allowing legitimate work and refusing the rest:")
    print("  * the declared purpose selects which policies resolve at all")
    print("  * a delegation chain may narrow at every hop and never widen")
    print("  * the action category is configuration, so a caller cannot name its own")
    print("  * the judge can only withdraw an allowance, never grant one")
    print()
    print("What this does NOT do: purpose is *asserted* by the caller. TOLAP checks that the")
    print("assertion matches a policy and that a chain is internally consistent. It cannot")
    print("check that the caller was honest. This constrains a cooperative agent that drifts,")
    print("not an integrator that lies.")
    print("=" * 70)


if __name__ == "__main__":
    main()
