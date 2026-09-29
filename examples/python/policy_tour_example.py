"""A tour of every policy rule the SDK enforces, one section per rule.

The framework examples all hold the same small policy, because their point is the integration.
This one holds the integration constant instead and changes the policy, so each rule is seen on
its own against data that shows what it did:

* **Masks** -- ``full``, ``partial`` (``showFirst``/``showLast``/``maskChar``), ``hash``
  (``sha256``, ``sha512``, ``blake2b``), ``null`` and ``redact``, raw value next to masked value.
* **Fields** -- ``allowedFields`` (keep only these) next to ``hiddenFields`` (drop only these).
* **Objects** -- ``allowedObjects`` next to ``hiddenObjects``, and a refused call for each.
* **Row filters** -- every operator family, each on its own, over the same six rows.
* **Permissions** -- ``canQuery: false``, ``readOnly: true`` refusing a write, and the write
  checks that still run once writes are granted.
* **Limits** -- ``minSimilarityScore``, ``maxObjectSizeBytes`` and ``maxResults``.
* **Merging** -- a user policy and a group policy resolved into one, where the most restrictive
  rule wins.

Every verdict and every masked value below comes from the SDK; the script only prints. Where a
rule refuses something, the reason is the SDK's own string.

Run it::

    python3 examples/python/policy_tour_example.py

Deliberately mirrors ``examples/typescript/policy-tour-example.ts`` and
``examples/dotnet/PolicyTourExample.cs`` -- same policies, same rows, byte-identical printed
output. A divergence between the languages then shows up as a different result rather than
hiding behind separately-written expectations.
"""

from __future__ import annotations

from typing import Any, NamedTuple

from tolap_core.context import build_security_context, sign_context
from tolap_core.enforcement import AccessResult
from tolap_core.enums import AssigneeType, FilterOperator, MaskType, WriteOperation
from tolap_core.models import (
    Assignee,
    AssignmentScope,
    AuditInfo,
    EffectivePolicy,
    FieldRules,
    MaskingParameters,
    MaskingRule,
    ObjectRules,
    PolicyAssignment,
    PolicyDefinition,
    PolicyLimits,
    PolicyPermissions,
    RowFilter,
    SecurityContext,
)
from tolap_core.resolution import resolve
from tolap_mcp.options import SecureMcpServerOptions
from tolap_mcp.wrapper import SecureMcpToolWrapper

SIGNING_KEY = "example-signing-key-do-not-use-in-production"

TENANT = "hospital-001"

SOURCE = "db:clinical:patients"

USER = "analyst-001"

# --------------------------------------------------------------------------------------------
# The data. Each "database" returns more than any policy below permits.
# --------------------------------------------------------------------------------------------

#: One patient, with a column for every mask type.
PATIENT: dict[str, Any] = {
    "id": 7,
    "name": "Alice Nguyen",
    "phone": "555-867-5309",
    "card": "4111111111111111",
    "address": "12 Elm Street",
    "email": "alice@example.com",
    "mrn": "MRN-00417",
    "member_id": "M-99812",
    "notes": "allergic to penicillin",
    "dob": "1979-04-12",
    "ssn": "111-22-3333",
}

#: Rows for the row-filter section. Row 6 has no ``discharged_at`` key at all.
ROWS: list[dict[str, Any]] = [
    {"id": 1, "region": "us-east", "age": 34, "ward": "cardiology", "email": "alice@clinic.org", "code": "PT-101", "discharged_at": None},
    {"id": 2, "region": "us-west", "age": 17, "ward": "pediatrics", "email": "bruno@clinic.org", "code": "PT-102", "discharged_at": "2026-08-01"},
    {"id": 3, "region": "eu-west", "age": 52, "ward": "cardiology", "email": "carol@partner.net", "code": "PT-10A", "discharged_at": None},
    {"id": 4, "region": "us-east", "age": 65, "ward": "oncology", "email": "dan@clinic.org", "code": "XX-104", "discharged_at": "2026-07-15"},
    {"id": 5, "region": "ap-south", "age": 41, "ward": "neurology", "email": "erin@partner.net", "code": "PT-105", "discharged_at": None},
    {"id": 6, "region": "us-east", "age": 29, "ward": "cardiology-icu", "email": "fay@clinic.org", "code": "pt-106"},
]

#: Search hits for the limits section. d5 carries no size and d6 no score.
DOCUMENTS: list[dict[str, Any]] = [
    {"id": "d1", "score": 0.92, "size": 1200},
    {"id": "d2", "score": 0.75, "size": 4096},
    {"id": "d3", "score": 0.60, "size": 800},
    {"id": "d4", "score": 0.88, "size": 2048},
    {"id": "d5", "score": 0.81},
    {"id": "d6", "size": 500},
    {"id": "d7", "score": 0.99, "size": 100},
]

#: Rows for the merge section.
MERGE_ROWS: list[dict[str, Any]] = [
    {"id": 1, "region": "us-east", "age": 34, "phone": "555-867-5309", "ssn": "111-22-3333", "notes": "stable"},
    {"id": 2, "region": "us-west", "age": 17, "phone": "555-201-4471", "ssn": "222-33-4444", "notes": "minor"},
    {"id": 3, "region": "eu-west", "age": 52, "phone": "555-310-9920", "ssn": "333-44-5555", "notes": "transfer"},
    {"id": 4, "region": "us-east", "age": 65, "phone": "555-448-1062", "ssn": "444-55-6666", "notes": "follow-up"},
]

#: The order columns are printed in, so the output does not depend on a runtime's map ordering.
PATIENT_COLUMNS = ["id", "name", "phone", "card", "address", "email", "mrn", "member_id", "notes", "dob", "ssn"]
FIELD_COLUMNS = ["id", "name", "region", "dob", "notes", "ssn"]
MERGE_COLUMNS = ["id", "region", "age", "phone", "notes", "ssn"]


# --------------------------------------------------------------------------------------------
# Policies. Each one is written inline so the rule under test is visible where it is used; in a
# real deployment they come from ``store.resolve_policy(...)``.
# --------------------------------------------------------------------------------------------


def policy(
    *,
    permissions: PolicyPermissions | None = None,
    object_rules: ObjectRules | None = None,
    limits: PolicyLimits | None = None,
) -> EffectivePolicy:
    """An effective policy holding only the rule a section is about."""
    return EffectivePolicy(
        version="1.0",
        user_id=USER,
        tenant_id=TENANT,
        source_connection_id=SOURCE,
        source_profiles=["policy-tour"],
        permissions=permissions or PolicyPermissions(can_query=True, read_only=True),
        object_rules=object_rules,
        limits=limits,
    )


def mask_policy() -> EffectivePolicy:
    """One rule per mask type, and ``ssn`` hidden outright for contrast."""
    return policy(
        object_rules=ObjectRules(
            field_rules=FieldRules(
                hidden_fields=["ssn"],
                masked_fields=[
                    MaskingRule(field="name", mask_type=MaskType.partial, parameters=MaskingParameters(show_first=1)),
                    MaskingRule(field="phone", mask_type=MaskType.partial, parameters=MaskingParameters(show_last=4, mask_char="#")),
                    MaskingRule(field="card", mask_type=MaskType.partial, parameters=MaskingParameters(show_first=4, show_last=4)),
                    MaskingRule(field="address", mask_type=MaskType.full),
                    MaskingRule(field="email", mask_type=MaskType.hash, parameters=MaskingParameters(algorithm="sha256")),
                    MaskingRule(field="mrn", mask_type=MaskType.hash, parameters=MaskingParameters(algorithm="sha512")),
                    MaskingRule(field="member_id", mask_type=MaskType.hash, parameters=MaskingParameters(algorithm="blake2b")),
                    MaskingRule(field="notes", mask_type=MaskType.null),
                    MaskingRule(field="dob", mask_type=MaskType.redact),
                ],
            )
        )
    )


#: Label shown for each mask rule, in PATIENT_COLUMNS order.
MASK_LABELS = {
    "id": "no rule",
    "name": "partial showFirst 1",
    "phone": "partial showLast 4 '#'",
    "card": "partial first 4 last 4",
    "address": "full",
    "email": "hash sha256",
    "mrn": "hash sha512",
    "member_id": "hash blake2b",
    "notes": "null",
    "dob": "redact",
    "ssn": "hiddenFields",
}


def allowed_fields_policy() -> EffectivePolicy:
    """An allow-list of fields: anything not named is dropped, including columns added later."""
    return policy(object_rules=ObjectRules(field_rules=FieldRules(allowed_fields=["id", "name", "region"])))


def hidden_fields_policy() -> EffectivePolicy:
    """A deny-list of fields: only the named ones are dropped."""
    return policy(object_rules=ObjectRules(field_rules=FieldRules(hidden_fields=["ssn", "notes"])))


def object_policy() -> EffectivePolicy:
    """``billing_*`` is allowed, and ``billing_internal`` is hidden anyway: hidden wins."""
    return policy(
        object_rules=ObjectRules(
            allowed_objects=["patients", "encounters", "billing_*"],
            hidden_objects=["billing_internal"],
        )
    )


OBJECT_PROBES = ["patients", "encounters", "billing_invoices", "billing_internal", "audit_log"]


class Filter(NamedTuple):
    label: str
    rule: RowFilter


FILTERS = [
    Filter("region equals us-east", RowFilter(field="region", operator=FilterOperator.equals, value="us-east")),
    Filter("region notEquals us-east", RowFilter(field="region", operator=FilterOperator.not_equals, value="us-east")),
    Filter("region in [us-east, us-west]", RowFilter(field="region", operator=FilterOperator.in_, values=["us-east", "us-west"])),
    Filter("region notIn [us-east, us-west]", RowFilter(field="region", operator=FilterOperator.not_in, values=["us-east", "us-west"])),
    Filter("age greaterThan 40", RowFilter(field="age", operator=FilterOperator.greater_than, value=40)),
    Filter("age lessThanOrEqual 29", RowFilter(field="age", operator=FilterOperator.less_than_or_equal, value=29)),
    Filter("age between [30, 52]", RowFilter(field="age", operator=FilterOperator.between, values=[30, 52])),
    Filter("email contains @clinic.", RowFilter(field="email", operator=FilterOperator.contains, value="@clinic.")),
    Filter("ward startsWith cardio", RowFilter(field="ward", operator=FilterOperator.starts_with, value="cardio")),
    Filter("email like %@partner.net", RowFilter(field="email", operator=FilterOperator.like, value="%@partner.net")),
    Filter("code matches PT-[0-9]{3}", RowFilter(field="code", operator=FilterOperator.matches, value="PT-[0-9]{3}")),
    Filter("discharged_at isNull", RowFilter(field="discharged_at", operator=FilterOperator.is_null)),
    Filter("discharged_at isNotNull", RowFilter(field="discharged_at", operator=FilterOperator.is_not_null)),
]


def filter_policy(rule: RowFilter) -> EffectivePolicy:
    return policy(object_rules=ObjectRules(row_filters=[rule]))


def query_denied_policy() -> EffectivePolicy:
    """Holds object rules, but no reads at all: ``canQuery`` is checked before any of them."""
    return policy(
        permissions=PolicyPermissions(can_query=False),
        object_rules=ObjectRules(allowed_objects=["patients"]),
    )


def read_only_policy() -> EffectivePolicy:
    """Grants inserts, and is read-only anyway: ``readOnly`` is a ceiling over the grants."""
    return policy(permissions=PolicyPermissions(can_query=True, can_insert=True, read_only=True))


def writer_policy() -> EffectivePolicy:
    """Inserts and updates granted, but only on us-east rows and never to ``mrn``."""
    return policy(
        permissions=PolicyPermissions(can_query=True, can_insert=True, can_update=True, read_only=False),
        object_rules=ObjectRules(
            field_rules=FieldRules(read_only_fields=["mrn"]),
            row_filters=[RowFilter(field="region", operator=FilterOperator.equals, value="us-east")],
        ),
    )


class Limit(NamedTuple):
    label: str
    limits: PolicyLimits


LIMITS = [
    Limit("minSimilarityScore 0.75", PolicyLimits(min_similarity_score=0.75)),
    Limit("maxObjectSizeBytes 2048", PolicyLimits(max_object_size_bytes=2048)),
    Limit("maxResults 2", PolicyLimits(max_results=2)),
    Limit("all three", PolicyLimits(max_results=2, min_similarity_score=0.75, max_object_size_bytes=2048)),
]


# --------------------------------------------------------------------------------------------
# Merging: two policy definitions, one granted to the user and one to a group they belong to.
# --------------------------------------------------------------------------------------------

GROUP = "clinicians"


def _audit(reason: str) -> AuditInfo:
    return AuditInfo(granted_by="admin-jane-doe", granted_at="2026-09-01T09:00:00Z", reason=reason)


def user_definition() -> PolicyDefinition:
    """Assigned to the analyst directly. Read-only, the wider row cap, a partial phone mask."""
    return PolicyDefinition(
        version="1.0",
        name="analyst-direct",
        permissions=PolicyPermissions(can_query=True, read_only=True),
        priority=10,
        source_patterns=["db:clinical:*"],
        object_rules=ObjectRules(
            allowed_objects=["patients", "encounters", "labs"],
            field_rules=FieldRules(
                hidden_fields=["ssn"],
                masked_fields=[
                    MaskingRule(field="phone", mask_type=MaskType.partial, parameters=MaskingParameters(show_last=4))
                ],
            ),
            row_filters=[
                RowFilter(field="region", operator=FilterOperator.in_, values=["us-east", "us-west"])
            ],
        ),
        limits=PolicyLimits(max_results=100),
    )


def group_definition() -> PolicyDefinition:
    """Assigned to the clinicians group. Grants inserts, a lower row cap, redacts the phone."""
    return PolicyDefinition(
        version="1.0",
        name="clinicians-group",
        permissions=PolicyPermissions(can_query=True, can_insert=True, read_only=False),
        priority=50,
        source_patterns=["db:clinical:*"],
        object_rules=ObjectRules(
            allowed_objects=["patients", "encounters", "billing"],
            field_rules=FieldRules(
                hidden_fields=["notes"],
                masked_fields=[MaskingRule(field="phone", mask_type=MaskType.redact)],
            ),
            row_filters=[
                RowFilter(field="age", operator=FilterOperator.greater_than_or_equal, value=18)
            ],
        ),
        limits=PolicyLimits(max_results=25),
    )


def merge_assignments() -> list[PolicyAssignment]:
    return [
        PolicyAssignment(
            version="1.0",
            policy_name="analyst-direct",
            assignee=Assignee(type=AssigneeType.user, identifier=USER),
            scope=AssignmentScope(tenant_id=TENANT),
            active=True,
            audit=_audit("policy tour: the user's own grant"),
        ),
        PolicyAssignment(
            version="1.0",
            policy_name="clinicians-group",
            assignee=Assignee(type=AssigneeType.group, identifier=GROUP),
            scope=AssignmentScope(tenant_id=TENANT),
            active=True,
            audit=_audit("policy tour: the group's grant"),
        ),
    ]


def merged_policy() -> EffectivePolicy:
    """Resolved exactly as a store would: both assignments match, so both definitions merge."""
    definitions = [user_definition(), group_definition()]
    return resolve(
        USER,
        TENANT,
        SOURCE,
        merge_assignments(),
        {d.name: d for d in definitions},
        lambda _: [GROUP],
        lambda _: [],
    )


# --------------------------------------------------------------------------------------------
# Enforcement. The same wrapper and the same three calls for every section.
# --------------------------------------------------------------------------------------------


def signed_context(effective: EffectivePolicy) -> SecurityContext:
    """Signed, so the policy cannot be edited in transit by the agent it constrains."""
    return sign_context(build_security_context(USER, TENANT, [effective]), SIGNING_KEY)


def wrapper() -> SecureMcpToolWrapper:
    return SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=SIGNING_KEY))


def enforce(effective: EffectivePolicy, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The post-execution pipeline over copies of ``rows``, so the source data is never touched."""
    return wrapper().post_execute(signed_context(effective), [dict(row) for row in rows])


def check(
    effective: EffectivePolicy, object_name: str | None = None, fields: list[str] | None = None
) -> AccessResult:
    return wrapper().pre_execute(
        signed_context(effective), "query_patients", object_name=object_name, fields=fields
    )


def check_write(
    effective: EffectivePolicy,
    operation: WriteOperation,
    payload: dict[str, Any],
    target_row: dict[str, Any] | None = None,
) -> AccessResult:
    if target_row is None:
        return wrapper().pre_write(signed_context(effective), operation, "patients", payload)
    return wrapper().pre_write(
        signed_context(effective), operation, "patients", payload, target_row=target_row
    )


# --------------------------------------------------------------------------------------------
# Printing. Every line below is byte-identical to the TypeScript and .NET examples.
# --------------------------------------------------------------------------------------------

LABEL_WIDTH = 34
VERDICT_WIDTH = 8


def _access(label: str, result: AccessResult) -> str:
    verdict = "ALLOW" if result.allowed else "DENY"
    return f"  {label:<{LABEL_WIDTH}}{verdict:<{VERDICT_WIDTH}}{result.reason or ''}".rstrip()


def _rule(title: str) -> str:
    return f"--- {title} " + "-" * max(0, 70 - 5 - len(title))


def _value(value: Any) -> str:
    return "null" if value is None else str(value)


def _columns(row: dict[str, Any], order: list[str]) -> str:
    return ", ".join(column for column in order if column in row)


def _format_row(row: dict[str, Any], order: list[str]) -> str:
    return "  ".join(f"{column}={_value(row[column])}" for column in order if column in row)


def _ids(rows: list[dict[str, Any]]) -> str:
    return ", ".join(str(row["id"]) for row in rows) or "(none)"



def _rules(source: PolicyDefinition | EffectivePolicy) -> ObjectRules:
    return source.object_rules or ObjectRules()


def _fields(source: PolicyDefinition | EffectivePolicy) -> FieldRules:
    return _rules(source).field_rules or FieldRules()


def _yes(flag: bool | None) -> str:
    return "yes" if flag else "no"


def _phone_mask(source: PolicyDefinition | EffectivePolicy) -> str:
    return ", ".join(m.mask_type.value for m in _fields(source).masked_fields or [] if m.field == "phone")


def _filters(source: PolicyDefinition | EffectivePolicy) -> str:
    return ", ".join(f"{f.field} {f.operator.value}" for f in _rules(source).row_filters or [])


def _max_results(source: PolicyDefinition | EffectivePolicy) -> str:
    return _value(source.limits.max_results if source.limits else None)


#: Each merged rule, how the merge combines it, and how to read it off a definition or a policy.
#: Lists are printed sorted, so the output does not depend on the order a merge emits them in.
MERGE_TABLE = [
    ("allowedObjects", "intersected", lambda s: ", ".join(sorted(_rules(s).allowed_objects or []))),
    ("hiddenFields", "unioned", lambda s: ", ".join(sorted(_fields(s).hidden_fields or []))),
    ("phone mask", "the most restrictive", _phone_mask),
    ("rowFilters", "all of them apply", _filters),
    ("maxResults", "the lowest", _max_results),
    ("canInsert", "only if every policy grants it", lambda s: _yes(s.permissions.can_insert)),
    ("readOnly", "if any policy sets it", lambda s: _yes(s.permissions.read_only)),
]


def main() -> None:
    print("=" * 70)
    print("Policy tour: every rule the SDK enforces, one section each")
    print("=" * 70)
    print()
    print("Every section below uses the same signed context, the same wrapper and the same")
    print("calls. Only the policy changes, and the source returns everything each time, so")
    print("what is missing or masked in the output is enforcement.")

    # -- Masks ---------------------------------------------------------------------------------
    print()
    print(_rule("Masks: one rule per mask type"))
    masked = enforce(mask_policy(), [PATIENT])[0]
    for column in PATIENT_COLUMNS:
        after = _value(masked[column]) if column in masked else "(dropped)"
        print(f"  {column:<11}{MASK_LABELS[column]:<24}{_value(PATIENT[column]):<24}{after}")
    if "ssn" in masked or masked["dob"] != "[REDACTED]":
        raise SystemExit("MASKING FAILED. ssn must be dropped and dob redacted.")
    print()
    print("Hashes are the first 16 hex characters of the digest, so the same input always")
    print("gives the same token: rows still join and group on email without revealing it.")

    # -- Fields --------------------------------------------------------------------------------
    print()
    print(_rule("Fields: allowedFields next to hiddenFields"))
    source = {"id": 1, "name": "Alice Nguyen", "region": "us-east", "dob": "1979-04-12", "notes": "stable", "ssn": "111-22-3333"}
    print("  the source returns    " + _columns(source, FIELD_COLUMNS))
    for label, effective in [
        ("allowedFields [id, name, region]", allowed_fields_policy()),
        ("hiddenFields [ssn, notes]", hidden_fields_policy()),
    ]:
        kept = enforce(effective, [source])[0]
        print()
        print(f"  {label}")
        print("    returns             " + _columns(kept, FIELD_COLUMNS))
        print(_access("    asks for [id, ssn]", check(effective, fields=["id", "ssn"])))
    print()
    print("An allow-list also drops a column the source adds tomorrow; a deny-list keeps it.")

    # -- Objects -------------------------------------------------------------------------------
    print()
    print(_rule("Objects: allowedObjects [patients, encounters, billing_*]"))
    print("                       hiddenObjects [billing_internal]")
    for name in OBJECT_PROBES:
        print(_access(name, check(object_policy(), object_name=name)))
    print()
    print("billing_internal matches the billing_* allow and is refused anyway: a hide wins.")

    # -- Row filters ---------------------------------------------------------------------------
    print()
    print(_rule("Row filters: one operator at a time over rows 1-6"))
    for entry in FILTERS:
        print(f"  {entry.label:<{LABEL_WIDTH}}ids {_ids(enforce(filter_policy(entry.rule), ROWS))}")
    print()
    print("Row 6 has no discharged_at key, so it fails isNull and isNotNull alike: a missing")
    print("field never passes a filter. matches is anchored and case-sensitive, so PT-10A")
    print("and pt-106 fail it; between is inclusive, so age 52 is kept.")

    # -- Permissions ---------------------------------------------------------------------------
    print()
    print(_rule("Permissions"))
    print("  canQuery false")
    print(_access("    query patients", check(query_denied_policy(), object_name="patients")))
    print("  canInsert true, readOnly true")
    print(_access("    insert", check_write(read_only_policy(), WriteOperation.insert, {"name": "Bo"})))
    print("  canInsert, canUpdate, readOnly false; mrn read-only; region us-east")
    writer = writer_policy()
    east = {"id": 1, "region": "us-east"}
    west = {"id": 3, "region": "eu-west"}
    print(_access("    insert", check_write(writer, WriteOperation.insert, {"name": "Bo", "region": "us-east"})))
    print(_access("    insert setting mrn", check_write(writer, WriteOperation.insert, {"name": "Bo", "mrn": "MRN-1"})))
    print(_access("    update a us-east row", check_write(writer, WriteOperation.update, {"name": "Bo"}, east)))
    print(_access("    update an eu-west row", check_write(writer, WriteOperation.update, {"name": "Bo"}, west)))
    print(_access("    delete", check_write(writer, WriteOperation.delete, {}, east)))
    print()
    print("readOnly is a ceiling over the grants, not a default beside them. Once writes are")
    print("granted, the field and row rules still apply to what a write touches.")

    # -- Limits --------------------------------------------------------------------------------
    print()
    print(_rule("Limits over seven search hits"))
    print("  scores  d1 0.92  d2 0.75  d3 0.60  d4 0.88  d5 0.81  d6 none  d7 0.99")
    print("  sizes   d1 1200  d2 4096  d3 800   d4 2048  d5 none  d6 500   d7 100")
    print()
    for limit in LIMITS:
        print(f"  {limit.label:<{LABEL_WIDTH}}{_ids(enforce(policy(limits=limit.limits), DOCUMENTS))}")
    print()
    print("Both bounds are inclusive, and a hit with no score or no size is dropped rather")
    print("than let through. maxResults applies last, to what the other rules kept.")

    # -- Merging -------------------------------------------------------------------------------
    print()
    print(_rule("Merging: a user policy and a group policy"))
    merged = merged_policy()
    print("  resolved from    " + ", ".join(merged.source_profiles))
    user, group = user_definition(), group_definition()
    for title, how, pick in MERGE_TABLE:
        print()
        print(f"  {title:<17}{how}")
        for name, source in [(user.name, user), (group.name, group), ("merged", merged)]:
            print(f"    {name:<19}{pick(source)}")
    print()
    print("The merged policy, enforced:")
    merged_rows = enforce(merged, MERGE_ROWS)
    if any("ssn" in row or "notes" in row for row in merged_rows):
        raise SystemExit("A HIDDEN FIELD LEAKED. The merge must union both policies' hidden fields.")
    for row in merged_rows:
        print("    " + _format_row(row, MERGE_COLUMNS))
    print(_access("labs", check(merged, object_name="labs")))
    print(_access("billing", check(merged, object_name="billing")))
    print(_access("insert", check_write(merged, WriteOperation.insert, {"name": "Bo"})))
    print()
    print("Most restrictive wins: allowed sets intersect, hidden fields union, the stronger")
    print("mask and the lower cap apply, every row filter holds, and a grant survives only if")
    print("every policy makes it. The group's insert grant is outvoted by the user's policy.")

    print()
    print("=" * 70)
    print("One wrapper, one set of calls; the policy alone decided every line above.")
    print("=" * 70)


if __name__ == "__main__":
    main()
