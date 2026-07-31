"""Shared TOLAP setup for the framework examples: one policy, one signed context, one gate.

Every example in this directory registers a tool with a different agent framework, and every one
of them funnels the actual data access through :func:`enforced_query` below. That is the point of
the set: the enforcement code is *identical* regardless of framework, because TOLAP wraps the
function the framework calls rather than integrating with the framework itself.

The policy is deliberately small and its effects are observable, so each example can assert that
enforcement happened rather than printing something that looks plausible:

* ``allowedObjects: [patients]``   -- ``encounters`` is refused before any query runs
* ``hiddenFields: [ssn]``          -- never reaches the agent, even though the "database"
                                      returns it
* ``maskedFields: dob -> redact``  -- replaced with ``[REDACTED]``
* ``rowFilters: region = us-east`` -- non-matching rows are dropped
* ``maxResults: 2``                -- the ceiling is applied last
"""

from __future__ import annotations

from typing import Any

from tolap_core.context import build_security_context, sign_context
from tolap_core.enums import FilterOperator, MaskType
from tolap_core.models import (
    EffectivePolicy,
    FieldRules,
    MaskingRule,
    ObjectRules,
    PolicyLimits,
    PolicyPermissions,
    RowFilter,
    SecurityContext,
)
from tolap_mcp.options import SecureMcpServerOptions
from tolap_mcp.wrapper import SecureMcpToolWrapper

SIGNING_KEY = "example-signing-key-do-not-use-in-production"

#: What the "database" returns: more rows and more columns than the policy permits, so the
#: difference between raw and enforced output is visible rather than asserted.
FAKE_ROWS: list[dict[str, Any]] = [
    {"id": 1, "name": "Alice Nguyen", "region": "us-east", "ssn": "111-22-3333", "dob": "1979-04-12"},
    {"id": 2, "name": "Bruno Sato", "region": "us-east", "ssn": "222-33-4444", "dob": "1985-11-02"},
    {"id": 3, "name": "Carol Diaz", "region": "us-east", "ssn": "333-44-5555", "dob": "1990-01-30"},
    {"id": 4, "name": "Dan Meyer", "region": "eu-west", "ssn": "444-55-6666", "dob": "1972-08-19"},
]


def build_policy() -> EffectivePolicy:
    """The effective policy an agent's user holds for this source.

    In a real deployment this comes from ``store.resolve_policy(...)``, which merges every
    assignment the user holds -- see docs/architecture.md. It is constructed inline here so the
    examples have no database dependency and so the rules under test are visible in one place.
    """
    return EffectivePolicy(
        version="1.0",
        user_id="analyst-001",
        tenant_id="hospital-001",
        source_connection_id="db:analytics:patients",
        source_profiles=["example-analyst"],
        permissions=PolicyPermissions(can_query=True, read_only=True),
        object_rules=ObjectRules(
            allowed_objects=["patients"],
            field_rules=FieldRules(
                hidden_fields=["ssn"],
                masked_fields=[MaskingRule(field="dob", mask_type=MaskType.redact)],
            ),
            row_filters=[
                RowFilter(field="region", operator=FilterOperator.equals, value="us-east")
            ],
        ),
        limits=PolicyLimits(max_results=2),
    )


def signed_context() -> SecurityContext:
    """A signed context for the policy above.

    Signing is not decoration. The wrapper verifies the signature and expiry before enforcing,
    so a tampered policy is refused rather than applied -- which is what stops an agent from
    editing its own permissions in transit.
    """
    context = build_security_context("analyst-001", "hospital-001", [build_policy()])
    return sign_context(context, SIGNING_KEY)


def wrapper() -> SecureMcpToolWrapper:
    return SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=SIGNING_KEY))


def query_patients_unsafe(table: str) -> list[dict[str, Any]]:
    """Stands in for the code that really talks to your data source.

    Deliberately returns everything: TOLAP is handed the *result*, so an example whose fake
    source pre-filtered would prove nothing. Swap this for psycopg, boto3 or an HTTP call --
    the enforcement above it does not change, and it never sees your credentials.
    """
    return list(FAKE_ROWS)


def enforced_query(table: str) -> list[dict[str, Any]]:
    """The one function every framework example calls. This is the whole integration.

    ``execute_with_enforcement`` runs the pre-execution checks (signature, expiry, ``canQuery``,
    the object allow-list), invokes ``tool_fn``, then applies the post-execution pipeline in the
    normative order. Passing ``object_name`` is what lets the object check happen *before* the
    query is issued rather than filtering an unauthorized result afterwards.

    Raises ``PermissionError`` when the policy refuses the call -- which the framework surfaces
    to the model as a tool error, so the agent learns it cannot reach that table.
    """
    return wrapper().execute_with_enforcement(
        context=signed_context(),
        tool_name="query_patients",
        tool_fn=query_patients_unsafe,
        tool_args={"table": table},
        object_name=table,
    )
