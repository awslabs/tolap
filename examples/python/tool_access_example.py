"""Gating which MCP tools an identity may call, not just what those tools return.

Your MCP host or gateway already decides whether an agent may reach a server, and it decides once,
for everyone behind that agent: every user sees the same tool list. The other examples here are
about the second question -- what a permitted call may return. This one is about the layer in
between. A policy that carries ``objectRules.toolRules`` gives each identity its own answer to
"which of these tools may I call at all?":

* ``allowedTools`` -- the only tools this identity may call. Matched exactly.
* ``hiddenTools``  -- tools this identity may never call. Matched case-insensitively, so a
  mis-cased name cannot slip past a hide.

One server registers four tools. Three identities hold three signed policies, and for each the
script prints what a ``tools/list`` handler would show, what happens when a client calls every tool
anyway, and what a permitted call returns -- because the data rules still apply to it.

There is no switch in the code. The same wrapper and the same calls run for all three identities;
the policy alone decides, and a policy without ``toolRules`` leaves tool gating with the host
exactly as before. Specified in docs/canonical-enforcement-spec.md section 16.

Run it::

    python3 examples/python/tool_access_example.py

Deliberately mirrors ``examples/typescript/tool-access-example.ts`` and
``examples/dotnet/ToolAccessExample.cs`` -- same tools, same policies, same rows, byte-identical
printed output. A divergence between the languages then shows up as a different result rather than
hiding behind separately-written expectations.
"""

from __future__ import annotations

from typing import Any, NamedTuple

from tolap_core.context import build_security_context, sign_context
from tolap_core.enums import FilterOperator, MaskType
from tolap_core.enforcement import AccessResult
from tolap_core.models import (
    EffectivePolicy,
    FieldRules,
    MaskingRule,
    ObjectRules,
    PolicyLimits,
    PolicyPermissions,
    RowFilter,
    SecurityContext,
    ToolRules,
)
from tolap_mcp.options import SecureMcpServerOptions
from tolap_mcp.wrapper import SecureMcpToolWrapper

SIGNING_KEY = "example-signing-key-do-not-use-in-production"

TENANT = "hospital-001"

#: What the agent server registers. The host shows this list to every user.
TOOLS = ["query_patients", "count_patients", "export_segment_csv", "delete_patient"]

#: What the "database" holds: more rows and more columns than the data rules permit.
FAKE_ROWS: list[dict[str, Any]] = [
    {"id": 1, "name": "Alice Nguyen", "region": "us-east", "ssn": "111-22-3333", "dob": "1979-04-12"},
    {"id": 2, "name": "Bruno Sato", "region": "us-east", "ssn": "222-33-4444", "dob": "1985-11-02"},
    {"id": 3, "name": "Carol Diaz", "region": "us-east", "ssn": "333-44-5555", "dob": "1990-01-30"},
    {"id": 4, "name": "Dan Meyer", "region": "eu-west", "ssn": "444-55-6666", "dob": "1972-08-19"},
]

#: The order columns are printed in, so the output does not depend on a runtime's map ordering.
COLUMNS = ["id", "name", "region", "ssn", "dob"]


class Identity(NamedTuple):
    user_id: str
    profile: str
    #: ``None`` is the data-only case: no tool gating in the policy at all.
    tool_rules: ToolRules | None
    #: A mis-cased name to try as well, or ``None``.
    mis_cased: str | None


IDENTITIES = [
    Identity(
        "analyst-001",
        "patients-analyst",
        ToolRules(allowed_tools=["query_patients", "count_patients"]),
        "Query_Patients",
    ),
    Identity(
        "support-001",
        "patients-support",
        ToolRules(hidden_tools=["export_segment_csv", "delete_patient"]),
        "Delete_Patient",
    ),
    Identity("auditor-001", "patients-data-only", None, None),
]


def build_policy(identity: Identity) -> EffectivePolicy:
    """The same data rules for everyone; only ``tool_rules`` differs.

    Holding the data rules constant is what makes the tool layer the only variable: every
    difference in the output below is ``toolRules`` at work. In a real deployment each policy
    comes from ``store.resolve_policy(...)``; it is written inline here so the rules under test
    are visible in one place.
    """
    return EffectivePolicy(
        version="1.0",
        user_id=identity.user_id,
        tenant_id=TENANT,
        source_connection_id="db:analytics:patients",
        source_profiles=[identity.profile],
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
            tool_rules=identity.tool_rules,
        ),
        limits=PolicyLimits(max_results=2),
    )


def signed_context(identity: Identity) -> SecurityContext:
    """Signed, so the tool rules cannot be edited in transit by the agent they constrain."""
    return sign_context(
        build_security_context(identity.user_id, TENANT, [build_policy(identity)]), SIGNING_KEY
    )


def wrapper() -> SecureMcpToolWrapper:
    """One wrapper for every identity. There is no tool-rules option to set on it."""
    return SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=SIGNING_KEY))


def fake_source() -> list[dict[str, Any]]:
    """Stands in for the database. Returns everything, so enforcement is visible."""
    return [dict(row) for row in FAKE_ROWS]


def call_tool(
    context: SecurityContext, tool_name: str
) -> tuple[AccessResult, list[dict[str, Any]] | None]:
    """What a ``tools/call`` handler does: check the tool, then fetch, then enforce on the rows.

    The tool check runs before ``canQuery`` and every data check, so a refused tool never
    reaches the source. Every tool reads ``patients`` here; that keeps the demo about the tool
    name rather than about which table each tool happens to touch.
    """
    decision = wrapper().pre_execute(context, tool_name, object_name="patients")
    if not decision.allowed:
        return decision, None
    return decision, wrapper().post_execute(context, fake_source())


# --------------------------------------------------------------------------------------------
# Printing. Every line below is byte-identical to the TypeScript and .NET examples.
# --------------------------------------------------------------------------------------------

LABEL_WIDTH = 22
VERDICT_WIDTH = 8


def _access(label: str, allowed: bool, detail: str = "") -> str:
    verdict = "ALLOW" if allowed else "DENY"
    return f"  {label:<{LABEL_WIDTH}}{verdict:<{VERDICT_WIDTH}}{detail}".rstrip()


def _rule(title: str) -> str:
    return f"--- {title} " + "-" * max(0, 70 - 5 - len(title))


def _describe(rules: ToolRules | None) -> str:
    if rules is None:
        return "no toolRules"
    if rules.allowed_tools is not None:
        return "allowedTools [" + ", ".join(rules.allowed_tools) + "]"
    return "hiddenTools [" + ", ".join(rules.hidden_tools or []) + "]"


def _format_row(row: dict[str, Any]) -> str:
    return "  ".join(f"{column}={row[column]}" for column in COLUMNS if column in row)


NOTES = {
    "analyst-001": [
        "An allow-list: two tools listed, the other two refused when called anyway. The",
        "match is exact, so 'Query_Patients' is not 'query_patients' and is refused too.",
    ],
    "support-001": [
        "A deny-list, landing on the analyst's list from the other side. The difference shows",
        "when the server adds a tool: an allow-list will not list it, a deny-list will. The",
        "hide is case-insensitive, so 'Delete_Patient' is refused rather than slipping past.",
    ],
    "auditor-001": [
        "No toolRules, so TOLAP does not gate tools at all: every tool is listed and",
        "callable, and the decision stays with the host, exactly as before. The data rules",
        "still apply, which is all this policy asks for.",
    ],
}


def main() -> None:
    print("=" * 70)
    print("Tool access: one server, one tool list, a different answer per identity")
    print("=" * 70)
    print()
    print("The server registers four tools, and the host shows every user the same list:")
    print("    " + ", ".join(TOOLS))
    print()
    print(f"The database holds {len(FAKE_ROWS)} rows. Every policy below carries the same data rules -- ssn")
    print("hidden, dob redacted, region us-east, at most 2 rows -- so the only thing that")
    print("differs between the three identities is objectRules.toolRules.")

    for identity in IDENTITIES:
        context = signed_context(identity)
        listed = wrapper().filter_tools(context, TOOLS)

        print()
        print(_rule(f"{identity.user_id}  {_describe(identity.tool_rules)}"))
        print("tools/list shows: " + ", ".join(listed))
        print()
        print("Every tool called anyway, as a client that ignores the list might:")

        called_through = []
        for tool in TOOLS + ([identity.mis_cased] if identity.mis_cased else []):
            decision, _ = call_tool(context, tool)
            print(_access(tool, decision.allowed, decision.reason or ""))
            if decision.allowed and tool in TOOLS:
                called_through.append(tool)

        if called_through != listed:
            raise SystemExit(
                "THE LIST AND THE CALLS DISAGREED. A tools/list handler must show exactly the "
                f"tools a call would not refuse by name.\n  listed: {listed}\n"
                f"  callable: {called_through}"
            )

        _, rows = call_tool(context, "query_patients")
        assert rows is not None
        if any("ssn" in row for row in rows):
            raise SystemExit("ssn LEAKED. A permitted tool must still meet the data rules.")

        print()
        print("query_patients is permitted, and still meets the data rules:")
        for row in rows:
            print("    " + _format_row(row))
        print()
        for line in NOTES[identity.user_id]:
            print(line)

    print()
    print("=" * 70)
    print("Three identities, one server, one wrapper, no code change between them.")
    print("The policy alone picks the combination:")
    print("  no toolRules              data access only; tool gating stays with the host")
    print("  toolRules and data rules  both layers narrow (the analyst and support above)")
    print("  toolRules, no data rules  tool access only")
    print()
    print("Listing is not permission. Every call is re-checked, which is why the tools the")
    print("list never showed were refused when called, before any query was built. And")
    print("allowedTools [] is not 'unrestricted': it denies every tool.")
    print("=" * 70)


if __name__ == "__main__":
    main()
