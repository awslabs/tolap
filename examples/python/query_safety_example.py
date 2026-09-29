"""What 1.2.0 changed about queries that span tables, and about results enforced twice.

The other examples read one table through one tool. Real agents join, and real data layers
sometimes enforce before TOLAP sees the rows. Three things behave differently from 1.1.0, and each
section below shows one of them with the SDK's own decisions:

1. **The SQL pre-check reads every table.** A joined, comma-joined or derived table is checked
   against ``allowedObjects``/``hiddenObjects`` like the ``FROM`` table, every column is resolved
   through its alias to the table it belongs to, and a construct the check cannot resolve is
   refused rather than guessed at. A refused query never reaches the source.
2. **Qualified names stay with their object.** A row filter on ``patients.region`` reads
   ``patients.region``, never ``encounters.region``, and ``allowedFields`` entry ``patients.name``
   no longer lets ``encounters.name`` through.
3. **A tool can declare its result already enforced.** A data layer that already ran the result
   pipeline returns ``EnforcedResult.for_context(rows, context)``, and the wrapper stops hashing
   hashed fields a second time. Only a marker bound to this exact signed context is honoured.

One identity, one signed policy, one wrapper. Specified in docs/canonical-enforcement-spec.md
sections 4 and 7 and docs/connector-spec.md section 5.

Run it::

    python3 examples/python/query_safety_example.py

Deliberately mirrors ``examples/typescript/query-safety-example.ts`` and
``examples/dotnet/QuerySafetyExample.cs`` -- same policy, same queries, same rows, byte-identical
printed output. A divergence between the languages then shows up as a different result rather than
hiding behind separately-written expectations.
"""

from __future__ import annotations

from typing import Any, Callable, NamedTuple

from tolap_core.context import build_security_context, sign_context
from tolap_core.enforced_result import EnforcedResult
from tolap_core.enforcement import apply_result_pipeline
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

#: The salt ``hash`` masking uses. The data layer in section 3 must use the wrapper's salt, or
#: its hashes would not match the wrapper's and the marker would be a lie.
HASH_SALT = "example-hash-salt-do-not-use-in-production"

TENANT = "hospital-001"

USER = "analyst-001"


class Query(NamedTuple):
    label: str
    sql: str


#: Section 1. The first query is the one the policy permits; every other one is refused.
QUERIES = [
    Query(
        "join an allowed table",
        "SELECT p.id, p.name, e.code FROM patients p JOIN encounters e ON e.patient_id = p.id",
    ),
    Query(
        "join a hidden table",
        "SELECT p.id, b.amount FROM patients p JOIN billing_internal b ON b.patient_id = p.id",
    ),
    Query("comma join", "SELECT p.id FROM patients p, billing_internal b"),
    Query("derived table", "SELECT x.id FROM (SELECT patient_id AS id FROM billing_internal) x"),
    Query(
        "subquery in WHERE",
        "SELECT p.id FROM patients p WHERE p.id IN (SELECT patient_id FROM billing_internal)",
    ),
    Query(
        "hidden field via alias",
        "SELECT p.ssn FROM patients p JOIN encounters e ON e.patient_id = p.id",
    ),
    Query(
        "other object's column",
        "SELECT e.name FROM patients p JOIN encounters e ON e.patient_id = p.id",
    ),
    Query("bare column in a join", "SELECT id FROM patients p JOIN encounters e ON e.patient_id = p.id"),
]

#: Section 2. What the join returns, keyed by object. Each row carries two ``region`` columns and
#: two ``name`` columns, one per table, so a rule that ignores the qualifier reads the wrong one.
JOIN_ROWS: list[dict[str, Any]] = [
    {
        "patients.id": 1,
        "patients.name": "Alice Nguyen",
        "patients.region": "eu-west",
        "patients.ssn": "111-22-3333",
        "encounters.region": "us-east",
        "encounters.name": "Dr Okafor",
        "encounters.code": "E11.9",
    },
    {
        "patients.id": 2,
        "patients.name": "Bruno Sato",
        "patients.region": "us-east",
        "patients.ssn": "222-33-4444",
        "encounters.region": "eu-west",
        "encounters.name": "Dr Lindqvist",
        "encounters.code": "I10",
    },
]

JOIN_COLUMNS = [
    "patients.id",
    "patients.name",
    "patients.region",
    "patients.ssn",
    "encounters.region",
    "encounters.name",
    "encounters.code",
]

#: Section 2. The field pre-check, told which object a bare field belongs to.
FIELD_CHECKS = [("patients", "name"), ("encounters", "name"), ("encounters", "code")]

#: Section 3. What the ``patients`` table holds.
PATIENT_ROWS: list[dict[str, Any]] = [
    {"id": 1, "name": "Alice Nguyen", "email": "alice@example.com", "region": "us-east", "ssn": "111-22-3333"},
    {"id": 2, "name": "Dan Meyer", "email": "dan@example.com", "region": "eu-west", "ssn": "444-55-6666"},
]

PATIENT_COLUMNS = ["id", "name", "email", "region", "ssn"]


def build_policy(user_id: str) -> EffectivePolicy:
    """Two objects the analyst may read, one they may not, and field rules on both.

    ``allowedFields`` names each object's columns with its qualifier, which is what makes the
    qualifier matter: ``patients.name`` is listed, ``encounters.name`` is not. In a real deployment
    this comes from ``store.resolve_policy(...)``; it is written inline here so the rules under
    test are visible in one place.
    """
    return EffectivePolicy(
        version="1.0",
        user_id=user_id,
        tenant_id=TENANT,
        source_connection_id="db:analytics:clinical",
        source_profiles=["clinical-analyst"],
        permissions=PolicyPermissions(can_query=True, read_only=True),
        object_rules=ObjectRules(
            allowed_objects=["patients", "encounters"],
            hidden_objects=["billing_internal"],
            field_rules=FieldRules(
                hidden_fields=["ssn"],
                allowed_fields=[
                    "patients.id",
                    "patients.name",
                    "patients.email",
                    "patients.region",
                    "encounters.id",
                    "encounters.patient_id",
                    "encounters.code",
                ],
                masked_fields=[MaskingRule(field="email", mask_type=MaskType.hash)],
            ),
            row_filters=[
                RowFilter(field="patients.region", operator=FilterOperator.equals, value="us-east")
            ],
        ),
        limits=PolicyLimits(max_results=10),
    )


def signed_context(user_id: str = USER) -> SecurityContext:
    return sign_context(
        build_security_context(user_id, TENANT, [build_policy(user_id)]), SIGNING_KEY
    )


def wrapper() -> SecureMcpToolWrapper:
    return SecureMcpToolWrapper(
        SecureMcpServerOptions(signing_key=SIGNING_KEY, hash_salt=HASH_SALT)
    )


def run_query(context: SecurityContext, sql: str) -> tuple[str | None, bool]:
    """Section 1: run one query through the SQL path. Returns the denial reason, and whether the
    source was reached. The fake source records the call and returns the join's rows."""
    reached: list[str] = []

    def source(query: str) -> list[dict[str, Any]]:
        reached.append(query)
        return [dict(row) for row in JOIN_ROWS]

    try:
        wrapper().execute_sql_with_enforcement(context, sql, source)
    except PermissionError as denied:
        return str(denied).removeprefix("Access denied: "), bool(reached)
    return None, bool(reached)


class Tool(NamedTuple):
    label: str
    note: str
    #: Builds the tool's return value from the signed context of the call.
    returns: Callable[[SecurityContext], Any]


def raw_rows() -> list[dict[str, Any]]:
    """Stands in for the database. Returns everything, so enforcement is visible."""
    return [dict(row) for row in PATIENT_ROWS]


def data_layer_rows(context: SecurityContext) -> list[dict[str, Any]]:
    """An ORM adapter that runs the result pipeline itself, with the wrapper's salt."""
    return apply_result_pipeline(raw_rows(), context.effective_policy, HASH_SALT)


#: Section 3. Five tools, one call each through ``execute_with_enforcement``.
TOOLS = [
    Tool("plain rows", "the wrapper enforces", lambda _: raw_rows()),
    Tool(
        "enforced, unmarked",
        "hashed twice",
        data_layer_rows,
    ),
    Tool(
        "enforced, marked",
        "marker honoured",
        lambda ctx: EnforcedResult.for_context(data_layer_rows(ctx), ctx),
    ),
    Tool(
        "marked for another user",
        "marker ignored",
        lambda _: EnforcedResult.for_context(raw_rows(), signed_context("analyst-002")),
    ),
    Tool(
        "marked, not enforced",
        "a false claim",
        lambda ctx: EnforcedResult.for_context(raw_rows(), ctx),
    ),
]


def call_tool(context: SecurityContext, tool: Tool) -> list[dict[str, Any]]:
    return wrapper().execute_with_enforcement(
        context, "query_patients", lambda: tool.returns(context), {}, object_name="patients"
    )


# --------------------------------------------------------------------------------------------
# Printing. Every line below is byte-identical to the TypeScript and .NET examples.
# --------------------------------------------------------------------------------------------

LABEL_WIDTH = 25
VERDICT_WIDTH = 8


def _access(label: str, allowed: bool, detail: str = "") -> str:
    verdict = "ALLOW" if allowed else "DENY"
    return f"  {label:<{LABEL_WIDTH}}{verdict:<{VERDICT_WIDTH}}{detail}".rstrip()


def _rule(title: str) -> str:
    return f"--- {title} " + "-" * max(0, 70 - 5 - len(title))


def _format_row(row: dict[str, Any], columns: list[str]) -> str:
    return "  ".join(f"{column}={row[column]}" for column in columns if column in row)


def main() -> None:
    context = signed_context()
    print("=" * 70)
    print("Query safety: every table checked, every name resolved, one enforcement")
    print("=" * 70)
    print()
    print("One analyst, one signed policy:")
    print("    allowedObjects  patients, encounters      hiddenObjects  billing_internal")
    print("    allowedFields   patients.{id,name,email,region}, encounters.{id,patient_id,code}")
    print("    hiddenFields    ssn        maskedFields  email (hash)")
    print("    rowFilters      patients.region = us-east")

    # 1. -------------------------------------------------------------------------------------
    print()
    print(_rule("1. the SQL pre-check reads every table"))
    print("Each query goes through the wrapper's SQL path. The source records whether it was")
    print("reached; a refused query never is.")
    print()
    for query in QUERIES:
        reason, reached = run_query(context, query.sql)
        if reason is not None and reached:
            raise SystemExit(f"A REFUSED QUERY REACHED THE SOURCE: {query.sql}")
        print("    " + query.sql)
        print(_access(query.label, reason is None, "the source ran" if reason is None else reason))
    print()
    print("Before 1.2.0 the check did not resolve joined, comma-joined or derived tables, so")
    print("the three queries that reach billing_internal that way were not refused by it.")

    # 2. -------------------------------------------------------------------------------------
    print()
    print(_rule("2. qualified names stay with their object"))
    print("The allowed join returns both tables' columns, keyed by object:")
    for row in JOIN_ROWS:
        print("    " + _format_row(row, JOIN_COLUMNS))
    print()
    print("After the result pipeline:")
    enforced = wrapper().post_execute(context, [dict(row) for row in JOIN_ROWS])
    for row in enforced:
        print("    " + _format_row(row, JOIN_COLUMNS))
    if any("patients.ssn" in row or "encounters.name" in row for row in enforced):
        raise SystemExit("A COLUMN THE POLICY DOES NOT ALLOW CAME BACK.")
    print()
    print("Alice's row is dropped: her patients.region is eu-west. The filter no longer falls")
    print("back to encounters.region, whose us-east used to keep her row. encounters.name and")
    print("encounters.region are projected out: patients.name does not allow encounters.name.")
    print()
    print("The field pre-check, told which object a bare field is read from:")
    for object_name, field in FIELD_CHECKS:
        decision = wrapper().pre_execute(
            context, "query_patients", object_name=object_name, fields=[field]
        )
        print(_access(f"{field} from {object_name}", decision.allowed, decision.reason or ""))

    # 3. -------------------------------------------------------------------------------------
    print()
    print(_rule("3. a tool can declare its result already enforced"))
    print("Each tool is called through the wrapper's tool path. email is hash-masked, and hash")
    print("masking is not idempotent: enforce twice and the value is hashed twice.")
    print()
    reference = call_tool(context, TOOLS[0])
    for tool in TOOLS:
        rows = call_tool(context, tool)
        print(f"  {tool.label:<{LABEL_WIDTH}}{tool.note}")
        for row in rows:
            print("    " + _format_row(row, PATIENT_COLUMNS))
        if any("ssn" in row for row in rows):
            raise SystemExit("ssn LEAKED. Hidden-field removal runs even for an honoured marker.")
    if call_tool(context, TOOLS[2]) != reference:
        raise SystemExit("AN HONOURED MARKER DID NOT MATCH THE WRAPPER'S OWN ENFORCEMENT.")
    print()
    print("An honoured marker skips masking and the size ceiling, nothing else: ssn is still")
    print("removed and the region filter still runs, which is why the last tool's raw email")
    print("comes back while its ssn and Dan's eu-west row do not. The marker is the tool's")
    print("claim, not proof, so return one only when the data layer really ran this context's")
    print("pipeline. A marker bound to another context is unwrapped and its rows get the full")
    print("pipeline, as before 1.2.0. Only the tool path honours a marker; the SQL path and a")
    print("direct post-execute call unwrap it and enforce in full.")

    print()
    print("=" * 70)
    print("Every decision above is the SDK's. A refused query never reached the source, a")
    print("qualified rule read only its own object, and a result was enforced exactly once.")
    print("=" * 70)


if __name__ == "__main__":
    main()
