"""Choosing where a database policy is applied: in the SQL, or only in the results.

The other examples in this directory wrap a framework's tool call. This one is about SQL
specifically, and shows the one knob an integrator has over *where* enforcement happens:

* ``rewrite_and_post`` (the default) -- TOLAP edits the query so the database returns less
  data, then enforces on what comes back.
* ``post_only`` -- your query runs byte for byte as written, and enforcement happens
  entirely on the rows returned.

**Both print the same rows.** That is the point, and it is why the choice is safe to
offer: the mode is a resource decision, not an access-control one. If it changed what the
caller saw it would be a security setting wearing a performance setting's clothes.

Run it::

    python3 examples/python/enforcement_mode_example.py

There is deliberately no third "rewrite only" mode. Two things have no SQL form at all --
masking (no ``SELECT`` returns ``[REDACTED]``) and the ``contains`` / ``startsWith`` /
``matches`` operators -- so skipping the post pass would return unmasked values and rows
the policy excludes. This script prints the evidence for that rather than asserting it.
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
from tolap_core.sql_rewriter import SqlDialect, SqlEnforcementMode, prepare_sql_query
from tolap_mcp.options import SecureMcpServerOptions
from tolap_mcp.wrapper import SecureMcpToolWrapper

SIGNING_KEY = "example-signing-key-do-not-use-in-production"

QUERY = "SELECT id, name, region, dob FROM patients ORDER BY id"

#: What the "database" holds: more rows and more columns than the policy permits.
FAKE_ROWS: list[dict[str, Any]] = [
    {"id": 1, "name": "Alice Nguyen", "region": "us-east", "dob": "1980-04-01", "ssn": "111-22-3333"},
    {"id": 2, "name": "Bruno Sato", "region": "us-east", "dob": "1975-09-12", "ssn": "222-33-4444"},
    {"id": 3, "name": "Chidi Okonkwo", "region": "us-east", "dob": "1990-01-30", "ssn": "333-44-5555"},
    {"id": 4, "name": "Dana Petrova", "region": "eu-west", "dob": "1988-07-19", "ssn": "444-55-6666"},
]


def policy() -> EffectivePolicy:
    """A policy whose every rule is observable in the output.

    Note the mix on purpose: ``region`` is an ``equals`` filter the rewriter CAN push into
    SQL, while ``name`` is a ``startsWith`` it cannot. So even in ``rewrite_and_post`` the
    post pass is doing real work -- which is the whole reason it is never optional.
    """
    return EffectivePolicy(
        version="1.0",
        user_id="user-123",
        tenant_id="tenant-acme",
        source_connection_id="db:analytics:patients",
        source_profiles=["enforcement-mode-example"],
        permissions=PolicyPermissions(can_query=True, read_only=True),
        object_rules=ObjectRules(
            allowed_objects=["patients"],
            row_filters=[
                # Pushable: becomes WHERE "region" = 'us-east'.
                RowFilter(field="region", operator=FilterOperator.equals, value="us-east"),
                # NOT pushable: no portable SQL form, so the post pass enforces it.
                RowFilter(field="name", operator=FilterOperator.starts_with, value="A"),
            ],
            field_rules=FieldRules(
                hidden_fields=["ssn"],
                masked_fields=[MaskingRule(field="dob", mask_type=MaskType.redact)],
            ),
        ),
        limits=PolicyLimits(max_results=2),
    )


def fake_database(query: str) -> list[dict[str, Any]]:
    """Stand in for an engine: honour a pushed WHERE and LIMIT, ignore the rest.

    Crude, and that is the point -- it responds differently to the two modes, so the
    equality of the final output below is a real result rather than a coincidence.
    """
    import re

    rows = list(FAKE_ROWS)
    match = re.search(r'"(\w+)" = \'([^\']*)\'', query)
    if match:
        rows = [r for r in rows if str(r.get(match.group(1))) == match.group(2)]
    limit = re.search(r"LIMIT (\d+)", query, re.IGNORECASE)
    if limit:
        rows = rows[: int(limit.group(1))]
    return rows


def run(context: SecurityContext, wrapper: SecureMcpToolWrapper, mode: SqlEnforcementMode):
    """Prepare in `mode`, execute, enforce. Returns (sql_sent, rows_from_db, final_rows)."""
    prep = prepare_sql_query(
        QUERY, context.effective_policy, dialect=SqlDialect.postgres, mode=mode
    )
    if not prep.allowed:
        raise PermissionError(prep.denial_reason)

    from_db = fake_database(prep.query)
    # Mandatory in BOTH modes. This is the enforcement boundary.
    final = wrapper.post_execute(context, from_db)
    return prep, from_db, final


def main() -> None:
    context = sign_context(
        build_security_context("user-123", "tenant-acme", [policy()]), SIGNING_KEY
    )
    wrapper = SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=SIGNING_KEY))

    print("The query the agent asked for:")
    print(f"  {QUERY}")
    print(f"\nThe database holds {len(FAKE_ROWS)} rows and 5 columns.\n")

    results = {}
    for mode in (SqlEnforcementMode.rewrite_and_post, SqlEnforcementMode.post_only):
        prep, from_db, final = run(context, wrapper, mode)
        results[mode] = final

        print(f"--- mode: {mode.value} " + "-" * (52 - len(mode.value)))
        print(f"  SQL sent to the database:")
        print(f"    {prep.query}")
        print(f"  query was edited: {prep.rewritten}")
        print(f"  rows the database returned: {len(from_db)}")
        print(f"  filters the database did NOT apply: "
              f"{[f.field for f in prep.unpushable_filters]}")
        print(f"  rows after enforcement: {len(final)}")
        for row in final:
            print(f"    {row}")
        print()

    rewritten = results[SqlEnforcementMode.rewrite_and_post]
    post_only = results[SqlEnforcementMode.post_only]

    print("=" * 70)
    if rewritten == post_only:
        print("Both modes returned the SAME rows, as they must.")
        print("The mode changed how much data the database produced -- "
              f"{len(fake_database(prepare_sql_query(QUERY, context.effective_policy, dialect=SqlDialect.postgres).query))}"
              f" rows versus {len(FAKE_ROWS)} -- and nothing about what the caller may see.")
    else:  # pragma: no cover - a failure here is a defect, not an example outcome
        raise SystemExit(
            "MODES DISAGREED. Rewriting is a resource optimization and must never change "
            f"the result.\n  rewrite_and_post: {rewritten}\n  post_only: {post_only}"
        )

    print()
    print("Note what enforcement did that no SQL could have:")
    print("  * `ssn` is absent, though the database returned it")
    print("  * `dob` reads [REDACTED] -- there is no SELECT that produces that")
    print("  * the `name startsWith A` filter was applied after the fetch, because it has")
    print("    no portable SQL form -- which is why the post pass is never optional")


if __name__ == "__main__":
    main()
