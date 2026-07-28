"""Cross-SDK row-filter scenarios, executed by the Python SDK.

Cases are loaded from fixtures/integration-scenarios/postgres-row-filters.json
so TypeScript and .NET can run the identical matrix. The Python implementation
verifies that SecureMcpToolWrapper.post_execute applies the row filters from
each scenario's policy.
"""

from __future__ import annotations

import pytest

from tolap_mcp.options import SecureMcpServerOptions
from tolap_mcp.wrapper import SecureMcpToolWrapper

from ._scenarios import (
    load_scenarios,
    policy_from_dict,
    safe_identifier,
    sign_policy,
)


SCENARIOS = load_scenarios("postgres-row-filters.json")["scenarios"]


@pytest.fixture
def wrapper(signing_key: str) -> SecureMcpToolWrapper:
    return SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=signing_key))


def _run_query(conn, table: str, columns: list[str]) -> list[dict]:
    col_sql = ", ".join(safe_identifier(c) for c in columns)
    sql = f"SELECT {col_sql} FROM {safe_identifier(table)} ORDER BY id"  # noqa: S608  # nosec B608 -- identifiers allow-list validated
    with conn.cursor() as cur:
        cur.execute(sql)
        return list(cur.fetchall())


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s["name"])
def test_row_filter_scenario(scenario, wrapper, signing_key, db_conn) -> None:
    policy = policy_from_dict(scenario["policy"])
    ctx = sign_policy(policy, signing_key)

    query = scenario["query"]
    expected = scenario["expected"]

    if expected["pass"]:
        rows = wrapper.execute_with_enforcement(
            context=ctx,
            tool_name="pg-query",
            tool_fn=_run_query,
            tool_args={"conn": db_conn, "table": query["table"], "columns": query["columns"]},
            object_name=query["table"],
        )
        _assert_pass(rows, expected)
    else:
        with pytest.raises(PermissionError, match=expected["errorContains"]):
            wrapper.execute_with_enforcement(
                context=ctx,
                tool_name="pg-query",
                tool_fn=_run_query,
                tool_args={"conn": db_conn, "table": query["table"], "columns": query["columns"]},
                object_name=query["table"],
            )


def _assert_pass(rows: list[dict], expected: dict) -> None:
    if "rowCount" in expected:
        assert len(rows) == expected["rowCount"], (
            f"expected {expected['rowCount']} rows, got {len(rows)}: {rows}"
        )
    if "regions" in expected:
        # Multiset equality on the region values.
        actual = sorted(r["region"] for r in rows)
        assert actual == sorted(expected["regions"]), (
            f"expected regions={expected['regions']}, got {actual}"
        )
    if "idsEqual" in expected:
        actual = sorted(r["id"] for r in rows)
        assert actual == sorted(expected["idsEqual"]), (
            f"expected ids={expected['idsEqual']}, got {actual}"
        )
    if "idsIn" in expected:
        allowed = set(expected["idsIn"])
        for r in rows:
            assert r["id"] in allowed, f"id {r['id']} not in {allowed}"
