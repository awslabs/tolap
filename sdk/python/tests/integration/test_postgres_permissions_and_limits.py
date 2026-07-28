"""Cross-SDK permission/limit scenarios. Loaded from fixtures/integration-scenarios/permissions-and-limits.json."""

from __future__ import annotations

import pytest

from tolap_mcp.options import SecureMcpServerOptions
from tolap_mcp.wrapper import SecureMcpToolWrapper

from ._scenarios import load_scenarios, policy_from_dict, safe_identifier, sign_policy


SCENARIOS = load_scenarios("permissions-and-limits.json")["scenarios"]


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
def test_permission_scenario(scenario, wrapper, signing_key, db_conn) -> None:
    policy = policy_from_dict(scenario["policy"])
    ctx = sign_policy(policy, signing_key)

    query = scenario["query"]
    fields = scenario.get("fields")
    expected = scenario["expected"]

    exec_args = {
        "context": ctx,
        "tool_name": "pg-query",
        "tool_fn": _run_query,
        "tool_args": {"conn": db_conn, "table": query["table"], "columns": query["columns"]},
        "object_name": query["table"],
    }
    if fields:
        exec_args["fields"] = fields

    if not expected["pass"]:
        with pytest.raises(PermissionError, match=expected["errorContains"]):
            wrapper.execute_with_enforcement(**exec_args)
        return

    rows = wrapper.execute_with_enforcement(**exec_args)
    if "rowCount" in expected:
        assert len(rows) == expected["rowCount"]
