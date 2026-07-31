"""Cross-SDK healthcare-analyst scenarios, executed by the Python SDK.

Cases are loaded from fixtures/integration-scenarios/postgres-healthcare-analyst.json.
"""

from __future__ import annotations

import hashlib

import psycopg
import pytest

from tolap_mcp.options import SecureMcpServerOptions
from tolap_mcp.wrapper import SecureMcpToolWrapper

from ._scenarios import (
    load_scenarios,
    merge_policy,
    policy_from_dict,
    safe_identifier,
    sign_policy,
)


_DOC = load_scenarios("postgres-healthcare-analyst.json")
BASE_POLICY = _DOC["basePolicy"]
SCENARIOS = _DOC["scenarios"]


@pytest.fixture
def wrapper(signing_key: str) -> SecureMcpToolWrapper:
    return SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=signing_key))


def _run_query(conn, table: str, columns: list[str]) -> list[dict]:
    col_sql = ", ".join(safe_identifier(c) for c in columns)
    sql = f"SELECT {col_sql} FROM {safe_identifier(table)} ORDER BY id"  # noqa: S608  # nosec B608 -- identifiers allow-list validated
    with conn.cursor() as cur:
        cur.execute(sql)
        return list(cur.fetchall())


def _qualified_fields(table: str, columns: list[str]) -> list[str]:
    return [f"{table}.{c}" for c in columns]


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s["name"])
def test_healthcare_analyst_scenario(scenario, wrapper, signing_key, db_conn) -> None:
    policy_dict = merge_policy(BASE_POLICY, scenario.get("policyOverride"))
    ctx = sign_policy(policy_from_dict(policy_dict), signing_key)

    query = scenario["query"]
    expected = scenario["expected"]

    fields = _qualified_fields(query["table"], query["columns"])

    if not expected["pass"]:
        with pytest.raises(PermissionError, match=expected["errorContains"]):
            wrapper.execute_with_enforcement(
                context=ctx,
                tool_name="pg-query",
                tool_fn=_run_query,
                tool_args={"conn": db_conn, "table": query["table"], "columns": query["columns"]},
                object_name=query["table"],
                fields=fields,
            )
        return

    rows = wrapper.execute_with_enforcement(
        context=ctx,
        tool_name="pg-query",
        tool_fn=_run_query,
        tool_args={"conn": db_conn, "table": query["table"], "columns": query["columns"]},
        object_name=query["table"],
        fields=fields,
    )
    _assert_pass(rows, expected, db_conn, query["table"])


def _assert_pass(rows: list[dict], expected: dict, db_conn, table: str) -> None:
    if "rowCount" in expected:
        assert len(rows) == expected["rowCount"], (
            f"expected {expected['rowCount']} rows, got {len(rows)}"
        )
    if "idsEqual" in expected:
        actual = sorted(r["id"] for r in rows)
        assert actual == sorted(expected["idsEqual"]), (
            f"expected ids={expected['idsEqual']}, got {actual}"
        )
    if "regions" in expected:
        actual = sorted(r["region"] for r in rows)
        assert actual == sorted(expected["regions"])
    if "maskedField" in expected:
        spec = expected["maskedField"]
        # Look up originals from the DB by id so we can verify each masked value.
        ids = [r["id"] for r in rows]
        with db_conn.cursor() as cur:
            cur.execute(
                f"SELECT id, {safe_identifier(spec['field'])} AS val FROM {safe_identifier(table)} WHERE id = ANY(%s) ORDER BY id",  # noqa: S608  # nosec B608 -- identifiers allow-list validated
                (ids,),
            )
            originals = {r["id"]: r["val"] for r in cur.fetchall()}
        for row in rows:
            actual = row[spec["field"]]
            original = originals[row["id"]]
            _assert_mask(actual, original, spec["mask"])


def _assert_mask(actual, original, mask: str) -> None:
    if mask == "sha256-16":
        assert actual == hashlib.sha256(str(original).encode()).hexdigest()[:16]
    elif mask == "redacted":
        assert actual == "[REDACTED]"
    elif mask == "partial-first-1":
        assert actual[0] == original[0]
        assert actual[1:] == "*" * (len(original) - 1)
    else:
        raise AssertionError(f"unknown mask kind: {mask}")
