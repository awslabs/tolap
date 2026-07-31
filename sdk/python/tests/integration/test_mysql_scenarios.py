"""Cross-SDK scenarios executed against MySQL.

Same shared JSON the Postgres tests use. Confirms TOLAP enforcement is
identical regardless of the underlying database engine.
"""

from __future__ import annotations

import hashlib

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


HEALTHCARE_DOC = load_scenarios("postgres-healthcare-analyst.json")
HEALTHCARE_BASE = HEALTHCARE_DOC["basePolicy"]
HEALTHCARE_SCENARIOS = HEALTHCARE_DOC["scenarios"]

ROW_FILTER_SCENARIOS = load_scenarios("postgres-row-filters.json")["scenarios"]
FIELD_RULE_SCENARIOS = load_scenarios("postgres-field-rules.json")["scenarios"]
PERMISSION_SCENARIOS = load_scenarios("permissions-and-limits.json")["scenarios"]


# MySQL reserved words that need backticks. `status` is a column we use heavily.
_RESERVED_COLUMNS = {"status"}


def _quote_column(c: str) -> str:
    # Allow-list validate the identifier before it can reach any SQL string.
    safe_identifier(c)
    return f"`{c}`" if c in _RESERVED_COLUMNS else c


def _run_query(conn, table: str, columns: list[str]) -> list[dict]:
    cols = ", ".join(_quote_column(c) for c in columns)
    sql = f"SELECT {cols} FROM {safe_identifier(table)} ORDER BY id"  # noqa: S608  # nosec B608 -- identifiers allow-list validated
    with conn.cursor() as cur:
        cur.execute(sql)
        rows = list(cur.fetchall())
    # PyMySQL DictCursor returns int(11) values as Python int, BIGINT as Python int — both fine.
    return rows


@pytest.fixture
def wrapper(signing_key: str) -> SecureMcpToolWrapper:
    return SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=signing_key))


# ---------- healthcare-analyst (the README policy) on MySQL ----------


@pytest.mark.parametrize("scenario", HEALTHCARE_SCENARIOS, ids=lambda s: s["name"])
def test_healthcare_analyst_on_mysql(scenario, wrapper, signing_key, mysql_conn) -> None:
    policy_dict = merge_policy(HEALTHCARE_BASE, scenario.get("policyOverride"))
    ctx = sign_policy(policy_from_dict(policy_dict), signing_key)
    query = scenario["query"]
    expected = scenario["expected"]
    fields = [f"{query['table']}.{c}" for c in query["columns"]]

    if not expected["pass"]:
        with pytest.raises(PermissionError, match=expected["errorContains"]):
            wrapper.execute_with_enforcement(
                context=ctx,
                tool_name="mysql-query",
                tool_fn=_run_query,
                tool_args={"conn": mysql_conn, "table": query["table"], "columns": query["columns"]},
                object_name=query["table"],
                fields=fields,
            )
        return

    rows = wrapper.execute_with_enforcement(
        context=ctx,
        tool_name="mysql-query",
        tool_fn=_run_query,
        tool_args={"conn": mysql_conn, "table": query["table"], "columns": query["columns"]},
        object_name=query["table"],
        fields=fields,
    )
    _assert_pass(rows, expected, mysql_conn, query["table"])


def _assert_pass(rows, expected, conn, table) -> None:
    if "rowCount" in expected:
        assert len(rows) == expected["rowCount"]
    if "idsEqual" in expected:
        actual = sorted(int(r["id"]) for r in rows)
        assert actual == sorted(expected["idsEqual"])
    if "regions" in expected:
        actual = sorted(r["region"] for r in rows)
        assert actual == sorted(expected["regions"])
    if "maskedField" in expected:
        spec = expected["maskedField"]
        ids = [int(r["id"]) for r in rows]
        if not ids:
            return
        placeholders = ", ".join(["%s"] * len(ids))
        sql = f"SELECT id, {_quote_column(spec['field'])} AS val FROM {safe_identifier(table)} WHERE id IN ({placeholders}) ORDER BY id"  # noqa: S608  # nosec B608 -- identifiers allow-list validated
        with conn.cursor() as cur:
            cur.execute(sql, ids)
            originals = {int(r["id"]): r["val"] for r in cur.fetchall()}
        for row in rows:
            _assert_mask(row[spec["field"]], originals[int(row["id"])], spec["mask"])


def _assert_mask(actual, original, mask: str) -> None:
    if mask == "sha256-16":
        assert actual == hashlib.sha256(str(original).encode()).hexdigest()[:16]
    elif mask == "redacted":
        assert actual == "[REDACTED]"
    elif mask == "partial-first-1":
        s = str(original)
        assert actual[0] == s[0]
        assert actual[1:] == "*" * (len(s) - 1)
    else:
        raise AssertionError(f"unknown mask kind {mask}")


# ---------- row filters on MySQL ----------


@pytest.mark.parametrize("scenario", ROW_FILTER_SCENARIOS, ids=lambda s: s["name"])
def test_row_filter_on_mysql(scenario, wrapper, signing_key, mysql_conn) -> None:
    policy = policy_from_dict(scenario["policy"])
    ctx = sign_policy(policy, signing_key)
    query = scenario["query"]
    expected = scenario["expected"]

    args = {
        "context": ctx,
        "tool_name": "mysql-query",
        "tool_fn": _run_query,
        "tool_args": {"conn": mysql_conn, "table": query["table"], "columns": query["columns"]},
        "object_name": query["table"],
    }

    if not expected["pass"]:
        with pytest.raises(PermissionError, match=expected["errorContains"]):
            wrapper.execute_with_enforcement(**args)
        return

    rows = wrapper.execute_with_enforcement(**args)
    if "rowCount" in expected:
        assert len(rows) == expected["rowCount"]
    if "regions" in expected:
        actual = sorted(r["region"] for r in rows)
        assert actual == sorted(expected["regions"])
    if "idsEqual" in expected:
        actual = sorted(int(r["id"]) for r in rows)
        assert actual == sorted(expected["idsEqual"])


# ---------- field rules on MySQL ----------


@pytest.mark.parametrize("scenario", FIELD_RULE_SCENARIOS, ids=lambda s: s["name"])
def test_field_rule_on_mysql(scenario, wrapper, signing_key, mysql_conn) -> None:
    policy = policy_from_dict(scenario["policy"])
    ctx = sign_policy(policy, signing_key)
    query = scenario["query"]
    fields = scenario.get("fields")
    expected = scenario["expected"]

    exec_args = {
        "context": ctx,
        "tool_name": "mysql-query",
        "tool_fn": _run_query,
        "tool_args": {"conn": mysql_conn, "table": query["table"], "columns": query["columns"]},
        "object_name": query["table"],
    }
    if fields:
        exec_args["fields"] = fields

    if not expected["pass"]:
        with pytest.raises(PermissionError, match=expected["errorContains"]):
            wrapper.execute_with_enforcement(**exec_args)
        return

    rows = wrapper.execute_with_enforcement(**exec_args)
    _assert_field_rule_pass(rows, expected, mysql_conn, query["table"])


def _assert_field_rule_pass(rows, expected, conn, table) -> None:
    if "rowCount" in expected:
        assert len(rows) == expected["rowCount"]
    if "maskedField" in expected:
        spec = expected["maskedField"]
        ids = [int(r["id"]) for r in rows]
        if not ids:
            return
        placeholders = ", ".join(["%s"] * len(ids))
        sql = f"SELECT id, {_quote_column(spec['field'])} AS val FROM {safe_identifier(table)} WHERE id IN ({placeholders}) ORDER BY id"  # noqa: S608  # nosec B608 -- identifiers allow-list validated
        with conn.cursor() as cur:
            cur.execute(sql, ids)
            originals = {int(r["id"]): r["val"] for r in cur.fetchall()}
        for row in rows:
            _assert_field_mask(row[spec["field"]], originals[int(row["id"])], spec["mask"])
    if "everyRowField" in expected:
        for row in rows:
            for spec in expected["everyRowField"]:
                assert row[spec["field"]] == spec["equals"], (
                    f"row {row['id']} field {spec['field']}: expected {spec['equals']!r}, got {row[spec['field']]!r}"
                )


def _assert_field_mask(actual, original, mask: str) -> None:
    if mask == "full-stars":
        assert actual == "*" * len(str(original))
    elif mask == "is-null":
        assert actual is None
    elif mask == "redacted":
        assert actual == "[REDACTED]"
    elif mask == "partial-last-4":
        s = str(original)
        assert actual.endswith(s[-4:])
        assert actual[:-4] == "*" * (len(s) - 4)
    elif mask == "partial-first-2-last-2":
        s = str(original)
        assert actual[:2] == s[:2]
        assert actual[-2:] == s[-2:]
        assert actual[2:-2] == "*" * (len(s) - 4)
    elif mask == "unchanged":
        # See the note in test_postgres_field_rules._assert_mask: a partial mask
        # that would show the whole value degrades to a full mask rather than
        # returning the original, which the fixture's label predates.
        assert str(actual) == "*" * len(str(original))
    elif mask == "partial-first-1-hash":
        s = str(original)
        assert actual[0] == s[0]
        assert actual[1:] == "#" * (len(s) - 1)
    elif mask == "sha256-16":
        assert actual == hashlib.sha256(str(original).encode()).hexdigest()[:16]
    else:
        raise AssertionError(f"unknown mask kind {mask}")


# ---------- permission/limit on MySQL ----------


@pytest.mark.parametrize("scenario", PERMISSION_SCENARIOS, ids=lambda s: s["name"])
def test_permission_on_mysql(scenario, wrapper, signing_key, mysql_conn) -> None:
    policy = policy_from_dict(scenario["policy"])
    ctx = sign_policy(policy, signing_key)
    query = scenario["query"]
    fields = scenario.get("fields")
    expected = scenario["expected"]

    exec_args = {
        "context": ctx,
        "tool_name": "mysql-query",
        "tool_fn": _run_query,
        "tool_args": {"conn": mysql_conn, "table": query["table"], "columns": query["columns"]},
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
