"""Cross-SDK field-rule scenarios. Loaded from fixtures/integration-scenarios/postgres-field-rules.json."""

from __future__ import annotations

import hashlib

import pytest

from tolap_mcp.options import SecureMcpServerOptions
from tolap_mcp.wrapper import SecureMcpToolWrapper

from ._scenarios import load_scenarios, policy_from_dict, safe_identifier, sign_policy


SCENARIOS = load_scenarios("postgres-field-rules.json")["scenarios"]


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
def test_field_rule_scenario(scenario, wrapper, signing_key, db_conn) -> None:
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
    if fields is not None:
        exec_args["fields"] = fields

    if not expected["pass"]:
        with pytest.raises(PermissionError, match=expected["errorContains"]):
            wrapper.execute_with_enforcement(**exec_args)
        return

    rows = wrapper.execute_with_enforcement(**exec_args)
    _assert_pass(rows, expected, db_conn, query["table"])


def _assert_pass(rows, expected, db_conn, table) -> None:
    if "rowCount" in expected:
        assert len(rows) == expected["rowCount"]

    if "maskedField" in expected:
        spec = expected["maskedField"]
        ids = [r["id"] for r in rows]
        with db_conn.cursor() as cur:
            cur.execute(
                f"SELECT id, {safe_identifier(spec['field'])} AS val FROM {safe_identifier(table)} WHERE id = ANY(%s) ORDER BY id",  # noqa: S608  # nosec B608 -- identifiers allow-list validated
                (ids,),
            )
            originals = {r["id"]: r["val"] for r in cur.fetchall()}
        for row in rows:
            _assert_mask(row[spec["field"]], originals[row["id"]], spec["mask"])

    if "everyRowField" in expected:
        for row in rows:
            for spec in expected["everyRowField"]:
                assert row[spec["field"]] == spec["equals"], (
                    f"row {row['id']} field {spec['field']} expected {spec['equals']!r}, got {row[spec['field']]!r}"
                )


def _assert_mask(actual, original, mask: str) -> None:
    if mask == "full-stars":
        assert isinstance(actual, str)
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
        # The shared fixture still labels this case "unchanged" and its comment
        # still claims the original is returned when showFirst+showLast >=
        # len(value). Per the canonical spec that is a disclosure bug: a partial
        # mask that would reveal everything degrades to a full mask. Asserted
        # against the spec here; the fixture label is corrected separately.
        assert actual == "*" * len(str(original))
    elif mask == "partial-first-1-hash":
        s = str(original)
        assert actual[0] == s[0]
        assert actual[1:] == "#" * (len(s) - 1)
    elif mask == "sha256-16":
        expected = hashlib.sha256(str(original).encode()).hexdigest()[:16]
        assert actual == expected
    else:
        raise AssertionError(f"unknown mask kind {mask!r}")
