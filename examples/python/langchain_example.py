"""TOLAP enforcement inside a LangChain tool.

The integration is one line: the ``@tool`` function calls :func:`enforced_query` instead of the
database directly. LangChain sees an ordinary tool; the model cannot reach the raw rows because
the only path to them runs through the policy.

    python langchain_example.py

Verified against langchain-core 1.5.x.
"""

from __future__ import annotations

from langchain_core.tools import tool

from tolap_setup import enforced_query


@tool
def query_patients(table: str) -> list[dict]:
    """Query a patient table. Returns only what the caller's policy permits."""
    # No enforcement logic here on purpose. Everything policy-related lives behind
    # enforced_query, so a second tool cannot accidentally implement it differently -- the
    # failure mode where one tool strips a hidden field and its neighbour forgets.
    return enforced_query(table)


def main() -> None:
    # `.invoke` is how LangChain calls a tool, so this is the real path the agent takes.
    rows = query_patients.invoke({"table": "patients"})
    print(f"permitted table -> {len(rows)} row(s)")
    for row in rows:
        print("   ", row)

    # A denial surfaces as an exception, which LangChain reports to the model as a tool error.
    # The agent learns the table is unavailable; it does not receive a filtered version of it.
    try:
        query_patients.invoke({"table": "encounters"})
        raise AssertionError("expected the denied table to raise")
    except Exception as exc:  # LangChain wraps the PermissionError
        print(f"denied table    -> {type(exc).__name__}: {str(exc)[:70]}")


if __name__ == "__main__":
    main()
