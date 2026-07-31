"""TOLAP enforcement inside a Strands Agents tool.

Strands' ``@tool`` decorator turns a plain function into an agent tool, so the integration is the
same one-line substitution as every other framework here: call :func:`enforced_query` rather than
the data source.

    python strands_example.py

Verified against strands-agents 1.50.x.
"""

from __future__ import annotations

from strands import tool

from tolap_setup import enforced_query


@tool
def query_patients(table: str) -> list[dict]:
    """Query a patient table. Returns only what the caller's policy permits."""
    return enforced_query(table)


def main() -> None:
    # Strands wraps the function but leaves the original callable reachable, so the example can
    # exercise the enforced path without standing up a model.
    fn = getattr(query_patients, "_tool_func", None) or getattr(query_patients, "__wrapped__", query_patients)

    rows = fn(table="patients")
    print(f"permitted table -> {len(rows)} row(s)")
    for row in rows:
        print("   ", row)

    try:
        fn(table="encounters")
        raise AssertionError("expected the denied table to raise")
    except PermissionError as exc:
        print(f"denied table    -> PermissionError: {str(exc)[:70]}")


if __name__ == "__main__":
    main()
