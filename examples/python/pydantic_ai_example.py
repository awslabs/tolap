"""TOLAP enforcement inside a Pydantic AI tool.

Tools are registered on the ``Agent`` with ``@agent.tool_plain`` (no run context needed) or
``@agent.tool``. Either way TOLAP goes inside the function body, so Pydantic AI's schema
generation and validation are untouched.

    python pydantic_ai_example.py

Verified against pydantic-ai-slim 2.21.x. No model call is made: the registered function is
invoked directly, which is the code path the agent takes once the model chooses the tool.
"""

from __future__ import annotations

from pydantic_ai import Agent

from tolap_setup import enforced_query

# `model=None` keeps this example offline. A real agent names a model here; nothing about the
# enforcement below changes.
agent = Agent(model=None)


@agent.tool_plain
def query_patients(table: str) -> list[dict]:
    """Query a patient table. Returns only what the caller's policy permits."""
    return enforced_query(table)


def main() -> None:
    rows = query_patients("patients")
    print(f"permitted table -> {len(rows)} row(s)")
    for row in rows:
        print("   ", row)

    # Pydantic AI turns an exception into a tool-error the model can see and react to, rather
    # than silently returning nothing -- which would leave the agent unable to tell "no rows"
    # from "not permitted".
    try:
        query_patients("encounters")
        raise AssertionError("expected the denied table to raise")
    except PermissionError as exc:
        print(f"denied table    -> PermissionError: {str(exc)[:70]}")


if __name__ == "__main__":
    main()
