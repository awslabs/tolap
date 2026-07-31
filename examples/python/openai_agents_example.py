"""TOLAP enforcement inside an OpenAI Agents SDK function tool.

``@function_tool`` builds a JSON schema from the signature and calls the function when the model
invokes it. TOLAP sits inside the function, so the schema the model sees is unchanged and the
rows it receives are already enforced.

    python openai_agents_example.py

Verified against openai-agents 0.19.x. No API key or network call is needed: the example invokes
the tool directly, which is the same code path the runtime takes.
"""

from __future__ import annotations

from agents import function_tool

from tolap_setup import enforced_query


def _query_patients(table: str) -> list[dict]:
    """Query a patient table. Returns only what the caller's policy permits."""
    return enforced_query(table)


#: The registered tool. `@function_tool` derives the JSON schema the model sees from the
#: signature and docstring of the function above; TOLAP lives inside that function, so the
#: schema is unchanged and the rows the model receives are already enforced.
query_patients = function_tool(_query_patients)


def main() -> None:
    # The enforced function is exercised directly. Driving `on_invoke_tool` instead would need a
    # full RunContextWrapper carrying a run_config, because the SDK's own error handler reads it
    # when a tool raises -- so a policy denial would surface as an unrelated AttributeError and
    # obscure the thing this example exists to show.
    print(f"registered tool : {query_patients.name}")

    rows = _query_patients("patients")
    print(f"permitted table -> {len(rows)} row(s)")
    for row in rows:
        print("   ", row)

    try:
        _query_patients("encounters")
        raise AssertionError("expected the denied table to raise")
    except PermissionError as exc:
        print(f"denied table    -> PermissionError: {str(exc)[:70]}")


if __name__ == "__main__":
    main()
