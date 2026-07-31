"""Asserts every framework example actually enforces, not merely that it runs.

An example that prints plausible-looking rows is worse than no example: it teaches a wiring
pattern nobody has checked. So each framework is driven through **its own** invocation path and
the result is compared against the four controls the shared policy sets.

The parametrised design is the point. A per-framework test would pass if one integration quietly
returned the raw rows, because nothing would compare it to the others. Here every framework must
produce the *same* enforced output, so a broken integration stands out against six correct ones.

Run: pytest examples/python/test_examples.py
Skips cleanly when a framework is not installed -- see examples/python/requirements.txt.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Callable

import pytest

from tolap_setup import FAKE_ROWS

#: What the policy must produce from FAKE_ROWS, whatever the framework:
#: region filter drops eu-west (4 -> 3), maxResults caps at 2, ssn is hidden, dob is redacted.
EXPECTED = [
    {"id": 1, "name": "Alice Nguyen", "region": "us-east", "dob": "[REDACTED]"},
    {"id": 2, "name": "Bruno Sato", "region": "us-east", "dob": "[REDACTED]"},
]


def _langchain() -> tuple[Callable[[str], Any], type[BaseException]]:
    pytest.importorskip("langchain_core")
    import langchain_example

    return (lambda t: langchain_example.query_patients.invoke({"table": t}), Exception)


def _strands() -> tuple[Callable[[str], Any], type[BaseException]]:
    pytest.importorskip("strands")
    import strands_example

    tool = strands_example.query_patients
    fn = getattr(tool, "_tool_func", None) or getattr(tool, "__wrapped__", tool)
    return (lambda t: fn(table=t), PermissionError)


def _openai_agents() -> tuple[Callable[[str], Any], type[BaseException]]:
    pytest.importorskip("agents")
    import openai_agents_example

    return (openai_agents_example._query_patients, PermissionError)


def _pydantic_ai() -> tuple[Callable[[str], Any], type[BaseException]]:
    pytest.importorskip("pydantic_ai")
    import pydantic_ai_example

    return (pydantic_ai_example.query_patients, PermissionError)


def _semantic_kernel() -> tuple[Callable[[str], Any], type[BaseException]]:
    pytest.importorskip("semantic_kernel")
    import semantic_kernel_example

    plugin = semantic_kernel_example.PatientsPlugin()
    return (lambda t: plugin.query_patients(table=t), PermissionError)


def _mcp_server() -> tuple[Callable[[str], Any], type[BaseException]]:
    pytest.importorskip("mcp")
    import mcp_server_example

    def call(table: str) -> Any:
        # Through the server's own call_tool, so the MCP SDK's marshalling is in the path.
        result = asyncio.run(mcp_server_example.mcp.call_tool("query_patients", {"table": table}))
        return result[1]["result"] if isinstance(result, tuple) else result

    return (call, Exception)


def _bedrock() -> tuple[Callable[[str], Any], type[BaseException]]:
    import bedrock_agent_example as bedrock
    from tolap_core.context import serialize_context

    from tolap_setup import signed_context

    serialized = serialize_context(signed_context())

    def call(table: str) -> Any:
        response = bedrock.lambda_handler(bedrock._event(table, serialized))
        body = bedrock._body(response)
        if response["response"]["httpStatusCode"] != 200:
            # Bedrock returns a status, not an exception, so the test raises to keep the
            # denial assertion uniform across frameworks.
            raise PermissionError(body["error"])
        return body["rows"]

    return (call, PermissionError)


FRAMEWORKS = {
    "mcp-server": _mcp_server,
    "strands": _strands,
    "langchain": _langchain,
    "openai-agents": _openai_agents,
    "pydantic-ai": _pydantic_ai,
    "semantic-kernel": _semantic_kernel,
    "bedrock-agents": _bedrock,
}


@pytest.mark.parametrize("name", sorted(FRAMEWORKS))
class TestEveryFrameworkEnforcesIdentically:
    """One policy, seven integrations, one expected outcome."""

    def test_permitted_table_returns_the_enforced_rows(self, name: str) -> None:
        call, _ = FRAMEWORKS[name]()
        rows = call("patients")

        assert rows == EXPECTED, f"{name} did not produce the enforced result"

    def test_the_fake_source_really_returns_more(self, name: str) -> None:
        """Paired control: without this, the assertion above could pass on an empty source."""
        assert len(FAKE_ROWS) > len(EXPECTED)
        assert any("ssn" in row for row in FAKE_ROWS)

    def test_hidden_field_never_reaches_the_caller(self, name: str) -> None:
        call, _ = FRAMEWORKS[name]()
        rows = call("patients")

        assert all("ssn" not in row for row in rows), f"{name} leaked a hidden field"

    def test_masked_field_is_redacted(self, name: str) -> None:
        call, _ = FRAMEWORKS[name]()
        rows = call("patients")

        originals = {row["dob"] for row in FAKE_ROWS}
        assert all(row["dob"] not in originals for row in rows), f"{name} returned an unmasked dob"

    def test_row_filter_and_limit_applied(self, name: str) -> None:
        call, _ = FRAMEWORKS[name]()
        rows = call("patients")

        assert all(row["region"] == "us-east" for row in rows), f"{name} returned a filtered region"
        assert len(rows) == 2, f"{name} ignored maxResults"

    def test_denied_table_raises_rather_than_returning_data(self, name: str) -> None:
        """A denial must be distinguishable from an empty result.

        An agent that cannot tell "no rows matched" from "you may not read this" will retry
        forever, and an audit trail that conflates them cannot answer what was refused.
        """
        call, error = FRAMEWORKS[name]()

        with pytest.raises(error):
            call("encounters")
