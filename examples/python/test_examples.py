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


class TestEnforcementModeExample:
    """The enforcement-mode example, executed rather than trusted.

    An example nothing runs will drift; one that mis-wires enforcement teaches people to
    bypass it. This runs the script's own functions and asserts the property the script
    claims -- that the two modes agree -- so a regression in either path fails here rather
    than in a reader's terminal.
    """

    def test_both_modes_return_identical_rows(self) -> None:
        from enforcement_mode_example import (
            SqlEnforcementMode,
            SecureMcpServerOptions,
            SecureMcpToolWrapper,
            SIGNING_KEY,
            build_security_context,
            policy,
            run,
            sign_context,
        )

        context = sign_context(
            build_security_context("user-123", "tenant-acme", [policy()]), SIGNING_KEY
        )
        wrapper = SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=SIGNING_KEY))

        rewritten_prep, rewritten_db, rewritten = run(
            context, wrapper, SqlEnforcementMode.rewrite_and_post
        )
        post_prep, post_db, post_only = run(context, wrapper, SqlEnforcementMode.post_only)

        assert rewritten == post_only, "the example's central claim no longer holds"

        # And the modes really did ask the database for different things -- otherwise the
        # equality above would hold trivially.
        assert rewritten_prep.rewritten is True
        assert post_prep.rewritten is False
        assert len(rewritten_db) < len(post_db)

    def test_the_example_script_runs_clean(self) -> None:
        """The script itself exits zero and prints the agreement line.

        It raises SystemExit if the modes disagree, so this also covers that path.
        """
        import pathlib
        import subprocess
        import sys

        script = pathlib.Path(__file__).parent / "enforcement_mode_example.py"
        result = subprocess.run(
            [sys.executable, str(script)], capture_output=True, text=True, timeout=60
        )

        assert result.returncode == 0, result.stderr
        assert "Both modes returned the SAME rows" in result.stdout
        assert "[REDACTED]" in result.stdout
        assert "ssn" not in result.stdout.split("Note what enforcement did")[0]
