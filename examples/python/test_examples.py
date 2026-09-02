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


#: The lines the purpose-binding example must print, byte for byte.
#:
#: Written out in full rather than matched loosely, and repeated verbatim in the TypeScript and
#: .NET suites, for the same reason ``EXPECTED`` above is: the three SDKs must agree, so a
#: divergence has to surface as a *different line* rather than hiding behind three separately
#: written substring matches. Each one is an outcome -- which policy resolved, which action was
#: refused, the reason string -- not evidence that the script ran.
PURPOSE_EXPECTED_LINES = [
    # 15.1 -- resolution filtering. Deny-all without a purpose, the scoped policy with one.
    "  (no purpose)                      DENY      deny-all: 0 policies resolved, canQuery=false",
    "  'campaign-x-overlap'              ALLOW     campaign-x-overlap-agent (maxResults=10000)",
    "  'fraud-detection'                 ALLOW     fraud-detection-agent (maxResults=500)",
    "  'Campaign-X-Overlap'              DENY      deny-all: 0 policies resolved, canQuery=false",
    "  (no purpose)                      ALLOW     marketing-baseline (maxResults=2000)",
    # 15.3 -- the chain narrows, and the sharp mid-segment case.
    "  three narrowing hops              ALLOW",
    "  + a fourth, wider hop             DENY      delegation hop 3 purpose 'campaign-y-export'"
    " is not within parent scope 'campaign-x-overlap'",
    "  campaign-x -> campaign-x-overlap  ALLOW     extends on a '-' segment boundary",
    "  campaign-x -> campaign-xyz-evil   DENY      delegation hop 1 purpose 'campaign-xyz-evil'"
    " is not within parent scope 'campaign-x'",
    "  [read, aggregate] -> [read]       ALLOW     a subset of the parent",
    "  [read] -> [read, write]           DENY      delegation hop 1 scopes exceed parent delegation",
    # 15.2 -- the three action outcomes, plus the permitted one.
    "  segment_overlap                   ALLOW     category 'aggregate_overlap' is allowed",
    "  export_customers                  DENY      action 'export_pii' is prohibited under"
    " purpose 'campaign-x-overlap'",
    "  inspect_account                   DENY      action 'inspect_account' not in allowed"
    " actions for purpose 'campaign-x-overlap'",
    "  join_external                     DENY      action category not declared for tool",
    # 15.4 -- the disposition mapping.
    "  aligned, confidence 0.95          allow     the deterministic allowance stands",
    "  misaligned, confidence 0.95       block     the allowance is withdrawn",
    "  aligned, confidence 0.70          escalate  a DENIAL unless a review handler is wired",
    # The purpose and the chain are inside the signature.
    "  as signed                         VALID     purpose 'campaign-x-overlap', 3 hops",
    "  declared purpose swapped          BROKEN    to 'fraud-detection'",
    "  last hop repurposed               BROKEN    to 'campaign-y-export'",
    "  a fourth hop appended             BROKEN    agent-exfil, 'campaign-y-export'",
    "  hops reordered                    BROKEN    hop 0 is the delegator; reversing inverts it",
]


class TestPurposeBindingExample:
    """The purpose-binding example, executed rather than trusted.

    Every assertion here is an *outcome*: which policy resolved, which action was allowed or
    refused, the verbatim reason string. An example that printed plausible-looking verdicts
    while enforcing nothing would teach a wiring pattern nobody has checked.
    """

    def test_no_declared_purpose_resolves_deny_all(self) -> None:
        """The control with teeth. A purpose-scoped policy is not a default grant."""
        import purpose_binding_example as ex

        policy = ex.resolve_for([ex.campaign_definition(), ex.fraud_definition()], None)

        assert policy.source_profiles == []
        assert policy.permissions.can_query is False
        assert policy.purpose_profile is None

    def test_declared_purpose_resolves_only_the_matching_policy(self) -> None:
        import purpose_binding_example as ex

        policy = ex.resolve_for(
            [ex.campaign_definition(), ex.fraud_definition()], ex.CAMPAIGN_PURPOSE
        )

        # The other purpose's rules were never merged -- which is why the filter runs before the
        # merge rather than after it.
        assert policy.source_profiles == ["campaign-x-overlap-agent"]
        assert policy.purpose_profile is not None
        assert policy.purpose_profile.purpose_id == "campaign-x-overlap"
        assert policy.limits is not None and policy.limits.max_results == 10000
        assert "flagged_accounts" not in (policy.object_rules.allowed_objects or [])

    def test_the_purpose_comparison_is_case_sensitive(self) -> None:
        import purpose_binding_example as ex

        policy = ex.resolve_for(
            [ex.campaign_definition(), ex.fraud_definition()], "Campaign-X-Overlap"
        )

        assert policy.source_profiles == []
        assert policy.permissions.can_query is False

    def test_a_purpose_agnostic_policy_still_resolves_without_a_purpose(self) -> None:
        """Paired allow: purpose binding is additive, so pre-purpose policies are untouched."""
        import purpose_binding_example as ex

        policy = ex.resolve_for(
            [ex.campaign_definition(), ex.fraud_definition(), ex.baseline_definition()], None
        )

        assert policy.source_profiles == ["marketing-baseline"]
        assert policy.permissions.can_query is True
        assert policy.purpose_profile is None

    def test_a_narrowing_chain_is_allowed_and_a_widening_hop_is_not(self) -> None:
        import purpose_binding_example as ex
        from tolap_core import validate_delegation_chain

        chain = ex.narrowing_chain()
        assert validate_delegation_chain(chain).allowed is True

        widened = validate_delegation_chain(chain + [ex.widening_hop()])
        assert widened.allowed is False
        assert widened.reason == (
            "delegation hop 3 purpose 'campaign-y-export' is not within parent scope "
            "'campaign-x-overlap'"
        )

    def test_a_segment_boundary_narrows_but_a_mid_segment_prefix_does_not(self) -> None:
        """The case a plain ``startsWith`` gets wrong, which is why it is in the example."""
        import purpose_binding_example as ex
        from tolap_core import validate_delegation_chain

        assert validate_delegation_chain(
            ex.two_hop("campaign-x", "campaign-x-overlap")
        ).allowed is True

        evil = validate_delegation_chain(ex.two_hop("campaign-x", "campaign-xyz-evil"))
        assert evil.allowed is False
        assert evil.reason == (
            "delegation hop 1 purpose 'campaign-xyz-evil' is not within parent scope 'campaign-x'"
        )

    def test_scopes_may_narrow_but_not_widen(self) -> None:
        import purpose_binding_example as ex
        from tolap_core import validate_delegation_chain

        assert validate_delegation_chain(
            ex.scope_hops(["read", "aggregate"], ["read"])
        ).allowed is True

        widened = validate_delegation_chain(ex.scope_hops(["read"], ["read", "write"]))
        assert widened.allowed is False
        assert widened.reason == "delegation hop 1 scopes exceed parent delegation"

    @pytest.mark.parametrize(
        ("tool", "expected_reason"),
        [
            ("segment_overlap", None),
            (
                "export_customers",
                "action 'export_pii' is prohibited under purpose 'campaign-x-overlap'",
            ),
            (
                "inspect_account",
                "action 'inspect_account' not in allowed actions for purpose 'campaign-x-overlap'",
            ),
            ("join_external", "action category not declared for tool"),
        ],
    )
    def test_the_action_category_map_decides(self, tool: str, expected_reason: str | None) -> None:
        """A permitted category passes; a prohibited one, an unlisted one and an *unmapped* one
        each fail, with their own reason.

        The map is deployment configuration on the wrapper, never a caller argument -- so this
        goes through the wrapper's own pre-execute rather than calling the validator directly.
        """
        import purpose_binding_example as ex
        from tolap_mcp.options import SecureMcpServerOptions
        from tolap_mcp.wrapper import SecureMcpToolWrapper

        wrapper = SecureMcpToolWrapper(
            SecureMcpServerOptions(
                signing_key=ex.SIGNING_KEY,
                tool_action_categories=ex.TOOL_ACTION_CATEGORIES,
            )
        )

        result = wrapper.pre_execute(ex.signed_context(), tool)

        assert result.allowed is (expected_reason is None)
        assert result.reason == expected_reason

    @pytest.mark.parametrize(
        ("aligned", "confidence", "expected"),
        [(True, 0.95, "allow"), (False, 0.95, "block"), (True, 0.70, "escalate")],
    )
    def test_the_judge_verdict_maps_to_the_documented_disposition(
        self, aligned: bool, confidence: float, expected: str
    ) -> None:
        import purpose_binding_example as ex
        from tolap_core import JudgeResult, evaluate_judge

        outcome = evaluate_judge(
            ex.judged_policy(),
            ex.StubJudge(JudgeResult(aligned=aligned, confidence=confidence, reasoning="stub")),
            "segment_overlap(campaign_x)",
        )

        assert outcome.disposition.value == expected
        # escalate is NOT an allow. A wrapper with no review handler denies.
        assert outcome.allowed is (expected == "allow")

    def test_mutating_the_purpose_or_the_chain_breaks_the_signature(self) -> None:
        """Without this, the chain validation above would check the attacker's own arithmetic."""
        import purpose_binding_example as ex
        from tolap_core import validate_context

        original = ex.signed_context()
        assert validate_context(original, ex.SIGNING_KEY) is True
        assert original.declared_purpose == "campaign-x-overlap"
        assert original.delegation_chain is not None and len(original.delegation_chain) == 3

        repurposed = ex.signed_context()
        repurposed.declared_purpose = ex.FRAUD_PURPOSE
        assert validate_context(repurposed, ex.SIGNING_KEY) is False

        rechained = ex.signed_context()
        assert rechained.delegation_chain is not None
        rechained.delegation_chain[-1].declared_purpose = "campaign-y-export"
        assert validate_context(rechained, ex.SIGNING_KEY) is False

        appended = ex.signed_context()
        assert appended.delegation_chain is not None
        appended.delegation_chain.append(ex.widening_hop())
        assert validate_context(appended, ex.SIGNING_KEY) is False

        # Reordering included: hop 0 is the delegator, so reversing a chain makes the sub-agent
        # the root.
        reordered = ex.signed_context()
        assert reordered.delegation_chain is not None
        reordered.delegation_chain.reverse()
        assert validate_context(reordered, ex.SIGNING_KEY) is False

    def test_the_example_script_prints_every_expected_line(self) -> None:
        """Runs the script as CI does, and checks the printed outcomes line by line.

        The script raises ``SystemExit`` if a mutated context still verifies, so this covers that
        path too.
        """
        import pathlib
        import subprocess
        import sys

        script = pathlib.Path(__file__).parent / "purpose_binding_example.py"
        result = subprocess.run(
            [sys.executable, str(script)], capture_output=True, text=True, timeout=60
        )

        assert result.returncode == 0, result.stderr
        lines = result.stdout.splitlines()
        for expected in PURPOSE_EXPECTED_LINES:
            assert expected in lines, f"missing line: {expected!r}"
