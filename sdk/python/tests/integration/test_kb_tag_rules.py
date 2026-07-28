"""Cross-SDK knowledge-base tag-rule scenarios.

A KB-style tool returns a list of documents, each with a `tags: list[str]`.
The TOLAP wrapper's tag filtering must drop or keep docs according to the
policy. The corpus is shared across all three SDKs via the scenario JSON.
"""

from __future__ import annotations

import pytest

from tolap_mcp.options import SecureMcpServerOptions
from tolap_mcp.wrapper import SecureMcpToolWrapper

from ._scenarios import load_scenarios, policy_from_dict, sign_policy


_DOC = load_scenarios("knowledge-base-tag-rules.json")
CORPUS = _DOC["corpus"]
SCENARIOS = _DOC["scenarios"]


@pytest.fixture
def wrapper(signing_key: str) -> SecureMcpToolWrapper:
    return SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=signing_key))


def _kb_tool() -> list[dict]:
    """Return a deep copy so per-test mutations can't bleed across runs."""
    import copy
    return copy.deepcopy(CORPUS)


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s["name"])
def test_tag_rule_scenario(scenario, wrapper, signing_key) -> None:
    policy = policy_from_dict(scenario["policy"])
    ctx = sign_policy(policy, signing_key)
    expected = scenario["expected"]

    docs = wrapper.execute_with_enforcement(
        context=ctx,
        tool_name="kb-search",
        tool_fn=_kb_tool,
        tool_args={},
    )

    if "idsEqual" in expected:
        actual = sorted(d["id"] for d in docs)
        assert actual == sorted(expected["idsEqual"])
    if "idMustNotInclude" in expected:
        actual = {d["id"] for d in docs}
        for forbidden in expected["idMustNotInclude"]:
            assert forbidden not in actual, f"{forbidden} should have been filtered out"
