"""objectRules.toolRules: the pure check, the merge, and the model's null-versus-empty.

Driven from fixtures/enforcement/validate-tool-access.json and the
fixtures/merge-scenarios/tool-rules-*.json files so the three SDKs are held to one table.
Wrapper order and filtering are tested in test_tool_gate_wrapper.py.
"""

from __future__ import annotations

import json

import pytest
from conftest import load_all_fixtures, load_fixture

from tolap_core import ToolRules, validate_tool_access
from tolap_core.context import _canonical_payload, sign_context, validate_context
from tolap_core.enums import SigningAlgorithm
from tolap_core.merger import merge
from tolap_core.models import EffectivePolicy, SecurityContext
from tolap_core.serialization import (
    deserialize_effective_policy,
    deserialize_policy_definition,
    serialize,
)

FIXTURE = "enforcement/validate-tool-access.json"
CASES = load_fixture(FIXTURE)["cases"]


def _build_effective_policy(data: dict) -> EffectivePolicy:
    """Build an EffectivePolicy from a fixture's policy section, through the real deserializer."""
    return deserialize_effective_policy(data)


def _case_id(index: int) -> str:
    case = CASES[index]
    if case.get("name"):
        return f"{index}-{case['name']}"
    outcome = "allow" if case["expected"]["allowed"] else "deny"
    return f"{index}-{outcome}-{case['toolName']}"


def _merge_scenario(name: str) -> dict:
    return next(d for n, d in load_all_fixtures("merge-scenarios") if n == name)


def _merged(name: str) -> EffectivePolicy:
    data = _merge_scenario(name)
    return merge([deserialize_policy_definition(p) for p in data["inputs"]])


def _expected_tool_rules(data: dict) -> ToolRules | None:
    raw = (data["expected"].get("objectRules") or {}).get("toolRules")
    if raw is None:
        return None
    return ToolRules(allowed_tools=raw.get("allowedTools"), hidden_tools=raw.get("hiddenTools"))


def _policy_with_tool_rules(tool_rules: object) -> dict:
    return {"permissions": {"canQuery": True}, "objectRules": {"toolRules": tool_rules}}


class TestTheSharedFixture:
    """Matrix rows A1-A25, plus the original twelve cases."""

    def test_the_fixture_exercises_both_outcomes(self) -> None:
        outcomes = {c["expected"]["allowed"] for c in CASES}
        assert outcomes == {True, False}

    def test_every_grammar_row_is_present(self) -> None:
        # The parametrized test below is only as good as the rows it is given; a fixture that
        # lost a row would still pass. Pin the named A rows so dropping one fails here.
        names = [c.get("name") for c in CASES]
        assert sorted(n for n in names if n) == sorted(f"A{i}" for i in range(1, 26))
        assert sum(1 for n in names if not n) == 12

    def test_a24_and_a25_really_carry_their_non_ascii_letters(self) -> None:
        # If a JSON escape were ever normalised to plain ASCII, the row would still pass while
        # no longer testing the fold. A24 (U+212A KELVIN SIGN) catches str.lower() and
        # str.casefold(); A25 (U+017F LATIN SMALL LETTER LONG S) is the only row that catches
        # str.upper(), which folds it to "S".
        by_name = {c.get("name"): c for c in CASES}
        a24 = by_name["A24"]["policy"]["objectRules"]["toolRules"]["hiddenTools"][0]
        a25 = by_name["A25"]["policy"]["objectRules"]["toolRules"]["hiddenTools"][0]
        assert a24[0] == "\u212a" and a24.lower() == "kill_switch"
        assert a25[0] == "\u017f" and a25.casefold() == by_name["A25"]["toolName"]

    @pytest.mark.parametrize("index", range(len(CASES)), ids=_case_id)
    def test_validate_tool_access_matches_the_shared_fixture(self, index: int) -> None:
        case = CASES[index]
        policy = _build_effective_policy(case["policy"])
        result = validate_tool_access(case["toolName"], policy)
        assert result.allowed is case["expected"]["allowed"]
        assert result.reason == case["expected"].get("reason")


class TestNullVersusEmpty:
    def test_absent_allowed_tools_is_unrestricted_and_empty_denies(self) -> None:
        assert ToolRules().allowed_tools is None
        assert ToolRules(allowed_tools=[]).allowed_tools == []

    def test_deserialization_keeps_empty_distinct_from_absent(self) -> None:
        policy = _build_effective_policy(_policy_with_tool_rules({"allowedTools": []}))
        assert policy.object_rules is not None
        assert policy.object_rules.tool_rules is not None
        assert policy.object_rules.tool_rules.allowed_tools == []
        assert policy.object_rules.tool_rules.hidden_tools is None

    def test_absent_tool_rules_is_omitted_on_serialization(self) -> None:
        policy = _build_effective_policy(
            {"permissions": {"canQuery": True}, "objectRules": {"allowedObjects": ["patients"]}}
        )
        assert "toolRules" not in serialize(policy)

    def test_empty_lists_serialize_as_empty_lists(self) -> None:
        policy = _build_effective_policy(
            _policy_with_tool_rules({"allowedTools": [], "hiddenTools": []})
        )
        emitted = json.loads(serialize(policy))["objectRules"]["toolRules"]
        assert emitted == {"allowedTools": [], "hiddenTools": []}

    def test_reasons_do_not_echo_the_tool_name(self) -> None:
        hidden = _build_effective_policy(_policy_with_tool_rules({"hiddenTools": ["secret_tool"]}))
        result = validate_tool_access("secret_tool", hidden)
        assert result.reason == "tool is hidden"
        assert "secret_tool" not in (result.reason or "")

        allowed = _build_effective_policy(_policy_with_tool_rules({"allowedTools": ["other"]}))
        result = validate_tool_access("secret_tool", allowed)
        assert result.reason == "tool not in allowed set"
        assert "secret_tool" not in (result.reason or "")

    def test_can_query_is_not_consulted(self) -> None:
        # The wrapper checks canQuery after the tool gate; the pure check must not pre-empt it.
        policy = _build_effective_policy(
            {"permissions": {"canQuery": False}, "objectRules": {"toolRules": {}}}
        )
        assert validate_tool_access("query_patients", policy).allowed is True


class TestMalformedInput:
    """Matrix rows E1, E2, E4 and E8."""

    def test_e1_a_string_allowed_tools_raises(self) -> None:
        with pytest.raises(ValueError):
            deserialize_effective_policy(_policy_with_tool_rules({"allowedTools": "query_patients"}))

    def test_e1_a_string_is_never_iterated_into_characters(self) -> None:
        # The specific Python hazard: list("query_patients") is a list of one-letter tool
        # names, any of which would then be "allowed".
        try:
            policy = deserialize_effective_policy(
                _policy_with_tool_rules({"allowedTools": "query_patients"})
            )
        except ValueError:
            return
        rules = policy.object_rules.tool_rules if policy.object_rules else None
        assert rules is None or rules.allowed_tools != list("query_patients")
        pytest.fail("a string allowedTools must be rejected, not admitted")

    def test_e1_a_string_hidden_tools_raises(self) -> None:
        with pytest.raises(ValueError):
            deserialize_effective_policy(_policy_with_tool_rules({"hiddenTools": "admin_reset"}))

    def test_e2_a_non_string_entry_raises(self) -> None:
        with pytest.raises(ValueError):
            deserialize_effective_policy(_policy_with_tool_rules({"allowedTools": [1]}))
        with pytest.raises(ValueError):
            deserialize_effective_policy(_policy_with_tool_rules({"hiddenTools": [None]}))

    def test_e4_an_array_tool_rules_raises(self) -> None:
        with pytest.raises(ValueError):
            deserialize_effective_policy(_policy_with_tool_rules([]))

    def test_e4_a_scalar_tool_rules_raises(self) -> None:
        with pytest.raises(ValueError):
            deserialize_effective_policy(_policy_with_tool_rules("query_patients"))

    def test_e8_a_null_tool_rules_is_absent(self) -> None:
        policy = deserialize_effective_policy(_policy_with_tool_rules(None))
        assert policy.object_rules is not None
        assert policy.object_rules.tool_rules is None
        # Absent means no grammar either: A12's name passes.
        assert validate_tool_access("export_segment_csv ", policy).allowed is True
        assert "toolRules" not in serialize(policy)

    def test_malformed_input_is_rejected_by_the_policy_definition_path_too(self) -> None:
        definition = {"version": "1.0", "name": "p", "permissions": {"canQuery": True},
                      "objectRules": {"toolRules": {"allowedTools": "query_patients"}}}
        with pytest.raises(ValueError):
            deserialize_policy_definition(definition)


class TestMerge:
    """Matrix rows D1-D6, one per merge fixture."""

    def test_d1_tool_rules_intersect_and_union(self) -> None:
        data = _merge_scenario("tool-rules-intersect-and-union")
        result = _merged("tool-rules-intersect-and-union")
        rules = result.object_rules
        assert rules is not None and rules.tool_rules is not None
        # Disjoint allow-lists: present and empty (deny every tool), never collapsed to None.
        assert rules.tool_rules.allowed_tools is not None
        assert rules.tool_rules == ToolRules(allowed_tools=[], hidden_tools=["admin_reset"])
        assert rules.tool_rules == _expected_tool_rules(data)
        assert rules.allowed_objects == ["patients"]
        assert result.source_profiles == data["expected"]["sourceProfiles"]

    def test_d2_tool_rules_order_independent(self) -> None:
        data = _merge_scenario("tool-rules-order-independent")
        forward = _merged("tool-rules-intersect-and-union")
        reversed_ = _merged("tool-rules-order-independent")
        assert reversed_.object_rules is not None and forward.object_rules is not None
        assert reversed_.object_rules.tool_rules == forward.object_rules.tool_rules
        assert reversed_.object_rules.tool_rules == _expected_tool_rules(data)
        assert reversed_.source_profiles == data["expected"]["sourceProfiles"]

    def test_d3_tool_rules_absent_everywhere(self) -> None:
        data = _merge_scenario("tool-rules-absent-everywhere")
        result = _merged("tool-rules-absent-everywhere")
        assert result.object_rules is not None
        assert result.object_rules.tool_rules is None
        assert "toolRules" not in serialize(result)
        assert json.loads(serialize(result))["objectRules"] == data["expected"]["objectRules"]

    def test_d4_tool_rules_absent_and_empty(self) -> None:
        data = _merge_scenario("tool-rules-absent-and-empty")
        result = _merged("tool-rules-absent-and-empty")
        assert result.object_rules is not None and result.object_rules.tool_rules is not None
        assert result.object_rules.tool_rules.allowed_tools == []
        assert result.object_rules.tool_rules == ToolRules(allowed_tools=[], hidden_tools=["x"])
        assert result.object_rules.tool_rules == _expected_tool_rules(data)

    def test_d5_tool_rules_case_variants(self) -> None:
        data = _merge_scenario("tool-rules-case-variants")
        result = _merged("tool-rules-case-variants")
        assert result.object_rules is not None
        assert result.object_rules.tool_rules == ToolRules(allowed_tools=[], hidden_tools=["A", "a"])
        assert result.object_rules.tool_rules == _expected_tool_rules(data)

    def test_d6_tool_rules_three_way(self) -> None:
        data = _merge_scenario("tool-rules-three-way")
        result = _merged("tool-rules-three-way")
        assert result.object_rules is not None
        assert result.object_rules.tool_rules == ToolRules(allowed_tools=["c"], hidden_tools=None)
        assert result.object_rules.tool_rules == _expected_tool_rules(data)
        emitted = json.loads(serialize(result))["objectRules"]["toolRules"]
        assert emitted == {"allowedTools": ["c"]}

    def test_a_tools_only_policy_keeps_its_object_rules(self) -> None:
        # _has_object_rules must count toolRules, or a policy whose only object rule is a
        # tool gate would lose objectRules entirely in the merge.
        result = merge([
            deserialize_policy_definition({
                "version": "1.0", "name": "only-tools", "permissions": {"canQuery": True},
                "objectRules": {"toolRules": {"hiddenTools": ["admin_reset"]}},
            })
        ])
        assert result.object_rules is not None
        assert result.object_rules.tool_rules == ToolRules(hidden_tools=["admin_reset"])


class TestSigning:
    """Matrix row F5 (the tool-rules known answer) and F6 (the older fixtures unchanged)."""

    FIXTURE = "signing/hmac-sha256-tool-rules.json"

    @staticmethod
    def _context(data: dict) -> SecurityContext:
        policy = deserialize_effective_policy(data["payload"])
        return SecurityContext(
            effective_policy=policy,
            issued_at=policy.resolved_at,
            expires_at=policy.expires_at,
        )

    def test_f5_the_canonical_payload_matches_the_fixture_bytes(self) -> None:
        data = load_fixture(self.FIXTURE)
        assert _canonical_payload(self._context(data)) == data["canonicalPayload"]

    def test_f5_hmac_sha256_matches_the_known_answer(self) -> None:
        data = load_fixture(self.FIXTURE)
        signed = sign_context(self._context(data), data["secretKey"], SigningAlgorithm.hmac_sha256)
        assert signed.signature == data["expectedSignature"]

    def test_f5_hmac_sha512_matches_the_known_answer(self) -> None:
        data = load_fixture(self.FIXTURE)
        signed = sign_context(self._context(data), data["secretKey"], SigningAlgorithm.hmac_sha512)
        assert signed.signature == data["expectedSignatureSha512"]

    def test_f5_the_signed_context_verifies(self) -> None:
        data = load_fixture(self.FIXTURE)
        signed = sign_context(self._context(data), data["secretKey"])
        assert validate_context(signed, data["secretKey"]) is True

    def test_f5_the_empty_hidden_tools_is_signed(self) -> None:
        data = load_fixture(self.FIXTURE)
        assert '"hiddenTools":[]' in _canonical_payload(self._context(data))

    @pytest.mark.parametrize(
        "name", ["hmac-sha256-known-answer", "hmac-sha256-subsecond", "hmac-sha256-purpose-bound"]
    )
    def test_f6_the_older_fixtures_carry_no_tool_rules(self, name: str) -> None:
        data = load_fixture(f"signing/{name}.json")
        policy = deserialize_effective_policy(data["payload"])
        assert policy.object_rules is None or policy.object_rules.tool_rules is None
        assert "toolRules" not in _canonical_payload(self._context(data))

    @pytest.mark.parametrize("name", ["hmac-sha256-known-answer", "hmac-sha256-subsecond"])
    def test_f6_the_older_fixtures_still_sign_to_their_known_answers(self, name: str) -> None:
        data = load_fixture(f"signing/{name}.json")
        context = self._context(data)
        assert _canonical_payload(context) == data["canonicalPayload"]
        signed = sign_context(context, data["secretKey"], SigningAlgorithm.hmac_sha256)
        assert signed.signature == data["expectedSignature"]
