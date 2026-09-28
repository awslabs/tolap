"""objectRules.toolRules on the signed-context MCP wrapper.

Driven from fixtures/enforcement/tool-gate-wrapper.json so all three SDKs agree on order
and filtering. There is no option to set: the policy alone decides. The tamper, judge,
history, factory and concurrency cases are hand-written because they are about signing,
wiring and state, which a table can't say.
"""

from __future__ import annotations

import copy
import dataclasses
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from conftest import load_fixture

from tolap_core.context import build_security_context, sign_context
from tolap_core.history import ToolCallHistory
from tolap_core.judge import Judge, JudgeRequest, JudgeResult
from tolap_core.models import ObjectRules, SecurityContext, ToolRules
from tolap_mcp.options import SecureMcpServerOptions
from tolap_mcp.tool_call import render_tool_call
from tolap_mcp.wrapper import SecureMcpToolWrapper
from test_enforcement import _build_effective_policy

KEY = "tool-gate-key"
WRONG_KEY = "tolap-fixture-wrong-key-000000000000"
FIXTURE = load_fixture("enforcement/tool-gate-wrapper.json")
HIDDEN_EXPORT = {
    "permissions": {"canQuery": True},
    "objectRules": {"toolRules": {"hiddenTools": ["export_segment_csv"]}},
}
# Every reason a denial can give that depends on the tool name alone, and so is one
# filter_tools must agree with. can_query and the data-layer reasons are not in here.
TOOL_NAME_REASONS = {
    "tool not in allowed list",
    "invalid tool name",
    "tool is hidden",
    "tool not in allowed set",
}

JUDGE_MODEL = "tool-gate-judge-model"
JUDGE_TOOL_MAP = {"query_patients": "aggregate_overlap", "export_segment_csv": "aggregate_overlap"}
JUDGE_POLICY = {
    "permissions": {"canQuery": True},
    "objectRules": {"toolRules": {"hiddenTools": ["export_segment_csv"]}},
    "purposeProfile": {
        "purposeId": "campaign-x-overlap",
        "description": "Aggregate overlap only.",
        "allowedActions": ["aggregate_overlap"],
        "judge": {"enabled": True, "model": JUDGE_MODEL},
    },
}


class _CountingJudge(Judge):
    """Always aligned and confident, so any call that reaches it would be allowed."""

    def __init__(self) -> None:
        self.calls = 0

    @property
    def model_id(self) -> str:
        return JUDGE_MODEL

    def evaluate(self, request: JudgeRequest) -> JudgeResult:
        self.calls += 1
        return JudgeResult(aligned=True, confidence=1.0, reasoning="stub")


def _signed(
    fragment: dict,
    *,
    override: str | None = None,
) -> SecurityContext:
    policy = _build_effective_policy(fragment)
    ttl = timedelta(hours=-1) if override == "expired" else timedelta(hours=1)
    key = WRONG_KEY if override == "wrongKey" else KEY
    return sign_context(
        build_security_context(
            "tool-user",
            "tool-tenant",
            [policy],
            ttl=ttl,
            declared_purpose=(
                policy.purpose_profile.purpose_id if policy.purpose_profile else None
            ),
        ),
        key,
    )


def _wrapper(case: dict) -> SecureMcpToolWrapper:
    return SecureMcpToolWrapper(
        SecureMcpServerOptions(
            signing_key=KEY,
            allowed_tools=case["staticAllowedTools"],
            tool_action_categories=case.get("toolActionCategories"),
        )
    )


def _expected_reason(expected: dict) -> str | None:
    family = expected.get("reasonFamily")
    if family is not None:
        return FIXTURE["reasonFamilies"][family]["python"]
    return expected.get("reason")


def _case_context(case: dict) -> SecurityContext:
    return _signed(case["policy"], override=case.get("contextOverride"))


class TestTheSharedFixture:
    """B1-B11 and the named wrapper rows; C1-C6 and the named filter rows."""

    @pytest.mark.parametrize("case", FIXTURE["cases"], ids=lambda c: c["name"])
    def test_pre_execute(self, case: dict) -> None:
        result = _wrapper(case).pre_execute(
            _case_context(case),
            case["toolName"],
            object_name=case.get("object"),
            fields=case.get("fields"),
        )
        assert result.allowed is case["expected"]["allowed"]
        assert result.reason == _expected_reason(case["expected"])

    @pytest.mark.parametrize("case", FIXTURE["filterCases"], ids=lambda c: c["name"])
    def test_filter_tools(self, case: dict) -> None:
        wrapper = _wrapper(case)
        assert wrapper.filter_tools(_case_context(case), case["toolNames"]) == case["expected"]

    @pytest.mark.parametrize("case", FIXTURE["writeCases"], ids=lambda c: c["name"])
    def test_pre_write(self, case: dict) -> None:
        kwargs = {"tool_name": case["toolName"]} if "toolName" in case else {}
        result = _wrapper(case).pre_write(
            _case_context(case),
            case["operation"],
            case.get("object"),
            case.get("payload"),
            **kwargs,
        )
        assert result.allowed is case["expected"]["allowed"]
        assert result.reason == _expected_reason(case["expected"])

    @pytest.mark.parametrize("case", FIXTURE["writeCases"], ids=lambda c: c["name"])
    def test_execute_write_with_enforcement(self, case: dict) -> None:
        # The helper must thread tool_name through to pre_write: a denied row never reaches
        # the write function.
        kwargs = {"tool_name": case["toolName"]} if "toolName" in case else {}
        calls: list[int] = []

        def write_fn() -> None:
            calls.append(1)

        wrapper = _wrapper(case)
        if case["expected"]["allowed"]:
            assert wrapper.execute_write_with_enforcement(
                _case_context(case),
                case["operation"],
                write_fn,
                object_name=case.get("object"),
                payload=case.get("payload"),
                **kwargs,
            ) is None
            assert calls == [1]
        else:
            with pytest.raises(PermissionError) as err:
                wrapper.execute_write_with_enforcement(
                    _case_context(case),
                    case["operation"],
                    write_fn,
                    object_name=case.get("object"),
                    payload=case.get("payload"),
                    **kwargs,
                )
            assert str(err.value) == f"Access denied: {_expected_reason(case['expected'])}"
            assert calls == []

    def test_the_fixture_covers_every_owned_row(self) -> None:
        # A fixture edit that drops a row would otherwise just run fewer cases, silently.
        case_names = {c["name"] for c in FIXTURE["cases"]}
        filter_names = {c["name"] for c in FIXTURE["filterCases"]}
        assert {f"B{i}" for i in range(1, 12)} <= case_names
        assert {f"C{i}" for i in range(1, 7)} <= filter_names
        assert "no-tool-rules-unchanged" in case_names
        assert "static-empty-policy-empty" in case_names
        assert "kelvin-sign-invalid-name" in case_names
        assert "mis-cased-not-in-allowed-set" in case_names
        assert "filter-no-tool-rules-no-grammar" in filter_names
        assert "filter-mis-cased-dropped" in filter_names
        assert "filter-deny-all-lists-nothing" in filter_names
        assert "filter-write-only-subject-to-tool-rules" in filter_names
        write_names = {c["name"] for c in FIXTURE["writeCases"]}
        assert {n for n in write_names if n.startswith("W")} == write_names
        assert {f"W{i}" for i in range(1, 13)} == {n.split("-")[0] for n in write_names}
        assert len(FIXTURE["cases"]) == 23
        assert len(FIXTURE["filterCases"]) == 18
        assert len(FIXTURE["writeCases"]) == 12
        # At least one write row omits the name, and at least one supplies it.
        assert any("toolName" not in c for c in FIXTURE["writeCases"])
        assert any("toolName" in c for c in FIXTURE["writeCases"])

    def test_the_runner_honours_every_override(self) -> None:
        # The runner reads contextOverride, object, fields and toolActionCategories. Pin
        # that each is actually exercised, so a runner that ignored one could not pass by
        # the fixture never using it.
        cases = FIXTURE["cases"] + FIXTURE["filterCases"] + FIXTURE["writeCases"]
        overrides = {c.get("contextOverride") for c in cases}
        assert {"expired", "wrongKey"} <= overrides
        assert any("object" in c for c in FIXTURE["cases"])
        assert any("fields" in c for c in FIXTURE["cases"])
        assert any("toolActionCategories" in c for c in FIXTURE["cases"])


class TestC10FilterAgreesWithPreExecute:
    """For every name filter_tools drops, pre_execute denies it; for every name it keeps,
    pre_execute does not deny it for a tool-name reason."""

    @pytest.mark.parametrize("case", FIXTURE["filterCases"], ids=lambda c: c["name"])
    def test_filter_and_pre_execute_agree(self, case: dict) -> None:
        wrapper = _wrapper(case)
        context = _case_context(case)
        kept = wrapper.filter_tools(context, case["toolNames"])
        for name in case["toolNames"]:
            result = wrapper.pre_execute(context, name)
            if name in kept:
                assert result.allowed or result.reason not in TOOL_NAME_REASONS, name
                # The only denial a kept name may still meet, with no call arguments,
                # is the read gate filter_tools deliberately does not apply.
                assert result.allowed or result.reason == "query not permitted", name
            else:
                assert result.allowed is False, name

    def test_the_property_is_not_vacuous(self) -> None:
        # At least one row drops a name and at least one keeps a name that pre_execute
        # still denies for can_query -- otherwise both branches above could be dead.
        dropped = kept_but_denied = 0
        for case in FIXTURE["filterCases"]:
            wrapper = _wrapper(case)
            context = _case_context(case)
            kept = wrapper.filter_tools(context, case["toolNames"])
            dropped += len([n for n in case["toolNames"] if n not in kept])
            kept_but_denied += len(
                [n for n in kept if not wrapper.pre_execute(context, n).allowed]
            )
        assert dropped > 0
        assert kept_but_denied > 0


class TestTamper:
    """F1-F4: every edit to toolRules after signing breaks the seal."""

    def _wrapper(self) -> SecureMcpToolWrapper:
        return SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=KEY))

    def test_control_the_untampered_context_is_valid(self) -> None:
        # Without this, a wrapper that rejected every context would pass the rows below.
        result = self._wrapper().pre_execute(_signed(HIDDEN_EXPORT), "export_segment_csv")
        assert result.reason == "tool is hidden"

    def test_f1_clearing_hidden_tools(self) -> None:
        context = _signed(HIDDEN_EXPORT)
        context.effective_policy.object_rules.tool_rules.hidden_tools = []
        result = self._wrapper().pre_execute(context, "export_segment_csv")
        assert result.allowed is False
        assert result.reason == "invalid signature"
        assert self._wrapper().filter_tools(context, ["query_patients"]) == []

    def test_f2_removing_tool_rules(self) -> None:
        context = _signed(HIDDEN_EXPORT)
        context.effective_policy.object_rules.tool_rules = None
        result = self._wrapper().pre_execute(context, "export_segment_csv")
        assert result.allowed is False
        assert result.reason == "invalid signature"
        assert self._wrapper().filter_tools(context, ["export_segment_csv"]) == []

    def test_f3_appending_to_allowed_tools(self) -> None:
        context = _signed(
            {
                "permissions": {"canQuery": True},
                "objectRules": {"toolRules": {"allowedTools": ["query_patients"]}},
            }
        )
        context.effective_policy.object_rules.tool_rules.allowed_tools.append(
            "export_segment_csv"
        )
        result = self._wrapper().pre_execute(context, "export_segment_csv")
        assert result.allowed is False
        assert result.reason == "invalid signature"
        assert self._wrapper().filter_tools(context, ["query_patients"]) == []

    def test_f4_adding_tool_rules_even_a_narrowing_edit(self) -> None:
        context = _signed({"permissions": {"canQuery": True}})
        policy = context.effective_policy
        if policy.object_rules is None:
            policy.object_rules = ObjectRules()
        policy.object_rules.tool_rules = ToolRules(hidden_tools=["export_segment_csv"])
        result = self._wrapper().pre_execute(context, "query_patients")
        assert result.allowed is False
        assert result.reason == "invalid signature"
        assert self._wrapper().filter_tools(context, ["query_patients"]) == []


class TestTheJudgeNeverSeesAToolDenial:
    def _wrapper(
        self, judge: Judge, history: ToolCallHistory | None = None
    ) -> SecureMcpToolWrapper:
        return SecureMcpToolWrapper(
            SecureMcpServerOptions(
                signing_key=KEY,
                tool_action_categories=JUDGE_TOOL_MAP,
                judge=judge,
                tool_call_history=history,
            )
        )

    def test_control_an_allowed_tool_reaches_the_judge(self) -> None:
        # Proves the stub is wired: otherwise zero calls below would be meaningless.
        judge = _CountingJudge()
        result = self._wrapper(judge).pre_execute(_signed(JUDGE_POLICY), "query_patients")
        assert result.allowed is True
        assert judge.calls == 1

    def test_b12_a_hidden_tool_is_denied_without_the_judge(self) -> None:
        # The stub would allow anything it saw, so reaching it would turn the hide into
        # an allow. Asserted on the call count, not only the outcome.
        judge = _CountingJudge()
        result = self._wrapper(judge).pre_execute(_signed(JUDGE_POLICY), "export_segment_csv")
        assert result.allowed is False
        assert result.reason == "tool is hidden"
        assert judge.calls == 0

    def test_c9_filter_tools_never_calls_the_judge(self) -> None:
        judge = _CountingJudge()
        kept = self._wrapper(judge).filter_tools(
            _signed(JUDGE_POLICY), ["query_patients", "export_segment_csv"]
        )
        assert kept == ["query_patients"]
        assert judge.calls == 0


class TestHistory:
    def _wrapper(self, history: ToolCallHistory) -> SecureMcpToolWrapper:
        return SecureMcpToolWrapper(
            SecureMcpServerOptions(signing_key=KEY, tool_call_history=history)
        )

    def test_b13_a_hidden_tool_denial_is_recorded(self) -> None:
        history = ToolCallHistory()
        result = self._wrapper(history).pre_execute(
            _signed(HIDDEN_EXPORT), "export_segment_csv"
        )
        assert result.reason == "tool is hidden"
        assert history.get_recent() == [render_tool_call("export_segment_csv", None, None, None, None)]

    def test_b13_recorded_exactly_like_an_existing_denial(self) -> None:
        # The comparison the row asks for: a can_query denial on the same tool records
        # the same entry, so the judge sees a refused tool the same way it sees any other
        # refused call.
        tool_history = ToolCallHistory()
        query_history = ToolCallHistory()
        self._wrapper(tool_history).pre_execute(_signed(HIDDEN_EXPORT), "export_segment_csv")
        self._wrapper(query_history).pre_execute(
            _signed({"permissions": {"canQuery": False}}), "export_segment_csv"
        )
        assert tool_history.get_recent() == query_history.get_recent()
        assert len(tool_history) == 1

    def test_c8_filter_tools_records_nothing(self) -> None:
        history = ToolCallHistory()
        history.record("earlier-call")
        before = history.get_recent()
        kept = self._wrapper(history).filter_tools(
            _signed(HIDDEN_EXPORT), ["query_patients", "export_segment_csv"]
        )
        assert kept == ["query_patients"]
        assert history.get_recent() == before


class TestFilterToolsSkipsNonStringNames:
    """M3: a null or non-string entry is dropped, with or without toolRules."""

    @pytest.mark.parametrize(
        "fragment",
        [{"permissions": {"canQuery": True}}, HIDDEN_EXPORT],
        ids=["no-tool-rules", "with-tool-rules"],
    )
    def test_non_string_entries_are_dropped(self, fragment: dict) -> None:
        wrapper = SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=KEY))
        names = [None, "query_patients", 5, b"query_patients", ["x"], {"n": 1}, "count_patients"]
        assert wrapper.filter_tools(_signed(fragment), names) == [  # type: ignore[arg-type]
            "query_patients",
            "count_patients",
        ]

    def test_non_string_dropped_even_when_the_static_list_is_empty(self) -> None:
        # Without toolRules and without a static list nothing else would reject None.
        wrapper = SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=KEY, allowed_tools=[]))
        assert wrapper.filter_tools(_signed({"permissions": {"canQuery": True}}), [None]) == []  # type: ignore[list-item]


class TestWriteGateHandWritten:
    """What the write-path fixture rows cannot say on their own."""

    WRITE_ONLY_HIDDEN = {
        "permissions": {"canQuery": False, "canInsert": True, "readOnly": False},
        "objectRules": {"toolRules": {"hiddenTools": ["delete_patient"]}},
    }

    def test_positional_callers_are_unchanged(self) -> None:
        # The new argument is keyword-only, so an existing positional call cannot bind to it.
        wrapper = SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=KEY))
        result = wrapper.pre_write(
            _signed(self.WRITE_ONLY_HIDDEN), "insert", "notes", {"body": "x"}
        )
        assert result.allowed is True
        with pytest.raises(TypeError):
            wrapper.pre_write(  # type: ignore[misc]
                _signed(self.WRITE_ONLY_HIDDEN), "insert", "notes", {"body": "x"}, "delete_patient"
            )

    def test_the_write_denial_matches_the_read_denial_exactly(self) -> None:
        wrapper = SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=KEY))
        context = _signed(
            {
                "permissions": {"canQuery": True, "canInsert": True, "readOnly": False},
                "objectRules": {
                    "toolRules": {"allowedTools": ["write_note"], "hiddenTools": ["delete_patient"]}
                },
            }
        )
        for name in ["delete_patient", "DELETE_patient", "export_csv", "bad name", "\u212Aill"]:
            read = wrapper.pre_execute(context, name)
            write = wrapper.pre_write(context, "insert", "notes", {"body": "x"}, tool_name=name)
            assert read.allowed is False and write.allowed is False, name
            assert write.reason == read.reason, name

    def test_an_empty_string_name_is_gated_not_treated_as_omitted(self) -> None:
        wrapper = SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=KEY))
        result = wrapper.pre_write(
            _signed(self.WRITE_ONLY_HIDDEN), "insert", "notes", {"body": "x"}, tool_name=""
        )
        assert result.allowed is False
        assert result.reason == "invalid tool name"

    def test_a_tampered_context_is_refused_before_the_tool_gate(self) -> None:
        context = _signed(self.WRITE_ONLY_HIDDEN)
        context.effective_policy.object_rules.tool_rules.hidden_tools = []
        wrapper = SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=KEY))
        result = wrapper.pre_write(
            context, "insert", "notes", {"body": "x"}, tool_name="delete_patient"
        )
        assert result.reason == "invalid signature"


class TestFilterToolsInput:
    def test_c7_the_input_list_is_not_mutated(self) -> None:
        wrapper = SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=KEY))
        names = ["query_patients", "export_segment_csv", "EXPORT_SEGMENT_CSV", "bad name"]
        snapshot = copy.deepcopy(names)
        kept = wrapper.filter_tools(_signed(HIDDEN_EXPORT), names)
        assert names == snapshot
        assert kept == ["query_patients"]
        assert kept is not names

    def test_c7_the_result_is_a_new_list_even_when_nothing_is_dropped(self) -> None:
        wrapper = SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=KEY))
        names = ["a", "b"]
        kept = wrapper.filter_tools(_signed({"permissions": {"canQuery": True}}), names)
        kept.append("c")
        assert names == ["a", "b"]

    def test_filter_tools_preserves_input_order(self) -> None:
        wrapper = SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=KEY))
        names = ["zeta", "alpha", "mid"]
        assert wrapper.filter_tools(_signed({"permissions": {"canQuery": True}}), names) == names

    def test_filter_tools_preserves_order_while_dropping(self) -> None:
        wrapper = SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=KEY))
        names = ["zeta", "export_segment_csv", "alpha", "Export_Segment_Csv", "mid"]
        assert wrapper.filter_tools(_signed(HIDDEN_EXPORT), names) == ["zeta", "alpha", "mid"]


def test_no_option_was_added() -> None:
    names = {f.name for f in dataclasses.fields(SecureMcpServerOptions)}
    assert not any("tool_rule" in n for n in names)


def test_b17_the_factory_enforces_tool_rules_with_default_options() -> None:
    from tolap_mcp.factory import SecureToolFactory

    factory = SecureToolFactory(SecureMcpServerOptions(signing_key=KEY))
    context = _signed({**HIDDEN_EXPORT, "sourceConnectionId": "db:clinical:patients"})
    tool = factory.create_tool(context)
    assert isinstance(tool, SecureMcpToolWrapper)
    hidden = tool.pre_execute(context, "export_segment_csv")
    assert hidden.allowed is False
    assert hidden.reason == "tool is hidden"
    # Paired control: the same factory tool allows a tool the rules do not touch.
    assert tool.pre_execute(context, "query_patients").allowed is True
    assert tool.filter_tools(context, ["export_segment_csv", "query_patients"]) == [
        "query_patients"
    ]


def test_b18_concurrent_calls_each_get_their_own_decision() -> None:
    # pre_execute is synchronous, so a thread pool. One shared wrapper and context,
    # alternating allowed and hidden tools: any per-call state in the gate would let one
    # call's decision leak into another's.
    wrapper = SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=KEY))
    context = _signed(HIDDEN_EXPORT)
    names = ["query_patients" if i % 2 == 0 else "export_segment_csv" for i in range(50)]

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda n: (n, wrapper.pre_execute(context, n)), names))

    assert len(results) == 50
    for name, result in results:
        if name == "query_patients":
            assert result.allowed is True and result.reason is None
        else:
            assert result.allowed is False and result.reason == "tool is hidden"
