"""The semantic judge as the wrapper actually runs it (spec section 15.4).

``test_judge_gate.py`` covers the decision. This covers the wiring, which is the part that
silently does not exist if it is wrong: a gate nobody calls passes all of its own tests while
a policy's ``judge`` block quietly governs nothing. Every case here goes through
``pre_execute`` -- the call an integrator makes.

The ordering assertions are the ones worth reading. A judge that ran *before* the
deterministic checks, or that could turn a denial into an allow, would be a privilege
escalation dressed as a safety feature.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from tolap_core.context import build_security_context, sign_context
from tolap_core.history import ToolCallHistory
from tolap_core.judge import (
    Judge,
    JudgeDisposition,
    JudgeOutcome,
    JudgeRequest,
    JudgeResult,
    JUDGE_MODEL_MISMATCH_REASON,
)
from tolap_core.models import (
    EffectivePolicy,
    JudgeConfig,
    PolicyPermissions,
    PurposeProfile,
    SecurityContext,
)
from tolap_mcp.options import SecureMcpServerOptions
from tolap_mcp.tool_call import render_tool_call
from tolap_mcp.wrapper import SecureMcpToolWrapper

KEY = "judge-wrapper-key"
MODEL = "test-model-1"
TOOL_MAP = {"segment_overlap": "aggregate_overlap", "export_csv": "export_pii"}


class _StubJudge(Judge):
    """A judge returning a fixed verdict, with a call counter."""

    def __init__(self, result: JudgeResult, model_id: str = MODEL) -> None:
        self._result = result
        self._model_id = model_id
        self.calls = 0
        self.last_tool_call: str | None = None
        self.last_history: list[str] | None = None

    @property
    def model_id(self) -> str:
        return self._model_id

    def evaluate(self, request: JudgeRequest) -> JudgeResult:
        self.calls += 1
        self.last_tool_call = request.current_tool_call
        self.last_history = list(request.recent_history)
        return self._result


def _verdict(aligned: bool, confidence: float) -> JudgeResult:
    return JudgeResult(aligned=aligned, confidence=confidence, reasoning="stub")


def _purpose(*, judge_enabled: bool) -> PurposeProfile:
    return PurposeProfile(
        purpose_id="campaign-x-overlap",
        description="Aggregate overlap only.",
        allowed_actions=["aggregate_overlap"],
        judge=JudgeConfig(enabled=True, model=MODEL) if judge_enabled else None,
    )


def _policy(profile: PurposeProfile | None, *, can_query: bool = True) -> EffectivePolicy:
    return EffectivePolicy(
        version="1.0",
        user_id="judge-user",
        tenant_id="judge-tenant",
        source_connection_id="db:marketing:segments",
        source_profiles=["judge-wrapper"],
        permissions=PolicyPermissions(can_query=can_query, read_only=True),
        purpose_profile=profile,
    )


def _signed(policy: EffectivePolicy) -> SecurityContext:
    return sign_context(
        build_security_context(
            "judge-user",
            "judge-tenant",
            [policy],
            ttl=timedelta(hours=1),
            declared_purpose=policy.purpose_profile.purpose_id
            if policy.purpose_profile
            else None,
        ),
        KEY,
    )


def _wrapper(
    judge: Judge | None,
    history: ToolCallHistory | None = None,
    escalation: object = None,
) -> SecureMcpToolWrapper:
    return SecureMcpToolWrapper(
        SecureMcpServerOptions(
            signing_key=KEY,
            tool_action_categories=TOOL_MAP,
            judge=judge,
            tool_call_history=history,
            escalation_handler=escalation,  # type: ignore[arg-type]
        )
    )


class TestTheJudgeRunsAndCanSubtract:
    def test_a_confidently_aligned_call_is_allowed(self) -> None:
        judge = _StubJudge(_verdict(aligned=True, confidence=0.95))

        result = _wrapper(judge).pre_execute(
            _signed(_policy(_purpose(judge_enabled=True))), "segment_overlap"
        )

        assert result.allowed is True
        assert judge.calls == 1

    def test_a_confidently_misaligned_call_is_denied(self) -> None:
        # The whole reason the judge exists: a call the deterministic rules permit, refused
        # because it does not serve the declared purpose.
        judge = _StubJudge(_verdict(aligned=False, confidence=0.95))

        result = _wrapper(judge).pre_execute(
            _signed(_policy(_purpose(judge_enabled=True))), "segment_overlap"
        )

        assert result.allowed is False
        assert result.reason


class TestTheJudgeCanOnlySubtract:
    def test_a_deterministic_denial_is_not_sent_to_the_judge(self) -> None:
        # The load-bearing assertion. If a denial reached the judge, a confidently-aligned
        # verdict could overturn it -- and a persuasive prompt would become a privilege
        # escalation. Asserted on the judge having been left uncalled, not on the outcome,
        # because the outcome is the same either way.
        judge = _StubJudge(_verdict(aligned=True, confidence=1.0))

        result = _wrapper(judge).pre_execute(
            _signed(_policy(_purpose(judge_enabled=True))), "export_csv"
        )

        assert result.allowed is False
        assert judge.calls == 0

    def test_a_can_query_denial_is_not_sent_to_the_judge_either(self) -> None:
        judge = _StubJudge(_verdict(aligned=True, confidence=1.0))

        result = _wrapper(judge).pre_execute(
            _signed(_policy(_purpose(judge_enabled=True), can_query=False)),
            "segment_overlap",
        )

        assert result.reason == "query not permitted"
        assert judge.calls == 0


class TestEscalationIsADenialWithoutAHandler:
    def test_escalation_with_no_handler_denies(self) -> None:
        judge = _StubJudge(_verdict(aligned=True, confidence=0.4))

        result = _wrapper(judge).pre_execute(
            _signed(_policy(_purpose(judge_enabled=True))), "segment_overlap"
        )

        assert result.allowed is False

    def test_escalation_with_a_handler_that_approves_allows(self) -> None:
        judge = _StubJudge(_verdict(aligned=True, confidence=0.4))
        seen: list[JudgeOutcome] = []

        def handler(outcome: JudgeOutcome) -> bool:
            seen.append(outcome)
            return True

        result = _wrapper(judge, escalation=handler).pre_execute(
            _signed(_policy(_purpose(judge_enabled=True))), "segment_overlap"
        )

        assert result.allowed is True
        assert seen and seen[0].disposition is JudgeDisposition.escalate

    def test_escalation_with_a_handler_that_refuses_denies(self) -> None:
        # The paired control: a handler consulted and saying no must still deny.
        judge = _StubJudge(_verdict(aligned=True, confidence=0.4))

        result = _wrapper(judge, escalation=lambda _o: False).pre_execute(
            _signed(_policy(_purpose(judge_enabled=True))), "segment_overlap"
        )

        assert result.allowed is False

    def test_a_blocking_verdict_ignores_the_escalation_handler(self) -> None:
        # A review handler is for the ambiguous case. Routing a confident block through it
        # would let a deployment approve away the judge's clearest refusals.
        judge = _StubJudge(_verdict(aligned=False, confidence=0.99))
        called = []

        def handler(outcome: JudgeOutcome) -> bool:
            called.append(outcome)
            return True

        result = _wrapper(judge, escalation=handler).pre_execute(
            _signed(_policy(_purpose(judge_enabled=True))), "segment_overlap"
        )

        assert result.allowed is False
        assert called == []


class TestModelVerification:
    def test_a_model_mismatch_escalates_before_the_call_is_issued(self) -> None:
        judge = _StubJudge(_verdict(aligned=True, confidence=1.0), model_id="other-model")

        result = _wrapper(judge).pre_execute(
            _signed(_policy(_purpose(judge_enabled=True))), "segment_overlap"
        )

        assert result.allowed is False
        assert JUDGE_MODEL_MISMATCH_REASON in (result.reason or "")
        assert judge.calls == 0


class TestOptingOut:
    def test_no_judge_configured_leaves_pre_execute_unchanged(self) -> None:
        # A policy asking for a judge with none wired is not an error: the deterministic
        # checks have run, and the judge could only have subtracted.
        context = _signed(_policy(_purpose(judge_enabled=True)))

        assert _wrapper(None).pre_execute(context, "segment_overlap").allowed is True

    def test_a_policy_with_no_judge_block_does_not_consult_the_judge(self) -> None:
        # A judge wired at the composition root must not start judging policies that never
        # asked for one -- otherwise enabling it for one policy changes every other.
        judge = _StubJudge(_verdict(aligned=False, confidence=1.0))

        result = _wrapper(judge).pre_execute(
            _signed(_policy(_purpose(judge_enabled=False))), "segment_overlap"
        )

        assert result.allowed is True
        assert judge.calls == 0


class TestHistory:
    def test_the_trajectory_reaches_the_judge_and_refused_calls_are_kept(self) -> None:
        # Drift is a property of the sequence, not of one call, so the history has to
        # arrive. Refused calls are recorded too: an agent probing for what it can reach is
        # exactly the pattern the judge is meant to notice.
        history = ToolCallHistory(max_size=8)
        judge = _StubJudge(_verdict(aligned=True, confidence=0.95))
        wrapper = _wrapper(judge, history)
        context = _signed(_policy(_purpose(judge_enabled=True)))

        wrapper.pre_execute(context, "export_csv")  # refused
        wrapper.pre_execute(context, "segment_overlap")

        assert any("export_csv" in entry for entry in (judge.last_history or []))
        assert len(history.get_recent()) == 2

    def test_the_rendered_call_carries_field_names_but_no_values(self) -> None:
        # Field names are most of what makes a read on-purpose. Values never reach the
        # renderer, so this path cannot send row data to a model.
        assert (
            render_tool_call("export_csv", "customers", ["email", "ssn"])
            == "export_csv(object=customers fields=[email,ssn])"
        )

    @pytest.mark.parametrize(
        ("kwargs", "expected"),
        [
            ({}, "ping()"),
            (
                {"endpoint_path": "/segments/overlap"},
                "ping(endpoint=GET /segments/overlap)",
            ),
            (
                {"endpoint_path": "/export/all.csv", "endpoint_method": "POST"},
                "ping(endpoint=POST /export/all.csv)",
            ),
            (
                {
                    "object_name": "customers",
                    "fields": ["email"],
                    "endpoint_path": "/c",
                    "endpoint_method": "PUT",
                },
                "ping(object=customers fields=[email] endpoint=PUT /c)",
            ),
        ],
    )
    def test_the_rendering_is_a_cross_sdk_contract(
        self, kwargs: dict[str, object], expected: str
    ) -> None:
        # Not a formatting detail: the same call has to render identically in all three
        # SDKs, or a policy's judge sees different text depending on which SDK the wrapper
        # came from -- and a verdict is only comparable against one rendering. The .NET and
        # TypeScript suites assert these same four strings.
        assert render_tool_call("ping", **kwargs) == expected  # type: ignore[arg-type]
