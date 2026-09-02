"""Turning a policy's judge configuration into an actual invocation (spec section 15.4).

This is the seam that makes ``purposeProfile.judge`` mean something. Without it a policy
could name a model, a history window, two thresholds and a latency budget, and a deployment
would honour none of them -- the judge would run with whatever the integrator's own glue
happened to pass. Every test here is about a policy field actually taking effect, or about
what happens when it cannot.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from tolap_core.history import ToolCallHistory
from tolap_core.judge import (
    DEFAULT_HISTORY_WINDOW,
    DEFAULT_MAX_LATENCY_MS,
    JUDGE_MODEL_MISMATCH_REASON,
    JUDGE_FAILED_REASON,
    NO_JUDGE_CONFIGURED_REASON,
    Judge,
    JudgeDisposition,
    JudgeOutcome,
    JudgeRequest,
    JudgeResult,
    build_judge_request,
    evaluate_judge,
    judge_enabled,
    judge_history_window,
)
from tolap_core.models import (
    EffectivePolicy,
    JudgeConfig,
    PolicyPermissions,
    PurposeProfile,
)


CONFIDENTLY_ALIGNED = JudgeResult(aligned=True, confidence=0.95, reasoning="on task")
CONFIDENTLY_MISALIGNED = JudgeResult(aligned=False, confidence=0.95, reasoning="off task")


class _StubJudge(Judge):
    """Records what it was asked, so "the judge was not called" is assertable."""

    def __init__(self, result: JudgeResult, model_id: str = "claude-sonnet") -> None:
        self._result = result
        self._model_id = model_id
        self.calls = 0
        self.last_request: JudgeRequest | None = None

    @property
    def model_id(self) -> str:
        return self._model_id

    def evaluate(self, request: JudgeRequest) -> JudgeResult:
        self.calls += 1
        self.last_request = request
        return self._result


def _policy(profile: PurposeProfile | None) -> EffectivePolicy:
    now = datetime.now(timezone.utc)
    return EffectivePolicy(
        version="1.0",
        user_id="u",
        tenant_id="t",
        source_connection_id="db:marketing:customer_segments",
        resolved_at=now.isoformat().replace("+00:00", "Z"),
        expires_at=(now + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        source_profiles=["p"],
        permissions=PolicyPermissions(can_query=True, read_only=True),
        purpose_profile=profile,
    )


def _with_judge(judge: JudgeConfig | None) -> PurposeProfile:
    return PurposeProfile(
        purpose_id="campaign-x-overlap",
        description="Aggregate overlap only.",
        judge=judge,
    )


class TestTheAbstractSeam:
    """The base class must refuse rather than answer.

    A subclass that forgot to override ``model_id`` would otherwise report whatever the
    base returned, and a base returning ``""`` would satisfy the gate's model check against
    a policy naming no model -- a judge nobody configured, silently accepted.
    """

    def test_an_incomplete_subclass_cannot_be_instantiated(self) -> None:
        class Incomplete(Judge):
            @property
            def model_id(self) -> str:
                return "m"

        with pytest.raises(TypeError):
            Incomplete()  # type: ignore[abstract]

    def test_the_base_model_id_raises_rather_than_returning_a_default(self) -> None:
        class Delegating(_StubJudge):
            @property
            def model_id(self) -> str:
                return Judge.model_id.fget(self)  # type: ignore[attr-defined]

        with pytest.raises(NotImplementedError):
            Delegating(CONFIDENTLY_ALIGNED).model_id

    def test_the_base_evaluate_raises_rather_than_allowing(self) -> None:
        class Delegating(_StubJudge):
            def evaluate(self, request: JudgeRequest) -> JudgeResult:
                return Judge.evaluate(self, request)

        policy = _policy(_with_judge(JudgeConfig(enabled=True)))
        request = build_judge_request(policy, "x")

        with pytest.raises(NotImplementedError):
            Delegating(CONFIDENTLY_ALIGNED).evaluate(request)


class TestWhetherTheJudgeRunsAtAll:
    @pytest.mark.parametrize(
        ("profile", "expected", "why"),
        [
            (None, False, "no purpose profile at all"),
            (_with_judge(None), False, "no judge block"),
            (_with_judge(JudgeConfig()), False, "enabled absent"),
            (_with_judge(JudgeConfig(enabled=False)), False, "enabled explicitly false"),
            (_with_judge(JudgeConfig(enabled=True)), True, "enabled explicitly true"),
        ],
        ids=lambda v: v if isinstance(v, str) else "",
    )
    def test_judge_enabled_requires_an_explicit_true(
        self, profile: PurposeProfile | None, expected: bool, why: str
    ) -> None:
        # Checked against `is True` rather than for truthiness, because `enabled` is
        # None-able: absent means "not configured", which is a different statement from an
        # explicit False even though both mean no judge today.
        assert judge_enabled(_policy(profile)) is expected, why

    def test_no_judge_enabled_allows_without_calling_the_judge(self) -> None:
        # A judge that is not asked for must not be invoked -- both because it costs a model
        # call and because a verdict nobody asked for should not be able to deny a call the
        # deterministic checks allowed.
        judge = _StubJudge(CONFIDENTLY_MISALIGNED)

        outcome = evaluate_judge(
            _policy(_with_judge(JudgeConfig(enabled=False))), judge, "aggregate_overlap()"
        )

        assert outcome.disposition is JudgeDisposition.allow
        assert judge.calls == 0

    def test_a_purpose_agnostic_policy_allows_without_calling_the_judge(self) -> None:
        judge = _StubJudge(CONFIDENTLY_MISALIGNED)

        outcome = evaluate_judge(_policy(None), judge, "anything()")

        assert outcome.disposition is JudgeDisposition.allow
        assert judge.calls == 0

    @pytest.mark.parametrize(
        "profile", [None, _with_judge(None), _with_judge(JudgeConfig())]
    )
    def test_build_judge_request_is_none_when_no_judge_is_enabled(
        self, profile: PurposeProfile | None
    ) -> None:
        assert build_judge_request(_policy(profile), "x") is None

    def test_build_judge_request_is_not_none_when_one_is(self) -> None:
        """The paired control for the theory above."""
        request = build_judge_request(_policy(_with_judge(JudgeConfig(enabled=True))), "x")

        assert request is not None
        assert request.current_tool_call == "x"


class TestTheModelCheck:
    def test_a_model_mismatch_escalates_without_calling_the_judge(self) -> None:
        # The gap this seam was written to close. A policy demanding one model must not be
        # silently judged by another -- a verdict is only meaningful against the model that
        # produced it. Checked BEFORE the call, so the wrong model is never invoked and no
        # authoritative-looking verdict lands in the audit log.
        judge = _StubJudge(CONFIDENTLY_ALIGNED, model_id="global.anthropic.claude-sonnet-5")
        policy = _policy(_with_judge(JudgeConfig(enabled=True, model="claude-opus")))

        outcome = evaluate_judge(policy, judge, "aggregate_overlap()")

        assert outcome.disposition is JudgeDisposition.escalate
        assert judge.calls == 0, "the wrong model is not invoked at all"

    def test_a_matching_model_proceeds_to_the_judge(self) -> None:
        # The paired control. Without it, a gate that escalated on every configured model
        # would satisfy the mismatch test and disable the judge entirely.
        judge = _StubJudge(CONFIDENTLY_ALIGNED, model_id="claude-sonnet")
        policy = _policy(_with_judge(JudgeConfig(enabled=True, model="claude-sonnet")))

        assert evaluate_judge(policy, judge, "aggregate_overlap()").disposition is JudgeDisposition.allow
        assert judge.calls == 1

    def test_a_policy_naming_no_model_accepts_any_judge(self) -> None:
        # The field is optional. Requiring it would make every judge-enabled policy fail
        # until someone pinned a model id, and those differ per account and region.
        judge = _StubJudge(CONFIDENTLY_ALIGNED, model_id="whatever-is-deployed")
        policy = _policy(_with_judge(JudgeConfig(enabled=True)))

        assert evaluate_judge(policy, judge, "x").disposition is JudgeDisposition.allow
        assert judge.calls == 1

    @pytest.mark.parametrize(
        "deployed_model",
        ["Claude-Sonnet", "claude-sonnet-5", "claude-sonne", "anthropic.claude-sonnet"],
    )
    def test_the_model_comparison_is_exact_and_case_sensitive(
        self, deployed_model: str
    ) -> None:
        # Not a prefix or substring rule. `claude-sonnet` and `claude-sonnet-5` are
        # different models, and a prefix match would let a deployment satisfy a policy
        # demanding one by wiring the other. An identifier is matched, not a pattern -- the
        # same reasoning as the purpose_id comparison.
        judge = _StubJudge(CONFIDENTLY_ALIGNED, model_id=deployed_model)
        policy = _policy(_with_judge(JudgeConfig(enabled=True, model="claude-sonnet")))

        assert evaluate_judge(policy, judge, "x").disposition is JudgeDisposition.escalate

    def test_the_model_mismatch_reason_is_part_of_the_contract(self) -> None:
        assert JUDGE_MODEL_MISMATCH_REASON == "judge model mismatch"


class TestThePolicysHistoryWindow:
    @pytest.mark.parametrize(
        ("profile", "expected", "why"),
        [
            (_with_judge(JudgeConfig(history_window=3)), 3, "configured"),
            (
                _with_judge(JudgeConfig()),
                DEFAULT_HISTORY_WINDOW,
                "judge block with no window",
            ),
            (_with_judge(None), DEFAULT_HISTORY_WINDOW, "purpose profile with no judge"),
            (None, DEFAULT_HISTORY_WINDOW, "no purpose profile at all"),
        ],
        ids=lambda v: v if isinstance(v, str) else "",
    )
    def test_history_window_comes_from_the_policy_or_the_documented_default(
        self, profile: PurposeProfile | None, expected: int, why: str
    ) -> None:
        assert judge_history_window(_policy(profile)) == expected, why

    def test_the_request_trims_history_to_the_policys_window(self) -> None:
        # An oversized buffer must not quietly widen what the policy chose to send. Trimmed
        # to the MOST RECENT entries, because a window of three means the last three calls,
        # not the first three.
        policy = _policy(_with_judge(JudgeConfig(enabled=True, history_window=2)))
        history = ToolCallHistory(max_size=10)
        for call in ("a", "b", "c"):
            history.record(call)

        request = build_judge_request(policy, "d", history)

        assert request.recent_history == ["b", "c"]

    def test_a_history_shorter_than_the_window_is_passed_whole(self) -> None:
        policy = _policy(_with_judge(JudgeConfig(enabled=True, history_window=10)))
        history = ToolCallHistory(max_size=10)
        history.record("a")

        assert build_judge_request(policy, "b", history).recent_history == ["a"]

    def test_a_history_exactly_at_the_window_is_passed_whole(self) -> None:
        """The boundary: trimming is ``>`` the window, not ``>=``."""
        policy = _policy(_with_judge(JudgeConfig(enabled=True, history_window=2)))
        history = ToolCallHistory(max_size=10)
        for call in ("a", "b"):
            history.record(call)

        assert build_judge_request(policy, "c", history).recent_history == ["a", "b"]

    def test_no_history_supplied_sends_an_empty_trajectory(self) -> None:
        policy = _policy(_with_judge(JudgeConfig(enabled=True)))

        assert build_judge_request(policy, "a").recent_history == []

    def test_an_unconfigured_window_still_trims_at_the_default(self) -> None:
        """Otherwise a 50-entry buffer would be sent to a judge nobody sized."""
        policy = _policy(_with_judge(JudgeConfig(enabled=True)))
        history = ToolCallHistory(max_size=50)
        for index in range(50):
            history.record(f"call-{index}")

        recent = build_judge_request(policy, "x", history).recent_history

        assert len(recent) == DEFAULT_HISTORY_WINDOW
        assert recent[-1] == "call-49", "the most recent calls, not the first"

    def test_the_request_holds_a_copy_of_the_history(self) -> None:
        """A later ``record`` must not retroactively change what the judge was asked."""
        policy = _policy(_with_judge(JudgeConfig(enabled=True)))
        history = ToolCallHistory(max_size=10)
        history.record("a")

        request = build_judge_request(policy, "x", history)
        history.record("b")

        assert request.recent_history == ["a"]

    def test_a_none_tool_call_is_refused(self) -> None:
        with pytest.raises(ValueError, match="not None"):
            build_judge_request(_policy(_with_judge(JudgeConfig(enabled=True))), None)

    def test_a_none_tool_call_is_refused_even_with_no_judge_enabled(self) -> None:
        """Validated before the enablement check, so the error does not depend on config."""
        with pytest.raises(ValueError, match="not None"):
            build_judge_request(_policy(None), None)


class TestThePolicysBudgetAndThresholds:
    def test_the_latency_budget_comes_from_the_policy(self) -> None:
        # max_latency_ms is a policy field, so it comes from the policy. A caller passing
        # its own value would make the policy's advisory.
        policy = _policy(_with_judge(JudgeConfig(enabled=True, max_latency_ms=750)))

        assert build_judge_request(policy, "x").max_latency_ms == 750

    def test_an_absent_latency_budget_uses_the_documented_default(self) -> None:
        policy = _policy(_with_judge(JudgeConfig(enabled=True)))

        assert build_judge_request(policy, "x").max_latency_ms == DEFAULT_MAX_LATENCY_MS

    def test_the_request_carries_the_policys_own_purpose_object(self) -> None:
        # The purpose description is what the judge compares the call against, so it has to
        # be the resolved policy's rather than anything the caller supplies.
        profile = PurposeProfile(
            purpose_id="campaign-x-overlap",
            description="Aggregate overlap only.",
            allowed_actions=["aggregate_overlap"],
            judge=JudgeConfig(enabled=True),
        )

        assert build_judge_request(_policy(profile), "x").purpose is profile

    def test_the_policys_thresholds_are_applied_to_the_verdict(self) -> None:
        # The same verdict, two policies, two outcomes -- which is what proves the
        # thresholds are read from the policy rather than from the defaults.
        judge = _StubJudge(JudgeResult(aligned=True, confidence=0.88, reasoning="fairly sure"))

        lenient = _policy(
            _with_judge(
                JudgeConfig(enabled=True, confidence_threshold=0.85, escalation_threshold=0.6)
            )
        )
        strict = _policy(
            _with_judge(
                JudgeConfig(enabled=True, confidence_threshold=0.95, escalation_threshold=0.6)
            )
        )

        assert evaluate_judge(lenient, judge, "x").disposition is JudgeDisposition.allow
        assert evaluate_judge(strict, judge, "x").disposition is JudgeDisposition.escalate

    def test_a_confidently_misaligned_verdict_blocks(self) -> None:
        policy = _policy(_with_judge(JudgeConfig(enabled=True)))

        assert (
            evaluate_judge(policy, _StubJudge(CONFIDENTLY_MISALIGNED), "x").disposition
            is JudgeDisposition.block
        )

    def test_an_unavailable_judge_escalates(self) -> None:
        # What BedrockJudge returns when the model could not be reached. Escalation, not
        # allow -- a judge that could not answer has not approved anything.
        unavailable = JudgeResult(
            aligned=False,
            confidence=0.0,
            reasoning="judge timed out",
            flags=["judge-unavailable"],
        )
        policy = _policy(_with_judge(JudgeConfig(enabled=True)))

        assert (
            evaluate_judge(policy, _StubJudge(unavailable), "x").disposition is JudgeDisposition.escalate
        )

    def test_the_current_tool_call_reaches_the_judge_verbatim(self) -> None:
        judge = _StubJudge(CONFIDENTLY_ALIGNED)
        policy = _policy(_with_judge(JudgeConfig(enabled=True)))

        evaluate_judge(policy, judge, "export_csv(customer_segments)")

        assert judge.last_request.current_tool_call == "export_csv(customer_segments)"


class TestTheOutcomeExplainsItself:
    """A bare disposition is not enough, and this is the reason the type exists.

    ``escalate`` is returned both when a deployment wired the wrong model and when the judge
    genuinely could not tell. Those are a configuration fault to fix and a call to put in
    front of a human -- entirely different responses to the same disposition. Without a
    reason on the outcome, ``JUDGE_MODEL_MISMATCH_REASON`` is unreachable from the call site,
    so the policy's ``model`` field would be checked and the check would be invisible.
    """

    def test_a_model_mismatch_names_both_models_and_carries_the_contract_token(self) -> None:
        judge = _StubJudge(CONFIDENTLY_ALIGNED, model_id="global.anthropic.claude-sonnet-5")
        policy = _policy(_with_judge(JudgeConfig(enabled=True, model="claude-opus")))

        outcome = evaluate_judge(policy, judge, "x")

        # The token stays a prefix, so an integrator can branch on the constant.
        assert outcome.reason.startswith(JUDGE_MODEL_MISMATCH_REASON)
        assert "claude-opus" in outcome.reason, "the model the policy asked for"
        assert "global.anthropic.claude-sonnet-5" in outcome.reason, "the model wired up"

    def test_a_model_mismatch_carries_no_result_because_no_model_was_consulted(self) -> None:
        # The distinction that lets an audit trail tell "no verdict exists" from "a verdict
        # was obtained and it was uncertain".
        judge = _StubJudge(CONFIDENTLY_ALIGNED, model_id="other-model")
        policy = _policy(_with_judge(JudgeConfig(enabled=True, model="claude-sonnet")))

        outcome = evaluate_judge(policy, judge, "x")

        assert outcome.result is None
        assert judge.calls == 0

    def test_no_judge_configured_says_so_and_carries_no_result(self) -> None:
        outcome = evaluate_judge(_policy(None), _StubJudge(CONFIDENTLY_MISALIGNED), "x")

        assert outcome.allowed is True
        assert outcome.reason == NO_JUDGE_CONFIGURED_REASON, (
            "the reason states that no judge ran rather than leaving a reviewer to infer it "
            "from an empty field; byte-identical to .NET's and TypeScript's"
        )
        assert outcome.result is None, "no model was consulted"

    def test_a_real_verdict_carries_the_judges_own_reasoning(self) -> None:
        policy = _policy(_with_judge(JudgeConfig(enabled=True)))

        outcome = evaluate_judge(policy, _StubJudge(CONFIDENTLY_MISALIGNED), "x")

        assert outcome.disposition is JudgeDisposition.block
        assert outcome.reason == "off task"
        assert outcome.result is CONFIDENTLY_MISALIGNED, (
            "the verdict itself is exposed, so an audit record can hold the confidence and "
            "the flags rather than just a label"
        )

    def test_an_escalating_verdict_also_carries_its_reasoning(self) -> None:
        """The case that must be distinguishable from the model mismatch above.

        Both escalate; one has a reason naming a configuration fault and no result, the other
        has the judge's own words and the verdict that produced them.
        """
        uncertain = JudgeResult(aligned=True, confidence=0.7, reasoning="cannot tell")
        policy = _policy(_with_judge(JudgeConfig(enabled=True)))

        outcome = evaluate_judge(policy, _StubJudge(uncertain), "x")

        assert outcome.disposition is JudgeDisposition.escalate
        assert outcome.reason == "cannot tell"
        assert not outcome.reason.startswith(JUDGE_MODEL_MISMATCH_REASON)
        assert outcome.result is uncertain

    def test_a_confident_allow_carries_both_the_result_and_the_reasoning(self) -> None:
        policy = _policy(_with_judge(JudgeConfig(enabled=True)))

        outcome = evaluate_judge(policy, _StubJudge(CONFIDENTLY_ALIGNED), "x")

        # An allow carries the model's reasoning too, unlike AccessResult. The convention does
        # not transfer: an AccessResult allow has nothing to explain, whereas a reviewer
        # auditing a borderline approval wants the view the model formed.
        assert outcome.reason == CONFIDENTLY_ALIGNED.reasoning
        assert outcome.result is CONFIDENTLY_ALIGNED

    @pytest.mark.parametrize(
        ("disposition", "expected"),
        [
            (JudgeDisposition.allow, True),
            (JudgeDisposition.block, False),
            (JudgeDisposition.escalate, False),
        ],
    )
    def test_allowed_treats_escalate_as_not_allowed(
        self, disposition: JudgeDisposition, expected: bool
    ) -> None:
        # The whole safety argument rests on this. A caller without a review path gets the
        # fail-closed reading by default, rather than "escalate to review" silently meaning
        # "permit" wherever the review step was never built.
        assert JudgeOutcome(disposition=disposition).allowed is expected

    def test_the_outcome_is_immutable(self) -> None:
        """A decision a caller can edit after the fact is not a decision."""
        outcome = evaluate_judge(
            _policy(_with_judge(JudgeConfig(enabled=True))),
            _StubJudge(CONFIDENTLY_MISALIGNED),
            "x",
        )

        with pytest.raises(Exception):
            outcome.disposition = JudgeDisposition.allow  # type: ignore[misc]


class TestArgumentValidation:
    def test_a_none_judge_is_refused(self) -> None:
        policy = _policy(_with_judge(JudgeConfig(enabled=True)))

        with pytest.raises(ValueError, match="None is not a decision"):
            evaluate_judge(policy, None, "x")

    def test_a_none_judge_is_refused_even_on_a_purpose_agnostic_policy(self) -> None:
        """Refused before the short-circuit, or the error depends on the policy."""
        with pytest.raises(ValueError, match="None is not a decision"):
            evaluate_judge(_policy(None), None, "x")

    def test_a_none_tool_call_is_refused(self) -> None:
        policy = _policy(_with_judge(JudgeConfig(enabled=True)))

        with pytest.raises(ValueError, match="not None"):
            evaluate_judge(policy, _StubJudge(CONFIDENTLY_ALIGNED), None)


class TestAThrowingJudgeDoesNotReachTheAuthorizationPath:
    """Section 15.4 requires every judge failure to escalate rather than raise.

    ``BedrockJudge`` honours that internally, but :class:`Judge` is a public ABC -- so a custom
    implementation can raise, and the natural fix for an exception on the authorization path is
    an ``except`` at the call site that returns "allow". That is the failure mode this guard
    designs out.
    """

    class _Raising(Judge):
        @property
        def model_id(self) -> str:
            return "stub-model"

        def evaluate(self, request: JudgeRequest) -> JudgeResult:
            raise RuntimeError("no credentials")

    def test_it_escalates_rather_than_propagating(self) -> None:
        policy = _policy(_with_judge(JudgeConfig(enabled=True)))

        outcome = evaluate_judge(policy, self._Raising(), "x")

        assert outcome.disposition is JudgeDisposition.escalate
        assert outcome.allowed is False
        assert outcome.reason.startswith(JUDGE_FAILED_REASON)
        assert "RuntimeError" in outcome.reason, (
            "the exception type is named so an operator can find the faulty implementation"
        )
        assert outcome.result is None, "no verdict was obtained"

    def test_the_reason_is_byte_identical_to_the_other_sdks(self) -> None:
        assert JUDGE_FAILED_REASON == "judge invocation failed"

