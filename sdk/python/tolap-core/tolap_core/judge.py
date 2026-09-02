"""The optional semantic judge (canonical-enforcement-spec.md section 15.4).

Advisory and strictly subtractive. A judge runs only after the three deterministic
checks -- purpose filtering, action validation, chain validation -- have allowed a
call, and it can only take that allowance away. It can never permit something they
denied: a non-deterministic component must not be able to widen access, because then
a prompt that talks the model round becomes a privilege escalation.

The interface lives here in ``tolap_core`` and every implementation that calls a model
lives in ``tolap_mcp``, which already carries external dependencies. Core ships with
none, and a judge needs a network client.

The three functions below are this SDK's equivalent of .NET's ``JudgeGate``:
:func:`judge_enabled`, :func:`judge_history_window`, :func:`build_judge_request` and
:func:`evaluate_judge`. They exist because a policy can configure a judge in full -- a
model, a history window, two thresholds, a latency budget -- and none of it takes
effect unless something reads those values and applies them. Left to each integrator,
the predictable outcome is a deployment where the judge runs with a window and
thresholds nobody chose, and where the policy's ``model`` is quietly ignored: a
control the configuration implies and that never runs.

The wrappers deliberately do **not** call any of this. The judge is opt-in glue: it
needs a network client, an escalation destination and a retention decision about
tool-call history, none of which a wrapper can assume.
"""

from __future__ import annotations

import math
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from tolap_core.models import EffectivePolicy, JudgeConfig, PurposeProfile

if TYPE_CHECKING:  # pragma: no cover - import cycle broken for typing only
    from tolap_core.history import ToolCallHistory


DEFAULT_CONFIDENCE_THRESHOLD = 0.85
"""Confidence at or above which a verdict is final, when unconfigured."""

DEFAULT_ESCALATION_THRESHOLD = 0.60
"""Confidence below which a call escalates, when unconfigured."""

DEFAULT_MAX_LATENCY_MS = 2000
"""Wall-clock budget for one evaluation, when unconfigured."""

DEFAULT_HISTORY_WINDOW = 10
"""Number of preceding calls to supply, when unconfigured."""

JUDGE_MODEL_MISMATCH_REASON = "judge model mismatch"

#: The reason on an allow that no judge was asked for.
#:
#: Byte-identical to .NET's ``JudgeGate.NoJudgeConfiguredReason`` and TypeScript's
#: ``NO_JUDGE_CONFIGURED_REASON``. It existed only in TypeScript, was an inline literal
#: spelled differently in .NET, and was absent here -- three behaviours for one outcome in a
#: field integrators log and branch on.
NO_JUDGE_CONFIGURED_REASON = "no judge configured"

#: The escalation reason when the judge itself raised.
#:
#: Section 15.4 requires a timeout, a transport failure and an unparseable response to
#: "produce escalation rather than an exception". ``BedrockJudge`` honours that internally,
#: but :class:`Judge` is a public ABC and a custom implementation can raise -- which would put
#: an exception on the authorization path, and the natural fix for that at a call site is an
#: ``except`` that returns "allow". Caught in :func:`evaluate_judge` so the safe reading is the
#: default rather than something each integrator has to remember.
#: Byte-identical to .NET's ``JudgeGate.JudgeFailedReason`` and TypeScript's
#: ``JUDGE_FAILED_REASON``.
JUDGE_FAILED_REASON = "judge invocation failed"
"""The escalation reason when the judge is not the model the policy asked for.

Part of the contract, and spelled as TypeScript's ``JUDGE_MODEL_MISMATCH_REASON`` and
.NET's ``JudgeGate.ModelMismatchReason`` spell it -- three spellings of one constant is
drift, whatever each language's own conventions say about interfaces.

Escalation rather than a hard block: the call may be perfectly legitimate, and the fault
is in the deployment, so a human is the right destination. What it must never be is a
silent substitution.

:attr:`JudgeOutcome.reason` carries this as a **prefix**, followed by the two model ids,
so an integrator can branch on the constant and still read which model was expected and
which was wired.
"""


@dataclass
class JudgeRequest:
    """What a judge is asked to decide.

    ``purpose`` is the profile from the resolved policy. Its ``description`` is what
    gives the judge something to compare the call against, which is why an author who
    enables the judge should write one.

    ``recent_history`` holds preceding calls, oldest first, bounded by
    ``JudgeConfig.history_window``. Drift is a property of a sequence rather than of
    one call: an agent asking for one more column each turn looks reasonable at every
    single step.

    ``max_latency_ms`` is the wall-clock budget. Exceeding it escalates rather than
    allowing.
    """

    purpose: PurposeProfile
    current_tool_call: str
    recent_history: list[str]
    max_latency_ms: int


@dataclass
class JudgeResult:
    """A judge's verdict.

    ``confidence`` is how sure the judge is, in ``[0, 1]``. A value outside that range
    is unusable and escalates -- see :func:`judge_disposition`.

    ``reasoning`` is the judge's explanation, for the audit trail. ``flags`` are
    optional machine-readable markers for downstream triage.
    """

    aligned: bool
    confidence: float
    reasoning: str
    flags: list[str] | None = None


class JudgeDisposition(Enum):
    """What to do with a judge's verdict."""

    #: Proceed. The deterministic checks already passed.
    allow = "allow"
    #: Refuse. The judge is confident the call does not serve the purpose.
    block = "block"
    #: Refer to a human. **Not** an allow: a wrapper with no escalation handler must
    #: deny, or "escalate to review" silently means "permit" wherever the review step
    #: was never built.
    escalate = "escalate"


@dataclass(frozen=True)
class JudgeOutcome:
    """What :func:`evaluate_judge` decided, and why.

    A bare :class:`JudgeDisposition` is not enough. ``escalate`` is returned both when a
    deployment wired the wrong model and when the judge genuinely could not tell, and those
    call for entirely different responses -- one is a configuration fault to fix, the other
    is a call to put in front of a human. Without a reason the mandated
    :data:`JUDGE_MODEL_MISMATCH_REASON` is unreachable from the call site, so the policy's
    ``model`` field would be checked and the check would be invisible.

    ``result`` is ``None`` whenever no model was consulted: either the policy enables no
    judge, or the model did not match and the call was refused before being issued. That
    distinction is what tells an audit trail "no verdict exists" apart from "a verdict was
    obtained and it was uncertain".

    ``reason`` is populated on **every** disposition, including an allow -- deliberately
    unlike :class:`~tolap_core.enforcement.AccessResult`, where an allow carries none. The
    convention does not transfer, because the two fields answer different questions. An
    ``AccessResult`` allow has nothing to explain: the policy permitted the call and that is
    the whole story. A judge allow does: a model formed a view, and an audit trail reviewing a
    borderline approval wants that view in the record rather than having to reach into
    ``result`` for it -- or, when no judge ran at all, wants to see that stated rather than
    inferring it from an empty field. All three SDKs populate it identically.
    """

    disposition: JudgeDisposition
    reason: str = NO_JUDGE_CONFIGURED_REASON
    result: JudgeResult | None = None

    @property
    def allowed(self) -> bool:
        """Whether the call may proceed.

        ``escalate`` is **not** allowed. A caller with a human-review path branches on
        :attr:`disposition` instead; a caller without one gets the fail-closed reading by
        default, rather than "escalate to review" silently meaning "permit" wherever the
        review step was never built.
        """
        return self.disposition is JudgeDisposition.allow


class Judge(ABC):
    """A semantic check on whether a tool call serves its authorized purpose.

    Named without an ``I`` prefix, matching this SDK's other seams
    (:class:`~tolap_core.context.ReplayGuard`,
    :class:`~tolap_store.PolicyStore`) where .NET writes ``IReplayGuard`` and
    ``IPolicyStore``.

    Synchronous, unlike .NET's ``IJudge.EvaluateAsync``, because every other
    enforcement entry point in this SDK is synchronous -- the HTTP wrapper drives a
    blocking ``httpx.Client``. An async judge would make the one optional check the
    only reason to introduce an event loop.
    """

    @property
    @abstractmethod
    def model_id(self) -> str:
        """The model this judge actually invokes.

        Declared so that :func:`evaluate_judge` can check it against the
        ``JudgeConfig.model`` the policy asked for. Without it, a policy demanding one
        model would be silently judged by whatever the deployment happened to wire up
        -- the policy field would look like a control and be decoration. A verdict is
        only meaningful against the model that produced it, which is also why two
        policies naming different models refuse to merge.

        Reported by the implementation rather than configured alongside it, so the
        value comes from whatever really issues the call.
        """
        raise NotImplementedError

    @abstractmethod
    def evaluate(self, request: JudgeRequest) -> JudgeResult:
        """Evaluate a call against its purpose.

        Implementations should surface a timeout or a transport failure as a
        low-confidence result rather than a confident ``aligned=True``. The caller
        maps either to :attr:`JudgeDisposition.escalate`; a fabricated confident
        alignment is the one response that cannot be recovered from.
        """
        raise NotImplementedError


def judge_disposition(
    result: JudgeResult, config: JudgeConfig | None
) -> JudgeDisposition:
    """Decide what to do with a verdict.

    Every path that is not a confident verdict escalates, and escalation denies unless
    a handler is wired. The ordering matters: the unusable-input checks come first, so
    a malformed result cannot reach the threshold comparisons and win one.

    Three unusable-input cases, each of which would otherwise produce a confident
    allow:

    - A confidence outside ``[0, 1]``. A judge reporting ``1.5`` has malfunctioned,
      and comparing it against a threshold would grant it more authority than a
      correct answer -- ``1.5`` clears every bar.
    - Thresholds inverted, with escalation above confidence. There is no reading of
      that configuration to act on, so it escalates rather than picking whichever
      bound happens to be checked first. Merging two judge configs can produce this,
      since both thresholds take the maximum independently.
    - ``nan``, which fails every comparison and would otherwise fall through to
      whatever the last branch happened to be.
    """
    judge = config if config is not None else JudgeConfig()
    confidence_threshold = (
        DEFAULT_CONFIDENCE_THRESHOLD
        if judge.confidence_threshold is None
        else judge.confidence_threshold
    )
    escalation_threshold = (
        DEFAULT_ESCALATION_THRESHOLD
        if judge.escalation_threshold is None
        else judge.escalation_threshold
    )

    if math.isnan(result.confidence) or result.confidence < 0.0 or result.confidence > 1.0:
        return JudgeDisposition.escalate

    if escalation_threshold > confidence_threshold:
        return JudgeDisposition.escalate

    if result.confidence < escalation_threshold:
        return JudgeDisposition.escalate

    if result.confidence < confidence_threshold:
        return JudgeDisposition.escalate

    return JudgeDisposition.allow if result.aligned else JudgeDisposition.block


def _enabled_judge(
    policy: EffectivePolicy,
) -> tuple[PurposeProfile, JudgeConfig] | None:
    """The profile and judge config when this policy asks for a judge, else ``None``.

    One place that answers "is there a judge, and which one", so the callers below
    need no ``assert`` to convince themselves both objects are present. An ``assert``
    would be a branch no test can take the other side of, which is the shape of
    coverage that reads as verified and is not.

    Checked against ``is True`` rather than for truthiness, because
    ``JudgeConfig.enabled`` is ``None``-able: absent means "not configured", which is
    not the same statement as an explicit ``False`` even though both mean no judge
    today.
    """
    profile = policy.purpose_profile
    if profile is None or profile.judge is None or profile.judge.enabled is not True:
        return None
    return profile, profile.judge


def judge_enabled(policy: EffectivePolicy) -> bool:
    """Whether this policy asks for a judge at all."""
    return _enabled_judge(policy) is not None


def judge_history_window(policy: EffectivePolicy) -> int:
    """How many preceding calls the policy wants the judge to see.

    Read this to size a :class:`~tolap_core.history.ToolCallHistory`, so the window is
    the policy author's choice rather than the integrator's default. A window smaller
    than the policy asked for hides exactly the trajectory the judge was enabled to
    notice.
    """
    profile = policy.purpose_profile
    if profile is None or profile.judge is None or profile.judge.history_window is None:
        return DEFAULT_HISTORY_WINDOW
    return profile.judge.history_window


def build_judge_request(
    policy: EffectivePolicy,
    current_tool_call: str,
    history: ToolCallHistory | None = None,
) -> JudgeRequest | None:
    """Build the request for a call, from the policy's judge configuration.

    Returns ``None`` when this policy has no judge enabled -- in which case there is
    nothing to ask and the deterministic decision stands.

    The latency budget comes from the policy rather than from the caller, which is the
    whole point: ``max_latency_ms`` is a policy field and a caller passing its own
    value would make it advisory.
    """
    if current_tool_call is None:
        raise ValueError("current_tool_call must be a string, not None")

    enabled = _enabled_judge(policy)
    if enabled is None:
        return None

    profile, config = enabled
    return _request_for(profile, config, current_tool_call, history)


def _request_for(
    profile: PurposeProfile,
    config: JudgeConfig,
    current_tool_call: str,
    history: ToolCallHistory | None,
) -> JudgeRequest:
    """Assemble a request from a profile and its (present) judge configuration."""
    # Trimmed to the policy's window even when the caller's history is larger, so an
    # oversized buffer cannot quietly widen what the policy chose to send. Trimmed to
    # the MOST RECENT entries: a window of three means the last three calls.
    window = (
        DEFAULT_HISTORY_WINDOW
        if config.history_window is None
        else config.history_window
    )
    recent = history.get_recent() if history is not None else []
    if len(recent) > window:
        recent = recent[-window:]

    return JudgeRequest(
        purpose=profile,
        current_tool_call=current_tool_call,
        recent_history=recent,
        max_latency_ms=(
            DEFAULT_MAX_LATENCY_MS
            if config.max_latency_ms is None
            else config.max_latency_ms
        ),
    )


def evaluate_judge(
    policy: EffectivePolicy,
    judge: Judge,
    current_tool_call: str,
    history: ToolCallHistory | None = None,
) -> JudgeOutcome:
    """Run the judge for a call and map the verdict to a disposition and a reason.

    A policy with no judge enabled yields an allow without the judge being invoked, and
    with ``result=None`` -- so it is safe to call unconditionally. Otherwise
    ``judge.model_id`` is verified against the policy's ``model`` **before** the call:
    invoking the wrong model and then noticing would have spent the tokens and, worse,
    produced a verdict that reads as authoritative in an audit log.

    :attr:`JudgeDisposition.escalate` is **not** an allow, which is why the return value
    carries :attr:`JudgeOutcome.allowed` rather than leaving each caller to remember.
    """
    if judge is None:
        raise ValueError("evaluate_judge needs a judge; None is not a decision")
    if current_tool_call is None:
        raise ValueError("current_tool_call must be a string, not None")

    enabled = _enabled_judge(policy)
    if enabled is None:
        return JudgeOutcome(
            disposition=JudgeDisposition.allow, reason=NO_JUDGE_CONFIGURED_REASON
        )

    profile, config = enabled

    if not _model_matches(config.model, judge.model_id):
        # Named in full, so an operator reads the fault rather than inferring it. The
        # contract token stays a prefix, so `reason.startswith(JUDGE_MODEL_MISMATCH_REASON)`
        # keeps working for an integrator branching on it. `result` stays None: no model was
        # consulted, and an audit trail must be able to tell that from an uncertain verdict.
        return JudgeOutcome(
            disposition=JudgeDisposition.escalate,
            reason=(
                f"{JUDGE_MODEL_MISMATCH_REASON}: policy requires {config.model!r}, "
                f"judge is {judge.model_id!r}"
            ),
        )

    request = _request_for(profile, config, current_tool_call, history)

    try:
        result = judge.evaluate(request)
    except Exception as exc:  # noqa: BLE001 -- deliberately broad; see JUDGE_FAILED_REASON
        # `Judge` is a public ABC, so the exception taxonomy is whatever an implementation
        # happens to raise, and every one of them means the same thing here: no verdict.
        # `result` stays absent, because none was obtained.
        return JudgeOutcome(
            disposition=JudgeDisposition.escalate,
            reason=f"{JUDGE_FAILED_REASON}: {type(exc).__name__}",
        )

    disposition = judge_disposition(result, config)

    return JudgeOutcome(
        disposition=disposition,
        # The judge's own words become the reason on every disposition, so an allow records
        # why the model approved rather than leaving a reviewer to reach into `result`. An
        # audit trail reading a borderline approval wants the view, not just the verdict.
        reason=result.reasoning,
        result=result,
    )


def _model_matches(configured: str | None, actual: str) -> bool:
    """Whether the judge in hand is the one the policy asked for.

    A policy naming no model accepts any judge: the field is optional, and requiring
    it would make every judge-enabled policy fail until someone pinned a model id that
    differs per account and region.

    When a policy does name one, the comparison is case-sensitive and exact. Not a
    prefix or substring match: ``claude-sonnet`` and ``claude-sonnet-5`` are different
    models, and a prefix rule would let a deployment satisfy a policy demanding one by
    wiring the other. This mirrors the ``purpose_id`` comparison -- an identifier is
    matched, not a pattern.
    """
    return configured is None or configured == actual
