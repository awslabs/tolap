from __future__ import annotations

from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:  # pragma: no cover - typing only
    from tolap_core.history import ToolCallHistory
    from tolap_core.judge import Judge, JudgeOutcome

from dataclasses import dataclass, field

from tolap_core.enums import SigningAlgorithm


@dataclass
class SecureMcpServerOptions:
    """Configuration options for the secure MCP tool wrapper."""

    signing_key: str
    signing_algorithm: SigningAlgorithm = SigningAlgorithm.hmac_sha256
    enforce_signatures: bool = True
    enforce_expiry: bool = True
    allowed_tools: list[str] = field(default_factory=list)
    hash_salt: str | bytes | None = None
    """Secret salt for ``hash`` masking, turning the digest into a keyed HMAC.

    Unset by default, which preserves the plain-digest pseudonym (and so existing
    join keys). Set it and ``hash`` becomes a confidentiality control: an unsalted
    digest of a low-entropy value -- an SSN, a date of birth, a small enumeration
    -- is recoverable by brute force or a rainbow table, because the input space is
    small enough to enumerate.

    Treat it as a secret on a par with ``signing_key``: store it in a secrets
    manager or KMS, never in the policy JSON (policies are visible to every admin
    and auditor who can read them). The same salt must be configured everywhere the
    pseudonym is joined, since changing it changes every masked value.
    """
    allow_unenforceable_shapes: bool = False
    """Pass through tool results the policy cannot be applied to.

    Off by default: a scalar, ``None``, a generator, or an arbitrary object is
    denied rather than returned unfiltered. Integrators mid-migration may opt in
    per wrapper, which is logged at WARNING every time it lets a result through.
    """
    tool_action_categories: dict[str, str] | None = None
    """Tool name to semantic action category, for purpose-bound action validation.

    Read by :class:`~tolap_mcp.SecureMcpToolWrapper` (canonical-enforcement-spec.md
    section 15.2). Set this alongside ``allowed_tools`` whenever any policy the wrapper
    may resolve carries a ``purposeProfile`` that constrains actions.

    Configuration rather than a caller argument, deliberately: an agent that can name
    its own action category can name a permitted one, which reduces the check to a
    formality. Unset, a purpose-agnostic policy behaves exactly as before -- and a
    purpose-bound one that constrains actions denies every call, because a tool the map
    does not classify cannot be shown to serve the purpose.

    Matched exactly and case-sensitively, as ``allowed_tools`` is: a tool name is an
    identifier, not a pattern.
    """
    http_action_categories: dict[str, str] | None = None
    """``"METHOD path-glob"`` to semantic action category, for the HTTP wrapper.

    Read by :class:`~tolap_mcp.SecureHttpToolWrapper` -- for example
    ``{"GET /segments/*": "aggregate_overlap"}``.

    Keyed by method and path rather than by tool name because an HTTP request has no
    tool name: ``request()`` takes a method and a path. A name-keyed map would leave
    this enforcement point permanently inert for API sources, which is worse than
    having none -- the configuration would imply a control that never ran. The path
    uses the same glob dialect as ``allowedEndpoints``, so a deployment writes one kind
    of endpoint pattern.

    Consulted on every redirect hop, like every other rule there: a 307 to
    ``/export/all.csv`` is a different action from the ``GET`` that started the chain.
    """

    judge: "Judge | None" = None
    """The semantic judge, enabling ``pre_execute`` to apply a policy's ``purposeProfile.judge``
    block (spec section 15.4).

    Unset, ``pre_execute`` behaves exactly as before -- a policy that asks for a judge with none
    configured is **not** an error, because the deterministic checks have already run and the
    judge can only subtract. Set it and the policy's ``model``, ``history_window``, thresholds
    and ``max_latency_ms`` take effect without any glue of yours; a mismatch between the
    policy's model and ``judge.model_id`` escalates before the call is issued.

    Wired into ``pre_execute`` itself rather than a separate async entry point, unlike .NET and
    TypeScript: :meth:`Judge.evaluate` is synchronous here, so there is nothing to await and a
    second method would differ from this one only in name.
    """

    tool_call_history: "ToolCallHistory | None" = None
    """The trajectory the judge reasons over.

    **You** own the instance, and therefore its retention: tool calls can carry the arguments a
    caller passed, so how long they live and where they are stored is a decision the wrapper
    must not make for you. Trimmed to the policy's ``history_window`` on each call regardless of
    how large it grows.

    Unset, the judge sees only the current call -- enough for an obviously off-purpose request,
    and not enough for drift, where each step is individually defensible and the sequence is
    not.
    """

    escalation_handler: "Callable[[JudgeOutcome], bool] | None" = None
    """Where an ambiguous verdict goes for review. Returns whether the call may proceed.

    Unset, ``escalate`` is a **denial**. That is the point of the disposition: if escalation
    defaulted to permitting, "escalate to human review" would silently mean "allow" in every
    deployment that never built a review path -- a fail-open on exactly the cases the judge
    exists to surface.
    """
