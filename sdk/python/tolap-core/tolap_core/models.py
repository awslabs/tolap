from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from tolap_core.enums import (
    AssigneeType,
    FilterOperator,
    MaskType,
    PrincipalType,
    SigningAlgorithm,
)


# -- Policy Definition models --


@dataclass
class MaskingParameters:
    show_first: int | None = None
    show_last: int | None = None
    mask_char: str | None = None
    algorithm: str | None = None


@dataclass
class MaskingRule:
    field: str
    mask_type: MaskType
    parameters: MaskingParameters | None = None


@dataclass
class RowFilter:
    field: str
    operator: FilterOperator
    value: Any | None = None
    values: list[Any] | None = None


@dataclass
class FieldRules:
    allowed_fields: list[str] | None = None
    hidden_fields: list[str] | None = None
    masked_fields: list[MaskingRule] | None = None
    read_only_fields: list[str] | None = None


@dataclass
class TagRules:
    allowed_tags: list[str] | None = None
    denied_tags: list[str] | None = None


@dataclass
class EndpointRules:
    allowed_endpoints: list[str] | None = None
    hidden_endpoints: list[str] | None = None
    allowed_methods: list[str] | None = None


@dataclass
class PolicyLimits:
    max_results: int | None = None
    min_similarity_score: float | None = None
    max_object_size_bytes: int | None = None


@dataclass
class JudgeConfig:
    """Configuration for the optional semantic judge (spec section 15.4).

    Every field is ``None``-defaulted and the documented defaults are applied when
    the value is *read* rather than when the object is built. A non-None default
    would serialize unconditionally -- ``serialize`` omits only ``None`` -- and so
    would change the canonical bytes of every purpose-bound policy.

    ``escalation_threshold`` must not exceed ``confidence_threshold``; an inverted
    pair escalates rather than guessing which bound was meant (see
    :func:`tolap_core.judge.judge_disposition`).
    """

    enabled: bool | None = None
    model: str | None = None
    history_window: int | None = None
    confidence_threshold: float | None = None
    escalation_threshold: float | None = None
    max_latency_ms: int | None = None


@dataclass
class PurposeProfile:
    """Binds a policy to a declared purpose (spec section 15).

    Present on a :class:`PolicyDefinition` it scopes resolution: the policy only
    resolves for a caller declaring a matching ``purpose_id``. It is carried through
    the merge onto the :class:`EffectivePolicy` because enforcement only ever sees an
    effective policy -- without that, the profile would be authorable and
    unenforceable. Carrying it on the policy also puts the purpose inside the signed
    bytes for free, since the policy is already part of the signed ``policies[]``.

    ``purpose_id`` is matched against the caller's declared purpose exactly and
    case-sensitively, so a mis-cased purpose resolves nothing rather than resolving
    something adjacent.

    ``allowed_actions`` follows the null-versus-empty rule in spec section 3:
    ``None`` is unrestricted, an empty list denies every action.
    ``prohibited_actions`` takes precedence over ``allowed_actions``: a category in
    both is denied.
    """

    purpose_id: str
    description: str | None = None
    allowed_actions: list[str] | None = None
    prohibited_actions: list[str] | None = None
    judge: JudgeConfig | None = None


@dataclass
class DelegationHop:
    """One hop in a delegation chain, from human to agent to sub-agent (section 15.3).

    ``scope_narrowing`` lists the scopes still **in force** at this hop -- not the
    scopes this hop removed. Each hop's set must be a subset of its parent's, so an
    empty set leaves nothing for a child to claim.

    ``delegated_at`` is part of the signed bytes when present, and is therefore
    truncated to milliseconds by the canonical projection like every other timestamp:
    the three runtimes do not agree below that (spec section 2 rule 5).

    It is carried as an RFC 3339 string, like every other timestamp on these models
    (``EffectivePolicy.resolved_at``, ``SecurityContext.issued_at``,
    ``PolicyAssignment.expires_at``). A :class:`~datetime.datetime` is also accepted and
    converted on construction, because that is the obvious thing to pass and the
    alternative -- storing it verbatim -- fails later, at ``json.dumps`` inside signing,
    where the traceback names neither this field nor the caller who set it.
    """

    principal_id: str
    principal_type: PrincipalType
    declared_purpose: str | None = None
    delegated_at: str | datetime | None = None
    scope_narrowing: list[str] | None = None

    def __post_init__(self) -> None:
        # Normalized to the same spelling ``build_security_context`` uses for the
        # envelope's own instants, so one hop built from a datetime and another from a
        # string cannot disagree about how the same moment is written -- and therefore
        # cannot sign differently.
        if isinstance(self.delegated_at, datetime):
            self.delegated_at = self.delegated_at.isoformat().replace("+00:00", "Z")


@dataclass
class ObjectRules:
    allowed_objects: list[str] | None = None
    hidden_objects: list[str] | None = None
    field_rules: FieldRules | None = None
    row_filters: list[RowFilter] | None = None
    tag_rules: TagRules | None = None
    endpoint_rules: EndpointRules | None = None


@dataclass
class PolicyPermissions:
    """Top-level permission flags.

    The three write permissions default to ``None``, which the merger and the
    write-validation path both read as the schema default of **False**. That is
    deliberately the opposite of ``can_query``'s ``True`` default: a policy
    authored before writes existed must not silently gain them, and an author who
    omitted a write permission has not asked for write access (connector spec
    section 4.1).
    """

    can_query: bool = False
    can_insert: bool | None = None
    can_update: bool | None = None
    can_delete: bool | None = None
    read_only: bool | None = None


@dataclass
class PolicyDefinition:
    version: str
    name: str
    permissions: PolicyPermissions
    description: str | None = None
    priority: int | None = None
    applies_to_all: bool | None = None
    source_patterns: list[str] | None = None
    object_rules: ObjectRules | None = None
    limits: PolicyLimits | None = None
    # Appended after `limits` rather than inserted, so every existing positional
    # construction keeps compiling and keeps meaning what it did.
    purpose_profile: PurposeProfile | None = None


# -- Policy Assignment models --


@dataclass
class Assignee:
    type: AssigneeType
    identifier: str


@dataclass
class AssignmentScope:
    tenant_id: str | None = None
    source_connection_id: str | None = None


@dataclass
class AuditInfo:
    granted_by: str
    granted_at: str
    reason: str


@dataclass
class PolicyAssignment:
    version: str
    policy_name: str
    assignee: Assignee
    scope: AssignmentScope
    active: bool
    audit: AuditInfo
    expires_at: str | None = None
    # Revocation tombstone (spec section 12). Set means the grant no longer
    # resolves while remaining visible to auditors; it is deliberately separate
    # from `active` so that un-setting `active` cannot be confused with revoking.
    revoked_at: str | None = None


# -- Effective Policy models --


@dataclass
class IntegrityBlock:
    algorithm: SigningAlgorithm
    signature: str


@dataclass
class EffectivePolicy:
    version: str = "1.0"
    user_id: str | None = None
    tenant_id: str | None = None
    source_connection_id: str | None = None
    resolved_at: str | None = None
    expires_at: str | None = None
    source_profiles: list[str] = field(default_factory=list)
    permissions: PolicyPermissions = field(default_factory=lambda: PolicyPermissions(can_query=False))
    object_rules: ObjectRules | None = None
    limits: PolicyLimits | None = None
    integrity: IntegrityBlock | None = None
    # Carried here by the merger because every enforcement entry point takes an
    # EffectivePolicy. A profile readable only on a definition would be authorable
    # and unenforceable (spec section 15.2).
    purpose_profile: PurposeProfile | None = None

    @classmethod
    def deny_all(cls) -> EffectivePolicy:
        return cls(
            version="1.0",
            source_profiles=[],
            # The three write permissions are deliberately left absent rather than
            # written as False. Absent already *means* False on the write path
            # (connector spec section 4.1), and ``read_only=True`` is a ceiling that
            # denies every write regardless -- so a deny-all policy denies writes
            # twice over without carrying three redundant keys into the signed bytes.
            permissions=PolicyPermissions(
                can_query=False,
                read_only=True,
            ),
        )


# -- Security Context --


@dataclass
class SecurityContext:
    effective_policy: EffectivePolicy
    issued_at: str | None = None
    expires_at: str | None = None
    signature: str | None = None
    algorithm: SigningAlgorithm | None = None
    # Unique context identifier for replay detection (spec section 13). Signed
    # when present, so it cannot be stripped or swapped without invalidating the
    # signature. Optional for backward compatibility: a context without a `jti`
    # produces the same canonical bytes it did before this field existed.
    jti: str | None = None
    # The purpose this context was resolved for (spec section 15). Signed when
    # present, so it cannot be swapped for a different purpose or stripped to escape
    # a purpose-scoped policy. Omitted from the canonical payload entirely when
    # absent or empty, so a context without a declared purpose signs to exactly the
    # bytes it did before this field existed. It records the purpose the caller
    # *asserted* at resolution; TOLAP checks that assertion against the policy set,
    # not the caller's honesty about it.
    declared_purpose: str | None = None
    # The chain of principals this authority passed through, oldest hop first.
    # Signed when present, hop for hop: mutating, reordering, or removing a hop
    # invalidates the signature, which is what makes
    # :func:`tolap_core.delegation.validate_delegation_chain` worth running at all.
    delegation_chain: list[DelegationHop] | None = None
