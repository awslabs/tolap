from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from tolap_core.enums import AssigneeType, FilterOperator, MaskType, SigningAlgorithm


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
