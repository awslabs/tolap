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
    max_query_time_seconds: int | None = None
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
    can_query: bool = False
    can_export: bool | None = None
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
            permissions=PolicyPermissions(
                can_query=False,
                can_export=False,
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
