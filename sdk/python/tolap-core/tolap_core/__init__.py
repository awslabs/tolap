"""TOLAP Core - Models, merge algorithm, signing, and enforcement."""

from tolap_core.enums import AssigneeType, FilterOperator, MaskType, SigningAlgorithm
from tolap_core.models import (
    Assignee,
    AssignmentScope,
    AuditInfo,
    EffectivePolicy,
    EndpointRules,
    FieldRules,
    IntegrityBlock,
    MaskingParameters,
    MaskingRule,
    ObjectRules,
    PolicyAssignment,
    PolicyDefinition,
    PolicyLimits,
    PolicyPermissions,
    RowFilter,
    SecurityContext,
    TagRules,
)
from tolap_core.serialization import (
    deserialize_effective_policy,
    deserialize_policy_assignment,
    deserialize_policy_definition,
    serialize,
)
from tolap_core.merger import merge
from tolap_core.resolution import resolve
from tolap_core.context import (
    build_security_context,
    deserialize_context,
    serialize_context,
    sign_context,
    validate_context,
)
from tolap_core.enforcement import (
    AccessResult,
    FieldAccessResult,
    apply_field_masking,
    apply_result_limit,
    filter_by_tags,
    validate_access,
    validate_endpoint,
    validate_field_access,
)

__all__ = [
    # Enums
    "AssigneeType",
    "FilterOperator",
    "MaskType",
    "SigningAlgorithm",
    # Models
    "Assignee",
    "AssignmentScope",
    "AuditInfo",
    "EffectivePolicy",
    "EndpointRules",
    "FieldRules",
    "IntegrityBlock",
    "MaskingParameters",
    "MaskingRule",
    "ObjectRules",
    "PolicyAssignment",
    "PolicyDefinition",
    "PolicyLimits",
    "PolicyPermissions",
    "RowFilter",
    "SecurityContext",
    "TagRules",
    # Serialization
    "deserialize_effective_policy",
    "deserialize_policy_assignment",
    "deserialize_policy_definition",
    "serialize",
    # Merger
    "merge",
    # Resolution
    "resolve",
    # Context / Signing
    "build_security_context",
    "deserialize_context",
    "serialize_context",
    "sign_context",
    "validate_context",
    # Enforcement
    "AccessResult",
    "FieldAccessResult",
    "apply_field_masking",
    "apply_result_limit",
    "filter_by_tags",
    "validate_access",
    "validate_endpoint",
    "validate_field_access",
]
