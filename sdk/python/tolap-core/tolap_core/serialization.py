from __future__ import annotations

import json
import re
from dataclasses import asdict, fields, is_dataclass
from enum import Enum
from typing import Any

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
    TagRules,
)


def _snake_to_camel(name: str) -> str:
    """Convert snake_case to camelCase."""
    parts = name.split("_")
    return parts[0] + "".join(p.capitalize() for p in parts[1:])


def _camel_to_snake(name: str) -> str:
    """Convert camelCase to snake_case."""
    result = re.sub(r"([A-Z])", r"_\1", name).lower()
    return result


def _convert_keys_to_camel(obj: Any) -> Any:
    """Recursively convert dict keys from snake_case to camelCase."""
    if isinstance(obj, dict):
        return {_snake_to_camel(k): _convert_keys_to_camel(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_convert_keys_to_camel(item) for item in obj]
    return obj


def _convert_keys_to_snake(obj: Any) -> Any:
    """Recursively convert dict keys from camelCase to snake_case."""
    if isinstance(obj, dict):
        return {_camel_to_snake(k): _convert_keys_to_snake(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_convert_keys_to_snake(item) for item in obj]
    return obj


def _strip_none(obj: Any) -> Any:
    """Recursively strip None values from dicts."""
    if isinstance(obj, dict):
        return {k: _strip_none(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [_strip_none(item) for item in obj]
    return obj


def _dataclass_to_dict(obj: Any) -> Any:
    """Convert a dataclass to a dict, handling enums."""
    if isinstance(obj, Enum):
        return obj.value
    if is_dataclass(obj) and not isinstance(obj, type):
        result = {}
        for f in fields(obj):
            value = getattr(obj, f.name)
            if value is not None:
                result[f.name] = _dataclass_to_dict(value)
        return result
    if isinstance(obj, list):
        return [_dataclass_to_dict(item) for item in obj]
    if isinstance(obj, dict):
        return {k: _dataclass_to_dict(v) for k, v in obj.items()}
    return obj


def serialize(obj: Any) -> str:
    """Serialize a dataclass to JSON with camelCase keys and None values omitted."""
    raw = _dataclass_to_dict(obj)
    camel = _convert_keys_to_camel(raw)
    return json.dumps(camel, separators=(",", ":"), sort_keys=False)


def _parse_input(data: dict | str) -> dict:
    """Accept dict or JSON string, return dict."""
    if isinstance(data, str):
        return json.loads(data)
    return data


# -- Enum lookup helpers --

_MASK_TYPE_MAP: dict[str, MaskType] = {m.value: m for m in MaskType}
_FILTER_OP_MAP: dict[str, FilterOperator] = {f.value: f for f in FilterOperator}
_ASSIGNEE_TYPE_MAP: dict[str, AssigneeType] = {a.value: a for a in AssigneeType}
_SIGNING_ALG_MAP: dict[str, SigningAlgorithm] = {s.value: s for s in SigningAlgorithm}


# -- Deserialization helpers --


def _deser_masking_parameters(data: dict | None) -> MaskingParameters | None:
    if data is None:
        return None
    d = _convert_keys_to_snake(data)
    return MaskingParameters(
        show_first=d.get("show_first"),
        show_last=d.get("show_last"),
        mask_char=d.get("mask_char"),
        algorithm=d.get("algorithm"),
    )


def _deser_masking_rule(data: dict) -> MaskingRule:
    d = _convert_keys_to_snake(data)
    raw_mask_type = d["mask_type"]
    if raw_mask_type not in _MASK_TYPE_MAP:
        # Fail closed at the boundary rather than admitting a rule whose
        # semantics we cannot honour. The runtime masking path also fails closed
        # on an unknown type (it redacts), but a policy should never load with a
        # mask type this SDK does not implement.
        valid = ", ".join(sorted(_MASK_TYPE_MAP))
        raise ValueError(
            f"unknown maskType {raw_mask_type!r} for field {d.get('field')!r}; expected one of: {valid}"
        )
    return MaskingRule(
        field=d["field"],
        mask_type=_MASK_TYPE_MAP[raw_mask_type],
        parameters=_deser_masking_parameters(d.get("parameters")),
    )


def _deser_row_filter(data: dict) -> RowFilter:
    d = _convert_keys_to_snake(data)
    return RowFilter(
        field=d["field"],
        operator=_FILTER_OP_MAP[d["operator"]],
        value=d.get("value"),
        values=d.get("values"),
    )


def _deser_field_rules(data: dict | None) -> FieldRules | None:
    if data is None:
        return None
    d = _convert_keys_to_snake(data)
    return FieldRules(
        allowed_fields=d.get("allowed_fields"),
        hidden_fields=d.get("hidden_fields"),
        masked_fields=[_deser_masking_rule(m) for m in d["masked_fields"]] if d.get("masked_fields") else None,
        read_only_fields=d.get("read_only_fields"),
    )


def _deser_tag_rules(data: dict | None) -> TagRules | None:
    if data is None:
        return None
    d = _convert_keys_to_snake(data)
    return TagRules(
        allowed_tags=d.get("allowed_tags"),
        denied_tags=d.get("denied_tags"),
    )


def _deser_endpoint_rules(data: dict | None) -> EndpointRules | None:
    if data is None:
        return None
    d = _convert_keys_to_snake(data)
    return EndpointRules(
        allowed_endpoints=d.get("allowed_endpoints"),
        hidden_endpoints=d.get("hidden_endpoints"),
        allowed_methods=d.get("allowed_methods"),
    )


def _deser_object_rules(data: dict | None) -> ObjectRules | None:
    if data is None:
        return None
    d = _convert_keys_to_snake(data)
    return ObjectRules(
        allowed_objects=d.get("allowed_objects"),
        hidden_objects=d.get("hidden_objects"),
        field_rules=_deser_field_rules(d.get("field_rules")),
        row_filters=[_deser_row_filter(r) for r in d["row_filters"]] if d.get("row_filters") else None,
        tag_rules=_deser_tag_rules(d.get("tag_rules")),
        endpoint_rules=_deser_endpoint_rules(d.get("endpoint_rules")),
    )


def _deser_limits(data: dict | None) -> PolicyLimits | None:
    if data is None:
        return None
    d = _convert_keys_to_snake(data)
    return PolicyLimits(
        max_results=d.get("max_results"),
        max_query_time_seconds=d.get("max_query_time_seconds"),
        min_similarity_score=d.get("min_similarity_score"),
        max_object_size_bytes=d.get("max_object_size_bytes"),
    )


def _deser_permissions(data: dict) -> PolicyPermissions:
    d = _convert_keys_to_snake(data)
    return PolicyPermissions(
        can_query=d.get("can_query", False),
        can_export=d.get("can_export"),
        read_only=d.get("read_only"),
    )


def deserialize_policy_definition(data: dict | str) -> PolicyDefinition:
    """Deserialize a JSON dict or string into a PolicyDefinition."""
    raw = _parse_input(data)
    d = _convert_keys_to_snake(raw)
    return PolicyDefinition(
        version=d["version"],
        name=d["name"],
        permissions=_deser_permissions(d["permissions"]),
        description=d.get("description"),
        priority=d.get("priority"),
        applies_to_all=d.get("applies_to_all"),
        source_patterns=d.get("source_patterns"),
        object_rules=_deser_object_rules(d.get("object_rules")),
        limits=_deser_limits(d.get("limits")),
    )


def _deser_assignee(data: dict) -> Assignee:
    d = _convert_keys_to_snake(data)
    return Assignee(
        type=_ASSIGNEE_TYPE_MAP[d["type"]],
        identifier=d["identifier"],
    )


def _deser_scope(data: dict) -> AssignmentScope:
    d = _convert_keys_to_snake(data)
    return AssignmentScope(
        tenant_id=d.get("tenant_id"),
        source_connection_id=d.get("source_connection_id"),
    )


def _deser_audit(data: dict) -> AuditInfo:
    d = _convert_keys_to_snake(data)
    return AuditInfo(
        granted_by=d["granted_by"],
        granted_at=d["granted_at"],
        reason=d["reason"],
    )


def deserialize_policy_assignment(data: dict | str) -> PolicyAssignment:
    """Deserialize a JSON dict or string into a PolicyAssignment."""
    raw = _parse_input(data)
    d = _convert_keys_to_snake(raw)
    return PolicyAssignment(
        version=d["version"],
        policy_name=d["policy_name"],
        assignee=_deser_assignee(d["assignee"]),
        scope=_deser_scope(d["scope"]),
        active=d["active"],
        audit=_deser_audit(d["audit"]),
        expires_at=d.get("expires_at"),
    )


def _deser_integrity(data: dict | None) -> IntegrityBlock | None:
    if data is None:
        return None
    d = _convert_keys_to_snake(data)
    return IntegrityBlock(
        algorithm=_SIGNING_ALG_MAP[d["algorithm"]],
        signature=d["signature"],
    )


def deserialize_effective_policy(data: dict | str) -> EffectivePolicy:
    """Deserialize a JSON dict or string into an EffectivePolicy."""
    raw = _parse_input(data)
    d = _convert_keys_to_snake(raw)
    return EffectivePolicy(
        version=d.get("version", "1.0"),
        user_id=d.get("user_id"),
        tenant_id=d.get("tenant_id"),
        source_connection_id=d.get("source_connection_id"),
        resolved_at=d.get("resolved_at"),
        expires_at=d.get("expires_at"),
        source_profiles=d.get("source_profiles", []),
        permissions=_deser_permissions(d["permissions"]),
        object_rules=_deser_object_rules(d.get("object_rules")),
        limits=_deser_limits(d.get("limits")),
        integrity=_deser_integrity(d.get("integrity")),
    )
