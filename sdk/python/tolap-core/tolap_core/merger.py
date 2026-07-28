from __future__ import annotations

from tolap_core.enums import MaskType
from tolap_core.models import (
    EffectivePolicy,
    EndpointRules,
    FieldRules,
    MaskingRule,
    ObjectRules,
    PolicyDefinition,
    PolicyLimits,
    PolicyPermissions,
    RowFilter,
    TagRules,
)


def merge(policies: list[PolicyDefinition]) -> EffectivePolicy:
    """Merge multiple PolicyDefinitions into a single EffectivePolicy.

    Merge rules:
    - Empty list -> deny_all()
    - Permissions: AND for can_query/can_export, OR for read_only
    - Allowed sets: Intersection (None means unrestricted from that policy)
    - Hidden/denied sets: Union
    - Row filters: Concatenate
    - Masked fields: Group by field, pick highest restrictiveness
    - Limits: min for maxima, max for minima (None means no limit from that policy)
    """
    if not policies:
        return EffectivePolicy.deny_all()

    source_profiles = [p.name for p in policies]
    permissions = _merge_permissions(policies)
    object_rules = _merge_object_rules(policies)
    limits = _merge_limits(policies)

    return EffectivePolicy(
        version="1.0",
        source_profiles=source_profiles,
        permissions=permissions,
        object_rules=object_rules if _has_object_rules(object_rules) else None,
        limits=limits if _has_limits(limits) else None,
    )


def _merge_permissions(policies: list[PolicyDefinition]) -> PolicyPermissions:
    # AND for can_query and can_export, OR for read_only
    can_query = all(p.permissions.can_query for p in policies)

    # For can_export: AND of all policies that specify it; if none specify it, None
    can_export_values = [p.permissions.can_export for p in policies if p.permissions.can_export is not None]
    can_export: bool | None = all(can_export_values) if can_export_values else None

    # For read_only: OR of all policies that specify it; if none specify it, None
    read_only_values = [p.permissions.read_only for p in policies if p.permissions.read_only is not None]
    read_only: bool | None = any(read_only_values) if read_only_values else None

    return PolicyPermissions(
        can_query=can_query,
        can_export=can_export,
        read_only=read_only,
    )


def _merge_object_rules(policies: list[PolicyDefinition]) -> ObjectRules | None:
    allowed_objects = _intersect_optional_lists([p.object_rules.allowed_objects if p.object_rules else None for p in policies])
    hidden_objects = _union_optional_lists([p.object_rules.hidden_objects if p.object_rules else None for p in policies])
    field_rules = _merge_field_rules(policies)
    row_filters = _merge_row_filters(policies)
    tag_rules = _merge_tag_rules(policies)
    endpoint_rules = _merge_endpoint_rules(policies)

    return ObjectRules(
        allowed_objects=allowed_objects,
        hidden_objects=hidden_objects,
        field_rules=field_rules if _has_field_rules(field_rules) else None,
        row_filters=row_filters if row_filters else None,
        tag_rules=tag_rules if _has_tag_rules(tag_rules) else None,
        endpoint_rules=endpoint_rules if _has_endpoint_rules(endpoint_rules) else None,
    )


def _merge_field_rules(policies: list[PolicyDefinition]) -> FieldRules | None:
    allowed = _intersect_optional_lists([
        p.object_rules.field_rules.allowed_fields
        if p.object_rules and p.object_rules.field_rules else None
        for p in policies
    ])
    hidden = _union_optional_lists([
        p.object_rules.field_rules.hidden_fields
        if p.object_rules and p.object_rules.field_rules else None
        for p in policies
    ])
    masked = _merge_masked_fields(policies)
    read_only = _union_optional_lists([
        p.object_rules.field_rules.read_only_fields
        if p.object_rules and p.object_rules.field_rules else None
        for p in policies
    ])

    return FieldRules(
        allowed_fields=allowed,
        hidden_fields=hidden,
        masked_fields=masked if masked else None,
        read_only_fields=read_only,
    )


def _merge_masked_fields(policies: list[PolicyDefinition]) -> list[MaskingRule] | None:
    # Group by field name, pick highest restrictiveness
    by_field: dict[str, MaskingRule] = {}
    for p in policies:
        if not p.object_rules or not p.object_rules.field_rules or not p.object_rules.field_rules.masked_fields:
            continue
        for rule in p.object_rules.field_rules.masked_fields:
            existing = by_field.get(rule.field)
            if existing is None or rule.mask_type.restrictiveness > existing.mask_type.restrictiveness:
                by_field[rule.field] = rule
    if not by_field:
        return None
    return list(by_field.values())


def _merge_row_filters(policies: list[PolicyDefinition]) -> list[RowFilter] | None:
    result: list[RowFilter] = []
    for p in policies:
        if p.object_rules and p.object_rules.row_filters:
            result.extend(p.object_rules.row_filters)
    return result if result else None


def _merge_tag_rules(policies: list[PolicyDefinition]) -> TagRules | None:
    allowed = _intersect_optional_lists([
        p.object_rules.tag_rules.allowed_tags
        if p.object_rules and p.object_rules.tag_rules else None
        for p in policies
    ])
    denied = _union_optional_lists([
        p.object_rules.tag_rules.denied_tags
        if p.object_rules and p.object_rules.tag_rules else None
        for p in policies
    ])
    return TagRules(allowed_tags=allowed, denied_tags=denied)


def _merge_endpoint_rules(policies: list[PolicyDefinition]) -> EndpointRules | None:
    allowed = _intersect_optional_lists([
        p.object_rules.endpoint_rules.allowed_endpoints
        if p.object_rules and p.object_rules.endpoint_rules else None
        for p in policies
    ])
    hidden = _union_optional_lists([
        p.object_rules.endpoint_rules.hidden_endpoints
        if p.object_rules and p.object_rules.endpoint_rules else None
        for p in policies
    ])
    methods = _intersect_optional_lists([
        p.object_rules.endpoint_rules.allowed_methods
        if p.object_rules and p.object_rules.endpoint_rules else None
        for p in policies
    ])
    return EndpointRules(
        allowed_endpoints=allowed,
        hidden_endpoints=hidden,
        allowed_methods=methods,
    )


def _merge_limits(policies: list[PolicyDefinition]) -> PolicyLimits | None:
    max_results = _min_of_maxima([p.limits.max_results if p.limits else None for p in policies])
    max_query_time = _min_of_maxima([p.limits.max_query_time_seconds if p.limits else None for p in policies])
    min_similarity = _max_of_minima([p.limits.min_similarity_score if p.limits else None for p in policies])
    max_object_size = _min_of_maxima([p.limits.max_object_size_bytes if p.limits else None for p in policies])

    return PolicyLimits(
        max_results=max_results,
        max_query_time_seconds=max_query_time,
        min_similarity_score=min_similarity,
        max_object_size_bytes=max_object_size,
    )


# -- Utility functions --


def _intersect_optional_lists(lists: list[list[str] | None]) -> list[str] | None:
    """Intersection of lists where None means unrestricted (i.e., all allowed)."""
    non_none = [set(lst) for lst in lists if lst is not None]
    if not non_none:
        return None
    result = non_none[0]
    for s in non_none[1:]:
        result = result & s
    # Preserve order from first non-None list
    first_list = next(lst for lst in lists if lst is not None)
    return [item for item in first_list if item in result]


def _union_optional_lists(lists: list[list[str] | None]) -> list[str] | None:
    """Union of lists where None means no items from that policy."""
    result: list[str] = []
    seen: set[str] = set()
    for lst in lists:
        if lst is None:
            continue
        for item in lst:
            if item not in seen:
                seen.add(item)
                result.append(item)
    return result if result else None


def _min_of_maxima(values: list[int | float | None]) -> int | float | None:
    """For maximum limits: take the minimum (most restrictive). None means no limit."""
    non_none = [v for v in values if v is not None]
    return min(non_none) if non_none else None


def _max_of_minima(values: list[int | float | None]) -> float | None:
    """For minimum limits: take the maximum (most restrictive). None means no limit."""
    non_none = [v for v in values if v is not None]
    return max(non_none) if non_none else None


def _has_object_rules(rules: ObjectRules | None) -> bool:
    if rules is None:
        return False
    return any([
        rules.allowed_objects,
        rules.hidden_objects,
        _has_field_rules(rules.field_rules),
        rules.row_filters,
        _has_tag_rules(rules.tag_rules),
        _has_endpoint_rules(rules.endpoint_rules),
    ])


def _has_field_rules(rules: FieldRules | None) -> bool:
    if rules is None:
        return False
    return any([
        rules.allowed_fields,
        rules.hidden_fields,
        rules.masked_fields,
        rules.read_only_fields,
    ])


def _has_tag_rules(rules: TagRules | None) -> bool:
    if rules is None:
        return False
    return any([rules.allowed_tags, rules.denied_tags])


def _has_endpoint_rules(rules: EndpointRules | None) -> bool:
    if rules is None:
        return False
    return any([rules.allowed_endpoints, rules.hidden_endpoints, rules.allowed_methods])


def _has_limits(limits: PolicyLimits | None) -> bool:
    if limits is None:
        return False
    return any([
        limits.max_results is not None,
        limits.max_query_time_seconds is not None,
        limits.min_similarity_score is not None,
        limits.max_object_size_bytes is not None,
    ])
