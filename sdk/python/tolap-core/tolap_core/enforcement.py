from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from fnmatch import fnmatch

from tolap_core.enums import FilterOperator, MaskType
from tolap_core.models import EffectivePolicy, MaskingRule, RowFilter


@dataclass
class AccessResult:
    allowed: bool
    reason: str | None = None


@dataclass
class FieldAccessResult:
    allowed: list[str] = field(default_factory=list)
    denied: list[str] = field(default_factory=list)


def validate_access(object_name: str, policy: EffectivePolicy) -> AccessResult:
    """Validate whether access to a named object is permitted by the policy."""
    if not policy.permissions.can_query:
        return AccessResult(allowed=False, reason="query not permitted")

    obj_rules = policy.object_rules
    if obj_rules is None:
        return AccessResult(allowed=True)

    # Check hidden objects first (hidden takes precedence)
    if obj_rules.hidden_objects:
        for pattern in obj_rules.hidden_objects:
            if fnmatch(object_name, pattern):
                return AccessResult(allowed=False, reason="object is hidden")

    # Check allowed objects (if specified, object must be in the set)
    if obj_rules.allowed_objects is not None:
        for pattern in obj_rules.allowed_objects:
            if fnmatch(object_name, pattern):
                return AccessResult(allowed=True)
        return AccessResult(allowed=False, reason="object not in allowed set")

    return AccessResult(allowed=True)


def validate_field_access(fields: list[str], policy: EffectivePolicy) -> FieldAccessResult:
    """Validate which fields are accessible under the policy."""
    result = FieldAccessResult()
    field_rules = None
    if policy.object_rules and policy.object_rules.field_rules:
        field_rules = policy.object_rules.field_rules

    for f in fields:
        denied = False

        # Check hidden fields first (takes precedence)
        if field_rules and field_rules.hidden_fields:
            for pattern in field_rules.hidden_fields:
                if fnmatch(f, pattern):
                    denied = True
                    break

        if denied:
            result.denied.append(f)
            continue

        # Check allowed fields (if specified, field must be in the set)
        if field_rules and field_rules.allowed_fields is not None:
            allowed = False
            for pattern in field_rules.allowed_fields:
                if fnmatch(f, pattern):
                    allowed = True
                    break
            if not allowed:
                result.denied.append(f)
                continue

        result.allowed.append(f)

    return result


def _apply_mask(value: str | None, rule: MaskingRule) -> str | None:
    """Apply a masking rule to a field value."""
    if value is None:
        return None

    str_value = str(value)
    mask_char = "*"
    if rule.parameters and rule.parameters.mask_char:
        mask_char = rule.parameters.mask_char

    match rule.mask_type:
        case MaskType.full:
            return mask_char * len(str_value)

        case MaskType.partial:
            show_first = rule.parameters.show_first if rule.parameters and rule.parameters.show_first is not None else 0
            show_last = rule.parameters.show_last if rule.parameters and rule.parameters.show_last is not None else 0
            total = len(str_value)

            if show_first + show_last >= total:
                return str_value

            masked_count = total - show_first - show_last
            prefix = str_value[:show_first] if show_first > 0 else ""
            suffix = str_value[-show_last:] if show_last > 0 else ""
            return prefix + (mask_char * masked_count) + suffix

        case MaskType.hash:
            digest = hashlib.sha256(str_value.encode("utf-8")).hexdigest()[:16]
            return digest

        case MaskType.null:
            return None

        case MaskType.redact:
            return "[REDACTED]"

    return str_value


def apply_field_masking(record: dict, policy: EffectivePolicy) -> dict:
    """Apply field masking rules to a record."""
    if not policy.object_rules or not policy.object_rules.field_rules:
        return dict(record)
    if not policy.object_rules.field_rules.masked_fields:
        return dict(record)

    result = dict(record)
    for rule in policy.object_rules.field_rules.masked_fields:
        # Support both "field" and "object.field" notation
        field_name = rule.field
        # Check for dot notation: use the last segment for record matching
        if "." in field_name:
            parts = field_name.split(".", 1)
            field_name = parts[1]

        if field_name in result:
            result[field_name] = _apply_mask(result[field_name], rule)

    return result


def apply_result_limit(results: list, policy: EffectivePolicy) -> list:
    """Apply the maxResults limit to a result set."""
    if policy.limits and policy.limits.max_results is not None:
        return results[: policy.limits.max_results]
    return results


def _row_field_value(row: dict, field_name: str) -> object:
    # Filters use either bare names ("region") or dotted paths
    # ("patients.region"); we accept both and prefer the unqualified key when
    # rows have already been projected by the tool function.
    if field_name in row:
        return row[field_name]
    if "." in field_name:
        leaf = field_name.split(".", 1)[1]
        return row.get(leaf)
    return None


def _row_passes_filter(row: dict, rf: RowFilter) -> bool:
    value = _row_field_value(row, rf.field)

    op = rf.operator
    if op is FilterOperator.equals:
        return value == rf.value
    if op is FilterOperator.not_equals:
        return value != rf.value
    if op is FilterOperator.in_:
        return value in (rf.values or [])
    if op is FilterOperator.not_in:
        return value not in (rf.values or [])
    if op is FilterOperator.greater_than:
        return value is not None and rf.value is not None and value > rf.value
    if op is FilterOperator.less_than:
        return value is not None and rf.value is not None and value < rf.value
    if op is FilterOperator.contains:
        return value is not None and rf.value is not None and str(rf.value) in str(value)
    if op is FilterOperator.starts_with:
        return value is not None and rf.value is not None and str(value).startswith(str(rf.value))
    if op is FilterOperator.matches:
        if value is None or rf.value is None:
            return False
        try:
            return re.fullmatch(str(rf.value), str(value)) is not None
        except re.error:
            return False
    return False


def apply_row_filters(results: list[dict], policy: EffectivePolicy) -> list[dict]:
    """Drop rows that fail any policy row filter (filters AND together).

    Most-restrictive-wins: a row must satisfy every filter to be kept. Rows that
    are missing the referenced field fail closed (they are dropped) — the
    policy author asked for a constraint and we cannot prove it holds.
    """
    if not policy.object_rules or not policy.object_rules.row_filters:
        return results

    filters = policy.object_rules.row_filters
    return [row for row in results if all(_row_passes_filter(row, rf) for rf in filters)]


def filter_by_tags(results: list[dict], policy: EffectivePolicy) -> list[dict]:
    """Filter results by tag rules.

    - If allowedTags is set, only include results with at least one allowed tag.
    - If deniedTags is set, exclude results with any denied tag.
    - Denied takes precedence over allowed.
    """
    if not policy.object_rules or not policy.object_rules.tag_rules:
        return results

    tag_rules = policy.object_rules.tag_rules
    allowed_tags = set(tag_rules.allowed_tags) if tag_rules.allowed_tags else None
    denied_tags = set(tag_rules.denied_tags) if tag_rules.denied_tags else None

    filtered: list[dict] = []
    for item in results:
        tags = set(item.get("tags", []))

        # Check denied tags first (takes precedence)
        if denied_tags and tags & denied_tags:
            continue

        # Check allowed tags
        if allowed_tags is not None and not (tags & allowed_tags):
            continue

        filtered.append(item)

    return filtered


def validate_endpoint(path: str, method: str, policy: EffectivePolicy) -> AccessResult:
    """Validate access to an API endpoint."""
    if not policy.permissions.can_query:
        return AccessResult(allowed=False, reason="query not permitted")

    if not policy.object_rules or not policy.object_rules.endpoint_rules:
        return AccessResult(allowed=True)

    rules = policy.object_rules.endpoint_rules

    # Check hidden endpoints first (takes precedence)
    if rules.hidden_endpoints:
        for pattern in rules.hidden_endpoints:
            if fnmatch(path, pattern):
                return AccessResult(allowed=False, reason="endpoint is hidden")

    # Check allowed endpoints
    if rules.allowed_endpoints is not None:
        matched = False
        for pattern in rules.allowed_endpoints:
            if fnmatch(path, pattern):
                matched = True
                break
        if not matched:
            return AccessResult(allowed=False, reason="endpoint not in allowed set")

    # Check allowed methods
    if rules.allowed_methods is not None:
        if method.upper() not in [m.upper() for m in rules.allowed_methods]:
            return AccessResult(allowed=False, reason="method not allowed")

    return AccessResult(allowed=True)
