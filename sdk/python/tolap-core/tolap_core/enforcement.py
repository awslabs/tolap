from __future__ import annotations

import copy
import functools
import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from fnmatch import fnmatch, fnmatchcase
from typing import Any

from tolap_core.enums import FilterOperator, MaskType, mask_restrictiveness
from tolap_core.models import EffectivePolicy, MaskingRule, RowFilter


@dataclass
class AccessResult:
    allowed: bool
    reason: str | None = None


@dataclass
class FieldAccessResult:
    allowed: list[str] = field(default_factory=list)
    denied: list[str] = field(default_factory=list)


class UnenforceableResultError(PermissionError):
    """Raised when a tool result cannot have policy applied to it.

    A subclass of PermissionError so wrappers that already deny on
    PermissionError fail closed without special-casing this type.
    """


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


# -- Field-name matching --
#
# A policy field reference and a record key may each be bare ("ssn") or
# table-qualified ("patients.ssn"), and the two do not have to agree: the rule
# "patients.ssn" must match a key "ssn" and the rule "ssn" must match a key
# "patients.ssn". Matching is case-insensitive and glob patterns are honoured.


def _match_forms(name: str) -> set[str]:
    """Every form a field reference may be compared in, lower-cased.

    Unqualified forms of a qualified name are included so the two sides need not
    agree on qualification. This intentionally lets a table-scoped wildcard such
    as ``patients.*`` match a bare key: rows reaching the pipeline have already
    been projected by the tool, so the qualifier is implied by the result set
    rather than repeated on every key.
    """
    lowered = name.lower()
    forms = {lowered}
    if "." in lowered:
        forms.add(lowered.split(".", 1)[1])  # drop the leading qualifier
        forms.add(lowered.rsplit(".", 1)[1])  # bare leaf
    return forms


def _field_name_matches(rule_field: str, key: str) -> bool:
    """Whether a policy field reference refers to a record key."""
    # fnmatchcase on pre-lowered strings: fnmatch's own case folding is
    # platform-dependent, which would make matching differ across OSes.
    return any(
        fnmatchcase(key_form, rule_form)
        for rule_form in _match_forms(rule_field)
        for key_form in _match_forms(key)
    )


def _apply_mask(value: object, rule: MaskingRule) -> object:
    """Apply a masking rule to a field value.

    Fails closed: an unrecognized mask type is treated as ``redact`` rather than
    returning the caller's original value.
    """
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

            # Showing the whole value is not masking; degrade to a full mask
            # instead of handing back the unmasked original.
            if show_first < 0 or show_last < 0 or show_first + show_last >= total:
                return mask_char * total

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

    # Unknown / future mask type: never disclose the original.
    return "[REDACTED]"


def _masking_rules(policy: EffectivePolicy) -> list[MaskingRule]:
    if not policy.object_rules or not policy.object_rules.field_rules:
        return []
    return policy.object_rules.field_rules.masked_fields or []


def _rule_for_key(rules: list[MaskingRule], key: str) -> MaskingRule | None:
    """The most restrictive masking rule that matches ``key``, if any."""
    matches = [rule for rule in rules if _field_name_matches(rule.field, key)]
    if not matches:
        return None
    return max(matches, key=lambda rule: mask_restrictiveness(rule.mask_type))


def _mask_node(node: Any, rules: list[MaskingRule]) -> Any:
    """Mask matching keys anywhere in a (possibly nested) structure, in place."""
    if isinstance(node, list):
        for index, item in enumerate(node):
            node[index] = _mask_node(item, rules)
        return node

    if not isinstance(node, dict):
        return node

    for key in list(node.keys()):
        rule = _rule_for_key(rules, str(key))
        if rule is not None:
            node[key] = _apply_mask(node[key], rule)
        else:
            node[key] = _mask_node(node[key], rules)
    return node


def apply_field_masking(record: dict, policy: EffectivePolicy) -> dict:
    """Apply field masking rules to a record.

    Returns a deep copy: the caller's record (including any nested objects) is
    never mutated. Matching recurses into nested dicts and lists so a rule for
    "patient.ssn" also masks {"patient": {"ssn": ...}}.
    """
    rules = _masking_rules(policy)
    if not rules:
        return copy.deepcopy(record)

    return _mask_node(copy.deepcopy(record), rules)


def _hidden_field_patterns(policy: EffectivePolicy) -> list[str]:
    if not policy.object_rules or not policy.object_rules.field_rules:
        return []
    return policy.object_rules.field_rules.hidden_fields or []


def _drop_node(node: Any, patterns: list[str]) -> Any:
    """Remove keys matching any hidden-field pattern, recursively, in place."""
    if isinstance(node, list):
        for index, item in enumerate(node):
            node[index] = _drop_node(item, patterns)
        return node

    if not isinstance(node, dict):
        return node

    for key in list(node.keys()):
        if any(_field_name_matches(pattern, str(key)) for pattern in patterns):
            node.pop(key, None)
            continue
        node[key] = _drop_node(node[key], patterns)
    return node


def strip_hidden_fields(result: Any, policy: EffectivePolicy) -> Any:
    """Remove every hiddenFields entry from a record, list of records, or JSON tree.

    Step 3 of the post-execution pipeline. A hidden field must never reach the
    agent, and a pre-execution field check cannot deliver that on its own: it
    only sees the fields a caller volunteered, so a tool that returns undeclared
    columns (``SELECT *``) would leak them. Returns a deep copy.
    """
    patterns = _hidden_field_patterns(policy)
    if not patterns:
        return copy.deepcopy(result)

    return _drop_node(copy.deepcopy(result), patterns)


def _allowed_field_patterns(policy: EffectivePolicy) -> list[str] | None:
    """The allowedFields allow-list, or None when the policy sets no allow-list.

    ``None`` means unrestricted; ``[]`` means deny every field.
    """
    if not policy.object_rules or not policy.object_rules.field_rules:
        return None
    return policy.object_rules.field_rules.allowed_fields


def _project_record(record: Mapping, patterns: list[str]) -> dict:
    return {
        key: value
        for key, value in record.items()
        if any(_field_name_matches(pattern, str(key)) for pattern in patterns)
    }


def project_allowed_fields(result: Any, policy: EffectivePolicy) -> Any:
    """Project a record or list of records down to allowedFields.

    Step 4 of the post-execution pipeline. When allowedFields is specified every
    other key is dropped, so a tool returning columns the policy never listed
    cannot disclose them. An empty allow-list denies every field (see the
    null-vs-empty-array rule in the canonical spec).
    """
    patterns = _allowed_field_patterns(policy)
    if patterns is None:
        return copy.deepcopy(result)

    if isinstance(result, Mapping):
        return _project_record(result, patterns)
    if isinstance(result, list):
        return [
            _project_record(item, patterns) if isinstance(item, Mapping) else copy.deepcopy(item)
            for item in result
        ]
    return copy.deepcopy(result)


def apply_result_limit(results: list, policy: EffectivePolicy) -> list:
    """Apply the maxResults limit to a result set."""
    if policy.limits and policy.limits.max_results is not None:
        return results[: policy.limits.max_results]
    return results


# -- Result shapes --

_RECORD_SHAPE = "record"
_RECORDS_SHAPE = "records"


def describe_result_shape(result: Any) -> str:
    """A human-readable description of a result shape, for denial messages."""
    if result is None:
        return "None"
    if isinstance(result, Mapping):
        return f"{type(result).__name__} (record)"
    if isinstance(result, (str, bytes, bytearray)):
        return f"{type(result).__name__} (scalar)"
    if isinstance(result, (bool, int, float)):
        return f"{type(result).__name__} (scalar)"
    if isinstance(result, list):
        offenders = {type(item).__name__ for item in result if not isinstance(item, Mapping)}
        if offenders:
            return f"list containing {', '.join(sorted(offenders))} (not records)"
        return "list of records"
    return f"{type(result).__name__} (not a record or list of records)"


def classify_result_shape(result: Any) -> str | None:
    """Classify a tool result as a record, a list of records, or unenforceable.

    Returns ``"record"``, ``"records"``, or ``None`` when the policy cannot be
    applied to the value (scalar, ``None``, generator, arbitrary object, or a
    list holding anything other than records).
    """
    if isinstance(result, Mapping):
        return _RECORD_SHAPE
    if isinstance(result, list) and all(isinstance(item, Mapping) for item in result):
        return _RECORDS_SHAPE
    return None


def apply_result_pipeline(result: Any, policy: EffectivePolicy) -> Any:
    """Run the full post-execution enforcement pipeline over a tool result.

    The canonical order, applied identically to a single record and to a list of
    records:

      1. row filters      drop rows the policy excludes
      2. tag filters      drop records by allowedTags / deniedTags
      3. hidden fields    remove hiddenFields from every record
      4. allowed fields   project to allowedFields when specified
      5. masking          apply maskedFields transformations
      6. result limit     truncate to maxResults

    Hidden/allowed removal precedes masking so a field that is both hidden and
    masked is removed rather than returned in masked form, and the limit runs
    last so filtering never yields fewer rows than maxResults when more
    qualifying rows exist.

    Raises UnenforceableResultError for a shape the policy cannot be applied to.
    """
    shape = classify_result_shape(result)
    if shape is None:
        raise UnenforceableResultError(
            "Access denied: tool result shape cannot be policy-enforced: "
            f"{describe_result_shape(result)}. Return a record (dict) or a list of "
            "records, or opt out explicitly with allow_unenforceable_shapes=True."
        )

    records = [result] if shape is _RECORD_SHAPE else list(result)

    filtered = apply_row_filters(records, policy)
    filtered = filter_by_tags(filtered, policy)
    stripped = strip_hidden_fields(filtered, policy)
    projected = project_allowed_fields(stripped, policy)
    masked = [apply_field_masking(record, policy) for record in projected]
    limited = apply_result_limit(masked, policy)

    if shape is _RECORD_SHAPE:
        # A single record that the pipeline dropped is a denial, not an empty
        # record: returning {} would imply the row existed but had no fields.
        return limited[0] if limited else None
    return limited


# -- Row filters --

_MISSING = object()

# ReDoS guard. Python's re module has no evaluation timeout, so bound the work a
# pattern can be asked to do instead: an over-long pattern or subject value is a
# non-match rather than an unbounded backtracking search.
_MAX_REGEX_PATTERN_LENGTH = 1024
_MAX_REGEX_VALUE_LENGTH = 4096


def _row_field_value(row: dict, field_name: str) -> object:
    """Look up a filter's field on a row, or ``_MISSING`` when it is absent.

    Filters use either bare names ("region") or dotted paths
    ("patients.region"); we accept both and prefer the unqualified key when
    rows have already been projected by the tool function. ``_MISSING`` is
    distinct from a stored ``None`` so that "field absent" can fail closed
    while an explicit null is still comparable.
    """
    if field_name in row:
        return row[field_name]
    for key in row:
        if _field_name_matches(field_name, str(key)):
            return row[key]
    return _MISSING


def _values_equal(left: object, right: object) -> bool:
    """Equality that does not conflate booleans with numbers (1 != True)."""
    if isinstance(left, bool) != isinstance(right, bool):
        return False
    return left == right


@functools.lru_cache(maxsize=256)
def _compile_row_filter_pattern(pattern: str) -> re.Pattern[str] | None:
    """Compile an anchored row-filter pattern, or None if it is unusable.

    The non-capturing group is required: ``^hr|finance$`` would otherwise bind
    ``^`` to ``hr`` alone and match "hr_secret_internal".
    """
    if len(pattern) > _MAX_REGEX_PATTERN_LENGTH:
        return None
    try:
        return re.compile(f"^(?:{pattern})$")
    except re.error:
        return None


def _row_passes_filter(row: dict, rf: RowFilter) -> bool:
    value = _row_field_value(row, rf.field)
    if value is _MISSING:
        # Fail closed for every operator, including the negative ones: a filter
        # written to exclude classified rows must not retain every row that
        # simply lacks the column.
        return False

    op = rf.operator
    if op is FilterOperator.equals:
        return _values_equal(value, rf.value)
    if op is FilterOperator.not_equals:
        return not _values_equal(value, rf.value)
    if op is FilterOperator.in_:
        return any(_values_equal(value, candidate) for candidate in (rf.values or []))
    if op is FilterOperator.not_in:
        return not any(_values_equal(value, candidate) for candidate in (rf.values or []))
    if op is FilterOperator.greater_than or op is FilterOperator.less_than:
        if value is None or rf.value is None:
            return False
        try:
            return value > rf.value if op is FilterOperator.greater_than else value < rf.value
        except TypeError:
            # Non-comparable value (e.g. age="notanumber" vs 30): a non-match,
            # never an exception that aborts the whole result pass.
            return False
    if op is FilterOperator.contains:
        return value is not None and rf.value is not None and str(rf.value) in str(value)
    if op is FilterOperator.starts_with:
        return value is not None and rf.value is not None and str(value).startswith(str(rf.value))
    if op is FilterOperator.matches:
        if value is None or rf.value is None:
            return False
        str_value = str(value)
        if len(str_value) > _MAX_REGEX_VALUE_LENGTH:
            return False
        compiled = _compile_row_filter_pattern(str(rf.value))
        if compiled is None:
            return False
        return compiled.fullmatch(str_value) is not None
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
      An empty allowedTags list denies every record (see the null-vs-empty-array
      rule in the canonical spec) rather than lifting the restriction.
    - If deniedTags is set, exclude results with any denied tag.
    - Denied takes precedence over allowed.
    """
    if not policy.object_rules or not policy.object_rules.tag_rules:
        return results

    tag_rules = policy.object_rules.tag_rules
    allowed_tags = set(tag_rules.allowed_tags) if tag_rules.allowed_tags is not None else None
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
