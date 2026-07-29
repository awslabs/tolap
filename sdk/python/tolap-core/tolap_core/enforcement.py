from __future__ import annotations

import copy
import functools
import hashlib
import math
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


def _pattern_matches(pattern: str, name: str) -> bool:
    """Case-insensitive glob match, identically on every platform.

    ``fnmatch.fnmatch`` applies ``os.path.normcase``, which lower-cases on Windows
    and is a no-op elsewhere -- so a rule ``hiddenObjects: ["Billing"]`` against a
    query for ``billing`` denied on Windows and allowed on macOS/Linux. The same
    signed policy must produce the same decision everywhere, so match with
    ``fnmatchcase`` over pre-lowered strings instead of relying on the platform's
    case rules. This mirrors :func:`_field_name_matches`, which already did so for
    the post-execution path.
    """
    return fnmatchcase(name.lower(), pattern.lower())


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
            if _pattern_matches(pattern, object_name):
                return AccessResult(allowed=False, reason="object is hidden")

    # Check allowed objects (if specified, object must be in the set)
    if obj_rules.allowed_objects is not None:
        for pattern in obj_rules.allowed_objects:
            if _pattern_matches(pattern, object_name):
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
                if _pattern_matches(pattern, f):
                    denied = True
                    break

        if denied:
            result.denied.append(f)
            continue

        # Check allowed fields (if specified, field must be in the set)
        if field_rules and field_rules.allowed_fields is not None:
            allowed = False
            for pattern in field_rules.allowed_fields:
                if _pattern_matches(pattern, f):
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


def _blake2b_512(data: bytes) -> str:
    """BLAKE2b-512 hex digest.

    ``digest_size=64`` is stated explicitly rather than relying on the default:
    ``hashlib.blake2b`` accepts any size from 1 to 64 bytes, and the schema's
    ``blake2b`` means BLAKE2b-512 specifically -- the variant Node spells
    ``blake2b512``. A different digest size is a different hash, so leaving it
    implicit would make the join key hostage to a CPython default.
    """
    return hashlib.blake2b(data, digest_size=64).hexdigest()


_HASH_ALGORITHMS: dict[str, Any] = {
    "sha256": lambda data: hashlib.sha256(data).hexdigest(),
    "sha512": lambda data: hashlib.sha512(data).hexdigest(),
    "blake2b": _blake2b_512,
}
"""Hash-mask algorithms, keyed by the exact schema value (canonical spec §6).

Only the three values the schema permits are accepted, matched exactly. Passing
the parameter straight to ``hashlib.new`` would accept anything the runtime
happens to offer -- ``md5`` included -- and would accept spellings the other SDKs
reject, which is how a pseudonym stops matching across services.
"""


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
            algorithm = "sha256"
            if rule.parameters and rule.parameters.algorithm:
                algorithm = rule.parameters.algorithm

            hasher = _HASH_ALGORITHMS.get(algorithm)
            if hasher is None:
                # An algorithm this runtime cannot provide must not abort the
                # result pass and must never disclose the original, so fail
                # closed as ``redact`` (canonical spec §6). Substituting sha256
                # would be worse than redacting: the value would look like a
                # valid pseudonym while silently failing to join against a
                # service that computed the requested algorithm.
                return "[REDACTED]"

            return hasher(str_value.encode("utf-8"))[:16]

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


def apply_masking(result: Any, policy: EffectivePolicy) -> Any:
    """Apply maskedFields to a record, list of records, or arbitrary JSON tree.

    The tree-walking counterpart to :func:`strip_hidden_fields`, and the shared
    implementation both the MCP and HTTP paths use so they cannot drift. A
    dotted-path walk that only honoured a rule anchored at the root of the body
    left a bare rule such as ``ssn`` matching only a top-level key, so the same
    policy masked ``{"demographics": {"ssn": ...}}`` through the MCP wrapper and
    disclosed it through the HTTP wrapper. Spec section 4 requires masking to
    recurse into nested objects and arrays and to match bare and qualified field
    forms in both directions.

    Returns a deep copy; the caller's value is never mutated.
    """
    rules = _masking_rules(policy)
    if not rules:
        return copy.deepcopy(result)

    return _mask_node(copy.deepcopy(result), rules)


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


# -- Numeric record floors and ceilings --

# Field names carrying a similarity score, in precedence order. Covers the common
# vector-store response shapes (Bedrock KB, OpenSearch, pgvector wrappers).
_SCORE_KEYS = ("score", "similarity", "similarityscore", "_score")

# Field names carrying an object size in bytes, in precedence order. Covers the
# common object-storage response shapes (S3, Azure Blob, GCS).
_SIZE_KEYS = ("size", "sizebytes", "contentlength", "objectsize")


def _numeric_field(record: Any, keys: tuple[str, ...]) -> float | None:
    """Read the first present numeric field named by ``keys``, case-insensitively.

    Returns None when no key is present or the value is not a finite number. The
    caller treats None as "cannot establish this record's value", which fails
    closed.
    """
    if not isinstance(record, Mapping):
        return None
    lowered = {str(k).lower(): v for k, v in record.items()}
    for key in keys:
        if key not in lowered:
            continue
        value = lowered[key]
        # bool is an int subclass; a True score is a type error, not a 1.0 score.
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            numeric = float(value)
            return numeric if math.isfinite(numeric) else None
        if isinstance(value, str):
            try:
                numeric = float(value.strip())
            except ValueError:
                return None
            return numeric if math.isfinite(numeric) else None
        return None
    return None


def apply_similarity_floor(results: list, policy: EffectivePolicy) -> list:
    """Drop records scoring below ``minSimilarityScore`` (spec section 4, step 3).

    Fails closed: a record with no recognizable score field, or a non-numeric
    score, is dropped when a floor is set. A record whose relevance cannot be
    established cannot be shown to satisfy the floor, and the documented purpose
    of this limit is to stop low-relevance vector hits from surfacing sensitive
    content -- so an unscored record must not slip through.

    A score exactly equal to the floor is kept.
    """
    if not policy.limits or policy.limits.min_similarity_score is None:
        return results

    floor = policy.limits.min_similarity_score
    kept = []
    for record in results:
        score = _numeric_field(record, _SCORE_KEYS)
        if score is None or score < floor:
            continue
        kept.append(record)
    return kept


def apply_object_size_ceiling(results: list, policy: EffectivePolicy) -> list:
    """Drop records larger than ``maxObjectSizeBytes`` (spec section 4, step 4).

    Fails closed on the same reasoning as the relevance floor: a record with no
    recognizable size field, or a non-numeric size, is dropped when a ceiling is
    set. A size exactly equal to the ceiling is kept.
    """
    if not policy.limits or policy.limits.max_object_size_bytes is None:
        return results

    ceiling = policy.limits.max_object_size_bytes
    kept = []
    for record in results:
        size = _numeric_field(record, _SIZE_KEYS)
        if size is None or size > ceiling:
            continue
        kept.append(record)
    return kept


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
      3. relevance floor  drop records scoring below minSimilarityScore
      4. size ceiling     drop records larger than maxObjectSizeBytes
      5. hidden fields    remove hiddenFields from every record
      6. allowed fields   project to allowedFields when specified
      7. masking          apply maskedFields transformations
      8. result limit     truncate to maxResults

    Every record-dropping step precedes every field-level step, so no work is
    spent masking a record that is about to be discarded. Hidden/allowed removal
    precedes masking so a field that is both hidden and masked is removed rather
    than returned in masked form, and the limit runs last so filtering never
    yields fewer rows than maxResults when more qualifying rows exist.

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
    filtered = apply_similarity_floor(filtered, policy)
    filtered = apply_object_size_ceiling(filtered, policy)
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


@functools.lru_cache(maxsize=256)
def _compile_like_pattern(pattern: str) -> re.Pattern[str] | None:
    """Translate a SQL ``LIKE`` pattern to an anchored regex, or None if unusable.

    ``%`` matches any run of characters, ``_`` matches exactly one, and ``\\``
    escapes the next character so a literal percent or underscore can be written.
    Every other character is ``re.escape``d, so a pattern containing regex
    metacharacters (``.``, ``(``, ``|``) is matched literally and cannot smuggle a
    pathological regex through the ``like`` operator.

    Case-sensitive, matching Postgres ``LIKE`` -- and matching the ``LIKE`` this
    SDK's query rewriter emits, so the post-fetch and pushed-down evaluations of
    the same filter agree. Deliberately distinct from ``matches`` (a full regex)
    and from ``contains`` (a plain substring test).
    """
    if len(pattern) > _MAX_REGEX_PATTERN_LENGTH:
        return None

    parts = ["^(?:"]
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\" and index + 1 < len(pattern):
            # An escaped wildcard is a literal; consume both characters.
            parts.append(re.escape(pattern[index + 1]))
            index += 2
            continue
        if char == "%":
            parts.append(".*")
        elif char == "_":
            parts.append(".")
        else:
            parts.append(re.escape(char))
        index += 1
    parts.append(")$")

    try:
        return re.compile("".join(parts), re.DOTALL)
    except re.error:  # pragma: no cover - every emitted fragment is valid regex
        return None


def _like_matches(pattern: object, value: object) -> bool | None:
    """Whether ``value`` matches a SQL ``LIKE`` ``pattern``.

    Returns None when the comparison cannot be made at all -- a null pattern or a
    null field value -- which callers treat as "drop the row" for both ``like``
    and ``notLike``. SQL evaluates ``NULL LIKE 'x'`` and ``NULL NOT LIKE 'x'``
    both to NULL, and neither retains a row; returning True for the negative case
    would reintroduce exactly the fail-open behaviour spec section 7 records for
    ``notEquals``/``notIn`` on a missing field.
    """
    if value is None or pattern is None:
        return None

    str_value = str(value)
    if len(str_value) > _MAX_REGEX_VALUE_LENGTH:
        return None
    compiled = _compile_like_pattern(str(pattern))
    if compiled is None:
        return None
    return compiled.fullmatch(str_value) is not None


def _compare(left: object, right: object) -> int | None:
    """Order two values, or None when they are not orderable.

    None when either side is null, either side is a boolean, or the pair has no
    ordering (``age="notanumber"`` against ``30``). Callers treat None as a
    non-match, so a type mismatch drops the row rather than raising an exception
    that would abort the whole result pass (spec section 7).

    Booleans are excluded for the same reason :func:`_values_equal` excludes
    them: Python orders ``True`` as ``1``, so ``flag > 0`` would silently treat a
    boolean field as a number.
    """
    if left is None or right is None:
        return None
    if isinstance(left, bool) or isinstance(right, bool):
        return None
    try:
        if left < right:  # type: ignore[operator]
            return -1
        if left > right:  # type: ignore[operator]
            return 1
    except TypeError:
        return None
    return 0


def _between_matches(value: object, rf: RowFilter) -> bool:
    """Whether ``value`` falls inside the inclusive range in ``rf.values``.

    The bounds are the first two entries of ``values``, ordered ``[low, high]``.
    Fails closed on a malformed range: fewer than two bounds, a null bound, or a
    bound that is not orderable against the row value all drop the row.

    An inverted range (low > high) matches nothing, exactly as SQL
    ``BETWEEN 10 AND 1`` does. The bounds are deliberately not reordered --
    silently swapping them would turn a policy author's typo into a wider grant
    than the one they wrote.
    """
    bounds = rf.values or []
    if len(bounds) < 2:
        return False

    lower = _compare(value, bounds[0])
    if lower is None or lower < 0:
        return False
    upper = _compare(value, bounds[1])
    return upper is not None and upper <= 0


def _row_passes_filter(row: dict, rf: RowFilter) -> bool:
    value = _row_field_value(row, rf.field)
    if value is _MISSING:
        # Fail closed for every operator, including the negative ones and the
        # null tests: a filter written to exclude classified rows must not retain
        # every row that simply lacks the column. See the isNull note below for
        # why "absent" and "present and null" are kept distinct.
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
    if op is FilterOperator.greater_than:
        ordering = _compare(value, rf.value)
        return ordering is not None and ordering > 0
    if op is FilterOperator.greater_than_or_equal:
        ordering = _compare(value, rf.value)
        return ordering is not None and ordering >= 0
    if op is FilterOperator.less_than:
        ordering = _compare(value, rf.value)
        return ordering is not None and ordering < 0
    if op is FilterOperator.less_than_or_equal:
        ordering = _compare(value, rf.value)
        return ordering is not None and ordering <= 0
    if op is FilterOperator.contains:
        return value is not None and rf.value is not None and str(rf.value) in str(value)
    if op is FilterOperator.starts_with:
        return value is not None and rf.value is not None and str(value).startswith(str(rf.value))
    if op is FilterOperator.like:
        return _like_matches(rf.value, value) is True
    if op is FilterOperator.not_like:
        # None (an incomparable pair) drops the row rather than retaining it;
        # only a definite non-match satisfies notLike.
        return _like_matches(rf.value, value) is False
    if op is FilterOperator.is_null:
        # The field is present -- a missing field was already dropped above -- so
        # this is the genuine "present and null" case. A MISSING field does NOT
        # satisfy isNull: "the field is absent" and "the field is present and
        # null" are different statements, and dropping the row is the fail-closed
        # reading of a constraint we cannot prove holds (spec section 7).
        return value is None
    if op is FilterOperator.is_not_null:
        return value is not None
    if op is FilterOperator.between:
        return _between_matches(value, rf)
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
    # An operator this SDK does not implement retains nothing. Deserialization
    # already refuses an unrecognized operator string, so this is reachable only
    # for a hand-built RowFilter -- but a future enum member added without a
    # branch here must deny rather than pass rows through.
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


# The methods that only read. Used twice: as the documented default for an
# omitted allowedMethods, and as the set readOnly permits.
_READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def validate_endpoint(path: str, method: str, policy: EffectivePolicy) -> AccessResult:
    """Validate access to an API endpoint.

    Three restrictions apply, most-restrictive-first:

    1. ``hiddenEndpoints`` then ``allowedEndpoints`` gate the path.
    2. ``readOnly`` gates the method. When the permission is true, only
       ``GET``/``HEAD``/``OPTIONS`` are permitted -- regardless of
       ``allowedMethods``, because a policy that grants ``DELETE`` while declaring
       itself read-only is contradictory and the restrictive half must win.
       ``readOnly`` was previously merged (OR-folded, so any read-only policy in
       the set made the result read-only) and then never consulted, so the whole
       fold had no effect on any decision.
    3. ``allowedMethods`` gates the method. When omitted it defaults to the read
       methods, as the schema documents ("If omitted, defaults to read-only
       methods: GET, HEAD, OPTIONS"). Treating omitted as unrestricted -- the
       previous behaviour -- let ``POST``/``PUT``/``PATCH``/``DELETE`` through on
       a policy whose author had been told the default was read-only.

    ``readOnly`` is unset on many policies; absent means the schema default of
    ``true`` (spec section 8), so an endpoint policy silent on ``readOnly`` is
    read-only.
    """
    if not policy.permissions.can_query:
        return AccessResult(allowed=False, reason="query not permitted")

    normalized_method = method.upper()
    rules = None
    if policy.object_rules and policy.object_rules.endpoint_rules:
        rules = policy.object_rules.endpoint_rules

    if rules is not None:
        # Check hidden endpoints first (takes precedence)
        if rules.hidden_endpoints:
            for pattern in rules.hidden_endpoints:
                if _pattern_matches(pattern, path):
                    return AccessResult(allowed=False, reason="endpoint is hidden")

        # Check allowed endpoints
        if rules.allowed_endpoints is not None:
            matched = False
            for pattern in rules.allowed_endpoints:
                if _pattern_matches(pattern, path):
                    matched = True
                    break
            if not matched:
                return AccessResult(allowed=False, reason="endpoint not in allowed set")

    # Check allowed methods. `None` is the documented read-only default, not
    # "unrestricted"; `[]` denies every method.
    allowed_methods = rules.allowed_methods if rules is not None else None
    permitted = _READ_METHODS if allowed_methods is None else {m.upper() for m in allowed_methods}
    if normalized_method not in permitted:
        return AccessResult(allowed=False, reason="method not allowed")

    # readOnly is checked last so an explicit allowedMethods denial keeps its more
    # specific reason. An absent readOnly takes its schema default of true,
    # matching the merge rules in spec section 8: excluding absent booleans from
    # the decision would invert it, letting a policy silent on readOnly permit
    # writes. A policy that lists DELETE in allowedMethods while declaring itself
    # read-only is contradictory, and the restrictive half wins.
    read_only = policy.permissions.read_only is not False
    if read_only and normalized_method not in _READ_METHODS:
        return AccessResult(allowed=False, reason="method not allowed on a read-only policy")

    return AccessResult(allowed=True)
