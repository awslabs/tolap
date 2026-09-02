from __future__ import annotations

from tolap_core.enums import mask_restrictiveness
from tolap_core.models import (
    EffectivePolicy,
    EndpointRules,
    FieldRules,
    JudgeConfig,
    MaskingRule,
    ObjectRules,
    PolicyDefinition,
    PolicyLimits,
    PolicyPermissions,
    PurposeProfile,
    RowFilter,
    TagRules,
)


def merge(policies: list[PolicyDefinition]) -> EffectivePolicy:
    """Merge multiple PolicyDefinitions into a single EffectivePolicy.

    Merge rules:
    - Empty list -> deny_all()
    - Permissions: absent booleans take their schema default first (can_query
      True, can_insert/can_update/can_delete False, read_only True),
      then AND for can_query/can_insert/can_update/can_delete and OR
      for read_only
    - Allowed sets: Intersection (None means unrestricted from that policy; an
      empty result means deny-all and is retained, never discarded)
    - Hidden/denied sets: Union
    - Row filters: Concatenate
    - Masked fields: Group by field, pick highest restrictiveness
    - Limits: min for maxima, max for minima (None means no limit from that policy)
    - Purpose profile: carried through, with allowed_actions intersected and
      prohibited_actions unioned. Two profiles naming different purposes cannot be
      merged and return deny_all() (spec section 15.2).
    """
    if not policies:
        return EffectivePolicy.deny_all()

    # Before anything else, because it can refuse the whole merge. Two policies bound
    # to different purposes have no most-restrictive combination -- picking one would
    # silently apply rules authored for a purpose the caller did not declare, and
    # dropping the profile would turn a purpose-scoped policy into an unscoped one.
    # Resolution never produces this input, having filtered to a single purpose
    # already; `merge` is public and must not rely on that.
    purpose_profile = _merge_purpose_profiles(policies)
    if purpose_profile is None and any(p.purpose_profile is not None for p in policies):
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
        purpose_profile=purpose_profile,
    )


def _merge_purpose_profiles(policies: list[PolicyDefinition]) -> PurposeProfile | None:
    """Combine the purpose profiles of the merged definitions.

    Returns ``None`` when none carry one -- and also ``None`` when they disagree about
    the purpose, which :func:`merge` reads as a refusal.

    The profile is carried onto the effective policy rather than consumed during
    resolution because enforcement only ever sees an :class:`EffectivePolicy`. It also
    means the purpose travels inside the signed bytes with no change to the signing
    projection: the policy is already part of the signed envelope.

    ``allowed_actions`` intersects and ``prohibited_actions`` unions, so both fold
    most-restrictively. Disjoint allow-lists intersect to an empty list, which per spec
    section 3 denies every action -- deliberately not collapsed to ``None``, which would
    mean the opposite.
    """
    profiles = [p.purpose_profile for p in policies if p.purpose_profile is not None]
    if not profiles:
        return None

    # Case-sensitive, matching the resolution-time comparison. Two spellings of the
    # same intent are two different purposes as far as this SDK is concerned, and
    # saying so loudly beats quietly treating them as one. `dict.fromkeys` de-dupes
    # while preserving order, so the surviving id is the first policy's.
    purpose_ids = list(dict.fromkeys(profile.purpose_id for profile in profiles))
    if len(purpose_ids) > 1:
        return None

    judge = _merge_judge_configs(profiles)
    if judge is None and any(profile.judge is not None for profile in profiles):
        return None

    return PurposeProfile(
        purpose_id=purpose_ids[0],
        # Lowest-priority definition first, so the description a reader sees is the one
        # from the most specific policy. `merge` is called with the list already ordered.
        description=next(
            (profile.description for profile in profiles if profile.description is not None),
            None,
        ),
        allowed_actions=_intersect_optional_lists(
            [profile.allowed_actions for profile in profiles]
        ),
        prohibited_actions=_union_retaining_empty(
            [profile.prohibited_actions for profile in profiles]
        ),
        judge=judge,
    )


def _merge_judge_configs(profiles: list[PurposeProfile]) -> JudgeConfig | None:
    """Combine judge configurations toward more escalation.

    Returns ``None`` when no profile configures a judge, and also ``None`` when two
    name different models -- which :func:`_merge_purpose_profiles` reads as a refusal.
    A verdict is only meaningful against the model that produced it, so two models
    cannot be reconciled at all.

    ``enabled`` ORs so any policy can switch the judge on, and preserves the three
    states: an explicit ``False`` everywhere stays ``False`` rather than collapsing to
    ``None``, because absent fields are omitted from the canonical form and collapsing
    would change the signed bytes as well as losing an author's decision.

    Both thresholds take the **maximum**: a higher confidence bar sends more calls to
    review rather than letting them through, and a higher escalation floor does the
    same. ``max_latency_ms`` takes the minimum, and ``history_window`` the maximum,
    since more context is the direction that helps a judge notice drift.
    """
    configs = [profile.judge for profile in profiles if profile.judge is not None]
    if not configs:
        return None

    models = list(dict.fromkeys(c.model for c in configs if c.model is not None))
    if len(models) > 1:
        return None

    if any(c.enabled is True for c in configs):
        enabled: bool | None = True
    elif any(c.enabled is not None for c in configs):
        enabled = False
    else:
        enabled = None

    # `_max_of_minima` and `_min_of_maxima` are the max and min of the non-None values;
    # their names describe the limit fields they were written for, and the arithmetic is
    # exactly what these four judge fields need. Duplicating them under judge-specific
    # names would leave two copies free to drift.
    return JudgeConfig(
        enabled=enabled,
        model=models[0] if models else None,
        history_window=_max_of_minima([c.history_window for c in configs]),
        confidence_threshold=_max_of_minima([c.confidence_threshold for c in configs]),
        escalation_threshold=_max_of_minima([c.escalation_threshold for c in configs]),
        max_latency_ms=_min_of_maxima([c.max_latency_ms for c in configs]),
    )


def _merge_permissions(policies: list[PolicyDefinition]) -> PolicyPermissions:
    """Fold permission flags, defaulting absent values before folding.

    Excluding an absent flag from the fold inverts the outcome: policy A silent
    on read_only plus policy B with read_only=False must yield True (the
    restrictive reading of "A did not grant write access"), not False.

    The three write permissions default to False and fold with AND, so *every*
    applicable policy has to grant a write for the merged policy to. ``read_only``
    keeps its True default and its OR fold, so *any* policy can impose the
    ceiling. Both directions therefore compose most-restrictively, and the
    asymmetry with ``can_query`` (default True) is intentional: a policy written
    before writes existed must not silently acquire them (connector spec
    section 4.1).
    """
    # Schema defaults for absent flags, applied BEFORE folding.
    can_query_values = [p.permissions.can_query if p.permissions.can_query is not None else True for p in policies]
    can_insert_values = [p.permissions.can_insert if p.permissions.can_insert is not None else False for p in policies]
    can_update_values = [p.permissions.can_update if p.permissions.can_update is not None else False for p in policies]
    can_delete_values = [p.permissions.can_delete if p.permissions.can_delete is not None else False for p in policies]
    read_only_values = [p.permissions.read_only if p.permissions.read_only is not None else True for p in policies]

    return PolicyPermissions(
        can_query=all(can_query_values),
        can_insert=all(can_insert_values),
        can_update=all(can_update_values),
        can_delete=all(can_delete_values),
        read_only=any(read_only_values),
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
            if existing is None or mask_restrictiveness(rule.mask_type) > mask_restrictiveness(existing.mask_type):
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
    min_similarity = _max_of_minima([p.limits.min_similarity_score if p.limits else None for p in policies])
    max_object_size = _min_of_maxima([p.limits.max_object_size_bytes if p.limits else None for p in policies])

    return PolicyLimits(
        max_results=max_results,
        min_similarity_score=min_similarity,
        max_object_size_bytes=max_object_size,
    )


# -- Utility functions --


def _intersect_optional_lists(lists: list[list[str] | None]) -> list[str] | None:
    """Intersection of allow-list style fields. ``None`` means unrestricted from that policy.

    Order comes from the first contributing list, so the merged output reads like the policy a
    reader is most likely to have in front of them. Duplicates are dropped: a set intersection
    cannot hold one, and the schema puts no ``uniqueItems`` on these arrays, so a definition
    listing ``["x", "x", "y"]`` is authorable.

    That last point was a real cross-SDK divergence. This function computed a set intersection
    and then re-projected it onto the first list, which reinstated the duplicates the set had
    just removed -- so Python emitted ``["x", "x", "y"]`` where .NET's ``IntersectNullable`` and
    TypeScript's ``intersectOptional`` both emitted ``["x", "y"]``. Since an allow-list travels
    inside the signed ``policies[]``, that meant different canonical bytes and a context signed
    by Python failing verification in the other two. Only visible with two or more contributing
    policies, which is why it survived: a single-policy merge passes the list through untouched
    in all three.

    Serves ``allowedActions`` and also ``allowedObjects``/``allowedFields``/``allowedTags``/
    ``allowedEndpoints``/``allowedMethods``.
    """
    contributing = [lst for lst in lists if lst is not None]
    if not contributing:
        return None

    # One contributing list means there is no intersection to perform, so it passes through
    # unchanged -- duplicates included. Two or more means an actual set intersection, which
    # cannot hold a duplicate. Not an arbitrary split: it is exactly what .NET's
    # `IntersectNullable` and TypeScript's `intersectOptional` do, and matching them byte for
    # byte is the requirement (sections 1 and 14). De-duplicating the single-list case too
    # would be tidier semantics and would change the canonical bytes of every existing policy
    # that authors a duplicate, breaking contexts that verify across all three SDKs today.
    if len(contributing) == 1:
        return list(contributing[0])

    permitted = set(contributing[0])
    for other in contributing[1:]:
        permitted &= set(other)

    # First-seen order from the first contributing list. `seen` is tracked separately rather
    # than discarding from `permitted`, because mutating the membership set while iterating
    # would change the test for a later duplicate.
    seen: set[str] = set()
    ordered: list[str] = []
    for item in contributing[0]:
        if item in permitted and item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered


def _union_optional_lists(lists: list[list[str] | None]) -> list[str] | None:
    """Union of deny-list style fields. ``None`` means the policy contributed nothing.

    Returns ``[]`` when at least one policy contributed a list and every one of them was
    empty, and ``None`` only when no policy contributed at all. The distinction is the one
    canonical-enforcement-spec.md section 3 makes load-bearing, and it is why the retention
    test here is ``contributed`` rather than ``if result``: a truthiness check collapses
    ``[]`` into ``None``, which section 3 names explicitly as the mistake to avoid.

    That collapse was a real cross-SDK divergence, found by porting this feature to Python
    and fixed here. .NET's ``UnionNullable`` and TypeScript's ``unionArrays`` both retain the
    empty array; Python alone returned ``None``. On a deny-list the two are indistinguishable
    to *enforcement* -- neither hides anything -- so no test comparing access outcomes could
    see it. But they are not indistinguishable to *signing*: ``serialize`` omits ``None`` and
    emits ``[]``, so a policy authoring an explicitly empty ``hiddenObjects``,
    ``deniedTags``, ``readOnlyFields`` or ``hiddenEndpoints`` produced different canonical
    bytes in Python than in the other two SDKs, and a context signed by one would not verify
    in the others. Section 14 calls that class of divergence a security defect rather than a
    stylistic difference.

    Nothing that previously worked breaks: such a policy was already failing cross-SDK
    verification, so aligning Python is the change that makes it verifiable at all.
    """
    return _union_retaining_empty(lists)


def _union_retaining_empty(lists: list[list[str] | None]) -> list[str] | None:
    """Union of lists, returning ``[]`` when every contributing list was empty.

    Distinct from :func:`_union_optional_lists`, which returns ``None`` in that case.
    The difference is invisible to enforcement -- ``[]`` and ``None`` both forbid
    nothing on a deny-list -- but it is *not* invisible to signing: ``serialize``
    omits ``None`` and emits ``[]``, so the two produce different canonical bytes.
    .NET's ``UnionNullable`` and TypeScript's ``unionArrays`` both retain the empty
    array, and a purpose profile travels inside the signed ``policies[]``, so Python
    has to agree byte for byte or a purpose-bound context signs differently here than
    in the other two SDKs.

    :func:`_union_optional_lists` now delegates here, so this is the single union
    implementation. The two names are kept apart only because the call sites read better
    for their field: one is about deny-lists in general, the other about a purpose
    profile's prohibited actions specifically.
    """
    result: list[str] = []
    seen: set[str] = set()
    contributed = False
    for lst in lists:
        if lst is None:
            continue
        contributed = True
        for item in lst:
            if item not in seen:
                seen.add(item)
                result.append(item)
    return result if contributed else None


def _min_of_maxima(values: list[int | float | None]) -> int | float | None:
    """For maximum limits: take the minimum (most restrictive). None means no limit."""
    non_none = [v for v in values if v is not None]
    return min(non_none) if non_none else None


def _max_of_minima(values: list[int | float | None]) -> float | None:
    """For minimum limits: take the maximum (most restrictive). None means no limit."""
    non_none = [v for v in values if v is not None]
    return max(non_none) if non_none else None


# Retention checks test `is not None`, never truthiness. An empty allow-list is
# the most restrictive possible outcome (deny everything); discarding the rules
# object because [] is falsy would silently convert it into no restriction at all.


def _has_object_rules(rules: ObjectRules | None) -> bool:
    # _merge_object_rules always constructs an ObjectRules, so None never reaches
    # here today; the guard keeps the signature honest for other callers.
    if rules is None:  # pragma: no cover - defensive
        return False
    return any([
        rules.allowed_objects is not None,
        rules.hidden_objects is not None,
        _has_field_rules(rules.field_rules),
        rules.row_filters is not None,
        _has_tag_rules(rules.tag_rules),
        _has_endpoint_rules(rules.endpoint_rules),
    ])


def _has_field_rules(rules: FieldRules | None) -> bool:
    if rules is None:
        return False
    return any([
        rules.allowed_fields is not None,
        rules.hidden_fields is not None,
        rules.masked_fields is not None,
        rules.read_only_fields is not None,
    ])


def _has_tag_rules(rules: TagRules | None) -> bool:
    if rules is None:
        return False
    return any([rules.allowed_tags is not None, rules.denied_tags is not None])


def _has_endpoint_rules(rules: EndpointRules | None) -> bool:
    if rules is None:
        return False
    return any([
        rules.allowed_endpoints is not None,
        rules.hidden_endpoints is not None,
        rules.allowed_methods is not None,
    ])


def _has_limits(limits: PolicyLimits | None) -> bool:
    # As above: _merge_limits always returns a PolicyLimits instance.
    if limits is None:  # pragma: no cover - defensive
        return False
    return any([
        limits.max_results is not None,
        limits.min_similarity_score is not None,
        limits.max_object_size_bytes is not None,
    ])
