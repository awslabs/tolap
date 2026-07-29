"""Resolution filtering on `sourcePatterns` (canonical spec section 9).

A definition's `sourcePatterns` declares which data sources the policy applies to,
in `category:namespace:pattern` form. Ignoring it means a policy scoped to
`db:production:*` also governs an unrelated API or knowledge-base source, so the
effective policy for a source is assembled from rules never intended to apply to
it. Whether that widens or narrows access depends on the policies involved — a
rule meant for one source can leak permissions into another, or an unrelated
restriction can deny a source it was never meant to cover.

Python previously ignored the field entirely while .NET filtered on it, so the same
policy set resolved to different effective access per language. .NET is the
reference for these semantics.
"""

from __future__ import annotations

import pytest

from tolap_core.enums import AssigneeType
from tolap_core.models import (
    Assignee,
    AssignmentScope,
    AuditInfo,
    ObjectRules,
    PolicyAssignment,
    PolicyDefinition,
    PolicyLimits,
    PolicyPermissions,
)
from tolap_core.resolution import resolve


def _definition(
    name: str,
    *,
    source_patterns: list[str] | None = None,
    applies_to_all: bool | None = None,
    priority: int | None = 100,
    allowed_objects: list[str] | None = None,
    max_results: int | None = None,
) -> PolicyDefinition:
    return PolicyDefinition(
        version="1.0",
        name=name,
        permissions=PolicyPermissions(can_query=True, read_only=True),
        priority=priority,
        applies_to_all=applies_to_all,
        source_patterns=source_patterns,
        object_rules=ObjectRules(allowed_objects=allowed_objects) if allowed_objects else None,
        limits=PolicyLimits(max_results=max_results) if max_results is not None else None,
    )


def _assignment(policy_name: str) -> PolicyAssignment:
    return PolicyAssignment(
        version="1.0",
        policy_name=policy_name,
        assignee=Assignee(type=AssigneeType.user, identifier="user-001"),
        scope=AssignmentScope(tenant_id="tenant-001"),
        active=True,
        audit=AuditInfo(
            granted_by="test-admin",
            granted_at="2026-01-01T00:00:00Z",
            reason="sourcePatterns coverage",
        ),
    )


def _resolve(definitions: list[PolicyDefinition], source_connection_id: str):
    return resolve(
        user_id="user-001",
        tenant_id="tenant-001",
        source_connection_id=source_connection_id,
        assignments=[_definition_assignment(d) for d in definitions],
        definitions={d.name: d for d in definitions},
        get_groups=lambda _uid: [],
        get_roles=lambda _uid: [],
    )


def _definition_assignment(definition: PolicyDefinition) -> PolicyAssignment:
    return _assignment(definition.name)


class TestNonEmptyPatternsFilter:
    def test_non_matching_pattern_excludes_the_policy(self) -> None:
        """A `db:production:*` policy must not govern an API source."""
        definition = _definition("prod-db", source_patterns=["db:production:*"])

        result = _resolve([definition], "api:internal:patients")

        assert result.source_profiles == []
        assert result.permissions.can_query is False

    def test_matching_pattern_includes_the_policy(self) -> None:
        definition = _definition("prod-db", source_patterns=["db:production:*"])

        result = _resolve([definition], "db:production:patients")

        assert result.source_profiles == ["prod-db"]
        assert result.permissions.can_query is True

    def test_exact_pattern_matches_only_that_source(self) -> None:
        definition = _definition("one-table", source_patterns=["db:production:patients"])

        assert _resolve([definition], "db:production:patients").source_profiles == ["one-table"]
        assert _resolve([definition], "db:production:encounters").source_profiles == []

    def test_any_one_of_several_patterns_is_enough(self) -> None:
        definition = _definition(
            "multi", source_patterns=["db:production:*", "api:internal:*"]
        )

        assert _resolve([definition], "api:internal:patients").source_profiles == ["multi"]
        assert _resolve([definition], "db:production:patients").source_profiles == ["multi"]
        assert _resolve([definition], "kb:public:articles").source_profiles == []

    def test_prefix_glob_within_the_last_segment(self) -> None:
        definition = _definition("tables", source_patterns=["db:production:patient_*"])

        assert _resolve([definition], "db:production:patient_notes").source_profiles == ["tables"]
        assert _resolve([definition], "db:production:billing").source_profiles == []

    def test_wildcard_namespace(self) -> None:
        definition = _definition("kb-any", source_patterns=["kb:*:*"])

        assert _resolve([definition], "kb:public:articles").source_profiles == ["kb-any"]
        assert _resolve([definition], "db:public:articles").source_profiles == []


class TestStarDoesNotCrossTheSeparator:
    """`*` matches within a segment and does not cross `:` (spec section 9).

    Python's `fnmatch` translates `*` to `.*`, which *does* cross a colon — so a
    policy scoped to `db:*` would have silently governed every database source in
    every namespace. The implementation must not use fnmatch here.
    """

    def test_single_segment_star_does_not_span_two_segments(self) -> None:
        definition = _definition("too-broad", source_patterns=["db:*"])

        assert _resolve([definition], "db:production:patients").source_profiles == []

    def test_two_segment_pattern_does_not_match_a_three_segment_source(self) -> None:
        definition = _definition("two-seg", source_patterns=["db:production"])

        assert _resolve([definition], "db:production:patients").source_profiles == []

    def test_star_matches_a_whole_segment_but_not_the_delimiter(self) -> None:
        definition = _definition("seg", source_patterns=["db:*:patients"])

        assert _resolve([definition], "db:production:patients").source_profiles == ["seg"]
        # `*` cannot absorb "production:staging" across the colon.
        assert _resolve([definition], "db:production:staging:patients").source_profiles == []

    def test_trailing_star_does_not_reach_into_a_further_segment(self) -> None:
        definition = _definition("trailing", source_patterns=["api:internal:*"])

        assert _resolve([definition], "api:internal:patients").source_profiles == ["trailing"]
        assert _resolve([definition], "api:internal:v2:patients").source_profiles == []


class TestAbsentAndEmptyMeanAppliesToAll:
    def test_absent_patterns_apply_to_every_source(self) -> None:
        definition = _definition("agnostic", source_patterns=None)

        for source in ("db:production:patients", "api:internal:x", "kb:public:y"):
            assert _resolve([definition], source).source_profiles == ["agnostic"]

    def test_empty_patterns_apply_to_every_source(self) -> None:
        """Unlike an allow-list, `[]` here is "unscoped", not "deny-all".

        Spec section 9 states this explicitly, and it is the opposite of the
        section 3 rule for allow-lists — worth pinning so the two are not conflated.
        """
        definition = _definition("unscoped", source_patterns=[])

        for source in ("db:production:patients", "api:internal:x"):
            assert _resolve([definition], source).source_profiles == ["unscoped"]


class TestAppliesToAllOverride:
    def test_applies_to_all_bypasses_non_matching_patterns(self) -> None:
        definition = _definition(
            "global", source_patterns=["db:production:*"], applies_to_all=True
        )

        result = _resolve([definition], "api:internal:patients")

        assert result.source_profiles == ["global"]

    def test_applies_to_all_false_still_filters(self) -> None:
        definition = _definition(
            "scoped", source_patterns=["db:production:*"], applies_to_all=False
        )

        assert _resolve([definition], "api:internal:patients").source_profiles == []

    def test_applies_to_all_with_no_patterns_resolves(self) -> None:
        definition = _definition("global", applies_to_all=True)

        assert _resolve([definition], "anything").source_profiles == ["global"]


class TestCaseInsensitiveMatching:
    def test_uppercase_source_matches_a_lowercase_pattern(self) -> None:
        definition = _definition("ci", source_patterns=["db:production:*"])

        assert _resolve([definition], "DB:PRODUCTION:PATIENTS").source_profiles == ["ci"]

    def test_uppercase_pattern_matches_a_lowercase_source(self) -> None:
        definition = _definition("ci", source_patterns=["DB:Production:*"])

        assert _resolve([definition], "db:production:patients").source_profiles == ["ci"]


class TestPatternIsGlobNotRegex:
    """Regex metacharacters in a pattern are literal, so they cannot over-match."""

    def test_dot_is_literal(self) -> None:
        definition = _definition("dotted", source_patterns=["api:internal:v1.0"])

        assert _resolve([definition], "api:internal:v1.0").source_profiles == ["dotted"]
        assert _resolve([definition], "api:internal:v1X0").source_profiles == []

    def test_plus_and_parens_are_literal(self) -> None:
        definition = _definition("odd", source_patterns=["api:internal:a+b(c)"])

        assert _resolve([definition], "api:internal:a+b(c)").source_profiles == ["odd"]
        assert _resolve([definition], "api:internal:aab").source_profiles == []

    def test_question_mark_is_literal_not_a_single_char_wildcard(self) -> None:
        """Spec section 9 defines only `*`, so `?` must not become a wildcard."""
        definition = _definition("q", source_patterns=["api:internal:a?c"])

        assert _resolve([definition], "api:internal:a?c").source_profiles == ["q"]
        assert _resolve([definition], "api:internal:abc").source_profiles == []

    def test_overlong_pattern_fails_closed(self) -> None:
        """A pathological pattern excludes its policy rather than being evaluated."""
        definition = _definition("huge", source_patterns=["db:production:" + "a" * 2000])

        assert _resolve([definition], "db:production:aaa").source_profiles == []


class TestFilteringInteractsWithMerging:
    def test_only_matching_definitions_contribute_to_the_merge(self) -> None:
        """The excluded policy's limits must not reach the effective policy."""
        matching = _definition(
            "db-policy", source_patterns=["db:production:*"], max_results=5000, priority=10
        )
        excluded = _definition(
            "api-policy", source_patterns=["api:internal:*"], max_results=10, priority=20
        )

        result = _resolve([matching, excluded], "db:production:patients")

        assert result.source_profiles == ["db-policy"]
        assert result.limits is not None
        # If the API policy had leaked in, min-of-maxima would have made this 10.
        assert result.limits.max_results == 5000

    def test_an_unrelated_restriction_cannot_deny_a_source_it_never_covered(self) -> None:
        """The narrowing direction of the same defect."""
        api_only_deny = PolicyDefinition(
            version="1.0",
            name="api-readonly",
            permissions=PolicyPermissions(can_query=False, read_only=True),
            priority=10,
            source_patterns=["api:internal:*"],
        )
        db_allow = _definition("db-allow", source_patterns=["db:production:*"], priority=20)

        result = _resolve([api_only_deny, db_allow], "db:production:patients")

        assert result.source_profiles == ["db-allow"]
        assert result.permissions.can_query is True

    def test_allowed_object_intersection_excludes_a_non_matching_policy(self) -> None:
        db_policy = _definition(
            "db", source_patterns=["db:production:*"], allowed_objects=["patients", "encounters"]
        )
        api_policy = _definition(
            "api", source_patterns=["api:internal:*"], allowed_objects=["reports"]
        )

        result = _resolve([db_policy, api_policy], "db:production:patients")

        assert result.object_rules is not None
        assert result.object_rules.allowed_objects == ["patients", "encounters"]

    def test_no_definition_matching_the_source_denies_all(self) -> None:
        definition = _definition("db", source_patterns=["db:production:*"])

        result = _resolve([definition], "kb:public:articles")

        assert result.permissions.can_query is False
        assert result.permissions.read_only is True
        assert result.source_profiles == []

    def test_priority_ordering_survives_the_filter(self) -> None:
        low = _definition("low", source_patterns=["db:*:*"], priority=100)
        high = _definition("high", source_patterns=["db:production:*"], priority=10)
        excluded = _definition("excluded", source_patterns=["api:*:*"], priority=1)

        result = _resolve([low, high, excluded], "db:production:patients")

        assert result.source_profiles == ["high", "low"]

    def test_the_resolved_source_is_still_stamped_on_the_result(self) -> None:
        definition = _definition("db", source_patterns=["db:production:*"])

        result = _resolve([definition], "db:production:patients")

        assert result.source_connection_id == "db:production:patients"


class TestStoreResolvesWithSourcePatterns:
    """The filter must apply through the store's resolve_policy, not just resolve()."""

    def test_scoped_policy_does_not_resolve_for_another_source(self) -> None:
        from tolap_store.in_memory_store import InMemoryPolicyStore
        from tolap_store.static_identity_resolver import StaticIdentityResolver

        store = InMemoryPolicyStore(StaticIdentityResolver())
        store.save_definition(_definition("db", source_patterns=["db:production:*"]))
        store.save_assignment(_assignment("db"))

        matching = store.resolve_policy("user-001", "tenant-001", "db:production:patients")
        other = store.resolve_policy("user-001", "tenant-001", "api:internal:patients")

        assert matching.permissions.can_query is True
        assert other.permissions.can_query is False
