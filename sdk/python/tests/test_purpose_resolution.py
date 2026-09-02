"""Resolution-time purpose filtering (canonical-enforcement-spec.md section 15.1).

The definitions and assignments come from the shared fixture corpus rather than being
restated here, so the same four policies drive the .NET, Python and TypeScript suites and
a divergence in the filter shows up as a fixture disagreement rather than three
independently-plausible test files.

Every denial has a paired allow. A filter that excluded everything would satisfy the
deny-all cases on its own, which is the failure mode ``docs/testing-antipatterns.md``
section 3 describes.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from conftest import load_fixture

from tolap_core.enums import AssigneeType
from tolap_core.models import Assignee, PolicyAssignment, PolicyDefinition
from tolap_core.resolution import resolve
from tolap_core.serialization import (
    deserialize_policy_assignment,
    deserialize_policy_definition,
)
from tolap_store.in_memory_store import InMemoryPolicyStore
from tolap_store.static_identity_resolver import StaticIdentityResolver


TENANT = "tenant-acme-retail"
USER = "user-marketing-001"
SOURCE = "db:marketing:customer_segments"
CAMPAIGN_PURPOSE = "campaign-x-overlap"


def _definition(name: str) -> PolicyDefinition:
    return deserialize_policy_definition(load_fixture(f"policies/{name}.json"))


def _assignment(name: str) -> PolicyAssignment:
    return deserialize_policy_assignment(load_fixture(f"assignments/{name}.json"))


SCOPED = _definition("purpose-campaign-overlap")
FRAUD = _definition("purpose-fraud-detection")
AGNOSTIC = _definition("purpose-agnostic-baseline")
JUDGED = _definition("purpose-judge-enabled")


def _resolve(
    definitions: list[PolicyDefinition],
    assignments: list[PolicyAssignment],
    declared_purpose: str | None,
    *,
    source: str = SOURCE,
    groups: list[str] | None = None,
):
    return resolve(
        user_id=USER,
        tenant_id=TENANT,
        source_connection_id=source,
        assignments=assignments,
        definitions={d.name: d for d in definitions},
        get_groups=lambda _: groups or [],
        get_roles=lambda _: [],
        declared_purpose=declared_purpose,
    )


class TestTheFixturesAreWhatTheseTestsAssume:
    """Guards every case below.

    If the fixtures were edited so that, say, the scoped policy lost its profile, the
    filtering assertions would pass against a policy set that no longer exercises
    filtering at all.
    """

    def test_the_purpose_ids_are_the_expected_ones(self) -> None:
        assert SCOPED.purpose_profile.purpose_id == CAMPAIGN_PURPOSE
        assert FRAUD.purpose_profile.purpose_id == "fraud-detection"
        assert JUDGED.purpose_profile.purpose_id == CAMPAIGN_PURPOSE
        assert AGNOSTIC.purpose_profile is None

    @pytest.mark.parametrize(
        "definition", [SCOPED, FRAUD, AGNOSTIC, JUDGED], ids=lambda d: d.name
    )
    def test_every_definition_reaches_the_source_under_test(
        self, definition: PolicyDefinition
    ) -> None:
        """Or a case would "pass" because sourcePatterns excluded the policy rather than
        because the purpose filter did."""
        assert "db:marketing:*" in definition.source_patterns

    @pytest.mark.parametrize(
        "assignment",
        [
            "purpose-campaign-overlap",
            "purpose-fraud-detection",
            "purpose-agnostic-baseline",
            "purpose-judged",
        ],
    )
    def test_every_assignment_names_the_user_and_tenant_under_test(
        self, assignment: str
    ) -> None:
        loaded = _assignment(assignment)

        assert loaded.assignee.identifier == USER
        assert loaded.scope.tenant_id == TENANT
        assert loaded.active is True


class TestFilteringBehaviour:
    def test_without_a_purpose_only_the_agnostic_policy_resolves(self) -> None:
        result = _resolve(
            [SCOPED, AGNOSTIC],
            [_assignment("purpose-campaign-overlap"), _assignment("purpose-agnostic-baseline")],
            declared_purpose=None,
        )

        assert result.source_profiles == ["marketing-baseline"]
        assert result.purpose_profile is None, "no purpose-scoped policy resolved"

        # The scoped policy's rules must not have leaked in. Asserting the profile is
        # absent is not enough on its own -- the rules could still have merged while the
        # profile was dropped, which is the specific failure filtering-after-merge
        # produces.
        assert result.object_rules.allowed_objects is None, (
            "the scoped policy's allowedObjects would restrict the baseline if it merged"
        )
        assert result.object_rules.row_filters is None, (
            "the scoped policy's consent_status filter must not apply"
        )
        assert result.limits.max_results == 2000, "only the baseline's limit applies"

    def test_with_a_matching_purpose_the_scoped_policy_is_included(self) -> None:
        result = _resolve(
            [SCOPED, AGNOSTIC],
            [_assignment("purpose-campaign-overlap"), _assignment("purpose-agnostic-baseline")],
            declared_purpose=CAMPAIGN_PURPOSE,
        )

        assert result.source_profiles == ["campaign-x-overlap-agent", "marketing-baseline"]
        assert result.purpose_profile.purpose_id == CAMPAIGN_PURPOSE
        assert "export_pii" in result.purpose_profile.prohibited_actions

        # The merge ran across both, so the more restrictive limit wins.
        assert result.limits.max_results == 2000

    def test_a_wrong_purpose_excludes_the_non_matching_scoped_policy(self) -> None:
        result = _resolve(
            [SCOPED, FRAUD],
            [_assignment("purpose-campaign-overlap"), _assignment("purpose-fraud-detection")],
            declared_purpose=CAMPAIGN_PURPOSE,
        )

        assert result.source_profiles == ["campaign-x-overlap-agent"]
        assert result.purpose_profile.purpose_id == CAMPAIGN_PURPOSE

        # The fraud policy permits inspect_account and enumerate_individuals, which the
        # campaign purpose does not. If it had merged, that grant would be present -- and
        # this is the case that shows purpose filtering changes the *access*, not just the
        # label.
        assert "inspect_account" not in result.purpose_profile.allowed_actions
        assert result.limits.max_results == 10000, (
            "the fraud policy's tighter limit of 500 must not apply"
        )

    def test_the_other_purpose_resolves_the_other_policy(self) -> None:
        # The paired control for the case above. Without it, a filter that dropped every
        # scoped policy except the first would still pass.
        result = _resolve(
            [SCOPED, FRAUD],
            [_assignment("purpose-campaign-overlap"), _assignment("purpose-fraud-detection")],
            declared_purpose="fraud-detection",
        )

        assert result.source_profiles == ["fraud-detection-agent"]
        assert result.limits.max_results == 500

    def test_all_policies_scoped_and_no_purpose_declared_is_deny_all(self) -> None:
        result = _resolve(
            [SCOPED, FRAUD],
            [_assignment("purpose-campaign-overlap"), _assignment("purpose-fraud-detection")],
            declared_purpose=None,
        )

        assert result.permissions.can_query is False
        assert result.permissions.read_only is True
        assert result.source_profiles == []
        assert result.purpose_profile is None

    def test_a_purpose_declared_with_no_scoped_policy_resolves_normally(self) -> None:
        # Declaring a purpose must not restrict a purpose-agnostic policy set. Otherwise
        # switching a caller to declare its purpose would silently reduce its access, and
        # integrators would learn to leave the field off.
        result = _resolve(
            [AGNOSTIC],
            [_assignment("purpose-agnostic-baseline")],
            declared_purpose="some-purpose-nothing-declares",
        )

        assert result.permissions.can_query is True
        assert result.source_profiles == ["marketing-baseline"]

    def test_two_policies_sharing_a_purpose_both_resolve_and_merge(self) -> None:
        result = _resolve(
            [SCOPED, JUDGED],
            [_assignment("purpose-campaign-overlap"), _assignment("purpose-judged")],
            declared_purpose=CAMPAIGN_PURPOSE,
        )

        assert result.source_profiles == [
            "campaign-x-overlap-agent",
            "campaign-x-overlap-judged",
        ]

        # Intersected allow-list, unioned deny-list.
        assert result.purpose_profile.allowed_actions == ["aggregate_overlap", "count_segments"]
        assert "export_pii" in result.purpose_profile.prohibited_actions
        assert "train_model" in result.purpose_profile.prohibited_actions

        # The judge config came from one policy only and survives the merge.
        assert result.purpose_profile.judge.enabled is True
        assert result.purpose_profile.judge.model == "claude-sonnet"


class TestComparisonSemantics:
    @pytest.mark.parametrize(
        "declared_purpose",
        ["Campaign-X-Overlap", "CAMPAIGN-X-OVERLAP", "campaign-X-overlap"],
    )
    def test_purpose_matching_is_case_sensitive(self, declared_purpose: str) -> None:
        # Exact, deliberately unlike sourcePatterns and the chain-narrowing globs, which
        # are both case-insensitive. A case-insensitive comparison here would let a caller
        # resolve a policy written for a different spelling of the purpose.
        result = _resolve([SCOPED], [_assignment("purpose-campaign-overlap")], declared_purpose)

        assert result.permissions.can_query is False, (
            f"{declared_purpose!r} is not 'campaign-x-overlap'"
        )

    def test_the_exact_purpose_resolves(self) -> None:
        # Paired with the casing theory above: the exact spelling must work, or that
        # theory would pass against a filter that rejected everything.
        result = _resolve(
            [SCOPED], [_assignment("purpose-campaign-overlap")], CAMPAIGN_PURPOSE
        )

        assert result.permissions.can_query is True

    def test_an_empty_purpose_string_is_treated_as_no_purpose(self) -> None:
        # "" and omitted must not behave as two different declarations, matching how the
        # signing projection normalizes them.
        result = _resolve(
            [SCOPED, AGNOSTIC],
            [_assignment("purpose-campaign-overlap"), _assignment("purpose-agnostic-baseline")],
            declared_purpose="",
        )

        assert result.source_profiles == ["marketing-baseline"]

    def test_a_purpose_is_not_a_glob(self) -> None:
        # Declaring '*' must not resolve every purpose-scoped policy. This is why the
        # comparison is equality rather than a reuse of the glob helpers, and it is the
        # case that makes the difference security-relevant rather than stylistic.
        result = _resolve(
            [SCOPED, FRAUD],
            [_assignment("purpose-campaign-overlap"), _assignment("purpose-fraud-detection")],
            declared_purpose="*",
        )

        assert result.permissions.can_query is False
        assert result.source_profiles == []

    def test_a_purpose_is_not_a_prefix_either(self) -> None:
        """``campaign-x`` must not resolve ``campaign-x-overlap`` at resolution.

        The segment-boundary rule exists for delegation *narrowing*, where a parent hands
        down a family of purposes. Resolution compares one asserted identifier against one
        declared identifier, so the same rule here would let a caller widen its own reach.
        """
        result = _resolve([SCOPED], [_assignment("purpose-campaign-overlap")], "campaign-x")

        assert result.permissions.can_query is False


class TestCompositionWithTheOtherFilters:
    def test_the_same_definition_reached_by_two_assignments_is_filtered_per_occurrence(
        self,
    ) -> None:
        # Resolution appends one definition per matching assignment, so the same policy
        # can appear twice. The filter must be a per-element predicate rather than a set
        # operation, or de-duplication changes which rules merge.
        by_group = replace(
            _assignment("purpose-campaign-overlap"),
            assignee=Assignee(type=AssigneeType.group, identifier="marketing-team"),
        )
        twice = [_assignment("purpose-campaign-overlap"), by_group]

        matched = _resolve([SCOPED], twice, CAMPAIGN_PURPOSE, groups=["marketing-team"])
        excluded = _resolve([SCOPED], twice, None, groups=["marketing-team"])

        assert len(matched.source_profiles) == 2, "one entry per matching assignment"
        assert matched.permissions.can_query is True

        assert excluded.source_profiles == []
        assert excluded.permissions.can_query is False

    def test_purpose_filtering_composes_with_source_patterns(self) -> None:
        # Both filters run before the merge and neither substitutes for the other. A
        # matching purpose must not rescue a policy scoped to a different source.
        right_source = _resolve(
            [SCOPED], [_assignment("purpose-campaign-overlap")], CAMPAIGN_PURPOSE
        )
        wrong_source = _resolve(
            [SCOPED],
            [_assignment("purpose-campaign-overlap")],
            CAMPAIGN_PURPOSE,
            source="db:production:patient_records",
        )

        assert right_source.permissions.can_query is True
        assert wrong_source.permissions.can_query is False

    def test_purpose_filtering_does_not_rescue_a_revoked_assignment(self) -> None:
        # Revocation is checked before definitions are even loaded (spec section 12), so a
        # declared purpose cannot reach a revoked grant. Asserted because purpose
        # filtering was inserted into the same pipeline.
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat().replace(
            "+00:00", "Z"
        )
        revoked = replace(_assignment("purpose-campaign-overlap"), revoked_at=yesterday)

        assert _resolve([SCOPED], [revoked], CAMPAIGN_PURPOSE).permissions.can_query is False

    def test_purpose_filtering_does_not_rescue_an_inactive_assignment(self) -> None:
        inactive = replace(_assignment("purpose-campaign-overlap"), active=False)

        assert _resolve([SCOPED], [inactive], CAMPAIGN_PURPOSE).permissions.can_query is False

    def test_without_the_parameter_it_behaves_as_before_this_feature(self) -> None:
        # The backward-compatibility assertion, made against the seven-argument call
        # rather than by passing None. Existing callers do not pass a purpose at all, and
        # this is the call they make.
        result = resolve(
            user_id=USER,
            tenant_id=TENANT,
            source_connection_id=SOURCE,
            assignments=[_assignment("purpose-agnostic-baseline")],
            definitions={AGNOSTIC.name: AGNOSTIC},
            get_groups=lambda _: [],
            get_roles=lambda _: [],
        )

        assert result.permissions.can_query is True
        assert result.purpose_profile is None

    def test_declared_purpose_is_keyword_only(self) -> None:
        """Positional callers must keep meaning what they did.

        Passing the purpose positionally has to be a ``TypeError`` rather than silently
        landing in some other parameter -- which is the failure a non-keyword-only
        addition invites the first time someone inserts a field above it.
        """
        with pytest.raises(TypeError):
            resolve(
                USER,
                TENANT,
                SOURCE,
                [_assignment("purpose-agnostic-baseline")],
                {AGNOSTIC.name: AGNOSTIC},
                lambda _: [],
                lambda _: [],
                CAMPAIGN_PURPOSE,  # type: ignore[misc]
            )


class TestTheStoreThreadsThePurposeThrough:
    """A store that dropped the parameter would resolve a policy nobody asked for.

    Purpose filtering has to happen before the merge, so there is no later point at which
    a caller could undo it -- which is why this is threaded through the store rather than
    left as something the caller applies afterwards.
    """

    def _store(self, definitions: list[PolicyDefinition], assignments: list[PolicyAssignment]):
        store = InMemoryPolicyStore(StaticIdentityResolver())
        for definition in definitions:
            store.save_definition(definition)
        for assignment in assignments:
            store.save_assignment(assignment)
        return store

    def test_a_matching_purpose_resolves_the_scoped_policy(self) -> None:
        store = self._store(
            [SCOPED, AGNOSTIC],
            [_assignment("purpose-campaign-overlap"), _assignment("purpose-agnostic-baseline")],
        )

        result = store.resolve_policy(
            USER, TENANT, SOURCE, declared_purpose=CAMPAIGN_PURPOSE
        )

        assert result.source_profiles == ["campaign-x-overlap-agent", "marketing-baseline"]
        assert result.purpose_profile.purpose_id == CAMPAIGN_PURPOSE

    def test_omitting_the_purpose_excludes_the_scoped_policy(self) -> None:
        store = self._store(
            [SCOPED, AGNOSTIC],
            [_assignment("purpose-campaign-overlap"), _assignment("purpose-agnostic-baseline")],
        )

        result = store.resolve_policy(USER, TENANT, SOURCE)

        assert result.source_profiles == ["marketing-baseline"]
        assert result.purpose_profile is None

    def test_a_wrong_purpose_is_deny_all_through_the_store(self) -> None:
        store = self._store([SCOPED], [_assignment("purpose-campaign-overlap")])

        result = store.resolve_policy(USER, TENANT, SOURCE, declared_purpose="fraud-detection")

        assert result.permissions.can_query is False

    def test_the_store_parameter_is_keyword_only(self) -> None:
        store = self._store([SCOPED], [_assignment("purpose-campaign-overlap")])

        with pytest.raises(TypeError):
            store.resolve_policy(USER, TENANT, SOURCE, CAMPAIGN_PURPOSE)  # type: ignore[misc]
