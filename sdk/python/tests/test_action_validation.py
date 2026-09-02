"""Action validation against a purpose profile (canonical-enforcement-spec.md section 15.2).

Driven from ``fixtures/enforcement/validate-action.json`` so the three SDKs are held to
one table rather than three readings of it. The hand-written cases below cover what a
shared fixture cannot: the ``None``-versus-``[]`` distinction asserted on the model
directly, and the reason strings as literals.
"""

from __future__ import annotations

import pytest
from conftest import load_fixture

from tolap_core.enforcement import validate_action
from tolap_core.models import PurposeProfile
from tolap_core.serialization import deserialize_effective_policy


FIXTURE = "enforcement/validate-action.json"
CASES = load_fixture(FIXTURE)["cases"]


def _case_id(index: int) -> str:
    case = CASES[index]
    outcome = "allow" if case["expected"]["allowed"] else "deny"
    return f"{index}-{outcome}-{case['actionCategory'] or 'empty'}"


class TestTheSharedFixture:
    """One table, three SDKs. A disagreement shows up as a fixture failure."""

    @pytest.mark.parametrize("index", range(len(CASES)), ids=_case_id)
    def test_validate_action_matches_the_shared_fixture(self, index: int) -> None:
        case = CASES[index]
        policy = deserialize_effective_policy(case["policy"])

        # Asserted rather than assumed: a fixture whose policy lost its purposeProfile
        # in deserialization would make every case below pass vacuously against nothing.
        assert policy.purpose_profile is not None, (
            f"case {index} exists to exercise a purpose profile"
        )

        result = validate_action(case["actionCategory"], policy.purpose_profile)

        assert result.allowed is case["expected"]["allowed"], (
            f"case {index} (action {case['actionCategory']!r})"
        )
        if "reason" in case["expected"]:
            assert result.reason == case["expected"]["reason"]
        else:
            assert result.reason is None, "an allow carries no reason"

    def test_the_fixture_covers_both_outcomes(self) -> None:
        """A corpus that drifted into all-denials would prove nothing.

        Blocking everything is trivially "correct" against a deny-only table. Spec
        section 14 and ``docs/testing-antipatterns.md`` both call this out, so the corpus
        itself is asserted rather than only the code that reads it.
        """
        outcomes = {case["expected"]["allowed"] for case in CASES}

        assert outcomes == {True, False}

    def test_every_fixture_policy_carries_a_purpose_profile(self) -> None:
        """The precondition of the whole file, asserted once outside the parametrize."""
        assert all("purposeProfile" in case["policy"] for case in CASES)


class TestNullVersusEmpty:
    """Spec section 3, on both lists, in both directions.

    The two arrays read in *opposite* directions and that asymmetry is the thing a
    truthiness check destroys, so each half is pinned next to its mirror rather than
    inferred from the other.
    """

    def test_absent_allowed_actions_permits_anything(self) -> None:
        # None is unrestricted. Unlike allowed_methods, absence here is a real grant
        # rather than an oversight: a purpose may constrain only what is forbidden.
        profile = PurposeProfile(purpose_id="campaign-x-overlap")

        assert validate_action("anything-at-all", profile).allowed is True

    def test_empty_allowed_actions_denies_everything(self) -> None:
        # The half a truthiness check breaks: an empty allow-list is the most restrictive
        # value the model can express, so reading it as falsy turns the strictest possible
        # policy into no policy at all.
        profile = PurposeProfile(purpose_id="campaign-x-overlap", allowed_actions=[])

        result = validate_action("aggregate_overlap", profile)

        assert result.allowed is False
        assert result.reason == (
            "action 'aggregate_overlap' not in allowed actions for purpose "
            "'campaign-x-overlap'"
        )

    def test_absent_prohibited_actions_restricts_nothing(self) -> None:
        profile = PurposeProfile(purpose_id="campaign-x-overlap")

        assert validate_action("export_pii", profile).allowed is True

    def test_empty_prohibited_actions_restricts_nothing(self) -> None:
        # The mirror of the empty allow-list: [] on a DENY-list forbids nothing, because
        # the list enumerates what is refused rather than what is permitted.
        profile = PurposeProfile(purpose_id="campaign-x-overlap", prohibited_actions=[])

        assert validate_action("export_pii", profile).allowed is True


class TestPrecedence:
    def test_prohibited_wins_when_a_category_is_in_both_lists(self) -> None:
        profile = PurposeProfile(
            purpose_id="campaign-x-overlap",
            allowed_actions=["export_pii", "aggregate_overlap"],
            prohibited_actions=["export_pii"],
        )

        denied = validate_action("export_pii", profile)
        allowed = validate_action("aggregate_overlap", profile)

        assert denied.allowed is False
        assert denied.reason == (
            "action 'export_pii' is prohibited under purpose 'campaign-x-overlap'"
        )
        # The paired control. Without it, an implementation that denied unconditionally
        # would satisfy the assertion above.
        assert allowed.allowed is True


class TestCaseInsensitivity:
    """Deliberately the opposite of the purpose comparison at resolution.

    Both choices deny: a mis-cased purpose resolves nothing, and a mis-cased category is
    still caught. A case-sensitive comparison here would let ``EXPORT_PII`` walk straight
    past a prohibition on ``export_pii``.
    """

    @pytest.mark.parametrize(
        "action_category", ["EXPORT_PII", "Export_Pii", "export_PII"]
    )
    def test_a_prohibition_catches_any_casing(self, action_category: str) -> None:
        profile = PurposeProfile(
            purpose_id="campaign-x-overlap", prohibited_actions=["export_pii"]
        )

        result = validate_action(action_category, profile)

        assert result.allowed is False
        assert result.reason == (
            f"action '{action_category}' is prohibited under purpose 'campaign-x-overlap'"
        ), "the reason echoes the category as supplied, so the log shows what was attempted"

    @pytest.mark.parametrize("action_category", ["AGGREGATE_OVERLAP", "Aggregate_Overlap"])
    def test_the_allow_list_also_matches_any_casing(self, action_category: str) -> None:
        # The paired direction: case-insensitivity must not be implemented only on the
        # deny path, or a correctly-configured tool is refused for its capitalization.
        profile = PurposeProfile(
            purpose_id="campaign-x-overlap", allowed_actions=["aggregate_overlap"]
        )

        assert validate_action(action_category, profile).allowed is True

    def test_a_mis_cased_entry_in_the_policy_is_matched_too(self) -> None:
        """Insensitivity applies to the policy's spelling, not just the caller's.

        An administrator who wrote ``Export_PII`` in ``prohibitedActions`` must still
        forbid ``export_pii``, or the prohibition is silently inert.
        """
        profile = PurposeProfile(
            purpose_id="campaign-x-overlap", prohibited_actions=["Export_PII"]
        )

        assert validate_action("export_pii", profile).allowed is False


class TestReasonStrings:
    def test_an_empty_category_is_denied_against_an_allow_list(self) -> None:
        # A wrapper that could not determine a category must not get a free pass by
        # handing over "". The empty string is in no allow-list, so it is refused.
        profile = PurposeProfile(
            purpose_id="campaign-x-overlap", allowed_actions=["aggregate_overlap"]
        )

        result = validate_action("", profile)

        assert result.allowed is False
        assert result.reason == (
            "action '' not in allowed actions for purpose 'campaign-x-overlap'"
        )

    def test_an_empty_category_is_allowed_by_an_unconstrained_purpose(self) -> None:
        """The paired control: "" is not itself a denial, the allow-list is."""
        assert validate_action("", PurposeProfile(purpose_id="campaign-x-overlap")).allowed

    def test_the_reason_names_the_purpose_not_just_the_action(self) -> None:
        # Two purposes can forbid the same category for different reasons, so the purpose
        # is in the message. Integrators log and branch on these strings.
        first = PurposeProfile(
            purpose_id="campaign-x-overlap", prohibited_actions=["export_pii"]
        )
        second = PurposeProfile(
            purpose_id="fraud-detection", prohibited_actions=["export_pii"]
        )

        assert "campaign-x-overlap" in validate_action("export_pii", first).reason
        assert "fraud-detection" in validate_action("export_pii", second).reason
