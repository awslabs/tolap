"""Merging purpose profiles into an effective policy (spec section 15.2).

The profile is carried through the merge rather than consumed at resolution because every
enforcement entry point takes an :class:`EffectivePolicy`. Without that, a
``purposeProfile`` would be authorable and unenforceable -- and it also means the purpose
rides inside the signed bytes with no change to the signing projection.
"""

from __future__ import annotations

import json

import pytest
from conftest import load_fixture

from tolap_core.enforcement import validate_action
from tolap_core.merger import merge
from tolap_core.models import (
    JudgeConfig,
    PolicyDefinition,
    PolicyPermissions,
    PurposeProfile,
)
from tolap_core.serialization import deserialize_policy_definition, serialize


SCENARIOS = (
    "purpose-profile-carried-through",
    "purpose-profile-actions-merge",
    "purpose-profile-conflicting-ids-deny-all",
    "purpose-profile-disjoint-allowed-denies-every-action",
)


def _with_profile(
    name: str, profile: PurposeProfile | None, priority: int = 10
) -> PolicyDefinition:
    return PolicyDefinition(
        version="1.0",
        name=name,
        permissions=PolicyPermissions(can_query=True, read_only=True),
        priority=priority,
        purpose_profile=profile,
    )


class TestTheSharedScenarios:
    """Four fixtures, three SDKs, one answer each."""

    @pytest.mark.parametrize("name", SCENARIOS, ids=lambda n: n)
    def test_merge_matches_the_shared_scenario(self, name: str) -> None:
        fixture = load_fixture(f"merge-scenarios/{name}.json")
        inputs = [deserialize_policy_definition(p) for p in fixture["inputs"]]
        expected = fixture["expected"]

        result = merge(inputs)

        assert result.source_profiles == expected["sourceProfiles"]
        assert result.permissions.can_query is expected["permissions"]["canQuery"]

        # Compared as serialized JSON, so absent (`None`, omitted) and empty (`[]`,
        # present) are distinguished exactly as the fixture writes them. A field-by-field
        # comparison is where a `[]` quietly read as absent would slip through.
        projected = json.loads(serialize(result)).get("purposeProfile")

        assert projected == expected.get("purposeProfile"), f"scenario {name!r}"

    @pytest.mark.parametrize("name", SCENARIOS, ids=lambda n: n)
    def test_every_scenario_input_carries_the_field_under_test(self, name: str) -> None:
        """Guards the four cases above: an input that lost its profile proves nothing."""
        fixture = load_fixture(f"merge-scenarios/{name}.json")

        assert any("purposeProfile" in p for p in fixture["inputs"])

    def test_the_scenarios_cover_both_a_carried_profile_and_a_refusal(self) -> None:
        """A corpus of only refusals would pass against a merger that always denied."""
        outcomes = {
            bool(
                load_fixture(f"merge-scenarios/{name}.json")["expected"][
                    "permissions"
                ]["canQuery"]
            )
            for name in SCENARIOS
        }

        assert outcomes == {True, False}


class TestPurposeIdAgreement:
    def test_no_policy_carrying_a_profile_leaves_the_policy_unscoped(self) -> None:
        # The backward-compatibility case: a purpose-agnostic policy set must produce
        # exactly what it did before this field existed, including a None rather than an
        # empty profile.
        result = merge([_with_profile("a", None), _with_profile("b", None)])

        assert result.purpose_profile is None
        assert result.permissions.can_query is True

    def test_conflicting_purpose_ids_are_deny_all(self) -> None:
        # Not "pick one" and not "drop the profile". Picking one applies rules authored
        # for a purpose the caller did not declare; dropping the profile turns a
        # purpose-scoped policy into an unscoped one. Both are worse than refusing.
        result = merge(
            [
                _with_profile("a", PurposeProfile(purpose_id="campaign-x-overlap")),
                _with_profile("b", PurposeProfile(purpose_id="fraud-detection")),
            ]
        )

        assert result.permissions.can_query is False
        assert result.source_profiles == []
        assert result.purpose_profile is None

    def test_the_purpose_id_comparison_is_case_sensitive(self) -> None:
        # Two spellings are two purposes, consistent with resolution. Collapsing them
        # would merge rules across what the SDK elsewhere treats as distinct purposes.
        result = merge(
            [
                _with_profile("a", PurposeProfile(purpose_id="campaign-x-overlap")),
                _with_profile("b", PurposeProfile(purpose_id="Campaign-X-Overlap")),
            ]
        )

        assert result.permissions.can_query is False

    def test_agreeing_purpose_ids_succeed(self) -> None:
        # The paired control for both cases above.
        result = merge(
            [
                _with_profile("a", PurposeProfile(purpose_id="campaign-x-overlap")),
                _with_profile("b", PurposeProfile(purpose_id="campaign-x-overlap")),
            ]
        )

        assert result.permissions.can_query is True
        assert result.purpose_profile.purpose_id == "campaign-x-overlap"

    def test_a_third_disagreeing_policy_still_refuses(self) -> None:
        """Two agreeing policies must not mask a third that disagrees."""
        result = merge(
            [
                _with_profile("a", PurposeProfile(purpose_id="campaign-x-overlap")),
                _with_profile("b", PurposeProfile(purpose_id="campaign-x-overlap")),
                _with_profile("c", PurposeProfile(purpose_id="fraud-detection")),
            ]
        )

        assert result.permissions.can_query is False


class TestActionListFolding:
    def test_disjoint_allowed_actions_yield_empty_rather_than_none(self) -> None:
        # The intersection is [] which denies every action. Collapsing it to None would
        # mean the opposite -- unrestricted -- so the assertion is on emptiness AND
        # non-noneness.
        result = merge(
            [
                _with_profile(
                    "a", PurposeProfile(purpose_id="p-x", allowed_actions=["aggregate_overlap"])
                ),
                _with_profile(
                    "b", PurposeProfile(purpose_id="p-x", allowed_actions=["inspect_account"])
                ),
            ]
        )

        assert result.purpose_profile.allowed_actions == []

        # And the consequence is real, not cosmetic: every action is now refused.
        assert validate_action("aggregate_overlap", result.purpose_profile).allowed is False

    def test_one_absent_allow_list_does_not_widen_the_other(self) -> None:
        # None means "adds no restriction", so intersecting it with a list must yield the
        # list. An implementation that treated None as a reset to unrestricted would
        # widen, which is the failure worth pinning.
        result = merge(
            [
                _with_profile(
                    "a", PurposeProfile(purpose_id="p-x", allowed_actions=["aggregate_overlap"])
                ),
                _with_profile("b", PurposeProfile(purpose_id="p-x", allowed_actions=None)),
            ]
        )

        assert result.purpose_profile.allowed_actions == ["aggregate_overlap"]

    def test_every_allow_list_absent_stays_absent(self) -> None:
        """The paired direction: nothing restricted must not become everything denied."""
        result = merge(
            [
                _with_profile("a", PurposeProfile(purpose_id="p-x")),
                _with_profile("b", PurposeProfile(purpose_id="p-x")),
            ]
        )

        assert result.purpose_profile.allowed_actions is None
        assert validate_action("anything", result.purpose_profile).allowed is True

    def test_prohibited_actions_union_keeps_every_policys_denials(self) -> None:
        result = merge(
            [
                _with_profile(
                    "a", PurposeProfile(purpose_id="p-x", prohibited_actions=["export_pii"])
                ),
                _with_profile(
                    "b", PurposeProfile(purpose_id="p-x", prohibited_actions=["train_model"])
                ),
            ]
        )

        assert result.purpose_profile.prohibited_actions == ["export_pii", "train_model"]

    def test_an_explicitly_empty_deny_list_is_retained_as_empty(self) -> None:
        """``[]`` and absent forbid the same things but do NOT sign the same bytes.

        ``serialize`` omits ``None`` and emits ``[]``, and the profile travels inside the
        signed ``policies[]``. .NET's ``UnionNullable`` and TypeScript's ``unionArrays``
        both retain the empty array, so folding it to ``None`` here would make a
        purpose-bound context sign differently in Python than in the other two SDKs --
        a cross-SDK verification failure with no behavioural symptom to point at it.
        """
        result = merge(
            [
                _with_profile("a", PurposeProfile(purpose_id="p-x", prohibited_actions=[])),
                _with_profile("b", PurposeProfile(purpose_id="p-x", prohibited_actions=[])),
            ]
        )

        assert result.purpose_profile.prohibited_actions == []
        assert "prohibitedActions" in json.loads(serialize(result))["purposeProfile"]

    def test_no_deny_list_anywhere_stays_absent(self) -> None:
        """The paired direction, and what keeps a profile's canonical bytes minimal."""
        result = merge(
            [
                _with_profile("a", PurposeProfile(purpose_id="p-x")),
                _with_profile("b", PurposeProfile(purpose_id="p-x")),
            ]
        )

        assert result.purpose_profile.prohibited_actions is None
        assert "prohibitedActions" not in json.loads(serialize(result))["purposeProfile"]

    def test_an_agnostic_policy_does_not_erase_a_scoped_ones_restrictions(self) -> None:
        result = merge(
            [
                _with_profile(
                    "scoped",
                    PurposeProfile(purpose_id="p-x", allowed_actions=["aggregate_overlap"]),
                ),
                _with_profile("agnostic", None),
            ]
        )

        assert result.purpose_profile.purpose_id == "p-x"
        assert result.purpose_profile.allowed_actions == ["aggregate_overlap"], (
            "a policy with no profile contributes no action restriction, and must not "
            "erase one"
        )


class TestJudgeConfigFolding:
    def test_enabled_is_ored(self) -> None:
        result = merge(
            [
                _with_profile(
                    "a", PurposeProfile(purpose_id="p-x", judge=JudgeConfig(enabled=False))
                ),
                _with_profile(
                    "b", PurposeProfile(purpose_id="p-x", judge=JudgeConfig(enabled=True))
                ),
            ]
        )

        assert result.purpose_profile.judge.enabled is True, (
            "any policy may switch the judge on"
        )

    def test_enabled_false_everywhere_stays_explicitly_false(self) -> None:
        # Not None. The policies said "no judge" rather than saying nothing, and
        # collapsing the two would lose an author's explicit decision -- and, because
        # absent fields are omitted from the canonical form, would change the signed
        # bytes as well.
        result = merge(
            [
                _with_profile(
                    "a", PurposeProfile(purpose_id="p-x", judge=JudgeConfig(enabled=False))
                ),
                _with_profile(
                    "b", PurposeProfile(purpose_id="p-x", judge=JudgeConfig(enabled=False))
                ),
            ]
        )

        assert result.purpose_profile.judge.enabled is False
        assert json.loads(serialize(result))["purposeProfile"]["judge"]["enabled"] is False

    def test_enabled_absent_everywhere_stays_absent(self) -> None:
        # The third state. A judge block configuring only a threshold has not said whether
        # the judge is on, and inventing a False would be as wrong as inventing a True.
        result = merge(
            [
                _with_profile(
                    "a", PurposeProfile(purpose_id="p-x", judge=JudgeConfig(history_window=5))
                ),
                _with_profile(
                    "b", PurposeProfile(purpose_id="p-x", judge=JudgeConfig(history_window=7))
                ),
            ]
        )

        assert result.purpose_profile.judge.enabled is None
        assert result.purpose_profile.judge.history_window == 7
        assert "enabled" not in json.loads(serialize(result))["purposeProfile"]["judge"]

    def test_one_absent_and_one_false_enabled_stays_false(self) -> None:
        """The mixed case between the two above, which the OR must not turn into None."""
        result = merge(
            [
                _with_profile("a", PurposeProfile(purpose_id="p-x", judge=JudgeConfig())),
                _with_profile(
                    "b", PurposeProfile(purpose_id="p-x", judge=JudgeConfig(enabled=False))
                ),
            ]
        )

        assert result.purpose_profile.judge.enabled is False

    def test_thresholds_take_the_maximum_and_latency_the_minimum(self) -> None:
        # Both thresholds are maxima, and for the same reason: a higher bar sends more
        # calls to human review rather than letting them through.
        result = merge(
            [
                _with_profile(
                    "a",
                    PurposeProfile(
                        purpose_id="p-x",
                        judge=JudgeConfig(
                            confidence_threshold=0.8,
                            escalation_threshold=0.5,
                            history_window=5,
                            max_latency_ms=2500,
                        ),
                    ),
                ),
                _with_profile(
                    "b",
                    PurposeProfile(
                        purpose_id="p-x",
                        judge=JudgeConfig(
                            confidence_threshold=0.9,
                            escalation_threshold=0.7,
                            history_window=12,
                            max_latency_ms=1500,
                        ),
                    ),
                ),
            ]
        )

        judge = result.purpose_profile.judge
        assert judge.confidence_threshold == 0.9
        assert judge.escalation_threshold == 0.7
        assert judge.history_window == 12, "more context helps a judge notice drift"
        assert judge.max_latency_ms == 1500, "the tighter budget wins"

    def test_different_judge_models_are_deny_all(self) -> None:
        # A verdict is only meaningful against the model that produced it, so there is no
        # most-restrictive combination of two models.
        result = merge(
            [
                _with_profile(
                    "a",
                    PurposeProfile(purpose_id="p-x", judge=JudgeConfig(model="claude-sonnet")),
                ),
                _with_profile(
                    "b",
                    PurposeProfile(
                        purpose_id="p-x", judge=JudgeConfig(model="some-other-model")
                    ),
                ),
            ]
        )

        assert result.permissions.can_query is False
        assert result.purpose_profile is None

    def test_one_judge_naming_a_model_and_one_not_keeps_the_named_one(self) -> None:
        # The paired control: only a genuine disagreement refuses.
        result = merge(
            [
                _with_profile(
                    "a",
                    PurposeProfile(purpose_id="p-x", judge=JudgeConfig(model="claude-sonnet")),
                ),
                _with_profile(
                    "b", PurposeProfile(purpose_id="p-x", judge=JudgeConfig(enabled=True))
                ),
            ]
        )

        assert result.purpose_profile.judge.model == "claude-sonnet"

    def test_the_model_comparison_is_case_sensitive(self) -> None:
        """Two casings are two models, matching how the gate compares them at call time."""
        result = merge(
            [
                _with_profile(
                    "a",
                    PurposeProfile(purpose_id="p-x", judge=JudgeConfig(model="claude-sonnet")),
                ),
                _with_profile(
                    "b",
                    PurposeProfile(purpose_id="p-x", judge=JudgeConfig(model="Claude-Sonnet")),
                ),
            ]
        )

        assert result.permissions.can_query is False

    def test_no_judge_configured_leaves_judge_absent(self) -> None:
        result = merge(
            [
                _with_profile("a", PurposeProfile(purpose_id="p-x")),
                _with_profile("b", PurposeProfile(purpose_id="p-x")),
            ]
        )

        assert result.purpose_profile.judge is None, (
            "an absent judge must stay absent, or every purpose-bound policy grows a "
            "judge block and the canonical bytes change"
        )
        assert "judge" not in json.loads(serialize(result))["purposeProfile"]

    def test_one_policy_configuring_a_judge_is_enough_to_carry_it(self) -> None:
        """The paired direction of the case above."""
        result = merge(
            [
                _with_profile("a", PurposeProfile(purpose_id="p-x")),
                _with_profile(
                    "b", PurposeProfile(purpose_id="p-x", judge=JudgeConfig(enabled=True))
                ),
            ]
        )

        assert result.purpose_profile.judge.enabled is True

    def test_judge_fields_absent_on_both_sides_stay_absent(self) -> None:
        # None-defaulted rather than value-defaulted, so an unset threshold serializes as
        # absent. Value defaults would be written unconditionally, changing the signed
        # bytes of every purpose-bound policy.
        result = merge(
            [
                _with_profile(
                    "a", PurposeProfile(purpose_id="p-x", judge=JudgeConfig(enabled=True))
                ),
                _with_profile(
                    "b", PurposeProfile(purpose_id="p-x", judge=JudgeConfig(enabled=True))
                ),
            ]
        )

        judge = result.purpose_profile.judge
        assert judge.confidence_threshold is None
        assert judge.escalation_threshold is None
        assert judge.history_window is None
        assert judge.max_latency_ms is None
        assert judge.model is None
        assert json.loads(serialize(result))["purposeProfile"]["judge"] == {"enabled": True}


class TestPassThroughAndDescription:
    def test_a_single_policy_passes_its_profile_through_unchanged(self) -> None:
        profile = PurposeProfile(
            purpose_id="campaign-x-overlap",
            description="Identify overlapping segments.",
            allowed_actions=["aggregate_overlap"],
            prohibited_actions=["export_pii"],
            judge=JudgeConfig(enabled=True, model="claude-sonnet"),
        )

        result = merge([_with_profile("only", profile)])

        assert result.purpose_profile == profile

    def test_the_description_comes_from_the_first_policy_that_has_one(self) -> None:
        # `merge` is called with the list already ordered by ascending priority, so this
        # is the most specific policy's description.
        result = merge(
            [
                _with_profile("a", PurposeProfile(purpose_id="p-x"), priority=10),
                _with_profile(
                    "b",
                    PurposeProfile(purpose_id="p-x", description="the only description"),
                    priority=20,
                ),
            ]
        )

        assert result.purpose_profile.description == "the only description"

    def test_no_description_anywhere_stays_absent(self) -> None:
        result = merge(
            [
                _with_profile("a", PurposeProfile(purpose_id="p-x")),
                _with_profile("b", PurposeProfile(purpose_id="p-x")),
            ]
        )

        assert result.purpose_profile.description is None

    def test_an_empty_policy_list_is_still_deny_all(self) -> None:
        """The purpose check runs first, so it must not disturb the zero-policy path."""
        result = merge([])

        assert result.permissions.can_query is False
        assert result.purpose_profile is None
