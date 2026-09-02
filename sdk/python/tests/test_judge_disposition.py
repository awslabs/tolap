"""Mapping a judge verdict onto a disposition (spec section 15.4).

The judge is the one non-deterministic component in the enforcement path, so the rule that
matters is not "does it decide correctly" -- it cannot be tested for that -- but "does
every answer it cannot give confidently end up somewhere safe". Every case below is either
a confident verdict or an escalation, and escalation denies unless a handler is wired.
"""

from __future__ import annotations

import math

import pytest
from conftest import load_fixture

from tolap_core.judge import (
    DEFAULT_CONFIDENCE_THRESHOLD,
    DEFAULT_ESCALATION_THRESHOLD,
    DEFAULT_HISTORY_WINDOW,
    DEFAULT_MAX_LATENCY_MS,
    JudgeDisposition,
    JudgeResult,
    judge_disposition,
)
from tolap_core.models import JudgeConfig
from tolap_core.serialization import _deser_judge_config


FIXTURE = "purpose-binding/judge-dispositions.json"
CASES = {case["name"]: case for case in load_fixture(FIXTURE)["cases"]}

STANDARD = JudgeConfig(confidence_threshold=0.85, escalation_threshold=0.60)


class TestTheSharedFixture:
    @pytest.mark.parametrize("name", sorted(CASES), ids=lambda n: n)
    def test_the_disposition_matches_the_shared_fixture(self, name: str) -> None:
        case = CASES[name]
        result = JudgeResult(
            aligned=case["result"]["aligned"],
            confidence=case["result"]["confidence"],
            reasoning=case["result"]["reasoning"],
        )
        # Read through the real deserializer, so an empty `config` object exercises the
        # all-fields-absent path rather than a hand-built default.
        config = _deser_judge_config(case["config"])

        assert judge_disposition(result, config) == JudgeDisposition[case["expected"]], (
            f"case {name!r}"
        )

    def test_the_fixture_covers_all_three_dispositions(self) -> None:
        """A corpus that had drifted into all-escalate would satisfy most cases above
        while proving nothing about the confident paths."""
        outcomes = {case["expected"] for case in CASES.values()}

        assert outcomes == {"allow", "block", "escalate"}

    def test_every_fixture_disposition_names_a_real_member(self) -> None:
        """A typo in the fixture would otherwise surface as a KeyError inside a case."""
        assert all(
            case["expected"] in JudgeDisposition.__members__ for case in CASES.values()
        )


class TestDefaults:
    def test_an_absent_config_uses_the_documented_defaults(self) -> None:
        # A profile may enable the judge and configure nothing. The defaults have to come
        # from somewhere, and reading them at decision time rather than baking them into
        # the model keeps an unset threshold serializing as absent.
        assert (
            judge_disposition(JudgeResult(True, 0.9, "above the default bar"), None)
            is JudgeDisposition.allow
        )
        assert (
            judge_disposition(JudgeResult(True, 0.7, "in the default band"), None)
            is JudgeDisposition.escalate
        )
        assert (
            judge_disposition(JudgeResult(False, 0.9, "confidently misaligned"), None)
            is JudgeDisposition.block
        )

    def test_an_empty_config_behaves_like_an_absent_one(self) -> None:
        """A judge block that configured only ``enabled`` must not change the thresholds."""
        empty = JudgeConfig(enabled=True)

        assert (
            judge_disposition(JudgeResult(True, 0.9, "x"), empty) is JudgeDisposition.allow
        )
        assert (
            judge_disposition(JudgeResult(True, 0.7, "x"), empty)
            is JudgeDisposition.escalate
        )

    def test_the_defaults_match_the_schema_documentation(self) -> None:
        # The schema documents these as its `default` annotations, which are advisory to a
        # validator and therefore not enforced by one. If the two drifted, a policy author
        # reading the schema would configure against numbers the SDK does not use.
        assert DEFAULT_CONFIDENCE_THRESHOLD == 0.85
        assert DEFAULT_ESCALATION_THRESHOLD == 0.60
        assert DEFAULT_MAX_LATENCY_MS == 2000
        assert DEFAULT_HISTORY_WINDOW == 10

    def test_the_default_escalation_threshold_is_below_the_confidence_one(self) -> None:
        # The defaults must not themselves be the inverted configuration that escalates
        # everything, which would make an unconfigured judge useless in a way no individual
        # disposition test would reveal.
        assert DEFAULT_ESCALATION_THRESHOLD < DEFAULT_CONFIDENCE_THRESHOLD

    def test_a_configured_confidence_bar_does_not_reset_the_escalation_floor(self) -> None:
        """Each bound falls back independently, so a half-configured judge is coherent.

        0.75 clears a configured bar of 0.70 while sitting below the 0.85 default, so a
        fallback that reset both would escalate here.
        """
        only_confidence = JudgeConfig(confidence_threshold=0.70)

        assert (
            judge_disposition(JudgeResult(True, 0.75, "x"), only_confidence)
            is JudgeDisposition.allow
        )
        assert (
            judge_disposition(JudgeResult(True, 0.75, "x"), None) is JudgeDisposition.escalate
        )

    def test_a_configured_escalation_floor_does_not_disturb_the_confidence_bar(self) -> None:
        """And it changes no disposition on its own, which is worth stating.

        Below the escalation floor and inside the ambiguous band both map to ``escalate``
        -- there are only three dispositions and no "refer urgently" among them. So while
        the floor is a real policy field (it is merged, and it is what makes an inverted
        pair detectable), it cannot by itself turn one outcome into another. Pinned so that
        a future reader does not conclude the field is being ignored, and so that a change
        which *did* give it an independent effect fails here.
        """
        raised_floor = JudgeConfig(escalation_threshold=0.80)

        for confidence in (0.1, 0.5, 0.79, 0.84):
            assert judge_disposition(
                JudgeResult(True, confidence, "x"), raised_floor
            ) is judge_disposition(JudgeResult(True, confidence, "x"), None)

        # And the bar it did not configure still decides the confident case.
        assert (
            judge_disposition(JudgeResult(True, 0.9, "x"), raised_floor)
            is JudgeDisposition.allow
        )


class TestThresholdBoundaries:
    @pytest.mark.parametrize(
        ("confidence", "expected"),
        [
            (0.85, JudgeDisposition.allow),
            (0.8499, JudgeDisposition.escalate),
            (0.6, JudgeDisposition.escalate),
            (0.5999, JudgeDisposition.escalate),
        ],
    )
    def test_the_thresholds_are_inclusive_at_their_bound(
        self, confidence: float, expected: JudgeDisposition
    ) -> None:
        # "At or above" for confidence and "below" for escalation. Off-by-one at a boundary
        # is the classic way a threshold ends up one case wider than intended, and here
        # that case is an allow.
        assert judge_disposition(JudgeResult(True, confidence, "boundary"), STANDARD) is expected

    def test_equal_thresholds_leave_no_ambiguous_band(self) -> None:
        # Equal is not inverted: it is a valid configuration that says "decide or escalate,
        # with nothing in between".
        equal = JudgeConfig(confidence_threshold=0.8, escalation_threshold=0.8)

        assert (
            judge_disposition(JudgeResult(True, 0.8, "at both bounds"), equal)
            is JudgeDisposition.allow
        )
        assert (
            judge_disposition(JudgeResult(False, 0.8, "at both bounds"), equal)
            is JudgeDisposition.block
        )
        assert (
            judge_disposition(JudgeResult(True, 0.79, "just below"), equal)
            is JudgeDisposition.escalate
        )

    def test_inverted_thresholds_escalate_rather_than_guessing(self) -> None:
        # Merging two judge configs can produce this, since both thresholds take the
        # maximum independently. There is no reading of the configuration to act on, so
        # neither a confident allow nor a confident block is available.
        inverted = JudgeConfig(confidence_threshold=0.6, escalation_threshold=0.9)

        assert (
            judge_disposition(JudgeResult(True, 0.95, "would otherwise allow"), inverted)
            is JudgeDisposition.escalate
        )
        assert (
            judge_disposition(JudgeResult(False, 0.95, "would otherwise block"), inverted)
            is JudgeDisposition.escalate
        )

    def test_the_inversion_check_runs_before_the_band_checks(self) -> None:
        """An inverted pair escalates at every confidence, not only a high one.

        Otherwise the check would be redundant with the band comparisons for most inputs
        and only bite at the top, which is where it looks like it works.
        """
        inverted = JudgeConfig(confidence_threshold=0.6, escalation_threshold=0.9)

        for confidence in (0.0, 0.5, 0.7, 1.0):
            assert (
                judge_disposition(JudgeResult(True, confidence, "x"), inverted)
                is JudgeDisposition.escalate
            )


class TestUnusableConfidence:
    @pytest.mark.parametrize(
        "confidence",
        [-0.1, 1.5, math.inf, -math.inf, math.nan],
        ids=["below-zero", "above-one", "+inf", "-inf", "nan"],
    )
    def test_a_confidence_outside_the_unit_range_escalates(self, confidence: float) -> None:
        # A judge reporting 1.5 has malfunctioned. Comparing that against a threshold would
        # hand a broken answer more authority than a correct one -- 1.5 clears every bar.
        # nan is here too because it fails every comparison and would otherwise fall
        # through to whichever branch happened to be last.
        assert (
            judge_disposition(JudgeResult(True, confidence, "out of range"), STANDARD)
            is JudgeDisposition.escalate
        )

    @pytest.mark.parametrize("confidence", [-0.1, 1.5, math.nan])
    def test_an_out_of_range_confidence_escalates_even_when_misaligned(
        self, confidence: float
    ) -> None:
        """It must not become a *block* either: the verdict is unusable, not adverse.

        Blocking would be safe here but wrong to record -- an audit trail would show a
        confident refusal where the judge in fact gave no answer at all.
        """
        assert (
            judge_disposition(JudgeResult(False, confidence, "out of range"), STANDARD)
            is JudgeDisposition.escalate
        )

    def test_the_range_check_runs_before_the_inversion_check(self) -> None:
        """Both would escalate, so the ordering is asserted rather than inferred.

        A malformed result must not be able to reach the threshold comparisons at all,
        because 1.5 clears every bar that could be configured.
        """
        inverted = JudgeConfig(confidence_threshold=0.6, escalation_threshold=0.9)

        assert (
            judge_disposition(JudgeResult(True, 1.5, "x"), inverted)
            is JudgeDisposition.escalate
        )


class TestAlignmentOnlyDecidesTheConfidentCase:
    def test_below_the_bar_alignment_is_irrelevant(self) -> None:
        # A low-confidence "aligned" is not an allow. This is the asymmetry that keeps the
        # judge subtractive.
        assert (
            judge_disposition(JudgeResult(True, 0.3, "unsure but positive"), STANDARD)
            is JudgeDisposition.escalate
        )
        assert (
            judge_disposition(JudgeResult(False, 0.3, "unsure and negative"), STANDARD)
            is JudgeDisposition.escalate
        )

    def test_zero_and_full_confidence_are_handled(self) -> None:
        assert (
            judge_disposition(JudgeResult(True, 0.0, "no signal"), STANDARD)
            is JudgeDisposition.escalate
        )
        assert (
            judge_disposition(JudgeResult(False, 1.0, "explicit exfiltration"), STANDARD)
            is JudgeDisposition.block
        )
        assert (
            judge_disposition(JudgeResult(True, 1.0, "plainly on task"), STANDARD)
            is JudgeDisposition.allow
        )

    def test_escalate_is_not_an_allow(self) -> None:
        """Pinned as a distinct member, because the whole safety argument rests on it.

        A wrapper with no escalation handler must deny; if ``escalate`` were an alias for
        ``allow`` the entire judge would be advisory in exactly the deployments that never
        built a review step.
        """
        assert JudgeDisposition.escalate is not JudgeDisposition.allow
        assert len(JudgeDisposition) == 3
