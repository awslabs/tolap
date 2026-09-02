"""The sliding window a judge reads its context from (spec section 15.4).

Small enough to look like it needs no tests, which is why it gets them: purpose drift is a
property of a sequence, so a window that silently returns the wrong entries -- or the right
entries in the wrong order -- hands the judge a trajectory that never happened, and the
judge has no way to notice.
"""

from __future__ import annotations

import pytest

from tolap_core.history import ToolCallHistory
from tolap_core.judge import DEFAULT_HISTORY_WINDOW, JudgeRequest
from tolap_core.models import PurposeProfile


class TestConstruction:
    def test_a_fresh_history_is_empty(self) -> None:
        assert ToolCallHistory().get_recent() == []

    def test_the_default_bound_matches_the_documented_history_window(self) -> None:
        # The schema documents historyWindow's default as 10. A different default here
        # would mean an unconfigured judge saw a different amount of history than the
        # policy author was told.
        assert ToolCallHistory().max_size == DEFAULT_HISTORY_WINDOW

    @pytest.mark.parametrize("max_size", [0, -1, -(2**31)])
    def test_a_non_positive_window_is_refused(self, max_size: int) -> None:
        # A zero-size window would make record a no-op and hand the judge an empty
        # history, which reads as a fresh conversation -- precisely the state a drifting
        # agent benefits from. Refused loudly rather than clamped, because clamping to 1
        # would silently give a caller a window they did not ask for.
        with pytest.raises(ValueError, match="at least one entry"):
            ToolCallHistory(max_size)

    def test_a_window_of_one_is_accepted(self) -> None:
        """The paired control: the bound is ``< 1``, not ``< 2``."""
        assert ToolCallHistory(1).max_size == 1


class TestRetention:
    def test_below_the_bound_everything_is_retained_oldest_first(self) -> None:
        history = ToolCallHistory(max_size=5)

        history.record("count_segments()")
        history.record("aggregate_overlap(campaign-x)")

        assert history.get_recent() == ["count_segments()", "aggregate_overlap(campaign-x)"]
        assert len(history) == 2

    def test_at_the_bound_everything_is_retained(self) -> None:
        history = ToolCallHistory(max_size=3)

        for call in ("a", "b", "c"):
            history.record(call)

        assert history.get_recent() == ["a", "b", "c"]

    def test_above_the_bound_the_oldest_is_evicted(self) -> None:
        history = ToolCallHistory(max_size=3)

        for call in ("a", "b", "c", "d", "e"):
            history.record(call)

        assert history.get_recent() == ["c", "d", "e"]
        assert len(history) == 3

    def test_a_window_of_one_keeps_only_the_latest(self) -> None:
        # The narrowest legal window. Worth its own case because an off-by-one in the
        # eviction rule shows up here and nowhere else.
        history = ToolCallHistory(max_size=1)

        history.record("a")
        history.record("b")

        assert history.get_recent() == ["b"]

    def test_duplicates_and_empty_strings_are_kept(self) -> None:
        # Not a set. An agent repeating the same call ten times is a signal, and
        # de-duplicating would erase exactly the pattern the judge is looking for.
        history = ToolCallHistory(max_size=4)

        history.record("aggregate_overlap()")
        history.record("aggregate_overlap()")
        history.record("")

        assert history.get_recent() == ["aggregate_overlap()", "aggregate_overlap()", ""]

    def test_recording_none_is_refused(self) -> None:
        """An accidental ``None`` would render in a prompt as the string "None"."""
        with pytest.raises(ValueError, match="not None"):
            ToolCallHistory().record(None)  # type: ignore[arg-type]


class TestSnapshotSemantics:
    def test_get_recent_returns_a_copy(self) -> None:
        # A caller holding the result must not see it change underneath them, and must not
        # be able to mutate the window by writing into what they were handed.
        history = ToolCallHistory(max_size=2)
        history.record("a")

        snapshot = history.get_recent()
        history.record("b")
        snapshot[0] = "mutated"

        assert snapshot == ["mutated"]
        assert history.get_recent() == ["a", "b"]

    def test_clear_discards_everything_but_keeps_the_bound(self) -> None:
        history = ToolCallHistory(max_size=2)
        history.record("a")

        history.clear()

        assert history.get_recent() == []
        assert len(history) == 0
        assert history.max_size == 2, (
            "clearing a conversation does not reconfigure the window"
        )

    def test_recording_after_clear_still_respects_the_bound(self) -> None:
        history = ToolCallHistory(max_size=2)
        history.clear()

        for call in ("a", "b", "c"):
            history.record(call)

        assert history.get_recent() == ["b", "c"]


class TestFeedingAJudgeRequest:
    def test_the_trajectory_reaches_the_request_in_chronological_order(self) -> None:
        # The reason order is asserted at all: a judge reading a trajectory backwards sees
        # an agent narrowing its scope rather than widening it, which inverts the finding.
        history = ToolCallHistory(max_size=3)
        history.record("count_segments()")
        history.record("aggregate_overlap(campaign-x)")
        history.record("export_csv(customer_segments)")

        request = JudgeRequest(
            purpose=PurposeProfile(purpose_id="campaign-x-overlap"),
            current_tool_call="export_csv(customer_segments)",
            recent_history=history.get_recent(),
            max_latency_ms=2000,
        )

        assert request.recent_history == [
            "count_segments()",
            "aggregate_overlap(campaign-x)",
            "export_csv(customer_segments)",
        ]
