"""The two canonical-form rules a cross-SDK parity audit found all three SDKs getting wrong.

Neither is observable through an access decision: both produce identical enforcement and differ
only in the *signed bytes*. So no test comparing what a policy permits could have caught either,
and the only thing that did was comparing bytes across the three languages -- which is exactly
what canonical-enforcement-spec.md section 14 recommends and why it recommends it.

The fixture is shared, so .NET and TypeScript assert the same table.
"""

from __future__ import annotations

import importlib
import json
import os
from pathlib import Path

import pytest
from conftest import FIXTURES_DIR

FIXTURE = json.loads(
    (FIXTURES_DIR / "canonical-form" / "number-and-timestamp-forms.json").read_text()
)


def _rule(name: str) -> dict:
    return next(r for r in FIXTURE["rules"] if r["rule"] == name)


class TestWholeNumberFloatsRenderAsIntegers:
    """``1.0`` must sign as ``1``, matching .NET and TypeScript."""

    @pytest.mark.parametrize(
        ("value", "expected"),
        [(c["input"], c["canonical"]) for c in _rule("whole-number-floats-render-as-integers")["cases"]],
    )
    def test_matches_the_shared_table(self, value: float | int, expected: str) -> None:
        from tolap_core.context import _shorten_whole_floats

        assert json.dumps(_shorten_whole_floats(value), separators=(",", ":")) == expected

    def test_a_boolean_is_not_shortened_into_a_number(self) -> None:
        """The trap in the fix rather than in the bug.

        Python's ``bool`` is a subclass of ``int``, so a numeric coercion that does not exclude
        it turns ``true`` into ``1`` -- a second and worse divergence introduced by the fix for
        the first, and one that would change the bytes of every policy carrying a permission
        flag rather than only those carrying a whole-number threshold.
        """
        from tolap_core.context import _shorten_whole_floats

        assert json.dumps(_shorten_whole_floats(True), separators=(",", ":")) == "true"
        assert json.dumps(_shorten_whole_floats(False), separators=(",", ":")) == "false"

    def test_it_reaches_nested_values(self) -> None:
        from tolap_core.context import _shorten_whole_floats

        rendered = json.dumps(
            _shorten_whole_floats({"a": [1.0, {"b": 0.0}], "c": 0.85}),
            separators=(",", ":"),
            sort_keys=True,
        )

        assert rendered == '{"a":[1,{"b":0}],"c":0.85}'

    def test_a_whole_number_threshold_signs_as_an_integer(self) -> None:
        """End to end, through the real signing projection.

        The unit above tests the helper; this tests that the helper is actually reached from
        ``_canonical_payload``. A correct helper nobody calls is the shape of bug this whole
        audit kept finding.
        """
        from tolap_core.context import _canonical_payload
        from tolap_core.models import (
            EffectivePolicy,
            JudgeConfig,
            PolicyPermissions,
            PurposeProfile,
            SecurityContext,
        )

        policy = EffectivePolicy(
            version="1.0",
            user_id="u",
            tenant_id="t",
            source_connection_id="db:m:s",
            resolved_at="2026-09-01T10:00:00Z",
            expires_at="2026-09-01T11:00:00Z",
            source_profiles=["p"],
            permissions=PolicyPermissions(can_query=True, read_only=True),
            purpose_profile=PurposeProfile(
                "campaign-x-overlap",
                judge=JudgeConfig(
                    enabled=True, confidence_threshold=1.0, escalation_threshold=0.0
                ),
            ),
        )
        payload = _canonical_payload(
            SecurityContext(
                effective_policy=policy,
                issued_at="2026-09-01T10:00:00Z",
                expires_at="2026-09-01T11:00:00Z",
            )
        )

        assert '"confidenceThreshold":1' in payload
        assert '"confidenceThreshold":1.0' not in payload
        assert '"escalationThreshold":0' in payload
        assert '"enabled":true' in payload, "a boolean survived as a boolean"


class TestOffsetlessTimestampsAreUtc:
    """An ISO 8601 date-time with no offset means UTC, never the host's local time."""

    @pytest.mark.parametrize(
        ("value", "expected"),
        [(c["input"], c["canonical"]) for c in _rule("offsetless-timestamps-are-utc")["cases"]],
    )
    @pytest.mark.parametrize("timezone", _rule("offsetless-timestamps-are-utc")["timezones"])
    def test_matches_the_shared_table_under_every_timezone(
        self, value: str, expected: str, timezone: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Parametrised over TZ because CI runs UTC-only.

        .NET and TypeScript both read an offset-less value as *local* time, so the same JSON
        signed to three different instants on three hosts -- a divergence between two
        deployments of one SDK. A suite that only ever runs in UTC cannot see it, which is why
        the timezone is varied here rather than assumed.
        """
        import time

        monkeypatch.setenv("TZ", timezone)
        time.tzset()

        from tolap_core import context

        importlib.reload(context)
        assert context._normalize_timestamp(value) == expected

    @classmethod
    def teardown_class(cls) -> None:
        # The reload above rebinds the module for the rest of the session; put the host's own
        # zone back so a later test does not inherit Asia/Tokyo.
        import time

        os.environ.pop("TZ", None)
        time.tzset()
        from tolap_core import context

        importlib.reload(context)
