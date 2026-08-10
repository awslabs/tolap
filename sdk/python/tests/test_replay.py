"""Replay detection for signed security contexts (spec section 13).

A signed context was previously a bearer credential replayable for its full TTL:
capture it and it worked until it expired, with expiry the only bound. `jti` plus
a `ReplayGuard` closes that. The two halves matter separately:

* the identifier is *inside the signed payload*, so it cannot be stripped or
  swapped to dodge the check without invalidating the signature;
* the guard is the state the SDK deliberately does not assume, supplied by the
  integrator.

A test that only asserted "the same context twice is rejected" would pass against
an implementation that left `jti` outside the signature -- where an attacker
simply removes it. The stripping and swapping cases below are the ones that
distinguish a real fix.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest

from tolap_core.context import (
    InMemoryReplayGuard,
    _canonical_payload,
    build_security_context,
    deserialize_context,
    serialize_context,
    sign_context,
    validate_context,
)
from tolap_core.models import EffectivePolicy, PolicyPermissions, SecurityContext

KEY = "test-signing-key-do-not-use-in-production"


def _policy() -> EffectivePolicy:
    return EffectivePolicy(
        version="1.0",
        user_id="user-001",
        tenant_id="tenant-001",
        permissions=PolicyPermissions(can_query=True, read_only=True),
    )


def _signed(jti: str | None = None) -> str:
    context = build_security_context(
        "user-001", "tenant-001", [_policy()], ttl=timedelta(hours=1), jti=jti
    )
    return serialize_context(sign_context(context, KEY))


def _decode(serialized: str) -> dict:
    return json.loads(base64.b64decode(serialized))


def _encode(payload: dict) -> str:
    return base64.b64encode(
        json.dumps(payload).encode("utf-8")
    ).decode("utf-8")


class TestJtiIsMinted:
    def test_build_mints_a_jti_by_default(self) -> None:
        context = build_security_context("user-001", "tenant-001", [_policy()])
        assert context.jti
        assert len(context.jti) >= 32

    def test_each_context_gets_a_distinct_jti(self) -> None:
        first = build_security_context("user-001", "tenant-001", [_policy()])
        second = build_security_context("user-001", "tenant-001", [_policy()])
        assert first.jti != second.jti

    def test_explicit_jti_is_honoured(self) -> None:
        context = build_security_context(
            "user-001", "tenant-001", [_policy()], jti="ctx-abc"
        )
        assert context.jti == "ctx-abc"

    def test_empty_jti_opts_out(self) -> None:
        context = build_security_context("user-001", "tenant-001", [_policy()], jti="")
        assert context.jti is None


class TestJtiIsSigned:
    """The half that makes the guard non-bypassable."""

    def test_jti_is_inside_the_signed_payload(self) -> None:
        context = build_security_context(
            "user-001", "tenant-001", [_policy()], jti="ctx-abc"
        )
        assert '"jti":"ctx-abc"' in _canonical_payload(context)

    def test_stripping_the_jti_invalidates_the_signature(self) -> None:
        """The attack a guard alone would not stop."""
        context = sign_context(
            build_security_context(
                "user-001", "tenant-001", [_policy()], jti="ctx-abc"
            ),
            KEY,
        )
        assert validate_context(context, KEY) is True

        context.jti = None
        assert validate_context(context, KEY) is False

    def test_swapping_the_jti_invalidates_the_signature(self) -> None:
        """Otherwise a replayer just mints a fresh id per replay."""
        context = sign_context(
            build_security_context(
                "user-001", "tenant-001", [_policy()], jti="ctx-abc"
            ),
            KEY,
        )
        context.jti = "ctx-xyz"
        assert validate_context(context, KEY) is False

    def test_absent_jti_preserves_the_legacy_signature(self) -> None:
        """Backward compatibility: no `jti` signs exactly as it did before."""
        without = build_security_context(
            "user-001", "tenant-001", [_policy()], jti=""
        )
        without.issued_at = "2026-01-15T10:00:00Z"
        without.expires_at = "2026-01-15T11:00:00Z"

        legacy = SecurityContext(
            effective_policy=_policy(),
            issued_at="2026-01-15T10:00:00Z",
            expires_at="2026-01-15T11:00:00Z",
        )

        assert _canonical_payload(without) == _canonical_payload(legacy)


class TestReplayGuardRejectsReuse:
    def test_first_use_is_accepted(self) -> None:
        guard = InMemoryReplayGuard()
        context = deserialize_context(_signed(), KEY, replay_guard=guard)
        assert context.effective_policy.permissions.can_query is True

    def test_second_use_of_the_same_context_is_rejected(self) -> None:
        guard = InMemoryReplayGuard()
        serialized = _signed()

        deserialize_context(serialized, KEY, replay_guard=guard)

        with pytest.raises(ValueError, match="replay"):
            deserialize_context(serialized, KEY, replay_guard=guard)

    def test_distinct_contexts_both_succeed(self) -> None:
        """The guard must not reject merely because a user appeared twice."""
        guard = InMemoryReplayGuard()
        deserialize_context(_signed(), KEY, replay_guard=guard)
        deserialize_context(_signed(), KEY, replay_guard=guard)

    def test_replay_is_allowed_without_a_guard(self) -> None:
        """Documents the default: no guard means TTL-bounded replay, as specified."""
        serialized = _signed()
        deserialize_context(serialized, KEY)
        deserialize_context(serialized, KEY)

    def test_separate_guards_do_not_share_state(self) -> None:
        """Pins the documented limitation of the in-memory guard."""
        serialized = _signed()
        deserialize_context(serialized, KEY, replay_guard=InMemoryReplayGuard())
        deserialize_context(serialized, KEY, replay_guard=InMemoryReplayGuard())


class TestGuardRequiresAJti:
    def test_context_without_a_jti_is_rejected_when_guarding(self) -> None:
        """Skipping the check for a jti-less context is the failure mode to avoid."""
        with pytest.raises(ValueError, match="requires a 'jti'"):
            deserialize_context(_signed(jti=""), KEY, replay_guard=InMemoryReplayGuard())

    def test_a_forged_jti_is_rejected_before_the_guard_sees_it(self) -> None:
        """An attacker cannot register an id of their choosing.

        Adding a `jti` to a context signed without one changes the signed bytes,
        so it fails on signature -- it never reaches the guard.
        """
        payload = _decode(_signed(jti=""))
        payload["jti"] = "attacker-chosen"

        with pytest.raises(ValueError, match="Invalid signature"):
            deserialize_context(
                _encode(payload), KEY, replay_guard=InMemoryReplayGuard()
            )


class TestGuardOrdering:
    def test_expired_context_does_not_consume_its_jti(self) -> None:
        """Ordering matters: otherwise a replayed *expired* context burns a live id.

        If the guard ran before expiry validation, an attacker could pre-register
        the id of a context that had not been used yet, and the legitimate holder
        would then be refused.
        """
        guard = InMemoryReplayGuard()
        context = build_security_context(
            "user-001", "tenant-001", [_policy()], jti="ctx-abc"
        )
        context.issued_at = "2020-01-01T00:00:00Z"
        context.expires_at = "2020-01-01T01:00:00Z"
        expired = serialize_context(sign_context(context, KEY))

        with pytest.raises(ValueError, match="expired"):
            deserialize_context(expired, KEY, replay_guard=guard)

        # The id was never consumed, so a fresh context using it still works.
        assert guard.check_and_register("ctx-abc", None) is True

    def test_bad_signature_does_not_consume_its_jti(self) -> None:
        guard = InMemoryReplayGuard()
        payload = _decode(_signed(jti="ctx-abc"))
        payload["signature"] = base64.b64encode(b"wrong").decode("utf-8")

        with pytest.raises(ValueError, match="Invalid signature"):
            deserialize_context(_encode(payload), KEY, replay_guard=guard)

        assert guard.check_and_register("ctx-abc", None) is True


class TestInMemoryReplayGuard:
    def test_check_and_register_is_first_wins(self) -> None:
        guard = InMemoryReplayGuard()
        assert guard.check_and_register("a", None) is True
        assert guard.check_and_register("a", None) is False

    def test_distinct_ids_are_independent(self) -> None:
        guard = InMemoryReplayGuard()
        assert guard.check_and_register("a", None) is True
        assert guard.check_and_register("b", None) is True

    def test_entries_are_dropped_once_expired(self) -> None:
        """Memory is bounded by one TTL's worth of contexts, not unbounded."""
        guard = InMemoryReplayGuard()
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat().replace(
            "+00:00", "Z"
        )
        assert guard.check_and_register("a", past) is True

        # A later call sweeps the expired entry; the id becomes reusable, which is
        # safe because a context carrying it would now fail the expiry check.
        assert guard.check_and_register("b", None) is True
        assert guard.check_and_register("a", None) is True

    def test_unparseable_expiry_does_not_pin_an_entry_forever(self) -> None:
        guard = InMemoryReplayGuard()
        assert guard.check_and_register("a", "not-a-date") is True
        # Still registered (bounded fallback), so a replay is caught.
        assert guard.check_and_register("a", "not-a-date") is False

    def test_is_safe_under_concurrent_use(self) -> None:
        """Exactly one caller may win a race for the same id."""
        import threading

        guard = InMemoryReplayGuard()
        results: list[bool] = []
        lock = threading.Lock()

        def attempt() -> None:
            outcome = guard.check_and_register("contended", None)
            with lock:
                results.append(outcome)

        threads = [threading.Thread(target=attempt) for _ in range(24)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert sum(results) == 1, "exactly one caller may register a given jti"
