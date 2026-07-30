from __future__ import annotations

from datetime import timedelta

import pytest

from conftest import load_fixture
from tolap_core.context import (
    _canonical_payload,
    _normalize_timestamp,
    build_security_context,
    deserialize_context,
    serialize_context,
    sign_context,
    validate_context,
)
from tolap_core.enums import SigningAlgorithm
from tolap_core.models import EffectivePolicy, PolicyPermissions, SecurityContext


class TestSignAndValidate:
    """Test signing and validation of security contexts."""

    def _make_effective_policy(self) -> EffectivePolicy:
        return EffectivePolicy(
            version="1.0",
            user_id="user-001",
            tenant_id="tenant-midwest-health",
            source_connection_id="ds-postgres-healthcare",
            source_profiles=["healthcare-analyst-db"],
            permissions=PolicyPermissions(
                can_query=True,
                read_only=True,
            ),
        )

    def test_sign_and_validate_hmac_sha256(self) -> None:
        policy = self._make_effective_policy()
        context = SecurityContext(effective_policy=policy)
        secret = "test-signing-key"

        signed = sign_context(context, secret, SigningAlgorithm.hmac_sha256)
        assert signed.signature is not None
        assert signed.algorithm == SigningAlgorithm.hmac_sha256
        assert validate_context(signed, secret) is True

    def test_sign_and_validate_hmac_sha512(self) -> None:
        policy = self._make_effective_policy()
        context = SecurityContext(effective_policy=policy)
        secret = "test-signing-key"

        signed = sign_context(context, secret, SigningAlgorithm.hmac_sha512)
        assert signed.signature is not None
        assert signed.algorithm == SigningAlgorithm.hmac_sha512
        assert validate_context(signed, secret) is True

    def test_invalid_key_fails_validation(self) -> None:
        policy = self._make_effective_policy()
        context = SecurityContext(effective_policy=policy)
        secret = "correct-key"

        signed = sign_context(context, secret)
        assert validate_context(signed, "wrong-key") is False

    def test_tampered_data_fails_validation(self) -> None:
        policy = self._make_effective_policy()
        context = SecurityContext(effective_policy=policy)
        secret = "test-key"

        signed = sign_context(context, secret)

        # Tamper with the policy
        signed.effective_policy.permissions.can_query = False
        assert validate_context(signed, secret) is False

    def test_missing_signature_fails(self) -> None:
        policy = self._make_effective_policy()
        context = SecurityContext(effective_policy=policy)
        assert validate_context(context, "any-key") is False


class TestSerializeDeserializeContext:
    """Test serialization round-trip for security contexts."""

    def test_round_trip(self) -> None:
        policy = EffectivePolicy(
            version="1.0",
            user_id="user-001",
            tenant_id="tenant-midwest-health",
            source_profiles=["test-policy"],
            permissions=PolicyPermissions(can_query=True, read_only=True),
        )
        context = build_security_context(
            user_id="user-001",
            tenant_id="tenant-midwest-health",
            policies=[policy],
            ttl=timedelta(hours=1),
        )
        signed = sign_context(context, "test-key")

        serialized = serialize_context(signed)
        assert isinstance(serialized, str)

        restored = deserialize_context(serialized, "test-key")
        assert restored.effective_policy.user_id == "user-001"
        assert restored.effective_policy.permissions.can_query is True

    def test_expired_context_raises(self) -> None:
        policy = EffectivePolicy(
            version="1.0",
            user_id="user-001",
            tenant_id="tenant-midwest-health",
            source_profiles=["test-policy"],
            permissions=PolicyPermissions(can_query=True),
        )
        # Use a negative TTL to create an already-expired context
        context = build_security_context(
            user_id="user-001",
            tenant_id="tenant-midwest-health",
            policies=[policy],
            ttl=timedelta(hours=-1),
        )
        signed = sign_context(context, "test-key")
        serialized = serialize_context(signed)

        with pytest.raises(ValueError, match="expired"):
            deserialize_context(serialized, "test-key")

    def test_wrong_key_raises(self) -> None:
        policy = EffectivePolicy(
            version="1.0",
            user_id="user-001",
            tenant_id="tenant-midwest-health",
            source_profiles=["test-policy"],
            permissions=PolicyPermissions(can_query=True),
        )
        context = build_security_context(
            user_id="user-001",
            tenant_id="tenant-midwest-health",
            policies=[policy],
            ttl=timedelta(hours=1),
        )
        signed = sign_context(context, "correct-key")
        serialized = serialize_context(signed)

        with pytest.raises(ValueError, match="Invalid signature"):
            deserialize_context(serialized, "wrong-key")


class TestKnownAnswer:
    """Test known-answer signing from fixture."""

    @staticmethod
    def _context_from_fixture(data: dict) -> SecurityContext:
        """Project the fixture payload into the canonical envelope shape.

        The fixture carries a single effective policy; the canonical signing
        payload wraps it in the envelope, taking issuedAt/expiresAt from the
        policy's resolvedAt/expiresAt so all three SDKs sign the same instants.
        """
        from tolap_core.serialization import deserialize_effective_policy

        policy = deserialize_effective_policy(data["payload"])
        return SecurityContext(
            effective_policy=policy,
            issued_at=policy.resolved_at,
            expires_at=policy.expires_at,
        )

    def test_hmac_sha256_matches_expected_signature(self) -> None:
        """Assert the fixture's cross-SDK expectedSignature byte-for-byte.

        A determinism-only assertion (sign twice, compare to itself) passes even
        when all three SDKs disagree with each other, which is exactly how the
        signing divergence went unnoticed. This test fails rather than skips when
        the fixture lacks its expected value -- a conditional pass would restore
        the very blind spot it exists to close. See spec section 11.
        """
        data = load_fixture("signing/hmac-sha256-known-answer.json")
        expected = data.get("expectedSignature")
        assert expected, "the cross-SDK known-answer fixture must carry an expectedSignature"

        signed = sign_context(
            self._context_from_fixture(data),
            data["secretKey"],
            SigningAlgorithm.hmac_sha256,
        )

        assert signed.signature == expected

    def test_canonical_payload_matches_fixture_bytes(self) -> None:
        """Assert the canonical signed bytes, not just the digest.

        Comparing bytes makes a cross-SDK mismatch diagnosable directly instead of
        leaving three identical-looking HMAC failures with no indication of which
        implementation serialized differently.
        """
        data = load_fixture("signing/hmac-sha256-known-answer.json")
        expected = data.get("canonicalPayload")
        assert expected, "the cross-SDK known-answer fixture must carry a canonicalPayload"

        payload = _canonical_payload(self._context_from_fixture(data))

        assert payload == expected

    def test_hmac_sha256_deterministic(self) -> None:
        """Verify that signing the same payload with the same key produces a consistent result."""
        data = load_fixture("signing/hmac-sha256-known-answer.json")

        signed = sign_context(
            self._context_from_fixture(data),
            data["secretKey"],
            SigningAlgorithm.hmac_sha256,
        )

        assert signed.signature is not None
        assert len(signed.signature) > 0

        # Sign again and verify deterministic
        signed2 = sign_context(
            self._context_from_fixture(data),
            data["secretKey"],
            SigningAlgorithm.hmac_sha256,
        )
        assert signed.signature == signed2.signature


class TestSubSecondKnownAnswer:
    """Cross-SDK conformance for MICROSECOND input timestamps (spec section 2 rule 5).

    The whole-second fixture cannot detect a precision mismatch: every runtime
    renders ``10:00:00`` the same way. This fixture's input carries microseconds
    (``.123456Z`` / ``.987654Z``) which MUST canonicalize to milliseconds
    (``.123Z`` / ``.987Z``). Without a mandated precision Python and .NET signed
    their native sub-second digits while JavaScript's ``Date`` could not represent
    them at all, so the same instant produced different bytes per language and the
    signature failed to verify across SDKs.
    """

    FIXTURE = "signing/hmac-sha256-subsecond.json"

    def test_canonical_payload_truncates_to_milliseconds(self) -> None:
        """Assert the fixture's canonical bytes, including the policy's own timestamps.

        The envelope's issuedAt/expiresAt are not the only instants in the signed
        bytes -- each policy repeats its own resolvedAt/expiresAt, and those were
        previously signed as the verbatim microsecond transport strings while .NET
        normalized them, which is precisely the divergence this fixture catches.
        """
        data = load_fixture(self.FIXTURE)
        expected = data.get("canonicalPayload")
        assert expected, "the sub-second conformance fixture must carry a canonicalPayload"

        payload = _canonical_payload(TestKnownAnswer._context_from_fixture(data))

        assert payload == expected
        # The microsecond input must not survive into the signed bytes anywhere.
        assert ".123456Z" not in payload
        assert ".987654Z" not in payload
        assert payload.count("2026-03-01T08:30:15.123Z") == 2
        assert payload.count("2026-03-01T09:30:15.987Z") == 2

    def test_hmac_sha256_matches_expected_signature(self) -> None:
        data = load_fixture(self.FIXTURE)
        expected = data.get("expectedSignature")
        assert expected, "the sub-second conformance fixture must carry an expectedSignature"

        signed = sign_context(
            TestKnownAnswer._context_from_fixture(data),
            data["secretKey"],
            SigningAlgorithm.hmac_sha256,
        )

        assert signed.signature == expected

    def test_hmac_sha512_matches_expected_signature(self) -> None:
        data = load_fixture(self.FIXTURE)
        expected = data.get("expectedSignatureSha512")
        assert expected, (
            "the sub-second conformance fixture must carry an expectedSignatureSha512"
        )

        signed = sign_context(
            TestKnownAnswer._context_from_fixture(data),
            data["secretKey"],
            SigningAlgorithm.hmac_sha512,
        )

        assert signed.signature == expected


class TestTimestampNormalization:
    """Spec section 2 rule 5: the normalization table, asserted directly.

    These seven cases are identical in all three SDKs. Asserting them here (rather
    than only through a signature) means a precision regression reports "expected
    .123Z, got .123456Z" instead of an opaque HMAC mismatch that cannot distinguish
    a truncation bug from a key or key-ordering bug.
    """

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            # Whole seconds: no fractional part is emitted at all.
            ("2026-01-15T10:00:00Z", "2026-01-15T10:00:00Z"),
            # "+00:00" and "Z" are the same instant and must fold to the same bytes.
            ("2026-01-15T10:00:00+00:00", "2026-01-15T10:00:00Z"),
            # A zero fraction is dropped rather than rendered as ".000".
            ("2026-01-15T10:00:00.000Z", "2026-01-15T10:00:00Z"),
            # Exactly three digits pass through unchanged.
            ("2026-01-15T10:00:00.123Z", "2026-01-15T10:00:00.123Z"),
            # Microseconds truncate to milliseconds.
            ("2026-01-15T10:00:00.123456Z", "2026-01-15T10:00:00.123Z"),
            # Truncation, never rounding: .1239 -> .123, not .124.
            ("2026-01-15T10:00:00.1239Z", "2026-01-15T10:00:00.123Z"),
            # Truncation must not carry into the next second.
            ("2026-01-15T10:00:00.999999Z", "2026-01-15T10:00:00.999Z"),
        ],
    )
    def test_normalization_table(self, value: str, expected: str) -> None:
        assert _normalize_timestamp(value) == expected

    def test_truncation_never_rounds_an_expiry_later(self) -> None:
        """Rounding could move an expiry past what the issuer intended."""
        assert _normalize_timestamp("2026-01-15T10:00:00.9999Z") == "2026-01-15T10:00:00.999Z"

    def test_non_utc_offset_is_converted_not_relabelled(self) -> None:
        assert _normalize_timestamp("2026-01-15T05:00:00.123456-05:00") == (
            "2026-01-15T10:00:00.123Z"
        )
