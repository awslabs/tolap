from __future__ import annotations

from datetime import timedelta

import pytest

from conftest import load_fixture
from tolap_core.context import (
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
                can_export=False,
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
            permissions=PolicyPermissions(can_query=True, can_export=False, read_only=True),
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

    def test_hmac_sha256_deterministic(self) -> None:
        """Verify that signing the same payload with the same key produces a consistent result."""
        data = load_fixture("signing/hmac-sha256-known-answer.json")

        # Build the effective policy from the fixture payload
        from tolap_core.serialization import deserialize_effective_policy
        policy = deserialize_effective_policy(data["payload"])

        context = SecurityContext(effective_policy=policy)
        signed = sign_context(context, data["secretKey"], SigningAlgorithm.hmac_sha256)

        assert signed.signature is not None
        assert len(signed.signature) > 0

        # Sign again and verify deterministic
        context2 = SecurityContext(effective_policy=policy)
        signed2 = sign_context(context2, data["secretKey"], SigningAlgorithm.hmac_sha256)
        assert signed.signature == signed2.signature
