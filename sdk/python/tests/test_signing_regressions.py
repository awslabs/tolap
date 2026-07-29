"""Regression tests for signed-context integrity and expiry validation.

Defect 5: the HMAC covered only the effective policy, so issued_at/expires_at
lived on the envelope outside the signature and could be rewritten by anyone
holding a serialized context — no signing key required.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest

from tolap_core.context import (
    _canonical_payload,
    _normalize_timestamp,
    build_security_context,
    deserialize_context,
    serialize_context,
    sign_context,
    validate_context,
    validate_expiry,
)
from tolap_core.enums import SigningAlgorithm
from tolap_core.models import (
    EffectivePolicy,
    IntegrityBlock,
    PolicyPermissions,
    SecurityContext,
)
from tolap_mcp.options import SecureMcpServerOptions
from tolap_mcp.wrapper import SecureMcpToolWrapper


KEY = "signing-regression-key"


def _policy() -> EffectivePolicy:
    return EffectivePolicy(
        version="1.0",
        user_id="user-001",
        tenant_id="tenant-midwest-health",
        source_profiles=["healthcare-analyst-db"],
        permissions=PolicyPermissions(can_query=True, read_only=True),
    )


def _reencode(serialized: str, **overrides: object) -> str:
    """Rewrite envelope fields on a serialized context without the signing key."""
    data = json.loads(base64.b64decode(serialized))
    data.update(overrides)
    return base64.b64encode(json.dumps(data).encode("utf-8")).decode("utf-8")


class TestExpiryIsAuthenticated:
    """The replay exploit: rewrite expiresAt on a signed context."""

    def test_rewriting_expires_at_invalidates_the_signature(self) -> None:
        """No signing key needed: take an expired context, push expiry out a year."""
        expired = build_security_context("user-001", "tenant-midwest-health", [_policy()], ttl=timedelta(hours=-1))
        signed = sign_context(expired, KEY)
        serialized = serialize_context(signed)

        far_future = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat().replace("+00:00", "Z")
        forged = _reencode(serialized, expiresAt=far_future)

        with pytest.raises(ValueError, match="Invalid signature"):
            deserialize_context(forged, KEY)

    def test_rewriting_issued_at_invalidates_the_signature(self) -> None:
        signed = sign_context(
            build_security_context("user-001", "tenant-midwest-health", [_policy()], ttl=timedelta(hours=1)),
            KEY,
        )
        forged = _reencode(serialize_context(signed), issuedAt="1999-01-01T00:00:00Z")

        with pytest.raises(ValueError, match="Invalid signature"):
            deserialize_context(forged, KEY)

    def test_expiry_is_inside_the_signed_payload(self) -> None:
        context = build_security_context("user-001", "tenant-midwest-health", [_policy()], ttl=timedelta(hours=1))
        payload = json.loads(_canonical_payload(context))

        assert "expiresAt" in payload
        assert "issuedAt" in payload
        # The signed value is the *normalized* timestamp, not the raw string: spec
        # section 2 rule 5 truncates to milliseconds so all three SDKs sign the same
        # bytes (JavaScript's Date cannot represent Python's microseconds). Compare
        # against the normalized form -- asserting equality with the raw string would
        # be asserting that this SDK signs at a precision the others cannot reproduce.
        assert payload["expiresAt"] == _normalize_timestamp(context.expires_at)
        assert payload["issuedAt"] == _normalize_timestamp(context.issued_at)
        # Still the property that matters: the signed instant is the real instant,
        # truncated at most a millisecond below it.
        assert payload["expiresAt"][:20] == context.expires_at[:20]

    def test_changing_expiry_changes_the_signature(self) -> None:
        base = build_security_context("user-001", "tenant-midwest-health", [_policy()], ttl=timedelta(hours=1))
        first = sign_context(base, KEY).signature

        base.expires_at = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat().replace("+00:00", "Z")
        second = sign_context(base, KEY).signature

        assert first != second

    def test_tampering_with_the_policy_still_invalidates(self) -> None:
        signed = sign_context(SecurityContext(effective_policy=_policy()), KEY)

        signed.effective_policy.permissions.can_query = False

        assert validate_context(signed, KEY) is False


class TestCanonicalPayloadShape:
    """Spec sections 1 and 2: the canonical projection and serialization rules."""

    def test_payload_has_the_canonical_envelope_shape(self) -> None:
        context = build_security_context("user-001", "tenant-midwest-health", [_policy()], ttl=timedelta(hours=1))

        payload = json.loads(_canonical_payload(context))

        assert sorted(payload) == ["expiresAt", "issuedAt", "policies", "tenantId", "userId", "version"]
        assert payload["userId"] == "user-001"
        assert payload["tenantId"] == "tenant-midwest-health"
        assert isinstance(payload["policies"], list)
        assert len(payload["policies"]) == 1, "a single-policy SDK projects to a one-element array"

    def test_integrity_block_is_excluded_from_the_policy(self) -> None:
        policy = _policy()
        policy.integrity = IntegrityBlock(algorithm=SigningAlgorithm.hmac_sha256, signature="pretend")
        context = SecurityContext(effective_policy=policy, issued_at="2026-01-15T10:00:00Z", expires_at="2026-01-15T11:00:00Z")

        payload = json.loads(_canonical_payload(context))

        assert "integrity" not in payload
        assert "integrity" not in payload["policies"][0]

    def test_integrity_block_does_not_affect_the_signature(self) -> None:
        without = SecurityContext(
            effective_policy=_policy(),
            issued_at="2026-01-15T10:00:00Z",
            expires_at="2026-01-15T11:00:00Z",
        )
        policy_with = _policy()
        policy_with.integrity = IntegrityBlock(algorithm=SigningAlgorithm.hmac_sha256, signature="pretend")
        with_block = SecurityContext(
            effective_policy=policy_with,
            issued_at="2026-01-15T10:00:00Z",
            expires_at="2026-01-15T11:00:00Z",
        )

        assert _canonical_payload(without) == _canonical_payload(with_block)

    def test_keys_are_recursively_sorted_and_compact(self) -> None:
        context = SecurityContext(
            effective_policy=_policy(),
            issued_at="2026-01-15T10:00:00Z",
            expires_at="2026-01-15T11:00:00Z",
        )

        payload = _canonical_payload(context)

        assert " " not in payload
        assert "\n" not in payload
        keys = [k for k in json.loads(payload)]
        assert keys == sorted(keys)
        policy_keys = list(json.loads(payload)["policies"][0])
        assert policy_keys == sorted(policy_keys)

    def test_non_ascii_is_not_escaped(self) -> None:
        policy = _policy()
        policy.tenant_id = "tenant-münchen-é"
        context = SecurityContext(
            effective_policy=policy,
            issued_at="2026-01-15T10:00:00Z",
            expires_at="2026-01-15T11:00:00Z",
        )

        payload = _canonical_payload(context)

        assert "\\u" not in payload
        assert "münchen" in payload

    def test_utc_offset_and_z_suffix_produce_identical_bytes(self) -> None:
        """'+00:00' and 'Z' are the same instant and must sign the same."""
        with_z = SecurityContext(
            effective_policy=_policy(),
            issued_at="2026-01-15T10:00:00Z",
            expires_at="2026-01-15T11:00:00Z",
        )
        with_offset = SecurityContext(
            effective_policy=_policy(),
            issued_at="2026-01-15T10:00:00+00:00",
            expires_at="2026-01-15T11:00:00+00:00",
        )

        assert _canonical_payload(with_z) == _canonical_payload(with_offset)
        assert sign_context(with_z, KEY).signature == sign_context(with_offset, KEY).signature

    def test_non_utc_offset_normalizes_to_the_same_instant(self) -> None:
        utc = SecurityContext(
            effective_policy=_policy(),
            issued_at="2026-01-15T10:00:00Z",
            expires_at="2026-01-15T11:00:00Z",
        )
        shifted = SecurityContext(
            effective_policy=_policy(),
            issued_at="2026-01-15T05:00:00-05:00",
            expires_at="2026-01-15T06:00:00-05:00",
        )

        assert _canonical_payload(utc) == _canonical_payload(shifted)


class TestExpiryValidationFailsClosed:
    """Spec section 2: missing and unparseable expiries are denials."""

    def test_missing_expiry_is_rejected(self) -> None:
        """Previously `if context.expires_at:` skipped the check = immortal context."""
        context = sign_context(SecurityContext(effective_policy=_policy()), KEY)

        assert validate_expiry(context) == "security context has no expiry"

        wrapper = SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=KEY))
        result = wrapper.validate_security_context(context)
        assert result.allowed is False
        assert result.reason == "security context has no expiry"

    def test_empty_expiry_is_rejected(self) -> None:
        context = sign_context(SecurityContext(effective_policy=_policy(), expires_at=""), KEY)

        wrapper = SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=KEY))
        assert wrapper.validate_security_context(context).allowed is False

    def test_unparseable_expiry_is_rejected(self) -> None:
        context = sign_context(SecurityContext(effective_policy=_policy(), expires_at="never"), KEY)

        assert validate_expiry(context) == "invalid expiry format"

        wrapper = SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=KEY))
        result = wrapper.validate_security_context(context)
        assert result.allowed is False
        assert result.reason == "invalid expiry format"

    def test_deserialize_rejects_a_signed_context_with_no_expiry(self) -> None:
        signed = sign_context(SecurityContext(effective_policy=_policy()), KEY)

        with pytest.raises(ValueError, match="no expiry"):
            deserialize_context(serialize_context(signed), KEY)

    def test_expiry_exactly_now_is_expired(self) -> None:
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        context = SecurityContext(effective_policy=_policy(), expires_at=now)

        assert validate_expiry(context) == "security context expired"

    def test_valid_future_expiry_passes(self) -> None:
        context = sign_context(
            build_security_context("user-001", "tenant-midwest-health", [_policy()], ttl=timedelta(hours=1)),
            KEY,
        )

        assert validate_expiry(context) is None
        wrapper = SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=KEY))
        assert wrapper.validate_security_context(context).allowed is True


class TestSignatureCheckedBeforeExpiry:
    """Spec section 2: a tampered context reports a signature failure."""

    def test_expired_and_tampered_reports_signature_failure(self) -> None:
        expired = sign_context(
            build_security_context("user-001", "tenant-midwest-health", [_policy()], ttl=timedelta(hours=-1)),
            KEY,
        )
        expired.effective_policy.permissions.can_query = False

        wrapper = SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=KEY))
        result = wrapper.validate_security_context(expired)

        assert result.reason == "invalid signature"

    def test_deserialize_reports_signature_before_expiry(self) -> None:
        expired = sign_context(
            build_security_context("user-001", "tenant-midwest-health", [_policy()], ttl=timedelta(hours=-1)),
            KEY,
        )

        with pytest.raises(ValueError, match="Invalid signature"):
            deserialize_context(serialize_context(expired), "wrong-key")
