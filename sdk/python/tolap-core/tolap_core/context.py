from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone

from tolap_core.enums import SigningAlgorithm
from tolap_core.models import EffectivePolicy, SecurityContext
from tolap_core.serialization import deserialize_effective_policy, serialize


def build_security_context(
    user_id: str,
    tenant_id: str,
    policies: list[EffectivePolicy],
    ttl: timedelta = timedelta(hours=1),
) -> SecurityContext:
    """Build a SecurityContext from resolved effective policies.

    Uses the first policy if multiple are provided (each effective policy is per-source).
    """
    now = datetime.now(timezone.utc)
    effective = policies[0] if policies else EffectivePolicy.deny_all()
    effective.user_id = user_id
    effective.tenant_id = tenant_id

    return SecurityContext(
        effective_policy=effective,
        issued_at=now.isoformat().replace("+00:00", "Z"),
        expires_at=(now + ttl).isoformat().replace("+00:00", "Z"),
    )


def _compute_signature(payload: str, secret_key: str, algorithm: SigningAlgorithm) -> str:
    """Compute HMAC signature over a payload string."""
    key_bytes = secret_key.encode("utf-8")
    payload_bytes = payload.encode("utf-8")

    match algorithm:
        case SigningAlgorithm.hmac_sha256:
            digest = hmac.new(key_bytes, payload_bytes, hashlib.sha256).digest()
        case SigningAlgorithm.hmac_sha512:
            digest = hmac.new(key_bytes, payload_bytes, hashlib.sha512).digest()
        case SigningAlgorithm.ed25519:
            raise NotImplementedError("Ed25519 signing requires an external library")

    return base64.b64encode(digest).decode("utf-8")


def sign_context(
    context: SecurityContext,
    secret_key: str,
    algorithm: SigningAlgorithm = SigningAlgorithm.hmac_sha256,
) -> SecurityContext:
    """Sign a SecurityContext, producing a new context with signature and algorithm set."""
    payload = serialize(context.effective_policy)
    signature = _compute_signature(payload, secret_key, algorithm)

    context.signature = signature
    context.algorithm = algorithm
    return context


def validate_context(context: SecurityContext, secret_key: str) -> bool:
    """Validate the signature on a SecurityContext."""
    if not context.signature or not context.algorithm:
        return False

    payload = serialize(context.effective_policy)
    expected = _compute_signature(payload, secret_key, context.algorithm)
    return hmac.compare_digest(context.signature, expected)


def serialize_context(context: SecurityContext) -> str:
    """Serialize a SecurityContext to a base64-encoded JSON string."""
    json_str = serialize(context)
    return base64.b64encode(json_str.encode("utf-8")).decode("utf-8")


def deserialize_context(serialized: str, secret_key: str) -> SecurityContext:
    """Deserialize a base64-encoded SecurityContext and validate it.

    Raises ValueError if the signature is invalid or the context has expired.
    """
    json_bytes = base64.b64decode(serialized)
    data = json.loads(json_bytes)

    # Convert camelCase keys
    from tolap_core.serialization import _convert_keys_to_snake, _SIGNING_ALG_MAP

    d = _convert_keys_to_snake(data)

    effective = deserialize_effective_policy(data.get("effectivePolicy", {}))
    context = SecurityContext(
        effective_policy=effective,
        issued_at=d.get("issued_at"),
        expires_at=d.get("expires_at"),
        signature=d.get("signature"),
        algorithm=_SIGNING_ALG_MAP.get(d.get("algorithm", ""), None) if d.get("algorithm") else None,
    )

    # Validate signature
    if not validate_context(context, secret_key):
        raise ValueError("Invalid signature")

    # Validate expiry
    if context.expires_at:
        expiry = datetime.fromisoformat(context.expires_at.replace("Z", "+00:00"))
        if expiry < datetime.now(timezone.utc):
            raise ValueError("Security context has expired")

    return context
