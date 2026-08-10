from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from tolap_core.enums import SigningAlgorithm
from tolap_core.models import EffectivePolicy, SecurityContext
from tolap_core.serialization import deserialize_effective_policy, serialize


def build_security_context(
    user_id: str,
    tenant_id: str,
    policies: list[EffectivePolicy],
    ttl: timedelta = timedelta(hours=1),
    *,
    jti: str | None = None,
) -> SecurityContext:
    """Build a SecurityContext from a resolved effective policy.

    ``SecurityContext`` carries exactly one effective policy, and every enforcement
    entry point in this SDK reads that single policy without being told which data
    source the call is aimed at. Passing more than one policy is therefore refused
    rather than truncated: this function used to keep ``policies[0]`` and drop the
    rest with no error and no warning, so an integrator wiring up a database policy
    and an API policy got a context that governed only the database and had no way
    to detect that the API was governed by nothing. Build one context per data
    source instead -- there is no per-source resolution rule for this SDK to apply.

    An empty list is *not* an error: it denies everything, which is the safe
    reading of "no policy resolved".

    ``jti`` is a unique context identifier used for replay detection (spec section
    13). It defaults to a fresh UUID4 so that contexts are replay-checkable
    without the caller having to remember to ask; pass a value to supply your own,
    or ``jti=""`` to omit it and reproduce the pre-``jti`` canonical bytes. The id
    is inside the signed payload, so it cannot be stripped or swapped without
    invalidating the signature. Detection still requires a
    :class:`ReplayGuard` at the verifying end -- an identifier alone records
    nothing.

    Raises:
        ValueError: if more than one effective policy is supplied.
    """
    if len(policies) > 1:
        raise ValueError(
            f"build_security_context accepts at most one effective policy, got "
            f"{len(policies)}; a SecurityContext carries a single policy, so build "
            f"one context per data source"
        )

    now = datetime.now(timezone.utc)
    effective = policies[0] if policies else EffectivePolicy.deny_all()
    effective.user_id = user_id
    effective.tenant_id = tenant_id

    return SecurityContext(
        effective_policy=effective,
        issued_at=now.isoformat().replace("+00:00", "Z"),
        expires_at=(now + ttl).isoformat().replace("+00:00", "Z"),
        jti=str(uuid.uuid4()) if jti is None else (jti or None),
    )


# -- Replay detection --


class ReplayGuard(Protocol):
    """Records which context identifiers have been seen (spec section 13).

    A signed context is otherwise a bearer credential replayable until it expires.
    Single-use enforcement needs state the SDK deliberately does not assume, so
    this is the seam: implement it over whatever store the deployment already has
    (Redis, DynamoDB, a database table) and pass it to
    :func:`deserialize_context`.

    Implementations MUST be safe to call concurrently and MUST be atomic --
    check-then-register as two separate steps lets two concurrent replays of the
    same context both succeed, which defeats the guard under exactly the load an
    attacker would generate.
    """

    def check_and_register(self, jti: str, expires_at: str | None) -> bool:
        """Atomically record ``jti``; return False if it was already present.

        ``expires_at`` is the context's expiry, supplied so implementations can
        expire their own entries: an id can be forgotten once the context carrying
        it would be rejected on expiry anyway.
        """
        ...


class InMemoryReplayGuard:
    """Process-local :class:`ReplayGuard`, suitable for a single-process tool.

    Not shared across processes or hosts: two workers behind a load balancer each
    keep their own set, so a context replayed against a *different* worker is not
    detected. Use a shared store for anything multi-process -- this class exists so
    that single-process deployments and tests have a working guard rather than none.

    Entries are dropped once their context has expired, so memory is bounded by the
    number of contexts issued within one TTL rather than growing without limit.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._seen: dict[str, datetime] = {}

    def check_and_register(self, jti: str, expires_at: str | None) -> bool:
        now = datetime.now(timezone.utc)
        # Fall back to a bounded retention when expiry is absent or unreadable, so
        # a malformed value cannot pin an entry in memory forever.
        expiry = _parse_timestamp(expires_at) or (now + timedelta(hours=1))

        with self._lock:
            # Opportunistic sweep: an id is only worth remembering while a context
            # bearing it could still pass the expiry check.
            if self._seen:
                self._seen = {k: v for k, v in self._seen.items() if v > now}
            if jti in self._seen:
                return False
            self._seen[jti] = expiry
            return True


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


# -- Canonical signing payload --


def _normalize_timestamp(value: str | None) -> str:
    """Normalize an RFC 3339 timestamp to UTC with a 'Z' suffix.

    Signing must not distinguish "+00:00" from "Z", so both forms are folded to
    the same bytes. An unparseable value is passed through verbatim: the
    signature then covers exactly what was transported, and expiry validation
    (which rejects unparseable values) is the control that stops it.

    Sub-second digits are **truncated to milliseconds** per spec section 2 rule 5.
    Milliseconds are the greatest precision all three SDKs represent exactly --
    JavaScript's Date cannot hold sub-millisecond values -- so signing at native
    microsecond precision here would produce bytes TypeScript can never reproduce.
    """
    if not value:
        return ""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    utc = parsed.astimezone(timezone.utc)
    millis = utc.microsecond // 1000  # truncate, never round
    base = utc.strftime("%Y-%m-%dT%H:%M:%S")
    return f"{base}Z" if millis == 0 else f"{base}.{millis:03d}Z"


def _strip_integrity(policy_dict: dict) -> dict:
    """Drop the integrity block from a serialized policy (it cannot sign itself)."""
    return {k: v for k, v in policy_dict.items() if k != "integrity"}


# Timestamp-valued keys on a serialized policy. These are normalized to the
# canonical millisecond form along with the envelope's own issuedAt/expiresAt.
_POLICY_TIMESTAMP_KEYS = ("resolvedAt", "expiresAt")


def _normalize_policy_timestamps(policy_dict: dict) -> dict:
    """Normalize the timestamps carried *inside* a projected policy.

    The envelope's ``issuedAt``/``expiresAt`` are not the only instants in the
    signed bytes: each policy repeats its own ``resolvedAt``/``expiresAt``. .NET
    normalizes those through a canonical ``DateTimeOffset`` converter, so leaving
    them as the verbatim transport strings here made Python sign
    ``.123456Z`` where .NET signed ``.123Z`` — the same context, two different
    signatures, and a cross-SDK verification failure that the whole-second
    fixture could not detect (spec section 2 rule 5).
    """
    return {
        key: _normalize_timestamp(value)
        if key in _POLICY_TIMESTAMP_KEYS and isinstance(value, str)
        else value
        for key, value in policy_dict.items()
    }


def _canonical_payload(context: SecurityContext) -> str:
    """Project a SecurityContext into the canonical signing shape and serialize it.

    The HMAC covers the whole envelope, not just the policy:

        {version, userId, tenantId, issuedAt, expiresAt, policies[]}

    issuedAt and expiresAt are *inside* the signed bytes, so rewriting an expiry
    on a captured context invalidates the signature instead of extending its
    life. Python's SecurityContext holds one policy, which projects to a
    one-element ``policies`` array so the bytes match the multi-policy SDKs.

    Serialization is compact, recursively key-sorted, and non-ASCII-preserving —
    ``ensure_ascii=True`` would escape non-ASCII text and break cross-language
    agreement.
    """
    policy = context.effective_policy
    policy_dict = _normalize_policy_timestamps(
        _strip_integrity(json.loads(serialize(policy)))
    )

    payload: dict[str, Any] = {
        "version": policy.version,
        "userId": policy.user_id or "",
        "tenantId": policy.tenant_id or "",
        "issuedAt": _normalize_timestamp(context.issued_at),
        "expiresAt": _normalize_timestamp(context.expires_at),
        "policies": [policy_dict],
    }
    # `jti` joins the signed bytes only when present. Emitting it unconditionally
    # (as `null` or `""`) would change the canonical form for every existing
    # context and break the known-answer fixtures and cross-SDK agreement, so
    # absence is byte-identical to the pre-`jti` form. When present it is signed,
    # so a replay guard cannot be defeated by stripping or swapping the id.
    if context.jti:
        payload["jti"] = context.jti
    return json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


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
        case _:
            # An algorithm this SDK cannot compute must fail closed and say so.
            # Without this arm the match simply fell through and `digest` was
            # unbound, so the failure surfaced as an UnboundLocalError that named
            # neither the algorithm nor the reason.
            raise ValueError(f"unsupported signing algorithm: {algorithm!r}")

    return base64.b64encode(digest).decode("utf-8")


def sign_context(
    context: SecurityContext,
    secret_key: str,
    algorithm: SigningAlgorithm = SigningAlgorithm.hmac_sha256,
) -> SecurityContext:
    """Sign a SecurityContext, producing a new context with signature and algorithm set."""
    payload = _canonical_payload(context)
    signature = _compute_signature(payload, secret_key, algorithm)

    context.signature = signature
    context.algorithm = algorithm
    return context


def validate_context(context: SecurityContext, secret_key: str) -> bool:
    """Validate the signature on a SecurityContext.

    Returns False rather than raising for an algorithm this SDK cannot verify.
    ``ed25519`` is enumerated in the schema but unimplemented, so a
    schema-conformant context can name it: an unverifiable signature is a
    validation *failure*, not an exception escaping an enforcement check.
    Raising would turn a deny into a crash, and a caller wrapping this in a
    ``try``/``except`` that swallows would turn it into an allow.
    """
    if not context.signature or not context.algorithm:
        return False

    payload = _canonical_payload(context)
    try:
        expected = _compute_signature(payload, secret_key, context.algorithm)
    except NotImplementedError:
        return False
    return hmac.compare_digest(context.signature, expected)


def validate_expiry(context: SecurityContext) -> str | None:
    """Check a context's expiry, returning a denial reason or None when valid.

    Fails closed on both ends: a missing or empty expiry is never "never
    expires", and an unparseable expiry is never a silently skipped check.
    """
    if not context.expires_at:
        return "security context has no expiry"
    try:
        expiry = datetime.fromisoformat(context.expires_at.replace("Z", "+00:00"))
    except ValueError:
        return "invalid expiry format"
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    if expiry <= datetime.now(timezone.utc):
        return "security context expired"
    return None


def serialize_context(context: SecurityContext) -> str:
    """Serialize a SecurityContext to a base64-encoded JSON string."""
    json_str = serialize(context)
    return base64.b64encode(json_str.encode("utf-8")).decode("utf-8")


def deserialize_context(
    serialized: str,
    secret_key: str,
    replay_guard: ReplayGuard | None = None,
) -> SecurityContext:
    """Deserialize a base64-encoded SecurityContext and validate it.

    Raises ValueError if the signature is invalid, the context has expired, or --
    when a ``replay_guard`` is supplied -- the context has already been used.
    The signature is checked first, so a tampered context reports a signature
    failure rather than leaking whether a valid context had merely expired.

    ``replay_guard`` is optional because single-use enforcement needs state the
    SDK cannot assume (spec section 13); pass one to turn a signed context from a
    bearer credential replayable for its full TTL into a single-use one. A context
    with no ``jti`` is rejected when a guard is active rather than waved through,
    since silently skipping the check is the failure mode a guard exists to
    prevent.
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
        jti=d.get("jti"),
    )

    # Validate signature before expiry
    if not validate_context(context, secret_key):
        raise ValueError("Invalid signature")

    expiry_reason = validate_expiry(context)
    if expiry_reason is not None:
        raise ValueError(f"Security context rejected: {expiry_reason}")

    # Replay check runs last: it consumes the `jti`, so it must not fire for a
    # context that was going to be rejected anyway. Doing it earlier would let an
    # attacker burn a legitimate id by replaying an already-expired context.
    if replay_guard is not None:
        if not context.jti:
            raise ValueError(
                "Security context rejected: replay checking requires a 'jti'; "
                "this context carries none"
            )
        if not replay_guard.check_and_register(context.jti, context.expires_at):
            raise ValueError("Security context rejected: context already used (replay)")

    return context
