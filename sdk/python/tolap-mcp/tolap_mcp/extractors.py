from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time


class HeaderIdentityExtractor:
    """Extract identity from HTTP headers."""

    def __init__(
        self,
        user_id_header: str = "X-User-Id",
        tenant_id_header: str = "X-Tenant-Id",
    ) -> None:
        self._user_id_header = user_id_header
        self._tenant_id_header = tenant_id_header

    def extract_user_id(self, request: dict) -> str | None:
        headers = request.get("headers", {})
        return headers.get(self._user_id_header)

    def extract_tenant_id(self, request: dict) -> str | None:
        headers = request.get("headers", {})
        return headers.get(self._tenant_id_header)


class TolapIdentityError(PermissionError):
    """Raised when a credential is *presented and rejected*.

    Per canonical-enforcement-spec.md section 9 an identity extractor either
    returns a trustworthy principal or it fails. Returning "no identity" for a
    token that was presented and rejected converts an authentication failure into
    an authorization decision: the caller sees ``None``, treats the request as
    anonymous, and resolves whatever a default or anonymous assignment happens to
    grant. The same expired token then succeeds here and fails on the .NET SDK,
    which throws.

    A subclass of ``PermissionError`` so integrators already catching the
    wrapper's denials (which raise ``PermissionError``) handle this without a
    code change, while callers that want to distinguish an authentication failure
    from an authorization denial can catch this type specifically.

    An *absent* credential is not an error -- it returns no identity, which the
    integrator may legitimately choose to allow as an anonymous request.
    """


# HMAC algorithms this SDK can verify with only the standard library.
_HMAC_ALGORITHMS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


class JwtIdentityExtractor:
    """Extract identity from a JWT after verifying its signature.

    By default this extractor **verifies the JWT signature** (HMAC / HS256-384-512)
    and the ``exp``/``nbf`` claims before trusting any identity claim.

    Failure semantics follow spec section 9 and are identical in all three SDKs:

    * **No credential presented** (absent or empty ``Authorization`` header, or no
      token after the scheme) -- returns ``None``. This is a legitimate anonymous
      request the integrator may choose to allow.
    * **Credential presented but invalid** -- malformed structure, non-allowlisted
      algorithm, ``alg=none``, bad signature, expired (``exp``), not-yet-valid
      (``nbf``), or a missing/non-string required claim -- raises
      :class:`TolapIdentityError`.

    The distinction matters because returning ``None`` for a rejected token makes
    an attacker's expired or forged credential indistinguishable from no
    credential at all, and the request then resolves whatever an anonymous or
    default assignment grants instead of being refused.

    Two modes:

    * **Verified (default, recommended):** pass ``secret`` (the shared HMAC key
      the issuer signed with). Only ``algorithms`` are accepted; the ``none``
      algorithm and any algorithm not in the allow-list are rejected, which
      defeats ``alg``-confusion and unsigned-token attacks.
    * **Unverified (opt-in, discouraged):** pass ``allow_unverified=True`` when
      signature verification has already been performed by a trusted upstream
      layer (e.g. an API gateway / auth middleware). This is unsafe if the token
      can reach the tool without prior validation. Constructing the extractor
      with neither ``secret`` nor ``allow_unverified`` raises ``ValueError`` so
      the insecure path can never be selected by accident.
    """

    def __init__(
        self,
        token_header: str = "Authorization",
        user_id_claim: str = "sub",
        tenant_id_claim: str = "tenant_id",
        *,
        secret: str | bytes | None = None,
        algorithms: tuple[str, ...] = ("HS256",),
        allow_unverified: bool = False,
        leeway_seconds: int = 0,
    ) -> None:
        if secret is None and not allow_unverified:
            raise ValueError(
                "JwtIdentityExtractor requires a signing 'secret' to verify JWTs. "
                "If (and only if) signatures are already verified by a trusted "
                "upstream layer, pass allow_unverified=True explicitly."
            )

        self._token_header = token_header
        self._user_id_claim = user_id_claim
        self._tenant_id_claim = tenant_id_claim
        self._secret = secret.encode("utf-8") if isinstance(secret, str) else secret
        self._algorithms = tuple(algorithms)
        self._allow_unverified = allow_unverified
        self._leeway_seconds = leeway_seconds

    @staticmethod
    def _b64url_decode(segment: str) -> bytes:
        padding = 4 - len(segment) % 4
        if padding != 4:
            segment += "=" * padding
        return base64.urlsafe_b64decode(segment)

    def _decode_verified_claims(self, token: str) -> dict:
        """Return the claims of a valid token, or raise ``TolapIdentityError``.

        Every rejection path raises: the token was presented, so silence would
        turn an authentication failure into an anonymous request (spec section 9).
        Callers must have already established that a credential *was* presented.
        """
        # Strip "Bearer " prefix if present
        if token.lower().startswith("bearer "):
            token = token[7:]

        parts = token.split(".")
        if len(parts) != 3:
            raise TolapIdentityError("Invalid JWT format: expected 3 dot-separated parts")
        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")

        try:
            header = json.loads(self._b64url_decode(parts[0]))
            payload = json.loads(self._b64url_decode(parts[1]))
            signature = self._b64url_decode(parts[2])
        except (ValueError, json.JSONDecodeError) as exc:
            raise TolapIdentityError("Malformed JWT encoding") from exc
        if not isinstance(payload, dict) or not isinstance(header, dict):
            raise TolapIdentityError("Malformed JWT: header and payload must be objects")

        if not self._allow_unverified:
            alg = header.get("alg")
            # Reject "none" and any algorithm outside the caller's allow-list.
            if alg not in self._algorithms or alg not in _HMAC_ALGORITHMS:
                raise TolapIdentityError(f"JWT algorithm not allowed: {alg or '(none)'}")
            if self._secret is None:  # defensive: constructor guards this
                raise TolapIdentityError("No signing secret configured for JWT verification")
            expected = hmac.new(
                self._secret, signing_input, _HMAC_ALGORITHMS[alg]
            ).digest()
            if not hmac.compare_digest(expected, signature):
                raise TolapIdentityError("Invalid JWT signature")

        # Temporal claims are checked in both modes when present.
        self._verify_temporal_claims(payload)

        return payload

    def _verify_temporal_claims(self, payload: dict) -> None:
        """Enforce ``exp`` and ``nbf`` with the same leeway.

        ``nbf`` is validated because a token presented before it becomes valid is
        invalid, not anonymous (spec section 9). Leaving it unchecked let a
        post-dated token -- one an issuer minted for a future window -- be used
        immediately.
        """
        now = time.time()

        exp = payload.get("exp")
        if isinstance(exp, (int, float)) and not isinstance(exp, bool):
            if now > exp + self._leeway_seconds:
                raise TolapIdentityError("JWT has expired")

        nbf = payload.get("nbf")
        if isinstance(nbf, (int, float)) and not isinstance(nbf, bool):
            if now < nbf - self._leeway_seconds:
                raise TolapIdentityError("JWT is not yet valid")

    def _token(self, request: dict) -> str | None:
        """Return the presented token, or ``None`` when no credential was sent.

        An absent header, an empty header, and a bare scheme with no token are all
        "no credential presented" -- the anonymous case. Anything else is a
        credential whose validity is then decided by verification.
        """
        headers = request.get("headers", {})
        raw = headers.get(self._token_header)
        if not raw or not raw.strip():
            return None
        token = raw.strip()
        # "Bearer" with nothing after it carries no credential to reject.
        if token.lower() == "bearer" or (
            token.lower().startswith("bearer ") and not token[7:].strip()
        ):
            return None
        # A scheme this extractor does not understand still means a credential was
        # presented, so it is rejected loudly rather than degrading to anonymous.
        # Reported distinctly from a malformed JWT so the integrator's log names the
        # actual misconfiguration, matching the TypeScript SDK's message.
        parts = token.split()
        if len(parts) > 1 and parts[0].lower() != "bearer":
            raise TolapIdentityError(
                "Invalid Authorization header: expected 'Bearer <token>'"
            )
        return token

    def _claim(self, request: dict, claim: str) -> str | None:
        token = self._token(request)
        if token is None:
            return None
        payload = self._decode_verified_claims(token)
        value = payload.get(claim)
        if not isinstance(value, str) or not value:
            # A verified token missing a required claim is a misconfiguration, not
            # an anonymous request: the issuer authenticated someone the policy
            # engine cannot identify.
            raise TolapIdentityError(f"Missing claim: {claim}")
        return value

    def extract_user_id(self, request: dict) -> str | None:
        return self._claim(request, self._user_id_claim)

    def extract_tenant_id(self, request: dict) -> str | None:
        return self._claim(request, self._tenant_id_claim)
