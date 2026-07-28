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


# HMAC algorithms this SDK can verify with only the standard library.
_HMAC_ALGORITHMS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


class JwtIdentityExtractor:
    """Extract identity from a JWT after verifying its signature.

    By default this extractor **verifies the JWT signature** (HMAC / HS256-384-512)
    and the ``exp`` claim before trusting any identity claim. A token that fails
    verification yields no identity (``extract_*`` return ``None``), so it fails
    closed: enforcement resolves an empty/anonymous policy rather than an
    attacker-supplied one.

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

    def _decode_verified_claims(self, token: str) -> dict | None:
        """Return JWT claims iff the token is valid, else None (fails closed)."""
        # Strip "Bearer " prefix if present
        if token.lower().startswith("bearer "):
            token = token[7:]

        parts = token.split(".")
        if len(parts) != 3:
            return None
        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")

        try:
            header = json.loads(self._b64url_decode(parts[0]))
            payload = json.loads(self._b64url_decode(parts[1]))
            signature = self._b64url_decode(parts[2])
        except (ValueError, json.JSONDecodeError):
            return None
        if not isinstance(payload, dict) or not isinstance(header, dict):
            return None

        if not self._allow_unverified:
            alg = header.get("alg")
            # Reject "none" and any algorithm outside the caller's allow-list.
            if alg not in self._algorithms or alg not in _HMAC_ALGORITHMS:
                return None
            if self._secret is None:  # defensive: constructor guards this
                return None
            expected = hmac.new(
                self._secret, signing_input, _HMAC_ALGORITHMS[alg]
            ).digest()
            if not hmac.compare_digest(expected, signature):
                return None

        # Expiry is checked in both modes when present.
        exp = payload.get("exp")
        if isinstance(exp, (int, float)):
            if time.time() > exp + self._leeway_seconds:
                return None

        return payload

    def _claim(self, request: dict, claim: str) -> str | None:
        headers = request.get("headers", {})
        token = headers.get(self._token_header)
        if not token:
            return None
        payload = self._decode_verified_claims(token)
        if not payload:
            return None
        value = payload.get(claim)
        return value if isinstance(value, str) else None

    def extract_user_id(self, request: dict) -> str | None:
        return self._claim(request, self._user_id_claim)

    def extract_tenant_id(self, request: dict) -> str | None:
        return self._claim(request, self._tenant_id_claim)
