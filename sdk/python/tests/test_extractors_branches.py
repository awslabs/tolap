"""Branch coverage for identity extraction (canonical spec section 9).

The controlling distinction is *absent* versus *presented and invalid*: absent
returns no identity, which the integrator may legitimately treat as anonymous,
while anything presented and rejected must raise. Returning ``None`` for a
rejected token converts an authentication failure into an authorization decision —
the request proceeds and resolves whatever an anonymous or default assignment
grants. Every rejection branch below therefore asserts that it *raises*, and every
anonymous branch asserts that it does not.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import pytest

from tolap_mcp.extractors import (
    HeaderIdentityExtractor,
    JwtIdentityExtractor,
    TolapIdentityError,
)


SECRET = "jwt-branch-secret"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _jwt(
    payload: dict,
    *,
    secret: str | None = SECRET,
    alg: str = "HS256",
    header: dict | None = None,
    signature: bytes | None = None,
) -> str:
    header_segment = _b64url(json.dumps(header if header is not None else {"alg": alg}).encode())
    payload_segment = _b64url(json.dumps(payload).encode())
    signing_input = f"{header_segment}.{payload_segment}".encode("ascii")

    if signature is not None:
        sig = signature
    elif secret is None:
        sig = b""
    else:
        digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg]
        sig = hmac.new(secret.encode(), signing_input, digest).digest()

    return f"{header_segment}.{payload_segment}.{_b64url(sig)}"


def _request(token: str | None, header: str = "Authorization") -> dict:
    return {"headers": {header: token} if token is not None else {}}


class TestHeaderIdentityExtractor:
    def test_extracts_both_ids_from_the_default_headers(self) -> None:
        extractor = HeaderIdentityExtractor()
        request = {"headers": {"X-User-Id": "user-1", "X-Tenant-Id": "tenant-1"}}

        assert extractor.extract_user_id(request) == "user-1"
        assert extractor.extract_tenant_id(request) == "tenant-1"

    def test_absent_headers_yield_no_identity(self) -> None:
        extractor = HeaderIdentityExtractor()

        assert extractor.extract_user_id({"headers": {}}) is None
        assert extractor.extract_tenant_id({"headers": {}}) is None

    def test_request_without_a_headers_key_yields_no_identity(self) -> None:
        extractor = HeaderIdentityExtractor()

        assert extractor.extract_user_id({}) is None
        assert extractor.extract_tenant_id({}) is None

    def test_custom_header_names_are_honoured(self) -> None:
        extractor = HeaderIdentityExtractor(
            user_id_header="X-Principal", tenant_id_header="X-Org"
        )
        request = {"headers": {"X-Principal": "p", "X-Org": "o"}}

        assert extractor.extract_user_id(request) == "p"
        assert extractor.extract_tenant_id(request) == "o"


class TestJwtExtractorConstruction:
    def test_neither_secret_nor_opt_in_is_refused(self) -> None:
        """The insecure path must never be selectable by accident."""
        with pytest.raises(ValueError, match="requires a signing 'secret'"):
            JwtIdentityExtractor()

    def test_allow_unverified_opt_in_is_accepted(self) -> None:
        extractor = JwtIdentityExtractor(allow_unverified=True)

        token = _jwt({"sub": "user-1"}, secret=None)

        assert extractor.extract_user_id(_request(token)) == "user-1"

    def test_bytes_secret_is_accepted(self) -> None:
        extractor = JwtIdentityExtractor(secret=SECRET.encode("utf-8"))

        assert extractor.extract_user_id(_request(_jwt({"sub": "user-1"}))) == "user-1"


class TestNoCredentialPresented:
    """Absent credentials return no identity — the legitimate anonymous case."""

    @pytest.fixture
    def extractor(self) -> JwtIdentityExtractor:
        return JwtIdentityExtractor(secret=SECRET)

    def test_absent_header_yields_no_identity(self, extractor: JwtIdentityExtractor) -> None:
        assert extractor.extract_user_id({"headers": {}}) is None

    def test_request_without_headers_yields_no_identity(
        self, extractor: JwtIdentityExtractor
    ) -> None:
        assert extractor.extract_user_id({}) is None

    def test_empty_header_yields_no_identity(self, extractor: JwtIdentityExtractor) -> None:
        assert extractor.extract_user_id(_request("")) is None

    def test_whitespace_only_header_yields_no_identity(
        self, extractor: JwtIdentityExtractor
    ) -> None:
        assert extractor.extract_user_id(_request("   ")) is None

    def test_bare_bearer_scheme_yields_no_identity(self, extractor: JwtIdentityExtractor) -> None:
        assert extractor.extract_user_id(_request("Bearer")) is None

    def test_bearer_with_only_whitespace_yields_no_identity(
        self, extractor: JwtIdentityExtractor
    ) -> None:
        assert extractor.extract_user_id(_request("Bearer    ")) is None


class TestCredentialPresentedAndRejected:
    """Every rejection raises. Spec section 9 forbids degrading to anonymous."""

    @pytest.fixture
    def extractor(self) -> JwtIdentityExtractor:
        return JwtIdentityExtractor(secret=SECRET)

    def test_wrong_number_of_segments_raises(self, extractor: JwtIdentityExtractor) -> None:
        with pytest.raises(TolapIdentityError, match="expected 3 dot-separated parts"):
            extractor.extract_user_id(_request("not.a-jwt"))

    def test_undecodable_segment_raises(self, extractor: JwtIdentityExtractor) -> None:
        with pytest.raises(TolapIdentityError, match="Malformed JWT encoding"):
            extractor.extract_user_id(_request("!!!.???.***"))

    def test_non_object_payload_raises(self, extractor: JwtIdentityExtractor) -> None:
        header = _b64url(json.dumps({"alg": "HS256"}).encode())
        payload = _b64url(json.dumps(["not", "an", "object"]).encode())
        signing_input = f"{header}.{payload}".encode("ascii")
        sig = hmac.new(SECRET.encode(), signing_input, hashlib.sha256).digest()

        with pytest.raises(TolapIdentityError, match="must be objects"):
            extractor.extract_user_id(_request(f"{header}.{payload}.{_b64url(sig)}"))

    def test_non_object_header_raises(self, extractor: JwtIdentityExtractor) -> None:
        header = _b64url(json.dumps("just-a-string").encode())
        payload = _b64url(json.dumps({"sub": "user-1"}).encode())
        signing_input = f"{header}.{payload}".encode("ascii")
        sig = hmac.new(SECRET.encode(), signing_input, hashlib.sha256).digest()

        with pytest.raises(TolapIdentityError, match="must be objects"):
            extractor.extract_user_id(_request(f"{header}.{payload}.{_b64url(sig)}"))

    def test_alg_none_raises(self, extractor: JwtIdentityExtractor) -> None:
        """An unsigned token must never be accepted."""
        token = _jwt({"sub": "user-1"}, secret=None, header={"alg": "none"})

        with pytest.raises(TolapIdentityError, match="algorithm not allowed"):
            extractor.extract_user_id(_request(token))

    def test_missing_alg_header_raises(self, extractor: JwtIdentityExtractor) -> None:
        token = _jwt({"sub": "user-1"}, secret=None, header={})

        with pytest.raises(TolapIdentityError, match=r"algorithm not allowed: \(none\)"):
            extractor.extract_user_id(_request(token))

    def test_algorithm_outside_the_allow_list_raises(self) -> None:
        """Defeats alg-confusion: HS512 is rejected by an HS256-only extractor."""
        extractor = JwtIdentityExtractor(secret=SECRET, algorithms=("HS256",))
        token = _jwt({"sub": "user-1"}, alg="HS512")

        with pytest.raises(TolapIdentityError, match="algorithm not allowed: HS512"):
            extractor.extract_user_id(_request(token))

    def test_non_hmac_algorithm_raises_even_when_allow_listed(self) -> None:
        """RS256 cannot be verified with only the stdlib, so it must not pass."""
        extractor = JwtIdentityExtractor(secret=SECRET, algorithms=("RS256",))
        token = _jwt({"sub": "user-1"}, secret=None, header={"alg": "RS256"})

        with pytest.raises(TolapIdentityError, match="algorithm not allowed: RS256"):
            extractor.extract_user_id(_request(token))

    def test_bad_signature_raises(self, extractor: JwtIdentityExtractor) -> None:
        token = _jwt({"sub": "user-1"}, signature=b"wrong-signature-bytes")

        with pytest.raises(TolapIdentityError, match="Invalid JWT signature"):
            extractor.extract_user_id(_request(token))

    def test_token_signed_with_another_key_raises(self, extractor: JwtIdentityExtractor) -> None:
        token = _jwt({"sub": "user-1"}, secret="attacker-key")

        with pytest.raises(TolapIdentityError, match="Invalid JWT signature"):
            extractor.extract_user_id(_request(token))

    def test_expired_token_raises(self, extractor: JwtIdentityExtractor) -> None:
        token = _jwt({"sub": "user-1", "exp": time.time() - 60})

        with pytest.raises(TolapIdentityError, match="expired"):
            extractor.extract_user_id(_request(token))

    def test_not_yet_valid_token_raises(self, extractor: JwtIdentityExtractor) -> None:
        """Spec section 9: a post-dated token is invalid, not anonymous."""
        token = _jwt({"sub": "user-1", "nbf": time.time() + 3600})

        with pytest.raises(TolapIdentityError, match="not yet valid"):
            extractor.extract_user_id(_request(token))

    def test_missing_claim_raises(self, extractor: JwtIdentityExtractor) -> None:
        """A verified token the policy engine cannot identify is a misconfiguration."""
        token = _jwt({"other": "value"})

        with pytest.raises(TolapIdentityError, match="Missing claim: sub"):
            extractor.extract_user_id(_request(token))

    def test_empty_claim_raises(self, extractor: JwtIdentityExtractor) -> None:
        token = _jwt({"sub": ""})

        with pytest.raises(TolapIdentityError, match="Missing claim: sub"):
            extractor.extract_user_id(_request(token))

    def test_non_string_claim_raises(self, extractor: JwtIdentityExtractor) -> None:
        token = _jwt({"sub": 12345})

        with pytest.raises(TolapIdentityError, match="Missing claim: sub"):
            extractor.extract_user_id(_request(token))

    def test_unknown_scheme_raises_rather_than_degrading_to_anonymous(
        self, extractor: JwtIdentityExtractor
    ) -> None:
        with pytest.raises(TolapIdentityError, match="expected 'Bearer <token>'"):
            extractor.extract_user_id(_request("Basic dXNlcjpwYXNz"))

    def test_identity_error_is_a_permission_error(self) -> None:
        """Integrators already catching PermissionError fail closed unchanged."""
        assert issubclass(TolapIdentityError, PermissionError)


class TestValidTokenAcceptance:
    @pytest.fixture
    def extractor(self) -> JwtIdentityExtractor:
        return JwtIdentityExtractor(secret=SECRET)

    def test_valid_token_yields_the_claims(self, extractor: JwtIdentityExtractor) -> None:
        token = _jwt({"sub": "user-1", "tenant_id": "tenant-1"})
        request = _request(token)

        assert extractor.extract_user_id(request) == "user-1"
        assert extractor.extract_tenant_id(request) == "tenant-1"

    def test_bearer_prefix_is_optional(self, extractor: JwtIdentityExtractor) -> None:
        token = _jwt({"sub": "user-1"})

        assert extractor.extract_user_id(_request(f"Bearer {token}")) == "user-1"
        assert extractor.extract_user_id(_request(token)) == "user-1"

    def test_bearer_prefix_is_case_insensitive(self, extractor: JwtIdentityExtractor) -> None:
        token = _jwt({"sub": "user-1"})

        assert extractor.extract_user_id(_request(f"bearer {token}")) == "user-1"
        assert extractor.extract_user_id(_request(f"BEARER {token}")) == "user-1"

    @pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
    def test_each_supported_hmac_algorithm_verifies(self, alg: str) -> None:
        extractor = JwtIdentityExtractor(secret=SECRET, algorithms=(alg,))
        token = _jwt({"sub": "user-1"}, alg=alg)

        assert extractor.extract_user_id(_request(token)) == "user-1"

    def test_unexpired_exp_is_accepted(self, extractor: JwtIdentityExtractor) -> None:
        token = _jwt({"sub": "user-1", "exp": time.time() + 3600})

        assert extractor.extract_user_id(_request(token)) == "user-1"

    def test_already_valid_nbf_is_accepted(self, extractor: JwtIdentityExtractor) -> None:
        token = _jwt({"sub": "user-1", "nbf": time.time() - 60})

        assert extractor.extract_user_id(_request(token)) == "user-1"

    @pytest.mark.parametrize("claim_value", [None, "not-a-number", True, False])
    def test_non_numeric_temporal_claims_are_ignored(
        self, extractor: JwtIdentityExtractor, claim_value: object
    ) -> None:
        """A bool is not a timestamp, so `exp: true` must not be arithmetic."""
        token = _jwt({"sub": "user-1", "exp": claim_value, "nbf": claim_value})

        assert extractor.extract_user_id(_request(token)) == "user-1"

    def test_leeway_admits_a_recently_expired_token(self) -> None:
        extractor = JwtIdentityExtractor(secret=SECRET, leeway_seconds=120)
        token = _jwt({"sub": "user-1", "exp": time.time() - 60})

        assert extractor.extract_user_id(_request(token)) == "user-1"

    def test_leeway_admits_a_barely_post_dated_token(self) -> None:
        """`nbf` gets the same leeway as `exp` (spec section 9)."""
        extractor = JwtIdentityExtractor(secret=SECRET, leeway_seconds=120)
        token = _jwt({"sub": "user-1", "nbf": time.time() + 60})

        assert extractor.extract_user_id(_request(token)) == "user-1"

    def test_leeway_does_not_admit_a_long_expired_token(self) -> None:
        extractor = JwtIdentityExtractor(secret=SECRET, leeway_seconds=60)
        token = _jwt({"sub": "user-1", "exp": time.time() - 3600})

        with pytest.raises(TolapIdentityError, match="expired"):
            extractor.extract_user_id(_request(token))

    def test_custom_claim_names_are_honoured(self) -> None:
        extractor = JwtIdentityExtractor(
            secret=SECRET, user_id_claim="uid", tenant_id_claim="org"
        )
        token = _jwt({"uid": "user-1", "org": "org-1"})
        request = _request(token)

        assert extractor.extract_user_id(request) == "user-1"
        assert extractor.extract_tenant_id(request) == "org-1"

    def test_custom_token_header_is_honoured(self) -> None:
        extractor = JwtIdentityExtractor(secret=SECRET, token_header="X-Auth")
        token = _jwt({"sub": "user-1"})

        assert extractor.extract_user_id(_request(token, header="X-Auth")) == "user-1"
        assert extractor.extract_user_id(_request(token, header="Authorization")) is None

    def test_padding_is_restored_for_each_segment_length(
        self, extractor: JwtIdentityExtractor
    ) -> None:
        """base64url segments arrive unpadded at every length mod 4."""
        for suffix_length in range(1, 6):
            token = _jwt({"sub": "u" * suffix_length})

            assert extractor.extract_user_id(_request(token)) == "u" * suffix_length


class TestUnverifiedMode:
    """The opt-out skips signature checks only — never the temporal claims."""

    @pytest.fixture
    def extractor(self) -> JwtIdentityExtractor:
        return JwtIdentityExtractor(allow_unverified=True)

    def test_unsigned_token_is_accepted(self, extractor: JwtIdentityExtractor) -> None:
        token = _jwt({"sub": "user-1"}, secret=None, header={"alg": "none"})

        assert extractor.extract_user_id(_request(token)) == "user-1"

    def test_bad_signature_is_accepted(self, extractor: JwtIdentityExtractor) -> None:
        token = _jwt({"sub": "user-1"}, signature=b"nonsense")

        assert extractor.extract_user_id(_request(token)) == "user-1"

    def test_expired_token_is_still_rejected(self, extractor: JwtIdentityExtractor) -> None:
        """Skipping the signature must not also skip expiry."""
        token = _jwt({"sub": "user-1", "exp": time.time() - 60}, secret=None)

        with pytest.raises(TolapIdentityError, match="expired"):
            extractor.extract_user_id(_request(token))

    def test_post_dated_token_is_still_rejected(self, extractor: JwtIdentityExtractor) -> None:
        token = _jwt({"sub": "user-1", "nbf": time.time() + 3600}, secret=None)

        with pytest.raises(TolapIdentityError, match="not yet valid"):
            extractor.extract_user_id(_request(token))

    def test_malformed_token_is_still_rejected(self, extractor: JwtIdentityExtractor) -> None:
        with pytest.raises(TolapIdentityError, match="expected 3 dot-separated parts"):
            extractor.extract_user_id(_request("only.two"))

    def test_missing_claim_is_still_rejected(self, extractor: JwtIdentityExtractor) -> None:
        token = _jwt({"other": "v"}, secret=None)

        with pytest.raises(TolapIdentityError, match="Missing claim"):
            extractor.extract_user_id(_request(token))

    def test_absent_credential_is_still_anonymous(self, extractor: JwtIdentityExtractor) -> None:
        assert extractor.extract_user_id({"headers": {}}) is None
