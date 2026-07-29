from __future__ import annotations

from datetime import timedelta

import pytest

from tolap_core.context import build_security_context, sign_context
from tolap_core.enums import MaskType, SigningAlgorithm
from tolap_core.models import (
    EffectivePolicy,
    EndpointRules,
    FieldRules,
    MaskingParameters,
    MaskingRule,
    ObjectRules,
    PolicyLimits,
    PolicyPermissions,
    SecurityContext,
)
from tolap_mcp.extractors import (
    HeaderIdentityExtractor,
    JwtIdentityExtractor,
    TolapIdentityError,
)
from tolap_mcp.options import SecureMcpServerOptions
from tolap_mcp.wrapper import SecureMcpToolWrapper


def _make_signed_context(
    can_query: bool = True,
    allowed_objects: list[str] | None = None,
    hidden_fields: list[str] | None = None,
    masked_fields: list[MaskingRule] | None = None,
    max_results: int | None = None,
    signing_key: str = "test-key",
    ttl: timedelta = timedelta(hours=1),
    endpoint_rules: EndpointRules | None = None,
) -> SecurityContext:
    field_rules = None
    if hidden_fields or masked_fields:
        field_rules = FieldRules(
            hidden_fields=hidden_fields,
            masked_fields=masked_fields,
        )

    object_rules = None
    if allowed_objects or field_rules or endpoint_rules:
        object_rules = ObjectRules(
            allowed_objects=allowed_objects,
            field_rules=field_rules,
            endpoint_rules=endpoint_rules,
        )

    limits = PolicyLimits(max_results=max_results) if max_results else None

    policy = EffectivePolicy(
        version="1.0",
        user_id="user-001",
        tenant_id="tenant-001",
        source_profiles=["test-policy"],
        permissions=PolicyPermissions(can_query=can_query, can_export=False, read_only=True),
        object_rules=object_rules,
        limits=limits,
    )

    context = build_security_context(
        user_id="user-001",
        tenant_id="tenant-001",
        policies=[policy],
        ttl=ttl,
    )
    return sign_context(context, signing_key)


class TestSecureMcpToolWrapper:
    """Test the MCP tool wrapper."""

    @pytest.fixture
    def options(self) -> SecureMcpServerOptions:
        return SecureMcpServerOptions(signing_key="test-key")

    @pytest.fixture
    def wrapper(self, options: SecureMcpServerOptions) -> SecureMcpToolWrapper:
        return SecureMcpToolWrapper(options)

    def test_pre_execute_allowed(self, wrapper: SecureMcpToolWrapper) -> None:
        context = _make_signed_context(allowed_objects=["patients"])
        result = wrapper.pre_execute(context, "query-tool", object_name="patients")
        assert result.allowed is True

    def test_pre_execute_denied_object(self, wrapper: SecureMcpToolWrapper) -> None:
        context = _make_signed_context(allowed_objects=["patients"])
        result = wrapper.pre_execute(context, "query-tool", object_name="billing")
        assert result.allowed is False

    def test_pre_execute_denied_query(self, wrapper: SecureMcpToolWrapper) -> None:
        context = _make_signed_context(can_query=False)
        result = wrapper.pre_execute(context, "query-tool")
        assert result.allowed is False
        assert result.reason == "query not permitted"

    def test_pre_execute_hidden_fields(self, wrapper: SecureMcpToolWrapper) -> None:
        context = _make_signed_context(hidden_fields=["ssn", "dob"])
        result = wrapper.pre_execute(context, "query-tool", fields=["name", "ssn"])
        assert result.allowed is False
        assert "ssn" in result.reason

    def test_pre_execute_invalid_signature(self) -> None:
        options = SecureMcpServerOptions(signing_key="different-key")
        wrapper = SecureMcpToolWrapper(options)
        context = _make_signed_context(signing_key="test-key")
        result = wrapper.pre_execute(context, "query-tool")
        assert result.allowed is False
        assert result.reason == "invalid signature"

    def test_pre_execute_expired_context(self, wrapper: SecureMcpToolWrapper) -> None:
        context = _make_signed_context(ttl=timedelta(hours=-1))
        result = wrapper.pre_execute(context, "query-tool")
        assert result.allowed is False
        assert "expired" in result.reason

    def test_post_execute_masking(self, wrapper: SecureMcpToolWrapper) -> None:
        context = _make_signed_context(
            masked_fields=[
                MaskingRule(field="ssn", mask_type=MaskType.full, parameters=MaskingParameters(mask_char="*")),
            ],
        )
        records = [{"name": "John", "ssn": "123-45-6789"}]
        result = wrapper.post_execute(context, records)
        assert result[0]["name"] == "John"
        assert result[0]["ssn"] == "***********"

    def test_post_execute_result_limit(self, wrapper: SecureMcpToolWrapper) -> None:
        context = _make_signed_context(max_results=2)
        records = [{"id": i} for i in range(10)]
        result = wrapper.post_execute(context, records)
        assert len(result) == 2

    def test_execute_with_enforcement(self, wrapper: SecureMcpToolWrapper) -> None:
        context = _make_signed_context(allowed_objects=["patients"], max_results=2)

        def mock_tool(query: str) -> list[dict]:
            return [{"id": i, "name": f"patient-{i}"} for i in range(5)]

        result = wrapper.execute_with_enforcement(
            context=context,
            tool_name="query-tool",
            tool_fn=mock_tool,
            tool_args={"query": "SELECT * FROM patients"},
            object_name="patients",
        )
        assert len(result) == 2

    def test_execute_with_enforcement_denied(self, wrapper: SecureMcpToolWrapper) -> None:
        context = _make_signed_context(allowed_objects=["patients"])

        def mock_tool() -> list[dict]:
            return []

        with pytest.raises(PermissionError, match="Access denied"):
            wrapper.execute_with_enforcement(
                context=context,
                tool_name="query-tool",
                tool_fn=mock_tool,
                tool_args={},
                object_name="billing",
            )

    def test_endpoint_enforcement(self, wrapper: SecureMcpToolWrapper) -> None:
        context = _make_signed_context(
            endpoint_rules=EndpointRules(
                allowed_endpoints=["/api/v1/patients", "/api/v1/patients/*"],
                hidden_endpoints=["/api/v1/admin/*"],
                allowed_methods=["GET"],
            ),
        )

        # Allowed endpoint
        result = wrapper.pre_execute(
            context, "api-tool",
            endpoint_path="/api/v1/patients",
            endpoint_method="GET",
        )
        assert result.allowed is True

        # Hidden endpoint
        result2 = wrapper.pre_execute(
            context, "api-tool",
            endpoint_path="/api/v1/admin/users",
            endpoint_method="GET",
        )
        assert result2.allowed is False

    def test_allowed_tools_filter(self) -> None:
        options = SecureMcpServerOptions(
            signing_key="test-key",
            allowed_tools=["approved-tool"],
        )
        wrapper = SecureMcpToolWrapper(options)
        context = _make_signed_context()

        result = wrapper.pre_execute(context, "unapproved-tool")
        assert result.allowed is False
        assert "not in allowed list" in result.reason


class TestIdentityExtractors:
    """Test identity extractors."""

    def test_header_extractor(self) -> None:
        extractor = HeaderIdentityExtractor()
        request = {
            "headers": {
                "X-User-Id": "user-001",
                "X-Tenant-Id": "tenant-001",
            }
        }
        assert extractor.extract_user_id(request) == "user-001"
        assert extractor.extract_tenant_id(request) == "tenant-001"

    def test_header_extractor_missing(self) -> None:
        extractor = HeaderIdentityExtractor()
        request = {"headers": {}}
        assert extractor.extract_user_id(request) is None
        assert extractor.extract_tenant_id(request) is None

    SECRET = "test-signing-secret-value"

    @staticmethod
    def _sign_jwt(payload: dict, secret: str, alg: str = "HS256") -> str:
        import base64
        import hashlib
        import hmac
        import json

        def b64(raw: bytes) -> str:
            return base64.urlsafe_b64encode(raw).decode().rstrip("=")

        header_seg = b64(json.dumps({"alg": alg, "typ": "JWT"}).encode())
        payload_seg = b64(json.dumps(payload).encode())
        signing_input = f"{header_seg}.{payload_seg}".encode("ascii")
        algos = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
        sig = hmac.new(secret.encode(), signing_input, algos[alg]).digest()
        return f"{header_seg}.{payload_seg}.{b64(sig)}"

    def test_jwt_extractor_valid_signed_token(self) -> None:
        token = self._sign_jwt({"sub": "user-001", "tenant_id": "tenant-001"}, self.SECRET)
        request = {"headers": {"Authorization": f"Bearer {token}"}}

        extractor = JwtIdentityExtractor(secret=self.SECRET)
        assert extractor.extract_user_id(request) == "user-001"
        assert extractor.extract_tenant_id(request) == "tenant-001"

    def test_jwt_extractor_requires_secret_or_optin(self) -> None:
        with pytest.raises(ValueError):
            JwtIdentityExtractor()

    # A credential that was PRESENTED and found invalid must raise, not resolve as
    # anonymous (canonical spec section 9). Returning None here would let a caller
    # treat an authentication failure as an anonymous request and resolve whatever a
    # default assignment grants -- the divergence that had .NET throwing while
    # Python and TypeScript silently degraded on the very same token.

    def test_jwt_extractor_tampered_signature_raises(self) -> None:
        # Signed with a different key -> signature will not match.
        token = self._sign_jwt({"sub": "attacker", "tenant_id": "victim"}, "wrong-secret")
        request = {"headers": {"Authorization": f"Bearer {token}"}}

        extractor = JwtIdentityExtractor(secret=self.SECRET)
        with pytest.raises(TolapIdentityError, match="signature"):
            extractor.extract_user_id(request)
        with pytest.raises(TolapIdentityError, match="signature"):
            extractor.extract_tenant_id(request)

    def test_jwt_extractor_none_algorithm_raises(self) -> None:
        import base64
        import json

        def b64(raw: bytes) -> str:
            return base64.urlsafe_b64encode(raw).decode().rstrip("=")

        header = b64(json.dumps({"alg": "none", "typ": "JWT"}).encode())
        payload = b64(json.dumps({"sub": "attacker", "tenant_id": "victim"}).encode())
        token = f"{header}.{payload}."
        request = {"headers": {"Authorization": f"Bearer {token}"}}

        extractor = JwtIdentityExtractor(secret=self.SECRET)
        with pytest.raises(TolapIdentityError, match="algorithm not allowed"):
            extractor.extract_user_id(request)

    def test_jwt_extractor_expired_token_raises(self) -> None:
        token = self._sign_jwt(
            {"sub": "user-001", "tenant_id": "tenant-001", "exp": 1},
            self.SECRET,
        )
        request = {"headers": {"Authorization": f"Bearer {token}"}}

        extractor = JwtIdentityExtractor(secret=self.SECRET)
        with pytest.raises(TolapIdentityError, match="expired"):
            extractor.extract_user_id(request)

    def test_jwt_extractor_identity_error_is_permission_error(self) -> None:
        """TolapIdentityError subclasses PermissionError.

        Integrators already catching the wrapper's PermissionError denials handle a
        rejected credential without a code change -- and, importantly, without it
        being mistaken for an anonymous request.
        """
        assert issubclass(TolapIdentityError, PermissionError)

    def test_jwt_extractor_unverified_optin(self) -> None:
        token = self._sign_jwt({"sub": "user-001", "tenant_id": "tenant-001"}, "any-key")
        request = {"headers": {"Authorization": f"Bearer {token}"}}

        extractor = JwtIdentityExtractor(allow_unverified=True)
        assert extractor.extract_user_id(request) == "user-001"

    def test_jwt_extractor_no_token(self) -> None:
        extractor = JwtIdentityExtractor(secret=self.SECRET)
        request = {"headers": {}}
        assert extractor.extract_user_id(request) is None

    def test_jwt_extractor_custom_claims(self) -> None:
        token = self._sign_jwt({"user_id": "custom-user", "org_id": "custom-org"}, self.SECRET)
        request = {"headers": {"Authorization": f"Bearer {token}"}}

        extractor = JwtIdentityExtractor(
            secret=self.SECRET,
            user_id_claim="user_id",
            tenant_id_claim="org_id",
        )
        assert extractor.extract_user_id(request) == "custom-user"
        assert extractor.extract_tenant_id(request) == "custom-org"


class TestIdentityExtractionFailureSemantics:
    """Spec section 9: absent credential vs presented-and-invalid credential.

    An extractor either returns a trustworthy principal or it fails. Returning "no
    identity" for a token that was presented and rejected converts an
    authentication failure into an authorization decision: the caller treats the
    request as anonymous and resolves whatever a default assignment grants. Before
    this change .NET threw while Python and TypeScript returned None on the very
    same token -- the same expired credential, opposite outcomes.
    """

    SECRET = "test-signing-secret-value"

    @staticmethod
    def _sign_jwt(payload: dict, secret: str = SECRET, alg: str = "HS256") -> str:
        return TestIdentityExtractors._sign_jwt(payload, secret, alg)

    def _extractor(self, **kwargs: object) -> JwtIdentityExtractor:
        return JwtIdentityExtractor(secret=self.SECRET, **kwargs)  # type: ignore[arg-type]

    # -- Absent credential: anonymous, not an error --

    @pytest.mark.parametrize(
        "headers",
        [
            pytest.param({}, id="no-authorization-header"),
            pytest.param({"Authorization": ""}, id="empty-header"),
            pytest.param({"Authorization": "   "}, id="whitespace-header"),
            pytest.param({"Authorization": "Bearer"}, id="scheme-with-no-token"),
            pytest.param({"Authorization": "Bearer "}, id="scheme-with-empty-token"),
        ],
    )
    def test_absent_credential_returns_no_identity(self, headers: dict) -> None:
        """No credential presented stays a legitimate anonymous request."""
        extractor = self._extractor()

        assert extractor.extract_user_id({"headers": headers}) is None
        assert extractor.extract_tenant_id({"headers": headers}) is None

    def test_missing_headers_key_returns_no_identity(self) -> None:
        assert self._extractor().extract_user_id({}) is None

    # -- Presented but invalid: raise --

    def test_malformed_structure_raises(self) -> None:
        request = {"headers": {"Authorization": "Bearer only.two"}}

        with pytest.raises(TolapIdentityError, match="Invalid JWT format"):
            self._extractor().extract_user_id(request)

    def test_unparseable_segments_raise(self) -> None:
        request = {"headers": {"Authorization": "Bearer aaa.bbb.ccc"}}

        with pytest.raises(TolapIdentityError):
            self._extractor().extract_user_id(request)

    def test_non_allowlisted_algorithm_raises(self) -> None:
        # HS512 is a real algorithm but outside the caller's allow-list, so accepting
        # it would defeat the point of pinning one.
        token = self._sign_jwt({"sub": "u", "tenant_id": "t"}, self.SECRET, alg="HS512")
        request = {"headers": {"Authorization": f"Bearer {token}"}}

        with pytest.raises(TolapIdentityError, match="algorithm not allowed"):
            self._extractor(algorithms=("HS256",)).extract_user_id(request)

    def test_missing_required_claim_raises(self) -> None:
        """A verified token the policy engine cannot identify is not anonymous."""
        token = self._sign_jwt({"sub": "user-001"})  # no tenant_id
        request = {"headers": {"Authorization": f"Bearer {token}"}}

        with pytest.raises(TolapIdentityError, match="Missing claim: tenant_id"):
            self._extractor().extract_tenant_id(request)

    def test_non_string_claim_raises(self) -> None:
        token = self._sign_jwt({"sub": 12345, "tenant_id": "t"})
        request = {"headers": {"Authorization": f"Bearer {token}"}}

        with pytest.raises(TolapIdentityError, match="Missing claim: sub"):
            self._extractor().extract_user_id(request)

    def test_error_is_a_permission_error(self) -> None:
        """Integrators already catching the wrapper's PermissionError still work."""
        token = self._sign_jwt({"sub": "a", "tenant_id": "b"}, "wrong-secret")
        request = {"headers": {"Authorization": f"Bearer {token}"}}

        with pytest.raises(PermissionError):
            self._extractor().extract_user_id(request)

    # -- nbf (not-before), spec section 9 --

    def test_not_yet_valid_token_raises(self) -> None:
        """A token presented before its nbf is INVALID, not anonymous.

        nbf was previously unchecked in every SDK, so a post-dated token -- one an
        issuer minted for a future window -- was usable immediately.
        """
        import time

        token = self._sign_jwt(
            {"sub": "user-001", "tenant_id": "tenant-001", "nbf": time.time() + 600}
        )
        request = {"headers": {"Authorization": f"Bearer {token}"}}

        with pytest.raises(TolapIdentityError, match="not yet valid"):
            self._extractor().extract_user_id(request)

    def test_already_valid_nbf_is_accepted(self) -> None:
        import time

        token = self._sign_jwt(
            {"sub": "user-001", "tenant_id": "tenant-001", "nbf": time.time() - 600}
        )
        request = {"headers": {"Authorization": f"Bearer {token}"}}

        assert self._extractor().extract_user_id(request) == "user-001"

    def test_nbf_honours_the_same_leeway_as_exp(self) -> None:
        """Ordinary clock skew must not reject a token the issuer considers valid."""
        import time

        token = self._sign_jwt(
            {"sub": "user-001", "tenant_id": "tenant-001", "nbf": time.time() + 30}
        )
        request = {"headers": {"Authorization": f"Bearer {token}"}}

        assert self._extractor(leeway_seconds=120).extract_user_id(request) == "user-001"

    def test_nbf_is_enforced_in_unverified_mode_too(self) -> None:
        import time

        token = self._sign_jwt(
            {"sub": "user-001", "tenant_id": "tenant-001", "nbf": time.time() + 600},
            "any-key",
        )
        request = {"headers": {"Authorization": f"Bearer {token}"}}

        with pytest.raises(TolapIdentityError, match="not yet valid"):
            JwtIdentityExtractor(allow_unverified=True).extract_user_id(request)


class TestUnenforceableModeWarning:
    """Threat-model R-6: a wrapper that cannot enforce must say so at startup.

    Python has no permissive *mode*; the equivalent opt-outs are
    allow_unenforceable_shapes and the enforce_signatures/enforce_expiry switches.
    The pass-through path already logs when it actually returns an unenforceable
    shape, but that warning is absent from a service which has not yet returned one
    -- so the misconfiguration ships unnoticed and only becomes visible on the
    request that leaks.
    """

    KEY = "warning-test-key"

    def test_allow_unenforceable_shapes_warns_at_construction(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level("WARNING"):
            SecureMcpToolWrapper(
                SecureMcpServerOptions(
                    signing_key=self.KEY, allow_unenforceable_shapes=True
                )
            )

        assert "NOT fully enforcing" in caplog.text
        assert "allow_unenforceable_shapes" in caplog.text
        assert "MUST NOT be used in production" in caplog.text

    def test_disabled_signature_enforcement_warns(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level("WARNING"):
            SecureMcpToolWrapper(
                SecureMcpServerOptions(signing_key=self.KEY, enforce_signatures=False)
            )

        assert "enforce_signatures=False" in caplog.text

    def test_disabled_expiry_enforcement_warns(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level("WARNING"):
            SecureMcpToolWrapper(
                SecureMcpServerOptions(signing_key=self.KEY, enforce_expiry=False)
            )

        assert "enforce_expiry=False" in caplog.text

    def test_secure_defaults_do_not_warn(self, caplog: pytest.LogCaptureFixture) -> None:
        """The warning must stay silent on the safe default, or it becomes noise."""
        with caplog.at_level("WARNING"):
            SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=self.KEY))

        assert caplog.text == ""
