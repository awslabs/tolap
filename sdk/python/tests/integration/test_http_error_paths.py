"""HTTP error and short-circuit behavior for SecureHttpToolWrapper.

These are SDK-specific (offline-only) — they assert behavior in the presence
of upstream HTTP errors that we can't reliably reproduce live. Each language
SDK has its own equivalent.
"""

from __future__ import annotations

from datetime import timedelta

import httpx
import pytest

from tolap_core.context import build_security_context, sign_context
from tolap_core.models import (
    EffectivePolicy,
    EndpointRules,
    ObjectRules,
    PolicyPermissions,
)
from tolap_mcp.http_wrapper import SecureHttpToolWrapper
from tolap_mcp.options import SecureMcpServerOptions


SIGNING_KEY = "openfda-integration-key"


def _allow_drug_policy() -> EffectivePolicy:
    return EffectivePolicy(
        version="1.0",
        user_id="u",
        tenant_id="t",
        source_profiles=["http-error-test"],
        permissions=PolicyPermissions(can_query=True),
        object_rules=ObjectRules(
            endpoint_rules=EndpointRules(
                allowed_endpoints=["/drug/*"],
                hidden_endpoints=["/food/*"],
                allowed_methods=["GET"],
            ),
        ),
    )


def _signed_ctx():
    ctx = build_security_context("u", "t", [_allow_drug_policy()], ttl=timedelta(hours=1))
    return sign_context(ctx, SIGNING_KEY)


def _wrapper(handler):
    transport = httpx.MockTransport(handler)
    client = httpx.Client(base_url="https://api.fda.gov", transport=transport)
    return SecureHttpToolWrapper(SecureMcpServerOptions(signing_key=SIGNING_KEY), client), client


class TestUpstreamErrorPropagation:
    def test_404_response_raises_after_policy_passes(self) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(404, json={"error": "not found"})

        wrapper, client = _wrapper(handler)
        try:
            with pytest.raises(httpx.HTTPStatusError):
                wrapper.request(_signed_ctx(), "GET", "/drug/event.json")
        finally:
            client.close()

    def test_429_rate_limit_propagates(self) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(429, json={"error": "rate limited"})

        wrapper, client = _wrapper(handler)
        try:
            with pytest.raises(httpx.HTTPStatusError):
                wrapper.request(_signed_ctx(), "GET", "/drug/event.json")
        finally:
            client.close()

    def test_500_server_error_propagates(self) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="internal server error")

        wrapper, client = _wrapper(handler)
        try:
            with pytest.raises(httpx.HTTPStatusError):
                wrapper.request(_signed_ctx(), "GET", "/drug/event.json")
        finally:
            client.close()


class TestPolicyShortCircuit:
    def test_hidden_endpoint_does_not_invoke_transport_even_on_500(self) -> None:
        """A denied endpoint must short-circuit BEFORE any HTTP call goes out.

        We install a transport that always 500s; the wrapper must reject the
        call without ever invoking it.
        """
        invocations: list[str] = []

        def handler(req: httpx.Request) -> httpx.Response:
            invocations.append(req.url.path)
            return httpx.Response(500)

        wrapper, client = _wrapper(handler)
        try:
            with pytest.raises(PermissionError, match="endpoint is hidden"):
                wrapper.request(_signed_ctx(), "GET", "/food/enforcement.json")
            assert invocations == [], "transport must not be called for a denied endpoint"
        finally:
            client.close()

    def test_method_denial_short_circuits_before_transport(self) -> None:
        invocations: list[str] = []

        def handler(req: httpx.Request) -> httpx.Response:
            invocations.append(req.method)
            return httpx.Response(200, json={"ok": True})

        wrapper, client = _wrapper(handler)
        try:
            with pytest.raises(PermissionError, match="method not allowed"):
                wrapper.request(_signed_ctx(), "DELETE", "/drug/event.json")
            assert invocations == []
        finally:
            client.close()
