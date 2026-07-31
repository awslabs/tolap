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
    FieldRules,
    ObjectRules,
    PolicyPermissions,
)
from tolap_mcp.http_wrapper import SecureHttpToolWrapper, UpstreamHttpError
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
    """A non-2xx raises -- but as :class:`UpstreamHttpError`, not ``HTTPStatusError``.

    These previously asserted ``httpx.HTTPStatusError``, which was the leak rather
    than the contract. ``raise_for_status`` ran before enforcement, so the response
    never reached the pipeline and the raised exception carried ``.response`` with
    the raw unenforced payload -- a caller catching the error read every
    ``hiddenFields`` entry in cleartext. Connector spec section 6 requires error
    bodies to be enforced, so the wrapper enforces first and raises an exception
    that exposes only the enforced body.
    """

    def test_404_response_raises_after_policy_passes(self) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(404, json={"error": "not found"})

        wrapper, client = _wrapper(handler)
        try:
            with pytest.raises(UpstreamHttpError) as exc_info:
                wrapper.request(_signed_ctx(), "GET", "/drug/event.json")
            assert exc_info.value.status_code == 404
        finally:
            client.close()

    def test_429_rate_limit_propagates(self) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(429, json={"error": "rate limited"})

        wrapper, client = _wrapper(handler)
        try:
            with pytest.raises(UpstreamHttpError) as exc_info:
                wrapper.request(_signed_ctx(), "GET", "/drug/event.json")
            assert exc_info.value.status_code == 429
        finally:
            client.close()

    def test_500_server_error_propagates(self) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="internal server error")

        wrapper, client = _wrapper(handler)
        try:
            with pytest.raises(UpstreamHttpError) as exc_info:
                wrapper.request(_signed_ctx(), "GET", "/drug/event.json")
            assert exc_info.value.status_code == 500
            # A non-JSON error body cannot have policy applied to it, so it is
            # withheld rather than handed back unenforced (spec section 5).
            assert exc_info.value.body is None
        finally:
            client.close()

    def test_the_raised_error_exposes_no_route_to_the_unenforced_body(self) -> None:
        """The exception must not carry a handle on the raw payload.

        The whole point of enforcing an error body is defeated if the exception
        also ships the response object it came from. ``httpx.HTTPStatusError``
        does exactly that via ``.response``; ``UpstreamHttpError`` deliberately
        holds a status, an enforced body and a URL, and nothing else.
        """

        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(422, json={"error": {"rejected_ssn": "111-22-3333"}})

        policy = _allow_drug_policy()
        policy.object_rules.field_rules = FieldRules(hidden_fields=["error"])
        context = sign_context(
            build_security_context("u", "t", [policy], ttl=timedelta(hours=1)), SIGNING_KEY
        )

        wrapper, client = _wrapper(handler)
        try:
            with pytest.raises(UpstreamHttpError) as exc_info:
                wrapper.request(context, "GET", "/drug/event.json")

            error = exc_info.value
            assert error.body == {}, "the hidden field is removed from the error body"
            assert not hasattr(error, "response")
            assert "111-22-3333" not in str(error)
            # Nothing reachable on the exception carries the raw payload.
            for value in vars(error).values():
                assert "111-22-3333" not in repr(value)
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
