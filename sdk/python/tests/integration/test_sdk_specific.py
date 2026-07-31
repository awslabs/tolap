"""Python-SDK-specific integration tests.

These cover behaviors that don't translate cleanly into declarative cross-SDK
scenarios (mutation-after-signing, transport-never-called assertions, expiry
windows). Each language SDK is free to add its own equivalents — the shared
JSON scenarios catch contract drift; this file catches per-language regressions.
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
from tolap_mcp.wrapper import SecureMcpToolWrapper


# ---------- Postgres-side SDK-specific behavior ----------


class TestSqlSignatureTampering:
    def test_mutating_policy_after_signing_invalidates_signature(
        self, signing_key, healthcare_analyst_context, db_conn
    ) -> None:
        wrapper = SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=signing_key))
        healthcare_analyst_context.effective_policy.object_rules.hidden_objects = []
        with pytest.raises(PermissionError, match="invalid signature"):
            wrapper.execute_with_enforcement(
                context=healthcare_analyst_context,
                tool_name="pg-query",
                tool_fn=lambda: db_conn.execute("SELECT 1").fetchall(),
                tool_args={},
                object_name="billing_internal",
            )

    def test_wrong_signing_key_rejected(self, healthcare_analyst_context, db_conn) -> None:
        wrapper = SecureMcpToolWrapper(SecureMcpServerOptions(signing_key="not-the-right-key"))
        with pytest.raises(PermissionError, match="invalid signature"):
            wrapper.execute_with_enforcement(
                context=healthcare_analyst_context,
                tool_name="pg-query",
                tool_fn=lambda: db_conn.execute("SELECT 1").fetchall(),
                tool_args={},
                object_name="patients",
            )


# ---------- API-side SDK-specific behavior ----------


class TestApiSignatureTampering:
    def test_mutating_endpoint_rules_after_signing(
        self, openfda_signing_key, openfda_analyst_context, openfda_replay_client
    ) -> None:
        wrapper = SecureHttpToolWrapper(
            SecureMcpServerOptions(signing_key=openfda_signing_key),
            openfda_replay_client,
        )
        openfda_analyst_context.effective_policy.object_rules.endpoint_rules.hidden_endpoints = []
        with pytest.raises(PermissionError, match="invalid signature"):
            wrapper.request(openfda_analyst_context, "GET", "/food/enforcement.json")

    def test_wrong_signing_key_rejected(
        self, openfda_analyst_context, openfda_replay_client
    ) -> None:
        wrapper = SecureHttpToolWrapper(
            SecureMcpServerOptions(signing_key="not-the-right-key"),
            openfda_replay_client,
        )
        with pytest.raises(PermissionError, match="invalid signature"):
            wrapper.request(openfda_analyst_context, "GET", "/drug/event.json")


class TestApiExpiry:
    def test_expired_context_rejected(
        self, openfda_signing_key, openfda_replay_client, openfda_expired_context
    ) -> None:
        wrapper = SecureHttpToolWrapper(
            SecureMcpServerOptions(signing_key=openfda_signing_key),
            openfda_replay_client,
        )
        with pytest.raises(PermissionError, match="expired"):
            wrapper.request(openfda_expired_context, "GET", "/drug/event.json")


class TestApiCanQueryShortCircuit:
    def test_can_query_false_blocks_before_endpoint_check(
        self, openfda_signing_key, openfda_replay_client, openfda_deny_query_context
    ) -> None:
        wrapper = SecureHttpToolWrapper(
            SecureMcpServerOptions(signing_key=openfda_signing_key),
            openfda_replay_client,
        )
        with pytest.raises(PermissionError, match="query not permitted"):
            wrapper.request(openfda_deny_query_context, "GET", "/drug/event.json")


class TestApiNetworkContract:
    def test_denied_call_does_not_invoke_transport(
        self, openfda_signing_key, openfda_analyst_context
    ) -> None:
        """A denied request must short-circuit before the HTTP transport is touched."""

        def must_not_be_called(_request: httpx.Request) -> httpx.Response:
            raise AssertionError("transport called for a denied request")

        with httpx.Client(
            base_url="https://api.fda.gov",
            transport=httpx.MockTransport(must_not_be_called),
        ) as client:
            wrapper = SecureHttpToolWrapper(
                SecureMcpServerOptions(signing_key=openfda_signing_key), client
            )
            with pytest.raises(PermissionError):
                wrapper.request(openfda_analyst_context, "GET", "/food/enforcement.json")


class TestApiWildcardDenyPrecedence:
    def test_hidden_pattern_takes_precedence_over_allow(
        self, openfda_signing_key, openfda_replay_client
    ) -> None:
        # Allow EVERYTHING under /drug/* but hide /drug/event.json explicitly.
        policy = EffectivePolicy(
            version="1.0",
            user_id="u",
            tenant_id="t",
            source_profiles=["wildcard"],
            permissions=PolicyPermissions(can_query=True),
            object_rules=ObjectRules(
                endpoint_rules=EndpointRules(
                    allowed_endpoints=["/drug/*"],
                    hidden_endpoints=["/drug/event.json"],
                    allowed_methods=["GET"],
                ),
            ),
        )
        ctx = build_security_context("u", "t", [policy], ttl=timedelta(hours=1))
        ctx = sign_context(ctx, openfda_signing_key)

        wrapper = SecureHttpToolWrapper(
            SecureMcpServerOptions(signing_key=openfda_signing_key),
            openfda_replay_client,
        )
        with pytest.raises(PermissionError, match="endpoint is hidden"):
            wrapper.request(ctx, "GET", "/drug/event.json")
        body = wrapper.request(ctx, "GET", "/drug/label.json", collection_path="results")
        assert "results" in body
