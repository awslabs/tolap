"""Regression tests for the HTTP wrapper's post-call enforcement.

The HTTP path already stripped hidden fields; these cover the allowedFields
projection it was missing (defect 2) and confirm the refactor onto the shared
core function preserved nested-tree walking (defect 1).
"""

from __future__ import annotations

from datetime import timedelta

import httpx
import pytest

from tolap_core.context import build_security_context, sign_context
from tolap_core.enums import MaskType
from tolap_core.models import (
    EffectivePolicy,
    EndpointRules,
    FieldRules,
    MaskingRule,
    ObjectRules,
    PolicyPermissions,
    SecurityContext,
)
from tolap_mcp.http_wrapper import SecureHttpToolWrapper
from tolap_mcp.options import SecureMcpServerOptions


KEY = "http-regression-key"

BODY = {
    "meta": {"disclaimer": "openFDA", "results": {"total": 2}},
    "results": [
        {"id": "r1", "safetyreportid": "111", "patient": {"ssn": "111-22-3333", "sex": "1"}},
        {"id": "r2", "safetyreportid": "222", "patient": {"ssn": "222-33-4444", "sex": "2"}},
    ],
}


def _client() -> httpx.Client:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=BODY)

    return httpx.Client(base_url="https://api.example.gov", transport=httpx.MockTransport(handler))


def _context(field_rules: FieldRules | None) -> SecurityContext:
    policy = EffectivePolicy(
        version="1.0",
        user_id="u",
        tenant_id="t",
        source_profiles=["http-test"],
        permissions=PolicyPermissions(can_query=True, read_only=True),
        object_rules=ObjectRules(
            endpoint_rules=EndpointRules(allowed_endpoints=["/v1/*"], allowed_methods=["GET"]),
            field_rules=field_rules,
        ),
    )
    return sign_context(build_security_context("u", "t", [policy], ttl=timedelta(hours=1)), KEY)


@pytest.fixture
def wrapper():
    with _client() as client:
        yield SecureHttpToolWrapper(SecureMcpServerOptions(signing_key=KEY), client)


class TestHttpAllowedFieldsProjection:
    """Defect 2: allowedFields was never applied to an HTTP response body."""

    def test_records_are_projected_to_allowed_fields(self, wrapper: SecureHttpToolWrapper) -> None:
        context = _context(FieldRules(allowed_fields=["id"]))

        body = wrapper.request(context, "GET", "/v1/reports", collection_path="results")

        for row in body["results"]:
            assert sorted(row) == ["id"]

    def test_envelope_is_preserved_while_records_are_projected(self, wrapper: SecureHttpToolWrapper) -> None:
        """The transport envelope (meta/paging) must survive projection."""
        context = _context(FieldRules(allowed_fields=["id"]))

        body = wrapper.request(context, "GET", "/v1/reports", collection_path="results")

        assert "meta" in body
        assert body["meta"]["disclaimer"] == "openFDA"

    def test_empty_allow_list_strips_every_record_field(self, wrapper: SecureHttpToolWrapper) -> None:
        context = _context(FieldRules(allowed_fields=[]))

        body = wrapper.request(context, "GET", "/v1/reports", collection_path="results")

        assert body["results"] == [{}, {}]

    def test_absent_allow_list_leaves_the_body_untouched(self, wrapper: SecureHttpToolWrapper) -> None:
        context = _context(None)

        body = wrapper.request(context, "GET", "/v1/reports", collection_path="results")

        assert body == BODY


class TestHttpHiddenFieldsAfterRefactor:
    """Defect 1: the shared core function must keep walking nested trees."""

    def test_dotted_hidden_path_still_strips_a_nested_leaf(self, wrapper: SecureHttpToolWrapper) -> None:
        context = _context(FieldRules(hidden_fields=["results.patient.ssn"]))

        body = wrapper.request(context, "GET", "/v1/reports", collection_path="results")

        for row in body["results"]:
            assert "ssn" not in row["patient"]
            assert row["patient"]["sex"] is not None

    def test_bare_hidden_name_strips_a_nested_leaf(self, wrapper: SecureHttpToolWrapper) -> None:
        context = _context(FieldRules(hidden_fields=["ssn"]))

        body = wrapper.request(context, "GET", "/v1/reports", collection_path="results")

        for row in body["results"]:
            assert "ssn" not in row["patient"]

    def test_hidden_removal_precedes_masking(self, wrapper: SecureHttpToolWrapper) -> None:
        """A field that is both hidden and masked is removed, not masked."""
        context = _context(
            FieldRules(
                hidden_fields=["results.safetyreportid"],
                masked_fields=[MaskingRule(field="results.safetyreportid", mask_type=MaskType.hash)],
            )
        )

        body = wrapper.request(context, "GET", "/v1/reports", collection_path="results")

        for row in body["results"]:
            assert "safetyreportid" not in row

    def test_response_is_not_mutated_for_the_next_caller(self, wrapper: SecureHttpToolWrapper) -> None:
        context = _context(FieldRules(hidden_fields=["ssn"]))

        wrapper.request(context, "GET", "/v1/reports", collection_path="results")

        assert BODY["results"][0]["patient"]["ssn"] == "111-22-3333"


class TestHttpExpiryFailsClosed:
    """Defect 5: a context with no expiry was accepted by the HTTP wrapper."""

    def test_missing_expiry_is_denied(self, wrapper: SecureHttpToolWrapper) -> None:
        policy = EffectivePolicy(
            version="1.0",
            user_id="u",
            tenant_id="t",
            source_profiles=["http-test"],
            permissions=PolicyPermissions(can_query=True),
            object_rules=ObjectRules(
                endpoint_rules=EndpointRules(allowed_endpoints=["/v1/*"], allowed_methods=["GET"]),
            ),
        )
        context = sign_context(SecurityContext(effective_policy=policy), KEY)

        with pytest.raises(PermissionError, match="no expiry"):
            wrapper.request(context, "GET", "/v1/reports")
