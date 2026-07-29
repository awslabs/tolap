"""SecureHttpToolWrapper against a real local HTTP server.

Every other HTTP test in this suite uses ``httpx.MockTransport``, which never puts
bytes on a socket. That is fast and hermetic but it cannot reach the paths that
only exist once a real response has to be received and parsed: a non-2xx status
raised by ``raise_for_status``, a body the server framed itself, a query string
the wrapper must strip before policy evaluation, and a real POST. The one suite
that did use the network hit api.fda.gov to *refresh fixtures*, so it mutated the
repository and failed offline.

This module starts ``tools/test-api/server.py`` as a subprocess and drives the
wrapper against it over loopback. It skips cleanly when the port cannot be bound
or the server does not come up, so it never turns an unrelated environment
problem into a suite failure.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import time
from datetime import timedelta
from pathlib import Path
from urllib.parse import quote

import httpx
import pytest

from tolap_core.context import build_security_context, sign_context
from tolap_core.enums import FilterOperator, MaskType
from tolap_core.models import (
    EffectivePolicy,
    EndpointRules,
    FieldRules,
    MaskingParameters,
    MaskingRule,
    ObjectRules,
    PolicyLimits,
    PolicyPermissions,
    RowFilter,
    SecurityContext,
    TagRules,
)
from tolap_mcp.http_wrapper import (
    MAX_REDIRECTS,
    SecureHttpToolWrapper,
    UpstreamHttpError,
)
from tolap_mcp.options import SecureMcpServerOptions


SERVER_SCRIPT = Path(__file__).parents[4] / "tools" / "test-api" / "server.py"
SIGNING_KEY = "live-http-api-key"
STARTUP_TIMEOUT_SECONDS = 10.0


def _free_port() -> int:
    """Bind port 0 to let the OS pick a free port, then release it.

    Picking dynamically rather than hard-coding 8888 keeps the suite runnable
    while a developer has the server up by hand.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(scope="module")
def live_api_base_url() -> str:
    """Start the stdlib test API as a subprocess for the module's duration."""
    if not SERVER_SCRIPT.exists():
        pytest.skip(f"test API server not found at {SERVER_SCRIPT}")

    port = _free_port()
    process = subprocess.Popen(
        [sys.executable, str(SERVER_SCRIPT), "--port", str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    base_url = f"http://127.0.0.1:{port}"

    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    ready = False
    while time.monotonic() < deadline:
        if process.poll() is not None:
            break
        try:
            response = httpx.get(f"{base_url}/healthz", timeout=0.5)
            if response.status_code == 200 and response.json().get("status") == "ok":
                ready = True
                break
        except httpx.HTTPError:
            time.sleep(0.05)

    if not ready:
        process.kill()
        output = process.stdout.read().decode("utf-8", "replace") if process.stdout else ""
        pytest.skip(f"test API server did not start on {base_url}: {output.strip()}")

    try:
        yield base_url
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()


@pytest.fixture
def live_client(live_api_base_url: str) -> httpx.Client:
    with httpx.Client(base_url=live_api_base_url, timeout=10.0) as client:
        yield client


def _signed(policy: EffectivePolicy, ttl: timedelta = timedelta(hours=1)) -> SecurityContext:
    context = build_security_context("live-user", "live-tenant", [policy], ttl=ttl)
    return sign_context(context, SIGNING_KEY)


def _wrapper(client: httpx.Client, **options) -> SecureHttpToolWrapper:
    return SecureHttpToolWrapper(
        SecureMcpServerOptions(signing_key=SIGNING_KEY, **options), client
    )


def _policy(
    *,
    can_query: bool = True,
    can_insert: bool | None = None,
    can_update: bool | None = None,
    can_delete: bool | None = None,
    read_only: bool | None = True,
    endpoint_rules: EndpointRules | None = None,
    field_rules: FieldRules | None = None,
    row_filters: list[RowFilter] | None = None,
    tag_rules: TagRules | None = None,
    allowed_objects: list[str] | None = None,
    hidden_objects: list[str] | None = None,
    limits: PolicyLimits | None = None,
) -> EffectivePolicy:
    has_object_rules = any(
        [endpoint_rules, field_rules, row_filters, tag_rules, allowed_objects, hidden_objects]
    )
    return EffectivePolicy(
        version="1.0",
        user_id="live-user",
        tenant_id="live-tenant",
        source_profiles=["live-http"],
        permissions=PolicyPermissions(
            can_query=can_query,
            can_insert=can_insert,
            can_update=can_update,
            can_delete=can_delete,
            read_only=read_only,
        ),
        object_rules=ObjectRules(
            endpoint_rules=endpoint_rules,
            field_rules=field_rules,
            row_filters=row_filters,
            tag_rules=tag_rules,
            allowed_objects=allowed_objects,
            hidden_objects=hidden_objects,
        )
        if has_object_rules
        else None,
        limits=limits,
    )


ALLOW_ALL_GET = EndpointRules(allowed_endpoints=["/*"], allowed_methods=["GET"])


class TestLiveServerReachable:
    """The fixture's own contract: without this the rest proves nothing."""

    def test_server_serves_records_over_a_real_socket(self, live_client: httpx.Client) -> None:
        response = live_client.get("/patients")

        assert response.status_code == 200
        records = response.json()["results"]
        # The unenforced response really does carry the PII the policies below
        # are expected to remove, so a passing enforcement test is meaningful.
        assert any("ssn" in record for record in records)


class TestFieldEnforcementOverRealHttp:
    def test_hidden_fields_are_removed_from_a_real_response(self, live_client: httpx.Client) -> None:
        context = _signed(
            _policy(
                endpoint_rules=ALLOW_ALL_GET,
                field_rules=FieldRules(hidden_fields=["ssn", "date_of_birth"]),
            )
        )

        body = _wrapper(live_client).request(
            context, "GET", "/patients", collection_path="results"
        )

        assert body["results"], "expected records to enforce against"
        for record in body["results"]:
            assert "ssn" not in record
            assert "date_of_birth" not in record
            assert "full_name" in record

    def test_allowed_fields_projection_keeps_the_envelope(self, live_client: httpx.Client) -> None:
        context = _signed(
            _policy(
                endpoint_rules=ALLOW_ALL_GET,
                field_rules=FieldRules(allowed_fields=["id", "region"]),
            )
        )

        body = _wrapper(live_client).request(
            context, "GET", "/patients/envelope", collection_path="items"
        )

        # The paging envelope survives; the records are trimmed.
        assert body["total"] == 5
        for record in body["items"]:
            assert sorted(record) == ["id", "region"]

    def test_empty_allowed_fields_denies_every_field(self, live_client: httpx.Client) -> None:
        """Spec section 3: `[]` is deny-all, not "unrestricted"."""
        context = _signed(
            _policy(endpoint_rules=ALLOW_ALL_GET, field_rules=FieldRules(allowed_fields=[]))
        )

        body = _wrapper(live_client).request(
            context, "GET", "/patients", collection_path="results"
        )

        assert body["results"], "records should still be present, just empty"
        assert all(record == {} for record in body["results"])

    def test_masking_applies_to_a_real_response(self, live_client: httpx.Client) -> None:
        context = _signed(
            _policy(
                endpoint_rules=ALLOW_ALL_GET,
                field_rules=FieldRules(
                    masked_fields=[
                        MaskingRule(field="ssn", mask_type=MaskType.redact),
                        MaskingRule(
                            field="full_name",
                            mask_type=MaskType.partial,
                            parameters=MaskingParameters(show_first=1, mask_char="*"),
                        ),
                    ]
                ),
            )
        )

        body = _wrapper(live_client).request(
            context, "GET", "/patients", collection_path="results"
        )

        first = body["results"][0]
        assert first["ssn"] == "[REDACTED]"
        assert first["full_name"].startswith("A")
        assert "Nguyen" not in first["full_name"]

    def test_nested_records_are_enforced_recursively(self, live_client: httpx.Client) -> None:
        """A wrapper that only walks the top level would leak demographics.ssn."""
        context = _signed(
            _policy(
                endpoint_rules=ALLOW_ALL_GET,
                field_rules=FieldRules(
                    hidden_fields=["ssn"],
                    masked_fields=[MaskingRule(field="email", mask_type=MaskType.hash)],
                ),
            )
        )

        body = _wrapper(live_client).request(
            context, "GET", "/patients/nested", collection_path="results"
        )

        for record in body["results"]:
            demographics = record["demographics"]
            assert "ssn" not in demographics
            email = demographics["contact"]["email"]
            assert "@" not in email
            assert len(email) == 16

    def test_result_limit_truncates_the_live_collection(self, live_client: httpx.Client) -> None:
        context = _signed(
            _policy(endpoint_rules=ALLOW_ALL_GET, limits=PolicyLimits(max_results=2))
        )

        body = _wrapper(live_client).request(
            context, "GET", "/patients", collection_path="results"
        )

        assert len(body["results"]) == 2


class TestRowAndTagFilteringOverRealHttp:
    """Pipeline steps 1 and 2 (spec section 4) applied to an HTTP body.

    These were missing from the HTTP wrapper: a policy that excluded rows was a
    silent no-op over HTTP even though the identical policy filtered correctly
    through the MCP wrapper.
    """

    def test_row_filter_drops_excluded_rows(self, live_client: httpx.Client) -> None:
        context = _signed(
            _policy(
                endpoint_rules=ALLOW_ALL_GET,
                row_filters=[
                    RowFilter(field="status", operator=FilterOperator.not_equals, value="deleted")
                ],
            )
        )

        body = _wrapper(live_client).request(
            context, "GET", "/patients", collection_path="results"
        )

        statuses = {record["status"] for record in body["results"]}
        assert "deleted" not in statuses
        # id 4 is the deleted record in the server's corpus.
        assert 4 not in {record["id"] for record in body["results"]}

    def test_row_filter_missing_field_fails_closed(self, live_client: httpx.Client) -> None:
        """Spec section 7: an absent field drops the row, even for notEquals.

        Record id 5 has no `tags` key, so a filter on `tags` must drop it rather
        than retain it on `undefined != x`.
        """
        context = _signed(
            _policy(
                endpoint_rules=ALLOW_ALL_GET,
                row_filters=[
                    RowFilter(field="status", operator=FilterOperator.not_equals, value="deleted"),
                    RowFilter(field="tags", operator=FilterOperator.not_equals, value="nothing"),
                ],
            )
        )

        body = _wrapper(live_client).request(
            context, "GET", "/patients", collection_path="results"
        )

        assert 5 not in {record["id"] for record in body["results"]}

    def test_denied_tags_drop_matching_records(self, live_client: httpx.Client) -> None:
        context = _signed(
            _policy(
                endpoint_rules=ALLOW_ALL_GET,
                tag_rules=TagRules(denied_tags=["confidential"]),
            )
        )

        body = _wrapper(live_client).request(
            context, "GET", "/patients", collection_path="results"
        )

        ids = {record["id"] for record in body["results"]}
        assert 3 not in ids, "the confidential-tagged record must be dropped"
        # The record with no tags key at all survives a denylist-only policy.
        assert 5 in ids

    def test_allowed_tags_drops_untagged_records(self, live_client: httpx.Client) -> None:
        context = _signed(
            _policy(endpoint_rules=ALLOW_ALL_GET, tag_rules=TagRules(allowed_tags=["research"]))
        )

        body = _wrapper(live_client).request(
            context, "GET", "/patients", collection_path="results"
        )

        assert [record["id"] for record in body["results"]] == [2]

    def test_empty_allowed_tags_denies_every_record(self, live_client: httpx.Client) -> None:
        """Spec section 3: an empty allow-list is the most restrictive outcome."""
        context = _signed(
            _policy(endpoint_rules=ALLOW_ALL_GET, tag_rules=TagRules(allowed_tags=[]))
        )

        body = _wrapper(live_client).request(
            context, "GET", "/patients", collection_path="results"
        )

        assert body["results"] == []

    def test_filtering_precedes_the_limit(self, live_client: httpx.Client) -> None:
        """Spec section 4: the limit runs last, so filtering never starves it.

        Four records survive the status filter; a limit of 3 must return 3. A
        wrapper that limited first would take rows 1-3, drop the deleted one, and
        return 2.
        """
        context = _signed(
            _policy(
                endpoint_rules=ALLOW_ALL_GET,
                row_filters=[
                    RowFilter(field="status", operator=FilterOperator.not_equals, value="deleted")
                ],
                limits=PolicyLimits(max_results=3),
            )
        )

        body = _wrapper(live_client).request(
            context, "GET", "/patients", collection_path="results"
        )

        assert len(body["results"]) == 3
        assert 4 not in {record["id"] for record in body["results"]}

    def test_envelope_survives_record_filtering(self, live_client: httpx.Client) -> None:
        context = _signed(
            _policy(
                endpoint_rules=ALLOW_ALL_GET,
                tag_rules=TagRules(denied_tags=["confidential"]),
            )
        )

        body = _wrapper(live_client).request(
            context, "GET", "/patients/envelope", collection_path="items"
        )

        assert body["total"] == 5, "the envelope's own metadata is not a record"
        assert 3 not in {record["id"] for record in body["items"]}

    def test_hidden_field_does_not_defeat_a_filter_on_it(self, live_client: httpx.Client) -> None:
        """Filtering runs before hidden-field removal, so both apply."""
        context = _signed(
            _policy(
                endpoint_rules=ALLOW_ALL_GET,
                field_rules=FieldRules(hidden_fields=["status"]),
                row_filters=[
                    RowFilter(field="status", operator=FilterOperator.not_equals, value="deleted")
                ],
            )
        )

        body = _wrapper(live_client).request(
            context, "GET", "/patients", collection_path="results"
        )

        assert 4 not in {record["id"] for record in body["results"]}
        for record in body["results"]:
            assert "status" not in record


class TestEndpointRulesOverRealHttp:
    def test_hidden_endpoint_is_denied_before_the_request_leaves(
        self, live_client: httpx.Client
    ) -> None:
        """The server would happily serve /admin/audit; the policy must not."""
        context = _signed(
            _policy(
                endpoint_rules=EndpointRules(
                    allowed_endpoints=["/*"],
                    hidden_endpoints=["/admin/*"],
                    allowed_methods=["GET"],
                )
            )
        )

        with pytest.raises(PermissionError, match="endpoint is hidden"):
            _wrapper(live_client).request(context, "GET", "/admin/audit")

    def test_endpoint_outside_the_allow_list_is_denied(self, live_client: httpx.Client) -> None:
        context = _signed(
            _policy(
                endpoint_rules=EndpointRules(
                    allowed_endpoints=["/patients*"], allowed_methods=["GET"]
                )
            )
        )

        with pytest.raises(PermissionError, match="endpoint not in allowed set"):
            _wrapper(live_client).request(context, "GET", "/admin/audit")

    def test_post_is_denied_for_a_get_only_policy(self, live_client: httpx.Client) -> None:
        """The server returns 201 for this POST, so denial is the policy's work."""
        context = _signed(_policy(endpoint_rules=ALLOW_ALL_GET))

        with pytest.raises(PermissionError, match="method not allowed"):
            _wrapper(live_client).request(
                context, "POST", "/patients", json={"full_name": "New Person"}
            )

    def test_post_succeeds_when_the_policy_permits_it(self, live_client: httpx.Client) -> None:
        """Permitting a write takes allowedMethods, readOnly=False, AND canInsert.

        Three independent gates, all of which must open (connector spec sections 4
        and 6). ``allowedMethods`` makes the verb reachable on the path, ``readOnly``
        is the ceiling over every write, and ``canInsert`` is the permission for the
        operation ``POST`` performs -- none of the three implies another.
        """
        context = _signed(
            _policy(
                can_insert=True,
                read_only=False,
                endpoint_rules=EndpointRules(
                    allowed_endpoints=["/patients*"], allowed_methods=["GET", "POST"]
                ),
            )
        )

        body = _wrapper(live_client).request(
            context, "POST", "/patients", json={"full_name": "New Person"}
        )

        assert body["created"] is True
        assert body["received"] == {"full_name": "New Person"}

    def test_post_is_denied_when_can_insert_is_absent(self, live_client: httpx.Client) -> None:
        """An omitted canInsert is a denial, not an unstated grant.

        The method is allowed and the policy is not read-only, so ``allowedMethods``
        and ``readOnly`` both open -- the only thing refusing this POST is the
        absent write permission. Absent defaults to false (connector spec
        section 4.1), deliberately opposite to ``canQuery``, so a policy authored
        before writes existed does not silently acquire them.
        """
        context = _signed(
            _policy(
                read_only=False,
                endpoint_rules=EndpointRules(
                    allowed_endpoints=["/patients*"], allowed_methods=["GET", "POST"]
                ),
            )
        )

        with pytest.raises(PermissionError, match="insert not permitted"):
            _wrapper(live_client).request(
                context, "POST", "/patients", json={"full_name": "New Person"}
            )

    def test_post_is_denied_when_the_policy_is_still_read_only(
        self, live_client: httpx.Client
    ) -> None:
        """The server would return 201, so denial is the readOnly permission's work."""
        context = _signed(
            _policy(
                read_only=True,
                endpoint_rules=EndpointRules(
                    allowed_endpoints=["/patients*"], allowed_methods=["GET", "POST"]
                ),
            )
        )

        with pytest.raises(PermissionError, match="read-only policy"):
            _wrapper(live_client).request(
                context, "POST", "/patients", json={"full_name": "New Person"}
            )

    def test_query_string_is_stripped_before_policy_evaluation(
        self, live_client: httpx.Client
    ) -> None:
        """Policy patterns are written against paths; a `?` must not defeat them."""
        context = _signed(
            _policy(
                endpoint_rules=EndpointRules(
                    allowed_endpoints=["/patients"], allowed_methods=["GET"]
                )
            )
        )

        body = _wrapper(live_client).request(
            context, "GET", "/patients?region=us-east", collection_path="results"
        )

        assert {record["region"] for record in body["results"]} == {"us-east"}

    def test_params_reach_the_server(self, live_client: httpx.Client) -> None:
        context = _signed(_policy(endpoint_rules=ALLOW_ALL_GET))

        body = _wrapper(live_client).request(
            context, "GET", "/echo", params={"region": "us-west"}
        )

        assert body["query"] == {"region": ["us-west"]}
        assert body["method"] == "GET"

    def test_headers_reach_the_server(self, live_client: httpx.Client) -> None:
        context = _signed(_policy(endpoint_rules=ALLOW_ALL_GET))

        body = _wrapper(live_client).request(
            context, "GET", "/echo", headers={"X-Case-Id": "abc-123"}
        )

        assert body["headers"]["x-case-id"] == "abc-123"


class TestContextValidationOverRealHttp:
    def test_can_query_false_denies_before_any_request(self, live_client: httpx.Client) -> None:
        context = _signed(_policy(can_query=False, endpoint_rules=ALLOW_ALL_GET))

        with pytest.raises(PermissionError, match="query not permitted"):
            _wrapper(live_client).request(context, "GET", "/patients")

    def test_forged_signature_is_denied(self, live_client: httpx.Client) -> None:
        context = _signed(_policy(endpoint_rules=ALLOW_ALL_GET))
        context.signature = "not-the-real-signature"

        with pytest.raises(PermissionError, match="invalid signature"):
            _wrapper(live_client).request(context, "GET", "/patients")

    def test_expired_context_is_denied(self, live_client: httpx.Client) -> None:
        context = _signed(_policy(endpoint_rules=ALLOW_ALL_GET), ttl=timedelta(hours=-1))

        with pytest.raises(PermissionError, match="expired"):
            _wrapper(live_client).request(context, "GET", "/patients")

    def test_rewritten_expiry_fails_the_signature_not_the_expiry_check(
        self, live_client: httpx.Client
    ) -> None:
        """Spec section 2: expiresAt is inside the signed bytes.

        Extending a captured context's life must invalidate the signature, and the
        signature is checked first so the denial names that rather than the expiry.
        """
        context = _signed(_policy(endpoint_rules=ALLOW_ALL_GET), ttl=timedelta(hours=-1))
        context.expires_at = "2099-01-01T00:00:00Z"

        with pytest.raises(PermissionError, match="invalid signature"):
            _wrapper(live_client).request(context, "GET", "/patients")

    def test_missing_expiry_is_denied(self, live_client: httpx.Client) -> None:
        """Absent expiry is never "never expires" (spec section 2)."""
        context = _signed(_policy(endpoint_rules=ALLOW_ALL_GET))
        context.expires_at = None
        context = sign_context(context, SIGNING_KEY)

        with pytest.raises(PermissionError, match="no expiry"):
            _wrapper(live_client).request(context, "GET", "/patients")

    def test_unparseable_expiry_is_denied(self, live_client: httpx.Client) -> None:
        context = _signed(_policy(endpoint_rules=ALLOW_ALL_GET))
        context.expires_at = "never"
        context = sign_context(context, SIGNING_KEY)

        with pytest.raises(PermissionError, match="invalid expiry format"):
            _wrapper(live_client).request(context, "GET", "/patients")

    def test_enforcement_disabled_accepts_an_unsigned_context(
        self, live_client: httpx.Client
    ) -> None:
        """The migration opt-out must actually opt out, and only that far."""
        context = build_security_context(
            "live-user", "live-tenant", [_policy(endpoint_rules=ALLOW_ALL_GET)],
            ttl=timedelta(hours=1),
        )

        body = _wrapper(
            live_client, enforce_signatures=False
        ).request(context, "GET", "/patients", collection_path="results")

        assert body["results"], "an unsigned context is accepted when not enforcing"


class TestUpstreamErrorsOverRealHttp:
    @pytest.mark.parametrize("status", [400, 403, 404, 429, 500, 503])
    def test_error_status_raises_after_the_policy_allows(
        self, live_client: httpx.Client, status: int
    ) -> None:
        """A real non-2xx must surface as an HTTP error, not an empty result set.

        Returning ``{}`` or ``[]`` here would let a caller mistake an upstream
        outage for "the policy filtered everything out".

        The exception is ``UpstreamHttpError`` rather than ``httpx.HTTPStatusError``:
        the latter exposes ``.response``, which handed the caller the raw
        unenforced payload (connector spec section 6, "error bodies are enforced").
        """
        context = _signed(_policy(endpoint_rules=ALLOW_ALL_GET))

        with pytest.raises(UpstreamHttpError) as exc_info:
            _wrapper(live_client).request(context, "GET", f"/status/{status}")

        assert exc_info.value.status_code == status

    @pytest.mark.parametrize("status", [400, 403, 404, 429, 500, 503])
    def test_the_error_body_runs_the_same_pipeline_as_a_success_body(
        self, live_client: httpx.Client, status: int
    ) -> None:
        """LEAK: a hidden field survived in a 4xx/5xx body over a real socket.

        The server's ``/status/<code>`` returns ``{"error": {"code": .., "message":
        ..}}``, so ``hiddenFields: ["error"]`` must empty it. Before the fix
        ``raise_for_status`` ran before the pipeline, the response never reached
        enforcement, and ``e.response.text`` on the raised ``HTTPStatusError``
        carried the field in cleartext -- an ordinary ``except`` block was enough
        to read it. Connector spec section 6: "A 4xx/5xx payload carries the same
        fields as a success payload."
        """
        context = _signed(
            _policy(
                endpoint_rules=ALLOW_ALL_GET,
                field_rules=FieldRules(hidden_fields=["error"]),
            )
        )

        with pytest.raises(UpstreamHttpError) as exc_info:
            _wrapper(live_client).request(context, "GET", f"/status/{status}")

        assert exc_info.value.body == {}, "the hidden field is gone from the error body"
        assert "synthetic" not in str(exc_info.value)

    def test_an_error_body_is_masked_rather_than_returned_in_cleartext(
        self, live_client: httpx.Client
    ) -> None:
        """Masking reaches an error payload's nested fields, not only a success one's."""
        context = _signed(
            _policy(
                endpoint_rules=ALLOW_ALL_GET,
                field_rules=FieldRules(
                    masked_fields=[MaskingRule(field="message", mask_type=MaskType.redact)]
                ),
            )
        )

        with pytest.raises(UpstreamHttpError) as exc_info:
            _wrapper(live_client).request(context, "GET", "/status/400")

        assert exc_info.value.body == {"error": {"code": 400, "message": "[REDACTED]"}}

    def test_the_record_dropping_steps_also_reach_an_error_body(
        self, live_client: httpx.Client
    ) -> None:
        """Row filters run over an error body, not only the field-level steps.

        The body ``{"error": {...}}`` is a single record (spec section 4, "Single
        records"), and a filter on a field it does not carry fails closed and drops
        it, so the enforced body is ``None``. That is the fail-closed direction and
        it is only observable if the record-dropping pass really ran -- a wrapper
        that only stripped fields from an error body would return the record.
        """
        context = _signed(
            _policy(
                endpoint_rules=ALLOW_ALL_GET,
                row_filters=[
                    RowFilter(
                        field="account", operator=FilterOperator.not_equals, value="other"
                    )
                ],
            )
        )

        with pytest.raises(UpstreamHttpError) as exc_info:
            _wrapper(live_client).request(context, "GET", "/status/404")

        assert exc_info.value.status_code == 404
        assert exc_info.value.body is None, "a dropped single record is None, not {}"

    def test_denial_short_circuits_before_the_error_status_is_reached(
        self, live_client: httpx.Client
    ) -> None:
        """A policy denial must beat the upstream error: no request is made."""
        context = _signed(
            _policy(
                endpoint_rules=EndpointRules(
                    allowed_endpoints=["/patients*"], allowed_methods=["GET"]
                )
            )
        )

        with pytest.raises(PermissionError):
            _wrapper(live_client).request(context, "GET", "/status/500")

    def test_timeout_propagates(self, live_api_base_url: str) -> None:
        """A slow upstream raises rather than returning a partial result."""
        context = _signed(_policy(endpoint_rules=ALLOW_ALL_GET))

        with httpx.Client(base_url=live_api_base_url, timeout=0.25) as client:
            with pytest.raises(httpx.TimeoutException):
                _wrapper(client).request(context, "GET", "/slow", params={"ms": 3000})


class TestRedirectsOverRealHttp:
    """Connector spec section 6: "Redirects are re-validated ... or not followed."

    A permitted endpoint that 302s to a denied one otherwise bypasses the endpoint
    check entirely. Nothing in the wrapper configured redirect behavior at all
    before this: it inherited whatever the client was constructed with. ``httpx``
    defaults ``follow_redirects`` to ``False``, so Python was safe only by luck --
    an integrator writing ``httpx.Client(follow_redirects=True)``, which is common
    and reasonable, silently lost every endpoint check on a redirect. These tests
    therefore build a *following* client deliberately: that is the configuration
    that used to be exploitable.
    """

    def test_a_redirect_to_a_denied_endpoint_is_refused(
        self, live_api_base_url: str
    ) -> None:
        """LEAK: /redirect/302 -> /admin/audit returned the audit log.

        The policy allows ``/redirect/*`` and hides ``/admin/*``. The server really
        does serve ``/admin/audit``, so a wrapper that followed the redirect handed
        back data the policy denies by name.
        """
        context = _signed(
            _policy(
                endpoint_rules=EndpointRules(
                    allowed_endpoints=["/redirect/*"],
                    hidden_endpoints=["/admin/*"],
                    allowed_methods=["GET"],
                )
            )
        )

        with httpx.Client(
            base_url=live_api_base_url, timeout=10.0, follow_redirects=True
        ) as client:
            with pytest.raises(PermissionError, match="redirect target rejected"):
                _wrapper(client).request(context, "GET", "/redirect/302")

    def test_the_denial_names_the_endpoint_rule_that_refused_the_hop(
        self, live_api_base_url: str
    ) -> None:
        context = _signed(
            _policy(
                endpoint_rules=EndpointRules(
                    allowed_endpoints=["/redirect/*"], allowed_methods=["GET"]
                )
            )
        )

        with httpx.Client(
            base_url=live_api_base_url, timeout=10.0, follow_redirects=True
        ) as client:
            with pytest.raises(PermissionError, match="endpoint not in allowed set"):
                _wrapper(client).request(context, "GET", "/redirect/302")

    @pytest.mark.parametrize("code", [301, 302, 307, 308])
    def test_every_redirect_code_is_re_validated(
        self, live_api_base_url: str, code: int
    ) -> None:
        """A 307/308 preserves the method; a 301/302 downgrades to GET. Both re-check."""
        context = _signed(
            _policy(
                endpoint_rules=EndpointRules(
                    allowed_endpoints=["/redirect/*"],
                    hidden_endpoints=["/admin/*"],
                    allowed_methods=["GET"],
                )
            )
        )

        with httpx.Client(
            base_url=live_api_base_url, timeout=10.0, follow_redirects=True
        ) as client:
            with pytest.raises(PermissionError, match="endpoint is hidden"):
                _wrapper(client).request(context, "GET", f"/redirect/{code}")

    def test_a_redirect_to_a_permitted_endpoint_is_followed_and_enforced(
        self, live_api_base_url: str
    ) -> None:
        """Re-validating is not refusing: a permitted target still works.

        And the body that comes back runs the full pipeline, so the hop is not a
        way around field rules either.
        """
        context = _signed(
            _policy(
                endpoint_rules=EndpointRules(
                    allowed_endpoints=["/redirect/*", "/patients"],
                    allowed_methods=["GET"],
                ),
                field_rules=FieldRules(hidden_fields=["ssn"]),
            )
        )

        with httpx.Client(
            base_url=live_api_base_url, timeout=10.0, follow_redirects=True
        ) as client:
            body = _wrapper(client).request(
                context,
                "GET",
                "/redirect/302",
                params={"to": "/patients"},
                collection_path="results",
            )

        assert body["results"], "the redirect was followed to the real collection"
        for record in body["results"]:
            assert "ssn" not in record, "the followed hop's body is still enforced"

    def test_a_cross_host_redirect_is_refused_rather_than_re_globbed(
        self, live_api_base_url: str
    ) -> None:
        """An absolute URL to another host is outside the policy's frame of reference.

        ``allowedEndpoints: ["/*"]`` describes paths on the source this policy was
        resolved for. Matching that glob against a path on another host would
        "permit" an origin the policy author never considered, so the hop is refused
        on the host change rather than re-globbed on the path.
        """
        context = _signed(
            _policy(
                endpoint_rules=EndpointRules(
                    allowed_endpoints=["/*", "/**"], allowed_methods=["GET"]
                )
            )
        )

        with httpx.Client(
            base_url=live_api_base_url, timeout=10.0, follow_redirects=True
        ) as client:
            with pytest.raises(PermissionError, match="redirect crosses origin"):
                _wrapper(client).request(
                    context,
                    "GET",
                    "/redirect/302",
                    params={"to": "http://127.0.0.1:9/blocked"},
                )

    def test_a_redirect_loop_is_bounded_rather_than_followed_forever(
        self, live_api_base_url: str
    ) -> None:
        """/redirect-loop points at itself; the hop budget has to be ours, not the client's.

        Every client's own limit differs (httpx 20, .NET 50, fetch 20), so the
        wrapper states its own and denies on it. The target is permitted at every
        hop, which is what makes this the bound's test rather than the endpoint
        rules'.
        """
        context = _signed(
            _policy(
                endpoint_rules=EndpointRules(
                    allowed_endpoints=["/redirect-loop"], allowed_methods=["GET"]
                )
            )
        )

        with httpx.Client(
            base_url=live_api_base_url, timeout=10.0, follow_redirects=True
        ) as client:
            with pytest.raises(PermissionError, match="too many redirects"):
                _wrapper(client).request(context, "GET", "/redirect-loop")

    def test_the_hop_budget_permits_a_chain_up_to_the_limit(
        self, live_api_base_url: str
    ) -> None:
        """MAX_REDIRECTS hops succeed; the (n+1)th is the one that is denied.

        Pins the number rather than merely "some bound exists", so the three SDKs
        can be asserted identical.
        """
        assert MAX_REDIRECTS == 5

        context = _signed(
            _policy(
                endpoint_rules=EndpointRules(
                    allowed_endpoints=["/redirect/*", "/patients"], allowed_methods=["GET"]
                )
            )
        )

        # A chain of exactly MAX_REDIRECTS hops ending at a real endpoint: each
        # /redirect/302 points at the next one, the last at /patients.
        target = "/patients"
        for _ in range(MAX_REDIRECTS - 1):
            target = f"/redirect/302?to={quote(target, safe='')}"

        with httpx.Client(
            base_url=live_api_base_url, timeout=10.0, follow_redirects=True
        ) as client:
            body = _wrapper(client).request(
                context, "GET", f"/redirect/302?to={quote(target, safe='')}",
                collection_path="results",
            )

        assert body["results"], "a chain at the limit is followed to its end"

    def test_a_chain_one_hop_past_the_limit_is_denied(
        self, live_api_base_url: str
    ) -> None:
        context = _signed(
            _policy(
                endpoint_rules=EndpointRules(
                    allowed_endpoints=["/redirect/*", "/patients"], allowed_methods=["GET"]
                )
            )
        )

        target = "/patients"
        for _ in range(MAX_REDIRECTS):
            target = f"/redirect/302?to={quote(target, safe='')}"

        with httpx.Client(
            base_url=live_api_base_url, timeout=10.0, follow_redirects=True
        ) as client:
            with pytest.raises(PermissionError, match="too many redirects"):
                _wrapper(client).request(
                    context, "GET", f"/redirect/302?to={quote(target, safe='')}"
                )

    def test_a_redirect_is_not_followed_even_when_the_client_says_to(
        self, live_api_base_url: str
    ) -> None:
        """The caller's follow_redirects=True must not reach the transport.

        This is the specific inheritance the spec forbids relying on: the wrapper
        passes follow_redirects=False per request, which overrides the client, so
        the wrapper -- not the client -- decides every hop. Proven by observing
        that the denied hop was never fetched: the audit log is unreachable even
        though the client would have followed the 302 to it.
        """
        context = _signed(
            _policy(
                endpoint_rules=EndpointRules(
                    allowed_endpoints=["/redirect/*"],
                    hidden_endpoints=["/admin/*"],
                    allowed_methods=["GET"],
                )
            )
        )

        with httpx.Client(
            base_url=live_api_base_url, timeout=10.0, follow_redirects=True
        ) as client:
            with pytest.raises(PermissionError):
                _wrapper(client).request(context, "GET", "/redirect/302")

            # The client really does follow redirects: the same client, used
            # directly, lands on the audit log the wrapper refused.
            assert client.get("/redirect/302").url.path == "/admin/audit"


class TestObjectRulesOnTheHttpPathOverRealHttp:
    """Connector spec section 6, last bullet: object rules are honoured when *named*.

    No resource name is derived from a path -- the spec is explicit that an author
    "MUST express API restrictions as endpointRules", and inferring a resource from
    a route is unspecified guesswork. But an integrator who names the object gets
    the check, on every method rather than only on a write.
    """

    def test_a_hidden_object_named_by_the_caller_denies_a_get(
        self, live_client: httpx.Client
    ) -> None:
        context = _signed(
            _policy(
                endpoint_rules=ALLOW_ALL_GET,
                hidden_objects=["patients"],
            )
        )

        with pytest.raises(PermissionError, match="object is hidden"):
            _wrapper(live_client).request(
                context, "GET", "/patients", object_name="patients"
            )

    def test_an_object_outside_the_allow_list_denies_a_get(
        self, live_client: httpx.Client
    ) -> None:
        context = _signed(
            _policy(endpoint_rules=ALLOW_ALL_GET, allowed_objects=["encounters"])
        )

        with pytest.raises(PermissionError, match="object not in allowed set"):
            _wrapper(live_client).request(
                context, "GET", "/patients", object_name="patients"
            )

    def test_a_permitted_object_name_still_returns_an_enforced_body(
        self, live_client: httpx.Client
    ) -> None:
        context = _signed(
            _policy(
                endpoint_rules=ALLOW_ALL_GET,
                allowed_objects=["patients"],
                field_rules=FieldRules(hidden_fields=["ssn"]),
            )
        )

        body = _wrapper(live_client).request(
            context, "GET", "/patients", object_name="patients", collection_path="results"
        )

        assert body["results"]
        for record in body["results"]:
            assert "ssn" not in record

    def test_omitting_the_object_name_skips_the_check_rather_than_guessing(
        self, live_client: httpx.Client
    ) -> None:
        """No inference: the identical policy allows the call when nothing is named.

        A wrapper that derived "patients" from ``/patients`` would deny this, which
        is exactly the unspecified behaviour section 6 marks with a warning.
        """
        context = _signed(_policy(endpoint_rules=ALLOW_ALL_GET, hidden_objects=["patients"]))

        body = _wrapper(live_client).request(
            context, "GET", "/patients", collection_path="results"
        )

        assert body["results"]

    def test_a_redirect_hop_re_checks_the_named_object(
        self, live_api_base_url: str
    ) -> None:
        """The object check is part of a hop, so a redirect cannot shed it."""
        context = _signed(
            _policy(
                endpoint_rules=EndpointRules(
                    allowed_endpoints=["/redirect/*", "/patients"],
                    allowed_methods=["GET"],
                ),
                hidden_objects=["patients"],
            )
        )

        with httpx.Client(
            base_url=live_api_base_url, timeout=10.0, follow_redirects=True
        ) as client:
            with pytest.raises(PermissionError, match="object is hidden"):
                _wrapper(client).request(
                    context, "GET", "/redirect/302", params={"to": "/patients"},
                    object_name="patients",
                )


class TestRecordedFixturesOverRealHttp:
    """The openFDA recordings, served over a socket instead of a mock transport."""

    def test_drug_event_enforcement_matches_the_offline_path(
        self, live_client: httpx.Client
    ) -> None:
        context = _signed(
            _policy(
                endpoint_rules=EndpointRules(
                    allowed_endpoints=["/drug/*"],
                    hidden_endpoints=["/food/*"],
                    allowed_methods=["GET"],
                ),
                field_rules=FieldRules(
                    hidden_fields=["results.patient.patientsex"],
                    masked_fields=[
                        MaskingRule(field="results.safetyreportid", mask_type=MaskType.hash),
                    ],
                ),
                limits=PolicyLimits(max_results=2),
            )
        )

        body = _wrapper(live_client).request(
            context, "GET", "/drug/event.json", params={"limit": 3},
            collection_path="results",
        )

        assert len(body["results"]) == 2, "maxResults truncates the 3 the server sent"
        for record in body["results"]:
            assert "patientsex" not in record.get("patient", {})
            assert len(record["safetyreportid"]) == 16

    def test_hidden_food_endpoint_is_denied_though_the_server_serves_it(
        self, live_client: httpx.Client
    ) -> None:
        context = _signed(
            _policy(
                endpoint_rules=EndpointRules(
                    allowed_endpoints=["/drug/*", "/food/*"],
                    hidden_endpoints=["/food/*"],
                    allowed_methods=["GET"],
                )
            )
        )

        with pytest.raises(PermissionError, match="endpoint is hidden"):
            _wrapper(live_client).request(context, "GET", "/food/enforcement.json")
