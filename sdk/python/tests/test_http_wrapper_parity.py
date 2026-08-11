"""Cross-SDK parity for the HTTP wrapper's §6 category requirements.

One case corpus -- status code x policy, and redirect shape x policy -> outcome --
asserted with byte-identical expected outcomes in all three SDKs. The counterparts
are:

- TypeScript: ``packages/mcp/tests/http-wrapper-parity.test.ts``
- .NET: ``tests/Tolap.Mcp.Tests/HttpWrapperParityTests.cs``

The three tables must stay identical case-for-case. This file is the reference
ordering; the other two follow it row for row so a diff of the three is readable.

**The denial reasons are asserted, not just the outcome kind.** They are the
contract integrators log and branch on, and each names a different policy or client
edit that would unblock the caller: ``endpoint is hidden`` is fixed by editing
``hiddenEndpoints``, ``redirect crosses origin`` cannot be fixed by a policy edit at
all, and ``too many redirects`` points at the chain rather than the rules.

A corpus of this shape is what catches divergence: three per-SDK suites each assert
the behaviour that SDK happens to implement, which is exactly how the single-record
body ended up with three different answers -- Python ``None``, TypeScript ``[]``,
.NET the record unfiltered -- while every suite stayed green.

Covers connector-spec.md §6 "Category requirements":

- error bodies are enforced (status x policy table)
- redirects are re-validated (redirect shape x policy table)
- ``allowedObjects``/``hiddenObjects`` are honoured when the caller names the object
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import httpx
import pytest

from tolap_core.context import build_security_context, sign_context
from tolap_core.enums import FilterOperator, MaskType
from tolap_core.models import (
    EffectivePolicy,
    EndpointRules,
    FieldRules,
    MaskingRule,
    ObjectRules,
    PolicyPermissions,
    RowFilter,
    SecurityContext,
)
from tolap_mcp.http_wrapper import (
    MAX_REDIRECTS,
    SecureHttpToolWrapper,
    UpstreamHttpError,
)
from tolap_mcp.options import SecureMcpServerOptions


KEY = "http-parity-key"
BASE = "https://parity.test"


def _policy(object_rules: ObjectRules) -> EffectivePolicy:
    return EffectivePolicy(
        version="1.0",
        user_id="parity-user",
        tenant_id="parity-tenant",
        source_profiles=["http-wrapper-parity"],
        permissions=PolicyPermissions(can_query=True, read_only=True),
        object_rules=object_rules,
    )


# -- The shared parity policies. Identical field-for-field in all three SDKs. --

#: Every path reachable by GET, no field rules: the control case, so a denial in any
#: other row is attributable to the rule that row adds.
OPEN = _policy(ObjectRules(endpoint_rules=EndpointRules(
    allowed_endpoints=["/*", "/**"], allowed_methods=["GET"])))

#: `error` hidden. The 4xx/5xx body is exactly {"error": {...}}, so an enforced error
#: body is {} and an unenforced one still carries the payload.
HIDE_ERROR = _policy(ObjectRules(
    endpoint_rules=EndpointRules(allowed_endpoints=["/*", "/**"], allowed_methods=["GET"]),
    field_rules=FieldRules(hidden_fields=["error"]),
))

#: `message` redacted, to prove masking reaches an error body's nested leaf rather
#: than only its top level.
MASK_MESSAGE = _policy(ObjectRules(
    endpoint_rules=EndpointRules(allowed_endpoints=["/*", "/**"], allowed_methods=["GET"]),
    field_rules=FieldRules(
        masked_fields=[MaskingRule(field="message", mask_type=MaskType.redact)]
    ),
))

#: A filter on a field the error body does not carry. Fails closed (spec §7), so the
#: single-record error body is dropped to the language's null value.
FILTER_DROPS_ERROR = _policy(ObjectRules(
    endpoint_rules=EndpointRules(allowed_endpoints=["/*", "/**"], allowed_methods=["GET"]),
    row_filters=[RowFilter(field="account", operator=FilterOperator.not_equals, value="other")],
))

#: Redirect sources permitted, the redirect *target* hidden. The row that proves a
#: 302 does not bypass `hiddenEndpoints`.
REDIRECT_TARGET_HIDDEN = _policy(ObjectRules(endpoint_rules=EndpointRules(
    allowed_endpoints=["/redirect/*"],
    hidden_endpoints=["/admin/*"],
    allowed_methods=["GET"],
)))

#: Redirect sources permitted and nothing else, so the target falls outside the
#: allow-list rather than into the hidden list -- a different reason, same refusal.
REDIRECT_ONLY = _policy(ObjectRules(endpoint_rules=EndpointRules(
    allowed_endpoints=["/redirect/*"], allowed_methods=["GET"])))

#: Both the redirect source and its target permitted: re-validating is not refusing.
REDIRECT_AND_TARGET = _policy(ObjectRules(endpoint_rules=EndpointRules(
    allowed_endpoints=["/redirect/*", "/patients"], allowed_methods=["GET"])))

#: The object named by the caller is hidden, on a policy whose endpoint rules allow
#: everything -- so only the object rule can produce the denial.
OBJECT_HIDDEN = _policy(ObjectRules(
    endpoint_rules=EndpointRules(allowed_endpoints=["/*", "/**"], allowed_methods=["GET"]),
    hidden_objects=["patients"],
))

#: An allow-list the named object is absent from.
OBJECT_NOT_ALLOWED = _policy(ObjectRules(
    endpoint_rules=EndpointRules(allowed_endpoints=["/*", "/**"], allowed_methods=["GET"]),
    allowed_objects=["encounters"],
))


# ---------------------------------------------------------------------------
# Table 1: status code x policy -> enforced error body (spec §6)
# ---------------------------------------------------------------------------

# Each row is (case id, policy, status, expected enforced body).
#
# A status of 200 is in the table on purpose: the success and error paths must run
# the *same* pipeline, and a table that only listed error codes could not show that.
# The 4xx/5xx rows assert `UpstreamHttpError.body`; the 200 row asserts the returned
# value. Both come from the identical corpus so a divergence between the two paths in
# any SDK is a row that disagrees with its own 200 twin.
ERROR_BODY_CORPUS: list[tuple[str, EffectivePolicy, int, Any]] = [
    # -- No field rules: the payload survives, whatever the status. --
    ("open-200", OPEN, 200, {"error": {"code": 200, "message": "synthetic"}}),
    ("open-400", OPEN, 400, {"error": {"code": 400, "message": "synthetic"}}),
    ("open-401", OPEN, 401, {"error": {"code": 401, "message": "synthetic"}}),
    ("open-403", OPEN, 403, {"error": {"code": 403, "message": "synthetic"}}),
    ("open-404", OPEN, 404, {"error": {"code": 404, "message": "synthetic"}}),
    ("open-422", OPEN, 422, {"error": {"code": 422, "message": "synthetic"}}),
    ("open-429", OPEN, 429, {"error": {"code": 429, "message": "synthetic"}}),
    ("open-500", OPEN, 500, {"error": {"code": 500, "message": "synthetic"}}),
    ("open-503", OPEN, 503, {"error": {"code": 503, "message": "synthetic"}}),

    # -- hiddenFields empties the body identically on every status. This is the
    # -- row that failed before the fix: raise_for_status ran first, so the 4xx/5xx
    # -- payload never reached the pipeline while the 200 twin was enforced.
    ("hide-error-200", HIDE_ERROR, 200, {}),
    ("hide-error-400", HIDE_ERROR, 400, {}),
    ("hide-error-401", HIDE_ERROR, 401, {}),
    ("hide-error-403", HIDE_ERROR, 403, {}),
    ("hide-error-404", HIDE_ERROR, 404, {}),
    ("hide-error-422", HIDE_ERROR, 422, {}),
    ("hide-error-429", HIDE_ERROR, 429, {}),
    ("hide-error-500", HIDE_ERROR, 500, {}),
    ("hide-error-503", HIDE_ERROR, 503, {}),

    # -- Masking reaches a nested leaf of an error body, not only a success one's.
    ("mask-200", MASK_MESSAGE, 200, {"error": {"code": 200, "message": "[REDACTED]"}}),
    ("mask-400", MASK_MESSAGE, 400, {"error": {"code": 400, "message": "[REDACTED]"}}),
    ("mask-500", MASK_MESSAGE, 500, {"error": {"code": 500, "message": "[REDACTED]"}}),

    # -- The record-dropping steps reach an error body too. The body is a single
    # -- record, and a filter it cannot satisfy drops it to null (spec §4).
    ("filter-drops-200", FILTER_DROPS_ERROR, 200, None),
    ("filter-drops-400", FILTER_DROPS_ERROR, 400, None),
    ("filter-drops-500", FILTER_DROPS_ERROR, 500, None),
]


# ---------------------------------------------------------------------------
# Table 2: redirect shape x policy -> outcome (spec §6)
# ---------------------------------------------------------------------------

# Each row is (case id, policy, Location header, hops, expected denial substring or
# None for "followed and enforced").
#
# `hops` is how many 302s the transport serves before the final 200, so the
# hop-budget rows are expressible in the same table as the single-hop ones.
REDIRECT_CORPUS: list[tuple[str, EffectivePolicy, str, int, str | None]] = [
    # -- A permitted source redirecting to a denied target: the whole point of §6. --
    ("hidden-target-relative", REDIRECT_TARGET_HIDDEN, "/admin/audit", 1,
     "redirect target rejected: endpoint is hidden"),
    ("not-allowed-target", REDIRECT_ONLY, "/admin/audit", 1,
     "redirect target rejected: endpoint not in allowed set"),
    # A relative Location that walks up: resolved against the request URL, then
    # re-globbed on the resulting path, so "../admin/audit" is denied like the
    # absolute spelling rather than matched literally.
    ("hidden-target-dot-dot", REDIRECT_TARGET_HIDDEN, "../admin/audit", 1,
     "redirect target rejected: endpoint is hidden"),
    # An absolute Location on the SAME origin is re-globbed normally: it is the host
    # change, not the absoluteness, that takes a hop out of the policy's frame.
    ("hidden-target-absolute-same-origin", REDIRECT_TARGET_HIDDEN,
     f"{BASE}/admin/audit", 1, "redirect target rejected: endpoint is hidden"),

    # -- A permitted target is followed: re-validating is not refusing. --
    ("permitted-target", REDIRECT_AND_TARGET, "/patients", 1, None),
    ("permitted-target-absolute", REDIRECT_AND_TARGET, f"{BASE}/patients", 1, None),
    # The Location's own query string is not policy-relevant (the path is), and it
    # must not be corrupted by re-appending the original request's params.
    ("permitted-target-with-query", REDIRECT_AND_TARGET, "/patients?region=us-east", 1, None),

    # -- Cross-origin: refused on the host change, never re-globbed on the path. --
    # OPEN allows "/*" and "/**", so a wrapper that globbed the path would ALLOW
    # every one of these. That is what makes them the fail-open rows.
    ("cross-host", OPEN, "https://attacker.test/patients", 1,
     "redirect crosses origin"),
    ("cross-port", OPEN, "https://parity.test:8443/patients", 1,
     "redirect crosses origin"),
    ("cross-scheme-downgrade", OPEN, "http://parity.test/patients", 1,
     "redirect crosses origin"),

    # -- The hop budget is the wrapper's, not the transport's. --
    ("chain-at-limit", REDIRECT_AND_TARGET, "/patients", MAX_REDIRECTS, None),
    ("chain-past-limit", REDIRECT_AND_TARGET, "/patients", MAX_REDIRECTS + 1,
     f"too many redirects (limit {MAX_REDIRECTS})"),

    # -- The object check is part of a hop, so a redirect cannot shed it. --
    ("object-hidden-on-hop", OBJECT_HIDDEN, "/patients", 1, "object is hidden"),
]


# ---------------------------------------------------------------------------
# Table 3: object name x policy -> outcome (spec §6, last bullet)
# ---------------------------------------------------------------------------

# Each row is (case id, policy, object name or None, expected denial or None).
#
# The `None` object-name rows are the ones that pin "no inference": the identical
# policy that denies a named object must ALLOW the same path when nothing is named,
# because deriving a resource from a route is the unspecified behaviour §6 warns
# against.
OBJECT_NAME_CORPUS: list[tuple[str, EffectivePolicy, str | None, str | None]] = [
    ("hidden-object-named", OBJECT_HIDDEN, "patients", "object is hidden"),
    ("hidden-object-not-named", OBJECT_HIDDEN, None, None),
    ("object-not-in-allow-list", OBJECT_NOT_ALLOWED, "patients", "object not in allowed set"),
    ("object-in-allow-list", OBJECT_NOT_ALLOWED, "encounters", None),
    ("allow-list-not-named", OBJECT_NOT_ALLOWED, None, None),
    ("no-object-rules-named", OPEN, "patients", None),
    # Object patterns are globs, matched case-insensitively, exactly as on the
    # database path (spec §3.2) -- the HTTP path must not invent its own matcher.
    ("hidden-object-case-insensitive", OBJECT_HIDDEN, "PATIENTS", "object is hidden"),
]


#: Table 4: request targets that are not host-relative paths.
#:
#: Every row is checked against :data:`OPEN` -- ``allowedEndpoints: ["/*", "/**"]``,
#: the most permissive policy in the corpus -- because the point is that the globs
#: cannot save you here. A glob decides *which paths* a policy reaches; by the time
#: one runs, the authority is already chosen. ``//evil.example/x`` matches ``/*`` on
#: its leading slash and then resolves as an authority, so the request left for a
#: host the policy author never named, carrying whatever auth headers the integrator
#: configured on the client. Confirmed reachable in .NET before this check existed.
#:
#: The transport must never be invoked: a denial that still made the request would
#: have already leaked the credentials, whatever it returned to the caller.
PATH_SHAPE_CORPUS: list[tuple[str, str, str]] = [
    ("protocol-relative", "//evil.example/x", "request path is protocol-relative"),
    ("protocol-relative-backslash", "/\\evil.example/x",
     "request path is protocol-relative"),
    ("absolute-https", "https://evil.example/x", "request path is not host-relative"),
    ("absolute-http", "http://evil.example/x", "request path is not host-relative"),
    ("leading-backslash", "\\\\evil.example\\x", "request path is not host-relative"),
    ("schemeless-relative", "drug/event.json", "request path is not host-relative"),
    ("dot-dot-escapes-prefix", "/drug/../../internal/admin",
     "request path contains a '..' segment"),
    ("dot-dot-before-query", "/drug/..?x=1", "request path contains a '..' segment"),
    ("empty", "", "request path is empty"),
]


def _signed(policy: EffectivePolicy) -> SecurityContext:
    context = build_security_context(
        "parity-user", "parity-tenant", [policy], ttl=timedelta(hours=1)
    )
    return sign_context(context, KEY)


def _wrapper(handler) -> tuple[SecureHttpToolWrapper, httpx.Client]:
    # follow_redirects=True on purpose: the wrapper must override the caller's
    # setting per request, so a corpus built on a *following* client is the one that
    # proves it.
    client = httpx.Client(
        base_url=BASE, transport=httpx.MockTransport(handler), follow_redirects=True
    )
    return (
        SecureHttpToolWrapper(SecureMcpServerOptions(signing_key=KEY), client),
        client,
    )


class TestErrorBodyParity:
    """Table 1: an error body carries the same enforcement as a success body."""

    @pytest.mark.parametrize(
        ("case_id", "policy", "status", "expected"),
        ERROR_BODY_CORPUS,
        ids=[row[0] for row in ERROR_BODY_CORPUS],
    )
    def test_case_matches_the_shared_expectation(
        self, case_id: str, policy: EffectivePolicy, status: int, expected: Any
    ) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                status, json={"error": {"code": status, "message": "synthetic"}}
            )

        wrapper, client = _wrapper(handler)
        try:
            if 200 <= status < 300:
                assert wrapper.request(_signed(policy), "GET", "/status") == expected
                return

            with pytest.raises(UpstreamHttpError) as exc_info:
                wrapper.request(_signed(policy), "GET", "/status")

            assert exc_info.value.status_code == status
            assert exc_info.value.body == expected
        finally:
            client.close()


class TestRedirectParity:
    """Table 2: every hop is re-validated, bounded, and same-origin."""

    @pytest.mark.parametrize(
        ("case_id", "policy", "location", "hops", "denial"),
        REDIRECT_CORPUS,
        ids=[row[0] for row in REDIRECT_CORPUS],
    )
    def test_case_matches_the_shared_expectation(
        self,
        case_id: str,
        policy: EffectivePolicy,
        location: str,
        hops: int,
        denial: str | None,
    ) -> None:
        served = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            # Serve `hops` redirects, then the real collection. The intermediate
            # hops point back at a permitted /redirect/N so only the FINAL hop
            # exercises the row's Location.
            served["count"] += 1
            if served["count"] <= hops - 1:
                return httpx.Response(
                    302, headers={"Location": f"/redirect/{served['count']}"}
                )
            if served["count"] == hops:
                return httpx.Response(302, headers={"Location": location})
            return httpx.Response(200, json={"results": [{"id": 1, "region": "us-east"}]})

        wrapper, client = _wrapper(handler)
        try:
            if denial is None:
                body = wrapper.request(
                    _signed(policy), "GET", "/redirect/0", collection_path="results"
                )
                assert body["results"] == [{"id": 1, "region": "us-east"}]
                return

            with pytest.raises(PermissionError) as exc_info:
                wrapper.request(
                    _signed(policy),
                    "GET",
                    "/redirect/0",
                    object_name="patients" if policy is OBJECT_HIDDEN else None,
                )
            assert denial in str(exc_info.value)
        finally:
            client.close()


class TestObjectNameParity:
    """Table 3: object rules are honoured when named, and never inferred."""

    @pytest.mark.parametrize(
        ("case_id", "policy", "object_name", "denial"),
        OBJECT_NAME_CORPUS,
        ids=[row[0] for row in OBJECT_NAME_CORPUS],
    )
    def test_case_matches_the_shared_expectation(
        self,
        case_id: str,
        policy: EffectivePolicy,
        object_name: str | None,
        denial: str | None,
    ) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"results": [{"id": 1}]})

        wrapper, client = _wrapper(handler)
        try:
            if denial is None:
                body = wrapper.request(
                    _signed(policy),
                    "GET",
                    "/patients",
                    object_name=object_name,
                    collection_path="results",
                )
                assert body["results"] == [{"id": 1}]
                return

            with pytest.raises(PermissionError, match=denial):
                wrapper.request(
                    _signed(policy), "GET", "/patients", object_name=object_name
                )
        finally:
            client.close()


class TestPathShapeParity:
    """Table 4: a request target that is not a host-relative path is refused."""

    @pytest.mark.parametrize(
        ("case_id", "path", "denial"),
        PATH_SHAPE_CORPUS,
        ids=[row[0] for row in PATH_SHAPE_CORPUS],
    )
    def test_case_matches_the_shared_expectation(
        self, case_id: str, path: str, denial: str
    ) -> None:
        served: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            served.append(str(request.url))
            return httpx.Response(200, json={"results": []})

        wrapper, client = _wrapper(handler)
        try:
            with pytest.raises(PermissionError) as exc_info:
                wrapper.request(_signed(OPEN), "GET", path)
            assert denial in str(exc_info.value)
            # The credentials are on the client, so a request that went out has
            # already leaked them regardless of what the wrapper returned.
            assert served == [], f"transport reached for {path!r}: {served}"
        finally:
            client.close()

    def test_an_ordinary_rooted_path_is_still_allowed(self) -> None:
        """The control: the check must not reject the paths policies are written for."""
        served: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            served.append(str(request.url))
            return httpx.Response(200, json={"results": [{"id": 1}]})

        wrapper, client = _wrapper(handler)
        try:
            body = wrapper.request(
                _signed(OPEN), "GET", "/drug/event.json?limit=3", collection_path="results"
            )
            assert body["results"] == [{"id": 1}]
            assert served == ["https://parity.test/drug/event.json?limit=3"]
        finally:
            client.close()


class TestTheCorpusItself:
    """A corpus that silently shrank would make every SDK agree by asserting nothing."""

    def test_the_tables_carry_the_expected_number_of_cases(self) -> None:
        assert len(ERROR_BODY_CORPUS) == 24
        assert len(REDIRECT_CORPUS) == 13
        assert len(OBJECT_NAME_CORPUS) == 7
        assert len(PATH_SHAPE_CORPUS) == 9

    def test_case_ids_are_unique_within_each_table(self) -> None:
        for corpus in (
            ERROR_BODY_CORPUS,
            REDIRECT_CORPUS,
            OBJECT_NAME_CORPUS,
            PATH_SHAPE_CORPUS,
        ):
            ids = [row[0] for row in corpus]
            assert len(ids) == len(set(ids))

    def test_the_hop_budget_is_the_agreed_number(self) -> None:
        """All three SDKs state 5, independently of any client's own default."""
        assert MAX_REDIRECTS == 5
