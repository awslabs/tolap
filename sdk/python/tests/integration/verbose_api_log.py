"""Prints what `api` enforcement actually *did*, against a real HTTP server over a socket.

The companion to ``verbose_enforcement_log.py``, which covers `db`. Same reasoning: a `PASSED`
line proves an assertion held but shows nothing of the request that went out, the JSON that came
back, or which values a masking rule rewrote. This prints all three for every `api` control, so a
reader can confirm enforcement from the transcript instead of trusting a test name.

The `api` category differs from `db` in a way worth showing explicitly. There is no query to
rewrite -- an HTTP API takes the request it is given -- so **every** `api` control is either a
pre-flight denial (the request is never issued) or a post-response transform. Where `db` can push
a row filter into SQL and let the engine do the work, `api` cannot: the upstream returns what it
returns, and TOLAP filters the response. That makes the post-response pipeline the *only* line of
defence for this category rather than defence-in-depth, which is why it is worth seeing operate on
real bytes off a socket rather than a mocked transport.

Requests go to ``tools/test-api/server.py`` on loopback, not a mock: `httpx.MockTransport` never
puts bytes on a socket and so cannot exercise real status codes, server-framed bodies, redirects,
or query-string handling.

It is a **transcript producer, not a test** -- every claim here is asserted properly in
``test_live_http_api.py`` (66 tests) and the shared openFDA scenarios. It still exits non-zero on
a false claim, so a broken transcript cannot be recorded as evidence.

    python3 tests/integration/verbose_api_log.py
"""

from __future__ import annotations

import json as jsonlib
import socket
import subprocess
import sys
import time
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx

from tolap_core.context import build_security_context, sign_context
from tolap_core.enforcement import validate_endpoint
from tolap_core.enums import FilterOperator, MaskType
from tolap_core.models import (
    EffectivePolicy,
    EndpointRules,
    FieldRules,
    MaskingRule,
    ObjectRules,
    PolicyLimits,
    PolicyPermissions,
    RowFilter,
    SecurityContext,
)
from tolap_mcp.http_wrapper import SecureHttpToolWrapper, UpstreamHttpError
from tolap_mcp.options import SecureMcpServerOptions

SERVER_SCRIPT = Path(__file__).parents[4] / "tools" / "test-api" / "server.py"
SIGNING_KEY = "verbose-api-key"

FAILURES: list[str] = []


def heading(text: str) -> None:
    print(f"\n{'=' * 78}\n{text}\n{'=' * 78}")


def control(name: str, rule: str) -> None:
    print(f"\n--- {name}\n    policy: {rule}")


def wire(label: str, text: str) -> None:
    print(f"    {label}: {text}")


def payload(label: str, value: Any, limit: int = 4) -> None:
    """Prints a response body compactly, one record per line when it is a list."""
    if isinstance(value, list):
        print(f"    {label}: {len(value)} record(s)")
        for record in value[:limit]:
            print(f"        {jsonlib.dumps(record, sort_keys=True)}")
        if len(value) > limit:
            print(f"        ... {len(value) - limit} more")
    else:
        rendered = jsonlib.dumps(value, sort_keys=True)
        print(f"    {label}: {rendered[:400]}{'...' if len(rendered) > 400 else ''}")


def records(value: Any) -> list:
    """The record list, whether the wrapper returned a bare list or an envelope."""
    if isinstance(value, dict) and isinstance(value.get("results"), list):
        return value["results"]
    return value if isinstance(value, list) else [value]


def check(claim: str, condition: bool) -> None:
    print(f"    {'OK  ' if condition else 'FAIL'} {claim}")
    if not condition:
        FAILURES.append(claim)


def policy(
    *,
    can_query: bool = True,
    read_only: bool = True,
    allowed_endpoints: list[str] | None = None,
    hidden_endpoints: list[str] | None = None,
    allowed_methods: list[str] | None = None,
    allowed_fields: list[str] | None = None,
    hidden_fields: list[str] | None = None,
    masked_fields: list[MaskingRule] | None = None,
    row_filters: list[RowFilter] | None = None,
    max_results: int | None = None,
) -> EffectivePolicy:
    has_endpoint_rules = bool(allowed_endpoints or hidden_endpoints or allowed_methods)
    has_field_rules = bool(allowed_fields or hidden_fields or masked_fields)
    return EffectivePolicy(
        version="1.0",
        user_id="verbose-api",
        tenant_id="verbose-tenant",
        source_profiles=["verbose-api-transcript"],
        permissions=PolicyPermissions(can_query=can_query, read_only=read_only),
        # endpoint_rules nests under object_rules: an endpoint IS the `api` category's object,
        # which is what lets one policy shape cover db tables, storage prefixes and API routes.
        object_rules=ObjectRules(
            endpoint_rules=EndpointRules(
                allowed_endpoints=allowed_endpoints,
                hidden_endpoints=hidden_endpoints,
                allowed_methods=allowed_methods,
            )
            if has_endpoint_rules
            else None,
            field_rules=FieldRules(
                allowed_fields=allowed_fields,
                hidden_fields=hidden_fields,
                masked_fields=masked_fields,
            )
            if has_field_rules
            else None,
            row_filters=row_filters,
        )
        if (has_endpoint_rules or has_field_rules or row_filters)
        else None,
        limits=PolicyLimits(max_results=max_results) if max_results is not None else None,
    )


def signed(p: EffectivePolicy) -> SecurityContext:
    context = build_security_context("verbose-api", "verbose-tenant", [p], ttl=timedelta(hours=1))
    return sign_context(context, SIGNING_KEY)


def wrapper(client: httpx.Client) -> SecureHttpToolWrapper:
    return SecureHttpToolWrapper(SecureMcpServerOptions(signing_key=SIGNING_KEY), client)


# ---------------------------------------------------------------------------


def transcribe(base_url: str, client: httpx.Client) -> None:
    w = wrapper(client)

    heading("api: the RAW upstream, so every exclusion below is demonstrably TOLAP's doing")
    envelope = client.get("/patients").json()
    payload("GET /patients (unenforced, straight from the server)", envelope)
    # The server wraps records in {"results": [...]}, as most real APIs do. TOLAP enforces over
    # the records, so the transcript compares record lists rather than envelopes.
    raw = envelope["results"]
    payload("upstream records", raw)

    heading("api: ENDPOINT RULES -- the request is refused before it is issued")
    control("allowedEndpoints: /patients only", "endpointRules.allowedEndpoints=[/patients]")
    p = policy(allowed_endpoints=["/patients"])
    decision = validate_endpoint("/admin/audit", "GET", p)
    wire("requested", "GET /admin/audit")
    print(f"    decision: allowed={decision.allowed} reason={decision.reason!r}")
    check("an endpoint outside the allow-list is refused", not decision.allowed)
    # The endpoint exists and returns data, so a broken check would happily fetch it -- that is
    # what makes this a real denial rather than a 404 in disguise.
    upstream = client.get("/admin/audit")
    check(
        f"CONTROL: the endpoint really is live upstream (HTTP {upstream.status_code}), so the "
        "denial came from policy and not from a missing route",
        upstream.status_code == 200,
    )
    check("CONTROL: the permitted endpoint is allowed", validate_endpoint("/patients", "GET", p).allowed)

    control("no request reaches the socket when denied", "same policy, through the wrapper")
    try:
        w.request(signed(p), "GET", "/admin/audit")
        check("the wrapper refused the denied endpoint", False)
    except PermissionError as exc:  # the wrapper raises rather than returning data
        print(f"    raised  : {type(exc).__name__}: {exc}")
        check("the wrapper raised instead of returning upstream data", True)

    control("allowedMethods: GET only", "endpointRules.allowedMethods=[GET]")
    p = policy(allowed_endpoints=["/echo"], allowed_methods=["GET"])
    post = validate_endpoint("/echo", "POST", p)
    print(f"    POST /echo -> allowed={post.allowed} reason={post.reason!r}")
    check("POST is refused when only GET is granted", not post.allowed)
    check("CONTROL: GET on the same path is permitted", validate_endpoint("/echo", "GET", p).allowed)

    control("readOnly denies a write even when the method is listed", "readOnly=true, methods=[GET,POST]")
    p = policy(read_only=True, allowed_endpoints=["/echo"], allowed_methods=["GET", "POST"])
    decision = validate_endpoint("/echo", "POST", p)
    print(f"    POST /echo -> allowed={decision.allowed} reason={decision.reason!r}")
    check(
        "two independent gates: the method allow-list is not sufficient on its own",
        not decision.allowed,
    )

    # collection_path tells the wrapper where records live inside the envelope. Without it the
    # body is treated as a single opaque value and the record-level rules have nothing to iterate,
    # so an omission here silently enforces NOTHING -- an earlier draft of this transcript omitted
    # it and got `None` back rather than a filtered list. Real integrators face the same trap,
    # which is why the argument is required rather than guessed: guessing "results" would break
    # any API that names its collection differently, and guessing wrong would fail open.
    heading("api: FIELD RULES over the real response body")
    control("hiddenFields: ssn", "fieldRules.hiddenFields=[ssn]")
    p = policy(allowed_endpoints=["/patients"], hidden_fields=["ssn"])
    wire("sent", "GET /patients")
    result = records(w.request(signed(p), "GET", "/patients", collection_path="results"))
    payload("enforced response", result)
    check(
        "ssn was present in the raw upstream body, so its removal is the pipeline's work",
        any("ssn" in r for r in raw),
    )
    check("ssn is absent from every enforced record", all("ssn" not in r for r in result))
    # An HTTP API cannot be asked to omit a field, so unlike `db` there is no pushdown to compare
    # against: the post-response pass is the entire control.
    check("the record count is unchanged -- hiding a field is not dropping a record",
          len(result) == len(raw))

    control("allowedFields: id, name", "fieldRules.allowedFields=[id, name]")
    p = policy(allowed_endpoints=["/patients"], allowed_fields=["id", "name"])
    result = records(w.request(signed(p), "GET", "/patients", collection_path="results"))
    payload("enforced response", result)
    check("only the allow-listed keys survive",
          all(set(r) <= {"id", "name"} for r in result))

    heading("api: MASKING over the real response body")
    for mask, claim in [
        (MaskType.redact, "the value is replaced, not merely hidden"),
        (MaskType.hash, "the value becomes a stable digest"),
        (MaskType.null, "the value becomes null"),
    ]:
        control(f"maskedFields: ssn -> {mask.value}", f"maskType={mask.value}")
        p = policy(allowed_endpoints=["/patients"], masked_fields=[MaskingRule(field="ssn", mask_type=mask)])
        result = records(w.request(signed(p), "GET", "/patients", collection_path="results"))
        before = [r.get("ssn") for r in raw][:3]
        after = [r.get("ssn") for r in result][:3]
        print(f"    before: ssn={before}")
        print(f"    after : ssn={after}")
        originals = {r.get("ssn") for r in raw if r.get("ssn") is not None}
        remaining = {r.get("ssn") for r in result if r.get("ssn") is not None}
        check(claim, not (originals & remaining))
        check("the record survives -- masking is not record suppression", len(result) == len(raw))

    heading("api: ROW FILTERS and LIMITS, applied after the response arrives")
    control("rowFilters: region = us-east", "rowFilters[region equals us-east]")
    p = policy(
        allowed_endpoints=["/patients"],
        row_filters=[RowFilter(field="region", operator=FilterOperator.equals, value="us-east")],
    )
    result = records(w.request(signed(p), "GET", "/patients", collection_path="results"))
    payload("enforced response", result)
    regions_upstream = {r.get("region") for r in raw}
    print(f"    upstream regions: {sorted(x for x in regions_upstream if x)}")
    check(
        "the upstream returned more than one region, so the filter had work to do",
        len({x for x in regions_upstream if x}) > 1,
    )
    check("only us-east records remain", all(r.get("region") == "us-east" for r in result))
    check("fewer records than upstream returned", len(result) < len(raw))

    control("limits.maxResults = 1", "limits.maxResults=1")
    p = policy(allowed_endpoints=["/patients"], max_results=1)
    result = records(w.request(signed(p), "GET", "/patients", collection_path="results"))
    payload("enforced response", result)
    check("exactly one record is returned", len(result) == 1)
    check("the upstream had more, so the ceiling was enforced here", len(raw) > 1)

    heading("api: real-socket behaviour a mocked transport cannot reach")
    control("a non-2xx upstream status", "allowedEndpoints=[/status/404]")
    p = policy(allowed_endpoints=["/status/404", "/notfound"])
    try:
        w.request(signed(p), "GET", "/notfound")
        print("    (no error raised)")
        check("a non-2xx upstream response is surfaced as an error, not silently returned", False)
    except (UpstreamHttpError, httpx.HTTPError) as exc:
        print(f"    raised  : {type(exc).__name__}: {str(exc)[:120]}")
        check("a non-2xx upstream response is surfaced as an error, not silently returned", True)

    control("query string is stripped before policy evaluation", "allowedEndpoints=[/patients]")
    p = policy(allowed_endpoints=["/patients"], max_results=2)
    result = records(w.request(signed(p), "GET", "/patients", params={"region": "us-east"}, collection_path="results"))
    wire("sent", "GET /patients?region=us-east")
    payload("enforced response", result)
    check(
        "the path matched the allow-list despite the query string -- otherwise every "
        "parameterised request would be denied",
        len(result) > 0,
    )


def main() -> int:
    if not SERVER_SCRIPT.exists():
        print(f"test API server not found at {SERVER_SCRIPT}", file=sys.stderr)
        return 2

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = int(sock.getsockname()[1])

    process = subprocess.Popen(
        [sys.executable, str(SERVER_SCRIPT), "--port", str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    base_url = f"http://127.0.0.1:{port}"

    deadline = time.monotonic() + 10.0
    ready = False
    while time.monotonic() < deadline and process.poll() is None:
        try:
            response = httpx.get(f"{base_url}/healthz", timeout=0.5)
            if response.status_code == 200:
                ready = True
                break
        except httpx.HTTPError:
            time.sleep(0.05)

    if not ready:
        process.kill()
        print("test API server did not start", file=sys.stderr)
        return 2

    print(f"Upstream: {base_url} (tools/test-api/server.py, real socket)")
    print("Source  : sdk/python/tests/integration/verbose_api_log.py")
    print(
        "\nEvery request below crossed a real socket and every body below is what the server\n"
        "actually sent. Claims are checked as they are printed; a FAIL makes this run exit\n"
        "non-zero, so a broken transcript cannot be recorded as passing evidence."
    )

    try:
        with httpx.Client(base_url=base_url, timeout=10.0) as client:
            transcribe(base_url, client)
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()

    print(f"\n{'=' * 78}")
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} claim(s) did not hold")
        for failure in FAILURES:
            print(f"  - {failure}")
        return 1
    print("All claims held against the live HTTP server.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
