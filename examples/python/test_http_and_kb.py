"""Asserts the HTTP and KB example enforces, not merely that it prints.

The expected lines are byte-identical to ``examples/typescript/http-and-kb.test.ts`` and
``examples/dotnet/HttpAndKbExampleTests.cs``. The reason strings are the SDK's own, so a
divergence between the SDKs surfaces as a different line.

Run: pytest examples/python/test_http_and_kb.py
"""

from __future__ import annotations

import pytest

pytest.importorskip("httpx")

import http_and_kb_example as ex  # noqa: E402
from tolap_core import KbFilterOp, build_kb_filter  # noqa: E402

EXPECTED_LINES = [
    # sourcePatterns: the same identity, a different policy per source, deny-all for neither.
    "  api:clinical:patients     patients-api-reader   canQuery=true",
    "  kb:clinical:guidelines    clinical-kb-reader    canQuery=true",
    "  api:research:patients     (none)                canQuery=false",
    # endpointRules, checked before the request is sent.
    "  GET /patients           ALLOW",
    "  GET /patients/1/notes   DENY    endpoint is hidden",
    "  GET /billing/invoices   DENY    endpoint not in allowed set",
    "  DELETE /patients/1      DENY    method not allowed",
    "  POST /patients          DENY    insert not permitted",
    "The fake API was reached 1 time. The four refused requests never",
    # The row, field and limit rules, still applied to the JSON response.
    "    id=1  name=Alice Nguyen  region=us-east  dob=[REDACTED]",
    "    id=2  name=Bruno Sato  region=us-east  dob=[REDACTED]",
    # The unmatched source is deny-all.
    "  GET /patients           DENY    query not permitted",
    # tagRules, pushed down to the provider.
    "    tags notIn [restricted]",
    "    tags in [clinical, public]",
    '    {"andAll":[{"notIn":{"key":"tags","value":["restricted"]}},{"in":{"key":"tags","value":["clinical","public"]}}]}',
    "Unpushed rules: none",
    "The provider returned 4 of 6: doc-1, doc-3, doc-5, doc-6",
    # And re-applied, with minSimilarityScore, in the post pass.
    "  doc-1  KEEP",
    "  doc-3  DROP  score 0.42 is below minSimilarityScore 0.5",
    "  doc-5  DROP  classification restricted, a key the provider never saw",
    "  doc-6  KEEP",
]


@pytest.mark.parametrize(
    ("method", "path", "reason"),
    [
        ("GET", "/patients/1/notes", "endpoint is hidden"),
        ("GET", "/billing/invoices", "endpoint not in allowed set"),
        ("DELETE", "/patients/1", "method not allowed"),
        ("POST", "/patients", "insert not permitted"),
    ],
)
def test_a_refused_request_never_reaches_the_api(method: str, path: str, reason: str) -> None:
    api = ex.FakeApi()

    call = ex.call_api(api, ex.signed_context(ex.API_SOURCE), method, path)

    assert not call.allowed
    assert call.reason == reason
    assert api.hits == []


def test_a_permitted_request_still_meets_the_row_field_and_limit_rules() -> None:
    api = ex.FakeApi()

    call = ex.call_api(api, ex.signed_context(ex.API_SOURCE), "GET", "/patients")

    assert call.allowed
    assert api.hits == ["GET /patients"]
    assert call.rows is not None
    assert [row["name"] for row in call.rows] == ["Alice Nguyen", "Bruno Sato"]
    assert all("ssn" not in row and row["dob"] == "[REDACTED]" for row in call.rows)


def test_an_unmatched_source_resolves_to_deny_all() -> None:
    policy = ex.resolve_for(ex.UNMATCHED_SOURCE)
    assert policy.source_profiles == []
    assert not policy.permissions.can_query

    api = ex.FakeApi()
    call = ex.call_api(api, ex.signed_context(ex.UNMATCHED_SOURCE), "GET", "/patients")

    assert not call.allowed
    assert call.reason == "query not permitted"
    assert api.hits == []


def test_the_kb_filter_is_built_from_the_resolved_tag_rules() -> None:
    kb_filter = build_kb_filter(ex.resolve_for(ex.KB_SOURCE), metadata_keys=["tags"])

    assert [(c.key, c.op, ",".join(c.values)) for c in kb_filter.clauses] == [
        ("tags", KbFilterOp.not_in, "restricted"),
        ("tags", KbFilterOp.in_, "clinical,public"),
    ]
    assert [r["id"] for r in ex.fake_kb_retrieve(kb_filter.clauses)] == [
        "doc-1",
        "doc-3",
        "doc-5",
        "doc-6",
    ]


def test_the_example_runs_clean_and_prints_the_lines_the_other_two_languages_print(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``main`` raises ``SystemExit`` if a refused request reached the API, if ssn leaks, if the
    unmatched source is served, or if the post pass drops other chunks, so this covers those."""
    ex.main()

    out = capsys.readouterr().out
    lines = out.splitlines()
    for expected in EXPECTED_LINES:
        assert expected in lines, f"missing line: {expected!r}"
    assert "111-22-3333" not in out
