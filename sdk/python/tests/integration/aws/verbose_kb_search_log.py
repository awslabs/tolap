"""Verifies the `opensearch` and `elasticsearch` kb filter renderers against the real engines.

TOLAP renders `kb` metadata filters for six providers. Only Bedrock was ever confirmed against a
live service; the other five carry ``KbFilterConfidence.from_grammar`` -- we wrote them from the
documented query DSL and no engine had ever accepted one. This closes two of the five, and prints
what happened so the result is reviewable rather than a bare PASSED.

Two questions a fixture we wrote ourselves cannot answer:

1. **Does the engine accept the document?** A filter that is byte-correct against our own
   expectation but malformed to OpenSearch is a runtime failure for every integrator.
2. **Does it actually exclude anything?** A syntactically valid filter that matches nothing --
   or everything -- parses fine and enforces nothing. This is the failure mode that matters,
   because it reads as success.

Both renderers currently emit an identical document. Whether that is *correct* is itself worth
testing: Elasticsearch 7.10 and OpenSearch 2.x diverged from a common ancestor, so a shared
implementation is an assumption until both engines confirm it. This script asserts they agree, so
if the DSLs drift the suite says so instead of one renderer silently breaking.

Requires domains from ``provision_search_domains.py``:

    python3 verbose_kb_search_log.py --state /tmp/search.env
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from typing import Any

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

from tolap_core.enforcement import filter_by_tags
from tolap_core.kb_filter import build_kb_filter
from tolap_core.kb_providers import KbProvider, render_kb_filter
from tolap_core.models import (
    EffectivePolicy,
    ObjectRules,
    PolicyPermissions,
    TagRules,
)

INDEX = "tolap-kb"
FAILURES: list[str] = []


def heading(text: str) -> None:
    print(f"\n{'=' * 78}\n{text}\n{'=' * 78}")


def control(name: str, rule: str) -> None:
    print(f"\n--- {name}\n    policy: {rule}")


def check(claim: str, condition: bool) -> None:
    print(f"    {'OK  ' if condition else 'FAIL'} {claim}")
    if not condition:
        FAILURES.append(claim)


def policy(tag_rules: TagRules) -> EffectivePolicy:
    return EffectivePolicy(
        version="1.0",
        user_id="kb-user",
        tenant_id="kb-tenant",
        source_connection_id="kb:research:trials",
        source_profiles=["kb-search-e2e"],
        permissions=PolicyPermissions(can_query=True),
        object_rules=ObjectRules(tag_rules=tag_rules),
    )


def rendered_for(tag_rules: TagRules, provider: KbProvider) -> Any:
    result = build_kb_filter(policy(tag_rules), metadata_keys=["classification"])
    return render_kb_filter(result, provider).filter


def search(endpoint: str, region: str, query_filter: Any | None) -> list[dict[str, Any]]:
    """Runs a search and returns the hit sources. Raises on a rejected query."""
    body: dict[str, Any] = {"size": 20}
    if query_filter is not None:
        body["query"] = query_filter
    url = f"https://{endpoint}/{INDEX}/_search"
    data = json.dumps(body).encode()

    signed = AWSRequest(method="POST", url=url, data=data, headers={"Content-Type": "application/json"})
    credentials = boto3.Session().get_credentials().get_frozen_credentials()
    SigV4Auth(credentials, "es", region).add_auth(signed)

    request = urllib.request.Request(url, data=data, method="POST")
    for header, value in signed.headers.items():
        request.add_header(header, value)

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            parsed = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise RuntimeError(f"HTTP {exc.code}: {detail[:400]}") from exc

    return [hit["_source"] for hit in parsed["hits"]["hits"]]


def transcribe(name: str, endpoint: str, region: str, provider: KbProvider) -> list[dict[str, Any]]:
    heading(f"{name}: the kb filter pushdown against the real engine")

    everything = search(endpoint, region, None)
    print(f"    unfiltered: {len(everything)} document(s)")
    for document in everything:
        print(f"        id={document['id']} classification={document['classification']!r}")
    classifications = {d["classification"] for d in everything}
    check(
        "the corpus holds BOTH classifications, so an exclusion test is not vacuous -- an index "
        "that never returns secret would make any filter look effective",
        {"public", "secret"} <= classifications,
    )

    control("deniedTags: [secret]", "tagRules.deniedTags=[secret]")
    tag_rules = TagRules(denied_tags=["secret"])
    query = rendered_for(tag_rules, provider)
    print(f"    filter sent: {json.dumps(query)}")
    hits = search(endpoint, region, query)
    print(f"    returned   : {len(hits)} document(s)")
    for document in hits:
        print(f"        id={document['id']} classification={document['classification']!r}")

    check("the engine ACCEPTED the generated filter document (no parse error)", True)
    check(
        "no secret document survived -- the real engine applied our filter",
        all(d["classification"] != "secret" for d in hits),
    )
    check(
        "public documents remain, so the filter excluded rather than matching nothing -- a "
        "query that returns zero hits parses fine and enforces nothing",
        len(hits) > 0,
    )
    check(
        "fewer hits than unfiltered, so the reduction is the engine's work",
        len(hits) < len(everything),
    )

    control("allowedTags: [public]", "tagRules.allowedTags=[public]")
    query = rendered_for(TagRules(allowed_tags=["public"]), provider)
    print(f"    filter sent: {json.dumps(query)}")
    allow_hits = search(endpoint, region, query)
    print(f"    returned   : {len(allow_hits)} document(s)")
    check("only public documents are returned",
          allow_hits and all(d["classification"] == "public" for d in allow_hits))

    control("both, ANDed", "allowedTags=[public], deniedTags=[secret]")
    query = rendered_for(TagRules(allowed_tags=["public"], denied_tags=["secret"]), provider)
    print(f"    filter sent: {json.dumps(query)}")
    both = search(endpoint, region, query)
    print(f"    returned   : {len(both)} document(s)")
    check("the combined filter is accepted and returns only public",
          both and all(d["classification"] == "public" for d in both))

    control("pushdown vs the normative post-pass", "deniedTags=[secret]")
    pushed = search(endpoint, region, rendered_for(tag_rules, provider))
    post_only = filter_by_tags(everything, policy(tag_rules))
    print(f"    pushdown : ids={sorted(d['id'] for d in pushed)}")
    print(f"    post-pass: ids={sorted(d['id'] for d in post_only)}")
    check(
        "the source filter and the shipped post-retrieval pass reach the SAME verdict -- this is "
        "the property that makes a pushdown safe rather than merely faster",
        sorted(d["id"] for d in pushed) == sorted(d["id"] for d in post_only),
    )

    control("NEGATIVE CONTROL: a malformed filter is refused", "hand-written invalid DSL")
    try:
        search(endpoint, region, {"bool": {"must_not": {"terms": "not-an-object"}}})
        check(
            "the engine rejects a malformed query -- without this, 'accepted' above would be "
            "meaningless because it could mean the engine validates nothing",
            False,
        )
    except RuntimeError as exc:
        print(f"    rejected: {str(exc)[:110]}")
        check(
            "the engine rejects a malformed query, so 'accepted' above is a real signal",
            True,
        )

    return pushed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True, help="state file from provision_search_domains.py")
    args = parser.parse_args()

    state: dict[str, str] = {}
    with open(args.state) as handle:
        for line in handle:
            if "=" in line:
                key, value = line.strip().split("=", 1)
                state[key] = value

    region = state.get("REGION", "us-east-1")
    engines = [
        ("OpenSearch 2.19", state["OPENSEARCH_ENDPOINT"], KbProvider.opensearch),
        ("Elasticsearch 7.10", state["ELASTICSEARCH_ENDPOINT"], KbProvider.elasticsearch),
    ]

    print("kb metadata-filter verification against real search engines")
    print(f"Region : {region}")
    for name, endpoint, provider in engines:
        print(f"  {name:20s} provider={provider.value:15s} {endpoint}")
    print(
        "\nBoth renderers are marked `fromGrammar`: written from the documented DSL, never\n"
        "confirmed by an engine. Every filter below was generated by the shipped renderer and\n"
        "sent to the real service. Claims are checked as they print; a FAIL exits non-zero."
    )

    results = {}
    for name, endpoint, provider in engines:
        results[provider.value] = transcribe(name, endpoint, region, provider)

    heading("cross-engine: the two renderers emit the same document -- do both engines agree?")
    os_query = json.dumps(rendered_for(TagRules(denied_tags=["secret"]), KbProvider.opensearch), sort_keys=True)
    es_query = json.dumps(rendered_for(TagRules(denied_tags=["secret"]), KbProvider.elasticsearch), sort_keys=True)
    print(f"    opensearch   : {os_query}")
    print(f"    elasticsearch: {es_query}")
    check(
        "the renderers emit identical documents, which is why they share an implementation",
        os_query == es_query,
    )
    check(
        "and both engines reached the same verdict on it -- if the DSLs had drifted, one of "
        "these would have failed above and the shared implementation would need splitting",
        sorted(d["id"] for d in results["opensearch"])
        == sorted(d["id"] for d in results["elasticsearch"]),
    )

    print(f"\n{'=' * 78}")
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} claim(s) did not hold")
        for failure in FAILURES:
            print(f"  - {failure}")
        return 1
    print("All claims held against both live engines.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
