"""End-to-end `kb` enforcement against a real Bedrock Knowledge Base (connector-spec §7).

This is the test the shape-acceptance one (test_bedrock_kb_filter.py) stops short of. That
one proves Bedrock accepts our filter grammar; this proves the filter actually *enforces* --
a chunk the policy denies is never returned by the live Retrieve API, and one it permits is.

It requires a provisioned KB, which is slow and costly to stand up, so it is gated on
TOLAP_TEST_KB_ID (set from provision_bedrock_kb.py's output) on top of TOLAP_TEST_AWS=1. It
skips otherwise rather than provisioning inline: a multi-minute ingestion job does not belong
in a fixture that runs on every invocation.

The KB was seeded with four documents, two tagged classification=public and two
classification=secret. The pushdown is the SDK's `build_kb_filter` -> `render_kb_filter`
output for the Bedrock provider; the assertions run against what Bedrock actually returned.

The pushdown is defence in depth, never the sole control: connector-spec §7 requires the
post-retrieval pass to run regardless. So the tests check both that the provider filter
excludes at the source AND that the shipped filter_by_tags would reach the same verdict --
if the two ever disagreed, the pushdown would be masking a bug rather than optimising.
"""

from __future__ import annotations

import os

import pytest

from tolap_core.enforcement import filter_by_tags
from tolap_core.kb_filter import build_kb_filter
from tolap_core.kb_providers import KbProvider, render_kb_filter
from tolap_core.models import EffectivePolicy, ObjectRules, PolicyPermissions, TagRules

_KB_ID = os.environ.get("TOLAP_TEST_KB_ID")

pytestmark = pytest.mark.skipif(
    not _KB_ID,
    reason="needs a provisioned KB; set TOLAP_TEST_KB_ID (see provision_bedrock_kb.py)",
)


def _policy(tag_rules: TagRules) -> EffectivePolicy:
    return EffectivePolicy(
        version="1.0",
        user_id="kb-user",
        tenant_id="kb-tenant",
        source_connection_id="kb:research:trials",
        source_profiles=["kb-e2e"],
        permissions=PolicyPermissions(can_query=True),
        object_rules=ObjectRules(tag_rules=tag_rules),
    )


@pytest.fixture(scope="session")
def kb_runtime(aws_region: str):
    boto3 = pytest.importorskip("boto3")
    return boto3.client("bedrock-agent-runtime", region_name=aws_region)


def _retrieve(client, query: str, filter_obj=None) -> list[dict]:
    """Retrieve against the real KB, optionally with our provider filter pushed down.

    Returns each chunk's text plus its classification metadata, so a test can assert on
    what actually came back rather than on counts alone.
    """
    cfg = {"vectorSearchConfiguration": {"numberOfResults": 10}}
    if filter_obj is not None:
        cfg["vectorSearchConfiguration"]["filter"] = filter_obj

    resp = client.retrieve(
        knowledgeBaseId=_KB_ID,
        retrievalQuery={"text": query},
        retrievalConfiguration=cfg,
    )
    out = []
    for r in resp.get("retrievalResults", []):
        md = r.get("metadata") or {}
        out.append({
            "text": r["content"]["text"],
            "classification": md.get("classification"),
        })
    return out


# A query broad enough to match every document, so exclusions are the policy's doing rather
# than a query that simply failed to retrieve the secret chunks.
_BROAD_QUERY = "company financial and product information"


class TestPushdownEnforcesAtTheSource:
    def test_unfiltered_retrieval_returns_both_classifications(self, kb_runtime):
        # Baseline: without a filter the KB returns public AND secret chunks. If this does
        # not hold, every filtered assertion below could pass for the wrong reason -- a KB
        # that never returns secret chunks would make the pushdown look effective while
        # doing nothing.
        results = _retrieve(kb_runtime, _BROAD_QUERY)
        classifications = {r["classification"] for r in results}

        assert "public" in classifications, "baseline retrieved no public chunks"
        assert "secret" in classifications, (
            "baseline retrieved no secret chunks; the exclusion tests would be vacuous"
        )

    def test_denylist_pushdown_excludes_secret_at_the_source(self, kb_runtime):
        # deniedTags: ["secret"] -> our Bedrock notIn filter. The live Retrieve must return
        # no secret chunk at all. This is the claim a fixture cannot make: the real vector
        # store applied our generated filter.
        policy = _policy(TagRules(denied_tags=["secret"]))
        rendered = render_kb_filter(
            build_kb_filter(policy, metadata_keys=["classification"]), KbProvider.bedrock
        )
        assert rendered.filter is not None

        results = _retrieve(kb_runtime, _BROAD_QUERY, rendered.filter)

        assert results, "the filter excluded everything; expected public chunks to remain"
        assert all(r["classification"] != "secret" for r in results), (
            "a secret chunk survived the pushed-down denylist filter"
        )
        # Defence-in-depth cross-check: the shipped post-pass agrees with the provider.
        post = filter_by_tags(
            [{"classification": r["classification"]} for r in results], policy
        )
        assert len(post) == len(results), "post-pass would have dropped a chunk the KB returned"

    def test_allowlist_pushdown_returns_only_public(self, kb_runtime):
        # allowedTags: ["public"] -> our Bedrock `in` filter. Only public chunks come back.
        policy = _policy(TagRules(allowed_tags=["public"]))
        rendered = render_kb_filter(
            build_kb_filter(policy, metadata_keys=["classification"]), KbProvider.bedrock
        )

        results = _retrieve(kb_runtime, _BROAD_QUERY, rendered.filter)

        assert results, "allowlist filter returned nothing; expected public chunks"
        assert all(r["classification"] == "public" for r in results)

    def test_pushdown_and_post_pass_reach_the_same_verdict(self, kb_runtime):
        # The property that makes a pushdown safe rather than merely faster: filtering at
        # the source must never disagree with the normative post-retrieval pass. Retrieve
        # everything, then compare "what the provider filter left" against "what
        # filter_by_tags keeps from the full set". They must match.
        policy = _policy(TagRules(denied_tags=["secret"]))
        rendered = render_kb_filter(
            build_kb_filter(policy, metadata_keys=["classification"]), KbProvider.bedrock
        )

        pushed = _retrieve(kb_runtime, _BROAD_QUERY, rendered.filter)
        everything = _retrieve(kb_runtime, _BROAD_QUERY)
        post_only = filter_by_tags(
            [{"classification": r["classification"], "text": r["text"]} for r in everything],
            policy,
        )

        assert {r["text"] for r in pushed} == {r["text"] for r in post_only}, (
            "the source filter and the post-retrieval pass disagreed; the pushdown is "
            "hiding a divergence rather than optimising the same decision"
        )
