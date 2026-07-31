"""Bedrock accepts the `kb` metadata filters we generate (connector-spec §7).

The provider-side filter builder emits a Bedrock `retrievalConfiguration` filter from a
policy's `tagRules`. Our own tests assert its *shape* against a fixture -- but a fixture we
also wrote cannot tell us whether **Bedrock** considers that shape valid. A filter that is
byte-correct against our expectation but malformed to the service is a runtime failure for
every integrator, and nothing in the suite would catch it.

This closes that gap without provisioning a Knowledge Base. Bedrock's `Retrieve` validates
the request body -- including the filter grammar -- *before* it looks up the knowledge base,
so the two failure modes are distinguishable against a KB id that does not exist:

    our generated filter   -> ResourceNotFoundException   (shape accepted, KB lookup reached)
    a malformed filter     -> parameter/validation error  (shape rejected first)

Both arms are asserted below, because a test that only checks "not a validation error" would
pass if Bedrock stopped validating filters altogether. The negative control is what gives
the positive one meaning.

Why not a real KB: one needs a vector store (OpenSearch Serverless), an IAM role, an S3 data
source, and a multi-minute ingestion job -- expensive to stand up, slow to iterate, and it
leaves costly infrastructure behind. None of that is needed to answer the one question a
fixture cannot: does the service accept our syntax. End-to-end retrieval semantics (a denied
chunk is never returned) are already proven at the unit level against the shipped
`filterByTags`, and the pushdown is defence-in-depth over that, never a replacement.
"""

from __future__ import annotations

import json

import pytest

# These import from tolap_core's kb filter builder. If the Python port of the builder is
# absent the tests error rather than silently pass, which is the honest outcome -- the
# point is to exercise real generated filters.
from tolap_core.kb_filter import build_kb_filter
from tolap_core.kb_providers import KbProvider, render_kb_filter
from tolap_core.models import EffectivePolicy, ObjectRules, PolicyPermissions, TagRules

# A KB id that does not exist. Bedrock validates the request body before resolving it, so a
# well-formed filter reaches this lookup and a malformed one is rejected earlier.
_ABSENT_KB_ID = "AAAAAAAAAA"


def _policy(tag_rules: TagRules) -> EffectivePolicy:
    return EffectivePolicy(
        version="1.0",
        user_id="kb-user",
        tenant_id="kb-tenant",
        source_connection_id="kb:research:trials",
        source_profiles=["kb-filter-test"],
        permissions=PolicyPermissions(can_query=True),
        object_rules=ObjectRules(tag_rules=tag_rules),
    )


@pytest.fixture(scope="session")
def bedrock_agent_runtime(aws_region: str):
    boto3 = pytest.importorskip("boto3")
    return boto3.client("bedrock-agent-runtime", region_name=aws_region)


def _retrieve_with_filter(client, filter_obj: dict):
    """Call Retrieve against a nonexistent KB with the given filter. Returns the botocore
    error code, so a test can tell 'shape accepted' from 'shape rejected'."""
    from botocore.exceptions import ClientError, ParamValidationError

    try:
        client.retrieve(
            knowledgeBaseId=_ABSENT_KB_ID,
            retrievalQuery={"text": "test"},
            retrievalConfiguration={"vectorSearchConfiguration": {"filter": filter_obj}},
        )
        return "OK"  # pragma: no cover - the KB does not exist, so this never returns 200
    except ParamValidationError:
        # botocore rejected the shape before it ever left the client.
        return "PARAM_VALIDATION"
    except ClientError as exc:
        return exc.response["Error"]["Code"]


# The tagRules shapes our builder can produce, spanning every rendered form: a bare notIn, a
# bare in, and the andAll combination of both.
_POLICIES = {
    "denylist-only": TagRules(denied_tags=["secret", "restricted"]),
    "allowlist-only": TagRules(allowed_tags=["public"]),
    "both-anded": TagRules(denied_tags=["secret"], allowed_tags=["public"]),
}


class TestBedrockAcceptsGeneratedFilters:
    @pytest.mark.parametrize("name", list(_POLICIES))
    def test_generated_filter_shape_is_accepted(self, bedrock_agent_runtime, name):
        # The filter we would actually send. If Bedrock rejects its grammar this fails,
        # which is the whole point: our fixture cannot vouch for the service's opinion.
        result = build_kb_filter(
            _policy(_POLICIES[name]), metadata_keys=["classification"]
        )
        rendered = render_kb_filter(result, KbProvider.bedrock)
        assert rendered.filter is not None, f"{name}: nothing rendered to send"

        code = _retrieve_with_filter(bedrock_agent_runtime, rendered.filter)

        # ResourceNotFound means the filter parsed and the request reached KB lookup.
        # A validation/param error would mean our syntax is wrong.
        assert code == "ResourceNotFoundException", (
            f"{name}: Bedrock rejected the generated filter shape "
            f"(got {code}); sent {json.dumps(rendered.filter)}"
        )

    def test_negative_control_a_malformed_filter_is_rejected(self, bedrock_agent_runtime):
        # Without this, the tests above would pass even if Bedrock had stopped validating
        # filters -- 'not a validation error' is only meaningful if malformed input still
        # produces one. A bogus operator must fail before KB lookup.
        code = _retrieve_with_filter(
            bedrock_agent_runtime,
            {"bogusOperator": {"key": "classification", "value": ["x"]}},
        )

        assert code != "ResourceNotFoundException", (
            "a malformed filter reached KB lookup; Bedrock is not validating filter shape, "
            "so the acceptance tests above prove nothing"
        )
