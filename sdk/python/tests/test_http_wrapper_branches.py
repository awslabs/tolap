"""Branch coverage for the HTTP wrapper's body-shape handling.

The wrapper walks a `collection_path` into an arbitrary JSON body, so each step of
the pipeline has to decide what to do when the path does not lead to a list: a
missing segment, a segment whose value is a scalar, a leaf that is an object
rather than an array, or a body that is a bare list with no path at all. Every one
of those is a real API response shape, and the fail-open risk is specific: if a
step silently returns the body untouched, the policy did not run and nothing says
so.

These assert the *enforcement outcome* for each shape rather than merely
traversing it, and pin the two shapes where "return unchanged" is correct
(unrestricted policy) against the shapes where it would be a leak.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import httpx
import pytest

from tolap_core.enums import FilterOperator, MaskType
from tolap_core.context import build_security_context, sign_context
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
    TagRules,
)
from tolap_mcp.http_wrapper import (
    SecureHttpToolWrapper,
    _apply_masking_to_body,
    _filter_records_in_body,
    _limit_collection,
    _project_allowed_fields_in_body,
)
from tolap_mcp.options import SecureMcpServerOptions


KEY = "http-branch-key"

DELETED_FILTER = RowFilter(field="status", operator=FilterOperator.not_equals, value="deleted")

ROWS = [
    {"id": 1, "status": "active", "tags": ["public"]},
    {"id": 2, "status": "deleted", "tags": ["public"]},
]


def _policy(
    *,
    field_rules: FieldRules | None = None,
    row_filters: list[RowFilter] | None = None,
    tag_rules: TagRules | None = None,
    limits: PolicyLimits | None = None,
    object_rules: bool = True,
) -> EffectivePolicy:
    return EffectivePolicy(
        version="1.0",
        user_id="u",
        tenant_id="t",
        source_profiles=["http-branch"],
        permissions=PolicyPermissions(can_query=True, can_export=False, read_only=True),
        object_rules=ObjectRules(
            endpoint_rules=EndpointRules(allowed_endpoints=["/*"], allowed_methods=["GET"]),
            field_rules=field_rules,
            row_filters=row_filters,
            tag_rules=tag_rules,
        )
        if object_rules
        else None,
        limits=limits,
    )


def _ids(records: list[dict]) -> list[int]:
    return [record["id"] for record in records]


class TestFilterRecordsInBody:
    """`_filter_records_in_body` — pipeline steps 1 and 2 over a JSON tree."""

    def test_no_object_rules_returns_body_unchanged(self) -> None:
        body = {"results": list(ROWS)}

        assert _filter_records_in_body(body, "results", _policy(object_rules=False)) == body

    def test_no_filters_or_tag_rules_returns_body_unchanged(self) -> None:
        """An unrestricted policy is the one case where passing through is right."""
        body = {"results": list(ROWS)}

        assert _filter_records_in_body(body, "results", _policy()) == body

    def test_nested_collection_path_is_filtered(self) -> None:
        body = {"data": {"page": {"rows": list(ROWS)}}}

        result = _filter_records_in_body(
            body, "data.page.rows", _policy(row_filters=[DELETED_FILTER])
        )

        assert _ids(result["data"]["page"]["rows"]) == [1]

    def test_missing_path_segment_leaves_body_intact(self) -> None:
        """A body that does not contain the configured path has no records here.

        Returning it unchanged is correct: there is nothing to filter. The risk
        this pins is the opposite mistake — raising, which would turn a
        paging-shape change into an outage.
        """
        body = {"other": {"rows": list(ROWS)}}

        result = _filter_records_in_body(
            body, "data.page.rows", _policy(row_filters=[DELETED_FILTER])
        )

        assert result == body

    def test_scalar_mid_path_leaves_body_intact(self) -> None:
        body = {"data": "not-an-object"}

        result = _filter_records_in_body(
            body, "data.rows", _policy(row_filters=[DELETED_FILTER])
        )

        assert result == body

    def test_leaf_that_is_not_a_list_leaves_body_intact(self) -> None:
        body = {"results": {"id": 1, "status": "deleted"}}

        result = _filter_records_in_body(
            body, "results", _policy(row_filters=[DELETED_FILTER])
        )

        assert result == body

    def test_bare_list_body_is_filtered_without_a_collection_path(self) -> None:
        result = _filter_records_in_body(list(ROWS), None, _policy(row_filters=[DELETED_FILTER]))

        assert _ids(result) == [1]

    def test_single_record_body_is_filtered_and_a_dropped_record_becomes_none(self) -> None:
        """Spec section 4, "Single records": one record runs the identical pipeline.

        Returning the body untouched disclosed the excluded record outright -- a
        `status != deleted` policy handed back the deleted row. None, not `{}`: an
        empty record would imply the row existed but had no visible fields.
        """
        body = {"id": 2, "status": "deleted"}

        result = _filter_records_in_body(body, None, _policy(row_filters=[DELETED_FILTER]))

        assert result is None

    def test_single_record_body_that_passes_the_filters_survives(self) -> None:
        body = {"id": 1, "status": "active"}

        result = _filter_records_in_body(body, None, _policy(row_filters=[DELETED_FILTER]))

        assert result == body

    def test_list_of_scalars_is_left_for_the_shape_rules(self) -> None:
        """A list of non-records cannot be row/tag filtered, so it is passed on."""
        body = {"results": [1, 2, 3]}

        result = _filter_records_in_body(
            body, "results", _policy(row_filters=[DELETED_FILTER])
        )

        assert result == body

    def test_input_body_is_never_mutated(self) -> None:
        body = {"results": list(ROWS)}

        _filter_records_in_body(body, "results", _policy(row_filters=[DELETED_FILTER]))

        assert _ids(body["results"]) == [1, 2]

    def test_tag_rules_alone_filter_without_row_filters(self) -> None:
        body = {"results": [{"id": 1, "tags": ["public"]}, {"id": 2, "tags": ["secret"]}]}

        result = _filter_records_in_body(
            body, "results", _policy(tag_rules=TagRules(denied_tags=["secret"]))
        )

        assert _ids(result["results"]) == [1]


class TestNumericLimitsOverHttp:
    """Pipeline steps 3 and 4 (spec section 4) were absent from this wrapper.

    `apply_similarity_floor` and `apply_object_size_ceiling` were never called on
    the HTTP path, so both limits were parsed, validated, and merged
    most-restrictively -- and then did nothing to an API response. Section 4 binds
    all eight steps to "every wrapper, in every language".
    """

    SCORED = [
        {"id": 1, "score": 0.99, "size": 10},
        {"id": 2, "score": 0.20, "size": 999999999},
    ]

    def test_relevance_floor_drops_low_scoring_records(self) -> None:
        body = {"results": list(self.SCORED)}

        result = _filter_records_in_body(
            body, "results", _policy(limits=PolicyLimits(min_similarity_score=0.8))
        )

        assert _ids(result["results"]) == [1]

    def test_size_ceiling_drops_oversized_records(self) -> None:
        body = {"results": list(self.SCORED)}

        result = _filter_records_in_body(
            body, "results", _policy(limits=PolicyLimits(max_object_size_bytes=100))
        )

        assert _ids(result["results"]) == [1]

    def test_both_limits_together_drop_the_offending_record(self) -> None:
        """The exact case that returned BOTH records before this was wired up."""
        body = {"results": list(self.SCORED)}

        result = _filter_records_in_body(
            body,
            "results",
            _policy(limits=PolicyLimits(min_similarity_score=0.8, max_object_size_bytes=100)),
        )

        assert _ids(result["results"]) == [1]

    def test_limits_apply_without_any_object_rules(self) -> None:
        """The limits live under `limits`, not `objectRules`, so the early return
        on absent object rules must not skip them."""
        body = {"results": list(self.SCORED)}

        result = _filter_records_in_body(
            body,
            "results",
            _policy(object_rules=False, limits=PolicyLimits(min_similarity_score=0.8)),
        )

        assert _ids(result["results"]) == [1]

    def test_an_unscored_record_is_dropped_when_a_floor_is_set(self) -> None:
        """Fail closed: relevance that cannot be established is not satisfied."""
        body = {"results": [{"id": 1, "score": 0.99}, {"id": 2}]}

        result = _filter_records_in_body(
            body, "results", _policy(limits=PolicyLimits(min_similarity_score=0.8))
        )

        assert _ids(result["results"]) == [1]

    def test_both_limits_apply_to_a_bare_list_body(self) -> None:
        result = _filter_records_in_body(
            list(self.SCORED), None, _policy(limits=PolicyLimits(max_object_size_bytes=100))
        )

        assert _ids(result) == [1]

    def test_both_limits_apply_to_a_single_record_body(self) -> None:
        body = {"id": 2, "score": 0.20}

        result = _filter_records_in_body(
            body, None, _policy(limits=PolicyLimits(min_similarity_score=0.8))
        )

        assert result is None

    def test_max_results_alone_does_not_trigger_the_filter_pass(self) -> None:
        """maxResults is step 8, applied by `_limit_collection`, not here."""
        body = {"results": list(self.SCORED)}

        assert _filter_records_in_body(body, "results", _policy(limits=PolicyLimits(max_results=1))) == body


class TestSingleRecordBodyRunsTheFullPipeline:
    """Spec section 4, "Single records": a get-by-id body is one record.

    The wrapper returned a dict body untouched whenever `collection_path` was
    None, so row filters, tag filters and both numeric limits were skipped
    entirely -- a `status != deleted` policy handed back the deleted record.
    """

    def test_a_denied_tag_on_a_single_record_body_drops_it(self) -> None:
        body = {"id": 1, "tags": ["secret"]}

        result = _filter_records_in_body(body, None, _policy(tag_rules=TagRules(denied_tags=["secret"])))

        assert result is None

    def test_an_allowed_tag_on_a_single_record_body_keeps_it(self) -> None:
        body = {"id": 1, "tags": ["public"]}

        result = _filter_records_in_body(body, None, _policy(tag_rules=TagRules(allowed_tags=["public"])))

        assert result == body

    def test_the_single_record_path_is_reached_end_to_end_through_request(self) -> None:
        """The wrapper's own return value, not just the helper's."""
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"id": 2, "status": "deleted"})

        client = httpx.Client(base_url="https://api.test", transport=httpx.MockTransport(handler))
        wrapper = SecureHttpToolWrapper(SecureMcpServerOptions(signing_key=KEY), client)
        ctx = sign_context(
            build_security_context("u", "t", [_policy(row_filters=[DELETED_FILTER])], ttl=timedelta(hours=1)),
            KEY,
        )

        assert wrapper.request(ctx, "GET", "/patients/2") is None

    def test_a_scalar_body_is_still_left_alone(self) -> None:
        """Only dicts and lists are records; a scalar is left to the shape rules."""
        assert _filter_records_in_body("plain text", None, _policy(row_filters=[DELETED_FILTER])) == "plain text"


class TestProjectAllowedFieldsInBody:
    def test_absent_field_rules_returns_body_unchanged(self) -> None:
        body = {"results": list(ROWS)}

        assert _project_allowed_fields_in_body(body, "results", _policy()) == body

    def test_none_allow_list_returns_body_unchanged(self) -> None:
        """Spec section 3: None is unrestricted, distinct from []."""
        body = {"results": list(ROWS)}
        policy = _policy(field_rules=FieldRules(allowed_fields=None))

        assert _project_allowed_fields_in_body(body, "results", policy) == body

    def test_nested_collection_path_is_projected(self) -> None:
        body = {"data": {"rows": list(ROWS)}}
        policy = _policy(field_rules=FieldRules(allowed_fields=["id"]))

        result = _project_allowed_fields_in_body(body, "data.rows", policy)

        assert result["data"]["rows"] == [{"id": 1}, {"id": 2}]

    def test_missing_path_segment_leaves_body_intact(self) -> None:
        body = {"other": {"rows": list(ROWS)}}
        policy = _policy(field_rules=FieldRules(allowed_fields=["id"]))

        assert _project_allowed_fields_in_body(body, "data.rows", policy) == body

    def test_scalar_mid_path_leaves_body_intact(self) -> None:
        body = {"data": 7}
        policy = _policy(field_rules=FieldRules(allowed_fields=["id"]))

        assert _project_allowed_fields_in_body(body, "data.rows", policy) == body

    def test_leaf_that_is_not_a_list_leaves_body_intact(self) -> None:
        body = {"results": {"id": 1, "ssn": "x"}}
        policy = _policy(field_rules=FieldRules(allowed_fields=["id"]))

        assert _project_allowed_fields_in_body(body, "results", policy) == body

    def test_bare_list_body_is_projected_without_a_collection_path(self) -> None:
        policy = _policy(field_rules=FieldRules(allowed_fields=["id"]))

        result = _project_allowed_fields_in_body(list(ROWS), None, policy)

        assert result == [{"id": 1}, {"id": 2}]

    def test_dict_body_is_projected_as_a_single_record(self) -> None:
        policy = _policy(field_rules=FieldRules(allowed_fields=["id"]))

        result = _project_allowed_fields_in_body({"id": 1, "ssn": "x"}, None, policy)

        assert result == {"id": 1}

    def test_scalar_body_without_a_collection_path_is_returned_unchanged(self) -> None:
        policy = _policy(field_rules=FieldRules(allowed_fields=["id"]))

        assert _project_allowed_fields_in_body("a-scalar", None, policy) == "a-scalar"


class TestLimitCollection:
    def test_absent_limits_returns_body_unchanged(self) -> None:
        body = {"results": list(ROWS)}

        assert _limit_collection(body, "results", _policy()) == body

    def test_none_max_results_returns_body_unchanged(self) -> None:
        body = {"results": list(ROWS)}
        policy = _policy(limits=PolicyLimits(max_query_time_seconds=5))

        assert _limit_collection(body, "results", policy) == body

    def test_nested_collection_path_is_truncated(self) -> None:
        body = {"data": {"rows": list(ROWS)}}

        result = _limit_collection(body, "data.rows", _policy(limits=PolicyLimits(max_results=1)))

        assert _ids(result["data"]["rows"]) == [1]

    def test_missing_path_segment_leaves_body_intact(self) -> None:
        body = {"other": {"rows": list(ROWS)}}

        assert _limit_collection(body, "data.rows", _policy(limits=PolicyLimits(max_results=1))) == body

    def test_scalar_mid_path_leaves_body_intact(self) -> None:
        body = {"data": None}

        assert _limit_collection(body, "data.rows", _policy(limits=PolicyLimits(max_results=1))) == body

    def test_leaf_that_is_not_a_list_leaves_body_intact(self) -> None:
        body = {"results": {"id": 1}}

        assert _limit_collection(body, "results", _policy(limits=PolicyLimits(max_results=1))) == body

    def test_bare_list_body_is_truncated_without_a_collection_path(self) -> None:
        result = _limit_collection(list(ROWS), None, _policy(limits=PolicyLimits(max_results=1)))

        assert _ids(result) == [1]

    def test_dict_body_without_a_collection_path_is_returned_unchanged(self) -> None:
        body = {"id": 1}

        assert _limit_collection(body, None, _policy(limits=PolicyLimits(max_results=1))) == body

    def test_zero_max_results_denies_every_row(self) -> None:
        """A limit of 0 is a real limit, not an absent one."""
        body = {"results": list(ROWS)}

        result = _limit_collection(body, "results", _policy(limits=PolicyLimits(max_results=0)))

        assert result["results"] == []


class TestApplyMaskingToBody:
    def test_absent_masked_fields_returns_an_equal_body(self) -> None:
        body = {"results": list(ROWS)}

        assert _apply_masking_to_body(body, _policy()) == body

    def test_masking_recurses_into_nested_objects(self) -> None:
        """The core walk must reach a nested key from a bare rule (spec section 4)."""
        body = {"results": [{"demographics": {"ssn": "111-22-3333"}}]}
        policy = _policy(
            field_rules=FieldRules(masked_fields=[MaskingRule(field="ssn", mask_type=MaskType.redact)])
        )

        result = _apply_masking_to_body(body, policy)

        assert result["results"][0]["demographics"]["ssn"] == "[REDACTED]"

    def test_dotted_rule_still_reaches_a_nested_leaf(self) -> None:
        body = {"results": [{"patient": {"ssn": "111-22-3333"}}]}
        policy = _policy(
            field_rules=FieldRules(
                masked_fields=[MaskingRule(field="results.patient.ssn", mask_type=MaskType.redact)]
            )
        )

        result = _apply_masking_to_body(body, policy)

        assert result["results"][0]["patient"]["ssn"] == "[REDACTED]"

    def test_input_body_is_never_mutated(self) -> None:
        body = {"results": [{"ssn": "111-22-3333"}]}
        policy = _policy(
            field_rules=FieldRules(masked_fields=[MaskingRule(field="ssn", mask_type=MaskType.redact)])
        )

        _apply_masking_to_body(body, policy)

        assert body["results"][0]["ssn"] == "111-22-3333"


# -- wrapper-level branches ---------------------------------------------------


def _client(body: Any, status: int = 200) -> httpx.Client:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json=body)

    return httpx.Client(
        base_url="https://api.example.gov", transport=httpx.MockTransport(handler)
    )


def _signed(policy: EffectivePolicy, ttl: timedelta = timedelta(hours=1)) -> SecurityContext:
    return sign_context(build_security_context("u", "t", [policy], ttl=ttl), KEY)


class TestValidateSecurityContextBranches:
    """Each combination of the two enforcement switches."""

    def test_both_enforced_accepts_a_valid_context(self) -> None:
        with _client({"results": []}) as client:
            wrapper = SecureHttpToolWrapper(SecureMcpServerOptions(signing_key=KEY), client)

            result = wrapper.validate_security_context(_signed(_policy()))

        assert result.allowed is True
        assert result.reason is None

    def test_signature_checked_before_expiry(self) -> None:
        """Spec section 2: a tampered context reports a signature failure.

        Reporting "expired" here would tell an attacker their forgery was
        otherwise well-formed.
        """
        context = _signed(_policy(), ttl=timedelta(hours=-1))
        context.signature = "forged"

        with _client({"results": []}) as client:
            wrapper = SecureHttpToolWrapper(SecureMcpServerOptions(signing_key=KEY), client)

            result = wrapper.validate_security_context(context)

        assert result.allowed is False
        assert result.reason == "invalid signature"

    def test_expiry_not_enforced_accepts_an_expired_context(self) -> None:
        context = _signed(_policy(), ttl=timedelta(hours=-1))

        with _client({"results": []}) as client:
            wrapper = SecureHttpToolWrapper(
                SecureMcpServerOptions(signing_key=KEY, enforce_expiry=False), client
            )

            result = wrapper.validate_security_context(context)

        assert result.allowed is True

    def test_signatures_not_enforced_accepts_an_unsigned_context(self) -> None:
        context = build_security_context("u", "t", [_policy()], ttl=timedelta(hours=1))

        with _client({"results": []}) as client:
            wrapper = SecureHttpToolWrapper(
                SecureMcpServerOptions(signing_key=KEY, enforce_signatures=False), client
            )

            result = wrapper.validate_security_context(context)

        assert result.allowed is True

    def test_neither_enforced_still_reports_allowed(self) -> None:
        context = build_security_context("u", "t", [_policy()], ttl=timedelta(hours=-1))

        with _client({"results": []}) as client:
            wrapper = SecureHttpToolWrapper(
                SecureMcpServerOptions(
                    signing_key=KEY, enforce_signatures=False, enforce_expiry=False
                ),
                client,
            )

            result = wrapper.validate_security_context(context)

        assert result.allowed is True


class TestRequestWithoutCollectionPath:
    """A body that is itself the collection, with no `collection_path` given."""

    def test_full_pipeline_runs_over_a_bare_list_body(self) -> None:
        policy = _policy(
            field_rules=FieldRules(
                hidden_fields=["tags"],
                masked_fields=[MaskingRule(field="status", mask_type=MaskType.redact)],
            ),
            row_filters=[DELETED_FILTER],
            limits=PolicyLimits(max_results=5),
        )
        context = _signed(policy)

        with _client(list(ROWS)) as client:
            wrapper = SecureHttpToolWrapper(SecureMcpServerOptions(signing_key=KEY), client)

            body = wrapper.request(context, "GET", "/rows")

        assert body == [{"id": 1, "status": "[REDACTED]"}]

    def test_single_record_body_is_enforced(self) -> None:
        policy = _policy(field_rules=FieldRules(hidden_fields=["ssn"]))
        context = _signed(policy)

        with _client({"id": 1, "ssn": "111-22-3333"}) as client:
            wrapper = SecureHttpToolWrapper(SecureMcpServerOptions(signing_key=KEY), client)

            body = wrapper.request(context, "GET", "/rows/1")

        assert body == {"id": 1}
