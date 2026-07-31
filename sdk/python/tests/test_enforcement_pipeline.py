"""Regression tests for the post-execution enforcement pipeline.

One test (or class) per confirmed defect in the canonical enforcement spec.
Every test here fails against the pre-hardening implementation.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from tolap_core.context import build_security_context, sign_context
from tolap_core.enforcement import (
    UnenforceableResultError,
    apply_field_masking,
    apply_result_pipeline,
    apply_row_filters,
    project_allowed_fields,
    strip_hidden_fields,
)
from tolap_core.enums import FilterOperator, MaskType
from tolap_core.models import (
    EffectivePolicy,
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
from tolap_mcp.options import SecureMcpServerOptions
from tolap_mcp.wrapper import SecureMcpToolWrapper


SIGNING_KEY = "pipeline-test-key"


def _policy(
    *,
    hidden_fields: list[str] | None = None,
    allowed_fields: list[str] | None = None,
    masked_fields: list[MaskingRule] | None = None,
    row_filters: list[RowFilter] | None = None,
    tag_rules: TagRules | None = None,
    max_results: int | None = None,
) -> EffectivePolicy:
    field_rules = None
    if hidden_fields is not None or allowed_fields is not None or masked_fields is not None:
        field_rules = FieldRules(
            allowed_fields=allowed_fields,
            hidden_fields=hidden_fields,
            masked_fields=masked_fields,
        )

    object_rules = None
    if field_rules or row_filters is not None or tag_rules is not None:
        object_rules = ObjectRules(
            field_rules=field_rules,
            row_filters=row_filters,
            tag_rules=tag_rules,
        )

    return EffectivePolicy(
        version="1.0",
        user_id="user-001",
        tenant_id="tenant-001",
        source_profiles=["pipeline-test"],
        permissions=PolicyPermissions(can_query=True, read_only=True),
        object_rules=object_rules,
        limits=PolicyLimits(max_results=max_results) if max_results is not None else None,
    )


def _signed(policy: EffectivePolicy, key: str = SIGNING_KEY) -> SecurityContext:
    context = build_security_context("user-001", "tenant-001", [policy], ttl=timedelta(hours=1))
    return sign_context(context, key)


@pytest.fixture
def wrapper() -> SecureMcpToolWrapper:
    return SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=SIGNING_KEY))


class TestHiddenFieldsStrippedFromResults:
    """Defect 1: hiddenFields were never removed from results by post_execute."""

    def test_hidden_field_is_removed_from_result(self, wrapper: SecureMcpToolWrapper) -> None:
        """The proven leak: policy hides ssn, tool returns it, post_execute kept it."""
        context = _signed(_policy(hidden_fields=["ssn"]))

        result = wrapper.post_execute(context, [{"ssn": "123-45-6789", "name": "bob"}])

        assert "ssn" not in result[0], "hidden field leaked through post_execute"
        assert result[0] == {"name": "bob"}

    def test_hidden_field_removed_from_undeclared_column(self, wrapper: SecureMcpToolWrapper) -> None:
        """A SELECT * style tool returns columns the caller never declared."""
        context = _signed(_policy(hidden_fields=["patients.ssn"]))

        result = wrapper.post_execute(context, [{"id": 1, "name": "bob", "ssn": "123-45-6789"}])

        assert result == [{"id": 1, "name": "bob"}]

    def test_hidden_wins_over_masked_for_same_field(self, wrapper: SecureMcpToolWrapper) -> None:
        """A field that is both hidden and masked is removed, not returned masked."""
        context = _signed(
            _policy(
                hidden_fields=["ssn"],
                masked_fields=[MaskingRule(field="ssn", mask_type=MaskType.hash)],
            )
        )

        result = wrapper.post_execute(context, [{"ssn": "123-45-6789"}])

        assert result == [{}]

    def test_hidden_field_removed_from_nested_record(self) -> None:
        context = _signed(_policy(hidden_fields=["ssn"]))

        result = strip_hidden_fields(
            {"patient": {"ssn": "123-45-6789", "name": "bob"}},
            context.effective_policy,
        )

        assert result == {"patient": {"name": "bob"}}

    def test_strip_hidden_fields_does_not_mutate_input(self) -> None:
        policy = _policy(hidden_fields=["ssn"])
        original = [{"ssn": "123-45-6789", "name": "bob"}]

        strip_hidden_fields(original, policy)

        assert original == [{"ssn": "123-45-6789", "name": "bob"}]


class TestAllowedFieldsProjection:
    """Defect 2: allowedFields was never enforced against results."""

    def test_result_is_projected_to_allowed_fields(self, wrapper: SecureMcpToolWrapper) -> None:
        context = _signed(_policy(allowed_fields=["id", "name"]))

        result = wrapper.post_execute(
            context,
            [{"id": 1, "name": "bob", "ssn": "123-45-6789", "salary": 90000}],
        )

        assert result == [{"id": 1, "name": "bob"}]

    def test_qualified_allow_list_matches_bare_keys(self, wrapper: SecureMcpToolWrapper) -> None:
        context = _signed(_policy(allowed_fields=["patients.id", "patients.name"]))

        result = wrapper.post_execute(context, [{"id": 1, "name": "bob", "ssn": "x"}])

        assert result == [{"id": 1, "name": "bob"}]

    def test_glob_allow_list_is_honoured(self, wrapper: SecureMcpToolWrapper) -> None:
        context = _signed(_policy(allowed_fields=["patients.*"]))

        result = wrapper.post_execute(context, [{"id": 1, "name": "bob"}])

        assert result == [{"id": 1, "name": "bob"}]

    def test_empty_allow_list_denies_every_field(self, wrapper: SecureMcpToolWrapper) -> None:
        """[] is deny-all, not 'unrestricted'."""
        context = _signed(_policy(allowed_fields=[]))

        result = wrapper.post_execute(context, [{"id": 1, "name": "bob"}])

        assert result == [{}]

    def test_absent_allow_list_is_unrestricted(self) -> None:
        policy = _policy(hidden_fields=["ssn"])

        result = project_allowed_fields([{"id": 1, "name": "bob"}], policy)

        assert result == [{"id": 1, "name": "bob"}]


class TestPipelineOrder:
    """Defect 1/2: the pipeline must run all six steps in canonical order."""

    def test_full_pipeline_order(self, wrapper: SecureMcpToolWrapper) -> None:
        context = _signed(
            _policy(
                row_filters=[RowFilter(field="region", operator=FilterOperator.equals, value="us-east")],
                tag_rules=TagRules(denied_tags=["classified"]),
                hidden_fields=["ssn"],
                allowed_fields=["id", "region", "email", "tags"],
                masked_fields=[MaskingRule(field="email", mask_type=MaskType.redact)],
                max_results=2,
            )
        )
        records = [
            {"id": 1, "region": "us-east", "ssn": "a", "email": "a@x", "salary": 1, "tags": []},
            {"id": 2, "region": "us-west", "ssn": "b", "email": "b@x", "salary": 2, "tags": []},
            {"id": 3, "region": "us-east", "ssn": "c", "email": "c@x", "salary": 3, "tags": ["classified"]},
            {"id": 4, "region": "us-east", "ssn": "d", "email": "d@x", "salary": 4, "tags": []},
            {"id": 5, "region": "us-east", "ssn": "e", "email": "e@x", "salary": 5, "tags": []},
        ]

        result = wrapper.post_execute(context, records)

        # row filter drops id 2, tag filter drops id 3, limit keeps the first 2
        # of the survivors (1, 4, 5).
        assert [r["id"] for r in result] == [1, 4]
        # hidden removed, non-allowed removed, allowed-and-masked still masked.
        assert all("ssn" not in r for r in result)
        assert all("salary" not in r for r in result)
        assert all(r["email"] == "[REDACTED]" for r in result)

    def test_limit_applies_after_filtering(self, wrapper: SecureMcpToolWrapper) -> None:
        """Filtering must not starve maxResults when enough rows qualify."""
        context = _signed(
            _policy(
                row_filters=[RowFilter(field="region", operator=FilterOperator.equals, value="us-east")],
                max_results=3,
            )
        )
        records = [{"id": i, "region": "us-west" if i < 5 else "us-east"} for i in range(10)]

        result = wrapper.post_execute(context, records)

        assert len(result) == 3


class TestSingleRecordRunsFullPipeline:
    """Spec section 4: a get-by-id tool must not skip row/tag filters."""

    def test_single_record_is_tag_filtered(self, wrapper: SecureMcpToolWrapper) -> None:
        context = _signed(_policy(tag_rules=TagRules(denied_tags=["classified"])))

        result = wrapper.post_execute(context, {"id": 1, "tags": ["classified"]})

        assert result is None, "a deniedTags record was disclosed by the single-record path"

    def test_single_record_is_row_filtered(self, wrapper: SecureMcpToolWrapper) -> None:
        context = _signed(
            _policy(row_filters=[RowFilter(field="region", operator=FilterOperator.equals, value="us-east")])
        )

        result = wrapper.post_execute(context, {"id": 1, "region": "eu-west"})

        assert result is None

    def test_single_record_is_stripped_and_masked(self, wrapper: SecureMcpToolWrapper) -> None:
        context = _signed(
            _policy(
                hidden_fields=["ssn"],
                masked_fields=[MaskingRule(field="email", mask_type=MaskType.redact)],
            )
        )

        result = wrapper.post_execute(context, {"id": 1, "ssn": "x", "email": "a@x"})

        assert result == {"id": 1, "email": "[REDACTED]"}


class TestUnknownMaskTypeFailsClosed:
    """Defect 6: an unrecognized maskType must never return the raw value."""

    def test_unknown_mask_type_redacts_at_runtime(self) -> None:
        rule = MaskingRule(field="ssn", mask_type="scramble")  # type: ignore[arg-type]
        policy = _policy(masked_fields=[rule])

        result = apply_field_masking({"ssn": "123-45-6789"}, policy)

        assert result["ssn"] == "[REDACTED]"

    def test_unknown_mask_type_is_rejected_at_deserialization(self) -> None:
        from conftest import load_fixture
        from tolap_core.serialization import deserialize_policy_definition

        data = load_fixture("policies/invalid-bad-mask-type.json")

        with pytest.raises(ValueError, match="unknown maskType"):
            deserialize_policy_definition(data)


class TestMaskRestrictivenessRanking:
    """Defect 7: null/redact must beat partial, and unknown ranks strictest."""

    def test_ranking_order(self) -> None:
        from tolap_core.enums import mask_restrictiveness

        assert mask_restrictiveness(MaskType.null) > mask_restrictiveness(MaskType.redact)
        assert mask_restrictiveness(MaskType.redact) > mask_restrictiveness(MaskType.full)
        assert mask_restrictiveness(MaskType.full) > mask_restrictiveness(MaskType.hash)
        assert mask_restrictiveness(MaskType.hash) > mask_restrictiveness(MaskType.partial)

    def test_unknown_mask_type_ranks_most_restrictive(self) -> None:
        from tolap_core.enums import mask_restrictiveness

        assert mask_restrictiveness("scramble") > mask_restrictiveness(MaskType.null)

    def test_partial_showing_everything_degrades_to_full_mask(self) -> None:
        policy = _policy(
            masked_fields=[
                MaskingRule(
                    field="region",
                    mask_type=MaskType.partial,
                    parameters=MaskingParameters(show_first=100, show_last=100),
                )
            ]
        )

        result = apply_field_masking({"region": "us-east"}, policy)

        assert result["region"] == "*" * len("us-east")

    def test_partial_showing_exactly_the_value_degrades_to_full_mask(self) -> None:
        policy = _policy(
            masked_fields=[
                MaskingRule(
                    field="ssn",
                    mask_type=MaskType.partial,
                    parameters=MaskingParameters(show_first=6, show_last=5),
                )
            ]
        )

        result = apply_field_masking({"ssn": "123-45-6789"}, policy)

        assert result["ssn"] == "*" * len("123-45-6789")


class TestNegativeOperatorsFailClosed:
    """Defect 8: notEquals/notIn kept rows that simply lacked the column."""

    def test_not_equals_drops_row_missing_the_field(self) -> None:
        policy = _policy(
            row_filters=[RowFilter(field="classification", operator=FilterOperator.not_equals, value="secret")]
        )
        rows = [{"id": 1, "classification": "public"}, {"id": 2}]

        result = apply_row_filters(rows, policy)

        assert [r["id"] for r in result] == [1]

    def test_not_in_drops_row_missing_the_field(self) -> None:
        policy = _policy(
            row_filters=[RowFilter(field="region", operator=FilterOperator.not_in, values=["eu-west"])]
        )
        rows = [{"id": 1, "region": "us-east"}, {"id": 2}]

        result = apply_row_filters(rows, policy)

        assert [r["id"] for r in result] == [1]

    def test_explicit_null_still_compares(self) -> None:
        """A stored None is a value, distinct from an absent field."""
        policy = _policy(
            row_filters=[RowFilter(field="region", operator=FilterOperator.not_equals, value="eu-west")]
        )
        rows = [{"id": 1, "region": None}]

        result = apply_row_filters(rows, policy)

        assert [r["id"] for r in result] == [1]


class TestNestedFieldMasking:
    """Defect 9: nested fields went unmasked on the MCP path."""

    def test_dotted_rule_masks_nested_leaf(self) -> None:
        policy = _policy(masked_fields=[MaskingRule(field="patient.ssn", mask_type=MaskType.redact)])

        result = apply_field_masking({"patient": {"ssn": "123-45-6789"}}, policy)

        assert result["patient"]["ssn"] == "[REDACTED]"

    def test_bare_rule_masks_qualified_key(self) -> None:
        policy = _policy(masked_fields=[MaskingRule(field="ssn", mask_type=MaskType.redact)])

        result = apply_field_masking({"patients.ssn": "123-45-6789"}, policy)

        assert result["patients.ssn"] == "[REDACTED]"

    def test_qualified_rule_masks_bare_key(self) -> None:
        policy = _policy(masked_fields=[MaskingRule(field="patients.ssn", mask_type=MaskType.redact)])

        result = apply_field_masking({"ssn": "123-45-6789"}, policy)

        assert result["ssn"] == "[REDACTED]"

    def test_matching_is_case_insensitive(self) -> None:
        policy = _policy(masked_fields=[MaskingRule(field="Patients.SSN", mask_type=MaskType.redact)])

        result = apply_field_masking({"ssn": "123-45-6789"}, policy)

        assert result["ssn"] == "[REDACTED]"

    def test_masking_recurses_into_lists(self) -> None:
        policy = _policy(masked_fields=[MaskingRule(field="ssn", mask_type=MaskType.redact)])

        result = apply_field_masking(
            {"patients": [{"ssn": "a"}, {"ssn": "b"}]},
            policy,
        )

        assert [p["ssn"] for p in result["patients"]] == ["[REDACTED]", "[REDACTED]"]


class TestMaskingDoesNotMutateCallerData:
    """Defect 10: shallow dict(record) shared nested objects with the caller."""

    def test_result_does_not_alias_the_callers_nested_objects(self) -> None:
        """The defect proper: a shallow copy hands back the caller's nested dict.

        Latent while masking never recursed, but load-bearing now that it does:
        without a deep copy, masking a nested leaf would write through into the
        caller's original record.
        """
        policy = _policy(masked_fields=[MaskingRule(field="email", mask_type=MaskType.redact)])
        original = {"id": 1, "nested": {"note": "keep"}}

        result = apply_field_masking(original, policy)

        assert result["nested"] is not original["nested"]

    def test_nested_object_is_not_mutated(self) -> None:
        policy = _policy(masked_fields=[MaskingRule(field="ssn", mask_type=MaskType.redact)])
        original = {"patient": {"ssn": "123-45-6789"}}

        apply_field_masking(original, policy)

        assert original["patient"]["ssn"] == "123-45-6789"

    def test_pipeline_does_not_mutate_caller_records(self, wrapper: SecureMcpToolWrapper) -> None:
        context = _signed(
            _policy(
                hidden_fields=["ssn"],
                masked_fields=[MaskingRule(field="email", mask_type=MaskType.redact)],
            )
        )
        original = [{"id": 1, "ssn": "x", "email": "a@x", "nested": {"email": "b@x"}}]

        wrapper.post_execute(context, original)

        assert original == [{"id": 1, "ssn": "x", "email": "a@x", "nested": {"email": "b@x"}}]


class TestFilterRobustness:
    """Defect 11: numeric filters raised, regex was unbounded, bool/int conflated."""

    def test_greater_than_type_mismatch_drops_row(self) -> None:
        policy = _policy(row_filters=[RowFilter(field="age", operator=FilterOperator.greater_than, value=30)])
        rows = [{"id": 1, "age": "notanumber"}, {"id": 2, "age": 40}]

        result = apply_row_filters(rows, policy)

        assert [r["id"] for r in result] == [2]

    def test_less_than_type_mismatch_drops_row(self) -> None:
        policy = _policy(row_filters=[RowFilter(field="age", operator=FilterOperator.less_than, value=30)])
        rows = [{"id": 1, "age": "notanumber"}, {"id": 2, "age": 10}]

        result = apply_row_filters(rows, policy)

        assert [r["id"] for r in result] == [2]

    def test_invalid_regex_is_a_non_match_not_an_exception(self) -> None:
        policy = _policy(row_filters=[RowFilter(field="region", operator=FilterOperator.matches, value="[unclosed")])
        rows = [{"id": 1, "region": "us-east"}]

        result = apply_row_filters(rows, policy)

        assert result == []

    def test_matches_is_anchored_with_a_non_capturing_group(self) -> None:
        """'^hr|finance$' must not match 'hr_secret_internal'."""
        policy = _policy(row_filters=[RowFilter(field="dept", operator=FilterOperator.matches, value="^hr|finance$")])
        rows = [{"id": 1, "dept": "hr_secret_internal"}, {"id": 2, "dept": "hr"}]

        result = apply_row_filters(rows, policy)

        assert [r["id"] for r in result] == [2]

    def test_oversized_regex_pattern_is_a_non_match(self) -> None:
        policy = _policy(
            row_filters=[RowFilter(field="v", operator=FilterOperator.matches, value="a" * 2000)]
        )

        assert apply_row_filters([{"id": 1, "v": "a"}], policy) == []

    def test_oversized_value_is_a_non_match(self) -> None:
        policy = _policy(row_filters=[RowFilter(field="v", operator=FilterOperator.matches, value="a*")])

        assert apply_row_filters([{"id": 1, "v": "a" * 5000}], policy) == []

    def test_equals_does_not_conflate_bool_and_int(self) -> None:
        policy = _policy(row_filters=[RowFilter(field="flag", operator=FilterOperator.equals, value=1)])
        rows = [{"id": 1, "flag": True}, {"id": 2, "flag": 1}]

        result = apply_row_filters(rows, policy)

        assert [r["id"] for r in result] == [2]

    def test_in_does_not_conflate_bool_and_int(self) -> None:
        policy = _policy(row_filters=[RowFilter(field="flag", operator=FilterOperator.in_, values=[1])])
        rows = [{"id": 1, "flag": True}, {"id": 2, "flag": 1}]

        result = apply_row_filters(rows, policy)

        assert [r["id"] for r in result] == [2]


class TestResultShapesFailClosed:
    """Defect 12: post_execute assumed list[dict] and crashed or passed through."""

    @pytest.mark.parametrize(
        "bad_result",
        [
            pytest.param("a string", id="scalar-str"),
            pytest.param(42, id="scalar-int"),
            pytest.param(None, id="none"),
            pytest.param((r for r in [{"a": 1}]), id="generator"),
            pytest.param(object(), id="arbitrary-object"),
            pytest.param([{"a": 1}, "not a record"], id="mixed-list"),
            pytest.param([1, 2, 3], id="list-of-scalars"),
        ],
    )
    def test_unenforceable_shape_is_denied(self, wrapper: SecureMcpToolWrapper, bad_result: object) -> None:
        context = _signed(_policy(hidden_fields=["ssn"]))

        with pytest.raises(PermissionError, match="cannot be policy-enforced"):
            wrapper.post_execute(context, bad_result)

    def test_bare_dict_no_longer_crashes(self, wrapper: SecureMcpToolWrapper) -> None:
        """Previously raised TypeError: string indices must be integers."""
        context = _signed(_policy(hidden_fields=["ssn"]))

        result = wrapper.post_execute(context, {"id": 1, "ssn": "x"})

        assert result == {"id": 1}

    def test_denial_message_names_the_observed_shape(self, wrapper: SecureMcpToolWrapper) -> None:
        context = _signed(_policy())

        with pytest.raises(UnenforceableResultError, match="str"):
            wrapper.post_execute(context, "a string")

    def test_execute_with_enforcement_denies_unenforceable_shape(self, wrapper: SecureMcpToolWrapper) -> None:
        context = _signed(_policy(hidden_fields=["ssn"]))

        with pytest.raises(PermissionError, match="cannot be policy-enforced"):
            wrapper.execute_with_enforcement(
                context=context,
                tool_name="scalar-tool",
                tool_fn=lambda: "just a string",
                tool_args={},
            )

    def test_opt_out_passes_shape_through_and_logs(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        wrapper = SecureMcpToolWrapper(
            SecureMcpServerOptions(signing_key=SIGNING_KEY, allow_unenforceable_shapes=True)
        )
        context = _signed(_policy(hidden_fields=["ssn"]))

        with caplog.at_level("WARNING"):
            result = wrapper.post_execute(context, "a string")

        assert result == "a string"
        assert "allow_unenforceable_shapes" in caplog.text

    def test_opt_out_defaults_to_off(self) -> None:
        assert SecureMcpServerOptions(signing_key=SIGNING_KEY).allow_unenforceable_shapes is False

    def test_empty_list_is_enforceable(self, wrapper: SecureMcpToolWrapper) -> None:
        context = _signed(_policy(hidden_fields=["ssn"]))

        assert wrapper.post_execute(context, []) == []

    def test_apply_result_pipeline_rejects_unenforceable_shape_directly(self) -> None:
        with pytest.raises(UnenforceableResultError):
            apply_result_pipeline(3.14, _policy())
