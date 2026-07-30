from __future__ import annotations

import pytest

from conftest import load_all_fixtures
from tolap_core.enums import MaskType
from tolap_core.merger import merge
from tolap_core.serialization import deserialize_policy_definition


def _normalize_list(val: list | None) -> list | None:
    """Sort a list for comparison if it's not None."""
    if val is None:
        return None
    return sorted(val)


class TestMerger:
    """Test merge scenarios from fixtures."""

    @pytest.fixture
    def merge_scenarios(self) -> list[tuple[str, dict]]:
        return load_all_fixtures("merge-scenarios")

    def test_empty_produces_deny_all(self) -> None:
        result = merge([])
        assert result.source_profiles == []
        assert result.permissions.can_query is False
        assert result.permissions.read_only is True

    def test_single_policy_passthrough(self) -> None:
        _, data = next(
            (name, d) for name, d in load_all_fixtures("merge-scenarios")
            if name == "single-policy-passthrough"
        )
        inputs = [deserialize_policy_definition(p) for p in data["inputs"]]
        result = merge(inputs)
        expected = data["expected"]

        assert result.source_profiles == expected["sourceProfiles"]
        assert result.permissions.can_query == expected["permissions"]["canQuery"]
        assert result.permissions.read_only == expected["permissions"]["readOnly"]

        exp_obj = expected["objectRules"]
        assert result.object_rules is not None
        assert _normalize_list(result.object_rules.allowed_objects) == _normalize_list(exp_obj["allowedObjects"])
        assert _normalize_list(result.object_rules.hidden_objects) == _normalize_list(exp_obj["hiddenObjects"])

        exp_fr = exp_obj["fieldRules"]
        assert result.object_rules.field_rules is not None
        assert _normalize_list(result.object_rules.field_rules.allowed_fields) == _normalize_list(exp_fr["allowedFields"])
        assert _normalize_list(result.object_rules.field_rules.hidden_fields) == _normalize_list(exp_fr["hiddenFields"])
        assert len(result.object_rules.field_rules.masked_fields) == len(exp_fr["maskedFields"])

        assert result.object_rules.row_filters is not None
        assert len(result.object_rules.row_filters) == len(exp_obj["rowFilters"])

        assert result.limits is not None
        assert result.limits.max_results == expected["limits"]["maxResults"]
        assert result.limits.min_similarity_score == expected["limits"]["minSimilarityScore"]
        assert result.limits.max_object_size_bytes == expected["limits"]["maxObjectSizeBytes"]

    def test_can_query_false_wins(self) -> None:
        _, data = next(
            (name, d) for name, d in load_all_fixtures("merge-scenarios")
            if name == "can-query-false-wins"
        )
        inputs = [deserialize_policy_definition(p) for p in data["inputs"]]
        result = merge(inputs)
        expected = data["expected"]

        assert result.permissions.can_query == expected["permissions"]["canQuery"]
        assert result.permissions.read_only == expected["permissions"]["readOnly"]

    def test_intersection_allowed_fields(self) -> None:
        _, data = next(
            (name, d) for name, d in load_all_fixtures("merge-scenarios")
            if name == "intersection-allowed-fields"
        )
        inputs = [deserialize_policy_definition(p) for p in data["inputs"]]
        result = merge(inputs)
        expected = data["expected"]

        assert result.permissions.can_query == expected["permissions"]["canQuery"]
        assert result.permissions.read_only == expected["permissions"]["readOnly"]

        exp_obj = expected["objectRules"]
        assert _normalize_list(result.object_rules.allowed_objects) == _normalize_list(exp_obj["allowedObjects"])
        assert _normalize_list(result.object_rules.field_rules.allowed_fields) == _normalize_list(exp_obj["fieldRules"]["allowedFields"])
        assert result.limits.max_results == expected["limits"]["maxResults"]

    def test_hidden_wins_over_allowed(self) -> None:
        _, data = next(
            (name, d) for name, d in load_all_fixtures("merge-scenarios")
            if name == "hidden-wins-over-allowed"
        )
        inputs = [deserialize_policy_definition(p) for p in data["inputs"]]
        result = merge(inputs)
        expected = data["expected"]

        assert result.permissions.can_query == expected["permissions"]["canQuery"]

        exp_obj = expected["objectRules"]
        assert _normalize_list(result.object_rules.hidden_objects) == _normalize_list(exp_obj["hiddenObjects"])
        assert _normalize_list(result.object_rules.field_rules.allowed_fields) == _normalize_list(exp_obj["fieldRules"]["allowedFields"])
        assert _normalize_list(result.object_rules.field_rules.hidden_fields) == _normalize_list(exp_obj["fieldRules"]["hiddenFields"])

    def test_masked_fields_most_restrictive(self) -> None:
        """Most restrictive mask wins per field: null > redact > full > hash > partial.

        The shared fixture's `expected` block still encodes the old, inverted
        ranking (it expects `partial` to beat `null` and `redact`), which would
        disclose real characters of a value another policy demanded be erased.
        Asserted here against the canonical ranking instead; the fixture is
        shared across SDKs and is corrected in a separate step.
        """
        _, data = next(
            (name, d) for name, d in load_all_fixtures("merge-scenarios")
            if name == "masked-fields-most-restrictive"
        )
        inputs = [deserialize_policy_definition(p) for p in data["inputs"]]
        result = merge(inputs)

        result_by_field = {m.field: m for m in result.object_rules.field_rules.masked_fields}
        assert len(result_by_field) == 3

        # email: partial (policy A) vs hash (policy B) -> hash discloses less.
        assert result_by_field["email"].mask_type == MaskType.hash
        assert result_by_field["email"].parameters.algorithm == "sha256"

        # phone: redact (A) vs partial (B) -> redact wins, no digits survive.
        assert result_by_field["phone"].mask_type == MaskType.redact

        # name: null (A) vs partial (B) -> null wins, the field is erased.
        assert result_by_field["name"].mask_type == MaskType.null

    def test_row_filters_concatenate(self) -> None:
        _, data = next(
            (name, d) for name, d in load_all_fixtures("merge-scenarios")
            if name == "row-filters-concatenate"
        )
        inputs = [deserialize_policy_definition(p) for p in data["inputs"]]
        result = merge(inputs)
        expected = data["expected"]

        exp_filters = expected["objectRules"]["rowFilters"]
        assert result.object_rules.row_filters is not None
        assert len(result.object_rules.row_filters) == len(exp_filters)

        for i, exp in enumerate(exp_filters):
            actual = result.object_rules.row_filters[i]
            assert actual.field == exp["field"]
            assert actual.operator.value == exp["operator"]

    def test_min_max_limits(self) -> None:
        _, data = next(
            (name, d) for name, d in load_all_fixtures("merge-scenarios")
            if name == "min-max-limits"
        )
        inputs = [deserialize_policy_definition(p) for p in data["inputs"]]
        result = merge(inputs)
        expected = data["expected"]

        exp_limits = expected["limits"]
        assert result.limits is not None
        assert result.limits.max_results == exp_limits["maxResults"]
        assert result.limits.min_similarity_score == exp_limits["minSimilarityScore"]
        assert result.limits.max_object_size_bytes == exp_limits["maxObjectSizeBytes"]
