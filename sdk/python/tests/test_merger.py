from __future__ import annotations

import json
import pathlib

import pytest

from conftest import load_all_fixtures
from tolap_core.enums import MaskType
from tolap_core.merger import merge
from tolap_core.models import PolicyDefinition, PolicyPermissions
from tolap_core.serialization import deserialize_policy_definition, serialize


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
        # Loads the fixture by name rather than hardcoding the expectation, so the shared
        # corpus stays the authority and the "every fixture is named" guard below needs no
        # exemption for this one.
        _, data = next(
            (name, d) for name, d in load_all_fixtures("merge-scenarios")
            if name == "empty-produces-deny-all"
        )
        expected = data["expected"]

        result = merge([deserialize_policy_definition(p) for p in data["inputs"]])

        assert result.source_profiles == expected["sourceProfiles"]
        assert result.permissions.can_query is expected["permissions"]["canQuery"]
        assert result.permissions.read_only is expected["permissions"]["readOnly"]

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

    def test_union_of_explicitly_empty_deny_lists_stays_empty(self) -> None:
        """``[]`` in, ``[]`` out -- the case Python got wrong (spec section 3).

        Python's union used ``return result if result else None``, so where every
        contributing list was explicitly empty it emitted no field while .NET and
        TypeScript emitted ``[]``. Invisible to enforcement, because neither hides
        anything -- and *not* invisible to signing, since ``serialize`` omits ``None``
        and emits ``[]``. A policy authoring an empty ``hiddenObjects`` therefore signed
        different bytes here than in the other two SDKs, and a context signed by one
        would not verify in the others.

        Asserted on all four fields the one shared helper produced, and on ``is not
        None`` as well as emptiness: an emptiness check alone passes against ``None``,
        which is the same collapse relocated from the code into the test.
        """
        _, data = next(
            (name, d) for name, d in load_all_fixtures("merge-scenarios")
            if name == "union-of-empty-lists-stays-empty"
        )
        inputs = [deserialize_policy_definition(p) for p in data["inputs"]]
        result = merge(inputs)

        rules = result.object_rules
        assert rules is not None
        for actual, label in (
            (rules.hidden_objects, "hiddenObjects"),
            (rules.field_rules.hidden_fields, "hiddenFields"),
            (rules.field_rules.read_only_fields, "readOnlyFields"),
            (rules.tag_rules.denied_tags, "deniedTags"),
            (rules.endpoint_rules.hidden_endpoints, "hiddenEndpoints"),
        ):
            assert actual is not None, f"{label} collapsed to None"
            assert actual == [], f"{label} should be empty, got {actual!r}"

        # And the canonical bytes carry them, which is the property the divergence broke.
        emitted = json.loads(serialize(result))["objectRules"]
        assert emitted["hiddenObjects"] == []
        assert emitted["tagRules"]["deniedTags"] == []

    def test_a_union_field_no_policy_mentions_stays_absent(self) -> None:
        """The paired direction, and why the fix is a flag rather than "always a list".

        When no policy mentions the field at all, absent is correct. Emitting ``[]``
        there would change the canonical bytes of every policy that never mentioned it --
        a far larger blast radius than the bug being fixed.
        """
        inputs = [
            PolicyDefinition(
                version="1.0", name="a", permissions=PolicyPermissions(can_query=True)
            ),
            PolicyDefinition(
                version="1.0", name="b", permissions=PolicyPermissions(can_query=True)
            ),
        ]

        result = merge(inputs)

        assert result.object_rules is None or result.object_rules.hidden_objects is None

    def test_every_merge_scenario_fixture_is_asserted_by_a_test(self) -> None:
        """A fixture nobody names is a fixture nobody checks.

        This suite selects fixtures **by name**, so adding one to ``merge-scenarios/``
        gets it schema-validated by ``test_schema_fixture_validation.py`` and behaviourally
        asserted by nothing. That is precisely what happened to
        ``union-of-empty-lists-stays-empty``: it was added to pin a cross-SDK fix in all
        three languages and, in the one SDK that had the bug, asserted nothing until a
        scan noticed. Cheaper to detect than to remember.
        """
        # The whole suite, not this file: the purpose-profile scenarios are asserted in
        # test_purpose_merge.py, and scanning one file reported them as gaps. A guard with
        # false positives gets an exemption list, and an exemption list is where the real
        # gap eventually hides.
        suite = "\n".join(
            path.read_text() for path in sorted(pathlib.Path(__file__).parent.glob("test_*.py"))
        )
        unnamed = [
            name
            for name, _ in load_all_fixtures("merge-scenarios")
            if f'"{name}"' not in suite
        ]

        assert unnamed == [], (
            "merge-scenario fixtures no test names, so nothing asserts their behaviour "
            "(the schema validator will still check their shape, which is not the same "
            "thing): " + ", ".join(unnamed)
        )
