"""Enforcement of minSimilarityScore and maxObjectSizeBytes (spec section 4, steps 3-4).

Both limits were parsed, validated, and merged most-restrictively -- and then never
applied to any result. The merge and round-trip paths *were* tested, so statement
and branch coverage reached 100% while neither control did anything: coverage
measures whether written code runs, never whether required code was written.

`minSimilarityScore` is documented as a confidentiality control ("similarity score
thresholds prevent low-relevance results from surfacing sensitive content"), so
these tests assert it fails closed rather than merely filtering when convenient.
"""

from __future__ import annotations

from tolap_core.enforcement import (
    apply_object_size_ceiling,
    apply_result_pipeline,
    apply_similarity_floor,
)
from tolap_core.models import (
    EffectivePolicy,
    FieldRules,
    MaskingRule,
    ObjectRules,
    PolicyLimits,
    PolicyPermissions,
)
from tolap_core.enums import MaskType


def _policy(**limits: object) -> EffectivePolicy:
    return EffectivePolicy(
        version="1.0",
        source_profiles=["p"],
        permissions=PolicyPermissions(can_query=True),
        limits=PolicyLimits(**limits),  # type: ignore[arg-type]
    )


class TestSimilarityFloor:
    """minSimilarityScore drops low-relevance records."""

    def test_records_below_the_floor_are_dropped(self) -> None:
        policy = _policy(min_similarity_score=0.9)

        kept = apply_similarity_floor(
            [{"id": "high", "score": 0.95}, {"id": "low", "score": 0.10}], policy
        )

        assert [r["id"] for r in kept] == ["high"]

    def test_a_score_exactly_at_the_floor_is_kept(self) -> None:
        policy = _policy(min_similarity_score=0.9)

        kept = apply_similarity_floor([{"id": "exact", "score": 0.9}], policy)

        assert [r["id"] for r in kept] == ["exact"]

    def test_an_unscored_record_is_dropped(self) -> None:
        """Fail closed: relevance that cannot be established cannot satisfy a floor."""
        policy = _policy(min_similarity_score=0.5)

        kept = apply_similarity_floor([{"id": "no-score-field"}], policy)

        assert kept == []

    def test_a_non_numeric_score_is_dropped(self) -> None:
        policy = _policy(min_similarity_score=0.5)

        kept = apply_similarity_floor(
            [{"id": "a", "score": "not-a-number"}, {"id": "b", "score": None}], policy
        )

        assert kept == []

    def test_a_boolean_score_is_dropped_not_coerced(self) -> None:
        """`bool` is an int subclass; True must not read as a passing 1.0 score."""
        policy = _policy(min_similarity_score=0.5)

        kept = apply_similarity_floor([{"id": "a", "score": True}], policy)

        assert kept == []

    def test_a_numeric_string_score_is_honored(self) -> None:
        policy = _policy(min_similarity_score=0.5)

        kept = apply_similarity_floor(
            [{"id": "pass", "score": "0.75"}, {"id": "fail", "score": "0.25"}], policy
        )

        assert [r["id"] for r in kept] == ["pass"]

    def test_a_non_finite_score_is_dropped(self) -> None:
        policy = _policy(min_similarity_score=0.5)

        kept = apply_similarity_floor(
            [{"id": "nan", "score": float("nan")}, {"id": "inf", "score": float("inf")}],
            policy,
        )

        # NaN comparisons are always false, so a NaN score must be rejected by the
        # finite check rather than silently passing the floor.
        assert [r["id"] for r in kept] == []

    def test_alternate_score_field_names_are_recognized(self) -> None:
        policy = _policy(min_similarity_score=0.5)

        kept = apply_similarity_floor(
            [
                {"id": "similarity", "similarity": 0.9},
                {"id": "similarityScore", "similarityScore": 0.9},
                {"id": "underscore", "_score": 0.9},
                {"id": "uppercase", "SCORE": 0.9},
            ],
            policy,
        )

        assert len(kept) == 4

    def test_no_floor_configured_is_a_passthrough(self) -> None:
        records = [{"id": "a"}, {"id": "b", "score": 0.01}]

        assert apply_similarity_floor(records, _policy()) == records

    def test_absent_limits_block_is_a_passthrough(self) -> None:
        policy = EffectivePolicy(
            version="1.0",
            source_profiles=["p"],
            permissions=PolicyPermissions(can_query=True),
        )
        records = [{"id": "a", "score": 0.01}]

        assert apply_similarity_floor(records, policy) == records


class TestObjectSizeCeiling:
    """maxObjectSizeBytes drops oversized records."""

    def test_records_above_the_ceiling_are_dropped(self) -> None:
        policy = _policy(max_object_size_bytes=1024)

        kept = apply_object_size_ceiling(
            [{"key": "small", "size": 500}, {"key": "huge", "size": 999_999_999}], policy
        )

        assert [r["key"] for r in kept] == ["small"]

    def test_a_size_exactly_at_the_ceiling_is_kept(self) -> None:
        policy = _policy(max_object_size_bytes=1024)

        kept = apply_object_size_ceiling([{"key": "exact", "size": 1024}], policy)

        assert [r["key"] for r in kept] == ["exact"]

    def test_an_unsized_record_is_dropped(self) -> None:
        policy = _policy(max_object_size_bytes=1024)

        kept = apply_object_size_ceiling([{"key": "no-size-field"}], policy)

        assert kept == []

    def test_a_non_numeric_size_is_dropped(self) -> None:
        policy = _policy(max_object_size_bytes=1024)

        kept = apply_object_size_ceiling([{"key": "a", "size": "big"}], policy)

        assert kept == []

    def test_alternate_size_field_names_are_recognized(self) -> None:
        policy = _policy(max_object_size_bytes=1024)

        kept = apply_object_size_ceiling(
            [
                {"key": "sizeBytes", "sizeBytes": 10},
                {"key": "contentLength", "contentLength": 10},
                {"key": "objectSize", "objectSize": 10},
                {"key": "uppercase", "SIZE": 10},
            ],
            policy,
        )

        assert len(kept) == 4

    def test_no_ceiling_configured_is_a_passthrough(self) -> None:
        records = [{"key": "a"}, {"key": "b", "size": 10**12}]

        assert apply_object_size_ceiling(records, _policy()) == records

    def test_a_non_record_entry_is_dropped(self) -> None:
        """A list carrying a non-record entry fails closed rather than raising.

        The pipeline classifies whole result shapes, but a heterogeneous list can
        still reach here; an entry whose size cannot be read is not admitted.
        """
        policy = _policy(max_object_size_bytes=1024)

        kept = apply_object_size_ceiling(["not-a-record", 42, None, {"key": "ok", "size": 1}], policy)

        assert kept == [{"key": "ok", "size": 1}]

    def test_a_non_record_entry_is_dropped_by_the_floor_too(self) -> None:
        policy = _policy(min_similarity_score=0.5)

        kept = apply_similarity_floor(["not-a-record", {"id": "ok", "score": 0.9}], policy)

        assert kept == [{"id": "ok", "score": 0.9}]


class TestPipelineIntegration:
    """Both limits run inside the canonical pipeline, before field-level steps."""

    def test_pipeline_applies_the_relevance_floor(self) -> None:
        policy = _policy(min_similarity_score=0.8)

        out = apply_result_pipeline(
            [{"id": "keep", "score": 0.9}, {"id": "drop", "score": 0.1}], policy
        )

        assert [r["id"] for r in out] == ["keep"]

    def test_pipeline_applies_the_size_ceiling(self) -> None:
        policy = _policy(max_object_size_bytes=100)

        out = apply_result_pipeline(
            [{"key": "keep", "size": 50}, {"key": "drop", "size": 5000}], policy
        )

        assert [r["key"] for r in out] == ["keep"]

    def test_a_dropped_single_record_is_a_denial(self) -> None:
        """A single record failing the floor returns None, not an empty record."""
        policy = _policy(min_similarity_score=0.9)

        assert apply_result_pipeline({"id": "low", "score": 0.1}, policy) is None

    def test_record_dropping_precedes_masking(self) -> None:
        """A record about to be dropped is not masked first (spec section 4 ordering).

        Asserted observably: the surviving record is masked, and the dropped one is
        absent entirely rather than present-and-masked.
        """
        policy = EffectivePolicy(
            version="1.0",
            source_profiles=["p"],
            permissions=PolicyPermissions(can_query=True),
            object_rules=ObjectRules(
                field_rules=FieldRules(
                    masked_fields=[MaskingRule(field="secret", mask_type=MaskType.redact)]
                )
            ),
            limits=PolicyLimits(min_similarity_score=0.5),
        )

        out = apply_result_pipeline(
            [
                {"id": "keep", "score": 0.9, "secret": "s1"},
                {"id": "drop", "score": 0.1, "secret": "s2"},
            ],
            policy,
        )

        assert len(out) == 1
        assert out[0]["id"] == "keep"
        assert out[0]["secret"] == "[REDACTED]"

    def test_both_limits_compose(self) -> None:
        policy = _policy(min_similarity_score=0.5, max_object_size_bytes=1000)

        out = apply_result_pipeline(
            [
                {"id": "ok", "score": 0.9, "size": 100},
                {"id": "low-score", "score": 0.1, "size": 100},
                {"id": "oversized", "score": 0.9, "size": 99_999},
            ],
            policy,
        )

        assert [r["id"] for r in out] == ["ok"]

    def test_limits_apply_before_the_result_limit(self) -> None:
        """maxResults must count only records that survived the floor."""
        policy = _policy(min_similarity_score=0.5, max_results=2)

        out = apply_result_pipeline(
            [
                {"id": "a", "score": 0.1},
                {"id": "b", "score": 0.9},
                {"id": "c", "score": 0.9},
            ],
            policy,
        )

        # Had the limit run first, "a" would consume a slot and only "b" would remain.
        assert [r["id"] for r in out] == ["b", "c"]
