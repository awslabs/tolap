"""Branch coverage for the enforcement primitives and the signing helpers.

The conditionals here are the ones the canonical spec is most explicit about:
row filters fail closed on a missing field for *every* operator (section 7),
comparison operators never raise on a type mismatch, an unknown mask type is
treated as `redact` (section 6), `[]` is deny-all rather than unrestricted
(section 3), and an unenforceable result shape is denied rather than passed
through (section 5). Each test asserts the decision, so a regression that flips
one of these branches fails here rather than shipping.
"""

from __future__ import annotations

import base64
import json
from datetime import timedelta

import pytest

from tolap_core.context import (
    _compute_signature,
    _normalize_timestamp,
    build_security_context,
    sign_context,
    validate_context,
    validate_expiry,
)
from tolap_core.enums import (
    AssigneeType,
    FilterOperator,
    MaskType,
    SigningAlgorithm,
    mask_restrictiveness,
)
from tolap_core.enforcement import (
    UnenforceableResultError,
    apply_field_masking,
    apply_masking,
    apply_result_limit,
    apply_result_pipeline,
    apply_row_filters,
    classify_result_shape,
    describe_result_shape,
    filter_by_tags,
    project_allowed_fields,
    strip_hidden_fields,
    validate_access,
    validate_endpoint,
    validate_field_access,
)
from tolap_core.merger import merge
from tolap_core.models import (
    EffectivePolicy,
    EndpointRules,
    FieldRules,
    IntegrityBlock,
    MaskingParameters,
    MaskingRule,
    ObjectRules,
    PolicyDefinition,
    PolicyLimits,
    PolicyPermissions,
    RowFilter,
    SecurityContext,
    TagRules,
)
from tolap_core.serialization import (
    deserialize_effective_policy,
    deserialize_policy_definition,
    serialize,
)


def _policy(
    *,
    can_query: bool = True,
    read_only: bool | None = True,
    object_rules: ObjectRules | None = None,
    limits: PolicyLimits | None = None,
) -> EffectivePolicy:
    return EffectivePolicy(
        version="1.0",
        user_id="u",
        tenant_id="t",
        source_profiles=["branches"],
        permissions=PolicyPermissions(can_query=can_query, read_only=read_only),
        object_rules=object_rules,
        limits=limits,
    )


def _filtered(rows: list[dict], *filters: RowFilter) -> list[dict]:
    return apply_row_filters(rows, _policy(object_rules=ObjectRules(row_filters=list(filters))))


class TestRowFilterMissingFieldFailsClosed:
    """Spec section 7: an absent field drops the row, for every operator.

    `notEquals` failing open on a missing field is the defect that shipped: a
    filter written to exclude classified rows retained every row that simply
    lacked the column.
    """

    @pytest.mark.parametrize(
        "row_filter",
        [
            RowFilter(field="region", operator=FilterOperator.equals, value="us-east"),
            RowFilter(field="region", operator=FilterOperator.not_equals, value="classified"),
            RowFilter(field="region", operator=FilterOperator.in_, values=["us-east"]),
            RowFilter(field="region", operator=FilterOperator.not_in, values=["classified"]),
            RowFilter(field="region", operator=FilterOperator.greater_than, value=1),
            RowFilter(field="region", operator=FilterOperator.less_than, value=1),
            RowFilter(field="region", operator=FilterOperator.contains, value="east"),
            RowFilter(field="region", operator=FilterOperator.starts_with, value="us"),
            RowFilter(field="region", operator=FilterOperator.matches, value="us-.*"),
        ],
        ids=lambda rf: rf.operator.value,
    )
    def test_row_without_the_field_is_dropped(self, row_filter: RowFilter) -> None:
        assert _filtered([{"id": 1}], row_filter) == []

    def test_explicit_none_is_distinct_from_absent(self) -> None:
        """A stored null is comparable; only true absence fails closed."""
        rows = [{"id": 1, "region": None}]

        kept = _filtered(
            rows, RowFilter(field="region", operator=FilterOperator.not_equals, value="classified")
        )

        assert kept == rows


class TestRowFilterOperatorBranches:
    def test_greater_than_and_less_than_both_directions(self) -> None:
        rows = [{"age": 20}, {"age": 40}]

        assert _filtered(rows, RowFilter(field="age", operator=FilterOperator.greater_than, value=30)) == [{"age": 40}]
        assert _filtered(rows, RowFilter(field="age", operator=FilterOperator.less_than, value=30)) == [{"age": 20}]

    def test_type_mismatch_is_a_non_match_not_an_exception(self) -> None:
        """Spec section 7: a non-comparable value drops the row, never raises."""
        rows = [{"age": "notanumber"}, {"age": 40}]

        assert _filtered(rows, RowFilter(field="age", operator=FilterOperator.greater_than, value=30)) == [{"age": 40}]
        assert _filtered(rows, RowFilter(field="age", operator=FilterOperator.less_than, value=30)) == []

    def test_none_comparand_on_either_side_drops_the_row(self) -> None:
        assert _filtered(
            [{"age": None}], RowFilter(field="age", operator=FilterOperator.greater_than, value=30)
        ) == []
        assert _filtered(
            [{"age": 40}], RowFilter(field="age", operator=FilterOperator.greater_than, value=None)
        ) == []

    def test_contains_and_starts_with_none_values_drop_the_row(self) -> None:
        assert _filtered(
            [{"name": None}], RowFilter(field="name", operator=FilterOperator.contains, value="a")
        ) == []
        assert _filtered(
            [{"name": "abc"}], RowFilter(field="name", operator=FilterOperator.contains, value=None)
        ) == []
        assert _filtered(
            [{"name": None}], RowFilter(field="name", operator=FilterOperator.starts_with, value="a")
        ) == []
        assert _filtered(
            [{"name": "abc"}], RowFilter(field="name", operator=FilterOperator.starts_with, value=None)
        ) == []

    def test_contains_and_starts_with_positive_and_negative(self) -> None:
        rows = [{"name": "abcdef"}, {"name": "xyz"}]

        assert _filtered(rows, RowFilter(field="name", operator=FilterOperator.contains, value="cde")) == [{"name": "abcdef"}]
        assert _filtered(rows, RowFilter(field="name", operator=FilterOperator.starts_with, value="abc")) == [{"name": "abcdef"}]

    def test_in_and_not_in_with_absent_values_list(self) -> None:
        """`values=None` means an empty candidate set: `in` matches nothing."""
        rows = [{"region": "us-east"}]

        assert _filtered(rows, RowFilter(field="region", operator=FilterOperator.in_, values=None)) == []
        assert _filtered(rows, RowFilter(field="region", operator=FilterOperator.not_in, values=None)) == rows

    def test_equals_does_not_conflate_booleans_with_numbers(self) -> None:
        """Spec section 7: `1` != `true`."""
        assert _filtered(
            [{"flag": True}, {"flag": 1}],
            RowFilter(field="flag", operator=FilterOperator.equals, value=1),
        ) == [{"flag": 1}]

        assert _filtered(
            [{"flag": True}, {"flag": 1}],
            RowFilter(field="flag", operator=FilterOperator.equals, value=True),
        ) == [{"flag": True}]

    def test_in_does_not_conflate_booleans_with_numbers(self) -> None:
        assert _filtered(
            [{"flag": True}, {"flag": 1}],
            RowFilter(field="flag", operator=FilterOperator.in_, values=[1]),
        ) == [{"flag": 1}]

    def test_matches_is_anchored_with_a_non_capturing_group(self) -> None:
        """Spec section 7: `^hr|finance$` must not match "hr_secret_internal"."""
        rows = [{"dept": "hr"}, {"dept": "finance"}, {"dept": "hr_secret_internal"}]

        kept = _filtered(rows, RowFilter(field="dept", operator=FilterOperator.matches, value="hr|finance"))

        assert kept == [{"dept": "hr"}, {"dept": "finance"}]

    def test_invalid_regex_is_a_non_match_not_an_exception(self) -> None:
        """A regex error must never abort the whole result pass."""
        kept = _filtered(
            [{"dept": "hr"}], RowFilter(field="dept", operator=FilterOperator.matches, value="([unclosed")
        )

        assert kept == []

    def test_overlong_pattern_is_refused(self) -> None:
        """ReDoS guard: an over-long pattern is a non-match, not a search."""
        kept = _filtered(
            [{"dept": "hr"}],
            RowFilter(field="dept", operator=FilterOperator.matches, value="a" * 2000),
        )

        assert kept == []

    def test_overlong_subject_value_is_refused(self) -> None:
        kept = _filtered(
            [{"dept": "a" * 5000}],
            RowFilter(field="dept", operator=FilterOperator.matches, value="a*"),
        )

        assert kept == []

    def test_matches_with_a_none_pattern_drops_the_row(self) -> None:
        """A filter with no pattern cannot be satisfied, so it must not pass."""
        assert _filtered(
            [{"dept": "hr"}], RowFilter(field="dept", operator=FilterOperator.matches, value=None)
        ) == []

    def test_matches_against_a_null_row_value_drops_the_row(self) -> None:
        assert _filtered(
            [{"dept": None}], RowFilter(field="dept", operator=FilterOperator.matches, value="hr")
        ) == []

    def test_unknown_operator_fails_closed(self) -> None:
        """An operator this SDK does not implement must not retain the row."""
        row_filter = RowFilter(field="dept", operator=FilterOperator.equals, value="hr")
        object.__setattr__(row_filter, "operator", "startsWithIgnoreCase")

        assert _filtered([{"dept": "hr"}], row_filter) == []

    def test_dotted_filter_field_matches_a_bare_key(self) -> None:
        kept = _filtered(
            [{"region": "us-east"}],
            RowFilter(field="patients.region", operator=FilterOperator.equals, value="us-east"),
        )

        assert kept == [{"region": "us-east"}]

    def test_filters_and_together(self) -> None:
        rows = [
            {"region": "us-east", "status": "active"},
            {"region": "us-east", "status": "deleted"},
            {"region": "eu-west", "status": "active"},
        ]

        kept = _filtered(
            rows,
            RowFilter(field="region", operator=FilterOperator.equals, value="us-east"),
            RowFilter(field="status", operator=FilterOperator.not_equals, value="deleted"),
        )

        assert kept == [{"region": "us-east", "status": "active"}]

    def test_absent_row_filters_returns_every_row(self) -> None:
        rows = [{"id": 1}]

        assert apply_row_filters(rows, _policy()) == rows
        assert apply_row_filters(rows, _policy(object_rules=ObjectRules())) == rows


class TestTagFilterBranches:
    def _tagged(self, rows: list[dict], tag_rules: TagRules) -> list[dict]:
        return filter_by_tags(rows, _policy(object_rules=ObjectRules(tag_rules=tag_rules)))

    def test_empty_allowed_tags_denies_every_record(self) -> None:
        """Spec section 3: `[]` is deny-all, never "no restriction"."""
        assert self._tagged([{"id": 1, "tags": ["public"]}], TagRules(allowed_tags=[])) == []

    def test_none_allowed_tags_is_unrestricted(self) -> None:
        rows = [{"id": 1, "tags": ["anything"]}]

        assert self._tagged(rows, TagRules(allowed_tags=None)) == rows

    def test_denied_takes_precedence_over_allowed(self) -> None:
        rows = [{"id": 1, "tags": ["public", "secret"]}]

        assert self._tagged(rows, TagRules(allowed_tags=["public"], denied_tags=["secret"])) == []

    def test_record_without_a_tags_key_is_dropped_by_an_allow_list(self) -> None:
        assert self._tagged([{"id": 1}], TagRules(allowed_tags=["public"])) == []

    def test_record_without_a_tags_key_survives_a_denylist(self) -> None:
        rows = [{"id": 1}]

        assert self._tagged(rows, TagRules(denied_tags=["secret"])) == rows

    def test_empty_denied_tags_denies_nothing(self) -> None:
        rows = [{"id": 1, "tags": ["public"]}]

        assert self._tagged(rows, TagRules(denied_tags=[])) == rows

    def test_absent_tag_rules_returns_every_record(self) -> None:
        rows = [{"id": 1, "tags": ["secret"]}]

        assert filter_by_tags(rows, _policy()) == rows
        assert filter_by_tags(rows, _policy(object_rules=ObjectRules())) == rows


class TestTagExtractionShapes:
    """Connector spec section 7: tag extraction must be robust.

    Classification IS tags -- there is no separate classification construct -- so
    tag filtering is the whole knowledge-base confidentiality control, and a
    literal lower-case `tags` lookup silently failed to enforce it on most real
    providers. Of five chunks tagged `secret` under `tags`, `Tags`,
    `metadata.tags`, `labels`, and a scalar `classification`, a naive lookup
    dropped one. Each case below is a provider shape that must now be recognized.
    """

    def _kept(self, record: dict, **tag_kwargs: object) -> bool:
        rules = TagRules(**tag_kwargs)  # type: ignore[arg-type]
        policy = _policy(object_rules=ObjectRules(tag_rules=rules))
        return filter_by_tags([record], policy) == [record]

    @pytest.mark.parametrize(
        "record",
        [
            pytest.param({"tags": ["secret"]}, id="tags-list"),
            pytest.param({"Tags": ["secret"]}, id="cased-key"),
            pytest.param({"metadata": {"tags": ["secret"]}}, id="nested-in-metadata"),
            pytest.param({"labels": ["secret"]}, id="alternate-key-labels"),
            pytest.param({"classification": "secret"}, id="scalar-classification"),
            pytest.param({"tags": "secret"}, id="scalar-tags"),
            pytest.param({"METADATA": {"LABELS": "secret"}}, id="nested-cased-scalar"),
            pytest.param({"chunks": [{"tags": ["secret"]}]}, id="inside-an-array"),
        ],
    )
    def test_a_denied_tag_is_found_in_every_provider_shape(self, record: dict) -> None:
        assert not self._kept(record, denied_tags=["secret"])

    def test_the_recognized_key_set_is_closed(self) -> None:
        """A key outside the documented set is ordinary data, not security metadata.

        The set is exactly the shapes connector spec section 7 names. Widening it is
        not automatically safer: an unrelated field whose value happens to appear in
        `allowedTags` would *admit* a record the allow-list would otherwise have
        dropped as untagged, so an over-broad set fails open just as a too-narrow one
        fails to enforce. Both directions are asserted so a future addition to
        `_TAG_KEYS` is a deliberate, reviewed change rather than a silent one.
        """
        assert self._kept({"categories": ["secret"]}, denied_tags=["secret"])
        assert not self._kept({"categories": ["public"]}, allowed_tags=["public"])

    def test_tag_values_compare_case_insensitively_in_both_directions(self) -> None:
        """Connector spec section 7: `deniedTags: ["Secret"]` MUST drop `secret`."""
        assert not self._kept({"tags": ["secret"]}, denied_tags=["Secret"])
        assert not self._kept({"tags": ["SECRET"]}, denied_tags=["secret"])
        assert not self._kept({"classification": "Secret"}, denied_tags=["sEcReT"])

        # And the same folding admits a record through an allow-list.
        assert self._kept({"tags": ["PUBLIC"]}, allowed_tags=["public"])

    def test_a_scalar_counts_as_a_one_element_tag_list(self) -> None:
        """A scalar tag satisfies an allow-list exactly as a one-element list does."""
        assert self._kept({"tags": "public"}, allowed_tags=["public"])
        assert self._kept({"classification": "public"}, allowed_tags=["public"])
        assert self._kept({"tags": ["public"]}, allowed_tags=["public"])

    def test_a_non_string_tag_value_contributes_no_tag(self) -> None:
        """A non-string cannot match a string tag without a per-language cast.

        `str(True)` is "True" in Python and "true" in JavaScript, so admitting
        non-strings would make a confidentiality decision depend on the host
        language. Contributing no tag fails closed under an allow-list.
        """
        assert not self._kept({"tags": 42}, allowed_tags=["42"])
        assert self._kept({"tags": 42}, denied_tags=["42"])
        assert not self._kept({"tags": [True]}, allowed_tags=["true", "True"])

    def test_a_recognized_key_holding_a_mapping_is_still_walked(self) -> None:
        """`{"tags": {"tags": [...]}}` must not hide a tag inside a tag key."""
        assert not self._kept({"tags": {"tags": ["secret"]}}, denied_tags=["secret"])

    def test_untagged_handling_is_unchanged(self) -> None:
        """Enforcement spec section 4: dropped under an allow-list, kept under a denylist.

        A classification that cannot be established cannot be shown to be
        permitted -- but a denylist alone gives no grounds to drop it.
        """
        for untagged in ({"id": 1}, {"id": 1, "tags": []}, {"id": 1, "tags": 42}):
            assert not self._kept(untagged, allowed_tags=["public"])
            assert self._kept(untagged, denied_tags=["secret"])

    def test_denied_still_beats_allowed_across_different_keys(self) -> None:
        record = {"tags": ["public"], "classification": "secret"}

        assert not self._kept(record, allowed_tags=["public"], denied_tags=["secret"])


class TestMaskingBranches:
    def test_unknown_mask_type_is_treated_as_redact(self) -> None:
        """Spec section 6: an unrecognized maskType must not return the raw value."""

        class FutureMaskType:
            pass

        rule = MaskingRule(field="ssn", mask_type=FutureMaskType())  # type: ignore[arg-type]
        record = {"ssn": "111-22-3333"}
        policy = _policy(object_rules=ObjectRules(field_rules=FieldRules(masked_fields=[rule])))

        assert apply_field_masking(record, policy)["ssn"] == "[REDACTED]"

    def test_unknown_mask_type_ranks_most_restrictive(self) -> None:
        """It must not be beaten by a known-but-weaker type when merging."""

        class FutureMaskType:
            pass

        assert mask_restrictiveness(FutureMaskType()) > mask_restrictiveness(MaskType.null)

    def test_restrictiveness_property_matches_the_function(self) -> None:
        for mask_type in MaskType:
            assert mask_type.restrictiveness == mask_restrictiveness(mask_type)

    def test_restrictiveness_ranking_puts_null_above_partial(self) -> None:
        """Spec section 6: merging null with partial must not yield partial."""
        assert MaskType.null.restrictiveness > MaskType.redact.restrictiveness
        assert MaskType.redact.restrictiveness > MaskType.full.restrictiveness
        assert MaskType.full.restrictiveness > MaskType.hash.restrictiveness
        assert MaskType.hash.restrictiveness > MaskType.partial.restrictiveness

    def test_none_value_is_left_as_none(self) -> None:
        rule = MaskingRule(field="ssn", mask_type=MaskType.full)
        policy = _policy(object_rules=ObjectRules(field_rules=FieldRules(masked_fields=[rule])))

        assert apply_field_masking({"ssn": None}, policy)["ssn"] is None

    def test_partial_showing_the_whole_value_degrades_to_a_full_mask(self) -> None:
        """Spec section 6: showFirst + showLast >= len must not disclose the value."""
        rule = MaskingRule(
            field="ssn",
            mask_type=MaskType.partial,
            parameters=MaskingParameters(show_first=5, show_last=5),
        )
        policy = _policy(object_rules=ObjectRules(field_rules=FieldRules(masked_fields=[rule])))

        assert apply_field_masking({"ssn": "12345"}, policy)["ssn"] == "*****"

    def test_negative_partial_parameters_degrade_to_a_full_mask(self) -> None:
        rule = MaskingRule(
            field="ssn",
            mask_type=MaskType.partial,
            parameters=MaskingParameters(show_first=-1, show_last=0),
        )
        policy = _policy(object_rules=ObjectRules(field_rules=FieldRules(masked_fields=[rule])))

        assert apply_field_masking({"ssn": "12345"}, policy)["ssn"] == "*****"

    def test_partial_with_no_parameters_masks_everything(self) -> None:
        rule = MaskingRule(field="ssn", mask_type=MaskType.partial)
        policy = _policy(object_rules=ObjectRules(field_rules=FieldRules(masked_fields=[rule])))

        assert apply_field_masking({"ssn": "12345"}, policy)["ssn"] == "*****"

    def test_partial_shows_only_the_configured_edges(self) -> None:
        rule = MaskingRule(
            field="ssn",
            mask_type=MaskType.partial,
            parameters=MaskingParameters(show_first=1, show_last=2, mask_char="#"),
        )
        policy = _policy(object_rules=ObjectRules(field_rules=FieldRules(masked_fields=[rule])))

        assert apply_field_masking({"ssn": "123456789"}, policy)["ssn"] == "1######89"

    def test_hash_is_a_stable_16_hex_digest(self) -> None:
        rule = MaskingRule(field="email", mask_type=MaskType.hash)
        policy = _policy(object_rules=ObjectRules(field_rules=FieldRules(masked_fields=[rule])))

        first = apply_field_masking({"email": "a@b.c"}, policy)["email"]
        second = apply_field_masking({"email": "a@b.c"}, policy)["email"]

        assert first == second
        assert len(first) == 16
        assert apply_field_masking({"email": "other@b.c"}, policy)["email"] != first

    # -- hash algorithm: the cross-language join key (spec section 6) --
    #
    # The `algorithm` parameter used to be ignored here, so a policy asking for
    # sha512 got a SHA-256 digest -- a different pseudonym than TypeScript computed
    # for the same value, so every cross-service join on the masked column silently
    # failed while both sides looked correct in isolation.

    # Masked value of "123-45-6789" per algorithm. These are known-answers shared
    # with the TypeScript and .NET suites: the same literals appear in
    # enforcement-branches.test.ts and EnforcementBranchCoverageTests.cs, so a
    # change that makes one SDK disagree fails in that SDK's own suite rather than
    # only in a cross-language integration test nobody runs.
    KNOWN_ANSWERS = {
        "sha256": "01a54629efb95228",
        "sha512": "fbe47783b1d59d46",
        "blake2b": "ddefd0f544edbef0",
    }

    def _hash_mask(self, value: str, algorithm: str | None) -> object:
        parameters = MaskingParameters(algorithm=algorithm) if algorithm else None
        rule = MaskingRule(field="ssn", mask_type=MaskType.hash, parameters=parameters)
        policy = _policy(object_rules=ObjectRules(field_rules=FieldRules(masked_fields=[rule])))
        return apply_field_masking({"ssn": value}, policy)["ssn"]

    @pytest.mark.parametrize("algorithm", ["sha256", "sha512", "blake2b"])
    def test_hash_matches_the_cross_sdk_known_answer(self, algorithm: str) -> None:
        """Every schema-permitted algorithm produces the digest the other SDKs do."""
        assert self._hash_mask("123-45-6789", algorithm) == self.KNOWN_ANSWERS[algorithm]

    def test_hash_defaults_to_sha256_when_algorithm_is_absent(self) -> None:
        assert self._hash_mask("123-45-6789", None) == self.KNOWN_ANSWERS["sha256"]

    def test_each_algorithm_yields_a_distinct_digest(self) -> None:
        """Guards the defect directly: the parameter must actually be read.

        Ignoring it produced three identical digests, which is exactly what the
        known-answer table would look like if `algorithm` were dropped again and the
        expected values were regenerated from the broken implementation.
        """
        digests = {self._hash_mask("123-45-6789", a) for a in self.KNOWN_ANSWERS}
        assert len(digests) == 3

    def test_blake2b_is_the_512_bit_variant(self) -> None:
        """``blake2b`` means BLAKE2b-512, matching Node's ``blake2b512``.

        ``hashlib.blake2b`` accepts any digest size from 1 to 64 bytes and a
        different size is a different hash, so this pins the 64-byte variant rather
        than trusting the CPython default to stay put.
        """
        import hashlib

        expected = hashlib.blake2b(b"123-45-6789", digest_size=64).hexdigest()[:16]
        assert self._hash_mask("123-45-6789", "blake2b") == expected

    @pytest.mark.parametrize(
        "algorithm",
        [
            "md5",  # available in hashlib, but not permitted by the schema
            "sha1",
            "blake2b512",  # Node's spelling; not the schema value
            "SHA256",  # wrong case
            "sha-256",
            "not-a-real-algorithm",
            " sha256",
        ],
    )
    def test_an_unpermitted_algorithm_redacts_rather_than_leaking(self, algorithm: str) -> None:
        """An algorithm outside the schema fails closed as ``redact`` (spec section 6).

        It must not raise (that would abort the whole result pass), must not return
        the original, and must not silently substitute sha256 -- a substituted digest
        looks like a valid pseudonym while failing to join. Note ``md5`` and ``sha1``
        are rejected despite being available: resolving the parameter through
        ``hashlib.new`` would have accepted both.
        """
        assert self._hash_mask("123-45-6789", algorithm) == "[REDACTED]"

    def test_hash_of_a_non_string_coerces_before_hashing(self) -> None:
        """A numeric field still yields 16 hex chars, per algorithm."""
        for algorithm in self.KNOWN_ANSWERS:
            masked = self._hash_mask(12345, algorithm)  # type: ignore[arg-type]
            assert isinstance(masked, str)
            assert len(masked) == 16
            assert int(masked, 16) >= 0  # lower-case hex

    def test_null_mask_erases_the_value(self) -> None:
        rule = MaskingRule(field="ssn", mask_type=MaskType.null)
        policy = _policy(object_rules=ObjectRules(field_rules=FieldRules(masked_fields=[rule])))

        assert apply_field_masking({"ssn": "111-22-3333"}, policy)["ssn"] is None

    def test_most_restrictive_rule_wins_for_one_key(self) -> None:
        policy = _policy(
            object_rules=ObjectRules(
                field_rules=FieldRules(
                    masked_fields=[
                        MaskingRule(
                            field="ssn",
                            mask_type=MaskType.partial,
                            parameters=MaskingParameters(show_last=4),
                        ),
                        MaskingRule(field="ssn", mask_type=MaskType.null),
                    ]
                )
            )
        )

        assert apply_field_masking({"ssn": "111-22-3333"}, policy)["ssn"] is None

    def test_masking_recurses_into_lists_of_objects(self) -> None:
        rule = MaskingRule(field="ssn", mask_type=MaskType.redact)
        policy = _policy(object_rules=ObjectRules(field_rules=FieldRules(masked_fields=[rule])))

        record = {"people": [{"ssn": "1"}, {"nested": {"ssn": "2"}}]}
        masked = apply_field_masking(record, policy)

        assert masked["people"][0]["ssn"] == "[REDACTED]"
        assert masked["people"][1]["nested"]["ssn"] == "[REDACTED]"

    def test_caller_record_is_never_mutated(self) -> None:
        rule = MaskingRule(field="ssn", mask_type=MaskType.redact)
        policy = _policy(object_rules=ObjectRules(field_rules=FieldRules(masked_fields=[rule])))
        record = {"nested": {"ssn": "111-22-3333"}}

        apply_field_masking(record, policy)

        assert record["nested"]["ssn"] == "111-22-3333"

    def test_no_rules_returns_an_equal_copy(self) -> None:
        record = {"ssn": "111-22-3333"}

        result = apply_field_masking(record, _policy())

        assert result == record
        assert result is not record

    def test_apply_masking_handles_a_list_and_a_scalar(self) -> None:
        """The shared tree walker is shape-agnostic."""
        rule = MaskingRule(field="ssn", mask_type=MaskType.redact)
        policy = _policy(object_rules=ObjectRules(field_rules=FieldRules(masked_fields=[rule])))

        assert apply_masking([{"ssn": "1"}], policy) == [{"ssn": "[REDACTED]"}]
        assert apply_masking("scalar", policy) == "scalar"

    def test_apply_masking_without_rules_returns_a_copy(self) -> None:
        body = {"results": [{"ssn": "1"}]}

        result = apply_masking(body, _policy())

        assert result == body
        assert result is not body


class TestHiddenAndAllowedFieldBranches:
    def test_strip_hidden_fields_without_patterns_returns_a_copy(self) -> None:
        record = {"ssn": "1"}

        result = strip_hidden_fields(record, _policy())

        assert result == record
        assert result is not record

    def test_strip_hidden_fields_recurses_into_lists(self) -> None:
        policy = _policy(object_rules=ObjectRules(field_rules=FieldRules(hidden_fields=["ssn"])))

        result = strip_hidden_fields({"rows": [{"ssn": "1", "id": 2}]}, policy)

        assert result == {"rows": [{"id": 2}]}

    def test_strip_hidden_fields_leaves_a_scalar_alone(self) -> None:
        policy = _policy(object_rules=ObjectRules(field_rules=FieldRules(hidden_fields=["ssn"])))

        assert strip_hidden_fields("a-scalar", policy) == "a-scalar"

    def test_project_allowed_fields_none_is_unrestricted(self) -> None:
        record = {"id": 1, "ssn": "x"}

        assert project_allowed_fields(record, _policy()) == record

    def test_project_allowed_fields_empty_denies_every_field(self) -> None:
        policy = _policy(object_rules=ObjectRules(field_rules=FieldRules(allowed_fields=[])))

        assert project_allowed_fields({"id": 1}, policy) == {}

    def test_project_allowed_fields_on_a_single_record(self) -> None:
        policy = _policy(object_rules=ObjectRules(field_rules=FieldRules(allowed_fields=["id"])))

        assert project_allowed_fields({"id": 1, "ssn": "x"}, policy) == {"id": 1}

    def test_project_allowed_fields_preserves_non_records_in_a_list(self) -> None:
        policy = _policy(object_rules=ObjectRules(field_rules=FieldRules(allowed_fields=["id"])))

        assert project_allowed_fields([{"id": 1, "ssn": "x"}, "scalar"], policy) == [{"id": 1}, "scalar"]

    def test_project_allowed_fields_leaves_a_scalar_alone(self) -> None:
        policy = _policy(object_rules=ObjectRules(field_rules=FieldRules(allowed_fields=["id"])))

        assert project_allowed_fields("a-scalar", policy) == "a-scalar"

    def test_qualified_rule_matches_a_bare_key_and_the_reverse(self) -> None:
        """Spec section 4: matching works in both directions, case-insensitively."""
        qualified = _policy(
            object_rules=ObjectRules(field_rules=FieldRules(hidden_fields=["patients.SSN"]))
        )
        bare = _policy(object_rules=ObjectRules(field_rules=FieldRules(hidden_fields=["ssn"])))

        assert strip_hidden_fields({"ssn": "x", "id": 1}, qualified) == {"id": 1}
        assert strip_hidden_fields({"patients.ssn": "x", "id": 1}, bare) == {"id": 1}


class TestResultLimitBranches:
    def test_absent_limits_returns_every_row(self) -> None:
        rows = [{"id": 1}, {"id": 2}]

        assert apply_result_limit(rows, _policy()) == rows
        assert apply_result_limit(rows, _policy(limits=PolicyLimits())) == rows

    def test_zero_limit_returns_nothing(self) -> None:
        assert apply_result_limit([{"id": 1}], _policy(limits=PolicyLimits(max_results=0))) == []

    def test_limit_larger_than_the_result_set_is_a_no_op(self) -> None:
        rows = [{"id": 1}]

        assert apply_result_limit(rows, _policy(limits=PolicyLimits(max_results=10))) == rows


class TestResultShapeClassification:
    @pytest.mark.parametrize(
        "value,expected",
        [
            ({"id": 1}, "record"),
            ([{"id": 1}], "records"),
            ([], "records"),
        ],
    )
    def test_enforceable_shapes(self, value: object, expected: str) -> None:
        assert classify_result_shape(value) == expected

    @pytest.mark.parametrize(
        "value",
        [None, "scalar", b"bytes", bytearray(b"x"), 5, 5.0, True, [1, 2], [{"a": 1}, "x"], object()],
    )
    def test_unenforceable_shapes_classify_as_none(self, value: object) -> None:
        assert classify_result_shape(value) is None

    @pytest.mark.parametrize(
        "value,fragment",
        [
            (None, "None"),
            ({"a": 1}, "record"),
            ("s", "scalar"),
            (b"s", "scalar"),
            (bytearray(b"s"), "scalar"),
            (5, "scalar"),
            (5.0, "scalar"),
            (True, "scalar"),
            ([{"a": 1}], "list of records"),
            ([1, 2], "not records"),
            (object(), "not a record or list of records"),
        ],
    )
    def test_describe_result_shape_names_the_observed_shape(
        self, value: object, fragment: str
    ) -> None:
        """The denial message must be actionable, naming what was actually seen."""
        assert fragment in describe_result_shape(value)

    def test_describe_lists_every_offending_type_sorted(self) -> None:
        description = describe_result_shape([{"a": 1}, "s", 5])

        assert "int" in description and "str" in description
        assert description.index("int") < description.index("str")


class TestResultPipelineBranches:
    def test_unenforceable_shape_is_denied_with_an_actionable_message(self) -> None:
        """Spec section 5: fail closed on a shape the policy cannot be applied to."""
        with pytest.raises(UnenforceableResultError) as exc_info:
            apply_result_pipeline((n for n in range(3)), _policy())

        message = str(exc_info.value)
        assert "generator" in message
        assert "allow_unenforceable_shapes=True" in message

    def test_unenforceable_error_is_a_permission_error(self) -> None:
        """Wrappers that deny on PermissionError must fail closed unmodified."""
        assert issubclass(UnenforceableResultError, PermissionError)

    def test_single_record_runs_the_full_pipeline(self) -> None:
        """Spec section 4: a get-by-id tool must not skip row/tag filters."""
        policy = _policy(
            object_rules=ObjectRules(tag_rules=TagRules(denied_tags=["secret"]))
        )

        assert apply_result_pipeline({"id": 1, "tags": ["secret"]}, policy) is None

    def test_single_record_that_survives_is_returned_as_a_record(self) -> None:
        policy = _policy(object_rules=ObjectRules(field_rules=FieldRules(hidden_fields=["ssn"])))

        assert apply_result_pipeline({"id": 1, "ssn": "x"}, policy) == {"id": 1}

    def test_hidden_field_removal_precedes_masking(self) -> None:
        """A field that is both hidden and masked is removed, not masked."""
        policy = _policy(
            object_rules=ObjectRules(
                field_rules=FieldRules(
                    hidden_fields=["ssn"],
                    masked_fields=[MaskingRule(field="ssn", mask_type=MaskType.hash)],
                )
            )
        )

        assert apply_result_pipeline([{"id": 1, "ssn": "x"}], policy) == [{"id": 1}]

    def test_limit_is_applied_after_filtering(self) -> None:
        """Filtering must never starve the limit (spec section 4)."""
        policy = _policy(
            object_rules=ObjectRules(
                row_filters=[
                    RowFilter(field="status", operator=FilterOperator.not_equals, value="deleted")
                ]
            ),
            limits=PolicyLimits(max_results=2),
        )
        rows = [
            {"id": 1, "status": "deleted"},
            {"id": 2, "status": "active"},
            {"id": 3, "status": "active"},
        ]

        assert [r["id"] for r in apply_result_pipeline(rows, policy)] == [2, 3]

    def test_empty_list_stays_an_empty_list(self) -> None:
        assert apply_result_pipeline([], _policy()) == []


class TestValidateAccessBranches:
    def test_can_query_false_denies_regardless_of_object_rules(self) -> None:
        result = validate_access("patients", _policy(can_query=False))

        assert result.allowed is False
        assert result.reason == "query not permitted"

    def test_absent_object_rules_allows(self) -> None:
        assert validate_access("patients", _policy()).allowed is True

    def test_hidden_object_takes_precedence_over_the_allow_list(self) -> None:
        policy = _policy(
            object_rules=ObjectRules(allowed_objects=["patients"], hidden_objects=["patients"])
        )

        result = validate_access("patients", policy)

        assert result.allowed is False
        assert result.reason == "object is hidden"

    def test_object_outside_the_allow_list_is_denied(self) -> None:
        policy = _policy(object_rules=ObjectRules(allowed_objects=["patients"]))

        result = validate_access("billing", policy)

        assert result.allowed is False
        assert result.reason == "object not in allowed set"

    def test_empty_allow_list_denies_every_object(self) -> None:
        policy = _policy(object_rules=ObjectRules(allowed_objects=[]))

        assert validate_access("patients", policy).allowed is False

    def test_glob_allow_list_matches(self) -> None:
        policy = _policy(object_rules=ObjectRules(allowed_objects=["patient*"]))

        assert validate_access("patients", policy).allowed is True

    def test_object_rules_without_either_list_allows(self) -> None:
        assert validate_access("patients", _policy(object_rules=ObjectRules())).allowed is True

    def test_non_matching_hidden_pattern_falls_through_to_allowed(self) -> None:
        policy = _policy(object_rules=ObjectRules(hidden_objects=["billing*"]))

        assert validate_access("patients", policy).allowed is True


class TestValidateFieldAccessBranches:
    def test_hidden_field_is_denied_even_when_allowed(self) -> None:
        policy = _policy(
            object_rules=ObjectRules(
                field_rules=FieldRules(allowed_fields=["ssn", "id"], hidden_fields=["ssn"])
            )
        )

        result = validate_field_access(["ssn", "id"], policy)

        assert result.denied == ["ssn"]
        assert result.allowed == ["id"]

    def test_field_outside_the_allow_list_is_denied(self) -> None:
        policy = _policy(object_rules=ObjectRules(field_rules=FieldRules(allowed_fields=["id"])))

        result = validate_field_access(["id", "ssn"], policy)

        assert result.allowed == ["id"]
        assert result.denied == ["ssn"]

    def test_absent_field_rules_allows_everything(self) -> None:
        result = validate_field_access(["id", "ssn"], _policy())

        assert result.allowed == ["id", "ssn"]
        assert result.denied == []

    def test_empty_allow_list_denies_every_field(self) -> None:
        policy = _policy(object_rules=ObjectRules(field_rules=FieldRules(allowed_fields=[])))

        result = validate_field_access(["id"], policy)

        assert result.denied == ["id"]

    def test_empty_field_list_yields_empty_results(self) -> None:
        result = validate_field_access([], _policy())

        assert result.allowed == []
        assert result.denied == []


class TestPreExecutionMatchingIsPlatformIndependent:
    """The pre-execution validators used bare `fnmatch`, which normcases.

    `fnmatch.fnmatch` applies `os.path.normcase`: lower-casing on Windows, a no-op
    everywhere else. So `hiddenObjects: ["Billing"]` against a query for
    `billing` was DENIED on Windows and ALLOWED on macOS/Linux -- the same signed
    policy producing two different access decisions. The post-execution path
    already matched case-insensitively via `_field_name_matches`; these pin the
    same behaviour for the three pre-execution validators, so the assertions hold
    on every platform rather than passing by accident on this one.
    """

    def test_hidden_object_matches_regardless_of_case(self) -> None:
        policy = _policy(object_rules=ObjectRules(hidden_objects=["Billing"]))

        result = validate_access("billing", policy)

        assert result.allowed is False
        assert result.reason == "object is hidden"

    def test_hidden_object_pattern_matches_regardless_of_case(self) -> None:
        policy = _policy(object_rules=ObjectRules(hidden_objects=["Billing_*"]))

        assert validate_access("BILLING_internal", policy).allowed is False

    def test_allowed_object_matches_regardless_of_case(self) -> None:
        policy = _policy(object_rules=ObjectRules(allowed_objects=["Patients"]))

        assert validate_access("patients", policy).allowed is True
        assert validate_access("PATIENTS", policy).allowed is True

    def test_a_genuinely_different_object_is_still_denied(self) -> None:
        """Case-insensitivity must not degrade into matching everything."""
        policy = _policy(object_rules=ObjectRules(allowed_objects=["Patients"]))

        assert validate_access("billing", policy).allowed is False

    def test_hidden_field_matches_regardless_of_case(self) -> None:
        policy = _policy(
            object_rules=ObjectRules(field_rules=FieldRules(hidden_fields=["SSN"]))
        )

        result = validate_field_access(["ssn", "id"], policy)

        assert result.denied == ["ssn"]
        assert result.allowed == ["id"]

    def test_allowed_field_matches_regardless_of_case(self) -> None:
        policy = _policy(
            object_rules=ObjectRules(field_rules=FieldRules(allowed_fields=["ID", "Name"]))
        )

        result = validate_field_access(["id", "name", "ssn"], policy)

        assert result.allowed == ["id", "name"]
        assert result.denied == ["ssn"]

    def test_hidden_endpoint_matches_regardless_of_case(self) -> None:
        policy = _policy(
            object_rules=ObjectRules(endpoint_rules=EndpointRules(hidden_endpoints=["/Admin/*"]))
        )

        result = validate_endpoint("/admin/users", "GET", policy)

        assert result.allowed is False
        assert result.reason == "endpoint is hidden"

    def test_allowed_endpoint_matches_regardless_of_case(self) -> None:
        policy = _policy(
            object_rules=ObjectRules(endpoint_rules=EndpointRules(allowed_endpoints=["/Drug/*"]))
        )

        assert validate_endpoint("/drug/event.json", "GET", policy).allowed is True

    def test_a_genuinely_different_endpoint_is_still_denied(self) -> None:
        policy = _policy(
            object_rules=ObjectRules(endpoint_rules=EndpointRules(allowed_endpoints=["/Drug/*"]))
        )

        assert validate_endpoint("/food/enforcement.json", "GET", policy).allowed is False


class TestValidateEndpointBranches:
    def test_can_query_false_denies(self) -> None:
        result = validate_endpoint("/drug/event.json", "GET", _policy(can_query=False))

        assert result.allowed is False
        assert result.reason == "query not permitted"

    def test_absent_endpoint_rules_allows(self) -> None:
        assert validate_endpoint("/anything", "GET", _policy()).allowed is True
        assert validate_endpoint("/anything", "GET", _policy(object_rules=ObjectRules())).allowed is True

    def test_hidden_endpoint_takes_precedence(self) -> None:
        policy = _policy(
            object_rules=ObjectRules(
                endpoint_rules=EndpointRules(
                    allowed_endpoints=["/food/*"], hidden_endpoints=["/food/*"]
                )
            )
        )

        result = validate_endpoint("/food/enforcement.json", "GET", policy)

        assert result.allowed is False
        assert result.reason == "endpoint is hidden"

    def test_endpoint_outside_the_allow_list_is_denied(self) -> None:
        policy = _policy(
            object_rules=ObjectRules(endpoint_rules=EndpointRules(allowed_endpoints=["/drug/*"]))
        )

        result = validate_endpoint("/food/enforcement.json", "GET", policy)

        assert result.reason == "endpoint not in allowed set"

    def test_method_not_in_the_allow_list_is_denied(self) -> None:
        policy = _policy(
            object_rules=ObjectRules(endpoint_rules=EndpointRules(allowed_methods=["GET"]))
        )

        result = validate_endpoint("/drug/event.json", "POST", policy)

        assert result.reason == "method not allowed"

    def test_method_matching_is_case_insensitive(self) -> None:
        policy = _policy(
            object_rules=ObjectRules(endpoint_rules=EndpointRules(allowed_methods=["get"]))
        )

        assert validate_endpoint("/drug/event.json", "GET", policy).allowed is True
        assert validate_endpoint("/drug/event.json", "get", policy).allowed is True

    def test_empty_allowed_methods_denies_every_method(self) -> None:
        policy = _policy(
            object_rules=ObjectRules(endpoint_rules=EndpointRules(allowed_methods=[]))
        )

        assert validate_endpoint("/drug/event.json", "GET", policy).allowed is False

    def test_endpoint_rules_without_lists_allows_reads(self) -> None:
        policy = _policy(object_rules=ObjectRules(endpoint_rules=EndpointRules()))

        assert validate_endpoint("/anything", "GET", policy).allowed is True

    def test_omitted_allowed_methods_defaults_to_read_only_methods(self) -> None:
        """The schema documents the default; treating omitted as unrestricted is fail-open.

        "If omitted, defaults to read-only methods: GET, HEAD, OPTIONS" -- so a
        policy author who wrote no allowedMethods was told writes were already
        blocked. The previous behaviour permitted DELETE/POST/PUT/PATCH.
        """
        policy = _policy(read_only=False, object_rules=ObjectRules(endpoint_rules=EndpointRules()))

        for method in ("GET", "HEAD", "OPTIONS"):
            assert validate_endpoint("/anything", method, policy).allowed is True
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            result = validate_endpoint("/anything", method, policy)
            assert result.allowed is False
            assert result.reason == "method not allowed"

    def test_allowed_endpoint_and_method_together_allow(self) -> None:
        policy = _policy(
            read_only=False,
            object_rules=ObjectRules(
                endpoint_rules=EndpointRules(
                    allowed_endpoints=["/drug/*"], allowed_methods=["GET", "POST"]
                )
            ),
        )

        assert validate_endpoint("/drug/event.json", "POST", policy).allowed is True

    def test_read_only_permission_denies_a_write_method_it_was_granted(self) -> None:
        """readOnly was merged (OR-folded) and then never consulted by any decision.

        A policy that lists DELETE in allowedMethods while declaring itself
        read-only is contradictory; the restrictive half wins.
        """
        policy = _policy(
            read_only=True,
            object_rules=ObjectRules(
                endpoint_rules=EndpointRules(allowed_methods=["GET", "DELETE", "POST"])
            ),
        )

        result = validate_endpoint("/api/x", "DELETE", policy)

        assert result.allowed is False
        assert result.reason == "method not allowed on a read-only policy"
        assert validate_endpoint("/api/x", "GET", policy).allowed is True

    def test_absent_read_only_takes_its_restrictive_schema_default(self) -> None:
        """Spec section 8: an absent readOnly defaults to true before folding."""
        policy = _policy(
            read_only=None,
            object_rules=ObjectRules(endpoint_rules=EndpointRules(allowed_methods=["POST"])),
        )

        result = validate_endpoint("/api/x", "POST", policy)

        assert result.allowed is False
        assert result.reason == "method not allowed on a read-only policy"

    def test_explicit_allowed_methods_denial_keeps_its_specific_reason(self) -> None:
        """A method absent from allowedMethods reports that, not the readOnly gate."""
        policy = _policy(
            read_only=True,
            object_rules=ObjectRules(endpoint_rules=EndpointRules(allowed_methods=["GET"])),
        )

        assert validate_endpoint("/api/x", "DELETE", policy).reason == "method not allowed"


class TestSigningBranches:
    def test_hmac_sha512_signs_and_verifies(self) -> None:
        context = build_security_context("u", "t", [_policy()], ttl=timedelta(hours=1))

        signed = sign_context(context, "key", algorithm=SigningAlgorithm.hmac_sha512)

        assert signed.algorithm is SigningAlgorithm.hmac_sha512
        assert validate_context(signed, "key") is True
        assert validate_context(signed, "other-key") is False

    def test_ed25519_is_refused_rather_than_silently_unsigned(self) -> None:
        """An unimplemented algorithm must raise, not produce a weak signature."""
        context = build_security_context("u", "t", [_policy()], ttl=timedelta(hours=1))

        with pytest.raises(NotImplementedError, match="Ed25519"):
            sign_context(context, "key", algorithm=SigningAlgorithm.ed25519)

    def test_context_without_a_signature_does_not_validate(self) -> None:
        context = build_security_context("u", "t", [_policy()], ttl=timedelta(hours=1))

        assert validate_context(context, "key") is False

    def test_context_with_a_signature_but_no_algorithm_does_not_validate(self) -> None:
        context = sign_context(
            build_security_context("u", "t", [_policy()], ttl=timedelta(hours=1)), "key"
        )
        context.algorithm = None

        assert validate_context(context, "key") is False

    def test_build_security_context_with_no_policies_denies_all(self) -> None:
        context = build_security_context("u", "t", [], ttl=timedelta(hours=1))

        assert context.effective_policy.permissions.can_query is False
        assert context.effective_policy.permissions.read_only is True

    def test_build_security_context_stamps_the_principal_onto_the_policy(self) -> None:
        context = build_security_context("user-9", "tenant-9", [_policy()], ttl=timedelta(hours=1))

        assert context.effective_policy.user_id == "user-9"
        assert context.effective_policy.tenant_id == "tenant-9"
        assert context.issued_at is not None and context.issued_at.endswith("Z")
        assert context.expires_at is not None and context.expires_at.endswith("Z")

    def test_build_security_context_refuses_more_than_one_policy(self) -> None:
        """Multiple policies must raise, never be truncated to the first.

        A SecurityContext carries one policy and enforcement reads it without being
        told which data source the call targets. This previously kept ``policies[0]``
        and discarded the rest silently, so a caller wiring up a database policy and
        an API policy got a context governing only the database -- with no error, no
        warning, and no way to detect that the API was governed by nothing.
        """
        db_policy = _policy()
        api_policy = _policy()

        with pytest.raises(ValueError, match="at most one effective policy, got 2"):
            build_security_context("u", "t", [db_policy, api_policy], ttl=timedelta(hours=1))

    def test_build_security_context_refusal_names_the_remedy(self) -> None:
        """The refusal must tell the caller what to do instead, not just say no."""
        with pytest.raises(ValueError, match="one context per data source"):
            build_security_context("u", "t", [_policy(), _policy(), _policy()])

    def test_build_security_context_accepts_exactly_one_policy(self) -> None:
        """The single-policy case is the supported one and must not be caught by the guard."""
        only = _policy()

        context = build_security_context("u", "t", [only], ttl=timedelta(hours=1))

        assert context.effective_policy is only

    def test_unsupported_algorithm_fails_closed_with_a_named_reason(self) -> None:
        """An algorithm this SDK cannot compute must raise, never sign weakly."""

        class FutureAlgorithm:
            def __repr__(self) -> str:
                return "FutureAlgorithm()"

        with pytest.raises(ValueError, match="unsupported signing algorithm"):
            _compute_signature("payload", "key", FutureAlgorithm())  # type: ignore[arg-type]

    def test_compute_signature_differs_by_algorithm(self) -> None:
        sha256 = _compute_signature("payload", "key", SigningAlgorithm.hmac_sha256)
        sha512 = _compute_signature("payload", "key", SigningAlgorithm.hmac_sha512)

        assert sha256 != sha512
        assert len(base64.b64decode(sha256)) == 32
        assert len(base64.b64decode(sha512)) == 64


class TestNormalizeTimestampBranches:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("2026-01-15T10:00:00Z", "2026-01-15T10:00:00Z"),
            ("2026-01-15T10:00:00+00:00", "2026-01-15T10:00:00Z"),
            ("2026-01-15T10:00:00.000Z", "2026-01-15T10:00:00Z"),
            ("2026-01-15T10:00:00.123Z", "2026-01-15T10:00:00.123Z"),
            ("2026-01-15T10:00:00.123456Z", "2026-01-15T10:00:00.123Z"),
            ("2026-01-15T10:00:00.1239Z", "2026-01-15T10:00:00.123Z"),
        ],
    )
    def test_spec_section_2_truncation_table(self, raw: str, expected: str) -> None:
        """The exact table in spec section 2 rule 5, truncated never rounded."""
        assert _normalize_timestamp(raw) == expected

    def test_non_utc_offset_is_converted_to_utc(self) -> None:
        assert _normalize_timestamp("2026-01-15T12:00:00+02:00") == "2026-01-15T10:00:00Z"

    def test_naive_timestamp_is_assumed_utc(self) -> None:
        """A timestamp with no zone must not shift with the host's locale."""
        assert _normalize_timestamp("2026-01-15T10:00:00") == "2026-01-15T10:00:00Z"

    def test_empty_and_none_normalize_to_an_empty_string(self) -> None:
        assert _normalize_timestamp("") == ""
        assert _normalize_timestamp(None) == ""

    def test_unparseable_value_is_passed_through_verbatim(self) -> None:
        """The signature then covers what was transported; expiry rejects it."""
        assert _normalize_timestamp("never") == "never"

    def test_rewriting_a_sub_second_expiry_still_breaks_the_signature(self) -> None:
        context = build_security_context("u", "t", [_policy()], ttl=timedelta(hours=1))
        context.expires_at = "2026-01-15T10:00:00.123Z"
        signed = sign_context(context, "key")

        signed.expires_at = "2026-01-15T10:00:00.124Z"

        assert validate_context(signed, "key") is False

    def test_equivalent_timestamp_spellings_verify_identically(self) -> None:
        """`+00:00` and `Z`, and microseconds beyond millis, are the same bytes."""
        context = build_security_context("u", "t", [_policy()], ttl=timedelta(hours=1))
        context.expires_at = "2026-01-15T10:00:00.123456Z"
        signed = sign_context(context, "key")

        signed.expires_at = "2026-01-15T10:00:00.123999+00:00"

        assert validate_context(signed, "key") is True


class TestValidateExpiryBranches:
    def test_missing_expiry_is_rejected(self) -> None:
        assert validate_expiry(SecurityContext(effective_policy=_policy())) == (
            "security context has no expiry"
        )

    def test_empty_expiry_is_rejected(self) -> None:
        context = SecurityContext(effective_policy=_policy(), expires_at="")

        assert validate_expiry(context) == "security context has no expiry"

    def test_unparseable_expiry_is_rejected(self) -> None:
        context = SecurityContext(effective_policy=_policy(), expires_at="never")

        assert validate_expiry(context) == "invalid expiry format"

    def test_naive_past_expiry_is_rejected(self) -> None:
        """A zoneless expiry is read as UTC rather than skipping the check."""
        context = SecurityContext(effective_policy=_policy(), expires_at="2020-01-01T00:00:00")

        assert validate_expiry(context) == "security context expired"

    def test_naive_future_expiry_is_accepted(self) -> None:
        context = SecurityContext(effective_policy=_policy(), expires_at="2099-01-01T00:00:00")

        assert validate_expiry(context) is None

    def test_future_expiry_is_accepted(self) -> None:
        context = SecurityContext(effective_policy=_policy(), expires_at="2099-01-01T00:00:00Z")

        assert validate_expiry(context) is None


class TestSerializationBranches:
    def test_integrity_block_round_trips(self) -> None:
        policy = deserialize_effective_policy(
            {
                "version": "1.0",
                "permissions": {"canQuery": True},
                "integrity": {"algorithm": "hmac-sha256", "signature": "abc"},
            }
        )

        assert policy.integrity is not None
        assert policy.integrity.algorithm is SigningAlgorithm.hmac_sha256
        assert policy.integrity.signature == "abc"

    def test_absent_integrity_block_is_none(self) -> None:
        policy = deserialize_effective_policy(
            {"version": "1.0", "permissions": {"canQuery": True}}
        )

        assert policy.integrity is None

    def test_serialize_omits_none_and_uses_camel_case(self) -> None:
        """Spec section 1: a null field is indistinguishable from absent."""
        policy = EffectivePolicy(
            version="1.0",
            user_id="u",
            permissions=PolicyPermissions(can_query=True),
        )

        payload = json.loads(serialize(policy))

        assert payload["userId"] == "u"
        assert "tenantId" not in payload
        assert "objectRules" not in payload

    def test_serialize_preserves_a_dict_valued_filter_value(self) -> None:
        """RowFilter.value is untyped, so a dict must survive serialization."""
        row_filter = RowFilter(
            field="meta", operator=FilterOperator.equals, value={"nested": {"deep": 1}}
        )

        payload = json.loads(serialize(row_filter))

        assert payload["value"] == {"nested": {"deep": 1}}
        assert payload["operator"] == "equals"

    def test_serialize_preserves_an_empty_allow_list(self) -> None:
        """Spec section 1: `[]` is preserved; it is not a null."""
        policy = EffectivePolicy(
            permissions=PolicyPermissions(can_query=True),
            object_rules=ObjectRules(field_rules=FieldRules(allowed_fields=[])),
        )

        payload = json.loads(serialize(policy))

        assert payload["objectRules"]["fieldRules"]["allowedFields"] == []

    def test_serialize_accepts_a_json_string_or_a_dict(self) -> None:
        as_dict = deserialize_policy_definition(
            {"version": "1.0", "name": "p", "permissions": {"canQuery": True}}
        )
        as_str = deserialize_policy_definition(
            '{"version":"1.0","name":"p","permissions":{"canQuery":true}}'
        )

        assert as_dict == as_str

    def test_unknown_mask_type_is_refused_at_the_boundary(self) -> None:
        """A policy must not load with a mask type this SDK cannot honour."""
        with pytest.raises(ValueError, match="unknown maskType"):
            deserialize_effective_policy(
                {
                    "version": "1.0",
                    "permissions": {"canQuery": True},
                    "objectRules": {
                        "fieldRules": {
                            "maskedFields": [{"field": "ssn", "maskType": "obfuscate"}]
                        }
                    },
                }
            )

    def test_integrity_is_excluded_from_the_signed_payload(self) -> None:
        """Spec section 2: the signature cannot sign itself."""
        policy = _policy()
        context = build_security_context("u", "t", [policy], ttl=timedelta(hours=1))
        signed = sign_context(context, "key")

        signed.effective_policy.integrity = IntegrityBlock(
            algorithm=SigningAlgorithm.hmac_sha256, signature="whatever"
        )

        assert validate_context(signed, "key") is True


class TestMergerBranches:
    def _definition(self, name: str, **kwargs) -> PolicyDefinition:
        return PolicyDefinition(
            version="1.0",
            name=name,
            permissions=kwargs.pop("permissions", PolicyPermissions(can_query=True)),
            **kwargs,
        )

    def test_empty_policy_list_denies_all(self) -> None:
        merged = merge([])

        assert merged.permissions.can_query is False
        assert merged.permissions.read_only is True

    def test_absent_read_only_defaults_to_restrictive_before_folding(self) -> None:
        """Spec section 8: silence on read_only must yield True, not False."""
        silent = self._definition("silent", permissions=PolicyPermissions(can_query=True))
        explicit = self._definition(
            "explicit", permissions=PolicyPermissions(can_query=True, read_only=False)
        )

        assert merge([silent, explicit]).permissions.read_only is True

    def test_can_query_folds_with_and(self) -> None:
        allow = self._definition("allow", permissions=PolicyPermissions(can_query=True))
        deny = self._definition("deny", permissions=PolicyPermissions(can_query=False))

        assert merge([allow, deny]).permissions.can_query is False

    def test_disjoint_allow_lists_intersect_to_deny_all_and_are_retained(self) -> None:
        """Spec section 3: the empty intersection must not be discarded as falsy."""
        a = self._definition("a", object_rules=ObjectRules(allowed_objects=["patients"]))
        b = self._definition("b", object_rules=ObjectRules(allowed_objects=["billing"]))

        merged = merge([a, b])

        assert merged.object_rules is not None
        assert merged.object_rules.allowed_objects == []

    def test_none_allow_list_does_not_restrict_the_intersection(self) -> None:
        a = self._definition("a", object_rules=ObjectRules(allowed_objects=["patients"]))
        b = self._definition("b", object_rules=ObjectRules(hidden_objects=["billing"]))

        merged = merge([a, b])

        assert merged.object_rules is not None
        assert merged.object_rules.allowed_objects == ["patients"]

    def test_hidden_sets_union_and_deduplicate_preserving_order(self) -> None:
        a = self._definition("a", object_rules=ObjectRules(hidden_objects=["audit", "billing"]))
        b = self._definition("b", object_rules=ObjectRules(hidden_objects=["billing", "secrets"]))

        merged = merge([a, b])

        assert merged.object_rules is not None
        assert merged.object_rules.hidden_objects == ["audit", "billing", "secrets"]

    def test_most_restrictive_mask_wins_across_policies(self) -> None:
        """Spec section 6: null must beat partial, not lose to it."""
        weak = self._definition(
            "weak",
            object_rules=ObjectRules(
                field_rules=FieldRules(
                    masked_fields=[
                        MaskingRule(
                            field="ssn",
                            mask_type=MaskType.partial,
                            parameters=MaskingParameters(show_last=4),
                        )
                    ]
                )
            ),
        )
        strong = self._definition(
            "strong",
            object_rules=ObjectRules(
                field_rules=FieldRules(
                    masked_fields=[MaskingRule(field="ssn", mask_type=MaskType.null)]
                )
            ),
        )

        for order in ([weak, strong], [strong, weak]):
            merged = merge(order)
            assert merged.object_rules is not None
            assert merged.object_rules.field_rules is not None
            rules = merged.object_rules.field_rules.masked_fields
            assert rules is not None
            assert [r.mask_type for r in rules] == [MaskType.null]

    def test_row_filters_concatenate(self) -> None:
        a = self._definition(
            "a",
            object_rules=ObjectRules(
                row_filters=[RowFilter(field="region", operator=FilterOperator.equals, value="us")]
            ),
        )
        b = self._definition(
            "b",
            object_rules=ObjectRules(
                row_filters=[
                    RowFilter(field="status", operator=FilterOperator.not_equals, value="deleted")
                ]
            ),
        )

        merged = merge([a, b])

        assert merged.object_rules is not None
        assert merged.object_rules.row_filters is not None
        assert len(merged.object_rules.row_filters) == 2

    def test_limits_take_the_most_restrictive_bound(self) -> None:
        a = self._definition("a", limits=PolicyLimits(max_results=5000, min_similarity_score=0.5))
        b = self._definition("b", limits=PolicyLimits(max_results=100, min_similarity_score=0.8))

        merged = merge([a, b])

        assert merged.limits is not None
        assert merged.limits.max_results == 100
        assert merged.limits.min_similarity_score == 0.8

    def test_limits_absent_everywhere_yields_no_limits_block(self) -> None:
        merged = merge([self._definition("a"), self._definition("b")])

        assert merged.limits is None

    def test_object_rules_absent_everywhere_yields_no_object_rules(self) -> None:
        merged = merge([self._definition("a")])

        assert merged.object_rules is None

    def test_endpoint_rules_merge_across_policies(self) -> None:
        a = self._definition(
            "a",
            object_rules=ObjectRules(
                endpoint_rules=EndpointRules(
                    allowed_endpoints=["/drug/*", "/food/*"], allowed_methods=["GET", "POST"]
                )
            ),
        )
        b = self._definition(
            "b",
            object_rules=ObjectRules(
                endpoint_rules=EndpointRules(
                    allowed_endpoints=["/drug/*"],
                    hidden_endpoints=["/admin/*"],
                    allowed_methods=["GET"],
                )
            ),
        )

        merged = merge([a, b])

        assert merged.object_rules is not None
        rules = merged.object_rules.endpoint_rules
        assert rules is not None
        assert rules.allowed_endpoints == ["/drug/*"]
        assert rules.hidden_endpoints == ["/admin/*"]
        assert rules.allowed_methods == ["GET"]

    def test_tag_rules_merge_as_intersection_and_union(self) -> None:
        a = self._definition(
            "a",
            object_rules=ObjectRules(
                tag_rules=TagRules(allowed_tags=["public", "internal"], denied_tags=["secret"])
            ),
        )
        b = self._definition(
            "b",
            object_rules=ObjectRules(
                tag_rules=TagRules(allowed_tags=["public"], denied_tags=["restricted"])
            ),
        )

        merged = merge([a, b])

        assert merged.object_rules is not None
        rules = merged.object_rules.tag_rules
        assert rules is not None
        assert rules.allowed_tags == ["public"]
        assert sorted(rules.denied_tags or []) == ["restricted", "secret"]

    def test_read_only_fields_union(self) -> None:
        a = self._definition(
            "a", object_rules=ObjectRules(field_rules=FieldRules(read_only_fields=["id"]))
        )
        b = self._definition(
            "b", object_rules=ObjectRules(field_rules=FieldRules(read_only_fields=["created_at"]))
        )

        merged = merge([a, b])

        assert merged.object_rules is not None
        assert merged.object_rules.field_rules is not None
        assert merged.object_rules.field_rules.read_only_fields == ["id", "created_at"]

    def test_source_profiles_records_every_contributing_policy(self) -> None:
        merged = merge([self._definition("a"), self._definition("b")])

        assert merged.source_profiles == ["a", "b"]
