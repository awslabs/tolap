"""The full 16-operator row-filter set (schema v1.0), applied post-fetch.

Python shipped 9 of the 16 operators the schema declares. The seven missing ones
-- `greaterThanOrEqual`, `lessThanOrEqual`, `like`, `notLike`, `isNull`,
`isNotNull`, `between` -- made a schema-valid policy behave differently in every
SDK while passing every integrity check, because the canonical signed payload
covers the policy verbatim: `{"operator": "between"}` crashed Python with a bare
`KeyError` from the deserializer, silently dropped every row in TypeScript, and
enforced correctly in .NET. That is the divergence class the canonical spec
exists to prevent, so these tests pin each operator's decision rather than merely
its presence.

Fail-closed decisions asserted here, per spec section 7:

- A row missing the referenced field is dropped for EVERY operator, including
  `isNull`. "The field is absent" and "the field is present and null" are
  different statements; only the second satisfies `isNull`.
- `notLike` against a null value or a null pattern drops the row. SQL evaluates
  `NULL NOT LIKE 'x'` to NULL, which retains nothing; returning true would
  reintroduce the fail-open bug section 7 records for `notEquals`/`notIn`.
- A malformed `between` range (fewer than two bounds, a null bound, an
  unorderable bound) drops the row. An inverted range matches nothing and is not
  silently reordered, because reordering turns a policy author's typo into a
  wider grant than the one they wrote.
- An unrecognized operator string is refused when the policy loads, rather than
  crashing or dropping every row at enforcement time.
"""

from __future__ import annotations

import pytest

from tolap_core.enforcement import apply_row_filters
from tolap_core.enums import FilterOperator
from tolap_core.models import (
    EffectivePolicy,
    ObjectRules,
    PolicyPermissions,
    RowFilter,
)
from tolap_core.serialization import deserialize_effective_policy, serialize


def _filtered(rows: list[dict], *filters: RowFilter) -> list[dict]:
    policy = EffectivePolicy(
        version="1.0",
        source_profiles=["operators"],
        permissions=PolicyPermissions(can_query=True),
        object_rules=ObjectRules(row_filters=list(filters)),
    )
    return apply_row_filters(rows, policy)


# The seven operators added to reach the schema's 16, with the exact camelCase
# JSON names the schema and the other two SDKs use.
NEW_OPERATOR_NAMES = [
    "greaterThanOrEqual",
    "lessThanOrEqual",
    "like",
    "notLike",
    "isNull",
    "isNotNull",
    "between",
]


class TestOperatorSetMatchesTheSchema:
    def test_every_new_operator_name_is_expressible(self) -> None:
        values = {op.value for op in FilterOperator}

        assert set(NEW_OPERATOR_NAMES) <= values

    def test_the_enum_carries_exactly_sixteen_operators(self) -> None:
        """A drift guard: the schema declares 16, so this SDK must express 16."""
        assert len(list(FilterOperator)) == 16

    @pytest.mark.parametrize("name", NEW_OPERATOR_NAMES)
    def test_each_new_operator_round_trips_through_serialization(self, name: str) -> None:
        payload = {
            "version": "1.0",
            "permissions": {"canQuery": True},
            "objectRules": {"rowFilters": [{"field": "age", "operator": name, "values": [1, 2]}]},
        }

        policy = deserialize_effective_policy(payload)

        assert policy.object_rules is not None
        assert policy.object_rules.row_filters is not None
        assert policy.object_rules.row_filters[0].operator.value == name
        assert f'"operator":"{name}"' in serialize(policy)

    def test_a_schema_valid_between_policy_no_longer_crashes(self) -> None:
        """The regression: this raised a bare `KeyError: 'between'`."""
        policy = deserialize_effective_policy(
            {
                "version": "1.0",
                "permissions": {"canQuery": True},
                "objectRules": {
                    "rowFilters": [{"field": "age", "operator": "between", "values": [18, 65]}]
                },
            }
        )

        kept = apply_row_filters([{"age": 30}, {"age": 70}], policy)

        assert kept == [{"age": 30}]

    def test_an_unknown_operator_is_refused_at_the_boundary(self) -> None:
        """A crash and a silent drop-everything are both unusable outcomes.

        The bare dict subscript this replaced raised `KeyError`, so a future
        schema addition would abort the caller instead of denying with a message
        naming what went wrong.
        """
        with pytest.raises(ValueError, match="unknown filter operator"):
            deserialize_effective_policy(
                {
                    "version": "1.0",
                    "permissions": {"canQuery": True},
                    "objectRules": {
                        "rowFilters": [
                            {"field": "dept", "operator": "startsWithIgnoreCase", "value": "hr"}
                        ]
                    },
                }
            )

    def test_the_refusal_names_the_operator_and_the_field(self) -> None:
        with pytest.raises(ValueError, match="'notBetween'.*'age'") as excinfo:
            deserialize_effective_policy(
                {
                    "version": "1.0",
                    "permissions": {"canQuery": True},
                    "objectRules": {
                        "rowFilters": [{"field": "age", "operator": "notBetween", "values": [1, 2]}]
                    },
                }
            )

        # The message lists what IS supported, so an integrator can act on it.
        assert "greaterThanOrEqual" in str(excinfo.value)


class TestMissingFieldFailsClosedForEveryNewOperator:
    """Spec section 7 covers all 16 operators, not just the original 9."""

    @pytest.mark.parametrize(
        "row_filter",
        [
            RowFilter(field="age", operator=FilterOperator.greater_than_or_equal, value=1),
            RowFilter(field="age", operator=FilterOperator.less_than_or_equal, value=1),
            RowFilter(field="age", operator=FilterOperator.like, value="%x%"),
            RowFilter(field="age", operator=FilterOperator.not_like, value="%x%"),
            RowFilter(field="age", operator=FilterOperator.is_null),
            RowFilter(field="age", operator=FilterOperator.is_not_null),
            RowFilter(field="age", operator=FilterOperator.between, values=[1, 2]),
        ],
        ids=lambda rf: rf.operator.value,
    )
    def test_row_without_the_field_is_dropped(self, row_filter: RowFilter) -> None:
        assert _filtered([{"id": 1}], row_filter) == []


class TestInclusiveComparisons:
    def test_greater_than_or_equal_keeps_the_boundary(self) -> None:
        rows = [{"age": 29}, {"age": 30}, {"age": 31}]

        kept = _filtered(rows, RowFilter(field="age", operator=FilterOperator.greater_than_or_equal, value=30))

        assert kept == [{"age": 30}, {"age": 31}]

    def test_less_than_or_equal_keeps_the_boundary(self) -> None:
        rows = [{"age": 29}, {"age": 30}, {"age": 31}]

        kept = _filtered(rows, RowFilter(field="age", operator=FilterOperator.less_than_or_equal, value=30))

        assert kept == [{"age": 29}, {"age": 30}]

    def test_exclusive_variants_still_exclude_the_boundary(self) -> None:
        """The inclusive operators must not have loosened the exclusive ones."""
        rows = [{"age": 30}]

        assert _filtered(rows, RowFilter(field="age", operator=FilterOperator.greater_than, value=30)) == []
        assert _filtered(rows, RowFilter(field="age", operator=FilterOperator.less_than, value=30)) == []

    @pytest.mark.parametrize(
        "operator",
        [
            FilterOperator.greater_than_or_equal,
            FilterOperator.less_than_or_equal,
        ],
        ids=lambda op: op.value,
    )
    def test_type_mismatch_is_a_non_match_not_an_exception(self, operator: FilterOperator) -> None:
        assert _filtered([{"age": "notanumber"}], RowFilter(field="age", operator=operator, value=30)) == []

    @pytest.mark.parametrize(
        "operator",
        [
            FilterOperator.greater_than_or_equal,
            FilterOperator.less_than_or_equal,
        ],
        ids=lambda op: op.value,
    )
    def test_a_null_on_either_side_drops_the_row(self, operator: FilterOperator) -> None:
        assert _filtered([{"age": None}], RowFilter(field="age", operator=operator, value=30)) == []
        assert _filtered([{"age": 30}], RowFilter(field="age", operator=operator, value=None)) == []

    @pytest.mark.parametrize(
        "operator",
        [
            FilterOperator.greater_than,
            FilterOperator.greater_than_or_equal,
            FilterOperator.less_than,
            FilterOperator.less_than_or_equal,
        ],
        ids=lambda op: op.value,
    )
    def test_booleans_are_not_ordered_as_numbers(self, operator: FilterOperator) -> None:
        """Python orders True as 1; a boolean field must not be compared numerically."""
        assert _filtered([{"flag": True}], RowFilter(field="flag", operator=operator, value=0)) == []
        assert _filtered([{"n": 1}], RowFilter(field="n", operator=operator, value=True)) == []

    def test_strings_order_lexicographically(self) -> None:
        rows = [{"code": "a"}, {"code": "m"}, {"code": "z"}]

        kept = _filtered(rows, RowFilter(field="code", operator=FilterOperator.greater_than_or_equal, value="m"))

        assert kept == [{"code": "m"}, {"code": "z"}]


class TestLikeOperators:
    """SQL LIKE semantics: `%` any run, `_` exactly one, anchored full match."""

    def test_percent_matches_any_run_of_characters(self) -> None:
        rows = [{"email": "a@example.com"}, {"email": "b@other.org"}]

        kept = _filtered(rows, RowFilter(field="email", operator=FilterOperator.like, value="%@example.com"))

        assert kept == [{"email": "a@example.com"}]

    def test_underscore_matches_exactly_one_character(self) -> None:
        rows = [{"code": "ab"}, {"code": "abc"}, {"code": "b"}]

        kept = _filtered(rows, RowFilter(field="code", operator=FilterOperator.like, value="a_"))

        assert kept == [{"code": "ab"}]

    def test_like_is_anchored_rather_than_a_substring_test(self) -> None:
        """Without anchoring, `like: "hr"` would match "hr_secret_internal"."""
        rows = [{"dept": "hr"}, {"dept": "hr_secret_internal"}]

        kept = _filtered(rows, RowFilter(field="dept", operator=FilterOperator.like, value="hr"))

        assert kept == [{"dept": "hr"}]

    def test_like_is_distinct_from_contains(self) -> None:
        """`contains` is an unanchored substring test; `like` is not."""
        rows = [{"dept": "public_hr_notes"}]

        assert _filtered(rows, RowFilter(field="dept", operator=FilterOperator.contains, value="hr")) == rows
        assert _filtered(rows, RowFilter(field="dept", operator=FilterOperator.like, value="hr")) == []
        assert _filtered(rows, RowFilter(field="dept", operator=FilterOperator.like, value="%hr%")) == rows

    def test_regex_metacharacters_in_a_like_pattern_are_literal(self) -> None:
        """`like` must not become a regex back door: `.` matches only a dot.

        Every non-wildcard character is escaped, so a pattern cannot smuggle in a
        pathological regex through the `like` operator.
        """
        rows = [{"host": "a.b"}, {"host": "axb"}]

        kept = _filtered(rows, RowFilter(field="host", operator=FilterOperator.like, value="a.b"))

        assert kept == [{"host": "a.b"}]

    def test_a_regex_alternation_in_a_like_pattern_is_literal(self) -> None:
        rows = [{"dept": "hr"}, {"dept": "hr|finance"}]

        kept = _filtered(rows, RowFilter(field="dept", operator=FilterOperator.like, value="hr|finance"))

        assert kept == [{"dept": "hr|finance"}]

    def test_like_is_distinct_from_matches(self) -> None:
        """`matches` is a full regex; `like` treats the same text literally."""
        rows = [{"dept": "hrrr"}]

        assert _filtered(rows, RowFilter(field="dept", operator=FilterOperator.matches, value="hr+")) == rows
        assert _filtered(rows, RowFilter(field="dept", operator=FilterOperator.like, value="hr+")) == []

    def test_a_backslash_escapes_a_wildcard_into_a_literal(self) -> None:
        rows = [{"pct": "50%"}, {"pct": "50abc"}]

        kept = _filtered(rows, RowFilter(field="pct", operator=FilterOperator.like, value=r"50\%"))

        assert kept == [{"pct": "50%"}]

    def test_a_trailing_backslash_is_a_literal_backslash(self) -> None:
        rows = [{"p": "a\\"}, {"p": "a"}]

        kept = _filtered(rows, RowFilter(field="p", operator=FilterOperator.like, value="a\\"))

        assert kept == [{"p": "a\\"}]

    def test_percent_matches_across_newlines(self) -> None:
        """`%` is "any run of characters" in SQL, newlines included."""
        rows = [{"note": "a\nb"}]

        kept = _filtered(rows, RowFilter(field="note", operator=FilterOperator.like, value="a%b"))

        assert kept == rows

    def test_not_like_is_the_complement_for_a_present_value(self) -> None:
        rows = [{"email": "a@example.com"}, {"email": "b@other.org"}]

        kept = _filtered(rows, RowFilter(field="email", operator=FilterOperator.not_like, value="%@example.com"))

        assert kept == [{"email": "b@other.org"}]

    def test_not_like_against_a_null_value_drops_the_row(self) -> None:
        """SQL evaluates `NULL NOT LIKE 'x'` to NULL, which retains nothing.

        Returning true here is the fail-open bug spec section 7 records for
        `notEquals`/`notIn` on a missing field.
        """
        assert _filtered([{"email": None}], RowFilter(field="email", operator=FilterOperator.not_like, value="%x%")) == []

    def test_like_against_a_null_value_drops_the_row(self) -> None:
        assert _filtered([{"email": None}], RowFilter(field="email", operator=FilterOperator.like, value="%x%")) == []

    @pytest.mark.parametrize(
        "operator",
        [FilterOperator.like, FilterOperator.not_like],
        ids=lambda op: op.value,
    )
    def test_a_null_pattern_drops_the_row(self, operator: FilterOperator) -> None:
        """A filter with no pattern cannot be satisfied, so it must not pass."""
        assert _filtered([{"email": "a@b.c"}], RowFilter(field="email", operator=operator, value=None)) == []

    @pytest.mark.parametrize(
        "operator",
        [FilterOperator.like, FilterOperator.not_like],
        ids=lambda op: op.value,
    )
    def test_an_overlong_pattern_is_refused(self, operator: FilterOperator) -> None:
        """ReDoS guard, matching the bound the `matches` operator already applies."""
        assert _filtered([{"d": "hr"}], RowFilter(field="d", operator=operator, value="a" * 2000)) == []

    @pytest.mark.parametrize(
        "operator",
        [FilterOperator.like, FilterOperator.not_like],
        ids=lambda op: op.value,
    )
    def test_an_overlong_subject_value_is_refused(self, operator: FilterOperator) -> None:
        assert _filtered([{"d": "a" * 5000}], RowFilter(field="d", operator=operator, value="%")) == []

    def test_a_non_string_value_is_compared_as_text(self) -> None:
        rows = [{"zip": 12345}]

        kept = _filtered(rows, RowFilter(field="zip", operator=FilterOperator.like, value="123%"))

        assert kept == rows


class TestNullTests:
    def test_is_null_keeps_a_present_null(self) -> None:
        rows = [{"deleted_at": None}, {"deleted_at": "2026-01-01"}]

        kept = _filtered(rows, RowFilter(field="deleted_at", operator=FilterOperator.is_null))

        assert kept == [{"deleted_at": None}]

    def test_is_null_does_not_treat_a_missing_field_as_null(self) -> None:
        """The documented decision: a MISSING field does NOT satisfy `isNull`.

        "The field is absent" and "the field is present and null" are different
        statements. Dropping the row is the fail-closed reading of a constraint we
        cannot prove holds, and it keeps `isNull` consistent with every other
        operator's treatment of an absent field (spec section 7).
        """
        assert _filtered([{"id": 1}], RowFilter(field="deleted_at", operator=FilterOperator.is_null)) == []

    def test_is_not_null_keeps_a_present_non_null(self) -> None:
        rows = [{"deleted_at": None}, {"deleted_at": "2026-01-01"}]

        kept = _filtered(rows, RowFilter(field="deleted_at", operator=FilterOperator.is_not_null))

        assert kept == [{"deleted_at": "2026-01-01"}]

    def test_is_not_null_drops_a_missing_field_too(self) -> None:
        """Both null tests fail closed on absence; neither is the other's inverse there."""
        assert _filtered([{"id": 1}], RowFilter(field="deleted_at", operator=FilterOperator.is_not_null)) == []

    def test_the_two_null_tests_are_complements_only_when_the_field_is_present(self) -> None:
        rows = [{"x": None}, {"x": 0}, {"x": ""}, {"x": False}]

        nulls = _filtered(rows, RowFilter(field="x", operator=FilterOperator.is_null))
        non_nulls = _filtered(rows, RowFilter(field="x", operator=FilterOperator.is_not_null))

        assert nulls == [{"x": None}]
        # Falsy-but-present values are NOT null: 0, "" and False all survive.
        assert non_nulls == [{"x": 0}, {"x": ""}, {"x": False}]

    def test_the_null_tests_ignore_value_and_values(self) -> None:
        """`isNull`/`isNotNull` take no operand; a stray one must not change the decision."""
        rows = [{"x": None}]

        assert _filtered(rows, RowFilter(field="x", operator=FilterOperator.is_null, value="ignored")) == rows
        assert _filtered(rows, RowFilter(field="x", operator=FilterOperator.is_null, values=[1, 2])) == rows


class TestBetween:
    def test_between_is_inclusive_on_both_bounds(self) -> None:
        rows = [{"age": 17}, {"age": 18}, {"age": 40}, {"age": 65}, {"age": 66}]

        kept = _filtered(rows, RowFilter(field="age", operator=FilterOperator.between, values=[18, 65]))

        assert kept == [{"age": 18}, {"age": 40}, {"age": 65}]

    def test_between_works_on_strings(self) -> None:
        rows = [{"code": "a"}, {"code": "m"}, {"code": "z"}]

        kept = _filtered(rows, RowFilter(field="code", operator=FilterOperator.between, values=["b", "n"]))

        assert kept == [{"code": "m"}]

    def test_an_inverted_range_matches_nothing_and_is_not_reordered(self) -> None:
        """SQL `BETWEEN 65 AND 18` matches nothing; silently swapping widens the grant."""
        rows = [{"age": 30}]

        assert _filtered(rows, RowFilter(field="age", operator=FilterOperator.between, values=[65, 18])) == []

    def test_fewer_than_two_bounds_drops_the_row(self) -> None:
        rows = [{"age": 30}]

        assert _filtered(rows, RowFilter(field="age", operator=FilterOperator.between, values=[18])) == []
        assert _filtered(rows, RowFilter(field="age", operator=FilterOperator.between, values=[])) == []
        assert _filtered(rows, RowFilter(field="age", operator=FilterOperator.between, values=None)) == []

    def test_extra_bounds_beyond_the_first_two_are_ignored(self) -> None:
        rows = [{"age": 30}]

        kept = _filtered(rows, RowFilter(field="age", operator=FilterOperator.between, values=[18, 65, 99]))

        assert kept == rows

    def test_a_null_bound_drops_the_row(self) -> None:
        rows = [{"age": 30}]

        assert _filtered(rows, RowFilter(field="age", operator=FilterOperator.between, values=[None, 65])) == []
        assert _filtered(rows, RowFilter(field="age", operator=FilterOperator.between, values=[18, None])) == []

    def test_a_null_row_value_drops_the_row(self) -> None:
        assert _filtered([{"age": None}], RowFilter(field="age", operator=FilterOperator.between, values=[18, 65])) == []

    def test_an_unorderable_bound_drops_the_row_rather_than_raising(self) -> None:
        rows = [{"age": "notanumber"}]

        assert _filtered(rows, RowFilter(field="age", operator=FilterOperator.between, values=[18, 65])) == []

    def test_an_unorderable_upper_bound_drops_the_row(self) -> None:
        """Reaches the upper-bound branch after the lower bound compared cleanly."""
        rows = [{"age": 30}]

        assert _filtered(rows, RowFilter(field="age", operator=FilterOperator.between, values=[18, "sixty"])) == []

    def test_booleans_are_not_ordered_as_numbers_in_a_range(self) -> None:
        assert _filtered([{"flag": True}], RowFilter(field="flag", operator=FilterOperator.between, values=[0, 2])) == []


class TestOperatorsCombineRestrictively:
    def test_every_filter_must_pass_for_a_row_to_survive(self) -> None:
        """Filters AND together; a mix of old and new operators is no exception."""
        rows = [
            {"age": 30, "email": "a@example.com", "deleted_at": None},
            {"age": 30, "email": "b@other.org", "deleted_at": None},
            {"age": 80, "email": "c@example.com", "deleted_at": None},
            {"age": 30, "email": "d@example.com", "deleted_at": "2026-01-01"},
        ]

        kept = _filtered(
            rows,
            RowFilter(field="age", operator=FilterOperator.between, values=[18, 65]),
            RowFilter(field="email", operator=FilterOperator.like, value="%@example.com"),
            RowFilter(field="deleted_at", operator=FilterOperator.is_null),
        )

        assert kept == [{"age": 30, "email": "a@example.com", "deleted_at": None}]
