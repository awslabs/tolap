"""SQL query rewriting: the 23 a prior implementation behaviors, ported, plus the bugs they hid.

The rewriter pushes a policy's field and row restrictions into the query so the
database never produces an excluded row. It is a **resource optimization, not an
enforcement mechanism** (canonical spec section 4): every test here that asserts a
rewrite also holds that the post-fetch pipeline still runs.

The a prior implementation reference implementation this was ported from had real defects, each
verified and each fixed rather than reproduced. They are grouped in
`TestKnownDefectsAreNotReproduced` with the specific fail-open each one caused.

Injection is the central risk, since this builds SQL text. Policy authors are
trusted (spec section 12), but a policy value or field name must not be able to
break out of its context, so the rewriter *refuses* rather than escapes-and-hopes.
`TestInjectionResistance` covers quotes, comment introducers, semicolons,
backslashes, control characters, and field names carrying quotes or dots.
"""

from __future__ import annotations

import pytest

from tolap_core.enums import FilterOperator, MaskType
from tolap_core.models import (
    EffectivePolicy,
    FieldRules,
    MaskingRule,
    ObjectRules,
    PolicyLimits,
    PolicyPermissions,
    RowFilter,
)
from tolap_core.sql_rewriter import (
    DEFAULT_DIALECT,
    SqlDialect,
    SqlQueryPreparation,
    _format_literal,
    _SqlScan,
    _truncate_for_log,
    _WHERE_KEYWORD,
    build_condition,
    build_where_clause,
    extract_referenced_fields,
    extract_table_name,
    prepare_sql_query,
    rewrite_query,
    unpushable_filters,
    validate_query,
)


#: The profiles whose ``LIKE`` is case-sensitive, and which may therefore push
#: ``like``/``notLike`` (spec section 4). Both quote with double quotes, so one
#: expected string covers them.
CASE_SENSITIVE_LIKE_DIALECTS = [SqlDialect.postgres, SqlDialect.trino]

#: The profiles that must decline ``like``/``notLike``. ``mysql`` and ``sqlserver``
#: have case-insensitive default collations; ``ansi`` is the strict intersection and
#: promises no collation at all.
COLLATION_DEPENDENT_LIKE_DIALECTS = [
    SqlDialect.mysql,
    SqlDialect.sqlserver,
    SqlDialect.ansi,
]


def _policy(
    *,
    can_query: bool = True,
    allowed_fields: list[str] | None = None,
    hidden_fields: list[str] | None = None,
    masked_fields: list[MaskingRule] | None = None,
    row_filters: list[RowFilter] | None = None,
    max_results: int | None = None,
    allowed_objects: list[str] | None = None,
    hidden_objects: list[str] | None = None,
) -> EffectivePolicy:
    has_field_rules = any([allowed_fields is not None, hidden_fields, masked_fields])
    has_object_rules = has_field_rules or row_filters or allowed_objects is not None or hidden_objects
    return EffectivePolicy(
        version="1.0",
        user_id="u",
        tenant_id="t",
        source_profiles=["rewriter"],
        permissions=PolicyPermissions(can_query=can_query, can_export=False, read_only=True),
        object_rules=ObjectRules(
            allowed_objects=allowed_objects,
            hidden_objects=hidden_objects,
            field_rules=FieldRules(
                allowed_fields=allowed_fields,
                hidden_fields=hidden_fields,
                masked_fields=masked_fields,
            )
            if has_field_rules
            else None,
            row_filters=row_filters,
        )
        if has_object_rules
        else None,
        limits=PolicyLimits(max_results=max_results) if max_results is not None else None,
    )


US_FILTER = RowFilter(field="region", operator=FilterOperator.equals, value="US")


# ---------------------------------------------------------------------------
# The 23 a prior implementation behaviors, ported to TOLAP models
# ---------------------------------------------------------------------------


class TestPortedRewriterBehaviors:
    """One test per behavior in a prior implementation's SqlQueryRewriterTests, adapted."""

    # 1
    def test_adds_where_clause_for_a_row_filter(self) -> None:
        result = rewrite_query("SELECT id, name FROM patients", _policy(row_filters=[US_FILTER]))

        assert "WHERE" in result
        assert '"region"' in result
        assert "'US'" in result

    # 2
    def test_removes_hidden_fields_from_the_select_list(self) -> None:
        result = rewrite_query(
            "SELECT id, name, ssn, date_of_birth FROM patients",
            _policy(hidden_fields=["ssn", "date_of_birth"]),
        )

        assert "ssn" not in result
        assert "date_of_birth" not in result
        assert "id" in result
        assert "name" in result

    # 3 -- the one that is easy to get wrong
    def test_does_not_remove_masked_fields_from_the_select_list(self) -> None:
        """A masked field must survive so the post-fetch pass has a value to mask.

        Removing it makes the field silently disappear from the result instead of
        appearing masked, which is a different (and unrequested) outcome.
        """
        result = rewrite_query(
            "SELECT id, name, email, phone FROM patients",
            _policy(
                masked_fields=[
                    MaskingRule(field="email", mask_type=MaskType.partial),
                    MaskingRule(field="phone", mask_type=MaskType.full),
                ]
            ),
        )

        assert "email" in result
        assert "phone" in result
        assert "id" in result
        assert "name" in result

    # 4
    def test_expands_select_star_to_allowed_minus_hidden(self) -> None:
        result = rewrite_query(
            "SELECT * FROM patients",
            _policy(allowed_fields=["id", "name", "ssn", "email"], hidden_fields=["ssn"]),
        )

        assert "*" not in result
        assert '"id"' in result
        assert '"name"' in result
        assert '"email"' in result
        assert '"ssn"' not in result

    # 5
    def test_a_policy_with_no_restrictions_returns_the_query_unchanged(self) -> None:
        query = "SELECT id, name, email FROM patients"

        assert rewrite_query(query, _policy()) == query

    # 6
    def test_multiple_tables_still_have_their_fields_filtered(self) -> None:
        result = rewrite_query(
            "SELECT p.id, p.name, p.ssn, d.diagnosis FROM patients p JOIN diagnoses d ON p.id = d.patient_id",
            _policy(hidden_fields=["ssn"]),
        )

        assert "p.ssn" not in result
        assert "p.id" in result
        assert "p.name" in result
        assert "d.diagnosis" in result

    # 7
    def test_an_existing_where_clause_is_preserved(self) -> None:
        result = rewrite_query(
            "SELECT id, name FROM patients WHERE status = 'active'",
            _policy(row_filters=[US_FILTER]),
        )

        assert '"region"' in result
        assert "'US'" in result
        assert "status = 'active'" in result
        assert "AND" in result

    # 8
    @pytest.mark.parametrize("query", ["", "   ", "\n\t "])
    def test_an_empty_query_is_returned_unchanged(self, query: str) -> None:
        assert rewrite_query(query, _policy(row_filters=[US_FILTER])) == query

    # 9
    def test_max_results_becomes_a_limit_when_none_exists(self) -> None:
        result = rewrite_query("SELECT id, name FROM patients", _policy(max_results=500))

        assert "LIMIT 500" in result

    # 10
    def test_an_existing_larger_limit_is_clamped_to_the_policy(self) -> None:
        result = rewrite_query("SELECT id FROM patients LIMIT 10000", _policy(max_results=500))

        assert "LIMIT 500" in result
        assert "LIMIT 10000" not in result

    # 11
    def test_an_existing_smaller_limit_is_preserved(self) -> None:
        """min(existing, policy): the caller's tighter bound is not loosened."""
        result = rewrite_query("SELECT id FROM patients LIMIT 100", _policy(max_results=500))

        assert "LIMIT 100" in result

    # 12
    def test_validate_query_rejects_a_hidden_field_reference(self) -> None:
        assert validate_query("SELECT id, ssn FROM patients", _policy(hidden_fields=["ssn"])) is False

    # 13
    def test_validate_query_accepts_only_allowed_field_references(self) -> None:
        assert validate_query(
            "SELECT id, name FROM patients", _policy(allowed_fields=["id", "name", "email"])
        ) is True

    # 14
    @pytest.mark.parametrize("query", ["", "   "])
    def test_validate_query_rejects_an_empty_query(self, query: str) -> None:
        assert validate_query(query, _policy()) is False

    # 15-17
    @pytest.mark.parametrize(
        ("query", "expected"),
        [
            ("SELECT * FROM patients", "patients"),
            ("SELECT * FROM public.patients", "patients"),
            ('SELECT * FROM "my_schema.my_table"', "my_table"),
        ],
    )
    def test_extract_table_name(self, query: str, expected: str) -> None:
        assert extract_table_name(query) == expected

    # 18
    def test_extract_table_name_returns_none_without_a_from_clause(self) -> None:
        assert extract_table_name("SHOW TABLES") is None

    @pytest.mark.parametrize("query", ["", "   "])
    def test_extract_table_name_returns_none_for_an_empty_query(self, query: str) -> None:
        assert extract_table_name(query) is None

    def test_extract_table_name_splits_on_the_quote_dot_quote_seam(self) -> None:
        """A dot inside either identifier must not be mistaken for the separator."""
        assert extract_table_name('SELECT * FROM "my.schema"."my.table"') == "my.table"

    def test_extract_table_name_unquotes_a_single_quoted_name(self) -> None:
        assert extract_table_name('SELECT * FROM "patients"') == "patients"

    # 19
    def test_build_where_clause_renders_an_equals_condition(self) -> None:
        clause = build_where_clause(
            [RowFilter(field="department", operator=FilterOperator.equals, value="cardiology")]
        )

        assert '"department"' in clause
        assert "'cardiology'" in clause

    # 20
    def test_build_where_clause_combines_filters_with_and(self) -> None:
        clause = build_where_clause(
            [
                US_FILTER,
                RowFilter(field="active", operator=FilterOperator.equals, value="true"),
            ]
        )

        assert "AND" in clause
        assert '"region"' in clause
        assert '"active"' in clause

    # 21
    def test_build_where_clause_returns_empty_for_no_filters(self) -> None:
        assert build_where_clause([]) == ""

    # 22
    def test_an_in_operator_row_filter_renders_a_list(self) -> None:
        result = rewrite_query(
            "SELECT id, name FROM patients",
            _policy(
                row_filters=[
                    RowFilter(field="region", operator=FilterOperator.in_, values=["US", "CA", "UK"])
                ]
            ),
        )

        assert "IN" in result
        assert "'US'" in result
        assert "'CA'" in result
        assert "'UK'" in result

    # 23
    def test_select_star_with_hidden_but_no_allowed_list_is_left_alone(self) -> None:
        """The documented limitation: expanding `*` needs the table's column list.

        Without `allowedFields` the rewriter cannot know which columns exist, so it
        cannot subtract the hidden ones. The query is left as-is and the
        post-fetch `strip_hidden_fields` removes them instead: identical disclosure
        outcome, higher transfer cost. See
        `TestKnownDefectsAreNotReproduced.test_select_star_leak_is_covered_by_the_post_pass`
        for why this is safe here and was not in a prior implementation.
        """
        result = rewrite_query("SELECT * FROM patients", _policy(hidden_fields=["ssn"]))

        assert "SELECT" in result
        assert "FROM patients" in result
        assert result == "SELECT * FROM patients"

    # 24
    def test_where_is_inserted_before_order_by(self) -> None:
        result = rewrite_query(
            "SELECT id, name FROM patients ORDER BY name",
            _policy(
                row_filters=[RowFilter(field="active", operator=FilterOperator.equals, value="true")]
            ),
        )

        assert result.upper().index("WHERE") < result.upper().index("ORDER BY")

    # 25
    def test_allowed_fields_restrict_an_explicit_select_list(self) -> None:
        result = rewrite_query(
            "SELECT id, name, email, phone FROM patients", _policy(allowed_fields=["id", "name"])
        )

        assert "id" in result
        assert "name" in result
        assert "email" not in result
        assert "phone" not in result


# ---------------------------------------------------------------------------
# a prior implementation defects, fixed rather than reproduced
# ---------------------------------------------------------------------------


class TestKnownDefectsAreNotReproduced:
    def test_a_hidden_field_inside_an_aggregate_is_rejected(self) -> None:
        """a prior implementation: `HAVING max(ssn) > '1'` passes validation.

        The token left of `>` is `)`, so no field is extracted. A hidden field then
        chooses which rows come back -- the aggregate's value is disclosed by the
        row set even though the field is absent from the projection.
        """
        assert validate_query(
            "SELECT region FROM patients GROUP BY region HAVING max(ssn) > '1'",
            _policy(hidden_fields=["ssn"]),
        ) is False

    def test_a_hidden_field_inside_a_select_aggregate_is_rejected(self) -> None:
        assert validate_query(
            "SELECT count(ssn) FROM patients", _policy(hidden_fields=["ssn"])
        ) is False

    def test_a_hidden_field_inside_a_where_function_is_rejected(self) -> None:
        assert validate_query(
            "SELECT id FROM patients WHERE length(ssn) > 3", _policy(hidden_fields=["ssn"])
        ) is False

    def test_a_string_literal_is_not_mistaken_for_a_field(self) -> None:
        """Literals are stripped before extracting a call's arguments."""
        assert validate_query(
            "SELECT id FROM patients WHERE coalesce(name, 'ssn') = 'x'",
            _policy(hidden_fields=["ssn"]),
        ) is True

    @pytest.mark.parametrize(
        "query",
        [
            "SELECT round(1.5) FROM patients",
            "SELECT cast(id AS text) FROM patients",
            "SELECT cast(id AS varchar) FROM patients",
        ],
    )
    def test_ordinary_call_expressions_are_not_falsely_rejected(self, query: str) -> None:
        """a prior implementation: splitting a call on its last dot yields `5)` as a "column".

        `round(1.5)` was refused under any allow-list, and `cast(id AS text)` was
        refused because `text` was extracted as a field name -- so type names are
        on the keyword denylist too.
        """
        assert validate_query(query, _policy(allowed_fields=["id"])) is True

    def test_a_numeric_literal_argument_is_not_a_field(self) -> None:
        assert validate_query("SELECT round(1.5) FROM t", _policy(allowed_fields=[])) is True

    def test_the_outer_where_is_targeted_not_a_subquery_s(self) -> None:
        """a prior implementation replaced the FIRST `WHERE`, which is the subquery's.

        That filters the subquery and leaves the caller's result set entirely
        unrestricted -- an outright fail-open.
        """
        result = rewrite_query(
            "SELECT id FROM t WHERE id IN (SELECT id FROM u WHERE x = 1)",
            _policy(row_filters=[US_FILTER]),
        )

        assert result == "SELECT id FROM t WHERE (\"region\" = 'US') AND (id IN (SELECT id FROM u WHERE x = 1))"

    def test_a_where_inside_a_string_literal_is_not_mistaken_for_a_clause(self) -> None:
        result = rewrite_query(
            "SELECT id FROM t WHERE note = 'where is it'", _policy(row_filters=[US_FILTER])
        )

        assert result.count("WHERE") == 1
        assert "'where is it'" in result

    def test_the_original_where_is_parenthesised_too(self) -> None:
        """A prior implementation emitted `WHERE (filters) AND a OR b`.

        That binds as `((filters) AND a) OR b`, admitting every row matching b --
        the injected filter is bypassed entirely.
        """
        result = rewrite_query(
            "SELECT id FROM t WHERE a = 1 OR b = 2", _policy(row_filters=[US_FILTER])
        )

        assert result == "SELECT id FROM t WHERE (\"region\" = 'US') AND (a = 1 OR b = 2)"

    def test_negative_operators_carry_an_is_null_arm(self) -> None:
        """SQL `col <> 'x'` is unknown-therefore-false for a null col.

        The database would drop a row the post-fetch pass KEEPS (spec section 7
        drops rows whose field is *absent*, not rows whose value is null), so the
        same policy would return fewer rows with the optimization enabled.
        """
        condition = build_condition(
            RowFilter(field="status", operator=FilterOperator.not_equals, value="deleted")
        )

        assert condition == "(\"status\" <> 'deleted' OR \"status\" IS NULL)"

    def test_not_in_carries_an_is_null_arm(self) -> None:
        condition = build_condition(
            RowFilter(field="region", operator=FilterOperator.not_in, values=["eu"])
        )

        assert condition == "(\"region\" NOT IN ('eu') OR \"region\" IS NULL)"

    def test_the_where_insert_point_is_the_earliest_clause_not_the_first_pattern(self) -> None:
        """A prior implementation iterated a fixed pattern list, so `GROUP BY ... ORDER BY ...`
        produced `GROUP BY x WHERE ... ORDER BY y` -- invalid SQL."""
        result = rewrite_query(
            "SELECT region, count(*) FROM t GROUP BY region ORDER BY region",
            _policy(row_filters=[US_FILTER]),
        )

        upper = result.upper()
        assert upper.index("WHERE") < upper.index("GROUP BY") < upper.index("ORDER BY")

    def test_a_malformed_between_never_emits_a_neutral_predicate(self) -> None:
        """A prior implementation emitted `1=1` for a malformed BETWEEN -- admitting every row.

        Spec section 4 forbids emitting a neutral predicate in place of one that
        failed to build. A range no row can satisfy renders as never-true.
        """
        condition = build_condition(
            RowFilter(field="age", operator=FilterOperator.between, values=[18])
        )

        assert condition == "1 = 0"
        assert condition != "1=1"

    def test_select_star_leak_is_covered_by_the_post_pass(self) -> None:
        """a prior implementation left `SELECT *` unchanged with no post-fetch pass to fall back on.

        Here the identical rewriter decision is only a missed optimization: the
        hidden field still arrives from the database, and the mandatory pipeline
        removes it. The test asserts the *combination*, since that is what makes
        the limitation safe.
        """
        from tolap_core.enforcement import apply_result_pipeline

        policy = _policy(hidden_fields=["ssn"])
        assert rewrite_query("SELECT * FROM patients", policy) == "SELECT * FROM patients"

        rows = apply_result_pipeline([{"id": 1, "ssn": "111-22-3333"}], policy)

        assert rows == [{"id": 1}]

    def test_no_free_text_where_clause_field_exists(self) -> None:
        """a prior implementation's `RowFilterRule.WhereClause` was an injection vector with no
        TOLAP equivalent -- and non-functional in a prior implementation anyway, since
        `BuildCondition` had no case for it and rendered a predicate on a
        nonexistent `"_raw_where"` column."""
        assert not hasattr(RowFilter, "where_clause")
        assert "_raw_where" not in build_where_clause(
            [RowFilter(field="region", operator=FilterOperator.equals, value="US")]
        )


# ---------------------------------------------------------------------------
# Injection resistance
# ---------------------------------------------------------------------------


class TestInjectionResistance:
    """A policy value or field name must not break out of its context.

    Policy authors are trusted (spec section 12), but this is a security boundary
    that emits SQL text, so the rewriter refuses what it cannot render safely
    rather than escaping and hoping.
    """

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("' OR 1=1 --", "\"r\" = ''' OR 1=1 --'"),
            ("o'brien", "\"r\" = 'o''brien'"),
            ("a;DROP TABLE t", "\"r\" = 'a;DROP TABLE t'"),
            ("--comment", "\"r\" = '--comment'"),
            ("100%", "\"r\" = '100%'"),
        ],
    )
    def test_a_quote_or_comment_or_semicolon_stays_inside_the_literal(
        self, value: str, expected: str
    ) -> None:
        condition = build_condition(RowFilter(field="r", operator=FilterOperator.equals, value=value))

        assert condition == expected

    @pytest.mark.parametrize(
        "value",
        [
            "back\\slash",
            "\\' OR 1=1 --",
            "nul\x00here",
            "new\nline",
            "carriage\rreturn",
            "tab\there",
        ],
    )
    def test_a_backslash_or_control_character_is_refused_not_escaped(self, value: str) -> None:
        """Doubling `'` is not sufficient. MySQL treats `\\` as a string escape by
        default, so `\\'` leaves the literal open; NUL truncates the statement for
        some client libraries and a newline ends a `--` comment."""
        assert build_condition(RowFilter(field="r", operator=FilterOperator.equals, value=value)) is None

    @pytest.mark.parametrize(
        "field_name",
        [
            're"gion',
            "region; DROP TABLE t",
            "region--",
            "has space",
            "region'",
            "*",
            "",
            "   ",
            "region\x00",
        ],
    )
    def test_an_unsafe_field_name_is_refused_not_quoted(self, field_name: str) -> None:
        """Validated against a conservative pattern rather than merely quoted."""
        assert build_condition(
            RowFilter(field=field_name, operator=FilterOperator.equals, value="x")
        ) is None

    @pytest.mark.parametrize("field_name", ["`region`", "region`", '"region"', "[region]"])
    def test_an_identifier_quote_is_unwrapped_then_revalidated(self, field_name: str) -> None:
        """A policy may spell a field in its engine's quoting style.

        The wrapping characters are stripped and what remains is validated again,
        so the emitted identifier is always the canonical double-quoted form and no
        input quote character survives into the SQL.
        """
        condition = build_condition(
            RowFilter(field=field_name, operator=FilterOperator.equals, value="x")
        )

        assert condition == "\"region\" = 'x'"

    def test_a_dotted_field_name_renders_as_its_bare_leaf(self) -> None:
        """The qualifier is stripped, not emitted: TOLAP already treats
        `patients.region` and `region` as the same field, and a qualifier naming
        the table would not resolve against `FROM patients p`."""
        condition = build_condition(
            RowFilter(field="patients.region", operator=FilterOperator.equals, value="US")
        )

        assert condition == "\"region\" = 'US'"

    def test_a_dotted_field_whose_leaf_is_unsafe_is_still_refused(self) -> None:
        assert build_condition(
            RowFilter(field='patients.re"gion', operator=FilterOperator.equals, value="x")
        ) is None

    def test_a_refused_filter_is_omitted_from_the_where_clause(self) -> None:
        """The safe direction: an omitted condition costs transfer, never disclosure."""
        clause = build_where_clause(
            [
                US_FILTER,
                RowFilter(field="note", operator=FilterOperator.equals, value="back\\slash"),
            ]
        )

        assert clause == "\"region\" = 'US'"

    def test_a_query_with_only_refused_filters_is_not_rewritten(self) -> None:
        query = "SELECT id FROM t"
        policy = _policy(
            row_filters=[RowFilter(field="n", operator=FilterOperator.equals, value="a\\b")]
        )

        assert rewrite_query(query, policy) == query

    def test_an_in_list_entry_that_cannot_be_rendered_refuses_the_whole_filter(self) -> None:
        """A partial IN list would be a *wider* grant than the policy states."""
        assert build_condition(
            RowFilter(field="r", operator=FilterOperator.in_, values=["ok", "back\\slash"])
        ) is None

    def test_a_null_in_list_entry_refuses_the_filter(self) -> None:
        """SQL `NOT IN (NULL, ...)` is never true and would drop rows the
        post-fetch pass keeps."""
        assert build_condition(
            RowFilter(field="r", operator=FilterOperator.not_in, values=["a", None])
        ) is None

    def test_a_like_pattern_carrying_a_backslash_is_refused(self) -> None:
        assert build_condition(
            RowFilter(field="r", operator=FilterOperator.like, value=r"a\%b")
        ) is None

    def test_an_injected_value_does_not_alter_the_statement_structure(self) -> None:
        """End to end: the malicious value lands wholly inside one literal."""
        result = rewrite_query(
            "SELECT id FROM patients",
            _policy(
                row_filters=[
                    RowFilter(field="region", operator=FilterOperator.equals, value="' OR 1=1 --")
                ]
            ),
        )

        assert result == "SELECT id FROM patients WHERE \"region\" = ''' OR 1=1 --'"
        # One WHERE, one statement, no comment introducer outside the literal.
        assert result.count("WHERE") == 1
        assert result.index("--") > result.index("'''")


# ---------------------------------------------------------------------------
# Literal rendering
# ---------------------------------------------------------------------------


class TestLiteralRendering:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (42, '"r" = 42'),
            (-7, '"r" = -7'),
            (1.5, '"r" = 1.5'),
            (True, '"r" = TRUE'),
            (False, '"r" = FALSE'),
        ],
    )
    def test_scalars_render_without_locale_dependence(self, value: object, expected: str) -> None:
        """A comma-decimal locale would render 1.5 as "1,5", which inside an IN
        list silently becomes two values."""
        assert build_condition(RowFilter(field="r", operator=FilterOperator.equals, value=value)) == expected

    def test_a_decimal_renders_in_fixed_point(self) -> None:
        from decimal import Decimal

        condition = build_condition(
            RowFilter(field="amount", operator=FilterOperator.equals, value=Decimal("1.50"))
        )

        assert condition == '"amount" = 1.50'

    def test_a_non_finite_decimal_is_refused(self) -> None:
        from decimal import Decimal

        assert build_condition(
            RowFilter(field="r", operator=FilterOperator.equals, value=Decimal("NaN"))
        ) is None

    @pytest.mark.parametrize("value", [float("inf"), float("-inf"), float("nan")])
    def test_a_non_finite_float_is_refused(self, value: float) -> None:
        assert build_condition(RowFilter(field="r", operator=FilterOperator.equals, value=value)) is None

    def test_a_date_renders_as_an_iso_literal(self) -> None:
        from datetime import date

        condition = build_condition(
            RowFilter(field="d", operator=FilterOperator.equals, value=date(2026, 1, 15))
        )

        assert condition == "\"d\" = '2026-01-15'"

    def test_a_datetime_renders_as_an_iso_literal(self) -> None:
        from datetime import datetime

        condition = build_condition(
            RowFilter(field="d", operator=FilterOperator.equals, value=datetime(2026, 1, 15, 9, 30, 0))
        )

        assert condition == "\"d\" = '2026-01-15 09:30:00'"

    def test_an_unknown_type_is_refused_rather_than_str_guessed(self) -> None:
        class Custom:
            def __str__(self) -> str:  # pragma: no cover - never called
                return "whatever"

        assert build_condition(
            RowFilter(field="r", operator=FilterOperator.equals, value=Custom())
        ) is None

    def test_a_bool_is_not_rendered_as_a_number(self) -> None:
        """bool is an int subclass; TRUE is not 1 here."""
        assert build_condition(RowFilter(field="r", operator=FilterOperator.equals, value=True)) == '"r" = TRUE'

    def test_an_in_list_containing_a_null_renders_none_for_the_positive_form_too(self) -> None:
        assert build_condition(
            RowFilter(field="r", operator=FilterOperator.in_, values=[1, None])
        ) is None

    def test_a_not_equals_against_an_unrenderable_value_is_declined(self) -> None:
        """The IS NULL arm must not be built around a condition that failed."""
        assert build_condition(
            RowFilter(field="r", operator=FilterOperator.not_equals, value="back\\slash")
        ) is None


# ---------------------------------------------------------------------------
# Every operator's SQL form
# ---------------------------------------------------------------------------


class TestOperatorSqlForms:
    @pytest.mark.parametrize(
        ("row_filter", "expected"),
        [
            (RowFilter(field="a", operator=FilterOperator.equals, value=1), '"a" = 1'),
            (
                RowFilter(field="a", operator=FilterOperator.not_equals, value=1),
                '("a" <> 1 OR "a" IS NULL)',
            ),
            (RowFilter(field="a", operator=FilterOperator.greater_than, value=1), '"a" > 1'),
            (
                RowFilter(field="a", operator=FilterOperator.greater_than_or_equal, value=1),
                '"a" >= 1',
            ),
            (RowFilter(field="a", operator=FilterOperator.less_than, value=1), '"a" < 1'),
            (
                RowFilter(field="a", operator=FilterOperator.less_than_or_equal, value=1),
                '"a" <= 1',
            ),
            (
                RowFilter(field="a", operator=FilterOperator.in_, values=[1, 2]),
                '"a" IN (1, 2)',
            ),
            (
                RowFilter(field="a", operator=FilterOperator.not_in, values=[1, 2]),
                '("a" NOT IN (1, 2) OR "a" IS NULL)',
            ),
            (RowFilter(field="a", operator=FilterOperator.is_null), '"a" IS NULL'),
            (RowFilter(field="a", operator=FilterOperator.is_not_null), '"a" IS NOT NULL'),
            (
                RowFilter(field="a", operator=FilterOperator.between, values=[1, 9]),
                '"a" BETWEEN 1 AND 9',
            ),
        ],
        ids=lambda rf: rf.operator.value if isinstance(rf, RowFilter) else "",
    )
    def test_each_dialect_independent_pushable_operator_renders(
        self, row_filter: RowFilter, expected: str
    ) -> None:
        """These operators render identically under every profile.

        ``like``/``notLike`` are deliberately absent: they are the one pair whose
        pushability depends on the dialect, so they are asserted separately under
        the profiles that may push them and under those that may not. Every other
        operator is pushable everywhere, which is what lets this case use the
        default profile.
        """
        assert build_condition(row_filter) == expected

    @pytest.mark.parametrize(
        ("row_filter", "expected"),
        [
            (
                RowFilter(field="a", operator=FilterOperator.like, value="x%"),
                "\"a\" LIKE 'x%'",
            ),
            (
                # The IS NULL arm, on the same footing as notEquals and notIn above:
                # NULL NOT LIKE 'x' is unknown, so the bare form would drop a
                # null-valued row the post-fetch pass keeps. Only ever emitted for a
                # case-sensitive profile, since the others do not push at all.
                RowFilter(field="a", operator=FilterOperator.not_like, value="x%"),
                "(\"a\" NOT LIKE 'x%' OR \"a\" IS NULL)",
            ),
        ],
        ids=lambda rf: rf.operator.value if isinstance(rf, RowFilter) else "",
    )
    @pytest.mark.parametrize("dialect", CASE_SENSITIVE_LIKE_DIALECTS)
    def test_like_renders_under_a_case_sensitive_profile(
        self, dialect: SqlDialect, row_filter: RowFilter, expected: str
    ) -> None:
        """The SQL rendering, which is still exercised -- just not everywhere.

        ``postgres`` and ``trino`` promise a case-sensitive ``LIKE``, so the
        comparison means what the post-fetch pass means and may be pushed. Both
        quote identifiers with double quotes, hence one shared expectation.
        """
        assert build_condition(row_filter, dialect=dialect) == expected

    @pytest.mark.parametrize(
        "operator",
        [FilterOperator.contains, FilterOperator.starts_with, FilterOperator.matches],
        ids=lambda op: op.value,
    )
    def test_the_three_unpushable_operators_are_declined(self, operator: FilterOperator) -> None:
        """No portable SQL form: contains/startsWith need an engine-specific cast,
        and matches has no portable regex operator at all."""
        assert build_condition(RowFilter(field="a", operator=operator, value="x")) is None

    def test_equals_null_becomes_is_null(self) -> None:
        """Post-fetch a null comparand means "the field is null"; SQL
        `col = NULL` is NULL for every row."""
        assert build_condition(
            RowFilter(field="a", operator=FilterOperator.equals, value=None)
        ) == '"a" IS NULL'

    def test_not_equals_null_becomes_is_not_null(self) -> None:
        assert build_condition(
            RowFilter(field="a", operator=FilterOperator.not_equals, value=None)
        ) == '"a" IS NOT NULL'

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
    def test_an_ordering_comparison_against_null_selects_no_row(
        self, operator: FilterOperator
    ) -> None:
        assert build_condition(RowFilter(field="a", operator=operator, value=None)) == "1 = 0"

    @pytest.mark.parametrize("dialect", CASE_SENSITIVE_LIKE_DIALECTS)
    def test_a_like_against_a_null_pattern_selects_no_row(self, dialect: SqlDialect) -> None:
        """Under a profile that may push at all -- the collation-dependent ones
        decline the operator before the pattern is even looked at."""
        assert build_condition(
            RowFilter(field="a", operator=FilterOperator.like, value=None), dialect=dialect
        ) == "1 = 0"

    def test_in_with_a_null_values_array_selects_no_row(self) -> None:
        assert build_condition(
            RowFilter(field="a", operator=FilterOperator.in_, values=None)
        ) == "1 = 0"

    def test_not_in_with_a_null_values_array_selects_no_row(self) -> None:
        """Mirrors the post-fetch pass, where a null values array satisfies neither."""
        assert build_condition(
            RowFilter(field="a", operator=FilterOperator.not_in, values=None)
        ) == "1 = 0"

    def test_in_with_an_empty_array_selects_no_row(self) -> None:
        assert build_condition(RowFilter(field="a", operator=FilterOperator.in_, values=[])) == "1 = 0"

    def test_not_in_with_an_empty_array_selects_every_row(self) -> None:
        assert build_condition(
            RowFilter(field="a", operator=FilterOperator.not_in, values=[])
        ) == "1 = 1"

    def test_between_with_a_null_bound_selects_no_row(self) -> None:
        assert build_condition(
            RowFilter(field="a", operator=FilterOperator.between, values=[None, 9])
        ) == "1 = 0"
        assert build_condition(
            RowFilter(field="a", operator=FilterOperator.between, values=[1, None])
        ) == "1 = 0"

    def test_between_with_no_values_selects_no_row(self) -> None:
        assert build_condition(
            RowFilter(field="a", operator=FilterOperator.between, values=None)
        ) == "1 = 0"

    def test_between_bounds_are_not_reordered(self) -> None:
        """An inverted range matches nothing in SQL and post-fetch alike;
        reordering would turn a typo into a wider grant."""
        assert build_condition(
            RowFilter(field="a", operator=FilterOperator.between, values=[9, 1])
        ) == '"a" BETWEEN 9 AND 1'

    def test_between_with_an_unrenderable_bound_is_declined(self) -> None:
        assert build_condition(
            RowFilter(field="a", operator=FilterOperator.between, values=["ok", "back\\slash"])
        ) is None
        assert build_condition(
            RowFilter(field="a", operator=FilterOperator.between, values=["back\\slash", "ok"])
        ) is None

    def test_an_unrecognized_operator_is_declined(self) -> None:
        """A future enum member without a branch here must not be pushed."""
        row_filter = RowFilter(field="a", operator=FilterOperator.equals, value=1)
        object.__setattr__(row_filter, "operator", "someFutureOperator")

        assert build_condition(row_filter) is None


# ---------------------------------------------------------------------------
# unpushable_filters reporting
# ---------------------------------------------------------------------------


class TestUnpushableFilterReporting:
    def test_a_fully_pushable_policy_reports_nothing(self) -> None:
        assert unpushable_filters(_policy(row_filters=[US_FILTER])) == []

    def test_a_policy_with_no_filters_reports_nothing(self) -> None:
        assert unpushable_filters(_policy()) == []
        assert unpushable_filters(_policy(hidden_fields=["ssn"])) == []

    def test_the_unpushable_operators_are_reported(self) -> None:
        matches = RowFilter(field="dept", operator=FilterOperator.matches, value="hr|fin")
        contains = RowFilter(field="note", operator=FilterOperator.contains, value="x")

        reported = unpushable_filters(_policy(row_filters=[US_FILTER, matches, contains]))

        assert reported == [matches, contains]

    def test_a_refused_value_is_reported_as_unpushable(self) -> None:
        refused = RowFilter(field="n", operator=FilterOperator.equals, value="back\\slash")

        assert unpushable_filters(_policy(row_filters=[refused])) == [refused]


# ---------------------------------------------------------------------------
# like/notLike pushdown is gated on the dialect's collation
# ---------------------------------------------------------------------------


#: Both operators, since the rule applies to the pair and not to one of them.
LIKE_OPERATORS = [FilterOperator.like, FilterOperator.not_like]


class TestLikePushdownRequiresACaseSensitiveDialect:
    """``like``/``notLike`` are pushed only where ``LIKE`` is case-sensitive.

    A **measured** divergence, not a theorised one. The post-fetch pass compares
    case-sensitively and is engine-independent, but a pushed-down ``LIKE`` inherits
    the *column's* collation::

        postgres:  SELECT 'ALICE JONES' LIKE 'alice%'   ->  f
        mysql:     SELECT 'ALICE JONES' LIKE 'alice%'   ->  1

    so a ``name notLike 'alice%'`` policy drops ``'ALICE JONES'`` on MySQL when the
    filter is pushed and keeps it when it is not. That is a difference in which
    **real records** a user sees, which is worse than a null-row asymmetry.

    Driven from the dialect list rather than written out per profile, so adding a
    profile without deciding its answer cannot pass by omission -- see
    :meth:`test_every_profile_is_classified`.
    """

    @pytest.mark.parametrize("operator", LIKE_OPERATORS, ids=lambda op: op.value)
    @pytest.mark.parametrize(
        "dialect", CASE_SENSITIVE_LIKE_DIALECTS, ids=lambda d: d.value
    )
    def test_a_case_sensitive_profile_emits_the_operator(
        self, dialect: SqlDialect, operator: FilterOperator
    ) -> None:
        rf = RowFilter(field="name", operator=operator, value="alice%")
        policy = _policy(row_filters=[rf])

        sql = rewrite_query("SELECT id, name FROM patients", policy, dialect=dialect)

        assert "LIKE 'alice%'" in sql
        assert unpushable_filters(policy, dialect=dialect) == []

    @pytest.mark.parametrize("operator", LIKE_OPERATORS, ids=lambda op: op.value)
    @pytest.mark.parametrize(
        "dialect", COLLATION_DEPENDENT_LIKE_DIALECTS, ids=lambda d: d.value
    )
    def test_a_collation_dependent_profile_declines_the_operator(
        self, dialect: SqlDialect, operator: FilterOperator
    ) -> None:
        """No ``LIKE`` in the text, and the filter reported through the existing
        unpushable mechanism so the post pass is known to be carrying it."""
        rf = RowFilter(field="name", operator=operator, value="alice%")
        policy = _policy(row_filters=[rf])
        query = "SELECT id, name FROM patients"

        sql = rewrite_query(query, policy, dialect=dialect)

        assert "LIKE" not in sql.upper()
        assert sql == query
        assert unpushable_filters(policy, dialect=dialect) == [rf]

    @pytest.mark.parametrize("operator", LIKE_OPERATORS, ids=lambda op: op.value)
    @pytest.mark.parametrize(
        "dialect", COLLATION_DEPENDENT_LIKE_DIALECTS, ids=lambda d: d.value
    )
    def test_a_declined_filter_reaches_prepare_sql_querys_report(
        self, dialect: SqlDialect, operator: FilterOperator
    ) -> None:
        """The integrator-facing surface, which is how a caller learns the post pass
        is still doing the filtering."""
        rf = RowFilter(field="name", operator=operator, value="alice%")

        prep = prepare_sql_query(
            "SELECT id, name FROM patients", _policy(row_filters=[rf]), dialect=dialect
        )

        assert prep.allowed is True
        assert prep.unpushable_filters == [rf]
        assert prep.fully_pushed_down is False

    def test_every_profile_is_classified(self) -> None:
        """A guard on the two lists above, so a new profile cannot skip the decision.

        Without this, adding a sixth dialect would silently be covered by neither
        list and its ``LIKE`` behavior would go unasserted.
        """
        classified = {*CASE_SENSITIVE_LIKE_DIALECTS, *COLLATION_DEPENDENT_LIKE_DIALECTS}

        assert classified == set(SqlDialect)
        # Disjoint: a profile is one or the other, never both.
        assert not set(CASE_SENSITIVE_LIKE_DIALECTS) & set(
            COLLATION_DEPENDENT_LIKE_DIALECTS
        )

    def test_the_default_profile_declines(self) -> None:
        """An omitted dialect selects ``ansi``, which promises no collation.

        Worth pinning separately: the default is the profile an integrator gets
        without thinking about it, and it is the conservative answer here.
        """
        rf = RowFilter(field="name", operator=FilterOperator.not_like, value="alice%")

        assert build_condition(rf) is None
        assert DEFAULT_DIALECT in COLLATION_DEPENDENT_LIKE_DIALECTS

    def test_no_collate_clause_is_ever_emitted(self) -> None:
        """``COLLATE`` *could* force case-sensitivity on MySQL, and is deliberately
        not used: the right collation name depends on the column's character set,
        which a rewriter holding only a policy and a query string does not know.
        Guessing wrong either fails the query or silently changes the comparison."""
        for dialect in SqlDialect:
            for operator in LIKE_OPERATORS:
                sql = rewrite_query(
                    "SELECT id, name FROM patients",
                    _policy(
                        row_filters=[
                            RowFilter(field="name", operator=operator, value="alice%")
                        ]
                    ),
                    dialect=dialect,
                )

                assert "COLLATE" not in sql.upper()
                assert "BINARY" not in sql.upper()

    @pytest.mark.parametrize(
        "dialect", COLLATION_DEPENDENT_LIKE_DIALECTS, ids=lambda d: d.value
    )
    def test_declining_like_does_not_decline_the_other_operators(
        self, dialect: SqlDialect
    ) -> None:
        """The gate is on ``like``/``notLike`` alone. Every other operator stays
        pushable under every profile, which is what keeps the connector-spec claim
        that a profile choice is otherwise a text choice."""
        equals = RowFilter(field="region", operator=FilterOperator.equals, value="us-east")
        like = RowFilter(field="name", operator=FilterOperator.like, value="alice%")
        policy = _policy(row_filters=[equals, like])

        sql = rewrite_query("SELECT id FROM patients", policy, dialect=dialect)

        assert "WHERE" in sql
        assert "us-east" in sql
        assert "LIKE" not in sql.upper()
        assert unpushable_filters(policy, dialect=dialect) == [like]


# ---------------------------------------------------------------------------
# Field extraction and validation
# ---------------------------------------------------------------------------


class TestFieldExtraction:
    def test_fields_are_extracted_from_every_clause(self) -> None:
        fields = extract_referenced_fields(
            "SELECT id, name FROM t WHERE region = 'us' "
            "GROUP BY dept HAVING count(code) > 1 ORDER BY created_at DESC"
        )

        assert {"id", "name", "region", "dept", "code", "created_at"} <= fields

    def test_an_alias_is_stripped(self) -> None:
        assert "id" in extract_referenced_fields("SELECT id AS patient_id FROM t")

    def test_a_qualified_reference_is_reduced_to_its_leaf(self) -> None:
        assert "region" in extract_referenced_fields("SELECT p.region FROM patients p")

    def test_a_quoted_reference_is_unquoted(self) -> None:
        assert "region" in extract_referenced_fields('SELECT "region" FROM t')

    def test_a_qualified_comparison_in_where_is_extracted(self) -> None:
        assert "ssn" in extract_referenced_fields("SELECT id FROM t WHERE p.ssn = '1'")

    def test_a_quoted_qualified_comparison_in_where_is_extracted(self) -> None:
        assert "ssn" in extract_referenced_fields('SELECT id FROM t WHERE p."ssn" = \'1\'')

    def test_keywords_are_not_extracted_as_fields(self) -> None:
        fields = extract_referenced_fields("SELECT id FROM t WHERE a IS NULL AND b IN (1)")

        assert "IS" not in fields
        assert "NULL" not in fields
        assert "IN" not in fields

    def test_order_by_suffixes_are_discarded(self) -> None:
        fields = extract_referenced_fields("SELECT id FROM t ORDER BY name DESC NULLS LAST")

        assert "name" in fields
        assert "DESC" not in fields

    def test_an_order_by_with_an_empty_entry_is_tolerated(self) -> None:
        assert "name" in extract_referenced_fields("SELECT id FROM t ORDER BY name, ")

    def test_a_group_by_with_an_empty_entry_is_tolerated(self) -> None:
        assert "dept" in extract_referenced_fields("SELECT id FROM t GROUP BY dept, ")

    def test_a_query_with_no_select_list_extracts_nothing_from_it(self) -> None:
        assert extract_referenced_fields("DELETE FROM t") == set()

    def test_a_select_without_a_from_extracts_nothing(self) -> None:
        assert extract_referenced_fields("SELECT 1") == set()

    def test_a_keyword_in_a_where_comparison_position_is_not_a_field(self) -> None:
        """`NULL IS NULL` puts a keyword where a field name would be."""
        fields = extract_referenced_fields("SELECT id FROM t WHERE NULL IS NULL")

        assert "NULL" not in fields

    def test_a_keyword_in_a_qualified_where_comparison_is_not_a_field(self) -> None:
        fields = extract_referenced_fields("SELECT id FROM t WHERE t.NULL IS NULL")

        assert "NULL" not in fields

    def test_a_keyword_in_order_by_is_not_a_field(self) -> None:
        assert "END" not in extract_referenced_fields("SELECT id FROM t ORDER BY END")

    def test_a_keyword_in_group_by_is_not_a_field(self) -> None:
        assert "END" not in extract_referenced_fields("SELECT id FROM t GROUP BY END")

    def test_a_leading_dot_reference_is_not_stripped_to_nothing(self) -> None:
        """A leading dot has no qualifier to remove, so the name is left intact."""
        assert extract_referenced_fields("SELECT .region FROM t") == {".region"}

    def test_a_select_list_ending_in_a_comma_yields_no_trailing_entry(self) -> None:
        fields = extract_referenced_fields("SELECT id, FROM t")

        assert "id" in fields


class TestValidateQuery:
    def test_an_empty_allow_list_denies_every_field(self) -> None:
        """Spec section 3: `[]` is deny-all, not unrestricted."""
        assert validate_query("SELECT id FROM t", _policy(allowed_fields=[])) is False

    def test_an_absent_allow_list_is_unrestricted(self) -> None:
        assert validate_query("SELECT anything FROM t", _policy()) is True

    def test_a_wildcard_select_is_settled_by_the_post_pass(self) -> None:
        assert validate_query("SELECT * FROM t", _policy(allowed_fields=["id"])) is True

    def test_an_aggregate_expression_is_settled_by_the_post_pass(self) -> None:
        """It has no single field name; its arguments were already checked."""
        assert validate_query("SELECT count(id) FROM t", _policy(allowed_fields=["id"])) is True

    def test_a_hidden_field_beats_an_allow_list_that_permits_it(self) -> None:
        assert validate_query(
            "SELECT ssn FROM t", _policy(allowed_fields=["ssn"], hidden_fields=["ssn"])
        ) is False

    def test_a_glob_hidden_pattern_is_honoured(self) -> None:
        assert validate_query("SELECT secret_code FROM t", _policy(hidden_fields=["secret_*"])) is False

    def test_matching_is_case_insensitive(self) -> None:
        assert validate_query("SELECT SSN FROM t", _policy(hidden_fields=["ssn"])) is False

    def test_a_qualified_policy_field_matches_a_bare_reference(self) -> None:
        assert validate_query("SELECT ssn FROM patients", _policy(hidden_fields=["patients.ssn"])) is False


# ---------------------------------------------------------------------------
# Select-list rewriting details
# ---------------------------------------------------------------------------


class TestSelectListRewriting:
    def test_an_empty_allow_list_projects_a_constant(self) -> None:
        """Every field is denied, so the statement stays valid by selecting 1.

        Matches the post-fetch outcome, where projecting to an empty allow-list
        leaves each surviving row with no fields.
        """
        result = rewrite_query("SELECT id, name FROM t", _policy(allowed_fields=[]))

        assert result == "SELECT 1 FROM t"

    def test_select_star_with_an_empty_allow_list_projects_a_constant(self) -> None:
        assert rewrite_query("SELECT * FROM t", _policy(allowed_fields=[])) == "SELECT 1 FROM t"

    def test_select_star_where_every_allowed_field_is_hidden_projects_a_constant(self) -> None:
        result = rewrite_query(
            "SELECT * FROM t", _policy(allowed_fields=["ssn"], hidden_fields=["ssn"])
        )

        assert result == "SELECT 1 FROM t"

    def test_a_wildcard_allow_list_does_not_expand_select_star(self) -> None:
        """A glob has no column list to expand to, and dropping the entries it
        stands for would narrow the projection below what the policy grants."""
        result = rewrite_query("SELECT * FROM t", _policy(allowed_fields=["patients.*"]))

        assert result == "SELECT * FROM t"

    def test_an_unsafe_allowed_field_name_is_skipped_during_expansion(self) -> None:
        result = rewrite_query(
            "SELECT * FROM t", _policy(allowed_fields=["id", 're"gion', "name"])
        )

        assert result == 'SELECT "id", "name" FROM t'

    def test_duplicate_allowed_fields_are_emitted_once(self) -> None:
        result = rewrite_query("SELECT * FROM t", _policy(allowed_fields=["id", "ID", "patients.id"]))

        assert result == 'SELECT "id" FROM t'

    def test_an_unchanged_select_list_is_left_byte_identical(self) -> None:
        query = "SELECT  id ,  name  FROM t"

        assert rewrite_query(query, _policy(hidden_fields=["ssn"])) == query

    def test_a_function_call_in_the_select_list_is_not_split_on_its_commas(self) -> None:
        result = rewrite_query(
            "SELECT coalesce(a, b) AS c, ssn FROM t", _policy(hidden_fields=["ssn"])
        )

        assert result == "SELECT coalesce(a, b) AS c FROM t"

    def test_a_query_without_a_from_clause_is_left_alone(self) -> None:
        assert rewrite_query("SELECT 1", _policy(hidden_fields=["ssn"])) == "SELECT 1"

    def test_a_query_without_a_select_is_left_alone(self) -> None:
        query = "SHOW TABLES"

        assert rewrite_query(query, _policy(hidden_fields=["ssn"])) == query

    def test_an_empty_select_list_is_left_alone(self) -> None:
        query = "SELECT FROM t"

        assert rewrite_query(query, _policy(hidden_fields=["ssn"])) == query

    def test_a_subquery_select_list_is_not_mistaken_for_the_outer_one(self) -> None:
        result = rewrite_query(
            "SELECT id, ssn FROM (SELECT id, ssn FROM raw) x", _policy(hidden_fields=["ssn"])
        )

        assert result == "SELECT id FROM (SELECT id, ssn FROM raw) x"

    def test_lowercase_keywords_are_handled(self) -> None:
        result = rewrite_query("select id, ssn from patients", _policy(hidden_fields=["ssn"]))

        assert result == "select id from patients"


# ---------------------------------------------------------------------------
# LIMIT clamping details
# ---------------------------------------------------------------------------


class TestLimitClamping:
    def test_a_trailing_semicolon_is_preserved(self) -> None:
        assert rewrite_query("SELECT id FROM t;", _policy(max_results=10)) == "SELECT id FROM t LIMIT 10;"

    def test_a_limit_is_added_before_a_trailing_semicolon_with_spaces(self) -> None:
        assert rewrite_query("SELECT id FROM t ; ", _policy(max_results=10)) == "SELECT id FROM t LIMIT 10;"

    def test_zero_max_results_emits_a_zero_limit(self) -> None:
        """`0` is a real bound (return nothing), not an absent one."""
        assert rewrite_query("SELECT id FROM t", _policy(max_results=0)) == "SELECT id FROM t LIMIT 0"

    def test_a_negative_max_results_leaves_the_query_alone(self) -> None:
        """`LIMIT -1` is a syntax error in Postgres; declining is safe because the
        post-fetch pass still truncates."""
        query = "SELECT id FROM t"

        assert rewrite_query(query, _policy(max_results=-5)) == query

    def test_a_subquery_limit_is_not_clamped(self) -> None:
        result = rewrite_query(
            "SELECT id FROM (SELECT id FROM raw LIMIT 10) x", _policy(max_results=500)
        )

        assert "LIMIT 10) x" in result
        assert result.endswith("LIMIT 500")

    def test_a_limit_inside_a_string_literal_is_not_clamped(self) -> None:
        result = rewrite_query(
            "SELECT id FROM t WHERE note = 'LIMIT 5'", _policy(max_results=500)
        )

        assert "'LIMIT 5'" in result
        assert result.endswith("LIMIT 500")

    def test_the_last_top_level_limit_is_the_statement_s_own(self) -> None:
        """An earlier top-level LIMIT belongs to a set operand; clamping it would
        change which rows the operand contributes, not how many the caller gets."""
        result = rewrite_query(
            "SELECT a FROM t LIMIT 10 UNION SELECT b FROM u LIMIT 9999", _policy(max_results=500)
        )

        assert "LIMIT 10 UNION" in result
        assert result.endswith("LIMIT 500")

    def test_no_max_results_leaves_an_existing_limit_alone(self) -> None:
        query = "SELECT id FROM t LIMIT 7"

        assert rewrite_query(query, _policy()) == query


# ---------------------------------------------------------------------------
# WHERE injection details
# ---------------------------------------------------------------------------


class TestWhereInjection:
    @pytest.mark.parametrize(
        "clause",
        ["GROUP BY x", "HAVING count(*) > 1", "ORDER BY x", "LIMIT 5", "OFFSET 5", "UNION SELECT 1"],
    )
    def test_where_is_inserted_before_each_following_clause(self, clause: str) -> None:
        result = rewrite_query(f"SELECT id FROM t {clause}", _policy(row_filters=[US_FILTER]))

        assert result == f"SELECT id FROM t WHERE \"region\" = 'US' {clause}"

    def test_where_is_inserted_before_a_trailing_semicolon(self) -> None:
        result = rewrite_query("SELECT id FROM t;", _policy(row_filters=[US_FILTER]))

        assert result == "SELECT id FROM t WHERE \"region\" = 'US';"

    def test_multiple_filters_are_anded(self) -> None:
        result = rewrite_query(
            "SELECT id FROM t",
            _policy(
                row_filters=[
                    US_FILTER,
                    RowFilter(field="status", operator=FilterOperator.not_equals, value="deleted"),
                ]
            ),
        )

        assert result == (
            "SELECT id FROM t WHERE \"region\" = 'US' AND "
            "(\"status\" <> 'deleted' OR \"status\" IS NULL)"
        )

    def test_a_lowercase_where_is_recognised(self) -> None:
        result = rewrite_query("SELECT id FROM t where a = 1", _policy(row_filters=[US_FILTER]))

        assert result == "SELECT id FROM t WHERE (\"region\" = 'US') AND (a = 1)"

    def test_an_unbalanced_paren_does_not_make_an_inner_keyword_look_top_level(self) -> None:
        """The depth scan is floored at zero, so a malformed query cannot drive it
        negative and expose a subquery's WHERE as the statement's own."""
        result = rewrite_query("SELECT id FROM t) WHERE a = 1", _policy(row_filters=[US_FILTER]))

        assert result.count("WHERE") == 1

    def test_a_quoted_identifier_containing_where_is_skipped(self) -> None:
        result = rewrite_query(
            'SELECT "where" FROM t', _policy(row_filters=[US_FILTER])
        )

        assert result == 'SELECT "where" FROM t WHERE "region" = \'US\''

    def test_a_doubled_quote_inside_a_literal_does_not_end_it(self) -> None:
        result = rewrite_query(
            "SELECT id FROM t WHERE n = 'o''brien'", _policy(row_filters=[US_FILTER])
        )

        assert "'o''brien'" in result
        assert result.count("WHERE") == 1

    def test_a_doubled_quote_inside_an_identifier_does_not_end_it(self) -> None:
        result = rewrite_query('SELECT "a""b" FROM t', _policy(row_filters=[US_FILTER]))

        assert '"a""b"' in result
        assert result.endswith("\"region\" = 'US'")


# ---------------------------------------------------------------------------
# prepare_sql_query
# ---------------------------------------------------------------------------


class TestPrepareSqlQuery:
    def test_a_permitted_query_is_allowed_and_rewritten(self) -> None:
        prep = prepare_sql_query(
            "SELECT id, name FROM patients",
            _policy(row_filters=[US_FILTER], max_results=100, allowed_objects=["patients"]),
        )

        assert prep.allowed is True
        assert prep.denial_reason is None
        assert prep.rewritten is True
        assert prep.query == "SELECT id, name FROM patients WHERE \"region\" = 'US' LIMIT 100"
        assert prep.fully_pushed_down is True

    def test_an_empty_query_is_denied(self) -> None:
        prep = prepare_sql_query("   ", _policy())

        assert prep.allowed is False
        assert prep.denial_reason == "query is empty"
        assert prep.query == "   "

    def test_a_policy_that_cannot_query_is_denied(self) -> None:
        prep = prepare_sql_query("SELECT id FROM t", _policy(can_query=False))

        assert prep.allowed is False
        assert prep.denial_reason == "query not permitted"

    def test_a_hidden_object_is_denied(self) -> None:
        prep = prepare_sql_query(
            "SELECT id FROM billing_internal", _policy(hidden_objects=["billing_internal"])
        )

        assert prep.allowed is False
        assert prep.denial_reason == "object is hidden"

    def test_an_object_outside_the_allow_list_is_denied(self) -> None:
        prep = prepare_sql_query("SELECT id FROM secrets", _policy(allowed_objects=["patients"]))

        assert prep.allowed is False
        assert prep.denial_reason == "object not in allowed set"

    def test_an_explicit_object_name_overrides_the_from_clause(self) -> None:
        prep = prepare_sql_query(
            "SELECT id FROM patients",
            _policy(allowed_objects=["patients"]),
            object_name="secrets",
        )

        assert prep.allowed is False

    def test_a_query_with_no_from_clause_skips_the_object_check(self) -> None:
        prep = prepare_sql_query("SELECT 1", _policy(allowed_objects=["patients"]))

        assert prep.allowed is True

    def test_a_hidden_field_reference_is_denied_rather_than_narrowed(self) -> None:
        """An agent must learn its query was refused, not silently get less."""
        prep = prepare_sql_query("SELECT id, ssn FROM patients", _policy(hidden_fields=["ssn"]))

        assert prep.allowed is False
        assert prep.denial_reason == "query references fields you do not have permission to access"
        assert prep.query == "SELECT id, ssn FROM patients"

    def test_a_denied_preparation_reports_no_unpushable_filters(self) -> None:
        prep = prepare_sql_query("SELECT id FROM t", _policy(can_query=False))

        assert prep.unpushable_filters == []
        assert prep.fully_pushed_down is True

    def test_an_unrewritable_query_reports_rewritten_false(self) -> None:
        prep = prepare_sql_query("SELECT id FROM patients", _policy())

        assert prep.allowed is True
        assert prep.rewritten is False
        assert prep.query == "SELECT id FROM patients"

    def test_unpushable_filters_are_reported_on_an_allowed_query(self) -> None:
        matches = RowFilter(field="dept", operator=FilterOperator.matches, value="hr|fin")
        prep = prepare_sql_query("SELECT id FROM t", _policy(row_filters=[US_FILTER, matches]))

        assert prep.allowed is True
        assert prep.unpushable_filters == [matches]
        assert prep.fully_pushed_down is False

    def test_the_denied_constructor_leaves_the_query_untouched(self) -> None:
        prep = SqlQueryPreparation.denied("nope", "SELECT 1")

        assert prep.allowed is False
        assert prep.query == "SELECT 1"
        assert prep.rewritten is False

    def test_a_pushed_filter_on_an_unprojected_field_returns_nothing(self) -> None:
        """The documented footgun, pinned.

        The database filters on `region` correctly, but the projection omits it, so
        the post-fetch pass drops every row -- spec section 7 fails closed on a
        field absent from the record. Fail-closed rather than a disclosure, but it
        surprises, so it is asserted rather than left to be discovered.
        """
        from tolap_core.enforcement import apply_result_pipeline

        policy = _policy(row_filters=[US_FILTER])
        prep = prepare_sql_query("SELECT id FROM patients", policy)

        assert prep.allowed is True
        assert '"region" = \'US\'' in prep.query
        # The DB would return the matching row, projected without `region`.
        assert apply_result_pipeline([{"id": 1}], policy) == []


class TestRewritingNeverReplacesThePipeline:
    """Spec section 4: rewriting is an optimization; the post pass is normative."""

    def test_the_pipeline_still_drops_rows_a_rewrite_could_not_push(self) -> None:
        from tolap_core.enforcement import apply_result_pipeline

        matches = RowFilter(field="dept", operator=FilterOperator.matches, value="hr")
        policy = _policy(row_filters=[matches])

        prep = prepare_sql_query("SELECT id, dept FROM t", policy)

        # Nothing was pushed, so the database returns both rows...
        assert prep.unpushable_filters == [matches]
        assert "WHERE" not in prep.query
        # ...and the mandatory post pass is what actually enforces the filter.
        rows = apply_result_pipeline([{"id": 1, "dept": "hr"}, {"id": 2, "dept": "fin"}], policy)
        assert rows == [{"id": 1, "dept": "hr"}]

    def test_masking_is_applied_only_by_the_pipeline(self) -> None:
        from tolap_core.enforcement import apply_result_pipeline

        policy = _policy(masked_fields=[MaskingRule(field="email", mask_type=MaskType.redact)])
        prep = prepare_sql_query("SELECT id, email FROM t", policy)

        # The masked column survives the rewrite so there is something to mask.
        assert "email" in prep.query
        assert apply_result_pipeline([{"id": 1, "email": "a@b.c"}], policy) == [
            {"id": 1, "email": "[REDACTED]"}
        ]


class TestInternalHelpers:
    """The remaining guards, reached directly because no query shape reaches them."""

    def test_scanning_past_the_end_of_a_query_finds_nothing(self) -> None:
        scan = _SqlScan("SELECT 1")

        assert scan.first_top_level(_WHERE_KEYWORD, 99) is None

    def test_is_top_level_is_false_for_an_out_of_range_offset(self) -> None:
        scan = _SqlScan("SELECT 1")

        assert scan.is_top_level(-1) is False
        assert scan.is_top_level(99) is False

    def test_a_none_value_renders_as_the_sql_null_keyword(self) -> None:
        """Every operator handles None before reaching here, so this is the
        defence-in-depth arm: it must emit NULL, never the string "None"."""
        assert _format_literal(None) == "NULL"

    def test_truncating_an_empty_string_returns_it_unchanged(self) -> None:
        assert _truncate_for_log("") == ""

    def test_a_long_query_is_truncated_with_an_ellipsis(self) -> None:
        truncated = _truncate_for_log("SELECT " + "a," * 500 + " FROM t")

        assert len(truncated) == 203
        assert truncated.endswith("...")

    def test_newlines_are_collapsed_before_truncation(self) -> None:
        """A log backend that splits on newlines would otherwise turn one record
        into one per line of the statement."""
        assert _truncate_for_log("SELECT id\nFROM t\n  WHERE a = 1") == "SELECT id FROM t WHERE a = 1"


# ---------------------------------------------------------------------------
# Dialect profiles (connector spec section 5.1)
# ---------------------------------------------------------------------------


class TestDialectProfiles:
    """Each profile's emitted identifier quoting and row-limit form.

    The bug these fix was measured, not theorised: the rewriter emitted
    Postgres-style `WHERE "region" = 'us-east'` for every engine, and MySQL without
    ANSI_QUOTES reads `"region"` as a *string literal*, so it evaluated
    `'region' = 'us-east'` -- false for every row, with no error reported. Against
    the six-row integration fixture the policy-filtered query returned 0 rows where
    backticks return 2. See `tests/integration/test_mysql_query_rewriting.py` for
    the live proof against both engines.
    """

    @pytest.mark.parametrize(
        ("dialect", "expected"),
        [
            (SqlDialect.ansi, '"region"'),
            (SqlDialect.postgres, '"region"'),
            (SqlDialect.trino, '"region"'),
            (SqlDialect.mysql, "`region`"),
            (SqlDialect.sqlserver, "[region]"),
        ],
    )
    def test_each_profile_quotes_identifiers_its_own_way(
        self, dialect: SqlDialect, expected: str
    ) -> None:
        condition = build_condition(US_FILTER, dialect=dialect)

        assert condition == f"{expected} = 'US'"

    @pytest.mark.parametrize(
        ("dialect", "expected"),
        [
            (SqlDialect.ansi, 'SELECT a FROM t WHERE "region" = \'US\' LIMIT 10'),
            (SqlDialect.postgres, 'SELECT a FROM t WHERE "region" = \'US\' LIMIT 10'),
            (SqlDialect.trino, 'SELECT a FROM t WHERE "region" = \'US\' LIMIT 10'),
            (SqlDialect.mysql, "SELECT a FROM t WHERE `region` = 'US' LIMIT 10"),
            (SqlDialect.sqlserver, "SELECT TOP 10 a FROM t WHERE [region] = 'US'"),
        ],
    )
    def test_each_profile_spells_its_row_limit_its_own_way(
        self, dialect: SqlDialect, expected: str
    ) -> None:
        result = rewrite_query(
            "SELECT a FROM t", _policy(row_filters=[US_FILTER], max_results=10), dialect=dialect
        )

        assert result == expected

    def test_an_omitted_dialect_selects_ansi(self) -> None:
        """Not a guess at the engine -- the subset most engines accept."""
        assert DEFAULT_DIALECT is SqlDialect.ansi

        policy = _policy(row_filters=[US_FILTER], max_results=10)

        assert rewrite_query("SELECT a FROM t", policy) == rewrite_query(
            "SELECT a FROM t", policy, dialect=SqlDialect.ansi
        )

    def test_a_dialect_may_be_named_by_its_string_form(self) -> None:
        """So an integrator can plumb a config value straight through."""
        assert build_condition(US_FILTER, dialect="mysql") == "`region` = 'US'"

    def test_the_expanded_select_star_is_quoted_for_the_profile(self) -> None:
        result = rewrite_query(
            "SELECT * FROM patients",
            _policy(allowed_fields=["id", "region"], hidden_fields=["ssn"]),
            dialect=SqlDialect.mysql,
        )

        assert result == "SELECT `id`, `region` FROM patients"


class TestUnrecognizedDialectDeclinesEntirely:
    """Rule 2: an unrecognized dialect is not guessed at, and does not raise.

    Guessing a profile is how the MySQL backtick defect happened. Raising would turn
    a deployment typo into an outage on a path that is only ever an optimization, so
    the query is returned untouched and the post-fetch pass -- which was always the
    enforcement boundary (spec section 4) -- does the whole job.
    """

    def test_nothing_is_rewritten(self) -> None:
        query = "SELECT a FROM t"

        result = rewrite_query(
            query, _policy(row_filters=[US_FILTER], max_results=10), dialect="oracle"
        )

        assert result == query

    def test_no_condition_is_built(self) -> None:
        assert build_condition(US_FILTER, dialect="oracle") is None

    def test_the_where_clause_is_empty(self) -> None:
        assert build_where_clause([US_FILTER], dialect="oracle") == ""

    def test_every_filter_is_reported_unpushable(self) -> None:
        filters = [
            US_FILTER,
            RowFilter(field="status", operator=FilterOperator.not_equals, value="deleted"),
        ]
        policy = _policy(row_filters=filters)

        assert unpushable_filters(policy, dialect="oracle") == filters
        # ...where a recognized profile pushes both.
        assert unpushable_filters(policy, dialect=SqlDialect.mysql) == []

    def test_it_does_not_raise(self) -> None:
        rewrite_query("SELECT a FROM t", _policy(row_filters=[US_FILTER]), dialect="nonsense")

    def test_prepare_still_runs_the_pre_execution_checks(self) -> None:
        """Declining to rewrite must never relax a denial."""
        prep = prepare_sql_query(
            "SELECT ssn FROM patients",
            _policy(hidden_fields=["ssn"]),
            dialect="oracle",
        )

        assert prep.allowed is False

    def test_prepare_reports_every_filter_and_is_not_fully_pushed_down(self) -> None:
        prep = prepare_sql_query(
            "SELECT id FROM patients", _policy(row_filters=[US_FILTER]), dialect="oracle"
        )

        assert prep.allowed is True
        assert prep.rewritten is False
        assert prep.unpushable_filters == [US_FILTER]
        assert prep.fully_pushed_down is False

    def test_the_post_pass_still_enforces_the_declined_filters(self) -> None:
        """The whole reason declining is safe: rewriting was only ever an
        optimization, so the rows are still correct."""
        from tolap_core.enforcement import apply_result_pipeline

        policy = _policy(row_filters=[US_FILTER])
        prep = prepare_sql_query("SELECT id, region FROM t", policy, dialect="oracle")

        rows = [
            {"id": 1, "region": "US"},
            {"id": 2, "region": "EU"},
            {"id": 3, "region": "US"},
        ]

        assert apply_result_pipeline(rows, policy) == [
            {"id": 1, "region": "US"},
            {"id": 3, "region": "US"},
        ]
        assert prep.query == "SELECT id, region FROM t"


class TestIdentifierCarryingTheProfilesOwnQuoteIsDeclined:
    """Rule 4: declined, never escaped by doubling.

    Declining costs an optimization; mis-escaping emits author-controlled text into
    the statement, and the doubling rule is not even the same in every engine.
    """

    @pytest.mark.parametrize(
        ("dialect", "field"),
        [
            (SqlDialect.ansi, 'reg"ion'),
            (SqlDialect.postgres, 'reg"ion'),
            (SqlDialect.trino, 'reg"ion'),
            (SqlDialect.mysql, "reg`ion"),
            (SqlDialect.sqlserver, "reg[ion"),
            (SqlDialect.sqlserver, "reg]ion"),
        ],
    )
    def test_the_filter_is_declined(self, dialect: SqlDialect, field: str) -> None:
        rf = RowFilter(field=field, operator=FilterOperator.equals, value="x")

        assert build_condition(rf, dialect=dialect) is None

    @pytest.mark.parametrize(
        ("dialect", "field"),
        [
            (SqlDialect.ansi, 'reg"ion'),
            (SqlDialect.mysql, "reg`ion"),
            (SqlDialect.sqlserver, "reg[ion"),
        ],
    )
    def test_no_doubled_quote_reaches_the_emitted_sql(
        self, dialect: SqlDialect, field: str
    ) -> None:
        rf = RowFilter(field=field, operator=FilterOperator.equals, value="x")
        result = rewrite_query("SELECT a FROM t", _policy(row_filters=[rf]), dialect=dialect)

        assert result == "SELECT a FROM t"
        assert "WHERE" not in result

    def test_a_quote_the_profile_does_not_use_is_still_declined(self) -> None:
        """A backtick is not MySQL's own delimiter under the ansi profile, but it is
        not a legal bare identifier character either, so the pattern refuses it."""
        rf = RowFilter(field="reg`ion", operator=FilterOperator.equals, value="x")

        assert build_condition(rf, dialect=SqlDialect.ansi) is None

    def test_a_wrapping_quote_is_still_unwrapped_and_accepted(self) -> None:
        """The delimiters a policy wrote *around* a name are not part of it. Only a
        quote character surviving *inside* the name is a decline."""
        rf = RowFilter(field="[region]", operator=FilterOperator.equals, value="x")

        assert build_condition(rf, dialect=SqlDialect.sqlserver) == "[region] = 'x'"
        assert build_condition(rf, dialect=SqlDialect.mysql) == "`region` = 'x'"


class TestBackslashValuesAreRefusedUnderEveryProfile:
    """Rule 5: uniform, so a policy behaves identically across engines.

    MySQL treats `\\` as a string escape by default and Postgres does not, so the
    same text would mean different things in the two engines. Refusing everywhere
    keeps a filter that is unpushable on one engine unpushable on all of them --
    and one profile treating `\\` as an escape is enough to make escaping unsafe to
    generalize.
    """

    @pytest.mark.parametrize(
        "dialect",
        [
            SqlDialect.ansi,
            SqlDialect.postgres,
            SqlDialect.trino,
            SqlDialect.mysql,
            SqlDialect.sqlserver,
        ],
    )
    def test_a_backslash_value_is_refused(self, dialect: SqlDialect) -> None:
        rf = RowFilter(
            field="region", operator=FilterOperator.equals, value="us-east\\' OR 1=1 --"
        )

        assert build_condition(rf, dialect=dialect) is None

    @pytest.mark.parametrize(
        "dialect",
        [
            SqlDialect.ansi,
            SqlDialect.postgres,
            SqlDialect.trino,
            SqlDialect.mysql,
            SqlDialect.sqlserver,
        ],
    )
    def test_a_control_character_value_is_refused(self, dialect: SqlDialect) -> None:
        rf = RowFilter(field="region", operator=FilterOperator.equals, value="us\x00east")

        assert build_condition(rf, dialect=dialect) is None

    @pytest.mark.parametrize(
        "dialect",
        [
            SqlDialect.ansi,
            SqlDialect.postgres,
            SqlDialect.trino,
            SqlDialect.mysql,
            SqlDialect.sqlserver,
        ],
    )
    def test_the_backslash_never_reaches_the_emitted_sql(self, dialect: SqlDialect) -> None:
        rf = RowFilter(field="region", operator=FilterOperator.equals, value="a\\b")

        result = rewrite_query("SELECT a FROM t", _policy(row_filters=[rf]), dialect=dialect)

        assert result == "SELECT a FROM t"
        assert "\\" not in result

    @pytest.mark.parametrize(
        "dialect",
        [
            SqlDialect.ansi,
            SqlDialect.postgres,
            SqlDialect.trino,
            SqlDialect.mysql,
            SqlDialect.sqlserver,
        ],
    )
    def test_a_plain_single_quote_is_still_escaped_by_doubling(
        self, dialect: SqlDialect
    ) -> None:
        """The refusal is specific to backslashes and control characters. Ordinary
        ANSI quote doubling is correct in every profile and stays."""
        rf = RowFilter(field="region", operator=FilterOperator.equals, value="it's")

        assert build_condition(rf, dialect=dialect) is not None
        assert "'it''s'" in build_condition(rf, dialect=dialect)


class TestSqlServerTopPlacement:
    """Rule 3: a profile is never approximated.

    `TOP n` goes after SELECT (and after DISTINCT/ALL), not at the end, so this is a
    structural placement rather than a token swap. Where it cannot be placed
    correctly the limit is simply **not pushed** -- never rendered as `LIMIT n`
    instead. An unpushed limit costs a transfer that `apply_result_limit` trims; a
    misplaced one is a broken statement or a wrong row count.
    """

    def test_top_goes_after_select_not_at_the_end(self) -> None:
        result = rewrite_query(
            "SELECT a FROM t", _policy(max_results=10), dialect=SqlDialect.sqlserver
        )

        assert result == "SELECT TOP 10 a FROM t"
        assert "LIMIT" not in result

    def test_top_goes_after_distinct(self) -> None:
        """`SELECT DISTINCT TOP 5` is a syntax error, and `SELECT TOP 5 DISTINCT`
        would count rows before duplicates are removed."""
        result = rewrite_query(
            "SELECT DISTINCT a FROM t", _policy(max_results=10), dialect=SqlDialect.sqlserver
        )

        assert result == "SELECT DISTINCT TOP 10 a FROM t"

    def test_top_goes_after_all(self) -> None:
        result = rewrite_query(
            "SELECT ALL a FROM t", _policy(max_results=10), dialect=SqlDialect.sqlserver
        )

        assert result == "SELECT ALL TOP 10 a FROM t"

    def test_an_existing_top_is_clamped_to_the_smaller_bound(self) -> None:
        result = rewrite_query(
            "SELECT TOP 50 a FROM t", _policy(max_results=10), dialect=SqlDialect.sqlserver
        )

        assert result == "SELECT TOP 10 a FROM t"

    def test_an_existing_smaller_top_wins(self) -> None:
        result = rewrite_query(
            "SELECT TOP 3 a FROM t", _policy(max_results=10), dialect=SqlDialect.sqlserver
        )

        assert result == "SELECT TOP 3 a FROM t"

    def test_the_parenthesised_top_form_is_clamped(self) -> None:
        result = rewrite_query(
            "SELECT TOP (50) a FROM t", _policy(max_results=10), dialect=SqlDialect.sqlserver
        )

        assert result == "SELECT TOP 10 a FROM t"

    @pytest.mark.parametrize(
        "query",
        [
            # A TOP on the first operand limits that operand, not the union, so the
            # caller would receive MORE rows than the policy allows.
            "SELECT a FROM t UNION SELECT b FROM u",
            "SELECT a FROM t INTERSECT SELECT b FROM u",
            "SELECT a FROM t EXCEPT SELECT b FROM u",
            # T-SQL forbids TOP alongside OFFSET ... FETCH.
            "SELECT a FROM t ORDER BY a OFFSET 5 ROWS",
            "SELECT a FROM t ORDER BY a FETCH FIRST 5 ROWS ONLY",
            # A percentage is not a row count; WITH TIES returns more rows than given.
            "SELECT TOP 5 PERCENT a FROM t",
            "SELECT TOP 5 WITH TIES a FROM t ORDER BY a",
            # Already not valid T-SQL; clamping around a clause this profile does not
            # emit would be guessing at what the caller meant.
            "SELECT a FROM t LIMIT 50",
        ],
    )
    def test_an_unplaceable_limit_is_declined_never_rendered_as_limit(
        self, query: str
    ) -> None:
        result = rewrite_query(
            query, _policy(max_results=10), dialect=SqlDialect.sqlserver
        )

        assert result == query
        assert "TOP 10" not in result
        assert "LIMIT 10" not in result

    def test_a_declined_limit_is_still_enforced_after_the_fetch(self) -> None:
        """The limit not reaching the statement costs transfer, not correctness."""
        from tolap_core.enforcement import apply_result_pipeline

        policy = _policy(max_results=2)
        query = "SELECT a FROM t UNION SELECT b FROM u"

        assert rewrite_query(query, policy, dialect=SqlDialect.sqlserver) == query
        assert apply_result_pipeline(
            [{"a": 1}, {"a": 2}, {"a": 3}, {"a": 4}], policy
        ) == [{"a": 1}, {"a": 2}]

    @pytest.mark.parametrize("query", ["DELETE FROM t", "UPDATE t SET a = 1"])
    def test_a_statement_with_no_top_level_select_is_declined(self, query: str) -> None:
        """There is nowhere to place a TOP. A non-SELECT statement should not reach a
        read-path rewriter at all -- `readOnly` blocks it earlier (connector spec
        section 4) -- but if one does, it is returned untouched rather than mangled."""
        result = rewrite_query(query, _policy(max_results=10), dialect=SqlDialect.sqlserver)

        assert result == query

    def test_a_row_filter_is_still_pushed_when_the_limit_is_declined(self) -> None:
        """The two pushdowns are independent: declining the limit must not cost the
        WHERE clause."""
        result = rewrite_query(
            "SELECT a FROM t LIMIT 50",
            _policy(row_filters=[US_FILTER], max_results=10),
            dialect=SqlDialect.sqlserver,
        )

        assert result == "SELECT a FROM t WHERE [region] = 'US' LIMIT 50"
