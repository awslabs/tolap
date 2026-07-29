"""The rewritten query runs against live Postgres and the DATABASE does the filtering.

Every other rewriter test asserts the SQL *text*. These execute it, which is the
only way to show that the pushdown is real: that the emitted SQL is valid in a
real engine, that it returns the rows the post-fetch pass would have selected, and
that the unfiltered form of the same query returns strictly more.

The injection cases are executed too. Asserting that a policy value containing
``' OR 1=1 --`` is escaped in the generated text proves the escaping; running it
proves the escaping *works* -- a hand-checked expectation about quoting is exactly
the kind of thing that looks right and is wrong.

Requires Postgres on 5432 with `tolap_integration_test` seeded from schema.sql;
skipped automatically otherwise (see conftest).
"""

from __future__ import annotations

import psycopg
import pytest

from tolap_core.enforcement import apply_result_pipeline
from tolap_core.enums import FilterOperator
from tolap_core.models import (
    EffectivePolicy,
    FieldRules,
    ObjectRules,
    PolicyLimits,
    PolicyPermissions,
    RowFilter,
)
from tolap_core.sql_rewriter import (
    SqlDialect,
    build_condition,
    prepare_sql_query,
    rewrite_query,
)


def _policy(
    *,
    row_filters: list[RowFilter] | None = None,
    allowed_fields: list[str] | None = None,
    hidden_fields: list[str] | None = None,
    max_results: int | None = None,
) -> EffectivePolicy:
    has_field_rules = allowed_fields is not None or hidden_fields is not None
    return EffectivePolicy(
        version="1.0",
        user_id="u",
        tenant_id="t",
        source_profiles=["rewrite-integration"],
        permissions=PolicyPermissions(can_query=True, can_export=False, read_only=True),
        object_rules=ObjectRules(
            field_rules=FieldRules(allowed_fields=allowed_fields, hidden_fields=hidden_fields)
            if has_field_rules
            else None,
            row_filters=row_filters,
        )
        if (row_filters or has_field_rules)
        else None,
        limits=PolicyLimits(max_results=max_results) if max_results is not None else None,
    )


def _run(conn, sql: str) -> list[dict]:
    with conn.cursor() as cur:
        cur.execute(sql)
        return list(cur.fetchall())


class TestTheDatabaseDoesTheFiltering:
    """The row count comes back already filtered, not filtered afterwards."""

    def test_a_row_filter_reaches_the_database(self, db_conn) -> None:
        query = "SELECT id, region FROM patients ORDER BY id"
        policy = _policy(
            row_filters=[
                RowFilter(field="region", operator=FilterOperator.in_, values=["us-east", "us-west"])
            ]
        )

        unfiltered = _run(db_conn, query)
        rewritten = rewrite_query(query, policy)
        filtered = _run(db_conn, rewritten)

        # The contrast is the point: the same query without the pushdown returns
        # more rows, so the reduction is the database's work and not the test's.
        assert len(unfiltered) == 6
        assert len(filtered) == 4
        assert {r["region"] for r in filtered} == {"us-east", "us-west"}
        # And the post-fetch pass, which still runs, has nothing left to remove.
        assert apply_result_pipeline(filtered, policy) == filtered

    def test_the_pushdown_and_the_post_pass_select_identical_rows(self, db_conn) -> None:
        """Two paths that are supposed to be equivalent, shown to be equivalent."""
        query = "SELECT id, region, status FROM patients ORDER BY id"
        policy = _policy(
            row_filters=[
                RowFilter(field="status", operator=FilterOperator.not_equals, value="deleted")
            ]
        )

        pushed = _run(db_conn, rewrite_query(query, policy))
        post_only = apply_result_pipeline(_run(db_conn, query), policy)

        assert [r["id"] for r in pushed] == [r["id"] for r in post_only]

    def test_a_negative_filter_keeps_null_valued_rows_in_both_paths(self, db_conn) -> None:
        """The `IS NULL` arm, verified against a real engine's three-valued logic.

        Without `OR col IS NULL`, Postgres evaluates `col <> 'x'` to unknown for a
        null col and drops the row -- while the post-fetch pass keeps it, because
        spec section 7 drops rows whose field is *absent*, not rows whose value is
        null. The two paths would then disagree.
        """
        with db_conn.cursor() as cur:
            cur.execute("DROP TABLE IF EXISTS nullable_regions")
            cur.execute("CREATE TEMP TABLE nullable_regions (id INT, region TEXT)")
            cur.execute(
                "INSERT INTO nullable_regions VALUES (1, 'us-east'), (2, 'eu-west'), (3, NULL)"
            )

        query = "SELECT id, region FROM nullable_regions ORDER BY id"
        policy = _policy(
            row_filters=[
                RowFilter(field="region", operator=FilterOperator.not_equals, value="eu-west")
            ]
        )

        condition = build_condition(policy.object_rules.row_filters[0])
        assert "IS NULL" in condition

        pushed = _run(db_conn, rewrite_query(query, policy))
        post_only = apply_result_pipeline(_run(db_conn, query), policy)

        # id 3 has a NULL region and is kept by BOTH paths.
        assert [r["id"] for r in pushed] == [1, 3]
        assert [r["id"] for r in post_only] == [1, 3]

    def test_a_not_in_filter_keeps_null_valued_rows_in_both_paths(self, db_conn) -> None:
        with db_conn.cursor() as cur:
            cur.execute("CREATE TEMP TABLE nullable_ni (id INT, region TEXT)")
            cur.execute("INSERT INTO nullable_ni VALUES (1, 'us-east'), (2, 'eu-west'), (3, NULL)")

        query = "SELECT id, region FROM nullable_ni ORDER BY id"
        policy = _policy(
            row_filters=[
                RowFilter(field="region", operator=FilterOperator.not_in, values=["eu-west"])
            ]
        )

        pushed = _run(db_conn, rewrite_query(query, policy))
        post_only = apply_result_pipeline(_run(db_conn, query), policy)

        assert [r["id"] for r in pushed] == [1, 3]
        assert [r["id"] for r in post_only] == [1, 3]

    def test_a_not_like_filter_keeps_null_valued_rows_in_both_paths(self, db_conn) -> None:
        """`notLike`'s `IS NULL` arm, proven against a real engine like the other two.

        `NULL NOT LIKE 'x'` is unknown -- therefore not true -- for exactly the same
        reason `NULL <> 'x'` is, so the bare form drops the null-valued row while the
        post-fetch pass keeps it. This asserts the two paths select the identical row
        set over a table containing a NULL in the filtered column.

        Postgres only, deliberately. A pushed-down `LIKE` inherits the column's
        collation, and MySQL's default (utf8mb4_0900_ai_ci) is case-insensitive, so
        the same comparison is engine-dependent there; that is a separate matter from
        the null handling proven here and is being handled on its own.
        """
        with db_conn.cursor() as cur:
            cur.execute("CREATE TEMP TABLE nullable_nl (id INT, name TEXT)")
            cur.execute(
                "INSERT INTO nullable_nl VALUES "
                "(1, 'alice smith'), (2, 'ALICE JONES'), (3, 'bob stone'), (4, NULL)"
            )

        query = "SELECT id, name FROM nullable_nl ORDER BY id"
        policy = _policy(
            row_filters=[RowFilter(field="name", operator=FilterOperator.not_like, value="alice%")]
        )

        condition = build_condition(
            policy.object_rules.row_filters[0], dialect=SqlDialect.postgres
        )
        assert "IS NULL" in condition

        pushed = _run(db_conn, rewrite_query(query, policy, dialect=SqlDialect.postgres))
        post_only = apply_result_pipeline(_run(db_conn, query), policy)

        # id 4 is NULL and is kept by BOTH paths; id 2 survives because Postgres LIKE
        # is case-sensitive, so 'ALICE JONES' does not match 'alice%'.
        assert [r["id"] for r in pushed] == [2, 3, 4]
        assert [r["id"] for r in post_only] == [2, 3, 4]

    def test_every_negative_operator_agrees_across_both_paths(self, db_conn) -> None:
        """The three negatives must select the same rows as each other, and as the DB.

        Regression guard against the asymmetry: `notLike` used to omit the `IS NULL`
        arm that `notEquals` and `notIn` carried, so the same policy's row set
        depended on which negative operator the author chose. Each filter below is
        phrased to exclude exactly 'us-east'.
        """
        with db_conn.cursor() as cur:
            cur.execute("CREATE TEMP TABLE nullable_neg (id INT, region TEXT)")
            cur.execute(
                "INSERT INTO nullable_neg VALUES "
                "(1, 'us-east'), (2, 'eu-west'), (3, NULL)"
            )

        query = "SELECT id, region FROM nullable_neg ORDER BY id"
        negatives = [
            RowFilter(field="region", operator=FilterOperator.not_equals, value="us-east"),
            RowFilter(field="region", operator=FilterOperator.not_in, values=["us-east"]),
            RowFilter(field="region", operator=FilterOperator.not_like, value="us-eas_"),
        ]

        for row_filter in negatives:
            policy = _policy(row_filters=[row_filter])

            pushed = _run(db_conn, rewrite_query(query, policy, dialect=SqlDialect.postgres))
            post_only = apply_result_pipeline(_run(db_conn, query), policy)

            # The null row is kept, the matching row is dropped, in BOTH paths.
            assert [r["id"] for r in pushed] == [2, 3], row_filter.operator.value
            assert [r["id"] for r in post_only] == [2, 3], row_filter.operator.value

    def test_a_limit_reaches_the_database(self, db_conn) -> None:
        query = "SELECT id FROM patients ORDER BY id"

        unfiltered = _run(db_conn, query)
        limited = _run(db_conn, rewrite_query(query, _policy(max_results=2)))

        assert len(unfiltered) == 6
        assert len(limited) == 2

    def test_an_existing_tighter_limit_is_not_loosened(self, db_conn) -> None:
        rows = _run(db_conn, rewrite_query("SELECT id FROM patients LIMIT 1", _policy(max_results=5)))

        assert len(rows) == 1

    def test_hidden_columns_are_absent_from_the_result_set(self, db_conn) -> None:
        query = "SELECT id, full_name, ssn FROM patients ORDER BY id"

        rows = _run(db_conn, rewrite_query(query, _policy(hidden_fields=["ssn"])))

        assert rows
        assert all("ssn" not in row for row in rows)
        assert all("full_name" in row for row in rows)

    def test_select_star_expands_to_the_allowed_columns(self, db_conn) -> None:
        policy = _policy(allowed_fields=["id", "full_name", "ssn"], hidden_fields=["ssn"])

        rows = _run(db_conn, rewrite_query("SELECT * FROM patients ORDER BY id", policy))

        assert rows
        assert set(rows[0]) == {"id", "full_name"}

    def test_every_pushable_operator_produces_valid_executable_sql(self, db_conn) -> None:
        """Each operator's rendering is run, so a syntax error cannot hide in one.

        ``like``/``notLike`` carry an explicit ``postgres`` dialect rather than the
        ``ansi`` default. That is not a workaround: ``ansi`` declines them because it
        promises no collation, while Postgres's ``LIKE`` *is* case-sensitive and so
        may be pushed (spec section 4). Naming the dialect is what makes the
        dependency visible -- and this suite runs against Postgres, so it is also
        the truthful dialect for it.
        """
        dialect_independent = [
            RowFilter(field="region", operator=FilterOperator.equals, value="us-east"),
            RowFilter(field="region", operator=FilterOperator.not_equals, value="eu-west"),
            RowFilter(field="region", operator=FilterOperator.in_, values=["us-east", "us-west"]),
            RowFilter(field="region", operator=FilterOperator.not_in, values=["eu-west"]),
            RowFilter(field="id", operator=FilterOperator.greater_than, value=1),
            RowFilter(field="id", operator=FilterOperator.greater_than_or_equal, value=1),
            RowFilter(field="id", operator=FilterOperator.less_than, value=6),
            RowFilter(field="id", operator=FilterOperator.less_than_or_equal, value=6),
            RowFilter(field="region", operator=FilterOperator.is_not_null),
            RowFilter(field="id", operator=FilterOperator.between, values=[2, 4]),
        ]
        needs_a_case_sensitive_dialect = [
            RowFilter(field="region", operator=FilterOperator.like, value="us-%"),
            RowFilter(field="region", operator=FilterOperator.not_like, value="eu-%"),
        ]

        cases = [(rf, None) for rf in dialect_independent]
        cases += [(rf, SqlDialect.postgres) for rf in needs_a_case_sensitive_dialect]

        for row_filter, dialect in cases:
            policy = _policy(row_filters=[row_filter])
            sql = rewrite_query(
                "SELECT id, region FROM patients ORDER BY id", policy, dialect=dialect
            )

            # The filter really did reach the database, rather than the query being
            # returned untouched and the comparison below passing trivially.
            assert sql != "SELECT id, region FROM patients ORDER BY id"

            rows = _run(db_conn, sql)

            # The database's answer and the post-fetch pass's answer must agree.
            expected = apply_result_pipeline(
                _run(db_conn, "SELECT id, region FROM patients ORDER BY id"), policy
            )
            assert [r["id"] for r in rows] == [r["id"] for r in expected], (
                f"{row_filter.operator.value} disagreed; sql={sql}"
            )

    def test_is_null_pushes_down_and_agrees_with_the_post_pass(self, db_conn) -> None:
        with db_conn.cursor() as cur:
            cur.execute("CREATE TEMP TABLE nullable_isnull (id INT, region TEXT)")
            cur.execute("INSERT INTO nullable_isnull VALUES (1, 'us-east'), (2, NULL)")

        query = "SELECT id, region FROM nullable_isnull ORDER BY id"
        policy = _policy(row_filters=[RowFilter(field="region", operator=FilterOperator.is_null)])

        pushed = _run(db_conn, rewrite_query(query, policy))
        post_only = apply_result_pipeline(_run(db_conn, query), policy)

        assert [r["id"] for r in pushed] == [2]
        assert [r["id"] for r in post_only] == [2]

    def test_an_injected_where_composes_with_the_caller_s_own(self, db_conn) -> None:
        query = "SELECT id, region, status FROM patients WHERE status = 'active' ORDER BY id"
        policy = _policy(
            row_filters=[RowFilter(field="region", operator=FilterOperator.equals, value="us-east")]
        )

        rows = _run(db_conn, rewrite_query(query, policy))

        assert [r["id"] for r in rows] == [1, 3]

    def test_an_or_in_the_caller_s_where_is_not_widened(self, db_conn) -> None:
        """`(filters) AND a OR b` would admit every row matching b.

        Executed rather than string-matched: the row count is what proves the
        binding, and a hand-read of the parentheses is what got a prior implementation this wrong.
        """
        query = (
            "SELECT id, region FROM patients "
            "WHERE region = 'us-east' OR region = 'eu-west' ORDER BY id"
        )
        policy = _policy(
            row_filters=[RowFilter(field="region", operator=FilterOperator.equals, value="us-east")]
        )

        rows = _run(db_conn, rewrite_query(query, policy))

        # eu-west matches the caller's OR but not the policy, so it must be gone.
        assert {r["region"] for r in rows} == {"us-east"}
        assert [r["id"] for r in rows] == [1, 3]

    def test_the_outer_query_is_filtered_when_a_subquery_has_its_own_where(self, db_conn) -> None:
        """A prior implementation filtered the subquery and left the outer result unrestricted."""
        query = (
            "SELECT id, region FROM patients "
            "WHERE id IN (SELECT patient_id FROM encounters WHERE status = 'active') "
            "ORDER BY id"
        )
        policy = _policy(
            row_filters=[RowFilter(field="region", operator=FilterOperator.equals, value="us-east")]
        )

        rows = _run(db_conn, rewrite_query(query, policy))

        assert {r["region"] for r in rows} == {"us-east"}

    def test_a_group_by_and_order_by_query_stays_valid(self, db_conn) -> None:
        """The insert-point bug produced `GROUP BY x WHERE ... ORDER BY y`, which
        is a syntax error -- so executing it is the assertion."""
        query = "SELECT region, count(*) AS n FROM patients GROUP BY region ORDER BY region"
        policy = _policy(
            row_filters=[
                RowFilter(field="status", operator=FilterOperator.not_equals, value="deleted")
            ]
        )

        rows = _run(db_conn, rewrite_query(query, policy))

        assert rows
        # 'deleted' rows are excluded, so us-west has 1 rather than 2.
        by_region = {r["region"]: r["n"] for r in rows}
        assert by_region["us-west"] == 1


class TestInjectionAgainstLivePostgres:
    """A malicious policy value must not return extra rows or alter the statement."""

    @pytest.mark.parametrize(
        "value",
        [
            "' OR 1=1 --",
            "' OR '1'='1",
            "'; DROP TABLE patients; --",
            "o'brien",
            "us-east' OR 1=1 --",
            "100%",
            "_",
        ],
    )
    def test_an_injected_value_matches_nothing_rather_than_everything(
        self, db_conn, value: str
    ) -> None:
        policy = _policy(
            row_filters=[RowFilter(field="region", operator=FilterOperator.equals, value=value)]
        )

        sql = rewrite_query("SELECT id FROM patients ORDER BY id", policy)
        rows = _run(db_conn, sql)

        # No patient has any of these as its region, so a correctly quoted literal
        # matches zero rows. Returning all 6 would mean the value broke out.
        assert rows == [], f"injection returned rows; sql={sql}"

    def test_the_patients_table_still_exists_after_a_drop_attempt(self, db_conn) -> None:
        policy = _policy(
            row_filters=[
                RowFilter(
                    field="region",
                    operator=FilterOperator.equals,
                    value="'; DROP TABLE patients; --",
                )
            ]
        )

        _run(db_conn, rewrite_query("SELECT id FROM patients", policy))

        assert len(_run(db_conn, "SELECT id FROM patients")) == 6

    def test_a_semicolon_in_a_value_does_not_start_a_second_statement(self, db_conn) -> None:
        """psycopg refuses multiple statements in one execute, so a value that
        escaped its literal would raise rather than quietly succeed."""
        policy = _policy(
            row_filters=[
                RowFilter(field="region", operator=FilterOperator.equals, value="a; SELECT 1")
            ]
        )

        rows = _run(db_conn, rewrite_query("SELECT id FROM patients", policy))

        assert rows == []

    def test_a_legitimate_value_containing_a_quote_still_matches(self, db_conn) -> None:
        """Escaping must not break real data: the quote is data, not syntax."""
        with db_conn.cursor() as cur:
            cur.execute("CREATE TEMP TABLE quoted_names (id INT, full_name TEXT)")
            cur.execute("INSERT INTO quoted_names VALUES (1, 'O''Brien'), (2, 'Smith')")

        policy = _policy(
            row_filters=[
                RowFilter(field="full_name", operator=FilterOperator.equals, value="O'Brien")
            ]
        )

        rows = _run(db_conn, rewrite_query("SELECT id FROM quoted_names ORDER BY id", policy))

        assert [r["id"] for r in rows] == [1]

    @pytest.mark.parametrize("value", ["back\\slash", "a\\' OR 1=1 --", "line\nbreak", "nul\x00byte"])
    def test_a_refused_value_is_not_pushed_and_the_query_stays_valid(
        self, db_conn, value: str
    ) -> None:
        """A value that cannot be safely rendered is declined, so the emitted SQL
        carries no condition for it at all -- and the post pass enforces it."""
        policy = _policy(
            row_filters=[RowFilter(field="region", operator=FilterOperator.equals, value=value)]
        )

        sql = rewrite_query("SELECT id, region FROM patients ORDER BY id", policy)

        assert "WHERE" not in sql
        rows = _run(db_conn, sql)
        # Unfiltered from the database, then filtered by the mandatory post pass.
        assert len(rows) == 6
        assert apply_result_pipeline(rows, policy) == []

    @pytest.mark.parametrize("field_name", ['re"gion', "region; DROP TABLE patients", "has space"])
    def test_an_unsafe_field_name_is_not_pushed_and_the_table_survives(
        self, db_conn, field_name: str
    ) -> None:
        policy = _policy(
            row_filters=[
                RowFilter(field=field_name, operator=FilterOperator.equals, value="us-east")
            ]
        )

        sql = rewrite_query("SELECT id FROM patients ORDER BY id", policy)

        assert "WHERE" not in sql
        assert len(_run(db_conn, sql)) == 6
        assert len(_run(db_conn, "SELECT id FROM patients")) == 6

    def test_a_dotted_field_name_resolves_against_the_real_table(self, db_conn) -> None:
        """The qualifier is stripped, so `patients.region` filters `region`."""
        policy = _policy(
            row_filters=[
                RowFilter(field="patients.region", operator=FilterOperator.equals, value="us-east")
            ]
        )

        rows = _run(db_conn, rewrite_query("SELECT id, region FROM patients ORDER BY id", policy))

        assert [r["id"] for r in rows] == [1, 3]

    def test_a_like_pattern_wildcard_is_a_wildcard_not_a_literal(self, db_conn) -> None:
        """``postgres`` explicitly, since that is the dialect that may push ``like``
        at all -- and the engine this test is talking to."""
        policy = _policy(
            row_filters=[RowFilter(field="region", operator=FilterOperator.like, value="us-%")]
        )

        rows = _run(
            db_conn,
            rewrite_query(
                "SELECT id, region FROM patients ORDER BY id",
                policy,
                dialect=SqlDialect.postgres,
            ),
        )

        assert {r["region"] for r in rows} == {"us-east", "us-west", "us-central"}


class TestPrepareSqlQueryAgainstLivePostgres:
    def test_the_prepared_query_executes_and_is_already_filtered(self, db_conn) -> None:
        policy = _policy(
            row_filters=[
                RowFilter(field="region", operator=FilterOperator.in_, values=["us-east"])
            ],
            max_results=10,
        )

        prep = prepare_sql_query("SELECT id, region FROM patients ORDER BY id", policy)

        assert prep.allowed is True
        assert prep.fully_pushed_down is True
        rows = _run(db_conn, prep.query)
        assert [r["id"] for r in rows] == [1, 3]

    def test_a_denied_preparation_s_query_is_never_executed(self, db_conn) -> None:
        """The contract: on denial `query` is the caller's original, and the caller
        must not run it. Shown by running it deliberately -- it returns the
        unfiltered rows, which is why `allowed` has to be checked."""
        policy = _policy(hidden_fields=["ssn"])

        prep = prepare_sql_query("SELECT id, ssn FROM patients", policy)

        assert prep.allowed is False
        assert prep.query == "SELECT id, ssn FROM patients"
        leaked = _run(db_conn, prep.query)
        assert any("ssn" in row for row in leaked)

    def test_an_unpushable_filter_is_reported_and_enforced_post_fetch(self, db_conn) -> None:
        matches = RowFilter(field="region", operator=FilterOperator.matches, value="us-(east|west)")
        policy = _policy(row_filters=[matches])

        prep = prepare_sql_query("SELECT id, region FROM patients ORDER BY id", policy)

        assert prep.unpushable_filters == [matches]
        assert prep.fully_pushed_down is False
        rows = _run(db_conn, prep.query)
        assert len(rows) == 6
        assert len(apply_result_pipeline(rows, policy)) == 4

    def test_a_pushed_filter_on_an_unprojected_column_returns_nothing(self, db_conn) -> None:
        """The footgun, against a real database.

        Postgres filters on `region` correctly and returns 4 rows; the projection
        omits `region`, so the post pass drops all 4 because the field is absent
        (spec section 7 fails closed). Fail-closed, but surprising, so pinned.
        """
        policy = _policy(
            row_filters=[
                RowFilter(field="region", operator=FilterOperator.in_, values=["us-east", "us-west"])
            ]
        )

        prep = prepare_sql_query("SELECT id FROM patients ORDER BY id", policy)
        rows = _run(db_conn, prep.query)

        assert len(rows) == 4
        assert apply_result_pipeline(rows, policy) == []

    def test_including_the_filtered_column_makes_the_two_passes_agree(self, db_conn) -> None:
        """The remedy for the footgun above: project what you filter on."""
        policy = _policy(
            row_filters=[
                RowFilter(field="region", operator=FilterOperator.in_, values=["us-east", "us-west"])
            ]
        )

        prep = prepare_sql_query("SELECT id, region FROM patients ORDER BY id", policy)
        rows = _run(db_conn, prep.query)

        assert len(rows) == 4
        assert apply_result_pipeline(rows, policy) == rows


class TestGeneratedSqlIsAcceptedByPostgres:
    """A rewrite that emits invalid SQL is a broken tool, not a safe one."""

    @pytest.mark.parametrize(
        "query",
        [
            "SELECT id FROM patients",
            "SELECT id FROM patients;",
            "SELECT * FROM patients",
            "SELECT id FROM patients WHERE status = 'active'",
            "SELECT id FROM patients ORDER BY id",
            "SELECT id FROM patients ORDER BY id LIMIT 3",
            "SELECT region, count(*) FROM patients GROUP BY region",
            "SELECT region, count(*) FROM patients GROUP BY region HAVING count(*) > 1",
            "SELECT region, count(*) FROM patients GROUP BY region ORDER BY region",
            "SELECT id FROM patients WHERE id IN (SELECT patient_id FROM encounters)",
            "SELECT p.id, p.region FROM patients p JOIN encounters e ON p.id = e.patient_id",
            "SELECT id FROM patients OFFSET 1",
        ],
    )
    def test_the_rewritten_form_parses_and_runs(self, db_conn, query: str) -> None:
        # `full_name` exists only on `patients`, so the bare identifier the
        # rewriter emits is unambiguous even in the join case; ambiguity has its
        # own test below.
        policy = _policy(
            row_filters=[
                RowFilter(field="full_name", operator=FilterOperator.not_equals, value="nobody")
            ],
            max_results=100,
        )

        sql = rewrite_query(query, policy)

        try:
            _run(db_conn, sql)
        except psycopg.Error as exc:  # pragma: no cover - only on a regression
            pytest.fail(f"rewritten SQL rejected by Postgres: {exc}\nquery={query}\nsql={sql}")

    def test_a_join_where_both_tables_carry_the_column_is_reported_as_ambiguous(
        self, db_conn
    ) -> None:
        """A bare column is emitted deliberately, and a join is where that shows.

        The filter is rendered as `"status"`, not `"patients"."status"`, because a
        table qualifier would not resolve against an aliased `FROM patients p` --
        and TOLAP's field matching already treats `patients.status` and `status` as
        the same field (spec section 4). The cost is that a join in which more than
        one table has the column is ambiguous.

        This is the safe failure: the database refuses the statement rather than
        silently filtering the wrong table's column, which would either leak rows
        or drop the wrong ones. An integrator hitting it should project and filter
        on a single table, or pre-narrow with a subquery. Pinned so the behaviour is
        a known, tested property rather than a surprise in production.
        """
        policy = _policy(
            row_filters=[
                RowFilter(field="status", operator=FilterOperator.not_equals, value="deleted")
            ]
        )
        sql = rewrite_query(
            "SELECT p.id FROM patients p JOIN encounters e ON p.id = e.patient_id", policy
        )

        assert '"status"' in sql
        with pytest.raises(psycopg.errors.AmbiguousColumn):
            _run(db_conn, sql)
