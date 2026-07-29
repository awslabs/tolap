"""The dialect profiles, proven against live Postgres AND live MySQL.

This is the regression suite for a **measured** defect, not a theorised one. The
rewriter emitted Postgres-style double-quoted identifiers for every engine:

    SELECT COUNT(*) FROM patients WHERE "region" = 'us-east'   ->  0   <-- wrong
    SELECT COUNT(*) FROM patients WHERE `region` = 'us-east'   ->  2   <-- correct
    SELECT COUNT(*) FROM patients                              ->  6

MySQL without ``ANSI_QUOTES`` reads ``"region"`` as a *string literal*, so it
evaluated ``'region' = 'us-east'`` -- false for every row. **The engine reported no
error either way**, which is what made this silent: an integrator on MySQL saw empty
results and concluded the product was broken.

The direction of the failure is worth stating precisely. It fails **closed** -- the
policy-filtered query returned *fewer* rows, never more -- so this was a
correctness and availability defect rather than a disclosure. The post-execution
pass remained the security boundary throughout (canonical spec section 4). That is
also why `TestRewritingDeclinedStillReturnsTheRightRows` matters: it shows the rows
are correct even when no rewriting happens at all.

Asserting the emitted SQL *text* cannot catch this class of bug, because the text
was perfectly well-formed -- it just meant something different in the other engine.
Only executing it against both engines can.

Requires Postgres on 5432 and MySQL on 3306, both with `tolap_integration_test`
seeded from schema.sql / schema_mysql.sql; each is skipped independently when its
engine is unreachable (see conftest).
"""

from __future__ import annotations

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
from tolap_core.sql_rewriter import SqlDialect, prepare_sql_query, rewrite_query


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
        source_profiles=["dialect-integration"],
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


#: The policy filter from the measured bug report: region = 'us-east'.
US_EAST = RowFilter(field="region", operator=FilterOperator.equals, value="us-east")

#: The seeded `patients` table holds 6 rows, 2 of them in us-east.
TOTAL_PATIENTS = 6
US_EAST_PATIENTS = 2


def _run_pg(conn, sql: str) -> list[dict]:
    with conn.cursor() as cur:
        cur.execute(sql)
        return list(cur.fetchall())


def _run_mysql(conn, sql: str) -> list[dict]:
    with conn.cursor() as cur:
        cur.execute(sql)
        return list(cur.fetchall())


# ---------------------------------------------------------------------------
# The measured defect, pinned so it cannot come back
# ---------------------------------------------------------------------------


class TestTheMysqlBacktickDefect:
    """The exact case from the bug report, executed against live MySQL."""

    def test_the_mysql_profile_returns_the_correct_rows(self, mysql_conn) -> None:
        """`mysql` profile -> backticks -> 2 rows, which is the right answer."""
        policy = _policy(row_filters=[US_EAST])

        sql = rewrite_query(
            "SELECT id, region FROM patients", policy, dialect=SqlDialect.mysql
        )

        assert "`region`" in sql
        rows = _run_mysql(mysql_conn, sql)

        assert len(rows) == US_EAST_PATIENTS
        assert {r["region"] for r in rows} == {"us-east"}

    def test_the_wrong_profile_silently_returns_nothing(self, mysql_conn) -> None:
        """**This is the regression.** The ansi/postgres profile emits `"region"`,
        which MySQL reads as the string literal 'region', so the predicate is
        `'region' = 'us-east'` -- false for every row.

        Pinned deliberately: if someone makes the default emit double quotes for
        MySQL again, this test fails and names the reason. Note the engine raises
        nothing; the only symptom is the empty result.
        """
        policy = _policy(row_filters=[US_EAST])

        wrong_sql = rewrite_query(
            "SELECT id, region FROM patients", policy, dialect=SqlDialect.postgres
        )

        assert '"region"' in wrong_sql
        assert len(_run_mysql(mysql_conn, wrong_sql)) == 0

        # ...and the same policy with the right profile finds the rows.
        right_sql = rewrite_query(
            "SELECT id, region FROM patients", policy, dialect=SqlDialect.mysql
        )
        assert len(_run_mysql(mysql_conn, right_sql)) == US_EAST_PATIENTS

    def test_the_engine_reports_no_error_for_either_form(self, mysql_conn) -> None:
        """Why this was silent: both statements execute successfully."""
        assert _run_mysql(mysql_conn, "SELECT COUNT(*) AS n FROM patients")[0]["n"] == (
            TOTAL_PATIENTS
        )
        assert _run_mysql(
            mysql_conn, "SELECT COUNT(*) AS n FROM patients WHERE \"region\" = 'us-east'"
        )[0]["n"] == 0
        assert _run_mysql(
            mysql_conn, "SELECT COUNT(*) AS n FROM patients WHERE `region` = 'us-east'"
        )[0]["n"] == US_EAST_PATIENTS

    def test_the_double_quoted_form_is_a_string_comparison(self, mysql_conn) -> None:
        """Direct proof of the mechanism, not just its effect."""
        rows = _run_mysql(mysql_conn, "SELECT \"region\" = 'us-east' AS cmp")

        assert int(rows[0]["cmp"]) == 0

    def test_the_failure_direction_is_closed_not_open(self, mysql_conn) -> None:
        """The wrong profile returned FEWER rows, never more.

        That is what makes this a correctness/availability defect rather than a
        disclosure: no row the policy excludes was ever returned.
        """
        policy = _policy(row_filters=[US_EAST])

        wrong = _run_mysql(
            mysql_conn,
            rewrite_query("SELECT id FROM patients", policy, dialect=SqlDialect.postgres),
        )
        right = _run_mysql(
            mysql_conn,
            rewrite_query("SELECT id FROM patients", policy, dialect=SqlDialect.mysql),
        )

        assert len(wrong) < len(right)
        assert len(wrong) == 0


class TestPostgresIsUnaffected:
    """The profile that was always correct stays correct."""

    def test_the_postgres_profile_returns_the_correct_rows(self, db_conn) -> None:
        policy = _policy(row_filters=[US_EAST])

        sql = rewrite_query(
            "SELECT id, region FROM patients", policy, dialect=SqlDialect.postgres
        )

        assert '"region"' in sql
        rows = _run_pg(db_conn, sql)

        assert len(rows) == US_EAST_PATIENTS
        assert {r["region"] for r in rows} == {"us-east"}

    def test_the_ansi_profile_also_works_on_postgres(self, db_conn) -> None:
        """`ansi` is the default, and Postgres accepts it -- which is exactly why
        the defect went unnoticed for so long."""
        policy = _policy(row_filters=[US_EAST])

        rows = _run_pg(
            db_conn,
            rewrite_query("SELECT id, region FROM patients", policy, dialect=SqlDialect.ansi),
        )

        assert len(rows) == US_EAST_PATIENTS

    def test_the_mysql_profile_is_a_syntax_error_on_postgres(self, db_conn) -> None:
        """The mirror image, which shows the profiles are genuinely not
        interchangeable. Postgres has no backtick quoting at all, so here the wrong
        profile fails loudly rather than silently -- the *lucky* direction."""
        import psycopg

        policy = _policy(row_filters=[US_EAST])
        sql = rewrite_query("SELECT id FROM patients", policy, dialect=SqlDialect.mysql)

        with pytest.raises(psycopg.Error):
            _run_pg(db_conn, sql)


# ---------------------------------------------------------------------------
# Both engines, same policy, correct rows
# ---------------------------------------------------------------------------


class TestTheSamePolicyAdmitsTheSameRowsOnBothEngines:
    """Only the emitted text differs by dialect; the row set must not.

    Connector spec section 5.1: "enabling rewriting never changes which rows a
    policy admits, only where the work happens."
    """

    def test_the_row_count_agrees_across_engines(self, db_conn, mysql_conn) -> None:
        policy = _policy(row_filters=[US_EAST])

        pg_rows = _run_pg(
            db_conn,
            rewrite_query("SELECT id FROM patients", policy, dialect=SqlDialect.postgres),
        )
        mysql_rows = _run_mysql(
            mysql_conn,
            rewrite_query("SELECT id FROM patients", policy, dialect=SqlDialect.mysql),
        )

        assert len(pg_rows) == len(mysql_rows) == US_EAST_PATIENTS

    def test_a_limit_is_pushed_on_both_engines(self, db_conn, mysql_conn) -> None:
        policy = _policy(max_results=3)

        pg_rows = _run_pg(
            db_conn, rewrite_query("SELECT id FROM patients", policy, dialect=SqlDialect.postgres)
        )
        mysql_rows = _run_mysql(
            mysql_conn,
            rewrite_query("SELECT id FROM patients", policy, dialect=SqlDialect.mysql),
        )

        assert len(pg_rows) == len(mysql_rows) == 3

    def test_a_projection_is_pushed_on_both_engines(self, db_conn, mysql_conn) -> None:
        policy = _policy(allowed_fields=["id", "region"], hidden_fields=["ssn"])

        pg_sql = rewrite_query(
            "SELECT * FROM patients", policy, dialect=SqlDialect.postgres
        )
        mysql_sql = rewrite_query(
            "SELECT * FROM patients", policy, dialect=SqlDialect.mysql
        )

        assert pg_sql == 'SELECT "id", "region" FROM patients'
        assert mysql_sql == "SELECT `id`, `region` FROM patients"

        pg_rows = _run_pg(db_conn, pg_sql)
        mysql_rows = _run_mysql(mysql_conn, mysql_sql)

        assert {*pg_rows[0]} == {*mysql_rows[0]} == {"id", "region"}
        # The hidden column never left either database.
        assert "ssn" not in pg_rows[0]
        assert "ssn" not in mysql_rows[0]


# ---------------------------------------------------------------------------
# Declining to rewrite is safe, because the post pass is the boundary
# ---------------------------------------------------------------------------


class TestRewritingDeclinedStillReturnsTheRightRows:
    """An unrecognized dialect rewrites nothing -- and the rows are still correct.

    This is the load-bearing claim behind rule 2. Declining is only acceptable
    because the post-execution pass was always the enforcement boundary (canonical
    spec section 4), so it is asserted end to end against both live engines rather
    than argued.
    """

    def test_mysql_rows_are_correct_with_rewriting_declined(self, mysql_conn) -> None:
        policy = _policy(row_filters=[US_EAST])

        prep = prepare_sql_query(
            "SELECT id, region FROM patients", policy, dialect="oracle"
        )

        # Nothing was pushed down: the database returns every row...
        assert prep.rewritten is False
        assert prep.unpushable_filters == [US_EAST]
        assert prep.fully_pushed_down is False

        raw = _run_mysql(mysql_conn, prep.query)
        assert len(raw) == TOTAL_PATIENTS

        # ...and the post pass produces exactly the right ones.
        enforced = apply_result_pipeline(raw, policy)
        assert len(enforced) == US_EAST_PATIENTS
        assert {r["region"] for r in enforced} == {"us-east"}

    def test_postgres_rows_are_correct_with_rewriting_declined(self, db_conn) -> None:
        policy = _policy(row_filters=[US_EAST])

        prep = prepare_sql_query(
            "SELECT id, region FROM patients", policy, dialect="oracle"
        )

        raw = _run_pg(db_conn, prep.query)
        assert len(raw) == TOTAL_PATIENTS

        enforced = apply_result_pipeline(raw, policy)
        assert len(enforced) == US_EAST_PATIENTS
        assert {r["region"] for r in enforced} == {"us-east"}

    def test_a_declined_limit_is_still_applied_after_the_fetch(self, mysql_conn) -> None:
        policy = _policy(max_results=2)

        prep = prepare_sql_query("SELECT id FROM patients", policy, dialect="oracle")

        assert len(_run_mysql(mysql_conn, prep.query)) == TOTAL_PATIENTS
        assert len(apply_result_pipeline(_run_mysql(mysql_conn, prep.query), policy)) == 2

    def test_declining_never_relaxes_a_denial(self, mysql_conn) -> None:
        """The pre-execution checks are not part of the rewrite and must still run."""
        prep = prepare_sql_query(
            "SELECT ssn FROM patients", _policy(hidden_fields=["ssn"]), dialect="oracle"
        )

        assert prep.allowed is False
        assert prep.denial_reason is not None


# ---------------------------------------------------------------------------
# Refusals hold against a live engine
# ---------------------------------------------------------------------------


class TestRefusalsHoldOnBothEngines:
    """A refused value stays out of the statement, and the rows stay correct.

    Executing this is the point: asserting a value was refused proves the refusal;
    running the query proves the *result* is still right, which a hand-checked
    expectation about quoting can easily get wrong.
    """

    @pytest.mark.parametrize(
        "dialect", [SqlDialect.mysql, SqlDialect.postgres, SqlDialect.ansi]
    )
    def test_a_backslash_value_never_reaches_the_statement(
        self, mysql_conn, db_conn, dialect: SqlDialect
    ) -> None:
        rf = RowFilter(
            field="region",
            operator=FilterOperator.equals,
            value="us-east\\' OR 1=1 --",
        )
        policy = _policy(row_filters=[rf])

        sql = rewrite_query("SELECT id, region FROM patients", policy, dialect=dialect)

        assert sql == "SELECT id, region FROM patients"
        assert "\\" not in sql

        conn = mysql_conn if dialect is SqlDialect.mysql else db_conn
        runner = _run_mysql if dialect is SqlDialect.mysql else _run_pg

        # The refused filter is enforced after the fetch instead, and admits no row:
        # no seeded region matches that literal text.
        raw = runner(conn, sql)
        assert len(raw) == TOTAL_PATIENTS
        assert apply_result_pipeline(raw, policy) == []

    def test_a_quoted_value_is_escaped_and_executes_on_mysql(self, mysql_conn) -> None:
        """An ordinary apostrophe is doubled, not refused, and MySQL accepts it."""
        rf = RowFilter(
            field="region", operator=FilterOperator.equals, value="it's-not-a-region"
        )
        sql = rewrite_query(
            "SELECT id FROM patients", _policy(row_filters=[rf]), dialect=SqlDialect.mysql
        )

        assert "'it''s-not-a-region'" in sql
        assert _run_mysql(mysql_conn, sql) == []
