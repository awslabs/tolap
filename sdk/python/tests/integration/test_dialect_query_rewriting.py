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

`TestLikeIsNotPushedWhereTheCollationCouldDisagree` is a **second measured defect of
the same class, and a worse one**. A pushed-down `LIKE` inherits the column's
collation, so `'ALICE JONES' LIKE 'alice%'` is false on Postgres and true under
MySQL's default `utf8mb4_0900_ai_ci`:

    postgres  WHERE (name NOT LIKE 'alice%' OR name IS NULL)  -> mid, high, nullish
    mysql     WHERE (name NOT LIKE 'alice%' OR name IS NULL)  -> high, nullish

The `mid` row is `'ALICE JONES'`. Its disappearing on MySQL is not a fail-closed
quoting mistake but a change in which **real records** a user sees, in either
direction depending on the operator. The fix is to decline the operator on the
profiles that cannot promise a case-sensitive comparison, so both engines reach the
same row set by different routes.

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


# ---------------------------------------------------------------------------
# like/notLike and the column's collation
# ---------------------------------------------------------------------------


#: The three-row set from the shared operator corpus
#: (fixtures/enforcement/apply-row-filters-all-operators.json), which is where the
#: expectations below come from rather than from any implementation. `mid` is the row
#: the two paths disagreed about.
COLLATION_ROWS = [
    ("mid", "ALICE JONES"),
    ("high", "bob stone"),
    ("nullish", None),
]

#: The policy filter that exposed it.
NOT_LIKE_ALICE = RowFilter(
    field="name", operator=FilterOperator.not_like, value="alice%"
)

#: What the case-sensitive post-fetch pass selects for that filter: `'ALICE JONES'`
#: does not match the lowercase pattern, so `mid` is kept, and `nullish` is kept
#: because its field is present with a null value (spec section 7).
#:
#: Compared as a set, because `ORDER BY id` sorts these ids lexically while the
#: corpus lists them in record order. Which rows survive is the claim; their order is
#: the database's business.
NOT_LIKE_ALICE_EXPECTED = {"mid", "high", "nullish"}


def _seed_collation_table_pg(conn) -> str:
    with conn.cursor() as cur:
        cur.execute("CREATE TEMP TABLE collation_probe (id TEXT, name TEXT)")
        for row_id, name in COLLATION_ROWS:
            cur.execute(
                "INSERT INTO collation_probe VALUES (%s, %s)", (row_id, name)
            )
    return "SELECT id, name FROM collation_probe ORDER BY id"


def _seed_collation_table_mysql(conn) -> str:
    with conn.cursor() as cur:
        cur.execute("DROP TEMPORARY TABLE IF EXISTS collation_probe")
        # No explicit COLLATE: the table takes the server default, which is what an
        # integrator's real table has and is the whole point of the case.
        cur.execute(
            "CREATE TEMPORARY TABLE collation_probe "
            "(id VARCHAR(32), name VARCHAR(255)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
        )
        for row_id, name in COLLATION_ROWS:
            cur.execute(
                "INSERT INTO collation_probe VALUES (%s, %s)", (row_id, name)
            )
    conn.commit()
    return "SELECT id, name FROM collation_probe ORDER BY id"


class TestLikeIsNotPushedWhereTheCollationCouldDisagree:
    """The measured `like`/`notLike` defect, executed against both live engines.

    The post-execution pass compares case-SENSITIVELY and is engine-independent, but
    a pushed-down `LIKE` inherits the **column's collation**::

        postgres:  SELECT 'ALICE JONES' LIKE 'alice%'   ->  f
        mysql:     SELECT 'ALICE JONES' LIKE 'alice%'   ->  1     (utf8mb4_0900_ai_ci)

    So a `name notLike 'alice%'` policy used to drop `'ALICE JONES'` on MySQL when
    pushdown was enabled and keep it when it was not -- a difference in which **real
    records** a user sees, which is strictly worse than the null-row asymmetry the
    `IS NULL` arm fixes. `mysql`, `sqlserver` and `ansi` therefore decline the
    operator; `postgres` and `trino` may push it (spec section 4).

    Asserting the emitted text cannot catch this class of bug: the text was
    well-formed and meant something different in the other engine. Only executing it
    against both engines can, which is why this is here and not in the unit suites.
    """

    def test_the_engines_genuinely_disagree_about_the_comparison(
        self, db_conn, mysql_conn
    ) -> None:
        """The mechanism, measured directly -- the premise everything below rests on.

        If this ever stops holding (a MySQL configured with a case-sensitive default
        collation, say), the rest of this class is testing a hazard that is no longer
        present, and that should be noticed here rather than inferred.
        """
        pg = _run_pg(db_conn, "SELECT ('ALICE JONES' LIKE 'alice%') AS cmp")
        assert pg[0]["cmp"] is False

        my = _run_mysql(mysql_conn, "SELECT ('ALICE JONES' LIKE 'alice%') AS cmp")
        assert int(my[0]["cmp"]) == 1

    def test_the_bare_mysql_predicate_would_drop_a_real_row(self, mysql_conn) -> None:
        """**The regression, stated as the row it costs.**

        This is the SQL the rewriter used to emit for `mysql`. Run against the
        corpus it drops `mid` -- `'ALICE JONES'` -- which the post-fetch pass keeps.
        Pinned so the effect is on record independently of whether the rewriter
        happens to emit it.
        """
        query = _seed_collation_table_mysql(mysql_conn)

        dropped = _run_mysql(
            mysql_conn,
            "SELECT id, name FROM collation_probe "
            "WHERE (`name` NOT LIKE 'alice%' OR `name` IS NULL) ORDER BY id",
        )

        assert [r["id"] for r in dropped] == ["high", "nullish"]
        assert "mid" not in [r["id"] for r in dropped]
        # ...while every row is present to begin with.
        assert len(_run_mysql(mysql_conn, query)) == len(COLLATION_ROWS)

    def test_mysql_does_not_push_and_the_post_pass_keeps_the_row(
        self, mysql_conn
    ) -> None:
        """**The regression guard.** `'ALICE JONES'` surviving is the assertion.

        The filter is not pushed, the database returns every row, and the
        case-sensitive post pass produces the corpus answer -- including `mid`, which
        the pushed-down form dropped.
        """
        query = _seed_collation_table_mysql(mysql_conn)
        policy = _policy(row_filters=[NOT_LIKE_ALICE])

        prep = prepare_sql_query(query, policy, dialect=SqlDialect.mysql)

        # Nothing pushed, and the decline is reported rather than silent.
        assert prep.allowed is True
        assert prep.query == query
        assert "LIKE" not in prep.query.upper()
        assert prep.unpushable_filters == [NOT_LIKE_ALICE]
        assert prep.fully_pushed_down is False

        raw = _run_mysql(mysql_conn, prep.query)
        assert len(raw) == len(COLLATION_ROWS)

        enforced = apply_result_pipeline(raw, policy)

        assert {r["id"] for r in enforced} == NOT_LIKE_ALICE_EXPECTED
        # Said the other way round, because this row is the whole point:
        assert "ALICE JONES" in {r["name"] for r in enforced}

    def test_postgres_still_pushes_and_still_agrees_with_the_post_pass(
        self, db_conn
    ) -> None:
        """The profile that was always safe keeps its optimization.

        Declining on MySQL must not cost Postgres its pushdown -- and the pushed-down
        answer must equal the post-fetch answer, which is the equivalence the whole
        rule exists to protect.
        """
        query = _seed_collation_table_pg(db_conn)
        policy = _policy(row_filters=[NOT_LIKE_ALICE])

        prep = prepare_sql_query(query, policy, dialect=SqlDialect.postgres)

        assert prep.rewritten is True
        assert "NOT LIKE 'alice%'" in prep.query
        assert prep.unpushable_filters == []
        assert prep.fully_pushed_down is True

        pushed = _run_pg(db_conn, prep.query)
        post_only = apply_result_pipeline(_run_pg(db_conn, query), policy)

        assert {r["id"] for r in pushed} == NOT_LIKE_ALICE_EXPECTED
        assert {r["id"] for r in post_only} == NOT_LIKE_ALICE_EXPECTED
        assert [r["id"] for r in pushed] == [r["id"] for r in post_only]

    def test_the_same_policy_admits_the_same_rows_on_both_engines(
        self, db_conn, mysql_conn
    ) -> None:
        """The claim the fix is for: one policy, one row set, two engines.

        Postgres reaches it by pushing the filter down; MySQL reaches it by declining
        and letting the post pass do the work. Different *mechanisms*, identical
        *result* -- which is what connector spec section 5.1 promises and what the
        defect broke.
        """
        pg_query = _seed_collation_table_pg(db_conn)
        mysql_query = _seed_collation_table_mysql(mysql_conn)
        policy = _policy(row_filters=[NOT_LIKE_ALICE])

        pg_prep = prepare_sql_query(pg_query, policy, dialect=SqlDialect.postgres)
        mysql_prep = prepare_sql_query(mysql_query, policy, dialect=SqlDialect.mysql)

        pg_rows = apply_result_pipeline(_run_pg(db_conn, pg_prep.query), policy)
        mysql_rows = apply_result_pipeline(
            _run_mysql(mysql_conn, mysql_prep.query), policy
        )

        assert [r["id"] for r in pg_rows] == [r["id"] for r in mysql_rows]
        assert {r["id"] for r in pg_rows} == NOT_LIKE_ALICE_EXPECTED

    def test_a_positive_like_is_declined_on_mysql_and_still_correct(
        self, mysql_conn
    ) -> None:
        """`like` and not only `notLike`. The rule is about the comparison, not the
        negation, so the positive operator is declined on the same profiles -- and
        the post pass gives the case-sensitive answer, which excludes
        `'ALICE JONES'`."""
        query = _seed_collation_table_mysql(mysql_conn)
        rf = RowFilter(field="name", operator=FilterOperator.like, value="alice%")
        policy = _policy(row_filters=[rf])

        prep = prepare_sql_query(query, policy, dialect=SqlDialect.mysql)

        assert prep.query == query
        assert prep.unpushable_filters == [rf]

        enforced = apply_result_pipeline(_run_mysql(mysql_conn, prep.query), policy)

        # No corpus row matches lowercase 'alice%' case-sensitively: 'ALICE JONES' is
        # the wrong case, and a pushed-down MySQL LIKE would have matched it.
        assert enforced == []
        # Proof the pushed-down form would have differed.
        assert [
            r["id"]
            for r in _run_mysql(
                mysql_conn,
                "SELECT id FROM collation_probe WHERE `name` LIKE 'alice%' ORDER BY id",
            )
        ] == ["mid"]

    @pytest.mark.parametrize(
        "dialect", [SqlDialect.mysql, SqlDialect.sqlserver, SqlDialect.ansi]
    )
    @pytest.mark.parametrize(
        "operator", [FilterOperator.like, FilterOperator.not_like]
    )
    def test_no_collate_or_binary_is_emitted_for_any_declining_profile(
        self, dialect: SqlDialect, operator: FilterOperator
    ) -> None:
        """`... LIKE 'alice%' COLLATE utf8mb4_0900_as_cs` and `BINARY ...` both force
        case-sensitivity on MySQL, so this *is* technically emittable. It is
        deliberately not emitted: the right collation name depends on the column's
        character set, which a rewriter holding only a policy and a query string does
        not know, and guessing wrong either fails the query or silently changes the
        comparison again."""
        sql = rewrite_query(
            "SELECT id, name FROM patients",
            _policy(
                row_filters=[RowFilter(field="name", operator=operator, value="alice%")]
            ),
            dialect=dialect,
        )

        assert "COLLATE" not in sql.upper()
        assert "BINARY" not in sql.upper()
        assert sql == "SELECT id, name FROM patients"
