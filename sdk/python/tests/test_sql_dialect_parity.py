"""Cross-SDK emitted-SQL parity for the dialect profiles.

**The same query + policy + profile must produce the SAME SQL text in Python,
TypeScript, and .NET.** This corpus is duplicated verbatim in all three SDKs:

  - sdk/python/tests/test_sql_dialect_parity.py            (this file)
  - sdk/typescript/packages/core/tests/sql-dialect-parity.test.ts
  - sdk/dotnet/tests/Tolap.Core.Tests/SqlDialectParityTests.cs

Every row is the exact string all three emit. A change to any one SDK's output
fails that SDK's copy and names the case, which is the point: three
implementations of one spec drift silently otherwise, and drift here means the
same policy behaves differently depending on which SDK an integrator picked.

Building this corpus found two real divergences that the per-SDK suites had
missed, both in the WHERE-injection path and both since fixed:

  - **.NET** left the original WHERE body unparenthesised, emitting
    `WHERE (filters) AND a = 1 OR b = 2`. AND binds tighter than OR, so that
    parses as `((filters) AND a = 1) OR b = 2` and admits every row matching
    `b` -- the known fail-open, which .NET's own test had *pinned* as expected.
  - **TypeScript** took the WHERE body to the end of the statement, pulling
    trailing clauses inside the added parentheses and emitting
    `WHERE (f) AND (status = 'active' ORDER BY a)` -- rejected outright as a
    syntax error by both Postgres and MySQL.

Neither was a dialect bug. Both were found only because parity was asserted
across SDKs on a shared corpus.

There are two corpora here, and both must agree across SDKs:
:data:`PARITY_CORPUS` fixes the emitted SQL text, and
:data:`UNPUSHABLE_PARITY_CORPUS` fixes how many filters each SDK reports as
unpushable. The second exists because ``like``/``notLike`` are *declined* on the
profiles whose collation could make ``LIKE`` case-insensitive, and a decline is only
correct if it is also reported -- text parity alone cannot tell "not pushed, and the
post pass is carrying it" apart from "silently dropped".
"""

from __future__ import annotations

import pytest

from tolap_core.enums import FilterOperator
from tolap_core.models import (
    EffectivePolicy,
    FieldRules,
    ObjectRules,
    PolicyLimits,
    PolicyPermissions,
    RowFilter,
)
from tolap_core.sql_rewriter import rewrite_query, unpushable_filters


def _policy(spec: str) -> EffectivePolicy:
    """The policy each corpus row names, built identically in all three SDKs."""
    row_filters: list[RowFilter] | None = None
    max_results: int | None = None
    field_rules: FieldRules | None = None

    def eq(field: str, value: object) -> list[RowFilter]:
        return [RowFilter(field=field, operator=FilterOperator.equals, value=value)]

    if spec == "us_filter":
        row_filters = eq("region", "us-east")
    elif spec == "limit10":
        max_results = 10
    elif spec == "us_filter_limit10":
        row_filters = eq("region", "us-east")
        max_results = 10
    elif spec == "fields":
        field_rules = FieldRules(allowed_fields=["id", "region"], hidden_fields=["ssn"])
    elif spec == "not_deleted":
        row_filters = [
            RowFilter(field="status", operator=FilterOperator.not_equals, value="deleted")
        ]
    elif spec == "in_regions":
        row_filters = [
            RowFilter(field="region", operator=FilterOperator.in_, values=["us-east", "us-west"])
        ]
    elif spec == "notin_regions":
        row_filters = [
            RowFilter(field="region", operator=FilterOperator.not_in, values=["eu-west"])
        ]
    elif spec == "between":
        row_filters = [
            RowFilter(field="age", operator=FilterOperator.between, values=[18, 65])
        ]
    elif spec == "isnull":
        row_filters = [RowFilter(field="deleted_at", operator=FilterOperator.is_null)]
    elif spec == "like":
        row_filters = [
            RowFilter(field="region", operator=FilterOperator.like, value="us-%")
        ]
    elif spec == "notlike":
        row_filters = [
            RowFilter(field="region", operator=FilterOperator.not_like, value="us-%")
        ]
    elif spec == "backslash":
        row_filters = eq("region", "us\\' OR 1=1 --")
    elif spec == "quote_in_field_backtick":
        row_filters = eq("reg`ion", "x")
    elif spec == "quote_in_field_dquote":
        row_filters = eq('reg"ion', "x")
    elif spec == "quote_in_field_bracket":
        row_filters = eq("reg[ion", "x")
    elif spec == "apostrophe":
        row_filters = eq("region", "it's")
    elif spec == "wrapped_field":
        row_filters = eq("[region]", "x")
    elif spec == "dotted_field":
        row_filters = eq("patients.region", "x")
    elif spec == "contains":
        row_filters = [
            RowFilter(field="region", operator=FilterOperator.contains, value="us")
        ]
    else:  # pragma: no cover - a typo in the corpus, not a code path
        raise AssertionError(f"unknown policy spec: {spec}")

    has_object_rules = field_rules is not None or row_filters is not None
    return EffectivePolicy(
        version="1.0",
        user_id="u",
        tenant_id="t",
        source_profiles=["parity"],
        permissions=PolicyPermissions(can_query=True, read_only=True),
        object_rules=ObjectRules(field_rules=field_rules, row_filters=row_filters)
        if has_object_rules
        else None,
        limits=PolicyLimits(max_results=max_results) if max_results is not None else None,
    )


#: (case id, query, policy spec, dialect, the SQL all three SDKs must emit).
PARITY_CORPUS: list[tuple[str, str, str, str, str]] = [
    (
        "filter-ansi",
        "SELECT id, region FROM patients",
        "us_filter",
        "ansi",
        "SELECT id, region FROM patients WHERE \"region\" = 'us-east'",
    ),
    (
        "filter-postgres",
        "SELECT id, region FROM patients",
        "us_filter",
        "postgres",
        "SELECT id, region FROM patients WHERE \"region\" = 'us-east'",
    ),
    (
        "filter-trino",
        "SELECT id, region FROM patients",
        "us_filter",
        "trino",
        "SELECT id, region FROM patients WHERE \"region\" = 'us-east'",
    ),
    (
        "filter-mysql",
        "SELECT id, region FROM patients",
        "us_filter",
        "mysql",
        "SELECT id, region FROM patients WHERE `region` = 'us-east'",
    ),
    (
        "filter-sqlserver",
        "SELECT id, region FROM patients",
        "us_filter",
        "sqlserver",
        "SELECT id, region FROM patients WHERE [region] = 'us-east'",
    ),
    (
        "filter-unknown",
        "SELECT id, region FROM patients",
        "us_filter",
        "oracle",
        "SELECT id, region FROM patients",
    ),
    (
        "limit-ansi",
        "SELECT a FROM t",
        "limit10",
        "ansi",
        "SELECT a FROM t LIMIT 10",
    ),
    (
        "limit-mysql",
        "SELECT a FROM t",
        "limit10",
        "mysql",
        "SELECT a FROM t LIMIT 10",
    ),
    (
        "limit-sqlserver",
        "SELECT a FROM t",
        "limit10",
        "sqlserver",
        "SELECT TOP 10 a FROM t",
    ),
    (
        "limit-clamp-ansi",
        "SELECT a FROM t LIMIT 900",
        "limit10",
        "ansi",
        "SELECT a FROM t LIMIT 10",
    ),
    (
        "limit-clamp-mysql",
        "SELECT a FROM t LIMIT 900",
        "limit10",
        "mysql",
        "SELECT a FROM t LIMIT 10",
    ),
    (
        "both-ansi",
        "SELECT a FROM t",
        "us_filter_limit10",
        "ansi",
        "SELECT a FROM t WHERE \"region\" = 'us-east' LIMIT 10",
    ),
    (
        "both-mysql",
        "SELECT a FROM t",
        "us_filter_limit10",
        "mysql",
        "SELECT a FROM t WHERE `region` = 'us-east' LIMIT 10",
    ),
    (
        "both-sqlserver",
        "SELECT a FROM t",
        "us_filter_limit10",
        "sqlserver",
        "SELECT TOP 10 a FROM t WHERE [region] = 'us-east'",
    ),
    (
        "star-ansi",
        "SELECT * FROM patients",
        "fields",
        "ansi",
        "SELECT \"id\", \"region\" FROM patients",
    ),
    (
        "star-mysql",
        "SELECT * FROM patients",
        "fields",
        "mysql",
        "SELECT `id`, `region` FROM patients",
    ),
    (
        "star-sqlserver",
        "SELECT * FROM patients",
        "fields",
        "sqlserver",
        "SELECT [id], [region] FROM patients",
    ),
    (
        "existing-where-ansi",
        "SELECT a FROM t WHERE x = 1 OR y = 2",
        "us_filter",
        "ansi",
        "SELECT a FROM t WHERE (\"region\" = 'us-east') AND (x = 1 OR y = 2)",
    ),
    (
        "existing-where-mysql",
        "SELECT a FROM t WHERE x = 1 OR y = 2",
        "us_filter",
        "mysql",
        "SELECT a FROM t WHERE (`region` = 'us-east') AND (x = 1 OR y = 2)",
    ),
    (
        "existing-where-orderby-mysql",
        "SELECT a FROM t WHERE status = 'active' ORDER BY a",
        "us_filter_limit10",
        "mysql",
        "SELECT a FROM t WHERE (`region` = 'us-east') AND (status = 'active') ORDER BY a LIMIT 10",
    ),
    (
        "distinct-sqlserver",
        "SELECT DISTINCT a FROM t",
        "limit10",
        "sqlserver",
        "SELECT DISTINCT TOP 10 a FROM t",
    ),
    (
        "all-sqlserver",
        "SELECT ALL a FROM t",
        "limit10",
        "sqlserver",
        "SELECT ALL TOP 10 a FROM t",
    ),
    (
        "existing-top-sqlserver",
        "SELECT TOP 50 a FROM t",
        "limit10",
        "sqlserver",
        "SELECT TOP 10 a FROM t",
    ),
    (
        "existing-top-paren-sqlserver",
        "SELECT TOP (50) a FROM t",
        "limit10",
        "sqlserver",
        "SELECT TOP 10 a FROM t",
    ),
    (
        "existing-top-smaller-sqlserver",
        "SELECT TOP 3 a FROM t",
        "limit10",
        "sqlserver",
        "SELECT TOP 3 a FROM t",
    ),
    (
        "top-percent-sqlserver",
        "SELECT TOP 5 PERCENT a FROM t",
        "limit10",
        "sqlserver",
        "SELECT TOP 5 PERCENT a FROM t",
    ),
    (
        "top-withties-sqlserver",
        "SELECT TOP 5 WITH TIES a FROM t ORDER BY a",
        "limit10",
        "sqlserver",
        "SELECT TOP 5 WITH TIES a FROM t ORDER BY a",
    ),
    (
        "union-sqlserver",
        "SELECT a FROM t UNION SELECT b FROM u",
        "limit10",
        "sqlserver",
        "SELECT a FROM t UNION SELECT b FROM u",
    ),
    (
        "offset-sqlserver",
        "SELECT a FROM t ORDER BY a OFFSET 5 ROWS",
        "limit10",
        "sqlserver",
        "SELECT a FROM t ORDER BY a OFFSET 5 ROWS",
    ),
    (
        "limitkw-sqlserver",
        "SELECT a FROM t LIMIT 50",
        "limit10",
        "sqlserver",
        "SELECT a FROM t LIMIT 50",
    ),
    (
        "nonselect-sqlserver",
        "DELETE FROM t",
        "limit10",
        "sqlserver",
        "DELETE FROM t",
    ),
    (
        "groupby-mysql",
        "SELECT region, count(*) FROM t GROUP BY region",
        "us_filter",
        "mysql",
        "SELECT region, count(*) FROM t WHERE `region` = 'us-east' GROUP BY region",
    ),
    (
        "subquery-mysql",
        "SELECT a FROM t WHERE id IN (SELECT id FROM u WHERE x = 1)",
        "us_filter",
        "mysql",
        "SELECT a FROM t WHERE (`region` = 'us-east') AND (id IN (SELECT id FROM u WHERE x = 1))",
    ),
    (
        "notequals-mysql",
        "SELECT a FROM t",
        "not_deleted",
        "mysql",
        "SELECT a FROM t WHERE (`status` <> 'deleted' OR `status` IS NULL)",
    ),
    (
        "notequals-sqlserver",
        "SELECT a FROM t",
        "not_deleted",
        "sqlserver",
        "SELECT a FROM t WHERE ([status] <> 'deleted' OR [status] IS NULL)",
    ),
    (
        "in-mysql",
        "SELECT a FROM t",
        "in_regions",
        "mysql",
        "SELECT a FROM t WHERE `region` IN ('us-east', 'us-west')",
    ),
    (
        "notin-mysql",
        "SELECT a FROM t",
        "notin_regions",
        "mysql",
        "SELECT a FROM t WHERE (`region` NOT IN ('eu-west') OR `region` IS NULL)",
    ),
    (
        "between-mysql",
        "SELECT a FROM t",
        "between",
        "mysql",
        "SELECT a FROM t WHERE `age` BETWEEN 18 AND 65",
    ),
    (
        "isnull-mysql",
        "SELECT a FROM t",
        "isnull",
        "mysql",
        "SELECT a FROM t WHERE `deleted_at` IS NULL",
    ),
    # like/notLike, every profile x both operators. The emitted text is the whole
    # point of the case: `postgres`/`trino` push a real LIKE, and `mysql`,
    # `sqlserver` and `ansi` emit the query untouched because their collation could
    # make the comparison case-insensitive (spec section 4).
    (
        "like-postgres",
        "SELECT a FROM t",
        "like",
        "postgres",
        "SELECT a FROM t WHERE \"region\" LIKE 'us-%'",
    ),
    (
        "like-trino",
        "SELECT a FROM t",
        "like",
        "trino",
        "SELECT a FROM t WHERE \"region\" LIKE 'us-%'",
    ),
    (
        "like-mysql",
        "SELECT a FROM t",
        "like",
        "mysql",
        "SELECT a FROM t",
    ),
    (
        "like-sqlserver",
        "SELECT a FROM t",
        "like",
        "sqlserver",
        "SELECT a FROM t",
    ),
    (
        "like-ansi",
        "SELECT a FROM t",
        "like",
        "ansi",
        "SELECT a FROM t",
    ),
    (
        "notlike-postgres",
        "SELECT a FROM t",
        "notlike",
        "postgres",
        "SELECT a FROM t WHERE (\"region\" NOT LIKE 'us-%' OR \"region\" IS NULL)",
    ),
    (
        "notlike-trino",
        "SELECT a FROM t",
        "notlike",
        "trino",
        "SELECT a FROM t WHERE (\"region\" NOT LIKE 'us-%' OR \"region\" IS NULL)",
    ),
    (
        "notlike-mysql",
        "SELECT a FROM t",
        "notlike",
        "mysql",
        "SELECT a FROM t",
    ),
    (
        "notlike-sqlserver",
        "SELECT a FROM t",
        "notlike",
        "sqlserver",
        "SELECT a FROM t",
    ),
    (
        "notlike-ansi",
        "SELECT a FROM t",
        "notlike",
        "ansi",
        "SELECT a FROM t",
    ),
    (
        "backslash-mysql",
        "SELECT a FROM t",
        "backslash",
        "mysql",
        "SELECT a FROM t",
    ),
    (
        "backslash-ansi",
        "SELECT a FROM t",
        "backslash",
        "ansi",
        "SELECT a FROM t",
    ),
    (
        "backslash-sqlserver",
        "SELECT a FROM t",
        "backslash",
        "sqlserver",
        "SELECT a FROM t",
    ),
    (
        "quotefield-mysql",
        "SELECT a FROM t",
        "quote_in_field_backtick",
        "mysql",
        "SELECT a FROM t",
    ),
    (
        "quotefield-ansi",
        "SELECT a FROM t",
        "quote_in_field_dquote",
        "ansi",
        "SELECT a FROM t",
    ),
    (
        "quotefield-sqlserver",
        "SELECT a FROM t",
        "quote_in_field_bracket",
        "sqlserver",
        "SELECT a FROM t",
    ),
    (
        "apostrophe-mysql",
        "SELECT a FROM t",
        "apostrophe",
        "mysql",
        "SELECT a FROM t WHERE `region` = 'it''s'",
    ),
    (
        "wrapped-field-mysql",
        "SELECT a FROM t",
        "wrapped_field",
        "mysql",
        "SELECT a FROM t WHERE `region` = 'x'",
    ),
    (
        "wrapped-field-sqlserver",
        "SELECT a FROM t",
        "wrapped_field",
        "sqlserver",
        "SELECT a FROM t WHERE [region] = 'x'",
    ),
    (
        "dotted-field-mysql",
        "SELECT a FROM t",
        "dotted_field",
        "mysql",
        "SELECT a FROM t WHERE `region` = 'x'",
    ),
    (
        "unpushable-op-mysql",
        "SELECT a FROM t",
        "contains",
        "mysql",
        "SELECT a FROM t",
    ),
]


@pytest.mark.parametrize(
    ("case_id", "query", "spec", "dialect", "expected"),
    PARITY_CORPUS,
    ids=[row[0] for row in PARITY_CORPUS],
)
def test_the_emitted_sql_matches_the_cross_sdk_corpus(
    case_id: str, query: str, spec: str, dialect: str, expected: str
) -> None:
    assert rewrite_query(query, _policy(spec), dialect=dialect) == expected


#: (case id, policy spec, dialect, how many filters all three SDKs must report as
#: unpushable). The emitted text and this report are two halves of one contract: a
#: filter that vanishes from the SQL without being reported would be a silent loss of
#: the optimization at best, and at worst an integrator's `fully_pushed_down`
#: assertion passing while the database returns unfiltered rows. Duplicated verbatim
#: in all three SDKs alongside PARITY_CORPUS.
UNPUSHABLE_PARITY_CORPUS: list[tuple[str, str, str, int]] = [
    # like/notLike: pushed on the case-sensitive profiles, reported on the others.
    ("like-postgres", "like", "postgres", 0),
    ("like-trino", "like", "trino", 0),
    ("like-mysql", "like", "mysql", 1),
    ("like-sqlserver", "like", "sqlserver", 1),
    ("like-ansi", "like", "ansi", 1),
    ("notlike-postgres", "notlike", "postgres", 0),
    ("notlike-trino", "notlike", "trino", 0),
    ("notlike-mysql", "notlike", "mysql", 1),
    ("notlike-sqlserver", "notlike", "sqlserver", 1),
    ("notlike-ansi", "notlike", "ansi", 1),
    # The decline paths that were already dialect-independent, held here so the two
    # kinds of decline are asserted by the same mechanism.
    ("contains-mysql", "contains", "mysql", 1),
    ("contains-postgres", "contains", "postgres", 1),
    ("backslash-postgres", "backslash", "postgres", 1),
    ("backslash-mysql", "backslash", "mysql", 1),
    ("equals-postgres", "us_filter", "postgres", 0),
    ("equals-mysql", "us_filter", "mysql", 0),
    # An unrecognized dialect rewrites nothing, so every filter is reported.
    ("like-unknown", "like", "oracle", 1),
    ("equals-unknown", "us_filter", "oracle", 1),
]


@pytest.mark.parametrize(
    ("case_id", "spec", "dialect", "expected_count"),
    UNPUSHABLE_PARITY_CORPUS,
    ids=[row[0] for row in UNPUSHABLE_PARITY_CORPUS],
)
def test_the_unpushable_report_matches_the_cross_sdk_corpus(
    case_id: str, spec: str, dialect: str, expected_count: int
) -> None:
    assert len(unpushable_filters(_policy(spec), dialect=dialect)) == expected_count


def test_the_corpus_covers_every_profile_and_both_decline_paths() -> None:
    """A guard on the corpus itself, so it cannot quietly stop covering a profile."""
    dialects = {row[3] for row in PARITY_CORPUS}

    assert {"ansi", "postgres", "trino", "mysql", "sqlserver"} <= dialects
    # The unrecognized-dialect path is part of the contract and must stay covered.
    assert "oracle" in dialects


def test_the_like_gate_is_covered_for_every_profile_and_both_operators() -> None:
    """``like``/``notLike`` are the one operator pair whose *pushability* depends on
    the dialect, so the corpus must state an answer for all five profiles rather
    than sampling one or two."""
    for spec in ("like", "notlike"):
        covered = {
            row[3] for row in PARITY_CORPUS if row[2] == spec and row[3] != "oracle"
        }
        assert covered == {"ansi", "postgres", "trino", "mysql", "sqlserver"}, spec

        reported = {
            row[2] for row in UNPUSHABLE_PARITY_CORPUS
            if row[1] == spec and row[2] != "oracle"
        }
        assert reported == {"ansi", "postgres", "trino", "mysql", "sqlserver"}, spec


def test_every_case_id_is_unique() -> None:
    ids = [row[0] for row in PARITY_CORPUS]

    assert len(ids) == len(set(ids))

    unpushable_ids = [row[0] for row in UNPUSHABLE_PARITY_CORPUS]

    assert len(unpushable_ids) == len(set(unpushable_ids))
