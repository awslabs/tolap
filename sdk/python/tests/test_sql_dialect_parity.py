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
from tolap_core.sql_rewriter import rewrite_query


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
        permissions=PolicyPermissions(can_query=True, can_export=False, read_only=True),
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
    (
        "like-mysql",
        "SELECT a FROM t",
        "like",
        "mysql",
        "SELECT a FROM t WHERE `region` LIKE 'us-%'",
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


def test_the_corpus_covers_every_profile_and_both_decline_paths() -> None:
    """A guard on the corpus itself, so it cannot quietly stop covering a profile."""
    dialects = {row[3] for row in PARITY_CORPUS}

    assert {"ansi", "postgres", "trino", "mysql", "sqlserver"} <= dialects
    # The unrecognized-dialect path is part of the contract and must stay covered.
    assert "oracle" in dialects


def test_every_case_id_is_unique() -> None:
    ids = [row[0] for row in PARITY_CORPUS]

    assert len(ids) == len(set(ids))
