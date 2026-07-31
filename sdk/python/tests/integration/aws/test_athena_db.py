"""`db` enforcement against real Athena / Trino (connector-spec §5).

The SQL rewriter carries a `trino` dialect profile -- which is what Athena speaks -- but
every existing test exercises it against Postgres and MySQL only. That matters more than a
missing engine: this is the category where a rewrite bug means **the database itself returns
unauthorized rows**, before any post-fetch filtering gets a chance. A `WHERE`-clause
fail-open was found in this rewriter's history exactly once before, and it was found by
running the generated SQL rather than by reading it.

So these tests take the SQL the shipped rewriter produces, execute it on Athena, and assert
on the rows Athena actually returned. Two properties are checked separately, because they
fail in different ways:

**Pushdown correctness.** The rewritten query must not return a row the policy excludes.
If the engine parses our `WHERE` differently than Postgres does, this is where it surfaces.

**Post-fetch completeness.** The rewriter deliberately does not push everything down --
`SELECT *` stays `*`, and hidden fields are removed after the fetch. So the pipeline must
still be run over the results, and the test asserts the combination is correct rather than
assuming the rewrite alone is sufficient.

Athena is used rather than Redshift because it is serverless: no cluster to provision, and
the only standing artifact is a Glue table over the seeded S3 data, deleted on teardown.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from tolap_core.enforcement import apply_result_pipeline
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
from tolap_core.sql_rewriter import SqlDialect, prepare_sql_query

# The seeded rows. Two regions and one row carrying an ssn, so row filters, field rules and
# limits each have something to bite on and something to leave alone.
ROWS = [
    ("1", "us-east", "Alice", "111-11-1111"),
    ("2", "us-east", "Bob", "222-22-2222"),
    ("3", "us-west", "Carol", "333-33-3333"),
    ("4", "eu-west", "Dave", "444-44-4444"),
]


def _policy(
    *,
    allowed_objects: list[str] | None = None,
    field_rules: FieldRules | None = None,
    row_filters: list[RowFilter] | None = None,
    limits: PolicyLimits | None = None,
    can_query: bool = True,
) -> EffectivePolicy:
    now = datetime.now(timezone.utc)
    return EffectivePolicy(
        version="1.0",
        user_id="athena-user",
        tenant_id="athena-tenant",
        source_connection_id="db:analytics:patients",
        resolved_at=now,
        expires_at=now + timedelta(hours=1),
        source_profiles=["athena-test"],
        permissions=PolicyPermissions(can_query=can_query, read_only=True),
        object_rules=ObjectRules(
            allowed_objects=allowed_objects,
            field_rules=field_rules,
            row_filters=row_filters,
        ),
        limits=limits,
    )


@pytest.fixture(scope="session")
def athena(aws_region: str):
    boto3 = pytest.importorskip("boto3")
    return boto3.client("athena", region_name=aws_region)


@pytest.fixture(scope="session")
def glue(aws_region: str):
    boto3 = pytest.importorskip("boto3")
    return boto3.client("glue", region_name=aws_region)


@pytest.fixture(scope="session")
def athena_table(s3_client, athena, glue, aws_region: str):
    """Seed S3 with CSV rows, register a Glue database + table, yield query context.

    Everything carries the same random suffix and is deleted on teardown. The Athena
    results bucket is the account's existing default -- Athena requires an output location
    and creating a second one per run would be needless.
    """
    suffix = uuid.uuid4().hex[:10]
    bucket = f"tolap-athena-{suffix}"
    database = f"tolap_db_{suffix}"
    table = "patients"
    results = f"s3://tolap-athena-{suffix}/_results/"

    s3_client.create_bucket(Bucket=bucket)
    try:
        body = "\n".join(",".join(r) for r in ROWS) + "\n"
        s3_client.put_object(Bucket=bucket, Key=f"{table}/data.csv", Body=body.encode())

        glue.create_database(DatabaseInput={"Name": database})
        glue.create_table(
            DatabaseName=database,
            TableInput={
                "Name": table,
                "StorageDescriptor": {
                    "Columns": [
                        {"Name": "id", "Type": "string"},
                        {"Name": "region", "Type": "string"},
                        {"Name": "full_name", "Type": "string"},
                        {"Name": "ssn", "Type": "string"},
                    ],
                    "Location": f"s3://{bucket}/{table}/",
                    "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                    "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                    "SerdeInfo": {
                        "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                        "Parameters": {"field.delim": ","},
                    },
                },
                "TableType": "EXTERNAL_TABLE",
            },
        )
        yield {"database": database, "table": table, "results": results}
    finally:
        try:
            glue.delete_table(DatabaseName=database, Name=table)
        except Exception:
            pass
        try:
            glue.delete_database(Name=database)
        except Exception:
            pass
        _empty_and_delete(s3_client, bucket)


def _empty_and_delete(s3_client, bucket: str) -> None:
    for page in s3_client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        objs = page.get("Contents") or []
        if objs:
            s3_client.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            )
    s3_client.delete_bucket(Bucket=bucket)


def _run_query(athena, ctx: dict, sql: str) -> list[dict]:
    """Execute SQL on Athena and return rows as dicts. Raises on query failure."""
    started = athena.start_query_execution(
        QueryString=sql,
        QueryExecutionContext={"Database": ctx["database"]},
        ResultConfiguration={"OutputLocation": ctx["results"]},
    )
    qid = started["QueryExecutionId"]

    for _ in range(60):
        ex = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
        state = ex["Status"]["State"]
        if state == "SUCCEEDED":
            break
        if state in ("FAILED", "CANCELLED"):
            raise RuntimeError(
                f"Athena query {state}: {ex['Status'].get('StateChangeReason')}\nSQL: {sql}"
            )
        time.sleep(2)
    else:
        raise TimeoutError(f"Athena query did not finish: {sql}")

    result = athena.get_query_results(QueryExecutionId=qid)
    meta = [c["Name"] for c in result["ResultSet"]["ResultSetMetadata"]["ColumnInfo"]]
    rows = []
    # Athena's first row is the header when the SerDe has no skip.header setting; detect it
    # rather than assume, so a header change cannot silently drop a data row.
    for r in result["ResultSet"]["Rows"]:
        values = [d.get("VarCharValue") for d in r["Data"]]
        if values == meta:
            continue
        rows.append(dict(zip(meta, values)))
    return rows


def _prepared(sql: str, policy: EffectivePolicy):
    return prepare_sql_query(sql, policy, dialect=SqlDialect.trino)


# ---------------------------------------------------------------------------
# Pushdown: the engine must not return rows the policy excludes
# ---------------------------------------------------------------------------


class TestRowFilterPushdown:
    def test_baseline_unfiltered_returns_every_region(self, athena, athena_table):
        # Without this the filtered assertions could pass because the table is empty or the
        # SerDe misparsed the CSV.
        rows = _run_query(athena, athena_table, "SELECT * FROM patients")

        assert {r["region"] for r in rows} == {"us-east", "us-west", "eu-west"}

    def test_row_filter_is_pushed_into_the_sql_and_honoured_by_athena(self, athena, athena_table):
        # The property a fixture cannot check: Athena's own parser applied our WHERE clause.
        policy = _policy(
            allowed_objects=["patients"],
            row_filters=[
                RowFilter(field="region", operator=FilterOperator.equals, value="us-east")
            ],
        )
        prep = _prepared("SELECT * FROM patients", policy)
        assert prep.allowed
        assert "WHERE" in prep.query.upper(), "the filter was not pushed down at all"

        rows = _run_query(athena, athena_table, prep.query)

        assert rows, "the pushed-down filter returned nothing; expected the us-east rows"
        assert {r["region"] for r in rows} == {"us-east"}

    def test_in_operator_pushdown(self, athena, athena_table):
        policy = _policy(
            allowed_objects=["patients"],
            row_filters=[
                RowFilter(
                    field="region",
                    operator=FilterOperator.in_,
                    values=["us-east", "eu-west"],
                )
            ],
        )
        prep = _prepared("SELECT * FROM patients", policy)

        rows = _run_query(athena, athena_table, prep.query)

        assert {r["region"] for r in rows} == {"us-east", "eu-west"}

    def test_not_equals_pushdown_excludes_the_region(self, athena, athena_table):
        # Negative operators are where this rewriter previously failed open, so the
        # excluded value is asserted absent rather than only counting rows.
        policy = _policy(
            allowed_objects=["patients"],
            row_filters=[
                RowFilter(
                    field="region", operator=FilterOperator.not_equals, value="us-west"
                )
            ],
        )
        prep = _prepared("SELECT * FROM patients", policy)

        rows = _run_query(athena, athena_table, prep.query)

        assert rows
        assert "us-west" not in {r["region"] for r in rows}

    def test_max_results_is_pushed_as_limit(self, athena, athena_table):
        policy = _policy(allowed_objects=["patients"], limits=PolicyLimits(max_results=2))
        prep = _prepared("SELECT * FROM patients", policy)
        assert "LIMIT" in prep.query.upper()

        rows = _run_query(athena, athena_table, prep.query)

        assert len(rows) == 2


# ---------------------------------------------------------------------------
# Denials happen before any SQL is sent
# ---------------------------------------------------------------------------


class TestDenialsPrecedeExecution:
    def test_can_query_false_yields_no_executable_sql(self, athena, athena_table):
        policy = _policy(can_query=False, allowed_objects=["patients"])

        prep = _prepared("SELECT * FROM patients", policy)

        assert prep.allowed is False
        assert prep.denial_reason

    def test_table_outside_allowed_objects_is_refused(self, athena, athena_table):
        # The table exists in Glue, so a broken check would happily query it.
        policy = _policy(allowed_objects=["encounters"])

        prep = _prepared("SELECT * FROM patients", policy)

        assert prep.allowed is False

    def test_control_permitted_table_produces_runnable_sql(self, athena, athena_table):
        policy = _policy(allowed_objects=["patients"])

        prep = _prepared("SELECT * FROM patients", policy)

        assert prep.allowed is True
        assert _run_query(athena, athena_table, prep.query)


# ---------------------------------------------------------------------------
# Post-fetch completeness: the rewrite is not the whole control
# ---------------------------------------------------------------------------


class TestPostFetchOverRealAthenaRows:
    def test_hidden_field_survives_the_rewrite_and_is_removed_after(self, athena, athena_table):
        # `SELECT *` is deliberately NOT expanded, so ssn comes back from Athena and the
        # post pass is what removes it. This asserts the seam rather than assuming the SQL
        # did the job -- if someone "optimised" the pipeline away, this fails.
        policy = _policy(
            allowed_objects=["patients"], field_rules=FieldRules(hidden_fields=["ssn"])
        )
        prep = _prepared("SELECT * FROM patients", policy)

        raw = _run_query(athena, athena_table, prep.query)
        assert any("ssn" in r for r in raw), (
            "Athena did not return ssn, so this test would pass without the post pass "
            "doing anything"
        )

        enforced = apply_result_pipeline(raw, policy)

        assert enforced
        assert all("ssn" not in r for r in enforced)

    def test_masking_applies_to_real_athena_rows(self, athena, athena_table):
        policy = _policy(
            allowed_objects=["patients"],
            field_rules=FieldRules(
                masked_fields=[MaskingRule(field="ssn", mask_type=MaskType.redact)]
            ),
        )
        prep = _prepared("SELECT * FROM patients", policy)
        raw = _run_query(athena, athena_table, prep.query)

        enforced = apply_result_pipeline(raw, policy)

        assert all(r["ssn"] != "111-11-1111" for r in enforced)
        assert "111-11-1111" not in str(enforced)

    def test_allowed_fields_projects_athena_rows(self, athena, athena_table):
        policy = _policy(
            allowed_objects=["patients"],
            field_rules=FieldRules(allowed_fields=["id", "region"]),
        )
        prep = _prepared("SELECT * FROM patients", policy)
        raw = _run_query(athena, athena_table, prep.query)

        enforced = apply_result_pipeline(raw, policy)

        for r in enforced:
            assert set(r).issubset({"id", "region"})

    def test_pushdown_and_post_pass_agree_on_the_same_policy(self, athena, athena_table):
        # The safety property, as for the kb pushdown: filtering in SQL must reach the same
        # verdict as filtering in the pipeline. Run the policy both ways over the same table
        # and compare. A disagreement means the rewrite is not a faithful translation.
        policy = _policy(
            allowed_objects=["patients"],
            row_filters=[
                RowFilter(field="region", operator=FilterOperator.equals, value="us-east")
            ],
        )

        pushed = _run_query(athena, athena_table, _prepared("SELECT * FROM patients", policy).query)
        everything = _run_query(athena, athena_table, "SELECT * FROM patients")
        post_only = apply_result_pipeline(everything, policy)

        assert {r["id"] for r in pushed} == {r["id"] for r in post_only}, (
            "the SQL rewrite and the post-execution pipeline disagreed on the same policy"
        )
