"""Prints what enforcement actually *did*, against real Postgres and MySQL.

A `PASSED` line proves an assertion held; it does not show the SQL that was sent, the rows the
engine returned, or which values a masking rule changed. Reviewers of this SDK have to take the
test names on trust. This harness closes that gap: for each control it prints the policy rule,
the exact SQL, the rows before, and the rows after -- so a reader can confirm the enforcement
from the transcript rather than from the assertion.

It is a **transcript producer, not a test**. Every claim it prints is asserted properly in
`test_postgres_query_rewriting.py`, `test_mysql_scenarios.py` and
`test_dialect_query_rewriting.py`; duplicating those assertions here would create a second,
weaker copy that could drift. What it adds is visibility, and it still fails loudly (non-zero
exit) if a control does not do what it claims, so a silently-broken transcript cannot be
recorded as evidence.

Run against both engines:

    python3 tests/integration/verbose_enforcement_log.py postgres
    python3 tests/integration/verbose_enforcement_log.py mysql
"""

from __future__ import annotations
# CodeQL raises py/clear-text-logging-sensitive-data on the before/after prints below,
# because it sees a field named `ssn` reaching stdout. That is exactly what this file is
# for: showing that masking changed the value. The inputs are synthetic fixtures seeded by
# tests/integration/schema.sql (111-22-3333 and friends), the output is a transcript
# committed as review evidence, and nothing here runs in a deployment or touches real data.
# The alerts are dismissed as false positives rather than suppressed in code, so the
# reasoning lives in the alert history where a reviewer will look for it.


import sys
from typing import Any, Callable

from tolap_core.enforcement import apply_result_pipeline, apply_row_filters, validate_field_access
from tolap_core.models import (
    EffectivePolicy,
    FieldRules,
    FilterOperator,
    MaskingRule,
    MaskType,
    ObjectRules,
    PolicyLimits,
    PolicyPermissions,
    RowFilter,
)
from tolap_core.sql_rewriter import SqlDialect, rewrite_query

FAILURES: list[str] = []


# ---------------------------------------------------------------------------
# transcript formatting
# ---------------------------------------------------------------------------


def heading(text: str) -> None:
    print(f"\n{'=' * 78}\n{text}\n{'=' * 78}")


def control(name: str, rule: str) -> None:
    print(f"\n--- {name}\n    policy: {rule}")


def sql(label: str, text: str) -> None:
    print(f"    {label}: {text}")


def rows(label: str, records: list[dict[str, Any]], limit: int = 6) -> None:
    if not records:
        print(f"    {label}: (no rows)")
        return
    keys = list(records[0].keys())
    print(f"    {label}: {len(records)} row(s), columns {keys}")
    for record in records[:limit]:
        rendered = ", ".join(f"{k}={record[k]!r}" for k in keys)
        print(f"        {rendered}")
    if len(records) > limit:
        print(f"        ... {len(records) - limit} more")


def check(claim: str, condition: bool) -> None:
    """Assert-and-narrate. A false claim is recorded and fails the run."""
    print(f"    {'OK  ' if condition else 'FAIL'} {claim}")
    if not condition:
        FAILURES.append(claim)


# ---------------------------------------------------------------------------
# policy construction
# ---------------------------------------------------------------------------


def policy(
    *,
    can_query: bool = True,
    allowed_objects: list[str] | None = None,
    allowed_fields: list[str] | None = None,
    hidden_fields: list[str] | None = None,
    masked_fields: list[MaskingRule] | None = None,
    row_filters: list[RowFilter] | None = None,
    max_results: int | None = None,
) -> EffectivePolicy:
    has_field_rules = bool(allowed_fields or hidden_fields or masked_fields)
    return EffectivePolicy(
        version="1.0",
        user_id="verbose-log",
        tenant_id="hospital-001",
        source_profiles=["verbose-transcript"],
        permissions=PolicyPermissions(can_query=can_query, read_only=True),
        object_rules=ObjectRules(
            allowed_objects=allowed_objects,
            field_rules=FieldRules(
                allowed_fields=allowed_fields,
                hidden_fields=hidden_fields,
                masked_fields=masked_fields,
            )
            if has_field_rules
            else None,
            row_filters=row_filters,
        )
        if (allowed_objects or row_filters or has_field_rules)
        else None,
        limits=PolicyLimits(max_results=max_results) if max_results is not None else None,
    )


# ---------------------------------------------------------------------------
# the transcript
# ---------------------------------------------------------------------------


def transcribe(engine: str, run: Callable[[str], list[dict[str, Any]]], dialect: SqlDialect) -> None:
    base = "SELECT id, region, status, full_name, ssn FROM patients ORDER BY id"

    heading(f"{engine}: the ENGINE does the filtering (row filters pushed into SQL)")
    everything = run(base)
    rows("unfiltered", everything)

    # Identifier quoting is dialect-specific and getting it wrong fails OPEN rather than loudly:
    # MySQL reads "status" as the string literal 'status', so `"status" <> 'deleted'` is always
    # true and every row comes back. An earlier draft of this harness forgot to pass `dialect`
    # and MySQL silently returned the deleted row. Asserted here so a missing dialect is a hard
    # error at the top of the transcript rather than a wrong row count in the middle.
    quote = "`" if dialect is SqlDialect.mysql else '"'
    probe = rewrite_query(base, policy(row_filters=[RowFilter(
        field="status", operator=FilterOperator.equals, value="active")]), dialect=dialect)
    control("dialect sanity: identifier quoting", f"dialect={dialect.value}")
    sql("probe", probe)
    check(f"identifiers are quoted with {quote} as {dialect.value} requires -- the wrong quote "
          f"style turns a column reference into a string literal and the filter fails OPEN",
          f"{quote}status{quote}" in probe)

    control("row filter: region IN (us-east, us-west)", "rowFilters[region in [us-east, us-west]]")
    p = policy(row_filters=[RowFilter(field="region", operator=FilterOperator.in_, values=["us-east", "us-west"])])
    rewritten = rewrite_query(base, p, dialect=dialect)
    sql("sent", rewritten)
    filtered = run(rewritten)
    rows("returned", filtered)
    check("the rewritten SQL carries a WHERE clause", "WHERE" in rewritten.upper())
    check(
        f"the engine returned fewer rows than unfiltered ({len(filtered)} < {len(everything)})",
        len(filtered) < len(everything),
    )
    check("no excluded region survived", {r["region"] for r in filtered} <= {"us-east", "us-west"})
    check(
        "the post-fetch pass finds nothing left to remove (pushdown was complete)",
        apply_result_pipeline(filtered, p) == filtered,
    )

    control("negative operator: status != deleted", "rowFilters[status notEquals deleted]")
    p = policy(row_filters=[RowFilter(field="status", operator=FilterOperator.not_equals, value="deleted")])
    rewritten = rewrite_query(base, p, dialect=dialect)
    sql("sent", rewritten)
    pushed = run(rewritten)
    rows("returned", pushed)
    check("'deleted' is absent from the engine's own result", all(r["status"] != "deleted" for r in pushed))
    # Negative operators are where a rewriter fails open, so the two paths are compared directly.
    post_only = apply_result_pipeline(everything, p)
    check(
        "pushdown and post-fetch pass select identical ids -- the rewrite is a faithful "
        "translation of the policy, not a looser one",
        [r["id"] for r in pushed] == [r["id"] for r in post_only],
    )

    heading(f"{engine}: MASKING applied to real rows returned by the engine")
    for mask, claim in [
        (MaskType.redact, "value is replaced, not merely hidden"),
        (MaskType.partial, "only a suffix/prefix remains visible"),
        (MaskType.hash, "value becomes a stable digest"),
        (MaskType.null, "value becomes null"),
    ]:
        control(f"maskedFields: ssn -> {mask.value}", f"maskType={mask.value}")
        p = policy(masked_fields=[MaskingRule(field="ssn", mask_type=mask)])
        raw = run(base)
        masked = apply_result_pipeline(raw, p)
        print(f"    before: ssn={[r['ssn'] for r in raw][:3]}")
        print(f"    after : ssn={[r['ssn'] for r in masked][:3]}")
        originals = {r["ssn"] for r in raw if r["ssn"] is not None}
        remaining = {r["ssn"] for r in masked if r["ssn"] is not None}
        check(f"{claim}", not (originals & remaining))
        check("the row itself survives -- masking is not row suppression", len(masked) == len(raw))
        if mask is MaskType.hash:
            again = apply_result_pipeline(run(base), p)
            check(
                "the digest is deterministic across runs (joinable without revealing the value)",
                [r["ssn"] for r in masked] == [r["ssn"] for r in again],
            )

    heading(f"{engine}: FIELD RULES over real rows")
    control("hiddenFields: ssn -- explicit column list", "fieldRules.hiddenFields=[ssn]")
    p = policy(hidden_fields=["ssn"])
    rewritten = rewrite_query(base, p, dialect=dialect)
    sql("sent", rewritten)
    raw = run(rewritten)
    # Two distinct behaviours, and the difference is the interesting part. With an explicit
    # column list the rewriter can prune ssn from the SELECT, so it never leaves the engine.
    check("ssn was pruned from the SELECT list, so the engine never returned it",
          "ssn" not in rewritten and all("ssn" not in r for r in raw))

    control("hiddenFields: ssn -- SELECT *", "same policy, SELECT * FROM patients")
    star = rewrite_query("SELECT * FROM patients ORDER BY id", p, dialect=dialect)
    sql("sent", star)
    star_raw = run(star)
    # SELECT * is deliberately NOT expanded: expanding it would require the rewriter to know the
    # table's real columns, which it cannot without a connection -- and TOLAP never holds one.
    # So ssn DOES come back, and the post-fetch pass is what removes it. This is the seam that
    # makes the pipeline load-bearing rather than a redundant second check.
    check("SELECT * is left alone, so the engine still returns ssn",
          any("ssn" in r for r in star_raw))
    enforced = apply_result_pipeline(star_raw, p)
    rows("after post-fetch pass", enforced)
    check("the post-fetch pass removed ssn from every row -- if it were optimised away, the "
          "hidden field would reach the caller", all("ssn" not in r for r in enforced))

    control("allowedFields: id, region", "fieldRules.allowedFields=[patients.id, patients.region]")
    p = policy(allowed_objects=["patients"], allowed_fields=["patients.id", "patients.region"])
    # validate_field_access partitions the request rather than returning a single verdict, so
    # the caller can report exactly which field was refused.
    decision = validate_field_access(["patients.id", "patients.ssn"], p)
    print("    requested: [patients.id, patients.ssn]")
    print(f"    allowed  : {decision.allowed}")
    print(f"    denied   : {decision.denied}")
    check("the out-of-allow-set field is denied before any SQL is sent",
          decision.denied == ["patients.ssn"])
    check("the in-allow-set field is still usable -- a denial is per field, not per request",
          decision.allowed == ["patients.id"])
    control("CONTROL: both fields inside the allow-set", "same policy")
    permitted = validate_field_access(["patients.id", "patients.region"], p)
    print(f"    allowed  : {permitted.allowed}")
    check("nothing is denied when every requested field is permitted", permitted.denied == [])

    heading(f"{engine}: LIMITS pushed into SQL")
    control("limits.maxResults = 2", "limits.maxResults=2")
    p = policy(max_results=2)
    rewritten = rewrite_query(base, p, dialect=dialect)
    sql("sent", rewritten)
    limited = run(rewritten)
    rows("returned", limited)
    check("LIMIT reached the SQL", "LIMIT" in rewritten.upper())
    check("the engine returned exactly 2 rows", len(limited) == 2)

    heading(f"{engine}: DENIALS happen before SQL is issued")
    control("permissions.canQuery = false", "canQuery=false")
    p = policy(can_query=False, allowed_objects=["patients"])
    from tolap_core.enforcement import validate_access

    decision = validate_access("patients", p)
    print(f"    decision: allowed={decision.allowed} reason={decision.reason!r}")
    check("no SQL is produced for a policy that cannot query", not decision.allowed)
    control("CONTROL: canQuery = true on the same object", "canQuery=true")
    check("the paired control is permitted", validate_access("patients", policy(allowed_objects=["patients"])).allowed)


def main() -> int:
    engine = sys.argv[1] if len(sys.argv) > 1 else "postgres"

    if engine == "postgres":
        import psycopg
        from psycopg.rows import dict_row

        conn = psycopg.connect("dbname=tolap_integration_test", row_factory=dict_row)
        with conn.cursor() as cur:
            cur.execute("SELECT version()")
            version = list(cur.fetchone().values())[0]
        dialect = SqlDialect.postgres

        def run(text: str) -> list[dict[str, Any]]:
            with conn.cursor() as cur:
                cur.execute(text)
                return [dict(r) for r in cur.fetchall()]

    elif engine == "mysql":
        import pymysql
        import pymysql.cursors

        conn = pymysql.connect(
            host="127.0.0.1",
            user="root",
            password="",
            database="tolap_integration_test",
            cursorclass=pymysql.cursors.DictCursor,
        )
        with conn.cursor() as cur:
            cur.execute("SELECT VERSION()")
            version = list(cur.fetchone().values())[0]
        dialect = SqlDialect.mysql

        def run(text: str) -> list[dict[str, Any]]:
            with conn.cursor() as cur:
                cur.execute(text)
                return [dict(r) for r in cur.fetchall()]

    else:
        print(f"unknown engine {engine!r}; expected 'postgres' or 'mysql'", file=sys.stderr)
        return 2

    print(f"Engine : {engine} {version}")
    print(f"Dialect: {dialect.value}")
    print("Source : sdk/python/tests/integration/verbose_enforcement_log.py")
    print(
        "\nEvery row and every SQL statement below came from the live engine. Claims are\n"
        "checked as they are printed; a FAIL line makes this run exit non-zero, so a broken\n"
        "transcript cannot be recorded as passing evidence."
    )

    transcribe(engine, run, dialect)

    print(f"\n{'=' * 78}")
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} claim(s) did not hold")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("All claims held against the live engine.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
