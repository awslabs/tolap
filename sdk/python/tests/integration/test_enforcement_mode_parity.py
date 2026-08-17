"""Both enforcement modes return the same rows, against live PostgreSQL and MySQL.

This is the test that makes ``SqlEnforcementMode`` safe to offer. The mode decides how
much data the database produces -- ``rewrite_and_post`` pushes filters, the limit and the
projection into the SQL; ``post_only`` leaves the query untouched -- and if the two ever
returned *different rows*, the mode would be an access-control setting wearing a
performance setting's clothes. That is the divergence class canonical-enforcement-spec
section 4 exists to prevent.

So the assertion here is equality between the modes, not correctness of each mode
separately. A per-mode test would pass if ``post_only`` quietly returned an extra row,
because nothing would compare the two against each other. The same reasoning as
``fixtures/`` demanding byte-identical output from the three SDKs rather than three
independently-written expectations.

Requires Postgres on 5432 and MySQL on 3306 seeded from schema.sql / schema_mysql.sql;
skipped automatically otherwise (see conftest).
"""

from __future__ import annotations

import psycopg
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
from tolap_core.sql_rewriter import (
    DEFAULT_ENFORCEMENT_MODE,
    SqlDialect,
    SqlEnforcementMode,
    prepare_sql_query,
)


def _policy(
    *,
    row_filters: list[RowFilter] | None = None,
    hidden_fields: list[str] | None = None,
    masked_fields: list[MaskingRule] | None = None,
    max_results: int | None = None,
) -> EffectivePolicy:
    return EffectivePolicy(
        version="1.0",
        user_id="u",
        tenant_id="t",
        source_connection_id="db:analytics:patients",
        source_profiles=["enforcement-mode-parity"],
        permissions=PolicyPermissions(can_query=True, read_only=True),
        object_rules=ObjectRules(
            allowed_objects=["patients"],
            row_filters=row_filters or [],
            field_rules=FieldRules(
                hidden_fields=hidden_fields or [],
                masked_fields=masked_fields or [],
            ),
        ),
        limits=PolicyLimits(max_results=max_results),
    )


def _run(conn, policy: EffectivePolicy, sql: str, mode, dialect) -> list[dict]:
    """Prepare in `mode`, execute, then run the mandatory post pass.

    Both fixtures already yield mapping rows -- `db_conn` via psycopg's `dict_row` and
    `mysql_conn` via PyMySQL's `DictCursor` -- so the rows are used as they come back.
    Re-zipping `cursor.description` over them produced a dict of column-name to
    column-name, which compared equal across every row and made the parity assertions
    meaningless while still failing on the row *count*.
    """
    prep = prepare_sql_query(sql, policy, dialect=dialect, mode=mode)
    assert prep.allowed, prep.denial_reason
    with conn.cursor() as cur:
        cur.execute(prep.query)
        rows = [dict(r) for r in cur.fetchall()]
    return apply_result_pipeline(rows, policy)


# Each case is a policy the two modes must agree on. They are chosen to cover both
# sides of the pushdown boundary: filters the rewriter CAN express, filters it cannot,
# and the ones where agreement is least obvious.
_CASES = {
    "pushable equals": _policy(
        row_filters=[RowFilter(field="region", operator=FilterOperator.equals, value="us-east")],
    ),
    # startsWith has no portable SQL form, so `rewrite_and_post` does not push it and
    # both modes rely on the post pass for this filter. Agreement here is the easy
    # direction; it is included because it is the case an implementer is most likely to
    # special-case wrongly.
    "unpushable startsWith": _policy(
        row_filters=[RowFilter(field="full_name", operator=FilterOperator.starts_with, value="J")],
    ),
    # A pushed filter AND an unpushed one together: the database applies half, the post
    # pass applies the rest, and the result must equal post-only doing all of it.
    "mixed pushable and not": _policy(
        row_filters=[
            RowFilter(field="region", operator=FilterOperator.equals, value="us-east"),
            RowFilter(field="full_name", operator=FilterOperator.starts_with, value="J"),
        ],
    ),
    # `notEquals` needs an `IS NULL` arm when pushed, or the database drops a row the
    # post pass keeps (spec section 4). This case fails loudly if that arm regresses.
    "negative operator needs IS NULL arm": _policy(
        row_filters=[RowFilter(field="status", operator=FilterOperator.not_equals, value="deleted")],
    ),
    # Masking has no SQL form at all, so it is post-pass work in both modes. Included to
    # prove the rewrite does not somehow drop the column that masking then needs.
    "masked field": _policy(
        masked_fields=[MaskingRule(field="email", mask_type=MaskType.redact)],
    ),
    # The limit is pushed as LIMIT n in one mode and applied post-fetch in the other.
    # Both must yield the same n rows -- and the same n, in the same order.
    "result limit": _policy(max_results=2),
    # Everything at once, which is what a real policy looks like.
    "combined": _policy(
        row_filters=[
            RowFilter(field="region", operator=FilterOperator.equals, value="us-east"),
            RowFilter(field="status", operator=FilterOperator.not_equals, value="deleted"),
        ],
        masked_fields=[MaskingRule(field="email", mask_type=MaskType.redact)],
        max_results=2,
    ),
}

_SQL = "SELECT id, full_name, email, region, status FROM patients ORDER BY id"


@pytest.mark.parametrize("name", list(_CASES))
def test_both_modes_return_identical_rows_postgres(db_conn, name: str) -> None:
    policy = _CASES[name]
    rewritten = _run(db_conn, policy, _SQL, SqlEnforcementMode.rewrite_and_post, SqlDialect.postgres)
    post_only = _run(db_conn, policy, _SQL, SqlEnforcementMode.post_only, SqlDialect.postgres)

    assert rewritten == post_only, (
        f"{name}: the mode changed the result. Rewriting is a resource optimization and "
        f"MUST NOT change what the caller sees (spec section 4).\n"
        f"  rewrite_and_post: {rewritten}\n"
        f"  post_only       : {post_only}"
    )


@pytest.mark.parametrize("name", list(_CASES))
def test_both_modes_return_identical_rows_mysql(mysql_conn, name: str) -> None:
    policy = _CASES[name]
    rewritten = _run(mysql_conn, policy, _SQL, SqlEnforcementMode.rewrite_and_post, SqlDialect.mysql)
    post_only = _run(mysql_conn, policy, _SQL, SqlEnforcementMode.post_only, SqlDialect.mysql)

    assert rewritten == post_only, f"{name}: the mode changed the result on MySQL"


def test_the_two_modes_really_did_differ_in_what_they_asked_the_database() -> None:
    """Guards the guard.

    Every equality assertion above would also pass if `mode` were ignored entirely and
    both calls rewrote (or both skipped). That is the failure this file is least likely
    to notice about itself, so the difference in emitted SQL is asserted directly.
    """
    policy = _CASES["combined"]
    rewritten = prepare_sql_query(
        _SQL, policy, dialect=SqlDialect.postgres, mode=SqlEnforcementMode.rewrite_and_post
    )
    post_only = prepare_sql_query(
        _SQL, policy, dialect=SqlDialect.postgres, mode=SqlEnforcementMode.post_only
    )

    assert rewritten.query != post_only.query
    assert rewritten.rewritten is True
    assert post_only.rewritten is False
    # post_only returns the caller's text byte for byte. An integrator choosing this mode
    # is choosing "the query that ran is the query I wrote"; a rewrite of any size,
    # including a cosmetic one, breaks that promise.
    assert post_only.query == _SQL
    assert "WHERE" in rewritten.query.upper()
    assert "LIMIT" in rewritten.query.upper()


def test_post_only_reports_every_filter_as_unpushed() -> None:
    """In post_only nothing reached the database, so nothing is 'pushed down'.

    `fully_pushed_down` is what an integrator checks before executing a query whose
    result set may be large. Reporting only the operators the rewriter *cannot* express
    would tell a post_only caller their filters were pushed when the database never saw
    them.
    """
    policy = _CASES["combined"]
    prep = prepare_sql_query(
        _SQL, policy, dialect=SqlDialect.postgres, mode=SqlEnforcementMode.post_only
    )

    assert len(prep.unpushable_filters) == len(policy.object_rules.row_filters)
    assert prep.fully_pushed_down is False


def test_post_only_still_denies_a_query_naming_a_hidden_field() -> None:
    """Skipping the rewrite must not skip a check.

    This is the property that makes post_only safe to offer: it declines to *rewrite*,
    not to *authorize*. If the hidden-field refusal only lived on the rewrite path, then
    choosing post_only would hand the agent a column the policy hides.
    """
    policy = _policy(hidden_fields=["ssn"])

    for mode in (SqlEnforcementMode.rewrite_and_post, SqlEnforcementMode.post_only):
        prep = prepare_sql_query(
            "SELECT id, ssn FROM patients", policy, dialect=SqlDialect.postgres, mode=mode
        )
        assert prep.allowed is False, f"{mode} allowed a query naming a hidden field"
        assert "permission" in (prep.denial_reason or "")


def test_post_only_still_denies_a_disallowed_object() -> None:
    policy = _policy()  # allowedObjects: ["patients"]

    for mode in (SqlEnforcementMode.rewrite_and_post, SqlEnforcementMode.post_only):
        prep = prepare_sql_query(
            "SELECT id FROM encounters", policy, dialect=SqlDialect.postgres, mode=mode
        )
        assert prep.allowed is False, f"{mode} allowed a disallowed object"


def test_post_only_still_denies_when_canquery_is_false() -> None:
    policy = EffectivePolicy(
        version="1.0",
        user_id="u",
        tenant_id="t",
        source_connection_id="db:analytics:patients",
        permissions=PolicyPermissions(can_query=False, read_only=True),
        object_rules=ObjectRules(allowed_objects=["patients"]),
        limits=PolicyLimits(),
    )

    for mode in (SqlEnforcementMode.rewrite_and_post, SqlEnforcementMode.post_only):
        prep = prepare_sql_query(_SQL, policy, dialect=SqlDialect.postgres, mode=mode)
        assert prep.allowed is False, f"{mode} allowed a query under canQuery=False"


def test_default_mode_rewrites() -> None:
    """The default is stated in one place and asserted here.

    Not a tautology: it pins the cross-SDK contract. .NET has always rewritten by
    default and Python did not rewrite at all unless asked, which is the divergence this
    enum exists to close. A change to the default has to break this test.
    """
    assert DEFAULT_ENFORCEMENT_MODE is SqlEnforcementMode.rewrite_and_post

    policy = _CASES["combined"]
    omitted = prepare_sql_query(_SQL, policy, dialect=SqlDialect.postgres)
    explicit = prepare_sql_query(
        _SQL, policy, dialect=SqlDialect.postgres, mode=SqlEnforcementMode.rewrite_and_post
    )
    assert omitted.query == explicit.query
    assert omitted.rewritten is True


@pytest.mark.parametrize("bad", ["post-only", "postonly", "rewrite", "", "PostOnly"])
def test_an_unrecognized_mode_raises_rather_than_defaulting(bad: str) -> None:
    """Fails closed, loudly.

    A typo silently selecting the default would rewrite SQL for an integrator who
    explicitly asked that it not be touched -- the exact surprise post_only exists to
    prevent. Note `"PostOnly"` is in this list: the wire value is `"postOnly"`, and
    accepting near-misses case-insensitively would make the accepted set unclear.
    """
    with pytest.raises(ValueError, match="unrecognized SQL enforcement mode"):
        prepare_sql_query(_SQL, _CASES["combined"], dialect=SqlDialect.postgres, mode=bad)


def test_a_string_mode_is_accepted_for_config_driven_callers() -> None:
    """The wire values work, so a mode can come from a config file or env var."""
    policy = _CASES["combined"]
    assert (
        prepare_sql_query(_SQL, policy, dialect=SqlDialect.postgres, mode="postOnly").query == _SQL
    )
    assert prepare_sql_query(
        _SQL, policy, dialect=SqlDialect.postgres, mode="rewriteAndPost"
    ).rewritten is True


def test_execute_sql_with_enforcement_rejects_an_unsigned_context() -> None:
    """The wrapper helper validates the context before it prepares anything.

    Regression: the first version of `execute_sql_with_enforcement` called the module-level
    `validate_context`, which requires the signing key and therefore raised TypeError on
    every call -- so the helper was unusable and no test noticed, because the parity tests
    above call `prepare_sql_query` directly. Found by running the snippet from the
    implementation guide.

    It now uses the wrapper's own `validate_security_context`, which carries the key and
    honours `enforce_signatures` / `enforce_expiry` rather than overriding them.
    """
    from tolap_core.context import build_security_context, sign_context
    from tolap_mcp.options import SecureMcpServerOptions
    from tolap_mcp.wrapper import SecureMcpToolWrapper

    key = "mode-test-signing-key"
    policy = _CASES["pushable equals"]
    wrapper = SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=key))

    signed = sign_context(build_security_context("u", "t", [policy]), key)
    rows = wrapper.execute_sql_with_enforcement(
        signed,
        _SQL,
        lambda q: [{"id": 1, "full_name": "John", "email": "j@x.com", "region": "us-east", "status": "active"}],
        dialect=SqlDialect.postgres,
    )
    assert rows == [
        {"id": 1, "full_name": "John", "email": "j@x.com", "region": "us-east", "status": "active"}
    ]

    unsigned = build_security_context("u", "t", [policy])
    with pytest.raises(PermissionError, match="Access denied"):
        wrapper.execute_sql_with_enforcement(
            unsigned, _SQL, lambda q: [], dialect=SqlDialect.postgres
        )


def test_execute_sql_with_enforcement_honours_the_mode() -> None:
    """The helper passes the mode through rather than always rewriting."""
    from tolap_core.context import build_security_context, sign_context
    from tolap_mcp.options import SecureMcpServerOptions
    from tolap_mcp.wrapper import SecureMcpToolWrapper

    key = "mode-test-signing-key"
    wrapper = SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=key))
    context = sign_context(build_security_context("u", "t", [_CASES["pushable equals"]]), key)

    seen: list[str] = []

    def execute(query: str) -> list[dict]:
        seen.append(query)
        return []

    wrapper.execute_sql_with_enforcement(context, _SQL, execute, dialect=SqlDialect.postgres)
    wrapper.execute_sql_with_enforcement(
        context, _SQL, execute, dialect=SqlDialect.postgres, mode=SqlEnforcementMode.post_only
    )

    assert "WHERE" in seen[0]
    assert seen[1] == _SQL
