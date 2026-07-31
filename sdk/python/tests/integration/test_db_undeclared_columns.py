"""Post-execution enforcement over real database rows the caller never declared.

Spec section 4 is explicit that `hiddenFields` and `allowedFields` are *not*
satisfied by a pre-execution check: the pre-check only inspects the field list a
caller volunteers, so a tool issuing `SELECT *` returns undeclared columns and
leaks them. That is exactly the shape a real driver produces and a hand-written
row fixture does not, so these run against live Postgres and MySQL.

They also pin the parts of the pipeline whose behavior depends on driver-native
values rather than JSON: a `DATE` arrives as `datetime.date` and a `NUMERIC` as
`Decimal`, and masking has to stringify those rather than raise.
"""

from __future__ import annotations

import datetime
from decimal import Decimal

import pytest

from tolap_core.enums import FilterOperator, MaskType
from tolap_core.models import (
    EffectivePolicy,
    FieldRules,
    MaskingParameters,
    MaskingRule,
    ObjectRules,
    PolicyLimits,
    PolicyPermissions,
    RowFilter,
)
from tolap_mcp.options import SecureMcpServerOptions
from tolap_mcp.wrapper import SecureMcpToolWrapper

from ._scenarios import sign_policy


@pytest.fixture
def wrapper(signing_key: str) -> SecureMcpToolWrapper:
    return SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=signing_key))


def _policy(
    *,
    field_rules: FieldRules | None = None,
    row_filters: list[RowFilter] | None = None,
    limits: PolicyLimits | None = None,
) -> EffectivePolicy:
    return EffectivePolicy(
        version="1.0",
        user_id="scenario-user",
        tenant_id="scenario-tenant",
        source_profiles=["undeclared-columns"],
        permissions=PolicyPermissions(can_query=True, read_only=True),
        object_rules=ObjectRules(field_rules=field_rules, row_filters=row_filters),
        limits=limits,
    )


def _select_star_pg(conn) -> list[dict]:
    """A tool that returns every column, declaring none of them."""
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM patients ORDER BY id")
        return list(cur.fetchall())


def _select_star_mysql(conn) -> list[dict]:
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM patients ORDER BY id")
        return list(cur.fetchall())


def _run(wrapper, signing_key, policy, tool_fn, conn) -> list[dict]:
    return wrapper.execute_with_enforcement(
        context=sign_policy(policy, signing_key),
        tool_name="db-query",
        tool_fn=tool_fn,
        tool_args={"conn": conn},
        object_name="patients",
        # Deliberately no `fields=`: the caller declares nothing, so only the
        # post-execution pipeline can protect these columns.
    )


class TestPostgresUndeclaredColumns:
    def test_select_star_still_has_hidden_columns_removed(
        self, wrapper, signing_key, db_conn
    ) -> None:
        policy = _policy(field_rules=FieldRules(hidden_fields=["ssn", "date_of_birth"]))

        rows = _run(wrapper, signing_key, policy, _select_star_pg, db_conn)

        assert rows, "expected seeded patients"
        for row in rows:
            assert "ssn" not in row
            assert "date_of_birth" not in row
            assert "full_name" in row

    def test_unenforced_query_really_does_return_the_sensitive_columns(
        self, db_conn
    ) -> None:
        """Control: proves the test above removes something that was present."""
        rows = _select_star_pg(db_conn)

        assert "ssn" in rows[0]

    def test_select_star_is_projected_to_allowed_columns(
        self, wrapper, signing_key, db_conn
    ) -> None:
        policy = _policy(field_rules=FieldRules(allowed_fields=["id", "region"]))

        rows = _run(wrapper, signing_key, policy, _select_star_pg, db_conn)

        for row in rows:
            assert sorted(row) == ["id", "region"]

    def test_empty_allow_list_denies_every_column(
        self, wrapper, signing_key, db_conn
    ) -> None:
        """Spec section 3: `[]` is deny-all over real rows too."""
        policy = _policy(field_rules=FieldRules(allowed_fields=[]))

        rows = _run(wrapper, signing_key, policy, _select_star_pg, db_conn)

        assert rows and all(row == {} for row in rows)

    def test_row_filters_apply_to_undeclared_columns(
        self, wrapper, signing_key, db_conn
    ) -> None:
        policy = _policy(
            row_filters=[
                RowFilter(field="status", operator=FilterOperator.not_equals, value="deleted"),
                RowFilter(field="region", operator=FilterOperator.in_, values=["us-east", "us-west"]),
            ]
        )

        rows = _run(wrapper, signing_key, policy, _select_star_pg, db_conn)

        assert rows
        for row in rows:
            assert row["status"] != "deleted"
            assert row["region"] in ("us-east", "us-west")
        # Carl Davis is us-west but deleted, so the AND must exclude him.
        assert all(row["full_name"] != "Carl Davis" for row in rows)

    def test_a_filter_on_a_column_the_policy_also_hides_still_applies(
        self, wrapper, signing_key, db_conn
    ) -> None:
        """Filtering precedes hidden-field removal, so both take effect."""
        policy = _policy(
            field_rules=FieldRules(hidden_fields=["status"]),
            row_filters=[
                RowFilter(field="status", operator=FilterOperator.not_equals, value="deleted")
            ],
        )

        rows = _run(wrapper, signing_key, policy, _select_star_pg, db_conn)

        assert rows
        for row in rows:
            assert "status" not in row
            assert row["full_name"] != "Carl Davis"

    def test_masking_stringifies_a_native_date_rather_than_raising(
        self, wrapper, signing_key, db_conn
    ) -> None:
        """`date_of_birth` arrives as datetime.date, not str."""
        assert isinstance(_select_star_pg(db_conn)[0]["date_of_birth"], datetime.date)

        policy = _policy(
            field_rules=FieldRules(
                masked_fields=[MaskingRule(field="date_of_birth", mask_type=MaskType.full)]
            )
        )

        rows = _run(wrapper, signing_key, policy, _select_star_pg, db_conn)

        for row in rows:
            assert set(row["date_of_birth"]) == {"*"}

    def test_hash_masking_of_a_real_column_is_stable_and_truncated(
        self, wrapper, signing_key, db_conn
    ) -> None:
        import hashlib

        original = _select_star_pg(db_conn)[0]["email"]
        policy = _policy(
            field_rules=FieldRules(
                masked_fields=[MaskingRule(field="email", mask_type=MaskType.hash)]
            )
        )

        rows = _run(wrapper, signing_key, policy, _select_star_pg, db_conn)

        expected = hashlib.sha256(original.encode("utf-8")).hexdigest()[:16]
        assert rows[0]["email"] == expected

    def test_most_restrictive_mask_wins_over_real_rows(
        self, wrapper, signing_key, db_conn
    ) -> None:
        """Spec section 6: null must beat partial, not disclose real characters."""
        policy = _policy(
            field_rules=FieldRules(
                masked_fields=[
                    MaskingRule(
                        field="ssn",
                        mask_type=MaskType.partial,
                        parameters=MaskingParameters(show_last=4),
                    ),
                    MaskingRule(field="ssn", mask_type=MaskType.null),
                ]
            )
        )

        rows = _run(wrapper, signing_key, policy, _select_star_pg, db_conn)

        for row in rows:
            assert row["ssn"] is None

    def test_limit_applies_after_filtering_over_real_rows(
        self, wrapper, signing_key, db_conn
    ) -> None:
        policy = _policy(
            row_filters=[
                RowFilter(field="status", operator=FilterOperator.not_equals, value="deleted")
            ],
            limits=PolicyLimits(max_results=3),
        )

        rows = _run(wrapper, signing_key, policy, _select_star_pg, db_conn)

        assert len(rows) == 3
        assert all(row["status"] != "deleted" for row in rows)

    def test_qualified_rule_matches_an_unqualified_driver_column(
        self, wrapper, signing_key, db_conn
    ) -> None:
        """A driver returns bare column names; `patients.ssn` must still match."""
        policy = _policy(field_rules=FieldRules(hidden_fields=["patients.ssn"]))

        rows = _run(wrapper, signing_key, policy, _select_star_pg, db_conn)

        for row in rows:
            assert "ssn" not in row

    def test_numeric_column_masking_handles_decimal(
        self, wrapper, signing_key, db_conn
    ) -> None:
        """billing_internal.amount_cents is NUMERIC/INTEGER, not a string."""

        def select_billing(conn) -> list[dict]:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM billing_internal ORDER BY id")
                return list(cur.fetchall())

        raw = select_billing(db_conn)
        assert isinstance(raw[0]["amount_cents"], (int, Decimal))

        policy = _policy(
            field_rules=FieldRules(
                masked_fields=[MaskingRule(field="amount_cents", mask_type=MaskType.redact)]
            )
        )
        rows = wrapper.execute_with_enforcement(
            context=sign_policy(policy, signing_key),
            tool_name="db-query",
            tool_fn=select_billing,
            tool_args={"conn": db_conn},
            object_name="billing_internal",
        )

        for row in rows:
            assert row["amount_cents"] == "[REDACTED]"


class TestMysqlUndeclaredColumns:
    """The same guarantees against a second real driver.

    MySQL's connector returns its own native types, so this catches an assumption
    that only happens to hold for psycopg.
    """

    def test_select_star_still_has_hidden_columns_removed(
        self, wrapper, signing_key, mysql_conn
    ) -> None:
        policy = _policy(field_rules=FieldRules(hidden_fields=["ssn", "date_of_birth"]))

        rows = _run(wrapper, signing_key, policy, _select_star_mysql, mysql_conn)

        assert rows
        for row in rows:
            assert "ssn" not in row
            assert "date_of_birth" not in row

    def test_unenforced_query_really_does_return_the_sensitive_columns(
        self, mysql_conn
    ) -> None:
        rows = _select_star_mysql(mysql_conn)

        assert "ssn" in rows[0]

    def test_select_star_is_projected_to_allowed_columns(
        self, wrapper, signing_key, mysql_conn
    ) -> None:
        policy = _policy(field_rules=FieldRules(allowed_fields=["id", "region"]))

        rows = _run(wrapper, signing_key, policy, _select_star_mysql, mysql_conn)

        for row in rows:
            assert sorted(row) == ["id", "region"]

    def test_row_filters_apply_to_undeclared_columns(
        self, wrapper, signing_key, mysql_conn
    ) -> None:
        policy = _policy(
            row_filters=[
                RowFilter(field="status", operator=FilterOperator.not_equals, value="deleted")
            ]
        )

        rows = _run(wrapper, signing_key, policy, _select_star_mysql, mysql_conn)

        assert rows
        assert all(row["status"] != "deleted" for row in rows)

    def test_masking_stringifies_a_native_date(
        self, wrapper, signing_key, mysql_conn
    ) -> None:
        assert isinstance(_select_star_mysql(mysql_conn)[0]["date_of_birth"], datetime.date)

        policy = _policy(
            field_rules=FieldRules(
                masked_fields=[MaskingRule(field="date_of_birth", mask_type=MaskType.full)]
            )
        )

        rows = _run(wrapper, signing_key, policy, _select_star_mysql, mysql_conn)

        for row in rows:
            assert set(row["date_of_birth"]) == {"*"}
