"""Write-path enforcement against live Postgres (connector spec section 4).

The unit suites already assert the write decision table: given a policy and a
payload, ``validate_write`` returns the documented ``AccessResult``. That proves
the *decision*, and nothing about the *effect*. A returned ``allowed=False`` is
worth exactly as much as the caller's willingness to honour it, and a validator
that is wired up wrongly -- consulted after the statement, consulted on a copy of
the payload, or short-circuited by a wrapper that swallows the denial -- still
produces a correct-looking boolean while the row changes anyway.

So every test here reads the database, asks the policy, and then reads the
database again. A denied write must leave the bytes it targeted identical; a
permitted write must actually land. Both halves are required: without the
permitted cases, a validator that denied unconditionally would pass the denial
tests, and a suite that cannot distinguish "enforced" from "broken" is not
evidence of anything.

The unverifiable-target case (:meth:`TestDeniedUpdateDoesNotReachTheRow`) is the
one an integrator meets first: they issue ``UPDATE ... WHERE id = %s`` without
reading the row, so the policy's row filters have nothing to evaluate. Section
4.2 requires that to be a refusal, not an allow, because the alternative is
modifying a row the caller could never have selected.

Isolation
---------
``schema.sql`` is reloaded **once per session** by the ``_seed_database`` fixture,
not per test, and the ``db_conn`` fixture's ``psycopg.connect`` context manager
**commits** on exit. A mutation left behind by one test is therefore visible to
every later test in the session and to every later session. Each test that can
mutate -- including the ones that expect a denial, because the failure mode under
test is precisely "the write happened anyway" -- runs inside
:func:`_rolled_back`, which unwinds the transaction unconditionally on the way
out. See that helper for why the rollback survives a failing assertion.
"""

from __future__ import annotations

import hashlib
from contextlib import contextmanager
from typing import Any, Iterator

import psycopg
import pytest

from tolap_core.enforcement import AccessResult
from tolap_core.enums import FilterOperator, MaskType, WriteOperation
from tolap_core.models import (
    EffectivePolicy,
    FieldRules,
    MaskingParameters,
    MaskingRule,
    ObjectRules,
    PolicyPermissions,
    RowFilter,
)
from tolap_mcp.options import SecureMcpServerOptions
from tolap_mcp.wrapper import SecureMcpToolWrapper

from ._scenarios import safe_identifier, sign_policy


# Seeded rows chosen for what the row filters below say about them, not for their
# ids. Naming them keeps the intent legible when schema.sql grows: a test that
# says PATIENT_OUT_OF_REGION cannot silently start targeting an in-scope row.
PATIENT_IN_SCOPE = 1  # John Smith,  us-east,    active  -> satisfies both filters
PATIENT_OUT_OF_REGION = 4  # Bob Wilson,  us-central, active  -> fails the region filter
DIAGNOSIS_IN_SCOPE = 1  # us-east,    active
DIAGNOSIS_OUT_OF_REGION = 4  # us-central, active

# `diagnoses` is the delete target rather than `patients` because every seeded
# patient is referenced by `encounters`; a permitted DELETE on `patients` would
# fail on the foreign key and the test would prove nothing about enforcement.
DIAGNOSES = "diagnoses"
PATIENTS = "patients"


@pytest.fixture
def wrapper(signing_key: str) -> SecureMcpToolWrapper:
    return SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=signing_key))


@contextmanager
def _rolled_back(conn: psycopg.Connection) -> Iterator[None]:
    """Run a block against ``conn`` and unwind everything it did.

    ``psycopg.Rollback`` is how psycopg spells "leave this transaction block and
    discard it"; ``conn.transaction()`` catches it, rolls back, and does not
    re-raise. An exception of any other type -- an ``AssertionError`` from a
    failing test, most importantly -- also rolls the transaction back and *is*
    re-raised, so a test that fails mid-mutation still cannot contaminate the
    session. That is the property that matters here: the tests below deliberately
    attempt writes that must not commit, and if enforcement regressed the write
    would succeed and the assertion would fail, which is exactly the moment the
    rollback has to hold.
    """
    with conn.transaction():
        yield
        raise psycopg.Rollback


def _scoped_filters() -> list[RowFilter]:
    """The canonical region/status scoping, as a fresh list per policy.

    A caller may only touch active rows in the two US regions. On the read path
    these drop rows from a result set; on the write path they decide whether the
    row an update or delete names is one the caller could have selected at all.
    """
    return [
        RowFilter(field="region", operator=FilterOperator.in_, values=["us-east", "us-west"]),
        RowFilter(field="status", operator=FilterOperator.not_equals, value="deleted"),
    ]


def _write_policy(
    *,
    can_insert: bool | None = None,
    can_update: bool | None = None,
    can_delete: bool | None = None,
    allowed_objects: list[str] | None = None,
    field_rules: FieldRules | None = None,
    row_filters: list[RowFilter] | None = None,
) -> EffectivePolicy:
    """A policy that can write.

    ``read_only`` is set explicitly to ``False``. It cannot be omitted: absent
    means the schema default of ``true``, which is a ceiling over the three write
    permissions, so a policy silent on it denies every write with ``read-only
    policy`` and none of the checks under test would ever be reached.
    """
    return EffectivePolicy(
        version="1.0",
        user_id="write-user",
        tenant_id="write-tenant",
        source_profiles=["postgres-write-path"],
        permissions=PolicyPermissions(
            can_query=True,
            can_insert=can_insert,
            can_update=can_update,
            can_delete=can_delete,
            read_only=False,
        ),
        object_rules=ObjectRules(
            allowed_objects=allowed_objects,
            field_rules=field_rules,
            row_filters=row_filters,
        ),
    )


def _read_row(conn: psycopg.Connection, table: str, row_id: int) -> dict:
    """The whole row, as the source holds it.

    Whole-row rather than the columns the test cares about: this is the value the
    integrator passes to ``pre_write`` as ``target_row``, and the row filters need
    every field they reference to be present. A filter whose field is absent fails
    closed, so handing over a partial row would produce ``target row not
    permitted`` for a row that in fact qualifies -- a denial for the wrong reason,
    which would make the in-scope control tests pass vacuously.
    """
    with conn.cursor() as cur:
        cur.execute(
            f"SELECT * FROM {safe_identifier(table)} WHERE id = %s",  # noqa: S608  # nosec B608 -- identifiers allow-list validated
            (row_id,),
        )
        row = cur.fetchone()
    assert row is not None, f"expected seeded {table} row {row_id}"
    return dict(row)


def _row_count(conn: psycopg.Connection, table: str) -> int:
    with conn.cursor() as cur:
        cur.execute(f"SELECT count(*) AS n FROM {safe_identifier(table)}")  # noqa: S608  # nosec B608 -- identifiers allow-list validated
        return cur.fetchone()["n"]


def _row_exists(conn: psycopg.Connection, table: str, row_id: int) -> bool:
    with conn.cursor() as cur:
        cur.execute(
            f"SELECT 1 FROM {safe_identifier(table)} WHERE id = %s",  # noqa: S608  # nosec B608 -- identifiers allow-list validated
            (row_id,),
        )
        return cur.fetchone() is not None


def _issue_if_allowed(
    decision: AccessResult,
    conn: psycopg.Connection,
    sql: str,
    params: tuple[Any, ...],
) -> bool:
    """Issue ``sql`` only when the policy allowed it; report whether it ran.

    A deliberately faithful stand-in for the integrator: the decision gates the
    statement and nothing else does. If enforcement wrongly allowed, this really
    does send the write to Postgres -- which is the point. The surrounding
    :func:`_rolled_back` is what keeps that failure contained to the failing test.
    """
    if not decision.allowed:
        return False
    with conn.cursor() as cur:
        cur.execute(sql, params)
    return True


class TestDeniedUpdateDoesNotReachTheRow:
    """An update the row filters reject must leave the row byte-identical.

    The load-bearing case for the whole write path. Everything else in the SDK's
    write story rests on the claim that a denial is a fact about the data source
    and not just a value the caller received, and the only way to establish that
    is to look at the column afterwards.

    Catches a wrapper that returns the denial but still forwards the statement, a
    ``target_row`` argument that is accepted and dropped, and a filter evaluation
    that runs against the payload instead of the existing row.
    """

    def test_out_of_region_row_is_refused_and_unmodified(
        self, wrapper, signing_key, db_conn
    ) -> None:
        policy = _write_policy(
            can_update=True, allowed_objects=[PATIENTS], row_filters=_scoped_filters()
        )
        ctx = sign_policy(policy, signing_key)

        with _rolled_back(db_conn):
            target = _read_row(db_conn, PATIENTS, PATIENT_OUT_OF_REGION)
            before = target["full_name"]

            decision = wrapper.pre_write(
                ctx,
                WriteOperation.update,
                object_name=PATIENTS,
                payload={"full_name": "Renamed By An Out Of Scope Caller"},
                target_row=target,
            )

            assert decision.allowed is False
            assert decision.reason == "target row not permitted"

            ran = _issue_if_allowed(
                decision,
                db_conn,
                f"UPDATE {safe_identifier(PATIENTS)} SET full_name = %s WHERE id = %s",  # noqa: S608  # nosec B608 -- identifiers allow-list validated
                ("Renamed By An Out Of Scope Caller", PATIENT_OUT_OF_REGION),
            )
            assert ran is False, "a denied write must never be issued"

            after = _read_row(db_conn, PATIENTS, PATIENT_OUT_OF_REGION)["full_name"]

        # Byte-for-byte, not "still looks like a name": a partially applied write
        # or a trigger-side effect would show up here and nowhere else.
        assert after == before

    def test_the_same_update_lands_on_an_in_scope_row(
        self, wrapper, signing_key, db_conn
    ) -> None:
        """The control, without which the test above is worthless.

        Identical policy, identical payload, identical statement -- only the target
        row differs. A validator that denied every update, or a target-row check
        that never matched anything, would satisfy the denial test above and fail
        here. Pairing them is what makes the denial evidence of discrimination
        rather than of breakage.
        """
        policy = _write_policy(
            can_update=True, allowed_objects=[PATIENTS], row_filters=_scoped_filters()
        )
        ctx = sign_policy(policy, signing_key)
        new_name = "Renamed By An In Scope Caller"

        with _rolled_back(db_conn):
            target = _read_row(db_conn, PATIENTS, PATIENT_IN_SCOPE)
            before = target["full_name"]
            assert before != new_name, "seed data would make this test vacuous"

            decision = wrapper.pre_write(
                ctx,
                WriteOperation.update,
                object_name=PATIENTS,
                payload={"full_name": new_name},
                target_row=target,
            )

            assert decision.allowed is True, decision.reason
            assert decision.reason is None

            ran = _issue_if_allowed(
                decision,
                db_conn,
                f"UPDATE {safe_identifier(PATIENTS)} SET full_name = %s WHERE id = %s",  # noqa: S608  # nosec B608 -- identifiers allow-list validated
                (new_name, PATIENT_IN_SCOPE),
            )
            assert ran is True

            after = _read_row(db_conn, PATIENTS, PATIENT_IN_SCOPE)["full_name"]
            assert after == new_name
            assert after != before

        # The rollback is not incidental to this test: it is the only reason the
        # committed database still holds the seeded name for every later test.
        assert _read_row(db_conn, PATIENTS, PATIENT_IN_SCOPE)["full_name"] == before

    def test_an_update_with_no_target_row_is_refused_outright(
        self, wrapper, signing_key, db_conn
    ) -> None:
        """Omitting ``target_row`` under row filters fails closed (section 4.2).

        The failure mode an integrator reaches without meaning to: they hold a
        primary key, they issue ``UPDATE ... WHERE id = %s``, and they never read
        the row -- so the policy's row filters have no row to evaluate. Returning
        ``allowed=True`` there would mean any caller with a key could modify any
        row in the table, which is the region scoping defeated by omission rather
        than by attack.

        The target here is deliberately the row that *would* have passed. The
        refusal is about the absence of proof, not about the row, and the distinct
        reason string is what tells the integrator to read-then-verify instead of
        to widen the policy.
        """
        policy = _write_policy(
            can_update=True, allowed_objects=[PATIENTS], row_filters=_scoped_filters()
        )
        ctx = sign_policy(policy, signing_key)

        with _rolled_back(db_conn):
            before = _read_row(db_conn, PATIENTS, PATIENT_IN_SCOPE)["status"]

            decision = wrapper.pre_write(
                ctx,
                WriteOperation.update,
                object_name=PATIENTS,
                payload={"status": "inactive"},
                # target_row deliberately omitted -- the whole point of the test.
            )

            assert decision.allowed is False
            assert decision.reason == "write target unverifiable"

            ran = _issue_if_allowed(
                decision,
                db_conn,
                f"UPDATE {safe_identifier(PATIENTS)} SET status = %s WHERE id = %s",  # noqa: S608  # nosec B608 -- identifiers allow-list validated
                ("inactive", PATIENT_IN_SCOPE),
            )
            assert ran is False

            after = _read_row(db_conn, PATIENTS, PATIENT_IN_SCOPE)["status"]

        assert after == before


class TestDeniedInsertAddsNoRow:
    """``readOnlyFields`` must stop a row from being created, not just complain.

    ``readOnlyFields`` is the one policy construct with no effect whatsoever on
    reads -- a field it names is returned normally -- so a broken implementation
    is invisible to every read-path test in the suite. Its only observable
    behaviour is here: the row count before and after.

    Both tests use one policy and two payloads differing by a single key, so the
    pair isolates the rule itself rather than any surrounding difference.
    """

    # A surrogate key the source assigns and the caller must not pin. Nothing else
    # in `patients` can carry this test: every remaining column is NOT NULL, so a
    # read-only rule over one of them would make the permitted-insert control
    # impossible to write without violating the schema.
    READ_ONLY = "patients.id"

    # Row filters are omitted on purpose. An insert has no pre-existing target row,
    # so section 4.2's row check does not apply to it -- and their presence would
    # invite the reader to think this denial came from them.
    def _policy(self) -> EffectivePolicy:
        return _write_policy(
            can_insert=True,
            allowed_objects=[PATIENTS],
            field_rules=FieldRules(read_only_fields=[self.READ_ONLY]),
        )

    @staticmethod
    def _writable_payload() -> dict[str, Any]:
        return {
            "full_name": "Newly Inserted Patient",
            "email": "newly.inserted@example.com",
            "ssn": "999-88-7777",
            "date_of_birth": "1991-06-15",
            "region": "us-east",
            "status": "active",
        }

    def test_insert_naming_a_read_only_field_creates_nothing(
        self, wrapper, signing_key, db_conn
    ) -> None:
        ctx = sign_policy(self._policy(), signing_key)
        payload = {"id": 9001, **self._writable_payload()}

        with _rolled_back(db_conn):
            before = _row_count(db_conn, PATIENTS)

            decision = wrapper.pre_write(
                ctx, WriteOperation.insert, object_name=PATIENTS, payload=payload
            )

            assert decision.allowed is False
            # The reason names the offending field. That discloses nothing the
            # caller did not already supply, and the exact string is the contract
            # integrators branch on -- so it is asserted, not merely matched.
            assert decision.reason == "field is read-only: id"

            columns = list(payload)
            ran = _issue_if_allowed(
                decision,
                db_conn,
                f"INSERT INTO {safe_identifier(PATIENTS)} ({', '.join(safe_identifier(c) for c in columns)}) "  # noqa: S608  # nosec B608 -- identifiers allow-list validated
                f"VALUES ({', '.join(['%s'] * len(columns))})",
                tuple(payload[c] for c in columns),
            )
            assert ran is False

            after = _row_count(db_conn, PATIENTS)

        # The whole-table count, not a lookup by the id the payload asked for: a
        # write that landed under a source-assigned key would be missed by the
        # narrower check.
        assert after == before

    def test_the_same_insert_without_that_field_creates_a_row(
        self, wrapper, signing_key, db_conn
    ) -> None:
        """The control for the test above: one key removed, and the row appears.

        Establishes that the denial came from ``readOnlyFields`` and not from
        ``canInsert``, the object rules, or a payload the source would have
        rejected anyway.
        """
        ctx = sign_policy(self._policy(), signing_key)
        payload = self._writable_payload()

        with _rolled_back(db_conn):
            before = _row_count(db_conn, PATIENTS)

            decision = wrapper.pre_write(
                ctx, WriteOperation.insert, object_name=PATIENTS, payload=payload
            )

            assert decision.allowed is True, decision.reason

            columns = list(payload)
            ran = _issue_if_allowed(
                decision,
                db_conn,
                f"INSERT INTO {safe_identifier(PATIENTS)} ({', '.join(safe_identifier(c) for c in columns)}) "  # noqa: S608  # nosec B608 -- identifiers allow-list validated
                f"VALUES ({', '.join(['%s'] * len(columns))})",
                tuple(payload[c] for c in columns),
            )
            assert ran is True

            assert _row_count(db_conn, PATIENTS) == before + 1

        assert _row_count(db_conn, PATIENTS) == before


class TestDeniedDeleteLeavesTheRowPresent:
    """A delete is the one operation whose denial cannot be recovered from.

    A wrongly permitted update overwrites a value; a wrongly permitted delete
    removes the row and the evidence with it. So the assertion is existence, taken
    from the source rather than from anything the SDK returned.
    """

    def _ctx(self, signing_key: str):
        policy = _write_policy(
            can_delete=True, allowed_objects=[DIAGNOSES], row_filters=_scoped_filters()
        )
        return sign_policy(policy, signing_key)

    def test_out_of_region_row_survives_a_denied_delete(
        self, wrapper, signing_key, db_conn
    ) -> None:
        ctx = self._ctx(signing_key)

        with _rolled_back(db_conn):
            target = _read_row(db_conn, DIAGNOSES, DIAGNOSIS_OUT_OF_REGION)

            decision = wrapper.pre_write(
                ctx,
                WriteOperation.delete,
                object_name=DIAGNOSES,
                payload=None,
                target_row=target,
            )

            assert decision.allowed is False
            assert decision.reason == "target row not permitted"

            ran = _issue_if_allowed(
                decision,
                db_conn,
                f"DELETE FROM {safe_identifier(DIAGNOSES)} WHERE id = %s",  # noqa: S608  # nosec B608 -- identifiers allow-list validated
                (DIAGNOSIS_OUT_OF_REGION,),
            )
            assert ran is False

            still_there = _row_exists(db_conn, DIAGNOSES, DIAGNOSIS_OUT_OF_REGION)

        assert still_there is True

    def test_in_scope_row_is_actually_deleted(self, wrapper, signing_key, db_conn) -> None:
        """The control: the same policy really can delete, so the refusal above
        was a decision about the row and not an inability to delete at all."""
        ctx = self._ctx(signing_key)

        with _rolled_back(db_conn):
            target = _read_row(db_conn, DIAGNOSES, DIAGNOSIS_IN_SCOPE)

            decision = wrapper.pre_write(
                ctx,
                WriteOperation.delete,
                object_name=DIAGNOSES,
                payload=None,
                target_row=target,
            )

            assert decision.allowed is True, decision.reason

            ran = _issue_if_allowed(
                decision,
                db_conn,
                f"DELETE FROM {safe_identifier(DIAGNOSES)} WHERE id = %s",  # noqa: S608  # nosec B608 -- identifiers allow-list validated
                (DIAGNOSIS_IN_SCOPE,),
            )
            assert ran is True

            assert _row_exists(db_conn, DIAGNOSES, DIAGNOSIS_IN_SCOPE) is False

        # Restored for the rest of the session by the rollback, not by a re-INSERT:
        # re-inserting would have consumed a sequence value and changed the id.
        assert _row_exists(db_conn, DIAGNOSES, DIAGNOSIS_IN_SCOPE) is True


class TestInsertReturningRunsTheReadPipeline:
    """``INSERT ... RETURNING`` is a write *and* a read (connector spec section 4.5).

    The tempting shortcut is to treat a write's response as the caller's own data
    -- they just supplied it, so what is there to protect? Two things. The source
    contributes columns the caller never sent (a generated key, a trigger-computed
    value), and the caller's own value has to come back in the form the policy
    says that field takes, because the response is where a downstream consumer
    reads it from and a pseudonym that is real on the write path and hashed on the
    read path does not join.

    Uses ``execute_write_with_enforcement``, which is the entry point that owes
    the caller both halves: refuse before the statement, and run the returned
    record through the post-execution pipeline afterwards.
    """

    # `id` is the hidden column: it is assigned by the source, so the payload does
    # not name it and the write is still permitted, yet the RETURNING clause asks
    # for it explicitly. That makes the assertion unambiguous -- the source
    # definitely produced a non-null value and the pipeline definitely removed it.
    HIDDEN = "patients.id"
    MASKED = "patients.email"

    def _ctx(self, signing_key: str):
        policy = _write_policy(
            can_insert=True,
            allowed_objects=[PATIENTS],
            field_rules=FieldRules(
                hidden_fields=[self.HIDDEN],
                masked_fields=[
                    MaskingRule(
                        field=self.MASKED,
                        mask_type=MaskType.hash,
                        parameters=MaskingParameters(algorithm="sha256"),
                    )
                ],
            ),
            row_filters=_scoped_filters(),
        )
        return sign_policy(policy, signing_key)

    def test_returned_record_is_masked_and_stripped(
        self, wrapper, signing_key, db_conn
    ) -> None:
        ctx = self._ctx(signing_key)
        email = "returning.case@example.com"
        payload = {
            "full_name": "Returning Case",
            "email": email,
            "ssn": "888-77-6666",
            "date_of_birth": "1979-04-02",
            "region": "us-east",
            "status": "active",
        }

        def insert_returning(conn: psycopg.Connection) -> dict:
            columns = list(payload)
            with conn.cursor() as cur:
                cur.execute(
                    f"INSERT INTO {safe_identifier(PATIENTS)} "  # noqa: S608  # nosec B608 -- identifiers allow-list validated
                    f"({', '.join(safe_identifier(c) for c in columns)}) "
                    f"VALUES ({', '.join(['%s'] * len(columns))}) "
                    # `region` and `status` are returned because the policy filters
                    # on them and the returned record goes through those filters.
                    # A filter whose field is absent fails closed, so a RETURNING
                    # list that omitted them would see the record dropped -- a
                    # correct outcome for the wrong reason, and one that would hide
                    # a masking regression behind an empty result.
                    "RETURNING id, full_name, email, region, status",
                    tuple(payload[c] for c in columns),
                )
                return dict(cur.fetchone())

        with _rolled_back(db_conn):
            raw = insert_returning(db_conn)
            # The unenforced shape, for contrast: the source really does hand back
            # the id and the plaintext address, so the assertions below are
            # removing and transforming something that was present.
            assert raw["id"] is not None
            assert raw["email"] == email

            record = wrapper.execute_write_with_enforcement(
                ctx,
                WriteOperation.insert,
                insert_returning,
                write_args={"conn": db_conn},
                object_name=PATIENTS,
                payload=payload,
            )

        assert record is not None, "the returned row satisfies the policy's row filters"

        # Hidden: absent, not present-and-null. A key holding None would still tell
        # a consumer the column exists and was readable.
        assert "id" not in record

        # Masked: the caller's own value comes back in the policy's form, computed
        # over the value the source stored rather than over anything the SDK kept
        # from the request.
        assert record["email"] == hashlib.sha256(email.encode("utf-8")).hexdigest()[:16]
        assert record["email"] != email

        # Unrestricted columns are untouched -- the pipeline is a filter, not a
        # blanket redaction.
        assert record["full_name"] == "Returning Case"
        assert record["region"] == "us-east"

    def test_a_denied_write_never_reaches_the_statement(
        self, wrapper, signing_key, db_conn
    ) -> None:
        """``execute_write_with_enforcement`` must refuse *before* calling the fn.

        Same policy, but the payload names the hidden column. If the wrapper
        validated after execution -- or validated the response instead of the
        request -- the row would already exist by the time the ``PermissionError``
        was raised, and the caller would have no way to know.
        """
        ctx = self._ctx(signing_key)
        calls: list[int] = []

        def must_not_run(conn: psycopg.Connection) -> dict:  # pragma: no cover - asserted below
            calls.append(1)
            with conn.cursor() as cur:
                cur.execute(
                    f"INSERT INTO {safe_identifier(PATIENTS)} "  # noqa: S608  # nosec B608 -- identifiers allow-list validated
                    "(id, full_name, email, ssn, date_of_birth, region, status) "
                    "VALUES (9002, 'Should Not Exist', 'no@example.com', '000-00-0000', "
                    "'2000-01-01', 'us-east', 'active') RETURNING id"
                )
                return dict(cur.fetchone())

        with _rolled_back(db_conn):
            before = _row_count(db_conn, PATIENTS)

            with pytest.raises(PermissionError, match="field is hidden: id"):
                wrapper.execute_write_with_enforcement(
                    ctx,
                    WriteOperation.insert,
                    must_not_run,
                    write_args={"conn": db_conn},
                    object_name=PATIENTS,
                    payload={"id": 9002, "full_name": "Should Not Exist"},
                )

            after = _row_count(db_conn, PATIENTS)

        assert calls == [], "the write function must not be invoked for a denied write"
        assert after == before
