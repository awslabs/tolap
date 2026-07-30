"""Cross-SDK parity for the write path (connector spec section 4).

One case corpus -- operation x policy x payload x target row -> allowed + reason --
asserted with byte-identical expected outcomes in all three SDKs. The counterparts
are:

- TypeScript: ``packages/core/tests/write-path-parity.test.ts``
- .NET: ``tests/Tolap.Core.Tests/WritePathParityTests.cs``

The three tables must stay identical case-for-case. This file is the reference
ordering; the other two follow it row for row so a diff of the three is readable.

**The reason strings are asserted, not just the boolean.** They are the contract
integrators log and branch on, and each one names a different policy edit that would
unblock the caller: ``insert not permitted`` is fixed by granting ``canInsert``,
``read-only policy`` by clearing ``readOnly``, ``field is read-only: x`` by removing
``x`` from ``readOnlyFields``, and ``write target unverifiable`` by reading the target
row first. An integrator who cannot tell them apart cannot tell which edit to make.

A corpus of this shape is what catches divergence: a prior cross-SDK table exposed a
real fail-open that no single-SDK test had found, because every SDK's own suite
asserted the behaviour that SDK happened to implement.
"""

from __future__ import annotations

from typing import Any

import pytest

from tolap_core.enforcement import validate_write
from tolap_core.enums import FilterOperator, MaskType, WriteOperation
from tolap_core.models import (
    EffectivePolicy,
    FieldRules,
    MaskingRule,
    ObjectRules,
    PolicyPermissions,
    RowFilter,
)


def _policy(permissions: PolicyPermissions, object_rules: ObjectRules | None = None) -> EffectivePolicy:
    return EffectivePolicy(
        version="1.0",
        user_id="parity-user",
        tenant_id="parity-tenant",
        source_profiles=["write-path-parity"],
        permissions=permissions,
        object_rules=object_rules,
    )


# -- The shared parity policies. Identical field-for-field in all three SDKs. --

#: Every write granted, with object rules, field rules and a row filter.
FULL_WRITE = _policy(
    PolicyPermissions(
        can_query=True,
        can_insert=True,
        can_update=True,
        can_delete=True,
        read_only=False,
    ),
    ObjectRules(
        allowed_objects=["patients", "encounters"],
        hidden_objects=["audit_log"],
        field_rules=FieldRules(
            hidden_fields=["patients.ssn"],
            read_only_fields=["patients.created_at"],
            masked_fields=[MaskingRule(field="patients.email", mask_type=MaskType.hash)],
        ),
        row_filters=[RowFilter(field="region", operator=FilterOperator.in_, values=["us-east"])],
    ),
)

#: A policy authored before writes existed: it grants reads and says nothing about
#: writes. Every write must be denied, which is the whole point of the false default.
SILENT = _policy(PolicyPermissions(can_query=True))

#: Contradictory on purpose: all three write permissions granted *and* readOnly set.
#: The ceiling has to win (connector spec section 4.1).
READ_ONLY_CEILING = _policy(
    PolicyPermissions(
        can_query=True,
        can_insert=True,
        can_update=True,
        can_delete=True,
        read_only=True,
    )
)

#: Insert and update granted, delete omitted; an allowedFields allow-list and no row
#: filters, so the row check has nothing to verify and must not deny.
ALLOW_LIST = _policy(
    PolicyPermissions(
        can_query=True, can_insert=True, can_update=True, read_only=False
    ),
    ObjectRules(field_rules=FieldRules(allowed_fields=["full_name", "status"])),
)

#: An EMPTY allowedFields, which denies every field (canonical spec section 3) rather
#: than lifting the restriction. The most restrictive possible field rule.
EMPTY_ALLOW_LIST = _policy(
    PolicyPermissions(can_query=True, can_insert=True, read_only=False),
    ObjectRules(field_rules=FieldRules(allowed_fields=[])),
)

#: canInsert without canUpdate, so an upsert -- which needs both -- is denied on the
#: half it lacks (connector spec section 8's safe intersection).
INSERT_ONLY = _policy(
    PolicyPermissions(can_query=True, can_insert=True, read_only=False)
)

POLICIES: dict[str, EffectivePolicy] = {
    "full-write": FULL_WRITE,
    "silent": SILENT,
    "read-only-ceiling": READ_ONLY_CEILING,
    "allow-list": ALLOW_LIST,
    "empty-allow-list": EMPTY_ALLOW_LIST,
    "insert-only": INSERT_ONLY,
}


# Marks a corpus row whose target row is an EXPLICIT null rather than absent.
#
# The distinction is not cosmetic and it is why this constant exists. "Absent"
# reaches the code through each SDK's own default (Python's TARGET_ROW_UNKNOWN
# sentinel, TypeScript's `?? TARGET_ROW_UNKNOWN`), while an explicit null reaches the
# separate "this is not a row I can evaluate filters against" guard. Both MUST deny
# with ``write target unverifiable``, but they are different branches, and a corpus
# that only ever spelled it one way left the other unexercised: with only the null
# spelling in the table, deleting the sentinel branch outright -- a textbook fail-open,
# "no target row supplied means nothing to check" -- kept all 45 cases green, because
# null happened to be caught downstream by the non-mapping guard. Both spellings are
# now in the table so neither branch can be removed silently.
EXPLICIT_NULL_TARGET = "explicit-null"

# The corpus. Each row is
#   (case id, policy key, operation, object, payload, target row, full replace,
#    allowed, reason)
# where a target row of None means "the caller supplied none, by omission" and
# EXPLICIT_NULL_TARGET means "the caller passed null".
PARITY_CORPUS: list[tuple[str, str, WriteOperation, str | None, Any, Any, bool, bool, str | None]] = [
    # -- Check 1: operation permission, then the readOnly ceiling --
    ("silent-insert", "silent", WriteOperation.insert, "patients", {"full_name": "x"}, None, False, False, "insert not permitted"),
    ("silent-update", "silent", WriteOperation.update, "patients", {"full_name": "x"}, None, False, False, "update not permitted"),
    ("silent-delete", "silent", WriteOperation.delete, "patients", None, None, False, False, "delete not permitted"),
    # An upsert reports the first permission it lacks, so the reason names insert.
    ("silent-upsert", "silent", WriteOperation.upsert, "patients", {"full_name": "x"}, None, False, False, "insert not permitted"),
    # The ceiling overrides all three grants, and reports itself rather than a
    # permission -- clearing readOnly is the edit that unblocks the caller.
    ("ceiling-insert", "read-only-ceiling", WriteOperation.insert, "patients", {"full_name": "x"}, None, False, False, "read-only policy"),
    ("ceiling-update", "read-only-ceiling", WriteOperation.update, "patients", {"full_name": "x"}, None, False, False, "read-only policy"),
    ("ceiling-delete", "read-only-ceiling", WriteOperation.delete, "patients", None, None, False, False, "read-only policy"),
    ("ceiling-upsert", "read-only-ceiling", WriteOperation.upsert, "patients", {"full_name": "x"}, None, False, False, "read-only policy"),
    # The safe intersection: insert alone is not enough for an upsert.
    ("insert-only-upsert", "insert-only", WriteOperation.upsert, "patients", {"full_name": "x"}, None, False, False, "update not permitted"),
    ("insert-only-insert", "insert-only", WriteOperation.insert, "patients", {"full_name": "x"}, None, False, True, None),
    ("allow-list-delete", "allow-list", WriteOperation.delete, "patients", None, None, False, False, "delete not permitted"),

    # -- Check 2: the target object --
    ("hidden-object", "full-write", WriteOperation.insert, "audit_log", {"full_name": "x"}, None, False, False, "object is hidden"),
    ("object-not-allowed", "full-write", WriteOperation.insert, "billing_internal", {"full_name": "x"}, None, False, False, "object not in allowed set"),
    # A hidden object is not writable even for a delete whose target row would pass.
    ("hidden-object-delete", "full-write", WriteOperation.delete, "audit_log", None, {"region": "us-east"}, False, False, "object is hidden"),
    ("allowed-object", "full-write", WriteOperation.insert, "encounters", {"full_name": "x"}, None, False, True, None),
    # No object supplied skips the check rather than denying: an integrator who cannot
    # name the object still gets the other three checks.
    ("no-object-name", "full-write", WriteOperation.insert, None, {"full_name": "x"}, None, False, True, None),

    # -- Check 3: every field in the payload --
    ("insert-plain-field", "full-write", WriteOperation.insert, "patients", {"full_name": "x"}, None, False, True, None),
    # A field the caller cannot read, it cannot write. The reason names the payload
    # key as the caller spelled it -- safe, since the caller supplied it.
    ("hidden-field-bare", "full-write", WriteOperation.insert, "patients", {"ssn": "1"}, None, False, False, "field is hidden: ssn"),
    # Bidirectional, case-insensitive matching: a rule of patients.ssn blocks a key of
    # PATIENTS.SSN and of ssn alike (connector spec section 3.2).
    ("hidden-field-qualified-upper", "full-write", WriteOperation.insert, "patients", {"PATIENTS.SSN": "1"}, None, False, False, "field is hidden: PATIENTS.SSN"),
    # The readOnlyFields rule is written qualified; the payload key is bare.
    ("read-only-field", "full-write", WriteOperation.insert, "patients", {"created_at": "2026-01-01"}, None, False, False, "field is read-only: created_at"),
    # Nested keys are reached at every depth, and the walk records the container key
    # first -- so the reported field is the offending leaf, not its parent.
    ("nested-hidden-field", "full-write", WriteOperation.insert, "patients", {"demographics": {"ssn": "1"}}, None, False, False, "field is hidden: ssn"),
    # Fail closed on the WHOLE write: a payload mixing a writable and an unwritable
    # field is rejected outright, never stripped down to the writable part.
    ("mixed-payload-rejected-whole", "full-write", WriteOperation.update, "patients", {"status": "active", "ssn": "1"}, {"region": "us-east"}, False, False, "field is hidden: ssn"),
    # readOnlyFields has NO effect on reads: a masked field is still writable here,
    # and this row exists to pin that maskedFields is not a write restriction.
    ("masked-field-is-writable", "full-write", WriteOperation.insert, "patients", {"email": "a@b.c"}, None, False, True, None),
    ("allow-list-permits-listed", "allow-list", WriteOperation.insert, "patients", {"full_name": "x"}, None, False, True, None),
    ("allow-list-denies-unlisted", "allow-list", WriteOperation.insert, "patients", {"full_name": "x", "region": "us-east"}, None, False, False, "field not in allowed set: region"),
    # [] denies every field rather than lifting the restriction.
    ("empty-allow-list-denies", "empty-allow-list", WriteOperation.insert, "patients", {"full_name": "x"}, None, False, False, "field not in allowed set: full_name"),
    # An empty payload names no fields, so the field check has nothing to reject. The
    # permission and object checks still ran and passed.
    ("empty-payload-under-empty-allow-list", "empty-allow-list", WriteOperation.insert, "patients", {}, None, False, True, None),

    # -- Check 4: row filters against the update/delete target --
    ("update-matching-row", "full-write", WriteOperation.update, "patients", {"full_name": "x"}, {"region": "us-east"}, False, True, None),
    # A caller must not modify a row it could not have selected. The reason names no
    # value -- section 4.4 permits naming a payload field, never a row value.
    ("update-non-matching-row", "full-write", WriteOperation.update, "patients", {"full_name": "x"}, {"region": "eu-west"}, False, False, "target row not permitted"),
    # A row missing the filtered field fails closed, exactly as it would on a read.
    ("update-row-missing-field", "full-write", WriteOperation.update, "patients", {"full_name": "x"}, {"id": 1}, False, False, "target row not permitted"),
    # No target row and filters present is UNVERIFIABLE, not an allow. This is the
    # fail-open a naive implementation reaches by treating "nothing to check" as pass.
    ("update-no-target-row", "full-write", WriteOperation.update, "patients", {"full_name": "x"}, None, False, False, "write target unverifiable"),
    ("delete-no-target-row", "full-write", WriteOperation.delete, "patients", None, None, False, False, "write target unverifiable"),
    # An EXPLICIT null target is a different code path from an omitted one (see
    # EXPLICIT_NULL_TARGET) and must deny identically. A caller who passes the row
    # they failed to read must not do better than one who passed nothing.
    ("update-explicit-null-target", "full-write", WriteOperation.update, "patients", {"full_name": "x"}, EXPLICIT_NULL_TARGET, False, False, "write target unverifiable"),
    ("delete-explicit-null-target", "full-write", WriteOperation.delete, "patients", None, EXPLICIT_NULL_TARGET, False, False, "write target unverifiable"),
    ("delete-matching-row", "full-write", WriteOperation.delete, "patients", None, {"region": "us-east"}, False, True, None),
    ("delete-non-matching-row", "full-write", WriteOperation.delete, "patients", None, {"region": "eu-west"}, False, False, "target row not permitted"),
    ("upsert-matching-row", "full-write", WriteOperation.upsert, "patients", {"full_name": "x"}, {"region": "us-east"}, False, True, None),
    ("upsert-no-target-row", "full-write", WriteOperation.upsert, "patients", {"full_name": "x"}, None, False, False, "write target unverifiable"),
    # An insert has no pre-existing target, so the row check does not apply to it --
    # this is why insert-plain-field above passes with no target row.
    ("insert-ignores-target-row", "full-write", WriteOperation.insert, "patients", {"full_name": "x"}, None, False, True, None),
    # A policy with no row filters has nothing to verify, so an absent target row is
    # not unverifiable -- the check is vacuous rather than fail-closed.
    ("no-filters-no-target-row", "allow-list", WriteOperation.update, "patients", {"status": "active"}, None, False, True, None),

    # -- Ordering: the field check precedes the row check --
    # Both would deny; the field reason wins because check 3 runs before check 4.
    ("field-denial-precedes-row-denial", "full-write", WriteOperation.update, "patients", {"created_at": "x"}, {"region": "eu-west"}, False, False, "field is read-only: created_at"),
    # And the permission check precedes everything: this payload and object would both
    # deny under full-write, but under `silent` the permission reason is reported.
    ("permission-denial-precedes-all", "silent", WriteOperation.insert, "audit_log", {"ssn": "1"}, None, False, False, "insert not permitted"),

    # -- The full-resource-replace rule (connector spec section 6) --
    # Identical payload, identical policy, identical target row: the ONLY difference is
    # that a replace overwrites every field of the resource, so omitting a protected
    # field is still an attempt to overwrite it with absent.
    ("partial-update-omitting-protected-field", "full-write", WriteOperation.update, "patients", {"full_name": "x"}, {"region": "us-east"}, False, True, None),
    ("full-replace-omitting-protected-field", "full-write", WriteOperation.update, "patients", {"full_name": "x"}, {"region": "us-east"}, True, False, "field is hidden: patients.ssn"),
    # A replace under a policy with no protected fields adds nothing, so it behaves
    # exactly like a partial update.
    ("full-replace-with-no-protected-fields", "insert-only", WriteOperation.insert, "patients", {"full_name": "x"}, None, True, True, None),
]


@pytest.mark.parametrize(
    ("case_id", "policy_key", "operation", "object_name", "payload", "target_row", "full_replace", "allowed", "reason"),
    PARITY_CORPUS,
    ids=[case[0] for case in PARITY_CORPUS],
)
def test_write_path_parity(
    case_id: str,
    policy_key: str,
    operation: WriteOperation,
    object_name: str | None,
    payload: Any,
    target_row: Any,
    full_replace: bool,
    allowed: bool,
    reason: str | None,
) -> None:
    # An omitted target row goes through the function's own default, so the sentinel
    # branch is exercised; EXPLICIT_NULL_TARGET goes through the null path instead.
    # Passing None for both would leave the sentinel branch untested -- see
    # EXPLICIT_NULL_TARGET.
    if target_row is None:
        result = validate_write(
            operation, object_name, payload, POLICIES[policy_key], full_replace=full_replace
        )
    else:
        result = validate_write(
            operation,
            object_name,
            payload,
            POLICIES[policy_key],
            target_row=None if target_row == EXPLICIT_NULL_TARGET else target_row,
            full_replace=full_replace,
        )

    assert result.allowed is allowed, f"{case_id}: {result.reason}"
    assert result.reason == reason, case_id


def test_corpus_covers_every_documented_write_denial_reason() -> None:
    """Every reason string in connector spec section 4.4 appears in the corpus.

    Without this, a reason could be dropped from the implementation *and* from the
    table together and the parity suite would keep passing -- the corpus would agree
    with itself across three SDKs while none of them enforced the rule.
    """
    documented = {
        "insert not permitted",
        "update not permitted",
        "delete not permitted",
        "read-only policy",
        "field is hidden",
        "field is read-only",
        "field not in allowed set",
        "target row not permitted",
        "write target unverifiable",
        # Not from section 4.4 but part of the same contract: the object rules'
        # reasons (section 3.3) are reachable on the write path too.
        "object is hidden",
        "object not in allowed set",
    }
    # A parameterized reason is compared on its prefix; the field name after the colon
    # is the caller's own payload key.
    seen = {
        (case[8].split(":", 1)[0] if case[8] is not None else None)
        for case in PARITY_CORPUS
    }

    assert documented <= seen, documented - seen


def test_corpus_case_ids_are_unique() -> None:
    """Duplicate ids would make a cross-SDK diff of the three tables unreadable."""
    ids = [case[0] for case in PARITY_CORPUS]

    assert len(ids) == len(set(ids))
