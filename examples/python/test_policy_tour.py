"""The policy tour, executed rather than trusted.

Each assertion is an outcome -- a masked value, a refusal and its reason, the ids a filter kept,
what a merge produced -- so a tour that printed plausible lines while enforcing nothing would fail
here. ``EXPECTED_LINES`` is byte-identical to the TypeScript and .NET suites'.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

import pytest

from tolap_core.enums import MaskType, WriteOperation

import policy_tour_example as ex

#: Every line of the tour that carries a result, in order.
EXPECTED_LINES = [
    "--- Masks: one rule per mask type ------------------------------------",
    "  id         no rule                 7                       7",
    "  name       partial showFirst 1     Alice Nguyen            A***********",
    "  phone      partial showLast 4 '#'  555-867-5309            ########5309",
    "  card       partial first 4 last 4  4111111111111111        4111********1111",
    "  address    full                    12 Elm Street           *************",
    "  email      hash sha256             alice@example.com       ff8d9819fc0e12bf",
    "  mrn        hash sha512             MRN-00417               972f27e06cb47c3e",
    "  member_id  hash blake2b            M-99812                 eeeb704b805ffb7c",
    "  notes      null                    allergic to penicillin  null",
    "  dob        redact                  1979-04-12              [REDACTED]",
    "  ssn        hiddenFields            111-22-3333             (dropped)",
    "--- Fields: allowedFields next to hiddenFields -----------------------",
    "  the source returns    id, name, region, dob, notes, ssn",
    "  allowedFields [id, name, region]",
    "    returns             id, name, region",
    "      asks for [id, ssn]            DENY    denied fields: ssn",
    "  hiddenFields [ssn, notes]",
    "    returns             id, name, region, dob",
    "      asks for [id, ssn]            DENY    denied fields: ssn",
    "--- Objects: allowedObjects [patients, encounters, billing_*] --------",
    "                       hiddenObjects [billing_internal]",
    "  patients                          ALLOW",
    "  encounters                        ALLOW",
    "  billing_invoices                  ALLOW",
    "  billing_internal                  DENY    object is hidden",
    "  audit_log                         DENY    object not in allowed set",
    "--- Row filters: one operator at a time over rows 1-6 ----------------",
    "  region equals us-east             ids 1, 4, 6",
    "  region notEquals us-east          ids 2, 3, 5",
    "  region in [us-east, us-west]      ids 1, 2, 4, 6",
    "  region notIn [us-east, us-west]   ids 3, 5",
    "  age greaterThan 40                ids 3, 4, 5",
    "  age lessThanOrEqual 29            ids 2, 6",
    "  age between [30, 52]              ids 1, 3, 5",
    "  email contains @clinic.           ids 1, 2, 4, 6",
    "  ward startsWith cardio            ids 1, 3, 6",
    "  email like %@partner.net          ids 3, 5",
    "  code matches PT-[0-9]{3}          ids 1, 2, 5",
    "  discharged_at isNull              ids 1, 3, 5",
    "  discharged_at isNotNull           ids 2, 4",
    "--- Permissions ------------------------------------------------------",
    "  canQuery false",
    "      query patients                DENY    query not permitted",
    "  canInsert true, readOnly true",
    "      insert                        DENY    read-only policy",
    "  canInsert, canUpdate, readOnly false; mrn read-only; region us-east",
    "      insert                        ALLOW",
    "      insert setting mrn            DENY    field is read-only: mrn",
    "      update a us-east row          ALLOW",
    "      update an eu-west row         DENY    target row not permitted",
    "      delete                        DENY    delete not permitted",
    "--- Limits over seven search hits ------------------------------------",
    "  scores  d1 0.92  d2 0.75  d3 0.60  d4 0.88  d5 0.81  d6 none  d7 0.99",
    "  sizes   d1 1200  d2 4096  d3 800   d4 2048  d5 none  d6 500   d7 100",
    "  minSimilarityScore 0.75           d1, d2, d4, d5, d7",
    "  maxObjectSizeBytes 2048           d1, d3, d4, d6, d7",
    "  maxResults 2                      d1, d2",
    "  all three                         d1, d4",
    "--- Merging: a user policy and a group policy ------------------------",
    "  resolved from    analyst-direct, clinicians-group",
    "  allowedObjects   intersected",
    "    analyst-direct     encounters, labs, patients",
    "    clinicians-group   billing, encounters, patients",
    "    merged             encounters, patients",
    "  hiddenFields     unioned",
    "    analyst-direct     ssn",
    "    clinicians-group   notes",
    "    merged             notes, ssn",
    "  phone mask       the most restrictive",
    "    analyst-direct     partial",
    "    clinicians-group   redact",
    "    merged             redact",
    "  rowFilters       all of them apply",
    "    analyst-direct     region in",
    "    clinicians-group   age greaterThanOrEqual",
    "    merged             region in, age greaterThanOrEqual",
    "  maxResults       the lowest",
    "    analyst-direct     100",
    "    clinicians-group   25",
    "    merged             25",
    "  canInsert        only if every policy grants it",
    "    analyst-direct     no",
    "    clinicians-group   yes",
    "    merged             no",
    "  readOnly         if any policy sets it",
    "    analyst-direct     yes",
    "    clinicians-group   no",
    "    merged             yes",
    "    id=1  region=us-east  age=34  phone=[REDACTED]",
    "    id=4  region=us-east  age=65  phone=[REDACTED]",
    "  labs                              DENY    object not in allowed set",
    "  billing                           DENY    object not in allowed set",
    "  insert                            DENY    insert not permitted",
]


def _by_label(entries, label):
    return next(e for e in entries if e.label == label)


def test_every_mask_type_changes_the_value_and_a_hidden_field_is_dropped() -> None:
    masked = ex.enforce(ex.mask_policy(), [ex.PATIENT])[0]

    assert masked == {
        "id": 7,
        "name": "A***********",
        "phone": "########5309",
        "card": "4111********1111",
        "address": "*************",
        "email": "ff8d9819fc0e12bf",
        "mrn": "972f27e06cb47c3e",
        "member_id": "eeeb704b805ffb7c",
        "notes": None,
        "dob": "[REDACTED]",
    }


def test_allowed_fields_keep_only_the_named_and_hidden_fields_drop_only_the_named() -> None:
    source = {"id": 1, "name": "n", "region": "r", "dob": "d", "notes": "x", "ssn": "s"}

    assert sorted(ex.enforce(ex.allowed_fields_policy(), [source])[0]) == ["id", "name", "region"]
    assert sorted(ex.enforce(ex.hidden_fields_policy(), [source])[0]) == ["dob", "id", "name", "region"]


@pytest.mark.parametrize(
    ("name", "allowed", "reason"),
    [
        ("patients", True, None),
        ("billing_invoices", True, None),
        ("billing_internal", False, "object is hidden"),
        ("audit_log", False, "object not in allowed set"),
    ],
)
def test_hidden_objects_win_over_allowed_objects(name: str, allowed: bool, reason: str | None) -> None:
    result = ex.check(ex.object_policy(), object_name=name)

    assert result.allowed is allowed
    if reason is not None:
        assert result.reason == reason


@pytest.mark.parametrize(
    ("label", "ids"),
    [
        ("region equals us-east", [1, 4, 6]),
        ("region notEquals us-east", [2, 3, 5]),
        ("region in [us-east, us-west]", [1, 2, 4, 6]),
        ("region notIn [us-east, us-west]", [3, 5]),
        ("age greaterThan 40", [3, 4, 5]),
        ("age lessThanOrEqual 29", [2, 6]),
        ("age between [30, 52]", [1, 3, 5]),
        ("email contains @clinic.", [1, 2, 4, 6]),
        ("ward startsWith cardio", [1, 3, 6]),
        ("email like %@partner.net", [3, 5]),
        ("code matches PT-[0-9]{3}", [1, 2, 5]),
        ("discharged_at isNull", [1, 3, 5]),
        ("discharged_at isNotNull", [2, 4]),
    ],
)
def test_each_row_filter_keeps_the_expected_rows(label: str, ids: list[int]) -> None:
    rule = _by_label(ex.FILTERS, label).rule

    assert [row["id"] for row in ex.enforce(ex.filter_policy(rule), ex.ROWS)] == ids


def test_can_query_false_and_read_only_refuse() -> None:
    query = ex.check(ex.query_denied_policy(), object_name="patients")
    assert query.allowed is False
    assert query.reason == "query not permitted"

    insert = ex.check_write(ex.read_only_policy(), WriteOperation.insert, {"name": "Bo"})
    assert insert.allowed is False
    assert insert.reason == "read-only policy"


def test_granted_writes_still_meet_the_field_and_row_rules() -> None:
    writer = ex.writer_policy()
    east = {"id": 1, "region": "us-east"}
    west = {"id": 3, "region": "eu-west"}

    assert ex.check_write(writer, WriteOperation.insert, {"name": "Bo", "region": "us-east"}).allowed
    assert ex.check_write(writer, WriteOperation.insert, {"mrn": "MRN-1"}).reason == "field is read-only: mrn"
    assert ex.check_write(writer, WriteOperation.update, {"name": "Bo"}, east).allowed
    assert ex.check_write(writer, WriteOperation.update, {"name": "Bo"}, west).reason == "target row not permitted"
    assert ex.check_write(writer, WriteOperation.delete, {}, east).reason == "delete not permitted"


@pytest.mark.parametrize(
    ("label", "ids"),
    [
        ("minSimilarityScore 0.75", ["d1", "d2", "d4", "d5", "d7"]),
        ("maxObjectSizeBytes 2048", ["d1", "d3", "d4", "d6", "d7"]),
        ("maxResults 2", ["d1", "d2"]),
        ("all three", ["d1", "d4"]),
    ],
)
def test_limits_keep_the_expected_hits(label: str, ids: list[str]) -> None:
    limits = _by_label(ex.LIMITS, label).limits

    assert [row["id"] for row in ex.enforce(ex.policy(limits=limits), ex.DOCUMENTS)] == ids


def test_merging_the_most_restrictive_rule_wins() -> None:
    merged = ex.merged_policy()
    rules = merged.object_rules
    assert rules is not None and rules.field_rules is not None

    assert merged.source_profiles == ["analyst-direct", "clinicians-group"]
    assert sorted(rules.allowed_objects or []) == ["encounters", "patients"]
    assert sorted(rules.field_rules.hidden_fields or []) == ["notes", "ssn"]
    phone = next(m for m in rules.field_rules.masked_fields or [] if m.field == "phone")
    assert phone.mask_type == MaskType.redact
    assert len(rules.row_filters or []) == 2
    assert merged.limits is not None and merged.limits.max_results == 25
    assert merged.permissions.can_insert is not True
    assert merged.permissions.read_only is True

    rows = ex.enforce(merged, ex.MERGE_ROWS)
    assert [row["id"] for row in rows] == [1, 4]
    assert all("ssn" not in row and "notes" not in row for row in rows)
    assert all(row["phone"] == "[REDACTED]" for row in rows)


def test_the_example_script_prints_the_lines_the_other_two_languages_print() -> None:
    """Runs the script as CI does. It raises ``SystemExit`` if a mask or the merge lets a hidden
    field through, so this covers those paths too."""
    script = pathlib.Path(__file__).parent / "policy_tour_example.py"
    result = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, timeout=60)

    assert result.returncode == 0, result.stderr
    results = [l for l in result.stdout.splitlines() if l.startswith("  ") or l.startswith("---")]
    assert results == EXPECTED_LINES
