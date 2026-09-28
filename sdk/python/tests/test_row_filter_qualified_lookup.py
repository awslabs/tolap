"""Cross-SDK conformance for how a row filter finds its field on a row (issue #32).

Driven by ``fixtures/enforcement/row-filter-qualified-lookup.json``. The
counterparts read the same file, case for case:

- TypeScript: ``packages/core/tests/row-filter-qualified-lookup.test.ts``
- .NET: ``tests/Tolap.Core.Tests/RowFilterQualifiedLookupTests.cs``

The lookup used to fall back to the field-name matcher. That matcher drops
qualifiers, so a filter on ``patients.region`` read ``encounters.region`` when
the row had no ``patients`` column, and a bare filter matching several qualified
keys used whichever key came first. The expectations live only in the fixture,
as they do for the operator corpus, so the three SDKs cannot drift apart.

Each case carries its own records because key order is part of what is being
tested. ``json`` preserves the order the fixture writes, which is the order the
lookup sees.
"""

from __future__ import annotations

from typing import Any

import pytest

from conftest import load_fixture
from tolap_core.enforcement import apply_row_filters, validate_write
from tolap_core.enums import WriteOperation
from tolap_core.serialization import deserialize_effective_policy

FIXTURE_PATH = "enforcement/row-filter-qualified-lookup.json"

#: Asserted so that a dropped case fails the suite rather than shrinking it quietly.
EXPECTED_CASE_COUNT = 29

_FIXTURE = load_fixture(FIXTURE_PATH)

CASES: list[dict] = _FIXTURE["cases"]


def _surviving_ids(case: dict) -> list[Any]:
    policy = deserialize_effective_policy(case["policy"])

    return [row["id"] for row in apply_row_filters(case["records"], policy)]


class TestCorpusIsIntact:
    def test_the_fixture_carries_the_expected_case_count(self) -> None:
        assert len(CASES) == EXPECTED_CASE_COUNT, (
            f"{FIXTURE_PATH} carries {len(CASES)} cases, expected {EXPECTED_CASE_COUNT}"
        )

    def test_case_names_are_unique(self) -> None:
        names = [case["name"] for case in CASES]

        assert len(set(names)) == len(names)

    def test_every_case_carries_records_and_row_filters(self) -> None:
        for case in CASES:
            assert case["records"], f"case {case['name']!r} carries no records"
            assert case["policy"]["objectRules"]["rowFilters"], (
                f"case {case['name']!r} carries no row filters"
            )


class TestSharedCorpus:
    @pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
    def test_case_matches_the_shared_expectation(self, case: dict) -> None:
        assert _surviving_ids(case) == case["expected"], (
            f"case {case['name']!r} from {FIXTURE_PATH} disagrees with the shared corpus"
        )


def _write_policy(field: str) -> Any:
    return deserialize_effective_policy(
        {
            "version": "1.0",
            "permissions": {
                "canQuery": True,
                "canUpdate": True,
                "canDelete": True,
                "readOnly": False,
            },
            "objectRules": {
                "rowFilters": [{"field": field, "operator": "equals", "value": "us-east"}]
            },
        }
    )


class TestWriteTargetUsesTheSameLookup:
    """An update or delete target is checked through the same row-filter lookup.

    So a target row the read path would drop, because of a conflicting qualifier
    or an ambiguous bare name, is also refused as a write target.
    """

    @pytest.mark.parametrize("operation", [WriteOperation.update, WriteOperation.delete])
    def test_a_target_with_only_another_objects_column_is_refused(
        self, operation: WriteOperation
    ) -> None:
        result = validate_write(
            operation,
            "patients",
            {"status": "x"} if operation is WriteOperation.update else None,
            _write_policy("patients.region"),
            target_row={"encounters.region": "us-east"},
        )

        assert result.allowed is False
        assert result.reason == "target row not permitted"

    def test_an_ambiguous_target_is_refused(self) -> None:
        result = validate_write(
            WriteOperation.update,
            "patients",
            {"status": "x"},
            _write_policy("region"),
            target_row={"patients.region": "us-east", "encounters.region": "us-east"},
        )

        assert result.allowed is False
        assert result.reason == "target row not permitted"

    def test_a_target_with_a_bare_key_is_still_permitted(self) -> None:
        result = validate_write(
            WriteOperation.update,
            "patients",
            {"status": "x"},
            _write_policy("patients.region"),
            target_row={"encounters.region": "eu-west", "region": "us-east"},
        )

        assert result.allowed is True
