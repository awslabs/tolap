"""Cross-SDK conformance: the SQL pre-checks validate every table a query references.

Driven by ``fixtures/enforcement/sql-multi-table.json``. The counterparts read
the same file, case for case:

- TypeScript: ``packages/core/tests/sql-multi-table.test.ts`` and
  ``packages/mcp/tests/sql-multi-table.test.ts``
- .NET: ``tests/Tolap.Core.Tests/SqlMultiTableTests.cs`` and
  ``tests/Tolap.Mcp.Tests/SqlMultiTableTests.cs``

Each case runs :func:`prepare_sql_query`, the full pre-execution path, and pins
whether the query may run and, when it may not, the reason given.
"""

from __future__ import annotations

import pytest

from conftest import load_fixture
from tolap_core.serialization import deserialize_effective_policy
from tolap_core.sql_rewriter import prepare_sql_query

FIXTURE_PATH = "enforcement/sql-multi-table.json"

#: Asserted so that a dropped case fails the suite rather than shrinking it quietly.
EXPECTED_CASE_COUNT = 98

CASES: list[dict] = load_fixture(FIXTURE_PATH)["cases"]


def _run(case: dict) -> dict:
    policy = deserialize_effective_policy(case["policy"])
    prep = prepare_sql_query(case["query"], policy, object_name=case.get("objectName"))
    actual: dict = {"allowed": prep.allowed}
    if "reason" in case["expected"]:
        actual["reason"] = prep.denial_reason
    return actual


class TestCorpusIsIntact:
    def test_the_fixture_carries_the_expected_case_count(self) -> None:
        assert len(CASES) == EXPECTED_CASE_COUNT, (
            f"{FIXTURE_PATH} carries {len(CASES)} cases, expected {EXPECTED_CASE_COUNT}"
        )

    def test_case_names_are_unique(self) -> None:
        names = [case["name"] for case in CASES]

        assert len(set(names)) == len(names)

    def test_every_refusal_names_its_reason(self) -> None:
        for case in CASES:
            if not case["expected"]["allowed"]:
                assert "reason" in case["expected"], case["name"]


class TestSharedCorpus:
    @pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
    def test_case_matches_the_shared_expectation(self, case: dict) -> None:
        assert _run(case) == case["expected"], (
            f"case {case['name']!r} from {FIXTURE_PATH} disagrees with the shared corpus"
        )
