"""Cross-SDK conformance for all 16 row-filter operators, from the shared corpus.

Driven by ``fixtures/enforcement/apply-row-filters-all-operators.json``. The
counterparts read the same file, case for case:

- TypeScript: ``packages/core/tests/row-filter-operator-corpus.test.ts``
- .NET: ``tests/Tolap.Core.Tests/RowFilterOperatorCorpusTests.cs``

``test_row_filter_operators.py`` already pins each operator's semantics *in this
SDK*. That is not the same guarantee: a per-SDK unit test asserts whatever that SDK
happens to implement, so three suites can all pass while three implementations
disagree. The corpus previously covered 9 of the schema's 16 operators, and the
seven it left out -- ``between``, ``greaterThanOrEqual``, ``lessThanOrEqual``,
``isNull``, ``isNotNull``, ``like``, ``notLike`` -- are exactly the ones that
diverged: a schema-valid ``{"operator": "between"}`` policy crashed Python with a
``KeyError``, silently dropped every row in TypeScript, and enforced correctly in
.NET, while the signature verified in all three. Nothing forced agreement because
nothing compared them.

So the expectations live in the fixture and only in the fixture. Restating them here
would create a second copy free to drift the same way the first one did, which is
the whole failure mode being closed.

Each case carries a complete ``policy`` rather than a bare filter, and this test
loads it through :func:`deserialize_effective_policy` -- the same boundary a real
caller crosses. That matters for the operator strings: an operator this SDK has no
:class:`~tolap_core.enums.FilterOperator` member for is refused *here*, loudly,
rather than quietly reaching the enforcement path's fallback and dropping every row.

Two properties this file deliberately does NOT soften:

- **No skips.** A missing fixture, or a case whose policy cannot be mapped, fails.
  An operator this SDK cannot express is the divergence itself, not a reason to
  stand down.
- **One test per case.** A single loop reports the first mismatch and hides the
  rest; 21 named cases report which *operator* disagrees, which is the fact worth
  having.
"""

from __future__ import annotations

from typing import Any

import pytest

from conftest import load_fixture
from tolap_core.enforcement import apply_row_filters
from tolap_core.enums import FilterOperator
from tolap_core.serialization import deserialize_effective_policy

FIXTURE_PATH = "enforcement/apply-row-filters-all-operators.json"

#: The number of cases the corpus is expected to carry. Asserted below so a future
#: edit that silently drops a case cannot look like a shrinking-but-passing suite.
EXPECTED_CASE_COUNT = 21

_FIXTURE = load_fixture(FIXTURE_PATH)

RECORDS: list[dict] = _FIXTURE["records"]
CASES: list[dict] = _FIXTURE["cases"]


def _case_filters(case: dict) -> list[dict]:
    """The raw filter objects a case's policy carries, as written in the fixture."""
    return case["policy"]["objectRules"]["rowFilters"]


def _surviving_ids(case: dict) -> list[Any]:
    """Run the case's policy over the shared records and return the surviving ids."""
    policy = deserialize_effective_policy(case["policy"])

    return [row["id"] for row in apply_row_filters(RECORDS, policy)]


class TestCorpusIsIntact:
    """Guards on the corpus itself, before any operator is evaluated."""

    def test_the_fixture_carries_the_expected_case_count(self) -> None:
        assert len(CASES) == EXPECTED_CASE_COUNT, (
            f"{FIXTURE_PATH} carries {len(CASES)} cases, expected "
            f"{EXPECTED_CASE_COUNT}; a dropped case is coverage lost silently"
        )

    def test_the_fixture_carries_the_expected_records(self) -> None:
        assert [row["id"] for row in RECORDS] == ["low", "mid", "high", "nullish", "missing"]

    def test_case_names_are_unique(self) -> None:
        """Duplicated names would let one case mask another in the report."""
        names = [case["name"] for case in CASES]

        assert len(set(names)) == len(names)

    def test_every_case_carries_a_policy_with_row_filters(self) -> None:
        """A case that cannot be mapped is a failure, never a skip."""
        for case in CASES:
            assert _case_filters(case), f"case {case['name']!r} carries no row filters"

    def test_every_operator_in_the_corpus_has_an_enum_member(self) -> None:
        """An operator string this SDK cannot express IS the divergence.

        Asserted as its own failure so the message names the offending operator
        rather than surfacing as a deserialization error inside one case.
        """
        expressible = {op.value for op in FilterOperator}
        used = {f["operator"] for case in CASES for f in _case_filters(case)}

        assert used <= expressible, (
            f"{FIXTURE_PATH} uses operator(s) this SDK has no FilterOperator member "
            f"for: {sorted(used - expressible)}"
        )

    def test_the_corpus_exercises_every_operator_the_schema_declares(self) -> None:
        """The point of the fixture: 16 of 16, not 9 of 16."""
        used = {f["operator"] for case in CASES for f in _case_filters(case)}

        assert used == {op.value for op in FilterOperator}


class TestSharedCorpus:
    """One test per corpus case, so a failure names the operator that disagreed."""

    @pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
    def test_case_matches_the_shared_expectation(self, case: dict) -> None:
        assert _surviving_ids(case) == case["expected"], (
            f"case {case['name']!r} from {FIXTURE_PATH} disagrees with the shared "
            "corpus; this SDK and at least one other now enforce the same "
            "schema-valid policy differently"
        )
