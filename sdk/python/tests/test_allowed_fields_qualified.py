"""Cross-SDK conformance for how allowedFields treats object qualifiers (issue #36).

Driven by ``fixtures/enforcement/allowed-fields-qualified.json``. The
counterparts read the same file, case for case:

- TypeScript: ``packages/core/tests/allowed-fields-qualified.test.ts``
- .NET: ``tests/Tolap.Core.Tests/AllowedFieldsQualifiedTests.cs``

allowedFields used the field-name matcher, which drops qualifiers, so an entry
``patients.name`` also allowed ``encounters.name``: the read projection kept a
column the policy never listed, and the write path accepted it. The
expectations live only in the fixture, so the three SDKs cannot drift apart.

Each case carries its own records or payload because key order is part of what
is being tested. ``json`` preserves the order the fixture writes.
"""

from __future__ import annotations

import pytest

from conftest import load_fixture
from tolap_core.enforcement import (
    apply_result_pipeline,
    project_allowed_fields,
    validate_write,
)
from tolap_core.serialization import deserialize_effective_policy

FIXTURE_PATH = "enforcement/allowed-fields-qualified.json"

#: Asserted so that a dropped case fails the suite rather than shrinking it quietly.
EXPECTED_CASE_COUNT = 53

_FIXTURE = load_fixture(FIXTURE_PATH)

CASES: list[dict] = _FIXTURE["cases"]

_ACTIONS = {"projectAllowedFields", "applyResultPipeline", "validateWrite"}


def _run(case: dict) -> object:
    policy = deserialize_effective_policy(case["policy"])
    action = case["action"]
    if action == "projectAllowedFields":
        return project_allowed_fields(case["records"], policy)
    if action == "applyResultPipeline":
        return apply_result_pipeline(case["records"], policy)
    result = validate_write(case["operation"], case["objectName"], case["payload"], policy)
    actual: dict = {"allowed": result.allowed}
    if "reason" in case["expected"]:
        actual["reason"] = result.reason
    return actual


class TestCorpusIsIntact:
    def test_the_fixture_carries_the_expected_case_count(self) -> None:
        assert len(CASES) == EXPECTED_CASE_COUNT, (
            f"{FIXTURE_PATH} carries {len(CASES)} cases, expected {EXPECTED_CASE_COUNT}"
        )

    def test_case_names_are_unique(self) -> None:
        names = [case["name"] for case in CASES]

        assert len(set(names)) == len(names)

    def test_every_case_names_a_known_action(self) -> None:
        for case in CASES:
            assert case["action"] in _ACTIONS, f"case {case['name']!r}: {case['action']!r}"

    def test_every_action_is_exercised(self) -> None:
        assert {case["action"] for case in CASES} == _ACTIONS


class TestSharedCorpus:
    @pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
    def test_case_matches_the_shared_expectation(self, case: dict) -> None:
        assert _run(case) == case["expected"], (
            f"case {case['name']!r} from {FIXTURE_PATH} disagrees with the shared corpus"
        )
