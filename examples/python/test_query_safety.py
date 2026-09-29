"""Asserts the query-safety example actually enforces, not merely that it runs.

Each assertion is an outcome -- which query was refused and with what reason, whether the source
was reached, which row and which columns survived the pipeline, how many times a field was hashed
-- so an example that printed plausible verdicts while enforcing nothing would fail here.

Run: pytest examples/python/test_query_safety.py
"""

from __future__ import annotations

from typing import Any

import pytest

#: The lines the query-safety example must print, byte for byte.
#:
#: Repeated verbatim in the TypeScript and .NET suites: a divergence between the SDKs has to
#: surface as a *different line*. The reason strings and the hashes are the SDK's own, not the
#: example's.
EXPECTED_LINES = [
    # 1. Every table a query reads is checked; a construct the check cannot resolve is refused.
    "  join an allowed table    ALLOW   the source ran",
    "  join a hidden table      DENY    object is hidden",
    "  comma join               DENY    object is hidden",
    "  derived table            DENY    object is hidden",
    "  subquery in WHERE        DENY    query uses a construct the pre-execution check cannot resolve: subquery",
    "  hidden field via alias   DENY    query references fields you do not have permission to access",
    "  other object's column    DENY    query references fields you do not have permission to access",
    "  bare column in a join    DENY    query references fields you do not have permission to access",
    # 2. The qualified filter reads patients.region only; encounters.name is projected out.
    "    patients.id=2  patients.name=Bruno Sato  patients.region=us-east  encounters.code=I10",
    "  name from patients       ALLOW",
    "  name from encounters     DENY    denied fields: name",
    "  code from encounters     ALLOW",
    # 3. Hashed once, hashed twice, and a marker honoured, ignored or taken on trust.
    "  plain rows               the wrapper enforces",
    "    id=1  name=Alice Nguyen  email=06c3aada7ffedc44  region=us-east",
    "  enforced, unmarked       hashed twice",
    "    id=1  name=Alice Nguyen  email=60d6b623948861a8  region=us-east",
    "  enforced, marked         marker honoured",
    "  marked for another user  marker ignored",
    "  marked, not enforced     a false claim",
    "    id=1  name=Alice Nguyen  email=alice@example.com  region=us-east",
]

#: What one enforcement of PATIENT_ROWS returns: Dan's eu-west row filtered, ssn hidden, email hashed.
HASHED_ONCE = [{"id": 1, "name": "Alice Nguyen", "email": "06c3aada7ffedc44", "region": "us-east"}]


class TestQuerySafetyExample:
    """The query-safety example, executed rather than trusted."""

    @pytest.mark.parametrize("index", range(1, 8))
    def test_a_refused_query_never_reaches_the_source(self, index: int) -> None:
        import query_safety_example as ex

        reason, reached = ex.run_query(ex.signed_context(), ex.QUERIES[index].sql)

        assert reason is not None
        assert reached is False

    def test_the_allowed_join_reaches_the_source(self) -> None:
        """Paired allow: the refusals above are the policy, not a check that refuses every join."""
        import query_safety_example as ex

        reason, reached = ex.run_query(ex.signed_context(), ex.QUERIES[0].sql)

        assert reason is None
        assert reached is True

    def test_a_qualified_row_filter_reads_only_its_own_object(self) -> None:
        import query_safety_example as ex

        rows = ex.wrapper().post_execute(ex.signed_context(), [dict(r) for r in ex.JOIN_ROWS])

        # Alice's encounters.region is us-east; only her patients.region may decide.
        assert rows == [
            {
                "patients.id": 2,
                "patients.name": "Bruno Sato",
                "patients.region": "us-east",
                "encounters.code": "I10",
            }
        ]

    @pytest.mark.parametrize(
        ("object_name", "field", "allowed"),
        [("patients", "name", True), ("encounters", "name", False), ("encounters", "code", True)],
    )
    def test_the_field_pre_check_reads_the_qualifier(
        self, object_name: str, field: str, allowed: bool
    ) -> None:
        import query_safety_example as ex

        decision = ex.wrapper().pre_execute(
            ex.signed_context(), "query_patients", object_name=object_name, fields=[field]
        )

        assert decision.allowed is allowed

    @pytest.mark.parametrize(
        ("label", "expected_email"),
        [
            ("plain rows", "06c3aada7ffedc44"),
            ("enforced, unmarked", "60d6b623948861a8"),
            ("enforced, marked", "06c3aada7ffedc44"),
            ("marked for another user", "06c3aada7ffedc44"),
            ("marked, not enforced", "alice@example.com"),
        ],
    )
    def test_a_marker_is_honoured_only_when_bound_to_this_context(
        self, label: str, expected_email: str
    ) -> None:
        import query_safety_example as ex

        tool = next(t for t in ex.TOOLS if t.label == label)
        rows: list[dict[str, Any]] = ex.call_tool(ex.signed_context(), tool)

        # Hidden-field removal and the row filter run whether or not the marker is honoured.
        assert rows == [{**HASHED_ONCE[0], "email": expected_email}]

    def test_the_example_script_prints_every_expected_line(self) -> None:
        """Runs the script as CI does, and checks the printed outcomes line by line.

        The script raises ``SystemExit`` if a refused query reached the source, if a column the
        policy does not allow came back, or if ssn leaked, so this covers those paths too.
        """
        import pathlib
        import subprocess
        import sys

        script = pathlib.Path(__file__).parent / "query_safety_example.py"
        result = subprocess.run(
            [sys.executable, str(script)], capture_output=True, text=True, timeout=60
        )

        assert result.returncode == 0, result.stderr
        lines = result.stdout.splitlines()
        for expected in EXPECTED_LINES:
            assert expected in lines, f"missing line: {expected!r}"
        # The honoured marker and the ignored one both match the wrapper's own enforcement.
        assert lines.count("    id=1  name=Alice Nguyen  email=06c3aada7ffedc44  region=us-east") == 3
        # The only ssn values printed are the two raw join rows shown before enforcement.
        assert sum("ssn=" in line for line in lines) == 2
        assert "444-55-6666" not in result.stdout
