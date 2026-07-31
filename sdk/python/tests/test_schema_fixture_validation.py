"""Every committed policy document must validate against the published schema.

The five example policies under ``schema/v1.0/examples/`` and every policy embedded
in ``fixtures/`` are what the three SDKs are tested against. Nothing in any suite
validated them, so a fixture using an unsupported operator -- or a schema field no
SDK reads -- was invisible; the SDK tests would pass because each SDK's own
deserializer accepted whatever the fixture happened to contain. Canonical spec
section 14 makes this check mandatory.

``jsonschema`` is a **test-only** dependency. ``tolap-core`` keeps zero runtime
dependencies, so it is imported here and appears in no package's ``dependencies``.
This module is the single validating runner for the repository: the .NET and
TypeScript suites assert the enum conformance natively (that part must run inside
each SDK, since the whole question is what each SDK's own types accept) but defer
JSON Schema *document* validation to this file rather than each pulling in a
validator of its own. Three validators would mean three interpretations of
draft 2020-12 and a fourth thing to keep in step.

Two validation modes, because the fixtures are not all whole documents:

- **Document** mode validates a complete file against its schema, ``required``
  included: the examples, ``fixtures/policies/``, ``fixtures/assignments/``, and
  each entry in a merge scenario's ``inputs``.
- **Fragment** mode drops the top-level ``required`` list and keeps everything
  else -- types, enums, bounds, ``additionalProperties: false``. Test fixtures
  legitimately carry partial policies: an enforcement fixture states the rules
  under test and omits ``userId``/``resolvedAt``/``integrity`` because the
  behaviour being pinned does not involve them. Dropping only ``required`` keeps
  the part that catches drift -- a bad operator, an out-of-range limit, a stray
  field -- without demanding envelope fields the fixture has no reason to carry.

Nested ``required`` lists are NOT relaxed: a masking rule still needs its ``field``
and ``maskType``, a row filter its ``field`` and ``operator``. Only the document
envelope is optional in fragment mode.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from conftest import FIXTURES_DIR, SCHEMA_DIR, load_schema
from jsonschema import Draft202012Validator, FormatChecker

EXAMPLES_DIR = SCHEMA_DIR / "examples"

# API response captures, not policy documents: recorded upstream payloads used as
# enforcement input. No policy schema applies to them.
NON_POLICY_DIRS = frozenset({"api"})

SCHEMA_NAMES = ("policy-definition", "effective-policy", "policy-assignment")


def _document_validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(load_schema(name), format_checker=FormatChecker())


def _fragment_validator(name: str) -> Draft202012Validator:
    """A validator with the top-level ``required`` dropped and nothing else changed."""
    schema = copy.deepcopy(load_schema(name))
    schema.pop("required", None)
    return Draft202012Validator(schema, format_checker=FormatChecker())


DOCUMENT_VALIDATORS = {name: _document_validator(name) for name in SCHEMA_NAMES}
FRAGMENT_VALIDATORS = {name: _fragment_validator(name) for name in SCHEMA_NAMES}


def _errors(data: object, schema_name: str, *, fragment: bool) -> list[str]:
    """Every validation error, rendered as ``json_path: message``.

    All errors are reported rather than the first, so a fixture with three problems
    takes one fix rather than three runs.
    """
    validator = (FRAGMENT_VALIDATORS if fragment else DOCUMENT_VALIDATORS)[schema_name]
    return [
        f"{error.json_path}: {error.message}"
        for error in sorted(validator.iter_errors(data), key=lambda e: e.json_path)
    ]


def _assert_valid(label: str, data: object, schema_name: str, *, fragment: bool) -> None:
    errors = _errors(data, schema_name, fragment=fragment)
    assert not errors, "\n".join(
        [f"{label} does not validate against {schema_name}.schema.json:", *errors]
    )


# -- Discovery -------------------------------------------------------------


def _embedded_policies(node: object, path: str = "") -> list[tuple[str, dict]]:
    """Find every policy embedded in a fixture, wherever it sits in the tree.

    Fixtures nest policies at varying depths -- ``policy``, ``basePolicy``,
    ``policyOverride``, inside ``scenarios[]`` and ``cases[]`` -- so they are
    discovered by walking rather than by enumerating known shapes. Enumerating
    would mean a fixture added under a new key silently stops being validated,
    which is the same blind spot in a different place.
    """
    found: list[tuple[str, dict]] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("policy", "basePolicy", "policyOverride") and isinstance(
                value, dict
            ):
                found.append((f"{path}.{key}", value))
            found.extend(_embedded_policies(value, f"{path}.{key}"))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            found.extend(_embedded_policies(value, f"{path}[{index}]"))
    return found


def _relative(path: Path) -> str:
    return str(path.relative_to(FIXTURES_DIR.parent))


def _policy_fixture_paths() -> list[Path]:
    return sorted(
        path
        for path in FIXTURES_DIR.rglob("*.json")
        if not NON_POLICY_DIRS & set(path.relative_to(FIXTURES_DIR).parts)
    )


EXAMPLE_PATHS = sorted(EXAMPLES_DIR.glob("*.json"))
POLICY_PATHS = sorted((FIXTURES_DIR / "policies").glob("*.json"))
ASSIGNMENT_PATHS = sorted((FIXTURES_DIR / "assignments").glob("*.json"))
MERGE_PATHS = sorted((FIXTURES_DIR / "merge-scenarios").glob("*.json"))
SIGNING_PATHS = sorted((FIXTURES_DIR / "signing").glob("*.json"))
EMBEDDED_PATHS = sorted(
    set(_policy_fixture_paths())
    - set(POLICY_PATHS)
    - set(ASSIGNMENT_PATHS)
    - set(MERGE_PATHS)
    - set(SIGNING_PATHS)
)

# Fixtures whose filename declares them invalid. They exist to prove the SDK
# REJECTS them, so schema-validating would invert their purpose -- but they must
# still be schema-invalid for the right reason, asserted below.
INVALID_BY_DESIGN = {
    "invalid-missing-name.json": "name",
    "invalid-bad-mask-type.json": "scramble",
}


class TestTheCorpusIsNotEmpty:
    """A discovery bug that found nothing would make every test below vacuous."""

    def test_the_examples_are_discovered(self) -> None:
        assert len(EXAMPLE_PATHS) == 5, [p.name for p in EXAMPLE_PATHS]

    def test_every_policy_fixture_directory_is_covered(self) -> None:
        assert POLICY_PATHS and ASSIGNMENT_PATHS and MERGE_PATHS and SIGNING_PATHS
        assert EMBEDDED_PATHS

    def test_no_policy_bearing_fixture_is_silently_skipped(self) -> None:
        """Every non-API fixture is claimed by exactly one of the groups below."""
        claimed = set(
            POLICY_PATHS + ASSIGNMENT_PATHS + MERGE_PATHS + SIGNING_PATHS + EMBEDDED_PATHS
        )

        assert set(_policy_fixture_paths()) == claimed

    def test_the_embedded_walk_finds_policies_in_every_such_fixture(self) -> None:
        """Except the one README, which carries prose rather than policies."""
        empty = [
            _relative(path)
            for path in EMBEDDED_PATHS
            if not _embedded_policies(json.loads(path.read_text()))
        ]

        assert empty == [], f"fixtures with no policy found by the walk: {empty}"


class TestExamplePolicies:
    """The published examples are the schema's own documentation of itself."""

    @pytest.mark.parametrize("path", EXAMPLE_PATHS, ids=lambda p: p.name)
    def test_validates_as_a_complete_policy_definition(self, path: Path) -> None:
        _assert_valid(
            _relative(path),
            json.loads(path.read_text()),
            "policy-definition",
            fragment=False,
        )


class TestPolicyFixtures:
    @pytest.mark.parametrize(
        "path",
        [p for p in POLICY_PATHS if p.name not in INVALID_BY_DESIGN],
        ids=lambda p: p.name,
    )
    def test_validates_as_a_complete_policy_definition(self, path: Path) -> None:
        _assert_valid(
            _relative(path),
            json.loads(path.read_text()),
            "policy-definition",
            fragment=False,
        )

    @pytest.mark.parametrize(
        ("name", "expected_in_message"), sorted(INVALID_BY_DESIGN.items())
    )
    def test_the_invalid_fixtures_are_invalid_for_the_stated_reason(
        self, name: str, expected_in_message: str
    ) -> None:
        """Asserted positively, so a fixture that became valid is a failure.

        These two exist to prove the deserializer refuses them. If one were
        silently corrected the SDK tests would keep passing while no longer
        exercising a rejection at all.
        """
        errors = _errors(
            json.loads((FIXTURES_DIR / "policies" / name).read_text()),
            "policy-definition",
            fragment=False,
        )

        assert errors, f"{name} is named invalid but the schema accepts it"
        assert any(expected_in_message in error for error in errors), errors


class TestAssignmentFixtures:
    @pytest.mark.parametrize("path", ASSIGNMENT_PATHS, ids=lambda p: p.name)
    def test_validates_as_a_complete_policy_assignment(self, path: Path) -> None:
        _assert_valid(
            _relative(path),
            json.loads(path.read_text()),
            "policy-assignment",
            fragment=False,
        )


class TestMergeScenarioFixtures:
    """``inputs`` are whole definitions; ``expected`` is a merge result fragment."""

    @pytest.mark.parametrize("path", MERGE_PATHS, ids=lambda p: p.name)
    def test_every_input_validates_as_a_complete_policy_definition(
        self, path: Path
    ) -> None:
        data = json.loads(path.read_text())

        for index, policy in enumerate(data.get("inputs", [])):
            _assert_valid(
                f"{_relative(path)}#/inputs/{index}",
                policy,
                "policy-definition",
                fragment=False,
            )

    @pytest.mark.parametrize("path", MERGE_PATHS, ids=lambda p: p.name)
    def test_the_expected_result_validates_as_an_effective_policy_fragment(
        self, path: Path
    ) -> None:
        """The merger's output shape, minus the envelope the merger does not set.

        ``merge`` produces rules and permissions; the identity and integrity fields
        are attached later by resolution and signing. Fragment mode is what makes
        this assertion about the rules rather than about who filled in ``userId``.

        This assertion found a schema/implementation conflict that has since been
        resolved in the schema. ``empty-produces-deny-all.json`` pins the deny-all a
        zero-policy merge produces, and that value carries ``sourceProfiles: []``
        while ``effective-policy.schema.json`` declared ``minItems: 1`` -- so the
        fail-closed sentinel every SDK emits could not be serialized against its own
        schema. The empty array is deliberate and load-bearing (spec section 3 makes
        ``[]`` mean "deny everything", distinct from absent), so the constraint was
        the wrong half; it has been dropped, with the reasoning recorded in the
        schema's own description.
        """
        data = json.loads(path.read_text())
        if "expected" not in data:
            return

        _assert_valid(
            f"{_relative(path)}#/expected",
            data["expected"],
            "effective-policy",
            fragment=True,
        )


class TestSigningFixtures:
    @pytest.mark.parametrize("path", SIGNING_PATHS, ids=lambda p: p.name)
    def test_the_signed_payload_validates_as_an_effective_policy_fragment(
        self, path: Path
    ) -> None:
        """Fragment mode: the payload is signed BEFORE its integrity block exists.

        A signature cannot cover itself, so the known-answer payload necessarily
        omits ``integrity`` -- the one field document mode would demand. Everything
        else about it is checked, which is the part that would catch a payload
        drifting into a shape the schema forbids.
        """
        _assert_valid(
            f"{_relative(path)}#/payload",
            json.loads(path.read_text())["payload"],
            "effective-policy",
            fragment=True,
        )


class TestEmbeddedPolicies:
    """Enforcement and integration fixtures state policies inline, partially."""

    @pytest.mark.parametrize("path", EMBEDDED_PATHS, ids=lambda p: p.name)
    def test_every_embedded_policy_validates_as_an_effective_policy_fragment(
        self, path: Path
    ) -> None:
        """This assertion found a fixture/schema conflict, since resolved.

        ``openfda-edge-cases.json`` scenario 6 is
        ``max-results-zero-empties-the-collection``: it pins that ``maxResults: 0``
        truncates a collection to length 0 rather than passing the full set through,
        which is precisely the fail-closed behaviour worth a test. But
        ``limits.maxResults`` declared ``minimum: 1`` in both schemas, so the fixture
        exercised a value no schema-valid policy could contain -- meaning either the
        limit was inexpressible or the scenario was testing an unreachable input. The
        bound is now ``minimum: 0``, making "return nothing" a limit a policy author
        can actually write. Exactly the class of defect section 14 says fixture
        validation exists to surface.
        """
        data = json.loads(path.read_text())

        for pointer, policy in _embedded_policies(data):
            _assert_valid(
                f"{_relative(path)}#{pointer}",
                policy,
                "effective-policy",
                fragment=True,
            )


class TestOperatorEnumsAgreeAcrossTheTwoSchemas:
    """Duplicated in both schemas, so a reviewer noticing is the only current guard.

    An effective policy is the merged product of definitions: every operator a
    definition can express has to survive resolution. If the definition schema
    gained an operator the effective schema lacked, a policy could be written and
    validated and then produce a resolved document its own schema rejects.
    """

    def test_the_row_filter_operator_enums_are_equal(self) -> None:
        definition = load_schema("policy-definition")["$defs"]["filterRule"][
            "properties"
        ]["operator"]["enum"]
        effective = load_schema("effective-policy")["properties"]["objectRules"][
            "properties"
        ]["rowFilters"]["items"]["properties"]["operator"]["enum"]

        assert definition == effective

    def test_the_allowed_method_enums_are_equal(self) -> None:
        """Same duplication, same reasoning, for the HTTP method allowlist."""
        definition = load_schema("policy-definition")["properties"]["objectRules"][
            "properties"
        ]["endpointRules"]["properties"]["allowedMethods"]["items"]["enum"]
        effective = load_schema("effective-policy")["properties"]["objectRules"][
            "properties"
        ]["endpointRules"]["properties"]["allowedMethods"]["items"]["enum"]

        assert definition == effective
