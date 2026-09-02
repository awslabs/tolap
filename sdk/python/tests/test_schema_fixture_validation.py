"""Every committed policy document must validate against the published schema.

The example policies under ``schema/v1.0/examples/`` and every policy embedded
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

Two of the four schemas describe things that are not policies. ``security-context``
describes the **canonical signing projection** -- the byte string the SDKs HMAC -- so it
is validated against each signing fixture's ``canonicalPayload`` parsed back to a dict,
never against a deserialized native ``SecurityContext``: the three SDKs deliberately
keep different public context types and agree only on the projection. Its
``$defs/delegationHop`` is validated separately against every hop in
``fixtures/purpose-binding/delegation-chains.json``.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path

import pytest
from conftest import FIXTURES_DIR, SCHEMA_DIR, load_schema
from jsonschema import Draft202012Validator, FormatChecker

EXAMPLES_DIR = SCHEMA_DIR / "examples"

# API response captures, not policy documents: recorded upstream payloads used as
# enforcement input. No policy schema applies to them.
NON_POLICY_DIRS = frozenset({"api"})

# Individual fixtures that carry no policy document and no envelope either, so nothing
# in ``schema/v1.0/`` describes them. Named one file at a time rather than by directory,
# because their neighbours ARE covered: ``purpose-binding/delegation-chains.json`` is
# validated hop by hop against the security-context schema below, and excluding the
# whole directory would have taken that with it.
#
# ``judge-dispositions.json`` is a verdict-to-disposition decision table -- an SDK
# behaviour matrix rather than a document any implementation transports -- so there is
# nothing for a schema to describe. Stated here rather than left implicit, because an
# unstated gap reads as coverage.
FIXTURES_NO_SCHEMA_DESCRIBES = frozenset(
    {
        "purpose-binding/judge-dispositions.json",
        # A prompt-construction table: the inputs are a purpose profile and agent-influenced
        # strings, and the expectations are about the rendered prompt text. Nothing in
        # schema/v1.0/ describes a prompt, so there is nothing to validate it against.
        "purpose-binding/judge-prompt-fencing.json",
        # A canonical-form rules table: number rendering and offset-less timestamp handling.
        # It carries no policy and no envelope -- the "cases" are scalar inputs and their
        # expected canonical spelling -- so no schema in schema/v1.0/ describes it.
        #
        # In its own directory rather than under signing/ deliberately. Everything in
        # fixtures/signing/ is a known-answer fixture, and CI asserts that each one carries
        # secretKey/payload/canonicalPayload/expectedSignature -- a guard worth keeping intact
        # rather than special-casing for a file that is a rules table, not an answer.
        "canonical-form/number-and-timestamp-forms.json",
    }
)

SCHEMA_NAMES = (
    "policy-definition",
    "effective-policy",
    "policy-assignment",
    "security-context",
)


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
        and path.relative_to(FIXTURES_DIR).as_posix() not in FIXTURES_NO_SCHEMA_DESCRIBES
    )


EXAMPLE_PATHS = sorted(EXAMPLES_DIR.glob("*.json"))
POLICY_PATHS = sorted((FIXTURES_DIR / "policies").glob("*.json"))
ASSIGNMENT_PATHS = sorted((FIXTURES_DIR / "assignments").glob("*.json"))
MERGE_PATHS = sorted((FIXTURES_DIR / "merge-scenarios").glob("*.json"))
SIGNING_PATHS = sorted((FIXTURES_DIR / "signing").glob("*.json"))
DELEGATION_PATHS = sorted(
    (FIXTURES_DIR / "purpose-binding").glob("delegation-chains.json")
)
EMBEDDED_PATHS = sorted(
    set(_policy_fixture_paths())
    - set(POLICY_PATHS)
    - set(ASSIGNMENT_PATHS)
    - set(MERGE_PATHS)
    - set(SIGNING_PATHS)
    - set(DELEGATION_PATHS)
)

# Fixtures whose filename declares them invalid. They exist to prove the SDK
# REJECTS them, so schema-validating would invert their purpose -- but they must
# still be schema-invalid for the right reason, asserted below.
INVALID_BY_DESIGN = {
    "invalid-missing-name.json": "name",
    "invalid-bad-mask-type.json": "scramble",
}

# A validator for one delegation hop, built from the security-context schema's ``$defs``
# so the ``$ref`` inside resolves. The ``$defs`` block is carried alongside the subschema
# rather than the whole document being validated, because a hop is not a context.
_HOP_SCHEMA = {
    "$defs": load_schema("security-context")["$defs"],
    **load_schema("security-context")["$defs"]["delegationHop"],
}
HOP_VALIDATOR = Draft202012Validator(_HOP_SCHEMA, format_checker=FormatChecker())


class TestTheCorpusIsNotEmpty:
    """A discovery bug that found nothing would make every test below vacuous."""

    def test_the_examples_are_discovered(self) -> None:
        assert len(EXAMPLE_PATHS) == 6, [p.name for p in EXAMPLE_PATHS]

    def test_every_policy_fixture_directory_is_covered(self) -> None:
        assert POLICY_PATHS and ASSIGNMENT_PATHS and MERGE_PATHS and SIGNING_PATHS
        assert EMBEDDED_PATHS
        assert DELEGATION_PATHS

    def test_no_policy_bearing_fixture_is_silently_skipped(self) -> None:
        """Every non-API fixture is claimed by exactly one of the groups below."""
        claimed = set(
            POLICY_PATHS
            + ASSIGNMENT_PATHS
            + MERGE_PATHS
            + SIGNING_PATHS
            + DELEGATION_PATHS
            + EMBEDDED_PATHS
        )

        assert set(_policy_fixture_paths()) == claimed

    def test_the_only_unvalidated_fixtures_are_the_named_ones(self) -> None:
        """The exclusion list is asserted to be exactly what it claims, and to exist.

        A frozenset naming a file that has been renamed or deleted would silently stop
        excluding anything, and the day a genuinely undescribable fixture arrived nobody
        would notice it had joined the corpus instead.
        """
        excluded = {FIXTURES_DIR / name for name in FIXTURES_NO_SCHEMA_DESCRIBES}

        assert all(path.is_file() for path in excluded), FIXTURES_NO_SCHEMA_DESCRIBES
        assert excluded & set(FIXTURES_DIR.rglob("*.json")) == excluded
        assert excluded & set(_policy_fixture_paths()) == set()

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

    @pytest.mark.parametrize("path", SIGNING_PATHS, ids=lambda p: p.name)
    def test_the_canonical_payload_validates_as_a_security_context(
        self, path: Path
    ) -> None:
        """The signed envelope, checked against the schema that describes it.

        ``canonicalPayload`` is the exact byte string the three SDKs HMAC, so parsing it
        back and validating the result is the only way the envelope's shape gets checked
        rather than merely described. Document mode: an envelope is a whole document,
        and every field the schema requires is one a signable context must carry --
        which is what makes a payload missing ``expiresAt`` a failure here rather than a
        fragment nobody minds.

        This is also where the optional-means-omitted rule is enforced from the outside.
        ``jti`` carries ``minLength: 1`` and ``delegationChain`` carries ``minItems: 1``
        because an empty value normalizes to absent in the canonical form; a payload
        emitting ``"jti": ""`` or ``"delegationChain": []`` would be a projection that
        had started signing two different byte strings for the same context, and the
        schema now refuses it.
        """
        data = json.loads(path.read_text())
        payload = data.get("canonicalPayload")
        assert payload, (
            f"{_relative(path)} must carry a canonicalPayload; the signed bytes are the "
            "contract, and a fixture without them pins only a digest"
        )

        _assert_valid(
            f"{_relative(path)}#/canonicalPayload",
            json.loads(payload),
            "security-context",
            fragment=False,
        )

    @pytest.mark.parametrize("path", SIGNING_PATHS, ids=lambda p: p.name)
    def test_each_policy_in_the_canonical_payload_validates_separately(
        self, path: Path
    ) -> None:
        """``policies`` items are ``{"type": "object"}``, so the entries need their own pass.

        The context schema deliberately carries no cross-file ``$ref`` to
        ``effective-policy.schema.json``: four validators in this repository read these
        files, and one of them silently lacking a configured resolver would mean a
        schema that validates nothing. The cost of that choice is this test -- without
        it, ``policies`` would accept any object at all and the envelope check would say
        nothing about the policy inside it.

        Fragment mode, for the same reason the ``payload`` check above uses it: a signed
        policy has its integrity block stripped, since a signature cannot cover itself.
        """
        payload = json.loads(json.loads(path.read_text())["canonicalPayload"])
        policies = payload["policies"]
        assert policies, f"{_relative(path)} signs an empty policies array"

        for index, policy in enumerate(policies):
            _assert_valid(
                f"{_relative(path)}#/canonicalPayload/policies/{index}",
                policy,
                "effective-policy",
                fragment=True,
            )


class TestDelegationChainFixtures:
    """Every hop in the shared chain corpus, against ``$defs/delegationHop``.

    A delegation chain is signed hop for hop and validated hop for hop, and until the
    security-context schema existed nothing checked that the fixtures driving that
    validation were themselves well-formed. A hop with a stray field or a principal type
    no SDK accepts would have surfaced as an opaque deserialization error inside whichever
    chain test happened to load it.
    """

    CASES = json.loads(
        (FIXTURES_DIR / "purpose-binding" / "delegation-chains.json").read_text()
    )["cases"]

    # The one case whose hop is schema-invalid on purpose, keyed to the fixture's own
    # explanation of why. Read from the fixture rather than restated, so the two cannot
    # disagree about which case it is.
    INVALID_BY_DESIGN = {
        case["name"]: case["schemaInvalidByDesign"]
        for case in CASES
        if "schemaInvalidByDesign" in case
    }

    @pytest.mark.parametrize(
        "case",
        [c for c in CASES if "schemaInvalidByDesign" not in c],
        ids=lambda c: c["name"],
    )
    def test_every_hop_validates_against_the_hop_subschema(self, case: dict) -> None:
        for index, hop in enumerate(case["chain"] or []):
            errors = [
                f"{error.json_path}: {error.message}"
                for error in sorted(
                    HOP_VALIDATOR.iter_errors(hop), key=lambda e: e.json_path
                )
            ]
            assert not errors, "\n".join(
                [f"case '{case['name']}' hop {index} is not a valid delegationHop:", *errors]
            )

    def test_exactly_one_case_is_invalid_by_design(self) -> None:
        """Pinned so the exclusion above cannot quietly grow.

        A second case acquiring the marker would remove it from the sweep, which is how a
        fixture stops being checked without anything failing.
        """
        assert set(self.INVALID_BY_DESIGN) == {"case-differing-purpose-denied"}

    @pytest.mark.parametrize("name", sorted(INVALID_BY_DESIGN))
    def test_the_invalid_by_design_case_stays_schema_invalid(self, name: str) -> None:
        """Asserted positively, so a fixture that became valid is a failure.

        ``case-differing-purpose-denied`` carries ``Campaign-X`` at its second hop, which
        violates the lowercase purpose pattern. It exists to prove the validator refuses a
        mis-cased purpose even though no schema-valid context could carry one -- defence in
        depth, since the SDK deserializers do not enforce schema patterns and a chain
        assembled in code can contain it. If the fixture were silently corrected the chain
        tests would keep passing while no longer exercising a rejection at all.
        """
        case = next(c for c in self.CASES if c["name"] == name)
        errors = [
            f"{error.json_path}: {error.message}"
            for hop in case["chain"]
            for error in HOP_VALIDATOR.iter_errors(hop)
        ]

        assert errors, f"case '{name}' is marked schema-invalid but the schema accepts it"
        assert any("declaredPurpose" in error for error in errors), errors

    def test_the_validator_would_reject_an_unknown_principal_type(self) -> None:
        """The paired control: the hop validator must not accept everything.

        Without this, every assertion above would pass against a validator built from an
        empty schema -- which is exactly what a mis-keyed ``$defs`` lookup would produce.
        """
        errors = list(
            HOP_VALIDATOR.iter_errors(
                {"principalId": "agent-1", "principalType": "daemon"}
            )
        )

        assert errors and any("daemon" in error.message for error in errors), errors


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

    def test_the_purpose_profile_subschemas_are_identical(self) -> None:
        """The whole subschema, not just an enum, because all of it must survive merge.

        A purpose profile is carried from definition into effective policy by the
        merger, so anything a definition may express has to be expressible in the
        resolved document -- otherwise a policy validates, resolves, and produces an
        artifact its own schema rejects. Compared in full rather than field by field
        so that adding a property to one side and not the other fails here.
        """
        definition = load_schema("policy-definition")["properties"]["purposeProfile"]
        effective = load_schema("effective-policy")["properties"]["purposeProfile"]

        assert definition == effective

    def test_the_envelope_and_hop_purpose_patterns_differ_deliberately(self) -> None:
        """A hop may carry a glob; the envelope's declared purpose may not.

        Asserted rather than left to a reader noticing, because the looser pattern is the
        kind of thing a later edit "tidies" into agreement. The envelope's
        ``declaredPurpose`` is a concrete assertion matched against a ``purposeId``
        exactly, so admitting ``*`` there would let a caller declare a purpose that
        resolves every purpose-scoped policy. A hop's is a delegable scope, so
        ``campaign-*`` has to be expressible or a parent cannot hand down a family.
        """
        context = load_schema("security-context")
        envelope = context["properties"]["declaredPurpose"]["pattern"]
        hop = context["$defs"]["delegationHop"]["properties"]["declaredPurpose"]["pattern"]

        # Asserted by behaviour on a concrete value rather than by comparing pattern
        # text, so a rewrite that preserves the meaning still passes.
        assert re.match(envelope, "campaign-x-overlap")
        assert re.match(hop, "campaign-x-overlap")

        assert not re.match(envelope, "campaign-*"), (
            "a declared purpose admitting '*' would let a caller resolve every "
            "purpose-scoped policy at once"
        )
        assert re.match(hop, "campaign-*"), (
            "a hop must be able to express a glob scope, or a parent cannot delegate "
            "a family of purposes"
        )
