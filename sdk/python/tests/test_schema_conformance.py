"""The native enums must match the published schema's enums, set for set.

``schema/v1.0/*.json`` is the published contract. This SDK re-declares parts of it
as Python ``Enum`` classes, and those declarations drift silently unless something
compares them -- which nothing in this suite did before this file: no Python test
read ``schema/v1.0/`` at all.

Two drifts had already happened by the time the canonical spec mandated this check
(section 14):

- The schema's row-filter operator enum grew to 16 values while Python and
  TypeScript declared 9. A schema-valid ``{"operator": "between"}`` policy raised
  an uncaught ``KeyError`` out of the Python deserializer, silently dropped every
  row in TypeScript, and enforced correctly in .NET. The signature verified in all
  three -- the canonical payload covers the policy verbatim -- so the policy passed
  every integrity check while producing three different access outcomes.
- The mask ``parameters.algorithm`` enum permits ``sha256|sha512|blake2b``; Python
  and .NET hardcoded SHA-256 and ignored the parameter, so the same policy produced
  a different pseudonym per language and every cross-service join on a hashed
  column silently failed while each side looked correct alone.

Three properties make this test able to catch the next one:

- The expected values are **read from the schema file on disk**, never restated
  here. A copy in the test is a second thing free to drift.
- Both directions are asserted. Schema-to-SDK alone misses an SDK that accepts what
  the schema forbids; SDK-to-schema alone misses the ``between`` case above.
- The assertions are unconditional. Each enum is located by keyword path and the
  helper raises when the path is absent, so a schema reorganization fails loudly
  instead of skipping -- a skip restores the blind spot rather than reporting it.

``ed25519`` is a deliberate special case. It is schema-valid and this SDK's
``SigningAlgorithm`` MUST carry it, because a policy naming it is a policy this SDK
has to *recognize in order to refuse*. Dropping the member to make a set comparison
pass would turn a loud refusal into an unrecognized-value path. So it is asserted
present in the enum and, separately, asserted to fail closed at signing time.
"""

from __future__ import annotations

import pytest
from conftest import load_schema, schema_enum_at

from tolap_core.context import build_security_context, sign_context, validate_context
from tolap_core.enforcement import apply_field_masking
from tolap_core.enums import (
    AssigneeType,
    FilterOperator,
    MaskType,
    SigningAlgorithm,
)
from tolap_core.models import (
    EffectivePolicy,
    FieldRules,
    MaskingParameters,
    MaskingRule,
    ObjectRules,
    PolicyPermissions,
)

POLICY_DEFINITION = load_schema("policy-definition")
EFFECTIVE_POLICY = load_schema("effective-policy")
POLICY_ASSIGNMENT = load_schema("policy-assignment")


# The keyword path to each enum in the published schema. Held as data so a missing
# path names the enum that moved rather than failing somewhere anonymous.
SCHEMA_OPERATOR_PATH = ("$defs", "filterRule", "properties", "operator", "enum")
SCHEMA_MASK_TYPE_PATH = ("$defs", "maskingRule", "properties", "maskType", "enum")
SCHEMA_MASK_ALGORITHM_PATH = (
    "$defs",
    "maskingRule",
    "properties",
    "parameters",
    "properties",
    "algorithm",
    "enum",
)
SCHEMA_ASSIGNEE_TYPE_PATH = (
    "properties",
    "assignee",
    "properties",
    "type",
    "enum",
)
SCHEMA_SIGNING_ALGORITHM_PATH = (
    "properties",
    "integrity",
    "properties",
    "algorithm",
    "enum",
)

# The effective-policy schema restates the operator and mask enums inline rather
# than through $defs, so its paths differ from the definition schema's.
EFFECTIVE_OPERATOR_PATH = (
    "properties",
    "objectRules",
    "properties",
    "rowFilters",
    "items",
    "properties",
    "operator",
    "enum",
)
EFFECTIVE_MASK_TYPE_PATH = (
    "properties",
    "objectRules",
    "properties",
    "fieldRules",
    "properties",
    "maskedFields",
    "items",
    "properties",
    "maskType",
    "enum",
)
EFFECTIVE_MASK_ALGORITHM_PATH = (
    "properties",
    "objectRules",
    "properties",
    "fieldRules",
    "properties",
    "maskedFields",
    "items",
    "properties",
    "parameters",
    "properties",
    "algorithm",
    "enum",
)


def _wire_values(enum_class: type) -> set[str]:
    """The JSON spellings this SDK accepts for an enum, not the member names.

    ``FilterOperator.not_equals`` is spelled ``notEquals`` on the wire; the member
    name is a Python convenience and is not part of the contract.
    """
    return {member.value for member in enum_class}


class TestSchemaLocatorFailsLoudly:
    """The locator must fail rather than skip, or the whole file proves nothing."""

    def test_a_missing_path_raises_instead_of_returning_a_default(self) -> None:
        with pytest.raises(AssertionError, match="is missing at segment"):
            schema_enum_at(POLICY_DEFINITION, "$defs", "notARule", "enum")

    def test_a_path_that_is_not_an_enum_list_raises(self) -> None:
        with pytest.raises(AssertionError, match="not a non-empty enum list"):
            schema_enum_at(POLICY_DEFINITION, "$defs", "filterRule")

    def test_a_missing_schema_file_raises_instead_of_skipping(self) -> None:
        with pytest.raises(AssertionError, match="MUST NOT be skipped"):
            load_schema("no-such-schema")


class TestFilterOperator:
    """16 operators. The 9-vs-16 drift is the reason this file exists."""

    def test_matches_the_schema_exactly_in_both_directions(self) -> None:
        schema_values = set(schema_enum_at(POLICY_DEFINITION, *SCHEMA_OPERATOR_PATH))
        sdk_values = _wire_values(FilterOperator)

        assert schema_values - sdk_values == set(), (
            "the schema permits operators this SDK cannot express; a schema-valid "
            "policy using one passes signature verification and then behaves "
            "differently here than in the other SDKs"
        )
        assert sdk_values - schema_values == set(), (
            "this SDK accepts operators the schema forbids; a policy written "
            "against it would be rejected by a schema-validating peer"
        )

    def test_the_two_schemas_declare_the_same_operator_enum(self) -> None:
        """An effective policy is the merged product of definitions.

        The operator enum is duplicated in ``policy-definition.schema.json`` and
        ``effective-policy.schema.json``. Any operator a definition can express has
        to survive resolution, so the two lists must be equal rather than merely
        overlapping -- an operator present only in the definition schema would be
        expressible in a policy and then unrepresentable in the resolved output.
        """
        definition = schema_enum_at(POLICY_DEFINITION, *SCHEMA_OPERATOR_PATH)
        effective = schema_enum_at(EFFECTIVE_POLICY, *EFFECTIVE_OPERATOR_PATH)

        assert set(definition) == set(effective)
        # Order is asserted too: the lists are maintained as copies of each other,
        # and a reordering is the cheapest signal that one was edited alone.
        assert definition == effective


class TestMaskType:
    def test_matches_the_schema_exactly_in_both_directions(self) -> None:
        schema_values = set(schema_enum_at(POLICY_DEFINITION, *SCHEMA_MASK_TYPE_PATH))
        sdk_values = _wire_values(MaskType)

        assert schema_values - sdk_values == set(), (
            "the schema permits mask types this SDK cannot express; the "
            "deserializer rejects them, so a schema-valid policy fails to load"
        )
        assert sdk_values - schema_values == set(), (
            "this SDK accepts mask types the schema forbids"
        )

    def test_the_two_schemas_declare_the_same_mask_type_enum(self) -> None:
        definition = schema_enum_at(POLICY_DEFINITION, *SCHEMA_MASK_TYPE_PATH)
        effective = schema_enum_at(EFFECTIVE_POLICY, *EFFECTIVE_MASK_TYPE_PATH)

        assert set(definition) == set(effective)

    def test_every_schema_value_ranks_below_the_unknown_rank(self) -> None:
        """A schema-valid mask type must never be treated as unrecognized.

        Unknown types rank most-restrictive so a typo cannot be downgraded into a
        weaker known type during a merge (spec section 6). That safety net becomes a
        bug if it catches a *legitimate* value: the mask would win every merge it
        should have lost.
        """
        from tolap_core.enums import _UNKNOWN_MASK_RESTRICTIVENESS, mask_restrictiveness

        for value in schema_enum_at(POLICY_DEFINITION, *SCHEMA_MASK_TYPE_PATH):
            assert mask_restrictiveness(MaskType(value)) < _UNKNOWN_MASK_RESTRICTIVENESS


class TestMaskParameterAlgorithm:
    """``parameters.algorithm`` is not a native enum, so it needs its own check.

    The hash mask exists to be a cross-service join key, which only holds if every
    SDK computes the same digest for the same policy. Python and .NET previously
    hardcoded SHA-256 and ignored this parameter while TypeScript honoured it, so a
    policy asking for ``sha512`` produced two different pseudonyms for one value.
    The schema's enum -- read from disk -- is the authority for what must work.
    """

    @staticmethod
    def _hashed(algorithm: str | None) -> object:
        parameters = (
            MaskingParameters(algorithm=algorithm) if algorithm is not None else None
        )
        policy = EffectivePolicy(
            version="1.0",
            source_profiles=["schema-conformance"],
            permissions=PolicyPermissions(can_query=True),
            object_rules=ObjectRules(
                field_rules=FieldRules(
                    masked_fields=[
                        MaskingRule(
                            field="email",
                            mask_type=MaskType.hash,
                            parameters=parameters,
                        )
                    ]
                )
            ),
        )
        return apply_field_masking({"email": "john.smith@example.com"}, policy)["email"]

    def test_every_schema_permitted_algorithm_actually_hashes(self) -> None:
        """Schema-to-SDK: no permitted algorithm may fail closed as ``redact``.

        Redacting is the correct response to an algorithm the runtime cannot
        provide, but applying it to a value the schema permits silently destroys
        data the policy author asked to have pseudonymized.
        """
        for algorithm in schema_enum_at(POLICY_DEFINITION, *SCHEMA_MASK_ALGORITHM_PATH):
            result = self._hashed(algorithm)

            assert result != "[REDACTED]", (
                f"algorithm {algorithm!r} is schema-valid but this SDK cannot "
                "compute it, so the field is redacted instead of pseudonymized"
            )
            assert isinstance(result, str)
            # Lower-case hex truncated to 16 characters (spec section 6): the
            # rendering is part of the join-key contract, not an implementation
            # detail, so a differently-rendered digest is still a divergence.
            assert len(result) == 16
            assert result == result.lower()
            int(result, 16)

    def test_the_schema_permitted_algorithms_produce_distinct_digests(self) -> None:
        """A substituted algorithm is worse than a refusal.

        If two schema values produced the same digest, one of them would be
        silently computing the other -- the field would look like a valid
        pseudonym while failing to join against a service that honoured the
        parameter as written.
        """
        algorithms = schema_enum_at(POLICY_DEFINITION, *SCHEMA_MASK_ALGORITHM_PATH)
        digests = {algorithm: self._hashed(algorithm) for algorithm in algorithms}

        assert len(set(digests.values())) == len(algorithms), digests

    def test_an_algorithm_outside_the_schema_enum_fails_closed(self) -> None:
        """SDK-to-schema: nothing beyond the schema's three may be honoured.

        Resolving the parameter through a general lookup would accept anything the
        runtime offers -- ``md5`` included -- plus spellings the other two SDKs
        reject, which is the original divergence in a new form.
        """
        permitted = set(schema_enum_at(POLICY_DEFINITION, *SCHEMA_MASK_ALGORITHM_PATH))

        for algorithm in ("md5", "sha1", "sha3_256", "sha384", "blake2s", "SHA256"):
            assert algorithm not in permitted, "test case is no longer out-of-schema"
            assert self._hashed(algorithm) == "[REDACTED]", (
                f"{algorithm!r} is outside the schema's enum and must fail closed "
                "rather than be honoured"
            )

    def test_the_default_when_absent_is_sha256(self) -> None:
        """Spec section 6 fixes the default, so all three SDKs agree when omitted."""
        assert self._hashed(None) == self._hashed("sha256")

    def test_an_empty_algorithm_string_fails_closed_rather_than_defaulting(self) -> None:
        """A regression guard over a cross-SDK divergence this test found.

        ``""`` is not in the schema's enum, so per the direction asserted above it
        must fail closed. This SDK used to honour it as ``sha256``: the guard read
        ``if rule.parameters and rule.parameters.algorithm``, and an empty string is
        falsy in Python, so ``""`` was indistinguishable from absent. TypeScript and
        .NET both use nullish-coalescing, which treats ``""`` as
        present-and-unrecognized and redacts.

        The consequence was the exact shape of the original defect: the same
        schema-invalid policy yielded ``8e621e3d0368631d`` here and ``[REDACTED]`` in
        the other two SDKs. Absent and ``None`` agree at ``sha256`` everywhere; only
        the empty string diverged, which is why an ``is not None`` check rather than
        a truthiness check is the load-bearing detail this pins.
        """
        permitted = set(schema_enum_at(POLICY_DEFINITION, *SCHEMA_MASK_ALGORITHM_PATH))
        assert "" not in permitted

        assert self._hashed("") == "[REDACTED]"

    def test_the_two_schemas_declare_the_same_algorithm_enum(self) -> None:
        definition = schema_enum_at(POLICY_DEFINITION, *SCHEMA_MASK_ALGORITHM_PATH)
        effective = schema_enum_at(EFFECTIVE_POLICY, *EFFECTIVE_MASK_ALGORITHM_PATH)

        assert set(definition) == set(effective)


class TestAssigneeType:
    def test_matches_the_schema_exactly_in_both_directions(self) -> None:
        schema_values = set(
            schema_enum_at(POLICY_ASSIGNMENT, *SCHEMA_ASSIGNEE_TYPE_PATH)
        )
        sdk_values = _wire_values(AssigneeType)

        assert schema_values - sdk_values == set(), (
            "the schema permits assignee types this SDK cannot express; an "
            "administrator's grant would silently resolve to nothing"
        )
        assert sdk_values - schema_values == set(), (
            "this SDK accepts assignee types the schema forbids"
        )


class TestSigningAlgorithm:
    def test_matches_the_schema_exactly_in_both_directions(self) -> None:
        """Including ``ed25519``, which this SDK carries in order to refuse it."""
        schema_values = set(
            schema_enum_at(EFFECTIVE_POLICY, *SCHEMA_SIGNING_ALGORITHM_PATH)
        )
        sdk_values = _wire_values(SigningAlgorithm)

        assert schema_values - sdk_values == set(), (
            "the schema permits signing algorithms this SDK cannot name; an "
            "unnameable algorithm cannot be refused by name either"
        )
        assert sdk_values - schema_values == set(), (
            "this SDK accepts signing algorithms the schema forbids"
        )

    def test_ed25519_is_present_in_the_enum_rather_than_omitted(self) -> None:
        """Asserted explicitly, not just as a by-product of the set comparison.

        ``ed25519`` is schema-valid and unimplemented here. Removing the member
        would make the set comparison above pass by narrowing the enum instead of
        by fixing anything, and would replace an explicit refusal with an
        unrecognized-value path.
        """
        assert SigningAlgorithm.ed25519.value == "ed25519"
        assert "ed25519" in schema_enum_at(
            EFFECTIVE_POLICY, *SCHEMA_SIGNING_ALGORITHM_PATH
        )

    def test_ed25519_fails_closed_at_signing_time(self) -> None:
        """Present in the enum, refused at use. The two halves are separate claims.

        Being nameable is what lets the refusal say which algorithm it refused;
        the refusal itself is what stops an unsigned context being treated as
        signed.
        """
        policy = EffectivePolicy(
            version="1.0",
            source_profiles=["schema-conformance"],
            permissions=PolicyPermissions(can_query=True),
        )
        context = build_security_context("user-001", "tenant-001", [policy])

        with pytest.raises(NotImplementedError, match="Ed25519"):
            sign_context(context, "key", algorithm=SigningAlgorithm.ed25519)

    def test_ed25519_on_validation_denies_rather_than_raising(self) -> None:
        """The other half of the fail-closed contract, and the reason the member stays.

        ``ed25519`` is schema-valid, so a signed context naming it is reachable
        through ordinary deserialization -- no malformed input required. Signing
        refuses loudly (above), but *verification* must DENY: spec section 5 requires
        an unenforceable input to be refused rather than to abort the pass. Raising
        here would turn a deny into a crash, and a caller wrapping validation in a
        bare ``except`` would turn it into an allow.

        Asserted in all three SDKs, because this is precisely where they diverged:
        .NET let its ``NotSupportedException`` escape ``Validate`` while TypeScript
        caught and denied, so one schema-valid context was a 500 in one SDK and a
        refusal in another.
        """
        policy = EffectivePolicy(
            version="1.0",
            source_profiles=["schema-conformance"],
            permissions=PolicyPermissions(can_query=True),
        )
        signed = sign_context(
            build_security_context("user-001", "tenant-001", [policy]), "key"
        )
        signed.algorithm = SigningAlgorithm.ed25519

        assert validate_context(signed, "key") is False

    def test_the_hmac_algorithms_are_the_ones_that_do_work(self) -> None:
        """The complement: the refusal above must not be the behaviour for all three."""
        policy = EffectivePolicy(
            version="1.0",
            source_profiles=["schema-conformance"],
            permissions=PolicyPermissions(can_query=True),
        )

        for algorithm in (SigningAlgorithm.hmac_sha256, SigningAlgorithm.hmac_sha512):
            context = build_security_context("user-001", "tenant-001", [policy])
            signed = sign_context(context, "key", algorithm=algorithm)

            assert signed.signature
            assert signed.algorithm == algorithm
