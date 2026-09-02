"""Purpose and delegation chain inside the signed bytes (spec sections 2 and 15).

The point of signing them is narrow and load-bearing: a purpose-scoped policy is only worth
resolving if the purpose that selected it cannot then be swapped, and a delegation chain
that can be rewritten is decoration -- :func:`validate_delegation_chain` would be
validating the attacker's own arithmetic. So the tests below assert tamper-detection, not
merely that a signature is produced.

Every assertion here is **unconditional**. A test that skipped when the fixture lacked an
expected value is how the original cross-SDK signing divergence survived.
"""

from __future__ import annotations

import copy
from dataclasses import replace
from datetime import timedelta

import pytest
from conftest import load_fixture

from tolap_core.context import (
    _canonical_payload,
    build_security_context,
    deserialize_context,
    serialize_context,
    sign_context,
    validate_context,
)
from tolap_core.enums import PrincipalType, SigningAlgorithm
from tolap_core.models import DelegationHop, SecurityContext
from tolap_core.serialization import (
    _deser_delegation_hop,
    deserialize_effective_policy,
)


FIXTURE = "signing/hmac-sha256-purpose-bound.json"


def _fixture() -> dict:
    return load_fixture(FIXTURE)


def _context_from_fixture(data: dict) -> SecurityContext:
    """Build the context the fixture describes, through the real deserializers.

    The policy and every hop go through ``deserialize_effective_policy`` and
    ``_deser_delegation_hop`` rather than being assembled field by field, so this exercises
    the path a consumer of the signed artifact actually takes (see
    ``docs/testing-antipatterns.md`` section 5).
    """
    policy = deserialize_effective_policy(data["payload"])
    return SecurityContext(
        effective_policy=policy,
        issued_at=policy.resolved_at,
        expires_at=policy.expires_at,
        declared_purpose=data["declaredPurpose"],
        delegation_chain=[_deser_delegation_hop(hop) for hop in data["delegationChain"]],
    )


class TestTheFixtureCarriesWhatTheseTestsAssume:
    def test_the_context_is_purpose_bound_and_delegated(self) -> None:
        context = _context_from_fixture(_fixture())

        assert context.declared_purpose == "campaign-x-overlap"
        assert len(context.delegation_chain) == 3
        assert context.effective_policy.purpose_profile is not None, (
            "the fixture exists to cover a purpose-bound policy"
        )

    def test_the_fixture_carries_every_expected_value(self) -> None:
        """Asserted first and unconditionally, so nothing below can silently skip."""
        data = _fixture()

        assert data["canonicalPayload"]
        assert data["expectedSignature"]
        assert data["expectedSignatureSha512"]
        assert data["secretKey"]

    def test_the_third_hop_carries_microsecond_input(self) -> None:
        """The precondition of the truncation test: the *input* must be sub-millisecond."""
        assert _fixture()["delegationChain"][2]["delegatedAt"].endswith(".123456Z")


class TestTheCanonicalBytes:
    def test_the_canonical_payload_matches_the_fixture_bytes(self) -> None:
        # Bytes, not signatures. When two SDKs disagree, comparing signatures says only
        # "different"; comparing the canonical string says where.
        data = _fixture()

        assert _canonical_payload(_context_from_fixture(data)) == data["canonicalPayload"]

    def test_a_hop_timestamp_is_truncated_to_milliseconds(self) -> None:
        # The fixture's third hop carries microsecond input. Milliseconds are the greatest
        # precision all three runtimes represent exactly, and this is the only fixture that
        # exercises the rule for a timestamp nested inside an array of objects.
        payload = _canonical_payload(_context_from_fixture(_fixture()))

        assert "2026-09-01T10:00:00.123Z" in payload
        assert "123456" not in payload, "sub-millisecond digits are truncated, never rounded"

    def test_a_hop_timestamp_offset_is_normalized_to_z(self) -> None:
        """``+00:00`` and ``Z`` are the same instant and must sign to the same bytes."""
        data = _fixture()
        with_offset = _context_from_fixture(data)
        with_offset.delegation_chain[0] = replace(
            with_offset.delegation_chain[0], delegated_at="2026-09-01T09:58:00+00:00"
        )

        assert _canonical_payload(with_offset) == data["canonicalPayload"]

    def test_a_non_utc_hop_timestamp_is_converted_before_signing(self) -> None:
        """Two spellings of one instant must not produce two valid signatures."""
        data = _fixture()
        shifted = _context_from_fixture(data)
        shifted.delegation_chain[0] = replace(
            shifted.delegation_chain[0], delegated_at="2026-09-01T11:58:00+02:00"
        )

        assert _canonical_payload(shifted) == data["canonicalPayload"]

    def test_a_hop_with_no_timestamp_omits_the_key_entirely(self) -> None:
        """Absent must not sign as ``null``, or the key becomes mandatory in practice."""
        chain = [
            DelegationHop(principal_id="p", principal_type=PrincipalType.user),
            DelegationHop(principal_id="c", principal_type=PrincipalType.agent),
        ]
        context = _context_from_fixture(_fixture())
        context.delegation_chain = chain

        payload = _canonical_payload(context)

        assert "delegatedAt" not in payload
        assert "scopeNarrowing" not in payload
        assert '"principalType":"user"' in payload

    def test_a_hop_built_from_a_datetime_signs_like_one_built_from_a_string(self) -> None:
        """``delegated_at`` accepts either, and both must reach the same bytes.

        A ``datetime`` is the obvious thing to pass, and storing it verbatim would fail
        later inside ``json.dumps`` with a traceback naming neither the field nor the
        caller. Converting on construction also means two hops describing the same moment
        cannot sign differently depending on how each was built.
        """
        from datetime import datetime, timezone

        data = _fixture()
        from_datetime = _context_from_fixture(data)
        from_datetime.delegation_chain[0] = replace(
            from_datetime.delegation_chain[0],
            delegated_at=datetime(2026, 9, 1, 9, 58, tzinfo=timezone.utc),
        )

        assert _canonical_payload(from_datetime) == data["canonicalPayload"]

    def test_a_microsecond_datetime_is_still_truncated_to_milliseconds(self) -> None:
        """The conversion must not smuggle sub-millisecond precision past the projection."""
        from datetime import datetime, timezone

        hop = DelegationHop(
            principal_id="p",
            principal_type=PrincipalType.user,
            delegated_at=datetime(2026, 9, 1, 10, 0, 0, 123456, tzinfo=timezone.utc),
        )
        context = _context_from_fixture(_fixture())
        context.delegation_chain = [hop]

        payload = _canonical_payload(context)

        assert "2026-09-01T10:00:00.123Z" in payload
        assert "123456" not in payload

    def test_a_string_delegated_at_is_left_exactly_as_given(self) -> None:
        """The other branch of the conversion: a string is not reformatted on the model."""
        hop = DelegationHop(
            principal_id="p",
            principal_type=PrincipalType.user,
            delegated_at="2026-09-01T09:58:00Z",
        )

        assert hop.delegated_at == "2026-09-01T09:58:00Z"

    def test_an_empty_hop_scope_is_retained_rather_than_omitted(self) -> None:
        """``[]`` on a hop is a claim -- "nothing is in force here" -- not an omission.

        This is the opposite of the rule for the chain itself, where ``[]`` normalizes to
        absent, and the distinction is load-bearing: an empty parent scope DENIES every
        child scope, so signing it as absent would turn the strictest hop into the most
        permissive one.
        """
        context = _context_from_fixture(_fixture())
        context.delegation_chain = [
            DelegationHop(
                principal_id="p", principal_type=PrincipalType.user, scope_narrowing=[]
            )
        ]

        assert '"scopeNarrowing":[]' in _canonical_payload(context)


class TestTheKnownAnswers:
    def test_hmac_sha256_matches_the_shared_known_answer(self) -> None:
        data = _fixture()

        signed = sign_context(
            _context_from_fixture(data), data["secretKey"], SigningAlgorithm.hmac_sha256
        )

        assert signed.signature == data["expectedSignature"]

    def test_hmac_sha512_matches_the_shared_known_answer(self) -> None:
        data = _fixture()

        signed = sign_context(
            _context_from_fixture(data), data["secretKey"], SigningAlgorithm.hmac_sha512
        )

        assert signed.signature == data["expectedSignatureSha512"]

    def test_the_signed_fixture_context_validates(self) -> None:
        # The paired control for every tamper case below: without it, a validate that always
        # returned False would satisfy all of them.
        data = _fixture()
        signed = sign_context(_context_from_fixture(data), data["secretKey"])

        assert validate_context(signed, data["secretKey"]) is True


class TestTamperDetection:
    """Each case mutates one thing and expects the signature to stop verifying."""

    def _signed(self) -> tuple[SecurityContext, str]:
        data = _fixture()
        return sign_context(_context_from_fixture(data), data["secretKey"]), data["secretKey"]

    def test_a_stripped_declared_purpose_is_rejected(self) -> None:
        # The attack this field exists to stop: remove the purpose and a purpose-scoped
        # context becomes an unscoped one.
        signed, key = self._signed()

        signed.declared_purpose = None

        assert validate_context(signed, key) is False

    def test_a_swapped_declared_purpose_is_rejected(self) -> None:
        signed, key = self._signed()

        signed.declared_purpose = "fraud-detection"

        assert validate_context(signed, key) is False

    def test_a_stripped_delegation_chain_is_rejected(self) -> None:
        signed, key = self._signed()

        signed.delegation_chain = None

        assert validate_context(signed, key) is False

    def test_an_emptied_delegation_chain_is_rejected(self) -> None:
        """``[]`` normalizes to absent, so emptying the chain is the same attack as
        stripping it -- and must fail the same way."""
        signed, key = self._signed()

        signed.delegation_chain = []

        assert validate_context(signed, key) is False

    def test_an_appended_hop_is_rejected(self) -> None:
        # Appending is the interesting direction: it is how a sub-agent would grant itself a
        # hop claiming a wider purpose than its parent passed down.
        signed, key = self._signed()

        signed.delegation_chain = signed.delegation_chain + [
            DelegationHop(
                principal_id="agent-exfil",
                principal_type=PrincipalType.agent,
                declared_purpose="campaign-y-export",
            )
        ]

        assert validate_context(signed, key) is False

    def test_a_mutated_hop_purpose_is_rejected(self) -> None:
        signed, key = self._signed()

        signed.delegation_chain[2] = replace(
            signed.delegation_chain[2], declared_purpose="campaign-*"
        )

        assert validate_context(signed, key) is False

    def test_a_widened_hop_scope_is_rejected(self) -> None:
        signed, key = self._signed()

        signed.delegation_chain[2] = replace(
            signed.delegation_chain[2], scope_narrowing=["read", "write"]
        )

        assert validate_context(signed, key) is False

    def test_a_mutated_hop_principal_is_rejected(self) -> None:
        signed, key = self._signed()

        signed.delegation_chain[0] = replace(
            signed.delegation_chain[0], principal_type=PrincipalType.agent
        )

        assert validate_context(signed, key) is False

    def test_reordered_hops_are_rejected(self) -> None:
        # Order carries meaning: hop 0 is the delegator. Reversing the chain would make the
        # sub-agent the root and every narrowing check compare the wrong pair.
        signed, key = self._signed()

        signed.delegation_chain = list(reversed(signed.delegation_chain))

        assert validate_context(signed, key) is False

    def test_a_mutated_purpose_profile_on_the_policy_is_rejected(self) -> None:
        # purposeProfile rides inside the signed policy, so it is covered with no change to
        # the projection. Asserted rather than assumed, because "covered for free" is exactly
        # the kind of claim that silently stops being true.
        signed, key = self._signed()

        signed.effective_policy.purpose_profile = replace(
            signed.effective_policy.purpose_profile, prohibited_actions=[]
        )

        assert validate_context(signed, key) is False

    def test_a_mutated_judge_model_on_the_policy_is_rejected(self) -> None:
        """The judge block is inside the profile, so it is inside the signature too.

        Swapping the model a policy demands would otherwise let a deployment substitute its
        own judge and pass the gate's model check.
        """
        from tolap_core.models import JudgeConfig

        data = _fixture()
        context = _context_from_fixture(data)
        context.effective_policy.purpose_profile = replace(
            context.effective_policy.purpose_profile,
            judge=JudgeConfig(enabled=True, model="claude-sonnet"),
        )
        signed = sign_context(context, data["secretKey"])

        signed.effective_policy.purpose_profile = replace(
            signed.effective_policy.purpose_profile,
            judge=JudgeConfig(enabled=True, model="some-other-model"),
        )

        assert validate_context(signed, data["secretKey"]) is False


class TestBackwardCompatibility:
    def test_absent_purpose_and_chain_sign_to_the_pre_feature_bytes(self) -> None:
        # The backward-compatibility guarantee, asserted directly rather than inferred from
        # the older fixtures still passing. Two contexts identical but for fields set to
        # None must produce byte-identical payloads, or every previously-signed context
        # fails to verify after this upgrade.
        data = _fixture()

        without = _context_from_fixture(data)
        without.declared_purpose = None
        without.delegation_chain = None

        with_empties = _context_from_fixture(data)
        with_empties.declared_purpose = ""
        with_empties.delegation_chain = []

        assert _canonical_payload(with_empties) == _canonical_payload(without), (
            '"" and [] normalize to absent, so one context cannot have two valid signatures'
        )

        payload = _canonical_payload(without)
        assert "declaredPurpose" not in payload
        assert "delegationChain" not in payload

    @pytest.mark.parametrize(
        "name", ["hmac-sha256-known-answer", "hmac-sha256-subsecond"]
    )
    def test_the_older_signing_fixtures_are_unchanged_by_this_feature(self, name: str) -> None:
        # The regression that matters most: every context signed before purpose binding must
        # still verify. Pinned here as well as in test_signer.py so a change to the
        # projection fails in the file that made it.
        data = load_fixture(f"signing/{name}.json")
        policy = deserialize_effective_policy(data["payload"])
        context = SecurityContext(
            effective_policy=policy,
            issued_at=policy.resolved_at,
            expires_at=policy.expires_at,
        )

        assert _canonical_payload(context) == data["canonicalPayload"]
        assert (
            sign_context(context, data["secretKey"], SigningAlgorithm.hmac_sha256).signature
            == data["expectedSignature"]
        )

    def test_a_purpose_agnostic_policy_adds_nothing_to_the_signed_policy(self) -> None:
        """A policy with no profile must not grow a ``purposeProfile`` key."""
        data = load_fixture("signing/hmac-sha256-known-answer.json")
        policy = deserialize_effective_policy(data["payload"])

        assert policy.purpose_profile is None
        assert "purposeProfile" not in _canonical_payload(
            SecurityContext(
                effective_policy=policy,
                issued_at=policy.resolved_at,
                expires_at=policy.expires_at,
            )
        )


class TestTheBuilderAndTransportRoundTrip:
    def test_the_builder_records_both_fields(self) -> None:
        data = _fixture()
        fixture_context = _context_from_fixture(data)

        context = build_security_context(
            user_id="u",
            tenant_id="t",
            policies=[fixture_context.effective_policy],
            declared_purpose="campaign-x-overlap",
            delegation_chain=fixture_context.delegation_chain,
        )

        assert context.declared_purpose == "campaign-x-overlap"
        assert len(context.delegation_chain) == 3

    def test_the_builder_normalizes_an_empty_purpose_to_absent(self) -> None:
        # Normalized on the model as well as in the projection, so a caller inspecting the
        # context cannot see a purpose the signature does not cover.
        data = _fixture()
        context = build_security_context(
            "u", "t", [_context_from_fixture(data).effective_policy], declared_purpose=""
        )

        assert context.declared_purpose is None

    def test_the_builder_defaults_both_fields_to_absent(self) -> None:
        """An existing caller that passes neither gets exactly what it got before."""
        data = _fixture()
        context = build_security_context(
            "u", "t", [_context_from_fixture(data).effective_policy]
        )

        assert context.declared_purpose is None
        assert context.delegation_chain is None

    @pytest.mark.parametrize("argument", ["declared_purpose", "delegation_chain"])
    def test_the_new_builder_parameters_are_keyword_only(self, argument: str) -> None:
        """``ttl`` sits before them positionally, and must keep doing so."""
        data = _fixture()
        policy = _context_from_fixture(data).effective_policy

        with pytest.raises(TypeError):
            build_security_context(
                "u", "t", [policy], timedelta(hours=1), None, "campaign-x-overlap", []
            )  # type: ignore[misc]

    def test_serialize_and_deserialize_round_trips_purpose_and_chain(self) -> None:
        # Transport, as distinct from signing. A context whose chain survived signing but
        # not the base64 round-trip would verify and then arrive with no hops to validate.
        #
        # Built through build_security_context rather than from the fixture, because
        # deserialize_context checks expiry and the fixture's instants are fixed in the past
        # -- which is exactly what a known-answer fixture needs and exactly what a
        # round-trip cannot use.
        data = _fixture()
        fixture_context = _context_from_fixture(data)
        context = build_security_context(
            user_id="user-marketing-001",
            tenant_id="tenant-acme-retail",
            policies=[fixture_context.effective_policy],
            declared_purpose=fixture_context.declared_purpose,
            delegation_chain=fixture_context.delegation_chain,
        )
        signed = sign_context(context, data["secretKey"])

        restored = deserialize_context(serialize_context(signed), data["secretKey"])

        assert restored.declared_purpose == "campaign-x-overlap"
        assert len(restored.delegation_chain) == 3
        assert restored.delegation_chain[2].principal_type is PrincipalType.agent
        assert restored.delegation_chain[2].scope_narrowing == ["read"]
        assert restored.delegation_chain[2].delegated_at == "2026-09-01T10:00:00.123456Z"
        assert restored.effective_policy.purpose_profile.purpose_id == "campaign-x-overlap"

    def test_a_context_with_no_chain_round_trips_as_none_not_as_empty(self) -> None:
        """The paired direction: absent must survive transport as absent."""
        data = _fixture()
        context = build_security_context(
            "u", "t", [_context_from_fixture(data).effective_policy]
        )
        signed = sign_context(context, data["secretKey"])

        restored = deserialize_context(serialize_context(signed), data["secretKey"])

        assert restored.declared_purpose is None
        assert restored.delegation_chain is None


class TestTheDeserializerFailsClosed:
    def test_an_unknown_principal_type_is_refused(self) -> None:
        # Fail closed at the boundary, matching how an unknown mask type or filter operator
        # is treated. An unrecognized principal type must not reach chain validation as a
        # value no narrowing rule covers.
        with pytest.raises(ValueError, match="daemon"):
            _deser_delegation_hop(
                {
                    "principalId": "agent-1",
                    "principalType": "daemon",
                    "declaredPurpose": "campaign-x",
                }
            )

    def test_the_error_names_the_principal_and_the_valid_set(self) -> None:
        """An operator has to be able to act on it without reading the source."""
        with pytest.raises(ValueError) as caught:
            _deser_delegation_hop({"principalId": "agent-1", "principalType": "daemon"})

        message = str(caught.value)
        assert "agent-1" in message
        assert "user" in message and "agent" in message and "service" in message

    @pytest.mark.parametrize("principal_type", ["user", "agent", "service"])
    def test_every_known_principal_type_is_accepted(self, principal_type: str) -> None:
        """The paired control: the guard must not refuse the legitimate set."""
        hop = _deser_delegation_hop(
            {"principalId": "p-1", "principalType": principal_type}
        )

        assert hop.principal_type.value == principal_type

    def test_a_context_carrying_an_unknown_principal_type_does_not_deserialize(self) -> None:
        """Asserted through the transport entry point, not only the private helper.

        A guard the real ``deserialize_context`` path does not reach is a guard that does
        not exist for an integrator.
        """
        import base64
        import json

        data = _fixture()
        fixture_context = _context_from_fixture(data)
        context = build_security_context(
            "u",
            "t",
            [fixture_context.effective_policy],
            declared_purpose="campaign-x-overlap",
            delegation_chain=fixture_context.delegation_chain,
        )
        signed = sign_context(context, data["secretKey"])

        tampered = json.loads(base64.b64decode(serialize_context(signed)))
        tampered["delegationChain"][1]["principalType"] = "daemon"
        payload = base64.b64encode(json.dumps(tampered).encode()).decode()

        with pytest.raises(ValueError, match="daemon"):
            deserialize_context(payload, data["secretKey"])

    def test_a_purpose_profile_survives_effective_policy_deserialization(self) -> None:
        """Including the judge block, whose absence would silently disable the gate."""
        data = load_fixture("policies/purpose-judge-enabled.json")

        profile = deserialize_effective_policy(
            {"permissions": data["permissions"], "purposeProfile": data["purposeProfile"]}
        ).purpose_profile

        assert profile.purpose_id == "campaign-x-overlap"
        assert profile.judge.enabled is True
        assert profile.judge.model == "claude-sonnet"
        assert profile.judge.history_window == 5
        assert profile.judge.confidence_threshold == 0.9
        assert profile.judge.escalation_threshold == 0.7
        assert profile.judge.max_latency_ms == 1500

    def test_an_absent_judge_block_deserializes_to_none(self) -> None:
        profile = deserialize_effective_policy(
            {"permissions": {"canQuery": True}, "purposeProfile": {"purposeId": "p-x"}}
        ).purpose_profile

        assert profile.judge is None
        assert profile.allowed_actions is None
        assert profile.prohibited_actions is None

    def test_an_empty_action_list_deserializes_as_empty_not_as_absent(self) -> None:
        """Spec section 3 at the deserialization boundary, where a ``or None`` would lose it."""
        profile = deserialize_effective_policy(
            {
                "permissions": {"canQuery": True},
                "purposeProfile": {
                    "purposeId": "p-x",
                    "allowedActions": [],
                    "prohibitedActions": [],
                },
            }
        ).purpose_profile

        assert profile.allowed_actions == []
        assert profile.prohibited_actions == []

    def test_a_policy_definition_carries_its_purpose_profile_too(self) -> None:
        """Both readers are wired, not just the effective-policy one.

        Resolution filters on the *definition's* profile, so a definition reader that
        dropped it would make every purpose-scoped policy resolve unconditionally.
        """
        from tolap_core.serialization import deserialize_policy_definition

        definition = deserialize_policy_definition(
            load_fixture("policies/purpose-campaign-overlap.json")
        )

        assert definition.purpose_profile.purpose_id == "campaign-x-overlap"
        assert definition.purpose_profile.allowed_actions == [
            "aggregate_overlap",
            "count_segments",
        ]

    def test_a_purpose_agnostic_definition_deserializes_with_no_profile(self) -> None:
        from tolap_core.serialization import deserialize_policy_definition

        definition = deserialize_policy_definition(
            load_fixture("policies/purpose-agnostic-baseline.json")
        )

        assert definition.purpose_profile is None

    def test_deserializing_a_hop_does_not_mutate_the_input(self) -> None:
        """The fixtures are shared across cases, so a reader that edited them would leak."""
        raw = {"principalId": "p-1", "principalType": "agent", "scopeNarrowing": ["read"]}
        before = copy.deepcopy(raw)

        _deser_delegation_hop(raw)

        assert raw == before
