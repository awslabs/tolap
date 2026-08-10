"""Salted `hash` masking (spec section 6).

The `hash` mask was an unsalted, truncated digest. That is fine as a pseudonymous
join key and *not* fine as confidentiality: the input spaces that matter here are
small enough to enumerate. There are ~10^9 SSNs and ~4x10^4 plausible dates of
birth, so a masked column of either is recoverable with a rainbow table in
seconds, while the output still looks like an opaque token.

An optional secret salt turns the digest into a keyed HMAC. The join-key property
survives -- the same salt over the same value yields the same pseudonym everywhere
-- but recovery now needs the salt, which is a deployment secret rather than
something derivable from the masked output.

The recovery test below is the point of this file: it demonstrates the actual
attack against the unsalted form and then shows the salt defeating it. Asserting
only "salted output differs from unsalted" would pass against a broken
implementation that merely appended the salt to the output.
"""

from __future__ import annotations

import hashlib

import pytest

from tolap_core.enforcement import apply_field_masking, apply_masking
from tolap_core.enums import MaskType
from tolap_core.models import (
    EffectivePolicy,
    FieldRules,
    MaskingParameters,
    MaskingRule,
    ObjectRules,
    PolicyPermissions,
)

SALT = "deployment-secret-salt-from-kms"


def _policy(algorithm: str | None = None) -> EffectivePolicy:
    return EffectivePolicy(
        version="1.0",
        permissions=PolicyPermissions(can_query=True, read_only=True),
        object_rules=ObjectRules(
            field_rules=FieldRules(
                masked_fields=[
                    MaskingRule(
                        field="ssn",
                        mask_type=MaskType.hash,
                        parameters=(
                            MaskingParameters(algorithm=algorithm)
                            if algorithm
                            else None
                        ),
                    )
                ]
            )
        ),
    )


class TestSaltDefeatsBruteForce:
    def test_unsalted_hash_is_recoverable_by_rainbow_table(self) -> None:
        """The vulnerability, demonstrated rather than asserted abstractly."""
        record = {"ssn": "123-45-6789"}

        masked = apply_field_masking(record, _policy())["ssn"]

        # An attacker who knows the format enumerates candidates and matches the
        # digest. Only the last four digits are unknown here, which is a 10^4
        # search -- the full 10^9 SSN space is minutes of CPU.
        recovered = None
        for candidate in range(6780, 6800):
            guess = f"123-45-{candidate}"
            if hashlib.sha256(guess.encode()).hexdigest()[:16] == masked:
                recovered = guess
                break

        assert recovered == "123-45-6789", "unsalted digest is trivially reversible"

    def test_salted_hash_resists_the_same_attack(self) -> None:
        """The fix: the same enumeration finds nothing without the salt."""
        record = {"ssn": "123-45-6789"}

        masked = apply_field_masking(record, _policy(), hash_salt=SALT)["ssn"]

        for candidate in range(6780, 6800):
            guess = f"123-45-{candidate}"
            assert hashlib.sha256(guess.encode()).hexdigest()[:16] != masked

        assert masked != "123-45-6789"

    def test_salted_value_is_not_the_plaintext_or_the_plain_digest(self) -> None:
        record = {"ssn": "123-45-6789"}

        masked = apply_field_masking(record, _policy(), hash_salt=SALT)["ssn"]
        unsalted = apply_field_masking(record, _policy())["ssn"]

        assert masked != "123-45-6789"
        assert masked != unsalted
        # Not merely the digest with the salt glued on, which would leak the digest.
        assert unsalted not in masked


class TestSaltPreservesTheJoinKeyProperty:
    def test_same_value_and_salt_yield_the_same_pseudonym(self) -> None:
        """Deterministic, so a cross-service join still works."""
        first = apply_field_masking({"ssn": "123-45-6789"}, _policy(), hash_salt=SALT)
        second = apply_field_masking({"ssn": "123-45-6789"}, _policy(), hash_salt=SALT)

        assert first["ssn"] == second["ssn"]

    def test_different_values_yield_different_pseudonyms(self) -> None:
        first = apply_field_masking({"ssn": "123-45-6789"}, _policy(), hash_salt=SALT)
        second = apply_field_masking({"ssn": "987-65-4321"}, _policy(), hash_salt=SALT)

        assert first["ssn"] != second["ssn"]

    def test_different_salts_yield_different_pseudonyms(self) -> None:
        """Why the salt must match everywhere the pseudonym is joined."""
        first = apply_field_masking({"ssn": "123-45-6789"}, _policy(), hash_salt="salt-a")
        second = apply_field_masking({"ssn": "123-45-6789"}, _policy(), hash_salt="salt-b")

        assert first["ssn"] != second["ssn"]

    def test_output_keeps_the_16_hex_char_shape(self) -> None:
        """The wire contract does not change, so a fixed-width column still fits."""
        masked = apply_field_masking({"ssn": "123-45-6789"}, _policy(), hash_salt=SALT)

        assert len(masked["ssn"]) == 16
        assert all(c in "0123456789abcdef" for c in masked["ssn"])


class TestBackwardCompatibility:
    def test_no_salt_preserves_the_existing_digest(self) -> None:
        """Existing join keys must not change for integrators who do not opt in."""
        masked = apply_field_masking({"ssn": "123-45-6789"}, _policy())

        assert masked["ssn"] == hashlib.sha256(b"123-45-6789").hexdigest()[:16]

    @pytest.mark.parametrize("empty", [None, ""])
    def test_empty_salt_is_treated_as_unsalted(self, empty: str | None) -> None:
        masked = apply_field_masking({"ssn": "123-45-6789"}, _policy(), hash_salt=empty)

        assert masked["ssn"] == hashlib.sha256(b"123-45-6789").hexdigest()[:16]


class TestSaltAcrossAlgorithms:
    @pytest.mark.parametrize("algorithm", ["sha256", "sha512", "blake2b"])
    def test_every_permitted_algorithm_honours_the_salt(self, algorithm: str) -> None:
        record = {"ssn": "123-45-6789"}

        salted = apply_field_masking(record, _policy(algorithm), hash_salt=SALT)["ssn"]
        unsalted = apply_field_masking(record, _policy(algorithm))["ssn"]

        assert salted != unsalted
        assert len(salted) == 16

    @pytest.mark.parametrize("algorithm", ["sha256", "sha512", "blake2b"])
    def test_salted_algorithms_differ_from_each_other(self, algorithm: str) -> None:
        """A salted sha512 must not collapse onto salted sha256."""
        salted = apply_field_masking(
            {"ssn": "123-45-6789"}, _policy(algorithm), hash_salt=SALT
        )["ssn"]
        baseline = apply_field_masking(
            {"ssn": "123-45-6789"}, _policy("sha256"), hash_salt=SALT
        )["ssn"]

        if algorithm != "sha256":
            assert salted != baseline

    def test_unsupported_algorithm_still_fails_closed_when_salted(self) -> None:
        """Salting must not turn a redact-on-unknown-algorithm into a disclosure."""
        masked = apply_field_masking(
            {"ssn": "123-45-6789"}, _policy("md5"), hash_salt=SALT
        )

        assert masked["ssn"] == "[REDACTED]"


class TestSaltReachesNestedAndTreeShapes:
    def test_nested_records_are_salted(self) -> None:
        body = {"results": [{"patient": {"ssn": "123-45-6789"}}]}

        masked = apply_masking(body, _policy(), hash_salt=SALT)
        unsalted = apply_masking(body, _policy())

        got = masked["results"][0]["patient"]["ssn"]
        assert got != "123-45-6789"
        assert got != unsalted["results"][0]["patient"]["ssn"]

    def test_bytes_salt_is_accepted(self) -> None:
        """A salt fetched from a KMS arrives as bytes as often as str."""
        as_str = apply_field_masking({"ssn": "1"}, _policy(), hash_salt="abc")
        as_bytes = apply_field_masking({"ssn": "1"}, _policy(), hash_salt=b"abc")

        assert as_str["ssn"] == as_bytes["ssn"]
