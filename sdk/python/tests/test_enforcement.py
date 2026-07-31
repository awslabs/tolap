from __future__ import annotations

import hashlib

import pytest

from conftest import load_fixture
from tolap_core.enforcement import (
    apply_field_masking,
    filter_by_tags,
    validate_access,
    validate_endpoint,
    validate_field_access,
)
from tolap_core.models import (
    EffectivePolicy,
    EndpointRules,
    FieldRules,
    MaskingParameters,
    MaskingRule,
    ObjectRules,
    PolicyLimits,
    PolicyPermissions,
    TagRules,
)
from tolap_core.enums import MaskType
from tolap_core.serialization import deserialize_effective_policy


def _build_effective_policy(data: dict) -> EffectivePolicy:
    """Build an EffectivePolicy from a fixture's policy section."""
    return deserialize_effective_policy(data)


class TestValidateObjectAccess:
    """Test object-level access validation."""

    def test_object_access_cases(self) -> None:
        data = load_fixture("enforcement/validate-object-access.json")
        for case in data["cases"]:
            policy = _build_effective_policy(case["policy"])
            result = validate_access(case["objectName"], policy)
            assert result.allowed == case["expected"]["allowed"], (
                f"Object '{case['objectName']}': expected allowed={case['expected']['allowed']}"
            )
            if not case["expected"]["allowed"]:
                assert result.reason == case["expected"]["reason"]

    def test_glob_metacharacter_cases(self) -> None:
        # Shared corpus: '*' and '?' are the only wildcards, '[abc]' is literal
        # (spec section 3.1). The .NET and TypeScript suites read the same file, case
        # for case, so a divergence over '?' or brackets fails somewhere.
        data = load_fixture(
            "enforcement/validate-object-access-glob-metacharacters.json"
        )
        for case in data["cases"]:
            policy = _build_effective_policy(case["policy"])
            result = validate_access(case["objectName"], policy)
            assert result.allowed == case["expected"]["allowed"], (
                f"{case['objectName']}: {case.get('note', '')}"
            )
            if not case["expected"]["allowed"]:
                assert result.reason == case["expected"]["reason"], (
                    f"{case['objectName']}: {case.get('note', '')}"
                )


class TestValidateFieldAccess:
    """Test field-level access validation."""

    def test_field_access_allowed_set(self) -> None:
        data = load_fixture("enforcement/validate-field-access-allowed-set.json")
        policy = _build_effective_policy(data["policy"])
        result = validate_field_access(data["input"]["fields"], policy)

        assert sorted(result.allowed) == sorted(data["expected"]["allowed"])
        assert sorted(result.denied) == sorted(data["expected"]["denied"])

    def test_field_access_hidden(self) -> None:
        data = load_fixture("enforcement/validate-field-access-hidden.json")
        policy = _build_effective_policy(data["policy"])
        result = validate_field_access(data["input"]["fields"], policy)

        assert sorted(result.allowed) == sorted(data["expected"]["allowed"])
        assert sorted(result.denied) == sorted(data["expected"]["denied"])


class TestApplyFieldMasking:
    """Test field masking application."""

    def test_all_mask_types(self) -> None:
        data = load_fixture("enforcement/apply-field-masking.json")
        policy = _build_effective_policy(data["policy"])
        record = data["input"]["record"]

        result = apply_field_masking(record, policy)

        # Partial mask: "John Smith" -> "J*********"
        assert result["name"] == "J*********"

        # Hash mask: SHA-256 of the original value, first 16 hex chars
        email_hash = hashlib.sha256("john.smith@example.com".encode()).hexdigest()[:16]
        assert result["email"] == email_hash

        # Full mask: all asterisks
        assert result["phone"] == "*" * len("555-123-4567")

        # Null mask
        assert result["ssn"] is None

        # Redact mask
        assert result["notes"] == "[REDACTED]"


class TestFilterByTags:
    """Test tag-based filtering."""

    def test_tag_filtering(self) -> None:
        data = load_fixture("enforcement/filter-by-tags.json")
        policy = _build_effective_policy(data["policy"])
        results = data["input"]["results"]

        filtered = filter_by_tags(results, policy)
        expected_ids = [r["id"] for r in data["expected"]["results"]]
        actual_ids = [r["id"] for r in filtered]

        assert actual_ids == expected_ids


class TestValidateEndpoint:
    """Test endpoint access validation."""

    def test_endpoint_access_cases(self) -> None:
        data = load_fixture("enforcement/validate-endpoint-access.json")
        for case in data["cases"]:
            policy = _build_effective_policy(case["policy"])
            result = validate_endpoint(case["path"], case["method"], policy)
            assert result.allowed == case["expected"]["allowed"], (
                f"Endpoint '{case['path']}' {case['method']}: expected allowed={case['expected']['allowed']}"
            )
            if not case["expected"]["allowed"]:
                assert result.reason == case["expected"]["reason"]
