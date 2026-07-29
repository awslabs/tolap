from __future__ import annotations

import json

import pytest

from conftest import load_fixture, load_all_fixtures
from tolap_core.enums import AssigneeType, FilterOperator, MaskType
from tolap_core.serialization import (
    deserialize_policy_assignment,
    deserialize_policy_definition,
    serialize,
)


class TestDeserializePolicyDefinition:
    """Test deserialization of policy definition fixtures."""

    def test_healthcare_analyst(self) -> None:
        data = load_fixture("policies/healthcare-analyst.json")
        policy = deserialize_policy_definition(data)

        assert policy.version == "1.0"
        assert policy.name == "healthcare-analyst-db"
        assert policy.priority == 10
        assert policy.permissions.can_query is True
        assert policy.permissions.read_only is True
        assert policy.source_patterns == ["db:production:patient_*", "db:production:encounter_*"]

        assert policy.object_rules is not None
        assert policy.object_rules.allowed_objects == ["patients", "encounters", "diagnoses", "medications"]
        assert policy.object_rules.hidden_objects == ["billing_internal", "audit_log", "admin_notes"]

        fr = policy.object_rules.field_rules
        assert fr is not None
        assert "patients.patient_id" in fr.allowed_fields
        assert "patients.ssn" in fr.hidden_fields
        assert len(fr.masked_fields) == 2

        name_mask = fr.masked_fields[0]
        assert name_mask.field == "patients.full_name"
        assert name_mask.mask_type == MaskType.partial
        assert name_mask.parameters.show_first == 1

        email_mask = fr.masked_fields[1]
        assert email_mask.field == "patients.email"
        assert email_mask.mask_type == MaskType.hash

        assert policy.object_rules.row_filters is not None
        assert len(policy.object_rules.row_filters) == 2
        assert policy.object_rules.row_filters[0].operator == FilterOperator.in_
        assert policy.object_rules.row_filters[0].values == ["us-east", "us-west"]

        assert policy.limits.max_results == 5000

    def test_api_readonly(self) -> None:
        data = load_fixture("policies/api-readonly.json")
        policy = deserialize_policy_definition(data)

        assert policy.name == "internal-api-readonly"
        assert policy.object_rules.endpoint_rules is not None
        assert "/api/v1/patients" in policy.object_rules.endpoint_rules.allowed_endpoints
        assert "/api/v1/admin/*" in policy.object_rules.endpoint_rules.hidden_endpoints
        assert policy.object_rules.endpoint_rules.allowed_methods == ["GET", "HEAD", "OPTIONS"]

    def test_kb_researcher(self) -> None:
        data = load_fixture("policies/kb-researcher.json")
        policy = deserialize_policy_definition(data)

        assert policy.name == "research-kb-access"
        assert policy.object_rules.tag_rules is not None
        assert "public" in policy.object_rules.tag_rules.allowed_tags
        assert "classified" in policy.object_rules.tag_rules.denied_tags
        assert policy.limits.min_similarity_score == 0.75

    def test_storage_analyst(self) -> None:
        data = load_fixture("policies/storage-analyst.json")
        policy = deserialize_policy_definition(data)

        assert policy.name == "data-lake-analyst"
        assert policy.limits.max_object_size_bytes == 104857600

    def test_from_json_string(self) -> None:
        data = load_fixture("policies/healthcare-analyst.json")
        json_str = json.dumps(data)
        policy = deserialize_policy_definition(json_str)
        assert policy.name == "healthcare-analyst-db"

    def test_all_valid_policies_deserialize(self) -> None:
        """All valid policy fixtures should deserialize without error."""
        valid = [
            "policies/healthcare-analyst.json",
            "policies/api-readonly.json",
            "policies/kb-researcher.json",
            "policies/storage-analyst.json",
        ]
        for path in valid:
            data = load_fixture(path)
            policy = deserialize_policy_definition(data)
            assert policy.name is not None


class TestDeserializePolicyAssignment:
    """Test deserialization of assignment fixtures."""

    def test_user_direct(self) -> None:
        data = load_fixture("assignments/user-direct.json")
        assignment = deserialize_policy_assignment(data)

        assert assignment.version == "1.0"
        assert assignment.policy_name == "healthcare-analyst-db"
        assert assignment.assignee.type == AssigneeType.user
        assert assignment.assignee.identifier == "user-001"
        assert assignment.scope.tenant_id == "tenant-midwest-health"
        assert assignment.active is True
        assert assignment.audit.granted_by == "admin-jane-doe"

    def test_group_assignment(self) -> None:
        data = load_fixture("assignments/group-assignment.json")
        assignment = deserialize_policy_assignment(data)

        assert assignment.assignee.type == AssigneeType.group
        assert assignment.assignee.identifier == "research-analysts"

    def test_time_bound(self) -> None:
        data = load_fixture("assignments/time-bound.json")
        assignment = deserialize_policy_assignment(data)

        assert assignment.expires_at == "2026-07-01T00:00:00Z"

    def test_multi_scope(self) -> None:
        data = load_fixture("assignments/multi-scope.json")
        assignment = deserialize_policy_assignment(data)

        assert assignment.assignee.type == AssigneeType.role
        assert assignment.scope.source_connection_id == "ds-s3-datalake-prod"

    def test_from_json_string(self) -> None:
        data = load_fixture("assignments/user-direct.json")
        json_str = json.dumps(data)
        assignment = deserialize_policy_assignment(json_str)
        assert assignment.policy_name == "healthcare-analyst-db"


class TestRoundTrip:
    """Test serialize -> deserialize round-trips."""

    def test_policy_definition_round_trip(self) -> None:
        data = load_fixture("policies/healthcare-analyst.json")
        policy = deserialize_policy_definition(data)
        json_str = serialize(policy)
        restored = deserialize_policy_definition(json_str)

        assert restored.name == policy.name
        assert restored.permissions.can_query == policy.permissions.can_query
        assert restored.object_rules.allowed_objects == policy.object_rules.allowed_objects
        assert restored.limits.max_results == policy.limits.max_results

    def test_assignment_round_trip(self) -> None:
        data = load_fixture("assignments/user-direct.json")
        assignment = deserialize_policy_assignment(data)
        json_str = serialize(assignment)
        restored = deserialize_policy_assignment(json_str)

        assert restored.policy_name == assignment.policy_name
        assert restored.assignee.type == assignment.assignee.type
        assert restored.assignee.identifier == assignment.assignee.identifier
