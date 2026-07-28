from __future__ import annotations

import pytest

from tolap_core.enums import AssigneeType
from tolap_core.models import (
    Assignee,
    AssignmentScope,
    AuditInfo,
    ObjectRules,
    PolicyAssignment,
    PolicyDefinition,
    PolicyLimits,
    PolicyPermissions,
)
from tolap_store.audit import PolicyAuditEvent
from tolap_store.in_memory_store import InMemoryPolicyStore
from tolap_store.static_identity_resolver import StaticIdentityResolver


def _make_policy(name: str, can_query: bool = True) -> PolicyDefinition:
    return PolicyDefinition(
        version="1.0",
        name=name,
        permissions=PolicyPermissions(can_query=can_query, can_export=False, read_only=True),
    )


def _make_assignment(
    policy_name: str,
    identifier: str,
    assignee_type: AssigneeType = AssigneeType.user,
    tenant_id: str = "tenant-001",
) -> PolicyAssignment:
    return PolicyAssignment(
        version="1.0",
        policy_name=policy_name,
        assignee=Assignee(type=assignee_type, identifier=identifier),
        scope=AssignmentScope(tenant_id=tenant_id),
        active=True,
        audit=AuditInfo(
            granted_by="test-admin",
            granted_at="2026-01-01T00:00:00Z",
            reason="Testing",
        ),
    )


class TestInMemoryPolicyStore:
    """Test the in-memory policy store."""

    @pytest.fixture
    def resolver(self) -> StaticIdentityResolver:
        return StaticIdentityResolver(
            groups={"user-001": ["analysts"], "user-002": ["engineers"]},
            roles={"user-001": ["data-analyst"], "user-002": ["developer"]},
        )

    @pytest.fixture
    def store(self, resolver: StaticIdentityResolver) -> InMemoryPolicyStore:
        return InMemoryPolicyStore(identity_resolver=resolver)

    def test_save_and_get_definition(self, store: InMemoryPolicyStore) -> None:
        policy = _make_policy("test-policy")
        store.save_definition(policy)

        retrieved = store.get_definition("test-policy")
        assert retrieved is not None
        assert retrieved.name == "test-policy"

    def test_get_nonexistent_definition(self, store: InMemoryPolicyStore) -> None:
        assert store.get_definition("nonexistent") is None

    def test_list_definitions(self, store: InMemoryPolicyStore) -> None:
        store.save_definition(_make_policy("policy-a"))
        store.save_definition(_make_policy("policy-b"))

        definitions = store.list_definitions()
        names = [d.name for d in definitions]
        assert "policy-a" in names
        assert "policy-b" in names

    def test_delete_definition(self, store: InMemoryPolicyStore) -> None:
        store.save_definition(_make_policy("to-delete"))
        assert store.delete_definition("to-delete") is True
        assert store.get_definition("to-delete") is None

    def test_delete_nonexistent(self, store: InMemoryPolicyStore) -> None:
        assert store.delete_definition("nonexistent") is False

    def test_update_definition(self, store: InMemoryPolicyStore) -> None:
        store.save_definition(_make_policy("test-policy", can_query=True))
        store.save_definition(_make_policy("test-policy", can_query=False))

        retrieved = store.get_definition("test-policy")
        assert retrieved.permissions.can_query is False

    def test_save_and_get_assignment(self, store: InMemoryPolicyStore) -> None:
        store.save_definition(_make_policy("test-policy"))
        assignment = _make_assignment("test-policy", "user-001")
        store.save_assignment(assignment)

        assignments = store.get_assignments("user-001", "tenant-001")
        assert len(assignments) == 1
        assert assignments[0].policy_name == "test-policy"

    def test_assignment_group_matching(self, store: InMemoryPolicyStore) -> None:
        store.save_definition(_make_policy("group-policy"))
        assignment = _make_assignment("group-policy", "analysts", AssigneeType.group)
        store.save_assignment(assignment)

        # user-001 is in the "analysts" group
        assignments = store.get_assignments("user-001", "tenant-001")
        assert len(assignments) == 1

        # user-002 is not in the "analysts" group
        assignments2 = store.get_assignments("user-002", "tenant-001")
        assert len(assignments2) == 0

    def test_delete_assignment(self, store: InMemoryPolicyStore) -> None:
        assignment = _make_assignment("test-policy", "user-001")
        store.save_assignment(assignment)

        assert store.delete_assignment("test-policy", "user-001") is True
        assignments = store.get_assignments("user-001", "tenant-001")
        assert len(assignments) == 0

    def test_resolve_policy(self, store: InMemoryPolicyStore) -> None:
        policy = PolicyDefinition(
            version="1.0",
            name="analyst-policy",
            permissions=PolicyPermissions(can_query=True, can_export=False, read_only=True),
            priority=10,
            object_rules=ObjectRules(allowed_objects=["patients", "encounters"]),
            limits=PolicyLimits(max_results=1000),
        )
        store.save_definition(policy)
        store.save_assignment(_make_assignment("analyst-policy", "user-001"))

        result = store.resolve_policy("user-001", "tenant-001", "ds-001")

        assert result.permissions.can_query is True
        assert "analyst-policy" in result.source_profiles
        assert result.user_id == "user-001"
        assert result.tenant_id == "tenant-001"

    def test_resolve_no_assignments(self, store: InMemoryPolicyStore) -> None:
        result = store.resolve_policy("user-999", "tenant-001", "ds-001")
        assert result.permissions.can_query is False

    def test_audit_events_fired(self) -> None:
        audit_events: list[PolicyAuditEvent] = []
        resolver = StaticIdentityResolver()
        store = InMemoryPolicyStore(
            identity_resolver=resolver,
            on_audit=lambda e: audit_events.append(e),
        )

        policy = _make_policy("audited-policy")
        store.save_definition(policy)

        assert len(audit_events) == 1
        assert audit_events[0].event_type == "definition_created"

        store.save_definition(policy)
        assert len(audit_events) == 2
        assert audit_events[1].event_type == "definition_updated"

        store.delete_definition("audited-policy")
        assert len(audit_events) == 3
        assert audit_events[2].event_type == "definition_deleted"

    def test_audit_log_property(self, store: InMemoryPolicyStore) -> None:
        store.save_definition(_make_policy("test-policy"))
        log = store.audit_log
        assert len(log) >= 1
        assert log[0].event_type == "definition_created"
