from __future__ import annotations

import pytest

from tolap_core.enums import AssigneeType
from tolap_core.models import (
    Assignee,
    AssignmentScope,
    AuditInfo,
    FieldRules,
    MaskingParameters,
    MaskingRule,
    ObjectRules,
    PolicyAssignment,
    PolicyDefinition,
    PolicyLimits,
    PolicyPermissions,
    RowFilter,
)
from tolap_core.enums import FilterOperator, MaskType
from tolap_core.resolution import resolve


def _make_policy(
    name: str,
    can_query: bool = True,
    priority: int = 100,
    allowed_objects: list[str] | None = None,
) -> PolicyDefinition:
    return PolicyDefinition(
        version="1.0",
        name=name,
        permissions=PolicyPermissions(can_query=can_query, can_export=False, read_only=True),
        priority=priority,
        object_rules=ObjectRules(allowed_objects=allowed_objects) if allowed_objects else None,
    )


def _make_assignment(
    policy_name: str,
    assignee_type: AssigneeType,
    identifier: str,
    tenant_id: str = "tenant-001",
    source_connection_id: str | None = None,
    active: bool = True,
    expires_at: str | None = None,
) -> PolicyAssignment:
    return PolicyAssignment(
        version="1.0",
        policy_name=policy_name,
        assignee=Assignee(type=assignee_type, identifier=identifier),
        scope=AssignmentScope(
            tenant_id=tenant_id,
            source_connection_id=source_connection_id,
        ),
        active=active,
        audit=AuditInfo(
            granted_by="test-admin",
            granted_at="2026-01-01T00:00:00Z",
            reason="Test assignment",
        ),
        expires_at=expires_at,
    )


class TestResolution:
    """Test policy resolution."""

    def test_direct_user_assignment(self) -> None:
        policy = _make_policy("test-policy", allowed_objects=["patients", "encounters"])
        assignment = _make_assignment("test-policy", AssigneeType.user, "user-001")

        result = resolve(
            user_id="user-001",
            tenant_id="tenant-001",
            source_connection_id="ds-postgres-001",
            assignments=[assignment],
            definitions={"test-policy": policy},
            get_groups=lambda uid: [],
            get_roles=lambda uid: [],
        )

        assert result.user_id == "user-001"
        assert result.tenant_id == "tenant-001"
        assert result.permissions.can_query is True
        assert result.source_profiles == ["test-policy"]

    def test_group_assignment(self) -> None:
        policy = _make_policy("group-policy")
        assignment = _make_assignment("group-policy", AssigneeType.group, "analysts")

        result = resolve(
            user_id="user-001",
            tenant_id="tenant-001",
            source_connection_id="ds-001",
            assignments=[assignment],
            definitions={"group-policy": policy},
            get_groups=lambda uid: ["analysts", "researchers"],
            get_roles=lambda uid: [],
        )

        assert result.permissions.can_query is True
        assert "group-policy" in result.source_profiles

    def test_role_assignment(self) -> None:
        policy = _make_policy("role-policy")
        assignment = _make_assignment("role-policy", AssigneeType.role, "data-analyst")

        result = resolve(
            user_id="user-001",
            tenant_id="tenant-001",
            source_connection_id="ds-001",
            assignments=[assignment],
            definitions={"role-policy": policy},
            get_groups=lambda uid: [],
            get_roles=lambda uid: ["data-analyst"],
        )

        assert "role-policy" in result.source_profiles

    def test_no_matching_assignments_returns_deny_all(self) -> None:
        policy = _make_policy("test-policy")
        assignment = _make_assignment("test-policy", AssigneeType.user, "other-user")

        result = resolve(
            user_id="user-001",
            tenant_id="tenant-001",
            source_connection_id="ds-001",
            assignments=[assignment],
            definitions={"test-policy": policy},
            get_groups=lambda uid: [],
            get_roles=lambda uid: [],
        )

        assert result.permissions.can_query is False
        assert result.source_profiles == []

    def test_inactive_assignment_ignored(self) -> None:
        policy = _make_policy("test-policy")
        assignment = _make_assignment("test-policy", AssigneeType.user, "user-001", active=False)

        result = resolve(
            user_id="user-001",
            tenant_id="tenant-001",
            source_connection_id="ds-001",
            assignments=[assignment],
            definitions={"test-policy": policy},
            get_groups=lambda uid: [],
            get_roles=lambda uid: [],
        )

        assert result.permissions.can_query is False

    def test_expired_assignment_ignored(self) -> None:
        policy = _make_policy("test-policy")
        assignment = _make_assignment(
            "test-policy",
            AssigneeType.user,
            "user-001",
            expires_at="2020-01-01T00:00:00Z",
        )

        result = resolve(
            user_id="user-001",
            tenant_id="tenant-001",
            source_connection_id="ds-001",
            assignments=[assignment],
            definitions={"test-policy": policy},
            get_groups=lambda uid: [],
            get_roles=lambda uid: [],
        )

        assert result.permissions.can_query is False

    def test_tenant_mismatch_ignored(self) -> None:
        policy = _make_policy("test-policy")
        assignment = _make_assignment(
            "test-policy",
            AssigneeType.user,
            "user-001",
            tenant_id="other-tenant",
        )

        result = resolve(
            user_id="user-001",
            tenant_id="tenant-001",
            source_connection_id="ds-001",
            assignments=[assignment],
            definitions={"test-policy": policy},
            get_groups=lambda uid: [],
            get_roles=lambda uid: [],
        )

        assert result.permissions.can_query is False

    def test_source_connection_scope_filter(self) -> None:
        policy = _make_policy("scoped-policy")
        assignment = _make_assignment(
            "scoped-policy",
            AssigneeType.user,
            "user-001",
            source_connection_id="ds-specific-001",
        )

        # Matching source
        result = resolve(
            user_id="user-001",
            tenant_id="tenant-001",
            source_connection_id="ds-specific-001",
            assignments=[assignment],
            definitions={"scoped-policy": policy},
            get_groups=lambda uid: [],
            get_roles=lambda uid: [],
        )
        assert result.permissions.can_query is True

        # Non-matching source
        result2 = resolve(
            user_id="user-001",
            tenant_id="tenant-001",
            source_connection_id="ds-other-002",
            assignments=[assignment],
            definitions={"scoped-policy": policy},
            get_groups=lambda uid: [],
            get_roles=lambda uid: [],
        )
        assert result2.permissions.can_query is False

    def test_multiple_policies_merged(self) -> None:
        policy_a = PolicyDefinition(
            version="1.0",
            name="policy-a",
            permissions=PolicyPermissions(can_query=True, can_export=True, read_only=False),
            priority=10,
            object_rules=ObjectRules(allowed_objects=["patients", "encounters"]),
            limits=PolicyLimits(max_results=5000),
        )
        policy_b = PolicyDefinition(
            version="1.0",
            name="policy-b",
            permissions=PolicyPermissions(can_query=True, can_export=False, read_only=True),
            priority=20,
            object_rules=ObjectRules(allowed_objects=["patients", "medications"]),
            limits=PolicyLimits(max_results=1000),
        )

        assign_a = _make_assignment("policy-a", AssigneeType.user, "user-001")
        assign_b = _make_assignment("policy-b", AssigneeType.user, "user-001")

        result = resolve(
            user_id="user-001",
            tenant_id="tenant-001",
            source_connection_id="ds-001",
            assignments=[assign_a, assign_b],
            definitions={"policy-a": policy_a, "policy-b": policy_b},
            get_groups=lambda uid: [],
            get_roles=lambda uid: [],
        )

        # AND for can_export, OR for read_only
        assert result.permissions.can_query is True
        assert result.permissions.can_export is False
        assert result.permissions.read_only is True

        # Intersection of allowed objects
        assert sorted(result.object_rules.allowed_objects) == ["patients"]

        # Min of maxima
        assert result.limits.max_results == 1000

    def test_priority_ordering(self) -> None:
        """Policies should be sorted by priority (lower first)."""
        policy_low = _make_policy("low-priority", priority=100)
        policy_high = _make_policy("high-priority", priority=10)

        assign_low = _make_assignment("low-priority", AssigneeType.user, "user-001")
        assign_high = _make_assignment("high-priority", AssigneeType.user, "user-001")

        result = resolve(
            user_id="user-001",
            tenant_id="tenant-001",
            source_connection_id="ds-001",
            assignments=[assign_low, assign_high],
            definitions={"low-priority": policy_low, "high-priority": policy_high},
            get_groups=lambda uid: [],
            get_roles=lambda uid: [],
        )

        # High priority (10) should come first
        assert result.source_profiles[0] == "high-priority"
        assert result.source_profiles[1] == "low-priority"
