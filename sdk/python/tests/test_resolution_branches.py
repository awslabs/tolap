"""Branch coverage for policy resolution and the in-memory store.

Resolution decides *which* policies apply to a principal, so a wrong branch here
grants a user someone else's policy — or, worse, silently resolves to a permissive
set. The assignee-type dispatch, the expiry guard, and the revocation path are the
security-relevant conditionals, and each is asserted on outcome (what the
principal can now do) rather than on the audit trail, per spec section 10.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pytest

from tolap_core.enums import AssigneeType
from tolap_core.models import (
    Assignee,
    AssignmentScope,
    AuditInfo,
    ObjectRules,
    PolicyAssignment,
    PolicyDefinition,
    PolicyPermissions,
)
from tolap_core.resolution import resolve
from tolap_store.in_memory_store import InMemoryPolicyStore
from tolap_store.static_identity_resolver import StaticIdentityResolver


def _policy(name: str, *, priority: int | None = 100, allowed_objects: list[str] | None = None) -> PolicyDefinition:
    return PolicyDefinition(
        version="1.0",
        name=name,
        permissions=PolicyPermissions(can_query=True, can_export=False, read_only=True),
        priority=priority,
        object_rules=ObjectRules(allowed_objects=allowed_objects) if allowed_objects else None,
    )


def _assignment(
    policy_name: str,
    assignee_type: AssigneeType,
    identifier: str,
    *,
    tenant_id: str | None = "tenant-001",
    source_connection_id: str | None = None,
    active: bool = True,
    expires_at: str | None = None,
) -> PolicyAssignment:
    return PolicyAssignment(
        version="1.0",
        policy_name=policy_name,
        assignee=Assignee(type=assignee_type, identifier=identifier),
        scope=AssignmentScope(tenant_id=tenant_id, source_connection_id=source_connection_id),
        active=active,
        audit=AuditInfo(
            granted_by="test-admin",
            granted_at="2026-01-01T00:00:00Z",
            reason="Branch coverage",
        ),
        expires_at=expires_at,
    )


def _resolve(
    assignments: list[PolicyAssignment],
    definitions: dict[str, PolicyDefinition],
    *,
    user_id: str = "user-001",
    groups: list[str] | None = None,
    roles: list[str] | None = None,
    source_connection_id: str = "ds-001",
):
    return resolve(
        user_id=user_id,
        tenant_id="tenant-001",
        source_connection_id=source_connection_id,
        assignments=assignments,
        definitions=definitions,
        get_groups=lambda _uid: groups or [],
        get_roles=lambda _uid: roles or [],
    )


class TestAssigneeTypeDispatch:
    """Every arm of the assignee match, including the non-matching ones."""

    def test_service_account_matching_the_user_id_resolves(self) -> None:
        result = _resolve(
            [_assignment("svc", AssigneeType.service_account, "svc-agent-01")],
            {"svc": _policy("svc")},
            user_id="svc-agent-01",
        )

        assert result.source_profiles == ["svc"]
        assert result.permissions.can_query is True

    def test_service_account_not_matching_the_user_id_is_denied(self) -> None:
        result = _resolve(
            [_assignment("svc", AssigneeType.service_account, "svc-agent-01")],
            {"svc": _policy("svc")},
            user_id="someone-else",
        )

        assert result.source_profiles == []
        assert result.permissions.can_query is False

    def test_group_assignment_does_not_match_a_non_member(self) -> None:
        result = _resolve(
            [_assignment("grp", AssigneeType.group, "analysts")],
            {"grp": _policy("grp")},
            groups=["interns"],
        )

        assert result.permissions.can_query is False

    def test_role_assignment_does_not_match_an_unheld_role(self) -> None:
        result = _resolve(
            [_assignment("rl", AssigneeType.role, "data-analyst")],
            {"rl": _policy("rl")},
            roles=["auditor"],
        )

        assert result.permissions.can_query is False

    def test_unknown_assignee_type_fails_closed(self) -> None:
        """A type from a newer schema must not resolve to a policy.

        The wildcard arm exists so an unrecognized assignee cannot be treated as a
        match; asserting that keeps the fallback from being "optimized away" into a
        permissive default.
        """

        @dataclass
        class UnknownAssignee:
            type: str = "orgUnit"
            identifier: str = "user-001"

        assignment = _assignment("p", AssigneeType.user, "user-001")
        assignment.assignee = UnknownAssignee()  # type: ignore[assignment]

        result = _resolve([assignment], {"p": _policy("p")})

        assert result.source_profiles == []
        assert result.permissions.can_query is False


class TestAssignmentExpiry:
    def test_future_expiry_still_resolves(self) -> None:
        future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat().replace("+00:00", "Z")

        result = _resolve(
            [_assignment("p", AssigneeType.user, "user-001", expires_at=future)],
            {"p": _policy("p")},
        )

        assert result.permissions.can_query is True

    def test_unparseable_expiry_fails_closed(self) -> None:
        """An invalid date must not be a skipped check.

        An assignment carries no signature, so its `expiresAt` is whatever the
        store returned; treating "never" as "no expiry" would grant an unbounded
        lifetime.
        """
        result = _resolve(
            [_assignment("p", AssigneeType.user, "user-001", expires_at="never")],
            {"p": _policy("p")},
        )

        assert result.source_profiles == []
        assert result.permissions.can_query is False

    def test_empty_string_expiry_is_treated_as_absent(self) -> None:
        """Documents current behavior: "" is falsy, so no expiry check runs."""
        result = _resolve(
            [_assignment("p", AssigneeType.user, "user-001", expires_at="")],
            {"p": _policy("p")},
        )

        assert result.permissions.can_query is True

    def test_offset_expiry_is_compared_correctly(self) -> None:
        future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        assert future.endswith("+00:00")

        result = _resolve(
            [_assignment("p", AssigneeType.user, "user-001", expires_at=future)],
            {"p": _policy("p")},
        )

        assert result.permissions.can_query is True


class TestDefinitionLookupAndScope:
    def test_assignment_referencing_an_unknown_definition_is_skipped(self) -> None:
        """A dangling reference must not resolve to anything permissive."""
        result = _resolve(
            [_assignment("does-not-exist", AssigneeType.user, "user-001")],
            {"other": _policy("other")},
        )

        assert result.source_profiles == []
        assert result.permissions.can_query is False

    def test_assignment_with_no_tenant_scope_matches_any_tenant(self) -> None:
        result = _resolve(
            [_assignment("p", AssigneeType.user, "user-001", tenant_id=None)],
            {"p": _policy("p")},
        )

        assert result.permissions.can_query is True

    def test_source_connection_scope_none_matches_any_source(self) -> None:
        result = _resolve(
            [_assignment("p", AssigneeType.user, "user-001", source_connection_id=None)],
            {"p": _policy("p")},
            source_connection_id="ds-anything",
        )

        assert result.permissions.can_query is True

    def test_absent_priority_sorts_after_an_explicit_lower_one(self) -> None:
        """A definition with no priority takes the default of 100."""
        result = _resolve(
            [
                _assignment("no-priority", AssigneeType.user, "user-001"),
                _assignment("explicit", AssigneeType.user, "user-001"),
            ],
            {
                "no-priority": _policy("no-priority", priority=None),
                "explicit": _policy("explicit", priority=10),
            },
        )

        assert result.source_profiles == ["explicit", "no-priority"]

    def test_resolved_at_is_stamped_in_utc_with_a_z_suffix(self) -> None:
        result = _resolve(
            [_assignment("p", AssigneeType.user, "user-001")], {"p": _policy("p")}
        )

        assert result.resolved_at is not None
        assert result.resolved_at.endswith("Z")
        assert result.source_connection_id == "ds-001"


class TestInMemoryStoreAssigneeDispatch:
    """`get_assignments` resolves groups/roles through the identity resolver."""

    @pytest.fixture
    def resolver(self) -> StaticIdentityResolver:
        return StaticIdentityResolver(
            groups={"user-001": ["analysts"]}, roles={"user-001": ["auditor"]}
        )

    @pytest.fixture
    def store(self, resolver: StaticIdentityResolver) -> InMemoryPolicyStore:
        store = InMemoryPolicyStore(resolver)
        store.save_definition(_policy("p"))
        return store

    def test_role_assignment_is_returned_for_a_role_holder(
        self, store: InMemoryPolicyStore
    ) -> None:
        store.save_assignment(_assignment("p", AssigneeType.role, "auditor"))

        assignments = store.get_assignments("user-001", "tenant-001")

        assert [a.policy_name for a in assignments] == ["p"]

    def test_role_assignment_is_withheld_from_a_non_holder(
        self, store: InMemoryPolicyStore
    ) -> None:
        store.save_assignment(_assignment("p", AssigneeType.role, "compliance-officer"))

        assert store.get_assignments("user-001", "tenant-001") == []

    def test_group_assignment_is_returned_for_a_member(self, store: InMemoryPolicyStore) -> None:
        store.save_assignment(_assignment("p", AssigneeType.group, "analysts"))

        assignments = store.get_assignments("user-001", "tenant-001")

        assert [a.policy_name for a in assignments] == ["p"]

    def test_service_account_assignment_matches_the_user_id(
        self, store: InMemoryPolicyStore
    ) -> None:
        store.save_assignment(_assignment("p", AssigneeType.service_account, "user-001"))

        assignments = store.get_assignments("user-001", "tenant-001")

        assert [a.policy_name for a in assignments] == ["p"]

    def test_service_account_assignment_for_another_principal_is_withheld(
        self, store: InMemoryPolicyStore
    ) -> None:
        store.save_assignment(_assignment("p", AssigneeType.service_account, "svc-other"))

        assert store.get_assignments("user-001", "tenant-001") == []

    def test_unknown_assignee_type_is_withheld(self, store: InMemoryPolicyStore) -> None:
        @dataclass
        class UnknownAssignee:
            type: str = "orgUnit"
            identifier: str = "user-001"

        assignment = _assignment("p", AssigneeType.user, "user-001")
        assignment.assignee = UnknownAssignee()  # type: ignore[assignment]
        store.save_assignment(assignment)

        assert store.get_assignments("user-001", "tenant-001") == []

    def test_tenant_scoped_assignment_is_withheld_from_another_tenant(
        self, store: InMemoryPolicyStore
    ) -> None:
        store.save_assignment(_assignment("p", AssigneeType.user, "user-001"))

        assert store.get_assignments("user-001", "other-tenant") == []


class TestInMemoryStoreRevocation:
    """Spec section 10: revoking must remove access, not just log an event."""

    @pytest.fixture
    def store(self) -> InMemoryPolicyStore:
        store = InMemoryPolicyStore(StaticIdentityResolver())
        store.save_definition(_policy("p", allowed_objects=["patients"]))
        store.save_assignment(_assignment("p", AssigneeType.user, "user-001"))
        return store

    def test_access_is_gone_after_the_assignment_is_deleted(
        self, store: InMemoryPolicyStore
    ) -> None:
        before = store.resolve_policy("user-001", "tenant-001", "ds-001")
        assert before.permissions.can_query is True

        assert store.delete_assignment("p", "user-001") is True

        after = store.resolve_policy("user-001", "tenant-001", "ds-001")
        assert after.permissions.can_query is False
        assert after.source_profiles == []

    def test_deleting_a_missing_assignment_reports_false_and_emits_no_event(
        self, store: InMemoryPolicyStore
    ) -> None:
        before = len(store.audit_log)

        assert store.delete_assignment("p", "nobody") is False
        assert store.delete_assignment("no-such-policy", "user-001") is False

        assert len(store.audit_log) == before

    def test_access_is_gone_after_the_definition_is_deleted(
        self, store: InMemoryPolicyStore
    ) -> None:
        assert store.delete_definition("p") is True

        after = store.resolve_policy("user-001", "tenant-001", "ds-001")
        assert after.permissions.can_query is False

    def test_deleting_a_missing_definition_reports_false(
        self, store: InMemoryPolicyStore
    ) -> None:
        assert store.delete_definition("no-such-policy") is False

    def test_deletion_emits_an_audit_event_in_addition_to_removing_access(
        self, store: InMemoryPolicyStore
    ) -> None:
        store.delete_assignment("p", "user-001")

        assert any(e.event_type == "assignment_deleted" for e in store.audit_log)


class TestStaticIdentityResolverMutators:
    def test_added_groups_change_what_resolves(self) -> None:
        """The mutator must affect resolution, not just the internal dict."""
        resolver = StaticIdentityResolver()
        store = InMemoryPolicyStore(resolver)
        store.save_definition(_policy("grp"))
        store.save_assignment(_assignment("grp", AssigneeType.group, "analysts"))

        assert store.resolve_policy("user-001", "tenant-001", "ds-001").permissions.can_query is False

        resolver.add_user_groups("user-001", ["analysts"])

        assert resolver.get_groups("user-001") == ["analysts"]
        assert store.resolve_policy("user-001", "tenant-001", "ds-001").permissions.can_query is True

    def test_added_roles_change_what_resolves(self) -> None:
        resolver = StaticIdentityResolver()
        store = InMemoryPolicyStore(resolver)
        store.save_definition(_policy("rl"))
        store.save_assignment(_assignment("rl", AssigneeType.role, "auditor"))

        assert store.resolve_policy("user-001", "tenant-001", "ds-001").permissions.can_query is False

        resolver.add_user_roles("user-001", ["auditor"])

        assert resolver.get_roles("user-001") == ["auditor"]
        assert store.resolve_policy("user-001", "tenant-001", "ds-001").permissions.can_query is True

    def test_adding_groups_replaces_rather_than_appends(self) -> None:
        resolver = StaticIdentityResolver(groups={"user-001": ["old"]})

        resolver.add_user_groups("user-001", ["new"])

        assert resolver.get_groups("user-001") == ["new"]

    def test_unknown_user_has_no_groups_or_roles(self) -> None:
        resolver = StaticIdentityResolver()

        assert resolver.get_groups("nobody") == []
        assert resolver.get_roles("nobody") == []
