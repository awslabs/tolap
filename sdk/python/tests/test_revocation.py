"""Revocation is enforced by the SDK resolver (spec section 12).

Before `revokedAt` existed in the model, revocation had no SDK backstop: a store
that forgot its own `revoked_at IS NULL` filter kept resolving a revoked grant
and nothing in the SDK would catch it. These tests assert the resolver itself
refuses a revoked assignment, so the guarantee no longer depends on every store
implementation remembering to filter.

The assertions are about *resolved access*, not about a flag or an audit event:
the spec names emitting a `PolicyRevoked` event while leaving access intact as
the fail-open to avoid.
"""

from __future__ import annotations

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
from tolap_core.serialization import deserialize_policy_assignment


def _policy(name: str = "analyst") -> PolicyDefinition:
    return PolicyDefinition(
        version="1.0",
        name=name,
        permissions=PolicyPermissions(can_query=True, read_only=True),
        priority=100,
        object_rules=ObjectRules(allowed_objects=["patients"]),
    )


def _assignment(
    *,
    active: bool = True,
    expires_at: str | None = None,
    revoked_at: str | None = None,
    policy_name: str = "analyst",
) -> PolicyAssignment:
    return PolicyAssignment(
        version="1.0",
        policy_name=policy_name,
        assignee=Assignee(type=AssigneeType.user, identifier="user-001"),
        scope=AssignmentScope(tenant_id="tenant-001"),
        active=active,
        audit=AuditInfo(
            granted_by="test-admin",
            granted_at="2026-01-01T00:00:00Z",
            reason="Test assignment",
        ),
        expires_at=expires_at,
        revoked_at=revoked_at,
    )


def _resolve(assignment: PolicyAssignment):
    return resolve(
        user_id="user-001",
        tenant_id="tenant-001",
        source_connection_id="ds-postgres-001",
        assignments=[assignment],
        definitions={"analyst": _policy()},
        get_groups=lambda uid: [],
        get_roles=lambda uid: [],
    )


def _iso(offset: timedelta) -> str:
    return (datetime.now(timezone.utc) + offset).isoformat().replace("+00:00", "Z")


class TestRevocationStopsResolution:
    def test_unrevoked_assignment_still_grants_access(self) -> None:
        """Baseline: without this the suite could pass by denying everything."""
        result = _resolve(_assignment())
        assert result.permissions.can_query is True
        assert result.source_profiles == ["analyst"]

    def test_revoked_assignment_does_not_resolve(self) -> None:
        result = _resolve(_assignment(revoked_at=_iso(timedelta(minutes=-5))))
        assert result.permissions.can_query is False
        assert result.source_profiles == []

    def test_revocation_overrides_active_true(self) -> None:
        """`active=True` must not resurrect a revoked grant."""
        result = _resolve(
            _assignment(active=True, revoked_at=_iso(timedelta(minutes=-1)))
        )
        assert result.permissions.can_query is False

    def test_revocation_overrides_unexpired_assignment(self) -> None:
        """A far-future `expiresAt` must not outrank the tombstone."""
        result = _resolve(
            _assignment(
                expires_at=_iso(timedelta(days=365)),
                revoked_at=_iso(timedelta(seconds=-1)),
            )
        )
        assert result.permissions.can_query is False

    def test_revoked_exactly_now_is_revoked(self) -> None:
        """Boundary: `revoked_at <= now` is revoked, not a race."""
        result = _resolve(_assignment(revoked_at=_iso(timedelta(seconds=-1))))
        assert result.permissions.can_query is False


class TestRevocationEdgeCases:
    def test_future_revocation_not_yet_in_effect(self) -> None:
        """A scheduled revocation does not deny early -- it mirrors expiry."""
        result = _resolve(_assignment(revoked_at=_iso(timedelta(hours=1))))
        assert result.permissions.can_query is True

    @pytest.mark.parametrize(
        "value",
        ["", "not-a-timestamp", "2026-13-45T99:99:99Z", "yesterday"],
    )
    def test_unparseable_revocation_fails_closed(self, value: str) -> None:
        """A revocation we cannot parse is honoured, not ignored.

        The opposite choice -- treating an unreadable tombstone as absent --
        keeps a revoked grant silently alive, which is the failure mode this
        field exists to remove.
        """
        result = _resolve(_assignment(revoked_at=value))
        assert result.permissions.can_query is False

    def test_naive_timestamp_treated_as_utc(self) -> None:
        """A tombstone without a zone must not raise or be ignored."""
        naive = (datetime.now(timezone.utc) - timedelta(hours=1)).replace(
            tzinfo=None
        ).isoformat()
        result = _resolve(_assignment(revoked_at=naive))
        assert result.permissions.can_query is False

    def test_none_revoked_at_is_not_revoked(self) -> None:
        result = _resolve(_assignment(revoked_at=None))
        assert result.permissions.can_query is True


class TestRevocationDeserialization:
    def test_revoked_at_survives_deserialization(self) -> None:
        """camelCase `revokedAt` from JSON must reach the model."""
        assignment = deserialize_policy_assignment(
            {
                "version": "1.0",
                "policyName": "analyst",
                "assignee": {"type": "user", "identifier": "user-001"},
                "scope": {"tenantId": "tenant-001"},
                "active": True,
                "revokedAt": "2026-01-02T00:00:00Z",
                "audit": {
                    "grantedBy": "admin",
                    "grantedAt": "2026-01-01T00:00:00Z",
                    "reason": "test",
                },
            }
        )
        assert assignment.revoked_at == "2026-01-02T00:00:00Z"

    def test_absent_revoked_at_deserializes_to_none(self) -> None:
        assignment = deserialize_policy_assignment(
            {
                "version": "1.0",
                "policyName": "analyst",
                "assignee": {"type": "user", "identifier": "user-001"},
                "scope": {"tenantId": "tenant-001"},
                "active": True,
                "audit": {
                    "grantedBy": "admin",
                    "grantedAt": "2026-01-01T00:00:00Z",
                    "reason": "test",
                },
            }
        )
        assert assignment.revoked_at is None

    def test_deserialized_revoked_assignment_denies(self) -> None:
        """End-to-end: JSON in, no access out."""
        assignment = deserialize_policy_assignment(
            {
                "version": "1.0",
                "policyName": "analyst",
                "assignee": {"type": "user", "identifier": "user-001"},
                "scope": {"tenantId": "tenant-001"},
                "active": True,
                "revokedAt": "2026-01-02T00:00:00Z",
                "audit": {
                    "grantedBy": "admin",
                    "grantedAt": "2026-01-01T00:00:00Z",
                    "reason": "test",
                },
            }
        )
        assert _resolve(assignment).permissions.can_query is False
