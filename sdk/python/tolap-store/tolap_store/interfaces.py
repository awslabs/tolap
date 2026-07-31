from __future__ import annotations

from typing import Protocol

from tolap_core.models import EffectivePolicy, PolicyAssignment, PolicyDefinition


class PolicyStore(Protocol):
    """Protocol for policy storage backends."""

    def get_definition(self, name: str) -> PolicyDefinition | None:
        """Retrieve a policy definition by name."""
        ...

    def list_definitions(self) -> list[PolicyDefinition]:
        """List all policy definitions."""
        ...

    def save_definition(self, definition: PolicyDefinition) -> None:
        """Save or update a policy definition."""
        ...

    def delete_definition(self, name: str) -> bool:
        """Delete a policy definition by name. Returns True if deleted."""
        ...

    def get_assignments(self, user_id: str, tenant_id: str) -> list[PolicyAssignment]:
        """Get all assignments applicable to a user in a tenant."""
        ...

    def save_assignment(self, assignment: PolicyAssignment) -> None:
        """Save or update a policy assignment."""
        ...

    def delete_assignment(self, policy_name: str, assignee_identifier: str) -> bool:
        """Delete an assignment. Returns True if deleted."""
        ...

    def resolve_policy(
        self,
        user_id: str,
        tenant_id: str,
        source_connection_id: str,
    ) -> EffectivePolicy:
        """Resolve the effective policy for a user, tenant, and source."""
        ...


class IdentityResolver(Protocol):
    """Protocol for resolving user identity attributes (groups, roles)."""

    def get_groups(self, user_id: str) -> list[str]:
        """Return the group identifiers the user belongs to."""
        ...

    def get_roles(self, user_id: str) -> list[str]:
        """Return the role identifiers assigned to the user."""
        ...
