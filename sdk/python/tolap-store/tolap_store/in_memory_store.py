from __future__ import annotations

import threading
from typing import Callable

from tolap_core.models import EffectivePolicy, PolicyAssignment, PolicyDefinition
from tolap_core.resolution import resolve

from tolap_store.audit import PolicyAuditEvent
from tolap_store.interfaces import IdentityResolver


class InMemoryPolicyStore:
    """Thread-safe in-memory implementation of the PolicyStore protocol.

    Fires audit events via an optional callback.
    """

    def __init__(
        self,
        identity_resolver: IdentityResolver,
        on_audit: Callable[[PolicyAuditEvent], None] | None = None,
    ) -> None:
        self._lock = threading.Lock()
        self._definitions: dict[str, PolicyDefinition] = {}
        self._assignments: list[PolicyAssignment] = []
        self._identity_resolver = identity_resolver
        self._on_audit = on_audit
        self._audit_log: list[PolicyAuditEvent] = []

    def _emit_audit(self, event: PolicyAuditEvent) -> None:
        self._audit_log.append(event)
        if self._on_audit:
            self._on_audit(event)

    @property
    def audit_log(self) -> list[PolicyAuditEvent]:
        with self._lock:
            return list(self._audit_log)

    def get_definition(self, name: str) -> PolicyDefinition | None:
        with self._lock:
            return self._definitions.get(name)

    def list_definitions(self) -> list[PolicyDefinition]:
        with self._lock:
            return list(self._definitions.values())

    def save_definition(self, definition: PolicyDefinition) -> None:
        with self._lock:
            is_update = definition.name in self._definitions
            self._definitions[definition.name] = definition
            event_type = "definition_updated" if is_update else "definition_created"
            self._emit_audit(PolicyAuditEvent.create(
                event_type=event_type,
                details=f"Policy definition '{definition.name}' {'updated' if is_update else 'created'}",
                policy_name=definition.name,
            ))

    def delete_definition(self, name: str) -> bool:
        with self._lock:
            if name in self._definitions:
                del self._definitions[name]
                self._emit_audit(PolicyAuditEvent.create(
                    event_type="definition_deleted",
                    details=f"Policy definition '{name}' deleted",
                    policy_name=name,
                ))
                return True
            return False

    def get_assignments(self, user_id: str, tenant_id: str) -> list[PolicyAssignment]:
        with self._lock:
            return [
                a for a in self._assignments
                if self._assignment_matches_user(a, user_id)
                and (a.scope.tenant_id is None or a.scope.tenant_id == tenant_id)
            ]

    def _assignment_matches_user(self, assignment: PolicyAssignment, user_id: str) -> bool:
        from tolap_core.enums import AssigneeType

        match assignment.assignee.type:
            case AssigneeType.user:
                return assignment.assignee.identifier == user_id
            case AssigneeType.group:
                groups = self._identity_resolver.get_groups(user_id)
                return assignment.assignee.identifier in groups
            case AssigneeType.role:
                roles = self._identity_resolver.get_roles(user_id)
                return assignment.assignee.identifier in roles
            case AssigneeType.service_account:
                return assignment.assignee.identifier == user_id
            case _:
                return False

    def save_assignment(self, assignment: PolicyAssignment) -> None:
        with self._lock:
            # Replace if same policy_name + assignee
            key = (assignment.policy_name, assignment.assignee.identifier)
            self._assignments = [
                a for a in self._assignments
                if (a.policy_name, a.assignee.identifier) != key
            ]
            self._assignments.append(assignment)
            self._emit_audit(PolicyAuditEvent.create(
                event_type="assignment_saved",
                details=f"Assignment for policy '{assignment.policy_name}' to '{assignment.assignee.identifier}' saved",
                policy_name=assignment.policy_name,
                assignee_identifier=assignment.assignee.identifier,
            ))

    def delete_assignment(self, policy_name: str, assignee_identifier: str) -> bool:
        with self._lock:
            key = (policy_name, assignee_identifier)
            before = len(self._assignments)
            self._assignments = [
                a for a in self._assignments
                if (a.policy_name, a.assignee.identifier) != key
            ]
            deleted = len(self._assignments) < before
            if deleted:
                self._emit_audit(PolicyAuditEvent.create(
                    event_type="assignment_deleted",
                    details=f"Assignment for policy '{policy_name}' to '{assignee_identifier}' deleted",
                    policy_name=policy_name,
                    assignee_identifier=assignee_identifier,
                ))
            return deleted

    def resolve_policy(
        self,
        user_id: str,
        tenant_id: str,
        source_connection_id: str,
    ) -> EffectivePolicy:
        with self._lock:
            assignments = list(self._assignments)
            definitions = dict(self._definitions)

        result = resolve(
            user_id=user_id,
            tenant_id=tenant_id,
            source_connection_id=source_connection_id,
            assignments=assignments,
            definitions=definitions,
            get_groups=self._identity_resolver.get_groups,
            get_roles=self._identity_resolver.get_roles,
        )

        self._emit_audit(PolicyAuditEvent.create(
            event_type="policy_resolved",
            details=f"Policy resolved for user '{user_id}' in tenant '{tenant_id}' for source '{source_connection_id}'",
            user_id=user_id,
        ))

        return result
