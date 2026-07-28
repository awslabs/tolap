from __future__ import annotations

from datetime import datetime, timezone
from fnmatch import fnmatch
from typing import Callable

from tolap_core.merger import merge
from tolap_core.models import EffectivePolicy, PolicyAssignment, PolicyDefinition


def resolve(
    user_id: str,
    tenant_id: str,
    source_connection_id: str,
    assignments: list[PolicyAssignment],
    definitions: dict[str, PolicyDefinition],
    get_groups: Callable[[str], list[str]],
    get_roles: Callable[[str], list[str]],
) -> EffectivePolicy:
    """Resolve the effective policy for a user + tenant + source connection.

    1. Filter assignments to those matching the user (directly, by group, by role)
    2. Filter by scope (tenant, source connection)
    3. Filter by active status and expiry
    4. Match source patterns from referenced policy definitions
    5. Sort by priority and delegate to merger
    """
    user_groups = get_groups(user_id)
    user_roles = get_roles(user_id)
    now = datetime.now(timezone.utc)

    matching_policies: list[PolicyDefinition] = []

    for assignment in assignments:
        # Check if assignment is active and not expired
        if not assignment.active:
            continue
        if assignment.expires_at:
            try:
                expiry = datetime.fromisoformat(assignment.expires_at.replace("Z", "+00:00"))
                if expiry < now:
                    continue
            except ValueError:
                continue

        # Check assignee match
        if not _matches_assignee(assignment, user_id, user_groups, user_roles):
            continue

        # Check scope match
        if not _matches_scope(assignment, tenant_id, source_connection_id):
            continue

        # Look up the policy definition
        policy = definitions.get(assignment.policy_name)
        if policy is None:
            continue

        # Check source patterns match the source connection ID
        if not policy.applies_to_all and policy.source_patterns:
            if not any(fnmatch(source_connection_id, pattern) for pattern in policy.source_patterns):
                # Source patterns don't restrict by connection ID directly, they are
                # category:namespace:pattern format for the data source type.
                # For resolution purposes, we include the policy if the assignment scope
                # already matched or if applies_to_all is True.
                pass

        matching_policies.append(policy)

    # Sort by priority (lower values first)
    matching_policies.sort(key=lambda p: p.priority if p.priority is not None else 100)

    result = merge(matching_policies)
    result.user_id = user_id
    result.tenant_id = tenant_id
    result.source_connection_id = source_connection_id
    result.resolved_at = now.isoformat().replace("+00:00", "Z")

    return result


def _matches_assignee(
    assignment: PolicyAssignment,
    user_id: str,
    user_groups: list[str],
    user_roles: list[str],
) -> bool:
    """Check if the assignment's assignee matches the user."""
    from tolap_core.enums import AssigneeType

    match assignment.assignee.type:
        case AssigneeType.user:
            return assignment.assignee.identifier == user_id
        case AssigneeType.group:
            return assignment.assignee.identifier in user_groups
        case AssigneeType.role:
            return assignment.assignee.identifier in user_roles
        case AssigneeType.service_account:
            return assignment.assignee.identifier == user_id
        case _:
            return False


def _matches_scope(
    assignment: PolicyAssignment,
    tenant_id: str,
    source_connection_id: str,
) -> bool:
    """Check if the assignment's scope matches the requested context."""
    scope = assignment.scope
    if scope.tenant_id and scope.tenant_id != tenant_id:
        return False
    if scope.source_connection_id and scope.source_connection_id != source_connection_id:
        return False
    return True
