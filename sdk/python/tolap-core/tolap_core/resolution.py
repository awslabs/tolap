from __future__ import annotations

import functools
import re
from datetime import datetime, timezone
from typing import Callable

from tolap_core.merger import merge
from tolap_core.models import EffectivePolicy, PolicyAssignment, PolicyDefinition


# Source-pattern globbing. Bounded like the row-filter patterns for the same
# reason: Python's re has no evaluation timeout, so an over-long pattern is a
# non-match rather than an unbounded backtracking search.
_MAX_SOURCE_PATTERN_LENGTH = 1024


@functools.lru_cache(maxsize=256)
def _compile_source_pattern(pattern: str) -> re.Pattern[str] | None:
    """Compile a `category:namespace:pattern` glob, or None if it is unusable.

    ``*`` matches within a segment and does not cross the ``:`` separator, so it
    translates to ``[^:]*`` rather than ``.*`` (spec section 10). Every other
    character is escaped, so a pattern is a glob and never a regex: a literal
    ``.``, ``+`` or ``?`` in a source name cannot widen the match. This is why
    ``fnmatch`` is unsuitable here -- it maps ``*`` to ``.*``, which would let
    ``db:*`` govern every namespace under ``db``.

    Matching is case-insensitive per spec section 10.
    """
    if len(pattern) > _MAX_SOURCE_PATTERN_LENGTH:
        return None
    translated = re.escape(pattern).replace(r"\*", "[^:]*")
    try:
        return re.compile(f"^(?:{translated})$", re.IGNORECASE)
    except re.error:  # pragma: no cover - re.escape output always compiles
        return None


def _matches_source_patterns(
    policy: PolicyDefinition,
    source_connection_id: str,
) -> bool:
    """Whether a definition applies to the source being resolved (spec section 10).

    Absent or empty ``source_patterns`` means the policy is source-agnostic and
    applies to every data source -- note this is the *opposite* of the section 3
    rule for allow-lists, where ``[]`` denies everything. A non-empty list applies
    only when one pattern matches, and a definition that matches none is excluded
    before merging: a policy scoped to ``db:production:*`` must not contribute its
    rules to an unrelated API or knowledge-base source.

    ``applies_to_all`` overrides the patterns entirely, matching the .NET
    reference implementation.
    """
    if policy.applies_to_all:
        return True
    if not policy.source_patterns:
        return True

    for pattern in policy.source_patterns:
        compiled = _compile_source_pattern(pattern)
        # An unusable pattern excludes its policy rather than admitting it: a
        # source pattern that cannot be evaluated is a non-match, which is the
        # fail-closed direction here.
        if compiled is not None and compiled.match(source_connection_id):
            return True
    return False


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

    Step 4 excludes a definition whose ``source_patterns`` do not cover
    ``source_connection_id`` (spec section 10), so the effective policy for a source
    is assembled only from rules intended to apply to it.
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

        # Check the definition applies to this data source (spec section 10). A
        # definition scoped to other sources is excluded before merging, so its
        # rules cannot leak into -- or restrict -- a source it never covered.
        if not _matches_source_patterns(policy, source_connection_id):
            continue

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
