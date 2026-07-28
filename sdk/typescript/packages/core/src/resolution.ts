/**
 * TOLAP Policy Resolution
 *
 * Resolves the effective policy for a specific user + tenant + source connection
 * by filtering applicable assignments, looking up their definitions, and merging.
 */

import {
  type PolicyDefinition,
  type PolicyAssignment,
  type EffectivePolicy,
} from "./types.js";
import { merge } from "./merger.js";

// ---------------------------------------------------------------------------
// Simple glob matching (zero dependencies)
// ---------------------------------------------------------------------------

/**
 * Convert a simple glob pattern to a RegExp.
 * Supports `*` (match any segment chars except `/`), `**` (match anything
 * including `/`), and `?` (match single char).
 */
export function globToRegex(pattern: string): RegExp {
  let regex = "";
  let i = 0;
  while (i < pattern.length) {
    const ch = pattern[i];
    if (ch === "*") {
      if (pattern[i + 1] === "*") {
        // ** matches everything including path separators
        regex += ".*";
        i += 2;
        // consume trailing /
        if (pattern[i] === "/") i++;
        continue;
      }
      // * matches everything except /
      regex += "[^/]*";
    } else if (ch === "?") {
      regex += "[^/]";
    } else if (
      ch === "." ||
      ch === "+" ||
      ch === "^" ||
      ch === "$" ||
      ch === "{" ||
      ch === "}" ||
      ch === "(" ||
      ch === ")" ||
      ch === "|" ||
      ch === "[" ||
      ch === "]" ||
      ch === "\\"
    ) {
      regex += "\\" + ch;
    } else {
      regex += ch;
    }
    i++;
  }
  return new RegExp("^" + regex + "$");
}

/**
 * Test whether a string matches a simple glob pattern.
 */
export function globMatch(pattern: string, value: string): boolean {
  return globToRegex(pattern).test(value);
}

// ---------------------------------------------------------------------------
// Identity resolution types
// ---------------------------------------------------------------------------

export type GetGroupsFn = (userId: string) => string[] | Promise<string[]>;
export type GetRolesFn = (userId: string) => string[] | Promise<string[]>;

// ---------------------------------------------------------------------------
// Assignment filtering
// ---------------------------------------------------------------------------

function isAssignmentActive(assignment: PolicyAssignment): boolean {
  if (!assignment.active) return false;
  if (assignment.expiresAt) {
    const expires = new Date(assignment.expiresAt);
    if (expires <= new Date()) return false;
  }
  return true;
}

function assignmentMatchesScope(
  assignment: PolicyAssignment,
  tenantId: string,
  sourceConnectionId: string,
): boolean {
  if (assignment.scope.tenantId && assignment.scope.tenantId !== tenantId) {
    return false;
  }
  if (
    assignment.scope.sourceConnectionId &&
    assignment.scope.sourceConnectionId !== sourceConnectionId
  ) {
    return false;
  }
  return true;
}

function assignmentMatchesIdentity(
  assignment: PolicyAssignment,
  userId: string,
  groups: string[],
  roles: string[],
): boolean {
  const { type, identifier } = assignment.assignee;
  switch (type) {
    case "user":
      return identifier === userId;
    case "group":
      return groups.includes(identifier);
    case "role":
      return roles.includes(identifier);
    case "serviceAccount":
      return identifier === userId;
    default:
      return false;
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Resolve the effective policy for a user given their assignments and
 * available definitions.
 *
 * @param userId - The user identifier
 * @param tenantId - The tenant context
 * @param sourceConnectionId - The data source connection
 * @param assignments - All policy assignments to consider
 * @param definitions - All available policy definitions (keyed by name)
 * @param getGroups - Returns groups the user belongs to
 * @param getRoles - Returns roles the user holds
 * @param ttlMs - Time-to-live in milliseconds for the effective policy (default 3600000 = 1h)
 */
export async function resolve(
  userId: string,
  tenantId: string,
  sourceConnectionId: string,
  assignments: PolicyAssignment[],
  definitions: Map<string, PolicyDefinition> | Record<string, PolicyDefinition>,
  getGroups: GetGroupsFn = () => [],
  getRoles: GetRolesFn = () => [],
  ttlMs: number = 3_600_000,
): Promise<EffectivePolicy> {
  const defMap =
    definitions instanceof Map
      ? definitions
      : new Map(Object.entries(definitions));

  // Resolve identity
  const groups = await getGroups(userId);
  const roles = await getRoles(userId);

  // Filter matching assignments
  const matching = assignments.filter(
    (a) =>
      isAssignmentActive(a) &&
      assignmentMatchesScope(a, tenantId, sourceConnectionId) &&
      assignmentMatchesIdentity(a, userId, groups, roles),
  );

  // Look up definitions
  const policies: PolicyDefinition[] = [];
  for (const assignment of matching) {
    const def = defMap.get(assignment.policyName);
    if (def) {
      policies.push(def);
    }
  }

  // Merge
  const merged = merge(policies);

  const now = new Date();
  const expiresAt = new Date(now.getTime() + ttlMs);

  return {
    version: "1.0",
    userId,
    tenantId,
    sourceConnectionId,
    resolvedAt: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
    sourceProfiles: merged.sourceProfiles,
    permissions: merged.permissions,
    ...(merged.objectRules ? { objectRules: merged.objectRules } : {}),
    ...(merged.limits ? { limits: merged.limits } : {}),
    integrity: {
      algorithm: "none",
      signature: "",
    },
  };
}
