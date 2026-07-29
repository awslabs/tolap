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
// Source-pattern matching (canonical spec §10)
// ---------------------------------------------------------------------------

/**
 * Match a `sourcePatterns` glob against a `sourceConnectionId`.
 *
 * A deliberately *different* glob dialect from {@link globMatch}: source
 * identifiers are `category:namespace:name`, so `*` matches within one segment and
 * must not cross the `:` separator (spec §10). `globMatch` is `/`-oriented — its
 * `*` expands to `[^/]*`, which crosses a colon freely — so reusing it would let
 * `db:*` capture every database source in every namespace, including ones the
 * administrator deliberately left out. Mirrors .NET's
 * `PolicyResolutionEngine.GlobMatch` (`[^:]*`) rather than its
 * `EnforcementEngine.GlobMatch` (`.*`).
 *
 * Matching is case-insensitive. Every other character is literal, so a `.` or `+`
 * in a pattern is not a regex operator.
 */
export function sourcePatternMatch(pattern: string, value: string): boolean {
  const escaped = pattern.replace(/[.*+?^${}()|[\]\\]/g, (ch) =>
    ch === "*" ? "[^:]*" : `\\${ch}`,
  );
  try {
    return new RegExp(`^${escaped}$`, "i").test(value);
  } catch {
    // A pattern that will not compile excludes its policy from the merge rather
    // than throwing out of resolution. A non-match is the fail-closed outcome
    // here: the policy simply does not apply.
    /* c8 ignore next 2 -- every metacharacter is escaped above, so the compiled
       source cannot be invalid; kept as a guard rather than a reachable path. */
    return false;
  }
}

/**
 * Whether a definition applies to the source being resolved (spec §10).
 *
 * Absent or `[]` means source-agnostic: the policy applies everywhere. Note this
 * is the opposite of the `null`-vs-`[]` rule for *allow-lists* (spec §3) — here
 * §10 assigns absent and empty the same "applies to all" meaning, because the
 * common case is a policy that is genuinely not source-scoped.
 *
 * `appliesToAll` short-circuits the check, matching .NET, so a policy asserting
 * "all sources" is not excluded by a leftover pattern list.
 */
function matchesSourcePatterns(
  definition: PolicyDefinition,
  sourceConnectionId: string,
): boolean {
  if (definition.appliesToAll) return true;
  const patterns = definition.sourcePatterns;
  if (patterns === undefined || patterns.length === 0) return true;
  return patterns.some((pattern) =>
    sourcePatternMatch(pattern, sourceConnectionId),
  );
}

// ---------------------------------------------------------------------------
// Identity resolution types
// ---------------------------------------------------------------------------

export type GetGroupsFn = (userId: string) => string[] | Promise<string[]>;
export type GetRolesFn = (userId: string) => string[] | Promise<string[]>;

// ---------------------------------------------------------------------------
// Assignment filtering
// ---------------------------------------------------------------------------

/**
 * Whether an assignment is still active.
 *
 * Expiry fails closed (canonical spec §2): an unparseable `expiresAt` is
 * treated as expired rather than skipped. `new Date("never") <= new Date()` is
 * `false` in JavaScript, so a comparison-only check silently granted a
 * malformed assignment an unbounded lifetime — and unlike a security context,
 * an assignment carries no signature at all, so its expiry string is whatever
 * the store hands back.
 */
function isAssignmentActive(assignment: PolicyAssignment): boolean {
  if (!assignment.active) return false;
  if (assignment.expiresAt !== undefined) {
    if (assignment.expiresAt === "") return false;
    const expires = new Date(assignment.expiresAt);
    if (Number.isNaN(expires.getTime())) return false;
    if (expires.getTime() <= Date.now()) return false;
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

  // Look up definitions, then filter by sourcePatterns (canonical spec §10): a
  // definition whose patterns do not cover this source is excluded BEFORE merging,
  // so its rules cannot fold into an effective policy for a source it was never
  // authored for.
  const policies: PolicyDefinition[] = [];
  for (const assignment of matching) {
    const def = defMap.get(assignment.policyName);
    if (def && matchesSourcePatterns(def, sourceConnectionId)) {
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
