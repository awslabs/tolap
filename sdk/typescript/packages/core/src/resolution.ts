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
// Enforcement glob matching (zero dependencies)
// ---------------------------------------------------------------------------
//
// This is the *enforcement* glob dialect: objects, fields, endpoints and storage
// prefixes. It is deliberately NOT the dialect `sourcePatternMatch` below uses, and
// the difference is load-bearing (spec §3.1). Do not unify them — see the note on
// `sourcePatternMatch` for what each direction breaks.

/**
 * Characters that must be escaped so a glob is a glob and not a regex.
 *
 * `[` and `]` are included, so a bracket in a pattern is a literal bracket rather
 * than a character class. That mirrors .NET's `EnforcementEngine.GlobMatch`, which
 * `Regex.Escape`s before expanding `*`, and it is the fail-closed reading: a literal
 * `[` matches strictly fewer names than a character class would, so an
 * `allowedObjects` entry cannot silently reach objects the administrator never
 * spelled out.
 */
const GLOB_METACHARACTERS = /[.+^$(){}|[\]\\]/;

/**
 * Convert an enforcement glob pattern to a RegExp (spec §3.1).
 *
 * `*` matches **any** run of characters, crossing every separator including `/` and
 * `.`; `?` matches exactly one character, also crossing separators. Every other
 * character is literal. The returned RegExp carries the `i` and `s` flags, so
 * matching is case-insensitive and a `*` spans a newline.
 *
 * Both properties are parity requirements rather than preferences:
 *
 * - **Case-insensitivity** closes a fail-open hole. Without the `i` flag,
 *   `hiddenObjects: ["patients"]` did not hide an object named `PATIENTS`, so a
 *   table Python and .NET both denied was reachable in TypeScript purely by case.
 *   Spec §3.1: "All enforcement matching is case-insensitive and
 *   platform-independent."
 * - **Crossing separators** closes a fail-closed divergence. `*` previously
 *   compiled to `[^/]*`, so `allowedEndpoints: ["/api/*"]` denied `/api/v1/x` that
 *   the same signed policy allowed under Python. The same policy must grant the
 *   same access in every SDK; §3.1 gives the worked example
 *   (`/api/v1/patients/*` reaches `/api/v1/patients/123/labs` but not the bare
 *   collection `/api/v1/patients`).
 *
 * `**` is accepted but is now a plain alias for `*`: once `*` crosses everything
 * there is nothing left for a second star to widen. Runs of consecutive stars are
 * collapsed to one `.*` rather than emitted as several, which keeps the compiled
 * source free of the adjacent-quantifier shapes that backtrack badly. Patterns in
 * the wild that spell `**` therefore keep working and mean exactly what they did.
 *
 * Mirrors Python's `_pattern_matches` (`fnmatchcase` over pre-lowered strings) and
 * .NET's `EnforcementEngine.GlobMatch` (`Regex.Escape` + `\* -> .*`,
 * `RegexOptions.IgnoreCase`). Python's choice of `fnmatchcase` over `fnmatch` is
 * itself deliberate: `fnmatch` applies `os.path.normcase`, which made the same
 * signed policy decide differently on Windows than on Linux.
 */
export function globToRegex(pattern: string): RegExp {
  let regex = "";
  let i = 0;
  while (i < pattern.length) {
    const ch = pattern[i];
    if (ch === "*") {
      // Collapse `*`, `**`, `***`… to a single `.*`. `**` is a historical alias:
      // `*` already crosses every separator, so a second star adds nothing.
      while (pattern[i] === "*") i++;
      regex += ".*";
      continue;
    }
    if (ch === "?") {
      // One character, separators included, matching Python's `?` -> `.` under
      // `(?s:…)`. `[^/]` would have made `?` the only enforcement wildcard that
      // still respected a path boundary.
      regex += ".";
    } else if (GLOB_METACHARACTERS.test(ch)) {
      regex += "\\" + ch;
    } else {
      regex += ch;
    }
    i++;
  }
  // `i`: case-insensitive (§3.1). `s`: `.` spans a newline, so `*` crosses one too,
  // which is what Python's `(?s:…)` wrapper does.
  return new RegExp("^" + regex + "$", "is");
}

/**
 * Test whether a string matches an enforcement glob pattern (spec §3.1).
 *
 * Case-insensitive, and `*` crosses every separator. For `sourcePatterns` use
 * {@link sourcePatternMatch} instead — its `*` must not cross `:`.
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
 * A deliberately *different* glob dialect from {@link globMatch}, and the two must
 * not be unified (spec §3.1 tabulates the split). Source identifiers are
 * `category:namespace:name`, so `*` matches within one segment and must not cross
 * the `:` separator (spec §10). `globMatch` is the enforcement dialect — its `*`
 * expands to `.*` and crosses every separator, a colon included — so reusing it
 * would let `db:*` capture every database source in every namespace, including ones
 * the administrator deliberately left out. Mirrors .NET's
 * `PolicyResolutionEngine.GlobMatch` (`[^:]*`) rather than its
 * `EnforcementEngine.GlobMatch` (`.*`).
 *
 * Unifying on `.*` would silently widen every source-scoped policy; unifying on
 * `[^:]*` would break endpoint and prefix rules. Tests pin both directions.
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
