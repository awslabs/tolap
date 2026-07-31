/**
 * TOLAP Policy Merger
 *
 * Merges multiple PolicyDefinitions into a single EffectivePolicy.
 *
 * Merge rules:
 *   - Permissions: AND for canQuery/canInsert/canUpdate/canDelete,
 *     OR for readOnly. Absent booleans take their schema default first
 *     (canQuery true, the write permissions false, readOnly true).
 *   - Allowed sets (objects, fields, endpoints, tags, methods): intersection
 *   - Hidden/denied sets: union
 *   - Row filters: concatenation (AND logic)
 *   - Masked fields: group by field, pick most restrictive mask type
 *   - Limits: Math.min for maxima, Math.max for minima
 */

import {
  type PolicyDefinition,
  type EffectivePolicy,
  type ObjectRules,
  type FieldRules,
  type TagRules,
  type EndpointRules,
  type PolicyLimits,
  type PolicyPermissions,
  type MaskingRule,
  type RowFilter,
  maskRestrictiveness,
} from "./types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Intersect optional arrays. If a policy does not define the array (undefined),
 * it means "unrestricted" -- i.e. it does not constrain the set.
 * - If all inputs are undefined, the result is undefined (unrestricted).
 * - If some define the array and some do not, only the defined sets are intersected.
 */
function intersectOptional(
  sets: Array<string[] | undefined>,
): string[] | undefined {
  const defined = sets.filter(
    (s): s is string[] => s !== undefined,
  );
  if (defined.length === 0) return undefined;
  if (defined.length === 1) return [...defined[0]];

  let result = new Set(defined[0]);
  for (let i = 1; i < defined.length; i++) {
    const next = new Set(defined[i]);
    result = new Set([...result].filter((item) => next.has(item)));
  }
  return [...result];
}

/**
 * Union multiple optional arrays. Undefined entries are skipped.
 * If all are undefined, returns undefined.
 */
function unionArrays(
  arrays: Array<string[] | undefined>,
): string[] | undefined {
  const defined = arrays.filter(
    (a): a is string[] => a !== undefined,
  );
  if (defined.length === 0) return undefined;
  const set = new Set<string>();
  for (const arr of defined) {
    for (const item of arr) {
      set.add(item);
    }
  }
  return [...set];
}

// ---------------------------------------------------------------------------
// Sub-mergers
// ---------------------------------------------------------------------------

/**
 * Fold the permission flags, defaulting absent values before folding.
 *
 * The three write permissions default to `false` and fold with AND, so *every*
 * applicable policy has to grant a write for the merged policy to. `readOnly` keeps
 * its `true` default and its OR fold, so *any* policy can impose the ceiling. Both
 * directions therefore compose most-restrictively, and the asymmetry with `canQuery`
 * (default `true`) is intentional: a policy written before writes existed must not
 * silently acquire them (connector spec §4.1).
 *
 * Defaulting rather than skipping an absent flag is load-bearing: excluding it from
 * the fold inverts the outcome, so a policy silent on `readOnly` merged with one
 * setting `readOnly: false` must yield `true` (canonical spec §8).
 */
function mergePermissions(policies: PolicyDefinition[]): PolicyPermissions {
  let canQuery = true;
  let canInsert = true;
  let canUpdate = true;
  let canDelete = true;
  let readOnly = false;

  for (const p of policies) {
    canQuery = canQuery && p.permissions.canQuery;
    canInsert = canInsert && (p.permissions.canInsert ?? false);
    canUpdate = canUpdate && (p.permissions.canUpdate ?? false);
    canDelete = canDelete && (p.permissions.canDelete ?? false);
    readOnly = readOnly || (p.permissions.readOnly ?? true);
  }

  return { canQuery, canInsert, canUpdate, canDelete, readOnly };
}

function mergeMaskedFields(
  allMasked: Array<MaskingRule[] | undefined>,
): MaskingRule[] | undefined {
  const defined = allMasked.filter(
    (m): m is MaskingRule[] => m !== undefined,
  );
  if (defined.length === 0) return undefined;

  const byField = new Map<string, MaskingRule>();
  for (const rules of defined) {
    for (const rule of rules) {
      const existing = byField.get(rule.field);
      if (!existing) {
        byField.set(rule.field, { ...rule });
      } else {
        // An unknown mask type ranks most-restrictive (see maskRestrictiveness)
        // so a typo cannot be downgraded into a weaker known type.
        const existingScore = maskRestrictiveness(existing.maskType);
        const newScore = maskRestrictiveness(rule.maskType);
        if (newScore > existingScore) {
          byField.set(rule.field, { ...rule });
        }
      }
    }
  }

  const result = [...byField.values()];
  return result.length > 0 ? result : undefined;
}

function mergeFieldRules(
  allFieldRules: Array<FieldRules | undefined>,
): FieldRules | undefined {
  const defined = allFieldRules.filter(
    (fr): fr is FieldRules => fr !== undefined,
  );
  if (defined.length === 0) return undefined;

  const result: FieldRules = {};

  const allowedFields = intersectOptional(
    defined.map((fr) => fr.allowedFields),
  );
  if (allowedFields !== undefined) result.allowedFields = allowedFields;

  const hiddenFields = unionArrays(defined.map((fr) => fr.hiddenFields));
  if (hiddenFields !== undefined) result.hiddenFields = hiddenFields;

  const maskedFields = mergeMaskedFields(
    defined.map((fr) => fr.maskedFields),
  );
  if (maskedFields !== undefined) result.maskedFields = maskedFields;

  const readOnlyFields = unionArrays(
    defined.map((fr) => fr.readOnlyFields),
  );
  if (readOnlyFields !== undefined) result.readOnlyFields = readOnlyFields;

  return Object.keys(result).length > 0 ? result : undefined;
}

function mergeTagRules(
  allTagRules: Array<TagRules | undefined>,
): TagRules | undefined {
  const defined = allTagRules.filter(
    (tr): tr is TagRules => tr !== undefined,
  );
  if (defined.length === 0) return undefined;

  const result: TagRules = {};

  const allowedTags = intersectOptional(
    defined.map((tr) => tr.allowedTags),
  );
  if (allowedTags !== undefined) result.allowedTags = allowedTags;

  const deniedTags = unionArrays(defined.map((tr) => tr.deniedTags));
  if (deniedTags !== undefined) result.deniedTags = deniedTags;

  return Object.keys(result).length > 0 ? result : undefined;
}

function mergeEndpointRules(
  allEndpointRules: Array<EndpointRules | undefined>,
): EndpointRules | undefined {
  const defined = allEndpointRules.filter(
    (er): er is EndpointRules => er !== undefined,
  );
  if (defined.length === 0) return undefined;

  const result: EndpointRules = {};

  const allowedEndpoints = intersectOptional(
    defined.map((er) => er.allowedEndpoints),
  );
  if (allowedEndpoints !== undefined) result.allowedEndpoints = allowedEndpoints;

  const hiddenEndpoints = unionArrays(
    defined.map((er) => er.hiddenEndpoints),
  );
  if (hiddenEndpoints !== undefined) result.hiddenEndpoints = hiddenEndpoints;

  const allowedMethods = intersectOptional(
    defined.map((er) => er.allowedMethods),
  );
  if (allowedMethods !== undefined) result.allowedMethods = allowedMethods;

  return Object.keys(result).length > 0 ? result : undefined;
}

function mergeRowFilters(
  allFilters: Array<RowFilter[] | undefined>,
): RowFilter[] | undefined {
  const defined = allFilters.filter(
    (f): f is RowFilter[] => f !== undefined,
  );
  if (defined.length === 0) return undefined;

  const result: RowFilter[] = [];
  for (const filters of defined) {
    result.push(...filters);
  }
  return result.length > 0 ? result : undefined;
}

function mergeObjectRules(
  policies: PolicyDefinition[],
): ObjectRules | undefined {
  const allRules = policies.map((p) => p.objectRules);
  const defined = allRules.filter(
    (or): or is ObjectRules => or !== undefined,
  );
  if (defined.length === 0) return undefined;

  const result: ObjectRules = {};

  const allowedObjects = intersectOptional(
    defined.map((or) => or.allowedObjects),
  );
  if (allowedObjects !== undefined) result.allowedObjects = allowedObjects;

  const hiddenObjects = unionArrays(
    defined.map((or) => or.hiddenObjects),
  );
  if (hiddenObjects !== undefined) result.hiddenObjects = hiddenObjects;

  const fieldRules = mergeFieldRules(
    defined.map((or) => or.fieldRules),
  );
  if (fieldRules !== undefined) result.fieldRules = fieldRules;

  const rowFilters = mergeRowFilters(
    defined.map((or) => or.rowFilters),
  );
  if (rowFilters !== undefined) result.rowFilters = rowFilters;

  const tagRules = mergeTagRules(
    defined.map((or) => or.tagRules),
  );
  if (tagRules !== undefined) result.tagRules = tagRules;

  const endpointRules = mergeEndpointRules(
    defined.map((or) => or.endpointRules),
  );
  if (endpointRules !== undefined) result.endpointRules = endpointRules;

  return Object.keys(result).length > 0 ? result : undefined;
}

function mergeLimits(policies: PolicyDefinition[]): PolicyLimits | undefined {
  const allLimits = policies.map((p) => p.limits);
  const defined = allLimits.filter(
    (l): l is PolicyLimits => l !== undefined,
  );
  if (defined.length === 0) return undefined;

  const result: PolicyLimits = {};

  // For maxima: Math.min (most restrictive)
  const maxResults = defined
    .map((l) => l.maxResults)
    .filter((v): v is number => v !== undefined);
  if (maxResults.length > 0) result.maxResults = Math.min(...maxResults);

  const maxObjectSizeBytes = defined
    .map((l) => l.maxObjectSizeBytes)
    .filter((v): v is number => v !== undefined);
  if (maxObjectSizeBytes.length > 0)
    result.maxObjectSizeBytes = Math.min(...maxObjectSizeBytes);

  // For minima: Math.max (most restrictive)
  const minSimilarityScore = defined
    .map((l) => l.minSimilarityScore)
    .filter((v): v is number => v !== undefined);
  if (minSimilarityScore.length > 0)
    result.minSimilarityScore = Math.max(...minSimilarityScore);

  return Object.keys(result).length > 0 ? result : undefined;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Merge result -- contains the merged data without EffectivePolicy envelope
 * fields (userId, tenantId, etc.) since those are added during resolution.
 */
export interface MergeResult {
  sourceProfiles: string[];
  permissions: PolicyPermissions;
  objectRules?: ObjectRules;
  limits?: PolicyLimits;
}

/**
 * Merge multiple PolicyDefinitions into a single MergeResult.
 */
export function merge(policies: PolicyDefinition[]): MergeResult {
  if (policies.length === 0) {
    return {
      sourceProfiles: [],
      permissions: {
        canQuery: false,
        readOnly: true,
      },
    };
  }

  // Sort by priority (lower = higher precedence) for deterministic ordering
  const sorted = [...policies].sort(
    (a, b) => (a.priority ?? 100) - (b.priority ?? 100),
  );

  const sourceProfiles = sorted.map((p) => p.name);
  const permissions = mergePermissions(sorted);
  const objectRules = mergeObjectRules(sorted);
  const limits = mergeLimits(sorted);

  const result: MergeResult = { sourceProfiles, permissions };
  if (objectRules !== undefined) result.objectRules = objectRules;
  if (limits !== undefined) result.limits = limits;

  return result;
}
