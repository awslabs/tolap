/**
 * TOLAP Enforcement Functions
 *
 * Runtime enforcement of effective policies against data access operations.
 */

import { createHash } from "node:crypto";
import {
  type EffectivePolicy,
  type AccessResult,
  type FieldAccessResult,
  type MaskingRule,
  type RowFilter,
} from "./types.js";
import { globToRegex } from "./resolution.js";

// ---------------------------------------------------------------------------
// Glob matching helper (reuses resolution.ts implementation)
// ---------------------------------------------------------------------------

function matchesGlob(pattern: string, value: string): boolean {
  return globToRegex(pattern).test(value);
}

function matchesAnyGlob(patterns: string[], value: string): boolean {
  return patterns.some((p) => matchesGlob(p, value));
}

// ---------------------------------------------------------------------------
// Object access
// ---------------------------------------------------------------------------

/**
 * Validate whether an object (table, endpoint, KB, etc.) can be accessed
 * under the given effective policy.
 */
export function validateAccess(
  objectName: string,
  policy: EffectivePolicy,
): AccessResult {
  if (!policy.permissions.canQuery) {
    return { allowed: false, reason: "query not permitted" };
  }

  const rules = policy.objectRules;
  if (!rules) return { allowed: true };

  // Hidden objects always take precedence
  if (rules.hiddenObjects && matchesAnyGlob(rules.hiddenObjects, objectName)) {
    return { allowed: false, reason: "object is hidden" };
  }

  // If allowedObjects is defined, object must be in it
  if (rules.allowedObjects) {
    if (!matchesAnyGlob(rules.allowedObjects, objectName)) {
      return { allowed: false, reason: "object not in allowed set" };
    }
  }

  return { allowed: true };
}

// ---------------------------------------------------------------------------
// Field access
// ---------------------------------------------------------------------------

/**
 * Validate which fields can be accessed under the given effective policy.
 */
export function validateFieldAccess(
  fields: string[],
  policy: EffectivePolicy,
): FieldAccessResult {
  const allowed: string[] = [];
  const denied: string[] = [];

  const fieldRules = policy.objectRules?.fieldRules;

  for (const field of fields) {
    // Hidden fields are always denied
    if (
      fieldRules?.hiddenFields &&
      matchesAnyGlob(fieldRules.hiddenFields, field)
    ) {
      denied.push(field);
      continue;
    }

    // If allowedFields is defined, field must be in it
    if (fieldRules?.allowedFields) {
      if (matchesAnyGlob(fieldRules.allowedFields, field)) {
        allowed.push(field);
      } else {
        denied.push(field);
      }
      continue;
    }

    // No restrictions: allow
    allowed.push(field);
  }

  return { allowed, denied };
}

// ---------------------------------------------------------------------------
// Masking implementations
// ---------------------------------------------------------------------------

function applyMask(value: unknown, rule: MaskingRule): unknown {
  switch (rule.maskType) {
    case "full":
      return applyFullMask(value, rule);
    case "partial":
      return applyPartialMask(value, rule);
    case "hash":
      return applyHashMask(value, rule);
    case "null":
      return null;
    case "redact":
      return "[REDACTED]";
    default:
      return value;
  }
}

function applyFullMask(value: unknown, rule: MaskingRule): string {
  const str = String(value);
  const maskChar = rule.parameters?.maskChar ?? "*";
  return maskChar.repeat(str.length);
}

function applyPartialMask(value: unknown, rule: MaskingRule): string {
  const str = String(value);
  const showFirst = rule.parameters?.showFirst ?? 0;
  const showLast = rule.parameters?.showLast ?? 0;
  const maskChar = rule.parameters?.maskChar ?? "*";

  if (showFirst + showLast >= str.length) {
    return str;
  }

  const prefix = str.slice(0, showFirst);
  const suffix = showLast > 0 ? str.slice(-showLast) : "";
  const maskedLength = str.length - showFirst - showLast;
  return prefix + maskChar.repeat(maskedLength) + suffix;
}

function applyHashMask(value: unknown, rule: MaskingRule): string {
  const str = String(value);
  const algorithm = rule.parameters?.algorithm ?? "sha256";
  const hash = createHash(algorithm).update(str).digest("hex");
  // Truncate to 16 hex chars to match Python and .NET SDKs.
  return hash.slice(0, 16);
}

// ---------------------------------------------------------------------------
// Field masking
// ---------------------------------------------------------------------------

/**
 * Apply field masking to a record according to the effective policy.
 * Returns a new record with masked values.
 */
export function applyFieldMasking(
  record: Record<string, unknown>,
  policy: EffectivePolicy,
): Record<string, unknown> {
  const maskedFields = policy.objectRules?.fieldRules?.maskedFields;
  if (!maskedFields || maskedFields.length === 0) return { ...record };

  const result: Record<string, unknown> = { ...record };

  for (const rule of maskedFields) {
    // Support both "field" and "object.field" notation; for dotted names,
    // match against the leaf segment (matches Python apply_field_masking).
    const fieldName = rule.field.includes(".")
      ? rule.field.slice(rule.field.indexOf(".") + 1)
      : rule.field;
    if (fieldName in result) {
      result[fieldName] = applyMask(result[fieldName], rule);
    }
  }

  return result;
}

// ---------------------------------------------------------------------------
// Result limiting
// ---------------------------------------------------------------------------

/**
 * Apply the maxResults limit from the effective policy.
 */
export function applyResultLimit<T>(
  results: T[],
  policy: EffectivePolicy,
): T[] {
  const maxResults = policy.limits?.maxResults;
  if (maxResults !== undefined && results.length > maxResults) {
    return results.slice(0, maxResults);
  }
  return results;
}

// ---------------------------------------------------------------------------
// Row filters
// ---------------------------------------------------------------------------

function rowFieldValue(
  row: Record<string, unknown>,
  fieldName: string,
): unknown {
  if (fieldName in row) return row[fieldName];
  if (fieldName.includes(".")) {
    const leaf = fieldName.slice(fieldName.indexOf(".") + 1);
    return row[leaf];
  }
  return undefined;
}

function rowPassesFilter(
  row: Record<string, unknown>,
  rf: RowFilter,
): boolean {
  const value = rowFieldValue(row, rf.field);
  switch (rf.operator) {
    case "equals":
      return value === rf.value;
    case "notEquals":
      return value !== rf.value;
    case "in":
      return Array.isArray(rf.values) && rf.values.includes(value);
    case "notIn":
      return Array.isArray(rf.values) && !rf.values.includes(value);
    case "greaterThan":
      return (
        value !== undefined &&
        value !== null &&
        rf.value !== undefined &&
        rf.value !== null &&
        (value as number) > (rf.value as number)
      );
    case "lessThan":
      return (
        value !== undefined &&
        value !== null &&
        rf.value !== undefined &&
        rf.value !== null &&
        (value as number) < (rf.value as number)
      );
    case "contains":
      return (
        value !== undefined &&
        value !== null &&
        rf.value !== undefined &&
        rf.value !== null &&
        String(value).includes(String(rf.value))
      );
    case "startsWith":
      return (
        value !== undefined &&
        value !== null &&
        rf.value !== undefined &&
        rf.value !== null &&
        String(value).startsWith(String(rf.value))
      );
    case "matches":
      if (
        value === undefined ||
        value === null ||
        rf.value === undefined ||
        rf.value === null
      ) {
        return false;
      }
      try {
        // Anchor with ^...$ to match Python's re.fullmatch semantics.
        return new RegExp(`^${String(rf.value)}$`).test(String(value));
      } catch {
        return false;
      }
    default:
      return false;
  }
}

/**
 * Drop rows that fail any policy row filter (filters AND together).
 *
 * Most-restrictive-wins: a row must satisfy every filter to be kept. Rows
 * missing the referenced field fail closed (the policy author asked for a
 * constraint and we cannot prove it holds).
 */
export function applyRowFilters(
  results: Array<Record<string, unknown>>,
  policy: EffectivePolicy,
): Array<Record<string, unknown>> {
  const filters = policy.objectRules?.rowFilters;
  if (!filters || filters.length === 0) return results;
  return results.filter((row) => filters.every((f) => rowPassesFilter(row, f)));
}

// ---------------------------------------------------------------------------
// Tag filtering
// ---------------------------------------------------------------------------

/**
 * Filter results by tag rules in the effective policy.
 * Each result must have a `tags` array of strings.
 */
export function filterByTags(
  results: Array<Record<string, unknown>>,
  policy: EffectivePolicy,
): Array<Record<string, unknown>> {
  const tagRules = policy.objectRules?.tagRules;
  if (!tagRules) return results;

  return results.filter((result) => {
    const tags = result["tags"];
    if (!Array.isArray(tags)) return false;

    const stringTags = tags as string[];

    // Denied tags take precedence: exclude if any tag is denied
    if (tagRules.deniedTags) {
      for (const tag of stringTags) {
        if (tagRules.deniedTags.includes(tag)) {
          return false;
        }
      }
    }

    // Allowed tags: include only if at least one tag is allowed
    if (tagRules.allowedTags) {
      let hasAllowedTag = false;
      for (const tag of stringTags) {
        if (tagRules.allowedTags.includes(tag)) {
          hasAllowedTag = true;
          break;
        }
      }
      if (!hasAllowedTag) return false;
    }

    return true;
  });
}

// ---------------------------------------------------------------------------
// Endpoint validation
// ---------------------------------------------------------------------------

/**
 * Validate whether an endpoint + method is accessible under the effective policy.
 */
export function validateEndpoint(
  path: string,
  method: string,
  policy: EffectivePolicy,
): AccessResult {
  if (!policy.permissions.canQuery) {
    return { allowed: false, reason: "query not permitted" };
  }

  const endpointRules = policy.objectRules?.endpointRules;
  if (!endpointRules) return { allowed: true };

  // Hidden endpoints take precedence
  if (
    endpointRules.hiddenEndpoints &&
    matchesAnyGlob(endpointRules.hiddenEndpoints, path)
  ) {
    return { allowed: false, reason: "endpoint is hidden" };
  }

  // Check allowed endpoints
  if (endpointRules.allowedEndpoints) {
    if (!matchesAnyGlob(endpointRules.allowedEndpoints, path)) {
      return { allowed: false, reason: "endpoint not in allowed set" };
    }
  }

  // Check allowed methods
  if (endpointRules.allowedMethods) {
    const upperMethod = method.toUpperCase();
    if (!endpointRules.allowedMethods.includes(upperMethod)) {
      return { allowed: false, reason: "method not allowed" };
    }
  }

  return { allowed: true };
}
