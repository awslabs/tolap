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
  maskRestrictiveness,
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
// Field-name matching
// ---------------------------------------------------------------------------
//
// A policy field reference and a record key may each be bare ("ssn") or
// table-qualified ("patients.ssn"), and the two do not have to agree: the rule
// "patients.ssn" must match a key "ssn" and the rule "ssn" must match a key
// "patients.ssn". Matching is case-insensitive and glob patterns are honoured
// (canonical spec §4).

/**
 * Every form a field reference may be compared in, lower-cased.
 *
 * Unqualified forms of a qualified name are included so the two sides need not
 * agree on qualification. This intentionally lets a table-scoped wildcard such
 * as `patients.*` match a bare key: rows reaching the pipeline have already
 * been projected by the tool, so the qualifier is implied by the result set
 * rather than repeated on every key.
 */
function matchForms(name: string): string[] {
  const lowered = name.toLowerCase();
  const forms = new Set<string>([lowered]);
  const first = lowered.indexOf(".");
  if (first >= 0) {
    forms.add(lowered.slice(first + 1)); // drop the leading qualifier
    forms.add(lowered.slice(lowered.lastIndexOf(".") + 1)); // bare leaf
  }
  return [...forms];
}

/** Whether a policy field reference refers to a record key. */
function fieldNameMatches(ruleField: string, key: string): boolean {
  const keyForms = matchForms(key);
  return matchForms(ruleField).some((ruleForm) =>
    keyForms.some((keyForm) => matchesGlob(ruleForm, keyForm)),
  );
}

// Keys that must never be walked into or assigned through. A plain
// `node[key] = value` where key is "__proto__" reassigns the object's prototype
// instead of adding a property, so a hostile result body could reshape
// Object.prototype during masking or hidden-field removal. Skipping the whole
// family (including "constructor" and "prototype") is defense-in-depth: no
// policy rule needs to address them, and no legitimate record should be walked
// through them.
const DANGEROUS_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function isDangerousKey(key: string): boolean {
  return DANGEROUS_KEYS.has(key);
}

/** Assign a key without ever tripping a prototype setter. */
function safeSet(
  node: Record<string, unknown>,
  key: string,
  value: unknown,
): void {
  if (isDangerousKey(key)) return;
  Object.defineProperty(node, key, {
    value,
    writable: true,
    enumerable: true,
    configurable: true,
  });
}

/**
 * Whether a value is a plain record the pipeline can enforce policy on.
 *
 * Deliberately strict about the prototype: only object literals (and
 * `Object.create(null)` bags) qualify. This is the TypeScript equivalent of
 * Python's `isinstance(node, Mapping)` check and it does two jobs at once —
 *
 *  - Values that carry data rather than structure (`Date` from a DATE column,
 *    `Map`, `Buffer`) are treated as leaves instead of being flattened into `{}`
 *    while cloning.
 *  - A class instance, generator, or stream is *not* a record, so the shape
 *    classifier denies it rather than enforcing a policy over accessors and
 *    prototype methods it cannot see (canonical spec §5).
 *
 * The `pg` and `mysql2` drivers both return plain object literals for rows, so
 * real query results classify as records.
 */
function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/**
 * Clone the record/array spine of a value, passing leaf values through by
 * reference.
 *
 * The pipeline mutates the structures it walks, so it must never hand back a
 * view onto the caller's records. A structural clone (rather than
 * `JSON.parse(JSON.stringify(...))`) is required so that values like `Date` —
 * which `pg` returns for DATE/TIMESTAMP columns — survive enforcement as dates
 * rather than being silently stringified.
 */
function deepClone<T>(value: T): T {
  if (Array.isArray(value)) {
    return value.map((item) => deepClone(item)) as unknown as T;
  }
  if (isRecord(value)) {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value)) {
      if (isDangerousKey(key)) continue;
      safeSet(out, key, deepClone(value[key]));
    }
    return out as unknown as T;
  }
  return value;
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

/**
 * Apply a masking rule to a field value.
 *
 * Fails closed (canonical spec §6): an unrecognized mask type is treated as
 * `redact` rather than returning the caller's original value. A typo, or a mask
 * type from a newer schema version, must not silently disable masking.
 */
export function applyMask(value: unknown, rule: MaskingRule): unknown {
  if (value === null || value === undefined) return null;
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
      // Unknown / future mask type: never disclose the original.
      return "[REDACTED]";
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

  // Showing the whole value is not masking; degrade to a full mask instead of
  // handing back the unmasked original (canonical spec §6). Negative parameters
  // are treated the same way rather than producing a nonsensical slice.
  if (showFirst < 0 || showLast < 0 || showFirst + showLast >= str.length) {
    return maskChar.repeat(str.length);
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

function maskingRules(policy: EffectivePolicy): MaskingRule[] {
  return policy.objectRules?.fieldRules?.maskedFields ?? [];
}

/** The most restrictive masking rule that matches `key`, if any. */
function ruleForKey(rules: MaskingRule[], key: string): MaskingRule | undefined {
  let best: MaskingRule | undefined;
  for (const rule of rules) {
    if (!fieldNameMatches(rule.field, key)) continue;
    if (
      best === undefined ||
      maskRestrictiveness(rule.maskType) > maskRestrictiveness(best.maskType)
    ) {
      best = rule;
    }
  }
  return best;
}

/** Mask matching keys anywhere in a (possibly nested) structure, in place. */
function maskNode(node: unknown, rules: MaskingRule[]): unknown {
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i++) {
      node[i] = maskNode(node[i], rules);
    }
    return node;
  }
  if (!isRecord(node)) return node;

  for (const key of Object.keys(node)) {
    if (isDangerousKey(key)) continue;
    const rule = ruleForKey(rules, key);
    if (rule !== undefined) {
      safeSet(node, key, applyMask(node[key], rule));
    } else {
      safeSet(node, key, maskNode(node[key], rules));
    }
  }
  return node;
}

/**
 * Apply field masking to a record according to the effective policy.
 *
 * Returns a deep copy: the caller's record (including any nested objects) is
 * never mutated. Matching recurses into nested records and arrays, so a rule for
 * "patient.ssn" also masks `{patient: {ssn: ...}}` (canonical spec §4).
 */
export function applyFieldMasking(
  record: Record<string, unknown>,
  policy: EffectivePolicy,
): Record<string, unknown> {
  const rules = maskingRules(policy);
  if (rules.length === 0) return deepClone(record);
  return maskNode(deepClone(record), rules) as Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Hidden fields (pipeline step 3)
// ---------------------------------------------------------------------------

function hiddenFieldPatterns(policy: EffectivePolicy): string[] {
  return policy.objectRules?.fieldRules?.hiddenFields ?? [];
}

/** Remove keys matching any hidden-field pattern, recursively, in place. */
function dropNode(node: unknown, patterns: string[]): unknown {
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i++) {
      node[i] = dropNode(node[i], patterns);
    }
    return node;
  }
  if (!isRecord(node)) return node;

  for (const key of Object.keys(node)) {
    if (isDangerousKey(key)) continue;
    if (patterns.some((pattern) => fieldNameMatches(pattern, key))) {
      delete node[key];
      continue;
    }
    safeSet(node, key, dropNode(node[key], patterns));
  }
  return node;
}

/**
 * Remove every `hiddenFields` entry from a record, list of records, or JSON tree.
 *
 * Step 3 of the post-execution pipeline. A hidden field must never reach the
 * agent, and a pre-execution field check cannot deliver that on its own: it only
 * sees the fields a caller volunteered, so a tool that returns undeclared
 * columns (`SELECT *`) would leak them. Returns a deep copy.
 */
export function stripHiddenFields<T>(result: T, policy: EffectivePolicy): T {
  const patterns = hiddenFieldPatterns(policy);
  if (patterns.length === 0) return deepClone(result);
  return dropNode(deepClone(result), patterns) as T;
}

// ---------------------------------------------------------------------------
// Allowed fields (pipeline step 4)
// ---------------------------------------------------------------------------

/**
 * The `allowedFields` allow-list, or `undefined` when the policy sets none.
 *
 * `undefined` means unrestricted; `[]` means deny every field (canonical spec §3).
 */
function allowedFieldPatterns(policy: EffectivePolicy): string[] | undefined {
  return policy.objectRules?.fieldRules?.allowedFields;
}

function projectRecord(
  record: Record<string, unknown>,
  patterns: string[],
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(record)) {
    if (isDangerousKey(key)) continue;
    if (patterns.some((pattern) => fieldNameMatches(pattern, key))) {
      safeSet(out, key, record[key]);
    }
  }
  return out;
}

/**
 * Project a record or list of records down to `allowedFields`.
 *
 * Step 4 of the post-execution pipeline. When `allowedFields` is specified every
 * other key is dropped, so a tool returning columns the policy never listed
 * cannot disclose them. An empty allow-list denies every field (see the
 * null-vs-empty-array rule, canonical spec §3).
 */
export function projectAllowedFields<T>(result: T, policy: EffectivePolicy): T {
  const patterns = allowedFieldPatterns(policy);
  if (patterns === undefined) return deepClone(result);

  const cloned = deepClone(result);
  if (Array.isArray(cloned)) {
    return cloned.map((item) =>
      isRecord(item) ? projectRecord(item, patterns) : item,
    ) as unknown as T;
  }
  if (isRecord(cloned)) {
    return projectRecord(cloned, patterns) as unknown as T;
  }
  return cloned;
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
// Result shapes -- fail closed
// ---------------------------------------------------------------------------

/**
 * Thrown when a tool result cannot have policy applied to it.
 *
 * A distinct type so wrappers can report it precisely, but it carries the same
 * "Access denied" prefix as every other denial so an integrator's existing
 * error handling fails closed without special-casing it.
 */
export class UnenforceableResultError extends Error {
  readonly shape: string;

  constructor(shape: string) {
    super(
      `Access denied: tool result shape cannot be policy-enforced: ${shape}. ` +
        "Return a record (object) or an array of records, or opt out explicitly " +
        "with allowUnenforceableShapes: true.",
    );
    this.name = "UnenforceableResultError";
    this.shape = shape;
  }
}

export type ResultShape = "record" | "records";

/**
 * Classify a tool result as a record, an array of records, or unenforceable.
 *
 * Returns `undefined` when the policy cannot be applied to the value: a scalar,
 * null/undefined, a class instance carrying no enumerable data, an iterator, or
 * an array holding anything other than records (canonical spec §5).
 */
export function classifyResultShape(result: unknown): ResultShape | undefined {
  if (Array.isArray(result)) {
    return result.every((item) => isRecord(item)) ? "records" : undefined;
  }
  if (isRecord(result)) return "record";
  return undefined;
}

/** A human-readable description of a result shape, for denial messages. */
export function describeResultShape(result: unknown): string {
  if (result === null) return "null";
  if (result === undefined) return "undefined";
  if (Array.isArray(result)) {
    const offenders = [
      ...new Set(
        result.filter((item) => !isRecord(item)).map((item) => typeofName(item)),
      ),
    ].sort();
    if (offenders.length > 0) {
      return `array containing ${offenders.join(", ")} (not records)`;
    }
    return "array of records";
  }
  if (isRecord(result)) return "object (record)";
  return `${typeofName(result)} (not a record or array of records)`;
}

function typeofName(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  if (typeof value === "object") {
    const name = (value as object).constructor?.name;
    return name ? name : "object";
  }
  return typeof value;
}

// ---------------------------------------------------------------------------
// Post-execution pipeline
// ---------------------------------------------------------------------------

/**
 * Run the full post-execution enforcement pipeline over a tool result.
 *
 * The canonical order (spec §4), applied identically to a single record and to
 * an array of records:
 *
 *   1. row filters      drop rows the policy excludes
 *   2. tag filters      drop records by allowedTags / deniedTags
 *   3. hidden fields    remove hiddenFields from every record
 *   4. allowed fields   project to allowedFields when specified
 *   5. masking          apply maskedFields transformations
 *   6. result limit     truncate to maxResults
 *
 * Hidden/allowed removal precedes masking so a field that is both hidden and
 * masked is removed rather than returned in masked form, and the limit runs last
 * so filtering never yields fewer rows than maxResults when more qualifying rows
 * exist.
 *
 * A single record runs the identical pipeline: a get-by-id tool must not skip row
 * and tag filters, which is how a `deniedTags` record was previously disclosed.
 *
 * @throws UnenforceableResultError for a shape the policy cannot be applied to.
 */
export function applyResultPipeline(
  result: unknown,
  policy: EffectivePolicy,
): unknown {
  const shape = classifyResultShape(result);
  if (shape === undefined) {
    throw new UnenforceableResultError(describeResultShape(result));
  }

  const records: Array<Record<string, unknown>> =
    shape === "record"
      ? [result as Record<string, unknown>]
      : (result as Array<Record<string, unknown>>);

  let out: Array<Record<string, unknown>> = applyRowFilters(records, policy);
  out = filterByTags(out, policy);
  out = stripHiddenFields(out, policy);
  out = projectAllowedFields(out, policy);
  out = out.map((record) => applyFieldMasking(record, policy));
  out = applyResultLimit(out, policy);

  if (shape === "record") {
    // A single record the pipeline dropped is a denial, not an empty record:
    // returning {} would imply the row existed but had no fields.
    return out.length > 0 ? out[0] : null;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Row filters
// ---------------------------------------------------------------------------

/** Sentinel for "the row has no such field", distinct from a stored null. */
const MISSING = Symbol("missing");

// ReDoS guard. JavaScript's RegExp has no evaluation timeout, so bound the work
// a pattern can be asked to do instead: an over-long pattern or subject value is
// a non-match rather than an unbounded backtracking search. Mirrors the Python
// SDK's limits so the three implementations drop the same inputs.
const MAX_REGEX_PATTERN_LENGTH = 1024;
const MAX_REGEX_VALUE_LENGTH = 4096;

const rowFilterPatternCache = new Map<string, RegExp | null>();

/**
 * Compile an anchored row-filter pattern, or `null` if it is unusable.
 *
 * The non-capturing group is required: `^hr|finance$` would otherwise bind `^`
 * to `hr` alone and match "hr_secret_internal" (canonical spec §7).
 */
function compileRowFilterPattern(pattern: string): RegExp | null {
  const cached = rowFilterPatternCache.get(pattern);
  if (cached !== undefined) return cached;

  let compiled: RegExp | null;
  if (pattern.length > MAX_REGEX_PATTERN_LENGTH) {
    compiled = null;
  } else {
    try {
      compiled = new RegExp(`^(?:${pattern})$`);
    } catch {
      compiled = null;
    }
  }
  // Bounded cache: a hostile policy stream must not grow this without limit.
  if (rowFilterPatternCache.size >= 256) rowFilterPatternCache.clear();
  rowFilterPatternCache.set(pattern, compiled);
  return compiled;
}

/**
 * Look up a filter's field on a row, or `MISSING` when it is absent.
 *
 * Filters use either bare names ("region") or dotted paths ("patients.region");
 * both are accepted, preferring the exact key when present. `MISSING` is
 * distinct from a stored `null` so that "field absent" can fail closed while an
 * explicit null is still comparable.
 */
function rowFieldValue(
  row: Record<string, unknown>,
  fieldName: string,
): unknown {
  if (Object.prototype.hasOwnProperty.call(row, fieldName)) {
    return row[fieldName];
  }
  for (const key of Object.keys(row)) {
    if (fieldNameMatches(fieldName, key)) return row[key];
  }
  return MISSING;
}

/** Equality that does not conflate booleans with numbers (`1` != `true`). */
function valuesEqual(left: unknown, right: unknown): boolean {
  if ((typeof left === "boolean") !== (typeof right === "boolean")) return false;
  return left === right;
}

/**
 * Compare two values, returning `undefined` when they are not comparable.
 *
 * A non-comparable pair (e.g. age="notanumber" vs 30) is a non-match — the row
 * is dropped — never a thrown error that aborts the whole result pass.
 */
function compareValues(left: unknown, right: unknown): number | undefined {
  if (typeof left === "number" && typeof right === "number") {
    if (Number.isNaN(left) || Number.isNaN(right)) return undefined;
    return left === right ? 0 : left < right ? -1 : 1;
  }
  if (typeof left === "string" && typeof right === "string") {
    return left === right ? 0 : left < right ? -1 : 1;
  }
  if (left instanceof Date && right instanceof Date) {
    const l = left.getTime();
    const r = right.getTime();
    if (Number.isNaN(l) || Number.isNaN(r)) return undefined;
    return l === r ? 0 : l < r ? -1 : 1;
  }
  if (typeof left === "bigint" && typeof right === "bigint") {
    return left === right ? 0 : left < right ? -1 : 1;
  }
  return undefined;
}

function rowPassesFilter(
  row: Record<string, unknown>,
  rf: RowFilter,
): boolean {
  const value = rowFieldValue(row, rf.field);
  if (value === MISSING) {
    // Fail closed for every operator, including the negative ones (canonical
    // spec §7): a filter written to exclude classified rows must not retain
    // every row that simply lacks the column. `undefined !== "classified"` and
    // `!values.includes(undefined)` are both true, which is how notEquals /
    // notIn previously kept every field-less row.
    return false;
  }

  switch (rf.operator) {
    case "equals":
      return valuesEqual(value, rf.value);
    case "notEquals":
      return !valuesEqual(value, rf.value);
    case "in":
      return (rf.values ?? []).some((candidate) => valuesEqual(value, candidate));
    case "notIn":
      return !(rf.values ?? []).some((candidate) => valuesEqual(value, candidate));
    case "greaterThan": {
      if (value === null || rf.value === undefined || rf.value === null) {
        return false;
      }
      const cmp = compareValues(value, rf.value);
      return cmp !== undefined && cmp > 0;
    }
    case "lessThan": {
      if (value === null || rf.value === undefined || rf.value === null) {
        return false;
      }
      const cmp = compareValues(value, rf.value);
      return cmp !== undefined && cmp < 0;
    }
    case "contains":
      return (
        value !== null &&
        rf.value !== undefined &&
        rf.value !== null &&
        String(value).includes(String(rf.value))
      );
    case "startsWith":
      return (
        value !== null &&
        rf.value !== undefined &&
        rf.value !== null &&
        String(value).startsWith(String(rf.value))
      );
    case "matches": {
      if (value === null || rf.value === undefined || rf.value === null) {
        return false;
      }
      const strValue = String(value);
      if (strValue.length > MAX_REGEX_VALUE_LENGTH) return false;
      const compiled = compileRowFilterPattern(String(rf.value));
      // A regex error is a non-match, never an exception that aborts the pass.
      if (compiled === null) return false;
      return compiled.test(strValue);
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
 *
 * - If `allowedTags` is set, only records with at least one allowed tag survive.
 *   An empty `allowedTags` list denies every record (canonical spec §3) rather
 *   than lifting the restriction, and an untagged record is dropped: no tag
 *   means no proof of allowance.
 * - If `deniedTags` is set, records carrying any denied tag are excluded. A pure
 *   denylist does NOT drop untagged records — an untagged record matches no
 *   denied tag, so dropping it enforced a restriction the policy never stated.
 * - Denied takes precedence over allowed.
 */
export function filterByTags(
  results: Array<Record<string, unknown>>,
  policy: EffectivePolicy,
): Array<Record<string, unknown>> {
  const tagRules = policy.objectRules?.tagRules;
  if (!tagRules) return results;

  const allowedTags = tagRules.allowedTags;
  const deniedTags = tagRules.deniedTags;

  return results.filter((result) => {
    const rawTags = result["tags"];
    const tags = Array.isArray(rawTags) ? (rawTags as string[]) : [];

    // Denied tags take precedence: exclude if any tag is denied.
    if (deniedTags && tags.some((tag) => deniedTags.includes(tag))) {
      return false;
    }

    // Allowed tags: include only if at least one tag is allowed.
    if (allowedTags && !tags.some((tag) => allowedTags.includes(tag))) {
      return false;
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
