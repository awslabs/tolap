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
  FilterOperator,
  WriteOperation,
  maskRestrictiveness,
} from "./types.js";
import { globToRegex } from "./resolution.js";

// Re-exported so the pushdown sits next to the post-retrieval pass it complements.
// `filterByTags` below is the normative control; `buildKbFilter` only asks the provider
// to do some of the same work earlier (connector-spec §7). Keeping them on one surface is
// meant to make that relationship hard to miss.
export { buildKbFilter } from "./kb-filter.js";

// ---------------------------------------------------------------------------
// Glob matching helper
// ---------------------------------------------------------------------------
//
// `globToRegex` is the ENFORCEMENT glob dialect (spec §3.1): case-insensitive, and
// `*` crosses every separator including `/` and `.`. It lives in resolution.ts for
// historical reasons but is used only from here — `sourcePatterns` resolution has
// its own `sourcePatternMatch`, whose `*` must NOT cross `:`. Reaching for that one
// here would deny `/api/v1/patients/123` under `/api/v1/patients/*`.

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

/**
 * Whether a policy field reference refers to a record key.
 *
 * Exported so `sql-rewriter.ts` decides "is this column hidden?" with exactly the
 * rule the post-execution pass uses. A rewriter with its own matching would push
 * down a projection that disagrees with what the post pass then strips, so the two
 * halves of enforcement must share one implementation (spec §4).
 */
export function fieldNameMatches(ruleField: string, key: string): boolean {
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

/**
 * Assign a key without ever tripping a prototype setter.
 *
 * `Object.defineProperty` is used rather than `node[key] = value` because a plain
 * assignment where key is "__proto__" reassigns the object's prototype instead of
 * adding a property.
 */
function safeSet(
  node: Record<string, unknown>,
  key: string,
  value: unknown,
): void {
  /* c8 ignore next -- defense in depth, currently unreachable. Every caller either
     already skipped dangerous keys (deepClone, maskNode, dropNode, projectRecord all
     `continue` on isDangerousKey first) or is walking a tree deepClone has already
     stripped them from. Retained because safeSet is the single choke point for
     assignment: a future caller that forgets its own check must still not be able to
     reassign a prototype. Reaching it in a test would require calling this private
     function directly, which asserts nothing about the pipeline. */
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

/**
 * The Node digest name for each schema-permitted `algorithm` value (spec §6).
 *
 * Mapped rather than passed through, for two reasons. Node spells BLAKE2b-512
 * `blake2b512` and throws on `blake2b`, so the schema value has to be translated.
 * And passing the parameter straight to `createHash` accepts anything OpenSSL
 * knows -- `md5` included -- plus spellings the Python and .NET SDKs reject, which
 * is how a pseudonym stops matching across services.
 */
const HASH_ALGORITHMS: Record<string, string> = {
  sha256: "sha256",
  sha512: "sha512",
  blake2b: "blake2b512",
};

function applyHashMask(value: unknown, rule: MaskingRule): string {
  const str = String(value);
  const algorithm = rule.parameters?.algorithm ?? "sha256";
  const nodeName = HASH_ALGORITHMS[algorithm];

  // Unknown, or unavailable in this runtime: fail closed as `redact`. Masking must
  // never return the raw value and must not abort the result pass (spec §6), and
  // substituting sha256 is worse than redacting -- the field would look like a
  // valid pseudonym while silently failing to join against a service that computed
  // the algorithm the policy actually asked for.
  if (nodeName === undefined) return "[REDACTED]";

  // Truncate to 16 hex chars to match the Python and .NET SDKs.
  return createHash(nodeName).update(str).digest("hex").slice(0, 16);
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
    /* c8 ignore next -- defense in depth, currently unreachable: every public entry
       point deep-clones first and deepClone drops dangerous keys, so no key reaching
       this walker can be one. Retained so the walker is safe on its own terms if a
       future caller passes an un-cloned tree. */
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
  return applyMaskingToTree(record, policy);
}

/**
 * Apply `maskedFields` to an arbitrary JSON tree (record, array, or nested body).
 *
 * The generic counterpart to {@link applyFieldMasking}, alongside
 * {@link stripHiddenFields} and {@link projectAllowedFields}. Exported so the HTTP
 * wrapper masks through this same walker rather than a private one of its own: a
 * wrapper-local path-walking implementation only reaches a key at the literal
 * dotted path from the root, so a bare rule such as `ssn` silently missed a
 * nested `demographics.ssn` and returned it in cleartext, while the identical rule
 * masked it on the DB/MCP path. Field-name matching is bidirectional,
 * case-insensitive, and recurses into nested records and arrays (spec §4).
 *
 * Returns a deep copy; the caller's tree is never mutated.
 */
export function applyMaskingToTree<T>(result: T, policy: EffectivePolicy): T {
  const rules = maskingRules(policy);
  if (rules.length === 0) return deepClone(result);
  return maskNode(deepClone(result), rules) as T;
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
    /* c8 ignore next -- defense in depth, unreachable for the same reason as in
       maskNode: stripHiddenFields deep-clones before walking, and deepClone has
       already dropped every dangerous key. */
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
    /* c8 ignore next -- defense in depth, unreachable: projectAllowedFields
       deep-clones before projecting, and deepClone has already dropped every
       dangerous key. Retained so the projection cannot copy one forward even if it
       is ever called on an un-cloned record. */
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
// Numeric record floors and ceilings
// ---------------------------------------------------------------------------

/**
 * Field names carrying a similarity score, in precedence order. Covers the common
 * vector-store response shapes (Bedrock KB, OpenSearch, pgvector wrappers).
 */
const SCORE_KEYS = ["score", "similarity", "similarityscore", "_score"] as const;

/**
 * Field names carrying an object size in bytes, in precedence order. Covers the
 * common object-storage response shapes (S3, Azure Blob, GCS).
 */
const SIZE_KEYS = ["size", "sizebytes", "contentlength", "objectsize"] as const;

/**
 * Read the first present numeric field named by `keys`, case-insensitively.
 *
 * Returns undefined when no key is present or the value is not a finite number.
 * The caller treats undefined as "cannot establish this record's value", which
 * fails closed.
 */
function numericField(
  record: unknown,
  keys: readonly string[],
): number | undefined {
  if (!isRecord(record)) return undefined;

  const lowered = new Map<string, unknown>();
  for (const [key, value] of Object.entries(record)) {
    lowered.set(key.toLowerCase(), value);
  }

  for (const key of keys) {
    if (!lowered.has(key)) continue;
    const value = lowered.get(key);
    // `typeof true === "boolean"`, so a boolean is rejected rather than coerced
    // to 1 -- a `true` score is a type error, not a passing score.
    if (typeof value === "number") {
      return Number.isFinite(value) ? value : undefined;
    }
    if (typeof value === "string") {
      const trimmed = value.trim();
      if (trimmed === "") return undefined;
      const parsed = Number(trimmed);
      return Number.isFinite(parsed) ? parsed : undefined;
    }
    return undefined;
  }
  return undefined;
}

/**
 * Drop records scoring below `minSimilarityScore` (canonical spec §4, step 3).
 *
 * Fails closed: a record with no recognizable score field, or a non-numeric score,
 * is dropped when a floor is set. A record whose relevance cannot be established
 * cannot be shown to satisfy the floor, and the documented purpose of this limit is
 * to stop low-relevance vector hits from surfacing sensitive content -- so an
 * unscored record must not slip through. A score exactly equal to the floor is kept.
 */
export function applySimilarityFloor<T>(
  results: T[],
  policy: EffectivePolicy,
): T[] {
  const floor = policy.limits?.minSimilarityScore;
  if (floor === undefined || floor === null) return results;

  return results.filter((record) => {
    const score = numericField(record, SCORE_KEYS);
    return score !== undefined && score >= floor;
  });
}

/**
 * Drop records larger than `maxObjectSizeBytes` (canonical spec §4, step 4).
 *
 * Fails closed on the same reasoning as the relevance floor: a record with no
 * recognizable size field, or a non-numeric size, is dropped when a ceiling is set.
 * A size exactly equal to the ceiling is kept.
 */
export function applyObjectSizeCeiling<T>(
  results: T[],
  policy: EffectivePolicy,
): T[] {
  const ceiling = policy.limits?.maxObjectSizeBytes;
  if (ceiling === undefined || ceiling === null) return results;

  return results.filter((record) => {
    const size = numericField(record, SIZE_KEYS);
    return size !== undefined && size <= ceiling;
  });
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
  out = applySimilarityFloor(out, policy);
  out = applyObjectSizeCeiling(out, policy);
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
 * Unrecognized operator names already warned about, so a filter evaluated over a
 * million rows produces one message rather than a million.
 *
 * Bounded for the same reason as {@link rowFilterPatternCache}: a hostile or
 * merely varied policy stream must not grow it without limit.
 */
const warnedUnknownOperators = new Set<string>();

/**
 * Report an operator the engine cannot evaluate, once per distinct spelling.
 *
 * The row is dropped either way -- see the `default` arm of
 * {@link rowPassesFilter} -- but a silent drop-everything is indistinguishable
 * from a filter that is working, so the integrator gets no signal that their
 * policy is not being enforced as written. Warning rather than throwing keeps the
 * behaviour consistent with how an unknown `maskType` is handled (spec §6: it
 * degrades to `redact` rather than aborting the result pass), and means one
 * malformed filter cannot take down a whole tool call. Deliberately NOT
 * fail-open.
 */
function warnUnknownOperator(operator: string): void {
  if (warnedUnknownOperators.has(operator)) return;
  if (warnedUnknownOperators.size >= 64) warnedUnknownOperators.clear();
  warnedUnknownOperators.add(operator);
  console.warn(
    `TOLAP row filter uses unrecognized operator "${operator}": every row is ` +
      "dropped (fail closed, canonical spec §7). This is almost certainly a typo " +
      "or a policy authored against a newer schema than this SDK implements; the " +
      "filter is NOT being enforced as written. Supported operators: " +
      `${Object.values(FilterOperator).join(", ")}.`,
  );
}

/**
 * Test a value against a SQL `LIKE` pattern.
 *
 * `%` matches any run of characters, `_` exactly one, and `\` escapes the next
 * character so a literal `%` or `_` can be matched. The match is anchored (the
 * whole value, as SQL `LIKE` is) and case-sensitive.
 *
 * Case-sensitivity is load-bearing rather than incidental. Postgres, Athena, and
 * Trino all evaluate `LIKE` case-sensitively, and {@link module:sql-rewriter} pushes
 * this operator into the query as a real `LIKE`. If the post-fetch pass were
 * case-insensitive, pushing the filter down would change which rows a caller sees:
 * the database would already have dropped the rows differing only in case, and no
 * post-fetch leniency could bring them back. The two paths must mean the same
 * thing, so both follow the SQL engines. (MySQL's default collation *is*
 * case-insensitive, so a pushed-down filter there matches a superset; the
 * post-fetch pass then removes the extras, which is the fail-closed direction.)
 *
 * Every non-wildcard character is regex-escaped, so a pattern containing regex
 * metacharacters (`.`, `(`, `|`, `+`) is matched literally and cannot smuggle in a
 * pathological regex. The translation only ever emits `.*`, `.`, and escaped
 * literals -- there is no nesting or alternation to backtrack over -- but pattern
 * and value length are still bounded, consistent with `matches`.
 */
function likeMatches(pattern: string, value: string): boolean {
  if (
    pattern.length > MAX_REGEX_PATTERN_LENGTH ||
    value.length > MAX_REGEX_VALUE_LENGTH
  ) {
    return false;
  }

  const compiled = compileLikePattern(pattern);
  // Unreachable alongside the corresponding `catch` in compileLikePattern, and kept
  // for the same reason: a pattern that cannot compile is a non-match (spec §7),
  // never an exception that aborts the result pass.
  /* c8 ignore next */
  if (compiled === null) return false;
  return compiled.test(value);
}

const likePatternCache = new Map<string, RegExp | null>();

function compileLikePattern(pattern: string): RegExp | null {
  const cached = likePatternCache.get(pattern);
  if (cached !== undefined) return cached;

  let body = "";
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i];
    if (ch === "\\" && i + 1 < pattern.length) {
      // An escaped character is a literal, wildcard or not. Consume both.
      body += escapeRegex(pattern[++i]!);
      continue;
    }
    if (ch === "%") {
      body += ".*";
    } else if (ch === "_") {
      body += ".";
    } else {
      // Includes a trailing backslash, which has nothing to escape and is literal.
      body += escapeRegex(ch!);
    }
  }

  let compiled: RegExp | null;
  try {
    // `s` so `_` and `%` also span a newline, matching SQL LIKE, where the
    // wildcards have no line semantics at all.
    compiled = new RegExp(`^(?:${body})$`, "s");
  } catch {
    // Unreachable as written: every character is either regex-escaped or one of
    // the two wildcard expansions, so `body` is always a valid pattern, and the
    // 1024-character bound above rules out "regex too large". Retained as the
    // second layer -- if `escapeRegex` is ever relaxed, a construction failure must
    // be a non-match (spec §7) rather than an exception that aborts the result pass.
    /* c8 ignore next */
    compiled = null;
  }

  if (likePatternCache.size >= 256) likePatternCache.clear();
  likePatternCache.set(pattern, compiled);
  return compiled;
}

/** Escape one character so a regex treats it as a literal. */
function escapeRegex(ch: string): string {
  return /[.*+?^${}()|[\]\\]/.test(ch) ? `\\${ch}` : ch;
}

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
    case "greaterThanOrEqual": {
      if (value === null || rf.value === undefined || rf.value === null) {
        return false;
      }
      const cmp = compareValues(value, rf.value);
      return cmp !== undefined && cmp >= 0;
    }
    case "lessThanOrEqual": {
      if (value === null || rf.value === undefined || rf.value === null) {
        return false;
      }
      const cmp = compareValues(value, rf.value);
      return cmp !== undefined && cmp <= 0;
    }
    case "like":
      if (value === null || rf.value === undefined || rf.value === null) {
        return false;
      }
      return likeMatches(String(rf.value), String(value));
    case "notLike":
      // notLike is a negative operator and behaves exactly like notEquals and
      // notIn on a null value: the row is KEPT. Two separate rules meet here and
      // are deliberately not conflated.
      //
      // 1. Present-and-null is KEPT. This is what keeps the pushed-down form and
      //    this pass equivalent: the rewriter emits
      //    `(col NOT LIKE 'x' OR col IS NULL)` precisely because bare SQL
      //    `NOT LIKE` is unknown-therefore-false for a null col, so without the
      //    arm the database would drop a row this pass keeps (spec §4). A key
      //    holding `undefined` counts as null here, exactly as it does for
      //    `isNull` below.
      // 2. An ABSENT field was already dropped above. That is the unrelated
      //    fail-closed rule: a value that cannot be established cannot be shown
      //    to satisfy the filter (spec §7). It applies to every operator.
      if (value === null || value === undefined) {
        return true;
      }
      // A null pattern states no constraint any value can be shown to satisfy, so
      // it matches nothing -- as for `like`.
      if (rf.value === undefined || rf.value === null) {
        return false;
      }
      return !likeMatches(String(rf.value), String(value));
    case "isNull":
      // The field is present -- a missing field was already dropped above -- so
      // this is the genuine "present and null" case. A key holding `undefined`
      // counts as null: it carries no value, and a JSON `null` round-trips to
      // `null` while `undefined` only arises from a driver or caller that means
      // the same thing.
      return value === null || value === undefined;
    case "isNotNull":
      return value !== null && value !== undefined;
    case "between": {
      // Inclusive, over the first two entries of `values`, in the order written.
      // Fails closed on a malformed range: fewer than two bounds, a null bound, or
      // a bound not ordered against the row value all drop the row. An inverted
      // range (low > high) matches nothing, exactly as SQL `BETWEEN 10 AND 1`
      // does, and is NOT silently reordered -- reordering would turn a policy
      // author's typo into a wider grant than what was written.
      const bounds = rf.values;
      if (bounds === undefined || bounds.length < 2) return false;
      if (value === null) return false;
      const [low, high] = bounds;
      if (low === undefined || low === null || high === undefined || high === null) {
        return false;
      }
      const lower = compareValues(value, low);
      if (lower === undefined || lower < 0) return false;
      const upper = compareValues(value, high);
      return upper !== undefined && upper <= 0;
    }
    default:
      // Fail closed, loudly. Dropping every row is the safe direction, but it is
      // indistinguishable from a filter that is working, so the integrator is told
      // once that their policy is not being enforced as written.
      warnUnknownOperator(String(rf.operator));
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

// A classification level *is* a tag: there is no separate classification
// construct, so tag filtering is the whole knowledge-base confidentiality control
// (connector spec §7). Extraction therefore has to be as robust as masking already
// is. A literal lower-case `tags` lookup enforced the control on exactly one of the
// five shapes real providers emit -- `tags`, `Tags`, `metadata.tags`, `labels`, and
// a scalar `classification` -- so four of five records tagged `secret` were
// disclosed.

/**
 * The record keys that carry classification tags, matched with
 * {@link fieldNameMatches} rather than looked up literally.
 *
 * The set is deliberately small, fixed, and not configurable. Every entry is a
 * shape connector spec §7 names; nothing is added on speculation, because widening
 * the set is not automatically safer in either direction. An unrelated `labels`
 * field whose value happens to appear in `allowedTags` would *admit* a record the
 * allow-list would otherwise have dropped as untagged, so an over-broad set can
 * fail open exactly as a too-narrow one fails to enforce. It is not an
 * integrator-supplied parameter for the same reason: the policy is signed, and an
 * unsigned knob deciding which keys count as security metadata would put part of
 * the decision outside the signature.
 */
const TAG_KEYS = ["tags", "labels", "classification"] as const;

/**
 * Collect the tag strings carried by a matched tag key's value.
 *
 * A scalar counts as a single tag: providers emit both `{tags: ["secret"]}` and
 * `{classification: "secret"}`, and connector spec §7 requires the two to behave
 * identically. Nested arrays are flattened.
 *
 * Only strings are collected. `allowedTags`/`deniedTags` are arrays of strings in
 * the schema, so a non-string value could only match after a stringification whose
 * result differs per language (`String(true)` is `"true"` here and `"True"` in
 * Python) -- and a confidentiality decision must not depend on the host language's
 * formatting. A non-string value still fails closed under an allow-list, because it
 * contributes no tag and therefore no proof of allowance.
 */
function harvestTagValues(value: unknown, into: string[]): void {
  if (typeof value === "string") {
    into.push(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) harvestTagValues(item, into);
  }
}

/**
 * Collect tags from every recognized tag key anywhere in `node`.
 *
 * Recurses into nested records and arrays, matching keys with the same
 * bidirectional, case-insensitive, glob-aware matcher masking and hidden-field
 * removal use (canonical spec §4), so `Tags` and `metadata.tags` are found
 * alongside `tags`.
 */
function collectTags(node: unknown, into: string[]): void {
  if (Array.isArray(node)) {
    for (const item of node) collectTags(item, into);
    return;
  }
  if (!isRecord(node)) return;

  for (const key of Object.keys(node)) {
    if (TAG_KEYS.some((tagKey) => fieldNameMatches(tagKey, key))) {
      harvestTagValues(node[key], into);
    }
    // Walked whether or not the key matched: a matched key holding a record may
    // still nest a tag key of its own.
    collectTags(node[key], into);
  }
}

/**
 * Every tag on a record, lower-cased, from any tag key at any depth.
 *
 * Lower-cased because tag values compare case-insensitively: `deniedTags:
 * ["Secret"]` must drop a record tagged `secret` (connector spec §7).
 */
function extractTags(record: unknown): Set<string> {
  const collected: string[] = [];
  collectTags(record, collected);
  return new Set(collected.map((tag) => tag.toLowerCase()));
}

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
 *
 * Tags are read by {@link extractTags} and compared case-insensitively on both
 * sides.
 */
export function filterByTags(
  results: Array<Record<string, unknown>>,
  policy: EffectivePolicy,
): Array<Record<string, unknown>> {
  const tagRules = policy.objectRules?.tagRules;
  if (!tagRules) return results;

  const allowedTags = tagRules.allowedTags?.map((tag) => tag.toLowerCase());
  const deniedTags = tagRules.deniedTags?.map((tag) => tag.toLowerCase());

  return results.filter((result) => {
    const tags = extractTags(result);

    // Denied tags take precedence: exclude if any tag is denied.
    if (deniedTags && deniedTags.some((tag) => tags.has(tag))) {
      return false;
    }

    // Allowed tags: include only if at least one tag is allowed.
    if (allowedTags && !allowedTags.some((tag) => tags.has(tag))) {
      return false;
    }

    return true;
  });
}

// ---------------------------------------------------------------------------
// Endpoint validation
// ---------------------------------------------------------------------------

/**
 * The methods that only read. Used twice: as the documented default for an
 * omitted allowedMethods, and as the set readOnly permits.
 */
const READ_METHODS = ["GET", "HEAD", "OPTIONS"];

/**
 * Validate whether an endpoint + method is accessible under the effective policy.
 *
 * Three restrictions apply, most-restrictive-first:
 *
 *   1. `hiddenEndpoints` then `allowedEndpoints` gate the path.
 *   2. `readOnly` gates the method. When the permission is true, only
 *      GET/HEAD/OPTIONS are permitted -- regardless of `allowedMethods`, because a
 *      policy that grants DELETE while declaring itself read-only is contradictory
 *      and the restrictive half must win (canonical spec §9). `readOnly` was
 *      previously merged (OR-folded, so any read-only policy in the set made the
 *      result read-only) and then never consulted, so the whole fold had no effect
 *      on any decision.
 *   3. `allowedMethods` gates the method. When omitted it defaults to the read
 *      methods, as the schema documents ("If omitted, defaults to read-only
 *      methods: GET, HEAD, OPTIONS"). Treating omitted as unrestricted -- the
 *      previous behaviour -- let POST/PUT/PATCH/DELETE through on a policy whose
 *      author had been told the default was read-only.
 *
 * `readOnly` is unset on many policies; absent means the schema default of `true`
 * (spec §8), so an endpoint policy silent on `readOnly` is read-only.
 */
export function validateEndpoint(
  path: string,
  method: string,
  policy: EffectivePolicy,
): AccessResult {
  if (!policy.permissions.canQuery) {
    return { allowed: false, reason: "query not permitted" };
  }

  const upperMethod = method.toUpperCase();
  const endpointRules = policy.objectRules?.endpointRules;

  if (endpointRules) {
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
  }

  // Check allowed methods. An omitted list is the documented read-only default,
  // NOT "unrestricted": canonical spec §9 makes this the single deliberate
  // exception to §3's null-means-unrestricted rule, because an absent method list
  // on an endpoint rule is far likelier to be an oversight than an intentional
  // grant of DELETE. Do not "fix" this back to unrestricted for consistency with
  // §3. An empty [] still denies every method, per §3.
  const allowedMethods = endpointRules?.allowedMethods;
  const permitted =
    allowedMethods === undefined
      ? READ_METHODS
      : allowedMethods.map((m) => m.toUpperCase());
  if (!permitted.includes(upperMethod)) {
    return { allowed: false, reason: "method not allowed" };
  }

  // readOnly is checked last so an explicit allowedMethods denial keeps its more
  // specific reason. An absent readOnly takes its schema default of true, matching
  // the merge rules in spec §8: excluding absent booleans from the decision would
  // invert it, letting a policy silent on readOnly permit writes. A policy that
  // lists DELETE in allowedMethods while declaring itself read-only is
  // contradictory, and the restrictive half wins.
  const readOnly = policy.permissions.readOnly !== false;
  if (readOnly && !READ_METHODS.includes(upperMethod)) {
    return { allowed: false, reason: "method not allowed on a read-only policy" };
  }

  return { allowed: true };
}

// ---------------------------------------------------------------------------
// Write validation (connector spec §4)
// ---------------------------------------------------------------------------
//
// Reads filter what comes back. Writes have to be validated BEFORE they reach the
// source, because there is nothing to filter afterwards -- the damage is already
// committed. Everything below runs pre-execution and returns a decision the caller
// must honour; nothing here talks to a data source.

/**
 * Sentinel for "the caller supplied no update/delete target row".
 *
 * Distinct from `{}`, which is a row that genuinely has no fields, and from
 * `undefined`, which a caller can reach by accident. The difference decides between
 * `target row not permitted` (the filters were evaluated and did not match) and
 * `write target unverifiable` (they could not be evaluated at all) — see
 * {@link validateWrite}.
 */
export const TARGET_ROW_UNKNOWN: unique symbol = Symbol("TARGET_ROW_UNKNOWN");

/** The target row a write will modify, or {@link TARGET_ROW_UNKNOWN}. */
export type WriteTargetRow =
  | Record<string, unknown>
  | typeof TARGET_ROW_UNKNOWN
  | undefined;

/**
 * HTTP methods mapped to the permission that governs them (connector spec §6).
 *
 * `GET`/`HEAD`/`OPTIONS` are reads governed by `canQuery`, which
 * {@link validateEndpoint} already enforces, so they are absent on purpose.
 */
const METHOD_WRITE_OPERATIONS: Record<string, WriteOperation> = {
  POST: WriteOperation.Insert,
  PUT: WriteOperation.Update,
  PATCH: WriteOperation.Update,
  DELETE: WriteOperation.Delete,
};

/**
 * The permission each operation consults, in the order it is reported.
 *
 * `upsert` requires both, which is the safe intersection connector spec §8 mandates
 * for a call that cannot distinguish a create from an overwrite.
 */
const OPERATION_PERMISSIONS: Record<WriteOperation, Array<"insert" | "update" | "delete">> = {
  [WriteOperation.Insert]: ["insert"],
  [WriteOperation.Update]: ["update"],
  [WriteOperation.Delete]: ["delete"],
  [WriteOperation.Upsert]: ["insert", "update"],
};

/**
 * The write operation an HTTP method performs, or `undefined` for a read method.
 *
 * `POST` inserts, `PUT`/`PATCH` update, `DELETE` deletes; `GET`/`HEAD`/`OPTIONS`
 * return `undefined` because they are reads governed by `canQuery` (connector spec
 * §6). An unrecognized method also returns `undefined` — it is not silently treated
 * as a read: {@link validateEndpoint} still gates it through `allowedMethods`, whose
 * omitted default is the read methods, so an unknown verb is denied there rather
 * than admitted here.
 */
export function writeOperationForMethod(method: string): WriteOperation | undefined {
  return METHOD_WRITE_OPERATIONS[method.toUpperCase()];
}

/**
 * Whether a write permission is granted, defaulting absent to `false`.
 *
 * The schema default for all three is `false` (connector spec §4.1), so an absent
 * flag is a denial. This is the opposite of `canQuery`, and the asymmetry is the
 * point: a policy authored before writes existed must not silently acquire them.
 */
function permissionGranted(
  policy: EffectivePolicy,
  name: "insert" | "update" | "delete",
): boolean {
  const permissions = policy.permissions;
  const flag =
    name === "insert"
      ? permissions.canInsert
      : name === "update"
        ? permissions.canUpdate
        : permissions.canDelete;
  return flag === true;
}

/** Check 1: the operation's permission, then the `readOnly` ceiling. */
function validateWritePermission(
  operation: WriteOperation,
  policy: EffectivePolicy,
): AccessResult {
  for (const name of OPERATION_PERMISSIONS[operation]) {
    if (!permissionGranted(policy, name)) {
      return { allowed: false, reason: `${name} not permitted` };
    }
  }

  // readOnly is a ceiling, not a peer: it denies every write regardless of the three
  // flags. Absent means the schema default of true (canonical spec §8), so a policy
  // silent on readOnly cannot write.
  if (policy.permissions.readOnly !== false) {
    return { allowed: false, reason: "read-only policy" };
  }

  return { allowed: true };
}

/**
 * Check 2: the target object against `hiddenObjects`/`allowedObjects`.
 *
 * Deliberately not {@link validateAccess}, which leads with `canQuery` and would
 * report `query not permitted` for a write. The object rules themselves are
 * identical, and the reasons stay the ones connector spec §3.3 documents.
 */
function validateWriteObject(
  objectName: string,
  policy: EffectivePolicy,
): AccessResult {
  const rules = policy.objectRules;
  if (!rules) return { allowed: true };

  if (rules.hiddenObjects && matchesAnyGlob(rules.hiddenObjects, objectName)) {
    return { allowed: false, reason: "object is hidden" };
  }

  if (rules.allowedObjects) {
    if (!matchesAnyGlob(rules.allowedObjects, objectName)) {
      return { allowed: false, reason: "object not in allowed set" };
    }
  }

  return { allowed: true };
}

/**
 * Check 3: every field in the payload must be writable.
 *
 * Fails closed on the *whole* write (connector spec §4.4): the first unwritable
 * field denies the entire operation rather than being stripped so the rest can
 * proceed. This is the one place where filtering — the correct answer on the read
 * path — is the wrong answer. A caller that submits `{status, ssn}` and is told the
 * write succeeded, when only `status` landed, holds a model of the data that is
 * wrong in a way it cannot detect.
 *
 * Field names match with the bidirectional, case-insensitive, glob-aware matcher the
 * read path uses (§3.2), so a `readOnlyFields` entry of `patients.created_at` blocks
 * a payload key of `created_at`.
 *
 * The field is named in the reason. That discloses nothing: the caller supplied it.
 * Row denials, by contrast, never name a value.
 */
function validateWrittenFields(
  fields: string[],
  policy: EffectivePolicy,
): AccessResult {
  const fieldRules = policy.objectRules?.fieldRules;
  if (!fieldRules) return { allowed: true };

  for (const name of fields) {
    // A field the caller cannot read, it cannot write.
    if (
      fieldRules.hiddenFields?.some((pattern) => fieldNameMatches(pattern, name))
    ) {
      return { allowed: false, reason: `field is hidden: ${name}` };
    }

    // readOnlyFields: readable but not writable. This is the whole meaning of the
    // field (connector spec §4.3) and it has no effect on reads.
    if (
      fieldRules.readOnlyFields?.some((pattern) => fieldNameMatches(pattern, name))
    ) {
      return { allowed: false, reason: `field is read-only: ${name}` };
    }

    // undefined is unrestricted; [] denies every field (canonical spec §3), so this
    // tests for presence rather than truthiness.
    if (fieldRules.allowedFields !== undefined) {
      if (!fieldRules.allowedFields.some((pattern) => fieldNameMatches(pattern, name))) {
        return { allowed: false, reason: `field not in allowed set: ${name}` };
      }
    }
  }

  return { allowed: true };
}

/**
 * Check 4: row filters must match the row an update or delete targets.
 *
 * A caller must not be able to modify a row it could not have selected, so the
 * policy's row filters are evaluated against the target and a non-match is
 * `target row not permitted`.
 *
 * When filters exist and no target row was supplied, the result is
 * `write target unverifiable` — **not** an allow. The integrator's options are to
 * read the row first and pass it here, or to push the filters into the statement's
 * `WHERE` so the source applies them; an unqualified `DELETE FROM patients` under a
 * region-scoped policy has to be refused rather than executed and hoped over
 * (connector spec §4.2 and §5).
 *
 * An insert has no pre-existing target, so this check does not apply to it. The row
 * it *creates* is governed by the field checks above: a policy scoped by `region`
 * cannot stop an insert writing a foreign region unless `region` is in
 * `readOnlyFields` or outside `allowedFields`, which is a gap in the policy language
 * rather than in this implementation.
 */
function validateWriteTargetRow(
  operation: WriteOperation,
  targetRow: WriteTargetRow,
  policy: EffectivePolicy,
): AccessResult {
  if (operation === WriteOperation.Insert) return { allowed: true };

  const filters = policy.objectRules?.rowFilters;
  if (!filters || filters.length === 0) return { allowed: true };

  // A target that is absent, or one the filters cannot be evaluated against, is
  // unverifiable for the same reason -- not a target that happens to pass.
  if (targetRow === TARGET_ROW_UNKNOWN || !isRecord(targetRow)) {
    return { allowed: false, reason: "write target unverifiable" };
  }

  // The row must satisfy every filter, exactly as it would to be returned by a read
  // (canonical spec §7): a missing field fails closed.
  if (!filters.every((filter) => rowPassesFilter(targetRow, filter))) {
    // Deliberately does not name the field or the value; §4.4 permits naming a
    // payload field the caller supplied, never a row value.
    return { allowed: false, reason: "target row not permitted" };
  }

  return { allowed: true };
}

/**
 * The field names a payload attempts to write.
 *
 * A record contributes its keys; anything else contributes nothing, because only a
 * record names fields. Nested keys are *not* flattened into dotted paths: the field
 * matcher already reaches a bare `ssn` from a rule of `patients.ssn` and vice versa
 * (§3.2), so walking the tree and collecting every key at every depth is what a rule
 * needs to see.
 *
 * `resourceFields` extends the set with fields the body does not mention. It exists
 * for the full-resource-replace rule (see {@link validateWrite}'s `fullReplace`); it
 * is deliberately not inferred from anything, because only the integrator knows a
 * resource's shape.
 */
export function payloadWriteFields(
  payload: unknown,
  resourceFields?: string[],
): string[] {
  const names: string[] = [];
  const seen = new Set<string>();

  const add = (name: string): void => {
    if (!seen.has(name)) {
      seen.add(name);
      names.push(name);
    }
  };

  const walk = (node: unknown): void => {
    if (Array.isArray(node)) {
      for (const item of node) walk(item);
      return;
    }
    if (!isRecord(node)) return;
    for (const key of Object.keys(node)) {
      add(key);
      walk(node[key]);
    }
  };

  walk(payload);
  if (resourceFields !== undefined) {
    for (const name of resourceFields) add(name);
  }
  return names;
}

/**
 * Every field the policy forbids writing, as written in the policy.
 *
 * Used to give the full-resource-replace rule (connector spec §6) teeth when the
 * caller cannot enumerate the resource: a replace writes every field of the
 * resource, and the fields whose overwrite must be denied are exactly the ones the
 * policy protects, so treating them as present is the fail-closed reading. It is
 * *not* an approximation of the resource's shape — it is the subset of any
 * resource's shape that the policy cares about.
 *
 * `allowedFields` cannot be handled this way: the risk there is a resource field the
 * allow-list omits, which is unknowable without the resource's field list. An
 * integrator combining `allowedFields` with full-resource replaces must pass
 * `resourceFields`.
 */
function protectedFieldNames(policy: EffectivePolicy): string[] {
  const fieldRules = policy.objectRules?.fieldRules;
  if (!fieldRules) return [];
  return [...(fieldRules.hiddenFields ?? []), ...(fieldRules.readOnlyFields ?? [])];
}

/** Optional arguments to {@link validateWrite}. */
export interface ValidateWriteOptions {
  /**
   * The row an update or delete will modify. Omitting it while the policy carries
   * row filters yields `write target unverifiable`, never an allow.
   */
  targetRow?: WriteTargetRow;
  /**
   * Fields of the resource the body does not mention, for a full-resource replace.
   * Required alongside {@link fullReplace} when the policy sets `allowedFields`.
   */
  resourceFields?: string[];
  /**
   * Whether this write replaces the whole resource rather than the keys it
   * mentions. An HTTP `PUT` is the canonical case (connector spec §6).
   */
  fullReplace?: boolean;
}

const WRITE_OPERATIONS: Record<string, WriteOperation> = Object.fromEntries(
  Object.values(WriteOperation).map((op) => [op, op]),
);

/** Resolve an operation name, case-insensitively, or `undefined` if unrecognized. */
function resolveWriteOperation(
  value: WriteOperation | string,
): WriteOperation | undefined {
  return WRITE_OPERATIONS[String(value).toLowerCase()];
}

/**
 * Validate a write before it reaches the data source (connector spec §4).
 *
 * Runs the four required pre-write checks in order — cheapest first, all of them
 * mandatory:
 *
 *   1. the operation's permission (`canInsert`/`canUpdate`/`canDelete`), then the
 *      `readOnly` ceiling
 *   2. the target object against `hiddenObjects`/`allowedObjects`
 *   3. every field in the payload against `hiddenFields`, `readOnlyFields` and
 *      `allowedFields`
 *   4. the policy's row filters against the update/delete target row
 *
 * Fails closed and rejects the whole write: one unwritable field denies the
 * operation rather than being dropped so the rest can proceed (§4.4). The reason
 * strings are part of the contract — integrators log and branch on them.
 *
 * `operation` accepts a {@link WriteOperation} or its string value. An `upsert` — a
 * call that cannot distinguish a create from an overwrite, such as an unconditional
 * object-store `PUT` — requires **both** `canInsert` and `canUpdate` (§8).
 *
 * `options.fullReplace` marks a write that replaces the whole resource rather than
 * the keys it mentions. Omitting a `readOnlyFields` field from a full replace is
 * still an attempt to overwrite it, this time with absent, so every field the policy
 * protects is validated as though the body had named it.
 *
 * A permitted write that returns data — `INSERT ... RETURNING`, a 201 body, updated
 * metadata — is a *read* of that data, so run {@link applyResultPipeline} over the
 * response (§4.5). A masked field must come back masked even when the caller just
 * wrote it.
 */
export function validateWrite(
  operation: WriteOperation | string,
  objectName: string | undefined,
  payload: unknown,
  policy: EffectivePolicy,
  options: ValidateWriteOptions = {},
): AccessResult {
  const resolved = resolveWriteOperation(operation);
  if (resolved === undefined) {
    // An operation this SDK cannot classify is denied rather than admitted: there is
    // no permission to consult, so there is no grant to rely on.
    return { allowed: false, reason: "unknown write operation" };
  }

  const permission = validateWritePermission(resolved, policy);
  if (!permission.allowed) return permission;

  if (objectName !== undefined) {
    const target = validateWriteObject(objectName, policy);
    if (!target.allowed) return target;
  }

  const written = payloadWriteFields(payload, options.resourceFields);
  if (options.fullReplace === true) {
    for (const name of protectedFieldNames(policy)) {
      if (!written.includes(name)) written.push(name);
    }
  }

  const fields = validateWrittenFields(written, policy);
  if (!fields.allowed) return fields;

  return validateWriteTargetRow(
    resolved,
    options.targetRow ?? TARGET_ROW_UNKNOWN,
    policy,
  );
}

/**
 * Validate an HTTP write: endpoint rules, then the §4 write checks.
 *
 * Method and permission must agree and *both* are checked (connector spec §6):
 * {@link validateEndpoint} gates the path and the method through
 * `allowedEndpoints`/`hiddenEndpoints`/`allowedMethods`, and the write checks then
 * gate the operation the method performs and the body it carries. Neither
 * substitutes for the other — `allowedMethods: ["POST"]` says nothing about
 * `canInsert`, and `canInsert` says nothing about which paths are reachable.
 *
 * A read method (`GET`/`HEAD`/`OPTIONS`) is not a write, so this returns the
 * endpoint decision unchanged rather than inventing a write permission for it.
 *
 * A `PUT` is treated as a **full-resource replace** (§6): every field the policy
 * protects is validated as though the body had named it, because a replace that omits
 * a `readOnlyFields` field is still attempting to overwrite it with absent. `PATCH`
 * is a partial update, so only the keys present are validated. Supply
 * `options.resourceFields` to extend the replace to fields the policy does not itself
 * name — needed when `allowedFields` is set, since a resource field missing from an
 * allow-list cannot be inferred from the policy alone.
 */
export function validateHttpWrite(
  method: string,
  path: string,
  payload: unknown,
  policy: EffectivePolicy,
  options: ValidateWriteOptions & { objectName?: string } = {},
): AccessResult {
  const endpoint = validateEndpoint(path, method, policy);
  if (!endpoint.allowed) return endpoint;

  const operation = writeOperationForMethod(method);
  if (operation === undefined) return endpoint;

  return validateWrite(operation, options.objectName, payload, policy, {
    targetRow: options.targetRow,
    resourceFields: options.resourceFields,
    fullReplace: method.toUpperCase() === "PUT",
  });
}
