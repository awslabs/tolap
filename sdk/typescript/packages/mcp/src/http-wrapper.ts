/**
 * TOLAP enforcement around a fetch-style HTTP transport.
 *
 * Direct counterpart to Python's tolap_mcp.http_wrapper.SecureHttpToolWrapper:
 *
 *   - Pre-call: validateEndpoint + signature/expiry on the SecurityContext.
 *   - Post-call: hidden-field stripping, allowed-field projection, dotted-path
 *     masking, and result-limit truncation of a configurable collectionPath in
 *     the JSON body.
 *
 * Bring your own fetch-shaped function so this works in Node, the browser, or
 * a vitest mock harness.
 */

import {
  applyMaskingToTree,
  applyObjectSizeCeiling,
  applyResultLimit,
  applyRowFilters,
  applySimilarityFloor,
  filterByTags,
  projectAllowedFields,
  stripHiddenFields,
  validateContext,
  validateEndpoint,
  validateExpiry,
  type AccessResult,
  type EffectivePolicy,
  type SecurityContext,
} from "@tolap/core";

export type FetchLike = (
  input: { method: string; url: string; body?: unknown; headers?: Record<string, string> },
) => Promise<{ ok: boolean; status: number; json: () => Promise<unknown> }>;

export interface SecureHttpWrapperOptions {
  signingKey: string;
  enforceSignatures?: boolean;
  enforceExpiry?: boolean;
  baseUrl?: string;
}

export interface RequestArgs {
  method: string;
  path: string;
  body?: unknown;
  headers?: Record<string, string>;
  collectionPath?: string;
}

export class SecureHttpToolWrapper {
  private options: Required<
    Pick<SecureHttpWrapperOptions, "enforceSignatures" | "enforceExpiry">
  > &
    SecureHttpWrapperOptions;
  private fetchFn: FetchLike;

  constructor(options: SecureHttpWrapperOptions, fetchFn: FetchLike) {
    this.options = {
      enforceSignatures: true,
      enforceExpiry: true,
      ...options,
    };
    this.fetchFn = fetchFn;
  }

  /** Validate signature then expiry; a missing or unparseable expiry is a denial. */
  validateSecurityContext(context: SecurityContext): AccessResult {
    if (this.options.enforceSignatures) {
      if (!validateContext(context, this.options.signingKey)) {
        return { allowed: false, reason: "invalid signature" };
      }
    }
    if (this.options.enforceExpiry) {
      const expiryReason = validateExpiry(context);
      if (expiryReason !== undefined) {
        return { allowed: false, reason: expiryReason };
      }
    }
    return { allowed: true };
  }

  async request(context: SecurityContext, args: RequestArgs): Promise<unknown> {
    const ctxResult = this.validateSecurityContext(context);
    if (!ctxResult.allowed) {
      throw new Error(`Access denied: ${ctxResult.reason}`);
    }

    const policy = context.effectivePolicy;
    if (!policy.permissions.canQuery) {
      throw new Error("Access denied: query not permitted");
    }

    // Strip any query string before policy evaluation; policy patterns are
    // written against paths, not URLs. Without this, /drug/event.json?limit=3
    // would not match an "/drug/*" allow-pattern.
    const queryIndex = args.path.indexOf("?");
    const policyPath = queryIndex >= 0 ? args.path.slice(0, queryIndex) : args.path;

    const ep = validateEndpoint(policyPath, args.method, policy);
    if (!ep.allowed) {
      throw new Error(`Access denied: ${ep.reason}`);
    }

    const url = (this.options.baseUrl ?? "") + args.path;
    const response = await this.fetchFn({
      method: args.method,
      url,
      body: args.body,
      headers: args.headers,
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status} from ${url}`);
    }
    let body = (await response.json()) as unknown;

    // Canonical pipeline order (spec §4), all eight steps: row filters, tag
    // filters, relevance floor, size ceiling, hidden fields, the allowedFields
    // projection, masking, then the result limit. The four record-dropping steps
    // were previously absent here, so rowFilters, allowedTags/deniedTags,
    // minSimilarityScore, and maxObjectSizeBytes were all silent no-ops on the API
    // path while the identical policy filtered correctly through the MCP and
    // context wrappers. Every record-dropping step precedes every field-level step
    // so work is not spent masking a record about to be discarded;
    // hidden/allowed removal precedes masking so a field that is both hidden and
    // masked is removed rather than returned in masked form; and the limit runs
    // last so filtering never yields fewer records than maxResults when more
    // qualifying records exist.
    body = filterRecordsInBody(body, args.collectionPath, policy);
    body = stripHiddenFields(body, policy);
    body = projectAllowedFieldsInBody(body, args.collectionPath, policy);
    body = applyMaskingToTree(body, policy);
    body = limitCollection(body, args.collectionPath, policy);
    return body;
  }
}

// ---------------------------------------------------------------------------
// JSON tree helpers (mirror Python implementation)
// ---------------------------------------------------------------------------

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function deepClone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

/**
 * Run the record-dropping steps -- row filters, tag filters, the relevance floor,
 * and the size ceiling -- over the record collection inside a response body.
 *
 * These were previously missing from the HTTP path entirely, which made
 * `rowFilters`, `allowedTags`/`deniedTags`, `minSimilarityScore`, and
 * `maxObjectSizeBytes` silent no-ops over HTTP while the same policy filtered
 * correctly on the DB/MCP path (spec §4 requires every wrapper, in every language,
 * to run all eight steps in order). The `[]` allow-list case matters most:
 * `allowedTags: []` is deny-all (spec §3), so skipping the step turned the most
 * restrictive possible policy into no policy at all.
 *
 * Filtering targets the records -- the array at `collectionPath`, or the body when
 * the body *is* the collection -- not the transport envelope, so an API's
 * meta/paging block survives, exactly as the projection and limit steps already do.
 * A body that is a single record runs the identical filters and becomes an empty
 * collection when it is dropped.
 */
function filterRecordsInBody(
  body: unknown,
  collectionPath: string | undefined,
  policy: EffectivePolicy,
): unknown {
  const objectRules = policy.objectRules;
  const hasRowFilters = (objectRules?.rowFilters?.length ?? 0) > 0;
  // `tagRules` present but empty-valued still constrains: allowedTags: [] denies
  // everything, so presence -- not truthiness of the arrays -- is the test.
  const hasTagRules = objectRules?.tagRules !== undefined;
  const hasRelevanceFloor = policy.limits?.minSimilarityScore !== undefined;
  const hasSizeCeiling = policy.limits?.maxObjectSizeBytes !== undefined;
  if (!hasRowFilters && !hasTagRules && !hasRelevanceFloor && !hasSizeCeiling) {
    return body;
  }

  const filter = (records: unknown[]): Array<Record<string, unknown>> => {
    // Non-record entries cannot be evaluated against a field, tag, score, or size
    // rule. Dropping them fails closed: the policy author asked for a constraint
    // and we cannot prove it holds (spec §5/§7).
    const asRecords = records.filter((item): item is Record<string, unknown> =>
      isObject(item),
    );
    return applyObjectSizeCeiling(
      applySimilarityFloor(
        filterByTags(applyRowFilters(asRecords, policy), policy),
        policy,
      ),
      policy,
    );
  };

  if (collectionPath === undefined) {
    if (Array.isArray(body)) return filter(deepClone(body));
    if (isObject(body)) return filter([deepClone(body)]);
    return body;
  }

  const parts = collectionPath.split(".");
  const filtered = deepClone(body);
  let cursor: unknown = filtered;
  for (let i = 0; i < parts.length - 1; i++) {
    if (!isObject(cursor) || !(parts[i] in cursor)) return filtered;
    cursor = cursor[parts[i]];
  }
  const leaf = parts[parts.length - 1];
  if (isObject(cursor) && Array.isArray(cursor[leaf])) {
    cursor[leaf] = filter(cursor[leaf] as unknown[]);
  }
  return filtered;
}

/**
 * Project the response's records down to allowedFields.
 *
 * Projection targets the records themselves — the array at `collectionPath`, or
 * the body when the body *is* the collection — rather than the transport
 * envelope, so an API's meta/paging block survives while a record returning
 * columns the policy never listed is trimmed. When no allowedFields is set
 * (undefined) the body is returned untouched; an empty allow-list denies every
 * field.
 */
function projectAllowedFieldsInBody(
  body: unknown,
  collectionPath: string | undefined,
  policy: EffectivePolicy,
): unknown {
  if (policy.objectRules?.fieldRules?.allowedFields === undefined) return body;

  if (collectionPath === undefined) {
    if (Array.isArray(body) || isObject(body)) {
      return projectAllowedFields(body, policy);
    }
    return body;
  }

  const parts = collectionPath.split(".");
  const projected = deepClone(body);
  let cursor: unknown = projected;
  for (let i = 0; i < parts.length - 1; i++) {
    if (!isObject(cursor) || !(parts[i] in cursor)) return projected;
    cursor = cursor[parts[i]];
  }
  const leaf = parts[parts.length - 1];
  if (isObject(cursor) && Array.isArray(cursor[leaf])) {
    cursor[leaf] = projectAllowedFields(
      cursor[leaf] as Array<Record<string, unknown>>,
      policy,
    );
  }
  return projected;
}

function limitCollection(
  body: unknown,
  collectionPath: string | undefined,
  policy: EffectivePolicy,
): unknown {
  if (policy.limits?.maxResults === undefined) return body;
  if (!collectionPath) {
    if (Array.isArray(body)) {
      return applyResultLimit(body, policy);
    }
    return body;
  }
  const parts = collectionPath.split(".");
  let cursor: unknown = body;
  for (let i = 0; i < parts.length - 1; i++) {
    if (!isObject(cursor) || !(parts[i] in cursor)) return body;
    cursor = (cursor as Record<string, unknown>)[parts[i]];
  }
  const leaf = parts[parts.length - 1];
  if (isObject(cursor) && Array.isArray(cursor[leaf])) {
    cursor[leaf] = applyResultLimit(cursor[leaf] as unknown[], policy);
  }
  return body;
}
