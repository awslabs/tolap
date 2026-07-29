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
  applyMask,
  applyResultLimit,
  projectAllowedFields,
  stripHiddenFields,
  validateContext,
  validateEndpoint,
  validateExpiry,
  type AccessResult,
  type EffectivePolicy,
  type MaskingRule,
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

    // Canonical pipeline order (spec §4): hidden fields, then the allowedFields
    // projection, then masking, then the result limit. Hidden/allowed removal
    // precedes masking so a field that is both hidden and masked is removed
    // rather than returned in masked form.
    body = stripHiddenFields(body, policy);
    body = projectAllowedFieldsInBody(body, args.collectionPath, policy);
    body = applyMaskingToBody(body, policy);
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

// A plain `node[key] = value` where key is "__proto__" reassigns the object's
// prototype instead of adding a property, so a hostile response body could
// reshape Object.prototype while being masked. Skipping the whole family
// (including "constructor" and "prototype") is defense-in-depth: no policy rule
// needs to address them, and no legitimate JSON body should be walked through
// them.
const DANGEROUS_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function isDangerousKey(key: string): boolean {
  return DANGEROUS_KEYS.has(key);
}

function walkAndMask(node: unknown, parts: string[], rule: MaskingRule): void {
  if (parts.length === 0) return;
  if (Array.isArray(node)) {
    for (const item of node) walkAndMask(item, parts, rule);
    return;
  }
  if (!isObject(node)) return;
  const [head, ...rest] = parts;
  if (isDangerousKey(head)) return;
  if (!Object.prototype.hasOwnProperty.call(node, head)) return;
  if (rest.length === 0) {
    Object.defineProperty(node, head, {
      value: applyMask(node[head], rule),
      writable: true,
      enumerable: true,
      configurable: true,
    });
  } else {
    walkAndMask(node[head], rest, rule);
  }
}

function deepClone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

/**
 * Apply every maskedFields rule to a (potentially nested) JSON body.
 *
 * Masking delegates to the shared core `applyMask`, so an unknown maskType
 * redacts here exactly as it does on the DB path rather than returning the raw
 * value.
 */
function applyMaskingToBody(body: unknown, policy: EffectivePolicy): unknown {
  const masked = policy.objectRules?.fieldRules?.maskedFields;
  if (!masked || masked.length === 0) return body;
  const cloned = deepClone(body);
  for (const rule of masked) {
    walkAndMask(cloned, rule.field.split("."), rule);
  }
  return cloned;
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
