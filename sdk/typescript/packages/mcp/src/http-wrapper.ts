/**
 * TOLAP enforcement around a fetch-style HTTP transport.
 *
 * Direct counterpart to Python's tolap_mcp.http_wrapper.SecureHttpToolWrapper:
 *
 *   - Pre-call: validateEndpoint + signature/expiry on the SecurityContext.
 *   - Post-call: dotted-path masking, hidden-field stripping, and result-limit
 *     truncation of a configurable collectionPath in the JSON body.
 *
 * Bring your own fetch-shaped function so this works in Node, the browser, or
 * a vitest mock harness.
 */

import {
  applyResultLimit,
  validateContext,
  validateEndpoint,
  type AccessResult,
  type EffectivePolicy,
  type MaskingRule,
  type SecurityContext,
} from "@tolap/core";

import { createHash } from "node:crypto";

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

  validateSecurityContext(context: SecurityContext): AccessResult {
    if (this.options.enforceSignatures) {
      if (!validateContext(context, this.options.signingKey)) {
        return { allowed: false, reason: "invalid signature" };
      }
    }
    if (this.options.enforceExpiry && context.expiresAt) {
      const expiry = new Date(context.expiresAt);
      if (expiry.getTime() < Date.now()) {
        return { allowed: false, reason: "security context expired" };
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

    body = stripHiddenFields(body, policy);
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

function walkAndDrop(node: unknown, parts: string[]): void {
  if (parts.length === 0) return;
  if (Array.isArray(node)) {
    for (const item of node) walkAndDrop(item, parts);
    return;
  }
  if (!isObject(node)) return;
  const [head, ...rest] = parts;
  if (!(head in node)) return;
  if (rest.length === 0) {
    delete node[head];
  } else {
    walkAndDrop(node[head], rest);
  }
}

function walkAndMask(node: unknown, parts: string[], rule: MaskingRule): void {
  if (parts.length === 0) return;
  if (Array.isArray(node)) {
    for (const item of node) walkAndMask(item, parts, rule);
    return;
  }
  if (!isObject(node)) return;
  const [head, ...rest] = parts;
  if (!(head in node)) return;
  if (rest.length === 0) {
    node[head] = applyMask(node[head], rule);
  } else {
    walkAndMask(node[head], rest, rule);
  }
}

function applyMask(value: unknown, rule: MaskingRule): unknown {
  switch (rule.maskType) {
    case "full": {
      const str = String(value ?? "");
      const mc = rule.parameters?.maskChar ?? "*";
      return mc.repeat(str.length);
    }
    case "partial": {
      const str = String(value ?? "");
      const showFirst = rule.parameters?.showFirst ?? 0;
      const showLast = rule.parameters?.showLast ?? 0;
      const mc = rule.parameters?.maskChar ?? "*";
      if (showFirst + showLast >= str.length) return str;
      return (
        str.slice(0, showFirst) +
        mc.repeat(str.length - showFirst - showLast) +
        (showLast > 0 ? str.slice(-showLast) : "")
      );
    }
    case "hash": {
      const str = String(value ?? "");
      const algo = rule.parameters?.algorithm ?? "sha256";
      return createHash(algo).update(str).digest("hex").slice(0, 16);
    }
    case "null":
      return null;
    case "redact":
      return "[REDACTED]";
    default:
      return value;
  }
}

function deepClone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function stripHiddenFields(body: unknown, policy: EffectivePolicy): unknown {
  const hidden = policy.objectRules?.fieldRules?.hiddenFields;
  if (!hidden || hidden.length === 0) return body;
  const cloned = deepClone(body);
  for (const pattern of hidden) {
    walkAndDrop(cloned, pattern.split("."));
  }
  return cloned;
}

function applyMaskingToBody(body: unknown, policy: EffectivePolicy): unknown {
  const masked = policy.objectRules?.fieldRules?.maskedFields;
  if (!masked || masked.length === 0) return body;
  const cloned = deepClone(body);
  for (const rule of masked) {
    walkAndMask(cloned, rule.field.split("."), rule);
  }
  return cloned;
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
