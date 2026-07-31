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
 *
 * Two connector spec §6 requirements shape the request loop rather than the body
 * pipeline:
 *
 *   - **Error bodies are enforced.** A 4xx/5xx payload carries the same fields as
 *     a success payload, so it runs the identical pipeline and surfaces as an
 *     {@link UpstreamHttpError} carrying the *enforced* body. Throwing a bare
 *     `Error` on `!response.ok` left the body unenforced and the response object
 *     in the caller's hands.
 *   - **Redirects are re-validated.** `redirect: "manual"` is requested on every
 *     hop and each target is re-checked against the endpoint rules, because a
 *     permitted endpoint that 302s to a denied one otherwise bypasses the check.
 *     `fetch` follows redirects by default, so this path was exposed.
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
  UnenforceableResultError,
  validateAccess,
  validateContext,
  validateExpiry,
  validateHttpWrite,
  type AccessResult,
  type EffectivePolicy,
  type SecurityContext,
  type WriteTargetRow,
} from "@tolap/core";

/**
 * How many redirect hops a single request may take before it is denied.
 *
 * Explicit, and identical in all three SDKs, precisely because every client's own
 * default differs — `fetch` allows 20, httpx 20, .NET's `HttpClientHandler` 50.
 * Inheriting whichever number the transport happened to pick is how the redirect
 * gap arose in the first place. Five is the historical HTTP recommendation and far
 * more than any legitimate API needs; a longer chain is a loop or a
 * misconfiguration, and either way the caller learns rather than hangs.
 */
export const MAX_REDIRECTS = 5;

/**
 * The 3xx codes that carry the original method and body to the new location.
 *
 * 301/302/303 downgrade to `GET` and drop the body, as every browser and HTTP
 * client does; the downgraded request is itself re-validated, so the downgrade
 * cannot smuggle a request past the method rules either.
 */
const METHOD_PRESERVING_REDIRECTS = new Set([307, 308]);

/** The 3xx statuses this wrapper treats as a redirect needing re-validation. */
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/**
 * A non-2xx response, carrying the policy-enforced body.
 *
 * Thrown instead of a bare `Error` because connector spec §6 requires a 4xx/5xx
 * payload to carry the same enforcement as a success payload — a validation error
 * echoing a rejected value is the common leak. `body` is the error payload after
 * the full pipeline (canonical spec §4) has run over it, or `undefined` when the
 * payload was not JSON and therefore could not be enforced at all: a body policy
 * cannot be applied to is withheld rather than passed through (canonical spec §5).
 *
 * Deliberately carries no handle on the response object. The whole point of
 * enforcing an error body is defeated if the exception also ships the raw one.
 */
export class UpstreamHttpError extends Error {
  readonly status: number;
  readonly body: unknown;
  readonly url: string;

  constructor(status: number, body: unknown, url: string) {
    super(`HTTP ${status} from ${url}`);
    this.name = "UpstreamHttpError";
    this.status = status;
    this.body = body;
    this.url = url;
  }
}

/**
 * The transport this wrapper drives.
 *
 * `redirect` is passed as `"manual"` on every call and MUST be honoured: the
 * wrapper re-validates each hop itself (connector spec §6), so a transport that
 * follows a redirect internally denies the wrapper the chance. A `fetch`-backed
 * implementation forwards it straight through to `fetch`, which is why it is
 * spelled the way `fetch` spells it.
 *
 * `headers` is needed to read `Location`; `redirected` lets the wrapper detect a
 * transport that followed anyway and refuse rather than enforce a body it never
 * authorized the fetch of.
 */
export type FetchLike = (
  input: {
    method: string;
    url: string;
    body?: unknown;
    headers?: Record<string, string>;
    redirect: "manual";
  },
) => Promise<{
  ok: boolean;
  status: number;
  json: () => Promise<unknown>;
  /** Response headers; `Location` is read from here on a 3xx. */
  headers?: { get(name: string): string | null };
  /** True when the transport followed a redirect despite `redirect: "manual"`. */
  redirected?: boolean;
  /** The URL the response actually came from, when the transport reports it. */
  url?: string;
}>;

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
  /**
   * The object behind this route, checked against `allowedObjects`/`hiddenObjects`.
   *
   * Honoured on **every** method when supplied, not only on a write, and re-checked
   * on every redirect hop. Omitting it skips the check rather than guessing: no
   * wrapper derives a resource name from a path, and connector spec §6 is explicit
   * that an author "MUST express API restrictions as `endpointRules`". Supplying it
   * is what makes the control usable over HTTP without inventing inference.
   */
  objectName?: string;
  /**
   * The row a `PUT`/`PATCH`/`DELETE` will modify. Omitting it while the policy
   * carries row filters denies the write with `write target unverifiable`.
   */
  targetRow?: WriteTargetRow;
  /**
   * Fields of the resource a `PUT` body does not mention. Required when the policy
   * sets `allowedFields` and the write is a full-resource replace (connector spec §6).
   */
  resourceFields?: string[];
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

  /**
   * Run every pre-request check for one request, initial hop or redirect.
   *
   * Factored out of {@link request} so a redirect hop cannot be validated more
   * weakly than the request that produced it: the identical function decides both.
   * Connector spec §6 requires a redirect to be "re-validated against the endpoint
   * rules before being followed", and a 307/308 preserves the method and body, so
   * the write checks are re-run too rather than just the path.
   *
   * The query string is cut before evaluation because policy patterns are written
   * against paths, not URLs, so `?` parameters cannot smuggle a path past a glob.
   */
  private validateHop(
    method: string,
    path: string,
    body: unknown,
    policy: EffectivePolicy,
    args: RequestArgs,
  ): AccessResult {
    const queryIndex = path.indexOf("?");
    const policyPath = queryIndex >= 0 ? path.slice(0, queryIndex) : path;

    // Endpoint rules and, for a write method, the §4 write checks. Both halves run:
    // an endpoint allow-list is not a write grant, and a write permission does not
    // make a path reachable.
    const decision = validateHttpWrite(method, policyPath, body, policy, {
      objectName: args.objectName,
      targetRow: args.targetRow,
      resourceFields: args.resourceFields,
    });
    if (!decision.allowed) return decision;

    // `allowedObjects`/`hiddenObjects` are honoured only when the integrator names
    // the object (connector spec §6, last bullet). No resource name is *derived*
    // from the path — that would be unspecified inference, and the spec requires API
    // restrictions to be expressed as `endpointRules`. But a caller who does know
    // the resource behind a route should not have the control silently ignored,
    // which is what happened before: `objectName` was forwarded to the write checks
    // and therefore consulted on a POST, while a GET to the same route skipped it.
    //
    // Runs after the endpoint decision so a hidden endpoint keeps reporting itself
    // as such, and re-checks the write path's object rules with the identical
    // outcome rather than branching on the method.
    if (args.objectName !== undefined) {
      return validateAccess(args.objectName, policy);
    }

    return decision;
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

  /**
   * Issue an HTTP request with full pre/post enforcement.
   *
   * A write method is additionally validated per connector spec §4 before the
   * request leaves the process: the operation's permission (`POST`->`canInsert`,
   * `PUT`/`PATCH`->`canUpdate`, `DELETE`->`canDelete`), the `readOnly` ceiling,
   * `args.objectName` against the object rules, every field in `args.body` against
   * `hiddenFields`/`readOnlyFields`/`allowedFields`, and the policy's row filters
   * against `args.targetRow`. Method and permission must both agree:
   * `allowedMethods: ["POST"]` says nothing about `canInsert`.
   *
   * A `PUT` is treated as replacing the whole resource, so every field the policy
   * protects is checked as though the body had named it — omitting a `readOnlyFields`
   * field from a replace is still an attempt to overwrite it. Supply
   * `args.resourceFields` when the policy also sets `allowedFields`.
   *
   * The response body runs the same post-execution pipeline as a read, because a
   * write's response *is* a read of the data it returns (§4.5). That includes a
   * **4xx/5xx** body: an error payload carries the same fields as a success
   * payload, so it is enforced and then thrown as an {@link UpstreamHttpError} with
   * the enforced body attached (§6).
   *
   * A **redirect is never followed blind** (§6). `redirect: "manual"` is requested
   * on every hop, and each target is re-validated against the endpoint rules before
   * it is fetched. A cross-origin redirect is refused outright, and the chain is
   * bounded by {@link MAX_REDIRECTS}.
   *
   * `args.objectName` is honoured on every method when supplied, not just on a
   * write, so `allowedObjects`/`hiddenObjects` are usable over HTTP for an
   * integrator who knows the resource behind a route. Nothing is inferred from the
   * path itself.
   */
  async request(context: SecurityContext, args: RequestArgs): Promise<unknown> {
    const ctxResult = this.validateSecurityContext(context);
    if (!ctxResult.allowed) {
      throw new Error(`Access denied: ${ctxResult.reason}`);
    }

    const policy = context.effectivePolicy;
    if (!policy.permissions.canQuery) {
      throw new Error("Access denied: query not permitted");
    }

    const first = this.validateHop(args.method, args.path, args.body, policy, args);
    if (!first.allowed) {
      throw new Error(`Access denied: ${first.reason}`);
    }

    // The redirect chain. `redirect: "manual"` is requested on every hop because
    // `fetch` follows redirects by default: a permitted endpoint that 302s to a
    // denied one bypassed every endpoint check, and the wrapper never saw the hop.
    let hopMethod = args.method;
    let hopBody = args.body;
    let url = (this.options.baseUrl ?? "") + args.path;
    let response: Awaited<ReturnType<FetchLike>> | undefined;

    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      response = await this.fetchFn({
        method: hopMethod,
        url,
        body: hopBody,
        headers: args.headers,
        redirect: "manual",
      });

      // A transport that followed the redirect itself, despite being asked not to,
      // has already fetched a location no check approved. Refused rather than
      // enforced: the body in hand came from an unvalidated hop.
      if (response.redirected === true) {
        throw new Error(
          "Access denied: transport followed a redirect that was not re-validated",
        );
      }

      const location = REDIRECT_STATUSES.has(response.status)
        ? (response.headers?.get("location") ?? null)
        : null;
      if (location === null) break;

      // Resolves a relative Location ("/admin/audit", "../v2/x") against the URL
      // actually requested, and leaves an absolute one alone.
      const next = resolveLocation(url, location);
      if (!sameOrigin(url, next)) {
        // A cross-origin redirect is refused rather than re-globbed. An absolute URL
        // to another host is outside the policy's frame of reference entirely:
        // `allowedEndpoints: ["/*"]` describes paths on the source this policy was
        // resolved for, and matching that glob against a path on another host would
        // "permit" an origin the author never considered.
        throw new Error(`Access denied: redirect crosses origin to ${originOf(next)}`);
      }

      // 301/302/303 downgrade to GET and drop the body; 307/308 preserve both. The
      // downgraded method is re-validated too, so the downgrade cannot smuggle a
      // request past the method rules in either direction.
      if (!METHOD_PRESERVING_REDIRECTS.has(response.status)) {
        hopMethod = "GET";
        hopBody = undefined;
      }

      const hopResult = this.validateHop(hopMethod, pathOf(next), hopBody, policy, args);
      if (!hopResult.allowed) {
        throw new Error(`Access denied: redirect target rejected: ${hopResult.reason}`);
      }

      if (hop === MAX_REDIRECTS) {
        // The budget is exhausted and a redirect is still pending. Denied rather
        // than followed: /redirect-loop points at itself, and a wrapper that trusts
        // the transport's own limit spins for as many hops as that client allows.
        throw new Error(`Access denied: too many redirects (limit ${MAX_REDIRECTS})`);
      }
      url = next;
    }

    // Unreachable: the loop always assigns before breaking or throwing. Narrows the
    // type without an assertion.
    if (response === undefined) {
      throw new Error("Access denied: no response");
    }

    if (response.ok) {
      return runPipeline(await response.json(), args.collectionPath, policy);
    }

    // A 4xx/5xx body is enforced first and thrown second. Throwing before parsing —
    // the previous behaviour — left the payload unenforced, and the caller could
    // reach it through the response object the transport had already handed back.
    let errorBody: unknown;
    try {
      errorBody = runPipeline(await response.json(), args.collectionPath, policy);
    } catch {
      // Not JSON, so the pipeline cannot walk it and no field rule applies.
      // Withheld rather than passed through (canonical spec §5) — the status still
      // tells the caller what happened.
      errorBody = undefined;
    }
    throw new UpstreamHttpError(response.status, errorBody, url);
  }
}

/**
 * Run the full canonical pipeline over a parsed response body.
 *
 * Canonical spec §4, all eight steps: row filters, tag filters, relevance floor,
 * size ceiling, hidden fields, the allowedFields projection, masking, then the
 * result limit. Every record-dropping step precedes every field-level step so work
 * is not spent masking a record about to be discarded; hidden/allowed removal
 * precedes masking so a field that is both hidden and masked is removed rather than
 * returned in masked form; and the limit runs last so filtering never yields fewer
 * records than `maxResults` when more qualifying records exist.
 *
 * Shared by the success and the 4xx/5xx paths, because an error payload is not a
 * different kind of data: connector spec §6 requires it to carry the same
 * enforcement as a success payload, since it carries the same fields.
 */
function runPipeline(
  body: unknown,
  collectionPath: string | undefined,
  policy: EffectivePolicy,
): unknown {
  let result = filterRecordsInBody(body, collectionPath, policy);
  result = stripHiddenFields(result, policy);
  result = projectAllowedFieldsInBody(result, collectionPath, policy);
  result = applyMaskingToTree(result, policy);
  return limitCollection(result, collectionPath, policy);
}

// ---------------------------------------------------------------------------
// Redirect URL handling (connector spec §6)
// ---------------------------------------------------------------------------

/**
 * A base for a wrapper configured without a `baseUrl`, whose paths are relative.
 *
 * `new URL()` needs an absolute base to resolve against. A reserved-TLD sentinel
 * keeps the arithmetic honest without pretending to name a real host: every path
 * then shares one origin, so a relative `Location` resolves and a `Location`
 * naming any real host reads as cross-origin and is refused — which is the
 * conservative answer when the wrapper does not know what origin it is talking to.
 */
const RELATIVE_ORIGIN = "http://relative.invalid";

/** Resolve a `Location` against the URL that produced it, relative or absolute. */
function resolveLocation(current: string, location: string): string {
  return new URL(location, new URL(current, RELATIVE_ORIGIN)).toString();
}

/** `scheme://host:port` of a URL, for a denial message. */
function originOf(url: string): string {
  return new URL(url, RELATIVE_ORIGIN).origin;
}

/** The path of a URL, for policy evaluation. */
function pathOf(url: string): string {
  return new URL(url, RELATIVE_ORIGIN).pathname;
}

/**
 * Whether a redirect target stays on the origin that issued the redirect.
 *
 * `URL.origin` compares scheme, host and port together and normalizes a default
 * port away, so `http://a.test:80` and `http://a.test` are one origin. An
 * http->https upgrade *is* a different origin and is refused: the policy was
 * resolved for one source, and silently moving to another scheme is a decision for
 * the integrator, not for this wrapper.
 */
function sameOrigin(current: string, target: string): boolean {
  return originOf(current) === originOf(target);
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
    if (isObject(body)) {
      // A single-record body is one record, not an envelope, so it runs the identical
      // pipeline (spec §4, "Single records"). A dropped single record becomes `null`
      // rather than `[]`: the spec is explicit that the result is "the language's null
      // value ... **not** an empty record", because an empty collection implies the
      // caller asked for a list. Python already returned `None` here and .NET returned
      // the record unfiltered, so all three disagreed on the same body; `null` is the
      // spelling the spec names and the one the other two now share.
      const kept = filter([deepClone(body)]);
      return kept.length > 0 ? kept[0] : null;
    }
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

/**
 * The single record-collection key in an envelope, or undefined if it is not unambiguous.
 *
 * Used only when the caller gave no `collectionPath`. Returns a key only when the body has
 * **exactly one** value that is a non-empty array of objects, so a body with two candidate
 * collections is never guessed at -- guessing the wrong one would enforce the limit on the wrong
 * array and read as success.
 */
function implicitCollectionKey(body: unknown): string | undefined {
  if (!isObject(body)) return undefined;
  const candidates = Object.keys(body).filter((key) => {
    const value = (body as Record<string, unknown>)[key];
    return Array.isArray(value) && value.length > 0 && value.every((item) => isObject(item));
  });
  return candidates.length === 1 ? candidates[0] : undefined;
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
    // An envelope with no collectionPath used to return unchanged, which meant
    // `maxResults: 1` handed back every record the upstream sent -- a fail-open, and the only
    // one of the three record-level controls that behaved this way: the projection returned
    // `{}` and the row filter dropped the body, both fail-closed. Silently disagreeing on the
    // same missing argument is worse than any single choice, so the limit now enforces on an
    // unambiguously-identifiable collection too. Ambiguous bodies throw rather than guess.
    const implicit = implicitCollectionKey(body);
    if (implicit !== undefined) {
      const limited = { ...(body as Record<string, unknown>) };
      limited[implicit] = applyResultLimit(
        (body as Record<string, unknown>)[implicit] as unknown[],
        policy,
      );
      return limited;
    }
    if (
      isObject(body) &&
      Object.values(body as Record<string, unknown>).some(
        (value) => Array.isArray(value) && value.length > 0 && value.every((item) => isObject(item)),
      )
    ) {
      throw new UnenforceableResultError(
        "limits.maxResults cannot be enforced: the response body has more than one candidate " +
          "record collection and no collectionPath was supplied. Pass collectionPath to name " +
          "the one the limit applies to.",
      );
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

/**
 * `limitCollection` exposed for tests that assert its no-`collectionPath` behaviour directly.
 *
 * The ambiguous-envelope and no-collection cases cannot be reached through `request()` -- the
 * test server would have to serve a body with two competing record arrays, which no real API
 * does. Exporting the internal is the smaller compromise: the alternative is leaving the
 * fail-closed branch of a fail-open fix unasserted.
 */
export { limitCollection as limitCollectionForTest };
