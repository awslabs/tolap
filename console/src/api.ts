/**
 * Client for the policy server's admin API.
 *
 * The console holds a Cognito token and sends it as a bearer credential. Two
 * decisions about that token:
 *
 * - It lives in memory (a module variable), **not** `localStorage`. A token in
 *   `localStorage` is readable by any script that reaches the page and survives
 *   the tab, which turns one XSS into durable admin access. In memory it dies
 *   with the tab, and the OIDC flow can silently re-acquire it.
 * - A `401` clears it and signals a re-login rather than being retried. Retrying
 *   an expired token just produces another 401, and treating one as "not logged
 *   in yet" is how a session gets silently downgraded.
 */

export type AdminRole = "admin" | "auditor";

export interface Me {
  readonly subject: string;
  readonly email?: string;
  readonly role: AdminRole;
}

export interface ValidationError {
  readonly path: string;
  readonly message: string;
}

/** Thrown for any non-2xx response. */
export class ApiError extends Error {
  readonly status: number;
  readonly errors: ValidationError[];

  constructor(status: number, message: string, errors: ValidationError[] = []) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.errors = errors;
  }

  /** The caller must authenticate again. */
  get isUnauthenticated(): boolean {
    return this.status === 401;
  }

  /** Authenticated, but the role is insufficient. */
  get isForbidden(): boolean {
    return this.status === 403;
  }
}

let token: string | undefined;
let onUnauthenticated: (() => void) | undefined;

export function setToken(value: string | undefined): void {
  token = value;
}

export function hasToken(): boolean {
  return token !== undefined;
}

/** Register a callback invoked when the server rejects the current token. */
export function setUnauthenticatedHandler(handler: () => void): void {
  onUnauthenticated = handler;
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
): Promise<T> {
  const response = await fetch(path, {
    method,
    headers: {
      ...(body !== undefined ? { "content-type": "application/json" } : {}),
      ...(token !== undefined ? { authorization: `Bearer ${token}` } : {}),
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    // The API is same-origin (proxied in dev, same host in production) and uses a
    // bearer token, not cookies. Omitting credentials means no ambient cookie is
    // ever sent, so a cross-site request cannot ride an existing session.
    credentials: "omit",
  });

  if (response.status === 401) {
    token = undefined;
    onUnauthenticated?.();
  }

  if (response.status === 204) return undefined as T;

  const text = await response.text();
  let parsed: unknown;
  try {
    parsed = text === "" ? {} : JSON.parse(text);
  } catch {
    // A non-JSON body from a proxy or gateway must not surface as a parse crash.
    throw new ApiError(response.status, text || response.statusText);
  }

  if (!response.ok) {
    const payload = parsed as { error?: string; errors?: ValidationError[] };
    throw new ApiError(
      response.status,
      payload.error ?? response.statusText,
      payload.errors ?? [],
    );
  }

  return parsed as T;
}

// -- Types mirroring the server's payloads ---------------------------------

export interface PolicyPermissions {
  canQuery: boolean;
  canInsert?: boolean;
  canUpdate?: boolean;
  canDelete?: boolean;
  readOnly?: boolean;
}

export interface MaskingRule {
  field: string;
  maskType: "full" | "partial" | "hash" | "null" | "redact";
  parameters?: MaskParameters;
}

/**
 * Mask parameters, spelled out rather than left as an open record.
 *
 * The schema closes this object to exactly these four keys, so an open
 * `Record<string, unknown>` would let the console build a rule that only fails at save
 * time. Which key applies depends on the mask type: `showFirst`/`showLast` on `partial`,
 * `maskChar` on `partial` and `full`, `algorithm` on `hash`.
 */
export interface MaskParameters {
  showFirst?: number;
  showLast?: number;
  maskChar?: string;
  algorithm?: "sha256" | "sha512" | "blake2b";
}

export interface RowFilter {
  field: string;
  operator: string;
  value?: unknown;
  values?: unknown[];
}

export interface PolicyDefinition {
  version: string;
  name: string;
  description?: string;
  priority?: number;
  appliesToAll?: boolean;
  sourcePatterns?: string[];
  permissions: PolicyPermissions;
  objectRules?: {
    allowedObjects?: string[];
    hiddenObjects?: string[];
    fieldRules?: {
      allowedFields?: string[];
      hiddenFields?: string[];
      maskedFields?: MaskingRule[];
      readOnlyFields?: string[];
    };
    rowFilters?: RowFilter[];
    tagRules?: { allowedTags?: string[]; deniedTags?: string[] };
    endpointRules?: {
      allowedEndpoints?: string[];
      hiddenEndpoints?: string[];
      allowedMethods?: string[];
    };
  };
  limits?: {
    maxResults?: number;
    minSimilarityScore?: number;
    maxObjectSizeBytes?: number;
  };
}

export interface PolicyAssignment {
  version: string;
  policyName: string;
  assignee: { type: "user" | "group" | "role" | "serviceAccount"; identifier: string };
  scope: { tenantId?: string; sourceConnectionId?: string };
  active: boolean;
  expiresAt?: string;
  audit: { grantedBy: string; grantedAt: string; reason: string };
}

export interface PolicyVersion {
  name: string;
  versionNo: number;
  policy: PolicyDefinition;
  state: "draft" | "published" | "superseded";
  note: string | null;
  createdBy: string;
  createdAt: string;
}

export interface SourceManifest {
  sourceConnectionId: string;
  category: "db" | "api" | "kb" | "storage";
  displayName?: string;
  objects: Array<{ name: string; fields: string[] }>;
  endpoints: Array<{ path: string; methods: string[]; responseFields: string[] }>;
  tags: string[];
  prefixes: string[];
}

export interface Install {
  id: string;
  name: string;
  createdAt: string;
  revokedAt: string | null;
  lastSeenAt: string | null;
}

export interface AuditEntry {
  at: string;
  actor: string;
  actorKind: string;
  action: string;
  targetKind: string | null;
  targetId: string | null;
  detail: unknown;
}

export interface ValidationResult {
  valid: boolean;
  errors: ValidationError[];
}

export interface ResolvePreview {
  effectivePolicy: Record<string, unknown>;
  contributingPolicies: string[];
}

/**
 * Every list endpoint's paging field.
 *
 * The server bounds each listing (one Node process serves both the admin API and
 * `/v1/resolve`, so an unbounded read stalls policy resolution for every install)
 * and returns `nextCursor: null` on the last page. Passing no cursor asks for the
 * first page, which is what every call below does today -- so these pages show the
 * newest or first N rows, not necessarily all of them.
 *
 * Optional here rather than required because the pages do not read it yet; wiring a
 * "load more" control is the follow-up, and typing it as required would only make
 * the compiler complain about mocks.
 */
export interface PageInfo {
  nextCursor?: string | null;
}

/** Serialize the paging arguments, omitting the ones left unset. */
function pageQuery(page?: { limit?: number; cursor?: string }): string {
  const parts: string[] = [];
  if (page?.limit !== undefined) parts.push(`limit=${page.limit}`);
  if (page?.cursor !== undefined)
    parts.push(`cursor=${encodeURIComponent(page.cursor)}`);
  return parts.length > 0 ? parts.join("&") : "";
}

// -- Endpoints -------------------------------------------------------------

export const api = {
  me: () => request<Me>("GET", "/v1/me"),

  listPolicies: (page?: { limit?: number; cursor?: string }) =>
    request<{ policies: PolicyDefinition[] } & PageInfo>(
      "GET",
      `/v1/policies${pageQuery(page) ? `?${pageQuery(page)}` : ""}`,
    ),
  getPolicy: (name: string) =>
    request<PolicyDefinition>("GET", `/v1/policies/${encodeURIComponent(name)}`),
  putPolicy: (policy: PolicyDefinition) =>
    request<PolicyDefinition>(
      "PUT",
      `/v1/policies/${encodeURIComponent(policy.name)}`,
      policy,
    ),
  deletePolicy: (name: string) =>
    request<void>("DELETE", `/v1/policies/${encodeURIComponent(name)}`),
  validatePolicy: (policy: unknown, fragment = false) =>
    request<ValidationResult>(
      "POST",
      `/v1/policies/validate${fragment ? "?fragment=true" : ""}`,
      policy,
    ),

  listVersions: (name: string, page?: { limit?: number; cursor?: string }) =>
    request<{ versions: PolicyVersion[] } & PageInfo>(
      "GET",
      `/v1/policies/${encodeURIComponent(name)}/versions${
        pageQuery(page) ? `?${pageQuery(page)}` : ""
      }`,
    ),
  saveDraft: (policy: PolicyDefinition, note?: string) =>
    request<{ name: string; versionNo: number }>(
      "POST",
      `/v1/policies/${encodeURIComponent(policy.name)}/versions`,
      { policy, note },
    ),
  publish: (name: string, versionNo: number) =>
    request<{ published: PolicyDefinition }>(
      "POST",
      `/v1/policies/${encodeURIComponent(name)}/versions/${versionNo}/publish`,
    ),
  rollback: (name: string, versionNo: number) =>
    request<{ newVersionNo: number }>(
      "POST",
      `/v1/policies/${encodeURIComponent(name)}/versions/${versionNo}/rollback`,
    ),

  listAssignments: (
    assignee?: string,
    page?: { limit?: number; cursor?: string },
  ) => {
    const query = [
      ...(assignee ? [`assignee=${encodeURIComponent(assignee)}`] : []),
      ...(pageQuery(page) ? [pageQuery(page)] : []),
    ].join("&");
    return request<{ assignments: PolicyAssignment[] } & PageInfo>(
      "GET",
      `/v1/assignments${query ? `?${query}` : ""}`,
    );
  },
  createAssignment: (assignment: PolicyAssignment) =>
    request<PolicyAssignment>("POST", "/v1/assignments", assignment),
  revokeAssignment: (policyName: string, assignee: string) =>
    request<void>(
      "DELETE",
      `/v1/assignments?policyName=${encodeURIComponent(policyName)}&assignee=${encodeURIComponent(assignee)}`,
    ),

  preview: (userId: string, tenantId: string, sourceConnectionId: string) =>
    request<ResolvePreview>(
      "GET",
      `/v1/resolve/preview?userId=${encodeURIComponent(userId)}&tenantId=${encodeURIComponent(tenantId)}&sourceConnectionId=${encodeURIComponent(sourceConnectionId)}`,
    ),

  listSources: (page?: { limit?: number; cursor?: string }) =>
    request<{ sources: SourceManifest[] } & PageInfo>(
      "GET",
      `/v1/catalog${pageQuery(page) ? `?${pageQuery(page)}` : ""}`,
    ),
  putSource: (manifest: unknown) =>
    request<SourceManifest>("PUT", "/v1/catalog", manifest),
  importOpenApi: (sourceConnectionId: string, spec: unknown) =>
    request<SourceManifest>("POST", "/v1/catalog/import/openapi", {
      sourceConnectionId,
      spec,
    }),
  importSql: (sourceConnectionId: string, ddl: string) =>
    request<SourceManifest>("POST", "/v1/catalog/import/sql", {
      sourceConnectionId,
      ddl,
    }),
  deleteSource: (id: string) =>
    request<void>("DELETE", `/v1/catalog/${encodeURIComponent(id)}`),

  listInstalls: (page?: { limit?: number; cursor?: string }) =>
    request<{ installs: Install[] } & PageInfo>(
      "GET",
      `/v1/installs${pageQuery(page) ? `?${pageQuery(page)}` : ""}`,
    ),
  createInstall: (id: string, name: string) =>
    request<{ id: string; name: string; credential: string; notice: string }>(
      "POST",
      "/v1/installs",
      { id, name },
    ),
  revokeInstall: (id: string) =>
    request<void>("DELETE", `/v1/installs/${encodeURIComponent(id)}`),

  // 500 is the server's ceiling, so this asks for the largest page it will grant.
  // A larger number is now a 400 rather than a silently truncated response -- if
  // the audit view needs more than one page it must follow `nextCursor`.
  listAudit: (limit = 200, cursor?: string) =>
    request<{ entries: AuditEntry[] } & PageInfo>(
      "GET",
      `/v1/audit?${pageQuery({ limit, ...(cursor !== undefined ? { cursor } : {}) })}`,
    ),
};
