/**
 * TOLAP Core Types
 *
 * All types, enums, and interfaces for Tool-Object Level Access Protocol.
 */

export type UUID = string;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

export enum MaskType {
  Full = "full",
  Partial = "partial",
  Hash = "hash",
  Null = "null",
  Redact = "redact",
}

/**
 * The row-filter comparison operators, spelled exactly as they appear on the wire.
 *
 * The enum is the public spelling of `policy-definition.schema.json`'s operator
 * enum, and the two MUST agree member-for-member: a schema-valid operator that
 * enforcement does not implement falls through to `rowPassesFilter`'s default arm
 * and drops every row, so an administrator's working filter becomes a silent
 * deny-all in one SDK while another SDK enforces it correctly. That divergence
 * survives signature verification (the canonical payload covers the policy
 * verbatim), which is precisely the class of drift the canonical spec exists to
 * prevent -- so `types-branches.test.ts` asserts every member is reachable and
 * enforceable.
 */
export enum FilterOperator {
  Equals = "equals",
  NotEquals = "notEquals",
  In = "in",
  NotIn = "notIn",
  GreaterThan = "greaterThan",
  GreaterThanOrEqual = "greaterThanOrEqual",
  LessThan = "lessThan",
  LessThanOrEqual = "lessThanOrEqual",
  Contains = "contains",
  StartsWith = "startsWith",
  /**
   * SQL `LIKE`: `%` matches any run of characters, `_` exactly one, `\` escapes
   * the next character. Anchored (a full-value match, not a substring search) and
   * case-sensitive, matching Postgres. Distinct from {@link Matches}, which is a
   * regular expression, and from {@link Contains}, which is an unanchored
   * substring test.
   */
  Like = "like",
  NotLike = "notLike",
  Matches = "matches",
  /**
   * The field is present on the row and holds null. A row *missing* the field is
   * dropped instead of satisfying this -- "absent" and "present and null" are
   * different statements (spec §7).
   */
  IsNull = "isNull",
  IsNotNull = "isNotNull",
  /** Inclusive range over `values[0]`..`values[1]`, in the order written. */
  Between = "between",
}

export enum AssigneeType {
  User = "user",
  Group = "group",
  Role = "role",
  ServiceAccount = "serviceAccount",
}

export enum SigningAlgorithm {
  HmacSha256 = "hmac-sha256",
  HmacSha512 = "hmac-sha512",
  Ed25519 = "ed25519",
}

// ---------------------------------------------------------------------------
// Masking
// ---------------------------------------------------------------------------

export interface MaskingParameters {
  showFirst?: number;
  showLast?: number;
  maskChar?: string;
  algorithm?: string;
}

export interface MaskingRule {
  field: string;
  maskType: MaskType | string;
  parameters?: MaskingParameters;
}

// ---------------------------------------------------------------------------
// Row Filters
// ---------------------------------------------------------------------------

export interface RowFilter {
  field: string;
  operator: FilterOperator | string;
  value?: unknown;
  values?: unknown[];
}

// ---------------------------------------------------------------------------
// Object Rules sub-types
// ---------------------------------------------------------------------------

export interface FieldRules {
  allowedFields?: string[];
  hiddenFields?: string[];
  maskedFields?: MaskingRule[];
  readOnlyFields?: string[];
}

export interface TagRules {
  allowedTags?: string[];
  deniedTags?: string[];
}

export interface EndpointRules {
  allowedEndpoints?: string[];
  hiddenEndpoints?: string[];
  allowedMethods?: string[];
}

export interface ObjectRules {
  allowedObjects?: string[];
  hiddenObjects?: string[];
  fieldRules?: FieldRules;
  rowFilters?: RowFilter[];
  tagRules?: TagRules;
  endpointRules?: EndpointRules;
}

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

export interface PolicyLimits {
  maxResults?: number;
  maxQueryTimeSeconds?: number;
  minSimilarityScore?: number;
  maxObjectSizeBytes?: number;
}

// ---------------------------------------------------------------------------
// Permissions
// ---------------------------------------------------------------------------

export interface PolicyPermissions {
  canQuery: boolean;
  canExport?: boolean;
  readOnly?: boolean;
}

// ---------------------------------------------------------------------------
// Policy Definition
// ---------------------------------------------------------------------------

export interface PolicyDefinition {
  version: string;
  name: string;
  description?: string;
  priority?: number;
  appliesToAll?: boolean;
  sourcePatterns?: string[];
  permissions: PolicyPermissions;
  objectRules?: ObjectRules;
  limits?: PolicyLimits;
}

// ---------------------------------------------------------------------------
// Policy Assignment
// ---------------------------------------------------------------------------

export interface Assignee {
  type: AssigneeType | string;
  identifier: string;
}

export interface AssignmentScope {
  tenantId?: string;
  sourceConnectionId?: string;
}

export interface AuditInfo {
  grantedBy: string;
  grantedAt: string;
  reason: string;
}

export interface PolicyAssignment {
  version: string;
  policyName: string;
  assignee: Assignee;
  scope: AssignmentScope;
  active: boolean;
  expiresAt?: string;
  audit: AuditInfo;
}

// ---------------------------------------------------------------------------
// Integrity & Effective Policy
// ---------------------------------------------------------------------------

export interface IntegrityBlock {
  algorithm: string;
  signature: string;
}

export interface EffectivePolicy {
  version: string;
  userId: string;
  tenantId: string;
  sourceConnectionId: string;
  resolvedAt: string;
  expiresAt: string;
  sourceProfiles: string[];
  permissions: PolicyPermissions;
  objectRules?: ObjectRules;
  limits?: PolicyLimits;
  integrity: IntegrityBlock;
}

// ---------------------------------------------------------------------------
// Security Context
// ---------------------------------------------------------------------------

export interface SecurityContext {
  effectivePolicy: EffectivePolicy;
  resolvedAt: string;
  expiresAt: string;
  signature?: string;
  algorithm?: string;
}

// ---------------------------------------------------------------------------
// Access Results
// ---------------------------------------------------------------------------

export interface AccessResult {
  allowed: boolean;
  reason?: string;
}

export interface FieldAccessResult {
  allowed: string[];
  denied: string[];
}

// ---------------------------------------------------------------------------
// Mask Restrictiveness
// ---------------------------------------------------------------------------

/**
 * Ranked by how much of the original value is disclosed (canonical spec §6):
 * `partial` leaks real characters, `hash` is irreversible but joinable, `full`
 * leaks the length, `redact` leaks nothing, `null` leaks not even the field's
 * presence. Higher rank wins a merge, so `null`/`redact` beat `partial` rather
 * than losing to it.
 */
export const MASK_RESTRICTIVENESS: Record<string, number> = {
  partial: 1,
  hash: 2,
  full: 3,
  redact: 4,
  null: 5,
};

/**
 * An unrecognized mask type (a typo, or a type from a newer schema version)
 * must never be beaten by a known-but-weaker type, so it ranks above every
 * known value.
 */
export const UNKNOWN_MASK_RESTRICTIVENESS: number =
  Math.max(...Object.values(MASK_RESTRICTIVENESS)) + 1;

/**
 * Rank a mask type by how little of the value it discloses (higher = stricter).
 *
 * Anything that is not a known mask type ranks most restrictive so that merging
 * can never downgrade an unknown mask into a weaker known one.
 */
export function maskRestrictiveness(maskType: MaskType | string): number {
  return MASK_RESTRICTIVENESS[maskType] ?? UNKNOWN_MASK_RESTRICTIVENESS;
}

// ---------------------------------------------------------------------------
// Deny-all helper
// ---------------------------------------------------------------------------

export function createDenyAllPolicy(
  userId: string,
  tenantId: string,
  sourceConnectionId: string,
): EffectivePolicy {
  const now = new Date().toISOString();
  return {
    version: "1.0",
    userId,
    tenantId,
    sourceConnectionId,
    resolvedAt: now,
    expiresAt: now,
    sourceProfiles: [],
    permissions: {
      canQuery: false,
      canExport: false,
      readOnly: true,
    },
    integrity: {
      algorithm: "none",
      signature: "",
    },
  };
}
