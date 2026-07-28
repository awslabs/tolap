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

export enum FilterOperator {
  Equals = "equals",
  NotEquals = "notEquals",
  In = "in",
  NotIn = "notIn",
  GreaterThan = "greaterThan",
  LessThan = "lessThan",
  Contains = "contains",
  StartsWith = "startsWith",
  Matches = "matches",
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

export const MASK_RESTRICTIVENESS: Record<string, number> = {
  full: 5,
  hash: 4,
  partial: 3,
  redact: 2,
  null: 1,
};

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
