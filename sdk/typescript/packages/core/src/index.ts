/**
 * @tolap/core - TOLAP TypeScript SDK Core Package
 *
 * Tool-Object Level Access Protocol: enforce data access policies
 * inside AI agent tools at the data-object level.
 */

// Types and enums
export {
  type UUID,
  MaskType,
  FilterOperator,
  AssigneeType,
  SigningAlgorithm,
  type MaskingParameters,
  type MaskingRule,
  type RowFilter,
  type FieldRules,
  type TagRules,
  type EndpointRules,
  type PolicyLimits,
  type ObjectRules,
  type PolicyPermissions,
  type PolicyDefinition,
  type Assignee,
  type AssignmentScope,
  type AuditInfo,
  type PolicyAssignment,
  type IntegrityBlock,
  type EffectivePolicy,
  type SecurityContext,
  type AccessResult,
  type FieldAccessResult,
  MASK_RESTRICTIVENESS,
  createDenyAllPolicy,
} from "./types.js";

// Merger
export { merge, type MergeResult } from "./merger.js";

// Resolution
export {
  resolve,
  globToRegex,
  globMatch,
  type GetGroupsFn,
  type GetRolesFn,
} from "./resolution.js";

// Context
export {
  buildSecurityContext,
  signContext,
  validateContext,
  serializeContext,
  deserializeContext,
  signPolicy,
  validatePolicy,
} from "./context.js";

// Enforcement
export {
  validateAccess,
  validateFieldAccess,
  applyFieldMasking,
  applyResultLimit,
  applyRowFilters,
  filterByTags,
  validateEndpoint,
} from "./enforcement.js";
