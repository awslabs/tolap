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
  UNKNOWN_MASK_RESTRICTIVENESS,
  maskRestrictiveness,
  createDenyAllPolicy,
} from "./types.js";

// Merger
export { merge, type MergeResult } from "./merger.js";

// Resolution
export {
  resolve,
  globToRegex,
  globMatch,
  sourcePatternMatch,
  type GetGroupsFn,
  type GetRolesFn,
} from "./resolution.js";

// Context
export {
  buildSecurityContext,
  signContext,
  validateContext,
  validateExpiry,
  serializeContext,
  deserializeContext,
  signPolicy,
  validatePolicy,
} from "./context.js";

// Enforcement
export {
  validateAccess,
  validateFieldAccess,
  applyMask,
  applyFieldMasking,
  applyObjectSizeCeiling,
  applyMaskingToTree,
  stripHiddenFields,
  projectAllowedFields,
  applyResultLimit,
  applySimilarityFloor,
  applyResultPipeline,
  applyRowFilters,
  filterByTags,
  classifyResultShape,
  describeResultShape,
  UnenforceableResultError,
  type ResultShape,
  validateEndpoint,
  fieldNameMatches,
} from "./enforcement.js";

// SQL query rewriting (canonical spec §4).
//
// An OPTIMIZATION, never the enforcement boundary: it reduces how much data crosses
// the wire by pushing row filters into WHERE, the result limit into LIMIT, and the
// field rules into the projection. `applyResultPipeline` remains mandatory over
// whatever the rewritten query returns -- some filters cannot be expressed in
// portable SQL at all, and the rewriter cannot know the query it was handed is the
// query that ran.
export {
  SqlQueryRewriter,
  SqlDialect,
  DEFAULT_DIALECT,
  MAX_QUERY_LENGTH,
  type RewriteResult,
  type RewriteDiagnostics,
  type SqlRewriterOptions,
} from "./sql-rewriter.js";
