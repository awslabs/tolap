/**
 * @aws/tolap-core - TOLAP TypeScript SDK Core Package
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
  WriteOperation,
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

// Source identity (connector-spec §1)
export {
  SourceCategory,
  parseSourceIdentity,
  sourceCategory,
  type SourceIdentity,
} from "./source-identity.js";

// kb provider-side metadata filters (connector-spec §7)
export {
  DEFAULT_KB_METADATA_KEYS,
  KbFilterOp,
  buildKbFilter,
  type KbFilterClause,
  type KbFilterOptions,
  type KbFilterResult,
  type UnpushedRule,
} from "./kb-filter.js";
export {
  KbFilterConfidence,
  KbProvider,
  renderKbFilter,
  type RenderKbFilterOptions,
  type RenderedKbFilter,
} from "./kb-providers.js";

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
  InMemoryReplayGuard,
  type ReplayGuard,
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

// Write validation (connector spec §4).
//
// Runs PRE-execution and is the whole enforcement point for a write: reads filter
// what comes back, writes have nothing to filter afterwards. Fails closed on the
// whole write -- one unwritable field denies the operation rather than being stripped
// so the rest can proceed (§4.4).
export {
  validateWrite,
  validateHttpWrite,
  payloadWriteFields,
  writeOperationForMethod,
  TARGET_ROW_UNKNOWN,
  type WriteTargetRow,
  type ValidateWriteOptions,
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
  // Which of the two enforcement points a caller wants. Both return the same rows;
  // the mode decides how much data the database produces. There is deliberately no
  // rewrite-only value -- see SqlEnforcementMode.
  SqlEnforcementMode,
  DEFAULT_ENFORCEMENT_MODE,
  resolveEnforcementMode,
  prepareSqlQuery,
  fullyPushedDown,
  type SqlQueryPreparation,
  type RewriteResult,
  type RewriteDiagnostics,
  type SqlRewriterOptions,
} from "./sql-rewriter.js";
