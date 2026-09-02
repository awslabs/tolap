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

/**
 * The kinds of write a policy governs (connector spec §4.1).
 *
 * `Insert`/`Update`/`Delete` map one-to-one onto `canInsert`, `canUpdate` and
 * `canDelete`. `Upsert` is for a call that cannot be classified as either a create
 * or an overwrite — an unconditional object-store `PUT`, for example — and requires
 * **both** `canInsert` and `canUpdate`, the safe intersection connector spec §8
 * mandates.
 */
export enum WriteOperation {
  Insert = "insert",
  Update = "update",
  Delete = "delete",
  Upsert = "upsert",
}

export enum AssigneeType {
  User = "user",
  Group = "group",
  Role = "role",
  ServiceAccount = "serviceAccount",
}

/**
 * Kind of principal at one hop of a delegation chain (canonical spec §15).
 *
 * A closed set rather than a bare string, so a hop names one of three things a
 * reader can reason about rather than whatever the producer felt like writing.
 *
 * Published as `security-context.schema.json`'s
 * `$defs.delegationHop.properties.principalType.enum`, and compared against it in
 * both directions by `schema-conformance.test.ts` like every other enum here. Note
 * that schema describes the **canonical signing projection** rather than any SDK's
 * native context type, which is why a delegation hop is pinned there and not on a
 * per-SDK model: the three SDKs keep different public shapes and agree only on the
 * bytes they sign.
 */
export enum PrincipalType {
  /** A human. Only ever the first hop: a person is delegated to, never by an agent. */
  User = "user",
  /** An autonomous agent acting on a principal's behalf. */
  Agent = "agent",
  /** A non-agent system component, such as an orchestrator passing work along. */
  Service = "service",
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
  minSimilarityScore?: number;
  maxObjectSizeBytes?: number;
}

// ---------------------------------------------------------------------------
// Permissions
// ---------------------------------------------------------------------------

/**
 * Top-level permission flags.
 *
 * The three write permissions are optional, and absent means the schema default of
 * **false** on both the merge and the write path. That is deliberately the opposite
 * of `canQuery`'s `true` default: a policy authored before writes existed must not
 * silently gain them, and an author who omitted a write permission has not asked
 * for write access (connector spec §4.1).
 */
export interface PolicyPermissions {
  canQuery: boolean;
  canInsert?: boolean;
  canUpdate?: boolean;
  canDelete?: boolean;
  readOnly?: boolean;
}

// ---------------------------------------------------------------------------
// Purpose binding (canonical spec §15)
// ---------------------------------------------------------------------------

/**
 * Configuration for the optional semantic judge (spec §15.4).
 *
 * **Every field is optional and the documented defaults are applied at read
 * time**, never baked into a value here. Concrete defaults would serialize
 * unconditionally and so change the canonical bytes — and therefore the
 * signature — of every purpose-bound policy that did not spell them out. The
 * defaults live on {@link module:judge} as `DEFAULT_*` constants, which is the
 * single place they are read.
 */
export interface JudgeConfig {
  /**
   * Whether to consult the judge.
   *
   * Three-state on purpose: `undefined` means "not configured", which is not the
   * same statement as an explicit `false` even though both mean no judge today.
   * The merge preserves the distinction (it ORs the `true`s but keeps `undefined`
   * when nothing said anything), so a policy that never mentioned the judge does
   * not start serializing `enabled: false`.
   */
  enabled?: boolean;
  /**
   * Model identifier, for example `claude-sonnet`.
   *
   * Checked against the judge implementation's own `modelId` before it is
   * invoked; a mismatch escalates. Two policies naming different models cannot be
   * merged — a verdict is only meaningful against the model that produced it —
   * and resolve to deny-all.
   */
  model?: string;
  /** How many preceding tool calls the judge is shown. Merged with maximum. */
  historyWindow?: number;
  /**
   * At or above this confidence the verdict is final, allow or block. Merged with
   * maximum: a higher bar sends more calls to escalation.
   */
  confidenceThreshold?: number;
  /**
   * Below this confidence the call escalates. Merged with maximum. Must not
   * exceed {@link confidenceThreshold}; an inverted pair escalates rather than
   * guessing which bound was meant.
   */
  escalationThreshold?: number;
  /** Wall-clock budget for one evaluation. Merged with minimum. */
  maxLatencyMs?: number;
}

/**
 * Binds a policy to a declared purpose (canonical spec §15).
 *
 * On a {@link PolicyDefinition} it scopes resolution: the policy resolves only
 * for a caller declaring a matching {@link purposeId}. It is carried through the
 * merge onto the {@link EffectivePolicy} because enforcement only ever sees an
 * effective policy — without that, `purposeProfile` would be authorable and
 * unenforceable. Carrying it there also puts the purpose inside the HMAC for
 * free, since the policy is already part of the signed envelope.
 */
export interface PurposeProfile {
  /**
   * Matched against the caller's declared purpose exactly and **case-sensitively**,
   * so a mis-cased purpose resolves nothing rather than resolving something
   * adjacent. Note the deliberate asymmetry with action-category comparison,
   * which is case-INsensitive: both choices deny rather than admit a mis-cased
   * value, which is the direction that matters.
   */
  purposeId: string;
  /**
   * Human-readable description of the purpose. This is what gives a judge
   * something to compare a call against, so an author who enables the judge
   * should write one.
   */
  description?: string;
  /**
   * Action categories permitted under this purpose.
   *
   * Follows the null-versus-empty rule in spec §3: `undefined` is unrestricted,
   * an empty array denies **every** action. Do not collapse the two with a
   * truthiness check — that turns the most restrictive outcome the model can
   * express into no restriction at all. Intersected on merge.
   */
  allowedActions?: string[];
  /**
   * Action categories denied under this purpose. Takes precedence over
   * {@link allowedActions}: a category in both is denied. Unioned on merge.
   */
  prohibitedActions?: string[];
  judge?: JudgeConfig;
}

/**
 * One hop in a delegation chain, from human to agent to sub-agent (spec §15.3).
 *
 * Hops are ordered oldest first and are signed hop for hop when carried on a
 * {@link SecurityContext}, which is the only reason validating a chain is worth
 * anything: an unsigned chain would be the attacker's own arithmetic.
 */
export interface DelegationHop {
  principalId: string;
  /**
   * Typed as `PrincipalType | string` to match {@link Assignee.type}: the value
   * arrives from JSON, where TypeScript's types are erased, so a union is the
   * honest declaration. Nothing branches on it — no narrowing rule reads the
   * principal kind — so an unrecognized value cannot change a decision, only how
   * a chain reads to a human and what bytes it signs.
   */
  principalType: PrincipalType | string;
  /**
   * The purpose asserted at this hop, or absent to assert none. Absent on either
   * side of a parent/child pair adds no constraint (spec §15.3).
   */
  declaredPurpose?: string;
  /**
   * When the hop was created. Inside the signed bytes when present, and therefore
   * truncated to milliseconds like every other timestamp — the three runtimes do
   * not agree below that (spec §2 rule 5).
   */
  delegatedAt?: string;
  /**
   * The scopes still **in force** at this hop — not the scopes this hop removed.
   *
   * Each hop's set must be a subset of its parent's, so an empty set leaves
   * nothing for a child to claim. Named for its effect rather than its contents,
   * which is the reading the subset rule requires.
   */
  scopeNarrowing?: string[];
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
  /**
   * Purpose binding (spec §15.1). Present, the definition resolves only for a
   * caller declaring a matching purpose; absent, it is purpose-agnostic and
   * resolves exactly as it did before this field existed.
   */
  purposeProfile?: PurposeProfile;
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
  /**
   * Revocation tombstone (spec §12). When set and not future-dated, the
   * assignment does not resolve regardless of `active` or `expiresAt`, while
   * staying visible to auditors. Deliberately separate from `active` so that
   * deactivating cannot be mistaken for revoking. An unparseable value is
   * treated as revoked (fail closed).
   */
  revokedAt?: string;
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
  /**
   * The merged purpose binding (spec §15.2), carried here because enforcement
   * only ever sees an effective policy — `validateAction` and the judge gate read
   * it from nowhere else. Absent means purpose-agnostic, in which case action
   * validation always allows.
   */
  purposeProfile?: PurposeProfile;
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
  /**
   * Unique context identifier for replay detection (spec §13). Signed when
   * present, so it cannot be stripped or swapped without invalidating the
   * signature. Optional for backward compatibility: a context without a `jti`
   * produces the same canonical bytes it did before this field existed.
   */
  jti?: string;
  /**
   * The purpose this context was resolved for (spec §15).
   *
   * Signed when present, so it cannot be swapped for a different purpose or
   * stripped to escape a purpose-scoped policy. Omitted from the canonical
   * payload entirely when absent or empty, so a context without a declared
   * purpose signs to exactly the bytes it did before this field existed — the
   * same rule {@link jti} follows.
   *
   * It records the purpose the caller *asserted* at resolution; TOLAP checks that
   * assertion against the policy set, not the caller's honesty about it.
   */
  declaredPurpose?: string;
  /**
   * The chain of principals this authority passed through, oldest hop first.
   *
   * Signed when present, hop for hop: mutating, reordering, or removing a hop
   * invalidates the signature, which is what makes `validateDelegationChain`
   * worth running at all. An empty array normalizes to absent for signing, on the
   * same reasoning as {@link jti} — `[]` carries no hops and so makes no claim.
   */
  delegationChain?: DelegationHop[];
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
      readOnly: true,
    },
    integrity: {
      algorithm: "none",
      signature: "",
    },
  };
}
