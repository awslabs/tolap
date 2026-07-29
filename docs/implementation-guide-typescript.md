# TOLAP Implementation Guide -- TypeScript

This guide walks through implementing TOLAP (Tool-Object Level Access Protocol) in a TypeScript / Node.js tool layer. The examples are practical, compilable TypeScript targeting ES2022+ and Node.js 18+. For a concrete reference implementation, see [reference-implementation.md](reference-implementation.md).

## Prerequisites

Before implementing TOLAP, you need:

1. **An authenticated user identity** -- TOLAP does not handle authentication. Your system must provide a verified user ID and tenant ID.
2. **A policy store** -- Somewhere to persist policy definitions and assignments (database, configuration files, policy service).
3. **A tool layer** -- The tools your AI agents use to access data sources (MCP servers, Semantic Kernel plugins, LangChain tools, etc.).

### Runtime and Toolchain

- **Node.js 18+** (for native `crypto` module, stable `fetch`, and `structuredClone`)
- **TypeScript 5+** with `strict: true` and `strictNullChecks: true`
- **npm packages** (recommended):
  - `minimatch` -- glob pattern matching for source patterns
  - A database driver or ORM for your policy store (e.g., `pg`, `prisma`, `drizzle-orm`)
  - `zod` (optional) -- runtime validation of policy JSON against the schema

## Step 1: Define Your Policy Store

TOLAP policies are defined using the [Policy Definition Schema](schema/v1.0/policy-definition.schema.json) and linked to users via the [Policy Assignment Schema](schema/v1.0/policy-assignment.schema.json).

Your policy store needs two collections:

### Type Definitions

```typescript
type UUID = string;

// ── Enums ──────────────────────────────────────────────────────────────

enum AssigneeType {
  User = "user",
  Group = "group",
  Role = "role",
  ServiceAccount = "serviceAccount",
}

enum MaskType {
  Null = "null",
  Redact = "redact",
  Partial = "partial",
  Hash = "hash",
  Full = "full",
}

enum FilterOperator {
  Equals = "equals",
  NotEquals = "notEquals",
  In = "in",
  NotIn = "notIn",
  GreaterThan = "greaterThan",
  LessThan = "lessThan",
  GreaterThanOrEqual = "greaterThanOrEqual",
  LessThanOrEqual = "lessThanOrEqual",
  Contains = "contains",
  StartsWith = "startsWith",
  IsNull = "isNull",
  IsNotNull = "isNotNull",
}

// ── Policy Definition ──────────────────────────────────────────────────

interface MaskedField {
  field: string;
  maskType: MaskType;
  visibleChars?: number;
  maskChar?: string;
}

interface RowFilter {
  field: string;
  operator: FilterOperator;
  value: string | number | boolean | string[];
}

interface FieldRules {
  allowedFields?: string[];
  hiddenFields?: string[];
  maskedFields?: MaskedField[];
}

interface TagRules {
  allowedTags?: string[];
  deniedTags?: string[];
}

interface EndpointRules {
  allowedEndpoints?: string[];
  hiddenEndpoints?: string[];
  allowedMethods?: string[];
}

interface ObjectRules {
  allowedObjects?: string[];
  hiddenObjects?: string[];
  fieldRules?: FieldRules;
  rowFilters?: RowFilter[];
  tagRules?: TagRules;
  endpointRules?: EndpointRules;
}

interface Permissions {
  canQuery: boolean;
  readOnly: boolean;
}

interface Limits {
  maxResults?: number;
  minSimilarityScore?: number;
  maxObjectSizeBytes?: number;
}

interface PolicyDefinition {
  name: string;
  description: string;
  priority: number;
  appliesToAll: boolean;
  sourcePatterns: string[];
  permissions: Permissions;
  objectRules: ObjectRules;
  limits: Limits;
  isActive: boolean;
}
```

**Policy Assignments** -- links between policies and users:

```typescript
interface PolicyAssignment {
  policyName: string;
  assigneeType: AssigneeType;
  assigneeIdentifier: string;
  tenantId?: UUID;
  sourceConnectionId?: UUID;
  active: boolean;
  expiresAt?: Date;
  grantedBy: string;
  grantedAt: Date;
  reason: string;
}
```

These can live in a relational database, a document store, configuration files, or any persistent storage your system uses.

## Step 2: Implement the Policy Resolution Engine

The Policy Resolution Engine computes the effective policy for a user and data source by merging all applicable policy definitions.

### Effective Policy Type

```typescript
interface EffectivePolicy {
  sourceConnectionId: UUID;
  resolvedAt: Date;
  expiresAt: Date;

  // Permissions (AND across all policies)
  canQuery: boolean;
  readOnly: boolean;

  // Allowed sets (intersection)
  allowedObjects: string[];
  allowedFields: string[];
  allowedEndpoints: string[];
  allowedTags: string[];
  allowedMethods: string[];

  // Hidden/denied sets (union)
  hiddenObjects: string[];
  hiddenFields: string[];
  hiddenEndpoints: string[];
  deniedTags: string[];

  // Row filters (concatenated)
  rowFilters: RowFilter[];

  // Masked fields (most restrictive per field)
  maskedFields: MaskedField[];

  // Numeric limits (most restrictive)
  maxResults?: number;
  maxObjectSizeBytes?: number;
  minSimilarityScore?: number;
}
```

### Policy Store Interface

```typescript
interface PolicyStore {
  loadAssignments(filter: AssignmentFilter): Promise<PolicyAssignment[]>;
  loadPolicyDefinition(name: string): Promise<PolicyDefinition | null>;
  getUserGroups(userId: UUID): Promise<string[]>;
  getUserRoles(userId: UUID): Promise<string[]>;
}

interface AssignmentFilter {
  assigneeIdentifiers: string[];
  assigneeTypes: AssigneeType[];
  activeOnly: boolean;
}
```

### Resolution Engine

```typescript
import { minimatch } from "minimatch";

const DENY_ALL_POLICY: EffectivePolicy = {
  sourceConnectionId: "",
  resolvedAt: new Date(),
  expiresAt: new Date(),
  canQuery: false,
  readOnly: true,
  allowedObjects: [],
  allowedFields: [],
  allowedEndpoints: [],
  allowedTags: [],
  allowedMethods: [],
  hiddenObjects: [],
  hiddenFields: [],
  hiddenEndpoints: [],
  deniedTags: [],
  rowFilters: [],
  maskedFields: [],
};

class PolicyResolutionEngine {
  constructor(private readonly store: PolicyStore) {}

  async resolveEffectivePolicy(
    userId: UUID,
    tenantId: UUID,
    sourceConnectionId: UUID,
    sourceCategory: string,
    sourceNamespace: string,
    sourceName: string,
  ): Promise<EffectivePolicy> {
    // 1. Load all active assignments for this user
    const userAssignments = await this.store.loadAssignments({
      assigneeIdentifiers: [userId],
      assigneeTypes: [AssigneeType.User],
      activeOnly: true,
    });

    // 2. Also load group/role assignments
    const [userGroups, userRoles] = await Promise.all([
      this.store.getUserGroups(userId),
      this.store.getUserRoles(userId),
    ]);

    const groupRoleAssignments = await this.store.loadAssignments({
      assigneeIdentifiers: [...userGroups, ...userRoles],
      assigneeTypes: [AssigneeType.Group, AssigneeType.Role],
      activeOnly: true,
    });

    let assignments = [...userAssignments, ...groupRoleAssignments];

    // 3. Filter out expired assignments
    const now = new Date();
    assignments = assignments.filter(
      (a) => a.expiresAt === undefined || a.expiresAt > now,
    );

    // 4. Narrow to tenant scope
    assignments = assignments.filter(
      (a) => a.tenantId === undefined || a.tenantId === tenantId,
    );

    // 5. Narrow to source scope
    assignments = assignments.filter(
      (a) =>
        a.sourceConnectionId === undefined ||
        a.sourceConnectionId === sourceConnectionId,
    );

    // 6. Load referenced policy definitions
    const policyResults = await Promise.all(
      assignments.map((a) => this.store.loadPolicyDefinition(a.policyName)),
    );
    let policies = policyResults.filter(
      (p): p is PolicyDefinition => p !== null && p.isActive,
    );

    // 7. Filter to policies that match this source
    const sourceIdentifier = `${sourceCategory}:${sourceNamespace}:${sourceName}`;
    policies = policies.filter(
      (p) =>
        p.appliesToAll ||
        p.sourcePatterns.some((pattern) =>
          minimatch(sourceIdentifier, pattern),
        ),
    );

    // 8. Sort by priority (lower number = higher precedence)
    policies.sort((a, b) => a.priority - b.priority);

    // 9. Merge using most-restrictive-wins
    return mergePolicies(policies);
  }
}
```

### The Merge Algorithm

```typescript
function mergePolicies(policies: PolicyDefinition[]): EffectivePolicy {
  if (policies.length === 0) {
    return { ...DENY_ALL_POLICY, resolvedAt: new Date() };
  }

  const now = new Date();

  // Permissions: AND (all must allow)
  const canQuery = policies.every((p) => p.permissions.canQuery);
  const readOnly = policies.some((p) => p.permissions.readOnly);

  // Allowed sets: INTERSECTION (only policies that define the field participate)
  const allowedObjects = intersectOptionalSets(
    policies.map((p) => p.objectRules.allowedObjects),
  );
  const allowedFields = intersectOptionalSets(
    policies.map((p) => p.objectRules.fieldRules?.allowedFields),
  );
  const allowedEndpoints = intersectOptionalSets(
    policies.map((p) => p.objectRules.endpointRules?.allowedEndpoints),
  );
  const allowedTags = intersectOptionalSets(
    policies.map((p) => p.objectRules.tagRules?.allowedTags),
  );
  const allowedMethods = intersectOptionalSets(
    policies.map((p) => p.objectRules.endpointRules?.allowedMethods),
  );

  // Hidden/denied sets: UNION
  const hiddenObjects = unionSets(
    policies.map((p) => p.objectRules.hiddenObjects ?? []),
  );
  const hiddenFields = unionSets(
    policies.map((p) => p.objectRules.fieldRules?.hiddenFields ?? []),
  );
  const hiddenEndpoints = unionSets(
    policies.map((p) => p.objectRules.endpointRules?.hiddenEndpoints ?? []),
  );
  const deniedTags = unionSets(
    policies.map((p) => p.objectRules.tagRules?.deniedTags ?? []),
  );

  // Row filters: AND (concatenate all)
  const rowFilters = policies.flatMap(
    (p) => p.objectRules.rowFilters ?? [],
  );

  // Masked fields: most restrictive mask type per field
  const maskedFields = mergeMaskedFields(policies);

  // Numeric limits: minimum (most restrictive)
  const maxResults = minDefined(
    policies.map((p) => p.limits.maxResults),
  );
  const maxObjectSizeBytes = minDefined(
    policies.map((p) => p.limits.maxObjectSizeBytes),
  );

  // Similarity score: maximum (most restrictive -- higher threshold is stricter)
  const minSimilarityScore = maxDefined(
    policies.map((p) => p.limits.minSimilarityScore),
  );

  return {
    sourceConnectionId: "",
    resolvedAt: now,
    expiresAt: now,
    canQuery,
    readOnly,
    allowedObjects,
    allowedFields,
    allowedEndpoints,
    allowedTags,
    allowedMethods,
    hiddenObjects,
    hiddenFields,
    hiddenEndpoints,
    deniedTags,
    rowFilters,
    maskedFields,
    maxResults,
    maxObjectSizeBytes,
    minSimilarityScore,
  };
}

// ── Merge Helpers ────────────────────────────────────────────────────────

/**
 * Intersect optional sets. Policies that omit the field (undefined) are
 * treated as "no restriction from this policy" and do not participate.
 * If no policies define the field, returns an empty array (unrestricted).
 */
function intersectOptionalSets(
  sets: (string[] | undefined)[],
): string[] {
  const defined = sets.filter(
    (s): s is string[] => s !== undefined && s.length > 0,
  );
  if (defined.length === 0) {
    return [];
  }
  const first = new Set(defined[0]);
  return defined
    .slice(1)
    .reduce(
      (acc, current) => {
        const currentSet = new Set(current);
        return acc.filter((item) => currentSet.has(item));
      },
      [...first],
    );
}

/**
 * Union all arrays into a deduplicated list.
 */
function unionSets(sets: string[][]): string[] {
  const combined = new Set<string>();
  for (const set of sets) {
    for (const item of set) {
      combined.add(item);
    }
  }
  return [...combined];
}

/**
 * Merge masked field rules across all policies.
 * For each field, the most restrictive mask type wins.
 */
function mergeMaskedFields(policies: PolicyDefinition[]): MaskedField[] {
  const allRules = policies.flatMap(
    (p) => p.objectRules.fieldRules?.maskedFields ?? [],
  );

  const byField = new Map<string, MaskedField[]>();
  for (const rule of allRules) {
    const existing = byField.get(rule.field) ?? [];
    existing.push(rule);
    byField.set(rule.field, existing);
  }

  const result: MaskedField[] = [];
  for (const [, rules] of byField) {
    const mostRestrictive = rules.reduce((prev, curr) =>
      maskRestrictiveness(curr.maskType) > maskRestrictiveness(prev.maskType)
        ? curr
        : prev,
    );
    result.push(mostRestrictive);
  }

  return result;
}

function maskRestrictiveness(maskType: MaskType): number {
  switch (maskType) {
    case MaskType.Full:
      return 5;
    case MaskType.Hash:
      return 4;
    case MaskType.Partial:
      return 3;
    case MaskType.Redact:
      return 2;
    case MaskType.Null:
      return 1;
  }
}

/**
 * Return the minimum of all defined (non-undefined) values, or undefined
 * if none are defined.
 */
function minDefined(values: (number | undefined)[]): number | undefined {
  const defined = values.filter((v): v is number => v !== undefined);
  return defined.length > 0 ? Math.min(...defined) : undefined;
}

/**
 * Return the maximum of all defined (non-undefined) values, or undefined
 * if none are defined.
 */
function maxDefined(values: (number | undefined)[]): number | undefined {
  const defined = values.filter((v): v is number => v !== undefined);
  return defined.length > 0 ? Math.max(...defined) : undefined;
}
```

**Handling omitted fields:** When a policy omits an optional field (e.g., `allowedObjects` is not specified), treat it as "no restriction from this policy" for intersection operations. Only policies that explicitly define a field participate in the intersection. If no policies define the field, the effective value is "unrestricted."

## Step 3: Build and Sign the Security Context

The Security Context packages the effective policies and transports them to the tool execution environment.

### Security Context Type

```typescript
interface IntegrityBlock {
  algorithm: "hmac-sha256";
  signature: string;
}

interface SecurityContext {
  userId: UUID;
  tenantId: UUID;
  issuedAt: Date;
  expiresAt: Date;
  policies: EffectivePolicy[];
  integrity?: IntegrityBlock;
}
```

### Building the Context

```typescript
const CONTEXT_TTL_MS = 60 * 60 * 1000; // 1 hour

async function buildSecurityContext(
  userId: UUID,
  tenantId: UUID,
  accessibleSources: AccessibleSource[],
  engine: PolicyResolutionEngine,
): Promise<SecurityContext> {
  const now = new Date();
  const expiresAt = new Date(now.getTime() + CONTEXT_TTL_MS);

  const policies = await Promise.all(
    accessibleSources.map(async (source) => {
      const effectivePolicy = await engine.resolveEffectivePolicy(
        userId,
        tenantId,
        source.connectionId,
        source.category,
        source.namespace,
        source.name,
      );
      effectivePolicy.sourceConnectionId = source.connectionId;
      effectivePolicy.resolvedAt = now;
      effectivePolicy.expiresAt = expiresAt;
      return effectivePolicy;
    }),
  );

  return {
    userId,
    tenantId,
    issuedAt: now,
    expiresAt,
    policies,
  };
}

interface AccessibleSource {
  connectionId: UUID;
  category: string;
  namespace: string;
  name: string;
}
```

### Signing and Transport

```typescript
import { createHmac } from "node:crypto";

function signContext(
  context: SecurityContext,
  secretKey: string,
): SecurityContext {
  // Serialize everything except the integrity block
  const { integrity: _, ...payload } = context;
  const payloadJson = JSON.stringify(payload, dateReplacer);
  const signature = createHmac("sha256", secretKey)
    .update(payloadJson)
    .digest("base64");

  return {
    ...context,
    integrity: {
      algorithm: "hmac-sha256",
      signature,
    },
  };
}

function serializeForTransport(context: SecurityContext): string {
  const json = JSON.stringify(context, dateReplacer);
  return Buffer.from(json, "utf-8").toString("base64");
}

function deserializeAndValidate(
  serialized: string,
  secretKey: string,
): SecurityContext {
  const json = Buffer.from(serialized, "base64").toString("utf-8");
  const context: SecurityContext = JSON.parse(json, dateReviver);

  // Validate expiry
  if (context.expiresAt < new Date()) {
    throw new Error("Security context has expired");
  }

  // Validate signature
  const { integrity: _, ...payload } = context;
  const payloadJson = JSON.stringify(payload, dateReplacer);
  const expectedSignature = createHmac("sha256", secretKey)
    .update(payloadJson)
    .digest("base64");

  if (context.integrity?.signature !== expectedSignature) {
    throw new Error("Security context signature is invalid");
  }

  return context;
}

// ── JSON Date Helpers ────────────────────────────────────────────────────

/**
 * JSON replacer that serializes Date objects to ISO strings.
 */
function dateReplacer(_key: string, value: unknown): unknown {
  if (value instanceof Date) {
    return value.toISOString();
  }
  return value;
}

/**
 * JSON reviver that deserializes ISO date strings back to Date objects.
 * Matches fields ending in "At" (issuedAt, expiresAt, resolvedAt, etc.).
 */
function dateReviver(key: string, value: unknown): unknown {
  if (typeof value === "string" && key.endsWith("At")) {
    const date = new Date(value);
    if (!isNaN(date.getTime())) {
      return date;
    }
  }
  return value;
}
```

**Context TTL guidance:** Keep the TTL short (15 minutes to 1 hour). Shorter TTLs reduce the replay window but require more frequent policy resolution. For same-process execution, the context can be passed in memory without serialization.

## Step 4: Implement Secure Tool Wrappers

Each Secure Tool Wrapper wraps a data source and enforces the effective policy. Here is the base wrapper and the enforcement logic:

### Data Source Interfaces

```typescript
interface DataSource {
  readonly type: string;
  execute(query: string): Promise<Record<string, unknown>[]>;
  listObjects(): Promise<string[]>;
  describeObject(objectName: string): Promise<string[]>;
}

interface QueryAnalysis {
  referencedObjects: string[];
  referencedFields: string[];
}
```

### Base Secure Tool Wrapper

```typescript
class SecureToolWrapper<T extends DataSource> {
  protected readonly dataSource: T;
  private effectivePolicy: EffectivePolicy | null = null;
  private userId: UUID = "";
  private tenantId: UUID = "";

  constructor(dataSource: T) {
    this.dataSource = dataSource;
  }

  setSecurityContext(
    userId: UUID,
    tenantId: UUID,
    sourceConnectionId: UUID,
    effectivePolicy: EffectivePolicy,
  ): void {
    this.userId = userId;
    this.tenantId = tenantId;
    this.effectivePolicy = effectivePolicy;
  }

  protected getPolicy(): EffectivePolicy {
    if (this.effectivePolicy === null) {
      throw new Error(
        "Security context not set. Call setSecurityContext() before operations.",
      );
    }
    return this.effectivePolicy;
  }

  async executeQuery(query: string): Promise<Record<string, unknown>[]> {
    const policy = this.getPolicy();

    // 1. Check permission
    if (!policy.canQuery) {
      throw new Error("Access denied: query permission not granted");
    }

    // 2. Validate requested objects
    const analysis = this.analyzeQuery(query);
    for (const obj of analysis.referencedObjects) {
      if (policy.hiddenObjects.includes(obj)) {
        throw new Error(
          `Access denied: object '${obj}' is not accessible`,
        );
      }
      if (
        policy.allowedObjects.length > 0 &&
        !policy.allowedObjects.includes(obj)
      ) {
        throw new Error(
          `Access denied: object '${obj}' is not in allowed set`,
        );
      }
    }

    // 3. Validate requested fields
    for (const field of analysis.referencedFields) {
      if (policy.hiddenFields.includes(field)) {
        throw new Error(
          `Access denied: field '${field}' is not accessible`,
        );
      }
    }

    // 4. Rewrite query with row filters
    let filteredQuery = query;
    for (const filter of policy.rowFilters) {
      filteredQuery = this.injectWhereClause(filteredQuery, filter);
    }

    // 5. Apply result limit
    if (policy.maxResults !== undefined) {
      filteredQuery = this.applyLimit(filteredQuery, policy.maxResults);
    }

    // 6. Execute against data source
    const results = await this.dataSource.execute(filteredQuery);

    // 7. Apply field masking to results
    return results.map((row) => this.applyMasking(row, policy.maskedFields));
  }

  async listAccessibleObjects(): Promise<string[]> {
    const policy = this.getPolicy();
    const allObjects = await this.dataSource.listObjects();
    return allObjects
      .filter((obj) => !policy.hiddenObjects.includes(obj))
      .filter(
        (obj) =>
          policy.allowedObjects.length === 0 ||
          policy.allowedObjects.includes(obj),
      );
  }

  async describeObject(objectName: string): Promise<string[]> {
    const policy = this.getPolicy();
    const allFields = await this.dataSource.describeObject(objectName);
    return allFields
      .filter((f) => !policy.hiddenFields.includes(f))
      .filter(
        (f) =>
          policy.allowedFields.length === 0 ||
          policy.allowedFields.includes(f),
      );
  }

  // ── Subclass extension points ──────────────────────────────────────

  protected analyzeQuery(query: string): QueryAnalysis {
    // Override in subclasses for source-specific query parsing
    return { referencedObjects: [], referencedFields: [] };
  }

  protected injectWhereClause(query: string, filter: RowFilter): string {
    // Override in subclasses for source-specific filter injection
    return query;
  }

  protected applyLimit(query: string, limit: number): string {
    // Override in subclasses for source-specific limit application
    return query;
  }

  private applyMasking(
    row: Record<string, unknown>,
    maskedFields: MaskedField[],
  ): Record<string, unknown> {
    const masked = { ...row };
    for (const rule of maskedFields) {
      if (rule.field in masked) {
        masked[rule.field] = applyMask(masked[rule.field], rule);
      }
    }
    return masked;
  }
}

// ── Masking Implementation ──────────────────────────────────────────────

function applyMask(value: unknown, rule: MaskedField): unknown {
  if (value === null || value === undefined) {
    return value;
  }

  switch (rule.maskType) {
    case MaskType.Null:
      return null;

    case MaskType.Full: {
      const str = String(value);
      const maskChar = rule.maskChar ?? "*";
      return maskChar.repeat(str.length);
    }

    case MaskType.Partial: {
      const str = String(value);
      const visible = rule.visibleChars ?? 4;
      const maskChar = rule.maskChar ?? "*";
      if (str.length <= visible) {
        return maskChar.repeat(str.length);
      }
      return maskChar.repeat(str.length - visible) + str.slice(-visible);
    }

    case MaskType.Redact:
      return "[REDACTED]";

    case MaskType.Hash: {
      const { createHash } = require("node:crypto") as typeof import("node:crypto");
      return createHash("sha256").update(String(value)).digest("hex");
    }
  }
}
```

### Source-Specific Enforcement

Different source categories require different enforcement strategies:

**Database sources:**
- Row filters become SQL WHERE clauses injected into the query
- Hidden columns are validated before query execution (reject queries that reference them)
- Column masking is applied to result rows after execution
- Schema introspection (list tables, describe columns) returns only accessible objects

**API sources:**
- Endpoint access is validated against allowed/hidden endpoint patterns before the HTTP request
- HTTP method is validated against the allowed methods list
- Response fields are masked after the response is received
- Endpoint listing returns only accessible endpoints

**Knowledge base sources:**
- Allowed/denied tags are converted to the vector store's native filter format
- Similarity score threshold is passed to the search request
- Results below the threshold or with denied tags are excluded
- Access info methods return the user's tag permissions

**Storage sources:**
- Allowed/denied prefixes are validated before object access
- File type restrictions are checked before retrieval
- Object size limits are enforced before download
- Object metadata masking is applied to listing results

## Step 5: Implement the Secure Tool Factory

The factory creates initialized Secure Tool Wrapper instances for a user.

### Data Source Registry and Credential Resolver

```typescript
interface DataSourceConnection {
  connectionId: UUID;
  type: string;
  config: Record<string, string>;
}

interface Credentials {
  readonly [key: string]: string;
}

interface DataSourceRegistry {
  getConnection(connectionId: UUID): Promise<DataSourceConnection>;
}

interface CredentialResolver {
  resolve(source: DataSourceConnection): Promise<Credentials>;
}
```

### Factory Implementation

```typescript
class SecureToolFactory {
  constructor(
    private readonly policyEngine: PolicyResolutionEngine,
    private readonly dataSourceRegistry: DataSourceRegistry,
    private readonly credentialResolver: CredentialResolver,
  ) {}

  async createAllAccessibleTools(
    securityContext: SecurityContext,
  ): Promise<SecureToolWrapper<DataSource>[]> {
    const tools: SecureToolWrapper<DataSource>[] = [];

    for (const policy of securityContext.policies) {
      if (!policy.canQuery) {
        continue; // Skip sources the user cannot query
      }

      const source = await this.dataSourceRegistry.getConnection(
        policy.sourceConnectionId,
      );
      const credentials = await this.credentialResolver.resolve(source);

      const wrapper = this.createWrapperForSourceType(
        source.type,
        source,
        credentials,
      );
      wrapper.setSecurityContext(
        securityContext.userId,
        securityContext.tenantId,
        policy.sourceConnectionId,
        policy,
      );
      tools.push(wrapper);
    }

    return tools;
  }

  async createToolForSource(
    securityContext: SecurityContext,
    sourceConnectionId: UUID,
  ): Promise<SecureToolWrapper<DataSource>> {
    const policy = securityContext.policies.find(
      (p) => p.sourceConnectionId === sourceConnectionId,
    );
    if (policy === undefined) {
      throw new Error(
        `No policy found for source: ${sourceConnectionId}`,
      );
    }

    const source = await this.dataSourceRegistry.getConnection(
      sourceConnectionId,
    );
    const credentials = await this.credentialResolver.resolve(source);

    const wrapper = this.createWrapperForSourceType(
      source.type,
      source,
      credentials,
    );
    wrapper.setSecurityContext(
      securityContext.userId,
      securityContext.tenantId,
      sourceConnectionId,
      policy,
    );
    return wrapper;
  }

  private createWrapperForSourceType(
    sourceType: string,
    source: DataSourceConnection,
    credentials: Credentials,
  ): SecureToolWrapper<DataSource> {
    switch (sourceType) {
      case "postgresql":
      case "mysql":
      case "sqlserver":
      case "athena":
        return new SecureDatabaseWrapper(
          createDatabaseSource(source, credentials),
        );

      case "rest":
      case "graphql":
      case "soap":
      case "fhir":
      case "grpc":
        return new SecureApiWrapper(
          createApiSource(source, credentials),
        );

      case "bedrock-kb":
      case "opensearch":
      case "elasticsearch":
        return new SecureKnowledgebaseWrapper(
          createKnowledgebaseSource(source, credentials),
        );

      case "s3":
      case "azure-blob":
      case "gcs":
        return new SecureStorageWrapper(
          createStorageSource(source, credentials),
        );

      default:
        throw new Error(`Unsupported source type: ${sourceType}`);
    }
  }
}

// ── Source-specific wrapper stubs ────────────────────────────────────────
// Each subclass overrides analyzeQuery, injectWhereClause, and applyLimit
// with source-appropriate logic.

class SecureDatabaseWrapper extends SecureToolWrapper<DataSource> {}
class SecureApiWrapper extends SecureToolWrapper<DataSource> {}
class SecureKnowledgebaseWrapper extends SecureToolWrapper<DataSource> {}
class SecureStorageWrapper extends SecureToolWrapper<DataSource> {}

// ── Source creation functions (implement per your infrastructure) ────────

function createDatabaseSource(
  source: DataSourceConnection,
  credentials: Credentials,
): DataSource {
  throw new Error("Implement for your database driver");
}

function createApiSource(
  source: DataSourceConnection,
  credentials: Credentials,
): DataSource {
  throw new Error("Implement for your HTTP client");
}

function createKnowledgebaseSource(
  source: DataSourceConnection,
  credentials: Credentials,
): DataSource {
  throw new Error("Implement for your vector store client");
}

function createStorageSource(
  source: DataSourceConnection,
  credentials: Credentials,
): DataSource {
  throw new Error("Implement for your storage client");
}
```

## Step 6: Wire It Together

Here is the complete flow from request to results:

```typescript
// ── In your request handler / orchestration layer ───────────────────────

const SIGNING_KEY = process.env.TOLAP_SIGNING_KEY!;

async function handleAgentRequest(
  authenticatedUserId: UUID,
  tenantId: UUID,
  request: string,
): Promise<unknown> {
  // 1. Resolve policies and build security context
  const accessibleSources = await getAccessibleSources(
    authenticatedUserId,
    tenantId,
  );
  const engine = new PolicyResolutionEngine(policyStore);
  const context = await buildSecurityContext(
    authenticatedUserId,
    tenantId,
    accessibleSources,
    engine,
  );
  const signedContext = signContext(context, SIGNING_KEY);

  // 2. If executing in a different process/service, serialize for transport
  // const serialized = serializeForTransport(signedContext);
  // ... send via queue, header, or RPC ...
  // const signedContext = deserializeAndValidate(serialized, SIGNING_KEY);

  // 3. Create secure tools
  const factory = new SecureToolFactory(
    engine,
    dataSourceRegistry,
    credentialResolver,
  );
  const tools = await factory.createAllAccessibleTools(signedContext);

  // 4. Give tools to the agent runtime
  const agent = createAgent(tools);
  const result = await agent.execute(request);

  return result;
}
```

The agent receives tools that can only return data the user is authorized to see. The agent does not need to know about security policies, check permissions, or filter results. Enforcement is invisible and non-bypassable.

## Testing Recommendations

### Unit Tests for Policy Resolution

Test the merge algorithm with multiple overlapping policies:

- Two policies with overlapping `allowedFields` -- verify intersection
- One policy hides a field, another allows it -- verify hidden wins
- Two policies with different `maxResults` -- verify minimum wins
- One policy sets `canQuery = false` -- verify AND produces false
- Policy with row filters from multiple profiles -- verify all filters are present

```typescript
import { describe, it, expect } from "vitest"; // or jest, node:test, etc.

describe("mergePolicies", () => {
  it("should intersect allowedFields across policies", () => {
    const policies: PolicyDefinition[] = [
      makePolicyWith({ allowedFields: ["id", "name", "email"] }),
      makePolicyWith({ allowedFields: ["id", "email", "phone"] }),
    ];
    const result = mergePolicies(policies);
    expect(result.allowedFields).toEqual(
      expect.arrayContaining(["id", "email"]),
    );
    expect(result.allowedFields).toHaveLength(2);
  });

  it("should deny query when any policy denies", () => {
    const policies: PolicyDefinition[] = [
      makePolicyWith({ canQuery: true }),
      makePolicyWith({ canQuery: false }),
    ];
    const result = mergePolicies(policies);
    expect(result.canQuery).toBe(false);
  });

  it("should take the minimum maxResults", () => {
    const policies: PolicyDefinition[] = [
      makePolicyWith({ maxResults: 1000 }),
      makePolicyWith({ maxResults: 100 }),
    ];
    const result = mergePolicies(policies);
    expect(result.maxResults).toBe(100);
  });

  it("should return DENY_ALL when no policies apply", () => {
    const result = mergePolicies([]);
    expect(result.canQuery).toBe(false);
    expect(result.readOnly).toBe(true);
  });
});
```

### Integration Tests for Tool Wrappers

Test enforcement at the tool level:

- Query referencing a hidden column -- verify rejection
- Query without row filters -- verify filters are injected
- Result with masked fields -- verify masking is applied
- Schema introspection -- verify hidden objects/fields are absent
- Expired security context -- verify rejection

```typescript
describe("SecureToolWrapper", () => {
  it("should reject queries referencing hidden fields", async () => {
    const wrapper = createTestWrapper({
      hiddenFields: ["ssn", "credit_card"],
    });
    // Assuming analyzeQuery returns { referencedFields: ["ssn"] }
    await expect(
      wrapper.executeQuery("SELECT ssn FROM patients"),
    ).rejects.toThrow("Access denied: field 'ssn' is not accessible");
  });

  it("should apply field masking to results", async () => {
    const wrapper = createTestWrapper({
      maskedFields: [
        { field: "email", maskType: MaskType.Partial, visibleChars: 4 },
      ],
    });
    const results = await wrapper.executeQuery("SELECT email FROM users");
    // Original value "user@example.com" should be partially masked
    expect(results[0].email).toMatch(/^\*+\.com$/);
  });

  it("should exclude hidden objects from listing", async () => {
    const wrapper = createTestWrapper({
      hiddenObjects: ["audit_log", "internal_config"],
    });
    const objects = await wrapper.listAccessibleObjects();
    expect(objects).not.toContain("audit_log");
    expect(objects).not.toContain("internal_config");
  });
});
```

### End-to-End Tests

Test the full flow from user identity to filtered results:

- User with restrictive policy queries a data source -- verify only authorized data returned
- User with no applicable policies -- verify access denied
- User with expired assignment -- verify access denied
- User with multiple overlapping assignments -- verify most-restrictive merge

```typescript
describe("TOLAP end-to-end", () => {
  it("should return only authorized data for a restricted user", async () => {
    // Set up: user has a policy that allows only the "patients" table,
    // hides the "ssn" column, and filters to region = "us-east"
    const context = await buildSecurityContext(
      restrictedUserId,
      tenantId,
      [patientDbSource],
      engine,
    );
    const signed = signContext(context, TEST_SIGNING_KEY);
    const tools = await factory.createAllAccessibleTools(signed);

    const results = await tools[0].executeQuery(
      "SELECT * FROM patients",
    );

    // Verify: ssn column is not present, all rows are us-east
    for (const row of results) {
      expect(row).not.toHaveProperty("ssn");
      expect(row.region).toBe("us-east");
    }
  });

  it("should deny access when no policies apply", async () => {
    const context = await buildSecurityContext(
      unknownUserId,
      tenantId,
      [],
      engine,
    );
    const signed = signContext(context, TEST_SIGNING_KEY);
    const tools = await factory.createAllAccessibleTools(signed);

    expect(tools).toHaveLength(0);
  });

  it("should reject an expired security context", () => {
    const expiredContext = serializeForTransport(
      signContext(
        { ...validContext, expiresAt: new Date("2020-01-01") },
        TEST_SIGNING_KEY,
      ),
    );

    expect(() =>
      deserializeAndValidate(expiredContext, TEST_SIGNING_KEY),
    ).toThrow("Security context has expired");
  });
});
```
