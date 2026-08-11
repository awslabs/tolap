# TOLAP -- Tool-Object Level Access Protocol

**The missing security layer for AI agent tools.**

When an AI agent queries a database, calls an API, or searches a knowledge base on behalf of a user, it does so through tools -- MCP servers, plugins, function calls. These tools connect directly to data sources. The agent constructs its own queries, decides which endpoints to call, and determines what data to retrieve.

**The problem:** the tool has unrestricted access to the underlying data. RBAC checks whether a user can access a resource. ABAC evaluates attributes at a gateway. Neither operates where agents actually touch data -- *inside the tool itself*. If the agent constructs a query the application layer did not anticipate, sensitive data leaks through.

**TOLAP fixes this** by moving security enforcement inside the tool, at the data-object level. Column-level masking, row-level filtering, field-level redaction, tag-based access, endpoint restrictions -- enforced transparently before any data reaches the agent. The agent never receives data the user is not authorized to see.

## The Problem in Practice

Both paths below start the same way and pass the same authorization check. They differ at
exactly one point -- what the tool is allowed to return -- and everything downstream
follows from that.

```mermaid
flowchart TD
    A[User request] --> B[Agent framework]
    B -->|"IAM / OAuth: may the agent invoke this tool? YES"| SPLIT{{"Tool executes<br/>the query it built"}}

    SPLIT --> W1
    SPLIT --> T1

    subgraph gap ["❌ WITHOUT TOLAP — enforcement above the tool"]
        direction TB
        W1["Tool has full access<br/>to the data source"]
        W1 --> W2["Every row and column<br/>returned to the agent"]
        W2 --> LEAK(["Unauthorized data is now in<br/>the agent's context window"])
        LEAK --> W3["Content guardrails<br/>redact PII in the output text"]
        W3 --> W4["Response to user"]
    end

    subgraph fix ["✅ WITH TOLAP — enforcement inside the tool"]
        direction TB
        T1["TOLAP wrapper enforces<br/>columns · rows · fields · tags · endpoints"]
        T1 --> T2["Only authorized data<br/>leaves the data source"]
        T2 --> T3["Agent receives<br/>filtered results"]
        T3 --> T4["Content guardrails"]
        T4 --> T5["Response to user"]
    end

    style W1 fill:#ff6b6b,color:#fff,stroke:#cc0000
    style W2 fill:#ff6b6b,color:#fff,stroke:#cc0000
    style LEAK fill:#8a1c1c,color:#fff,stroke:#5c0000
    style T1 fill:#51cf66,color:#fff,stroke:#2b8a3e
    style T2 fill:#51cf66,color:#fff,stroke:#2b8a3e
    style T3 fill:#51cf66,color:#fff,stroke:#2b8a3e
```

The dark red step is the whole argument, and note **where** it sits: before the
guardrails, not after. By the time anything filters the output, the unrestricted data is
already in the agent's context window. Guardrails constrain what the model *says*, not
what the model *saw* -- so a prompt injection, a tool-call trace, or a follow-up question
can still surface it.

Note what the two paths share. The IAM/OAuth check passes in both, because it answers a
different question: *may this agent call this tool?* Neither RBAC at the identity layer
nor ABAC at a gateway can answer *which columns and rows may this particular user see
through this particular call* -- that decision has to be made where the query meets the
data. Every major agent framework -- AWS Bedrock Agents, Azure AI Agent Service, Google
Vertex AI Agents, LangChain -- acknowledges this and tells you to solve it yourself inside
your tool code.

On the green path there is nothing to bypass, because the restricted data never left the
source.

## Three Principles

**Source-Point Enforcement** -- Security is enforced where data originates, not in a layer above it. The tool wraps the data source and applies policies before any data crosses the boundary. There is no path to the data that bypasses enforcement.

**Object Granularity** -- Policies operate on individual data objects: columns, rows, fields, tags, endpoints, HTTP methods, similarity thresholds, file prefixes, result limits. A single policy can say "this user can query the patients table but cannot see the SSN column, rows are filtered to their region, and the email field is returned as a SHA-256 hash."

**Agent Transparency** -- The calling agent requires zero security-awareness code. Restricted data simply does not exist from the agent's perspective. This eliminates an entire class of prompt injection and data exfiltration risks.

## What TOLAP Covers

| Data Source | Enforcement |
|-------------|------------|
| **Databases** (PostgreSQL, MySQL, Athena, BigQuery, ...) | Column hiding, row filtering, field masking, result limits |
| **APIs** (REST, GraphQL, SOAP, FHIR, gRPC, ...) | Endpoint allow/deny, HTTP method restrictions, response field masking |
| **Knowledge Bases** (Bedrock KB, OpenSearch, Elasticsearch, ...) | Tag-based filtering (classification levels are expressed as tags), similarity thresholds |
| **Object Storage** (S3, Azure Blob, GCS, ...) | Prefix allow/deny, size limits, metadata masking |

One policy schema covers all source types. No category-specific schemas.

Enforcement is applied to results **after** the tool executes — that pass is the
security boundary and always runs. The agent never receives an excluded row.

For SQL sources the .NET SDK additionally offers **optional query rewriting**, which
pushes row filters into a `WHERE` clause and the result limit into a `LIMIT` so the
database returns less data. That is a resource optimization, not the enforcement: the
post-execution pass still runs, because some filters have no portable SQL form. Without
rewriting, a large result set is fetched and then trimmed, so push limits into your own
queries when a collection may be large.

## How It Works

1. **Define policies** -- Declarative JSON policies specify what each user/group/role can access, at the object level
2. **Assign policies** -- Link policies to users, groups, roles, or service accounts with mandatory audit trails
3. **Resolve** -- The SDK merges all applicable policies using most-restrictive-wins rules
4. **Sign** -- The merged policy is HMAC-signed for tamper-proof cross-boundary transport
5. **Enforce** -- The secure tool wrapper applies the policy transparently on every tool call

```json
{
  "name": "healthcare-analyst",
  "permissions": { "canQuery": true, "readOnly": true },
  "objectRules": {
    "allowedObjects": ["patients", "encounters", "diagnoses"],
    "hiddenObjects": ["billing_internal", "audit_log"],
    "fieldRules": {
      "hiddenFields": ["patients.ssn", "patients.date_of_birth"],
      "maskedFields": [
        { "field": "patients.email", "maskType": "hash", "parameters": { "algorithm": "sha256" } },
        { "field": "patients.full_name", "maskType": "partial", "parameters": { "showFirst": 1, "maskChar": "*" } }
      ]
    },
    "rowFilters": [
      { "field": "region", "operator": "in", "values": ["us-east", "us-west"] },
      { "field": "status", "operator": "notEquals", "value": "deleted" }
    ]
  },
  "limits": { "maxResults": 5000 }
}
```

The agent sees: `J*********` for the name, a SHA-256 hash for the email, no SSN column at all, and only rows from us-east and us-west. The restricted data never crosses the tool boundary.

## SDK Packages

The TOLAP SDK ships in three languages, each with three packages:

> **Not yet on the public registries.** The nine packages below are built and verified by
> [`.github/workflows/publish.yml`](.github/workflows/publish.yml) but have not been pushed
> to PyPI, npm or NuGet yet, so the install commands in this section do not resolve. Until
> the first release lands, build from a clone: `pip install ./sdk/python/tolap-core` (and
> its siblings), `npm ci && npx tsc -p tsconfig.json` per package under
> `sdk/typescript/packages/`, or `dotnet build sdk/dotnet/Tolap.sln`.
> [`docs/releasing.md`](docs/releasing.md) describes what has to happen first. **Delete this
> note when the packages are live.**

### .NET

```bash
dotnet add package Tolap.Core
dotnet add package Tolap.Store
dotnet add package Tolap.Mcp
```

| Package | Description |
|---------|-------------|
| **Tolap.Core** | Policy models, merge algorithm, HMAC signing, enforcement engine. Zero dependencies. |
| **Tolap.Store** | `IPolicyStore` interface + in-memory implementation. Pluggable for any backend. |
| **Tolap.Mcp** | Enforcement wrappers for the function your tool layer calls -- MCP servers, agent-framework tools, Lambda handlers. Speaks no wire protocol of its own. |

### Python

```bash
pip install tolap-core
pip install tolap-store
pip install tolap-mcp
```

| Package | Description |
|---------|-------------|
| **tolap-core** | Policy models, merge algorithm, HMAC signing, enforcement engine. Zero dependencies. |
| **tolap-store** | `PolicyStore` protocol + in-memory implementation. Pluggable for any backend. |
| **tolap-mcp** | Enforcement wrappers for the function your tool layer calls -- MCP servers, agent-framework tools, Lambda handlers. Speaks no wire protocol of its own. |

### TypeScript

```bash
npm install @tolap/core
npm install @tolap/store
npm install @tolap/mcp
```

| Package | Description |
|---------|-------------|
| **@tolap/core** | Policy models, merge algorithm, HMAC signing, enforcement engine. Zero dependencies. |
| **@tolap/store** | `PolicyStore` interface + in-memory implementation. Pluggable for any backend. |
| **@tolap/mcp** | Enforcement wrappers for the function your tool layer calls -- MCP servers, agent-framework tools, Lambda handlers. Speaks no wire protocol of its own. |

**Core packages have zero external dependencies** in all three languages. Crypto, JSON, and collections use standard library only. The enforcement engine is embeddable anywhere -- MCP servers, Lambda functions, edge workers, Semantic Kernel plugins. [`examples/`](examples/) shows it wired into fourteen agent frameworks; none of the integrations adds a dependency to your enforcement path.

## Quick Start

### Resolve a policy and sign a context (TypeScript)

```typescript
import { merge, signContext, buildSecurityContext } from "@tolap/core";
import { InMemoryPolicyStore } from "@tolap/store";
import { SecureMcpToolWrapper } from "@tolap/mcp";

// 1. Create a policy store and add policies
const store = new InMemoryPolicyStore();
await store.putDefinition({
  version: "1.0",
  name: "analyst-db-access",
  permissions: { canQuery: true, readOnly: true },
  objectRules: {
    // hiddenFields and maskedFields nest under fieldRules, not directly under objectRules.
    fieldRules: {
      hiddenFields: ["ssn", "date_of_birth"],
      maskedFields: [{ field: "email", maskType: "hash", parameters: { algorithm: "sha256" } }]
    }
  },
  limits: { maxResults: 1000 }
});

// 2. Assign the policy to a user
await store.putAssignment({
  version: "1.0",
  policyName: "analyst-db-access",
  assignee: { type: "user", identifier: "user-123" },
  scope: { tenantId: "tenant-acme" },
  active: true,
  audit: { grantedBy: "admin", grantedAt: new Date().toISOString(), reason: "Analyst role" }
});

// 3. Resolve -- this merges EVERY assignment the user holds for that source into one
//    effective policy, most-restrictive-wins.
const policy = await store.resolvePolicy("user-123", "tenant-acme", "ds-postgres");
// policy.objectRules.fieldRules.hiddenFields -> ["ssn", "date_of_birth"]

// 4. Sign it. The signature covers the whole envelope including sourceConnectionId, so a
//    context cannot be replayed against a different source. Never hand-roll this: a plain
//    JSON.stringify is not the canonical form and the signature will not verify.
const context = signContext(buildSecurityContext("user-123", "tenant-acme", policy), signingKey);
```

For a runnable version of this wired into an actual agent framework, see
[`examples/`](examples/) -- 14 integrations, each CI-tested.

### Enforce on Query Results (Python)

```python
from tolap_core import apply_field_masking, validate_field_access, EffectivePolicy

policy = ...  # resolved effective policy

# Check which fields the user can access
result = validate_field_access(["name", "email", "ssn", "region"], policy)
# result.allowed = ["name", "email", "region"]
# result.denied = ["ssn"]

# Mask sensitive fields in a result record
record = {"name": "John Smith", "email": "john@example.com", "region": "us-east"}
masked = apply_field_masking(record, policy)
# masked = {"name": "J*********", "email": "a1b2c3d4e5f6...", "region": "us-east"}
```

### Merge Multiple Policies (.NET)

```csharp
using Tolap.Core;

// Two overlapping policies -- most restrictive wins
var merged = PolicyMerger.Merge(new[] { policyA, policyB });

// Permissions: AND (both must allow)
// Allowed fields: intersection (only fields in both)
// Hidden fields: union (hidden in either = hidden)
// Max results: minimum (stricter limit wins)
// Masked fields: most restrictive mask type per field
```

## Centralizing the Policy Store

The Quick Start examples above use the built-in `InMemoryPolicyStore` -- great for development, testing, and single-process deployments. In production, you will want a centralized store backed by a database so that all services share the same policies.

> **There is a working implementation of this.** [`server/`](server/) is a policy
> server with a PostgreSQL store, a `GET /v1/resolve` endpoint that returns a signed
> policy every one of the three SDKs can verify, schema validation, immutable policy
> versions with publish and rollback, an audit trail, and Cognito-authenticated
> admin access. [`console/`](console/) is its UI: it authors every rule in the policy
> model from a catalog imported from your OpenAPI document or SQL DDL, so a policy names
> columns and endpoints that exist -- `hiddenFields: ["ssn"]` protects nothing when the
> column is `ssn_number`, and nothing in TOLAP can detect that. Start with
> [`docs/policy-server.md`](docs/policy-server.md) if you would rather run one than
> build one.
>
> The rest of this section is for integrators embedding TOLAP directly, or building
> a store against a different backend.

The SDK defines a store interface (`IPolicyStore` in .NET, `PolicyStore` protocol in Python, `PolicyStore` interface in TypeScript). Implement it against any backend. Here is a PostgreSQL example for each language:

### Schema

```sql
CREATE TABLE tolap_policies (
    name        TEXT PRIMARY KEY,
    version     TEXT NOT NULL DEFAULT '1.0',
    priority    INTEGER NOT NULL DEFAULT 0,
    policy_json JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE tolap_assignments (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_name   TEXT NOT NULL REFERENCES tolap_policies(name),
    assignee_type TEXT NOT NULL,
    assignee_id   TEXT NOT NULL,
    tenant_id     TEXT,
    data_source_id TEXT,
    active        BOOLEAN NOT NULL DEFAULT true,
    expires_at    TIMESTAMPTZ,
    granted_by    TEXT NOT NULL,
    granted_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    reason        TEXT
);
```

### .NET (PostgreSQL with Npgsql)

```csharp
public class PostgresPolicyStore : IPolicyStore
{
    private readonly NpgsqlDataSource _db;

    public PostgresPolicyStore(string connectionString)
        => _db = NpgsqlDataSource.Create(connectionString);

    public async Task<EffectivePolicy> ResolveEffectivePolicyAsync(
        string userId, string tenantId, string dataSourceId, CancellationToken ct = default)
    {
        const string sql = """
            SELECT p.policy_json FROM tolap_assignments a
            JOIN tolap_policies p ON a.policy_name = p.name
            WHERE a.assignee_id = @userId
              AND (a.tenant_id IS NULL OR a.tenant_id = @tenantId)
              AND (a.data_source_id IS NULL OR a.data_source_id = @dsId)
              AND a.active = true
              AND (a.expires_at IS NULL OR a.expires_at > now())
            ORDER BY p.priority DESC
            """;
        var policies = new List<PolicyDefinition>();
        await using var cmd = _db.CreateCommand(sql);
        cmd.Parameters.AddWithValue("userId", userId);
        cmd.Parameters.AddWithValue("tenantId", tenantId);
        cmd.Parameters.AddWithValue("dsId", dataSourceId);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            policies.Add(Deserialize<PolicyDefinition>(reader.GetString(0)));
        return PolicyMerger.Merge(policies);
    }
}
```

### Python (asyncpg)

```python
class PostgresPolicyStore(PolicyStore):
    def __init__(self, pool: asyncpg.Pool):
        self._pool = pool

    async def resolve_effective_policy(self, user_id, tenant_id, data_source_id):
        rows = await self._pool.fetch(
            """SELECT p.policy_json FROM tolap_assignments a
               JOIN tolap_policies p ON a.policy_name = p.name
               WHERE a.assignee_id = $1
                 AND (a.tenant_id IS NULL OR a.tenant_id = $2)
                 AND (a.data_source_id IS NULL OR a.data_source_id = $3)
                 AND a.active = true
                 AND (a.expires_at IS NULL OR a.expires_at > now())
               ORDER BY p.priority DESC""",
            user_id, tenant_id, data_source_id,
        )
        policies = [PolicyDefinition.from_json(r["policy_json"]) for r in rows]
        return merge(policies)
```

### TypeScript (pg)

```typescript
export class PostgresPolicyStore implements PolicyStore {
  constructor(private pool: Pool) {}

  async resolveEffectivePolicy(
    userId: string, tenantId: string, dataSourceId: string
  ): Promise<EffectivePolicy> {
    const { rows } = await this.pool.query(
      `SELECT p.policy_json FROM tolap_assignments a
       JOIN tolap_policies p ON a.policy_name = p.name
       WHERE a.assignee_id = $1
         AND (a.tenant_id IS NULL OR a.tenant_id = $2)
         AND (a.data_source_id IS NULL OR a.data_source_id = $3)
         AND a.active = true
         AND (a.expires_at IS NULL OR a.expires_at > now())
       ORDER BY p.priority DESC`,
      [userId, tenantId, dataSourceId]
    );
    return merge(rows.map((r) => r.policy_json));
  }
}
```

### Other Backends

The same interface works with any backend:

| Backend | Best for |
|---------|----------|
| **PostgreSQL** | Relational data, JSONB querying, existing Postgres infrastructure |
| **DynamoDB** | Serverless, AWS-native, high-throughput reads |
| **Redis** | Low-latency caching layer in front of a primary store |
| **REST API** | Dedicated policy service shared across teams |

For caching, architecture diagrams, and a complete policy service API design, see the [Architecture Guide](docs/architecture.md#deployment-patterns-centralized-policy-store).

## Policy Merge Rules

When multiple policies apply to a user, TOLAP merges them using most-restrictive-wins:

| Field Type | Strategy | Example |
|-----------|----------|---------|
| Allowed sets | Intersection | `allowedFields` from two policies -> only fields in both |
| Hidden/denied sets | Union | `hiddenFields` from two policies -> all hidden fields combined |
| Boolean permissions | AND | `canQuery` true + false -> false |
| Numeric limits (maxima) | Minimum | `maxResults` 100 + 50 -> 50 |
| Numeric limits (minima) | Maximum | `minSimilarityScore` 0.7 + 0.8 -> 0.8 |
| Masked fields | Most restrictive | ranked by disclosure: null > redact > full > hash > partial |
| Row filters | Concatenate | All filters from all policies apply (AND) |

## TOLAP vs Traditional Approaches

| | RBAC | ABAC | Database RLS | **TOLAP** |
|---|---|---|---|---|
| **Enforcement point** | Application layer | Policy engine / gateway | Database engine | **Inside the tool** |
| **Granularity** | Role / resource | Attribute / policy | Row | **Column, row, field, tag, endpoint** |
| **Cross-source** | Per-system | Centralized but bypassable | Database only | **All source types unified** |
| **Agent-safe** | Requires agent compliance | Requires routing through engine | N/A | **Transparent -- agent unaware** |
| **Masking** | Not built-in | Policy-dependent | Not built-in | **Built-in per-field masking** |
| **Multi-tenant** | Application logic | Policy logic | Database logic | **Embedded in every tool** |

## Policy Schema

TOLAP policies are defined in three layers:

1. **[Policy Definition](schema/v1.0/policy-definition.schema.json)** -- Declares access rules: objects, fields, rows, tags, endpoints, masking, limits
2. **[Policy Assignment](schema/v1.0/policy-assignment.schema.json)** -- Links a policy to a user/group/role with scope, expiry, and audit trail
3. **[Effective Policy](schema/v1.0/effective-policy.schema.json)** -- The merged, signed result enforced at the tool layer

Schema version: **v1.0** (strict versioning, no extension points)

## Security Properties

- **Non-bypassable where the wrapper is the only path** -- Enforcement runs inside the
  tool, so an agent cannot route around it. This holds only as far as the integrator
  wires it: a tool that reaches a data source without going through a secure wrapper is
  outside the boundary, and TOLAP cannot know about it.
- **Tamper-proof** -- Effective policies are HMAC-signed over a canonical form that
  covers the whole context including its expiry. Any modification invalidates the
  signature, and a context signed by one SDK verifies in the other two.
- **Replay-bounded** -- Signed contexts carry an expiry that is inside the signature, so
  it cannot be extended without the key. Each context also carries a signed `jti`, and the
  deserializers accept an optional `ReplayGuard` that makes a context single-use. Without a
  guard a valid context is replayable until it expires, so keep TTLs short.
- **Cross-boundary** -- Signed contexts can be transported across process, network, and
  cloud boundaries without losing integrity.
- **Revocation is enforced by the SDK** -- An assignment carrying `revokedAt` stops
  resolving, overriding `active` and `expiresAt`, and an unreadable value fails closed.
  If you write your own store, filter revoked rows anyway, but that filter is no longer
  the only thing standing between a revoked grant and a resolved policy.
- **Masking can be a confidentiality control** -- Configure a `hashSalt` and `hash`
  becomes a keyed HMAC rather than a plain digest, so a masked SSN or date of birth is
  not recoverable by rainbow table. The same salt yields the same pseudonym in every
  SDK, so it still works as a cross-service join key.
- **Audit fields are mandatory in the schema** -- Every policy assignment must carry who
  granted it, when, and why. This is a schema constraint on stored assignments; validate
  assignments against the schema in your store, because the SDK does not reject an
  assignment that omits them at load time.

See [Known limitations](docs/canonical-enforcement-spec.md#13-known-limitations) for the
full list of what TOLAP does not guarantee.

## Documentation

- [Architecture Guide](docs/architecture.md) -- Components, data flow, sequence diagrams
- [Policy Server](docs/policy-server.md) -- Running the central policy server in [`server/`](server/) and its console: Cognito setup, the two roles, install registration, and the signed artifact `/v1/resolve` returns
- [Canonical Enforcement Spec](docs/canonical-enforcement-spec.md) -- Normative cross-language behavior: canonical signing, enforcement pipeline order, fail-closed rules
- [Connector Spec](docs/connector-spec.md) -- Normative per-category behavior: which policy fields apply to `db` / `api` / `kb` / `storage`, what an object and a record mean for each, and which fields are advisory rather than enforced
- [Local Testing](docs/local-testing.md) -- Running the suites against live Postgres/MySQL and the test API server
- [Releasing](docs/releasing.md) -- Publishing the nine packages to PyPI, npm and NuGet: registry setup, the version-agreement gate, and recovering a partial release
- [Integration examples](examples/) -- Fourteen integrations across Python, TypeScript and .NET (MCP SDK, Strands, LangChain, Vercel AI, Mastra, OpenAI Agents, Pydantic AI, Semantic Kernel, Bedrock Agents), each CI-tested to enforce the same policy identically
- [Threat Model](docs/security/threat-model.md) -- STRIDE analysis per trust boundary, with the defects found and fixed since revision 1
- [Testing Anti-Patterns](docs/testing-antipatterns.md) -- Six defects that shipped here while the suite was green, and the smell to grep for in each
- Test evidence:
  - [`security/aws/`](security/aws/) -- 129 tests against real S3, Athena, Bedrock KB, OpenSearch and Elasticsearch, with the findings each one produced
  - [`security/databases/`](security/databases/) -- Verbose transcripts showing the actual SQL, rows before and after, and each masking type, against live PostgreSQL, MySQL, pgvector and a real HTTP socket
- Implementation Guides:
  - [.NET / C#](docs/implementation-guide-dotnet.md)
  - [Python](docs/implementation-guide-python.md)
  - [TypeScript](docs/implementation-guide-typescript.md)
- [Schema Examples](schema/v1.0/examples/) -- Database (read and write), API, knowledge base, and storage policy examples

## Integration Examples

Fourteen runnable integrations across three languages, each CI-tested to enforce the **same policy
identically**. See [`examples/`](examples/).

| Language | Frameworks | Tests |
| --- | --- | --: |
| [Python](examples/python/) | MCP SDK, Strands, LangChain, OpenAI Agents, Pydantic AI, Semantic Kernel, Bedrock Agents | 42 |
| [TypeScript](examples/typescript/) | MCP SDK, LangChain.js, Vercel AI SDK, Mastra, OpenAI Agents JS | 30 |
| [.NET](examples/dotnet/) | MCP SDK, Semantic Kernel | 12 |

**TOLAP is not an MCP server and does not speak the MCP protocol.** It ships no JSON-RPC, no stdio
transport, no `tools/list`, and declares no MCP dependency in any package. The `*-mcp` packages
provide enforcement *around the function your tool layer already calls* -- which is why the
integration is the same substitution in all fourteen cases, and why none of them takes a credential.
Your code fetches the data; TOLAP decides what may leave.

Every example runs against a fake source returning **4 rows and 5 columns**, and every one returns:

```
{ id: 1, name: "Alice Nguyen", region: "us-east", dob: "[REDACTED]" }
{ id: 2, name: "Bruno Sato",   region: "us-east", dob: "[REDACTED]" }
```

`ssn` hidden · `dob` redacted · `eu-west` filtered out · capped at 2 · `encounters` refused before
any query runs.

The expected output is written identically in all three test suites on purpose, and each suite is
parametrised across its frameworks rather than written per framework. A per-framework test would
pass if one integration quietly returned the raw rows, because nothing would compare it to the
others. All three are mutation-verified: bypassing enforcement in the shared helper fails 30/42,
20/30 and 8/12 assertions respectively.

Thirteen of the fourteen are in-process. **Bedrock Agents** is the exception -- it invokes a Lambda,
so the signed context arrives as a session attribute and the handler verifies the signature before
enforcing. A handler that fell back to "no policy" on a missing attribute would be an
unauthenticated read of the data source, so it returns `403`; that case is tested.

## Project Structure

```
tolap/
  docs/            TOLAP standard: normative specs, architecture, implementation guides
  schema/v1.0/     JSON Schema specification
  fixtures/        Shared test data -- all three SDKs must produce identical results
  sdk/
    dotnet/        Tolap.Core, Tolap.Store, Tolap.Mcp
    python/        tolap-core, tolap-store, tolap-mcp
    typescript/    @tolap/core, @tolap/store, @tolap/mcp
  server/          Policy server: central store, resolve API, Cognito admin auth
  console/         Admin UI for the policy server
  examples/        14 agent-framework integrations, CI-tested (see below)
    python/        MCP SDK, Strands, LangChain, OpenAI Agents,
                   Pydantic AI, Semantic Kernel, Bedrock Agents
    typescript/    MCP SDK, LangChain.js, Vercel AI SDK, Mastra, OpenAI Agents JS
    dotnet/        MCP SDK, Semantic Kernel
  security/        Test evidence against real services, and the findings each run produced
    aws/           S3, Athena, Bedrock KB, OpenSearch, Elasticsearch
    databases/     PostgreSQL, MySQL, pgvector, and the `api` transport
  tools/test-api/  Local HTTP server for socket-level enforcement tests
  .github/         CI: the SDK gate, plus a separate weekly examples workflow
```

`fixtures/` and `examples/` both exist for the same reason. A behaviour difference between .NET,
Python and TypeScript is a security defect, not an inconsistency -- so the shared fixtures demand
byte-identical output from the three SDKs, and the examples demand the same enforced result from
14 integrations across all three. Both are structured so a divergence shows up as a *different
result* rather than hiding behind separately-written expectations.

## Contributing

TOLAP is protocol-agnostic: it enforces around the function your tool layer calls, so it works with
MCP servers, Semantic Kernel plugins, LangChain tools, Bedrock Agents or any other tool-based agent
architecture. [`examples/`](examples/) demonstrates fourteen of them.

Adding a framework is welcome, and the bar is a runnable example plus its assertions in the
matching `test_examples` suite -- an example nothing executes will drift silently, and one that
mis-wires enforcement teaches people to bypass it. Contributions welcome -- see
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
