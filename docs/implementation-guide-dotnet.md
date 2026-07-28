# TOLAP Implementation Guide -- .NET / C#

This guide walks through implementing TOLAP (Tool-Object Level Access Protocol) in a .NET / C# tool layer. The examples use idiomatic C# with `async/await`, LINQ, `System.Text.Json`, and nullable reference types. For a concrete reference implementation, see [reference-implementation.md](reference-implementation.md).

## Prerequisites

Before implementing TOLAP, you need:

1. **An authenticated user identity** -- TOLAP does not handle authentication. Your system must provide a verified user ID and tenant ID.
2. **A policy store** -- Somewhere to persist policy definitions and assignments (database, configuration files, policy service).
3. **A tool layer** -- The tools your AI agents use to access data sources (MCP servers, Semantic Kernel plugins, LangChain tools, etc.).

## Step 1: Define Your Policy Store

TOLAP policies are defined using the [Policy Definition Schema](schema/v1.0/policy-definition.schema.json) and linked to users via the [Policy Assignment Schema](schema/v1.0/policy-assignment.schema.json).

Your policy store needs two collections:

**Policy Definitions** -- reusable rule sets:

```csharp
using System.Text.Json.Serialization;

// ── Enums ────────────────────────────────────────────────────────────

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum AssigneeType
{
    User,
    Group,
    Role,
    ServiceAccount
}

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum MaskType
{
    Null = 1,
    Redact = 2,
    Partial = 3,
    Hash = 4,
    Full = 5
}

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum FilterOperator
{
    Equals,
    NotEquals,
    In,
    NotIn,
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
    Contains,
    StartsWith,
    Between
}

// ── Policy Definition Models ─────────────────────────────────────────

public sealed class PolicyDefinition
{
    public required string Name { get; init; }
    public string Description { get; init; } = string.Empty;
    public int Priority { get; init; }
    public bool AppliesToAll { get; init; }
    public List<string> SourcePatterns { get; init; } = [];
    public PolicyPermissions Permissions { get; init; } = new();
    public ObjectRules ObjectRules { get; init; } = new();
    public PolicyLimits Limits { get; init; } = new();
    public bool IsActive { get; init; } = true;
}

public sealed class PolicyPermissions
{
    public bool CanQuery { get; init; } = true;
    public bool CanExport { get; init; }
    public bool ReadOnly { get; init; } = true;
}

public sealed class ObjectRules
{
    public List<string>? AllowedObjects { get; init; }
    public List<string>? HiddenObjects { get; init; }
    public FieldRules? FieldRules { get; init; }
    public List<RowFilter>? RowFilters { get; init; }
    public TagRules? TagRules { get; init; }
    public EndpointRules? EndpointRules { get; init; }
}

public sealed class FieldRules
{
    public List<string>? AllowedFields { get; init; }
    public List<string>? HiddenFields { get; init; }
    public List<MaskedFieldRule>? MaskedFields { get; init; }
}

public sealed class MaskedFieldRule
{
    public required string Field { get; init; }
    public MaskType MaskType { get; init; }
    public string? Pattern { get; init; }
}

public sealed class RowFilter
{
    public required string Field { get; init; }
    public FilterOperator Operator { get; init; }
    public required object Value { get; init; }
}

public sealed class TagRules
{
    public List<string>? AllowedTags { get; init; }
    public List<string>? DeniedTags { get; init; }
}

public sealed class EndpointRules
{
    public List<string>? AllowedEndpoints { get; init; }
    public List<string>? HiddenEndpoints { get; init; }
    public List<string>? AllowedMethods { get; init; }
}

public sealed class PolicyLimits
{
    public int? MaxResults { get; init; }
    public int? MaxQueryTimeSeconds { get; init; }
    public double? MinSimilarityScore { get; init; }
    public long? MaxObjectSizeBytes { get; init; }
}
```

**Policy Assignments** -- links between policies and users:

```csharp
public sealed class PolicyAssignment
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public required string PolicyName { get; init; }
    public AssigneeType AssigneeType { get; init; }
    public required string AssigneeIdentifier { get; init; }
    public Guid? TenantId { get; init; }
    public Guid? SourceConnectionId { get; init; }
    public bool Active { get; init; } = true;
    public DateTimeOffset? ExpiresAt { get; init; }
    public required string GrantedBy { get; init; }
    public DateTimeOffset GrantedAt { get; init; } = DateTimeOffset.UtcNow;
    public string Reason { get; init; } = string.Empty;
}
```

These can live in a relational database, a document store, configuration files, or any persistent storage your system uses.

**Policy Store interface:**

```csharp
public interface IPolicyStore
{
    Task<IReadOnlyList<PolicyAssignment>> GetAssignmentsAsync(
        string assigneeIdentifier,
        AssigneeType assigneeType,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<PolicyAssignment>> GetAssignmentsByIdentifiersAsync(
        IEnumerable<(string Identifier, AssigneeType Type)> assignees,
        CancellationToken cancellationToken = default);

    Task<PolicyDefinition?> GetPolicyDefinitionAsync(
        string policyName,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<string>> GetUserGroupsAsync(
        string userId,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<string>> GetUserRolesAsync(
        string userId,
        CancellationToken cancellationToken = default);
}
```

## Step 2: Implement the Policy Resolution Engine

The Policy Resolution Engine computes the effective policy for a user and data source by merging all applicable policy definitions.

```csharp
using System.Text.RegularExpressions;

// ── Effective Policy (result of merging) ─────────────────────────────

public sealed class EffectivePolicy
{
    public Guid SourceConnectionId { get; set; }
    public DateTimeOffset ResolvedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }

    // Permissions
    public bool CanQuery { get; set; }
    public bool CanExport { get; set; }
    public bool ReadOnly { get; set; }

    // Allowed sets (null means unrestricted)
    public List<string>? AllowedObjects { get; set; }
    public List<string>? AllowedFields { get; set; }
    public List<string>? AllowedEndpoints { get; set; }
    public List<string>? AllowedTags { get; set; }
    public List<string>? AllowedMethods { get; set; }

    // Hidden/denied sets
    public List<string> HiddenObjects { get; set; } = [];
    public List<string> HiddenFields { get; set; } = [];
    public List<string> HiddenEndpoints { get; set; } = [];
    public List<string> DeniedTags { get; set; } = [];

    // Row filters
    public List<RowFilter> RowFilters { get; set; } = [];

    // Masked fields
    public List<MaskedFieldRule> MaskedFields { get; set; } = [];

    // Limits
    public int? MaxResults { get; set; }
    public int? MaxQueryTimeSeconds { get; set; }
    public long? MaxObjectSizeBytes { get; set; }
    public double? MinSimilarityScore { get; set; }

    /// <summary>
    /// A deny-all policy returned when no policies apply to the user.
    /// </summary>
    public static EffectivePolicy DenyAll => new()
    {
        CanQuery = false,
        CanExport = false,
        ReadOnly = true,
        AllowedObjects = [],
        AllowedFields = [],
        AllowedEndpoints = [],
        AllowedTags = [],
        AllowedMethods = [],
        MaxResults = 0
    };
}

// ── Policy Resolution Engine ─────────────────────────────────────────

public interface IPolicyResolutionEngine
{
    Task<EffectivePolicy> ResolveEffectivePolicyAsync(
        string userId,
        Guid tenantId,
        Guid sourceConnectionId,
        string sourceCategory,
        string sourceNamespace,
        string sourceName,
        CancellationToken cancellationToken = default);
}

public sealed class PolicyResolutionEngine : IPolicyResolutionEngine
{
    private readonly IPolicyStore _policyStore;

    public PolicyResolutionEngine(IPolicyStore policyStore)
    {
        _policyStore = policyStore;
    }

    public async Task<EffectivePolicy> ResolveEffectivePolicyAsync(
        string userId,
        Guid tenantId,
        Guid sourceConnectionId,
        string sourceCategory,
        string sourceNamespace,
        string sourceName,
        CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;

        // 1. Load all active assignments for this user
        var directAssignments = await _policyStore.GetAssignmentsAsync(
            userId, AssigneeType.User, cancellationToken);

        // 2. Also load group/role assignments
        var userGroups = await _policyStore.GetUserGroupsAsync(userId, cancellationToken);
        var userRoles = await _policyStore.GetUserRolesAsync(userId, cancellationToken);

        var groupAndRoleIdentifiers = userGroups
            .Select(g => (Identifier: g, Type: AssigneeType.Group))
            .Concat(userRoles.Select(r => (Identifier: r, Type: AssigneeType.Role)))
            .ToList();

        var groupRoleAssignments = groupAndRoleIdentifiers.Count > 0
            ? await _policyStore.GetAssignmentsByIdentifiersAsync(
                groupAndRoleIdentifiers, cancellationToken)
            : [];

        var assignments = directAssignments
            .Concat(groupRoleAssignments)
            .Where(a => a.Active)
            .Where(a => a.ExpiresAt is null || a.ExpiresAt > now)
            // 3. Narrow to tenant scope
            .Where(a => a.TenantId is null || a.TenantId == tenantId)
            // 4. Narrow to source scope
            .Where(a => a.SourceConnectionId is null || a.SourceConnectionId == sourceConnectionId)
            .ToList();

        // 5. Load referenced policy definitions
        var policies = new List<PolicyDefinition>();
        foreach (var assignment in assignments)
        {
            var policy = await _policyStore.GetPolicyDefinitionAsync(
                assignment.PolicyName, cancellationToken);
            if (policy is { IsActive: true })
            {
                policies.Add(policy);
            }
        }

        // 6. Filter to policies that match this source
        string sourceIdentifier = $"{sourceCategory}:{sourceNamespace}:{sourceName}";
        policies = policies
            .Where(p => p.AppliesToAll ||
                        p.SourcePatterns.Any(pattern => GlobMatch(sourceIdentifier, pattern)))
            .ToList();

        // 7. Sort by priority (lower = higher precedence)
        policies = policies.OrderBy(p => p.Priority).ToList();

        // 8. Merge using most-restrictive-wins
        return PolicyMerger.MergePolicies(policies);
    }

    /// <summary>
    /// Matches a source identifier against a glob pattern.
    /// Supports '*' (any characters within a segment) and '**' (any segments).
    /// </summary>
    private static bool GlobMatch(string input, string pattern)
    {
        string regexPattern = "^"
            + Regex.Escape(pattern)
                .Replace("\\*\\*", ".*")
                .Replace("\\*", "[^:]*")
            + "$";

        return Regex.IsMatch(input, regexPattern, RegexOptions.IgnoreCase);
    }
}
```

### The Merge Algorithm

```csharp
public static class PolicyMerger
{
    /// <summary>
    /// Merges multiple policies using the most-restrictive-wins strategy.
    /// </summary>
    public static EffectivePolicy MergePolicies(IReadOnlyList<PolicyDefinition> policies)
    {
        if (policies.Count == 0)
        {
            return EffectivePolicy.DenyAll;
        }

        var result = new EffectivePolicy
        {
            // Permissions: AND (all must allow)
            CanQuery = policies.All(p => p.Permissions.CanQuery),
            CanExport = policies.All(p => p.Permissions.CanExport),
            ReadOnly = policies.Any(p => p.Permissions.ReadOnly),

            // Allowed sets: INTERSECTION (null means "no restriction from this policy")
            AllowedObjects = IntersectNullable(
                policies.Select(p => p.ObjectRules.AllowedObjects)),
            AllowedFields = IntersectNullable(
                policies.Select(p => p.ObjectRules.FieldRules?.AllowedFields)),
            AllowedEndpoints = IntersectNullable(
                policies.Select(p => p.ObjectRules.EndpointRules?.AllowedEndpoints)),
            AllowedTags = IntersectNullable(
                policies.Select(p => p.ObjectRules.TagRules?.AllowedTags)),
            AllowedMethods = IntersectNullable(
                policies.Select(p => p.ObjectRules.EndpointRules?.AllowedMethods)),

            // Hidden/denied sets: UNION
            HiddenObjects = policies
                .SelectMany(p => p.ObjectRules.HiddenObjects ?? [])
                .Distinct()
                .ToList(),
            HiddenFields = policies
                .SelectMany(p => p.ObjectRules.FieldRules?.HiddenFields ?? [])
                .Distinct()
                .ToList(),
            HiddenEndpoints = policies
                .SelectMany(p => p.ObjectRules.EndpointRules?.HiddenEndpoints ?? [])
                .Distinct()
                .ToList(),
            DeniedTags = policies
                .SelectMany(p => p.ObjectRules.TagRules?.DeniedTags ?? [])
                .Distinct()
                .ToList(),

            // Row filters: AND (concatenate all)
            RowFilters = policies
                .SelectMany(p => p.ObjectRules.RowFilters ?? [])
                .ToList(),

            // Masked fields: most restrictive mask type per field
            MaskedFields = MergeMaskedFields(policies),

            // Numeric limits: minimum (most restrictive)
            MaxResults = MinNullable(policies.Select(p => p.Limits.MaxResults)),
            MaxQueryTimeSeconds = MinNullable(policies.Select(p => p.Limits.MaxQueryTimeSeconds)),
            MaxObjectSizeBytes = MinNullable(policies.Select(p => p.Limits.MaxObjectSizeBytes)),

            // Similarity score: maximum (most restrictive)
            MinSimilarityScore = MaxNullable(policies.Select(p => p.Limits.MinSimilarityScore))
        };

        return result;
    }

    /// <summary>
    /// Merges masked field rules across policies, keeping the most restrictive
    /// mask type for each field.
    /// </summary>
    private static List<MaskedFieldRule> MergeMaskedFields(
        IReadOnlyList<PolicyDefinition> policies)
    {
        return policies
            .SelectMany(p => p.ObjectRules.FieldRules?.MaskedFields ?? [])
            .GroupBy(rule => rule.Field, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.MaxBy(r => r.MaskType)!)
            .ToList();
    }

    /// <summary>
    /// Computes the intersection of nullable lists. Lists that are null are
    /// treated as "unrestricted" and do not participate in the intersection.
    /// If no lists define the field, returns null (unrestricted).
    /// </summary>
    private static List<string>? IntersectNullable(IEnumerable<List<string>?> sets)
    {
        List<string>? result = null;

        foreach (var set in sets)
        {
            if (set is null)
            {
                continue; // No restriction from this policy
            }

            result = result is null
                ? new List<string>(set)
                : result.Intersect(set, StringComparer.OrdinalIgnoreCase).ToList();
        }

        return result;
    }

    /// <summary>
    /// Returns the minimum non-null value, or null if all values are null.
    /// </summary>
    private static int? MinNullable(IEnumerable<int?> values)
    {
        var nonNull = values.Where(v => v.HasValue).Select(v => v!.Value).ToList();
        return nonNull.Count > 0 ? nonNull.Min() : null;
    }

    private static long? MinNullable(IEnumerable<long?> values)
    {
        var nonNull = values.Where(v => v.HasValue).Select(v => v!.Value).ToList();
        return nonNull.Count > 0 ? nonNull.Min() : null;
    }

    /// <summary>
    /// Returns the maximum non-null value, or null if all values are null.
    /// </summary>
    private static double? MaxNullable(IEnumerable<double?> values)
    {
        var nonNull = values.Where(v => v.HasValue).Select(v => v!.Value).ToList();
        return nonNull.Count > 0 ? nonNull.Max() : null;
    }
}
```

**Handling omitted fields:** When a policy omits an optional field (e.g., `AllowedObjects` is not specified), treat it as "no restriction from this policy" for intersection operations. Only policies that explicitly define a field participate in the intersection. If no policies define the field, the effective value is "unrestricted" (represented as `null` in the `IntersectNullable` method above).

## Step 3: Build and Sign the Security Context

The Security Context packages the effective policies and transports them to the tool execution environment.

```csharp
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

// ── Security Context Models ──────────────────────────────────────────

public sealed class SecurityContext
{
    public required string UserId { get; init; }
    public Guid TenantId { get; init; }
    public DateTimeOffset IssuedAt { get; init; }
    public DateTimeOffset ExpiresAt { get; init; }
    public List<EffectivePolicy> Policies { get; init; } = [];

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IntegrityBlock? Integrity { get; set; }
}

public sealed class IntegrityBlock
{
    public string Algorithm { get; init; } = "hmac-sha256";
    public required string Signature { get; init; }
}

// ── Security Context Builder ─────────────────────────────────────────

public interface ISecurityContextBuilder
{
    Task<SecurityContext> BuildAsync(
        string userId,
        Guid tenantId,
        IReadOnlyList<AccessibleSource> accessibleSources,
        CancellationToken cancellationToken = default);

    SecurityContext Sign(SecurityContext context, byte[] secretKey);
    string SerializeForTransport(SecurityContext context);
    SecurityContext DeserializeAndValidate(string serialized, byte[] secretKey);
}

public sealed record AccessibleSource(
    Guid ConnectionId,
    string Category,
    string Namespace,
    string Name);

public sealed class SecurityContextBuilder : ISecurityContextBuilder
{
    private static readonly TimeSpan ContextTtl = TimeSpan.FromHours(1);
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly IPolicyResolutionEngine _policyEngine;

    public SecurityContextBuilder(IPolicyResolutionEngine policyEngine)
    {
        _policyEngine = policyEngine;
    }

    public async Task<SecurityContext> BuildAsync(
        string userId,
        Guid tenantId,
        IReadOnlyList<AccessibleSource> accessibleSources,
        CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;
        var expiresAt = now + ContextTtl;

        var policies = new List<EffectivePolicy>();
        foreach (var source in accessibleSources)
        {
            var effectivePolicy = await _policyEngine.ResolveEffectivePolicyAsync(
                userId, tenantId, source.ConnectionId,
                source.Category, source.Namespace, source.Name,
                cancellationToken);

            effectivePolicy.SourceConnectionId = source.ConnectionId;
            effectivePolicy.ResolvedAt = now;
            effectivePolicy.ExpiresAt = expiresAt;
            policies.Add(effectivePolicy);
        }

        return new SecurityContext
        {
            UserId = userId,
            TenantId = tenantId,
            IssuedAt = now,
            ExpiresAt = expiresAt,
            Policies = policies
        };
    }

    public SecurityContext Sign(SecurityContext context, byte[] secretKey)
    {
        // Serialize everything except the integrity block
        var payload = SerializePayload(context);
        var signature = ComputeHmac(payload, secretKey);

        context.Integrity = new IntegrityBlock
        {
            Algorithm = "hmac-sha256",
            Signature = Convert.ToBase64String(signature)
        };

        return context;
    }

    public string SerializeForTransport(SecurityContext context)
    {
        var json = JsonSerializer.Serialize(context, SerializerOptions);
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(json));
    }

    public SecurityContext DeserializeAndValidate(string serialized, byte[] secretKey)
    {
        var json = Encoding.UTF8.GetString(Convert.FromBase64String(serialized));
        var context = JsonSerializer.Deserialize<SecurityContext>(json, SerializerOptions)
            ?? throw new InvalidOperationException("Failed to deserialize security context.");

        // Validate expiry
        if (context.ExpiresAt < DateTimeOffset.UtcNow)
        {
            throw new SecurityException("Security context has expired.");
        }

        // Validate signature
        if (context.Integrity is null)
        {
            throw new SecurityException("Security context has no integrity block.");
        }

        var payload = SerializePayload(context);
        var expectedSignature = ComputeHmac(payload, secretKey);
        var actualSignature = Convert.FromBase64String(context.Integrity.Signature);

        if (!CryptographicOperations.FixedTimeEquals(expectedSignature, actualSignature))
        {
            throw new SecurityException("Security context signature is invalid.");
        }

        return context;
    }

    /// <summary>
    /// Serializes the context excluding the Integrity block for signing.
    /// </summary>
    private static byte[] SerializePayload(SecurityContext context)
    {
        var savedIntegrity = context.Integrity;
        context.Integrity = null;

        var json = JsonSerializer.Serialize(context, SerializerOptions);

        context.Integrity = savedIntegrity;

        return Encoding.UTF8.GetBytes(json);
    }

    private static byte[] ComputeHmac(byte[] payload, byte[] secretKey)
    {
        using var hmac = new HMACSHA256(secretKey);
        return hmac.ComputeHash(payload);
    }
}
```

**Context TTL guidance:** Keep the TTL short (15 minutes to 1 hour). Shorter TTLs reduce the replay window but require more frequent policy resolution. For same-process execution, the context can be passed in memory without serialization.

## Step 4: Implement Secure Tool Wrappers

Each Secure Tool Wrapper wraps a data source and enforces the effective policy. Here is a C# template:

```csharp
// ── Data Source Abstraction ──────────────────────────────────────────

public interface IDataSource
{
    Task<IReadOnlyList<Dictionary<string, object?>>> ExecuteQueryAsync(
        string query,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<string>> ListObjectsAsync(
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<string>> DescribeObjectAsync(
        string objectName,
        CancellationToken cancellationToken = default);
}

// ── Query Utilities (abstract; concrete per source type) ─────────────

public interface IQueryRewriter
{
    IReadOnlyList<string> ExtractObjects(string query);
    IReadOnlyList<string> ExtractFields(string query);
    string InjectWhereClause(string query, RowFilter filter);
    string ApplyLimit(string query, int limit);
}

// ── Secure Tool Wrapper ──────────────────────────────────────────────

public interface ISecureToolWrapper
{
    void SetSecurityContext(
        string userId, Guid tenantId, Guid sourceConnectionId,
        EffectivePolicy effectivePolicy);

    Task<IReadOnlyList<Dictionary<string, object?>>> ExecuteQueryAsync(
        string query, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<string>> ListAccessibleObjectsAsync(
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<string>> DescribeObjectAsync(
        string objectName, CancellationToken cancellationToken = default);
}

public class SecureToolWrapper : ISecureToolWrapper
{
    private readonly IDataSource _dataSource;
    private readonly IQueryRewriter _queryRewriter;

    private string _userId = string.Empty;
    private Guid _tenantId;
    private EffectivePolicy _policy = EffectivePolicy.DenyAll;

    public SecureToolWrapper(IDataSource dataSource, IQueryRewriter queryRewriter)
    {
        _dataSource = dataSource;
        _queryRewriter = queryRewriter;
    }

    public void SetSecurityContext(
        string userId, Guid tenantId, Guid sourceConnectionId,
        EffectivePolicy effectivePolicy)
    {
        _userId = userId;
        _tenantId = tenantId;
        _policy = effectivePolicy;
    }

    public async Task<IReadOnlyList<Dictionary<string, object?>>> ExecuteQueryAsync(
        string query, CancellationToken cancellationToken = default)
    {
        // 1. Check permission
        if (!_policy.CanQuery)
        {
            throw new UnauthorizedAccessException(
                "Access denied: query permission not granted.");
        }

        // 2. Validate requested objects
        var requestedObjects = _queryRewriter.ExtractObjects(query);
        foreach (var obj in requestedObjects)
        {
            if (_policy.HiddenObjects.Contains(obj, StringComparer.OrdinalIgnoreCase))
            {
                throw new UnauthorizedAccessException(
                    $"Access denied: object '{obj}' is not accessible.");
            }

            if (_policy.AllowedObjects is { Count: > 0 } &&
                !_policy.AllowedObjects.Contains(obj, StringComparer.OrdinalIgnoreCase))
            {
                throw new UnauthorizedAccessException(
                    $"Access denied: object '{obj}' is not in allowed set.");
            }
        }

        // 3. Validate requested fields
        var requestedFields = _queryRewriter.ExtractFields(query);
        foreach (var field in requestedFields)
        {
            if (_policy.HiddenFields.Contains(field, StringComparer.OrdinalIgnoreCase))
            {
                throw new UnauthorizedAccessException(
                    $"Access denied: field '{field}' is not accessible.");
            }
        }

        // 4. Rewrite query with row filters
        foreach (var filter in _policy.RowFilters)
        {
            query = _queryRewriter.InjectWhereClause(query, filter);
        }

        // 5. Apply result limit
        if (_policy.MaxResults.HasValue)
        {
            query = _queryRewriter.ApplyLimit(query, _policy.MaxResults.Value);
        }

        // 6. Execute against data source
        var results = await _dataSource.ExecuteQueryAsync(query, cancellationToken);

        // 7. Apply field masking to results
        return ApplyFieldMasking(results);
    }

    public async Task<IReadOnlyList<string>> ListAccessibleObjectsAsync(
        CancellationToken cancellationToken = default)
    {
        var allObjects = await _dataSource.ListObjectsAsync(cancellationToken);

        return allObjects
            .Where(obj => !_policy.HiddenObjects.Contains(obj, StringComparer.OrdinalIgnoreCase))
            .Where(obj => _policy.AllowedObjects is null or { Count: 0 } ||
                          _policy.AllowedObjects.Contains(obj, StringComparer.OrdinalIgnoreCase))
            .ToList();
    }

    public async Task<IReadOnlyList<string>> DescribeObjectAsync(
        string objectName, CancellationToken cancellationToken = default)
    {
        var allFields = await _dataSource.DescribeObjectAsync(objectName, cancellationToken);

        return allFields
            .Where(f => !_policy.HiddenFields.Contains(f, StringComparer.OrdinalIgnoreCase))
            .Where(f => _policy.AllowedFields is null or { Count: 0 } ||
                        _policy.AllowedFields.Contains(f, StringComparer.OrdinalIgnoreCase))
            .ToList();
    }

    private IReadOnlyList<Dictionary<string, object?>> ApplyFieldMasking(
        IReadOnlyList<Dictionary<string, object?>> results)
    {
        if (_policy.MaskedFields.Count == 0)
        {
            return results;
        }

        var maskedResults = new List<Dictionary<string, object?>>(results.Count);

        foreach (var row in results)
        {
            var maskedRow = new Dictionary<string, object?>(row, StringComparer.OrdinalIgnoreCase);

            foreach (var maskRule in _policy.MaskedFields)
            {
                if (maskedRow.TryGetValue(maskRule.Field, out var value) && value is not null)
                {
                    maskedRow[maskRule.Field] = ApplyMask(value, maskRule);
                }
            }

            maskedResults.Add(maskedRow);
        }

        return maskedResults;
    }

    private static object? ApplyMask(object value, MaskedFieldRule rule)
    {
        return rule.MaskType switch
        {
            MaskType.Null => null,
            MaskType.Redact => "[REDACTED]",
            MaskType.Partial => MaskPartial(value.ToString() ?? string.Empty, rule.Pattern),
            MaskType.Hash => ComputeHash(value.ToString() ?? string.Empty),
            MaskType.Full => "***",
            _ => value
        };
    }

    private static string MaskPartial(string value, string? pattern)
    {
        if (string.IsNullOrEmpty(value) || value.Length <= 4)
        {
            return "****";
        }

        // Default partial mask: show last 4 characters
        int visibleChars = pattern is not null && int.TryParse(pattern, out int n) ? n : 4;
        int maskedLength = Math.Max(0, value.Length - visibleChars);
        return new string('*', maskedLength) + value[^Math.Min(visibleChars, value.Length)..];
    }

    private static string ComputeHash(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexStringLower(bytes)[..16]; // Truncated hash for display
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

```csharp
// ── Supporting Abstractions ──────────────────────────────────────────

public sealed record DataSourceConnection(
    Guid ConnectionId,
    string Type,
    string Name,
    string ConnectionString);

public interface IDataSourceRegistry
{
    Task<DataSourceConnection> GetConnectionAsync(
        Guid connectionId,
        CancellationToken cancellationToken = default);
}

public interface ICredentialResolver
{
    Task<object> ResolveAsync(
        DataSourceConnection connection,
        CancellationToken cancellationToken = default);
}

// ── Secure Tool Factory ──────────────────────────────────────────────

public interface ISecureToolFactory
{
    Task<IReadOnlyList<ISecureToolWrapper>> CreateAllAccessibleToolsAsync(
        SecurityContext securityContext,
        CancellationToken cancellationToken = default);

    Task<ISecureToolWrapper> CreateToolForSourceAsync(
        SecurityContext securityContext,
        Guid sourceConnectionId,
        CancellationToken cancellationToken = default);
}

public sealed class SecureToolFactory : ISecureToolFactory
{
    private readonly IDataSourceRegistry _dataSourceRegistry;
    private readonly ICredentialResolver _credentialResolver;

    public SecureToolFactory(
        IDataSourceRegistry dataSourceRegistry,
        ICredentialResolver credentialResolver)
    {
        _dataSourceRegistry = dataSourceRegistry;
        _credentialResolver = credentialResolver;
    }

    public async Task<IReadOnlyList<ISecureToolWrapper>> CreateAllAccessibleToolsAsync(
        SecurityContext securityContext,
        CancellationToken cancellationToken = default)
    {
        var tools = new List<ISecureToolWrapper>();

        foreach (var policy in securityContext.Policies)
        {
            if (!policy.CanQuery)
            {
                continue; // Skip sources the user cannot query
            }

            var wrapper = await CreateWrapperAsync(
                securityContext, policy, cancellationToken);
            tools.Add(wrapper);
        }

        return tools;
    }

    public async Task<ISecureToolWrapper> CreateToolForSourceAsync(
        SecurityContext securityContext,
        Guid sourceConnectionId,
        CancellationToken cancellationToken = default)
    {
        var policy = securityContext.Policies
            .FirstOrDefault(p => p.SourceConnectionId == sourceConnectionId)
            ?? throw new InvalidOperationException(
                $"No policy found for source: {sourceConnectionId}");

        return await CreateWrapperAsync(securityContext, policy, cancellationToken);
    }

    private async Task<ISecureToolWrapper> CreateWrapperAsync(
        SecurityContext securityContext,
        EffectivePolicy policy,
        CancellationToken cancellationToken)
    {
        var source = await _dataSourceRegistry.GetConnectionAsync(
            policy.SourceConnectionId, cancellationToken);
        var credentials = await _credentialResolver.ResolveAsync(source, cancellationToken);

        var wrapper = CreateWrapperForSourceType(source, credentials);
        wrapper.SetSecurityContext(
            securityContext.UserId,
            securityContext.TenantId,
            policy.SourceConnectionId,
            policy);

        return wrapper;
    }

    private static ISecureToolWrapper CreateWrapperForSourceType(
        DataSourceConnection source,
        object credentials)
    {
        return source.Type.ToLowerInvariant() switch
        {
            "postgresql" or "mysql" or "sqlserver" or "athena"
                or "bigquery" or "redshift" or "oracle" or "mariadb"
                => CreateDatabaseWrapper(source, credentials),

            "rest" or "graphql" or "soap" or "fhir" or "grpc"
                => CreateApiWrapper(source, credentials),

            "bedrock-kb" or "opensearch" or "elasticsearch"
                or "azure-ai-search" or "vertex-ai-search"
                => CreateKnowledgebaseWrapper(source, credentials),

            "s3" or "azure-blob" or "gcs"
                => CreateStorageWrapper(source, credentials),

            _ => throw new NotSupportedException(
                $"Unsupported source type: {source.Type}")
        };
    }

    // These factory methods return concrete wrapper implementations.
    // Each concrete type provides the appropriate IQueryRewriter and
    // IDataSource for its source category.

    private static ISecureToolWrapper CreateDatabaseWrapper(
        DataSourceConnection source, object credentials)
    {
        // Concrete implementation would instantiate the database-specific
        // IDataSource and IQueryRewriter (e.g., SqlQueryRewriter)
        throw new NotImplementedException(
            "Replace with your SecureDatabaseWrapper implementation.");
    }

    private static ISecureToolWrapper CreateApiWrapper(
        DataSourceConnection source, object credentials)
    {
        throw new NotImplementedException(
            "Replace with your SecureApiWrapper implementation.");
    }

    private static ISecureToolWrapper CreateKnowledgebaseWrapper(
        DataSourceConnection source, object credentials)
    {
        throw new NotImplementedException(
            "Replace with your SecureKnowledgebaseWrapper implementation.");
    }

    private static ISecureToolWrapper CreateStorageWrapper(
        DataSourceConnection source, object credentials)
    {
        throw new NotImplementedException(
            "Replace with your SecureStorageWrapper implementation.");
    }
}
```

## Step 6: Wire It Together

Here is the complete flow from request to results:

```csharp
using Microsoft.Extensions.DependencyInjection;

// ── Dependency Injection Registration ────────────────────────────────

public static class TolapServiceExtensions
{
    public static IServiceCollection AddTolap(this IServiceCollection services)
    {
        services.AddScoped<IPolicyStore, PolicyStore>();
        services.AddScoped<IPolicyResolutionEngine, PolicyResolutionEngine>();
        services.AddScoped<ISecurityContextBuilder, SecurityContextBuilder>();
        services.AddScoped<ISecureToolFactory, SecureToolFactory>();
        services.AddScoped<IDataSourceRegistry, DataSourceRegistry>();
        services.AddScoped<ICredentialResolver, CredentialResolver>();
        return services;
    }
}

// ── Request Handler / Orchestration Layer ────────────────────────────

public sealed class AgentOrchestrator
{
    private readonly ISecurityContextBuilder _contextBuilder;
    private readonly ISecureToolFactory _toolFactory;
    private readonly byte[] _signingKey;

    public AgentOrchestrator(
        ISecurityContextBuilder contextBuilder,
        ISecureToolFactory toolFactory,
        byte[] signingKey)
    {
        _contextBuilder = contextBuilder;
        _toolFactory = toolFactory;
        _signingKey = signingKey;
    }

    public async Task<object> HandleAgentRequestAsync(
        string authenticatedUserId,
        Guid tenantId,
        IReadOnlyList<AccessibleSource> accessibleSources,
        string request,
        CancellationToken cancellationToken = default)
    {
        // 1. Resolve policies and build security context
        var context = await _contextBuilder.BuildAsync(
            authenticatedUserId, tenantId, accessibleSources, cancellationToken);
        var signedContext = _contextBuilder.Sign(context, _signingKey);

        // 2. If executing in a different process/service, serialize for transport
        // string serialized = _contextBuilder.SerializeForTransport(signedContext);
        // ... send via queue, header, or RPC ...
        // var signedContext = _contextBuilder.DeserializeAndValidate(serialized, _signingKey);

        // 3. Create secure tools
        var tools = await _toolFactory.CreateAllAccessibleToolsAsync(
            signedContext, cancellationToken);

        // 4. Give tools to the agent runtime
        var agent = CreateAgent(tools);
        var result = await agent.ExecuteAsync(request, cancellationToken);

        return result;
    }

    private static IAgent CreateAgent(IReadOnlyList<ISecureToolWrapper> tools)
    {
        // Plug into your agent framework (Strands SDK, Semantic Kernel, etc.)
        throw new NotImplementedException(
            "Replace with your agent runtime initialization.");
    }
}

// Placeholder for the agent abstraction
public interface IAgent
{
    Task<object> ExecuteAsync(string request, CancellationToken cancellationToken = default);
}
```

The agent receives tools that can only return data the user is authorized to see. The agent does not need to know about security policies, check permissions, or filter results. Enforcement is invisible and non-bypassable.

## Testing Recommendations

### Unit Tests for Policy Resolution

Test the merge algorithm with multiple overlapping policies:

- Two policies with overlapping `AllowedFields` -- verify intersection
- One policy hides a field, another allows it -- verify hidden wins
- Two policies with different `MaxResults` -- verify minimum wins
- One policy sets `CanQuery = false` -- verify AND produces false
- Policy with row filters from multiple profiles -- verify all filters are present

### Integration Tests for Tool Wrappers

Test enforcement at the tool level:

- Query referencing a hidden column -- verify rejection
- Query without row filters -- verify filters are injected
- Result with masked fields -- verify masking is applied
- Schema introspection -- verify hidden objects/fields are absent
- Expired security context -- verify rejection

### End-to-End Tests

Test the full flow from user identity to filtered results:

- User with restrictive policy queries a data source -- verify only authorized data returned
- User with no applicable policies -- verify access denied
- User with expired assignment -- verify access denied
- User with multiple overlapping assignments -- verify most-restrictive merge
