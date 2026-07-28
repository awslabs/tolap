namespace Tolap.Core;

/// <summary>
/// Parameters controlling how field masking is applied.
/// </summary>
public sealed record MaskingParameters(
    int? ShowFirst = null,
    int? ShowLast = null,
    char MaskChar = '*',
    string? Algorithm = null);

/// <summary>
/// Defines how a specific field's value is masked before being returned.
/// </summary>
public sealed record MaskingRule(
    string Field,
    MaskType MaskType,
    MaskingParameters? Parameters = null);

/// <summary>
/// A filter condition applied to data before it is returned.
/// </summary>
public sealed record RowFilter(
    string Field,
    FilterOperator Operator,
    object? Value = null,
    object[]? Values = null);

/// <summary>
/// Rules governing access to fields within objects.
/// </summary>
public sealed record FieldRules(
    string[]? AllowedFields = null,
    string[]? HiddenFields = null,
    MaskingRule[]? MaskedFields = null,
    string[]? ReadOnlyFields = null);

/// <summary>
/// Tag-based access control for knowledge bases and document stores.
/// </summary>
public sealed record TagRules(
    string[]? AllowedTags = null,
    string[]? DeniedTags = null);

/// <summary>
/// Endpoint-based access control for API sources.
/// </summary>
public sealed record EndpointRules(
    string[]? AllowedEndpoints = null,
    string[]? HiddenEndpoints = null,
    string[]? AllowedMethods = null);

/// <summary>
/// Operational limits applied to queries and results.
/// </summary>
public sealed record PolicyLimits(
    int? MaxResults = null,
    int? MaxQueryTimeSeconds = null,
    double? MinSimilarityScore = null,
    long? MaxObjectSizeBytes = null);

/// <summary>
/// Rules governing access to data objects (tables, endpoints, knowledge bases, storage prefixes).
/// </summary>
public sealed record ObjectRules(
    string[]? AllowedObjects = null,
    string[]? HiddenObjects = null,
    FieldRules? FieldRules = null,
    RowFilter[]? RowFilters = null,
    TagRules? TagRules = null,
    EndpointRules? EndpointRules = null);

/// <summary>
/// Top-level permission flags for a policy.
/// </summary>
public sealed record PolicyPermissions(
    bool CanQuery,
    bool CanExport = false,
    bool ReadOnly = true);

/// <summary>
/// Defines a reusable security policy for Tool-Object Level Access Protocol.
/// </summary>
public sealed record PolicyDefinition(
    string Version,
    string Name,
    PolicyPermissions Permissions,
    string? Description = null,
    int Priority = 100,
    bool AppliesToAll = false,
    string[]? SourcePatterns = null,
    ObjectRules? ObjectRules = null,
    PolicyLimits? Limits = null);

/// <summary>
/// The entity receiving a policy assignment.
/// </summary>
public sealed record Assignee(
    AssigneeType Type,
    string Identifier);

/// <summary>
/// Narrows where a policy assignment applies.
/// </summary>
public sealed record AssignmentScope(
    string? TenantId = null,
    string? SourceConnectionId = null);

/// <summary>
/// Audit trail for a policy assignment.
/// </summary>
public sealed record AuditInfo(
    string GrantedBy,
    DateTimeOffset GrantedAt,
    string Reason);

/// <summary>
/// Links a policy definition to a user, group, role, or service account.
/// </summary>
public sealed record PolicyAssignment(
    string Version,
    string PolicyName,
    Assignee Assignee,
    AssignmentScope Scope,
    bool Active,
    AuditInfo Audit,
    DateTimeOffset? ExpiresAt = null);

/// <summary>
/// Cryptographic integrity verification block.
/// </summary>
public sealed record IntegrityBlock(
    SigningAlgorithm Algorithm,
    string Signature);

/// <summary>
/// The merged result of all applicable TOLAP policies for a specific user and data source.
/// </summary>
public sealed record EffectivePolicy(
    string Version,
    string? UserId,
    string? TenantId,
    string? SourceConnectionId,
    DateTimeOffset? ResolvedAt,
    DateTimeOffset? ExpiresAt,
    string[] SourceProfiles,
    PolicyPermissions Permissions,
    ObjectRules? ObjectRules = null,
    PolicyLimits? Limits = null,
    IntegrityBlock? Integrity = null)
{
    /// <summary>
    /// Creates a deny-all effective policy with no permissions.
    /// </summary>
    public static EffectivePolicy DenyAll() => new(
        Version: "1.0",
        UserId: null,
        TenantId: null,
        SourceConnectionId: null,
        ResolvedAt: null,
        ExpiresAt: null,
        SourceProfiles: Array.Empty<string>(),
        Permissions: new PolicyPermissions(CanQuery: false, CanExport: false, ReadOnly: true));
}

/// <summary>
/// A signed, time-bound container holding effective policies for transport to the tool execution environment.
/// </summary>
public sealed record SecurityContext(
    string Version,
    string UserId,
    string TenantId,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    EffectivePolicy[] Policies,
    IntegrityBlock? Integrity = null);
