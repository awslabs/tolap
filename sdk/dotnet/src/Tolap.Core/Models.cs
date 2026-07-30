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
/// <remarks>
/// <para>
/// The three write permissions are <c>bool?</c> rather than <c>bool</c> so that absent
/// stays distinguishable from an explicit <c>false</c>. Both readings deny — the schema
/// default is <c>false</c> (connector-spec.md section 4.1) — but the distinction is
/// load-bearing for <b>signing</b>: <c>null</c> is omitted from the canonical form
/// (canonical-enforcement-spec.md section 1), so a policy that never mentioned a write
/// permission signs to the same bytes here as it does in the Python and TypeScript SDKs,
/// where the fields are simply absent. Declaring them non-nullable would emit
/// <c>"canDelete":false,"canInsert":false,"canUpdate":false</c> into every signed payload
/// and make .NET the only SDK unable to verify a context the others produced.
/// </para>
/// <para>
/// The default is deliberately the opposite of <see cref="CanQuery"/>'s: a policy authored
/// before writes existed must not silently gain them, and an author who omitted a write
/// permission has not asked for write access.
/// </para>
/// </remarks>
public sealed record PolicyPermissions(
    bool CanQuery,
    bool? CanInsert = null,
    bool? CanUpdate = null,
    bool? CanDelete = null,
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
        Permissions: new PolicyPermissions(CanQuery: false, ReadOnly: true));
}

/// <summary>
/// A signed, time-bound container carrying one effective policy for transport to the
/// tool execution environment.
/// </summary>
/// <remarks>
/// <para><see cref="Policies"/> is an array because that is the wire shape the canonical
/// signing projection uses (spec section 2 rule 3), but a context governs exactly
/// <b>one</b> data source. Every enforcement path reads only the first element, so a
/// context carrying two policies would sign both and enforce one — a silent truncation
/// at enforcement time rather than at construction. The constructor therefore refuses
/// more than one policy, matching the Python and TypeScript SDKs, which refuse the same
/// shape. A deployment spanning several sources issues one context per source.</para>
/// </remarks>
public sealed record SecurityContext
{
    public SecurityContext(
        string Version,
        string UserId,
        string TenantId,
        DateTimeOffset IssuedAt,
        DateTimeOffset ExpiresAt,
        EffectivePolicy[] Policies,
        IntegrityBlock? Integrity = null)
    {
        // A null array is left alone deliberately: a context deserialized without a
        // "policies" key must still produce signable bytes rather than throwing here,
        // and the signing projection renders it as an empty array. Carrying *no* policy
        // is safe -- it grants nothing -- whereas carrying two is the ambiguity worth
        // refusing.
        if (Policies is { Length: > 1 })
        {
            throw new ArgumentException(
                $"A SecurityContext carries a single effective policy, got {Policies.Length}; " +
                "build one context per data source.",
                nameof(Policies));
        }

        this.Version = Version;
        this.UserId = UserId;
        this.TenantId = TenantId;
        this.IssuedAt = IssuedAt;
        this.ExpiresAt = ExpiresAt;
        this.Policies = Policies;
        this.Integrity = Integrity;
    }

    public string Version { get; init; }
    public string UserId { get; init; }
    public string TenantId { get; init; }
    public DateTimeOffset IssuedAt { get; init; }
    public DateTimeOffset ExpiresAt { get; init; }
    public EffectivePolicy[] Policies { get; init; }
    public IntegrityBlock? Integrity { get; init; }
}
