namespace Tolap.Core;

/// <summary>
/// Type of masking applied to a field value. Integer values represent restrictiveness order
/// (higher = more restrictive), ranked by how much of the original value is disclosed:
/// <c>partial</c> leaks real characters, <c>hash</c> is irreversible but joinable, <c>full</c>
/// leaks the length, <c>redact</c> leaks nothing, and <c>null</c> leaks not even the field's
/// presence. See canonical-enforcement-spec.md section 6.
/// </summary>
public enum MaskType
{
    Partial = 1,
    Hash = 2,
    Full = 3,
    Redact = 4,
    Null = 5
}

/// <summary>
/// Restrictiveness ranking helpers for <see cref="MaskType"/>.
/// </summary>
public static class MaskTypeExtensions
{
    /// <summary>
    /// Rank of an unrecognized mask type. A typo or a mask type from a newer schema
    /// version must never be beaten by a known-but-weaker type, so it ranks above
    /// every known value.
    /// </summary>
    private const int UnknownRestrictiveness = 6;

    /// <summary>
    /// Ranks a mask type by how little of the value it discloses (higher = stricter).
    /// Anything outside the known set ranks most restrictive so that merging can never
    /// downgrade an unknown mask into a weaker known one.
    /// </summary>
    public static int Restrictiveness(this MaskType maskType) => maskType switch
    {
        MaskType.Partial => 1,
        MaskType.Hash => 2,
        MaskType.Full => 3,
        MaskType.Redact => 4,
        MaskType.Null => 5,
        _ => UnknownRestrictiveness
    };
}

/// <summary>
/// Comparison operator for row filter conditions.
/// </summary>
public enum FilterOperator
{
    Equals,
    NotEquals,
    In,
    NotIn,
    GreaterThan,
    LessThan,
    Contains,
    StartsWith,
    Matches
}

/// <summary>
/// Type of entity receiving a policy assignment.
/// </summary>
public enum AssigneeType
{
    User,
    Group,
    Role,
    ServiceAccount
}

/// <summary>
/// Cryptographic algorithm used for signing security contexts.
/// </summary>
public enum SigningAlgorithm
{
    HmacSha256,
    HmacSha512,
    Ed25519
}
