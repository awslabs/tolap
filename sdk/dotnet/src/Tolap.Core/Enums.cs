namespace Tolap.Core;

/// <summary>
/// Type of masking applied to a field value. Integer values represent restrictiveness order
/// (higher = more restrictive).
/// </summary>
public enum MaskType
{
    Null = 1,
    Redact = 2,
    Partial = 3,
    Hash = 4,
    Full = 5
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
