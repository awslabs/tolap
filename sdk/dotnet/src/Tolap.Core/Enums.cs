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
/// <remarks>
/// Every operator is supported by both enforcement paths: the post-fetch pass in
/// <see cref="EnforcementEngine.ApplyRowFilters"/> and the pre-execution SQL push-down in
/// <see cref="SqlQueryRewriter"/>, except <see cref="Matches"/> whose regex dialect is not
/// portable across engines (see <see cref="SqlQueryRewriter.UnpushableFilters"/>). New
/// members are appended so existing ordinal values are unchanged; the wire form is the
/// camelCase string emitted by <see cref="FilterOperatorJsonConverter"/>, never the ordinal.
/// </remarks>
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
    Matches,

    /// <summary>Field value is ordered at or after the comparison value.</summary>
    GreaterThanOrEqual,

    /// <summary>Field value is ordered at or before the comparison value.</summary>
    LessThanOrEqual,

    /// <summary>
    /// Field value matches a SQL <c>LIKE</c> pattern, where <c>%</c> matches any run of
    /// characters and <c>_</c> matches exactly one. Case-sensitive, and <c>\</c> escapes
    /// a literal <c>%</c>, <c>_</c>, or <c>\</c>.
    /// </summary>
    Like,

    /// <summary>Negation of <see cref="Like"/>.</summary>
    NotLike,

    /// <summary>
    /// Field is present on the row and its value is null. A row missing the field
    /// entirely is dropped, per the fail-closed rule in spec section 7.
    /// </summary>
    IsNull,

    /// <summary>Field is present on the row and its value is not null.</summary>
    IsNotNull,

    /// <summary>
    /// Field value falls within an inclusive range given as the first two entries of
    /// <see cref="RowFilter.Values"/>.
    /// </summary>
    Between
}

/// <summary>
/// The kinds of write a policy governs (connector-spec.md section 4.1).
/// </summary>
/// <remarks>
/// <see cref="Insert"/>, <see cref="Update"/> and <see cref="Delete"/> map one-to-one
/// onto <c>canInsert</c>, <c>canUpdate</c> and <c>canDelete</c>. <see cref="Upsert"/> is
/// for a call that cannot be classified as either a create or an overwrite — an
/// unconditional object-store <c>PUT</c>, for example — and requires <b>both</b>
/// <c>canInsert</c> and <c>canUpdate</c>, the safe intersection connector-spec.md
/// section 8 mandates.
/// </remarks>
public enum WriteOperation
{
    /// <summary>Creating a new record or object. Governed by <c>canInsert</c>.</summary>
    Insert,

    /// <summary>Modifying an existing record or object. Governed by <c>canUpdate</c>.</summary>
    Update,

    /// <summary>Removing a record or object. Governed by <c>canDelete</c>.</summary>
    Delete,

    /// <summary>
    /// A write that may create or overwrite and cannot tell which. Requires both
    /// <c>canInsert</c> and <c>canUpdate</c>.
    /// </summary>
    Upsert
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
