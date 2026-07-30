namespace Tolap.Core;

/// <summary>
/// The four connector categories (connector-spec.md section 1).
/// </summary>
/// <remarks>
/// A fixed set; adding one is a breaking change (section 10).
/// </remarks>
public enum SourceCategory
{
    /// <summary>Relational and query-engine sources (section 5).</summary>
    Db,

    /// <summary>HTTP-shaped services (section 6).</summary>
    Api,

    /// <summary>Knowledge bases and vector stores (section 7).</summary>
    Kb,

    /// <summary>Object stores (section 8).</summary>
    Storage
}

/// <summary>
/// The three parts of a source connection identifier.
/// </summary>
public sealed record SourceIdentity(SourceCategory Category, string Namespace, string Name);

/// <summary>
/// Parsing <c>category:namespace:name</c> (connector-spec.md section 1).
/// </summary>
/// <remarks>
/// <para>
/// Every data source is identified by exactly three colon-separated segments. The first is
/// a fixed-set category; the other two are opaque to TOLAP.
/// </para>
/// <para>
/// The category matters beyond documentation: it decides which wrapper enforces a source,
/// and it is read from the <b>signed</b> <c>SourceConnectionId</c> rather than from a
/// separate registry field. That is deliberate — a category taken from unsigned
/// configuration could disagree with the policy the context carries, and an attacker who
/// could flip <c>db</c> to <c>api</c> would pick the wrapper that enforces the
/// <i>other</i> category's rules (<c>endpointRules</c> do not constrain a SQL query).
/// Inside the signed bytes, changing it invalidates the signature.
/// </para>
/// <para>
/// Mirrors <c>source-identity.ts</c> and <c>source_identity.py</c>.
/// </para>
/// </remarks>
public static class SourceIdentityParser
{
    /// <summary>
    /// Parse a <c>category:namespace:name</c> identifier, or return null if it is not one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Returns null rather than throwing so a caller can decide whether an unparseable
    /// identifier is a denial or a configuration error; every caller in this SDK treats it
    /// as a denial.
    /// </para>
    /// <para>
    /// Rejected: a wrong segment count (<c>db:production</c> and <c>db:a:b:c</c> both), an
    /// unknown category, and an empty segment — an empty namespace or name would let
    /// <c>db::</c> match a <c>db:*:*</c> pattern while naming no actual source.
    /// </para>
    /// <para>
    /// The category is compared case-insensitively, matching the case-insensitive
    /// <c>sourcePatterns</c> matching of the canonical spec section 10. The namespace and
    /// name are returned verbatim: they are opaque, and folding their case here would make
    /// this method lie about what the identifier says.
    /// </para>
    /// </remarks>
    public static SourceIdentity? Parse(string? sourceConnectionId)
    {
        if (string.IsNullOrEmpty(sourceConnectionId))
            return null;

        var segments = sourceConnectionId.Split(':');
        if (segments.Length != 3)
            return null;

        foreach (var segment in segments)
        {
            if (segment.Length == 0)
                return null;
        }

        var category = segments[0] switch
        {
            var s when s.Equals("db", StringComparison.OrdinalIgnoreCase) => SourceCategory.Db,
            var s when s.Equals("api", StringComparison.OrdinalIgnoreCase) => SourceCategory.Api,
            var s when s.Equals("kb", StringComparison.OrdinalIgnoreCase) => SourceCategory.Kb,
            var s when s.Equals("storage", StringComparison.OrdinalIgnoreCase) => SourceCategory.Storage,
            _ => (SourceCategory?)null
        };

        if (category is null)
            return null;

        return new SourceIdentity(category.Value, segments[1], segments[2]);
    }

    /// <summary>
    /// The category of a source connection identifier, or null if unparseable.
    /// </summary>
    /// <remarks>
    /// Convenience over <see cref="Parse"/> for the common case: the wrapper a source needs
    /// depends only on its category.
    /// </remarks>
    public static SourceCategory? CategoryOf(string? sourceConnectionId)
        => Parse(sourceConnectionId)?.Category;
}
