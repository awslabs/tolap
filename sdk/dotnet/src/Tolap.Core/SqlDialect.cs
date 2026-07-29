namespace Tolap.Core;

/// <summary>
/// The engine a rewritten statement is destined for (connector-spec.md section 5.1).
/// </summary>
/// <remarks>
/// Supplied by the integrator, because the dialect is a property of <i>their</i> connection and
/// only they know it — they already chose <c>Npgsql</c> or <c>MySqlConnector</c>. It is
/// deliberately not derivable from the policy: a signed security artifact must not depend on
/// deployment detail, and <c>sourceConnectionId</c>'s <c>db</c> category does not distinguish
/// engines.
/// </remarks>
public enum SqlDialect
{
    /// <summary>
    /// The strict intersection: double-quoted identifiers, <c>LIMIT n</c>. The default,
    /// chosen when no dialect is named. Not a guess at the engine — the subset most engines
    /// accept.
    /// </summary>
    Ansi = 0,

    /// <summary>PostgreSQL, and the Redshift/Greenplum forks that share its quoting.</summary>
    Postgres = 1,

    /// <summary>Trino, Presto, and Athena.</summary>
    Trino = 2,

    /// <summary>
    /// MySQL and MariaDB. Backtick identifiers, because <c>"region"</c> is a string literal
    /// here unless <c>ANSI_QUOTES</c> is set.
    /// </summary>
    MySql = 3,

    /// <summary>
    /// Microsoft SQL Server and Azure SQL. Bracket identifiers, and <c>TOP n</c> after
    /// <c>SELECT</c> rather than <c>LIMIT n</c> at the end.
    /// </summary>
    SqlServer = 4
}

/// <summary>
/// How a profile spells its row limit.
/// </summary>
/// <remarks>
/// <c>LIMIT n</c> is a suffix; <c>TOP n</c> is an infix that binds to a single <c>SELECT</c>,
/// which is a structural difference rather than a token swap.
/// </remarks>
internal enum RowLimitForm
{
    /// <summary><c>LIMIT n</c>, at the end of the statement.</summary>
    LimitSuffix,

    /// <summary><c>TOP n</c>, immediately after <c>SELECT</c>.</summary>
    TopPrefix
}

/// <summary>
/// The emitted-text rules for one engine.
/// </summary>
/// <remarks>
/// Only <i>text</i> lives here. Which operators are pushable, which values are refused, and
/// every fail-closed rule are profile-independent by design (connector-spec.md section 5.1): a
/// filter unpushable in one profile is unpushable in all of them, so selecting a profile never
/// changes which rows a policy admits.
/// </remarks>
internal sealed record DialectProfile(
    SqlDialect Dialect,
    char QuoteOpen,
    char QuoteClose,
    RowLimitForm RowLimit)
{
    /// <summary>
    /// The characters this profile uses to delimit an identifier.
    /// </summary>
    /// <remarks>
    /// An identifier containing one of them is <i>declined</i> rather than escaped by doubling
    /// (connector-spec.md section 5.1 rule 4). Declining costs an optimization; mis-escaping
    /// emits author-controlled text into a statement.
    /// </remarks>
    public char[] QuoteChars { get; } = QuoteOpen == QuoteClose
        ? [QuoteOpen]
        : [QuoteOpen, QuoteClose];
}

/// <summary>
/// The dialect profile table, and the lookup that declines an unrecognized dialect.
/// </summary>
internal static class DialectProfiles
{
    /// <summary>What an omitted dialect selects.</summary>
    public const SqlDialect Default = SqlDialect.Ansi;

    private static readonly Dictionary<SqlDialect, DialectProfile> Profiles = new()
    {
        [SqlDialect.Ansi] = new(SqlDialect.Ansi, '"', '"', RowLimitForm.LimitSuffix),
        [SqlDialect.Postgres] = new(SqlDialect.Postgres, '"', '"', RowLimitForm.LimitSuffix),
        [SqlDialect.Trino] = new(SqlDialect.Trino, '"', '"', RowLimitForm.LimitSuffix),
        [SqlDialect.MySql] = new(SqlDialect.MySql, '`', '`', RowLimitForm.LimitSuffix),
        [SqlDialect.SqlServer] = new(SqlDialect.SqlServer, '[', ']', RowLimitForm.TopPrefix)
    };

    /// <summary>
    /// The profile for a dialect, or null when it is not recognized.
    /// </summary>
    /// <remarks>
    /// A null <paramref name="dialect"/> means "omitted" and selects <see cref="Default"/>. An
    /// <b>unrecognized</b> dialect returns null <i>without throwing</i>, and every caller
    /// treats that as "do not rewrite at all" (connector-spec.md section 5.1 rule 2). Neither
    /// guessing a profile nor throwing is acceptable: guessing is how the MySQL backtick defect
    /// happened, and throwing would turn a deployment typo into an outage on a path that is
    /// only ever an optimization.
    /// </remarks>
    public static DialectProfile? Resolve(SqlDialect? dialect)
    {
        if (dialect is null)
            return Profiles[Default];

        // A cast from an out-of-range int -- (SqlDialect)99 -- is legal C#, so an
        // unrecognized member reaches this lookup and must decline rather than throw.
        return Profiles.GetValueOrDefault(dialect.Value);
    }
}
