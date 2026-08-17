namespace Tolap.Core;

/// <summary>
/// Where a database policy is applied: in the query, or only in the results.
/// </summary>
/// <remarks>
/// <para>
/// Both modes enforce the same policy and <b>return the same rows</b>. The difference is how
/// much data the database is asked to produce, which is a resource decision rather than an
/// access-control one. That equality is the whole safety argument for exposing the choice, and
/// it is asserted against live PostgreSQL and MySQL rather than inferred.
/// </para>
/// <para>
/// Deliberately two values, not three. A "rewrite only" mode that skipped the post-execution
/// pass would be unsafe and is not offered, because two things have no SQL form at all:
/// </para>
/// <list type="bullet">
///   <item><b>Masking.</b> No <c>SELECT</c> returns <c>[REDACTED]</c> or a salted hash, so a
///   masked SSN would come back in clear text.</item>
///   <item><b><c>contains</c>, <c>startsWith</c>, <c>matches</c>.</b> Not portably
///   expressible, so the rewriter declines to push them and reports them in
///   <see cref="SqlQueryPreparation.UnpushableFilters"/>. The post pass enforces them.</item>
/// </list>
/// <para>
/// An enum with no name for the unsafe option cannot select it by accident.
/// </para>
/// </remarks>
public enum SqlEnforcementMode
{
    /// <summary>
    /// Push row filters into <c>WHERE</c>, the result limit into <c>LIMIT</c>, and hidden
    /// columns out of the <c>SELECT</c>, then enforce on the results as well. The default.
    /// </summary>
    /// <remarks>
    /// The database returns less data, which is the point — without it a large result set is
    /// fetched and materialized before being trimmed (threat model D2).
    /// </remarks>
    RewriteAndPost = 0,

    /// <summary>
    /// Leave the query untouched, byte for byte, and enforce entirely on the results.
    /// </summary>
    /// <remarks>
    /// <para>
    /// For integrators who will not have their SQL edited: a statement the rewriter's parser
    /// does not handle, a stored procedure, an ORM that owns its own SQL, or a reviewer who
    /// needs the query that ran to be the query they wrote. The cost is that the database
    /// returns rows and columns the post pass then discards.
    /// </para>
    /// <para>
    /// This skips the <i>rewrite</i>, not the checks. <c>canQuery</c>, <c>allowedObjects</c>
    /// and the refusal of a query naming a hidden field all still apply — declining to rewrite
    /// must never relax a denial.
    /// </para>
    /// </remarks>
    PostOnly = 1,
}

/// <summary>
/// Resolution helpers for <see cref="SqlEnforcementMode"/>.
/// </summary>
public static class SqlEnforcementModes
{
    /// <summary>
    /// What an omitted mode selects.
    /// </summary>
    /// <remarks>
    /// Rewriting is the better default: it is what this SDK has always done, it reduces what
    /// the database produces, and it is safe because the post-execution pass runs identically
    /// either way. Python and TypeScript now agree, which they previously did not.
    /// </remarks>
    public const SqlEnforcementMode Default = SqlEnforcementMode.RewriteAndPost;

    /// <summary>
    /// Resolve a mode, failing closed on an unrecognized one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Null means "omitted" and selects <see cref="Default"/>. An out-of-range value throws
    /// rather than falling back.
    /// </para>
    /// <para>
    /// This is the opposite of <see cref="DialectProfile"/> resolution, deliberately. An
    /// unrecognized <i>dialect</i> declines to rewrite, because there fail-closed means "push
    /// nothing and let the post pass do everything". An unrecognized <i>mode</i> has no such
    /// safe reading: silently choosing <see cref="SqlEnforcementMode.RewriteAndPost"/> would
    /// rewrite SQL for a caller who asked that it not be touched, which is the exact surprise
    /// <see cref="SqlEnforcementMode.PostOnly"/> exists to prevent.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">The value is not a defined member.</exception>
    public static SqlEnforcementMode Resolve(SqlEnforcementMode? mode)
    {
        if (mode is null)
            return Default;

        // A cast from an out-of-range int -- (SqlEnforcementMode)99 -- is legal C#, so an
        // undefined member reaches here and must be refused rather than treated as 0, which
        // is RewriteAndPost.
        if (!Enum.IsDefined(typeof(SqlEnforcementMode), mode.Value))
        {
            throw new ArgumentOutOfRangeException(
                nameof(mode),
                mode.Value,
                "unrecognized SQL enforcement mode; expected RewriteAndPost or PostOnly");
        }

        return mode.Value;
    }
}
