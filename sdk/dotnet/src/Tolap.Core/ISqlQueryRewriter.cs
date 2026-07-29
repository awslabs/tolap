namespace Tolap.Core;

/// <summary>
/// Rewrites a SQL query so that a TOLAP policy's field and row restrictions are enforced by
/// the database rather than after the rows have been fetched.
/// </summary>
/// <remarks>
/// <para>
/// This is a <b>resource optimization, not a replacement for enforcement.</b> The
/// post-execution pipeline in <see cref="EnforcementEngine.ApplyRecordPipeline"/> remains
/// mandatory and remains the normative enforcement point (canonical-enforcement-spec.md
/// section 4). Rewriting narrows what the database produces so a filtered-out row is never
/// transferred or materialized (threat-model D2); it does not and cannot replace the
/// post-fetch pass, because:
/// </para>
/// <list type="bullet">
///   <item><description>
///     Not every filter is expressible in portable SQL. <see cref="FilterOperator.Matches"/>
///     has no cross-engine regex form, and any string carrying a backslash is refused to
///     avoid dialect-dependent literal escaping. Such filters are reported by
///     <see cref="UnpushableFilters"/> and are enforced only post-fetch.
///   </description></item>
///   <item><description>
///     Masking has no SQL form here at all. Masked fields are deliberately <b>kept</b> in the
///     rewritten SELECT so the post-fetch pass can still mask them.
///   </description></item>
///   <item><description>
///     A rewritten <c>SELECT *</c> cannot be expanded without an <c>allowedFields</c> list,
///     so hidden fields can still arrive from the database and must still be stripped.
///   </description></item>
/// </list>
/// <para>
/// The rewriter is therefore designed to fail <i>safe</i> rather than fail closed: when a
/// construct cannot be handled it leaves that part of the query alone and lets the
/// post-fetch pass do the work. It never emits a query that is <i>less</i> restrictive than
/// the one it was given.
/// </para>
/// </remarks>
public interface ISqlQueryRewriter
{
    /// <summary>
    /// Rewrites a SQL query to push a policy's restrictions into the database.
    /// </summary>
    /// <remarks>
    /// Applies, in order: <c>SELECT *</c> expansion to allowed-minus-hidden fields;
    /// removal of hidden and non-allowed fields from an explicit SELECT list;
    /// injection of row filters as <c>WHERE</c> conditions; and clamping of
    /// <c>LIMIT</c> to <c>min(existing, maxResults)</c>. Masked fields are preserved.
    /// </remarks>
    /// <param name="originalQuery">The query to rewrite. Null, empty, or whitespace is returned unchanged.</param>
    /// <param name="policy">The effective policy to push down.</param>
    /// <param name="dialect">
    /// The engine the text is destined for (connector-spec.md section 5.1) — the integrator's
    /// to supply, since only they know which connection this is for. Null selects the
    /// rewriter's own dialect, or <see cref="SqlDialect.Ansi"/> if it has none. An
    /// <b>unrecognized</b> dialect returns the query untouched rather than guessing a profile,
    /// and reports every filter through <see cref="UnpushableFilters"/>.
    /// </param>
    /// <returns>The rewritten query.</returns>
    string RewriteQuery(string originalQuery, EffectivePolicy policy, SqlDialect? dialect = null);

    /// <summary>
    /// Reports whether a query references only fields the policy permits.
    /// </summary>
    /// <remarks>
    /// A pre-execution check intended to reject a query outright rather than silently
    /// narrow it, so an agent learns its query was refused. Returns false for a null or
    /// blank query, for any reference to a hidden field, and — when <c>allowedFields</c> is
    /// specified — for any reference outside it. Because field extraction is regular-expression
    /// based, a false result is authoritative but a true result is not a guarantee: the
    /// post-fetch pass, not this method, is what makes hidden fields unreachable.
    /// </remarks>
    bool ValidateQuery(string query, EffectivePolicy policy);

    /// <summary>
    /// Extracts the primary table name from a query's <c>FROM</c> clause.
    /// </summary>
    /// <remarks>
    /// Handles bare (<c>patients</c>), qualified (<c>public.patients</c>), and quoted
    /// (<c>"schema"."table"</c>) forms, returning the unqualified table name so it can be
    /// passed to <see cref="EnforcementEngine.ValidateAccess"/>. Returns null when the
    /// query has no <c>FROM</c> clause.
    /// </remarks>
    string? ExtractTableName(string query);

    /// <summary>
    /// Builds a <c>WHERE</c> clause body (without the <c>WHERE</c> keyword) from row filters.
    /// </summary>
    /// <remarks>
    /// Conditions are combined with <c>AND</c>, matching the most-restrictive-wins semantics
    /// of the post-fetch pass. Filters that cannot be expressed are omitted; use
    /// <see cref="UnpushableFilters"/> to enumerate them. Returns the empty string when no
    /// filter can be expressed — including for an unrecognized <paramref name="dialect"/>,
    /// which declines every filter.
    /// </remarks>
    /// <param name="filters">The row filters to render.</param>
    /// <param name="dialect">
    /// The engine to emit for. Null selects the rewriter's own dialect, or
    /// <see cref="SqlDialect.Ansi"/>.
    /// </param>
    string BuildWhereClause(IEnumerable<RowFilter> filters, SqlDialect? dialect = null);

    /// <summary>
    /// The filters in a policy that cannot be pushed into SQL and are therefore enforced
    /// only by the post-fetch pass.
    /// </summary>
    /// <remarks>
    /// Exposed so an integrator can assert this is empty for a policy whose filtering must
    /// happen entirely in the database — a non-empty result means the query will return
    /// rows that <see cref="EnforcementEngine.ApplyRecordPipeline"/> still has to discard.
    /// An unrecognized <paramref name="dialect"/> reports <b>every</b> filter, since nothing is
    /// rewritten at all in that case (connector-spec.md section 5.1 rule 2).
    /// </remarks>
    /// <param name="policy">The effective policy whose filters to classify.</param>
    /// <param name="dialect">
    /// The engine to classify against. Null selects the rewriter's own dialect, or
    /// <see cref="SqlDialect.Ansi"/>.
    /// </param>
    IReadOnlyList<RowFilter> UnpushableFilters(EffectivePolicy policy, SqlDialect? dialect = null);
}
