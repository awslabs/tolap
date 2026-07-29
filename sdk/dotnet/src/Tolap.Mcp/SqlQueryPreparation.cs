using Tolap.Core;

namespace Tolap.Mcp;

/// <summary>
/// The outcome of preparing a SQL query for execution under a policy.
/// </summary>
/// <param name="Allowed">
/// Whether the query may be executed at all. When false, <see cref="Query"/> is the caller's
/// original text and must not be executed.
/// </param>
/// <param name="DenialReason">Why the query was refused, or null when it was allowed.</param>
/// <param name="Query">
/// The query to execute: rewritten to carry the policy's field restrictions, row filters, and
/// result limit. Identical to the caller's query when nothing could be pushed down.
/// </param>
/// <param name="Rewritten">Whether <see cref="Query"/> differs from the caller's original.</param>
/// <param name="UnpushableFilters">
/// Row filters that could not be expressed in portable SQL and are therefore enforced only by
/// the post-execution pipeline. Non-empty means the database will return rows that
/// <see cref="EnforcementEngine.ApplyRecordPipeline"/> still has to discard.
/// </param>
public sealed record SqlQueryPreparation(
    bool Allowed,
    string? DenialReason,
    string Query,
    bool Rewritten,
    IReadOnlyList<RowFilter> UnpushableFilters)
{
    /// <summary>
    /// Whether every row filter in the policy reached the database.
    /// </summary>
    /// <remarks>
    /// Useful as an assertion for an integrator whose result sets are large enough that
    /// post-fetch filtering is not an acceptable fallback.
    /// </remarks>
    public bool FullyPushedDown => UnpushableFilters.Count == 0;

    internal static SqlQueryPreparation Denied(string reason, string query)
        => new(false, reason, query, Rewritten: false, Array.Empty<RowFilter>());
}
