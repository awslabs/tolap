using System.Text.RegularExpressions;

namespace Tolap.Core;

/// <summary>
/// The providers a <c>kb</c> filter can be rendered for.
/// </summary>
public enum KbProvider
{
    /// <summary>Amazon Bedrock Knowledge Bases <c>retrievalConfiguration.filter</c>.</summary>
    Bedrock,

    /// <summary>OpenSearch bool query filter clauses.</summary>
    OpenSearch,

    /// <summary>Elasticsearch — same DSL as OpenSearch; kept distinct for intent.</summary>
    Elasticsearch,

    /// <summary>Azure AI Search OData <c>$filter</c>.</summary>
    AzureAiSearch,

    /// <summary>Vertex AI Search / Discovery Engine filter expression.</summary>
    VertexAiSearch,

    /// <summary>pgvector — a SQL <c>WHERE</c> fragment over a metadata column.</summary>
    Pgvector
}

/// <summary>
/// Whether a provider's filter has been exercised against the live service, or written from
/// its published grammar only.
/// </summary>
/// <remarks>
/// Carried into <see cref="RenderedKbFilter"/> so the distinction reaches the integrator
/// rather than living only in a comment.
/// </remarks>
public enum KbFilterConfidence
{
    /// <summary>Exercised against the real service.</summary>
    Verified,

    /// <summary>Written from published filter grammar; not exercised here.</summary>
    FromGrammar
}

/// <summary>
/// A filter rendered for one provider.
/// </summary>
/// <param name="Filter">
/// The provider-native filter: a nested dictionary/list structure for Bedrock and OpenSearch,
/// a string for OData and SQL. Null when nothing could be rendered — retrieve unfiltered and
/// rely on the post pass.
/// </param>
/// <param name="DeniesEverything">
/// True when the policy denies every chunk; the caller MUST skip retrieval.
/// </param>
/// <param name="UnpushedRules">Rules not represented in <paramref name="Filter"/>.</param>
public sealed record RenderedKbFilter(
    KbProvider Provider,
    object? Filter,
    bool DeniesEverything,
    UnpushedRule[] UnpushedRules,
    KbFilterConfidence Confidence);

/// <summary>
/// Provider renderers for <c>kb</c> metadata filters (connector-spec.md section 7).
/// </summary>
/// <remarks>
/// <para>
/// <see cref="KbFilter.Build"/> produces provider-neutral clauses; these render them into each
/// provider's own filter syntax. Splitting the two keeps the semantics in one place: the
/// decision about <i>what</i> is safe to push is made once in <see cref="KbFilter"/>, and a
/// renderer only translates. A renderer that cannot express a clause returns null, which
/// surfaces as an unpushed rule rather than a silently weakened filter.
/// </para>
/// <para>
/// <b>Every renderer here is a pushdown, and the post-retrieval pass remains normative.</b>
/// None can reproduce TOLAP's tag extraction — recursive, case-insensitive, across five key
/// shapes — so a filter matching nothing is expected and harmless. See <see cref="KbFilter"/>
/// for why that direction is the safe one.
/// </para>
/// <para>
/// Only the Bedrock shape is exercised against a real service in the reference implementation;
/// the other five are written from each provider's published filter grammar and are marked
/// <see cref="KbFilterConfidence.FromGrammar"/>, because "looks right" is not the same
/// evidence as "observed to filter".
/// </para>
/// <para>Mirrors <c>kb-providers.ts</c> and <c>kb_providers.py</c>.</para>
/// </remarks>
public static class KbProviders
{
    private static readonly Regex Identifier = new(
        "^[A-Za-z_][A-Za-z0-9_]*$", RegexOptions.Compiled);

    private static KbFilterConfidence ConfidenceFor(KbProvider provider) => provider switch
    {
        KbProvider.Bedrock => KbFilterConfidence.Verified,
        _ => KbFilterConfidence.FromGrammar
    };

    /// <summary>
    /// Render a provider-neutral filter for one provider.
    /// </summary>
    /// <remarks>
    /// A rule this provider cannot express is added to
    /// <see cref="RenderedKbFilter.UnpushedRules"/> rather than approximated, so the returned
    /// filter is never broader than the policy.
    /// </remarks>
    public static RenderedKbFilter Render(
        KbFilterResult result,
        KbProvider provider,
        string pgvectorColumn = "metadata")
    {
        // Deny-all short-circuits: there is nothing to render, and the caller must skip
        // retrieval rather than read an absent filter as "unrestricted".
        if (result.DeniesEverything)
        {
            return new RenderedKbFilter(
                provider, null, true, result.UnpushedRules, ConfidenceFor(provider));
        }

        var filter = provider switch
        {
            KbProvider.Bedrock => RenderBedrock(result.Clauses),
            KbProvider.OpenSearch or KbProvider.Elasticsearch => RenderOpenSearch(result.Clauses),
            KbProvider.AzureAiSearch => RenderAzure(result.Clauses),
            KbProvider.VertexAiSearch => RenderVertex(result.Clauses),
            _ => RenderPgvector(result.Clauses, pgvectorColumn)
        };

        // A renderer that refused the clauses reports every rule it was given as unpushed: the
        // provider will return chunks the post pass has to discard, and saying so is the
        // difference between a missed optimization and a false sense of enforcement.
        var unpushed = filter is null && result.Clauses.Length > 0
            ? result.UnpushedRules
                .Append(new UnpushedRule(
                    "deniedTags",
                    $"{provider} cannot express these tag values; left to the post pass"))
                .ToArray()
            : result.UnpushedRules;

        return new RenderedKbFilter(provider, filter, false, unpushed, ConfidenceFor(provider));
    }

    /// <summary>
    /// Bedrock: <c>{"in": {"key", "value"}}</c> / <c>{"notIn": ...}</c>, combined with
    /// <c>andAll</c>.
    /// </summary>
    /// <remarks>
    /// A single clause is emitted bare rather than wrapped in a one-element <c>andAll</c>,
    /// because Bedrock rejects an <c>andAll</c> with fewer than two members.
    /// </remarks>
    private static object? RenderBedrock(KbFilterClause[] clauses)
    {
        if (clauses.Length == 0)
            return null;

        var rendered = clauses
            .Select(clause => (object)new Dictionary<string, object>
            {
                [clause.Op == KbFilterOp.In ? "in" : "notIn"] = new Dictionary<string, object>
                {
                    ["key"] = clause.Key,
                    ["value"] = clause.Values
                }
            })
            .ToList();

        return rendered.Count == 1
            ? rendered[0]
            : new Dictionary<string, object> { ["andAll"] = rendered };
    }

    /// <summary>
    /// A <c>bool</c> query: <c>terms</c> under <c>filter</c> for a positive match, under
    /// <c>must_not</c> for a negated one. <c>filter</c> rather than <c>must</c> because scoring
    /// is irrelevant to an access decision.
    /// </summary>
    /// <remarks>
    /// Note <c>.keyword</c>: a <c>text</c>-mapped field is analyzed, and <c>terms</c> against
    /// an analyzed field matches unpredictably. The suffix assumes the conventional keyword
    /// sub-field. If a deployment maps its metadata differently the filter matches nothing —
    /// the usual harmless miss.
    /// </remarks>
    private static object? RenderOpenSearch(KbFilterClause[] clauses)
    {
        if (clauses.Length == 0)
            return null;

        var positive = new List<object>();
        var negative = new List<object>();

        foreach (var clause in clauses)
        {
            var terms = new Dictionary<string, object>
            {
                ["terms"] = new Dictionary<string, object> { [$"{clause.Key}.keyword"] = clause.Values }
            };
            (clause.Op == KbFilterOp.In ? positive : negative).Add(terms);
        }

        var boolQuery = new Dictionary<string, object>();
        if (positive.Count > 0) boolQuery["filter"] = positive;
        if (negative.Count > 0) boolQuery["must_not"] = negative;
        return new Dictionary<string, object> { ["bool"] = boolQuery };
    }

    private static string ODataLiteral(string value) => "'" + value.Replace("'", "''") + "'";

    /// <summary>
    /// OData <c>$filter</c> over a collection: <c>tags/any(t: search.in(t, '...'))</c>.
    /// </summary>
    /// <remarks>
    /// <c>search.in</c> takes a comma-delimited list, so a tag containing a comma would corrupt
    /// the predicate. Rather than emit something that silently matches the wrong set, such a
    /// clause is refused — null here becomes an unpushed rule.
    /// </remarks>
    private static object? RenderAzure(KbFilterClause[] clauses)
    {
        if (clauses.Length == 0)
            return null;

        var parts = new List<string>();
        foreach (var clause in clauses)
        {
            if (clause.Values.Any(v => v.Contains(',', StringComparison.Ordinal)))
                return null;

            var any = $"{clause.Key}/any(t: search.in(t, {ODataLiteral(string.Join(",", clause.Values))}))";
            parts.Add(clause.Op == KbFilterOp.In ? any : $"not {any}");
        }

        return string.Join(" and ", parts);
    }

    /// <summary>
    /// Discovery Engine expression: <c>ANY("a", "b")</c> / <c>NOT ANY(...)</c>.
    /// </summary>
    /// <remarks>
    /// A double quote inside a value would break the expression and the grammar offers no
    /// escape, so such a clause is refused rather than mangled.
    /// </remarks>
    private static object? RenderVertex(KbFilterClause[] clauses)
    {
        if (clauses.Length == 0)
            return null;

        var parts = new List<string>();
        foreach (var clause in clauses)
        {
            if (clause.Values.Any(v => v.Contains('"', StringComparison.Ordinal)))
                return null;

            var values = string.Join(", ", clause.Values.Select(v => $"\"{v}\""));
            var any = $"{clause.Key}: ANY({values})";
            parts.Add(clause.Op == KbFilterOp.In ? any : $"NOT {any}");
        }

        return string.Join(" AND ", parts);
    }

    private static string SqlLiteral(string value) => "'" + value.Replace("'", "''") + "'";

    /// <summary>
    /// A <c>WHERE</c> fragment over a <c>jsonb</c> metadata column, using containment:
    /// <c>metadata-&gt;'tags' ?| array[...]</c>.
    /// </summary>
    /// <remarks>
    /// Rendered with literals rather than placeholders because the caller appends this to a
    /// query it owns; every value is a tag from a <b>signed</b> policy and is quote-escaped
    /// here, so it cannot introduce SQL the policy author did not write. Identifiers are
    /// validated rather than escaped, since a metadata key is deployment configuration and an
    /// unexpected one should be refused, not quoted into existence.
    /// </remarks>
    private static object? RenderPgvector(KbFilterClause[] clauses, string column)
    {
        if (clauses.Length == 0)
            return null;

        var parts = new List<string>();
        foreach (var clause in clauses)
        {
            if (!Identifier.IsMatch(clause.Key))
                return null;

            var array = "array[" + string.Join(", ", clause.Values.Select(SqlLiteral)) + "]";
            var contains = $"{column}->'{clause.Key}' ?| {array}";
            // NOT (...) alone would also drop a row whose key is absent, because the operator
            // yields NULL there and NOT NULL is not true — that would discard untagged chunks
            // the policy permits. The IS NULL arm restores them.
            parts.Add(clause.Op == KbFilterOp.In
                ? contains
                : $"(NOT ({contains}) OR {column}->'{clause.Key}' IS NULL)");
        }

        return string.Join(" AND ", parts);
    }
}
