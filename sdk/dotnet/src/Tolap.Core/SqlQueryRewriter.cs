using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Tolap.Core;

/// <summary>
/// Pushes a TOLAP policy's field and row restrictions into a SQL query so the database
/// never produces a row or column the policy excludes.
/// </summary>
/// <remarks>
/// <para>
/// <b>There is no portable SQL, so the dialect is an explicit parameter.</b> An earlier
/// version of this class claimed to target "the ANSI-ish intersection of Postgres, MySQL, and
/// Athena/Trino: double-quoted identifiers". That intersection does not exist. MySQL's default
/// identifier quote is the backtick, and without <c>ANSI_QUOTES</c> it reads
/// <c>"region"</c> as a <i>string literal</i> — so the emitted
/// <c>WHERE "region" = 'us-east'</c> evaluated <c>'region' = 'us-east'</c> and matched no row
/// at all, with no error reported by the engine. Against the six-row integration fixture the
/// policy-filtered query returned 0 rows where backticks return 2.
/// </para>
/// <para>
/// Callers therefore name their engine with <see cref="SqlDialect"/> (connector-spec.md
/// section 5.1). The dialect is <i>never</i> inferred and <i>never</i> read from the policy: a
/// signed security artifact must not depend on deployment detail, and
/// <c>sourceConnectionId</c>'s <c>db</c> category deliberately does not distinguish engines.
/// An omitted dialect selects <see cref="SqlDialect.Ansi"/> — not a guess at the engine, but
/// the subset most engines accept. An <i>unrecognized</i> dialect is not guessed at either:
/// nothing is rewritten and every filter is reported unpushable, because guessing a profile is
/// how the MySQL defect above happened.
/// </para>
/// <para>
/// The emitted <i>text</i> is dialect-specific, and so — for <c>like</c>/<c>notLike</c> alone —
/// is whether the filter is pushed at all: those two are declined unless the profile guarantees
/// a case-sensitive <c>LIKE</c>, because a pushed-down <c>LIKE</c> inherits the column's
/// collation while the post-fetch pass does not (see <see cref="BuildLikeCondition"/>).
/// Everything else — the pushable operators, the fail-closed rules, the post-fetch pipeline —
/// is identical under every profile. Either way, choosing a profile never changes which rows a
/// policy admits, only where the work happens: a declined filter is reported by
/// <see cref="UnpushableFilters"/> and enforced after the fetch.
/// </para>
/// <para>
/// <b>Never a substitute for <see cref="EnforcementEngine.ApplyRecordPipeline"/></b>, which
/// stays mandatory and normative (canonical-enforcement-spec.md section 4). See
/// <see cref="ISqlQueryRewriter"/> for why. Every code path here is designed so that a
/// construct it cannot handle is left untouched: the rewriter narrows a query or leaves it
/// alone, and never widens it.
/// </para>
/// <para>
/// Parsing is regular-expression and depth-scan based, not a full SQL grammar. Keyword
/// matches are restricted to parenthesis depth zero and skip over string literals and quoted
/// identifiers, so a subquery's <c>WHERE</c> or <c>LIMIT</c> is not mistaken for the
/// statement's own. Constructs beyond that — CTEs, set operations, lateral joins — are
/// recognised well enough to be declined, not to be rewritten.
/// </para>
/// </remarks>
public sealed class SqlQueryRewriter : ISqlQueryRewriter
{
    /// <summary>
    /// Optional diagnostic sink, invoked with a human-readable message whenever a rewrite
    /// step declines to act.
    /// </summary>
    /// <remarks>
    /// A plain callback rather than an <c>ILogger</c>: <c>Tolap.Core</c> ships zero runtime
    /// package dependencies, and taking
    /// <c>Microsoft.Extensions.Logging.Abstractions</c> for four diagnostic messages would
    /// end that. Integrators wire this to whatever logger they already have.
    /// </remarks>
    private readonly Action<string>? _diagnostics;

    /// <summary>
    /// The dialect every call defaults to, as given to the constructor.
    /// </summary>
    /// <remarks>
    /// Retained unresolved so an unrecognized value declines at each call site with a
    /// diagnostic, rather than throwing during construction.
    /// </remarks>
    private readonly SqlDialect? _dialect;

    /// <summary>
    /// Constructs a rewriter.
    /// </summary>
    /// <param name="diagnostics">
    /// Optional sink for messages explaining why a rewrite step declined to act. Messages
    /// may embed policy field names and fragments of the query, so route them somewhere with
    /// the same handling as query logs.
    /// </param>
    /// <param name="dialect">
    /// The engine this rewriter emits for (connector-spec.md section 5.1). Null selects
    /// <see cref="SqlDialect.Ansi"/>; an unrecognized value declines to rewrite anything.
    /// Settable per rewriter <i>and</i> per call, so an integrator with one connection can
    /// construct one rewriter and an integrator fanning out across engines can pass it per
    /// query.
    /// </param>
    public SqlQueryRewriter(Action<string>? diagnostics = null, SqlDialect? dialect = null)
    {
        _diagnostics = diagnostics;
        _dialect = dialect;
    }

    /// <summary>
    /// Resolves a per-call dialect against the rewriter's own, or returns null when the result
    /// is unrecognized (in which case nothing is rewritten).
    /// </summary>
    private DialectProfile? ProfileFor(SqlDialect? dialect)
    {
        var requested = dialect ?? _dialect;
        var profile = DialectProfiles.Resolve(requested);
        if (profile is null)
        {
            Diagnose(
                $"unrecognized SQL dialect '{requested}': nothing is pushed down and the "
                + "post-execution pass enforces the policy in full");
        }
        return profile;
    }

    // -- Keyword patterns --
    //
    // Each is matched against the whole query and then filtered to occurrences at
    // parenthesis depth zero and outside string literals, so a subquery cannot supply the
    // match that governs the outer statement.

    private static readonly Regex SelectKeyword = new(
        @"\bSELECT\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex FromKeyword = new(
        @"\bFROM\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex WhereKeyword = new(
        @"\bWHERE\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex LimitClause = new(
        @"\bLIMIT\s+(\d+)", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // -- sqlserver TOP placement --
    //
    // Individually matched keywords, so the shapes in which `TOP n` cannot be placed
    // correctly can be recognised and declined rather than approximated.

    private static readonly Regex LimitKeyword = new(
        @"\bLIMIT\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex OffsetKeyword = new(
        @"\bOFFSET\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex FetchKeyword = new(
        @"\bFETCH\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex UnionKeyword = new(
        @"\bUNION\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex IntersectKeyword = new(
        @"\bINTERSECT\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ExceptKeyword = new(
        @"\bEXCEPT\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>
    /// <c>SELECT DISTINCT</c>/<c>SELECT ALL</c>: <c>TOP</c> goes <i>after</i> the quantifier,
    /// since <c>SELECT DISTINCT TOP 5</c> is a syntax error and <c>SELECT TOP 5 DISTINCT</c>
    /// would count rows before duplicates are removed.
    /// </summary>
    private static readonly Regex SelectQuantifier = new(
        @"\G\s+(?:DISTINCT|ALL)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>
    /// An existing <c>TOP n</c> or <c>TOP (n)</c>, with the modifiers that make it not a plain
    /// row count.
    /// </summary>
    /// <remarks>
    /// <c>PERCENT</c> is a proportion rather than a count and <c>WITH TIES</c> returns more
    /// rows than the number given, so neither can be clamped to a row limit. The count
    /// alternatives are separate branches rather than one <c>\(?\s*(\d+)\s*\)?</c>: a trailing
    /// <c>\s*</c> would swallow the space before <c>PERCENT</c> and hide the modifier, which
    /// makes <c>TOP 5 PERCENT</c> look like a plain <c>TOP 5</c>.
    /// </remarks>
    private static readonly Regex TopClause = new(
        @"\G\s+TOP\s*(?:\(\s*(?<parenCount>\d+)\s*\)|(?<count>\d+))"
        + @"(?<modifier>\s+PERCENT\b|\s+WITH\s+TIES\b)?",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>
    /// Clauses that may follow the <c>FROM</c>/join list. An injected <c>WHERE</c> goes
    /// before whichever of them appears earliest.
    /// </summary>
    private static readonly Regex[] PostFromClauses =
    [
        new(@"\bGROUP\s+BY\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\bHAVING\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\bWINDOW\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\bORDER\s+BY\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\bLIMIT\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\bOFFSET\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\bFETCH\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\bUNION\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\bINTERSECT\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\bEXCEPT\b", RegexOptions.IgnoreCase | RegexOptions.Compiled)
    ];

    /// <summary>
    /// The table reference immediately after <c>FROM</c>: a bare, dotted, or quoted name.
    /// </summary>
    private static readonly Regex FromTablePattern = new(
        @"\bFROM\s+((?:""[^""]+""|\w+)(?:\.(?:""[^""]+""|\w+))*)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // -- Clause-body patterns, used only by ValidateQuery's field extraction --

    private static readonly Regex WhereClausePattern = new(
        @"\bWHERE\s+(.+?)(?:\bORDER\s+BY\b|\bGROUP\s+BY\b|\bHAVING\b|\bLIMIT\b|\bOFFSET\b|\bUNION\b|;|$)",
        RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);

    private static readonly Regex OrderByClausePattern = new(
        @"\bORDER\s+BY\s+(.+?)(?:\bLIMIT\b|\bOFFSET\b|\bUNION\b|;|$)",
        RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);

    private static readonly Regex GroupByClausePattern = new(
        @"\bGROUP\s+BY\s+(.+?)(?:\bHAVING\b|\bORDER\s+BY\b|\bLIMIT\b|\bOFFSET\b|\bUNION\b|;|$)",
        RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);

    private static readonly Regex HavingClausePattern = new(
        @"\bHAVING\s+(.+?)(?:\bORDER\s+BY\b|\bLIMIT\b|\bOFFSET\b|\bUNION\b|;|$)",
        RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);

    /// <summary>Unqualified field references on the left of a comparison operator.</summary>
    private static readonly Regex ColumnComparisonPattern = new(
        @"(?<![.""'`\w])(\w+)\s*(?:=|!=|<>|<=|>=|<|>|\bLIKE\b|\bIN\b|\bIS\b|\bBETWEEN\b|\bNOT\s+LIKE\b|\bNOT\s+IN\b)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>Table-qualified field references on the left of a comparison operator.</summary>
    private static readonly Regex QualifiedColumnComparisonPattern = new(
        @"(?:""[^""]+""|\w+)\.(?:""([^""]+)""|(\w+))\s*(?:=|!=|<>|<=|>=|<|>|\bLIKE\b|\bIN\b|\bIS\b|\bBETWEEN\b|\bNOT\s+LIKE\b|\bNOT\s+IN\b)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>
    /// A function call and its argument list, used to reach field references that are not on
    /// the left of a comparison operator.
    /// </summary>
    /// <remarks>
    /// Without this, <c>HAVING max(ssn) &gt; '1'</c> yields no field name at all — the token
    /// left of <c>&gt;</c> is <c>)</c> — and a hidden field is used to select which rows come
    /// back while passing validation.
    /// </remarks>
    private static readonly Regex FunctionCallPattern = new(
        @"\b(\w+)\s*\(([^()]*)\)", RegexOptions.Compiled);

    /// <summary>A bare word token, for pulling field names out of a function's arguments.</summary>
    private static readonly Regex WordPattern = new(@"\w+", RegexOptions.Compiled);

    /// <summary>A quoted string literal, whose contents are values rather than field names.</summary>
    private static readonly Regex StringLiteralPattern = new(@"'(?:[^']|'')*'", RegexOptions.Compiled);

    private static readonly Regex OrderBySuffixPattern = new(
        @"\s+(ASC|DESC)(\s+NULLS\s+(FIRST|LAST))?\s*$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>
    /// A field name safe to emit as a quoted SQL identifier: a letter or underscore followed
    /// by letters, digits, underscores, or dollars. Deliberately excludes the quote
    /// characters, dots, whitespace, and control characters, so a name that could alter the
    /// statement's structure is declined rather than escaped and hoped for.
    /// </summary>
    private static readonly Regex SafeIdentifierPattern = new(
        @"^[\p{L}_][\p{L}\p{N}_$]*$", RegexOptions.Compiled);

    /// <summary>
    /// Keywords that must never be mistaken for a field name during extraction.
    /// </summary>
    private static readonly HashSet<string> SqlKeywords = new(StringComparer.OrdinalIgnoreCase)
    {
        "SELECT", "FROM", "WHERE", "AND", "OR", "NOT", "IN", "IS", "NULL",
        "LIKE", "BETWEEN", "EXISTS", "HAVING", "ORDER", "BY", "GROUP",
        "ASC", "DESC", "LIMIT", "OFFSET", "UNION", "ALL", "DISTINCT",
        "AS", "ON", "JOIN", "LEFT", "RIGHT", "INNER", "OUTER", "CROSS",
        "FULL", "CASE", "WHEN", "THEN", "ELSE", "END", "CAST", "TRUE",
        "FALSE", "INSERT", "UPDATE", "DELETE", "SET", "VALUES", "INTO",
        "CREATE", "ALTER", "DROP", "TABLE", "INDEX", "WITH", "RECURSIVE",
        "OVER", "PARTITION", "ROW", "ROWS", "RANGE", "UNBOUNDED",
        "PRECEDING", "FOLLOWING", "CURRENT", "FETCH", "FIRST", "LAST",
        "NEXT", "ONLY", "NULLS", "FILTER", "WITHIN", "ARRAY", "ANY",
        "SOME", "EVERY", "ESCAPE", "ILIKE", "SIMILAR", "TO",

        // Type names, which appear as a bare word inside CAST(x AS type) and would otherwise
        // be extracted as a field and refused under an allow-list.
        "TEXT", "VARCHAR", "CHAR", "INT", "INTEGER", "BIGINT", "SMALLINT",
        "DECIMAL", "NUMERIC", "REAL", "DOUBLE", "PRECISION", "FLOAT",
        "BOOLEAN", "BOOL", "DATE", "TIME", "TIMESTAMP", "TIMESTAMPTZ",
        "INTERVAL", "JSON", "JSONB", "UUID", "BYTEA", "BLOB", "SERIAL",
        "ZONE", "VARYING", "UNSIGNED", "SIGNED"
    };

    /// <summary>A condition that admits every row, for a filter that restricts nothing.</summary>
    private const string AlwaysTrue = "1 = 1";

    /// <summary>A condition that admits no row, for a filter that can never be satisfied.</summary>
    private const string AlwaysFalse = "1 = 0";

    // -----------------------------------------------------------------------
    // RewriteQuery
    // -----------------------------------------------------------------------

    /// <inheritdoc />
    public string RewriteQuery(string originalQuery, EffectivePolicy policy, SqlDialect? dialect = null)
    {
        if (string.IsNullOrWhiteSpace(originalQuery))
            return originalQuery;

        var profile = ProfileFor(dialect);
        if (profile is null)
            return originalQuery;

        var query = originalQuery.Trim();

        query = RewriteSelectList(query, policy, profile);
        query = InjectRowFilters(query, policy, profile);
        query = ClampLimit(query, policy, profile);

        return query;
    }

    /// <summary>
    /// Expands <c>SELECT *</c> to the permitted fields, or removes hidden and non-allowed
    /// fields from an explicit select list.
    /// </summary>
    private string RewriteSelectList(string query, EffectivePolicy policy, DialectProfile profile)
    {
        var fieldRules = policy.ObjectRules?.FieldRules;
        var allowed = fieldRules?.AllowedFields;
        var hidden = fieldRules?.HiddenFields;

        // Nothing to do: an absent allow-list is unrestricted and there is nothing to hide.
        if (allowed is null && (hidden is null || hidden.Length == 0))
            return query;

        var span = FindSelectListSpan(query);
        if (span is null)
        {
            Diagnose("select list not located; leaving the projection to the post-fetch pass");
            return query;
        }

        var (start, length) = span.Value;
        var selectList = query.Substring(start, length);

        var replacement = selectList.Trim() == "*"
            ? ExpandSelectStar(allowed, hidden, profile)
            : FilterSelectList(selectList, allowed, hidden);

        if (replacement is null)
            return query;

        return string.Concat(query.AsSpan(0, start), replacement, query.AsSpan(start + length));
    }

    /// <summary>
    /// The explicit field list replacing <c>*</c>, or null when it cannot be determined.
    /// </summary>
    /// <remarks>
    /// Requires <c>allowedFields</c>: without it the set of columns the table actually has is
    /// unknown, so hidden fields cannot be subtracted from <c>*</c> without schema access the
    /// SDK deliberately does not assume. In that case <c>*</c> is left alone and
    /// <see cref="EnforcementEngine.StripHiddenFields"/> removes the hidden columns after the
    /// fetch — the disclosure outcome is identical, the transfer cost is not.
    /// </remarks>
    private string? ExpandSelectStar(string[]? allowed, string[]? hidden, DialectProfile profile)
    {
        if (allowed is null)
        {
            Diagnose(
                "SELECT * with hiddenFields but no allowedFields: the table's column list is "
                + "unknown, so hidden columns are removed after the fetch instead");
            return null;
        }

        // A glob cannot be emitted as an identifier, and dropping the entries it stands for
        // would narrow the projection below what the policy grants.
        if (allowed.Any(a => a.Contains('*')))
        {
            Diagnose(
                "SELECT * not expanded: allowedFields contains a wildcard pattern, which has "
                + "no column list to expand to");
            return null;
        }

        var columns = allowed
            .Where(a => hidden is null || !hidden.Any(h => EnforcementEngine.FieldNameMatches(h, a)))
            .Select(a => LeafIdentifier(a, profile))
            .Where(c => c is not null)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (columns.Count == 0)
        {
            // No field is permitted. Selecting a constant keeps the statement valid and
            // matches the post-fetch outcome, where projecting to an empty allow-list leaves
            // each surviving row with no fields.
            Diagnose("no field permitted after filtering; projecting a constant");
            return "1";
        }

        return string.Join(", ", columns.Select(c => Quote(c!, profile)));
    }

    /// <summary>
    /// Removes hidden and non-allowed entries from an explicit select list, or returns null
    /// when the list should be left alone.
    /// </summary>
    /// <remarks>
    /// Masked fields are deliberately <b>not</b> removed. Masking happens after the fetch, so
    /// a masked column must survive into the executed query or there is nothing left to mask
    /// and the field silently disappears from the result instead of appearing masked.
    /// </remarks>
    private string? FilterSelectList(string selectList, string[]? allowed, string[]? hidden)
    {
        var entries = SplitTopLevel(selectList);
        var kept = new List<string>(entries.Count);

        foreach (var entry in entries)
        {
            var name = ExtractFieldName(entry);

            if (hidden is not null && hidden.Any(h => EnforcementEngine.FieldNameMatches(h, name)))
            {
                Diagnose($"removing hidden field from select list: {name}");
                continue;
            }

            if (allowed is not null
                && !allowed.Any(a => EnforcementEngine.FieldNameMatches(a, name)))
            {
                Diagnose($"removing non-allowed field from select list: {name}");
                continue;
            }

            kept.Add(entry.Trim());
        }

        if (kept.Count == entries.Count)
            return null;

        if (kept.Count == 0)
        {
            Diagnose("every selected field was removed; projecting a constant");
            return "1";
        }

        return string.Join(", ", kept);
    }

    /// <summary>
    /// Injects the policy's row filters as a <c>WHERE</c> condition.
    /// </summary>
    private string InjectRowFilters(string query, EffectivePolicy policy, DialectProfile profile)
    {
        var filters = policy.ObjectRules?.RowFilters;
        if (filters is null || filters.Length == 0)
            return query;

        var clause = BuildWhereClause(filters, profile.Dialect);
        if (clause.Length == 0)
            return query;

        var scan = new SqlScan(query);

        var existing = scan.FirstTopLevel(WhereKeyword);
        if (existing is not null)
        {
            // The original WHERE body ends at the next top-level clause, not at the end of the
            // statement. Taking the rest of the text would pull ORDER BY/GROUP BY/LIMIT inside
            // the parentheses added below and emit invalid SQL.
            var bodyStart = existing.Index + existing.Length;
            var bodyEnd = query.AsSpan().TrimEnd().TrimEnd(';').TrimEnd().Length;
            foreach (var pattern in PostFromClauses)
            {
                var match = scan.FirstTopLevelAfter(pattern, bodyStart);
                if (match is not null && match.Index < bodyEnd)
                    bodyEnd = match.Index;
            }

            // Parenthesise BOTH sides. The injected conditions must be grouped so an existing
            // OR cannot widen them, and the original must be grouped too:
            // "WHERE (filters) AND a OR b" binds as "((filters) AND a) OR b" and admits every
            // row matching b. Back up over the whitespace so the tail keeps its own separator;
            // the parenthesised body is trimmed, so otherwise ") ORDER BY" would run together
            // as ")ORDER BY".
            while (bodyEnd > bodyStart && char.IsWhiteSpace(query[bodyEnd - 1])) bodyEnd--;

            var original = query[bodyStart..bodyEnd].Trim();
            return string.Concat(
                query.AsSpan(0, existing.Index),
                $"WHERE ({clause}) AND ({original})",
                query.AsSpan(bodyEnd));
        }

        var insertAt = FindWhereInsertPoint(query, scan);
        return query.Insert(insertAt, $" WHERE {clause}");
    }

    /// <summary>
    /// The offset at which a fresh <c>WHERE</c> clause belongs.
    /// </summary>
    /// <remarks>
    /// The earliest top-level clause that must follow <c>WHERE</c>, or the end of the
    /// statement with any trailing semicolon and whitespace excluded. Taking the earliest
    /// rather than the first pattern to match is what keeps <c>GROUP BY x ORDER BY y</c> from
    /// producing <c>GROUP BY x WHERE ... ORDER BY y</c>.
    /// </remarks>
    private static int FindWhereInsertPoint(string query, SqlScan scan)
    {
        var earliest = int.MaxValue;
        foreach (var pattern in PostFromClauses)
        {
            var match = scan.FirstTopLevel(pattern);
            if (match is not null && match.Index < earliest)
                earliest = match.Index;
        }

        if (earliest != int.MaxValue)
        {
            // Back up over the whitespace before the clause. The injected text carries its own
            // leading space, so inserting at the clause's own offset would strand the original
            // separator on the left and leave none on the right:
            // "FROM patients  WHERE ...GROUP BY region".
            while (earliest > 0 && char.IsWhiteSpace(query[earliest - 1])) earliest--;
            return earliest;
        }

        return query.AsSpan().TrimEnd().TrimEnd(';').TrimEnd().Length;
    }

    /// <summary>
    /// Pushes <c>maxResults</c> into the statement's row limit, in the profile's own form.
    /// </summary>
    private string ClampLimit(string query, EffectivePolicy policy, DialectProfile profile)
    {
        var maxResults = policy.Limits?.MaxResults;
        if (maxResults is null)
            return query;

        if (maxResults.Value < 0)
        {
            Diagnose(
                $"negative maxResults ({maxResults.Value}) is not a row limit; leaving the "
                + "query alone");
            return query;
        }

        return profile.RowLimit == RowLimitForm.TopPrefix
            ? ClampLimitTop(query, maxResults.Value)
            : ClampLimitSuffix(query, maxResults.Value);
    }

    /// <summary>
    /// Clamps or appends a trailing <c>LIMIT n</c>.
    /// </summary>
    private static string ClampLimitSuffix(string query, int maxResults)
    {
        var scan = new SqlScan(query);

        // The statement's own LIMIT is the last one at top level; an earlier top-level LIMIT
        // belongs to a set operand ("... UNION SELECT ... LIMIT 5"), and clamping that would
        // alter which rows the operand contributes rather than how many the caller receives.
        var match = scan.LastTopLevel(LimitClause);
        if (match is null)
        {
            var trimmed = query.AsSpan().TrimEnd();
            var hadSemicolon = trimmed.EndsWith(";");
            var body = hadSemicolon ? trimmed[..^1].TrimEnd() : trimmed;
            return $"{body} LIMIT {maxResults.ToString(CultureInfo.InvariantCulture)}"
                   + (hadSemicolon ? ";" : string.Empty);
        }

        var digits = match.Groups[1].Value;
        // A literal too large for long is certainly larger than any policy limit; parsing it
        // with int.Parse would throw and abort the rewrite.
        var effective = long.TryParse(digits, NumberStyles.None, CultureInfo.InvariantCulture, out var existing)
            ? Math.Min(existing, maxResults)
            : maxResults;

        return string.Concat(
            query.AsSpan(0, match.Index),
            $"LIMIT {effective.ToString(CultureInfo.InvariantCulture)}",
            query.AsSpan(match.Index + match.Length));
    }

    /// <summary>
    /// Clamps or inserts a <c>TOP n</c>, or returns the query unchanged.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>TOP n</c> is <b>not a token swap for <c>LIMIT n</c></b>: it sits immediately after
    /// <c>SELECT</c> (and after <c>DISTINCT</c>/<c>ALL</c>), not at the end of the statement,
    /// and it binds to one <c>SELECT</c> rather than to the statement's final result. So this
    /// is a structural placement, and where it cannot be placed <i>correctly</i> the limit is
    /// simply <b>not pushed</b> — never rendered as <c>LIMIT n</c> instead (connector-spec.md
    /// section 5.1 rule 3). An unpushed limit costs a transfer that
    /// <see cref="EnforcementEngine.ApplyResultLimit"/> then trims; a misplaced or mis-spelled
    /// one is a broken statement or a wrong row count.
    /// </para>
    /// <para>Declined shapes, each for a reason that is not a parser limitation:</para>
    /// <list type="bullet">
    ///   <item><description>
    ///     <b>A top-level set operation.</b> In <c>SELECT ... UNION SELECT ...</c>, a
    ///     <c>TOP</c> on the first operand limits that operand, not the union, so the caller
    ///     would receive more rows than the policy allows.
    ///   </description></item>
    ///   <item><description>
    ///     <b><c>OFFSET</c>/<c>FETCH</c>.</b> T-SQL rejects <c>TOP</c> combined with
    ///     <c>OFFSET ... FETCH</c> outright.
    ///   </description></item>
    ///   <item><description>
    ///     <b>An existing <c>TOP n PERCENT</c> or <c>WITH TIES</c>.</b> A percentage is not a
    ///     row count, and <c>WITH TIES</c> returns more rows than the number given.
    ///   </description></item>
    ///   <item><description>
    ///     <b>An existing top-level <c>LIMIT</c>.</b> The statement is already not valid
    ///     T-SQL; clamping around a clause this profile does not emit would be guessing at
    ///     what the caller meant.
    ///   </description></item>
    /// </list>
    /// </remarks>
    private string ClampLimitTop(string query, int maxResults)
    {
        var scan = new SqlScan(query);

        (Regex Pattern, string Reason)[] declineOn =
        [
            (UnionKeyword, "a top-level set operation, where TOP would bind to one operand"),
            (IntersectKeyword, "a top-level set operation, where TOP would bind to one operand"),
            (ExceptKeyword, "a top-level set operation, where TOP would bind to one operand"),
            (OffsetKeyword, "an OFFSET clause, which T-SQL forbids alongside TOP"),
            (FetchKeyword, "a FETCH clause, which T-SQL forbids alongside TOP"),
            (LimitKeyword, "a LIMIT clause, which is not valid T-SQL to begin with")
        ];

        foreach (var (pattern, reason) in declineOn)
        {
            if (scan.FirstTopLevel(pattern) is not null)
            {
                Diagnose(
                    $"the row limit is not pushed as TOP: the statement contains {reason}; "
                    + "ApplyResultLimit truncates the result instead");
                return query;
            }
        }

        var select = scan.FirstTopLevel(SelectKeyword);
        if (select is null)
        {
            Diagnose(
                "the row limit is not pushed as TOP: there is no top-level SELECT to place it "
                + "after; ApplyResultLimit truncates the result instead");
            return query;
        }

        var afterSelect = select.Index + select.Length;

        var existingTop = TopClause.Match(query, afterSelect);
        if (existingTop.Success)
        {
            if (existingTop.Groups["modifier"].Success)
            {
                Diagnose(
                    "the row limit is not pushed as TOP: the statement already uses TOP ..."
                    + $"{existingTop.Groups["modifier"].Value}, which is not a plain row count; "
                    + "ApplyResultLimit truncates the result instead");
                return query;
            }

            // One of the two count branches always matches when TopClause does. A literal too
            // large for long is certainly larger than any policy limit.
            var written = existingTop.Groups["count"].Success
                ? existingTop.Groups["count"].Value
                : existingTop.Groups["parenCount"].Value;
            var effective = long.TryParse(
                written, NumberStyles.None, CultureInfo.InvariantCulture, out var existing)
                ? Math.Min(existing, maxResults)
                : maxResults;

            return string.Concat(
                query.AsSpan(0, afterSelect),
                $" TOP {effective.ToString(CultureInfo.InvariantCulture)}",
                query.AsSpan(existingTop.Index + existingTop.Length));
        }

        // DISTINCT and ALL bind to the SELECT, so TOP goes after them: "SELECT DISTINCT TOP 5"
        // is a syntax error where "SELECT TOP 5 DISTINCT" changes which rows are counted --
        // TOP would apply before duplicates are removed.
        var quantifier = SelectQuantifier.Match(query, afterSelect);
        var insertAt = quantifier.Success ? quantifier.Index + quantifier.Length : afterSelect;

        return query.Insert(
            insertAt, $" TOP {maxResults.ToString(CultureInfo.InvariantCulture)}");
    }

    // -----------------------------------------------------------------------
    // ValidateQuery
    // -----------------------------------------------------------------------

    /// <inheritdoc />
    public bool ValidateQuery(string query, EffectivePolicy policy)
    {
        if (string.IsNullOrWhiteSpace(query))
            return false;

        var fieldRules = policy.ObjectRules?.FieldRules;
        var hidden = fieldRules?.HiddenFields;
        var allowed = fieldRules?.AllowedFields;

        var referenced = ExtractReferencedFields(query);

        foreach (var field in referenced)
        {
            if (hidden is not null && hidden.Any(h => EnforcementEngine.FieldNameMatches(h, field)))
            {
                Diagnose($"query references hidden field: {field}");
                return false;
            }
        }

        // Tested for null, not for emptiness: an empty allow-list denies every field
        // (spec section 3), so treating it as "no restriction" would invert the rule.
        if (allowed is not null)
        {
            foreach (var field in referenced)
            {
                // A wildcard discloses nothing by itself and an aggregate has no single
                // field name; both are settled by the post-fetch projection.
                if (field == "*" || field.Contains('('))
                    continue;

                if (!allowed.Any(a => EnforcementEngine.FieldNameMatches(a, field)))
                {
                    Diagnose($"query references non-allowed field: {field}");
                    return false;
                }
            }
        }

        return true;
    }

    /// <summary>
    /// Every field name the query mentions in its SELECT, WHERE, ORDER BY, GROUP BY, or
    /// HAVING clauses.
    /// </summary>
    private HashSet<string> ExtractReferencedFields(string query)
    {
        var fields = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var span = FindSelectListSpan(query);
        if (span is not null)
        {
            var selectList = query.Substring(span.Value.Start, span.Value.Length);
            foreach (var entry in SplitTopLevel(selectList))
            {
                fields.Add(ExtractFieldName(entry));
            }

            // A field wrapped in an aggregate would otherwise be extracted as the whole
            // expression ("max(ssn)"), which matches no policy field and is then skipped by
            // the allow-list check for containing a parenthesis.
            AddFieldsFromFunctionArguments(selectList, fields);
        }

        AddFieldsFromConditionClause(query, WhereClausePattern, fields);
        AddFieldsFromOrderBy(query, fields);
        AddFieldsFromCommaSeparatedClause(query, GroupByClausePattern, fields);
        AddFieldsFromConditionClause(query, HavingClausePattern, fields);

        return fields;
    }

    /// <summary>
    /// Adds the field names appearing on the left of a comparison in a WHERE or HAVING clause.
    /// </summary>
    private static void AddFieldsFromConditionClause(string query, Regex clausePattern, HashSet<string> fields)
    {
        var clauseMatch = clausePattern.Match(query);
        if (!clauseMatch.Success)
            return;

        var body = clauseMatch.Groups[1].Value;

        foreach (Match match in QualifiedColumnComparisonPattern.Matches(body))
        {
            var name = match.Groups[1].Value.Length > 0
                ? match.Groups[1].Value
                : match.Groups[2].Value;
            if (name.Length > 0 && !SqlKeywords.Contains(name))
                fields.Add(name);
        }

        foreach (Match match in ColumnComparisonPattern.Matches(body))
        {
            var name = match.Groups[1].Value;
            if (!SqlKeywords.Contains(name))
                fields.Add(name);
        }

        AddFieldsFromFunctionArguments(body, fields);
    }

    /// <summary>
    /// Adds the field names appearing inside a function call's argument list.
    /// </summary>
    /// <remarks>
    /// A field wrapped in an aggregate is not on the left of any comparison operator, so the
    /// comparison patterns never see it: <c>HAVING max(ssn) &gt; '1'</c> presents <c>)</c> as
    /// the left operand. Left unextracted, a hidden field can be used to choose which rows are
    /// returned — the aggregate's value is disclosed by the row set even though the field is
    /// absent from the projection. String literals are removed first so a value is not mistaken
    /// for a field name.
    /// </remarks>
    private static void AddFieldsFromFunctionArguments(string body, HashSet<string> fields)
    {
        var withoutLiterals = StringLiteralPattern.Replace(body, " ");

        foreach (Match call in FunctionCallPattern.Matches(withoutLiterals))
        {
            foreach (Match word in WordPattern.Matches(call.Groups[2].Value))
            {
                var name = word.Value;
                // A numeric argument is a literal, not a field.
                if (!SqlKeywords.Contains(name) && !char.IsDigit(name[0]))
                    fields.Add(name);
            }
        }
    }

    /// <summary>
    /// Adds the field names in an ORDER BY clause, discarding ASC/DESC and NULLS suffixes.
    /// </summary>
    private static void AddFieldsFromOrderBy(string query, HashSet<string> fields)
    {
        var clauseMatch = OrderByClausePattern.Match(query);
        if (!clauseMatch.Success)
            return;

        foreach (var part in clauseMatch.Groups[1].Value.Split(','))
        {
            var trimmed = OrderBySuffixPattern.Replace(part.Trim(), string.Empty).Trim();
            if (trimmed.Length == 0)
                continue;

            var name = ExtractFieldName(trimmed);
            if (name.Length > 0 && !SqlKeywords.Contains(name))
                fields.Add(name);
        }
    }

    /// <summary>
    /// Adds the field names in a comma-separated clause whose entries are plain references.
    /// </summary>
    private static void AddFieldsFromCommaSeparatedClause(string query, Regex clausePattern, HashSet<string> fields)
    {
        var clauseMatch = clausePattern.Match(query);
        if (!clauseMatch.Success)
            return;

        foreach (var part in clauseMatch.Groups[1].Value.Split(','))
        {
            var trimmed = part.Trim();
            if (trimmed.Length == 0)
                continue;

            var name = ExtractFieldName(trimmed);
            if (name.Length > 0 && !SqlKeywords.Contains(name))
                fields.Add(name);
        }
    }

    // -----------------------------------------------------------------------
    // ExtractTableName
    // -----------------------------------------------------------------------

    /// <inheritdoc />
    public string? ExtractTableName(string query)
    {
        if (string.IsNullOrWhiteSpace(query))
            return null;

        var match = FromTablePattern.Match(query);
        if (!match.Success)
            return null;

        var reference = match.Groups[1].Value;

        // "schema"."table": split on the quote-dot-quote seam so a dot inside either
        // identifier is not mistaken for the separator.
        if (reference.Contains("\".\"", StringComparison.Ordinal))
        {
            var quotedParts = reference.Split("\".\"", StringSplitOptions.None);
            return quotedParts[^1].Trim('"', '\'', ' ');
        }

        var name = reference.Trim('"', '\'', ' ');

        // schema.table, including the "schema.table" form where the whole dotted name was
        // written inside one pair of quotes.
        if (name.Contains('.'))
        {
            var parts = name.Split('.');
            return parts[^1];
        }

        return name;
    }

    // -----------------------------------------------------------------------
    // Row filter conditions
    // -----------------------------------------------------------------------

    /// <inheritdoc />
    public string BuildWhereClause(IEnumerable<RowFilter> filters, SqlDialect? dialect = null)
    {
        var profile = DialectProfiles.Resolve(dialect ?? _dialect);
        if (profile is null)
            return string.Empty;

        var conditions = new List<string>();

        foreach (var filter in filters)
        {
            if (TryBuildCondition(filter, profile, out var condition))
                conditions.Add(condition);
        }

        return conditions.Count == 0 ? string.Empty : string.Join(" AND ", conditions);
    }

    /// <inheritdoc />
    public IReadOnlyList<RowFilter> UnpushableFilters(EffectivePolicy policy, SqlDialect? dialect = null)
    {
        var filters = policy.ObjectRules?.RowFilters;
        if (filters is null || filters.Length == 0)
            return Array.Empty<RowFilter>();

        // An unrecognized dialect rewrites nothing, so every filter is unpushable.
        var profile = DialectProfiles.Resolve(dialect ?? _dialect);
        if (profile is null)
            return filters.ToList();

        return filters.Where(f => !TryBuildCondition(f, profile, out _)).ToList();
    }

    /// <summary>
    /// Renders one row filter as a SQL condition, or reports that it cannot be pushed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every condition is built to mean exactly what
    /// <see cref="EnforcementEngine.ApplyRowFilters"/> means, including where SQL's
    /// three-valued logic would otherwise differ. The negative operators are the important
    /// case: post-fetch, a field present with a null value satisfies <c>notEquals 'x'</c> and
    /// the row is kept, whereas plain SQL <c>col != 'x'</c> evaluates to NULL and drops it.
    /// An explicit <c>OR col IS NULL</c> keeps the two paths agreeing, so pushing a filter
    /// down never changes which rows the caller sees.
    /// </para>
    /// <para>
    /// Returns false — leaving the filter to the post-fetch pass — for a field name that is
    /// not a safe identifier, a value that cannot be rendered as a portable literal, the
    /// operators with no portable SQL form, and <c>like</c>/<c>notLike</c> on a dialect whose
    /// collation could make the comparison case-insensitive (see
    /// <see cref="BuildLikeCondition"/>). That is the safe direction: an omitted condition
    /// costs transfer, never disclosure.
    /// </para>
    /// </remarks>
    private bool TryBuildCondition(RowFilter filter, DialectProfile profile, out string condition)
    {
        condition = string.Empty;

        var leaf = LeafIdentifier(filter.Field, profile);
        if (leaf is null)
        {
            Diagnose(
                $"row filter on '{filter.Field}' not pushed into SQL: the field name is not a "
                + $"plain identifier for the {profile.Dialect} dialect; it is enforced after "
                + "the fetch instead");
            return false;
        }

        var column = Quote(leaf, profile);

        switch (filter.Operator)
        {
            case FilterOperator.Equals:
                // A null comparison value means "the field is null" post-fetch, but SQL
                // "col = NULL" is NULL for every row.
                if (filter.Value is null || IsJsonNull(filter.Value))
                {
                    condition = $"{column} IS NULL";
                    return true;
                }
                return Compare(column, "=", filter.Value, out condition);

            case FilterOperator.NotEquals:
                if (filter.Value is null || IsJsonNull(filter.Value))
                {
                    condition = $"{column} IS NOT NULL";
                    return true;
                }
                if (!Compare(column, "<>", filter.Value, out condition))
                    return false;
                condition = $"({condition} OR {column} IS NULL)";
                return true;

            case FilterOperator.GreaterThan:
                return Compare(column, ">", filter.Value, out condition);
            case FilterOperator.GreaterThanOrEqual:
                return Compare(column, ">=", filter.Value, out condition);
            case FilterOperator.LessThan:
                return Compare(column, "<", filter.Value, out condition);
            case FilterOperator.LessThanOrEqual:
                return Compare(column, "<=", filter.Value, out condition);

            case FilterOperator.In:
                return BuildInCondition(column, filter, negated: false, out condition);
            case FilterOperator.NotIn:
                return BuildInCondition(column, filter, negated: true, out condition);

            case FilterOperator.Like:
                return BuildLikeCondition(column, filter.Value, profile, negated: false, out condition);
            case FilterOperator.NotLike:
                return BuildLikeCondition(column, filter.Value, profile, negated: true, out condition);

            case FilterOperator.IsNull:
                condition = $"{column} IS NULL";
                return true;
            case FilterOperator.IsNotNull:
                condition = $"{column} IS NOT NULL";
                return true;

            case FilterOperator.Between:
                return BuildBetweenCondition(column, filter, out condition);

            case FilterOperator.Contains:
            case FilterOperator.StartsWith:
            case FilterOperator.Matches:
                // Contains and startsWith compare a value's string form regardless of its
                // declared type; the SQL equivalent needs a cast whose spelling differs by
                // engine ("AS TEXT" vs "AS CHAR"), and getting it wrong makes the query
                // fail rather than over-return. Matches has no portable regex operator at
                // all (Postgres "~", MySQL "REGEXP", Trino "regexp_like"), and its pattern
                // dialect differs even where an operator exists.
                Diagnose(
                    $"row filter on '{filter.Field}' with operator {filter.Operator} has no "
                    + "portable SQL form; it is enforced after the fetch instead");
                return false;

            default:
                // An operator from a newer schema version. Declining to push it leaves
                // enforcement with the post-fetch pass, which fails closed on an operator
                // it does not recognise.
                Diagnose(
                    $"row filter on '{filter.Field}' uses unrecognized operator "
                    + $"{filter.Operator}; it is enforced after the fetch instead");
                return false;
        }
    }

    /// <summary>
    /// Renders a binary comparison, declining when the operand has no portable literal form.
    /// </summary>
    private bool Compare(string column, string op, object? value, out string condition)
    {
        if (value is null || IsJsonNull(value))
        {
            // Post-fetch, an ordering comparison against null is not satisfiable by any row.
            condition = AlwaysFalse;
            return true;
        }

        var literal = FormatLiteral(value);
        if (literal is null)
        {
            condition = string.Empty;
            return false;
        }

        condition = $"{column} {op} {literal}";
        return true;
    }

    /// <summary>
    /// Renders an <c>IN</c> or <c>NOT IN</c> condition from <see cref="RowFilter.Values"/>.
    /// </summary>
    /// <remarks>
    /// Mirrors the post-fetch pass exactly, including its degenerate cases: a null
    /// <c>values</c> array satisfies neither operator and admits no row, while an empty array
    /// admits no row for <c>in</c> and every row for <c>notIn</c>. A list containing null is
    /// declined, because SQL's <c>NOT IN (NULL, ...)</c> is never true and would drop rows the
    /// post-fetch pass keeps.
    /// </remarks>
    private bool BuildInCondition(string column, RowFilter filter, bool negated, out string condition)
    {
        var values = filter.Values;

        if (values is null)
        {
            condition = AlwaysFalse;
            return true;
        }

        if (values.Length == 0)
        {
            condition = negated ? AlwaysTrue : AlwaysFalse;
            return true;
        }

        var literals = new List<string>(values.Length);
        foreach (var value in values)
        {
            if (value is null || IsJsonNull(value))
            {
                Diagnose(
                    $"row filter on '{filter.Field}' not pushed into SQL: a null entry in "
                    + "values has no SQL IN equivalent; it is enforced after the fetch instead");
                condition = string.Empty;
                return false;
            }

            var literal = FormatLiteral(value);
            if (literal is null)
            {
                condition = string.Empty;
                return false;
            }
            literals.Add(literal);
        }

        var list = string.Join(", ", literals);
        condition = negated
            // NOT IN drops a null-valued row; the post-fetch pass keeps it.
            ? $"({column} NOT IN ({list}) OR {column} IS NULL)"
            : $"{column} IN ({list})";
        return true;
    }

    /// <summary>
    /// Renders a <c>LIKE</c> or <c>NOT LIKE</c> condition, or declines when the profile cannot
    /// guarantee the comparison means what the post-fetch pass means.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The profile must guarantee a case-sensitive <c>LIKE</c>, or nothing is pushed</b>
    /// (canonical-enforcement-spec.md section 4). The post-fetch pass compares case-sensitively
    /// and is engine-independent, but a pushed-down <c>LIKE</c> inherits the <i>column's</i>
    /// collation: <c>'ALICE JONES' LIKE 'alice%'</c> is false on Postgres and <b>true</b> under
    /// MySQL's default <c>utf8mb4_0900_ai_ci</c>. So on MySQL a <c>name notLike 'alice%'</c>
    /// filter drops <c>'ALICE JONES'</c> when pushed down and keeps it when applied post-fetch —
    /// a difference in which <i>real</i> records the caller sees. <c>Postgres</c> and
    /// <c>Trino</c> may push; <c>MySql</c>, <c>SqlServer</c> and <c>Ansi</c> may not
    /// (<c>Ansi</c> because the strict intersection promises no collation, <c>SqlServer</c>
    /// because its default is insensitive too).
    /// </para>
    /// <para>
    /// A <c>COLLATE</c> clause <i>can</i> force the comparison, and is deliberately <b>not</b>
    /// emitted: the correct collation name depends on the column's character set, which a
    /// rewriter holding only a policy and a query string does not know, and guessing wrong
    /// either fails the query or silently changes the comparison again. Declining is the same
    /// move as refusing a value containing a backslash — where the pushed-down form cannot be
    /// guaranteed to mean what the post-fetch form means, it is not emitted.
    /// </para>
    /// <para>
    /// The decline is unconditional for those profiles rather than case-by-case, so whether a
    /// filter is pushed is a plain function of its operator and the dialect. A null pattern
    /// would render as a collation-independent <c>1 = 0</c>, but exempting it would make the
    /// rule read "not pushed, except sometimes" for no gain beyond one unreachable
    /// optimization.
    /// </para>
    /// <para>
    /// Otherwise: the pattern is a SQL <c>LIKE</c> pattern already, so it passes through as a
    /// literal with no wildcard translation. A pattern containing a backslash is declined:
    /// <see cref="FormatLiteral"/> refuses backslashes in every literal, because MySQL treats
    /// one as an escape inside a string literal by default while Postgres does not, so the
    /// same text would mean different things in the two engines.
    /// </para>
    /// <para>
    /// <c>NOT LIKE</c> gets an <c>IS NULL</c> arm, exactly as <c>&lt;&gt;</c> and
    /// <c>NOT IN</c> do. <c>NULL NOT LIKE 'x'</c> is unknown — therefore not true — for the
    /// same reason <c>NULL &lt;&gt; 'x'</c> is, so the bare form drops a null-valued row
    /// while the post-fetch pass keeps it (spec section 7 drops rows whose field is
    /// <i>absent</i>, not rows whose value is null). Omitting the arm for this one negative
    /// operator while emitting it for the other two would make the same policy's row set
    /// depend on which operator the author happened to choose. Since only the case-sensitive
    /// profiles push the operator at all, that arm is only ever emitted for <c>Postgres</c>
    /// and <c>Trino</c>.
    /// </para>
    /// </remarks>
    private bool BuildLikeCondition(
        string column, object? value, DialectProfile profile, bool negated, out string condition)
    {
        if (!profile.CaseSensitiveLike)
        {
            Diagnose(
                $"row filter not pushed into SQL: the {profile.Dialect} dialect does not "
                + "guarantee a case-sensitive LIKE, so a pushed-down comparison could select "
                + "different rows than the case-sensitive post-fetch pass; it is enforced after "
                + "the fetch instead");
            condition = string.Empty;
            return false;
        }

        if (value is null || IsJsonNull(value))
        {
            condition = AlwaysFalse;
            return true;
        }

        var literal = FormatLiteral(value);
        if (literal is null)
        {
            condition = string.Empty;
            return false;
        }

        condition = negated
            // NOT LIKE drops a null-valued row; the post-fetch pass keeps it.
            ? $"({column} NOT LIKE {literal} OR {column} IS NULL)"
            : $"{column} LIKE {literal}";
        return true;
    }

    /// <summary>
    /// Renders an inclusive <c>BETWEEN</c> condition from the first two entries of
    /// <see cref="RowFilter.Values"/>.
    /// </summary>
    private bool BuildBetweenCondition(string column, RowFilter filter, out string condition)
    {
        var values = filter.Values;

        if (values is null || values.Length < 2)
        {
            // A malformed range is satisfiable by no row post-fetch.
            Diagnose(
                $"row filter on '{filter.Field}' uses between with fewer than two bounds; "
                + "no row can satisfy it");
            condition = AlwaysFalse;
            return true;
        }

        if (values[0] is null || IsJsonNull(values[0])
            || values[1] is null || IsJsonNull(values[1]))
        {
            condition = AlwaysFalse;
            return true;
        }

        var low = FormatLiteral(values[0]);
        var high = FormatLiteral(values[1]);
        if (low is null || high is null)
        {
            condition = string.Empty;
            return false;
        }

        // Bounds are emitted in the order written. An inverted range matches nothing, in
        // SQL and post-fetch alike; silently reordering it would turn an author's typo into a
        // wider grant than the policy states.
        condition = $"{column} BETWEEN {low} AND {high}";
        return true;
    }

    // -----------------------------------------------------------------------
    // Literals and identifiers
    // -----------------------------------------------------------------------

    /// <summary>
    /// Renders a policy value as a SQL literal, or null when it has no safe portable form.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The single defence that matters here is on strings. Doubling <c>'</c> is correct ANSI
    /// escaping, but it is not sufficient on its own: MySQL, by default, also treats
    /// <c>\</c> as an escape inside a string literal, so <c>'\''</c> leaves the literal open
    /// and the rest of the policy value becomes statement text. Rather than emit a
    /// dialect-conditional escape, a string containing a backslash is refused outright and
    /// the filter falls back to the post-fetch pass.
    /// </para>
    /// <para>
    /// Control characters — including NUL, which truncates the statement for some client
    /// libraries, and newlines, which end a <c>--</c> comment — are refused for the same
    /// reason.
    /// </para>
    /// <para>
    /// Numbers are formatted with <see cref="CultureInfo.InvariantCulture"/>. Under a culture
    /// whose decimal separator is a comma, the ambient-culture form of <c>1.5</c> is
    /// <c>"1,5"</c>, which in an <c>IN</c> list silently becomes two values.
    /// </para>
    /// </remarks>
    private string? FormatLiteral(object? value)
    {
        switch (value)
        {
            case null:
                return "NULL";

            case string s:
                return FormatStringLiteral(s);

            case bool b:
                return b ? "TRUE" : "FALSE";

            case char c:
                return FormatStringLiteral(c.ToString());

            case DateTime dt:
                return $"'{dt.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)}'";

            case DateTimeOffset dto:
                return $"'{dto.ToString("yyyy-MM-dd HH:mm:ssK", CultureInfo.InvariantCulture)}'";

            case DateOnly d:
                return $"'{d.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)}'";

            case sbyte or byte or short or ushort or int or uint or long or ulong:
                return Convert.ToInt64(value, CultureInfo.InvariantCulture)
                    .ToString(CultureInfo.InvariantCulture);

            case float or double:
                var d64 = Convert.ToDouble(value, CultureInfo.InvariantCulture);
                if (!double.IsFinite(d64))
                {
                    Diagnose($"value '{value}' has no SQL literal form; filter left to the post-fetch pass");
                    return null;
                }
                return d64.ToString("R", CultureInfo.InvariantCulture);

            case decimal m:
                return m.ToString(CultureInfo.InvariantCulture);

            case JsonElement je:
                return FormatJsonLiteral(je);

            default:
                // A driver-specific or policy-specific CLR type. Its ToString form is not
                // known to be a valid literal in any dialect, so it is not guessed at.
                Diagnose(
                    $"value of type {value.GetType().Name} has no known SQL literal form; "
                    + "filter left to the post-fetch pass");
                return null;
        }
    }

    /// <summary>
    /// Renders a string as a quoted literal, or null when it contains a character that
    /// cannot be escaped identically across dialects.
    /// </summary>
    /// <remarks>
    /// <b>The refusal is uniform across every profile, including the ones where <c>\</c> is not
    /// an escape</b> (connector-spec.md section 5.1 rule 5). Two reasons: a policy must behave
    /// identically on every engine, so a filter unpushable on MySQL must be unpushable on
    /// Postgres too; and a single profile treating <c>\</c> as an escape is enough to make
    /// escaping unsafe to generalize. The profile is deliberately not a parameter here.
    /// </remarks>
    private string? FormatStringLiteral(string value)
    {
        foreach (var c in value)
        {
            if (c == '\\' || char.IsControl(c))
            {
                Diagnose(
                    "string value refused as a SQL literal: it contains a backslash or a "
                    + "control character, which do not escape identically across engines; "
                    + "filter left to the post-fetch pass");
                return null;
            }
        }

        return $"'{value.Replace("'", "''", StringComparison.Ordinal)}'";
    }

    private string? FormatJsonLiteral(JsonElement element)
    {
        return element.ValueKind switch
        {
            JsonValueKind.String => FormatStringLiteral(element.GetString() ?? string.Empty),
            JsonValueKind.Number => element.GetRawText(),
            JsonValueKind.True => "TRUE",
            JsonValueKind.False => "FALSE",
            JsonValueKind.Null => "NULL",
            // An array or object is not a scalar comparand.
            _ => DeclineJson(element)
        };

        string? DeclineJson(JsonElement e)
        {
            Diagnose(
                $"JSON value of kind {e.ValueKind} is not a scalar comparand; filter left to "
                + "the post-fetch pass");
            return null;
        }
    }

    private static bool IsJsonNull(object? value)
        => value is JsonElement { ValueKind: JsonValueKind.Null };

    /// <summary>
    /// The unqualified, emit-safe form of a policy field reference, or null when it is not a
    /// plain identifier.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The qualifier is stripped rather than emitted as <c>"table"."column"</c>: TOLAP's own
    /// field matching already treats <c>patients.region</c> and <c>region</c> as the same
    /// field (spec section 4), and a qualifier that names the table would not resolve against
    /// a query that aliases it (<c>FROM patients p</c>). A bare column resolves under either
    /// spelling, and is ambiguous only in a join — where the database reports the ambiguity
    /// rather than silently filtering the wrong column.
    /// </para>
    /// <para>
    /// A <i>wrapping</i> quote character is unwrapped first, in any engine's style, so a policy
    /// may spell a field as <c>"region"</c>, <c>`region`</c> or <c>[region]</c> and still
    /// resolve: those characters are delimiters, not part of the name. What remains is then
    /// checked against the profile's <b>own</b> quote characters and declined if it contains
    /// one (connector-spec.md section 5.1 rule 4).
    /// </para>
    /// </remarks>
    private static string? LeafIdentifier(string field, DialectProfile profile)
    {
        if (string.IsNullOrWhiteSpace(field))
            return null;

        var leaf = field.Trim();
        var lastDot = leaf.LastIndexOf('.');
        if (lastDot >= 0)
            leaf = leaf[(lastDot + 1)..];

        leaf = leaf.Trim('"', '`', '[', ']', ' ');

        // The profile's own delimiter, anywhere in what is left, is declined rather than
        // escaped by doubling: the doubling rule is not even the same in every engine, and a
        // name that needs escaping is a name we should refuse to emit.
        if (leaf.IndexOfAny(profile.QuoteChars) >= 0)
            return null;

        return SafeIdentifierPattern.IsMatch(leaf) ? leaf : null;
    }

    /// <summary>
    /// Quotes an identifier already validated by <see cref="LeafIdentifier"/>.
    /// </summary>
    /// <remarks>
    /// Plain delimiting, with no escaping: <see cref="LeafIdentifier"/> has already declined
    /// any name carrying the profile's quote character, so there is nothing here to escape.
    /// That is deliberate — doubling the quote is exactly what connector-spec.md section 5.1
    /// rule 4 forbids, because a name that needs escaping is a name we should be refusing to
    /// emit.
    /// </remarks>
    private static string Quote(string identifier, DialectProfile profile)
        => $"{profile.QuoteOpen}{identifier}{profile.QuoteClose}";

    // -----------------------------------------------------------------------
    // Lightweight SQL structure scanning
    // -----------------------------------------------------------------------

    /// <summary>
    /// The offset and length of the statement's select list — everything between its
    /// top-level <c>SELECT</c> and its top-level <c>FROM</c>.
    /// </summary>
    private static (int Start, int Length)? FindSelectListSpan(string query)
    {
        var scan = new SqlScan(query);

        var select = scan.FirstTopLevel(SelectKeyword);
        if (select is null)
            return null;

        var listStart = select.Index + select.Length;

        var from = scan.FirstTopLevelAfter(FromKeyword, listStart);
        if (from is null)
            return null;

        // Keep the surrounding whitespace out of the span so a replacement does not have to
        // reproduce it.
        var start = listStart;
        while (start < from.Index && char.IsWhiteSpace(query[start])) start++;

        var end = from.Index;
        while (end > start && char.IsWhiteSpace(query[end - 1])) end--;

        return end <= start ? null : (start, end - start);
    }

    /// <summary>
    /// Splits a comma-separated list on the commas at parenthesis depth zero, so a function
    /// call's own arguments are not split apart.
    /// </summary>
    private static List<string> SplitTopLevel(string list)
    {
        var entries = new List<string>();
        var scan = new SqlScan(list);
        var current = new StringBuilder();

        for (var i = 0; i < list.Length; i++)
        {
            if (list[i] == ',' && scan.IsTopLevel(i))
            {
                entries.Add(current.ToString().Trim());
                current.Clear();
                continue;
            }
            current.Append(list[i]);
        }

        if (current.Length > 0)
            entries.Add(current.ToString().Trim());

        return entries;
    }

    /// <summary>
    /// The field name a select-list or clause entry refers to: alias and table qualifier
    /// removed, quotes stripped.
    /// </summary>
    private static string ExtractFieldName(string expression)
    {
        var expr = expression.Trim();

        var asIndex = expr.IndexOf(" AS ", StringComparison.OrdinalIgnoreCase);
        if (asIndex > 0)
            expr = expr[..asIndex].Trim();

        // Only a plain reference has a table qualifier to strip. Splitting a call expression on
        // its last dot yields a fragment of the expression rather than a field name --
        // "round(1.5)" would become "5)", which matches no policy field and made ValidateQuery
        // refuse an ordinary query. Fields inside a call are reached by
        // AddFieldsFromFunctionArguments instead.
        if (expr.Contains('(', StringComparison.Ordinal))
            return expr;

        var dotIndex = expr.LastIndexOf('.');
        if (dotIndex > 0)
            expr = expr[(dotIndex + 1)..].Trim();

        return expr.Trim('"', '\'', '`', ' ');
    }

    private void Diagnose(string message) => _diagnostics?.Invoke(message);

    /// <summary>
    /// A per-character map of a query's parenthesis depth and literal spans, so keyword
    /// matches can be restricted to the outermost statement.
    /// </summary>
    /// <remarks>
    /// Without this, a subquery donates the match that governs the outer statement: the
    /// <c>WHERE</c> in <c>SELECT * FROM t WHERE id IN (SELECT id FROM u WHERE x = 1)</c>
    /// would be found twice, and injecting into the wrong one filters the subquery instead of
    /// the result. String literals and quoted identifiers are skipped so that a parenthesis
    /// or the word <c>where</c> inside a literal changes nothing.
    /// </remarks>
    private readonly struct SqlScan
    {
        /// <summary>
        /// The scanned text, retained so a match's index and the depth map share one
        /// coordinate space.
        /// </summary>
        private readonly string _query;

        private readonly int[] _depth;
        private readonly bool[] _inLiteral;

        public SqlScan(string query)
        {
            _query = query;
            _depth = new int[query.Length];
            _inLiteral = new bool[query.Length];

            var depth = 0;
            var inString = false;
            var inQuotedIdentifier = false;

            for (var i = 0; i < query.Length; i++)
            {
                var c = query[i];

                if (inString)
                {
                    _inLiteral[i] = true;
                    _depth[i] = depth;
                    if (c == '\'')
                    {
                        // '' is an escaped quote, not the end of the literal.
                        if (i + 1 < query.Length && query[i + 1] == '\'') i++;
                        else inString = false;
                        if (i < query.Length) { _inLiteral[i] = true; _depth[i] = depth; }
                    }
                    continue;
                }

                if (inQuotedIdentifier)
                {
                    _inLiteral[i] = true;
                    _depth[i] = depth;
                    if (c == '"')
                    {
                        if (i + 1 < query.Length && query[i + 1] == '"') i++;
                        else inQuotedIdentifier = false;
                        if (i < query.Length) { _inLiteral[i] = true; _depth[i] = depth; }
                    }
                    continue;
                }

                switch (c)
                {
                    case '\'':
                        inString = true;
                        _inLiteral[i] = true;
                        break;
                    case '"':
                        inQuotedIdentifier = true;
                        _inLiteral[i] = true;
                        break;
                    case '(':
                        depth++;
                        break;
                    case ')':
                        // Guarded so an unbalanced query cannot drive the depth negative and
                        // make an inner keyword look top-level.
                        if (depth > 0) depth--;
                        break;
                }

                _depth[i] = depth;
            }
        }

        /// <summary>Whether the character at an offset is outside every paren and literal.</summary>
        public bool IsTopLevel(int index)
            => index >= 0 && index < _depth.Length && _depth[index] == 0 && !_inLiteral[index];

        /// <summary>The first match of a pattern at top level, or null.</summary>
        public Match? FirstTopLevel(Regex pattern) => FirstTopLevelAfter(pattern, 0);

        /// <summary>The first match of a pattern at top level at or after an offset, or null.</summary>
        public Match? FirstTopLevelAfter(Regex pattern, int startAt)
        {
            if (startAt >= _query.Length) return null;

            var match = pattern.Match(_query, startAt);
            while (match.Success)
            {
                if (IsTopLevel(match.Index))
                    return match;
                match = match.NextMatch();
            }
            return null;
        }

        /// <summary>The last match of a pattern at top level, or null.</summary>
        public Match? LastTopLevel(Regex pattern)
        {
            Match? found = null;
            var match = pattern.Match(_query);
            while (match.Success)
            {
                if (IsTopLevel(match.Index))
                    found = match;
                match = match.NextMatch();
            }
            return found;
        }
    }
}
