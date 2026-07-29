using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Tolap.Core;

/// <summary>
/// Result of an access validation check.
/// </summary>
public sealed record AccessResult(bool Allowed, string? Reason = null);

/// <summary>
/// Result of a field access validation check.
/// </summary>
public sealed record FieldAccessResult(string[] Allowed, string[] Denied);

/// <summary>
/// Thrown when a tool result cannot have policy applied to it.
/// </summary>
/// <remarks>
/// Derives from <see cref="UnauthorizedAccessException"/> so wrappers that already deny
/// on unauthorized access fail closed without special-casing this type.
/// </remarks>
public sealed class UnenforceableResultException : UnauthorizedAccessException
{
    public UnenforceableResultException(string message) : base(message) { }
}

/// <summary>
/// The classification of a tool result for enforcement purposes.
/// </summary>
public enum ResultShape
{
    /// <summary>A single record (a string-keyed map).</summary>
    Record,

    /// <summary>A materialized sequence of records.</summary>
    RecordList,

    /// <summary>
    /// A shape the policy cannot be applied to: a POCO/DTO, a scalar, a stream, or an
    /// unmaterialized iterator.
    /// </summary>
    Unenforceable
}

/// <summary>
/// Enforces TOLAP policies at the data-object level. Provides validation,
/// masking, filtering, field removal/projection, and result limiting.
/// </summary>
public static class EnforcementEngine
{
    /// <summary>
    /// Upper bound on a single regex evaluation. A ReDoS guard: an adversarial pattern
    /// or subject must not be able to stall the result pass (spec section 7).
    /// </summary>
    private static readonly TimeSpan RegexMatchTimeout = TimeSpan.FromMilliseconds(100);

    /// <summary>
    /// Validates whether access to an object is permitted under the given policy.
    /// Hidden objects are rejected first, then allowed objects are checked.
    /// </summary>
    public static AccessResult ValidateAccess(string objectName, EffectivePolicy policy)
    {
        var objectRules = policy.ObjectRules;

        // Check hidden objects first (they take precedence)
        if (objectRules?.HiddenObjects is not null)
        {
            foreach (var hidden in objectRules.HiddenObjects)
            {
                if (GlobMatch(hidden, objectName))
                    return new AccessResult(false, "object is hidden");
            }
        }

        // Check allowed objects (if specified, object must be in the set)
        if (objectRules?.AllowedObjects is not null)
        {
            var isAllowed = objectRules.AllowedObjects.Any(a => GlobMatch(a, objectName));
            if (!isAllowed)
                return new AccessResult(false, "object not in allowed set");
        }

        return new AccessResult(true);
    }

    /// <summary>
    /// Validates which fields are accessible under the given policy.
    /// Returns lists of allowed and denied fields.
    /// </summary>
    public static FieldAccessResult ValidateFieldAccess(string[] fields, EffectivePolicy policy)
    {
        var fieldRules = policy.ObjectRules?.FieldRules;

        var allowed = new List<string>();
        var denied = new List<string>();

        foreach (var field in fields)
        {
            // Check hidden fields first
            if (fieldRules?.HiddenFields is not null
                && fieldRules.HiddenFields.Any(h => GlobMatch(h, field)))
            {
                denied.Add(field);
                continue;
            }

            // Check allowed fields (if specified, field must be in the set)
            if (fieldRules?.AllowedFields is not null)
            {
                var isAllowed = fieldRules.AllowedFields.Any(a => GlobMatch(a, field));
                if (!isAllowed)
                {
                    denied.Add(field);
                    continue;
                }
            }

            allowed.Add(field);
        }

        return new FieldAccessResult(allowed.ToArray(), denied.ToArray());
    }

    // -- Field-name matching --
    //
    // A policy field reference and a record key may each be bare ("ssn") or
    // table-qualified ("patients.ssn"), and the two do not have to agree: the rule
    // "patients.ssn" must match a key "ssn" and the rule "ssn" must match a key
    // "patients.ssn". Matching is case-insensitive and glob patterns are honoured
    // (spec section 4).

    /// <summary>
    /// Every form a field reference may be compared in, lower-cased.
    /// </summary>
    /// <remarks>
    /// Unqualified forms of a qualified name are included so the two sides need not
    /// agree on qualification. This intentionally lets a table-scoped wildcard such as
    /// <c>patients.*</c> match a bare key: rows reaching the pipeline have already been
    /// projected by the tool, so the qualifier is implied by the result set rather than
    /// repeated on every key.
    /// </remarks>
    private static IEnumerable<string> MatchForms(string name)
    {
        var lowered = name.ToLowerInvariant();
        var forms = new HashSet<string>(StringComparer.Ordinal) { lowered };
        var firstDot = lowered.IndexOf('.');
        if (firstDot >= 0)
        {
            forms.Add(lowered[(firstDot + 1)..]);          // drop the leading qualifier
            forms.Add(lowered[(lowered.LastIndexOf('.') + 1)..]); // bare leaf
        }
        return forms;
    }

    /// <summary>
    /// Whether a policy field reference refers to a record key. Matching accepts bare and
    /// table-qualified forms in both directions, is case-insensitive, and honours globs.
    /// </summary>
    public static bool FieldNameMatches(string ruleField, string key)
    {
        foreach (var ruleForm in MatchForms(ruleField))
        {
            foreach (var keyForm in MatchForms(key))
            {
                if (GlobMatch(ruleForm, keyForm))
                    return true;
            }
        }
        return false;
    }

    /// <summary>
    /// Applies field masking rules to a data record.
    /// </summary>
    /// <remarks>
    /// Returns a copy; the caller's record is never mutated. Matching recurses into
    /// nested objects and arrays so a rule for "patient.ssn" also masks
    /// <c>{"patient": {"ssn": ...}}</c>.
    /// </remarks>
    public static Dictionary<string, object?> ApplyFieldMasking(
        Dictionary<string, object?> record,
        EffectivePolicy policy)
    {
        var maskedFields = policy.ObjectRules?.FieldRules?.MaskedFields;
        if (maskedFields is null || maskedFields.Length == 0)
            return new Dictionary<string, object?>(record);

        return (Dictionary<string, object?>)MaskNode(CloneNode(record), maskedFields)!;
    }

    /// <summary>
    /// The most restrictive masking rule matching a key, or null when none does.
    /// </summary>
    private static MaskingRule? RuleForKey(MaskingRule[] rules, string key)
    {
        MaskingRule? best = null;
        foreach (var rule in rules)
        {
            if (!FieldNameMatches(rule.Field, key)) continue;
            if (best is null || rule.MaskType.Restrictiveness() > best.MaskType.Restrictiveness())
                best = rule;
        }
        return best;
    }

    private static object? MaskNode(object? node, MaskingRule[] rules)
    {
        if (node is Dictionary<string, object?> dict)
        {
            foreach (var key in dict.Keys.ToList())
            {
                var rule = RuleForKey(rules, key);
                dict[key] = rule is not null
                    ? ApplyMask(dict[key], rule)
                    : MaskNode(dict[key], rules);
            }
            return dict;
        }

        if (node is List<object?> list)
        {
            for (var i = 0; i < list.Count; i++)
            {
                list[i] = MaskNode(list[i], rules);
            }
            return list;
        }

        return node;
    }

    /// <summary>
    /// Removes every hiddenFields entry from a record, recursing into nested structures.
    /// </summary>
    /// <remarks>
    /// Step 3 of the post-execution pipeline (spec section 4). A hidden field must never
    /// reach the agent, and a pre-execution field check cannot deliver that on its own:
    /// it only sees the fields a caller volunteered, so a tool that returns undeclared
    /// columns (<c>SELECT *</c>) would leak them. Returns a copy.
    /// </remarks>
    public static Dictionary<string, object?> StripHiddenFields(
        Dictionary<string, object?> record,
        EffectivePolicy policy)
    {
        var hidden = policy.ObjectRules?.FieldRules?.HiddenFields;
        if (hidden is null || hidden.Length == 0)
            return new Dictionary<string, object?>(record);

        return (Dictionary<string, object?>)DropNode(CloneNode(record), hidden)!;
    }

    /// <summary>
    /// Removes every hiddenFields entry from each record in a result set.
    /// </summary>
    public static IReadOnlyList<Dictionary<string, object?>> StripHiddenFields(
        IReadOnlyList<Dictionary<string, object?>> records,
        EffectivePolicy policy)
    {
        var hidden = policy.ObjectRules?.FieldRules?.HiddenFields;
        if (hidden is null || hidden.Length == 0)
            return records;

        return records.Select(r => StripHiddenFields(r, policy)).ToList();
    }

    /// <summary>
    /// Removes every hiddenFields entry from an arbitrary JSON node tree, in place.
    /// </summary>
    /// <remarks>
    /// The HTTP wrapper walks a mutable
    /// <c>Dictionary&lt;string, object?&gt;</c>/<c>List&lt;object?&gt;</c> tree rather
    /// than flat records; routing it through the same matcher keeps the HTTP and
    /// database/MCP paths from drifting.
    /// </remarks>
    public static object? StripHiddenFieldsFromTree(object? node, EffectivePolicy policy)
    {
        var hidden = policy.ObjectRules?.FieldRules?.HiddenFields;
        if (hidden is null || hidden.Length == 0)
            return node;

        return DropNode(node, hidden);
    }

    private static object? DropNode(object? node, string[] patterns)
    {
        if (node is Dictionary<string, object?> dict)
        {
            foreach (var key in dict.Keys.ToList())
            {
                if (patterns.Any(p => FieldNameMatches(p, key)))
                {
                    dict.Remove(key);
                    continue;
                }
                dict[key] = DropNode(dict[key], patterns);
            }
            return dict;
        }

        if (node is List<object?> list)
        {
            for (var i = 0; i < list.Count; i++)
            {
                list[i] = DropNode(list[i], patterns);
            }
            return list;
        }

        return node;
    }

    /// <summary>
    /// Projects a record down to allowedFields, dropping every other key.
    /// </summary>
    /// <remarks>
    /// Step 4 of the post-execution pipeline (spec section 4). When allowedFields is
    /// specified every other key is dropped, so a tool returning columns the policy
    /// never listed cannot disclose them. A null allow-list is unrestricted; an empty
    /// allow-list denies every field (spec section 3).
    /// </remarks>
    public static Dictionary<string, object?> ProjectAllowedFields(
        Dictionary<string, object?> record,
        EffectivePolicy policy)
    {
        var allowed = policy.ObjectRules?.FieldRules?.AllowedFields;
        if (allowed is null)
            return new Dictionary<string, object?>(record);

        var projected = new Dictionary<string, object?>();
        foreach (var (key, value) in record)
        {
            if (allowed.Any(a => FieldNameMatches(a, key)))
                projected[key] = value;
        }
        return projected;
    }

    /// <summary>
    /// Projects every record in a result set down to allowedFields.
    /// </summary>
    public static IReadOnlyList<Dictionary<string, object?>> ProjectAllowedFields(
        IReadOnlyList<Dictionary<string, object?>> records,
        EffectivePolicy policy)
    {
        if (policy.ObjectRules?.FieldRules?.AllowedFields is null)
            return records;

        return records.Select(r => ProjectAllowedFields(r, policy)).ToList();
    }

    /// <summary>
    /// Truncates a result set to the maxResults limit specified in the policy.
    /// </summary>
    public static IReadOnlyList<T> ApplyResultLimit<T>(IReadOnlyList<T> results, EffectivePolicy policy)
    {
        var maxResults = policy.Limits?.MaxResults;
        if (maxResults is null || results.Count <= maxResults.Value)
            return results;

        return results.Take(maxResults.Value).ToList();
    }

    /// <summary>
    /// Filters results by tag rules. Documents must have at least one allowed tag
    /// and must not have any denied tags.
    /// </summary>
    public static IReadOnlyList<Dictionary<string, object?>> FilterByTags(
        IReadOnlyList<Dictionary<string, object?>> results,
        EffectivePolicy policy)
    {
        var tagRules = policy.ObjectRules?.TagRules;
        if (tagRules is null)
            return results;

        var filtered = new List<Dictionary<string, object?>>();

        foreach (var result in results)
        {
            var tags = ExtractTags(result);

            // Check denied tags first (takes precedence)
            if (tagRules.DeniedTags is not null && tags.Any(t => tagRules.DeniedTags.Contains(t)))
                continue;

            // Check allowed tags (document must have at least one)
            if (tagRules.AllowedTags is not null && !tags.Any(t => tagRules.AllowedTags.Contains(t)))
                continue;

            filtered.Add(result);
        }

        return filtered;
    }

    // -- Result shapes --

    /// <summary>
    /// Classifies a tool result as a record, a materialized list of records, or a shape
    /// the policy cannot be applied to (spec section 5).
    /// </summary>
    public static ResultShape ClassifyResultShape(object? result)
    {
        if (result is Dictionary<string, object?>) return ResultShape.Record;
        if (result is IReadOnlyDictionary<string, object?>) return ResultShape.Record;

        // Only a materialized collection can be enforced: enumerating a lazy
        // IEnumerable here would be a side effect, and the caller could enumerate the
        // unfiltered original again.
        if (result is IReadOnlyList<Dictionary<string, object?>>) return ResultShape.RecordList;
        if (result is IReadOnlyList<object?> objectList
            && objectList.All(item => item is Dictionary<string, object?>))
        {
            return ResultShape.RecordList;
        }

        return ResultShape.Unenforceable;
    }

    /// <summary>
    /// A human-readable description of a result shape, for denial messages.
    /// </summary>
    public static string DescribeResultShape(object? result)
    {
        if (result is null) return "null";

        var typeName = result.GetType().Name;

        if (result is string) return $"{typeName} (scalar)";
        if (result is bool or sbyte or byte or short or ushort or int or uint
            or long or ulong or float or double or decimal)
        {
            return $"{typeName} (scalar)";
        }
        if (result is System.Text.Json.JsonElement je)
            return $"JsonElement ({je.ValueKind})";
        if (result is System.Collections.IEnumerable and not System.Collections.ICollection)
            return $"{typeName} (unmaterialized sequence)";
        if (result is System.Collections.IEnumerable enumerable)
        {
            var offenders = enumerable.Cast<object?>()
                .Where(item => item is not Dictionary<string, object?>)
                .Select(item => item?.GetType().Name ?? "null")
                .Distinct()
                .OrderBy(n => n, StringComparer.Ordinal)
                .ToArray();
            return offenders.Length > 0
                ? $"{typeName} containing {string.Join(", ", offenders)} (not records)"
                : $"{typeName} (list of records)";
        }

        return $"{typeName} (not a record or list of records)";
    }

    /// <summary>
    /// Runs the full post-execution enforcement pipeline over a tool result.
    /// </summary>
    /// <remarks>
    /// The canonical order (spec section 4), applied identically to a single record and
    /// to a list of records:
    /// <list type="number">
    ///   <item><description>row filters — drop rows the policy excludes</description></item>
    ///   <item><description>tag filters — drop records by allowedTags / deniedTags</description></item>
    ///   <item><description>hidden fields — remove hiddenFields from every record</description></item>
    ///   <item><description>allowed fields — project to allowedFields when specified</description></item>
    ///   <item><description>masking — apply maskedFields transformations</description></item>
    ///   <item><description>result limit — truncate to maxResults</description></item>
    /// </list>
    /// Hidden/allowed removal precedes masking so a field that is both hidden and masked
    /// is removed rather than returned in masked form, and the limit runs last so
    /// filtering never yields fewer rows than maxResults when more qualifying rows exist.
    /// </remarks>
    /// <exception cref="UnenforceableResultException">
    /// Thrown for a shape the policy cannot be applied to.
    /// </exception>
    public static object? ApplyResultPipeline(object? result, EffectivePolicy policy)
    {
        var shape = ClassifyResultShape(result);

        if (shape == ResultShape.Unenforceable)
        {
            throw new UnenforceableResultException(
                "Access denied: tool result shape cannot be policy-enforced: "
                + $"{DescribeResultShape(result)}. Return a Dictionary<string, object?> or an "
                + "IReadOnlyList<Dictionary<string, object?>>, or opt out explicitly with "
                + "AllowUnenforceableShapes = true.");
        }

        var records = shape == ResultShape.Record
            ? new List<Dictionary<string, object?>> { ToRecord(result!) }
            : ToRecordList(result!);

        var processed = ApplyRecordPipeline(records, policy);

        if (shape == ResultShape.Record)
        {
            // A single record the pipeline dropped is a denial, not an empty record:
            // returning {} would imply the row existed but had no fields.
            return processed.Count > 0 ? processed[0] : null;
        }

        return processed;
    }

    /// <summary>
    /// Runs the canonical eight-step pipeline over a materialized list of records.
    /// </summary>
    /// <remarks>
    /// Every record-dropping step precedes every field-level step, so no work is spent
    /// masking a record that is about to be discarded (spec section 4).
    /// </remarks>
    public static IReadOnlyList<Dictionary<string, object?>> ApplyRecordPipeline(
        IReadOnlyList<Dictionary<string, object?>> records,
        EffectivePolicy policy)
    {
        var working = ApplyRowFilters(records, policy);
        working = FilterByTags(working, policy);
        working = ApplySimilarityFloor(working, policy);
        working = ApplyObjectSizeCeiling(working, policy);
        working = StripHiddenFields(working, policy);
        working = ProjectAllowedFields(working, policy);
        working = working.Select(r => ApplyFieldMasking(r, policy)).ToList();
        return ApplyResultLimit(working, policy);
    }

    /// <summary>
    /// Field names carrying a similarity score, in precedence order. Covers the common
    /// vector-store response shapes (Bedrock KB, OpenSearch, pgvector wrappers).
    /// </summary>
    private static readonly string[] ScoreKeys = ["score", "similarity", "similarityscore", "_score"];

    /// <summary>
    /// Field names carrying an object size in bytes, in precedence order. Covers the
    /// common object-storage response shapes (S3, Azure Blob, GCS).
    /// </summary>
    private static readonly string[] SizeKeys = ["size", "sizebytes", "contentlength", "objectsize"];

    /// <summary>
    /// Reads the first present numeric field named by <paramref name="keys"/>,
    /// case-insensitively. Returns null when no key is present or the value is not a
    /// finite number; the caller treats null as "cannot establish this record's value",
    /// which fails closed.
    /// </summary>
    private static double? NumericField(Dictionary<string, object?> record, string[] keys)
    {
        foreach (var key in keys)
        {
            var match = record.Keys.FirstOrDefault(
                k => string.Equals(k, key, StringComparison.OrdinalIgnoreCase));
            if (match is null) continue;

            var value = record[match];
            return value switch
            {
                // bool is checked first: it must be a type error, not a passing 1.0.
                bool => null,
                sbyte or byte or short or ushort or int or uint or long or ulong
                    or float or double or decimal => Finite(Convert.ToDouble(value)),
                string s => double.TryParse(s.Trim(), out var parsed) ? Finite(parsed) : null,
                _ => null
            };
        }

        return null;

        static double? Finite(double candidate)
            => double.IsFinite(candidate) ? candidate : null;
    }

    /// <summary>
    /// Drops records scoring below <c>MinSimilarityScore</c> (spec section 4, step 3).
    /// </summary>
    /// <remarks>
    /// Fails closed: a record with no recognizable score field, or a non-numeric score,
    /// is dropped when a floor is set. A record whose relevance cannot be established
    /// cannot be shown to satisfy the floor, and the documented purpose of this limit is
    /// to stop low-relevance vector hits from surfacing sensitive content -- so an
    /// unscored record must not slip through. A score exactly equal to the floor is kept.
    /// </remarks>
    public static IReadOnlyList<Dictionary<string, object?>> ApplySimilarityFloor(
        IReadOnlyList<Dictionary<string, object?>> records,
        EffectivePolicy policy)
    {
        var floor = policy.Limits?.MinSimilarityScore;
        if (floor is null) return records;

        return records
            .Where(r => NumericField(r, ScoreKeys) is double score && score >= floor.Value)
            .ToList();
    }

    /// <summary>
    /// Drops records larger than <c>MaxObjectSizeBytes</c> (spec section 4, step 4).
    /// </summary>
    /// <remarks>
    /// Fails closed on the same reasoning as the relevance floor: a record with no
    /// recognizable size field, or a non-numeric size, is dropped when a ceiling is set.
    /// A size exactly equal to the ceiling is kept.
    /// </remarks>
    public static IReadOnlyList<Dictionary<string, object?>> ApplyObjectSizeCeiling(
        IReadOnlyList<Dictionary<string, object?>> records,
        EffectivePolicy policy)
    {
        var ceiling = policy.Limits?.MaxObjectSizeBytes;
        if (ceiling is null) return records;

        return records
            .Where(r => NumericField(r, SizeKeys) is double size && size <= ceiling.Value)
            .ToList();
    }

    private static Dictionary<string, object?> ToRecord(object result)
    {
        if (result is Dictionary<string, object?> dict) return dict;
        var readOnly = (IReadOnlyDictionary<string, object?>)result;
        return new Dictionary<string, object?>(readOnly);
    }

    private static IReadOnlyList<Dictionary<string, object?>> ToRecordList(object result)
    {
        if (result is IReadOnlyList<Dictionary<string, object?>> typed) return typed;
        return ((IReadOnlyList<object?>)result)
            .Select(item => (Dictionary<string, object?>)item!)
            .ToList();
    }

    /// <summary>
    /// Drops rows that fail any policy row filter (filters AND together).
    /// Most-restrictive-wins: a row must satisfy every filter to be kept. Rows
    /// missing the referenced field fail closed.
    /// </summary>
    public static IReadOnlyList<Dictionary<string, object?>> ApplyRowFilters(
        IReadOnlyList<Dictionary<string, object?>> results,
        EffectivePolicy policy)
    {
        var filters = policy.ObjectRules?.RowFilters;
        if (filters is null || filters.Length == 0)
            return results;

        var output = new List<Dictionary<string, object?>>(results.Count);
        foreach (var row in results)
        {
            if (filters.All(f => RowPassesFilter(row, f)))
                output.Add(row);
        }
        return output;
    }

    /// <summary>
    /// Sentinel distinguishing "field absent from the row" from "field present and null",
    /// so the former can fail closed while the latter stays comparable.
    /// </summary>
    private static readonly object Missing = new();

    private static object? RowFieldValue(Dictionary<string, object?> row, string fieldName)
    {
        if (row.TryGetValue(fieldName, out var v)) return v;
        foreach (var key in row.Keys)
        {
            if (FieldNameMatches(fieldName, key)) return row[key];
        }
        return Missing;
    }

    private static bool RowPassesFilter(Dictionary<string, object?> row, RowFilter rf)
    {
        var value = RowFieldValue(row, rf.Field);
        if (ReferenceEquals(value, Missing))
        {
            // Fail closed for every operator, including the negative ones (spec
            // section 7): a filter written to exclude classified rows must not retain
            // every row that simply lacks the column.
            return false;
        }

        switch (rf.Operator)
        {
            case FilterOperator.Equals:
                return ValuesEqual(value, rf.Value);
            case FilterOperator.NotEquals:
                return !ValuesEqual(value, rf.Value);
            case FilterOperator.In:
                if (rf.Values is null) return false;
                return rf.Values.Any(v => ValuesEqual(value, v));
            case FilterOperator.NotIn:
                if (rf.Values is null) return false;
                return !rf.Values.Any(v => ValuesEqual(value, v));
            case FilterOperator.GreaterThan:
                // A non-comparable operand pair is a non-match, never an exception
                // that aborts the whole result pass.
                return CompareNullable(value, rf.Value) is int g && g > 0;
            case FilterOperator.LessThan:
                return CompareNullable(value, rf.Value) is int l && l < 0;
            case FilterOperator.Contains:
                return value is not null && rf.Value is not null
                    && value.ToString()!.Contains(rf.Value.ToString()!);
            case FilterOperator.StartsWith:
                return value is not null && rf.Value is not null
                    && value.ToString()!.StartsWith(rf.Value.ToString()!);
            case FilterOperator.Matches:
                if (value is null || rf.Value is null) return false;
                return RegexMatches(rf.Value.ToString()!, value.ToString()!);
            case FilterOperator.GreaterThanOrEqual:
                return CompareNullable(value, rf.Value) is int ge && ge >= 0;
            case FilterOperator.LessThanOrEqual:
                return CompareNullable(value, rf.Value) is int le && le <= 0;
            case FilterOperator.Like:
                if (value is null || rf.Value is null) return false;
                return LikeMatches(rf.Value.ToString()!, value.ToString()!);
            case FilterOperator.NotLike:
                // A null field value is not "unlike" the pattern, it is incomparable:
                // SQL evaluates NULL NOT LIKE 'x' to NULL, which does not retain the row.
                // Returning true here would be the same fail-open bug spec section 7
                // records for notEquals/notIn on a missing field.
                if (value is null || rf.Value is null) return false;
                return !LikeMatches(rf.Value.ToString()!, value.ToString()!);
            case FilterOperator.IsNull:
                // The field is present (a missing field was already dropped above), so
                // this is the genuine "present and null" case.
                return Normalize(value) is null;
            case FilterOperator.IsNotNull:
                return Normalize(value) is not null;
            case FilterOperator.Between:
                return BetweenMatches(value, rf);
            default:
                return false;
        }
    }

    /// <summary>
    /// Evaluates an inclusive <c>between</c> range taken from the first two entries of
    /// <see cref="RowFilter.Values"/>.
    /// </summary>
    /// <remarks>
    /// Fails closed on a malformed range: fewer than two bounds, a null bound, or a bound
    /// that is not ordered against the row value all drop the row rather than admitting it.
    /// An inverted range (low &gt; high) matches nothing, exactly as SQL
    /// <c>BETWEEN 10 AND 1</c> does, and is not silently reordered — reordering would turn
    /// a policy author's typo into a wider grant than what was written.
    /// </remarks>
    private static bool BetweenMatches(object? value, RowFilter rf)
    {
        var bounds = rf.Values;
        if (bounds is null || bounds.Length < 2) return false;

        return CompareNullable(value, bounds[0]) is int lower && lower >= 0
               && CompareNullable(value, bounds[1]) is int upper && upper <= 0;
    }

    /// <summary>
    /// Matches a value against a SQL <c>LIKE</c> pattern: <c>%</c> matches any run of
    /// characters, <c>_</c> matches exactly one, and <c>\</c> escapes the next character.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Case-sensitive, matching Postgres <c>LIKE</c> (and unlike MySQL's default
    /// case-insensitive collation). The post-fetch path is the normative one, so an
    /// integrator pushing the same filter into MySQL may see MySQL match more rows than
    /// this does; the post-fetch pass then removes the extras, which is the fail-closed
    /// direction.
    /// </para>
    /// <para>
    /// Every non-wildcard character is <see cref="Regex.Escape(string)"/>d, so a pattern
    /// containing regex metacharacters (<c>.</c>, <c>(</c>, <c>|</c>) is treated literally and
    /// cannot be used to smuggle in a pathological regex. The translation can only emit
    /// <c>.*</c>, <c>.</c>, and escaped literals — no alternation, no backreferences, and no
    /// nested quantifiers — so it cannot express a catastrophically backtracking pattern, and
    /// unlike <c>matches</c> this operator does not need a length bound to be safe.
    /// </para>
    /// <para>
    /// The timeout is nonetheless applied and its catch retained, on the same reasoning as
    /// <see cref="GlobMatch"/>'s: it is currently unreachable, and it is what keeps a future
    /// change to the translation from turning a pathological pattern into an exception that
    /// aborts the whole result pass (spec section 7).
    /// </para>
    /// </remarks>
    private static bool LikeMatches(string pattern, string value)
    {
        var regex = new StringBuilder(pattern.Length * 2 + 4);
        regex.Append("^(?:");

        for (var i = 0; i < pattern.Length; i++)
        {
            var c = pattern[i];
            if (c == '\\' && i + 1 < pattern.Length)
            {
                // An escaped wildcard is a literal; consume both characters.
                regex.Append(Regex.Escape(pattern[++i].ToString()));
                continue;
            }
            regex.Append(c switch
            {
                '%' => ".*",
                '_' => ".",
                _ => Regex.Escape(c.ToString())
            });
        }

        regex.Append(")$");

        try
        {
            return Regex.IsMatch(value, regex.ToString(), RegexOptions.None, RegexMatchTimeout);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    /// <summary>
    /// Evaluates an anchored row-filter pattern under a bounded timeout.
    /// </summary>
    /// <remarks>
    /// The non-capturing group is required (spec section 7): <c>^hr|finance$</c> would
    /// otherwise bind <c>^</c> to <c>hr</c> alone and match "hr_secret_internal". A
    /// pattern error or a timeout is a non-match — the row is dropped — never an
    /// unhandled exception.
    /// </remarks>
    private static bool RegexMatches(string pattern, string value)
    {
        try
        {
            return Regex.IsMatch(value, $"^(?:{pattern})$", RegexOptions.None, RegexMatchTimeout);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static bool ValuesEqual(object? a, object? b)
    {
        a = Normalize(a);
        b = Normalize(b);
        if (a is null && b is null) return true;
        if (a is null || b is null) return false;

        // Booleans are not numbers: 1 != true (spec section 7).
        if (a is bool != b is bool) return false;

        if (a.Equals(b)) return true;
        // Cross-type numeric: scenarios JSON deserializes ints/longs/doubles
        // depending on parser; coerce to a common form for the comparison.
        if (IsNumeric(a) && IsNumeric(b))
        {
            return Convert.ToDouble(a) == Convert.ToDouble(b);
        }
        if (IsNumeric(a) != IsNumeric(b)) return a.ToString() == b.ToString();
        return a.ToString() == b.ToString();
    }

    private static int? CompareNullable(object? a, object? b)
    {
        a = Normalize(a);
        b = Normalize(b);
        if (a is null || b is null) return null;
        if (a is bool || b is bool) return null;
        if (IsNumeric(a) && IsNumeric(b))
        {
            return Convert.ToDouble(a).CompareTo(Convert.ToDouble(b));
        }
        if (IsNumeric(a) || IsNumeric(b))
        {
            // A number against a non-number (age="notanumber" vs 30) is not ordered.
            return null;
        }
        if (a is IComparable ca && a.GetType() == b.GetType())
        {
            try
            {
                return ca.CompareTo(b);
            }
            catch (ArgumentException)
            {
                // Reached only by an IComparable whose CompareTo rejects a same-typed
                // operand, which the BCL primitives never do. Kept because a row value can
                // be any CLR type a driver produces, and spec section 7 requires a
                // non-comparable pair to be a non-match rather than an exception that
                // aborts the result pass.
                return null;
            }
        }
        return null;
    }

    /// <summary>
    /// Unwrap System.Text.Json's JsonElement into a primitive type so cross-source
    /// comparisons (DB values vs. scenario JSON values) can use the same code path.
    /// </summary>
    private static object? Normalize(object? value)
    {
        if (value is System.Text.Json.JsonElement je)
        {
            return je.ValueKind switch
            {
                System.Text.Json.JsonValueKind.String => je.GetString(),
                System.Text.Json.JsonValueKind.Number => je.TryGetInt64(out var l) ? l : je.GetDouble(),
                System.Text.Json.JsonValueKind.True => true,
                System.Text.Json.JsonValueKind.False => false,
                System.Text.Json.JsonValueKind.Null => null,
                _ => je.ToString()
            };
        }
        return value;
    }

    private static bool IsNumeric(object value) =>
        value is sbyte or byte or short or ushort or int or uint or long or ulong or float or double or decimal;

    /// <summary>
    /// The methods that only read. Used twice: as the documented default for an omitted
    /// <c>allowedMethods</c>, and as the set <c>readOnly</c> permits.
    /// </summary>
    private static readonly string[] ReadMethods = { "GET", "HEAD", "OPTIONS" };

    /// <summary>
    /// Validates whether an endpoint and HTTP method are permitted under the given policy.
    /// </summary>
    /// <remarks>
    /// <para>Three restrictions apply, most-restrictive-first:</para>
    /// <list type="number">
    /// <item><c>hiddenEndpoints</c> then <c>allowedEndpoints</c> gate the path.</item>
    /// <item><c>readOnly</c> gates the method. When the permission is true, only
    /// GET/HEAD/OPTIONS are permitted — regardless of <c>allowedMethods</c>, because a
    /// policy that grants DELETE while declaring itself read-only is contradictory and the
    /// restrictive half must win (spec section 9). <c>readOnly</c> was previously merged
    /// (OR-folded, so any read-only policy in the set made the result read-only) and then
    /// never consulted, so the whole fold had no effect on any decision.</item>
    /// <item><c>allowedMethods</c> gates the method. When omitted it defaults to the read
    /// methods, as the schema documents ("If omitted, defaults to read-only methods: GET,
    /// HEAD, OPTIONS"). Treating omitted as unrestricted — the previous behavior — let
    /// POST/PUT/PATCH/DELETE through on a policy whose author had been told the default was
    /// read-only.</item>
    /// </list>
    /// <para><see cref="PolicyPermissions.ReadOnly"/> defaults to <c>true</c>, matching the
    /// schema default that spec section 8 requires be applied before folding, so a policy
    /// silent on <c>readOnly</c> is read-only.</para>
    /// </remarks>
    public static AccessResult ValidateEndpoint(string path, string method, EffectivePolicy policy)
    {
        // The top-level read gate applies here as it does to every other read. Omitting it
        // let a policy with canQuery=false still reach an API endpoint in .NET while Python
        // and TypeScript denied the same policy -- a fail-open on the broadest permission
        // there is, and a cross-SDK divergence for an identically signed policy.
        if (!policy.Permissions.CanQuery)
            return new AccessResult(false, "query not permitted");

        var endpointRules = policy.ObjectRules?.EndpointRules;

        if (endpointRules is not null)
        {
            // Check hidden endpoints first (takes precedence)
            if (endpointRules.HiddenEndpoints is not null)
            {
                foreach (var hidden in endpointRules.HiddenEndpoints)
                {
                    if (GlobMatch(hidden, path))
                        return new AccessResult(false, "endpoint is hidden");
                }
            }

            // Check allowed endpoints
            if (endpointRules.AllowedEndpoints is not null)
            {
                var isAllowed = endpointRules.AllowedEndpoints.Any(a => GlobMatch(a, path));
                if (!isAllowed)
                    return new AccessResult(false, "endpoint not in allowed set");
            }
        }

        // Check allowed methods. A null list is the documented read-only default, NOT
        // "unrestricted": spec section 9 makes this the single deliberate exception to
        // section 3's null-means-unrestricted rule, because an absent method list on an
        // endpoint rule is far likelier to be an oversight than an intentional grant of
        // DELETE. Do not "fix" this back to unrestricted for consistency with section 3.
        // An empty array still denies every method, per section 3.
        var permitted = endpointRules?.AllowedMethods ?? ReadMethods;
        if (!permitted.Contains(method, StringComparer.OrdinalIgnoreCase))
            return new AccessResult(false, "method not allowed");

        // readOnly is checked last so an explicit allowedMethods denial keeps its more
        // specific reason. A policy that lists DELETE in allowedMethods while declaring
        // itself read-only is contradictory, and the restrictive half wins.
        if (policy.Permissions.ReadOnly
            && !ReadMethods.Contains(method, StringComparer.OrdinalIgnoreCase))
        {
            return new AccessResult(false, "method not allowed on a read-only policy");
        }

        return new AccessResult(true);
    }

    /// <summary>
    /// Applies a masking rule to a single value.
    /// </summary>
    /// <remarks>
    /// Fails closed (spec section 6): an unrecognized mask type is treated as
    /// <c>redact</c> rather than returning the caller's original value, so a typo or a
    /// mask type from a newer schema version cannot silently disable masking.
    /// </remarks>
    public static object? ApplyMask(object? value, MaskingRule rule)
    {
        return rule.MaskType switch
        {
            MaskType.Null => null,
            MaskType.Redact => "[REDACTED]",
            MaskType.Full => ApplyFullMask(value, rule.Parameters),
            MaskType.Partial => ApplyPartialMask(value, rule.Parameters),
            MaskType.Hash => ApplyHashMask(value, rule.Parameters),
            _ => "[REDACTED]"
        };
    }

    private static string ApplyFullMask(object? value, MaskingParameters? parameters)
    {
        var str = value?.ToString() ?? "";
        var maskChar = parameters?.MaskChar ?? '*';
        return new string(maskChar, str.Length);
    }

    private static string ApplyPartialMask(object? value, MaskingParameters? parameters)
    {
        var str = value?.ToString() ?? "";
        var showFirst = parameters?.ShowFirst ?? 0;
        var showLast = parameters?.ShowLast ?? 0;
        var maskChar = parameters?.MaskChar ?? '*';

        // Showing the whole value is not masking; degrade to a full mask instead of
        // handing back the unmasked original (spec section 6).
        if (showFirst < 0 || showLast < 0 || showFirst + showLast >= str.Length)
            return new string(maskChar, str.Length);

        var sb = new StringBuilder(str.Length);

        // Show first N characters
        if (showFirst > 0)
            sb.Append(str[..showFirst]);

        // Mask middle characters
        var maskLength = str.Length - showFirst - showLast;
        sb.Append(new string(maskChar, maskLength));

        // Show last N characters
        if (showLast > 0)
            sb.Append(str[^showLast..]);

        return sb.ToString();
    }

    /// <summary>
    /// Hashes a value into a stable pseudonym: lower-case hex, first 16 characters.
    /// </summary>
    /// <remarks>
    /// The <c>algorithm</c> parameter is honoured, defaulting to <c>sha256</c> when absent
    /// (spec section 6). The hash mask exists to be a cross-service join key, so the digest
    /// must agree byte-for-byte with the Python and TypeScript SDKs; this previously
    /// hardcoded SHA-256 and ignored the parameter, so a policy asking for <c>sha512</c>
    /// produced a different pseudonym here than in TypeScript and every cross-service join
    /// on the masked column silently failed.
    /// <para>
    /// Only the three schema-permitted values are accepted, matched exactly. Resolving the
    /// parameter through a general algorithm lookup would accept anything the runtime
    /// offers (<c>md5</c> included) plus spellings the other SDKs reject, which is the same
    /// divergence in a new form. An unrecognized value fails closed as <c>redact</c>.
    /// </para>
    /// </remarks>
    private static string ApplyHashMask(object? value, MaskingParameters? parameters)
    {
        var str = value?.ToString() ?? "";
        var bytes = Encoding.UTF8.GetBytes(str);
        var algorithm = parameters?.Algorithm ?? "sha256";

        byte[] hash;
        switch (algorithm)
        {
            case "sha256":
                hash = SHA256.HashData(bytes);
                break;
            case "sha512":
                hash = SHA512.HashData(bytes);
                break;
            case "blake2b":
                hash = Blake2b512.HashData(bytes);
                break;
            default:
                // Unknown or unavailable: never disclose the original, and never
                // substitute a different algorithm -- a substituted digest looks like a
                // valid pseudonym while failing to join (spec section 6).
                return "[REDACTED]";
        }

        var hex = Convert.ToHexString(hash).ToLowerInvariant();
        return hex[..16];
    }

    /// <summary>
    /// Shallow-clones a node tree so pipeline steps never mutate the caller's records.
    /// </summary>
    private static object? CloneNode(object? node)
    {
        if (node is Dictionary<string, object?> dict)
        {
            var copy = new Dictionary<string, object?>(dict.Count);
            foreach (var (key, value) in dict)
            {
                copy[key] = CloneNode(value);
            }
            return copy;
        }

        if (node is List<object?> list)
        {
            return list.Select(CloneNode).ToList();
        }

        // Materialize other object collections into the mutable node shape so nested
        // masking/removal can reach records inside them. Strings and typed primitive
        // arrays (e.g. a "tags" string[]) hold no keys, so they are left alone.
        if (node is object[] array)
        {
            return array.Select(CloneNode).ToList();
        }

        if (node is IEnumerable<Dictionary<string, object?>> records)
        {
            return records.Select(r => CloneNode(r)).ToList();
        }

        return node;
    }

    private static string[] ExtractTags(Dictionary<string, object?> record)
    {
        if (!record.TryGetValue("tags", out var tagsObj) || tagsObj is null)
            return Array.Empty<string>();

        if (tagsObj is string[] strArray)
            return strArray;

        if (tagsObj is IEnumerable<object> enumerable)
            return enumerable.Select(o => o?.ToString() ?? "").ToArray();

        if (tagsObj is System.Text.Json.JsonElement jsonElement
            && jsonElement.ValueKind == System.Text.Json.JsonValueKind.Array)
        {
            return jsonElement.EnumerateArray()
                .Select(e => e.GetString() ?? "")
                .ToArray();
        }

        return Array.Empty<string>();
    }

    /// <summary>
    /// Performs glob pattern matching for object, field and endpoint names, where '*'
    /// matches any sequence of characters including path separators.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Evaluated under the same bounded timeout as row-filter regexes; a timeout is a
    /// non-match rather than an unhandled exception (spec section 7).
    /// </para>
    /// <para>
    /// <b>Deliberately different from <see cref="PolicyResolutionEngine.GlobMatch"/>,
    /// which must not be unified with this method.</b> Here <c>*</c> expands to
    /// <c>.*</c> so <c>/drug/*</c> reaches <c>/drug/event.json</c> and
    /// <c>patients.*</c> reaches a nested field — these names are not segmented into a
    /// fixed shape. <see cref="PolicyResolutionEngine.GlobMatch"/> expands <c>*</c> to
    /// <c>[^:]*</c> instead because a source-connection id is a colon-delimited triple
    /// and spec section 10 requires a wildcard to stay inside one segment. Adopting this
    /// method's semantics there would let a policy scoped to <c>db:*</c> govern every
    /// namespace under <c>db:</c>.
    /// </para>
    /// </remarks>
    internal static bool GlobMatch(string pattern, string value)
    {
        // Convert glob pattern to regex
        var regexPattern = "^" + Regex.Escape(pattern)
            .Replace("\\*", ".*")
            + "$";

        try
        {
            return Regex.IsMatch(value, regexPattern, RegexOptions.IgnoreCase, RegexMatchTimeout);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            // Defence in depth, and currently unreachable: the pattern is Regex.Escape'd
            // before '*' is expanded, so every glob compiles to a valid regex. Retained so
            // that a future change to the glob-to-regex translation cannot turn a malformed
            // pattern into an exception that aborts the whole result pass (spec section 7).
            return false;
        }
    }
}

/// <summary>
/// BLAKE2b-512 (RFC 7693), unkeyed, for the <c>blake2b</c> hash mask.
/// </summary>
/// <remarks>
/// Implemented here rather than taken from a package because
/// <see cref="System.Security.Cryptography"/> does not provide BLAKE2b (it offers SHA-3
/// and SHAKE, but not BLAKE2), and Tolap.Core ships zero runtime dependencies. The
/// alternative was to fail closed and redact every <c>blake2b</c> field, which the schema
/// permits and both other SDKs compute natively -- so .NET would have been the only SDK
/// unable to participate in a BLAKE2b join.
/// <para>
/// This is used for pseudonymisation, not authentication: the value is a stable join key,
/// never a MAC or a signature. Only the unkeyed 64-byte-digest variant is implemented,
/// which is what Node's <c>blake2b512</c> and Python's
/// <c>blake2b(digest_size=64)</c> compute. Verified against the RFC 7693 test vectors
/// and against both other SDKs, including the exact-128-byte block boundary and
/// multi-block inputs.
/// </para>
/// </remarks>
internal static class Blake2b512
{
    private const int BlockBytes = 128;
    private const int DigestBytes = 64;

    private static readonly ulong[] Iv =
    {
        0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL, 0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
        0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL, 0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL
    };

    /// <summary>Message-word permutation per round (RFC 7693 section 2.7).</summary>
    private static readonly byte[] Sigma =
    {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
        11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
        7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
        9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
        2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
        12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
        13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
        6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
        10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3
    };

    /// <summary>Computes the unkeyed BLAKE2b-512 digest of <paramref name="input"/>.</summary>
    internal static byte[] HashData(ReadOnlySpan<byte> input)
    {
        var h = (ulong[])Iv.Clone();
        // Parameter block byte 0: digest length; byte 2: fanout 1; byte 3: depth 1.
        h[0] ^= 0x01010000UL ^ DigestBytes;

        ulong counter = 0;
        var offset = 0;

        // Every full block except the last is compressed as non-final. The strict
        // inequality matters: an input that is an exact multiple of the block size must
        // leave its trailing block for the final call, not compress it here and then
        // finalize an empty one.
        while (input.Length - offset > BlockBytes)
        {
            counter += BlockBytes;
            Compress(h, input.Slice(offset, BlockBytes), counter, final: false);
            offset += BlockBytes;
        }

        // The final block is zero-padded; the counter still records only the real bytes.
        var remaining = input.Length - offset;
        Span<byte> lastBlock = stackalloc byte[BlockBytes];
        lastBlock.Clear();
        input.Slice(offset, remaining).CopyTo(lastBlock);
        counter += (ulong)remaining;
        Compress(h, lastBlock, counter, final: true);

        var digest = new byte[DigestBytes];
        for (var i = 0; i < 8; i++)
            BinaryPrimitives.WriteUInt64LittleEndian(digest.AsSpan(i * 8), h[i]);
        return digest;
    }

    private static void Compress(ulong[] h, ReadOnlySpan<byte> block, ulong counter, bool final)
    {
        Span<ulong> m = stackalloc ulong[16];
        for (var i = 0; i < 16; i++)
            m[i] = BinaryPrimitives.ReadUInt64LittleEndian(block.Slice(i * 8, 8));

        Span<ulong> v = stackalloc ulong[16];
        for (var i = 0; i < 8; i++)
        {
            v[i] = h[i];
            v[i + 8] = Iv[i];
        }

        v[12] ^= counter;
        // BLAKE2b supports a 128-bit counter; v[13] would take the high half. Inputs here
        // are field values, so 2^64 bytes is unreachable and the high half stays zero.
        if (final)
            v[14] = ~v[14];

        for (var round = 0; round < 12; round++)
        {
            var s = round * 16;
            Mix(v, 0, 4, 8, 12, m[Sigma[s + 0]], m[Sigma[s + 1]]);
            Mix(v, 1, 5, 9, 13, m[Sigma[s + 2]], m[Sigma[s + 3]]);
            Mix(v, 2, 6, 10, 14, m[Sigma[s + 4]], m[Sigma[s + 5]]);
            Mix(v, 3, 7, 11, 15, m[Sigma[s + 6]], m[Sigma[s + 7]]);
            Mix(v, 0, 5, 10, 15, m[Sigma[s + 8]], m[Sigma[s + 9]]);
            Mix(v, 1, 6, 11, 12, m[Sigma[s + 10]], m[Sigma[s + 11]]);
            Mix(v, 2, 7, 8, 13, m[Sigma[s + 12]], m[Sigma[s + 13]]);
            Mix(v, 3, 4, 9, 14, m[Sigma[s + 14]], m[Sigma[s + 15]]);
        }

        for (var i = 0; i < 8; i++)
            h[i] ^= v[i] ^ v[i + 8];
    }

    /// <summary>The G mixing function (RFC 7693 section 3.1).</summary>
    private static void Mix(Span<ulong> v, int a, int b, int c, int d, ulong x, ulong y)
    {
        v[a] = v[a] + v[b] + x;
        v[d] = BitOperations.RotateRight(v[d] ^ v[a], 32);
        v[c] += v[d];
        v[b] = BitOperations.RotateRight(v[b] ^ v[c], 24);
        v[a] = v[a] + v[b] + y;
        v[d] = BitOperations.RotateRight(v[d] ^ v[a], 16);
        v[c] += v[d];
        v[b] = BitOperations.RotateRight(v[b] ^ v[c], 63);
    }
}
