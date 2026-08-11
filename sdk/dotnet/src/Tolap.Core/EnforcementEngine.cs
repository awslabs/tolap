using System.Buffers.Binary;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
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
/// Optional inputs to <see cref="EnforcementEngine.ValidateWrite"/>.
/// </summary>
/// <param name="TargetRow">
/// The row an update or delete will modify. <c>null</c> means the caller supplied none,
/// which yields <c>write target unverifiable</c> when the policy carries row filters —
/// never an allow.
/// </param>
/// <param name="ResourceFields">
/// Fields of the resource the payload does not mention, for a full-resource replace.
/// Required alongside <paramref name="FullReplace"/> when the policy sets
/// <c>allowedFields</c>.
/// </param>
/// <param name="FullReplace">
/// Whether this write replaces the whole resource rather than the keys it names. An HTTP
/// <c>PUT</c> is the canonical case (connector-spec.md section 6).
/// </param>
public sealed record WriteValidationOptions(
    IReadOnlyDictionary<string, object?>? TargetRow = null,
    string[]? ResourceFields = null,
    bool FullReplace = false);

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
    /// <c>canQuery</c> is checked first, then hidden objects, then allowed objects.
    /// </summary>
    /// <remarks>
    /// The <c>canQuery</c> gate was missing here while Python's <c>validate_access</c> and
    /// TypeScript's <c>validateAccess</c> both had it, so a policy with <c>canQuery: false</c>
    /// had its object check <b>pass</b> in this SDK alone — a fail-open on the broadest
    /// permission there is, and a cross-SDK divergence for an identically signed policy. It
    /// went unnoticed because the MCP wrapper checks the gate separately before calling here;
    /// but this is public API, and a <c>storage</c> wrapper must call it directly to satisfy
    /// connector-spec §8's "validate the prefix before the provider call". Exactly the same
    /// omission was fixed in <see cref="ValidateEndpoint"/> earlier.
    /// </remarks>
    public static AccessResult ValidateAccess(string objectName, EffectivePolicy policy)
    {
        if (!policy.Permissions.CanQuery)
            return new AccessResult(false, "query not permitted");

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
        EffectivePolicy policy,
        string? hashSalt = null)
    {
        var maskedFields = policy.ObjectRules?.FieldRules?.MaskedFields;
        if (maskedFields is null || maskedFields.Length == 0)
            return new Dictionary<string, object?>(record);

        return (Dictionary<string, object?>)MaskNode(CloneNode(record), maskedFields, hashSalt)!;
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

    private static object? MaskNode(object? node, MaskingRule[] rules, string? hashSalt = null)
    {
        if (node is Dictionary<string, object?> dict)
        {
            foreach (var key in dict.Keys.ToList())
            {
                var rule = RuleForKey(rules, key);
                dict[key] = rule is not null
                    ? ApplyMask(dict[key], rule, hashSalt)
                    : MaskNode(dict[key], rules, hashSalt);
            }
            return dict;
        }

        if (node is List<object?> list)
        {
            for (var i = 0; i < list.Count; i++)
            {
                list[i] = MaskNode(list[i], rules, hashSalt);
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
    /// <remarks>
    /// A null <c>AllowedTags</c> is unrestricted; an empty one denies every record (spec
    /// section 3). A record with no recognizable tags is dropped under an allow-list — a
    /// classification that cannot be established cannot be shown to be permitted — and
    /// kept under a denylist alone, which gives no grounds to drop it. Denied takes
    /// precedence over allowed. Tags are read by <see cref="ExtractTags"/> and compared
    /// case-insensitively on both sides.
    /// </remarks>
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
            if (tagRules.DeniedTags is not null && tagRules.DeniedTags.Any(tags.Contains))
                continue;

            // Check allowed tags (document must have at least one)
            if (tagRules.AllowedTags is not null && !tagRules.AllowedTags.Any(tags.Contains))
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
    public static object? ApplyResultPipeline(
        object? result, EffectivePolicy policy, string? hashSalt = null)
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

        var processed = ApplyRecordPipeline(records, policy, hashSalt);

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
        EffectivePolicy policy,
        string? hashSalt = null)
    {
        var working = ApplyRowFilters(records, policy);
        working = FilterByTags(working, policy);
        working = ApplySimilarityFloor(working, policy);
        working = ApplyObjectSizeCeiling(working, policy);
        working = StripHiddenFields(working, policy);
        working = ProjectAllowedFields(working, policy);
        working = working.Select(r => ApplyFieldMasking(r, policy, hashSalt)).ToList();
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
            {
                // Normalize before the null test: a JSON null arrives as a JsonElement of
                // kind Null, which is NOT a CLR null, and whose ToString() is the empty
                // string. Testing `value is null` alone would compare the pattern against
                // "" instead of dropping the row, so `like '%'` would match a null-valued
                // row (spec section 7 says a null value is a non-match).
                var likeValue = Normalize(value);
                var likePattern = Normalize(rf.Value);
                if (likeValue is null || likePattern is null) return false;
                return LikeMatches(likePattern.ToString()!, likeValue.ToString()!);
            }
            case FilterOperator.NotLike:
            {
                // notLike is a negative operator and behaves exactly like NotEquals and
                // NotIn on a null value: the row is KEPT. Two separate rules meet here and
                // are deliberately not conflated.
                //
                // 1. Present-and-null is KEPT. This is what keeps the pushed-down form and
                //    this pass equivalent: the rewriter emits
                //    (col NOT LIKE 'x' OR col IS NULL) precisely because bare SQL
                //    NOT LIKE is unknown-therefore-false for a null col, so without the arm
                //    the database would drop a row this pass keeps (spec section 4).
                // 2. An ABSENT field was already dropped above. That is the unrelated
                //    fail-closed rule: a value that cannot be established cannot be shown
                //    to satisfy the filter (spec section 7). It applies to every operator.
                //
                // Normalize is load-bearing for the same reason as in Like above: a JSON
                // null is a JsonElement of kind Null, not a CLR null.
                var notLikeValue = Normalize(value);
                if (notLikeValue is null) return true;
                // A null pattern states no constraint any value can be shown to satisfy,
                // so it matches nothing -- as for Like.
                var notLikePattern = Normalize(rf.Value);
                if (notLikePattern is null) return false;
                return !LikeMatches(notLikePattern.ToString()!, notLikeValue.ToString()!);
            }
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

        // Cross-WIDTH numeric only: a JSON parser yields int/long/double for the same
        // literal depending on its size and the driver, so 30 and 30L and 30.0 are the
        // same value. InvariantCulture because ToDouble on a string is culture-sensitive
        // and a de-DE host would otherwise read "1.5" as 15.
        if (IsNumeric(a) && IsNumeric(b))
        {
            return Convert.ToDouble(a, CultureInfo.InvariantCulture)
                == Convert.ToDouble(b, CultureInfo.InvariantCulture);
        }

        // Cross-TYPE comparison is NOT equality. The former `a.ToString() == b.ToString()`
        // fallback made int 30 equal string "30" here while Python (`left == right`) and
        // TypeScript (`===`) both said false — so `equals` and `notEquals` returned
        // opposite verdicts across the SDKs for the identical policy and row, which is the
        // divergence class this codebase exists to prevent. It was also culture-sensitive:
        // (1.5).ToString() is "1,5" on a de-DE host, so a numeric filter silently stopped
        // matching depending on where the process ran.
        //
        // EnforcementBranchCoverageTests already states the rule in a comment — "coercing
        // them would make a policy's type discipline depend on the driver that produced the
        // row" — but its case used "thirty", which passes either way; the behaviour was
        // never pinned. It is now.
        return false;
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

    // -- Write validation (connector-spec.md section 4) --
    //
    // Reads filter what comes back. Writes have to be validated BEFORE they reach the
    // source, because there is nothing to filter afterwards -- the damage is already
    // committed. Everything below runs pre-execution and returns a decision the caller
    // must honour; nothing here talks to a data source.

    /// <summary>
    /// HTTP methods mapped to the write operation they perform (connector-spec.md
    /// section 6). <c>GET</c>/<c>HEAD</c>/<c>OPTIONS</c> are reads governed by
    /// <c>canQuery</c>, which <see cref="ValidateEndpoint"/> already enforces, so they are
    /// absent on purpose.
    /// </summary>
    private static readonly Dictionary<string, WriteOperation> MethodWriteOperations =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["POST"] = WriteOperation.Insert,
            ["PUT"] = WriteOperation.Update,
            ["PATCH"] = WriteOperation.Update,
            ["DELETE"] = WriteOperation.Delete
        };

    /// <summary>
    /// The write operation an HTTP method performs, or null for a read method.
    /// </summary>
    /// <remarks>
    /// <c>POST</c> inserts, <c>PUT</c>/<c>PATCH</c> update, <c>DELETE</c> deletes;
    /// <c>GET</c>/<c>HEAD</c>/<c>OPTIONS</c> return null because they are reads governed by
    /// <c>canQuery</c> (connector-spec.md section 6). An unrecognized method also returns
    /// null — it is not silently treated as a read: <see cref="ValidateEndpoint"/> still
    /// gates it through <c>allowedMethods</c>, whose omitted default is the read methods, so
    /// an unknown verb is denied there rather than admitted here.
    /// </remarks>
    public static WriteOperation? WriteOperationForMethod(string method)
        => MethodWriteOperations.TryGetValue(method, out var operation) ? operation : null;

    /// <summary>
    /// Validates a write before it reaches the data source (connector-spec.md section 4).
    /// </summary>
    /// <remarks>
    /// <para>Runs the four required pre-write checks in order — cheapest first, all of them
    /// mandatory:</para>
    /// <list type="number">
    ///   <item><description>the operation's permission
    ///     (<c>canInsert</c>/<c>canUpdate</c>/<c>canDelete</c>), then the <c>readOnly</c>
    ///     ceiling</description></item>
    ///   <item><description>the target object against
    ///     <c>hiddenObjects</c>/<c>allowedObjects</c></description></item>
    ///   <item><description>every field in the payload against <c>hiddenFields</c>,
    ///     <c>readOnlyFields</c> and <c>allowedFields</c></description></item>
    ///   <item><description>the policy's row filters against the update/delete target
    ///     row</description></item>
    /// </list>
    /// <para>
    /// Fails closed and rejects the whole write: one unwritable field denies the operation
    /// rather than being dropped so the rest can proceed (section 4.4). The reason strings
    /// are part of the contract — integrators log and branch on them.
    /// </para>
    /// <para>
    /// <see cref="WriteOperation.Upsert"/> — a call that cannot distinguish a create from an
    /// overwrite, such as an unconditional object-store <c>PUT</c> — requires <b>both</b>
    /// <c>canInsert</c> and <c>canUpdate</c> (section 8).
    /// </para>
    /// <para>
    /// A permitted write that returns data — <c>INSERT ... RETURNING</c>, a 201 body, updated
    /// metadata — is a <i>read</i> of that data, so run
    /// <see cref="ApplyResultPipeline"/> over the response (section 4.5). A masked field must
    /// come back masked even when the caller just wrote it.
    /// </para>
    /// </remarks>
    /// <param name="operation">The write being attempted.</param>
    /// <param name="objectName">
    /// The table, resource, or key being written, or null to skip the object check.
    /// </param>
    /// <param name="payload">
    /// The record being written. Its keys, at every depth, are the fields validated.
    /// </param>
    /// <param name="policy">The effective policy governing the write.</param>
    /// <param name="options">
    /// The target row, resource fields, and full-replace flag. Null selects the defaults,
    /// which means no target row is supplied.
    /// </param>
    public static AccessResult ValidateWrite(
        WriteOperation operation,
        string? objectName,
        object? payload,
        EffectivePolicy policy,
        WriteValidationOptions? options = null)
    {
        options ??= new WriteValidationOptions();

        var permission = ValidateWritePermission(operation, policy);
        if (!permission.Allowed) return permission;

        if (objectName is not null)
        {
            var target = ValidateWriteObject(objectName, policy);
            if (!target.Allowed) return target;
        }

        var written = PayloadWriteFields(payload, options.ResourceFields);
        if (options.FullReplace)
        {
            foreach (var name in ProtectedFieldNames(policy))
            {
                if (!written.Contains(name)) written.Add(name);
            }
        }

        var fields = ValidateWrittenFields(written, policy);
        if (!fields.Allowed) return fields;

        return ValidateWriteTargetRow(operation, options.TargetRow, policy);
    }

    /// <summary>
    /// Validates an HTTP write: endpoint rules, then the section 4 write checks.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Method and permission must agree and <b>both</b> are checked (connector-spec.md
    /// section 6): <see cref="ValidateEndpoint"/> gates the path and the method through
    /// <c>allowedEndpoints</c>/<c>hiddenEndpoints</c>/<c>allowedMethods</c>, and the write
    /// checks then gate the operation the method performs and the body it carries. Neither
    /// substitutes for the other — <c>allowedMethods: ["POST"]</c> says nothing about
    /// <c>canInsert</c>, and <c>canInsert</c> says nothing about which paths are reachable.
    /// </para>
    /// <para>
    /// A read method (<c>GET</c>/<c>HEAD</c>/<c>OPTIONS</c>) is not a write, so this returns
    /// the endpoint decision unchanged rather than inventing a write permission for it.
    /// </para>
    /// <para>
    /// A <c>PUT</c> is treated as a <b>full-resource replace</b> (section 6): every field the
    /// policy protects is validated as though the body had named it, because a replace that
    /// omits a <c>readOnlyFields</c> field is still attempting to overwrite it with absent.
    /// <c>PATCH</c> is a partial update, so only the keys present are validated. Supply
    /// <see cref="WriteValidationOptions.ResourceFields"/> to extend the replace to fields the
    /// policy does not itself name — needed when <c>allowedFields</c> is set, since a resource
    /// field missing from an allow-list cannot be inferred from the policy alone.
    /// </para>
    /// </remarks>
    public static AccessResult ValidateHttpWrite(
        string method,
        string path,
        object? payload,
        EffectivePolicy policy,
        string? objectName = null,
        WriteValidationOptions? options = null)
    {
        var endpoint = ValidateEndpoint(path, method, policy);
        if (!endpoint.Allowed) return endpoint;

        var operation = WriteOperationForMethod(method);
        if (operation is null) return endpoint;

        options ??= new WriteValidationOptions();
        return ValidateWrite(
            operation.Value,
            objectName,
            payload,
            policy,
            options with { FullReplace = string.Equals(method, "PUT", StringComparison.OrdinalIgnoreCase) });
    }

    /// <summary>
    /// Check 1: the operation's permission, then the <c>readOnly</c> ceiling.
    /// </summary>
    /// <remarks>
    /// An absent write permission is a denial: the schema default for all three is
    /// <c>false</c> (connector-spec.md section 4.1), the opposite of <c>canQuery</c>. The
    /// asymmetry is the point — a policy authored before writes existed must not silently
    /// acquire them.
    /// </remarks>
    private static AccessResult ValidateWritePermission(
        WriteOperation operation,
        EffectivePolicy policy)
    {
        var permissions = policy.Permissions;

        // Upsert consults both, which is the safe intersection connector-spec.md section 8
        // mandates for a call that cannot distinguish a create from an overwrite.
        if (operation is WriteOperation.Insert or WriteOperation.Upsert
            && permissions.CanInsert != true)
        {
            return new AccessResult(false, "insert not permitted");
        }

        if (operation is WriteOperation.Update or WriteOperation.Upsert
            && permissions.CanUpdate != true)
        {
            return new AccessResult(false, "update not permitted");
        }

        if (operation is WriteOperation.Delete && permissions.CanDelete != true)
        {
            return new AccessResult(false, "delete not permitted");
        }

        // readOnly is a ceiling, not a peer: it denies every write regardless of the three
        // flags. It defaults to true, matching the schema default that spec section 8
        // requires be applied before folding, so a policy silent on readOnly cannot write.
        if (permissions.ReadOnly)
        {
            return new AccessResult(false, "read-only policy");
        }

        return new AccessResult(true);
    }

    /// <summary>
    /// Check 2: the target object against <c>hiddenObjects</c>/<c>allowedObjects</c>.
    /// </summary>
    /// <remarks>
    /// Deliberately not <see cref="ValidateAccess"/>: that method is the read-path entry
    /// point and would be the wrong gate to lean on if it ever grows a <c>canQuery</c> check
    /// like its Python and TypeScript counterparts. The object rules themselves are
    /// identical, and the reasons stay the ones connector-spec.md section 3.3 documents.
    /// </remarks>
    private static AccessResult ValidateWriteObject(string objectName, EffectivePolicy policy)
    {
        var objectRules = policy.ObjectRules;

        if (objectRules?.HiddenObjects is not null)
        {
            foreach (var hidden in objectRules.HiddenObjects)
            {
                if (GlobMatch(hidden, objectName))
                    return new AccessResult(false, "object is hidden");
            }
        }

        if (objectRules?.AllowedObjects is not null
            && !objectRules.AllowedObjects.Any(a => GlobMatch(a, objectName)))
        {
            return new AccessResult(false, "object not in allowed set");
        }

        return new AccessResult(true);
    }

    /// <summary>
    /// Check 3: every field in the payload must be writable.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Fails closed on the <i>whole</i> write (connector-spec.md section 4.4): the first
    /// unwritable field denies the entire operation rather than being stripped so the rest
    /// can proceed. This is the one place where filtering — the correct answer on the read
    /// path — is the wrong answer. A caller that submits <c>{status, ssn}</c> and is told the
    /// write succeeded, when only <c>status</c> landed, holds a model of the data that is
    /// wrong in a way it cannot detect.
    /// </para>
    /// <para>
    /// Field names match with the bidirectional, case-insensitive, glob-aware matcher the
    /// read path uses (section 3.2), so a <c>readOnlyFields</c> entry of
    /// <c>patients.created_at</c> blocks a payload key of <c>created_at</c>.
    /// </para>
    /// <para>
    /// The field is named in the reason. That discloses nothing: the caller supplied it. Row
    /// denials, by contrast, never name a value.
    /// </para>
    /// </remarks>
    private static AccessResult ValidateWrittenFields(
        IReadOnlyList<string> fields,
        EffectivePolicy policy)
    {
        var fieldRules = policy.ObjectRules?.FieldRules;
        if (fieldRules is null) return new AccessResult(true);

        foreach (var name in fields)
        {
            // A field the caller cannot read, it cannot write.
            if (fieldRules.HiddenFields is not null
                && fieldRules.HiddenFields.Any(p => FieldNameMatches(p, name)))
            {
                return new AccessResult(false, $"field is hidden: {name}");
            }

            // readOnlyFields: readable but not writable. This is the whole meaning of the
            // field (connector-spec.md section 4.3) and it has no effect on reads.
            if (fieldRules.ReadOnlyFields is not null
                && fieldRules.ReadOnlyFields.Any(p => FieldNameMatches(p, name)))
            {
                return new AccessResult(false, $"field is read-only: {name}");
            }

            // A null allow-list is unrestricted; an empty one denies every field (spec
            // section 3), so this tests for null rather than for emptiness.
            if (fieldRules.AllowedFields is not null
                && !fieldRules.AllowedFields.Any(p => FieldNameMatches(p, name)))
            {
                return new AccessResult(false, $"field not in allowed set: {name}");
            }
        }

        return new AccessResult(true);
    }

    /// <summary>
    /// Check 4: row filters must match the row an update or delete targets.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A caller must not be able to modify a row it could not have selected, so the policy's
    /// row filters are evaluated against the target and a non-match is
    /// <c>target row not permitted</c>.
    /// </para>
    /// <para>
    /// When filters exist and no target row was supplied, the result is
    /// <c>write target unverifiable</c> — <b>not</b> an allow. The integrator's options are to
    /// read the row first and pass it here, or to push the filters into the statement's
    /// <c>WHERE</c> so the source applies them; an unqualified <c>DELETE FROM patients</c>
    /// under a region-scoped policy has to be refused rather than executed and hoped over
    /// (connector-spec.md sections 4.2 and 5).
    /// </para>
    /// <para>
    /// An insert has no pre-existing target, so this check does not apply to it. The row it
    /// <i>creates</i> is governed by the field checks above: a policy scoped by <c>region</c>
    /// cannot stop an insert writing a foreign region unless <c>region</c> is in
    /// <c>readOnlyFields</c> or outside <c>allowedFields</c>, which is a gap in the policy
    /// language rather than in this implementation.
    /// </para>
    /// </remarks>
    private static AccessResult ValidateWriteTargetRow(
        WriteOperation operation,
        IReadOnlyDictionary<string, object?>? targetRow,
        EffectivePolicy policy)
    {
        if (operation == WriteOperation.Insert) return new AccessResult(true);

        var filters = policy.ObjectRules?.RowFilters;
        if (filters is null || filters.Length == 0) return new AccessResult(true);

        if (targetRow is null)
        {
            return new AccessResult(false, "write target unverifiable");
        }

        // The row must satisfy every filter, exactly as it would to be returned by a read
        // (spec section 7): a missing field fails closed.
        var row = targetRow as Dictionary<string, object?>
                  ?? new Dictionary<string, object?>(targetRow);
        if (!filters.All(f => RowPassesFilter(row, f)))
        {
            // Deliberately does not name the field or the value; section 4.4 permits naming
            // a payload field the caller supplied, never a row value.
            return new AccessResult(false, "target row not permitted");
        }

        return new AccessResult(true);
    }

    /// <summary>
    /// The field names a payload attempts to write.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Nested keys are <b>not</b> flattened into dotted paths: the field matcher already
    /// reaches a bare <c>ssn</c> from a rule of <c>patients.ssn</c> and vice versa
    /// (section 3.2), so walking the tree and collecting every key at every depth is what a
    /// rule needs to see.
    /// </para>
    /// <para>
    /// Four payload shapes are enumerated: a string-keyed dictionary, a
    /// <see cref="System.Text.Json.JsonElement"/>, a sequence of any of these, and — via
    /// reflection over public readable instance properties — a POCO or anonymous type. The
    /// last arm exists because <see cref="Tolap.Mcp"/>'s HTTP wrapper takes an
    /// <c>object?</c> body and integrators naturally pass
    /// <c>new { full_name = "..." }</c>. Without it a POCO body would contribute no field
    /// names at all and every field rule would silently pass — a fail-open on the write path,
    /// where there is nothing to filter afterwards.
    /// </para>
    /// <para>
    /// <paramref name="resourceFields"/> extends the set with fields the payload does not
    /// mention. It exists for the full-resource-replace rule (see
    /// <see cref="WriteValidationOptions.FullReplace"/>); it is deliberately not inferred
    /// from anything, because only the integrator knows a resource's shape.
    /// </para>
    /// </remarks>
    public static List<string> PayloadWriteFields(
        object? payload,
        string[]? resourceFields = null)
    {
        var names = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        // Guards against a cyclic object graph, which reflection can reach even though JSON
        // cannot. Reference identity, so two equal-but-distinct records are both walked.
        var visited = new HashSet<object>(ReferenceEqualityComparer.Instance);

        void Add(string name)
        {
            if (seen.Add(name)) names.Add(name);
        }

        void Walk(object? node)
        {
            switch (node)
            {
                case null:
                    return;
                case IReadOnlyDictionary<string, object?> record:
                    if (!visited.Add(record)) return;
                    foreach (var (key, value) in record)
                    {
                        Add(key);
                        Walk(value);
                    }
                    return;
                case System.Text.Json.JsonElement element:
                    WalkJson(element);
                    return;
                case string:
                    // A string is IEnumerable; without this arm it would be walked
                    // character by character to no purpose.
                    return;
                case System.Collections.IEnumerable sequence:
                    if (!visited.Add(sequence)) return;
                    foreach (var item in sequence) Walk(item);
                    return;
                default:
                    WalkProperties(node);
                    return;
            }
        }

        void WalkProperties(object node)
        {
            var type = node.GetType();
            // A primitive or value-like leaf names no fields. Checked before the visited
            // guard because boxing means every int would otherwise consume a slot.
            if (type.IsPrimitive || node is decimal or DateTime or DateTimeOffset
                or TimeSpan or Guid || type.IsEnum)
            {
                return;
            }
            if (!visited.Add(node)) return;

            foreach (var property in type.GetProperties(
                System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance))
            {
                if (!property.CanRead || property.GetIndexParameters().Length > 0) continue;
                Add(property.Name);

                object? value;
                try
                {
                    value = property.GetValue(node);
                }
                catch (System.Reflection.TargetInvocationException)
                {
                    // A throwing getter names its field either way -- the name is what a rule
                    // matches on -- so the property is already recorded above. Swallowed
                    // rather than propagated because a write must be denied or allowed on
                    // policy grounds, never crash on the shape of the caller's DTO.
                    continue;
                }
                Walk(value);
            }
        }

        void WalkJson(System.Text.Json.JsonElement element)
        {
            switch (element.ValueKind)
            {
                case System.Text.Json.JsonValueKind.Object:
                    foreach (var property in element.EnumerateObject())
                    {
                        Add(property.Name);
                        WalkJson(property.Value);
                    }
                    return;
                case System.Text.Json.JsonValueKind.Array:
                    foreach (var item in element.EnumerateArray()) WalkJson(item);
                    return;
            }
        }

        Walk(payload);

        if (resourceFields is not null)
        {
            foreach (var name in resourceFields) Add(name);
        }

        return names;
    }

    /// <summary>
    /// Every field the policy forbids writing, as written in the policy.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Used to give the full-resource-replace rule (connector-spec.md section 6) teeth when
    /// the caller cannot enumerate the resource: a replace writes every field of the
    /// resource, and the fields whose overwrite must be denied are exactly the ones the
    /// policy protects, so treating them as present is the fail-closed reading. It is
    /// <i>not</i> an approximation of the resource's shape — it is the subset of any
    /// resource's shape that the policy cares about.
    /// </para>
    /// <para>
    /// <c>allowedFields</c> cannot be handled this way: the risk there is a resource field
    /// the allow-list omits, which is unknowable without the resource's field list. An
    /// integrator combining <c>allowedFields</c> with full-resource replaces must pass
    /// <see cref="WriteValidationOptions.ResourceFields"/>.
    /// </para>
    /// </remarks>
    private static IEnumerable<string> ProtectedFieldNames(EffectivePolicy policy)
    {
        var fieldRules = policy.ObjectRules?.FieldRules;
        if (fieldRules is null) return Array.Empty<string>();

        return (fieldRules.HiddenFields ?? Array.Empty<string>())
            .Concat(fieldRules.ReadOnlyFields ?? Array.Empty<string>());
    }

    /// <summary>
    /// Applies a masking rule to a single value.
    /// </summary>
    /// <remarks>
    /// Fails closed (spec section 6): an unrecognized mask type is treated as
    /// <c>redact</c> rather than returning the caller's original value, so a typo or a
    /// mask type from a newer schema version cannot silently disable masking.
    /// </remarks>
    public static object? ApplyMask(object? value, MaskingRule rule, string? hashSalt = null)
    {
        return rule.MaskType switch
        {
            MaskType.Null => null,
            MaskType.Redact => "[REDACTED]",
            MaskType.Full => ApplyFullMask(value, rule.Parameters),
            MaskType.Partial => ApplyPartialMask(value, rule.Parameters),
            MaskType.Hash => ApplyHashMask(value, rule.Parameters, hashSalt),
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
    private static string ApplyHashMask(
        object? value, MaskingParameters? parameters, string? hashSalt = null)
    {
        var str = value?.ToString() ?? "";
        var bytes = Encoding.UTF8.GetBytes(str);
        var algorithm = parameters?.Algorithm ?? "sha256";

        // Salted (keyed) form: HMAC over the value. An unsalted digest of a low-entropy
        // value (SSN, DOB, small enumeration) is recoverable by brute force or a rainbow
        // table, so the salt is what makes `hash` a confidentiality control rather than
        // only a pseudonym. The join-key property survives because the same salt yields
        // the same pseudonym everywhere -- which is also why the salt is a
        // deployment-wide secret and not a per-policy field.
        var salted = !string.IsNullOrEmpty(hashSalt);
        var saltBytes = salted ? Encoding.UTF8.GetBytes(hashSalt!) : Array.Empty<byte>();

        byte[] hash;
        switch (algorithm)
        {
            case "sha256":
                hash = salted ? HMACSHA256.HashData(saltBytes, bytes) : SHA256.HashData(bytes);
                break;
            case "sha512":
                hash = salted ? HMACSHA512.HashData(saltBytes, bytes) : SHA512.HashData(bytes);
                break;
            case "blake2b":
                hash = salted
                    ? Blake2b512.HashKeyed(saltBytes, bytes)
                    : Blake2b512.HashData(bytes);
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

    // -- Tag extraction --
    //
    // A classification level *is* a tag: there is no separate classification construct,
    // so tag filtering is the whole knowledge-base confidentiality control
    // (connector-spec.md section 7). Extraction therefore has to be as robust as masking
    // already is. A literal lower-case "tags" TryGetValue enforced the control on exactly
    // one of the five shapes real providers emit -- "tags", "Tags", "metadata.tags",
    // "labels", and a scalar "classification" -- so four of five records tagged "secret"
    // were disclosed.

    /// <summary>
    /// The record keys that carry classification tags, matched with
    /// <see cref="FieldNameMatches"/> rather than looked up literally.
    /// </summary>
    /// <remarks>
    /// The set is deliberately small, fixed, and not configurable. Every entry is a shape
    /// connector spec section 7 names; nothing is added on speculation, because widening
    /// the set is not automatically safer in either direction. An unrelated
    /// <c>labels</c> field whose value happens to appear in <c>allowedTags</c> would
    /// <i>admit</i> a record the allow-list would otherwise have dropped as untagged, so
    /// an over-broad set can fail open exactly as a too-narrow one fails to enforce. It is
    /// not an integrator-supplied parameter for the same reason: the policy is signed, and
    /// an unsigned knob deciding which keys count as security metadata would put part of
    /// the decision outside the signature.
    /// </remarks>
    private static readonly string[] TagKeys = { "tags", "labels", "classification" };

    /// <summary>
    /// Every tag on a record, from any recognized tag key at any depth.
    /// </summary>
    /// <remarks>
    /// The set is <see cref="StringComparer.OrdinalIgnoreCase"/> because tag values
    /// compare case-insensitively: <c>deniedTags: ["Secret"]</c> must drop a record tagged
    /// <c>secret</c> (connector spec section 7).
    /// </remarks>
    private static HashSet<string> ExtractTags(Dictionary<string, object?> record)
    {
        var tags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        CollectTags(record, tags);
        return tags;
    }

    /// <summary>
    /// Collects tags from every recognized tag key anywhere in a node tree.
    /// </summary>
    /// <remarks>
    /// Recurses into nested maps and lists, matching keys with the same bidirectional,
    /// case-insensitive, glob-aware matcher masking and hidden-field removal use (spec
    /// section 4), so <c>Tags</c> and <c>metadata.tags</c> are found alongside
    /// <c>tags</c>.
    /// </remarks>
    private static void CollectTags(object? node, HashSet<string> into)
    {
        if (node is Dictionary<string, object?> dict)
        {
            foreach (var (key, value) in dict)
            {
                if (TagKeys.Any(tagKey => FieldNameMatches(tagKey, key)))
                    HarvestTagValues(value, into);
                // Walked whether or not the key matched: a matched key holding a map may
                // still nest a tag key of its own.
                CollectTags(value, into);
            }
            return;
        }

        if (node is JsonElement element)
        {
            if (element.ValueKind == JsonValueKind.Object)
            {
                foreach (var property in element.EnumerateObject())
                {
                    if (TagKeys.Any(tagKey => FieldNameMatches(tagKey, property.Name)))
                        HarvestTagValues(property.Value, into);
                    CollectTags(property.Value, into);
                }
            }
            else if (element.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in element.EnumerateArray())
                    CollectTags(item, into);
            }
            return;
        }

        // A string is a leaf, not a character sequence to walk. Every other enumerable
        // -- List<object?>, object[], string[], a materialized record sequence -- may
        // hold records that nest a tag key.
        if (node is string) return;
        if (node is System.Collections.IEnumerable enumerable)
        {
            foreach (var item in enumerable)
                CollectTags(item, into);
        }
    }

    /// <summary>
    /// Collects the tag strings carried by a matched tag key's value.
    /// </summary>
    /// <remarks>
    /// A scalar counts as a single tag: providers emit both <c>{"tags": ["secret"]}</c>
    /// and <c>{"classification": "secret"}</c>, and connector spec section 7 requires the
    /// two to behave identically. Nested arrays are flattened.
    /// <para>
    /// Only strings are collected. <c>allowedTags</c>/<c>deniedTags</c> are arrays of
    /// strings in the schema, so a non-string value could only match after a
    /// stringification whose result differs per language (<c>true.ToString()</c> is
    /// <c>"True"</c> here and <c>"true"</c> in JavaScript) -- and a confidentiality
    /// decision must not depend on the host language's formatting. A non-string value
    /// still fails closed under an allow-list, because it contributes no tag and therefore
    /// no proof of allowance.
    /// </para>
    /// </remarks>
    private static void HarvestTagValues(object? value, HashSet<string> into)
    {
        if (value is string str)
        {
            into.Add(str);
            return;
        }

        if (value is JsonElement element)
        {
            if (element.ValueKind == JsonValueKind.String)
            {
                into.Add(element.GetString()!);
            }
            else if (element.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in element.EnumerateArray())
                    HarvestTagValues(item, into);
            }
            return;
        }

        if (value is System.Collections.IEnumerable enumerable)
        {
            foreach (var item in enumerable)
                HarvestTagValues(item, into);
        }
    }

    /// <summary>
    /// Performs glob pattern matching for object, field and endpoint names, where '*'
    /// matches any sequence of characters including path separators and '?' matches
    /// exactly one character.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Evaluated under the same bounded timeout as row-filter regexes; a timeout is a
    /// non-match rather than an unhandled exception (spec section 7).
    /// </para>
    /// <para>
    /// <c>*</c> and <c>?</c> are the only metacharacters (spec section 3.1). Everything
    /// else is <see cref="Regex.Escape(string)"/>d and therefore literal — including
    /// <c>[abc]</c>, which is the four-character text <c>[abc]</c> and not a character
    /// class. Python's <c>fnmatch</c> reads brackets as classes and had to be corrected
    /// to match; this engine has always escaped them, so no change was needed here. The
    /// <c>?</c> wildcard, on the other hand, was previously escaped to a literal — the
    /// divergence this method's <c>\?</c> → <c>.</c> replacement now closes.
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
        // Convert glob pattern to regex. Regex.Escape turns '*' into '\*' and '?' into
        // '\?', so the wildcards are recovered from their escaped forms; every other
        // character stays escaped and therefore literal.
        var regexPattern = "^" + Regex.Escape(pattern)
            .Replace("\\*", ".*")
            .Replace("\\?", ".")
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

    /// <summary>
    /// Computes HMAC-BLAKE2b-512 (RFC 2104 construction) over <paramref name="input"/>.
    /// </summary>
    /// <remarks>
    /// <para>Deliberately the generic HMAC construction rather than BLAKE2b's own keyed
    /// mode. The two produce different digests, and the salted mask has to agree
    /// byte-for-byte across the three SDKs: Python computes
    /// <c>hmac.new(salt, value, blake2b)</c> and Node computes
    /// <c>createHmac("blake2b512", salt)</c>, both of which are RFC 2104 over BLAKE2b.
    /// Using native keyed BLAKE2b here would yield a pseudonym that silently failed to
    /// join against either — exactly the class of cross-language divergence the
    /// canonical spec exists to prevent.</para>
    ///
    /// <para>The block size is 128 bytes (BLAKE2b's), not the 64 of SHA-256; a key
    /// longer than one block is hashed down first, per RFC 2104.</para>
    /// </remarks>
    internal static byte[] HashKeyed(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input)
    {
        // RFC 2104: keys longer than the block size are replaced by their digest.
        var normalizedKey = key.Length > BlockBytes ? HashData(key) : key.ToArray();

        var ipad = new byte[BlockBytes];
        var opad = new byte[BlockBytes];
        for (var i = 0; i < BlockBytes; i++)
        {
            var keyByte = i < normalizedKey.Length ? normalizedKey[i] : (byte)0;
            ipad[i] = (byte)(keyByte ^ 0x36);
            opad[i] = (byte)(keyByte ^ 0x5c);
        }

        var inner = new byte[BlockBytes + input.Length];
        ipad.CopyTo(inner.AsSpan());
        input.CopyTo(inner.AsSpan(BlockBytes));
        var innerHash = HashData(inner);

        var outer = new byte[BlockBytes + innerHash.Length];
        opad.CopyTo(outer.AsSpan());
        innerHash.CopyTo(outer.AsSpan(BlockBytes));
        return HashData(outer);
    }

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
