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
    /// Runs the canonical six-step pipeline over a materialized list of records.
    /// </summary>
    public static IReadOnlyList<Dictionary<string, object?>> ApplyRecordPipeline(
        IReadOnlyList<Dictionary<string, object?>> records,
        EffectivePolicy policy)
    {
        var working = ApplyRowFilters(records, policy);
        working = FilterByTags(working, policy);
        working = StripHiddenFields(working, policy);
        working = ProjectAllowedFields(working, policy);
        working = working.Select(r => ApplyFieldMasking(r, policy)).ToList();
        return ApplyResultLimit(working, policy);
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
            default:
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
    /// Validates whether an endpoint and HTTP method are permitted under the given policy.
    /// </summary>
    public static AccessResult ValidateEndpoint(string path, string method, EffectivePolicy policy)
    {
        var endpointRules = policy.ObjectRules?.EndpointRules;
        if (endpointRules is null)
            return new AccessResult(true);

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

        // Check allowed methods
        if (endpointRules.AllowedMethods is not null)
        {
            if (!endpointRules.AllowedMethods.Contains(method, StringComparer.OrdinalIgnoreCase))
                return new AccessResult(false, "method not allowed");
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

    private static string ApplyHashMask(object? value, MaskingParameters? parameters)
    {
        var str = value?.ToString() ?? "";
        var bytes = Encoding.UTF8.GetBytes(str);

        byte[] hash;
        using (var sha256 = SHA256.Create())
        {
            hash = sha256.ComputeHash(bytes);
        }

        // Return hex string truncated to 16 chars
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
    /// Performs glob pattern matching where '*' matches any sequence of characters
    /// within a path segment and '**' would match across segments.
    /// </summary>
    /// <remarks>
    /// Evaluated under the same bounded timeout as row-filter regexes; a timeout is a
    /// non-match rather than an unhandled exception (spec section 7).
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
            return false;
        }
    }
}
