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
/// Enforces TOLAP policies at the data-object level. Provides validation,
/// masking, filtering, and result limiting.
/// </summary>
public static class EnforcementEngine
{
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

    /// <summary>
    /// Applies field masking rules to a data record.
    /// </summary>
    public static Dictionary<string, object?> ApplyFieldMasking(
        Dictionary<string, object?> record,
        EffectivePolicy policy)
    {
        var maskedFields = policy.ObjectRules?.FieldRules?.MaskedFields;
        if (maskedFields is null || maskedFields.Length == 0)
            return new Dictionary<string, object?>(record);

        var result = new Dictionary<string, object?>(record);

        foreach (var rule in maskedFields)
        {
            // Match against both simple field name and dot-notation
            var matchingKeys = result.Keys
                .Where(k => k == rule.Field || rule.Field.EndsWith("." + k))
                .ToList();

            foreach (var key in matchingKeys)
            {
                result[key] = ApplyMask(result[key], rule);
            }
        }

        return result;
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

    private static object? RowFieldValue(Dictionary<string, object?> row, string fieldName)
    {
        if (row.TryGetValue(fieldName, out var v)) return v;
        var dot = fieldName.IndexOf('.');
        if (dot >= 0)
        {
            var leaf = fieldName[(dot + 1)..];
            if (row.TryGetValue(leaf, out var v2)) return v2;
        }
        return null;
    }

    private static bool RowPassesFilter(Dictionary<string, object?> row, RowFilter rf)
    {
        var value = RowFieldValue(row, rf.Field);
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
                try
                {
                    var pattern = "^" + rf.Value.ToString() + "$";
                    return Regex.IsMatch(value.ToString()!, pattern);
                }
                catch (ArgumentException)
                {
                    return false;
                }
            default:
                return false;
        }
    }

    private static bool ValuesEqual(object? a, object? b)
    {
        a = Normalize(a);
        b = Normalize(b);
        if (a is null && b is null) return true;
        if (a is null || b is null) return false;
        if (a.Equals(b)) return true;
        // Cross-type numeric: scenarios JSON deserializes ints/longs/doubles
        // depending on parser; coerce to a common form for the comparison.
        if (IsNumeric(a) && IsNumeric(b))
        {
            return Convert.ToDouble(a) == Convert.ToDouble(b);
        }
        return a.ToString() == b.ToString();
    }

    private static int? CompareNullable(object? a, object? b)
    {
        a = Normalize(a);
        b = Normalize(b);
        if (a is null || b is null) return null;
        if (IsNumeric(a) && IsNumeric(b))
        {
            return Convert.ToDouble(a).CompareTo(Convert.ToDouble(b));
        }
        if (a is IComparable ca && a.GetType() == b.GetType())
        {
            return ca.CompareTo(b);
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

    private static object? ApplyMask(object? value, MaskingRule rule)
    {
        return rule.MaskType switch
        {
            MaskType.Null => null,
            MaskType.Redact => "[REDACTED]",
            MaskType.Full => ApplyFullMask(value, rule.Parameters),
            MaskType.Partial => ApplyPartialMask(value, rule.Parameters),
            MaskType.Hash => ApplyHashMask(value, rule.Parameters),
            _ => value
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

        if (str.Length <= showFirst + showLast)
            return str;

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
    internal static bool GlobMatch(string pattern, string value)
    {
        // Convert glob pattern to regex
        var regexPattern = "^" + Regex.Escape(pattern)
            .Replace("\\*", ".*")
            + "$";

        return Regex.IsMatch(value, regexPattern, RegexOptions.IgnoreCase);
    }
}
