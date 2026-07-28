namespace Tolap.Core;

/// <summary>
/// Merges multiple policy definitions into a single effective policy using TOLAP merge rules.
/// </summary>
public static class PolicyMerger
{
    /// <summary>
    /// Merges a set of policy definitions into a single effective policy.
    /// </summary>
    /// <remarks>
    /// Merge rules:
    /// - Empty list returns DenyAll
    /// - Permissions: AND for canQuery/canExport, OR for readOnly
    /// - AllowedObjects/AllowedFields/AllowedEndpoints/AllowedMethods/AllowedTags: Intersection (null = unrestricted)
    /// - HiddenObjects/HiddenFields/HiddenEndpoints/DeniedTags/ReadOnlyFields: Union
    /// - RowFilters: Concatenate all
    /// - MaskedFields: Group by field name, pick highest MaskType int value (most restrictive)
    /// - Limits: Min for maxResults/maxQueryTimeSeconds/maxObjectSizeBytes, Max for minSimilarityScore
    /// </remarks>
    public static EffectivePolicy Merge(IReadOnlyList<PolicyDefinition> policies)
    {
        if (policies.Count == 0)
            return EffectivePolicy.DenyAll();

        var sourceProfiles = policies.Select(p => p.Name).ToArray();

        // Permissions: AND for canQuery/canExport, OR for readOnly
        var canQuery = policies.All(p => p.Permissions.CanQuery);
        var canExport = policies.All(p => p.Permissions.CanExport);
        var readOnly = policies.Any(p => p.Permissions.ReadOnly);
        var permissions = new PolicyPermissions(canQuery, canExport, readOnly);

        // Object rules
        var objectRules = MergeObjectRules(policies);

        // Limits
        var limits = MergeLimits(policies);

        return new EffectivePolicy(
            Version: "1.0",
            UserId: null,
            TenantId: null,
            SourceConnectionId: null,
            ResolvedAt: null,
            ExpiresAt: null,
            SourceProfiles: sourceProfiles,
            Permissions: permissions,
            ObjectRules: objectRules,
            Limits: limits);
    }

    private static ObjectRules? MergeObjectRules(IReadOnlyList<PolicyDefinition> policies)
    {
        var hasAnyObjectRules = policies.Any(p => p.ObjectRules is not null);
        if (!hasAnyObjectRules)
            return null;

        var allowedObjects = IntersectNullable(policies
            .Select(p => p.ObjectRules?.AllowedObjects));

        var hiddenObjects = UnionNullable(policies
            .Select(p => p.ObjectRules?.HiddenObjects));

        var fieldRules = MergeFieldRules(policies);
        var rowFilters = ConcatenateRowFilters(policies);
        var tagRules = MergeTagRules(policies);
        var endpointRules = MergeEndpointRules(policies);

        // Only return ObjectRules if there is at least one non-null property
        if (allowedObjects is null && hiddenObjects is null && fieldRules is null
            && rowFilters is null && tagRules is null && endpointRules is null)
            return null;

        return new ObjectRules(
            AllowedObjects: allowedObjects,
            HiddenObjects: hiddenObjects,
            FieldRules: fieldRules,
            RowFilters: rowFilters,
            TagRules: tagRules,
            EndpointRules: endpointRules);
    }

    private static FieldRules? MergeFieldRules(IReadOnlyList<PolicyDefinition> policies)
    {
        var hasAnyFieldRules = policies.Any(p => p.ObjectRules?.FieldRules is not null);
        if (!hasAnyFieldRules)
            return null;

        var allowedFields = IntersectNullable(policies
            .Select(p => p.ObjectRules?.FieldRules?.AllowedFields));

        var hiddenFields = UnionNullable(policies
            .Select(p => p.ObjectRules?.FieldRules?.HiddenFields));

        var maskedFields = MergeMaskedFields(policies);

        var readOnlyFields = UnionNullable(policies
            .Select(p => p.ObjectRules?.FieldRules?.ReadOnlyFields));

        if (allowedFields is null && hiddenFields is null && maskedFields is null && readOnlyFields is null)
            return null;

        return new FieldRules(
            AllowedFields: allowedFields,
            HiddenFields: hiddenFields,
            MaskedFields: maskedFields,
            ReadOnlyFields: readOnlyFields);
    }

    private static MaskingRule[]? MergeMaskedFields(IReadOnlyList<PolicyDefinition> policies)
    {
        var allMasked = policies
            .Where(p => p.ObjectRules?.FieldRules?.MaskedFields is not null)
            .SelectMany(p => p.ObjectRules!.FieldRules!.MaskedFields!)
            .ToList();

        if (allMasked.Count == 0)
            return null;

        // Group by field name, pick most restrictive (highest int value)
        var merged = allMasked
            .GroupBy(m => m.Field)
            .Select(g =>
            {
                var mostRestrictive = g.OrderByDescending(m => (int)m.MaskType).First();
                return mostRestrictive;
            })
            .ToArray();

        return merged;
    }

    private static RowFilter[]? ConcatenateRowFilters(IReadOnlyList<PolicyDefinition> policies)
    {
        var allFilters = policies
            .Where(p => p.ObjectRules?.RowFilters is not null)
            .SelectMany(p => p.ObjectRules!.RowFilters!)
            .ToArray();

        return allFilters.Length > 0 ? allFilters : null;
    }

    private static TagRules? MergeTagRules(IReadOnlyList<PolicyDefinition> policies)
    {
        var hasAnyTagRules = policies.Any(p => p.ObjectRules?.TagRules is not null);
        if (!hasAnyTagRules)
            return null;

        var allowedTags = IntersectNullable(policies
            .Select(p => p.ObjectRules?.TagRules?.AllowedTags));

        var deniedTags = UnionNullable(policies
            .Select(p => p.ObjectRules?.TagRules?.DeniedTags));

        if (allowedTags is null && deniedTags is null)
            return null;

        return new TagRules(
            AllowedTags: allowedTags,
            DeniedTags: deniedTags);
    }

    private static EndpointRules? MergeEndpointRules(IReadOnlyList<PolicyDefinition> policies)
    {
        var hasAnyEndpointRules = policies.Any(p => p.ObjectRules?.EndpointRules is not null);
        if (!hasAnyEndpointRules)
            return null;

        var allowedEndpoints = IntersectNullable(policies
            .Select(p => p.ObjectRules?.EndpointRules?.AllowedEndpoints));

        var hiddenEndpoints = UnionNullable(policies
            .Select(p => p.ObjectRules?.EndpointRules?.HiddenEndpoints));

        var allowedMethods = IntersectNullable(policies
            .Select(p => p.ObjectRules?.EndpointRules?.AllowedMethods));

        if (allowedEndpoints is null && hiddenEndpoints is null && allowedMethods is null)
            return null;

        return new EndpointRules(
            AllowedEndpoints: allowedEndpoints,
            HiddenEndpoints: hiddenEndpoints,
            AllowedMethods: allowedMethods);
    }

    private static PolicyLimits? MergeLimits(IReadOnlyList<PolicyDefinition> policies)
    {
        var hasAnyLimits = policies.Any(p => p.Limits is not null);
        if (!hasAnyLimits)
            return null;

        int? maxResults = MinNullable(policies.Select(p => p.Limits?.MaxResults));
        int? maxQueryTimeSeconds = MinNullable(policies.Select(p => p.Limits?.MaxQueryTimeSeconds));
        double? minSimilarityScore = MaxNullableDouble(policies.Select(p => p.Limits?.MinSimilarityScore));
        long? maxObjectSizeBytes = MinNullableLong(policies.Select(p => p.Limits?.MaxObjectSizeBytes));

        if (maxResults is null && maxQueryTimeSeconds is null
            && minSimilarityScore is null && maxObjectSizeBytes is null)
            return null;

        return new PolicyLimits(maxResults, maxQueryTimeSeconds, minSimilarityScore, maxObjectSizeBytes);
    }

    /// <summary>
    /// Computes the intersection of multiple nullable arrays. Null means "unrestricted from this policy".
    /// If all arrays are null, returns null (unrestricted). If some are null and some are not,
    /// the non-null ones constrain the result.
    /// </summary>
    private static string[]? IntersectNullable(IEnumerable<string[]?> sets)
    {
        string[]? result = null;
        bool anyNonNull = false;

        foreach (var set in sets)
        {
            if (set is null)
                continue;

            anyNonNull = true;
            if (result is null)
            {
                result = set.ToArray();
            }
            else
            {
                result = result.Intersect(set).ToArray();
            }
        }

        return anyNonNull ? result : null;
    }

    /// <summary>
    /// Computes the union of multiple nullable arrays.
    /// </summary>
    private static string[]? UnionNullable(IEnumerable<string[]?> sets)
    {
        var combined = new HashSet<string>();
        bool anyNonNull = false;

        foreach (var set in sets)
        {
            if (set is null)
                continue;

            anyNonNull = true;
            foreach (var item in set)
                combined.Add(item);
        }

        return anyNonNull ? combined.ToArray() : null;
    }

    /// <summary>
    /// Returns the minimum non-null value, or null if all are null.
    /// </summary>
    private static int? MinNullable(IEnumerable<int?> values)
    {
        int? result = null;
        foreach (var v in values)
        {
            if (v is null) continue;
            result = result is null ? v : Math.Min(result.Value, v.Value);
        }
        return result;
    }

    private static long? MinNullableLong(IEnumerable<long?> values)
    {
        long? result = null;
        foreach (var v in values)
        {
            if (v is null) continue;
            result = result is null ? v : Math.Min(result.Value, v.Value);
        }
        return result;
    }

    private static double? MaxNullableDouble(IEnumerable<double?> values)
    {
        double? result = null;
        foreach (var v in values)
        {
            if (v is null) continue;
            result = result is null ? v : Math.Max(result.Value, v.Value);
        }
        return result;
    }
}
