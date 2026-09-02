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
    /// - Permissions: AND for canQuery/canInsert/canUpdate/canDelete, OR for
    ///   readOnly. Absent booleans take their schema default first (canQuery true, the
    ///   three write permissions false, readOnly true).
    /// - AllowedObjects/AllowedFields/AllowedEndpoints/AllowedMethods/AllowedTags: Intersection (null = unrestricted)
    /// - HiddenObjects/HiddenFields/HiddenEndpoints/DeniedTags/ReadOnlyFields: Union
    /// - RowFilters: Concatenate all
    /// - MaskedFields: Group by field name, pick the most restrictive by disclosure
    ///   ranking (null &gt; redact &gt; full &gt; hash &gt; partial); an unknown mask type
    ///   ranks most restrictive
    /// - Limits: Min for maxResults/maxObjectSizeBytes, Max for minSimilarityScore
    /// - PurposeProfile: carried through, with allowedActions intersected and
    ///   prohibitedActions unioned. Two profiles naming different purposes cannot be
    ///   merged and return DenyAll (spec section 15.2).
    /// </remarks>
    public static EffectivePolicy Merge(IReadOnlyList<PolicyDefinition> policies)
    {
        if (policies.Count == 0)
            return EffectivePolicy.DenyAll();

        // Before anything else, because it can refuse the whole merge. Two policies bound
        // to different purposes have no most-restrictive combination -- picking one would
        // silently apply rules authored for a purpose the caller did not declare, and
        // dropping the profile would turn a purpose-scoped policy into an unscoped one.
        // Resolution never produces this input, having filtered to a single purpose
        // already; Merge is public and must not rely on that.
        var purposeProfile = MergePurposeProfiles(policies);
        if (purposeProfile is null && policies.Any(p => p.PurposeProfile is not null))
            return EffectivePolicy.DenyAll();

        var sourceProfiles = policies.Select(p => p.Name).ToArray();

        // Permissions: AND for the grants, OR for the readOnly ceiling. The three write
        // permissions default to false when absent and fold with AND, so *every*
        // applicable policy has to grant a write for the merged policy to; readOnly keeps
        // its true default and its OR fold, so *any* policy can impose the ceiling. Both
        // directions therefore compose most-restrictively (connector-spec.md section 4.1).
        var canQuery = policies.All(p => p.Permissions.CanQuery);
        var canInsert = policies.All(p => p.Permissions.CanInsert == true);
        var canUpdate = policies.All(p => p.Permissions.CanUpdate == true);
        var canDelete = policies.All(p => p.Permissions.CanDelete == true);
        var readOnly = policies.Any(p => p.Permissions.ReadOnly);
        var permissions = new PolicyPermissions(
            CanQuery: canQuery,
            CanInsert: canInsert,
            CanUpdate: canUpdate,
            CanDelete: canDelete,
            ReadOnly: readOnly);

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
            Limits: limits,
            PurposeProfile: purposeProfile);
    }

    /// <summary>
    /// Combines the purpose profiles of the merged definitions, or <c>null</c> when none
    /// carry one — and also <c>null</c> when they disagree about the purpose, which the
    /// caller reads as a refusal.
    /// </summary>
    /// <remarks>
    /// <para>The profile is carried onto the effective policy rather than consumed during
    /// resolution because enforcement only ever sees an <see cref="EffectivePolicy"/>. It
    /// also means the purpose travels inside the signed bytes without any change to the
    /// signing projection: the policy is already part of the signed envelope.</para>
    /// <para><c>allowedActions</c> intersects and <c>prohibitedActions</c> unions, so both
    /// fold most-restrictively. Disjoint allow-lists intersect to an empty array, which per
    /// spec section 3 denies every action — deliberately not collapsed to <c>null</c>, which
    /// would mean the opposite.</para>
    /// </remarks>
    private static PurposeProfile? MergePurposeProfiles(IReadOnlyList<PolicyDefinition> policies)
    {
        var profiles = policies
            .Select(p => p.PurposeProfile)
            .Where(profile => profile is not null)
            .Select(profile => profile!)
            .ToList();

        if (profiles.Count == 0)
            return null;

        // Case-sensitive, matching the resolution-time comparison. Two spellings of the
        // same intent are two different purposes as far as this SDK is concerned, and
        // saying so loudly beats quietly treating them as one.
        var purposeIds = profiles
            .Select(profile => profile.PurposeId)
            .Distinct(StringComparer.Ordinal)
            .ToList();

        if (purposeIds.Count > 1)
            return null;

        var judge = MergeJudgeConfigs(profiles);
        if (judge is null && profiles.Any(profile => profile.Judge is not null))
            return null;

        return new PurposeProfile(
            PurposeId: purposeIds[0],
            // Lowest-priority definition first, so the description a reader sees is the one
            // from the most specific policy. Merge is called with the list already ordered.
            Description: profiles.Select(profile => profile.Description).FirstOrDefault(d => d is not null),
            AllowedActions: IntersectNullable(profiles.Select(profile => profile.AllowedActions)),
            ProhibitedActions: UnionNullable(profiles.Select(profile => profile.ProhibitedActions)),
            Judge: judge);
    }

    /// <summary>
    /// Combines judge configurations toward more escalation, or <c>null</c> when the
    /// profiles name different models — which the caller reads as a refusal.
    /// </summary>
    /// <remarks>
    /// <c>enabled</c> ORs so any policy can switch the judge on. Both thresholds take the
    /// <b>maximum</b>: a higher confidence bar sends more calls to review rather than
    /// letting them through, and a higher escalation floor does the same. <c>maxLatencyMs</c>
    /// takes the minimum, and <c>historyWindow</c> the maximum, since more context is the
    /// direction that helps a judge notice drift. Two different models cannot be reconciled
    /// at all — a verdict is only meaningful against the model that produced it.
    /// </remarks>
    private static JudgeConfig? MergeJudgeConfigs(IReadOnlyList<PurposeProfile> profiles)
    {
        var configs = profiles
            .Select(profile => profile.Judge)
            .Where(judge => judge is not null)
            .Select(judge => judge!)
            .ToList();

        if (configs.Count == 0)
            return null;

        var models = configs
            .Select(config => config.Model)
            .Where(model => model is not null)
            .Distinct(StringComparer.Ordinal)
            .ToList();

        if (models.Count > 1)
            return null;

        return new JudgeConfig(
            Enabled: configs.Any(config => config.Enabled == true)
                ? true
                : configs.Any(config => config.Enabled is not null) ? false : null,
            Model: models.Count == 1 ? models[0] : null,
            HistoryWindow: MaxNullableInt(configs.Select(config => config.HistoryWindow)),
            ConfidenceThreshold: MaxNullableDouble(configs.Select(config => config.ConfidenceThreshold)),
            EscalationThreshold: MaxNullableDouble(configs.Select(config => config.EscalationThreshold)),
            MaxLatencyMs: MinNullable(configs.Select(config => config.MaxLatencyMs)));
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

        // Group by field name, pick most restrictive by disclosure ranking. null/redact
        // reveal nothing and therefore beat partial/hash, which reveal real characters;
        // an unrecognized mask type ranks above every known value so it cannot be
        // downgraded (canonical-enforcement-spec.md section 6).
        var merged = allMasked
            .GroupBy(m => m.Field)
            .Select(g => g.OrderByDescending(m => m.MaskType.Restrictiveness()).First())
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
        double? minSimilarityScore = MaxNullableDouble(policies.Select(p => p.Limits?.MinSimilarityScore));
        long? maxObjectSizeBytes = MinNullableLong(policies.Select(p => p.Limits?.MaxObjectSizeBytes));

        if (maxResults is null
            && minSimilarityScore is null && maxObjectSizeBytes is null)
            return null;

        return new PolicyLimits(maxResults, minSimilarityScore, maxObjectSizeBytes);
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

    /// <summary>
    /// Returns the maximum non-null value, or null if all are null.
    /// </summary>
    private static int? MaxNullableInt(IEnumerable<int?> values)
    {
        int? result = null;
        foreach (var v in values)
        {
            if (v is null) continue;
            result = result is null ? v : Math.Max(result.Value, v.Value);
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
