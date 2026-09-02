namespace Tolap.Core;

/// <summary>
/// Resolves a call's action category from administrator-supplied configuration and validates
/// it against the resolved purpose (canonical-enforcement-spec.md section 15.2).
/// </summary>
/// <remarks>
/// <para>Two lookups rather than one, because the two wrapper families identify a call
/// differently. An MCP-style tool has a name. An HTTP request has a method and a path and no
/// name at all — <c>HttpRequestArgs</c> carries no tool identifier — so a single
/// name-keyed map would mean this enforcement point silently never ran for API sources. A gate
/// that does not exist is worse than no gate, because the configuration implies one does.</para>
/// <para>The maps are configuration on the wrapper, set by whoever deploys it. They are
/// deliberately not policy fields and deliberately not caller arguments: an agent that can
/// name its own action category can name an allowed one, which turns the whole check into a
/// formality.</para>
/// <para>Lives in <c>Tolap.Core</c> rather than in the wrappers so that both wrappers, in all
/// three SDKs, share one fail-closed rule and one set of tests — and because the endpoint glob
/// dialect it needs is internal to this assembly.</para>
/// </remarks>
public static class PurposeActionResolver
{
    /// <summary>
    /// The denial for a call whose action category cannot be determined under a purpose that
    /// constrains actions.
    /// </summary>
    /// <remarks>
    /// Part of the contract; integrators log and branch on it. Phrased as a configuration
    /// problem rather than an access problem, because that is what it is: the fix is to add
    /// the tool to the map, not to widen the policy.
    /// </remarks>
    public const string UndeclaredCategoryReason = "action category not declared for tool";

    /// <summary>
    /// Validates a named tool call against the policy's purpose.
    /// </summary>
    /// <param name="policy">The resolved policy. A policy with no purpose profile always allows.</param>
    /// <param name="toolName">The tool about to run.</param>
    /// <param name="toolActionCategories">
    /// Tool name to action category, supplied by the integrator. Matched exactly and
    /// case-sensitively, as <c>AllowedTools</c> is — a tool name is an identifier, not a
    /// pattern.
    /// </param>
    public static AccessResult ValidateTool(
        EffectivePolicy policy,
        string toolName,
        IReadOnlyDictionary<string, string>? toolActionCategories)
    {
        var profile = policy.PurposeProfile;
        if (profile is null)
            return new AccessResult(true);

        if (toolActionCategories is not null &&
            toolActionCategories.TryGetValue(toolName, out var category))
        {
            return EnforcementEngine.ValidateAction(category, profile);
        }

        return UnclassifiedResult(profile);
    }

    /// <summary>
    /// Validates an HTTP request against the policy's purpose.
    /// </summary>
    /// <param name="policy">The resolved policy. A policy with no purpose profile always allows.</param>
    /// <param name="method">The HTTP method.</param>
    /// <param name="path">The request path, without host or query.</param>
    /// <param name="httpActionCategories">
    /// Keys of the form <c>"METHOD path-glob"</c> — for example <c>"GET /segments/*"</c> —
    /// mapped to an action category. The method is compared case-insensitively, matching how
    /// <c>allowedMethods</c> is compared; the path is matched with the same glob dialect
    /// <c>allowedEndpoints</c> uses, so a deployment writes one kind of endpoint pattern rather
    /// than two.
    /// </param>
    /// <remarks>
    /// When several entries match, <b>all</b> of them are validated and the first denial is
    /// returned. Picking a single "best" match would need a specificity rule, and any such rule
    /// can be gamed by adding a broader entry; evaluating every match makes the outcome
    /// independent of ordering and of how the map happens to be written. Keys are considered in
    /// ordinal order so the reason string is stable.
    /// </remarks>
    public static AccessResult ValidateHttpRequest(
        EffectivePolicy policy,
        string method,
        string path,
        IReadOnlyDictionary<string, string>? httpActionCategories)
    {
        var profile = policy.PurposeProfile;
        if (profile is null)
            return new AccessResult(true);

        var matched = false;

        if (httpActionCategories is not null)
        {
            foreach (var entry in httpActionCategories.OrderBy(e => e.Key, StringComparer.Ordinal))
            {
                if (!KeyMatches(entry.Key, method, path))
                    continue;

                matched = true;
                var result = EnforcementEngine.ValidateAction(entry.Value, profile);
                if (!result.Allowed)
                    return result;
            }
        }

        return matched ? new AccessResult(true) : UnclassifiedResult(profile);
    }

    /// <summary>
    /// What to do with a call no map entry classified.
    /// </summary>
    /// <remarks>
    /// Denied whenever the purpose constrains actions at all — whether by an allow-list or by a
    /// non-empty deny-list. The deny-list case is the less obvious half and the more important
    /// one: a purpose declaring only <c>prohibitedActions: ["export_pii"]</c> means "anything
    /// but exporting PII", and an unclassified tool might be an exporter. Letting it through
    /// because no rule named it would permit the unclassified while forbidding the classified,
    /// which cannot be what the author meant.
    /// <para>An empty <c>prohibitedActions</c> restricts nothing, so it does not make a call
    /// unclassifiable — mirroring the null-versus-empty rule in spec section 3, where the two
    /// arrays read in opposite directions.</para>
    /// </remarks>
    private static AccessResult UnclassifiedResult(PurposeProfile profile)
    {
        var constrainsActions =
            profile.AllowedActions is not null ||
            profile.ProhibitedActions is { Length: > 0 };

        return constrainsActions
            ? new AccessResult(false, UndeclaredCategoryReason)
            : new AccessResult(true);
    }

    /// <summary>
    /// Whether a <c>"METHOD path-glob"</c> key covers this request.
    /// </summary>
    /// <remarks>
    /// A key with no space, or with an empty pattern, matches nothing. It is a
    /// misconfiguration, and a key that silently matched everything would be the worst possible
    /// reading of one — the map exists to narrow.
    /// </remarks>
    private static bool KeyMatches(string key, string method, string path)
    {
        var separator = key.IndexOf(' ');
        if (separator <= 0 || separator == key.Length - 1)
            return false;

        var keyMethod = key.AsSpan(0, separator);
        var keyPattern = key[(separator + 1)..];

        return keyMethod.Equals(method, StringComparison.OrdinalIgnoreCase)
            && EnforcementEngine.GlobMatch(keyPattern, path);
    }
}
