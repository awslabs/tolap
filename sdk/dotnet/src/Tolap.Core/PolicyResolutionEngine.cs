using System.Text.RegularExpressions;

namespace Tolap.Core;

/// <summary>
/// Resolves the effective policy for a user by filtering assignments, loading definitions,
/// and delegating to PolicyMerger.
/// </summary>
public static class PolicyResolutionEngine
{
    /// <summary>
    /// Upper bound on a single glob evaluation, matching
    /// <see cref="EnforcementEngine"/>'s row-filter bound.
    /// </summary>
    /// <remarks>
    /// canonical-enforcement-spec.md section 13 names a regex match timeout as .NET's
    /// ReDoS mitigation. Without it a source pattern containing many <c>*</c> wildcards
    /// expands to a regex with nested quantifiers that can stall policy resolution
    /// indefinitely — and resolution runs before any policy decision, so the stall
    /// precedes every allow or deny.
    /// </remarks>
    private static readonly TimeSpan RegexMatchTimeout = TimeSpan.FromMilliseconds(100);

    /// <summary>
    /// Resolves the effective policy for a specific user, tenant, and source connection.
    /// </summary>
    /// <param name="userId">The user's unique identifier.</param>
    /// <param name="tenantId">The tenant context.</param>
    /// <param name="sourceConnectionId">The data source connection being accessed.</param>
    /// <param name="assignments">All known policy assignments.</param>
    /// <param name="definitions">All known policy definitions.</param>
    /// <param name="getGroups">Function returning group identifiers for a user.</param>
    /// <param name="getRoles">Function returning role identifiers for a user.</param>
    /// <returns>The merged effective policy.</returns>
    public static EffectivePolicy Resolve(
        string userId,
        string tenantId,
        string sourceConnectionId,
        IReadOnlyList<PolicyAssignment> assignments,
        IReadOnlyList<PolicyDefinition> definitions,
        Func<string, string[]> getGroups,
        Func<string, string[]> getRoles)
    {
        var now = DateTimeOffset.UtcNow;
        var groups = getGroups(userId);
        var roles = getRoles(userId);

        // Filter assignments matching user (direct + groups + roles), active, non-expired
        var matchingAssignments = assignments
            .Where(a => a.Active)
            .Where(a => a.ExpiresAt is null || a.ExpiresAt > now)
            .Where(a => MatchesAssignee(a.Assignee, userId, groups, roles))
            .Where(a => MatchesScope(a.Scope, tenantId, sourceConnectionId))
            .ToList();

        if (matchingAssignments.Count == 0)
            return EffectivePolicy.DenyAll();

        // Build a dictionary of definitions by name for quick lookup
        var definitionsByName = definitions.ToDictionary(d => d.Name, d => d);

        // Load referenced definitions, filter by source patterns
        var matchedDefinitions = matchingAssignments
            .Where(a => definitionsByName.ContainsKey(a.PolicyName))
            .Select(a => definitionsByName[a.PolicyName])
            .Where(d => d.AppliesToAll || MatchesSourcePatterns(d.SourcePatterns, sourceConnectionId))
            .OrderBy(d => d.Priority)
            .ToList();

        if (matchedDefinitions.Count == 0)
            return EffectivePolicy.DenyAll();

        var merged = PolicyMerger.Merge(matchedDefinitions);

        return merged with
        {
            UserId = userId,
            TenantId = tenantId,
            SourceConnectionId = sourceConnectionId,
            ResolvedAt = now
        };
    }

    private static bool MatchesAssignee(Assignee assignee, string userId, string[] groups, string[] roles)
    {
        return assignee.Type switch
        {
            AssigneeType.User => assignee.Identifier == userId,
            AssigneeType.Group => groups.Contains(assignee.Identifier),
            AssigneeType.Role => roles.Contains(assignee.Identifier),
            AssigneeType.ServiceAccount => assignee.Identifier == userId,
            _ => false
        };
    }

    private static bool MatchesScope(AssignmentScope scope, string tenantId, string sourceConnectionId)
    {
        if (scope.TenantId is not null && scope.TenantId != tenantId)
            return false;

        if (scope.SourceConnectionId is not null && scope.SourceConnectionId != sourceConnectionId)
            return false;

        return true;
    }

    /// <summary>
    /// Whether a definition's <c>sourcePatterns</c> admit the source being resolved.
    /// </summary>
    /// <remarks>
    /// Per canonical-enforcement-spec.md section 10: absent <b>or empty</b> patterns mean
    /// the policy applies to every data source, and a non-empty list admits only a source
    /// one pattern matches. A definition whose patterns do not match is excluded before
    /// merging.
    ///
    /// <para>
    /// The empty-array case is deliberate and is the one place in this library where an
    /// empty array does <b>not</b> mean deny-all. Spec section 3's deny-all reading applies
    /// to an <i>allow-list of what may be accessed</i>; <c>sourcePatterns</c> is instead a
    /// declaration of <i>where a policy is in scope</i>, and a policy that names no scope
    /// is source-agnostic rather than scoped to nothing. Reading <c>[]</c> as "applies
    /// nowhere" would silently disable every policy that omitted the field's contents, so
    /// the two readings are not interchangeable.
    /// </para>
    /// </remarks>
    private static bool MatchesSourcePatterns(string[]? sourcePatterns, string sourceConnectionId)
    {
        if (sourcePatterns is null || sourcePatterns.Length == 0)
            return true;

        return sourcePatterns.Any(pattern => GlobMatch(pattern, sourceConnectionId));
    }

    /// <summary>
    /// Performs glob pattern matching for source-connection identifiers, where <c>*</c>
    /// matches within a <c>category:namespace:name</c> segment and does not cross the
    /// <c>:</c> separator.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>These semantics differ deliberately from <see cref="EnforcementEngine.GlobMatch"/>
    /// and the two must not be unified.</b> This method expands <c>*</c> to
    /// <c>[^:]*</c> because a source id is a structured, colon-delimited triple and spec
    /// section 10 requires <c>*</c> to stay within one segment: a policy scoped to
    /// <c>db:*</c> must not capture <c>db:production:patients</c> and thereby govern an
    /// entire category it never named.
    /// <see cref="EnforcementEngine.GlobMatch"/> expands <c>*</c> to <c>.*</c> because it
    /// matches object, field and endpoint names, which are not segmented that way and
    /// where <c>/drug/*</c> is expected to reach <c>/drug/event.json</c>.
    /// </para>
    /// <para>
    /// Unifying them on <c>.*</c> would make <c>sourcePatterns</c> silently over-match and
    /// widen every scoped policy; unifying on <c>[^:]*</c> would break endpoint rules.
    /// Both directions are covered by tests that pin the difference.
    /// </para>
    /// <para>
    /// Evaluated under a bounded timeout, and a timeout or an invalid pattern is a
    /// non-match rather than an escaping exception — the same fail-closed treatment
    /// <see cref="EnforcementEngine"/> applies to row-filter patterns (spec sections 7
    /// and 11). A non-match is the safe outcome here: a source pattern that fails to
    /// evaluate excludes its policy from the merge rather than granting it.
    /// </para>
    /// </remarks>
    public static bool GlobMatch(string pattern, string value)
    {
        // Convert glob pattern to regex
        // Escape regex special chars, then convert glob wildcards
        var regexPattern = "^" + Regex.Escape(pattern)
            .Replace("\\*", "[^:]*")  // * matches anything except colon (segment separator)
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
            // Defence in depth, and currently unreachable for the same reason as
            // EnforcementEngine.GlobMatch: the pattern is escaped before '*' is expanded,
            // so it always compiles. A non-match is the fail-closed outcome here — an
            // unevaluable source pattern excludes its policy rather than granting it.
            return false;
        }
    }
}
