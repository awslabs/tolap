using System.Text.RegularExpressions;

namespace Tolap.Core;

/// <summary>
/// Resolves the effective policy for a user by filtering assignments, loading definitions,
/// and delegating to PolicyMerger.
/// </summary>
public static class PolicyResolutionEngine
{
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

    private static bool MatchesSourcePatterns(string[]? sourcePatterns, string sourceConnectionId)
    {
        if (sourcePatterns is null || sourcePatterns.Length == 0)
            return true;

        return sourcePatterns.Any(pattern => GlobMatch(pattern, sourceConnectionId));
    }

    /// <summary>
    /// Performs glob pattern matching. Supports '*' (match any sequence of non-separator characters)
    /// and '**' would match anything. The pattern uses a simple translation to regex.
    /// </summary>
    public static bool GlobMatch(string pattern, string value)
    {
        // Convert glob pattern to regex
        // Escape regex special chars, then convert glob wildcards
        var regexPattern = "^" + Regex.Escape(pattern)
            .Replace("\\*", "[^:]*")  // * matches anything except colon (segment separator)
            + "$";

        return Regex.IsMatch(value, regexPattern, RegexOptions.IgnoreCase);
    }
}
