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
    /// <param name="declaredPurpose">
    /// The purpose the caller declares for this resolution, or <c>null</c> to declare none
    /// (spec section 15.1). A definition carrying no <c>purposeProfile</c> resolves either
    /// way, so omitting this reproduces the pre-purpose behaviour exactly. A definition that
    /// <i>is</i> purpose-scoped resolves only on an exact, case-sensitive match — including
    /// not at all when no purpose is declared.
    /// </param>
    /// <returns>The merged effective policy.</returns>
    public static EffectivePolicy Resolve(
        string userId,
        string tenantId,
        string sourceConnectionId,
        IReadOnlyList<PolicyAssignment> assignments,
        IReadOnlyList<PolicyDefinition> definitions,
        Func<string, string[]> getGroups,
        Func<string, string[]> getRoles,
        string? declaredPurpose = null)
    {
        var now = DateTimeOffset.UtcNow;
        var groups = getGroups(userId);
        var roles = getRoles(userId);

        // Filter assignments matching user (direct + groups + roles), not revoked,
        // active, non-expired. Revocation is checked first and overrides both
        // Active and ExpiresAt: a revoked assignment MUST NOT resolve (spec
        // section 12). A future-dated RevokedAt is not yet in effect, which keeps
        // revocation consistent with expiry rather than a boolean in disguise.
        // The `is not { } x` pattern unwraps to a non-nullable local, so the comparison is a
        // plain one rather than C#'s lifted `>`. Written the obvious way --
        // `a.RevokedAt is null || a.RevokedAt > now` -- the lifted operator emits a second
        // `HasValue` check that control can only reach when the first one already returned
        // true, so one arm of it is unreachable IL and the file can never reach 100% branch
        // coverage. Since `RevokedAt` is an `init`-only property the two reads are provably
        // the same value, so this is identical in behaviour and honest in its coverage
        // number. Note the future-versus-past distinction is not a branch either way: the
        // comparison's bool is the return value, which is why a test for scheduled
        // revocation does not move the figure.
        var matchingAssignments = assignments
            .Where(a => a.RevokedAt is not { } revokedAt || revokedAt > now)
            .Where(a => a.Active)
            .Where(a => a.ExpiresAt is not { } expiresAt || expiresAt > now)
            .Where(a => MatchesAssignee(a.Assignee, userId, groups, roles))
            .Where(a => MatchesScope(a.Scope, tenantId, sourceConnectionId))
            .ToList();

        if (matchingAssignments.Count == 0)
            return EffectivePolicy.DenyAll();

        // Build a dictionary of definitions by name for quick lookup
        var definitionsByName = definitions.ToDictionary(d => d.Name, d => d);

        // Load referenced definitions, then filter by source patterns and by declared
        // purpose. Both filters run BEFORE the merge, and for the same reason: a definition
        // that does not apply must not fold its rules into the effective policy at all.
        // Filtering afterwards would mean the rules had already merged, and whether that
        // widens or narrows access depends on the policies involved -- either way the
        // resolved policy is not the one the administrator authored (spec sections 10, 15.1).
        var matchedDefinitions = matchingAssignments
            .Where(a => definitionsByName.ContainsKey(a.PolicyName))
            .Select(a => definitionsByName[a.PolicyName])
            .Where(d => d.AppliesToAll || MatchesSourcePatterns(d.SourcePatterns, sourceConnectionId))
            .Where(d => MatchesDeclaredPurpose(d.PurposeProfile, declaredPurpose))
            .OrderBy(d => d.Priority)
            .ToList();

        // Covers the purpose filter too: when every candidate was purpose-scoped and no
        // matching purpose was declared, the list is empty here and this is the deny-all.
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

    /// <summary>
    /// Whether a definition's purpose profile admits the caller's declared purpose
    /// (spec section 15.1).
    /// </summary>
    /// <remarks>
    /// <para>Three cases, in this order:</para>
    /// <list type="bullet">
    /// <item>No profile — the definition is purpose-agnostic and always applies. This is
    /// what keeps every pre-purpose policy resolving unchanged.</item>
    /// <item>A profile but no declared purpose — excluded. A purpose-scoped policy is not a
    /// default grant, so the absence of a purpose cannot satisfy it.</item>
    /// <item>Both present — an exact, ordinal comparison. Deliberately <b>not</b> the glob
    /// matching used for chain narrowing or source patterns: those are authored patterns
    /// meant to span a family of values, whereas this compares one asserted identifier
    /// against one declared identifier. A case-insensitive or glob comparison here would let
    /// a caller declaring <c>Campaign-X</c> — or <c>*</c> — resolve a policy written for
    /// <c>campaign-x</c>.</item>
    /// </list>
    /// </remarks>
    private static bool MatchesDeclaredPurpose(PurposeProfile? profile, string? declaredPurpose)
    {
        if (profile is null)
            return true;

        // Empty normalizes to absent, matching how the signing projection treats it: "" and
        // omitted must not behave as two different declarations.
        if (string.IsNullOrEmpty(declaredPurpose))
            return false;

        return string.Equals(profile.PurposeId, declaredPurpose, StringComparison.Ordinal);
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

        // A timeout is a non-match, which is the fail-closed outcome here: an unevaluable
        // source pattern excludes its policy rather than granting it.
        //
        // There is deliberately no `catch (ArgumentException)`. The pattern is escaped before
        // '*' is expanded, so it always compiles and the catch could never run --
        // `GlobMatch_RegexMetacharacters_AreLiteral_SoTheInvalidPatternCatchIsUnreachable`
        // asserts the property that makes that true, rather than asserting the catch. It was
        // removed because unreachable defensive code reads as a handled case that no test can
        // exercise, which is a worse signal to a reader than its absence.
        try
        {
            return Regex.IsMatch(value, regexPattern, RegexOptions.IgnoreCase, RegexMatchTimeout);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }
}
