using System.Text.RegularExpressions;

namespace Tolap.Core;

/// <summary>
/// Validates that a delegation chain narrows at every hop and never widens
/// (canonical-enforcement-spec.md section 15.3).
/// </summary>
/// <remarks>
/// <para>A chain records how authority reached the principal making a call: a human
/// delegates to an agent, which delegates to a sub-agent. The invariant is that each hop
/// may hold less authority than its parent and never more. Without it, a sub-agent could
/// declare any purpose it liked and the chain would be decoration.</para>
/// <para>The chain is only worth validating because it is inside the signed bytes — see
/// <see cref="SecurityContext.DelegationChain"/>. Validating an unsigned chain would check
/// the attacker's own arithmetic.</para>
/// <para>This validates the chain's <i>internal consistency</i>. It cannot establish that
/// the first hop's purpose was honestly declared; that is the stated limitation in spec
/// section 13.</para>
/// </remarks>
public static class DelegationChainValidator
{
    /// <summary>
    /// Upper bound on one purpose-glob evaluation, matching
    /// <see cref="PolicyResolutionEngine"/>'s source-pattern bound.
    /// </summary>
    private static readonly TimeSpan RegexMatchTimeout = TimeSpan.FromMilliseconds(100);

    /// <summary>
    /// Validates a delegation chain.
    /// </summary>
    /// <param name="chain">
    /// The hops, oldest first. <c>null</c>, empty, and single-hop chains are allowed: there
    /// is no parent to widen against, so there is nothing to check. An absent chain is not
    /// treated as suspicious because delegation is opt-in — every pre-purpose context has
    /// none.
    /// </param>
    /// <returns>
    /// An allow, or a denial naming the offending hop by index. The reason strings are part
    /// of the contract; integrators log and branch on them.
    /// </returns>
    public static AccessResult Validate(DelegationHop[]? chain)
    {
        if (chain is null || chain.Length <= 1)
            return new AccessResult(true);

        for (var i = 0; i < chain.Length - 1; i++)
        {
            var parent = chain[i];
            var child = chain[i + 1];

            // Either side absent adds no constraint. A hop that declares no purpose is not
            // claiming one, so there is nothing to narrow and nothing to exceed; the
            // purpose-scoped policy check at resolution is what refuses an undeclared
            // purpose, and doing it twice here would deny every legitimate partial chain.
            if (parent.DeclaredPurpose is { Length: > 0 } parentPurpose &&
                child.DeclaredPurpose is { Length: > 0 } childPurpose &&
                !IsWithinScope(childPurpose, parentPurpose))
            {
                return new AccessResult(false,
                    $"delegation hop {i + 1} purpose '{childPurpose}' " +
                    $"is not within parent scope '{parentPurpose}'");
            }

            // Subset, not equality: a hop may hold fewer scopes than its parent. An empty
            // parent set is therefore not "unrestricted" but "nothing left to pass on", so
            // any child scope exceeds it (spec section 3). Absent on either side adds no
            // constraint, matching the purpose rule above.
            if (parent.ScopeNarrowing is not null && child.ScopeNarrowing is not null &&
                !child.ScopeNarrowing.ToHashSet(StringComparer.Ordinal)
                    .IsSubsetOf(parent.ScopeNarrowing))
            {
                return new AccessResult(false,
                    $"delegation hop {i + 1} scopes exceed parent delegation");
            }
        }

        return new AccessResult(true);
    }

    /// <summary>
    /// Whether a child purpose sits within a parent's scope.
    /// </summary>
    /// <remarks>
    /// <para>Three ways in, and the third is the one that matters:</para>
    /// <list type="number">
    /// <item>Exactly equal. Delegation without narrowing.</item>
    /// <item>The parent is a glob that matches the child, so <c>campaign-*</c> admits
    /// <c>campaign-x-overlap</c>. This is how a parent expresses "any purpose in this
    /// family".</item>
    /// <item>The child extends the parent on a <c>-</c> segment boundary, so
    /// <c>campaign-x</c> admits <c>campaign-x-overlap</c> but <b>not</b>
    /// <c>campaign-xyz-evil</c>.</item>
    /// </list>
    /// <para>The third rule exists because a plain prefix test — the obvious
    /// implementation — accepts <c>campaign-xyz-evil</c> under <c>campaign-x</c>. The two purposes are unrelated;
    /// one merely starts with the other's characters. Requiring the boundary makes the
    /// prefix mean what a reader assumes it means.</para>
    /// <para>Case-sensitive, matching the purpose comparison at resolution, and unlike the
    /// glob helpers this delegates to. Both choices deny a mis-cased purpose rather than
    /// admitting it, which is the direction that matters.</para>
    /// </remarks>
    private static bool IsWithinScope(string childPurpose, string parentPurpose)
    {
        if (string.Equals(childPurpose, parentPurpose, StringComparison.Ordinal))
            return true;

        if (parentPurpose.Contains('*', StringComparison.Ordinal))
            return CaseSensitiveGlobMatch(parentPurpose, childPurpose);

        return childPurpose.StartsWith(parentPurpose + "-", StringComparison.Ordinal);
    }

    /// <summary>
    /// Glob matching for purpose identifiers: <c>*</c> matches any run of characters, and
    /// the comparison is case-sensitive.
    /// </summary>
    /// <remarks>
    /// <para>Neither existing helper fits, which is why this is here rather than a call to
    /// one of them. <see cref="PolicyResolutionEngine.GlobMatch"/> expands <c>*</c> to
    /// <c>[^:]*</c> for colon-delimited source triples and is case-insensitive;
    /// <see cref="EnforcementEngine"/>'s expands to <c>.*</c> but is also case-insensitive
    /// and is <c>internal</c>. Purpose identifiers are hyphen-delimited, not
    /// colon-delimited, and must compare case-sensitively — so borrowing either would
    /// change the answer. The three dialects are documented as deliberately separate
    /// rather than unified.</para>
    /// <para>Bounded and fail-closed like the others: a timeout is a non-match, which denies the
    /// hop rather than admitting it. There is deliberately no <c>ArgumentException</c> catch —
    /// <see cref="Regex.Escape"/> escapes every metacharacter and the only substitution made
    /// afterwards is <c>\*</c> to <c>.*</c>, so the constructed pattern is always well-formed.
    /// A catch for it would be unreachable, and unreachable defensive code is worse than none: it
    /// reads as a handled case that no test can exercise.</para>
    /// </remarks>
    private static bool CaseSensitiveGlobMatch(string pattern, string value)
    {
        var regexPattern = "^" + Regex.Escape(pattern).Replace("\\*", ".*", StringComparison.Ordinal) + "$";

        try
        {
            return Regex.IsMatch(value, regexPattern, RegexOptions.None, RegexMatchTimeout);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }
}
