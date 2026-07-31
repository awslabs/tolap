using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// Conformance tests for canonical-enforcement-spec.md section 9,
/// "Policy resolution — sourcePatterns".
/// </summary>
/// <remarks>
/// .NET is the reference implementation for this section: it filtered on
/// <c>sourcePatterns</c> while Python and TypeScript ignored the field entirely, so the
/// same policy set resolved to different effective access per language. These tests pin
/// the behaviour the spec was written from, so the reference cannot drift while the
/// siblings are brought into line with it.
/// </remarks>
public class SourcePatternResolutionTests
{
    // -- The spec section 9 table --

    [Fact]
    public void AbsentSourcePatterns_ApplyToEverySource()
    {
        // Row 1 of the table: absent means source-agnostic, which is the common case for a
        // policy that genuinely governs everything.
        foreach (var source in new[] { "db:production:patients", "api:internal:x", "kb:corp:wiki" })
        {
            Resolve(Definition(sourcePatterns: null), source)
                .Permissions.CanQuery.Should().BeTrue($"an unscoped policy governs {source}");
        }
    }

    [Fact]
    public void EmptySourcePatterns_ApplyToEverySource()
    {
        // Also row 1: an empty array means "applies to all", NOT deny-all.
        //
        // This is the one place in the library where an empty array does not mean
        // deny-everything, and the distinction is deliberate rather than an accident of
        // `.Length == 0`. Spec section 3's deny-all reading governs an allow-list of what
        // may be accessed; sourcePatterns instead declares where a policy is in scope, and
        // a policy naming no scope is source-agnostic rather than scoped to nothing.
        // Reading [] as "applies nowhere" would silently disable the policy entirely.
        foreach (var source in new[] { "db:production:patients", "api:internal:x" })
        {
            Resolve(Definition(sourcePatterns: Array.Empty<string>()), source)
                .Permissions.CanQuery.Should().BeTrue($"an empty pattern list governs {source}");
        }
    }

    [Fact]
    public void ContrastEmptySourcePatternsWithAnEmptyAllowList()
    {
        // The two empty arrays in the same policy mean opposite things, and that is the
        // point: [] sourcePatterns admits the source, while [] allowedObjects then denies
        // every object within it. A future change that "consistently" treated both the
        // same way would break one of them.
        var definition = Definition(
            sourcePatterns: Array.Empty<string>(),
            objectRules: new ObjectRules(AllowedObjects: Array.Empty<string>()));

        var resolved = Resolve(definition, "db:production:patients");

        resolved.Permissions.CanQuery.Should().BeTrue("empty sourcePatterns admitted the source");
        EnforcementEngine.ValidateAccess("patients", resolved)
            .Allowed.Should().BeFalse("but an empty allowedObjects denies every object");
    }

    [Fact]
    public void NonEmptySourcePatterns_ResolveOnlyForAMatchingSource()
    {
        // Row 2 of the table.
        Resolve(Definition(sourcePatterns: new[] { "db:production:*" }), "db:production:patients")
            .Permissions.CanQuery.Should().BeTrue();

        Resolve(Definition(sourcePatterns: new[] { "db:production:*" }), "api:internal:patient-api")
            .Permissions.CanQuery.Should().BeFalse();
    }

    [Fact]
    public void NonMatchingDefinition_IsExcludedBeforeMerging()
    {
        // "Excluded before merging" is the operative requirement: the non-matching
        // definition must not contribute its rules to the merge at all. Asserted through
        // SourceProfiles, which records exactly which definitions were folded in — a
        // definition that merely contributed nothing visible would still be a spec
        // violation, because its restrictions could narrow an unrelated source.
        var resolved = PolicyResolutionEngine.Resolve(
            "alice", "t", "db:production:patients",
            new[] { Assignment("in-scope"), Assignment("out-of-scope") },
            new[]
            {
                Definition("in-scope", sourcePatterns: new[] { "db:production:*" }),
                Definition("out-of-scope", sourcePatterns: new[] { "api:internal:*" })
            },
            _ => Array.Empty<string>(), _ => Array.Empty<string>());

        resolved.SourceProfiles.Should().Equal("in-scope");
    }

    [Fact]
    public void OutOfScopeRestrictionsDoNotLeakIntoAnUnrelatedSource()
    {
        // The concrete harm the spec names: a rule authored for one source must not govern
        // another. The API policy hides `ssn`; resolving the DB source must not inherit it.
        var resolved = PolicyResolutionEngine.Resolve(
            "alice", "t", "db:production:patients",
            new[] { Assignment("db-policy"), Assignment("api-policy") },
            new[]
            {
                Definition("db-policy", sourcePatterns: new[] { "db:production:*" }),
                Definition("api-policy", sourcePatterns: new[] { "api:internal:*" },
                    objectRules: new ObjectRules(
                        FieldRules: new FieldRules(HiddenFields: new[] { "ssn" })))
            },
            _ => Array.Empty<string>(), _ => Array.Empty<string>());

        resolved.ObjectRules?.FieldRules?.HiddenFields.Should().BeNull(
            "the API policy's hiddenFields must not govern the database source");
    }

    [Fact]
    public void AnyOneMatchingPatternAdmitsTheDefinition()
    {
        // The list is a disjunction, so a policy covering two source families matches
        // either of them and neither of an unrelated third.
        var patterns = new[] { "api:internal:*", "db:production:*" };

        Resolve(Definition(sourcePatterns: patterns), "api:internal:x").Permissions.CanQuery.Should().BeTrue();
        Resolve(Definition(sourcePatterns: patterns), "db:production:x").Permissions.CanQuery.Should().BeTrue();
        Resolve(Definition(sourcePatterns: patterns), "kb:corp:wiki").Permissions.CanQuery.Should().BeFalse();
    }

    [Fact]
    public void AppliesToAll_ShortCircuitsAnOtherwiseNonMatchingPatternList()
    {
        // appliesToAll is checked first, so a definition carrying both wins on
        // appliesToAll. Pinned because the precedence is otherwise invisible, and the two
        // fields can plausibly be set together by a policy author.
        var definition = Definition(
            appliesToAll: true,
            sourcePatterns: new[] { "db:production:*" });

        Resolve(definition, "api:internal:something-unrelated")
            .Permissions.CanQuery.Should().BeTrue();
    }

    [Fact]
    public void AppliesToAllFalseWithNoPatterns_StillAppliesEverywhere()
    {
        // The default (appliesToAll false, no patterns) must not be a deny: it is the
        // ordinary shape of a source-agnostic policy.
        Definition().AppliesToAll.Should().BeFalse();

        Resolve(Definition(), "anything:at:all").Permissions.CanQuery.Should().BeTrue();
    }

    // -- Glob semantics required by spec section 9 --

    [Fact]
    public void SourceGlob_MatchesWithinASegmentAndNotAcrossTheColonSeparator()
    {
        // The load-bearing case: `*` must stay inside one segment, so a policy scoped to
        // `db:*` cannot capture `db:production:patients` and govern an entire category it
        // never named.
        PolicyResolutionEngine.GlobMatch("db:*", "db:production").Should().BeTrue();
        PolicyResolutionEngine.GlobMatch("db:*", "db:production:patients").Should().BeFalse(
            "'*' must not cross the ':' segment separator");

        PolicyResolutionEngine.GlobMatch("db:*:*", "db:production:patients").Should().BeTrue();
        PolicyResolutionEngine.GlobMatch("db:production:patient_*", "db:production:patient_records").Should().BeTrue();
        PolicyResolutionEngine.GlobMatch("db:production:patient_*", "db:production:encounter_records").Should().BeFalse();
        PolicyResolutionEngine.GlobMatch("kb:*:*", "kb:corp:wiki").Should().BeTrue();
    }

    [Fact]
    public void SourceGlob_IsCaseInsensitive()
    {
        PolicyResolutionEngine.GlobMatch("DB:PRODUCTION:*", "db:production:patients").Should().BeTrue();
        PolicyResolutionEngine.GlobMatch("db:production:*", "DB:PRODUCTION:PATIENTS").Should().BeTrue();
    }

    [Fact]
    public void SourceGlob_ExactPatternWithNoWildcardMatchesOnlyItself()
    {
        PolicyResolutionEngine.GlobMatch("db:production:patients", "db:production:patients").Should().BeTrue();
        PolicyResolutionEngine.GlobMatch("db:production:patients", "db:production:patients_v2").Should().BeFalse();
    }

    [Fact]
    public void SourceGlob_RegexMetacharactersInAPatternAreLiteral()
    {
        // The pattern is a glob, not a regex: a '.' means a literal dot, or a pattern
        // would silently match more sources than it names.
        PolicyResolutionEngine.GlobMatch("db:prod.db:x", "db:prodXdb:x").Should().BeFalse();
        PolicyResolutionEngine.GlobMatch("db:prod.db:x", "db:prod.db:x").Should().BeTrue();
    }

    [Fact]
    public void ResolutionUsesTheSegmentAwareGlobNotTheEnforcementOne()
    {
        // End-to-end proof that the resolution path is wired to the [^:]* helper rather
        // than EnforcementEngine's .* one: a `db:*` scoped policy must not resolve for a
        // three-segment source. This is the regression a careless unification of the two
        // helpers would introduce, and it would silently widen every scoped policy.
        Resolve(Definition(sourcePatterns: new[] { "db:*" }), "db:production:patients")
            .Permissions.CanQuery.Should().BeFalse();

        Resolve(Definition(sourcePatterns: new[] { "db:*" }), "db:production")
            .Permissions.CanQuery.Should().BeTrue();
    }

    [Fact]
    public void TheTwoGlobHelpersDivergeDeliberately()
    {
        // Documents the divergence as an assertion rather than only in a comment. The
        // enforcement matcher crosses separators because object/field/endpoint names are
        // not segmented (/drug/* must reach /drug/event.json); the resolution matcher does
        // not, because a source id is a colon-delimited triple (spec section 9). Unifying
        // them in either direction breaks one of the two, so this test fails loudly if
        // someone does.
        const string pattern = "db:*";
        const string threeSegmentValue = "db:production:patients";

        PolicyResolutionEngine.GlobMatch(pattern, threeSegmentValue).Should().BeFalse(
            "sourcePatterns matching must stay within a segment (spec section 9)");

        var policy = new EffectivePolicy(
            Version: "1.0", UserId: null, TenantId: null, SourceConnectionId: null,
            ResolvedAt: null, ExpiresAt: null,
            SourceProfiles: Array.Empty<string>(),
            Permissions: new PolicyPermissions(CanQuery: true),
            ObjectRules: new ObjectRules(AllowedObjects: new[] { pattern }));

        EnforcementEngine.ValidateAccess(threeSegmentValue, policy).Allowed.Should().BeTrue(
            "object-name matching crosses separators, which is why the two helpers differ");

        // And the endpoint case the enforcement semantics exist for.
        var endpointPolicy = policy with
        {
            ObjectRules = new ObjectRules(EndpointRules: new EndpointRules(
                AllowedEndpoints: new[] { "/drug/*" }))
        };
        EnforcementEngine.ValidateEndpoint("/drug/event.json", "GET", endpointPolicy)
            .Allowed.Should().BeTrue();
    }

    // -- Helpers --

    private static EffectivePolicy Resolve(PolicyDefinition definition, string sourceConnectionId) =>
        PolicyResolutionEngine.Resolve(
            "alice", "t", sourceConnectionId,
            new[] { Assignment(definition.Name) },
            new[] { definition },
            _ => Array.Empty<string>(), _ => Array.Empty<string>());

    private static PolicyDefinition Definition(
        string name = "p",
        string[]? sourcePatterns = null,
        bool appliesToAll = false,
        ObjectRules? objectRules = null) =>
        new(Version: "1.0",
            Name: name,
            Permissions: new PolicyPermissions(CanQuery: true),
            AppliesToAll: appliesToAll,
            SourcePatterns: sourcePatterns,
            ObjectRules: objectRules);

    private static PolicyAssignment Assignment(string policyName) =>
        new(Version: "1.0",
            PolicyName: policyName,
            Assignee: new Assignee(AssigneeType.User, "alice"),
            Scope: new AssignmentScope(),
            Active: true,
            Audit: new AuditInfo("admin", DateTimeOffset.UtcNow, "test"));
}
