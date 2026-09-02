using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

public class PolicyResolutionEngineTests
{
    private static readonly PolicyDefinition HealthcarePolicy = new(
        Version: "1.0",
        Name: "healthcare-analyst-db",
        Permissions: new PolicyPermissions(CanQuery: true, ReadOnly: true),
        Priority: 10,
        AppliesToAll: false,
        SourcePatterns: new[] { "db:production:patient_*", "db:production:encounter_*" },
        ObjectRules: new ObjectRules(
            AllowedObjects: new[] { "patients", "encounters" },
            HiddenObjects: new[] { "audit_log" }));

    private static readonly PolicyDefinition ApiPolicy = new(
        Version: "1.0",
        Name: "internal-api-readonly",
        Permissions: new PolicyPermissions(CanQuery: true, ReadOnly: true),
        Priority: 20,
        AppliesToAll: false,
        SourcePatterns: new[] { "api:internal:*" });

    [Fact]
    public void Resolve_DirectUserAssignment_ProducesEffectivePolicy()
    {
        var assignments = new[]
        {
            new PolicyAssignment(
                Version: "1.0",
                PolicyName: "healthcare-analyst-db",
                Assignee: new Assignee(AssigneeType.User, "user-001"),
                Scope: new AssignmentScope(TenantId: "tenant-midwest-health"),
                Active: true,
                Audit: new AuditInfo("admin", DateTimeOffset.UtcNow, "Test"))
        };

        var definitions = new[] { HealthcarePolicy, ApiPolicy };

        var result = PolicyResolutionEngine.Resolve(
            userId: "user-001",
            tenantId: "tenant-midwest-health",
            sourceConnectionId: "db:production:patient_records",
            assignments: assignments,
            definitions: definitions,
            getGroups: _ => Array.Empty<string>(),
            getRoles: _ => Array.Empty<string>());

        result.Permissions.CanQuery.Should().BeTrue();
        result.SourceProfiles.Should().Contain("healthcare-analyst-db");
        result.UserId.Should().Be("user-001");
        result.TenantId.Should().Be("tenant-midwest-health");
        result.SourceConnectionId.Should().Be("db:production:patient_records");
    }

    [Fact]
    public void Resolve_GroupAssignment_MatchesGroupMember()
    {
        var assignments = new[]
        {
            new PolicyAssignment(
                Version: "1.0",
                PolicyName: "internal-api-readonly",
                Assignee: new Assignee(AssigneeType.Group, "research-analysts"),
                Scope: new AssignmentScope(TenantId: "tenant-midwest-health"),
                Active: true,
                Audit: new AuditInfo("admin", DateTimeOffset.UtcNow, "Test"))
        };

        var definitions = new[] { HealthcarePolicy, ApiPolicy };

        var result = PolicyResolutionEngine.Resolve(
            userId: "user-001",
            tenantId: "tenant-midwest-health",
            sourceConnectionId: "api:internal:patient-api",
            assignments: assignments,
            definitions: definitions,
            getGroups: _ => new[] { "research-analysts" },
            getRoles: _ => Array.Empty<string>());

        result.Permissions.CanQuery.Should().BeTrue();
        result.SourceProfiles.Should().Contain("internal-api-readonly");
    }

    [Fact]
    public void Resolve_RoleAssignment_MatchesRoleHolder()
    {
        var assignments = new[]
        {
            new PolicyAssignment(
                Version: "1.0",
                PolicyName: "healthcare-analyst-db",
                Assignee: new Assignee(AssigneeType.Role, "data-analyst"),
                Scope: new AssignmentScope(TenantId: "tenant-midwest-health"),
                Active: true,
                Audit: new AuditInfo("admin", DateTimeOffset.UtcNow, "Test"))
        };

        var definitions = new[] { HealthcarePolicy };

        var result = PolicyResolutionEngine.Resolve(
            userId: "user-001",
            tenantId: "tenant-midwest-health",
            sourceConnectionId: "db:production:patient_records",
            assignments: assignments,
            definitions: definitions,
            getGroups: _ => Array.Empty<string>(),
            getRoles: _ => new[] { "data-analyst" });

        result.Permissions.CanQuery.Should().BeTrue();
        result.SourceProfiles.Should().Contain("healthcare-analyst-db");
    }

    [Fact]
    public void Resolve_InactiveAssignment_IsIgnored()
    {
        var assignments = new[]
        {
            new PolicyAssignment(
                Version: "1.0",
                PolicyName: "healthcare-analyst-db",
                Assignee: new Assignee(AssigneeType.User, "user-001"),
                Scope: new AssignmentScope(TenantId: "tenant-midwest-health"),
                Active: false,
                Audit: new AuditInfo("admin", DateTimeOffset.UtcNow, "Deactivated"))
        };

        var definitions = new[] { HealthcarePolicy };

        var result = PolicyResolutionEngine.Resolve(
            userId: "user-001",
            tenantId: "tenant-midwest-health",
            sourceConnectionId: "db:production:patient_records",
            assignments: assignments,
            definitions: definitions,
            getGroups: _ => Array.Empty<string>(),
            getRoles: _ => Array.Empty<string>());

        result.Permissions.CanQuery.Should().BeFalse();
        result.SourceProfiles.Should().BeEmpty();
    }

    [Fact]
    public void Resolve_ExpiredAssignment_IsIgnored()
    {
        var assignments = new[]
        {
            new PolicyAssignment(
                Version: "1.0",
                PolicyName: "healthcare-analyst-db",
                Assignee: new Assignee(AssigneeType.User, "user-001"),
                Scope: new AssignmentScope(TenantId: "tenant-midwest-health"),
                Active: true,
                Audit: new AuditInfo("admin", DateTimeOffset.UtcNow, "Expired"),
                ExpiresAt: DateTimeOffset.UtcNow - TimeSpan.FromHours(1))
        };

        var definitions = new[] { HealthcarePolicy };

        var result = PolicyResolutionEngine.Resolve(
            userId: "user-001",
            tenantId: "tenant-midwest-health",
            sourceConnectionId: "db:production:patient_records",
            assignments: assignments,
            definitions: definitions,
            getGroups: _ => Array.Empty<string>(),
            getRoles: _ => Array.Empty<string>());

        result.Permissions.CanQuery.Should().BeFalse();
        result.SourceProfiles.Should().BeEmpty();
    }

    [Fact]
    public void Resolve_WrongTenant_IsIgnored()
    {
        var assignments = new[]
        {
            new PolicyAssignment(
                Version: "1.0",
                PolicyName: "healthcare-analyst-db",
                Assignee: new Assignee(AssigneeType.User, "user-001"),
                Scope: new AssignmentScope(TenantId: "tenant-other"),
                Active: true,
                Audit: new AuditInfo("admin", DateTimeOffset.UtcNow, "Test"))
        };

        var definitions = new[] { HealthcarePolicy };

        var result = PolicyResolutionEngine.Resolve(
            userId: "user-001",
            tenantId: "tenant-midwest-health",
            sourceConnectionId: "db:production:patient_records",
            assignments: assignments,
            definitions: definitions,
            getGroups: _ => Array.Empty<string>(),
            getRoles: _ => Array.Empty<string>());

        result.Permissions.CanQuery.Should().BeFalse();
    }

    [Fact]
    public void Resolve_SourcePatternMismatch_IsIgnored()
    {
        var assignments = new[]
        {
            new PolicyAssignment(
                Version: "1.0",
                PolicyName: "healthcare-analyst-db",
                Assignee: new Assignee(AssigneeType.User, "user-001"),
                Scope: new AssignmentScope(TenantId: "tenant-midwest-health"),
                Active: true,
                Audit: new AuditInfo("admin", DateTimeOffset.UtcNow, "Test"))
        };

        var definitions = new[] { HealthcarePolicy };

        // Source doesn't match the policy's source patterns
        var result = PolicyResolutionEngine.Resolve(
            userId: "user-001",
            tenantId: "tenant-midwest-health",
            sourceConnectionId: "api:internal:some-api",
            assignments: assignments,
            definitions: definitions,
            getGroups: _ => Array.Empty<string>(),
            getRoles: _ => Array.Empty<string>());

        result.Permissions.CanQuery.Should().BeFalse();
    }

    [Fact]
    public void Resolve_NoAssignments_ProducesDenyAll()
    {
        var result = PolicyResolutionEngine.Resolve(
            userId: "user-001",
            tenantId: "tenant-midwest-health",
            sourceConnectionId: "db:production:patient_records",
            assignments: Array.Empty<PolicyAssignment>(),
            definitions: new[] { HealthcarePolicy },
            getGroups: _ => Array.Empty<string>(),
            getRoles: _ => Array.Empty<string>());

        result.Permissions.CanQuery.Should().BeFalse();
        result.SourceProfiles.Should().BeEmpty();
    }

    [Fact]
    public void Resolve_MultipleMatchingPolicies_MergesCorrectly()
    {
        var exportPolicy = new PolicyDefinition(
            Version: "1.0",
            Name: "export-allowed",
            Permissions: new PolicyPermissions(CanQuery: true, ReadOnly: true),
            Priority: 20,
            AppliesToAll: true);

        var assignments = new[]
        {
            new PolicyAssignment(
                Version: "1.0",
                PolicyName: "healthcare-analyst-db",
                Assignee: new Assignee(AssigneeType.User, "user-001"),
                Scope: new AssignmentScope(TenantId: "tenant-midwest-health"),
                Active: true,
                Audit: new AuditInfo("admin", DateTimeOffset.UtcNow, "Test")),
            new PolicyAssignment(
                Version: "1.0",
                PolicyName: "export-allowed",
                Assignee: new Assignee(AssigneeType.User, "user-001"),
                Scope: new AssignmentScope(TenantId: "tenant-midwest-health"),
                Active: true,
                Audit: new AuditInfo("admin", DateTimeOffset.UtcNow, "Test"))
        };

        var definitions = new[] { HealthcarePolicy, exportPolicy };

        var result = PolicyResolutionEngine.Resolve(
            userId: "user-001",
            tenantId: "tenant-midwest-health",
            sourceConnectionId: "db:production:patient_records",
            assignments: assignments,
            definitions: definitions,
            getGroups: _ => Array.Empty<string>(),
            getRoles: _ => Array.Empty<string>());

        result.SourceProfiles.Should().HaveCount(2);
        result.Permissions.CanQuery.Should().BeTrue();
    }

    [Fact]
    public void GlobMatch_WildcardPattern_MatchesCorrectly()
    {
        PolicyResolutionEngine.GlobMatch("db:production:patient_*", "db:production:patient_records")
            .Should().BeTrue();

        PolicyResolutionEngine.GlobMatch("db:production:patient_*", "db:production:encounter_records")
            .Should().BeFalse();

        PolicyResolutionEngine.GlobMatch("api:internal:*", "api:internal:patient-api")
            .Should().BeTrue();

        PolicyResolutionEngine.GlobMatch("api:internal:*", "api:external:patient-api")
            .Should().BeFalse();
    }

    /// <summary>
    /// Records why <see cref="PolicyResolutionEngine.GlobMatch"/>'s
    /// <c>catch (ArgumentException)</c> is defence in depth rather than a tested path, by
    /// asserting the property that makes it unreachable.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The pattern goes through <c>Regex.Escape</c> before <c>\*</c> is expanded to
    /// <c>[^:]*</c>, so every metacharacter arrives at the engine already neutralised and the
    /// constructed regex always compiles. There is no source pattern — however hostile — that
    /// reaches the <c>ArgumentException</c> handler, so <b>those lines stay uncovered by
    /// design</b>. Contriving a test that reached them would mean asserting behaviour the code
    /// cannot exhibit. The handler has since been REMOVED for exactly that reason -- unreachable
    /// defensive code reads as a handled case no test can exercise -- so this test is now what
    /// stands in its place: it fails first if an edit ever made an unescaped pattern reach the
    /// regex engine, which is the change that would have made the handler necessary.
    /// </para>
    /// <para>
    /// So the assertion is the escaping itself, not "it did not throw". Each pattern must match
    /// <b>itself</b> — proof it was escaped rather than compiled — and must not match an
    /// unrelated source, proof nothing here is quietly acting as a wildcard. A change that
    /// interpolated the pattern unescaped would widen every scoped policy and make an invalid
    /// pattern a live, security-relevant path; both halves fail here before that ships.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData("")]
    [InlineData("[")]
    [InlineData("(")]
    [InlineData(")")]
    [InlineData("[a-")]
    [InlineData("(?<name>")]
    [InlineData("(a+)+")]
    [InlineData("a{")]
    [InlineData("{2,}")]
    [InlineData("+")]
    [InlineData("?")]
    [InlineData("|")]
    [InlineData(".")]
    [InlineData("^$")]
    [InlineData("\\")]
    [InlineData("\\1")]
    public void GlobMatch_RegexMetacharacters_AreLiteral_SoTheInvalidPatternCatchIsUnreachable(
        string pattern)
    {
        PolicyResolutionEngine.GlobMatch(pattern, pattern)
            .Should().BeTrue("an escaped pattern matches itself as a literal");

        PolicyResolutionEngine.GlobMatch(pattern, "db:production:patient_records")
            .Should().BeFalse("a metacharacter must not behave as a wildcard");
    }

    [Fact]
    public void GlobMatch_LongWildcardRun_StillReturnsABoundedAnswer()
    {
        // A run of wildcards is a *valid* pattern, so it never reaches the ArgumentException
        // handler either — it expands to 32 adjacent `[^:]*` groups, the nested-quantifier
        // shape spec section 13 names as .NET's ReDoS exposure, and is bounded by the 100 ms
        // match timeout instead. A colon-free source matches; a colon-bearing one cannot, and
        // returns false either on its own or via that timeout. Both routes give the same
        // fail-closed answer, which is why this asserts the answer and not a duration: a
        // threshold nobody measured hides the defect it was meant to catch
        // (testing-antipatterns.md section 6).
        var pattern = new string('*', 32);

        PolicyResolutionEngine.GlobMatch(pattern, "patient_records").Should().BeTrue();
        PolicyResolutionEngine.GlobMatch(pattern, "db:production:patient_records")
            .Should().BeFalse();
    }
}
