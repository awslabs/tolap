using System.Text.Json;
using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// Revocation is enforced by the SDK resolver (canonical-enforcement-spec.md
/// section 12).
///
/// Before <c>RevokedAt</c> existed in the model, revocation had no SDK backstop: a
/// store that forgot its own <c>revoked_at IS NULL</c> filter kept resolving a
/// revoked grant with nothing in the SDK to catch it. These tests assert the
/// resolver itself refuses a revoked assignment.
///
/// The assertions are about resolved access, not about a flag or an audit event —
/// the spec names emitting a <c>PolicyRevoked</c> event while leaving access
/// intact as the fail-open to avoid.
/// </summary>
public class RevocationTests
{
    private static readonly PolicyDefinition AnalystPolicy = new(
        Version: "1.0",
        Name: "analyst",
        Permissions: new PolicyPermissions(CanQuery: true, ReadOnly: true),
        Priority: 100,
        AppliesToAll: true,
        ObjectRules: new ObjectRules(AllowedObjects: new[] { "patients" }));

    private static PolicyAssignment Assignment(
        bool active = true,
        DateTimeOffset? expiresAt = null,
        DateTimeOffset? revokedAt = null)
        => new(
            Version: "1.0",
            PolicyName: "analyst",
            Assignee: new Assignee(AssigneeType.User, "user-001"),
            Scope: new AssignmentScope(TenantId: "tenant-001"),
            Active: active,
            Audit: new AuditInfo("test-admin", DateTimeOffset.UtcNow, "Test assignment"),
            ExpiresAt: expiresAt,
            RevokedAt: revokedAt);

    private static EffectivePolicy Resolve(PolicyAssignment assignment)
        => PolicyResolutionEngine.Resolve(
            userId: "user-001",
            tenantId: "tenant-001",
            sourceConnectionId: "ds-postgres-001",
            assignments: new[] { assignment },
            definitions: new[] { AnalystPolicy },
            getGroups: _ => Array.Empty<string>(),
            getRoles: _ => Array.Empty<string>());

    [Fact]
    public void NotRevoked_GrantsAccess()
    {
        // Baseline: without this the suite could pass by denying everything.
        var result = Resolve(Assignment());

        result.Permissions.CanQuery.Should().BeTrue();
        result.SourceProfiles.Should().Equal("analyst");
    }

    [Fact]
    public void RevokedAssignment_DoesNotResolve()
    {
        var result = Resolve(Assignment(revokedAt: DateTimeOffset.UtcNow.AddMinutes(-5)));

        result.Permissions.CanQuery.Should().BeFalse();
        result.SourceProfiles.Should().BeEmpty();
    }

    [Fact]
    public void Revocation_OverridesActiveTrue()
    {
        var result = Resolve(Assignment(
            active: true,
            revokedAt: DateTimeOffset.UtcNow.AddMinutes(-1)));

        result.Permissions.CanQuery.Should().BeFalse();
    }

    [Fact]
    public void Revocation_OverridesFarFutureExpiry()
    {
        var result = Resolve(Assignment(
            expiresAt: DateTimeOffset.UtcNow.AddYears(1),
            revokedAt: DateTimeOffset.UtcNow.AddSeconds(-1)));

        result.Permissions.CanQuery.Should().BeFalse();
    }

    [Fact]
    public void FutureRevocation_IsNotYetInEffect()
    {
        // Mirrors expiry rather than behaving as a boolean flag.
        var result = Resolve(Assignment(revokedAt: DateTimeOffset.UtcNow.AddHours(1)));

        result.Permissions.CanQuery.Should().BeTrue();
    }

    [Fact]
    public void NullRevokedAt_IsNotRevoked()
    {
        var result = Resolve(Assignment(revokedAt: null));

        result.Permissions.CanQuery.Should().BeTrue();
    }

    [Fact]
    public void RevokedAt_SurvivesJsonRoundTrip()
    {
        // Assignments arrive as JSON from a store, not as hand-built records.
        var json = TolapJsonOptions.Serialize(Assignment(
            revokedAt: DateTimeOffset.Parse("2026-01-02T00:00:00Z")));

        json.Should().Contain("revokedAt");

        var parsed = TolapJsonOptions.Deserialize<PolicyAssignment>(json);

        parsed.RevokedAt.Should().Be(DateTimeOffset.Parse("2026-01-02T00:00:00Z"));
        Resolve(parsed).Permissions.CanQuery.Should().BeFalse();
    }

    [Theory]
    [InlineData("\"\"")]
    [InlineData("\"   \"")]
    [InlineData("\"garbage\"")]
    [InlineData("\"2026-13-45T99:99:99Z\"")]
    public void MalformedRevokedAt_FailsClosedAtDeserialization(string rawJson)
    {
        // Spec section 12: no unreadable `revokedAt` may yield a *resolving* assignment.
        // The mechanism differs by language and the spec allows that: Python and
        // TypeScript model the field as a string and treat an unreadable value as revoked
        // inside the resolver, while .NET types it as DateTimeOffset? so the value is
        // rejected before the resolver ever sees it. Both deny; this pins .NET's half so
        // a future switch to a lenient converter cannot quietly turn it into an allow.
        var json = $$"""
        {
          "version": "1.0",
          "policyName": "analyst",
          "assignee": { "type": "user", "identifier": "user-001" },
          "scope": { "tenantId": "tenant-001" },
          "active": true,
          "revokedAt": {{rawJson}},
          "audit": {
            "grantedBy": "admin",
            "grantedAt": "2026-01-01T00:00:00Z",
            "reason": "test"
          }
        }
        """;

        var parse = () => TolapJsonOptions.Deserialize<PolicyAssignment>(json);

        parse.Should().Throw<JsonException>(
            "an unreadable revocation must not deserialize into a live assignment");
    }

    [Fact]
    public void AbsentRevokedAt_DeserializesToNull()
    {
        const string json = """
        {
          "version": "1.0",
          "policyName": "analyst",
          "assignee": { "type": "user", "identifier": "user-001" },
          "scope": { "tenantId": "tenant-001" },
          "active": true,
          "audit": {
            "grantedBy": "admin",
            "grantedAt": "2026-01-01T00:00:00Z",
            "reason": "test"
          }
        }
        """;

        var parsed = TolapJsonOptions.Deserialize<PolicyAssignment>(json);

        parsed.RevokedAt.Should().BeNull();
        Resolve(parsed).Permissions.CanQuery.Should().BeTrue();
    }
}
