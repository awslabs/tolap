using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// The top-level read gate applies to endpoint validation (canonical spec section 3).
/// </summary>
/// <remarks>
/// <para>Regression test for a cross-SDK divergence: .NET's <c>ValidateEndpoint</c> did not
/// consult <c>CanQuery</c>, so a policy revoking reads entirely still permitted API endpoint
/// access here while Python and TypeScript denied the identical signed policy. That is a
/// fail-open on the broadest permission in the schema.</para>
/// </remarks>
public class EndpointCanQueryTests
{
    private static EffectivePolicy Policy(bool canQuery) =>
        new(Version: "1.0", UserId: "u", TenantId: "t", SourceConnectionId: null,
            ResolvedAt: null, ExpiresAt: null, SourceProfiles: ["p"],
            Permissions: new PolicyPermissions(CanQuery: canQuery, ReadOnly: false),
            ObjectRules: new ObjectRules(EndpointRules: new EndpointRules(
                AllowedEndpoints: ["/api/*"], AllowedMethods: ["GET", "POST"])));

    [Theory]
    [InlineData("GET")]
    [InlineData("POST")]
    public void CanQueryFalse_DeniesEvenAnOtherwisePermittedEndpoint(string method)
    {
        var result = EnforcementEngine.ValidateEndpoint("/api/x", method, Policy(canQuery: false));

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be("query not permitted");
    }

    [Fact]
    public void CanQueryTrue_StillPermitsThePermittedEndpoint()
    {
        // Guards against over-correcting into a blanket denial.
        EnforcementEngine.ValidateEndpoint("/api/x", "GET", Policy(canQuery: true))
            .Allowed.Should().BeTrue();
    }

    [Fact]
    public void CanQueryFalse_DeniesBeforeConsultingEndpointRules()
    {
        // No endpointRules at all: the gate must still deny rather than falling through
        // to the "unrestricted" path.
        var policy = new EffectivePolicy(
            Version: "1.0", UserId: "u", TenantId: "t", SourceConnectionId: null,
            ResolvedAt: null, ExpiresAt: null, SourceProfiles: ["p"],
            Permissions: new PolicyPermissions(CanQuery: false, ReadOnly: false));

        EnforcementEngine.ValidateEndpoint("/anything", "GET", policy)
            .Allowed.Should().BeFalse();
    }
}
