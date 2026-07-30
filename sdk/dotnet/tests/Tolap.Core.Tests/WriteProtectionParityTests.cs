using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// Cross-SDK parity for write protection (canonical spec section 9).
/// </summary>
/// <remarks>
/// <para>One policy, one method table, asserted with identical expected outcomes in all
/// three SDKs. The counterparts are <c>sdk/python/tests/test_write_protection_parity.py</c>
/// and <c>packages/core/tests/write-protection-parity.test.ts</c>.</para>
/// <para>The table is deliberately mixed so a single divergence in either control is
/// visible: the policy grants DELETE and POST while declaring itself read-only (so the
/// ReadOnly ceiling must override them), omits HEAD and OPTIONS from an otherwise present
/// AllowedMethods (so the read methods are not implicitly re-added), and spells one request
/// method in lower case (so the comparison must be case-insensitive).</para>
/// <para>The two denial reasons are asserted, not just the boolean. They must stay
/// distinguishable across languages, because "method not allowed" is fixed by widening
/// AllowedMethods and "method not allowed on a read-only policy" is fixed by clearing
/// ReadOnly — an integrator who cannot tell them apart cannot tell which policy edit will
/// unblock them.</para>
/// <para>Both controls previously failed OPEN in all three SDKs, and did so
/// <em>inconsistently</em> once partially fixed, which is the divergence class this file
/// guards.</para>
/// </remarks>
public class WriteProtectionParityTests
{
    /// <summary>The shared parity policy. Identical field-for-field in all three SDKs.</summary>
    private static readonly EffectivePolicy ParityPolicy = new(
        Version: "1.0",
        UserId: "parity-user",
        TenantId: "parity-tenant",
        SourceConnectionId: "api:internal:parity",
        ResolvedAt: null,
        ExpiresAt: null,
        SourceProfiles: new[] { "write-protection-parity" },
        Permissions: new PolicyPermissions(CanQuery: true, ReadOnly: true),
        ObjectRules: new ObjectRules(EndpointRules: new EndpointRules(
            AllowedEndpoints: new[] { "/api/*" },
            HiddenEndpoints: new[] { "/api/admin/*" },
            AllowedMethods: new[] { "GET", "POST", "DELETE" })),
        Limits: null);

    // path, method, allowed, reason -- the canonical table.
    [Theory]
    [InlineData("/api/x", "GET", true, null)]
    [InlineData("/api/x", "get", true, null)]
    [InlineData("/api/x", "HEAD", false, "method not allowed")]
    [InlineData("/api/x", "OPTIONS", false, "method not allowed")]
    [InlineData("/api/x", "POST", false, "method not allowed on a read-only policy")]
    [InlineData("/api/x", "delete", false, "method not allowed on a read-only policy")]
    [InlineData("/api/x", "PUT", false, "method not allowed")]
    [InlineData("/api/admin/y", "GET", false, "endpoint is hidden")]
    [InlineData("/other/z", "GET", false, "endpoint not in allowed set")]
    public void WriteProtectionParity(string path, string method, bool allowed, string? reason)
    {
        var result = EnforcementEngine.ValidateEndpoint(path, method, ParityPolicy);

        result.Allowed.Should().Be(allowed);
        result.Reason.Should().Be(reason);
    }
}
