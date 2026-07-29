using FluentAssertions;
using Tolap.Core;
using Tolap.Store;
using Xunit;

namespace Tolap.Mcp.Tests;

/// <summary>
/// Regression tests for the wrapper-level enforcement defects closed against
/// docs/canonical-enforcement-spec.md. Each test fails on the pre-fix code.
/// </summary>
public class WrapperEnforcementRegressionTests
{
    private const string SigningKey = "wrapper-regression-key";

    // -- SecureMcpToolWrapper --

    private static async Task<SecureMcpToolWrapper> CreateMcpWrapper(
        ObjectRules? objectRules = null,
        PolicyLimits? limits = null,
        bool allowUnenforceableShapes = false)
    {
        var store = new InMemoryPolicyStore();
        await store.CreatePolicyAsync(new PolicyDefinition(
            Version: "1.0",
            Name: "regression-policy",
            Permissions: new PolicyPermissions(CanQuery: true, CanExport: false, ReadOnly: true),
            Priority: 10,
            AppliesToAll: true,
            ObjectRules: objectRules ?? new ObjectRules(AllowedObjects: new[] { "patients" }),
            Limits: limits));

        await store.AssignPolicyAsync(new PolicyAssignment(
            Version: "1.0",
            PolicyName: "regression-policy",
            Assignee: new Assignee(AssigneeType.User, "user-001"),
            Scope: new AssignmentScope(TenantId: "tenant-001"),
            Active: true,
            Audit: new AuditInfo("admin", DateTimeOffset.UtcNow, "Regression test")));

        return new SecureMcpToolWrapper(new SecureMcpServerOptions(
            PolicyStore: store,
            IdentityResolver: new StaticIdentityResolver(),
            IdentityExtractor: new HeaderIdentityExtractor(),
            SigningKey: SigningKey,
            AllowUnenforceableShapes: allowUnenforceableShapes));
    }

    private static Dictionary<string, string> Headers() => new()
    {
        ["X-Tolap-User-Id"] = "user-001",
        ["X-Tolap-Tenant-Id"] = "tenant-001"
    };

    // Defect 1: hiddenFields were never removed from MCP results.

    [Fact]
    public async Task McpWrapper_HiddenField_IsRemovedFromRecordList()
    {
        var wrapper = await CreateMcpWrapper(new ObjectRules(
            AllowedObjects: new[] { "patients" },
            FieldRules: new FieldRules(HiddenFields: new[] { "patients.ssn" })));

        var result = await wrapper.ExecuteWithEnforcementAsync(
            Headers(), "query", "patients", "ds-1",
            () => Task.FromResult<object?>(new List<Dictionary<string, object?>>
            {
                new() { ["id"] = 1, ["ssn"] = "123-45-6789", ["region"] = "us-east" }
            }));

        result.Allowed.Should().BeTrue();
        var rows = (IReadOnlyList<Dictionary<string, object?>>)result.Result!;
        rows[0].Should().NotContainKey("ssn");
        rows[0].Should().ContainKey("region");
    }

    [Fact]
    public async Task McpWrapper_HiddenField_IsRemovedFromSingleRecord()
    {
        // The single-record branch used to apply masking only, skipping hidden fields
        // entirely, so a get-by-id tool leaked them.
        var wrapper = await CreateMcpWrapper(new ObjectRules(
            AllowedObjects: new[] { "patients" },
            FieldRules: new FieldRules(HiddenFields: new[] { "ssn" })));

        var result = await wrapper.ExecuteWithEnforcementAsync(
            Headers(), "get-by-id", "patients", "ds-1",
            () => Task.FromResult<object?>(new Dictionary<string, object?>
            {
                ["id"] = 1,
                ["ssn"] = "123-45-6789"
            }));

        ((Dictionary<string, object?>)result.Result!).Should().NotContainKey("ssn");
    }

    // Defect 2: allowedFields were never enforced on results.

    [Fact]
    public async Task McpWrapper_AllowedFields_ProjectsAwayUndeclaredColumns()
    {
        // Simulates SELECT *: the tool returns columns the policy never listed.
        var wrapper = await CreateMcpWrapper(new ObjectRules(
            AllowedObjects: new[] { "patients" },
            FieldRules: new FieldRules(AllowedFields: new[] { "patients.id", "patients.region" })));

        var result = await wrapper.ExecuteWithEnforcementAsync(
            Headers(), "query", "patients", "ds-1",
            () => Task.FromResult<object?>(new List<Dictionary<string, object?>>
            {
                new()
                {
                    ["id"] = 1,
                    ["region"] = "us-east",
                    ["ssn"] = "123-45-6789",
                    ["email"] = "a@example.com"
                }
            }));

        var rows = (IReadOnlyList<Dictionary<string, object?>>)result.Result!;
        rows[0].Keys.Should().BeEquivalentTo(new[] { "id", "region" });
    }

    // Defect 3: result-shape bypass.

    [Fact]
    public async Task McpWrapper_PocoResult_IsDenied()
    {
        var wrapper = await CreateMcpWrapper(new ObjectRules(
            AllowedObjects: new[] { "patients" },
            FieldRules: new FieldRules(HiddenFields: new[] { "ssn" })));

        var act = () => wrapper.ExecuteWithEnforcementAsync(
            Headers(), "query", "patients", "ds-1",
            () => Task.FromResult<object?>(new PatientDto("1", "123-45-6789")));

        (await act.Should().ThrowAsync<UnenforceableResultException>())
            .WithMessage("*PatientDto*");
    }

    [Fact]
    public async Task McpWrapper_UnmaterializedEnumerableResult_IsDenied()
    {
        var wrapper = await CreateMcpWrapper(new ObjectRules(
            AllowedObjects: new[] { "patients" },
            FieldRules: new FieldRules(HiddenFields: new[] { "ssn" })));

        var act = () => wrapper.ExecuteWithEnforcementAsync(
            Headers(), "query", "patients", "ds-1",
            () => Task.FromResult<object?>(LazyRows()));

        await act.Should().ThrowAsync<UnenforceableResultException>();
    }

    [Fact]
    public async Task McpWrapper_EnvelopeShapeResult_HiddenFieldIsStrippedFromNestedRows()
    {
        // A {"items": [...]} envelope is a map, so per spec section 5 it runs the full
        // pipeline as a record. The old single-record branch applied only top-level
        // masking, so an ssn nested inside "items" was disclosed unfiltered.
        var wrapper = await CreateMcpWrapper(new ObjectRules(
            AllowedObjects: new[] { "patients" },
            FieldRules: new FieldRules(HiddenFields: new[] { "ssn" })));

        var envelope = new Dictionary<string, object?>
        {
            ["items"] = new List<Dictionary<string, object?>>
            {
                new() { ["id"] = 1, ["ssn"] = "123-45-6789" }
            }
        };

        var result = await wrapper.ExecuteWithEnforcementAsync(
            Headers(), "query", "patients", "ds-1",
            () => Task.FromResult<object?>(envelope));

        var enforced = (Dictionary<string, object?>)result.Result!;
        var items = (List<object?>)enforced["items"]!;
        var row = (Dictionary<string, object?>)items[0]!;
        row.Should().NotContainKey("ssn");
        row.Should().ContainKey("id");
    }

    [Fact]
    public async Task McpWrapper_ScalarResult_IsDenied()
    {
        var wrapper = await CreateMcpWrapper();

        var act = () => wrapper.ExecuteWithEnforcementAsync(
            Headers(), "query", "patients", "ds-1",
            () => Task.FromResult<object?>("raw string result"));

        await act.Should().ThrowAsync<UnenforceableResultException>();
    }

    [Fact]
    public async Task McpWrapper_AllowUnenforceableShapes_LetsPocoThrough()
    {
        // The opt-out must be off by default (asserted above) but honoured when set.
        var wrapper = await CreateMcpWrapper(
            new ObjectRules(AllowedObjects: new[] { "patients" }),
            allowUnenforceableShapes: true);

        var poco = new PatientDto("1", "123-45-6789");

        var result = await wrapper.ExecuteWithEnforcementAsync(
            Headers(), "query", "patients", "ds-1",
            () => Task.FromResult<object?>(poco));

        result.Allowed.Should().BeTrue();
        result.Result.Should().BeSameAs(poco);
    }

    [Fact]
    public async Task McpWrapper_ObjectArrayOfRecords_IsEnforced()
    {
        // object[] never matched the old IReadOnlyList<Dictionary<string, object?>> check.
        var wrapper = await CreateMcpWrapper(new ObjectRules(
            AllowedObjects: new[] { "patients" },
            FieldRules: new FieldRules(HiddenFields: new[] { "ssn" })));

        object?[] rows = { new Dictionary<string, object?> { ["id"] = 1, ["ssn"] = "123-45-6789" } };

        var result = await wrapper.ExecuteWithEnforcementAsync(
            Headers(), "query", "patients", "ds-1",
            () => Task.FromResult<object?>(rows));

        var enforced = (IReadOnlyList<Dictionary<string, object?>>)result.Result!;
        enforced[0].Should().NotContainKey("ssn");
    }

    [Fact]
    public async Task McpWrapper_SingleRecord_AppliesRowFiltersAndLimit()
    {
        // The single-record branch used to skip row/tag/limit steps entirely.
        var wrapper = await CreateMcpWrapper(new ObjectRules(
            AllowedObjects: new[] { "patients" },
            RowFilters: new[] { new RowFilter("region", FilterOperator.Equals, "us-east") }));

        var result = await wrapper.ExecuteWithEnforcementAsync(
            Headers(), "get-by-id", "patients", "ds-1",
            () => Task.FromResult<object?>(new Dictionary<string, object?>
            {
                ["id"] = 1,
                ["region"] = "eu-west"
            }));

        result.Result.Should().BeNull();
    }

    // -- SecureContextToolWrapper --

    private static SecurityContext SignedContext(
        ObjectRules? objectRules = null,
        PolicyLimits? limits = null)
    {
        var now = DateTimeOffset.UtcNow;
        var policy = new EffectivePolicy(
            Version: "1.0",
            UserId: "user-001",
            TenantId: "tenant-001",
            SourceConnectionId: "ds-1",
            ResolvedAt: now,
            ExpiresAt: now.AddHours(1),
            SourceProfiles: new[] { "regression" },
            Permissions: new PolicyPermissions(CanQuery: true),
            ObjectRules: objectRules,
            Limits: limits);

        var context = SecurityContextBuilder.Build("user-001", "tenant-001", new[] { policy });
        return SecurityContextSigner.Sign(context, SigningKey);
    }

    [Fact]
    public async Task ContextWrapper_HiddenField_IsRemovedFromResults()
    {
        var context = SignedContext(new ObjectRules(
            FieldRules: new FieldRules(HiddenFields: new[] { "patients.ssn" })));
        var wrapper = new SecureContextToolWrapper(new SecureContextWrapperOptions(SigningKey));

        var rows = await wrapper.ExecuteWithEnforcementAsync(
            context,
            new PreExecuteArgs("pg-query", ObjectName: "patients"),
            () => Task.FromResult<IReadOnlyList<Dictionary<string, object?>>>(
                new List<Dictionary<string, object?>>
                {
                    new() { ["id"] = 1, ["ssn"] = "123-45-6789", ["region"] = "us-east" }
                }));

        rows[0].Should().NotContainKey("ssn");
        rows[0].Should().ContainKey("region");
    }

    [Fact]
    public async Task ContextWrapper_AllowedFields_ProjectsAwayUndeclaredColumns()
    {
        var context = SignedContext(new ObjectRules(
            FieldRules: new FieldRules(AllowedFields: new[] { "patients.id" })));
        var wrapper = new SecureContextToolWrapper(new SecureContextWrapperOptions(SigningKey));

        var rows = await wrapper.ExecuteWithEnforcementAsync(
            context,
            new PreExecuteArgs("pg-query", ObjectName: "patients"),
            () => Task.FromResult<IReadOnlyList<Dictionary<string, object?>>>(
                new List<Dictionary<string, object?>>
                {
                    new() { ["id"] = 1, ["ssn"] = "123-45-6789" }
                }));

        rows[0].Keys.Should().BeEquivalentTo(new[] { "id" });
    }

    [Fact]
    public async Task ContextWrapper_PocoResult_IsDenied()
    {
        var context = SignedContext();
        var wrapper = new SecureContextToolWrapper(new SecureContextWrapperOptions(SigningKey));

        var act = () => wrapper.ExecuteWithEnforcementAsync(
            context,
            new PreExecuteArgs("pg-query"),
            () => Task.FromResult<object?>(new PatientDto("1", "123-45-6789")));

        (await act.Should().ThrowAsync<UnenforceableResultException>())
            .WithMessage("*PatientDto*");
    }

    [Fact]
    public async Task ContextWrapper_AllowUnenforceableShapes_LetsPocoThrough()
    {
        var context = SignedContext();
        var wrapper = new SecureContextToolWrapper(
            new SecureContextWrapperOptions(SigningKey, AllowUnenforceableShapes: true));
        var poco = new PatientDto("1", "123-45-6789");

        var result = await wrapper.ExecuteWithEnforcementAsync(
            context, new PreExecuteArgs("pg-query"), () => Task.FromResult<object?>(poco));

        result.Should().BeSameAs(poco);
    }

    [Fact]
    public void ContextWrapper_MissingExpiry_IsDenied()
    {
        // Never treat absent expiry as "never expires" (spec section 2).
        var now = DateTimeOffset.UtcNow;
        var policy = new EffectivePolicy(
            Version: "1.0", UserId: "u", TenantId: "t", SourceConnectionId: "ds-1",
            ResolvedAt: now, ExpiresAt: now.AddHours(1),
            SourceProfiles: Array.Empty<string>(),
            Permissions: new PolicyPermissions(CanQuery: true));

        var context = SecurityContextSigner.Sign(
            new SecurityContext(
                Version: "1.0", UserId: "u", TenantId: "t",
                IssuedAt: now, ExpiresAt: default,
                Policies: new[] { policy }),
            SigningKey);

        var wrapper = new SecureContextToolWrapper(new SecureContextWrapperOptions(SigningKey));

        var result = wrapper.ValidateSecurityContext(context);

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Contain("no expiry");
    }

    [Fact]
    public void ContextWrapper_MalformedSignature_IsDeniedNotThrown()
    {
        var context = SignedContext() with
        {
            Integrity = new IntegrityBlock(SigningAlgorithm.HmacSha256, "!!!not-base64!!!")
        };
        var wrapper = new SecureContextToolWrapper(new SecureContextWrapperOptions(SigningKey));

        var act = () => wrapper.ValidateSecurityContext(context);

        act.Should().NotThrow<FormatException>();
        act().Allowed.Should().BeFalse();
    }

    // -- Threat-model R-6: permissive mode must warn loudly --

    [Fact]
    public void PermissiveMode_WarnsAtConstruction()
    {
        // EnforcementMode.Permissive turns every denial into an allow, so a deployment
        // that reaches production still carrying it has no enforcement at all while
        // continuing to look configured. Warned at construction rather than on the first
        // denial: a service whose policies happen not to deny anything during a smoke
        // test would otherwise ship silently.
        using var listener = new CapturingTraceListener();

        SecureMcpToolWrapper.WarnIfEnforcementDisabled(EnforcementMode.Permissive);

        listener.Warnings.Should().ContainSingle();
        var warning = listener.Warnings[0];
        warning.Should().Contain("NOT enforcing");
        warning.Should().Contain("Permissive");
        warning.Should().Contain("MUST NOT be used in production");
    }

    [Fact]
    public void StrictMode_DoesNotWarn()
    {
        // The warning must stay silent on the safe default, or it becomes noise that
        // integrators filter out and then miss when it matters.
        using var listener = new CapturingTraceListener();

        SecureMcpToolWrapper.WarnIfEnforcementDisabled(EnforcementMode.Strict);

        listener.Warnings.Should().BeEmpty();
    }

    [Fact]
    public async Task ConstructingWrapperInPermissiveMode_EmitsTheWarning()
    {
        // End-to-end through the real constructor, so the warning cannot be lost by a
        // constructor that forgets to call the check.
        using var listener = new CapturingTraceListener();

        var store = new InMemoryPolicyStore();
        await store.CreatePolicyAsync(new PolicyDefinition(
            Version: "1.0",
            Name: "permissive-policy",
            Permissions: new PolicyPermissions(CanQuery: true),
            AppliesToAll: true));

        _ = new SecureMcpToolWrapper(new SecureMcpServerOptions(
            PolicyStore: store,
            IdentityResolver: new StaticIdentityResolver(),
            IdentityExtractor: new HeaderIdentityExtractor(),
            SigningKey: SigningKey,
            EnforcementMode: EnforcementMode.Permissive));

        listener.Warnings.Should().ContainSingle()
            .Which.Should().Contain("NOT enforcing");
    }

    /// <summary>
    /// Captures <see cref="System.Diagnostics.Trace"/> warnings for assertion, matching
    /// the channel the AllowUnenforceableShapes opt-out already writes to.
    /// </summary>
    private sealed class CapturingTraceListener : System.Diagnostics.TraceListener
    {
        public List<string> Warnings { get; } = new();

        public CapturingTraceListener() => System.Diagnostics.Trace.Listeners.Add(this);

        public override void Write(string? message) { }

        public override void WriteLine(string? message) { }

        public override void TraceEvent(
            System.Diagnostics.TraceEventCache? eventCache,
            string source,
            System.Diagnostics.TraceEventType eventType,
            int id,
            string? message)
        {
            if (eventType == System.Diagnostics.TraceEventType.Warning && message is not null)
                Warnings.Add(message);
        }

        protected override void Dispose(bool disposing)
        {
            System.Diagnostics.Trace.Listeners.Remove(this);
            base.Dispose(disposing);
        }
    }

    private static IEnumerable<Dictionary<string, object?>> LazyRows()
    {
        yield return new Dictionary<string, object?> { ["ssn"] = "123-45-6789" };
    }

    private sealed record PatientDto(string Id, string Ssn);
}
