using FluentAssertions;
using Tolap.Core;
using Xunit;

namespace Tolap.Mcp.Tests;

/// <summary>
/// Secure Tool Factory (architecture.md section 5).
/// </summary>
/// <remarks>
/// <para>
/// The factory's reason for existing is that the wrapper must be the only path to a data
/// source (architecture.md section 4). So the tests that matter are the ones asserting it
/// <i>refuses to hand back a tool</i> — a factory that returns an unenforced tool, or the
/// wrong category's tool, defeats the guarantee it exists to provide.
/// </para>
/// <para>
/// Three properties are pinned here, and the Python and TypeScript suites pin the same ones
/// case-for-case (<c>test_factory.py</c>, <c>factory.test.ts</c>):
/// </para>
/// <list type="number">
/// <item><b>A context that fails validation yields no tool at all</b>, rather than a tool
/// that will deny later. A caller holding a tool reasonably assumes it is usable, and a
/// per-call denial is easy to misread as a transient error and retry.</item>
/// <item><b>Dispatch follows the SIGNED category.</b> The category is the first segment of
/// <c>SourceConnectionId</c> (connector-spec section 1), which lives inside the signed bytes.
/// Were it taken from unsigned configuration, flipping <c>db</c> to <c>api</c> would select
/// the wrapper enforcing the other category's rules — and <c>endpointRules</c> do not
/// constrain a SQL query.</item>
/// <item><b>Wrappers stay stateless.</b> The factory does not retain the context, so one
/// user's context cannot outlive its request on a shared instance and be reused for the next
/// caller.</item>
/// </list>
/// </remarks>
public class SecureToolFactoryTests
{
    private const string Key = "factory-test-key";

    /// <summary>
    /// A handler that fails if used: these tests build tools, they do not send requests.
    /// </summary>
    private sealed class UnusedHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
            => throw new InvalidOperationException("the factory must not perform requests");
    }

    private static HttpClient Client() => new(new UnusedHandler());

    private static SecurityContext Context(
        string sourceConnectionId = "db:production:patients",
        bool canQuery = true,
        TimeSpan? ttl = null,
        ObjectRules? objectRules = null,
        string userId = "user-001")
    {
        var now = DateTimeOffset.UtcNow;
        var life = ttl ?? TimeSpan.FromHours(1);

        return new SecurityContext(
            Version: "1.0",
            UserId: userId,
            TenantId: "tenant-001",
            IssuedAt: now,
            ExpiresAt: now + life,
            Policies: new[]
            {
                new EffectivePolicy(
                    Version: "1.0",
                    UserId: userId,
                    TenantId: "tenant-001",
                    SourceConnectionId: sourceConnectionId,
                    ResolvedAt: now,
                    ExpiresAt: now + life,
                    SourceProfiles: new[] { "factory-test" },
                    Permissions: new PolicyPermissions(CanQuery: canQuery, ReadOnly: true),
                    ObjectRules: objectRules)
            });
    }

    private static SecurityContext Signed(
        string sourceConnectionId = "db:production:patients",
        bool canQuery = true,
        TimeSpan? ttl = null,
        ObjectRules? objectRules = null,
        string userId = "user-001")
        => SecurityContextSigner.Sign(
            Context(sourceConnectionId, canQuery, ttl, objectRules, userId), Key);

    private static SecureToolFactory Factory(
        bool enforceSignatures = true,
        string[]? allowedTools = null)
        => new(
            new SecureToolFactoryOptions(
                SigningKey: Key,
                EnforceSignatures: enforceSignatures,
                AllowedTools: allowedTools),
            Client());

    // =======================================================================
    // Dispatch on the signed category
    // =======================================================================

    [Theory]
    [InlineData("db:production:patients")]
    [InlineData("kb:research:trials")]
    [InlineData("storage:archive:exports")]
    public void RecordShapedCategories_YieldTheRecordWrapper(string sourceConnectionId)
    {
        // db, kb and storage all return records and share the post-execution pipeline. Which
        // policy fields are meaningful differs, but that is decided by the policy, not the
        // wrapper type (connector-spec section 2).
        var tool = Factory().CreateTool(Signed(sourceConnectionId));

        tool.RecordTool.Should().NotBeNull();
        tool.HttpTool.Should().BeNull();
    }

    [Fact]
    public void Api_YieldsTheHttpWrapper()
    {
        var tool = Factory().CreateTool(Signed("api:internal:orders"));

        tool.HttpTool.Should().NotBeNull();
        tool.RecordTool.Should().BeNull();
        tool.Category.Should().Be(SourceCategory.Api);
    }

    [Fact]
    public void Exploit_CategoryCannotBeChangedWithoutBreakingTheSignature()
    {
        // The whole reason dispatch reads the signed identifier. Swapping the category
        // post-signing would otherwise pick the wrapper that enforces a different category's
        // rules — endpointRules do not constrain SQL, and vice versa.
        var signed = Signed("db:production:patients");
        var tampered = signed with
        {
            Policies = new[]
            {
                signed.Policies[0] with { SourceConnectionId = "api:internal:orders" }
            }
        };

        var act = () => Factory().CreateTool(tampered);

        act.Should().Throw<ToolCreationException>().WithMessage("*invalid signature*");
    }

    [Fact]
    public void UnparseableIdentifier_YieldsNoToolRatherThanAGuess()
    {
        // Two segments is the documented authoring mistake. There is no safe default
        // wrapper: guessing would enforce some category's rules on a source whose category
        // is unknown.
        var act = () => Factory().CreateTool(Signed("db:production"));

        act.Should().Throw<ToolCreationException>().WithMessage("*category:namespace:name*");
    }

    [Fact]
    public void CategoryOf_ReportsWithoutBuildingATool()
    {
        Factory().CategoryOf(Signed("kb:research:trials")).Should().Be(SourceCategory.Kb);
    }

    // =======================================================================
    // A context that fails validation yields NO tool
    // =======================================================================

    [Fact]
    public void Exploit_AForgedSignatureYieldsNoTool()
    {
        var signed = Signed();
        var forged = signed with
        {
            Integrity = new IntegrityBlock(SigningAlgorithm.HmacSha256, "not-the-real-signature")
        };

        var act = () => Factory().CreateTool(forged);

        act.Should().Throw<ToolCreationException>().WithMessage("*invalid signature*");
    }

    [Fact]
    public void Exploit_TamperingWithThePolicyYieldsNoTool()
    {
        // Escalating ReadOnly on a signed context is the canonical tamper case.
        var signed = Signed();
        var tampered = signed with
        {
            Policies = new[]
            {
                signed.Policies[0] with
                {
                    Permissions = new PolicyPermissions(CanQuery: true, ReadOnly: false)
                }
            }
        };

        var act = () => Factory().CreateTool(tampered);

        act.Should().Throw<ToolCreationException>().WithMessage("*invalid signature*");
    }

    [Fact]
    public void AnExpiredContext_YieldsNoTool()
    {
        var act = () => Factory().CreateTool(Signed(ttl: TimeSpan.FromSeconds(-1)));

        act.Should().Throw<ToolCreationException>();
    }

    [Fact]
    public void SignatureIsReportedBeforeExpiry()
    {
        // Matching the wrappers: a tampered context must not disclose that an
        // otherwise-valid context had merely expired.
        var expired = Signed(ttl: TimeSpan.FromSeconds(-1));
        var forged = expired with
        {
            Integrity = new IntegrityBlock(SigningAlgorithm.HmacSha256, "forged")
        };

        var act = () => Factory().CreateTool(forged);

        act.Should().Throw<ToolCreationException>().WithMessage("*invalid signature*");
    }

    [Fact]
    public void CanQueryFalse_YieldsNoTool()
    {
        // The top-level read gate. Returning a wrapper that denies every call invites a
        // caller to treat the denial as transient and retry.
        var act = () => Factory().CreateTool(Signed(canQuery: false));

        act.Should().Throw<ToolCreationException>().WithMessage("*query not permitted*");
    }

    [Fact]
    public void AContextCarryingNoPolicy_YieldsNoTool()
    {
        // Signature enforcement is off so the test reaches the policy check rather than
        // stopping at the signature the empty policy array invalidated.
        var now = DateTimeOffset.UtcNow;
        var empty = new SecurityContext(
            Version: "1.0",
            UserId: "user-001",
            TenantId: "tenant-001",
            IssuedAt: now,
            ExpiresAt: now + TimeSpan.FromHours(1),
            Policies: Array.Empty<EffectivePolicy>());

        var act = () => Factory(enforceSignatures: false).CreateTool(empty);

        act.Should().Throw<ToolCreationException>().WithMessage("*no effective policy*");
    }

    // =======================================================================
    // The factory holds no connection and no credentials
    // =======================================================================

    [Fact]
    public void ApiWithoutAClient_IsAnErrorNotADefaultClient()
    {
        // Silently constructing a default HttpClient would bypass the caller's handler
        // chain, proxy and timeout configuration while appearing to work.
        var bare = new SecureToolFactory(new SecureToolFactoryOptions(SigningKey: Key));

        var act = () => bare.CreateTool(Signed("api:internal:orders"));

        act.Should().Throw<ToolCreationException>().WithMessage("*HttpClient*");
    }

    [Fact]
    public void RecordCategories_NeedNoClient()
    {
        var bare = new SecureToolFactory(new SecureToolFactoryOptions(SigningKey: Key));

        bare.CreateTool(Signed()).RecordTool.Should().NotBeNull();
    }

    [Fact]
    public void BuildingATool_PerformsNoRequest()
    {
        // UnusedHandler throws if called, so reaching the assertion proves the factory did
        // not touch the transport while composing.
        var tool = Factory().CreateTool(Signed("api:internal:orders"));

        tool.HttpTool.Should().NotBeNull();
    }

    // =======================================================================
    // Wrappers stay stateless and reusable
    // =======================================================================

    [Fact]
    public void TwoCalls_YieldIndependentWrappers()
    {
        var factory = Factory();

        factory.CreateTool(Signed()).RecordTool
            .Should().NotBeSameAs(factory.CreateTool(Signed()).RecordTool);
    }

    [Fact]
    public void Exploit_AToolBuiltForOneUserDoesNotCarryThatUsersPolicy()
    {
        // The failure mode a stateful SetSecurityContext() would introduce: a wrapper
        // holding user A's context, reused for user B. Because the context is supplied per
        // call, a wrapper built from A's context enforces B's policy when B calls it.
        var tool = Factory().CreateTool(
            Signed(objectRules: new ObjectRules(AllowedObjects: new[] { "patients" }),
                   userId: "user-A")).RecordTool!;

        var bContext = Signed(
            objectRules: new ObjectRules(AllowedObjects: new[] { "encounters" }),
            userId: "user-B");

        tool.PreExecute(bContext, new PreExecuteArgs("q", ObjectName: "encounters"))
            .Allowed.Should().BeTrue();
        // And A's allow-list does not leak in to grant `patients` to B.
        tool.PreExecute(bContext, new PreExecuteArgs("q", ObjectName: "patients"))
            .Allowed.Should().BeFalse();
    }

    [Fact]
    public void TheBuiltWrapper_StillValidatesOnEveryCall()
    {
        // Composition-time validation is redundancy, not the gate: the wrapper is reusable
        // and the context arrives again with every request, so a forged context presented
        // later must still be refused.
        var tool = Factory().CreateTool(Signed()).RecordTool!;
        var signed = Signed();
        var forged = signed with
        {
            Integrity = new IntegrityBlock(SigningAlgorithm.HmacSha256, "forged")
        };

        var result = tool.PreExecute(forged, new PreExecuteArgs("q", ObjectName: "patients"));

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be("invalid signature");
    }

    // =======================================================================
    // Options forwarding
    // =======================================================================

    [Fact]
    public void AllowedTools_IsHonouredByTheProducedWrapper()
    {
        var tool = Factory(allowedTools: new[] { "permitted" }).CreateTool(Signed()).RecordTool!;

        tool.PreExecute(Signed(), new PreExecuteArgs("permitted")).Allowed.Should().BeTrue();
        var denied = tool.PreExecute(Signed(), new PreExecuteArgs("other"));
        denied.Allowed.Should().BeFalse();
        denied.Reason.Should().Be("tool not in allowed list");
    }

    [Fact]
    public void EnforceSignaturesFalse_IsForwarded()
    {
        // Asserted because it is a footgun worth being explicit about: the option exists for
        // migrations, and this documents that it really does disable the check rather than
        // being quietly ignored.
        var signed = Signed();
        var forged = signed with
        {
            Integrity = new IntegrityBlock(SigningAlgorithm.HmacSha256, "forged")
        };

        var tool = Factory(enforceSignatures: false).CreateTool(forged).RecordTool!;

        tool.PreExecute(forged, new PreExecuteArgs("q", ObjectName: "patients"))
            .Allowed.Should().BeTrue();
    }
}
