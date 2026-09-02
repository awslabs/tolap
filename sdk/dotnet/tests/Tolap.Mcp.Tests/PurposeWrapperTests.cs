using System.Net;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Tolap.Core;
using Tolap.Mcp;
using Xunit;

namespace Tolap.Mcp.Tests;

/// <summary>
/// Purpose-bound action validation as the wrappers actually run it (spec section 15.2).
/// </summary>
/// <remarks>
/// <para><c>PurposeActionResolverTests</c> covers the decision. This covers the wiring, which is
/// the part that silently does not exist if it is wrong: a resolver nobody calls passes all its
/// own tests. Every case here goes through <c>PreExecute</c> or <c>RequestAsync</c> — the calls an
/// integrator makes — rather than through the resolver directly.</para>
/// <para>The two wrappers are keyed differently on purpose. An HTTP request has no tool name, so
/// the HTTP map is keyed by <c>METHOD path-glob</c>. Testing only the MCP path would have left
/// that half unverified, which is how the gap was there to find in the first place.</para>
/// </remarks>
public class PurposeWrapperTests
{
    private const string Key = "purpose-wrapper-key";
    private const string Base = "https://purpose.test";

    private static readonly PurposeProfile Constrained = new(
        PurposeId: "campaign-x-overlap",
        Description: "Aggregate segment overlap only.",
        AllowedActions: new[] { "aggregate_overlap", "count_segments" },
        ProhibitedActions: new[] { "export_pii" });

    private static EffectivePolicy PolicyWith(
        PurposeProfile? profile, ObjectRules? objectRules = null)
    {
        var now = DateTimeOffset.UtcNow;
        return new EffectivePolicy(
            Version: "1.0",
            UserId: "purpose-user",
            TenantId: "purpose-tenant",
            SourceConnectionId: "api:purpose:test",
            ResolvedAt: now,
            ExpiresAt: now.AddHours(1),
            SourceProfiles: new[] { "purpose-wrapper" },
            Permissions: new PolicyPermissions(CanQuery: true, ReadOnly: true),
            ObjectRules: objectRules,
            PurposeProfile: profile);
    }

    private static SecurityContext SignedContext(EffectivePolicy policy) =>
        SecurityContextSigner.Sign(
            SecurityContextBuilder.Build(
                "purpose-user", "purpose-tenant", new[] { policy },
                declaredPurpose: policy.PurposeProfile?.PurposeId),
            Key);

    // -- The MCP / context wrapper ----------------------------------------

    private static readonly Dictionary<string, string> ToolMap = new()
    {
        ["segment_overlap"] = "aggregate_overlap",
        ["export_csv"] = "export_pii"
    };

    private static SecureContextToolWrapper ContextWrapper(
        IReadOnlyDictionary<string, string>? map) =>
        new(new SecureContextWrapperOptions(Key, ToolActionCategories: map));

    [Fact]
    public void PreExecute_AProhibitedTool_IsDenied()
    {
        var result = ContextWrapper(ToolMap).PreExecute(
            SignedContext(PolicyWith(Constrained)), new PreExecuteArgs("export_csv"));

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be(
            "action 'export_pii' is prohibited under purpose 'campaign-x-overlap'");
    }

    [Fact]
    public void PreExecute_APermittedTool_IsAllowed()
    {
        // The paired control. Without it, a wrapper that denied every call would satisfy the
        // case above and look correct.
        ContextWrapper(ToolMap).PreExecute(
            SignedContext(PolicyWith(Constrained)), new PreExecuteArgs("segment_overlap"))
            .Allowed.Should().BeTrue();
    }

    [Fact]
    public void PreExecute_AnUnmappedTool_IsDeniedUnderAConstrainingPurpose()
    {
        ContextWrapper(ToolMap).PreExecute(
            SignedContext(PolicyWith(Constrained)), new PreExecuteArgs("some_other_tool"))
            .Reason.Should().Be(PurposeActionResolver.UndeclaredCategoryReason);
    }

    [Fact]
    public void PreExecute_NoMapConfigured_DeniesEveryCallUnderAConstrainingPurpose()
    {
        // The deployment mistake worth failing loudly on: a purpose-bound policy reaches a
        // wrapper whose operator never classified the tools. Denying everything is noisy and
        // obvious; allowing everything would look like the feature working.
        ContextWrapper(null).PreExecute(
            SignedContext(PolicyWith(Constrained)), new PreExecuteArgs("segment_overlap"))
            .Reason.Should().Be(PurposeActionResolver.UndeclaredCategoryReason);
    }

    [Fact]
    public void PreExecute_APurposeAgnosticPolicy_IsUnaffectedByTheMap()
    {
        // The backward-compatibility guarantee at the wrapper boundary: an existing deployment
        // with no purposes behaves identically whether or not a map is configured.
        var agnostic = SignedContext(PolicyWith(null));

        ContextWrapper(null).PreExecute(agnostic, new PreExecuteArgs("export_csv"))
            .Allowed.Should().BeTrue();
        ContextWrapper(ToolMap).PreExecute(agnostic, new PreExecuteArgs("export_csv"))
            .Allowed.Should().BeTrue();
    }

    [Fact]
    public void PreExecute_ChecksTheActionBeforeTheObjectRules()
    {
        // Both would deny. "This action does not serve the declared purpose" is the more useful
        // answer, and the ordering is asserted rather than left to whichever check happens to
        // run first after a refactor.
        var policy = PolicyWith(
            Constrained,
            new ObjectRules(HiddenObjects: new[] { "customer_segments" }));

        var result = ContextWrapper(ToolMap).PreExecute(
            SignedContext(policy),
            new PreExecuteArgs("export_csv", ObjectName: "customer_segments"));

        result.Reason.Should().Be(
            "action 'export_pii' is prohibited under purpose 'campaign-x-overlap'");
    }

    [Fact]
    public void PreExecute_ChecksCanQueryBeforeTheAction()
    {
        // The other side of the ordering. A policy granting no reads should say so rather than
        // complain about a category, because the category is not the problem.
        var noReads = PolicyWith(Constrained) with
        {
            Permissions = new PolicyPermissions(CanQuery: false, ReadOnly: true)
        };

        ContextWrapper(ToolMap).PreExecute(
            SignedContext(noReads), new PreExecuteArgs("export_csv"))
            .Reason.Should().Be("query not permitted");
    }

    [Fact]
    public void PreExecute_ChecksTheContextSignatureBeforeTheAction()
    {
        // A tampered context must report tampering. Reaching the action check first would let an
        // attacker learn which categories a forged policy permits.
        var tampered = SignedContext(PolicyWith(Constrained)) with { DeclaredPurpose = "fraud-detection" };

        ContextWrapper(ToolMap).PreExecute(tampered, new PreExecuteArgs("segment_overlap"))
            .Reason.Should().Be("invalid signature");
    }

    // -- The HTTP wrapper -------------------------------------------------

    private static readonly Dictionary<string, string> HttpMap = new()
    {
        ["GET /segments/*"] = "aggregate_overlap",
        ["GET /export/*"] = "export_pii"
    };

    private static EndpointRules AllGet() => new(
        AllowedEndpoints: new[] { "/*", "/**" }, AllowedMethods: new[] { "GET" });

    private static HttpClient ClientOver(HttpMessageHandler handler) =>
        new(handler) { BaseAddress = new Uri(Base + "/") };

    /// <summary>Returns a fixed 200 JSON body for any request.</summary>
    private sealed class OkHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
            => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    """{"count":3}""", Encoding.UTF8, "application/json"),
                RequestMessage = request
            });
    }

    /// <summary>Redirects once to a fixed location, then returns a body.</summary>
    private sealed class OneRedirectHandler : HttpMessageHandler
    {
        private readonly string _location;
        private bool _redirected;

        public OneRedirectHandler(string location) => _location = location;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            if (!_redirected)
            {
                _redirected = true;
                var redirect = new HttpResponseMessage(HttpStatusCode.TemporaryRedirect)
                {
                    RequestMessage = request
                };
                redirect.Headers.Location = new Uri(_location, UriKind.Relative);
                return Task.FromResult(redirect);
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    """{"count":3}""", Encoding.UTF8, "application/json"),
                RequestMessage = request
            });
        }
    }

    private static SecureHttpToolWrapper HttpWrapper(
        HttpMessageHandler handler, IReadOnlyDictionary<string, string>? map) =>
        new(new SecureHttpWrapperOptions(Key, HttpActionCategories: map), ClientOver(handler));

    [Fact]
    public async Task Request_AProhibitedPath_IsDenied()
    {
        var wrapper = HttpWrapper(new OkHandler(), HttpMap);

        var act = () => wrapper.RequestAsync(
            SignedContext(PolicyWith(Constrained, new ObjectRules(EndpointRules: AllGet()))),
            new HttpRequestArgs("GET", "/export/all.csv"));

        (await act.Should().ThrowAsync<Exception>()).Which.Message
            .Should().Contain("action 'export_pii' is prohibited under purpose 'campaign-x-overlap'");
    }

    [Fact]
    public async Task Request_APermittedPath_Succeeds()
    {
        // The paired control, and the case that proves the HTTP map is consulted at all rather
        // than the wrapper simply refusing everything once a purpose is present.
        var wrapper = HttpWrapper(new OkHandler(), HttpMap);

        var body = await wrapper.RequestAsync(
            SignedContext(PolicyWith(Constrained, new ObjectRules(EndpointRules: AllGet()))),
            new HttpRequestArgs("GET", "/segments/overlap"));

        body.GetProperty("count").GetInt32().Should().Be(3);
    }

    [Fact]
    public async Task Request_AnUnmappedPath_IsDeniedUnderAConstrainingPurpose()
    {
        var wrapper = HttpWrapper(new OkHandler(), HttpMap);

        var act = () => wrapper.RequestAsync(
            SignedContext(PolicyWith(Constrained, new ObjectRules(EndpointRules: AllGet()))),
            new HttpRequestArgs("GET", "/reports/monthly"));

        (await act.Should().ThrowAsync<Exception>()).Which.Message
            .Should().Contain(PurposeActionResolver.UndeclaredCategoryReason);
    }

    [Fact]
    public async Task Request_APurposeAgnosticPolicy_IsUnaffected()
    {
        var wrapper = HttpWrapper(new OkHandler(), HttpMap);

        var body = await wrapper.RequestAsync(
            SignedContext(PolicyWith(null, new ObjectRules(EndpointRules: AllGet()))),
            new HttpRequestArgs("GET", "/export/all.csv"));

        body.GetProperty("count").GetInt32().Should().Be(3);
    }

    [Fact]
    public async Task Request_TheCategoryIsCheckedOnARedirectTarget()
    {
        // The case that makes per-hop checking worth its complexity: the request that leaves is
        // an allowed aggregate, and the location it is sent to is an export. Checking only the
        // original request would let a redirect launder a prohibited action.
        var wrapper = HttpWrapper(new OneRedirectHandler("/export/all.csv"), HttpMap);

        var act = () => wrapper.RequestAsync(
            SignedContext(PolicyWith(Constrained, new ObjectRules(EndpointRules: AllGet()))),
            new HttpRequestArgs("GET", "/segments/overlap"));

        (await act.Should().ThrowAsync<Exception>()).Which.Message
            .Should().Contain("action 'export_pii' is prohibited under purpose 'campaign-x-overlap'");
    }

    [Fact]
    public async Task Request_ARedirectToAPermittedPath_StillSucceeds()
    {
        // Paired with the case above: per-hop checking must not refuse every redirect.
        var wrapper = HttpWrapper(new OneRedirectHandler("/segments/count"), HttpMap);
        var map = new Dictionary<string, string>(HttpMap) { ["GET /segments/count"] = "count_segments" };
        var permissive = HttpWrapper(new OneRedirectHandler("/segments/count"), map);
        _ = wrapper;

        var body = await permissive.RequestAsync(
            SignedContext(PolicyWith(Constrained, new ObjectRules(EndpointRules: AllGet()))),
            new HttpRequestArgs("GET", "/segments/overlap"));

        body.GetProperty("count").GetInt32().Should().Be(3);
    }

    [Fact]
    public async Task Request_TheCategoryIsMatchedWithTheQueryStringStripped()
    {
        // A category must not be dodged by appending a query, and equally must not be missed
        // because one was present. Matched on the same path the endpoint rules see.
        var wrapper = HttpWrapper(new OkHandler(), HttpMap);

        var act = () => wrapper.RequestAsync(
            SignedContext(PolicyWith(Constrained, new ObjectRules(EndpointRules: AllGet()))),
            new HttpRequestArgs("GET", "/export/all.csv?format=json"));

        (await act.Should().ThrowAsync<Exception>()).Which.Message
            .Should().Contain("action 'export_pii' is prohibited");
    }

    [Fact]
    public async Task Request_ChecksTheActionBeforeTheEndpointRules()
    {
        // Both deny. The action answer names what the agent tried to do; "endpoint is hidden"
        // names only where.
        var policy = PolicyWith(
            Constrained,
            new ObjectRules(EndpointRules: new EndpointRules(
                AllowedEndpoints: new[] { "/*", "/**" },
                HiddenEndpoints: new[] { "/export/*" },
                AllowedMethods: new[] { "GET" })));

        var wrapper = HttpWrapper(new OkHandler(), HttpMap);

        var act = () => wrapper.RequestAsync(
            SignedContext(policy), new HttpRequestArgs("GET", "/export/all.csv"));

        (await act.Should().ThrowAsync<Exception>()).Which.Message
            .Should().Contain("action 'export_pii' is prohibited");
    }

    // -- The delegation chain is checked, not merely carried ----------------

    /// <summary>A chain whose second hop widens its parent's purpose.</summary>
    private static DelegationHop[] WideningChain() => new[]
    {
        new DelegationHop("analyst@example.test", PrincipalType.User,
            DeclaredPurpose: "campaign-x"),
        new DelegationHop("agent-1", PrincipalType.Agent,
            DeclaredPurpose: "campaign-xyz-evil")
    };

    /// <summary>The same shape, narrowing legitimately on a segment boundary.</summary>
    private static DelegationHop[] NarrowingChain() => new[]
    {
        new DelegationHop("analyst@example.test", PrincipalType.User,
            DeclaredPurpose: "campaign-x"),
        new DelegationHop("agent-1", PrincipalType.Agent,
            DeclaredPurpose: "campaign-x-overlap")
    };

    private static SecurityContext SignedWithChain(DelegationHop[]? chain) =>
        SecurityContextSigner.Sign(
            SecurityContextBuilder.Build(
                "purpose-user", "purpose-tenant", new[] { PolicyWith(null) },
                delegationChain: chain),
            Key);

    [Fact]
    public void ValidateSecurityContext_AWideningChain_IsDenied()
    {
        // Through the wrapper, not the validator: a validator nobody calls passes all of its
        // own tests while enforcing nothing (testing-antipatterns.md section 4). What is
        // asserted here is that a context carrying a widened hop is actually refused at the
        // point a call is made.
        var result = ContextWrapper(null).ValidateSecurityContext(SignedWithChain(WideningChain()));

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be(
            "delegation hop 1 purpose 'campaign-xyz-evil' is not within parent scope 'campaign-x'");
    }

    [Fact]
    public void ValidateSecurityContext_ANarrowingChain_IsAllowed()
    {
        // The paired control: a wrapper that rejected every chain would satisfy the case above.
        ContextWrapper(null).ValidateSecurityContext(SignedWithChain(NarrowingChain()))
            .Allowed.Should().BeTrue();
    }

    [Fact]
    public void ValidateSecurityContext_NoChain_IsAllowed()
    {
        // Backward compatibility, stated as a test rather than as a comment: every context
        // issued before this feature carries no chain, and none of them may start failing.
        ContextWrapper(null).ValidateSecurityContext(SignedWithChain(null))
            .Allowed.Should().BeTrue();
    }

    [Fact]
    public void PreExecute_AWideningChain_IsDeniedBeforeAnythingElse()
    {
        // Through the call an integrator actually makes, not just the validator it may forget.
        ContextWrapper(ToolMap).PreExecute(
            SignedWithChain(WideningChain()), new PreExecuteArgs("segment_overlap"))
            .Allowed.Should().BeFalse();
    }

    [Fact]
    public void ValidateSecurityContext_ChecksTheSignatureBeforeTheChain()
    {
        // The ordering is the whole reason chain validation is worth doing. Validating an
        // unsigned chain checks the attacker's own arithmetic: anyone who can rewrite a hop can
        // rewrite it into something consistent. So a context with both a bad signature and a
        // widening chain must report the signature.
        var tampered = SignedWithChain(NarrowingChain()) with
        {
            DelegationChain = WideningChain()
        };

        ContextWrapper(null).ValidateSecurityContext(tampered)
            .Reason.Should().Be("invalid signature");
    }

    [Fact]
    public async Task HttpWrapper_AWideningChain_IsDenied()
    {
        // The HTTP wrapper validates contexts through its own private path, so a fix applied
        // only to the record wrapper would leave `api` sources unguarded.
        var wrapper = new SecureHttpToolWrapper(
            new SecureHttpWrapperOptions(Key), ClientOver(new OkHandler()));

        var policy = PolicyWith(null, new ObjectRules(EndpointRules: AllGet()));
        var context = SecurityContextSigner.Sign(
            SecurityContextBuilder.Build(
                "purpose-user", "purpose-tenant", new[] { policy },
                delegationChain: WideningChain()),
            Key);

        var act = () => wrapper.RequestAsync(context, new HttpRequestArgs("GET", "/segments/x"));

        (await act.Should().ThrowAsync<Exception>()).Which.Message
            .Should().Contain("is not within parent scope");
    }

    [Fact]
    public async Task HttpWrapper_ANarrowingChain_IsAllowed()
    {
        var wrapper = new SecureHttpToolWrapper(
            new SecureHttpWrapperOptions(Key), ClientOver(new OkHandler()));

        var policy = PolicyWith(null, new ObjectRules(EndpointRules: AllGet()));
        var context = SecurityContextSigner.Sign(
            SecurityContextBuilder.Build(
                "purpose-user", "purpose-tenant", new[] { policy },
                delegationChain: NarrowingChain()),
            Key);

        var body = await wrapper.RequestAsync(context, new HttpRequestArgs("GET", "/segments/x"));

        body.GetProperty("count").GetInt32().Should().Be(3);
    }

    // -- The salt must reach the HTTP wrapper too ---------------------------

    [Fact]
    public async Task HashSalt_ProducesTheSamePseudonymOverApiAsOverADatabase()
    {
        // The join-key property is the entire reason `hashSalt` is a deployment-wide value
        // rather than a per-wrapper one: the same input must hash to the same pseudonym
        // wherever it is masked, so an `api`-sourced row can be joined to a `db`-sourced one.
        //
        // `SecureHttpWrapperOptions` had no `HashSalt` at all, so .NET hashed unsalted over
        // `api` while Python and TypeScript salted it. That broke the property in two
        // directions at once — across SDKs for one policy, and across categories inside a
        // single .NET deployment — and it broke it silently, because an unsalted digest is a
        // perfectly plausible-looking hash.
        const string salt = "deployment-secret";
        var masked = new ObjectRules(
            EndpointRules: AllGet(),
            FieldRules: new FieldRules(MaskedFields: new[]
            {
                new MaskingRule("email", MaskType.Hash, new MaskingParameters(Algorithm: "sha256"))
            }));

        var context = SignedContext(PolicyWith(null, masked));

        // The api path, through the HTTP wrapper.
        var httpWrapper = new SecureHttpToolWrapper(
            new SecureHttpWrapperOptions(Key, HashSalt: salt),
            ClientOver(new EmailHandler()));
        var body = await httpWrapper.RequestAsync(context, new HttpRequestArgs("GET", "/customers"));
        var overApi = body.GetProperty("email").GetString();

        // The db path, through the record wrapper, with the identical salt and policy.
        var recordWrapper = new SecureContextToolWrapper(
            new SecureContextWrapperOptions(Key, HashSalt: salt));
        var rows = recordWrapper.PostExecute(
            context,
            new[] { new Dictionary<string, object?> { ["email"] = "a@example.test" } });
        var overDb = (string)rows[0]["email"]!;

        overApi.Should().Be(overDb,
            "the same value masked under the same salt must yield the same pseudonym in both "
            + "wrappers, or a masked identifier cannot be joined across source categories");

        // And the salt is doing something: an unsalted wrapper must differ. Without this the
        // assertion above would pass just as well if neither wrapper salted at all.
        var unsalted = new SecureHttpToolWrapper(
            new SecureHttpWrapperOptions(Key), ClientOver(new EmailHandler()));
        var withoutSalt = (await unsalted.RequestAsync(
            context, new HttpRequestArgs("GET", "/customers"))).GetProperty("email").GetString();

        withoutSalt.Should().NotBe(overApi, "a configured salt must change the digest");
    }

    /// <summary>Returns one JSON object carrying an email, for the masking assertions.</summary>
    private sealed class EmailHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
            => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    """{"email":"a@example.test"}""", Encoding.UTF8, "application/json"),
                RequestMessage = request
            });
    }
}
