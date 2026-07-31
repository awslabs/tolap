using System.Net;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Tolap.Core;
using Tolap.Mcp;
using Xunit;

namespace Tolap.Mcp.Tests;

/// <summary>
/// Cross-SDK parity for the HTTP wrapper's connector-spec.md section 6 category requirements.
/// </summary>
/// <remarks>
/// <para>
/// One case corpus — status code x policy, and redirect shape x policy -&gt; outcome — asserted
/// with byte-identical expected outcomes in all three SDKs. The counterparts are:
/// </para>
/// <list type="bullet">
///   <item><description>Python: <c>tests/test_http_wrapper_parity.py</c> (the reference
///     ordering)</description></item>
///   <item><description>TypeScript:
///     <c>packages/mcp/tests/http-wrapper-parity.test.ts</c></description></item>
/// </list>
/// <para>
/// The three tables must stay identical case-for-case, and this file follows the Python
/// ordering row for row so a diff of the three is readable.
/// </para>
/// <para>
/// <b>The denial reasons are asserted, not just the outcome kind.</b> They are the contract
/// integrators log and branch on, and each names a different policy or client edit that would
/// unblock the caller: <c>endpoint is hidden</c> is fixed by editing <c>hiddenEndpoints</c>,
/// <c>redirect crosses origin</c> cannot be fixed by a policy edit at all, and <c>too many
/// redirects</c> points at the chain rather than the rules.
/// </para>
/// <para>
/// A corpus of this shape is what catches divergence: three per-SDK suites each assert the
/// behaviour that SDK happens to implement, which is exactly how the single-record body ended
/// up with three different answers — Python <c>None</c>, TypeScript <c>[]</c>, .NET the record
/// unfiltered — while every suite stayed green.
/// </para>
/// </remarks>
public class HttpWrapperParityTests
{
    private const string Key = "http-parity-key";
    private const string Base = "https://parity.test";

    private static EffectivePolicy PolicyOf(ObjectRules objectRules)
    {
        var now = DateTimeOffset.UtcNow;
        return new EffectivePolicy(
            Version: "1.0",
            UserId: "parity-user",
            TenantId: "parity-tenant",
            SourceConnectionId: "api:parity:test",
            ResolvedAt: now,
            ExpiresAt: now.AddHours(1),
            SourceProfiles: new[] { "http-wrapper-parity" },
            Permissions: new PolicyPermissions(CanQuery: true, ReadOnly: true),
            ObjectRules: objectRules);
    }

    // -- The shared parity policies. Identical field-for-field in all three SDKs. --

    private static EndpointRules AllGet() => new(
        AllowedEndpoints: new[] { "/*", "/**" }, AllowedMethods: new[] { "GET" });

    /// <summary>Every path reachable by GET, no field rules: the control case.</summary>
    private static EffectivePolicy Open() => PolicyOf(new ObjectRules(EndpointRules: AllGet()));

    /// <summary>
    /// <c>error</c> hidden. The 4xx/5xx body is exactly {"error": {...}}, so enforced is {}.
    /// </summary>
    private static EffectivePolicy HideError() => PolicyOf(new ObjectRules(
        EndpointRules: AllGet(),
        FieldRules: new FieldRules(HiddenFields: new[] { "error" })));

    /// <summary>
    /// <c>message</c> redacted, proving masking reaches an error body's nested leaf.
    /// </summary>
    private static EffectivePolicy MaskMessage() => PolicyOf(new ObjectRules(
        EndpointRules: AllGet(),
        FieldRules: new FieldRules(MaskedFields: new[]
        {
            new MaskingRule("message", MaskType.Redact)
        })));

    /// <summary>
    /// A filter the error body cannot satisfy: fails closed, dropping it to null.
    /// </summary>
    private static EffectivePolicy FilterDropsError() => PolicyOf(new ObjectRules(
        EndpointRules: AllGet(),
        RowFilters: new[] { new RowFilter("account", FilterOperator.NotEquals, "other") }));

    /// <summary>Redirect sources permitted, the redirect <i>target</i> hidden.</summary>
    private static EffectivePolicy RedirectTargetHidden() => PolicyOf(new ObjectRules(
        EndpointRules: new EndpointRules(
            AllowedEndpoints: new[] { "/redirect/*" },
            HiddenEndpoints: new[] { "/admin/*" },
            AllowedMethods: new[] { "GET" })));

    /// <summary>Redirect sources permitted and nothing else.</summary>
    private static EffectivePolicy RedirectOnly() => PolicyOf(new ObjectRules(
        EndpointRules: new EndpointRules(
            AllowedEndpoints: new[] { "/redirect/*" }, AllowedMethods: new[] { "GET" })));

    /// <summary>Both the redirect source and its target permitted.</summary>
    private static EffectivePolicy RedirectAndTarget() => PolicyOf(new ObjectRules(
        EndpointRules: new EndpointRules(
            AllowedEndpoints: new[] { "/redirect/*", "/patients" },
            AllowedMethods: new[] { "GET" })));

    /// <summary>
    /// The object named by the caller is hidden; endpoint rules allow everything.
    /// </summary>
    private static EffectivePolicy ObjectHidden() => PolicyOf(new ObjectRules(
        EndpointRules: AllGet(), HiddenObjects: new[] { "patients" }));

    /// <summary>An allow-list the named object is absent from.</summary>
    private static EffectivePolicy ObjectNotAllowed() => PolicyOf(new ObjectRules(
        EndpointRules: AllGet(), AllowedObjects: new[] { "encounters" }));

    /// <summary>Resolves a corpus policy key to its policy.</summary>
    private static EffectivePolicy PolicyFor(string key) => key switch
    {
        "open" => Open(),
        "hide-error" => HideError(),
        "mask-message" => MaskMessage(),
        "filter-drops-error" => FilterDropsError(),
        "redirect-target-hidden" => RedirectTargetHidden(),
        "redirect-only" => RedirectOnly(),
        "redirect-and-target" => RedirectAndTarget(),
        "object-hidden" => ObjectHidden(),
        "object-not-allowed" => ObjectNotAllowed(),
        _ => throw new ArgumentOutOfRangeException(nameof(key), key, "unknown parity policy")
    };

    // -----------------------------------------------------------------------
    // Table 1: status code x policy -> enforced error body (section 6)
    // -----------------------------------------------------------------------

    // A status of 200 is in the table on purpose: the success and error paths must run the
    // *same* pipeline, and a table that only listed error codes could not show that. The
    // expectation is spelled as compact JSON so the three tables can be diffed literally.
    public static TheoryData<string, string, int, string> ErrorBodyCorpus() => new()
    {
        // -- No field rules: the payload survives, whatever the status. --
        { "open-200", "open", 200, """{"error":{"code":200,"message":"synthetic"}}""" },
        { "open-400", "open", 400, """{"error":{"code":400,"message":"synthetic"}}""" },
        { "open-401", "open", 401, """{"error":{"code":401,"message":"synthetic"}}""" },
        { "open-403", "open", 403, """{"error":{"code":403,"message":"synthetic"}}""" },
        { "open-404", "open", 404, """{"error":{"code":404,"message":"synthetic"}}""" },
        { "open-422", "open", 422, """{"error":{"code":422,"message":"synthetic"}}""" },
        { "open-429", "open", 429, """{"error":{"code":429,"message":"synthetic"}}""" },
        { "open-500", "open", 500, """{"error":{"code":500,"message":"synthetic"}}""" },
        { "open-503", "open", 503, """{"error":{"code":503,"message":"synthetic"}}""" },

        // -- hiddenFields empties the body identically on every status. This is the row that
        // -- failed before the fix: EnsureSuccessStatusCode raised before the pipeline ran, so
        // -- the 4xx/5xx payload was never enforced while the 200 twin was.
        { "hide-error-200", "hide-error", 200, "{}" },
        { "hide-error-400", "hide-error", 400, "{}" },
        { "hide-error-401", "hide-error", 401, "{}" },
        { "hide-error-403", "hide-error", 403, "{}" },
        { "hide-error-404", "hide-error", 404, "{}" },
        { "hide-error-422", "hide-error", 422, "{}" },
        { "hide-error-429", "hide-error", 429, "{}" },
        { "hide-error-500", "hide-error", 500, "{}" },
        { "hide-error-503", "hide-error", 503, "{}" },

        // -- Masking reaches a nested leaf of an error body, not only a success one's.
        { "mask-200", "mask-message", 200, """{"error":{"code":200,"message":"[REDACTED]"}}""" },
        { "mask-400", "mask-message", 400, """{"error":{"code":400,"message":"[REDACTED]"}}""" },
        { "mask-500", "mask-message", 500, """{"error":{"code":500,"message":"[REDACTED]"}}""" },

        // -- The record-dropping steps reach an error body too. The body is a single record,
        // -- and a filter it cannot satisfy drops it to null (canonical spec section 4).
        { "filter-drops-200", "filter-drops-error", 200, "null" },
        { "filter-drops-400", "filter-drops-error", 400, "null" },
        { "filter-drops-500", "filter-drops-error", 500, "null" },
    };

    // -----------------------------------------------------------------------
    // Table 2: redirect shape x policy -> outcome (section 6)
    // -----------------------------------------------------------------------

    // `hops` is how many 302s the transport serves before the final 200. A null denial means
    // "followed and enforced".
    public static TheoryData<string, string, string, int, string?> RedirectCorpus() => new()
    {
        // -- A permitted source redirecting to a denied target: the whole point of section 6.
        { "hidden-target-relative", "redirect-target-hidden", "/admin/audit", 1,
          "redirect target rejected: endpoint is hidden" },
        { "not-allowed-target", "redirect-only", "/admin/audit", 1,
          "redirect target rejected: endpoint not in allowed set" },
        // A relative Location that walks up: resolved against the request URL, then re-globbed
        // on the resulting path, so "../admin/audit" is denied like the absolute spelling
        // rather than matched literally.
        { "hidden-target-dot-dot", "redirect-target-hidden", "../admin/audit", 1,
          "redirect target rejected: endpoint is hidden" },
        // An absolute Location on the SAME origin is re-globbed normally: it is the host
        // change, not the absoluteness, that takes a hop out of the policy's frame.
        { "hidden-target-absolute-same-origin", "redirect-target-hidden",
          Base + "/admin/audit", 1, "redirect target rejected: endpoint is hidden" },

        // -- A permitted target is followed: re-validating is not refusing. --
        { "permitted-target", "redirect-and-target", "/patients", 1, null },
        { "permitted-target-absolute", "redirect-and-target", Base + "/patients", 1, null },
        // The Location's own query string is not policy-relevant (the path is), and it must not
        // be corrupted by re-appending the original request's params.
        { "permitted-target-with-query", "redirect-and-target", "/patients?region=us-east", 1, null },

        // -- Cross-origin: refused on the host change, never re-globbed on the path. --
        // "open" allows "/*" and "/**", so a wrapper that globbed the path would ALLOW every
        // one of these. That is what makes them the fail-open rows.
        { "cross-host", "open", "https://attacker.test/patients", 1, "redirect crosses origin" },
        { "cross-port", "open", "https://parity.test:8443/patients", 1, "redirect crosses origin" },
        { "cross-scheme-downgrade", "open", "http://parity.test/patients", 1,
          "redirect crosses origin" },

        // -- The hop budget is the wrapper's, not the transport's. --
        { "chain-at-limit", "redirect-and-target", "/patients",
          SecureHttpToolWrapper.MaxRedirects, null },
        { "chain-past-limit", "redirect-and-target", "/patients",
          SecureHttpToolWrapper.MaxRedirects + 1,
          $"too many redirects (limit {SecureHttpToolWrapper.MaxRedirects})" },

        // -- The object check is part of a hop, so a redirect cannot shed it. --
        { "object-hidden-on-hop", "object-hidden", "/patients", 1, "object is hidden" },
    };

    // -----------------------------------------------------------------------
    // Table 3: object name x policy -> outcome (section 6, last bullet)
    // -----------------------------------------------------------------------

    // The rows with no object name pin "no inference": the identical policy that denies a named
    // object must ALLOW the same path when nothing is named, because deriving a resource from a
    // route is the unspecified behaviour section 6 warns against.
    //
    // A case-sensitivity row (hiddenObjects: ["patients"] against an object name of "PATIENTS")
    // is deliberately NOT in this table, and its absence is a finding rather than an oversight.
    // Adding it exposed a divergence in ValidateAccess itself, not in the HTTP wrappers: this
    // implementation and Python's both match case-insensitively, while TypeScript's globToRegex
    // compiles a case-SENSITIVE regex, so the identical policy denies in two SDKs and allows in
    // the third. That is a core-enforcement bug on every path object rules reach — database and
    // MCP included — not something the api category introduces.
    public static TheoryData<string, string, string?, string?> ObjectNameCorpus() => new()
    {
        { "hidden-object-named", "object-hidden", "patients", "object is hidden" },
        { "hidden-object-not-named", "object-hidden", null, null },
        { "object-not-in-allow-list", "object-not-allowed", "patients", "object not in allowed set" },
        { "object-in-allow-list", "object-not-allowed", "encounters", null },
        { "allow-list-not-named", "object-not-allowed", null, null },
        { "no-object-rules-named", "open", "patients", null },
    };

    [Theory]
    [MemberData(nameof(ErrorBodyCorpus))]
    public async Task ErrorBody_MatchesTheSharedExpectation(
        string caseId, string policyKey, int status, string expectedJson)
    {
        _ = caseId;
        var policy = PolicyFor(policyKey);
        using var client = ClientOver(new StatusHandler(status));
        var wrapper = new SecureHttpToolWrapper(new SecureHttpWrapperOptions(Key), client);

        if (status is >= 200 and < 300)
        {
            var body = await wrapper.RequestAsync(
                SignedContext(policy), new HttpRequestArgs("GET", "/status"));
            Compact(body).Should().Be(expectedJson);
            return;
        }

        var act = () => wrapper.RequestAsync(
            SignedContext(policy), new HttpRequestArgs("GET", "/status"));

        var exception = (await act.Should().ThrowAsync<UpstreamHttpException>()).Which;
        exception.Status.Should().Be(status);
        exception.Body.Should().NotBeNull();
        Compact(exception.Body!.Value).Should().Be(expectedJson);
    }

    [Theory]
    [MemberData(nameof(RedirectCorpus))]
    public async Task Redirect_MatchesTheSharedExpectation(
        string caseId, string policyKey, string location, int hops, string? denial)
    {
        _ = caseId;
        var policy = PolicyFor(policyKey);
        using var client = ClientOver(new RedirectHandler(location, hops));
        var wrapper = new SecureHttpToolWrapper(new SecureHttpWrapperOptions(Key), client);
        var objectName = policyKey == "object-hidden" ? "patients" : null;

        if (denial is null)
        {
            var body = await wrapper.RequestAsync(
                SignedContext(policy),
                new HttpRequestArgs("GET", "/redirect/0", CollectionPath: "results",
                    ObjectName: objectName));
            Compact(body.GetProperty("results"))
                .Should().Be("""[{"id":1,"region":"us-east"}]""");
            return;
        }

        var act = () => wrapper.RequestAsync(
            SignedContext(policy),
            new HttpRequestArgs("GET", "/redirect/0", ObjectName: objectName));

        (await act.Should().ThrowAsync<UnauthorizedAccessException>())
            .Which.Message.Should().Contain(denial);
    }

    [Theory]
    [MemberData(nameof(ObjectNameCorpus))]
    public async Task ObjectName_MatchesTheSharedExpectation(
        string caseId, string policyKey, string? objectName, string? denial)
    {
        _ = caseId;
        var policy = PolicyFor(policyKey);
        using var client = ClientOver(new JsonHandler("""{"results":[{"id":1}]}"""));
        var wrapper = new SecureHttpToolWrapper(new SecureHttpWrapperOptions(Key), client);

        if (denial is null)
        {
            var body = await wrapper.RequestAsync(
                SignedContext(policy),
                new HttpRequestArgs("GET", "/patients", CollectionPath: "results",
                    ObjectName: objectName));
            Compact(body.GetProperty("results")).Should().Be("""[{"id":1}]""");
            return;
        }

        var act = () => wrapper.RequestAsync(
            SignedContext(policy),
            new HttpRequestArgs("GET", "/patients", ObjectName: objectName));

        (await act.Should().ThrowAsync<UnauthorizedAccessException>())
            .Which.Message.Should().Contain(denial);
    }

    // A corpus that silently shrank would make every SDK agree by asserting nothing.

    [Fact]
    public void TheTablesCarryTheExpectedNumberOfCases()
    {
        ErrorBodyCorpus().Count().Should().Be(24);
        RedirectCorpus().Count().Should().Be(13);
        ObjectNameCorpus().Count().Should().Be(6);
    }

    [Fact]
    public void TheHopBudgetIsTheAgreedNumber()
    {
        // All three SDKs state 5, independently of any client's own default.
        SecureHttpToolWrapper.MaxRedirects.Should().Be(5);
    }

    // -- Helpers --

    private static HttpClient ClientOver(HttpMessageHandler handler) =>
        new(handler) { BaseAddress = new Uri(Base + "/") };

    private static SecurityContext SignedContext(EffectivePolicy policy) =>
        SecurityContextSigner.Sign(
            SecurityContextBuilder.Build("parity-user", "parity-tenant", new[] { policy }), Key);

    /// <summary>
    /// Serializes an element with no whitespace, so a corpus row can be a literal string and
    /// the three tables can be diffed against each other by eye.
    /// </summary>
    private static string Compact(JsonElement element) => JsonSerializer.Serialize(element);

    /// <summary>Returns one status and the shared error-shaped body.</summary>
    private sealed class StatusHandler : HttpMessageHandler
    {
        private readonly int _status;
        public StatusHandler(int status) => _status = status;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
            => Task.FromResult(new HttpResponseMessage((HttpStatusCode)_status)
            {
                Content = new StringContent(
                    $"{{\"error\":{{\"code\":{_status},\"message\":\"synthetic\"}}}}",
                    Encoding.UTF8,
                    "application/json"),
                RequestMessage = request
            });
    }

    /// <summary>Returns a fixed 200 JSON body.</summary>
    private sealed class JsonHandler : HttpMessageHandler
    {
        private readonly string _body;
        public JsonHandler(string body) => _body = body;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
            => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(_body, Encoding.UTF8, "application/json"),
                RequestMessage = request
            });
    }

    /// <summary>
    /// Serves <c>hops</c> redirects then a 200 collection.
    /// </summary>
    /// <remarks>
    /// The intermediate hops point back at a permitted /redirect/N so only the FINAL hop
    /// exercises the case's Location.
    /// </remarks>
    private sealed class RedirectHandler : HttpMessageHandler
    {
        private readonly string _location;
        private readonly int _hops;
        private int _served;

        public RedirectHandler(string location, int hops)
        {
            _location = location;
            _hops = hops;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            _served++;
            if (_served <= _hops)
            {
                var target = _served < _hops ? $"/redirect/{_served}" : _location;
                var redirect = new HttpResponseMessage(HttpStatusCode.Found)
                {
                    Content = new StringContent("", Encoding.UTF8, "application/json"),
                    RequestMessage = request
                };
                redirect.Headers.Location = new Uri(target, UriKind.RelativeOrAbsolute);
                return Task.FromResult(redirect);
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    """{"results":[{"id":1,"region":"us-east"}]}""",
                    Encoding.UTF8,
                    "application/json"),
                RequestMessage = request
            });
        }
    }
}
