using System.Net;
using System.Text;
using FluentAssertions;
using Tolap.Core;
using Tolap.Mcp;

namespace Tolap.Integration.Tests;

/// <summary>
/// HTTP error and short-circuit behavior for the .NET SecureHttpToolWrapper.
/// Mirrors the Python and TypeScript suites.
/// </summary>
public sealed class HttpErrorPathsTests
{
    private const string SigningKey = "openfda-integration-key";

    private static EffectivePolicy AllowDrugPolicy()
    {
        var now = DateTimeOffset.UtcNow;
        return new EffectivePolicy(
            Version: "1.0",
            UserId: "u",
            TenantId: "t",
            SourceConnectionId: "s",
            ResolvedAt: now,
            ExpiresAt: now.AddHours(1),
            SourceProfiles: new[] { "http-error-test" },
            Permissions: new PolicyPermissions(CanQuery: true),
            ObjectRules: new ObjectRules(
                EndpointRules: new EndpointRules(
                    AllowedEndpoints: new[] { "/drug/*" },
                    HiddenEndpoints: new[] { "/food/*" },
                    AllowedMethods: new[] { "GET" })));
    }

    private static SecurityContext SignedCtx()
    {
        var ctx = SecurityContextBuilder.Build("u", "t", new[] { AllowDrugPolicy() });
        return SecurityContextSigner.Sign(ctx, SigningKey);
    }

    [Theory]
    [InlineData(404)]
    [InlineData(429)]
    [InlineData(500)]
    public async Task UpstreamErrorIsPropagated(int status)
    {
        var handler = new StatusHandler((HttpStatusCode)status);
        using var http = new HttpClient(handler) { BaseAddress = new Uri("https://api.fda.gov/") };
        var wrapper = new SecureHttpToolWrapper(new SecureHttpWrapperOptions(SigningKey), http);

        var ex = await Record.ExceptionAsync(() =>
            wrapper.RequestAsync(SignedCtx(), new HttpRequestArgs("GET", "/drug/event.json")));
        ex.Should().NotBeNull();
    }

    [Fact]
    public async Task HiddenEndpointDoesNotInvokeTransport()
    {
        var counter = new CountingHandler((HttpStatusCode)500);
        using var http = new HttpClient(counter) { BaseAddress = new Uri("https://api.fda.gov/") };
        var wrapper = new SecureHttpToolWrapper(new SecureHttpWrapperOptions(SigningKey), http);

        var ex = await Record.ExceptionAsync(() =>
            wrapper.RequestAsync(SignedCtx(), new HttpRequestArgs("GET", "/food/enforcement.json")));
        ex.Should().NotBeNull();
        ex!.Message.Should().Contain("endpoint is hidden");
        counter.Calls.Should().Be(0, "transport must not be called for a denied endpoint");
    }

    [Fact]
    public async Task MethodDenialDoesNotInvokeTransport()
    {
        var counter = new CountingHandler(HttpStatusCode.OK);
        using var http = new HttpClient(counter) { BaseAddress = new Uri("https://api.fda.gov/") };
        var wrapper = new SecureHttpToolWrapper(new SecureHttpWrapperOptions(SigningKey), http);

        var ex = await Record.ExceptionAsync(() =>
            wrapper.RequestAsync(SignedCtx(), new HttpRequestArgs("DELETE", "/drug/event.json")));
        ex.Should().NotBeNull();
        ex!.Message.Should().Contain("method not allowed");
        counter.Calls.Should().Be(0);
    }

    private sealed class StatusHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _code;
        public StatusHandler(HttpStatusCode code) { _code = code; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
            => Task.FromResult(new HttpResponseMessage(_code) { Content = new StringContent("{}", Encoding.UTF8, "application/json") });
    }

    private sealed class CountingHandler : HttpMessageHandler
    {
        public int Calls;
        private readonly HttpStatusCode _code;
        public CountingHandler(HttpStatusCode code) { _code = code; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Interlocked.Increment(ref Calls);
            return Task.FromResult(new HttpResponseMessage(_code) { Content = new StringContent("{}", Encoding.UTF8, "application/json") });
        }
    }
}
