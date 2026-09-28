using System.Net;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Tolap.Core;
using Tolap.Mcp;
using Xunit;

namespace Tolap.Mcp.Tests;

/// <summary>
/// The HTTP wrapper's own allowedFields projection honours object qualifiers (issue #36).
/// </summary>
/// <remarks>
/// The Python and TypeScript HTTP wrappers project through the core
/// <c>project_allowed_fields</c>/<c>projectAllowedFields</c>, which the shared fixture
/// <c>fixtures/enforcement/allowed-fields-qualified.json</c> already pins. The .NET wrapper
/// walks the body with a projection of its own, so it is pinned here: an entry qualified with
/// one object must not keep another object's column.
/// </remarks>
public class HttpWrapperAllowedFieldsQualifierTests
{
    private const string Key = "http-allowed-qualifier-key";
    private const string Base = "https://allowed-qualifier.test";

    private static SecurityContext SignedContext(string[] allowedFields)
    {
        var now = DateTimeOffset.UtcNow;
        var policy = new EffectivePolicy(
            Version: "1.0",
            UserId: "qualifier-user",
            TenantId: "qualifier-tenant",
            SourceConnectionId: "api:qualifier:test",
            ResolvedAt: now,
            ExpiresAt: now.AddHours(1),
            SourceProfiles: new[] { "allowed-fields-qualified" },
            Permissions: new PolicyPermissions(CanQuery: true, ReadOnly: true),
            ObjectRules: new ObjectRules(
                EndpointRules: new EndpointRules(
                    AllowedEndpoints: new[] { "/*", "/**" }, AllowedMethods: new[] { "GET" }),
                FieldRules: new FieldRules(AllowedFields: allowedFields)));
        return SecurityContextSigner.Sign(
            SecurityContextBuilder.Build("qualifier-user", "qualifier-tenant", new[] { policy }), Key);
    }

    private static async Task<string> ResultsFor(string[] allowedFields, string? collectionPath)
    {
        const string body =
            """{"results":[{"patients.name":"pat","encounters.name":"enc","name":"bare","patients.id":1,"encounters.id":2}]}""";
        using var client = new HttpClient(new JsonHandler(collectionPath is null ? ExtractArray(body) : body))
        {
            BaseAddress = new Uri(Base + "/")
        };
        var wrapper = new SecureHttpToolWrapper(new SecureHttpWrapperOptions(Key), client);

        var result = await wrapper.RequestAsync(
            SignedContext(allowedFields),
            new HttpRequestArgs("GET", "/patients", CollectionPath: collectionPath));

        return JsonSerializer.Serialize(collectionPath is null ? result : result.GetProperty("results"));
    }

    private static string ExtractArray(string body)
        => JsonDocument.Parse(body).RootElement.GetProperty("results").GetRawText();

    [Theory]
    [InlineData("results")]
    [InlineData(null)]
    public async Task AQualifiedEntryKeepsItsOwnObjectAndBareKeysOnly(string? collectionPath)
    {
        var results = await ResultsFor(new[] { "patients.name" }, collectionPath);

        results.Should().Be("""[{"patients.name":"pat","name":"bare"}]""");
    }

    [Theory]
    [InlineData("results")]
    [InlineData(null)]
    public async Task AnObjectWildcardDoesNotReachAnotherObject(string? collectionPath)
    {
        var results = await ResultsFor(new[] { "patients.*" }, collectionPath);

        results.Should().Be("""[{"patients.name":"pat","name":"bare","patients.id":1}]""");
    }

    [Fact]
    public async Task ABareEntryStillKeepsEveryObjectsColumn()
    {
        var results = await ResultsFor(new[] { "name" }, "results");

        results.Should().Be("""[{"patients.name":"pat","encounters.name":"enc","name":"bare"}]""");
    }

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
}
