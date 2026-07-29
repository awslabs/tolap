using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Tolap.Core;
using Tolap.Mcp;

namespace Tolap.Integration.Tests;

/// <summary>
/// openFDA scenarios.
///
/// Default mode: replay against pre-recorded responses in
/// fixtures/api/openfda/. Live mode (TOLAP_TEST_LIVE=1): refresh the recordings
/// from api.fda.gov once per test class, then run the SAME enforcement
/// assertions against the real responses.
/// </summary>
public sealed class OpenFdaTests : IClassFixture<OpenFdaTests.RecordingsFixture>
{
    private const string SigningKey = "openfda-integration-key";
    private static readonly bool LiveMode = Environment.GetEnvironmentVariable("TOLAP_TEST_LIVE") == "1";

    private static readonly Dictionary<string, string> Routes = new()
    {
        ["GET /drug/event.json"] = "drug_event_limit3.json",
        ["GET /drug/label.json"] = "drug_label_limit3.json",
        ["GET /food/enforcement.json"] = "food_enforcement_limit2.json",
    };

    private static readonly Dictionary<string, int> LiveLimits = new()
    {
        ["/drug/event.json"] = 3,
        ["/drug/label.json"] = 3,
        ["/food/enforcement.json"] = 2,
    };

    private readonly RecordingsFixture _recordings;

    public OpenFdaTests(RecordingsFixture recordings) { _recordings = recordings; }

    /// <summary>
    /// Refreshes the on-disk recordings from api.fda.gov once per test class
    /// when TOLAP_TEST_LIVE=1 is set. Subsequent assertions cross-reference
    /// the fresh recording for the canonical pre-mask values.
    /// </summary>
    public sealed class RecordingsFixture : IAsyncLifetime
    {
        public async Task InitializeAsync()
        {
            if (Environment.GetEnvironmentVariable("TOLAP_TEST_LIVE") != "1") return;

            using var http = new HttpClient { BaseAddress = new Uri("https://api.fda.gov/") };
            http.DefaultRequestHeaders.UserAgent.ParseAdd("tolap-sdk-tests/1.0");
            foreach (var (routeKey, fixtureFile) in Routes)
            {
                var path = routeKey.Split(' ')[1];
                var url = $"{path}?limit={LiveLimits[path]}";
                using var response = await http.GetAsync(url);
                response.EnsureSuccessStatusCode();
                var body = await response.Content.ReadAsStringAsync();
                var fixturePath = Path.Combine(ScenarioHelpers.OpenFdaFixturesDir, fixtureFile);
                await File.WriteAllTextAsync(fixturePath, body);
            }
        }

        public Task DisposeAsync() => Task.CompletedTask;
    }

    public static IEnumerable<object[]> Scenarios
    {
        get
        {
            var json = ScenarioHelpers.LoadScenarioFile("openfda-api-enforcement.json");
            using var doc = JsonDocument.Parse(json);
            var basePolicy = doc.RootElement.GetProperty("basePolicy").GetRawText();
            foreach (var s in doc.RootElement.GetProperty("scenarios").EnumerateArray())
            {
                yield return new object[]
                {
                    s.GetProperty("name").GetString()!,
                    basePolicy,
                    s.GetRawText()
                };
            }
        }
    }

    [Theory]
    [MemberData(nameof(Scenarios))]
    public async Task OpenFdaScenario(string name, string baseJson, string scenarioJson)
    {
        using var baseDoc = JsonDocument.Parse(baseJson);
        using var scenarioDoc = JsonDocument.Parse(scenarioJson);
        var scenario = scenarioDoc.RootElement;

        var policy = ScenarioHelpers.PolicyFromJson(baseDoc.RootElement);
        var ctx = ScenarioHelpers.SignPolicy(policy, SigningKey);

        var request = scenario.GetProperty("request");
        var method = request.GetProperty("method").GetString()!;
        var basePath = request.GetProperty("path").GetString()!;
        string? collectionPath = null;
        if (request.TryGetProperty("collectionPath", out var cp))
        {
            collectionPath = cp.GetString();
        }

        // In live mode pass ?limit=N so the wrapper's response matches the
        // recording row count refreshed by the fixture.
        var path = LiveMode && LiveLimits.TryGetValue(basePath, out var limit)
            ? $"{basePath}?limit={limit}"
            : basePath;

        using var http = LiveMode ? CreateLiveClient() : CreateReplayClient();
        var wrapper = new SecureHttpToolWrapper(new SecureHttpWrapperOptions(SigningKey), http);
        var args = new HttpRequestArgs(method, path, collectionPath);

        var expected = scenario.GetProperty("expected");
        if (!expected.GetProperty("pass").GetBoolean())
        {
            var errorContains = expected.GetProperty("errorContains").GetString()!;
            var ex = await Record.ExceptionAsync(() => wrapper.RequestAsync(ctx, args));
            ex.Should().NotBeNull($"scenario {name}");
            ex!.Message.Should().Contain(errorContains);
            return;
        }

        var body = await wrapper.RequestAsync(ctx, args);
        AssertPass(body, expected, request);
    }

    private static void AssertPass(JsonElement body, JsonElement expected, JsonElement request)
    {
        string? collectionPath = null;
        if (request.TryGetProperty("collectionPath", out var cp))
        {
            collectionPath = cp.GetString();
        }

        if (expected.TryGetProperty("rowCount", out var rowCount) && collectionPath is not null)
        {
            var coll = Walk(body, collectionPath.Split('.'));
            coll.Should().NotBeNull($"the response should carry a collection at '{collectionPath}'");
            coll!.Value.ValueKind.Should().Be(JsonValueKind.Array);
            coll.Value.GetArrayLength().Should().Be(rowCount.GetInt32());
        }

        if (expected.TryGetProperty("maskedField", out var maskedSpec))
        {
            var cpath = maskedSpec.GetProperty("collectionPath").GetString()!;
            var field = maskedSpec.GetProperty("field").GetString()!;
            var mask = maskedSpec.GetProperty("mask").GetString()!;
            var coll = Walk(body, cpath.Split('.'));
            coll.Should().NotBeNull($"the response should carry a collection at '{cpath}'");
            var path = request.GetProperty("path").GetString()!;
            var fixturePath = Path.Combine(ScenarioHelpers.OpenFdaFixturesDir, Routes[$"GET {path}"]);
            using var origDoc = JsonDocument.Parse(File.ReadAllText(fixturePath));
            var origColl = Walk(origDoc.RootElement, cpath.Split('.'))!.Value;

            var actuals = coll!.Value.EnumerateArray().ToArray();
            var origs = origColl.EnumerateArray().ToArray();
            for (var i = 0; i < actuals.Length; i++)
            {
                var actualValue = Walk(actuals[i], field.Split('.'));
                var origValue = Walk(origs[i], field.Split('.'));
                AssertMask(actualValue, origValue, mask);
            }
        }

        if (expected.TryGetProperty("hiddenField", out var hiddenSpec))
        {
            var cpath = hiddenSpec.GetProperty("collectionPath").GetString()!;
            var field = hiddenSpec.GetProperty("field").GetString()!;
            var coll = Walk(body, cpath.Split('.'))!.Value;
            foreach (var row in coll.EnumerateArray())
            {
                var hidden = Walk(row, field.Split('.'));
                hidden.Should().BeNull($"hidden field {field} must not appear");
            }
        }
    }

    private static void AssertMask(JsonElement? actual, JsonElement? original, string mask)
    {
        actual.Should().NotBeNull();
        original.Should().NotBeNull();

        var actualStr = ExtractString(actual!.Value);
        var originalStr = ExtractString(original!.Value);

        switch (mask)
        {
            case "sha256-16":
            {
                using var sha = SHA256.Create();
                var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(originalStr));
                var hex = Convert.ToHexString(hash).ToLowerInvariant()[..16];
                actualStr.Should().Be(hex);
                break;
            }
            case "redacted":
                actualStr.Should().Be("[REDACTED]");
                break;
            default:
                throw new InvalidOperationException($"unknown mask {mask}");
        }
    }

    private static string ExtractString(JsonElement el) => el.ValueKind switch
    {
        JsonValueKind.String => el.GetString() ?? "",
        JsonValueKind.Number => el.GetRawText(),
        _ => el.GetRawText()
    };

    private static JsonElement? Walk(JsonElement node, string[] parts)
    {
        var cur = node;
        foreach (var p in parts)
        {
            if (cur.ValueKind != JsonValueKind.Object || !cur.TryGetProperty(p, out var next))
                return null;
            cur = next;
        }
        return cur;
    }

    private static HttpClient CreateLiveClient()
    {
        var http = new HttpClient { BaseAddress = new Uri("https://api.fda.gov/") };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("tolap-sdk-tests/1.0");
        return http;
    }

    private static HttpClient CreateReplayClient()
    {
        return new HttpClient(new ReplayHandler())
        {
            BaseAddress = new Uri("https://api.fda.gov/"),
        };
    }

    private sealed class ReplayHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var key = $"{request.Method.Method.ToUpper()} {request.RequestUri!.AbsolutePath}";
            if (!Routes.TryGetValue(key, out var fixtureFile))
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            }
            var path = Path.Combine(ScenarioHelpers.OpenFdaFixturesDir, fixtureFile);
            var body = File.ReadAllText(path);
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            };
            return Task.FromResult(response);
        }
    }
}
