using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using FluentAssertions;
using Tolap.Core;
using Tolap.Mcp;

namespace Tolap.Integration.Tests;

/// <summary>
/// Cross-SDK adversarial / edge-case scenarios for the openFDA wrapper.
/// Same JSON file the Python and TypeScript SDKs consume.
/// </summary>
public sealed class OpenFdaEdgeCasesTests : IClassFixture<OpenFdaEdgeCasesTests.RecordingsFixture>
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
            var json = ScenarioHelpers.LoadScenarioFile("openfda-edge-cases.json");
            using var doc = JsonDocument.Parse(json);
            foreach (var s in doc.RootElement.GetProperty("scenarios").EnumerateArray())
            {
                yield return new object[] { s.GetProperty("name").GetString()!, s.GetRawText() };
            }
        }
    }

    [Theory]
    [MemberData(nameof(Scenarios))]
    public async Task EdgeCase(string name, string scenarioJson)
    {
        using var doc = JsonDocument.Parse(scenarioJson);
        var scenario = doc.RootElement;

        var policy = ScenarioHelpers.PolicyFromJson(scenario.GetProperty("policy"));
        var ctx = ScenarioHelpers.SignPolicy(policy, SigningKey);

        var request = scenario.GetProperty("request");
        var method = request.GetProperty("method").GetString()!;
        var basePath = request.GetProperty("path").GetString()!;
        string? collectionPath = null;
        if (request.TryGetProperty("collectionPath", out var cp))
            collectionPath = cp.GetString();

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
            ex.Should().NotBeNull();
            ex!.Message.Should().Contain(errorContains, $"scenario {name}");
            return;
        }

        var body = await wrapper.RequestAsync(ctx, args);
        AssertPass(name, body, expected, request);
    }

    private static void AssertPass(string name, JsonElement body, JsonElement expected, JsonElement request)
    {
        string? cp = null;
        if (request.TryGetProperty("collectionPath", out var cpEl))
            cp = cpEl.GetString();

        if (expected.TryGetProperty("rowCount", out var rowCount) && cp is not null)
        {
            var coll = Walk(body, cp.Split('.'));
            coll!.Value.ValueKind.Should().Be(JsonValueKind.Array, $"scenario {name}");
            coll!.Value.GetArrayLength().Should().Be(rowCount.GetInt32());
        }

        if (expected.TryGetProperty("minResultsCount", out var minCount) && cp is not null)
        {
            var coll = Walk(body, cp.Split('.'));
            coll!.Value.ValueKind.Should().Be(JsonValueKind.Array);
            coll.Value.GetArrayLength().Should().BeGreaterThanOrEqualTo(minCount.GetInt32());
        }

        if (expected.TryGetProperty("hiddenField", out var hiddenSpec))
        {
            var cpath = hiddenSpec.GetProperty("collectionPath").GetString()!;
            var field = hiddenSpec.GetProperty("field").GetString()!;
            var coll = Walk(body, cpath.Split('.'))!.Value;
            foreach (var row in coll.EnumerateArray())
            {
                var leaves = WalkCollect(row, field.Split('.'));
                leaves.Should().BeEmpty($"scenario {name}: hidden field {field} must not appear");
            }
        }

        if (expected.TryGetProperty("everyArrayElementMasked", out var spec))
        {
            var arrayPath = spec.GetProperty("arrayPath").GetString()!;
            var field = spec.GetProperty("field").GetString()!;
            var expectedValue = spec.GetProperty("expectedValue").GetString()!;
            var arrays = WalkCollect(body, arrayPath.Split('.'));
            arrays.Count.Should().BeGreaterThan(0, $"scenario {name}: no arrays at {arrayPath}");
            var masked = 0;
            foreach (var arr in arrays)
            {
                arr.ValueKind.Should().Be(JsonValueKind.Array);
                foreach (var item in arr.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.Object && item.TryGetProperty(field, out var fv))
                    {
                        fv.GetString().Should().Be(expectedValue);
                        masked++;
                    }
                }
            }
            masked.Should().BeGreaterThan(0, $"scenario {name}: nothing was masked");
        }

        if (expected.TryGetProperty("everyArrayElementMatchesPattern", out var patSpec))
        {
            var arrayPath = patSpec.GetProperty("arrayPath").GetString()!;
            var field = patSpec.GetProperty("field").GetString()!;
            var pattern = patSpec.GetProperty("pattern").GetString()!;
            var allowMissing = patSpec.TryGetProperty("allowMissing", out var amProp) && amProp.GetBoolean();
            var rx = new Regex(pattern);
            var items = WalkCollect(body, arrayPath.Split('.'));
            // If we got back a single array, descend into it.
            if (items.Count == 1 && items[0].ValueKind == JsonValueKind.Array)
                items = items[0].EnumerateArray().ToList();
            foreach (var row in items)
            {
                var value = Walk(row, field.Split('.'));
                if (value is null)
                {
                    if (allowMissing) continue;
                    throw new InvalidOperationException($"missing {field}");
                }
                var s = value.Value.ValueKind == JsonValueKind.String
                    ? value.Value.GetString()!
                    : value.Value.GetRawText();
                rx.IsMatch(s).Should().BeTrue($"{s} does not match {pattern}");
            }
        }

        if (expected.TryGetProperty("responseShape", out var shape))
        {
            if (shape.TryGetProperty("topLevelKeys", out var keys))
            {
                body.ValueKind.Should().Be(JsonValueKind.Object);
                foreach (var k in keys.EnumerateArray())
                {
                    body.TryGetProperty(k.GetString()!, out _).Should().BeTrue();
                }
            }
            if (shape.TryGetProperty("minResultsCount", out var minR) && cp is not null)
            {
                var coll = Walk(body, cp.Split('.'));
                coll!.Value.GetArrayLength().Should().BeGreaterThanOrEqualTo(minR.GetInt32());
            }
            if (shape.TryGetProperty("metaMustContainKeys", out var metaKeys))
            {
                body.TryGetProperty("meta", out var meta).Should().BeTrue();
                meta.ValueKind.Should().Be(JsonValueKind.Object);
                foreach (var k in metaKeys.EnumerateArray())
                {
                    meta.TryGetProperty(k.GetString()!, out _).Should().BeTrue();
                }
            }
        }
    }

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

    private static List<JsonElement> WalkCollect(JsonElement node, string[] parts)
    {
        if (parts.Length == 0) return new List<JsonElement> { node };
        if (node.ValueKind == JsonValueKind.Array)
        {
            var result = new List<JsonElement>();
            foreach (var item in node.EnumerateArray())
            {
                result.AddRange(WalkCollect(item, parts));
            }
            return result;
        }
        if (node.ValueKind != JsonValueKind.Object) return new List<JsonElement>();
        var head = parts[0];
        if (!node.TryGetProperty(head, out var next)) return new List<JsonElement>();
        return WalkCollect(next, parts[1..]);
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
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            var path = Path.Combine(ScenarioHelpers.OpenFdaFixturesDir, fixtureFile);
            var body = File.ReadAllText(path);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            });
        }
    }
}
