using System.Text.Json;
using FluentAssertions;
using Tolap.Core;
using Tolap.Mcp;

namespace Tolap.Integration.Tests;

/// <summary>
/// KB tag-rule scenarios fed via an in-process document corpus.
/// </summary>
public sealed class KbTagRulesTests
{
    private const string SigningKey = "integration-test-signing-key";

    public static IEnumerable<object[]> Scenarios
    {
        get
        {
            var json = ScenarioHelpers.LoadScenarioFile("knowledge-base-tag-rules.json");
            using var doc = JsonDocument.Parse(json);
            var corpus = doc.RootElement.GetProperty("corpus").GetRawText();
            foreach (var s in doc.RootElement.GetProperty("scenarios").EnumerateArray())
            {
                yield return new object[]
                {
                    s.GetProperty("name").GetString()!,
                    corpus,
                    s.GetRawText(),
                };
            }
        }
    }

    [Theory]
    [MemberData(nameof(Scenarios))]
    public async Task TagRuleScenario(string name, string corpusJson, string scenarioJson)
    {
        using var corpusDoc = JsonDocument.Parse(corpusJson);
        using var scenarioDoc = JsonDocument.Parse(scenarioJson);
        var scenario = scenarioDoc.RootElement;

        var policy = ScenarioHelpers.PolicyFromJson(scenario.GetProperty("policy"));
        var ctx = ScenarioHelpers.SignPolicy(policy, SigningKey);

        var wrapper = new SecureContextToolWrapper(new SecureContextWrapperOptions(SigningKey));
        var args = new PreExecuteArgs("kb-search");

        var docs = await wrapper.ExecuteWithEnforcementAsync(
            ctx, args, () => Task.FromResult(LoadCorpus(corpusDoc.RootElement)));

        var expected = scenario.GetProperty("expected");
        if (expected.TryGetProperty("idsEqual", out var idsEqual))
        {
            var actual = docs.Select(d => (string)d["id"]!).OrderBy(s => s).ToArray();
            var want = idsEqual.EnumerateArray().Select(e => e.GetString()!).OrderBy(s => s).ToArray();
            actual.Should().BeEquivalentTo(want, opts => opts.WithStrictOrdering(), name);
        }
        if (expected.TryGetProperty("idMustNotInclude", out var forbidden))
        {
            var actualIds = docs.Select(d => (string)d["id"]!).ToHashSet();
            foreach (var id in forbidden.EnumerateArray().Select(e => e.GetString()!))
            {
                actualIds.Contains(id).Should().BeFalse($"{id} should be filtered out");
            }
        }
    }

    private static IReadOnlyList<Dictionary<string, object?>> LoadCorpus(JsonElement corpus)
    {
        var docs = new List<Dictionary<string, object?>>();
        foreach (var d in corpus.EnumerateArray())
        {
            var row = new Dictionary<string, object?>();
            foreach (var prop in d.EnumerateObject())
            {
                if (prop.Value.ValueKind == JsonValueKind.Array)
                {
                    row[prop.Name] = prop.Value.EnumerateArray().Select(e => e.GetString() ?? "").ToArray();
                }
                else
                {
                    row[prop.Name] = prop.Value.GetString();
                }
            }
            docs.Add(row);
        }
        return docs;
    }
}
