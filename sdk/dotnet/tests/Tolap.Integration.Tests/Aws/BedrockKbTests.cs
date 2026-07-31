using Amazon;
using Amazon.BedrockAgentRuntime;
using Amazon.BedrockAgentRuntime.Model;
using FluentAssertions;
using Tolap.Core;
using Xunit;

namespace Tolap.Integration.Tests.Aws;

/// <summary>
/// End-to-end <c>kb</c> enforcement against a real Bedrock Knowledge Base (connector-spec §7).
/// </summary>
/// <remarks>
/// <para>
/// The .NET counterpart of <c>test_bedrock_kb_e2e.py</c> and
/// <c>test_bedrock_kb_filter.py</c>. Our own unit tests assert the filter's <i>shape</i>
/// against a fixture we wrote — which cannot tell us whether <b>Bedrock</b> accepts it, or
/// whether it actually excludes anything. A filter that is byte-correct against our
/// expectation but malformed to the service is a runtime failure for every integrator.
/// </para>
/// <para>
/// Requires a provisioned KB, so it is gated on <c>TOLAP_TEST_KB_ID</c> in addition to
/// <c>TOLAP_TEST_AWS=1</c>. The KB is stood up by the Python
/// <c>provision_bedrock_kb.py</c> script rather than reimplemented here: provisioning is test
/// infrastructure (OpenSearch Serverless collection, vector index, IAM role, S3 data source,
/// a multi-minute ingestion job), not SDK behaviour, and building the same chain three times
/// would triple the maintenance for no additional signal. What must be independent per SDK is
/// the <i>enforcement</i> assertion, and that is what runs here.
/// </para>
/// <para>
/// The KB is seeded with four documents, two <c>classification=public</c> and two
/// <c>classification=secret</c>.
/// </para>
/// </remarks>
public class BedrockKbTests
{
    private static readonly string? KbId = Environment.GetEnvironmentVariable("TOLAP_TEST_KB_ID");


    /// <summary>A KB id that does not exist, for the shape-acceptance probe.</summary>
    private const string AbsentKbId = "AAAAAAAAAA";

    /// <summary>Broad enough to match every document, so exclusions are the policy's doing.</summary>
    private const string BroadQuery = "company financial and product information";

    private static IAmazonBedrockAgentRuntime Client()
    {
        var regionName = Environment.GetEnvironmentVariable("AWS_REGION") ?? "us-east-1";
        return new AmazonBedrockAgentRuntimeClient(RegionEndpoint.GetBySystemName(regionName));
    }

    private static EffectivePolicy Policy(TagRules tagRules)
    {
        var now = DateTimeOffset.UtcNow;
        return new EffectivePolicy(
            Version: "1.0",
            UserId: "kb-user",
            TenantId: "kb-tenant",
            SourceConnectionId: "kb:research:trials",
            ResolvedAt: now,
            ExpiresAt: now.AddHours(1),
            SourceProfiles: new[] { "kb-e2e" },
            Permissions: new PolicyPermissions(CanQuery: true),
            ObjectRules: new ObjectRules(TagRules: tagRules));
    }

    /// <summary>
    /// Turns our provider-neutral filter into the Bedrock request shape.
    /// </summary>
    /// <remarks>
    /// The SDK renders a nested dictionary; the AWS SDK wants a typed
    /// <see cref="RetrievalFilter"/>. Translating here rather than in the SDK is deliberate --
    /// TOLAP emits a provider-native <i>document</i> so an integrator can use any client, and
    /// binding to one AWS SDK version inside the library would be the wrong coupling.
    /// </remarks>
    private static RetrievalFilter ToRetrievalFilter(object rendered)
    {
        var map = (IDictionary<string, object>)rendered;

        if (map.TryGetValue("andAll", out var andAll))
        {
            var members = ((IEnumerable<object>)andAll).Select(ToRetrievalFilter).ToList();
            return new RetrievalFilter { AndAll = members };
        }

        foreach (var (op, value) in map)
        {
            var operand = (IDictionary<string, object>)value;
            var attribute = new FilterAttribute
            {
                Key = (string)operand["key"],
                Value = Amazon.Runtime.Documents.Document.FromObject(operand["value"]),
            };
            return op switch
            {
                "in" => new RetrievalFilter { In = attribute },
                "notIn" => new RetrievalFilter { NotIn = attribute },
                _ => throw new InvalidOperationException($"unmapped operator '{op}'"),
            };
        }

        throw new InvalidOperationException("empty filter document");
    }

    /// <summary>Retrieves from the real KB, optionally with our provider filter pushed down.</summary>
    private static async Task<List<(string Text, string? Classification)>> RetrieveAsync(
        IAmazonBedrockAgentRuntime client, string query, object? renderedFilter, string kbId)
    {
        var vector = new KnowledgeBaseVectorSearchConfiguration { NumberOfResults = 10 };
        if (renderedFilter is not null)
            vector.Filter = ToRetrievalFilter(renderedFilter);

        var response = await client.RetrieveAsync(new RetrieveRequest
        {
            KnowledgeBaseId = kbId,
            RetrievalQuery = new KnowledgeBaseQuery { Text = query },
            RetrievalConfiguration = new KnowledgeBaseRetrievalConfiguration
            {
                VectorSearchConfiguration = vector,
            },
        });

        var results = new List<(string, string?)>();
        foreach (var r in response.RetrievalResults)
        {
            r.Metadata.TryGetValue("classification", out var classification);
            results.Add((r.Content.Text, classification.ToString()?.Trim('"')));
        }
        return results;
    }

    private static object? RenderedFor(TagRules tagRules)
        => KbProviders.Render(
            KbFilter.Build(Policy(tagRules), new[] { "classification" }),
            KbProvider.Bedrock).Filter;

    // =======================================================================
    // The pushdown enforces at the source
    // =======================================================================

    [KbFact]
    public async Task Baseline_UnfilteredRetrievalReturnsBothClassifications()
    {
        // Without a filter the KB returns public AND secret chunks. If this does not hold,
        // every filtered assertion below could pass for the wrong reason -- a KB that never
        // returns secret chunks would make the pushdown look effective while doing nothing.
        var results = await RetrieveAsync(Client(), BroadQuery, null, KbId!);
        var classifications = results.Select(r => r.Classification).ToHashSet();

        classifications.Should().Contain("public", "baseline retrieved no public chunks");
        classifications.Should().Contain("secret",
            "baseline retrieved no secret chunks; the exclusion tests would be vacuous");
    }

    [KbFact]
    public async Task DenylistPushdown_ExcludesSecretAtTheSource()
    {
        // deniedTags -> our Bedrock notIn filter. The live Retrieve must return no secret
        // chunk at all. This is the claim a fixture cannot make: the real vector store applied
        // our generated filter.
        var policy = Policy(new TagRules(DeniedTags: new[] { "secret" }));
        var rendered = RenderedFor(new TagRules(DeniedTags: new[] { "secret" }));
        rendered.Should().NotBeNull();

        var results = await RetrieveAsync(Client(), BroadQuery, rendered, KbId!);

        results.Should().NotBeEmpty("expected public chunks to remain");
        results.Should().OnlyContain(r => r.Classification != "secret",
            "a secret chunk survived the pushed-down denylist filter");

        // Defence-in-depth cross-check: the shipped post-pass agrees with the provider.
        var asRecords = results
            .Select(r => new Dictionary<string, object?> { ["classification"] = r.Classification })
            .ToList();
        EnforcementEngine.FilterByTags(asRecords, policy).Should().HaveCount(results.Count,
            "the post pass would have dropped a chunk the KB returned");
    }

    [KbFact]
    public async Task AllowlistPushdown_ReturnsOnlyPublic()
    {
        var rendered = RenderedFor(new TagRules(AllowedTags: new[] { "public" }));

        var results = await RetrieveAsync(Client(), BroadQuery, rendered, KbId!);

        results.Should().NotBeEmpty("allowlist filter returned nothing; expected public chunks");
        results.Should().OnlyContain(r => r.Classification == "public");
    }

    [KbFact]
    public async Task PushdownAndPostPass_ReachTheSameVerdict()
    {
        // The property that makes a pushdown safe rather than merely faster: filtering at the
        // source must never disagree with the normative post-retrieval pass.
        var policy = Policy(new TagRules(DeniedTags: new[] { "secret" }));
        var rendered = RenderedFor(new TagRules(DeniedTags: new[] { "secret" }));
        var client = Client();

        var pushed = await RetrieveAsync(client, BroadQuery, rendered, KbId!);
        var everything = await RetrieveAsync(client, BroadQuery, null, KbId!);
        var postOnly = EnforcementEngine.FilterByTags(
            everything.Select(r => new Dictionary<string, object?>
            {
                ["classification"] = r.Classification,
                ["text"] = r.Text,
            }).ToList(),
            policy);

        pushed.Select(r => r.Text).Should().BeEquivalentTo(
            postOnly.Select(r => (string?)r["text"]),
            "the source filter and the post-retrieval pass disagreed; the pushdown is hiding a "
            + "divergence rather than optimising the same decision");
    }

    // =======================================================================
    // Bedrock accepts the filter shapes we generate
    // =======================================================================

    [AwsTheory]
    [InlineData("denylist-only")]
    [InlineData("allowlist-only")]
    [InlineData("both-anded")]
    public async Task GeneratedFilterShape_IsAccepted(string name)
    {
        // Sent against a KB id that does not exist: Bedrock validates the request body before
        // resolving the KB, so ResourceNotFound means the filter parsed and a validation error
        // would mean our syntax is wrong. No KB needed for this one.
        var tagRules = name switch
        {
            "denylist-only" => new TagRules(DeniedTags: new[] { "secret", "restricted" }),
            "allowlist-only" => new TagRules(AllowedTags: new[] { "public" }),
            _ => new TagRules(AllowedTags: new[] { "public" }, DeniedTags: new[] { "secret" }),
        };
        var rendered = RenderedFor(tagRules);
        rendered.Should().NotBeNull($"{name}: nothing rendered to send");

        var act = async () => await RetrieveAsync(Client(), "test", rendered, AbsentKbId);

        (await act.Should().ThrowAsync<Amazon.BedrockAgentRuntime.Model.ResourceNotFoundException>(
            $"{name}: Bedrock rejected the generated filter shape"))
            .Which.Should().NotBeNull();
    }

    [KbFact]
    public async Task NegativeControl_AMalformedFilterIsRejected()
    {
        // Without this, the tests above would pass even if Bedrock had stopped validating
        // filters -- "not a validation error" is only meaningful if malformed input still
        // produces one. An empty filter document cannot be mapped, so the mapper itself
        // refuses: the assertion is that a bad shape never reaches KB lookup.
        var act = async () => await RetrieveAsync(
            Client(), "test", new Dictionary<string, object>(), AbsentKbId);

        await act.Should().ThrowAsync<InvalidOperationException>(
            "a malformed filter must be refused before it is sent");
    }
}
