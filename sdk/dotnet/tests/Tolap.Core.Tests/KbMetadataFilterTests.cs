using System.Text.Json;
using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// Provider-side kb metadata filters (connector-spec.md section 7).
/// </summary>
/// <remarks>
/// <para>
/// Two distinct things are asserted here, and the second matters more than the first.
/// </para>
/// <para>
/// <b>1. Cross-SDK agreement</b>, driven by
/// <c>fixtures/enforcement/kb-metadata-filters.json</c>. The Python and TypeScript suites read
/// the same file case-for-case, so a divergence in how a policy renders for a provider fails
/// somewhere. The rendered filter is compared as <i>JSON</i> rather than as CLR objects,
/// because the point is that all three SDKs emit the same bytes to the provider.
/// </para>
/// <para>
/// <b>2. The safety property</b>, which no fixture can express: a pushdown must never exclude
/// a chunk the policy permits. Section 7 calls a provider filter "an optimization on the same
/// footing as SQL rewriting, never a replacement for the post pass", and the reason it can
/// only ever be advisory is structural — post-retrieval extraction reads tags recursively,
/// case-insensitively, from tags/Tags/labels/classification/metadata.tags, and no provider
/// filter reproduces that. It filters one indexed field.
/// </para>
/// <para>
/// So the asymmetry is deliberate: a filter matching <i>nothing</i> costs efficiency and
/// nothing else, because the post pass is unconditional. A filter matching <i>too little</i>
/// is a correctness bug. The last region simulates a provider applying our clause and asserts
/// the first never happens.
/// </para>
/// </remarks>
public class KbMetadataFilterTests
{
    private const string FixturePath = "enforcement/kb-metadata-filters.json";

    private static readonly JsonElement Fixture =
        FixtureHelper.ReadFixtureAsJson(FixturePath).Clone();

    private static readonly IReadOnlyList<JsonElement> Cases =
        Fixture.GetProperty("cases").EnumerateArray().Select(c => c.Clone()).ToList();

    /// <summary>Provider wire names, matching the fixture's keys and the other two SDKs.</summary>
    private static string WireName(KbProvider provider) => provider switch
    {
        KbProvider.Bedrock => "bedrock",
        KbProvider.OpenSearch => "opensearch",
        KbProvider.Elasticsearch => "elasticsearch",
        KbProvider.AzureAiSearch => "azureAiSearch",
        KbProvider.VertexAiSearch => "vertexAiSearch",
        KbProvider.Pgvector => "pgvector",
        _ => throw new ArgumentOutOfRangeException(nameof(provider))
    };

    private static string OpWireName(KbFilterOp op) => op == KbFilterOp.In ? "in" : "notIn";

    private static EffectivePolicy Policy(TagRules tagRules)
        => new(
            Version: "1.0",
            UserId: "u",
            TenantId: "t",
            SourceConnectionId: "kb:research:trials",
            ResolvedAt: DateTimeOffset.UtcNow,
            ExpiresAt: DateTimeOffset.UtcNow.AddHours(1),
            SourceProfiles: Array.Empty<string>(),
            Permissions: new PolicyPermissions(CanQuery: true),
            ObjectRules: new ObjectRules(TagRules: tagRules));

    /// <summary>
    /// The case's tagRules, read from its embedded policy. The fixture stores a real policy
    /// fragment rather than a bare tagRules block so the shared schema-validation walk covers
    /// it like every other fixture.
    /// </summary>
    private static TagRules TagRulesOf(JsonElement testCase)
    {
        if (!testCase.GetProperty("policy").TryGetProperty("objectRules", out var objectRules)
            || !objectRules.TryGetProperty("tagRules", out var tagRules))
        {
            return new TagRules();
        }
        return TagRulesFrom(tagRules);
    }

    private static TagRules TagRulesFrom(JsonElement raw)
        => new(
            AllowedTags: raw.TryGetProperty("allowedTags", out var a)
                ? a.EnumerateArray().Select(v => v.GetString()!).ToArray()
                : null,
            DeniedTags: raw.TryGetProperty("deniedTags", out var d)
                ? d.EnumerateArray().Select(v => v.GetString()!).ToArray()
                : null);

    private static string[] KeysFrom(JsonElement testCase)
        => testCase.GetProperty("metadataKeys").EnumerateArray().Select(k => k.GetString()!).ToArray();

    /// <summary>
    /// Serialize a rendered filter to canonical JSON so it can be compared with the fixture's
    /// expectation regardless of CLR type.
    /// </summary>
    private static string Canonical(object? value)
        => value is null ? "null" : JsonSerializer.Serialize(value);

    /// <summary>Re-serialize a fixture JSON node with the same writer, for a fair comparison.</summary>
    private static string CanonicalFixture(JsonElement element)
        => element.ValueKind == JsonValueKind.Null
            ? "null"
            : JsonSerializer.Serialize(JsonSerializer.Deserialize<object>(element.GetRawText()));

    public static IEnumerable<object[]> CaseIndices()
        => Cases.Select((c, i) => new object[] { i, c.GetProperty("name").GetString()! });

    // =======================================================================
    // The shared corpus
    // =======================================================================

    [Fact]
    public void TheCorpusCarriesTheExpectedCaseCount()
    {
        // A case dropped from the fixture is coverage lost silently.
        Cases.Should().HaveCount(7);
    }

    [Theory]
    [MemberData(nameof(CaseIndices))]
    public void NeutralClausesAndFlagsMatch(int index, string name)
    {
        var testCase = Cases[index];
        var result = KbFilter.Build(
            Policy(TagRulesOf(testCase)), KeysFrom(testCase));
        var expected = testCase.GetProperty("expected");
        var note = testCase.GetProperty("note").GetString();

        var actualClauses = result.Clauses
            .Select(c => new { key = c.Key, op = OpWireName(c.Op), values = c.Values })
            .ToArray();
        Canonical(actualClauses).Should()
            .Be(CanonicalFixture(expected.GetProperty("clauses")), $"{name}: {note}");

        result.DeniesEverything.Should()
            .Be(expected.GetProperty("deniesEverything").GetBoolean(), $"{name}: {note}");

        result.UnpushedRules.Select(r => r.Rule).Should().Equal(
            expected.GetProperty("unpushedRules").EnumerateArray().Select(v => v.GetString()!),
            $"{name}: {note}");
    }

    [Theory]
    [MemberData(nameof(CaseIndices))]
    public void RendersIdenticallyForEveryProvider(int index, string name)
    {
        var testCase = Cases[index];
        var result = KbFilter.Build(
            Policy(TagRulesOf(testCase)), KeysFrom(testCase));
        var rendered = testCase.GetProperty("expected").GetProperty("rendered");
        var column = Fixture.GetProperty("pgvectorColumn").GetString()!;

        foreach (var provider in Enum.GetValues<KbProvider>())
        {
            var actual = KbProviders.Render(result, provider, column);
            Canonical(actual.Filter).Should()
                .Be(CanonicalFixture(rendered.GetProperty(WireName(provider))),
                    $"{name} / {WireName(provider)}");
        }
    }

    // =======================================================================
    // Deny-all must not render as "no restriction"
    // =======================================================================

    [Fact]
    public void Exploit_EmptyAllowedTagsIsNotANoOpFilter()
    {
        // The fail-open this guards. An empty AllowedTags denies every chunk (spec section 3),
        // and no portable metadata predicate means match-nothing. Emitting an empty filter and
        // retrieving anyway would return everything, so the flag is the contract.
        var result = KbFilter.Build(Policy(new TagRules(AllowedTags: Array.Empty<string>())));

        result.DeniesEverything.Should().BeTrue();
        result.Clauses.Should().BeEmpty();
        result.UnpushedRules.Should().HaveCount(1);

        foreach (var provider in Enum.GetValues<KbProvider>())
        {
            var rendered = KbProviders.Render(result, provider);
            rendered.Filter.Should().BeNull();
            rendered.DeniesEverything.Should().BeTrue();
        }
    }

    [Fact]
    public void DenyAllIsDistinguishableFromNothingToPush()
    {
        // An empty DeniedTags also yields no clauses, but denies nothing. The two must not be
        // conflated: one means skip retrieval, the other means retrieve unfiltered.
        var result = KbFilter.Build(Policy(new TagRules(DeniedTags: Array.Empty<string>())));

        result.Clauses.Should().BeEmpty();
        result.DeniesEverything.Should().BeFalse();
    }

    // =======================================================================
    // Normalization keeps the three SDKs byte-identical
    // =======================================================================

    [Fact]
    public void LowerCasesValues()
    {
        var result = KbFilter.Build(
            Policy(new TagRules(DeniedTags: new[] { "SECRET", "Restricted" })),
            new[] { "classification" });

        result.Clauses[0].Values.Should().Equal("restricted", "secret");
    }

    [Fact]
    public void DeduplicatesAndSorts()
    {
        // Unstable ordering would make the shared fixture fail for the wrong reason — a
        // difference in iteration order rather than in semantics.
        var result = KbFilter.Build(
            Policy(new TagRules(DeniedTags: new[] { "b", "a", "B", "a" })),
            new[] { "classification" });

        result.Clauses[0].Values.Should().Equal("a", "b");
    }

    [Fact]
    public void DefaultsToTheDocumentedKeys()
    {
        var result = KbFilter.Build(Policy(new TagRules(DeniedTags: new[] { "secret" })));

        result.Clauses.Select(c => c.Key).Should().Equal(KbFilter.DefaultMetadataKeys);
    }

    [Fact]
    public void NoTagRulesYieldsNothing()
    {
        var policy = Policy(new TagRules()) with { ObjectRules = new ObjectRules() };

        var result = KbFilter.Build(policy);

        result.Clauses.Should().BeEmpty();
        result.DeniesEverything.Should().BeFalse();
        result.UnpushedRules.Should().BeEmpty();
    }

    [Fact]
    public void EmptyMetadataKeysPushesNothingAndSaysSo()
    {
        var result = KbFilter.Build(
            Policy(new TagRules(DeniedTags: new[] { "secret" })), Array.Empty<string>());

        result.Clauses.Should().BeEmpty();
        result.UnpushedRules.Select(r => r.Rule).Should().Equal("deniedTags");
    }

    // =======================================================================
    // Renderers refuse what they cannot express
    // =======================================================================

    [Fact]
    public void AzureRefusesAComma()
    {
        // search.in is comma-delimited, so a comma inside a value would silently change which
        // set matches. Refusing yields an unpushed rule; the post pass still enforces.
        var result = KbFilter.Build(
            Policy(new TagRules(DeniedTags: new[] { "a,b" })), new[] { "classification" });
        var rendered = KbProviders.Render(result, KbProvider.AzureAiSearch);

        rendered.Filter.Should().BeNull();
        rendered.UnpushedRules.Should().NotBeEmpty();
    }

    [Fact]
    public void VertexRefusesADoubleQuote()
    {
        var result = KbFilter.Build(
            Policy(new TagRules(DeniedTags: new[] { "a\"b" })), new[] { "classification" });
        var rendered = KbProviders.Render(result, KbProvider.VertexAiSearch);

        rendered.Filter.Should().BeNull();
        rendered.UnpushedRules.Should().NotBeEmpty();
    }

    [Fact]
    public void PgvectorRefusesANonIdentifierKey()
    {
        // A key is deployment configuration, not policy data. An unexpected one is refused
        // rather than quoted into a query.
        var result = KbFilter.Build(
            Policy(new TagRules(DeniedTags: new[] { "secret" })),
            new[] { "tags'; DROP TABLE chunks --" });

        KbProviders.Render(result, KbProvider.Pgvector).Filter.Should().BeNull();
    }

    [Fact]
    public void PgvectorEscapesAQuoteInAValue()
    {
        // Tag values come from a signed policy, so they are trusted content — but still
        // escaped, so a value cannot terminate the literal.
        var result = KbFilter.Build(
            Policy(new TagRules(DeniedTags: new[] { "o'brien" })), new[] { "tags" });

        KbProviders.Render(result, KbProvider.Pgvector).Filter
            .Should().BeOfType<string>()
            .Which.Should().Contain("'o''brien'");
    }

    // =======================================================================
    // THE safety property: a pushdown never excludes what the policy permits
    // =======================================================================

    private static readonly Dictionary<string, object?>[] Chunks =
    {
        new() { ["id"] = "secret-indexed", ["classification"] = "secret" },
        new() { ["id"] = "public-indexed", ["classification"] = "public" },
        new() { ["id"] = "untagged" },
        new() { ["id"] = "secret-other-key", ["tags"] = new object?[] { "secret" } },
        new()
        {
            ["id"] = "secret-nested",
            ["metadata"] = new Dictionary<string, object?> { ["tags"] = new object?[] { "secret" } }
        },
        new() { ["id"] = "secret-cased", ["classification"] = "SECRET" }
    };

    /// <summary>
    /// Apply clauses the way a provider would: one indexed key, at the top level, with an
    /// absent key meaning no match (so a negated clause keeps the chunk).
    /// </summary>
    private static HashSet<string> SimulateProvider(KbFilterClause[] clauses)
    {
        var kept = new HashSet<string>(StringComparer.Ordinal);

        foreach (var chunk in Chunks)
        {
            var keep = true;
            foreach (var clause in clauses)
            {
                chunk.TryGetValue(clause.Key, out var raw);
                var present = raw is not null;
                var values = (raw is object?[] array ? array : new[] { raw })
                    .OfType<string>()
                    .Select(v => v.ToLowerInvariant())
                    .ToList();
                var hit = values.Any(v => clause.Values.Contains(v, StringComparer.Ordinal));

                if (clause.Op == KbFilterOp.In)
                {
                    if (!hit) { keep = false; break; }
                }
                else if (present && hit)
                {
                    keep = false;
                    break;
                }
            }

            if (keep)
                kept.Add((string)chunk["id"]!);
        }

        return kept;
    }

    private static HashSet<string> PostPassKeeps(EffectivePolicy policy)
        => EnforcementEngine
            .FilterByTags(Chunks, policy)
            .Select(c => (string)c["id"]!)
            .ToHashSet(StringComparer.Ordinal);

    [Fact]
    public void Denylist_KeepsEverythingThePostPassKeeps()
    {
        // The property that makes a pushdown safe. If this ever fails, the provider is hiding
        // chunks the policy allows and the SDK is silently over-restricting.
        var policy = Policy(new TagRules(DeniedTags: new[] { "secret" }));
        var result = KbFilter.Build(policy, new[] { "classification" });

        PostPassKeeps(policy).Should().BeSubsetOf(SimulateProvider(result.Clauses));
    }

    [Fact]
    public void TheProviderMissesOtherKeysAndNesting()
    {
        // Documents the structural weakness with evidence rather than a comment: these two
        // chunks reach the client and are dropped post-retrieval. This is why section 7
        // forbids treating the filter as a replacement.
        var policy = Policy(new TagRules(DeniedTags: new[] { "secret" }));
        var result = KbFilter.Build(policy, new[] { "classification" });

        var provided = SimulateProvider(result.Clauses);
        provided.Should().Contain("secret-other-key").And.Contain("secret-nested");

        var permitted = PostPassKeeps(policy);
        permitted.Should().NotContain("secret-other-key").And.NotContain("secret-nested");
    }

    [Fact]
    public void Allowlist_KeepsEverythingThePostPassKeeps()
    {
        var policy = Policy(new TagRules(AllowedTags: new[] { "public" }));
        var result = KbFilter.Build(policy, new[] { "classification" });

        PostPassKeeps(policy).Should().BeSubsetOf(SimulateProvider(result.Clauses));
    }

    [Fact]
    public void MultiKeyAllowlist_PushesNothingSoCannotOverRestrict()
    {
        // The case the builder refuses. ANDing a positive clause per key would drop chunks
        // carrying the allowed tag under only one key — narrower than the policy.
        var policy = Policy(new TagRules(AllowedTags: new[] { "public" }));
        var result = KbFilter.Build(policy, new[] { "tags", "classification" });

        result.Clauses.Should().BeEmpty();
        result.UnpushedRules.Select(r => r.Rule).Should().Equal("allowedTags");

        PostPassKeeps(policy).Should().BeEquivalentTo(new[] { "public-indexed" });
    }
}
