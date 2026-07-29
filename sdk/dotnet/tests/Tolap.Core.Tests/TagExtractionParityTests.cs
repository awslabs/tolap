using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// Cross-SDK parity for tag extraction (connector spec section 7).
/// </summary>
/// <remarks>
/// <para>One record corpus, one policy set, one outcome table, asserted with identical
/// expected outcomes in all three SDKs. The counterparts are
/// <c>sdk/python/tests/test_tag_extraction_parity.py</c> and
/// <c>packages/core/tests/tag-extraction-parity.test.ts</c>.</para>
/// <para>Tag filtering is the whole knowledge-base confidentiality control: a
/// classification level <b>is</b> a tag and there is no separate classification construct,
/// so a gap here is a disclosure rather than a cosmetic difference. The corpus is the set of
/// shapes real providers emit — a lower-case <c>tags</c> array, a differently-cased key,
/// tags nested in a metadata object, an alternate key name, a scalar instead of an array,
/// and a tag key inside an array of chunks — because a literal lower-case <c>tags</c>
/// lookup found exactly one of them and disclosed the other four.</para>
/// <para>Each shape is run against five policies rather than one, so the two halves of the
/// control are separable: a denylist must <em>drop</em> the carrier and an allow-list must
/// <em>not admit</em> it, and an SDK that extracts a tag for one purpose but not the other
/// fails a specific cell rather than passing on average.</para>
/// <para>The corpus also pins the boundaries the fix must not move: <c>categories</c> is
/// outside the recognized key set and is therefore ordinary data (an over-broad set fails
/// open, because an unrelated field whose value appears in <c>allowedTags</c> would admit a
/// record the allow-list would otherwise have dropped), a non-string tag value contributes
/// no tag, and an untagged record is dropped under an allow-list but kept under a denylist
/// alone.</para>
/// </remarks>
public class TagExtractionParityTests
{
    /// <summary>
    /// The shared record corpus, keyed by case id. Identical field-for-field in all three
    /// SDKs.
    /// </summary>
    private static readonly Dictionary<string, Dictionary<string, object?>> ParityRecords = new()
    {
        // The five shapes measured as leaking: only "tags-list" was enforced.
        ["tags-list"] = new() { ["tags"] = new[] { "secret" } },
        ["cased-key"] = new() { ["Tags"] = new[] { "secret" } },
        ["nested-metadata"] = new()
        {
            ["metadata"] = new Dictionary<string, object?> { ["tags"] = new[] { "secret" } }
        },
        ["labels-key"] = new() { ["labels"] = new[] { "secret" } },
        ["scalar-classification"] = new() { ["classification"] = "secret" },
        // Further provider shapes and case variants.
        ["scalar-tags"] = new() { ["tags"] = "secret" },
        ["upper-value"] = new() { ["tags"] = new[] { "SECRET" } },
        ["cased-key-and-value"] = new() { ["CLASSIFICATION"] = "Secret" },
        ["nested-labels"] = new()
        {
            ["metadata"] = new Dictionary<string, object?> { ["labels"] = new[] { "secret" } }
        },
        ["in-array"] = new()
        {
            ["chunks"] = new List<object?>
            {
                new Dictionary<string, object?> { ["tags"] = new[] { "secret" } }
            }
        },
        // Boundaries the fix must not move.
        ["public-tag"] = new() { ["tags"] = new[] { "public" } },
        ["untagged"] = new() { ["note"] = "no tags at all" },
        ["empty-tags"] = new() { ["tags"] = Array.Empty<string>() },
        ["non-string-tags"] = new() { ["tags"] = 42 },
        ["unrecognized-key"] = new() { ["categories"] = new[] { "secret" } },
    };

    /// <summary>The shared policy set, keyed by policy id. Identical in all three SDKs.</summary>
    private static readonly Dictionary<string, TagRules> ParityTagRules = new()
    {
        ["deny-secret"] = new TagRules(DeniedTags: new[] { "secret" }),
        ["deny-Secret-cased"] = new TagRules(DeniedTags: new[] { "Secret" }),
        ["allow-public"] = new TagRules(AllowedTags: new[] { "public" }),
        ["allow-secret"] = new TagRules(AllowedTags: new[] { "secret" }),
        ["allow-public-deny-secret"] = new TagRules(
            AllowedTags: new[] { "public" },
            DeniedTags: new[] { "secret" }),
    };

    /// <summary>Every shape carrying "secret" behaves the same way under every policy.</summary>
    private static readonly string[] SecretCarriers =
    {
        "tags-list", "cased-key", "nested-metadata", "labels-key", "scalar-classification",
        "scalar-tags", "upper-value", "cased-key-and-value", "nested-labels", "in-array"
    };

    /// <summary>
    /// The shapes with no recognizable tags. No tags means dropped under an allow-list,
    /// kept under a denylist (canonical spec section 4).
    /// </summary>
    private static readonly string[] UntaggedEquivalents =
    {
        "untagged", "empty-tags", "non-string-tags", "unrecognized-key"
    };

    /// <summary>
    /// (record id, policy id, kept) — the canonical table. <c>true</c> means the record
    /// survives the filter; <c>false</c> means it is dropped.
    /// </summary>
    public static TheoryData<string, string, bool> ParityTable()
    {
        var data = new TheoryData<string, string, bool>();

        foreach (var recordId in SecretCarriers)
        {
            data.Add(recordId, "deny-secret", false);
            data.Add(recordId, "deny-Secret-cased", false);
            data.Add(recordId, "allow-public", false);
            data.Add(recordId, "allow-secret", true);
            data.Add(recordId, "allow-public-deny-secret", false);
        }

        // A record carrying only an allowed tag.
        data.Add("public-tag", "deny-secret", true);
        data.Add("public-tag", "deny-Secret-cased", true);
        data.Add("public-tag", "allow-public", true);
        data.Add("public-tag", "allow-secret", false);
        data.Add("public-tag", "allow-public-deny-secret", true);

        foreach (var recordId in UntaggedEquivalents)
        {
            data.Add(recordId, "deny-secret", true);
            data.Add(recordId, "deny-Secret-cased", true);
            data.Add(recordId, "allow-public", false);
            data.Add(recordId, "allow-secret", false);
            data.Add(recordId, "allow-public-deny-secret", false);
        }

        return data;
    }

    private static EffectivePolicy ParityPolicy(TagRules tagRules) => new(
        Version: "1.0",
        UserId: "parity-user",
        TenantId: "parity-tenant",
        SourceConnectionId: "kb:internal:parity",
        ResolvedAt: null,
        ExpiresAt: null,
        SourceProfiles: new[] { "tag-extraction-parity" },
        Permissions: new PolicyPermissions(CanQuery: true, CanExport: false, ReadOnly: true),
        ObjectRules: new ObjectRules(TagRules: tagRules),
        Limits: null);

    [Theory]
    [MemberData(nameof(ParityTable))]
    public void TagExtractionParity(string recordId, string policyId, bool kept)
    {
        var record = ParityRecords[recordId];

        var filtered = EnforcementEngine.FilterByTags(
            new[] { record },
            ParityPolicy(ParityTagRules[policyId]));

        if (kept)
            filtered.Should().BeEquivalentTo(new[] { record });
        else
            filtered.Should().BeEmpty();
    }

    [Fact]
    public void TheCorpusAndTableStayInStep()
    {
        // A shape silently dropped from the table would look like a passing parity run
        // while enforcing nothing, which is the failure mode this file exists to catch.
        var covered = ParityTable()
            .Select(row => $"{row[0]}|{row[1]}")
            .ToHashSet();
        var expected = ParityRecords.Keys
            .SelectMany(recordId => ParityTagRules.Keys.Select(policyId => $"{recordId}|{policyId}"))
            .ToHashSet();

        covered.Should().BeEquivalentTo(expected);
    }
}
