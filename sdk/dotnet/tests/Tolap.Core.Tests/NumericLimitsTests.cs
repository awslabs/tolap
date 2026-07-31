using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// Enforcement of MinSimilarityScore and MaxObjectSizeBytes
/// (docs/canonical-enforcement-spec.md section 4, steps 3 and 4).
/// </summary>
/// <remarks>
/// Both limits were parsed, validated, and merged most-restrictively -- and then never
/// applied to any result. The merge and round-trip paths <i>were</i> tested, so branch
/// coverage reached ~100% while neither control did anything: coverage measures whether
/// written code runs, never whether required code was written.
/// </remarks>
public class NumericLimitsTests
{
    private static EffectivePolicy Policy(double? floor = null, long? ceiling = null) =>
        new(Version: "1.0", UserId: "u", TenantId: "t", SourceConnectionId: null,
            ResolvedAt: null, ExpiresAt: null, SourceProfiles: ["p"],
            Permissions: new PolicyPermissions(CanQuery: true),
            Limits: new PolicyLimits(MinSimilarityScore: floor, MaxObjectSizeBytes: ceiling));

    private static List<Dictionary<string, object?>> Records(
        params (string Id, object? Score, object? Size)[] rows) =>
        rows.Select(r =>
        {
            var record = new Dictionary<string, object?> { ["id"] = r.Id };
            if (r.Score is not null) record["score"] = r.Score;
            if (r.Size is not null) record["size"] = r.Size;
            return record;
        }).ToList();

    private static string[] Ids(IEnumerable<Dictionary<string, object?>> records) =>
        records.Select(r => (string)r["id"]!).ToArray();

    [Fact]
    public void SimilarityFloor_DropsLowScoringRecords()
    {
        var kept = EnforcementEngine.ApplySimilarityFloor(
            Records(("high", 0.95, null), ("low", 0.10, null)), Policy(floor: 0.9));

        Ids(kept).Should().Equal("high");
    }

    [Fact]
    public void SimilarityFloor_KeepsAScoreExactlyAtTheFloor()
    {
        var kept = EnforcementEngine.ApplySimilarityFloor(
            Records(("exact", 0.9, null)), Policy(floor: 0.9));

        Ids(kept).Should().Equal("exact");
    }

    [Fact]
    public void SimilarityFloor_DropsAnUnscoredRecord()
    {
        // Fail closed: relevance that cannot be established cannot satisfy a floor.
        var kept = EnforcementEngine.ApplySimilarityFloor(
            Records(("no-score", null, null)), Policy(floor: 0.5));

        kept.Should().BeEmpty();
    }

    [Theory]
    [InlineData("not-a-number")]
    [InlineData(true)]          // bool must be a type error, never a passing 1.0
    [InlineData(double.NaN)]    // NaN comparisons are always false
    [InlineData(double.PositiveInfinity)]
    public void SimilarityFloor_DropsANonNumericOrNonFiniteScore(object score)
    {
        var kept = EnforcementEngine.ApplySimilarityFloor(
            Records(("bad", score, null)), Policy(floor: 0.5));

        kept.Should().BeEmpty();
    }

    [Fact]
    public void SimilarityFloor_HonoursANumericStringScore()
    {
        var kept = EnforcementEngine.ApplySimilarityFloor(
            Records(("pass", "0.75", null), ("fail", "0.25", null)), Policy(floor: 0.5));

        Ids(kept).Should().Equal("pass");
    }

    [Theory]
    [InlineData("similarity")]
    [InlineData("similarityScore")]
    [InlineData("_score")]
    [InlineData("SCORE")]
    public void SimilarityFloor_RecognizesAlternateFieldNames(string key)
    {
        var record = new Dictionary<string, object?> { ["id"] = "a", [key] = 0.9 };

        var kept = EnforcementEngine.ApplySimilarityFloor([record], Policy(floor: 0.5));

        Ids(kept).Should().Equal("a");
    }

    [Fact]
    public void SimilarityFloor_WithNoFloorConfigured_IsAPassthrough()
    {
        var records = Records(("a", null, null), ("b", 0.01, null));

        EnforcementEngine.ApplySimilarityFloor(records, Policy()).Should().BeSameAs(records);
    }

    [Fact]
    public void SizeCeiling_DropsOversizedRecords()
    {
        var kept = EnforcementEngine.ApplyObjectSizeCeiling(
            Records(("small", null, 500), ("huge", null, 999_999_999)), Policy(ceiling: 1024));

        Ids(kept).Should().Equal("small");
    }

    [Fact]
    public void SizeCeiling_KeepsASizeExactlyAtTheCeiling()
    {
        var kept = EnforcementEngine.ApplyObjectSizeCeiling(
            Records(("exact", null, 1024)), Policy(ceiling: 1024));

        Ids(kept).Should().Equal("exact");
    }

    [Fact]
    public void SizeCeiling_DropsAnUnsizedRecord()
    {
        var kept = EnforcementEngine.ApplyObjectSizeCeiling(
            Records(("no-size", null, null)), Policy(ceiling: 1024));

        kept.Should().BeEmpty();
    }

    [Theory]
    [InlineData("sizeBytes")]
    [InlineData("contentLength")]
    [InlineData("objectSize")]
    [InlineData("SIZE")]
    public void SizeCeiling_RecognizesAlternateFieldNames(string key)
    {
        var record = new Dictionary<string, object?> { ["id"] = "a", [key] = 10 };

        var kept = EnforcementEngine.ApplyObjectSizeCeiling([record], Policy(ceiling: 1024));

        Ids(kept).Should().Equal("a");
    }

    [Fact]
    public void Pipeline_AppliesBothLimits_AndMatchesPythonAndTypeScript()
    {
        // The identical input and expectation are asserted in the Python and TypeScript
        // suites. Divergence here means one SDK enforces a policy the others do not.
        var records = Records(
            ("ok", 0.9, 100),
            ("low", 0.1, 100),
            ("big", 0.9, 99_999),
            ("noscore", null, 100),
            ("exact", 0.5, 1000),
            ("boolscore", true, 10));

        var kept = EnforcementEngine.ApplyRecordPipeline(
            records, Policy(floor: 0.5, ceiling: 1000));

        Ids(kept).Should().Equal("ok", "exact");
    }

    [Fact]
    public void Pipeline_DropsRecordsBeforeMasking()
    {
        // Spec section 4 ordering: a record about to be dropped is not masked first.
        var policy = new EffectivePolicy(
            Version: "1.0", UserId: "u", TenantId: "t", SourceConnectionId: null,
            ResolvedAt: null, ExpiresAt: null, SourceProfiles: ["p"],
            Permissions: new PolicyPermissions(CanQuery: true),
            ObjectRules: new ObjectRules(FieldRules: new FieldRules(
                MaskedFields: [new MaskingRule("secret", MaskType.Redact)])),
            Limits: new PolicyLimits(MinSimilarityScore: 0.5));

        var records = new List<Dictionary<string, object?>>
        {
            new() { ["id"] = "keep", ["score"] = 0.9, ["secret"] = "s1" },
            new() { ["id"] = "drop", ["score"] = 0.1, ["secret"] = "s2" },
        };

        var kept = EnforcementEngine.ApplyRecordPipeline(records, policy);

        kept.Should().HaveCount(1);
        kept[0]["id"].Should().Be("keep");
        kept[0]["secret"].Should().Be("[REDACTED]");
    }

    [Fact]
    public void Pipeline_AppliesLimitsBeforeTheResultLimit()
    {
        // maxResults must count only records that survived the floor: had the limit run
        // first, "a" would consume a slot and only "b" would remain.
        var kept = EnforcementEngine.ApplyRecordPipeline(
            Records(("a", 0.1, null), ("b", 0.9, null), ("c", 0.9, null)),
            new EffectivePolicy(
                Version: "1.0", UserId: "u", TenantId: "t", SourceConnectionId: null,
                ResolvedAt: null, ExpiresAt: null, SourceProfiles: ["p"],
                Permissions: new PolicyPermissions(CanQuery: true),
                Limits: new PolicyLimits(MaxResults: 2, MinSimilarityScore: 0.5)));

        Ids(kept).Should().Equal("b", "c");
    }
}
