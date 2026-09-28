using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// Core halves of the already-enforced result marker (issue #33): the constant-time
/// binding check, the nested-marker unwrap every pipeline run performs, and the
/// idempotent subset of the pipeline an honoured marker still gets. The wrapper-level
/// behaviour, and the shared fixture, are covered in Tolap.Mcp.Tests.
/// </summary>
public class EnforcedResultTests
{
    private static readonly EffectivePolicy Policy = TolapJsonOptions.Deserialize<EffectivePolicy>("""
        {
          "version": "1.0", "userId": "u", "tenantId": "t", "sourceConnectionId": "s",
          "resolvedAt": "2026-01-01T00:00:00Z", "expiresAt": "2099-01-01T00:00:00Z",
          "sourceProfiles": [],
          "permissions": { "canQuery": true },
          "objectRules": {
            "fieldRules": {
              "hiddenFields": ["ssn"],
              "maskedFields": [{ "field": "email", "maskType": "hash" }]
            },
            "rowFilters": [{ "field": "region", "operator": "equals", "value": "us-east" }]
          },
          "limits": { "maxResults": 2 }
        }
        """);

    private static SecurityContext ContextWith(string? signature) =>
        new(
            Version: "1.0",
            UserId: "u",
            TenantId: "t",
            IssuedAt: DateTimeOffset.UtcNow,
            ExpiresAt: DateTimeOffset.UtcNow.AddHours(1),
            Policies: [Policy],
            Integrity: signature is null ? null : new IntegrityBlock(SigningAlgorithm.HmacSha256, signature));

    [Fact]
    public void IsBoundToMatchesTheExactSignatureOnly()
    {
        var marker = new EnforcedResult<object?>(null, "abc123");

        EnforcedResult.IsBoundTo(marker, ContextWith("abc123")).Should().BeTrue();
        EnforcedResult.IsBoundTo(marker, ContextWith("abc124")).Should().BeFalse();
        EnforcedResult.IsBoundTo(marker, ContextWith("abc1234")).Should().BeFalse();
    }

    [Fact]
    public void IsBoundToNeverMatchesAnEmptyOrAbsentContextSignature()
    {
        EnforcedResult.IsBoundTo(new EnforcedResult<object?>(null, ""), ContextWith("")).Should().BeFalse();
        EnforcedResult.IsBoundTo(new EnforcedResult<object?>(null, ""), ContextWith(null)).Should().BeFalse();
    }

    [Fact]
    public void UnwrapReturnsUnmarkedDataByIdentity()
    {
        var data = new List<Dictionary<string, object?>>
        {
            new() { ["a"] = 1, ["nested"] = new Dictionary<string, object?> { ["b"] = 2 } },
        };

        EnforcedResult.Unwrap(data).Should().BeSameAs(data);
        EnforcedResult.Contains(data).Should().BeFalse();
    }

    [Fact]
    public void UnwrapReplacesMarkersAtAnyDepth()
    {
        var data = new Dictionary<string, object?>
        {
            ["top"] = new EnforcedResult<object?>(
                new Dictionary<string, object?>
                {
                    ["inner"] = new List<object?>
                    {
                        new EnforcedResult<object?>(new Dictionary<string, object?> { ["deep"] = 1 }, "x"),
                    },
                },
                "y"),
        };

        EnforcedResult.Contains(data).Should().BeTrue();
        var unwrapped = EnforcedResult.Unwrap(data);

        EnforcedResult.Contains(unwrapped).Should().BeFalse();
        var top = (Dictionary<string, object?>)((Dictionary<string, object?>)unwrapped!)["top"]!;
        var inner = (IReadOnlyList<object?>)top["inner"]!;
        ((Dictionary<string, object?>)inner[0]!)["deep"].Should().Be(1);
    }

    [Fact]
    public void UnwrapKeepsARecordsKeyComparer()
    {
        var record = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
        {
            ["Id"] = new EnforcedResult<int>(1, "s"),
        };

        var unwrapped = (Dictionary<string, object?>)EnforcedResult.Unwrap(record)!;

        unwrapped.Comparer.Should().BeSameAs(StringComparer.OrdinalIgnoreCase);
        unwrapped["id"].Should().Be(1);
    }

    [Fact]
    public void ThePipelineUnwrapsATopLevelMarkerAndEnforcesItInFull()
    {
        List<Dictionary<string, object?>> Rows() =>
            [new() { ["region"] = "us-east", ["email"] = "a@example.com" }];

        var marked = EnforcementEngine.ApplyResultPipeline(new EnforcedResult<object?>(Rows(), "s"), Policy);
        var plain = EnforcementEngine.ApplyResultPipeline(Rows(), Policy);

        marked.Should().BeEquivalentTo(plain);
    }

    [Fact]
    public void ThePipelineStripsHiddenFieldsInsideANestedMarker()
    {
        var record = new Dictionary<string, object?>
        {
            ["region"] = "us-east",
            ["p"] = new EnforcedResult<object?>(
                new Dictionary<string, object?> { ["ssn"] = "1", ["id"] = 2 }, "s"),
        };

        var output = (Dictionary<string, object?>)EnforcementEngine.ApplyResultPipeline(record, Policy)!;

        output["p"].Should().BeEquivalentTo(new Dictionary<string, object?> { ["id"] = 2 });
    }

    private static EffectivePolicy PolicyFrom(string objectRulesAndLimits) =>
        TolapJsonOptions.Deserialize<EffectivePolicy>($$"""
            {
              "version": "1.0", "userId": "u", "tenantId": "t", "sourceConnectionId": "s",
              "resolvedAt": "2026-01-01T00:00:00Z", "expiresAt": "2099-01-01T00:00:00Z",
              "sourceProfiles": [],
              "permissions": { "canQuery": true },
              {{objectRulesAndLimits}}
            }
            """);

    [Fact]
    public void IdempotentStepsStripAndTruncateAndReRunAVisibleFilterButNeverMask()
    {
        var rows = new List<Dictionary<string, object?>>
        {
            new() { ["region"] = "eu-west", ["email"] = "already-hashed", ["ssn"] = "1" },
            new() { ["region"] = "us-east", ["email"] = "already-hashed", ["ssn"] = "2" },
            new() { ["region"] = "us-east", ["email"] = "already-hashed" },
            new() { ["region"] = "us-east", ["email"] = "already-hashed" },
        };

        EnforcementEngine.ApplyIdempotentResultSteps(rows, Policy).Should().BeEquivalentTo(
            new List<Dictionary<string, object?>>
            {
                new() { ["region"] = "us-east", ["email"] = "already-hashed" },
                new() { ["region"] = "us-east", ["email"] = "already-hashed" },
            });
    }

    [Fact]
    public void IdempotentStepsSkipARowFilterOnAMaskedField()
    {
        var policy = PolicyFrom("""
            "objectRules": {
              "fieldRules": { "maskedFields": [{ "field": "email", "maskType": "hash" }] },
              "rowFilters": [{ "field": "email", "operator": "equals", "value": "a@example.com" }]
            }
            """);
        var rows = new List<Dictionary<string, object?>> { new() { ["email"] = "hash" } };

        EnforcementEngine.ApplyIdempotentResultSteps(rows, policy).Should().BeEquivalentTo(rows);
    }

    [Fact]
    public void IdempotentStepsSkipARowFilterOnAHiddenOrProjectedOutField()
    {
        var hidden = PolicyFrom("""
            "objectRules": {
              "fieldRules": { "hiddenFields": ["status"] },
              "rowFilters": [{ "field": "status", "operator": "equals", "value": "active" }]
            }
            """);
        var projected = PolicyFrom("""
            "objectRules": {
              "fieldRules": { "allowedFields": ["id"] },
              "rowFilters": [{ "field": "region", "operator": "equals", "value": "us-east" }]
            }
            """);
        var rows = new List<Dictionary<string, object?>> { new() { ["id"] = 1 } };

        EnforcementEngine.ApplyIdempotentResultSteps(rows, hidden).Should().BeEquivalentTo(rows);
        EnforcementEngine.ApplyIdempotentResultSteps(rows, projected).Should().BeEquivalentTo(rows);
    }

    [Fact]
    public void IdempotentStepsReRunTagAndSimilarityFiltersOnVisibleKeysOnly()
    {
        var tags = PolicyFrom("""
            "objectRules": { "tagRules": { "deniedTags": ["secret"] } }
            """);
        var hiddenTags = PolicyFrom("""
            "objectRules": {
              "fieldRules": { "hiddenFields": ["tags"] },
              "tagRules": { "allowedTags": ["public"] }
            }
            """);
        var floor = PolicyFrom("""
            "limits": { "minSimilarityScore": 0.5 }
            """);

        EnforcementEngine.ApplyIdempotentResultSteps(
                new List<Dictionary<string, object?>> { new() { ["id"] = 1, ["tags"] = new List<object?> { "secret" } } },
                tags)
            .Should().BeEquivalentTo(new List<Dictionary<string, object?>>());
        EnforcementEngine.ApplyIdempotentResultSteps(
                new List<Dictionary<string, object?>> { new() { ["id"] = 1 } }, hiddenTags)
            .Should().BeEquivalentTo(new List<Dictionary<string, object?>> { new() { ["id"] = 1 } });
        EnforcementEngine.ApplyIdempotentResultSteps(
                new List<Dictionary<string, object?>> { new() { ["id"] = 1, ["score"] = 0.1 } }, floor)
            .Should().BeEquivalentTo(new List<Dictionary<string, object?>>());
    }

    [Fact]
    public void IdempotentStepsSkipTheSizeCeiling()
    {
        var policy = PolicyFrom("""
            "limits": { "maxObjectSizeBytes": 10 }
            """);
        var rows = new List<Dictionary<string, object?>> { new() { ["id"] = 1, ["size"] = 100 } };

        EnforcementEngine.ApplyIdempotentResultSteps(rows, policy).Should().BeEquivalentTo(rows);
    }

    [Fact]
    public void IdempotentStepsAreIdempotent()
    {
        var once = EnforcementEngine.ApplyResultPipeline(
            new List<Dictionary<string, object?>>
            {
                new() { ["region"] = "us-east", ["email"] = "a@example.com", ["ssn"] = "1" },
                new() { ["region"] = "us-east", ["email"] = "b@example.com" },
            },
            Policy);

        var twice = EnforcementEngine.ApplyIdempotentResultSteps(once, Policy);

        twice.Should().BeEquivalentTo(once);
        EnforcementEngine.ApplyIdempotentResultSteps(twice, Policy).Should().BeEquivalentTo(once);
    }

    [Fact]
    public void IdempotentStepsKeepASingleRecordASingleRecordAndNullWhenLimitedAway()
    {
        var zero = Policy with { Limits = new PolicyLimits(MaxResults: 0) };

        EnforcementEngine.ApplyIdempotentResultSteps(
                new Dictionary<string, object?> { ["id"] = 1, ["region"] = "us-east", ["ssn"] = "x" }, Policy)
            .Should().BeEquivalentTo(new Dictionary<string, object?> { ["id"] = 1, ["region"] = "us-east" });
        EnforcementEngine.ApplyIdempotentResultSteps(
                new Dictionary<string, object?> { ["id"] = 1, ["region"] = "eu-west" }, Policy)
            .Should().BeNull();
        EnforcementEngine.ApplyIdempotentResultSteps(
                new Dictionary<string, object?> { ["id"] = 1, ["region"] = "us-east" }, zero)
            .Should().BeNull();
    }

    [Fact]
    public void IdempotentStepsDenyAnUnenforceableShape()
    {
        var act = () => EnforcementEngine.ApplyIdempotentResultSteps("scalar", Policy);

        act.Should().Throw<UnenforceableResultException>();
    }
}
