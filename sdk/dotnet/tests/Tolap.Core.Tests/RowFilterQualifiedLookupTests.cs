using System.Text.Json;
using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// Cross-SDK conformance for how a row filter finds its field on a row (issue #32).
/// </summary>
/// <remarks>
/// Driven by <c>fixtures/enforcement/row-filter-qualified-lookup.json</c>. The counterparts
/// read the same file, case for case: Python's <c>tests/test_row_filter_qualified_lookup.py</c>
/// and TypeScript's <c>packages/core/tests/row-filter-qualified-lookup.test.ts</c>.
///
/// The lookup used to fall back to the field-name matcher. That matcher drops qualifiers, so
/// a filter on <c>patients.region</c> read <c>encounters.region</c> when the row had no
/// <c>patients</c> column, and a bare filter matching several qualified keys used whichever
/// key came first. The expectations live only in the fixture.
///
/// Each case carries its own records because key order is part of what is being tested. The
/// records are built in the order the fixture writes them; a <see cref="Dictionary{TKey,TValue}"/>
/// that is only ever added to enumerates in insertion order.
/// </remarks>
public class RowFilterQualifiedLookupTests
{
    private const string FixturePath = "enforcement/row-filter-qualified-lookup.json";

    /// <summary>Asserted so that a dropped case fails the suite rather than shrinking it quietly.</summary>
    private const int ExpectedCaseCount = 30;

    private static readonly IReadOnlyList<JsonElement> Cases =
        FixtureHelper.ReadFixtureAsJson(FixturePath).Clone()
            .GetProperty("cases").EnumerateArray().Select(c => c.Clone()).ToList();

    private static object? Unwrap(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.String => value.GetString(),
        JsonValueKind.Number => value.TryGetInt64(out var l) ? l : value.GetDouble(),
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.Null => null,
        _ => value.GetRawText()
    };

    private static string CaseName(JsonElement testCase) => testCase.GetProperty("name").GetString()!;

    private static JsonElement CaseByName(string name)
        => Cases.SingleOrDefault(c => CaseName(c) == name) is { ValueKind: JsonValueKind.Object } found
            ? found
            : throw new InvalidOperationException(
                $"no case named '{name}' in {FixturePath}; the corpus changed shape under the test");

    private static IReadOnlyList<Dictionary<string, object?>> RecordsOf(JsonElement testCase)
        => testCase.GetProperty("records").EnumerateArray()
            .Select(record =>
            {
                var row = new Dictionary<string, object?>(StringComparer.Ordinal);
                foreach (var property in record.EnumerateObject())
                    row.Add(property.Name, Unwrap(property.Value));
                return row;
            })
            .ToList();

    private static IReadOnlyList<string> SurvivingIds(JsonElement testCase)
        => EnforcementEngine.ApplyRowFilters(
                RecordsOf(testCase),
                TolapJsonOptions.Deserialize<EffectivePolicy>(testCase.GetProperty("policy").GetRawText()))
            .Select(row => (string)row["id"]!)
            .ToList();

    private static IReadOnlyList<string> ExpectedIds(JsonElement testCase)
        => testCase.GetProperty("expected").EnumerateArray().Select(e => e.GetString()!).ToList();

    public static IEnumerable<object[]> CaseNames()
        => Cases.Select(c => new object[] { CaseName(c) });

    [Fact]
    public void TheCorpusCarriesTheExpectedCaseCount()
    {
        Cases.Should().HaveCount(ExpectedCaseCount,
            $"a case dropped from {FixturePath} is coverage lost silently");
    }

    [Fact]
    public void EveryCaseNameIsUnique()
    {
        var names = Cases.Select(CaseName).ToList();

        names.Distinct(StringComparer.Ordinal).Should().HaveCount(names.Count);
    }

    [Fact]
    public void EveryCaseCarriesRecordsAndRowFilters()
    {
        foreach (var testCase in Cases)
        {
            RecordsOf(testCase).Should().NotBeEmpty(CaseName(testCase));
            testCase.GetProperty("policy").GetProperty("objectRules").GetProperty("rowFilters")
                .EnumerateArray().Should().NotBeEmpty(CaseName(testCase));
        }
    }

    [Fact]
    public void RecordsKeepTheKeyOrderTheFixtureWrites()
    {
        // The order-dependent cases are only meaningful if the row the engine sees enumerates
        // its keys in fixture order. Pinned here rather than left implicit.
        var row = RecordsOf(CaseByName("qualified-filter-picks-own-object-conflicting-key-first"))[0];

        row.Keys.Should().Equal("id", "ENCOUNTERS.REGION", "PATIENTS.REGION");
    }

    [Theory]
    [MemberData(nameof(CaseNames))]
    public void ApplyRowFilters_MatchesTheSharedCorpus(string caseName)
    {
        var testCase = CaseByName(caseName);

        SurvivingIds(testCase).Should().Equal(ExpectedIds(testCase),
            $"case '{caseName}' from {FixturePath} disagrees with the shared corpus");
    }

    // =======================================================================
    // An update or delete target is checked through the same row-filter lookup, so a target
    // row the read path would drop is also refused as a write target.
    // =======================================================================

    private static EffectivePolicy WritePolicy(string field)
        => TolapJsonOptions.Deserialize<EffectivePolicy>(JsonSerializer.Serialize(new
        {
            version = "1.0",
            permissions = new { canQuery = true, canUpdate = true, canDelete = true, readOnly = false },
            objectRules = new
            {
                rowFilters = new[] { new { field, @operator = "equals", value = "us-east" } }
            }
        }));

    [Theory]
    [InlineData(WriteOperation.Update)]
    [InlineData(WriteOperation.Delete)]
    public void ValidateWrite_RefusesATargetCarryingOnlyAnotherObjectsColumn(WriteOperation operation)
    {
        var result = EnforcementEngine.ValidateWrite(
            operation,
            "patients",
            operation == WriteOperation.Update ? new Dictionary<string, object?> { ["status"] = "x" } : null,
            WritePolicy("patients.region"),
            new WriteValidationOptions(TargetRow: new Dictionary<string, object?>
            {
                ["encounters.region"] = "us-east"
            }));

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be("target row not permitted");
    }

    [Fact]
    public void ValidateWrite_RefusesAnAmbiguousTarget()
    {
        var result = EnforcementEngine.ValidateWrite(
            WriteOperation.Update,
            "patients",
            new Dictionary<string, object?> { ["status"] = "x" },
            WritePolicy("region"),
            new WriteValidationOptions(TargetRow: new Dictionary<string, object?>
            {
                ["patients.region"] = "us-east",
                ["encounters.region"] = "us-east"
            }));

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be("target row not permitted");
    }

    [Fact]
    public void ValidateWrite_StillPermitsATargetWhoseBareKeySatisfiesTheFilter()
    {
        var result = EnforcementEngine.ValidateWrite(
            WriteOperation.Update,
            "patients",
            new Dictionary<string, object?> { ["status"] = "x" },
            WritePolicy("patients.region"),
            new WriteValidationOptions(TargetRow: new Dictionary<string, object?>
            {
                ["encounters.region"] = "eu-west",
                ["region"] = "us-east"
            }));

        result.Allowed.Should().BeTrue();
    }
}
