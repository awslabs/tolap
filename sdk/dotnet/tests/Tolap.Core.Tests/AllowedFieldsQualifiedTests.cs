using System.Text.Json;
using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// Cross-SDK conformance for how allowedFields treats object qualifiers (issue #36).
/// </summary>
/// <remarks>
/// Driven by <c>fixtures/enforcement/allowed-fields-qualified.json</c>. The counterparts read
/// the same file, case for case: Python's <c>tests/test_allowed_fields_qualified.py</c> and
/// TypeScript's <c>packages/core/tests/allowed-fields-qualified.test.ts</c>.
///
/// allowedFields used the field-name matcher, which drops qualifiers, so an entry
/// <c>patients.name</c> also allowed <c>encounters.name</c>: the read projection kept a column
/// the policy never listed, and the write path accepted it. The expectations live only in the
/// fixture.
///
/// Each case carries its own records or payload because key order is part of what is being
/// tested. They are built in the order the fixture writes them; a
/// <see cref="Dictionary{TKey,TValue}"/> that is only ever added to enumerates in insertion order.
/// </remarks>
public class AllowedFieldsQualifiedTests
{
    private const string FixturePath = "enforcement/allowed-fields-qualified.json";

    /// <summary>Asserted so that a dropped case fails the suite rather than shrinking it quietly.</summary>
    private const int ExpectedCaseCount = 53;

    private static readonly string[] Actions =
        ["projectAllowedFields", "applyResultPipeline", "validateWrite"];

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

    private static string Action(JsonElement testCase) => testCase.GetProperty("action").GetString()!;

    private static JsonElement CaseByName(string name)
        => Cases.SingleOrDefault(c => CaseName(c) == name) is { ValueKind: JsonValueKind.Object } found
            ? found
            : throw new InvalidOperationException(
                $"no case named '{name}' in {FixturePath}; the corpus changed shape under the test");

    private static Dictionary<string, object?> RecordOf(JsonElement record)
    {
        var row = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var property in record.EnumerateObject())
            row.Add(property.Name, Unwrap(property.Value));
        return row;
    }

    private static IReadOnlyList<Dictionary<string, object?>> RecordsOf(JsonElement testCase, string property)
        => testCase.GetProperty(property).EnumerateArray().Select(RecordOf).ToList();

    private static WriteOperation OperationOf(JsonElement testCase)
        => testCase.GetProperty("operation").GetString() switch
        {
            "insert" => WriteOperation.Insert,
            "update" => WriteOperation.Update,
            "delete" => WriteOperation.Delete,
            "upsert" => WriteOperation.Upsert,
            var other => throw new InvalidOperationException(
                $"case '{CaseName(testCase)}' names an unknown operation '{other}'")
        };

    private static EffectivePolicy PolicyOf(JsonElement testCase)
        => TolapJsonOptions.Deserialize<EffectivePolicy>(testCase.GetProperty("policy").GetRawText());

    public static IEnumerable<object[]> CaseNames(string action)
        => Cases.Where(c => Action(c) == action).Select(c => new object[] { CaseName(c) });

    public static IEnumerable<object[]> ProjectCases() => CaseNames("projectAllowedFields");

    public static IEnumerable<object[]> PipelineCases() => CaseNames("applyResultPipeline");

    public static IEnumerable<object[]> WriteCases() => CaseNames("validateWrite");

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
    public void EveryCaseNamesAKnownActionAndEveryActionIsExercised()
    {
        Cases.Select(Action).Should().OnlyContain(a => Actions.Contains(a));
        Cases.Select(Action).Distinct().Should().BeEquivalentTo(Actions);
    }

    [Fact]
    public void RecordsKeepTheKeyOrderTheFixtureWrites()
    {
        // The order-dependent cases are only meaningful if the record the engine sees
        // enumerates its keys in fixture order. Pinned here rather than left implicit.
        var row = RecordsOf(CaseByName("qualified-entry-keeps-own-object-key-other-first"), "records")[0];

        row.Keys.Should().Equal("encounters.name", "patients.name");
    }

    [Theory]
    [MemberData(nameof(ProjectCases))]
    public void ProjectAllowedFields_MatchesTheSharedCorpus(string caseName)
    {
        var testCase = CaseByName(caseName);

        var actual = EnforcementEngine.ProjectAllowedFields(RecordsOf(testCase, "records"), PolicyOf(testCase));

        actual.Should().BeEquivalentTo(RecordsOf(testCase, "expected"), options => options.WithStrictOrdering(),
            $"case '{caseName}' from {FixturePath} disagrees with the shared corpus");
    }

    [Theory]
    [MemberData(nameof(PipelineCases))]
    public void ApplyRecordPipeline_MatchesTheSharedCorpus(string caseName)
    {
        var testCase = CaseByName(caseName);

        var actual = EnforcementEngine.ApplyRecordPipeline(RecordsOf(testCase, "records"), PolicyOf(testCase));

        actual.Should().BeEquivalentTo(RecordsOf(testCase, "expected"), options => options.WithStrictOrdering(),
            $"case '{caseName}' from {FixturePath} disagrees with the shared corpus");
    }

    [Theory]
    [MemberData(nameof(WriteCases))]
    public void ValidateWrite_MatchesTheSharedCorpus(string caseName)
    {
        var testCase = CaseByName(caseName);

        var result = EnforcementEngine.ValidateWrite(
            OperationOf(testCase),
            testCase.GetProperty("objectName").GetString(),
            RecordOf(testCase.GetProperty("payload")),
            PolicyOf(testCase));

        var expected = testCase.GetProperty("expected");
        result.Allowed.Should().Be(expected.GetProperty("allowed").GetBoolean(), caseName);
        if (expected.TryGetProperty("reason", out var reason))
            result.Reason.Should().Be(reason.GetString(), caseName);
    }
}
