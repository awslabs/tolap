using System.Text.Json;
using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// Cross-SDK conformance for all 16 row-filter operators, driven by
/// <c>fixtures/enforcement/apply-row-filters-all-operators.json</c>.
/// </summary>
/// <remarks>
/// <para>
/// The counterparts read the same file, case for case:
/// <c>sdk/python/tests/test_row_filter_operator_corpus.py</c> and
/// <c>packages/core/tests/row-filter-operator-corpus.test.ts</c>.
/// </para>
/// <para>
/// <see cref="RowFilterOperatorTests"/> already pins each operator's semantics <i>in this
/// SDK</i>. That is not the same guarantee: a per-SDK unit test asserts whatever that SDK
/// happens to implement, so three suites can all pass while three implementations disagree.
/// The shared corpus previously covered 9 of the schema's 16 operators, and the seven it
/// left out — <c>between</c>, <c>greaterThanOrEqual</c>, <c>lessThanOrEqual</c>,
/// <c>isNull</c>, <c>isNotNull</c>, <c>like</c>, <c>notLike</c> — are exactly the ones that
/// diverged: a schema-valid <c>{"operator":"between"}</c> policy crashed Python with a
/// <c>KeyError</c>, silently dropped every row in TypeScript, and enforced correctly here,
/// while the signature verified in all three. Nothing forced agreement because nothing
/// compared them.
/// </para>
/// <para>
/// So the expectations live in the fixture and only in the fixture. Restating them here
/// would create a second copy free to drift the same way the first one did, which is the
/// whole failure mode being closed.
/// </para>
/// <para>
/// Two properties this file deliberately does NOT soften. <b>No skips:</b> a missing fixture
/// throws out of <see cref="FixtureHelper"/>, and an operator string this SDK's converter
/// cannot map fails its own assertion — an operator this SDK cannot express IS the
/// divergence, not a reason to stand down. <b>One test per case:</b> a single loop reports
/// the first mismatch and hides the rest, whereas 21 named cases report which
/// <i>operator</i> disagrees.
/// </para>
/// <para>
/// Record values are unwrapped from JSON to CLR primitives, with a JSON null becoming a CLR
/// <c>null</c>. That is deliberately the shape the shipped code produces: the HTTP wrapper
/// builds its record dictionaries with <c>JsonNodeFromElement</c>, which maps
/// <see cref="JsonValueKind.Null"/> to <c>null</c> before
/// <see cref="EnforcementEngine.ApplyRowFilters"/> ever sees the row. It is also the faithful
/// cross-SDK equivalent of the Python dict and the TypeScript object the other two suites
/// feed, so all three compare like with like.
/// </para>
/// <para>
/// Leaving the values as raw <see cref="JsonElement"/> instead would make this file lie.
/// A boxed <see cref="JsonElement"/> holding JSON null is not <c>null</c> under
/// <c>is null</c>, and it stringifies to the empty string — so the <c>notLike</c> arm's
/// <c>value is null</c> guard misses it, the empty string is compared against the pattern,
/// and the null row is RETAINED. That direction is fail-open, and it is not confined to
/// <c>notLike</c>: under the same representation a null row value also satisfies
/// <c>like '%'</c>, <c>contains ''</c>, <c>startsWith ''</c> and <c>matches '.*'</c>, none of
/// which a null value may ever match. A representation that turns a null into an empty string
/// would let this corpus pass for the wrong reason.
/// </para>
/// </remarks>
public class RowFilterOperatorCorpusTests
{
    private const string FixturePath = "enforcement/apply-row-filters-all-operators.json";

    /// <summary>
    /// The number of cases the corpus is expected to carry. Asserted below so a future edit
    /// that silently drops a case cannot look like a shrinking-but-passing suite.
    /// </summary>
    private const int ExpectedCaseCount = 21;

    private static readonly JsonElement Corpus =
        FixtureHelper.ReadFixtureAsJson(FixturePath).Clone();

    private static readonly IReadOnlyList<JsonElement> Cases =
        Corpus.GetProperty("cases").EnumerateArray().Select(c => c.Clone()).ToList();

    /// <summary>
    /// Unwrap one JSON value to the CLR form the shipped wrappers hand the engine.
    /// </summary>
    /// <remarks>
    /// A JSON null becomes a CLR <c>null</c>, matching <c>JsonNodeFromElement</c> in
    /// <c>SecureHttpToolWrapper</c>. See the type-level remarks for why leaving it as a
    /// <see cref="JsonElement"/> would make the <c>nullish</c> record pass fail-open.
    /// </remarks>
    private static object? Unwrap(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.String => value.GetString(),
        JsonValueKind.Number => value.TryGetInt64(out var l) ? l : value.GetDouble(),
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.Null => null,
        _ => value.GetRawText()
    };

    /// <summary>The shared record set, in fixture order, in CLR form.</summary>
    private static readonly IReadOnlyList<Dictionary<string, object?>> Records =
        Corpus.GetProperty("records").EnumerateArray()
            .Select(record => record.EnumerateObject()
                .ToDictionary(p => p.Name, p => Unwrap(p.Value), StringComparer.Ordinal))
            .ToList();

    private static string CaseName(JsonElement testCase) => testCase.GetProperty("name").GetString()!;

    /// <summary>The one case carrying <paramref name="name"/>, or a failure if absent.</summary>
    private static JsonElement CaseByName(string name)
        => Cases.SingleOrDefault(c => CaseName(c) == name) is { ValueKind: JsonValueKind.Object } found
            ? found
            : throw new InvalidOperationException(
                $"no case named '{name}' in {FixturePath}; the corpus changed shape under the test");

    /// <summary>The raw operator strings a case's policy carries, as written in the fixture.</summary>
    private static IEnumerable<string> OperatorsIn(JsonElement testCase)
        => testCase.GetProperty("policy").GetProperty("objectRules").GetProperty("rowFilters")
            .EnumerateArray()
            .Select(f => f.GetProperty("operator").GetString()!);

    /// <summary>Every operator string the corpus uses, deduplicated.</summary>
    private static ISet<string> OperatorsUsed()
        => Cases.SelectMany(OperatorsIn).ToHashSet(StringComparer.Ordinal);

    /// <summary>Whether this SDK's converter maps a wire operator to an enum member.</summary>
    private static bool Accepts(string wireOperator)
    {
        try
        {
            TolapJsonOptions.Deserialize<FilterOperator>(JsonSerializer.Serialize(wireOperator));
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    /// <summary>
    /// The case's policy, deserialized through the shipped converters.
    /// </summary>
    /// <remarks>
    /// Loading the policy rather than constructing <see cref="RowFilter"/> values from mapped
    /// enum members is the point: the fixture holds each operator as the camelCase string the
    /// schema publishes, which is what a real policy carries, so this crosses the boundary an
    /// integrator actually crosses. The envelope fields the fixture omits (user, tenant,
    /// timestamps) do not bear on a row-filter decision and are left at their defaults.
    /// </remarks>
    private static EffectivePolicy PolicyFor(JsonElement testCase)
        => TolapJsonOptions.Deserialize<EffectivePolicy>(
            testCase.GetProperty("policy").GetRawText());

    /// <summary>The ids of the records that survive a case's filters, in order.</summary>
    private static IReadOnlyList<string> SurvivingIds(JsonElement testCase)
        => EnforcementEngine.ApplyRowFilters(Records, PolicyFor(testCase))
            .Select(row => (string)row["id"]!)
            .ToList();

    private static IReadOnlyList<string> ExpectedIds(JsonElement testCase)
        => testCase.GetProperty("expected").EnumerateArray().Select(e => e.GetString()!).ToList();

    public static IEnumerable<object[]> CaseNames()
        => Cases.Select(c => new object[] { CaseName(c) });

    // =======================================================================
    // Guards on the corpus itself, before any operator is evaluated
    // =======================================================================

    [Fact]
    public void TheCorpusCarriesTheExpectedCaseCount()
    {
        Cases.Should().HaveCount(ExpectedCaseCount,
            $"a case dropped from {FixturePath} is coverage lost silently");
    }

    [Fact]
    public void TheCorpusCarriesTheExpectedSharedRecords()
    {
        Records.Select(r => (string)r["id"]!)
            .Should().Equal("low", "mid", "high", "nullish", "missing");
    }

    [Fact]
    public void TheNullishRecordCarriesRealNullsNotEmptyStrings()
    {
        // The representation guard. If `nullish` ever arrived carrying JsonElement values,
        // its fields would stringify to "" and a null row value would start satisfying
        // notLike, like '%', contains '' and matches '.*' -- so this corpus would pass in the
        // fail-open direction. Pinned here rather than left implicit in Unwrap.
        var nullish = Records.Single(r => (string)r["id"]! == "nullish");

        foreach (var field in new[] { "score", "region", "name" })
            nullish[field].Should().BeNull($"'{field}' on the nullish record must be a CLR null");
    }

    [Fact]
    public void EveryCaseNameIsUnique()
    {
        // Duplicated names would let one case mask another in the report, and would make
        // CaseByName ambiguous.
        var names = Cases.Select(CaseName).ToList();

        names.Distinct(StringComparer.Ordinal).Should().HaveCount(names.Count);
    }

    [Fact]
    public void EveryCaseCarriesAPolicyWithRowFilters()
    {
        // A case that cannot be mapped is a failure, never a skip.
        foreach (var testCase in Cases)
            OperatorsIn(testCase).Should().NotBeEmpty(CaseName(testCase));
    }

    [Fact]
    public void EveryOperatorInTheCorpusMapsToAnEnumMember()
    {
        // An operator string with no FilterOperator member IS the divergence this fixture
        // exists to catch. Asserted on its own so the message names the offending value
        // rather than surfacing as 21 identical deserialization failures below.
        var unmappable = OperatorsUsed().Where(op => !Accepts(op)).OrderBy(op => op, StringComparer.Ordinal);

        unmappable.Should().BeEmpty(
            $"{FixturePath} uses operator(s) this SDK's converter rejects");
    }

    [Fact]
    public void TheCorpusExercisesEveryOperatorTheSchemaDeclares()
    {
        // The point of the fixture: 16 of 16, not 9 of 16.
        var declared = SchemaHelper.EnumAt(
            "policy-definition", "$defs", "filterRule", "properties", "operator", "enum");

        OperatorsUsed().Should().BeEquivalentTo(declared);
    }

    // =======================================================================
    // One test per case, so a failure names the operator that disagreed
    // =======================================================================

    [Theory]
    [MemberData(nameof(CaseNames))]
    public void ApplyRowFilters_MatchesTheSharedCorpus(string caseName)
    {
        var testCase = CaseByName(caseName);

        SurvivingIds(testCase).Should().Equal(ExpectedIds(testCase),
            $"case '{caseName}' from {FixturePath} disagrees with the shared corpus; this " +
            "SDK and at least one other now enforce the same schema-valid policy differently");
    }
}
