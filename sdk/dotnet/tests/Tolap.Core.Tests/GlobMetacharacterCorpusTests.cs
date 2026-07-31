using System.Text.Json;
using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// Cross-SDK conformance for the enforcement glob metacharacter set (connector-spec
/// §3.1), driven by
/// <c>fixtures/enforcement/validate-object-access-glob-metacharacters.json</c>.
/// </summary>
/// <remarks>
/// <para>
/// The counterparts read the same file, case for case:
/// <c>sdk/python/tests/test_enforcement.py</c> (<c>test_glob_metacharacter_cases</c>) and
/// <c>packages/core/tests/enforcement.test.ts</c> ("validateAccess (glob metacharacters)").
/// </para>
/// <para>
/// <c>*</c> and <c>?</c> are the only wildcards; every other character, <c>[abc]</c>
/// included, is literal. The three SDKs disagreed here: <c>?</c> was a wildcard in Python
/// and TypeScript but a literal in .NET, and <c>[abc]</c> was a character class in Python
/// (via <c>fnmatch</c>) but literal in the other two. The same signed <c>allowedObjects</c>
/// entry therefore granted different access per language. Both are now specified §3.1 and
/// pinned here.
/// </para>
/// <para>
/// No skips and one test per case, on the same reasoning as
/// <see cref="RowFilterOperatorCorpusTests"/>: a missing fixture throws out of
/// <see cref="FixtureHelper"/>, and a single loop would hide every mismatch after the
/// first.
/// </para>
/// </remarks>
public class GlobMetacharacterCorpusTests
{
    private const string FixturePath =
        "enforcement/validate-object-access-glob-metacharacters.json";

    /// <summary>
    /// The number of cases the corpus is expected to carry, so a case dropped from the
    /// fixture cannot look like a shrinking-but-passing suite.
    /// </summary>
    private const int ExpectedCaseCount = 14;

    private static readonly JsonElement Corpus =
        FixtureHelper.ReadFixtureAsJson(FixturePath).Clone();

    private static readonly IReadOnlyList<JsonElement> Cases =
        Corpus.GetProperty("cases").EnumerateArray().Select(c => c.Clone()).ToList();

    public static IEnumerable<object[]> CaseData()
        => Cases.Select((c, i) => new object[] { i, c.GetProperty("objectName").GetString()! });

    [Fact]
    public void TheCorpusCarriesTheExpectedCaseCount()
    {
        Cases.Should().HaveCount(ExpectedCaseCount,
            $"a case dropped from {FixturePath} is coverage lost silently");
    }

    [Theory]
    [MemberData(nameof(CaseData))]
    public void CaseMatchesTheSharedExpectation(int index, string objectName)
    {
        var testCase = Cases[index];
        var policy = TolapJsonOptions.Deserialize<EffectivePolicy>(
            testCase.GetProperty("policy").GetRawText());

        var result = EnforcementEngine.ValidateAccess(objectName, policy);

        var expected = testCase.GetProperty("expected");
        var note = testCase.TryGetProperty("note", out var n) ? n.GetString() : null;

        result.Allowed.Should().Be(expected.GetProperty("allowed").GetBoolean(), note);

        if (!expected.GetProperty("allowed").GetBoolean())
        {
            result.Reason.Should().Be(expected.GetProperty("reason").GetString(), note);
        }
    }
}
