using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// Mapping a judge verdict onto a disposition (spec section 15.4).
/// </summary>
/// <remarks>
/// The judge is the one non-deterministic component in the enforcement path, so the rule that
/// matters is not "does it decide correctly" — it cannot be tested for that — but "does every
/// answer it cannot give confidently end up somewhere safe". Every case below is either a
/// confident verdict or an escalation, and escalation denies unless a handler is wired.
/// </remarks>
public class JudgeDispositionTests
{
    private const string Fixture = "purpose-binding/judge-dispositions.json";

    public static TheoryData<string> FixtureCases()
    {
        var data = new TheoryData<string>();
        foreach (var testCase in FixtureHelper.ReadFixtureAsJson(Fixture).GetProperty("cases").EnumerateArray())
            data.Add(testCase.GetProperty("name").GetString()!);
        return data;
    }

    [Theory]
    [MemberData(nameof(FixtureCases))]
    public void For_MatchesTheSharedFixture(string name)
    {
        var testCase = FixtureHelper.ReadFixtureAsJson(Fixture).GetProperty("cases")
            .EnumerateArray()
            .Single(c => c.GetProperty("name").GetString() == name);

        var result = TolapJsonOptions.Deserialize<JudgeResult>(
            testCase.GetProperty("result").GetRawText());
        var config = TolapJsonOptions.Deserialize<JudgeConfig>(
            testCase.GetProperty("config").GetRawText());

        var expected = testCase.GetProperty("expected").GetString() switch
        {
            "allow" => JudgeDisposition.Allow,
            "block" => JudgeDisposition.Block,
            "escalate" => JudgeDisposition.Escalate,
            var other => throw new InvalidOperationException($"unknown disposition '{other}'")
        };

        JudgeDispositions.For(result, config).Should().Be(expected, "case '{0}'", name);
    }

    [Fact]
    public void FixtureCases_CoverAllThreeDispositions()
    {
        // A fixture that had drifted into all-escalate would satisfy most cases above while
        // proving nothing about the confident paths.
        var outcomes = FixtureHelper.ReadFixtureAsJson(Fixture).GetProperty("cases")
            .EnumerateArray()
            .Select(c => c.GetProperty("expected").GetString())
            .ToList();

        outcomes.Should().Contain("allow").And.Contain("block").And.Contain("escalate");
    }

    private static readonly JudgeConfig Standard =
        new(ConfidenceThreshold: 0.85, EscalationThreshold: 0.60);

    [Fact]
    public void For_NullConfig_UsesTheDocumentedDefaults()
    {
        // A profile may enable the judge and configure nothing. The defaults have to come from
        // somewhere, and reading them here rather than baking them into the record keeps an
        // unset threshold serializing as absent.
        JudgeDispositions.For(new JudgeResult(true, 0.9, "above the default bar"), null)
            .Should().Be(JudgeDisposition.Allow);

        JudgeDispositions.For(new JudgeResult(true, 0.7, "in the default band"), null)
            .Should().Be(JudgeDisposition.Escalate);

        JudgeDispositions.For(new JudgeResult(false, 0.9, "confidently misaligned"), null)
            .Should().Be(JudgeDisposition.Block);
    }

    [Theory]
    [InlineData(0.85, JudgeDisposition.Allow)]
    [InlineData(0.8499, JudgeDisposition.Escalate)]
    [InlineData(0.6, JudgeDisposition.Escalate)]
    [InlineData(0.5999, JudgeDisposition.Escalate)]
    public void For_ThresholdsAreInclusiveAtTheirBound(double confidence, JudgeDisposition expected)
    {
        // "At or above" for confidence and "below" for escalation. Off-by-one at a boundary is
        // the classic way a threshold ends up one case wider than intended, and here that case
        // is an allow.
        JudgeDispositions.For(new JudgeResult(true, confidence, "boundary"), Standard)
            .Should().Be(expected);
    }

    [Theory]
    [InlineData(-0.1)]
    [InlineData(1.5)]
    [InlineData(double.PositiveInfinity)]
    [InlineData(double.NegativeInfinity)]
    [InlineData(double.NaN)]
    public void For_ConfidenceOutsideTheUnitRange_Escalates(double confidence)
    {
        // A judge reporting 1.5 has malfunctioned. Comparing that against a threshold would
        // hand a broken answer more authority than a correct one -- 1.5 clears every bar. NaN
        // is here too because it fails every comparison and would otherwise fall through to
        // whichever branch happened to be last.
        JudgeDispositions.For(new JudgeResult(true, confidence, "out of range"), Standard)
            .Should().Be(JudgeDisposition.Escalate);
    }

    [Fact]
    public void For_InvertedThresholds_EscalateRatherThanGuessing()
    {
        // Merging two judge configs can produce this, since both thresholds take the maximum
        // independently. There is no reading of the configuration to act on, so neither a
        // confident allow nor a confident block is available.
        var inverted = new JudgeConfig(ConfidenceThreshold: 0.6, EscalationThreshold: 0.9);

        JudgeDispositions.For(new JudgeResult(true, 0.95, "would otherwise allow"), inverted)
            .Should().Be(JudgeDisposition.Escalate);
        JudgeDispositions.For(new JudgeResult(false, 0.95, "would otherwise block"), inverted)
            .Should().Be(JudgeDisposition.Escalate);
    }

    [Fact]
    public void For_EqualThresholds_LeaveNoAmbiguousBand()
    {
        // Equal is not inverted: it is a valid configuration that says "decide or escalate,
        // with nothing in between".
        var equal = new JudgeConfig(ConfidenceThreshold: 0.8, EscalationThreshold: 0.8);

        JudgeDispositions.For(new JudgeResult(true, 0.8, "at both bounds"), equal)
            .Should().Be(JudgeDisposition.Allow);
        JudgeDispositions.For(new JudgeResult(false, 0.8, "at both bounds"), equal)
            .Should().Be(JudgeDisposition.Block);
        JudgeDispositions.For(new JudgeResult(true, 0.79, "just below"), equal)
            .Should().Be(JudgeDisposition.Escalate);
    }

    [Fact]
    public void For_AlignmentOnlyDecidesTheConfidentCase()
    {
        // Below the bar, alignment is irrelevant -- a low-confidence "aligned" is not an allow.
        // This is the asymmetry that keeps the judge subtractive.
        JudgeDispositions.For(new JudgeResult(true, 0.3, "unsure but positive"), Standard)
            .Should().Be(JudgeDisposition.Escalate);
        JudgeDispositions.For(new JudgeResult(false, 0.3, "unsure and negative"), Standard)
            .Should().Be(JudgeDisposition.Escalate);
    }

    [Fact]
    public void For_ZeroAndFullConfidence_AreHandled()
    {
        JudgeDispositions.For(new JudgeResult(true, 0.0, "no signal"), Standard)
            .Should().Be(JudgeDisposition.Escalate);
        JudgeDispositions.For(new JudgeResult(false, 1.0, "explicit exfiltration"), Standard)
            .Should().Be(JudgeDisposition.Block);
        JudgeDispositions.For(new JudgeResult(true, 1.0, "plainly on task"), Standard)
            .Should().Be(JudgeDisposition.Allow);
    }

    [Fact]
    public void TheDefaults_MatchTheSchemaDocumentation()
    {
        // The schema documents these as its `default` annotations, which are advisory to a
        // validator and therefore not enforced by one. If the two drifted, a policy author
        // reading the schema would configure against numbers the SDK does not use.
        JudgeDispositions.DefaultConfidenceThreshold.Should().Be(0.85);
        JudgeDispositions.DefaultEscalationThreshold.Should().Be(0.60);
        JudgeDispositions.DefaultMaxLatencyMs.Should().Be(2000);
        JudgeDispositions.DefaultHistoryWindow.Should().Be(10);
    }

    [Fact]
    public void DefaultEscalationThreshold_IsBelowDefaultConfidenceThreshold()
    {
        // The defaults must not themselves be the inverted configuration that escalates
        // everything, which would make an unconfigured judge useless in a way no individual
        // disposition test would reveal.
        JudgeDispositions.DefaultEscalationThreshold
            .Should().BeLessThan(JudgeDispositions.DefaultConfidenceThreshold);
    }
}
