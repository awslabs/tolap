using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// The sliding window a judge reads its context from (spec section 15.4).
/// </summary>
/// <remarks>
/// Small enough to look like it needs no tests, which is why it gets them: purpose drift is a
/// property of a sequence, so a window that silently returns the wrong entries — or the right
/// entries in the wrong order — hands the judge a trajectory that never happened, and the
/// judge has no way to notice.
/// </remarks>
public class ToolCallHistoryTests
{
    [Fact]
    public void GetRecent_OnAFreshHistory_IsEmpty()
    {
        new ToolCallHistory().GetRecent().Should().BeEmpty();
    }

    [Fact]
    public void DefaultMaxSize_MatchesTheDocumentedHistoryWindow()
    {
        // The schema documents historyWindow's default as 10. A different default here would
        // mean an unconfigured judge saw a different amount of history than the policy author
        // was told.
        new ToolCallHistory().MaxSize.Should().Be(JudgeDispositions.DefaultHistoryWindow);
    }

    [Fact]
    public void Record_BelowTheBound_RetainsEverythingOldestFirst()
    {
        var history = new ToolCallHistory(maxSize: 5);

        history.Record("count_segments()");
        history.Record("aggregate_overlap(campaign-x)");

        history.GetRecent().Should().Equal("count_segments()", "aggregate_overlap(campaign-x)");
        history.Count.Should().Be(2);
    }

    [Fact]
    public void Record_AtTheBound_RetainsEverything()
    {
        var history = new ToolCallHistory(maxSize: 3);

        history.Record("a");
        history.Record("b");
        history.Record("c");

        history.GetRecent().Should().Equal("a", "b", "c");
    }

    [Fact]
    public void Record_AboveTheBound_EvictsTheOldest()
    {
        var history = new ToolCallHistory(maxSize: 3);

        foreach (var call in new[] { "a", "b", "c", "d", "e" })
            history.Record(call);

        history.GetRecent().Should().Equal("c", "d", "e");
        history.Count.Should().Be(3);
    }

    [Fact]
    public void Record_WithAWindowOfOne_KeepsOnlyTheLatest()
    {
        // The narrowest legal window. Worth its own case because an off-by-one in the eviction
        // loop shows up here and nowhere else.
        var history = new ToolCallHistory(maxSize: 1);

        history.Record("a");
        history.Record("b");

        history.GetRecent().Should().Equal("b");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void Constructor_RefusesANonPositiveWindow(int maxSize)
    {
        // A zero-size window would make Record a no-op and hand the judge an empty history,
        // which reads as a fresh conversation -- precisely the state a drifting agent benefits
        // from. Refused loudly rather than clamped, because clamping to 1 would silently give
        // a caller a window they did not ask for.
        var act = () => new ToolCallHistory(maxSize);

        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void Record_RefusesNull()
    {
        var act = () => new ToolCallHistory().Record(null!);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Record_KeepsDuplicatesAndEmptyStrings()
    {
        // Not a set. An agent repeating the same call ten times is a signal, and de-duplicating
        // would erase exactly the pattern the judge is looking for.
        var history = new ToolCallHistory(maxSize: 4);

        history.Record("aggregate_overlap()");
        history.Record("aggregate_overlap()");
        history.Record("");

        history.GetRecent().Should().Equal("aggregate_overlap()", "aggregate_overlap()", "");
    }

    [Fact]
    public void GetRecent_ReturnsACopy()
    {
        // A caller holding the result must not see it change underneath them, and must not be
        // able to mutate the window by writing into what they were handed.
        var history = new ToolCallHistory(maxSize: 2);
        history.Record("a");

        var snapshot = history.GetRecent();
        history.Record("b");
        snapshot[0] = "mutated";

        snapshot.Should().Equal("mutated");
        history.GetRecent().Should().Equal("a", "b");
    }

    [Fact]
    public void Clear_DiscardsEverythingButKeepsTheBound()
    {
        var history = new ToolCallHistory(maxSize: 2);
        history.Record("a");

        history.Clear();

        history.GetRecent().Should().BeEmpty();
        history.Count.Should().Be(0);
        history.MaxSize.Should().Be(2, "clearing a conversation does not reconfigure the window");
    }

    [Fact]
    public void GetRecent_FeedsAJudgeRequestInChronologicalOrder()
    {
        // The reason order is asserted at all: a judge reading a trajectory backwards sees an
        // agent narrowing its scope rather than widening it, which inverts the finding.
        var history = new ToolCallHistory(maxSize: 3);
        history.Record("count_segments()");
        history.Record("aggregate_overlap(campaign-x)");
        history.Record("export_csv(customer_segments)");

        var request = new JudgeRequest(
            new PurposeProfile("campaign-x-overlap"),
            CurrentToolCall: "export_csv(customer_segments)",
            RecentHistory: history.GetRecent(),
            MaxLatencyMs: JudgeDispositions.DefaultMaxLatencyMs);

        request.RecentHistory.Should().Equal(
            "count_segments()", "aggregate_overlap(campaign-x)", "export_csv(customer_segments)");
    }
}
