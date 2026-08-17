using Tolap.Core;
using FluentAssertions;
using Microsoft.SemanticKernel;
using Xunit;

namespace Tolap.Examples;

/// <summary>
/// Asserts both .NET framework examples enforce, not merely that they compile.
/// </summary>
/// <remarks>
/// <para>
/// Parametrised across frameworks on purpose. A per-framework test would pass if one integration
/// quietly returned the raw rows, because nothing would compare it to the other. Here both must
/// produce the <i>same</i> enforced output.
/// </para>
/// <para>
/// <see cref="Expected"/> is identical to the Python and TypeScript suites', which is the point:
/// the examples across all three languages make one claim, so a cross-language divergence shows up
/// as a different result rather than hiding behind separately-written expectations.
/// </para>
/// </remarks>
public class ExamplesTests
{
    /// <summary>
    /// What the policy must produce from <see cref="TolapSetup.FakeRows"/>: the region filter drops
    /// eu-west (4 -> 3), MaxResults caps at 2, ssn is hidden, dob is redacted.
    /// </summary>
    private static readonly List<Dictionary<string, object?>> Expected = new()
    {
        new() { ["id"] = 1, ["name"] = "Alice Nguyen", ["region"] = "us-east", ["dob"] = "[REDACTED]" },
        new() { ["id"] = 2, ["name"] = "Bruno Sato", ["region"] = "us-east", ["dob"] = "[REDACTED]" },
    };

    /// <summary>Each framework driven through its own registered entry point.</summary>
    private static List<Dictionary<string, object?>> Invoke(string framework, string table)
        => framework switch
        {
            "mcp-server" => McpServerExample.QueryPatients(table),
            "semantic-kernel" => new SemanticKernelExample().QueryPatients(table),
            _ => throw new ArgumentOutOfRangeException(nameof(framework)),
        };

    [Theory]
    [InlineData("mcp-server")]
    [InlineData("semantic-kernel")]
    public void PermittedTable_ReturnsTheEnforcedRows(string framework)
    {
        Invoke(framework, "patients").Should().BeEquivalentTo(Expected);
    }

    [Fact]
    public void Control_TheFakeSourceReallyReturnsMore()
    {
        // Without this, the assertion above could pass against an empty source.
        TolapSetup.FakeRows.Count.Should().BeGreaterThan(Expected.Count);
        TolapSetup.FakeRows.Should().Contain(r => r.ContainsKey("ssn"));
    }

    [Theory]
    [InlineData("mcp-server")]
    [InlineData("semantic-kernel")]
    public void HiddenField_NeverReachesTheCaller(string framework)
    {
        Invoke(framework, "patients").Should().OnlyContain(r => !r.ContainsKey("ssn"));
    }

    [Theory]
    [InlineData("mcp-server")]
    [InlineData("semantic-kernel")]
    public void MaskedField_IsRedacted(string framework)
    {
        var originals = TolapSetup.FakeRows.Select(r => (string?)r["dob"]).ToHashSet();

        Invoke(framework, "patients").Should().OnlyContain(r => !originals.Contains((string?)r["dob"]));
    }

    [Theory]
    [InlineData("mcp-server")]
    [InlineData("semantic-kernel")]
    public void RowFilterAndLimit_AreApplied(string framework)
    {
        var rows = Invoke(framework, "patients");

        rows.Should().OnlyContain(r => (string?)r["region"] == "us-east");
        rows.Should().HaveCount(2);
    }

    [Theory]
    [InlineData("mcp-server")]
    [InlineData("semantic-kernel")]
    public void DeniedTable_ThrowsRatherThanReturningData(string framework)
    {
        // A denial must be distinguishable from an empty result: an agent that cannot tell "no
        // rows matched" from "you may not read this" will retry forever, and an audit trail that
        // conflates them cannot answer what was refused.
        var act = () => Invoke(framework, "encounters");

        act.Should().Throw<UnauthorizedAccessException>();
    }

    [Fact]
    public void SemanticKernel_RegistersTheFunctionWithTheKernel()
    {
        // Proves the attribute wiring works, not just the method body: a plugin whose function is
        // never discovered would pass every assertion above while being invisible to the planner.
        var kernel = Kernel.CreateBuilder().Build();
        kernel.Plugins.AddFromType<SemanticKernelExample>("patients");

        kernel.Plugins.GetFunction("patients", "query_patients").Should().NotBeNull();
    }
}

/// <summary>
/// The enforcement-mode example, executed rather than trusted.
/// </summary>
/// <remarks>
/// An example nothing runs will drift; one that mis-wires enforcement teaches people to bypass it.
/// These run the example's own methods and assert the property it claims — that the two modes agree
/// — so a regression in either path fails here rather than in a reader's terminal.
/// </remarks>
public class EnforcementModeExampleTests
{
    [Fact]
    public async Task BothModes_ReturnIdenticalRows()
    {
        var rewritten = await EnforcementModeExample.RunAsync(SqlEnforcementMode.RewriteAndPost);
        var postOnly = await EnforcementModeExample.RunAsync(SqlEnforcementMode.PostOnly);

        postOnly.Final.Should().BeEquivalentTo(rewritten.Final);

        // And the modes really did ask the database for different things — otherwise the
        // equality above would hold trivially.
        rewritten.Prep.Rewritten.Should().BeTrue();
        postOnly.Prep.Rewritten.Should().BeFalse();
        postOnly.Prep.Query.Should().Be(EnforcementModeExample.Query);
        rewritten.FromDatabase.Count.Should().BeLessThan(postOnly.FromDatabase.Count);
    }

    [Fact]
    public async Task MatchesThePythonAndTypeScriptExamples()
    {
        // All three languages state the same expectation on purpose. A per-language expectation
        // would let one SDK quietly return something else, because nothing would compare them.
        var run = await EnforcementModeExample.RunAsync(SqlEnforcementMode.RewriteAndPost);

        run.Final.Should().HaveCount(1);
        run.Final[0]["id"].Should().Be(1);
        run.Final[0]["name"].Should().Be("Alice Nguyen");
        run.Final[0]["region"].Should().Be("us-east");
        run.Final[0]["dob"].Should().Be("[REDACTED]");
    }

    [Theory]
    [InlineData(SqlEnforcementMode.RewriteAndPost)]
    [InlineData(SqlEnforcementMode.PostOnly)]
    public async Task HidesSsnAndRedactsDob_InBothModes(SqlEnforcementMode mode)
    {
        var run = await EnforcementModeExample.RunAsync(mode);

        // The fake database really did return ssn, so its absence is enforcement rather than a
        // fixture that never had it.
        run.FromDatabase.Should().Contain(r => r.ContainsKey("ssn"));
        run.Final.Should().OnlyContain(r => !r.ContainsKey("ssn"));
        run.Final.Should().OnlyContain(r => Equals(r["dob"], "[REDACTED]"));
    }

    [Fact]
    public async Task TheExampleRunsCleanAndAgrees()
    {
        // RunExampleAsync throws if the modes disagree, so this covers that path too.
        var act = async () => await EnforcementModeExample.RunExampleAsync();

        await act.Should().NotThrowAsync();
    }
}

