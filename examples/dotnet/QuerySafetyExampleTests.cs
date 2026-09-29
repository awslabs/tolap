using Tolap.Mcp;
using FluentAssertions;
using Xunit;

namespace Tolap.Examples;

/// <summary>
/// Asserts the query-safety example actually enforces, not merely that it runs.
/// </summary>
/// <remarks>
/// Each assertion is an outcome — which query was refused and with what reason, whether the source
/// was reached, which row and which columns survived the pipeline, how many times a field was
/// hashed — so an example that printed plausible verdicts while enforcing nothing would fail here.
/// </remarks>
[Collection(ConsoleCapture.Name)]
public class QuerySafetyExampleTests
{
    /// <summary>
    /// The lines the query-safety example must print, byte for byte. Repeated verbatim in the
    /// Python and TypeScript suites: a divergence between the SDKs has to surface as a different
    /// line. The reason strings and the hashes are the SDK's own, not the example's.
    /// </summary>
    private static readonly string[] ExpectedLines =
    [
        // 1. Every table a query reads is checked; a construct the check cannot resolve is refused.
        "  join an allowed table    ALLOW   the source ran",
        "  join a hidden table      DENY    object is hidden",
        "  comma join               DENY    object is hidden",
        "  derived table            DENY    object is hidden",
        "  subquery in WHERE        DENY    query uses a construct the pre-execution check cannot resolve: subquery",
        "  hidden field via alias   DENY    query references fields you do not have permission to access",
        "  other object's column    DENY    query references fields you do not have permission to access",
        "  bare column in a join    DENY    query references fields you do not have permission to access",
        // 2. The qualified filter reads patients.region only; encounters.name is projected out.
        "    patients.id=2  patients.name=Bruno Sato  patients.region=us-east  encounters.code=I10",
        "  name from patients       ALLOW",
        "  name from encounters     DENY    denied fields: name",
        "  code from encounters     ALLOW",
        // 3. Hashed once, hashed twice, and a marker honoured, ignored or taken on trust.
        "  plain rows               the wrapper enforces",
        "    id=1  name=Alice Nguyen  email=06c3aada7ffedc44  region=us-east",
        "  enforced, unmarked       hashed twice",
        "    id=1  name=Alice Nguyen  email=60d6b623948861a8  region=us-east",
        "  enforced, marked         marker honoured",
        "  marked for another user  marker ignored",
        "  marked, not enforced     a false claim",
        "    id=1  name=Alice Nguyen  email=alice@example.com  region=us-east",
    ];

    /// <summary>What one enforcement of PatientRows returns: Dan's eu-west row filtered, ssn hidden, email hashed.</summary>
    private static Dictionary<string, object?> HashedOnce(string email) => new()
    {
        ["id"] = 1, ["name"] = "Alice Nguyen", ["email"] = email, ["region"] = "us-east",
    };

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    public async Task ARefusedQuery_NeverReachesTheSource(int index)
    {
        var outcome = await QuerySafetyExample.RunQueryAsync(
            QuerySafetyExample.SignedContext(), QuerySafetyExample.Queries[index].Sql);

        outcome.Reason.Should().NotBeNull();
        outcome.Reached.Should().BeFalse();
    }

    [Fact]
    public async Task TheAllowedJoin_ReachesTheSource()
    {
        // Paired allow: the refusals above are the policy, not a check that refuses every join.
        var outcome = await QuerySafetyExample.RunQueryAsync(
            QuerySafetyExample.SignedContext(), QuerySafetyExample.Queries[0].Sql);

        outcome.Reason.Should().BeNull();
        outcome.Reached.Should().BeTrue();
    }

    [Fact]
    public void AQualifiedRowFilter_ReadsOnlyItsOwnObject()
    {
        var rows = QuerySafetyExample.Wrapper().PostExecute(
            QuerySafetyExample.SignedContext(), QuerySafetyExample.JoinRows());

        // Alice's encounters.region is us-east; only her patients.region may decide.
        rows.Should().BeEquivalentTo(new List<Dictionary<string, object?>>
        {
            new()
            {
                ["patients.id"] = 2,
                ["patients.name"] = "Bruno Sato",
                ["patients.region"] = "us-east",
                ["encounters.code"] = "I10",
            },
        });
    }

    [Theory]
    [InlineData("patients", "name", true)]
    [InlineData("encounters", "name", false)]
    [InlineData("encounters", "code", true)]
    public void TheFieldPreCheck_ReadsTheQualifier(string objectName, string field, bool allowed)
    {
        var decision = QuerySafetyExample.Wrapper().PreExecute(
            QuerySafetyExample.SignedContext(),
            new PreExecuteArgs("query_patients", ObjectName: objectName, Fields: [field]));

        decision.Allowed.Should().Be(allowed);
    }

    [Theory]
    [InlineData("plain rows", "06c3aada7ffedc44")]
    [InlineData("enforced, unmarked", "60d6b623948861a8")]
    [InlineData("enforced, marked", "06c3aada7ffedc44")]
    [InlineData("marked for another user", "06c3aada7ffedc44")]
    [InlineData("marked, not enforced", "alice@example.com")]
    public async Task AMarker_IsHonouredOnlyWhenBoundToThisContext(string label, string expectedEmail)
    {
        var tool = QuerySafetyExample.Tools.Single(t => t.Label == label);

        var rows = await QuerySafetyExample.CallToolAsync(QuerySafetyExample.SignedContext(), tool);

        // Hidden-field removal and the row filter run whether or not the marker is honoured.
        rows.Should().BeEquivalentTo(new List<Dictionary<string, object?>> { HashedOnce(expectedEmail) });
    }

    [Fact]
    public async Task TheExampleRunsClean_AndPrintsTheLinesTheOtherTwoLanguagesPrint()
    {
        // RunExampleAsync throws if a refused query reached the source, if a column the policy does
        // not allow came back, or if ssn leaked, so this covers those paths too.
        var original = Console.Out;
        var captured = new StringWriter();
        try
        {
            Console.SetOut(captured);
            await QuerySafetyExample.RunExampleAsync();
        }
        finally
        {
            Console.SetOut(original);
        }

        var lines = captured.ToString().Split(Environment.NewLine);

        foreach (var expected in ExpectedLines)
            lines.Should().Contain(expected);
        // The honoured marker and the ignored one both match the wrapper's own enforcement.
        lines.Count(l => l == "    id=1  name=Alice Nguyen  email=06c3aada7ffedc44  region=us-east").Should().Be(3);
        // The only ssn values printed are the two raw join rows shown before enforcement.
        lines.Count(l => l.Contains("ssn=")).Should().Be(2);
        captured.ToString().Should().NotContain("444-55-6666");
    }
}
