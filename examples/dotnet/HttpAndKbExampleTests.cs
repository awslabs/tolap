using FluentAssertions;
using Tolap.Core;
using Xunit;

namespace Tolap.Examples;

/// <summary>
/// Asserts the HTTP and KB example enforces, not merely that it prints.
/// </summary>
/// <remarks>
/// The expected lines are byte-identical to <c>examples/python/test_http_and_kb.py</c> and
/// <c>examples/typescript/http-and-kb.test.ts</c>. The reason strings are the SDK's own, so a
/// divergence between the SDKs surfaces as a different line.
/// </remarks>
[Collection(ConsoleCapture.Name)]
public class HttpAndKbExampleTests
{
    private static readonly string[] ExpectedLines =
    [
        // sourcePatterns: the same identity, a different policy per source, deny-all for neither.
        "  api:clinical:patients     patients-api-reader   canQuery=true",
        "  kb:clinical:guidelines    clinical-kb-reader    canQuery=true",
        "  api:research:patients     (none)                canQuery=false",
        // endpointRules, checked before the request is sent.
        "  GET /patients           ALLOW",
        "  GET /patients/1/notes   DENY    endpoint is hidden",
        "  GET /billing/invoices   DENY    endpoint not in allowed set",
        "  DELETE /patients/1      DENY    method not allowed",
        "  POST /patients          DENY    insert not permitted",
        "The fake API was reached 1 time. The four refused requests never",
        // The row, field and limit rules, still applied to the JSON response.
        "    id=1  name=Alice Nguyen  region=us-east  dob=[REDACTED]",
        "    id=2  name=Bruno Sato  region=us-east  dob=[REDACTED]",
        // The unmatched source is deny-all.
        "  GET /patients           DENY    query not permitted",
        // tagRules, pushed down to the provider.
        "    tags notIn [restricted]",
        "    tags in [clinical, public]",
        "    {\"andAll\":[{\"notIn\":{\"key\":\"tags\",\"value\":[\"restricted\"]}},{\"in\":{\"key\":\"tags\",\"value\":[\"clinical\",\"public\"]}}]}",
        "Unpushed rules: none",
        "The provider returned 4 of 6: doc-1, doc-3, doc-5, doc-6",
        // And re-applied, with minSimilarityScore, in the post pass.
        "  doc-1  KEEP",
        "  doc-3  DROP  score 0.42 is below minSimilarityScore 0.5",
        "  doc-5  DROP  classification restricted, a key the provider never saw",
        "  doc-6  KEEP",
    ];

    [Theory]
    [InlineData("GET", "/patients/1/notes", "endpoint is hidden")]
    [InlineData("GET", "/billing/invoices", "endpoint not in allowed set")]
    [InlineData("DELETE", "/patients/1", "method not allowed")]
    [InlineData("POST", "/patients", "insert not permitted")]
    public async Task ARefusedRequest_NeverReachesTheApi(string method, string path, string reason)
    {
        var api = new HttpAndKbExample.FakeApi();

        var call = await HttpAndKbExample.CallApiAsync(
            api, HttpAndKbExample.SignedContext(HttpAndKbExample.ApiSource), method, path);

        call.Allowed.Should().BeFalse();
        call.Reason.Should().Be(reason);
        api.Hits.Should().BeEmpty();
    }

    [Fact]
    public async Task APermittedRequest_StillMeetsTheRowFieldAndLimitRules()
    {
        var api = new HttpAndKbExample.FakeApi();

        var call = await HttpAndKbExample.CallApiAsync(
            api, HttpAndKbExample.SignedContext(HttpAndKbExample.ApiSource), "GET", "/patients");

        call.Allowed.Should().BeTrue();
        api.Hits.Should().Equal("GET /patients");
        call.Rows!.Select(r => r["name"]).Should().Equal("Alice Nguyen", "Bruno Sato");
        call.Rows.Should().OnlyContain(r => !r.ContainsKey("ssn") && (string?)r["dob"] == "[REDACTED]");
    }

    [Fact]
    public async Task AnUnmatchedSource_ResolvesToDenyAll()
    {
        var policy = HttpAndKbExample.ResolveFor(HttpAndKbExample.UnmatchedSource);
        policy.SourceProfiles.Should().BeEmpty();
        policy.Permissions.CanQuery.Should().BeFalse();

        var api = new HttpAndKbExample.FakeApi();
        var call = await HttpAndKbExample.CallApiAsync(
            api, HttpAndKbExample.SignedContext(HttpAndKbExample.UnmatchedSource), "GET", "/patients");

        call.Allowed.Should().BeFalse();
        call.Reason.Should().Be("query not permitted");
        api.Hits.Should().BeEmpty();
    }

    [Fact]
    public void TheKbFilter_IsBuiltFromTheResolvedTagRules()
    {
        var filter = KbFilter.Build(HttpAndKbExample.ResolveFor(HttpAndKbExample.KbSource), ["tags"]);

        filter.Clauses.Select(c => (c.Key, c.Op, string.Join(",", c.Values))).Should().Equal(
            ("tags", KbFilterOp.NotIn, "restricted"),
            ("tags", KbFilterOp.In, "clinical,public"));
        HttpAndKbExample.FakeKbRetrieve(filter.Clauses).Select(r => r["id"])
            .Should().Equal("doc-1", "doc-3", "doc-5", "doc-6");
    }

    [Fact]
    public async Task TheExampleRunsClean_AndPrintsTheLinesTheOtherTwoLanguagesPrint()
    {
        // RunExampleAsync throws if a refused request reached the API, if ssn leaks, if the
        // unmatched source is served, or if the post pass drops other chunks, so this covers those.
        var original = Console.Out;
        var captured = new StringWriter();
        try
        {
            Console.SetOut(captured);
            await HttpAndKbExample.RunExampleAsync();
        }
        finally
        {
            Console.SetOut(original);
        }

        var lines = captured.ToString().Split(Environment.NewLine);

        foreach (var expected in ExpectedLines)
            lines.Should().Contain(expected);
        captured.ToString().Should().NotContain("111-22-3333");
    }
}
