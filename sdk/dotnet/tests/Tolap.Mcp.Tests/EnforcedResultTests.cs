using System.Text.Json;
using System.Text.Json.Nodes;
using FluentAssertions;
using Tolap.Core;
using Tolap.Store;
using Xunit;

namespace Tolap.Mcp.Tests;

/// <summary>
/// A tool can declare its result already enforced (issue #33).
/// </summary>
/// <remarks>
/// <c>hash</c> masking is not idempotent: when a data layer has already run the result
/// pipeline, running it again in <c>ExecuteWithEnforcementAsync</c> hashes every hashed
/// field a second time. A tool opts out by returning <see cref="EnforcedResult{T}"/>,
/// bound to the signed context's signature. Only <c>ExecuteWithEnforcementAsync</c>
/// honours the marker, and only on an exact, constant-time match. It still re-applies the
/// steps that are no-ops over enforced output: filters on visible fields, the
/// hidden-field strip, the allowed-field projection and maxResults. Every other marker,
/// and every marker on another path, falls back to the full pipeline. The shared cases in
/// <c>fixtures/enforcement/already-enforced-results.json</c> hold the Python and
/// TypeScript SDKs to the same results.
/// </remarks>
public class EnforcedResultTests
{
    private const string Placeholder = "$CONTEXT_SIGNATURE";
    private static readonly JsonElement Fixture = LoadFixture();
    private static readonly string Key = Fixture.GetProperty("signingKey").GetString()!;
    private static readonly JsonElement PolicyA =
        Fixture.GetProperty("cases")[0].GetProperty("policy");

    // -- fixture plumbing -------------------------------------------------------

    private static JsonElement LoadFixture()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(
                directory.FullName, "fixtures", "enforcement", "already-enforced-results.json");
            if (File.Exists(candidate))
                return JsonDocument.Parse(File.ReadAllText(candidate)).RootElement.Clone();
            directory = directory.Parent;
        }
        throw new FileNotFoundException(
            "fixtures/enforcement/already-enforced-results.json not found above "
            + AppContext.BaseDirectory);
    }

    private static (string UserId, string TenantId) Who(string property)
    {
        var who = Fixture.GetProperty(property);
        return (who.GetProperty("userId").GetString()!, who.GetProperty("tenantId").GetString()!);
    }

    private static EffectivePolicy ToPolicy(JsonNode partial, (string UserId, string TenantId) who)
    {
        var node = partial.DeepClone().AsObject();
        node["userId"] = who.UserId;
        node["tenantId"] = who.TenantId;
        node["sourceConnectionId"] = "test-source";
        node["resolvedAt"] = DateTimeOffset.UtcNow.ToString("O");
        node["expiresAt"] = DateTimeOffset.UtcNow.AddHours(1).ToString("O");
        node["sourceProfiles"] = new JsonArray();
        return TolapJsonOptions.Deserialize<EffectivePolicy>(node.ToJsonString());
    }

    private static SecurityContext MakeContext(
        JsonNode partial, string who = "context", string? jti = null)
    {
        var identity = Who(who);
        var context = SecurityContextBuilder.Build(
            identity.UserId, identity.TenantId, new[] { ToPolicy(partial, identity) }, jti: jti);
        return SecurityContextSigner.Sign(context, Key);
    }

    private static SecurityContext MakeContext(
        JsonElement partial, string who = "context", string? jti = null)
        => MakeContext(JsonNode.Parse(partial.GetRawText())!, who, jti);

    private static string Signature(SecurityContext context) => context.Integrity!.Signature;

    private static string Tampered(string signature)
        => signature[..^1] + (signature.EndsWith('0') ? "1" : "0");

    /// <summary>A JSON element as the dictionary/list/primitive tree a tool returns.</summary>
    private static object? ToTree(JsonElement element, string signature) => element.ValueKind switch
    {
        JsonValueKind.Object => element.EnumerateObject()
            .ToDictionary(p => p.Name, p => ToTree(p.Value, signature)),
        JsonValueKind.Array => element.GetArrayLength() == 0
                               || element.EnumerateArray().All(e => e.ValueKind == JsonValueKind.Object)
            ? element.EnumerateArray()
                .Select(e => (Dictionary<string, object?>)ToTree(e, signature)!)
                .ToList()
            : element.EnumerateArray().Select(e => ToTree(e, signature)).ToList<object?>(),
        JsonValueKind.String => element.GetString() == Placeholder ? signature : element.GetString(),
        JsonValueKind.Number => element.TryGetInt64(out var l) ? l : element.GetDouble(),
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        _ => null,
    };

    private static object? ToolResult(JsonElement testCase, SecurityContext context)
    {
        var data = ToTree(testCase.GetProperty("data"), Signature(context));
        var marker = testCase.GetProperty("marker");
        if (marker.ValueKind == JsonValueKind.Null)
            return data;

        switch (marker.GetString())
        {
            case "context":
                return EnforcedResult.For(data, context);
            case "otherContext":
                var other = MakeContext(testCase.GetProperty("policy"), "otherContext");
                Signature(other).Should().NotBe(Signature(context));
                return EnforcedResult.For(data, other);
            case "tampered":
                return new EnforcedResult<object?>(data, Tampered(Signature(context)));
            case "empty":
                return new EnforcedResult<object?>(data, "");
            default:
                throw new InvalidOperationException($"unknown marker {marker}");
        }
    }

    private static SecureContextToolWrapper Wrapper(
        bool enforceSignatures = true,
        bool allowUnenforceableShapes = false,
        ToolCallHistory? history = null)
        => new(new SecureContextWrapperOptions(
            Key,
            EnforceSignatures: enforceSignatures,
            AllowUnenforceableShapes: allowUnenforceableShapes,
            ToolCallHistory: history));

    private static Task<object?> Run(
        SecureContextToolWrapper wrapper, SecurityContext context, object? result)
        => wrapper.ExecuteWithEnforcementAsync(
            context, new PreExecuteArgs("orm-query"), () => Task.FromResult(result));

    private static JsonNode? AsJson(object? value)
        => JsonNode.Parse(JsonSerializer.Serialize(value));

    private static void ShouldMatch(object? actual, object? expected)
        => JsonNode.DeepEquals(AsJson(actual), AsJson(expected)).Should().BeTrue(
            $"expected {AsJson(expected)?.ToJsonString() ?? "null"}, "
            + $"got {AsJson(actual)?.ToJsonString() ?? "null"}");

    /// <summary>The pipeline applied once, as a data layer would have.</summary>
    private static List<Dictionary<string, object?>> EnforcedOnce(
        SecurityContext context, List<Dictionary<string, object?>> rows)
        => ((IReadOnlyList<Dictionary<string, object?>>)EnforcementEngine.ApplyResultPipeline(
            rows, context.Policies[0])!).ToList();

    private static object? FullPipeline(SecurityContext context, object? data)
        => EnforcementEngine.ApplyResultPipeline(data, context.Policies[0]);

    private static List<Dictionary<string, object?>> Raw() =>
    [
        new() { ["id"] = 1L, ["region"] = "us-east", ["email"] = "a@example.com" },
    ];

    // -- shared fixture ---------------------------------------------------------

    public static TheoryData<string> CaseNames()
    {
        var data = new TheoryData<string>();
        foreach (var testCase in Fixture.GetProperty("cases").EnumerateArray())
            data.Add(testCase.GetProperty("name").GetString()!);
        return data;
    }

    [Theory]
    [MemberData(nameof(CaseNames))]
    public async Task SharedFixture(string name)
    {
        var testCase = Fixture.GetProperty("cases").EnumerateArray()
            .Single(c => c.GetProperty("name").GetString() == name);
        var context = MakeContext(testCase.GetProperty("policy"));
        var result = ToolResult(testCase, context);

        if (testCase.TryGetProperty("expectDenied", out var denied) && denied.GetBoolean())
        {
            var act = () => Run(Wrapper(), context, result);
            await act.Should().ThrowAsync<UnauthorizedAccessException>();
            return;
        }

        var actual = await Run(Wrapper(), context, result);

        JsonNode.DeepEquals(AsJson(actual), JsonNode.Parse(testCase.GetProperty("expected").GetRawText()))
            .Should().BeTrue($"case '{name}' returned {AsJson(actual)?.ToJsonString() ?? "null"}");
    }

    // -- the marker is bound to the exact context -------------------------------

    [Fact]
    public async Task AMatchingMarkerIsNotHashedTwice()
    {
        var context = MakeContext(PolicyA);
        var once = EnforcedOnce(context, Raw());

        ShouldMatch(await Run(Wrapper(), context, EnforcedResult.For(once, context)), once);
    }

    [Fact]
    public async Task AMarkerFromAContextWithTheSamePolicyButAnotherJtiIsNotHonoured()
    {
        var context = MakeContext(PolicyA, jti: "call-1");
        var replayedFrom = MakeContext(PolicyA, jti: "call-0");
        var once = EnforcedOnce(context, Raw());

        var output = await Run(Wrapper(), context, EnforcedResult.For(once, replayedFrom));

        ShouldMatch(output, FullPipeline(context, once));
        JsonNode.DeepEquals(AsJson(output), AsJson(once)).Should().BeFalse();
    }

    [Fact]
    public async Task AMarkerIsNotHonouredWhenSignaturesAreNotEnforced()
    {
        // Without verification the signature field is whatever the sender wrote, so
        // matching it proves nothing.
        var context = MakeContext(PolicyA);
        var once = EnforcedOnce(context, Raw());

        var output = await Run(
            Wrapper(enforceSignatures: false), context, EnforcedResult.For(once, context));

        ShouldMatch(output, FullPipeline(context, once));
    }

    [Fact]
    public void AContextWhoseSignatureDoesNotVerifyNeverHonoursAMarker()
    {
        // A forged context plus a marker copying its forged signature must not skip
        // anything, whichever path it reaches.
        var context = MakeContext(PolicyA);
        var forged = context with
        {
            Integrity = context.Integrity! with { Signature = Tampered(Signature(context)) },
        };
        var once = EnforcedOnce(context, Raw());

        var output = Wrapper().PostExecuteResult(forged, EnforcedResult.For(once, forged));

        ShouldMatch(output, FullPipeline(context, once));
    }

    // -- only ExecuteWithEnforcementAsync honours a marker ----------------------

    private static JsonNode WritePolicy()
    {
        var node = JsonNode.Parse(PolicyA.GetRawText())!;
        node["permissions"] = new JsonObject
        {
            ["canQuery"] = true,
            ["canInsert"] = true,
            ["readOnly"] = false,
        };
        return node;
    }

    [Fact]
    public async Task ExecuteWithEnforcementHonoursAMarker()
    {
        var context = MakeContext(PolicyA);
        var once = EnforcedOnce(context, Raw());

        ShouldMatch(await Run(Wrapper(), context, EnforcedResult.For(once, context)), once);
    }

    [Fact]
    public void PostExecuteResultCalledDirectlyDoesNotHonourAMarker()
    {
        var context = MakeContext(PolicyA);
        var once = EnforcedOnce(context, Raw());

        var output = Wrapper().PostExecuteResult(context, EnforcedResult.For(once, context));

        ShouldMatch(output, FullPipeline(context, once));
        JsonNode.DeepEquals(AsJson(output), AsJson(once)).Should().BeFalse();
    }

    [Fact]
    public async Task TheWritePathDoesNotHonourAMarker()
    {
        var context = MakeContext(WritePolicy());
        var once = EnforcedOnce(context, Raw());

        var output = await Wrapper().ExecuteWriteWithEnforcementAsync(
            context,
            WriteOperation.Insert,
            () => Task.FromResult<object?>(EnforcedResult.For(once, context)),
            "patients",
            new Dictionary<string, object?> { ["region"] = "us-east" });

        ShouldMatch(output, FullPipeline(context, once));
        JsonNode.DeepEquals(AsJson(output), AsJson(once)).Should().BeFalse();
    }

    [Fact]
    public async Task TheSqlPathDoesNotHonourAMarker()
    {
        // The SQL path is typed to a list of records, so a marker can reach it only
        // inside a record. It is unwrapped there and its contents fully enforced.
        var context = MakeContext(PolicyA);
        var once = EnforcedOnce(context, Raw());
        IReadOnlyList<Dictionary<string, object?>> rows =
        [
            new() { ["id"] = 1L, ["region"] = "us-east", ["p"] = EnforcedResult.For(once, context) },
        ];

        var output = await Wrapper().ExecuteSqlWithEnforcementAsync(
            context,
            new PreExecuteArgs("sql-query"),
            "SELECT id, region, p FROM patients",
            _ => Task.FromResult(rows));

        ShouldMatch(
            output,
            FullPipeline(
                context,
                new List<Dictionary<string, object?>>
                {
                    new() { ["id"] = 1L, ["region"] = "us-east", ["p"] = once },
                }));
    }

    [Fact]
    public async Task TheSqlPathStillEnforcesAFilterOnAVisibleField()
    {
        // A record carrying a valid marker in one of its fields still fails the row
        // filter on its own visible field: the marker does not vouch for the record.
        var context = MakeContext(PolicyA);
        var once = EnforcedOnce(context, Raw());
        IReadOnlyList<Dictionary<string, object?>> rows =
        [
            new() { ["id"] = 2L, ["region"] = "eu-west", ["p"] = EnforcedResult.For(once, context) },
        ];

        var output = await Wrapper().ExecuteSqlWithEnforcementAsync(
            context,
            new PreExecuteArgs("sql-query"),
            "SELECT id, region, p FROM patients",
            _ => Task.FromResult(rows));

        output.Should().BeEmpty();
    }

    // -- an honoured marker still runs the filters on visible fields ------------

    [Fact]
    public async Task AnHonouredMarkerStillAppliesARowFilterOnAVisibleField()
    {
        var context = MakeContext(PolicyA);
        var rows = new List<Dictionary<string, object?>>
        {
            new() { ["id"] = 1L, ["region"] = "us-east", ["email"] = "h1" },
            new() { ["id"] = 2L, ["region"] = "eu-west", ["email"] = "h2" },
        };

        ShouldMatch(
            await Run(Wrapper(), context, EnforcedResult.For(rows, context)),
            new List<Dictionary<string, object?>> { rows[0] });
    }

    [Fact]
    public async Task AnHonouredMarkerSkipsARowFilterOnAMaskedField()
    {
        var policy = JsonNode.Parse("""
            {
              "version": "1.0",
              "permissions": { "canQuery": true },
              "objectRules": {
                "fieldRules": { "maskedFields": [{ "field": "email", "maskType": "hash" }] },
                "rowFilters": [{ "field": "email", "operator": "equals", "value": "a@example.com" }]
              }
            }
            """)!;
        var context = MakeContext(policy);
        var rows = new List<Dictionary<string, object?>> { new() { ["id"] = 1L, ["email"] = "already-hashed" } };

        ShouldMatch(await Run(Wrapper(), context, EnforcedResult.For(rows, context)), rows);
    }

    [Fact]
    public async Task AMarkerWithANullSignatureIsNotHonoured()
    {
        var context = MakeContext(PolicyA);
        var once = EnforcedOnce(context, Raw());

        var output = await Run(Wrapper(), context, new EnforcedResult<object?>(once, null!));

        ShouldMatch(output, FullPipeline(context, once));
    }

    [Fact]
    public async Task ASignatureDifferingOnlyPastTheAsciiRangeIsAMismatchNotACrash()
    {
        var context = MakeContext(PolicyA);
        var once = EnforcedOnce(context, Raw());

        var output = await Run(
            Wrapper(), context, new EnforcedResult<object?>(once, new string('é', 32)));

        ShouldMatch(output, FullPipeline(context, once));
    }

    [Fact]
    public async Task AContextReSignedWithANewJtiInvalidatesTheMarker()
    {
        var context = MakeContext(PolicyA);
        var once = EnforcedOnce(context, Raw());
        var marker = EnforcedResult.For(once, context);
        var resigned = SecurityContextSigner.Sign(context with { Jti = "rotated" }, Key);

        ShouldMatch(await Run(Wrapper(), resigned, marker), FullPipeline(context, once));
    }

    [Fact]
    public async Task AMismatchedMarkerIsLoggedWithoutTheSignatures()
    {
        using var listener = new CapturingTraceListener();
        var context = MakeContext(PolicyA);

        await Run(
            Wrapper(), context,
            new EnforcedResult<List<Dictionary<string, object?>>>([], "not-the-signature"));

        listener.Warnings.Should().Contain(w => w.Contains("EnforcedResult"));
        listener.Warnings.Should().NotContain(w => w.Contains(Signature(context)));
        listener.Warnings.Should().NotContain(w => w.Contains("not-the-signature"));
    }

    // -- only the marker type counts --------------------------------------------

    [Fact]
    public async Task ARecordShapedLikeTheMarkerIsData()
    {
        var context = MakeContext(PolicyA);
        var lookalike = new Dictionary<string, object?>
        {
            ["data"] = new List<Dictionary<string, object?>>
            {
                new() { ["id"] = 1L, ["region"] = "us-east", ["email"] = "raw@example.com" },
            },
            ["contextSignature"] = Signature(context),
            ["ContextSignature"] = Signature(context),
        };

        // No region field, so the region filter drops it: the raw email never returns.
        (await Run(Wrapper(), context, lookalike)).Should().BeNull();
    }

    [Fact]
    public void BindingToAnUnsignedContextIsRefused()
    {
        var unsigned = SecurityContextBuilder.Build(
            "u", "t", new[] { ToPolicy(JsonNode.Parse(PolicyA.GetRawText())!, ("u", "t")) });

        var act = () => EnforcedResult.For(new List<object?>(), unsigned);

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void TheMarkerDoesNotPrintItsData()
    {
        var context = MakeContext(PolicyA);
        var marker = EnforcedResult.For(
            new Dictionary<string, object?> { ["ssn"] = "123-45-6789" }, context);

        marker.ToString().Should().NotContain("123-45-6789");
    }

    // -- nested markers are never honoured --------------------------------------

    [Fact]
    public async Task AMarkerInsideAListIsUnwrappedAndFullyEnforced()
    {
        var context = MakeContext(PolicyA);
        var once = EnforcedOnce(context, Raw());

        var output = await Run(
            Wrapper(), context, new List<object?> { EnforcedResult.For(once[0], context) });

        ShouldMatch(output, FullPipeline(context, once));
    }

    [Fact]
    public async Task AMarkerInsideARecordFieldCannotSmuggleHiddenFields()
    {
        var context = MakeContext(PolicyA);
        var record = new Dictionary<string, object?>
        {
            ["region"] = "us-east",
            ["patient"] = EnforcedResult.For(
                new Dictionary<string, object?> { ["ssn"] = "123-45-6789", ["id"] = 7L }, context),
        };

        var output = await Run(Wrapper(), context, record);

        ShouldMatch(output, new Dictionary<string, object?>
        {
            ["region"] = "us-east",
            ["patient"] = new Dictionary<string, object?> { ["id"] = 7L },
        });
        JsonSerializer.Serialize(output).Should().NotContain("123-45-6789");
    }

    [Fact]
    public async Task AMarkerWrappingAMarkerIsFullyEnforced()
    {
        var context = MakeContext(PolicyA);
        var once = EnforcedOnce(context, Raw());
        var outer = EnforcedResult.For(EnforcedResult.For(once, context), context);

        ShouldMatch(await Run(Wrapper(), context, outer), FullPipeline(context, once));
    }

    [Fact]
    public async Task AnHonouredMarkerWithANestedMarkerInsideIsFullyEnforced()
    {
        var context = MakeContext(PolicyA);
        var once = EnforcedOnce(context, Raw());
        var outer = EnforcedResult.For(
            new List<object?> { once[0], EnforcedResult.For(once[0], context) }, context);

        ShouldMatch(
            await Run(Wrapper(), context, outer),
            FullPipeline(context, new List<Dictionary<string, object?>> { once[0], once[0] }));
    }

    [Fact]
    public void TheTypedPostExecuteUnwrapsMarkersInsideRecords()
    {
        var context = MakeContext(PolicyA);
        var rows = new List<Dictionary<string, object?>>
        {
            new()
            {
                ["region"] = "us-east",
                ["patient"] = EnforcedResult.For(
                    new Dictionary<string, object?> { ["ssn"] = "123-45-6789" }, context),
            },
        };

        var output = Wrapper().PostExecute(context, rows);

        JsonSerializer.Serialize(output).Should().NotContain("123-45-6789");
    }

    // -- every other post-execution step still runs -----------------------------

    [Fact]
    public async Task HistoryIsRecordedOnTheAsyncPathWhichDoesNotHonourAMarker()
    {
        var history = new ToolCallHistory(4);
        var wrapper = Wrapper(history: history);
        var context = MakeContext(PolicyA);
        var once = EnforcedOnce(context, Raw());

        var pre = await wrapper.PreExecuteAsync(context, new PreExecuteArgs("orm-query"));
        var output = wrapper.PostExecuteResult(context, EnforcedResult.For(once, context));

        pre.Allowed.Should().BeTrue();
        ShouldMatch(output, FullPipeline(context, once));
        history.Count.Should().Be(1);
    }

    [Fact]
    public async Task AMarkerDoesNotChangeWhatExecuteWithEnforcementRecords()
    {
        var marked = new ToolCallHistory(4);
        var unmarked = new ToolCallHistory(4);
        var context = MakeContext(PolicyA);
        var once = EnforcedOnce(context, Raw());

        await Run(Wrapper(history: marked), context, EnforcedResult.For(once, context));
        await Run(Wrapper(history: unmarked), context, once);

        marked.Count.Should().Be(unmarked.Count);
    }

    [Fact]
    public async Task MaxResultsTruncatesAnHonouredMarker()
    {
        var context = MakeContext(PolicyA);
        var rows = Enumerable.Range(0, 5)
            .Select(i => new Dictionary<string, object?> { ["id"] = (long)i, ["region"] = "us-east" })
            .ToList();

        ShouldMatch(
            await Run(Wrapper(), context, EnforcedResult.For(rows, context)),
            rows.Take(2).ToList());
    }

    [Fact]
    public async Task AllowedFieldsProjectsAnHonouredMarker()
    {
        var policy = JsonNode.Parse(PolicyA.GetRawText())!;
        policy["objectRules"]!["fieldRules"]!["allowedFields"] = new JsonArray("id");
        var context = MakeContext(policy);

        var output = await Run(
            Wrapper(), context,
            EnforcedResult.For(
                new List<Dictionary<string, object?>> { new() { ["id"] = 1L, ["internal"] = "x" } },
                context));

        ShouldMatch(output, new List<Dictionary<string, object?>> { new() { ["id"] = 1L } });
    }

    [Fact]
    public async Task APreExecutionDenialStillThrowsBeforeTheToolRuns()
    {
        var policy = JsonNode.Parse(PolicyA.GetRawText())!;
        policy["permissions"]!["canQuery"] = false;
        var context = MakeContext(policy);
        var called = false;

        var act = () => Wrapper().ExecuteWithEnforcementAsync(
            context, new PreExecuteArgs("orm-query"), () =>
            {
                called = true;
                return Task.FromResult<object?>(EnforcedResult.For(new List<object?>(), context));
            });

        await act.Should().ThrowAsync<UnauthorizedAccessException>().WithMessage("Access denied*");
        called.Should().BeFalse();
    }

    [Fact]
    public async Task AnUnenforceableShapeInsideAnHonouredMarkerIsDenied()
    {
        var context = MakeContext(PolicyA);

        var act = () => Run(Wrapper(), context, EnforcedResult.For("a scalar", context));

        await act.Should().ThrowAsync<UnenforceableResultException>();
    }

    [Fact]
    public async Task AnUnenforceableShapeInsideAnHonouredMarkerPassesWhenOptedOut()
    {
        using var listener = new CapturingTraceListener();
        var context = MakeContext(PolicyA);

        var output = await Run(
            Wrapper(allowUnenforceableShapes: true), context,
            EnforcedResult.For("a scalar", context));

        output.Should().Be("a scalar");
        listener.Warnings.Should().Contain(w => w.Contains("AllowUnenforceableShapes"));
    }

    [Fact]
    public async Task AnUnenforceableShapeInsideAnUnhonouredMarkerIsUnwrappedFirst()
    {
        // AllowUnenforceableShapes passes an unenforceable shape through whole. The marker
        // itself must not count as that shape, or its records would pass through unread.
        using var listener = new CapturingTraceListener();
        var context = MakeContext(PolicyA);
        var leaky = new EnforcedResult<List<Dictionary<string, object?>>>(
            [new() { ["id"] = 1L, ["region"] = "us-east", ["ssn"] = "123-45-6789" }], "any");

        var output = await Run(Wrapper(allowUnenforceableShapes: true), context, leaky);

        JsonSerializer.Serialize(output).Should().NotContain("123-45-6789");
    }

    [Fact]
    public async Task AnUnmarkedResultBehavesAsBefore()
    {
        var context = MakeContext(PolicyA);
        List<Dictionary<string, object?>> Rows() =>
        [
            new() { ["id"] = 1L, ["region"] = "us-east", ["email"] = "a@example.com", ["ssn"] = "1" },
            new() { ["id"] = 2L, ["region"] = "eu-west", ["email"] = "b@example.com" },
        ];

        ShouldMatch(await Run(Wrapper(), context, Rows()), FullPipeline(context, Rows()));
    }

    // -- the registry wrapper never honours a marker ----------------------------

    private static async Task<ToolExecutionResult> Registry(
        bool allowUnenforceableShapes, object? result)
    {
        var store = new InMemoryPolicyStore();
        await store.CreatePolicyAsync(new PolicyDefinition(
            Version: "1.0",
            Name: "orm-policy",
            Permissions: new PolicyPermissions(CanQuery: true, ReadOnly: true),
            Priority: 10,
            AppliesToAll: true,
            ObjectRules: new ObjectRules(
                FieldRules: new FieldRules(
                    HiddenFields: ["ssn"],
                    MaskedFields: [new MaskingRule("email", MaskType.Hash)]),
                RowFilters: [new RowFilter("region", FilterOperator.Equals, "us-east")]),
            Limits: new PolicyLimits(MaxResults: 2)));
        await store.AssignPolicyAsync(new PolicyAssignment(
            Version: "1.0",
            PolicyName: "orm-policy",
            Assignee: new Assignee(AssigneeType.User, "user-1"),
            Scope: new AssignmentScope(TenantId: "tenant-1"),
            Active: true,
            Audit: new AuditInfo("admin", DateTimeOffset.UtcNow, "Test")));

        var wrapper = new SecureMcpToolWrapper(new SecureMcpServerOptions(
            PolicyStore: store,
            IdentityResolver: new StaticIdentityResolver(),
            IdentityExtractor: new HeaderIdentityExtractor(),
            SigningKey: Key,
            AllowUnenforceableShapes: allowUnenforceableShapes));

        return await wrapper.ExecuteWithEnforcementAsync(
            new Dictionary<string, string>
            {
                ["X-Tolap-User-Id"] = "user-1",
                ["X-Tolap-Tenant-Id"] = "tenant-1",
            },
            "orm-query", "patients", "any-source",
            () => Task.FromResult(result));
    }

    [Fact]
    public async Task TheRegistryWrapperUnwrapsAndFullyEnforcesAMarker()
    {
        var context = MakeContext(PolicyA);
        var once = EnforcedOnce(context, Raw());

        var output = await Registry(false, EnforcedResult.For(once, context));

        output.Allowed.Should().BeTrue();
        ShouldMatch(output.Result, FullPipeline(context, once));
    }

    [Fact]
    public async Task TheRegistryWrapperDoesNotLetAllowUnenforceableShapesPassAMarkerWhole()
    {
        using var listener = new CapturingTraceListener();
        var leaky = new EnforcedResult<List<Dictionary<string, object?>>>(
            [new() { ["id"] = 1L, ["region"] = "us-east", ["email"] = "raw@example.com", ["ssn"] = "123-45-6789" }],
            "any");

        var output = await Registry(true, leaky);

        var json = JsonSerializer.Serialize(output.Result);
        json.Should().NotContain("123-45-6789");
        json.Should().NotContain("raw@example.com");
    }
}
