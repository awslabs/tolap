using System.Text.Json;
using System.Text.Json.Nodes;
using FluentAssertions;
using Tolap.Core;
using Tolap.Store;
using Xunit;

namespace Tolap.Mcp.Tests;

/// <summary>
/// objectRules.toolRules on the MCP wrappers (canonical spec section 16).
/// </summary>
/// <remarks>
/// Driven from <c>fixtures/enforcement/tool-gate-wrapper.json</c> so all three SDKs agree on
/// order and filtering. There is no option to set: the policy alone decides. The tamper,
/// judge, history, factory, store-wrapper and concurrency cases are hand-written because they
/// are about signing, wiring and state, which a table can't say.
/// </remarks>
public class ToolGateWrapperTests
{
    private const string Key = "tool-gate-key";
    private const string WrongKey = "tolap-fixture-wrong-key-000000000000";
    private const string Model = "tool-gate-model";

    // =======================================================================
    // Fixture plumbing
    // =======================================================================

    private static readonly JsonElement FixtureRoot = LoadFixture();

    private static JsonElement LoadFixture()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "fixtures", "enforcement")))
            dir = dir.Parent;
        if (dir is null) throw new FileNotFoundException("fixtures/enforcement not found above the test output");
        var path = Path.Combine(dir.FullName, "fixtures", "enforcement", "tool-gate-wrapper.json");
        return JsonDocument.Parse(File.ReadAllText(path)).RootElement.Clone();
    }

    /// <summary>
    /// The fixture's policy fragment, completed with the envelope fields every effective
    /// policy carries, deserialized through the SDK's own converters.
    /// </summary>
    private static EffectivePolicy PolicyFrom(JsonElement fragment, string sourceConnectionId = "api:tool:test")
    {
        var node = JsonNode.Parse(fragment.GetRawText())!.AsObject();
        var now = DateTimeOffset.UtcNow;
        node["version"] = "1.0";
        node["userId"] = "tool-user";
        node["tenantId"] = "tool-tenant";
        node["sourceConnectionId"] = sourceConnectionId;
        node["resolvedAt"] = now.ToString("O");
        node["expiresAt"] = now.AddHours(1).ToString("O");
        node["sourceProfiles"] = new JsonArray("tool-gate");
        return TolapJsonOptions.Deserialize<EffectivePolicy>(node.ToJsonString());
    }

    private static EffectivePolicy PolicyFrom(string fragmentJson, string sourceConnectionId = "api:tool:test") =>
        PolicyFrom(JsonDocument.Parse(fragmentJson).RootElement, sourceConnectionId);

    private static SecurityContext Signed(EffectivePolicy policy, string? contextOverride = null) =>
        SecurityContextSigner.Sign(
            SecurityContextBuilder.Build(
                "tool-user", "tool-tenant", new[] { policy },
                ttl: contextOverride == "expired" ? TimeSpan.FromHours(-1) : null,
                declaredPurpose: policy.PurposeProfile?.PurposeId),
            contextOverride == "wrongKey" ? WrongKey : Key);

    private static string? Override(JsonElement c) =>
        c.TryGetProperty("contextOverride", out var o) ? o.GetString() : null;

    private static SecureContextToolWrapper Wrapper(JsonElement c)
    {
        var staticTools = c.GetProperty("staticAllowedTools").EnumerateArray()
            .Select(e => e.GetString()!).ToArray();
        Dictionary<string, string>? categories = null;
        if (c.TryGetProperty("toolActionCategories", out var cats))
            categories = cats.EnumerateObject().ToDictionary(p => p.Name, p => p.Value.GetString()!);
        return new SecureContextToolWrapper(new SecureContextWrapperOptions(
            SigningKey: Key,
            AllowedTools: staticTools,
            ToolActionCategories: categories));
    }

    private static PreExecuteArgs ArgsFrom(JsonElement c) => new(
        c.GetProperty("toolName").GetString()!,
        ObjectName: c.TryGetProperty("object", out var o) ? o.GetString() : null,
        Fields: c.TryGetProperty("fields", out var f)
            ? f.EnumerateArray().Select(e => e.GetString()!).ToArray()
            : null);

    public static TheoryData<string> Cases() => Names("cases");
    public static TheoryData<string> FilterCases() => Names("filterCases");
    public static TheoryData<string> WriteCases() => Names("writeCases");

    private static TheoryData<string> Names(string key)
    {
        var data = new TheoryData<string>();
        foreach (var c in FixtureRoot.GetProperty(key).EnumerateArray())
            data.Add(c.GetProperty("name").GetString()!);
        return data;
    }

    private static JsonElement Case(string key, string name) =>
        FixtureRoot.GetProperty(key).EnumerateArray()
            .Single(c => c.GetProperty("name").GetString() == name);

    private static string[] Strings(JsonElement array) =>
        array.EnumerateArray().Select(e => e.GetString()!).ToArray();

    // =======================================================================
    // B1-B11, and the named rows: PreExecute over the shared fixture
    // =======================================================================

    [Theory]
    [MemberData(nameof(Cases))]
    public void PreExecute_MatchesTheSharedFixture(string name)
    {
        var c = Case("cases", name);
        var result = Wrapper(c).PreExecute(
            Signed(PolicyFrom(c.GetProperty("policy")), Override(c)), ArgsFrom(c));

        var expected = c.GetProperty("expected");
        result.Allowed.Should().Be(expected.GetProperty("allowed").GetBoolean());

        string? reason = null;
        if (expected.TryGetProperty("reason", out var r))
            reason = r.GetString();
        else if (expected.TryGetProperty("reasonFamily", out var fam))
            reason = FixtureRoot.GetProperty("reasonFamilies").GetProperty(fam.GetString()!)
                .GetProperty("dotnet").GetString();
        result.Reason.Should().Be(reason);
    }

    // =======================================================================
    // C1-C6, and the named rows: FilterTools over the shared fixture
    // =======================================================================

    [Theory]
    [MemberData(nameof(FilterCases))]
    public void FilterTools_MatchesTheSharedFixture(string name)
    {
        var c = Case("filterCases", name);
        Wrapper(c)
            .FilterTools(Signed(PolicyFrom(c.GetProperty("policy")), Override(c)), Strings(c.GetProperty("toolNames")))
            .Should().Equal(Strings(c.GetProperty("expected")));
    }

    // =======================================================================
    // W1-W12: PreWrite over the shared fixture
    // =======================================================================

    private static WriteOperation OperationFrom(JsonElement c) =>
        Enum.Parse<WriteOperation>(c.GetProperty("operation").GetString()!, ignoreCase: true);

    private static IReadOnlyDictionary<string, object?>? PayloadFrom(JsonElement c) =>
        c.TryGetProperty("payload", out var p)
            ? p.EnumerateObject().ToDictionary(e => e.Name, e => (object?)e.Value.GetString())
            : null;

    private static string? ExpectedReason(JsonElement expected)
    {
        if (expected.TryGetProperty("reason", out var r)) return r.GetString();
        if (expected.TryGetProperty("reasonFamily", out var fam))
            return FixtureRoot.GetProperty("reasonFamilies").GetProperty(fam.GetString()!)
                .GetProperty("dotnet").GetString();
        return null;
    }

    [Theory]
    [MemberData(nameof(WriteCases))]
    public void PreWrite_MatchesTheSharedFixture(string name)
    {
        var c = Case("writeCases", name);
        var ctx = Signed(PolicyFrom(c.GetProperty("policy")), Override(c));
        var obj = c.TryGetProperty("object", out var o) ? o.GetString() : null;
        // A row with no toolName key calls the overload compiled callers already bind to.
        var result = c.TryGetProperty("toolName", out var t)
            ? Wrapper(c).PreWrite(ctx, OperationFrom(c), obj, PayloadFrom(c), options: null, toolName: t.GetString())
            : Wrapper(c).PreWrite(ctx, OperationFrom(c), obj, PayloadFrom(c), null);

        var expected = c.GetProperty("expected");
        result.Allowed.Should().Be(expected.GetProperty("allowed").GetBoolean());
        result.Reason.Should().Be(ExpectedReason(expected));
    }

    [Theory]
    [MemberData(nameof(WriteCases))]
    public async Task ExecuteWriteWithEnforcement_MatchesTheSharedFixture(string name)
    {
        // The helper must thread the tool name through: a denied row never reaches the write.
        var c = Case("writeCases", name);
        var ctx = Signed(PolicyFrom(c.GetProperty("policy")), Override(c));
        var obj = c.TryGetProperty("object", out var o) ? o.GetString() : null;
        var calls = 0;
        Func<Task<object?>> writeFn = () => { calls++; return Task.FromResult<object?>(null); };
        Func<Task<object?>> run = c.TryGetProperty("toolName", out var t)
            ? () => Wrapper(c).ExecuteWriteWithEnforcementAsync(
                ctx, OperationFrom(c), writeFn, obj, PayloadFrom(c), toolName: t.GetString())
            : () => Wrapper(c).ExecuteWriteWithEnforcementAsync(
                ctx, OperationFrom(c), writeFn, obj, PayloadFrom(c));

        var expected = c.GetProperty("expected");
        if (expected.GetProperty("allowed").GetBoolean())
        {
            (await run()).Should().BeNull();
            calls.Should().Be(1);
        }
        else
        {
            (await run.Should().ThrowAsync<UnauthorizedAccessException>())
                .WithMessage($"Access denied: {ExpectedReason(expected)}");
            calls.Should().Be(0);
        }
    }

    private const string WriteOnlyHiddenJson =
        "{\"permissions\":{\"canQuery\":false,\"canInsert\":true,\"readOnly\":false},\"objectRules\":{\"toolRules\":{\"hiddenTools\":[\"delete_patient\"]}}}";

    private static readonly IReadOnlyDictionary<string, object?> NoteBody =
        new Dictionary<string, object?> { ["body"] = "x" };

    [Fact]
    public void PreWrite_TheWriteDenialMatchesTheReadDenialExactly()
    {
        var ctx = Signed(PolicyFrom(
            "{\"permissions\":{\"canQuery\":true,\"canInsert\":true,\"readOnly\":false},\"objectRules\":{\"toolRules\":{\"allowedTools\":[\"write_note\"],\"hiddenTools\":[\"delete_patient\"]}}}"));
        foreach (var n in new[] { "delete_patient", "DELETE_patient", "export_csv", "bad name", "\u212Aill" })
        {
            var read = Plain().PreExecute(ctx, new PreExecuteArgs(n));
            var write = Plain().PreWrite(ctx, WriteOperation.Insert, "notes", NoteBody, toolName: n);
            read.Allowed.Should().BeFalse(n);
            write.Should().Be(read, n);
        }
    }

    [Fact]
    public void PreWrite_AnEmptyStringNameIsGatedNotTreatedAsOmitted()
    {
        Plain().PreWrite(Signed(PolicyFrom(WriteOnlyHiddenJson)), WriteOperation.Insert, "notes", NoteBody, toolName: "")
            .Should().Be(new AccessResult(false, "invalid tool name"));
    }

    [Fact]
    public void PreWrite_ATamperedContextIsRefusedBeforeTheToolGate()
    {
        var ctx = Signed(PolicyFrom(WriteOnlyHiddenJson));
        var p = ctx.Policies[0];
        var tampered = WithPolicy(ctx, p with
        {
            ObjectRules = p.ObjectRules! with { ToolRules = new ToolRules(HiddenTools: Array.Empty<string>()) },
        });
        Plain().PreWrite(tampered, WriteOperation.Insert, "notes", NoteBody, toolName: "delete_patient")
            .Should().Be(new AccessResult(false, "invalid signature"));
    }

    [Fact]
    public void PreWrite_TheOriginalFiveParameterOverloadStillExistsForBinaryCompatibility()
    {
        // Assemblies compiled before the tool-name parameter bind to this exact signature.
        var m = typeof(SecureContextToolWrapper).GetMethod(nameof(SecureContextToolWrapper.PreWrite), new[]
        {
            typeof(SecurityContext), typeof(WriteOperation), typeof(string),
            typeof(IReadOnlyDictionary<string, object?>), typeof(WriteValidationOptions),
        });
        m.Should().NotBeNull();
        m!.ReturnType.Should().Be(typeof(AccessResult));
        var e = typeof(SecureContextToolWrapper).GetMethod(nameof(SecureContextToolWrapper.ExecuteWriteWithEnforcementAsync), new[]
        {
            typeof(SecurityContext), typeof(WriteOperation), typeof(Func<Task<object?>>), typeof(string),
            typeof(IReadOnlyDictionary<string, object?>), typeof(WriteValidationOptions),
        });
        e.Should().NotBeNull();
        e!.ReturnType.Should().Be(typeof(Task<object?>));
        // And it applies no tool gate: the hidden tool cannot be named through it.
        Plain().PreWrite(Signed(PolicyFrom(WriteOnlyHiddenJson)), WriteOperation.Insert, "notes", NoteBody, null)
            .Allowed.Should().BeTrue();
    }

    // =======================================================================
    // M3: FilterTools drops null names, with or without tool rules
    // =======================================================================

    [Theory]
    [InlineData("{\"permissions\":{\"canQuery\":true}}")]
    [InlineData(HiddenExportJson)]
    public void FilterTools_DropsNullNames(string policyJson)
    {
        var names = new string?[] { null, "query_patients", null, "count_patients" };
        Plain().FilterTools(Signed(PolicyFrom(policyJson)), names!)
            .Should().Equal("query_patients", "count_patients");
    }

    [Fact]
    public void TheRunnerCoversEveryOwnedRow()
    {
        // A fixture edit that drops a row would otherwise just run fewer cases, silently.
        var caseNames = FixtureRoot.GetProperty("cases").EnumerateArray()
            .Select(c => c.GetProperty("name").GetString()).ToHashSet();
        var filterNames = FixtureRoot.GetProperty("filterCases").EnumerateArray()
            .Select(c => c.GetProperty("name").GetString()).ToHashSet();

        for (var i = 1; i <= 11; i++) caseNames.Should().Contain($"B{i}");
        for (var i = 1; i <= 6; i++) filterNames.Should().Contain($"C{i}");
        caseNames.Should().Contain(new[]
        {
            "no-tool-rules-unchanged", "hidden", "not-in-allowed-set", "allowed",
            "tools-only-policy", "static-list-wins-first", "static-empty-policy-empty",
            "static-and-policy-intersect", "tool-rules-before-can-query",
            "allowed-tool-still-needs-can-query", "kelvin-sign-invalid-name",
            "mis-cased-not-in-allowed-set",
        });
        filterNames.Should().Contain(new[]
        {
            "filter-tool-rules", "filter-no-tool-rules-lists-everything",
            "filter-static-list-applies", "filter-ignores-can-query",
            "filter-purpose-action-applies", "filter-no-tool-rules-no-grammar",
            "filter-mis-cased-dropped",
        });
        filterNames.Should().Contain(new[]
        {
            "filter-deny-all-lists-nothing", "filter-deny-all-explicit-false-lists-nothing",
            "filter-write-only-subject-to-tool-rules", "filter-update-only-lists",
            "filter-delete-only-lists",
        });
        var writeCases = FixtureRoot.GetProperty("writeCases").EnumerateArray().ToArray();
        var writePrefixes = writeCases.Select(c => c.GetProperty("name").GetString()!.Split('-')[0]).ToHashSet();
        for (var i = 1; i <= 12; i++) writePrefixes.Should().Contain($"W{i}");
        writeCases.Any(c => !c.TryGetProperty("toolName", out _)).Should().BeTrue();
        writeCases.Any(c => c.TryGetProperty("toolName", out _)).Should().BeTrue();
        FixtureRoot.GetProperty("cases").GetArrayLength().Should().Be(23);
        FixtureRoot.GetProperty("filterCases").GetArrayLength().Should().Be(18);
        FixtureRoot.GetProperty("writeCases").GetArrayLength().Should().Be(12);
    }

    [Fact]
    public void EveryOverrideTheRunnerReadsIsExercised()
    {
        // Pins that contextOverride, object, fields and toolActionCategories are each used, so
        // a runner that ignored one could not pass by the fixture never using it.
        var cases = FixtureRoot.GetProperty("cases").EnumerateArray().ToArray();
        var filters = FixtureRoot.GetProperty("filterCases").EnumerateArray().ToArray();
        var writes = FixtureRoot.GetProperty("writeCases").EnumerateArray().ToArray();
        var overrides = cases.Concat(filters).Concat(writes).Select(Override).ToHashSet();

        overrides.Should().Contain("expired").And.Contain("wrongKey");
        static bool Has(JsonElement c, string key) => c.TryGetProperty(key, out var _);
        cases.Any(c => Has(c, "object")).Should().BeTrue();
        cases.Any(c => Has(c, "fields")).Should().BeTrue();
        cases.Any(c => Has(c, "toolActionCategories")).Should().BeTrue();
        filters.Any(c => Has(c, "toolActionCategories")).Should().BeTrue();
        filters.Any(c => Override(c) == "expired").Should().BeTrue();
        filters.Any(c => Override(c) == "wrongKey").Should().BeTrue();
    }

    [Fact]
    public void EveryReasonFamilyResolvesToADotnetReason()
    {
        foreach (var c in FixtureRoot.GetProperty("cases").EnumerateArray())
        {
            if (!c.GetProperty("expected").TryGetProperty("reasonFamily", out var fam)) continue;
            FixtureRoot.GetProperty("reasonFamilies").GetProperty(fam.GetString()!)
                .GetProperty("dotnet").GetString().Should().NotBeNullOrEmpty();
        }
    }

    // =======================================================================
    // C10: FilterTools agrees with PreExecute over every filterCases row
    // =======================================================================

    [Theory]
    [MemberData(nameof(FilterCases))]
    public void C10_FilterToolsAgreesWithPreExecute(string name)
    {
        var c = Case("filterCases", name);
        var w = Wrapper(c);
        var ctx = Signed(PolicyFrom(c.GetProperty("policy")), Override(c));
        var names = Strings(c.GetProperty("toolNames"));
        var kept = w.FilterTools(ctx, names);

        foreach (var n in names)
        {
            var result = w.PreExecute(ctx, new PreExecuteArgs(n));
            if (kept.Contains(n))
            {
                // The only denial a kept name may still meet, with no call arguments, is the
                // read gate FilterTools deliberately does not apply -- never a tool-name reason.
                (result.Allowed || result.Reason == "query not permitted")
                    .Should().BeTrue($"'{n}' was listed but PreExecute said '{result.Reason}'");
            }
            else
            {
                result.Allowed.Should().BeFalse($"'{n}' was dropped but PreExecute allows it");
            }
        }
    }

    [Fact]
    public void C10_ThePropertyIsNotVacuous()
    {
        // At least one row drops a name and at least one keeps a name PreExecute still denies
        // for CanQuery -- otherwise both branches above could be dead.
        var dropped = 0;
        var keptButDenied = 0;
        foreach (var c in FixtureRoot.GetProperty("filterCases").EnumerateArray())
        {
            var w = Wrapper(c);
            var ctx = Signed(PolicyFrom(c.GetProperty("policy")), Override(c));
            var names = Strings(c.GetProperty("toolNames"));
            var kept = w.FilterTools(ctx, names);
            dropped += names.Count(n => !kept.Contains(n));
            keptButDenied += kept.Count(n => !w.PreExecute(ctx, new PreExecuteArgs(n)).Allowed);
        }
        dropped.Should().BePositive();
        keptButDenied.Should().BePositive();
    }

    // =======================================================================
    // F1-F4: every edit to toolRules after signing breaks the seal
    // =======================================================================

    private const string HiddenExportJson =
        "{\"permissions\":{\"canQuery\":true},\"objectRules\":{\"toolRules\":{\"hiddenTools\":[\"export_segment_csv\"]}}}";

    private static EffectivePolicy HiddenExport(string sourceConnectionId = "api:tool:test") =>
        PolicyFrom(HiddenExportJson, sourceConnectionId);

    private static SecureContextToolWrapper Plain(
        IJudge? judge = null, ToolCallHistory? history = null, string[]? allowedTools = null) =>
        new(new SecureContextWrapperOptions(
            SigningKey: Key, AllowedTools: allowedTools, Judge: judge, ToolCallHistory: history));

    private static SecurityContext WithPolicy(SecurityContext ctx, EffectivePolicy policy) =>
        ctx with { Policies = new[] { policy } };

    private static void ShouldBeInvalid(SecurityContext tampered, string toolName)
    {
        var wrapper = Plain();
        wrapper.PreExecute(tampered, new PreExecuteArgs(toolName))
            .Should().Be(new AccessResult(false, "invalid signature"));
        wrapper.FilterTools(tampered, new[] { "query_patients", toolName }).Should().BeEmpty();
    }

    [Fact]
    public void F_Control_TheUntamperedContextIsValid()
    {
        var ctx = Signed(HiddenExport());
        Plain().PreExecute(ctx, new PreExecuteArgs("export_segment_csv"))
            .Should().Be(new AccessResult(false, "tool is hidden"));
        Plain().FilterTools(ctx, new[] { "query_patients" }).Should().Equal("query_patients");
    }

    [Fact]
    public void F1_ClearingHiddenTools_InvalidatesTheContext()
    {
        var ctx = Signed(HiddenExport());
        var p = ctx.Policies[0];
        ShouldBeInvalid(
            WithPolicy(ctx, p with { ObjectRules = p.ObjectRules! with { ToolRules = new ToolRules(HiddenTools: Array.Empty<string>()) } }),
            "export_segment_csv");
    }

    [Fact]
    public void F2_RemovingToolRules_InvalidatesTheContext()
    {
        var ctx = Signed(HiddenExport());
        var p = ctx.Policies[0];
        ShouldBeInvalid(
            WithPolicy(ctx, p with { ObjectRules = p.ObjectRules! with { ToolRules = null } }),
            "export_segment_csv");
    }

    [Fact]
    public void F3_AppendingToAllowedTools_InvalidatesTheContext()
    {
        var ctx = Signed(PolicyFrom(
            "{\"permissions\":{\"canQuery\":true},\"objectRules\":{\"toolRules\":{\"allowedTools\":[\"query_patients\"]}}}"));
        var p = ctx.Policies[0];
        ShouldBeInvalid(
            WithPolicy(ctx, p with
            {
                ObjectRules = p.ObjectRules! with
                {
                    ToolRules = new ToolRules(AllowedTools: new[] { "query_patients", "export_segment_csv" }),
                },
            }),
            "export_segment_csv");
    }

    [Fact]
    public void F4_AddingToolRules_EvenANarrowingEdit_InvalidatesTheContext()
    {
        var ctx = Signed(PolicyFrom("{\"permissions\":{\"canQuery\":true}}"));
        var p = ctx.Policies[0];
        ShouldBeInvalid(
            WithPolicy(ctx, p with
            {
                ObjectRules = new ObjectRules(ToolRules: new ToolRules(HiddenTools: new[] { "export_segment_csv" })),
            }),
            "export_segment_csv");
    }

    // =======================================================================
    // B12 / C9: the judge never sees a tool denial
    // =======================================================================

    private sealed class CountingJudge : IJudge
    {
        private int _calls;
        public int Calls => Volatile.Read(ref _calls);
        public string ModelId => Model;

        public Task<JudgeResult> EvaluateAsync(JudgeRequest request, CancellationToken ct = default)
        {
            Interlocked.Increment(ref _calls);
            return Task.FromResult(new JudgeResult(Aligned: true, Confidence: 0.99, Reasoning: "stub"));
        }
    }

    /// <summary>A purpose-bound, judge-enabled policy that also carries tool rules.</summary>
    private static EffectivePolicy JudgedPolicy(string toolRulesJson, bool canQuery = true) =>
        PolicyFrom(
            "{\"permissions\":{\"canQuery\":" + (canQuery ? "true" : "false") + "}," +
            "\"objectRules\":{\"toolRules\":" + toolRulesJson + "}," +
            "\"purposeProfile\":{\"purposeId\":\"tool-gate-purpose\"," +
            "\"judge\":{\"enabled\":true,\"model\":\"" + Model + "\"}}}");

    [Fact]
    public async Task B12_Control_AnAllowedToolReachesTheJudge()
    {
        var judge = new CountingJudge();
        var result = await Plain(judge).PreExecuteAsync(
            Signed(JudgedPolicy("{\"hiddenTools\":[\"export_segment_csv\"]}")),
            new PreExecuteArgs("query_patients"));

        result.Allowed.Should().BeTrue();
        judge.Calls.Should().Be(1, "without this control, 'zero calls' below proves nothing");
    }

    [Fact]
    public async Task B12_AHiddenToolIsDeniedWithoutTheJudge()
    {
        var judge = new CountingJudge();
        var result = await Plain(judge).PreExecuteAsync(
            Signed(JudgedPolicy("{\"hiddenTools\":[\"export_segment_csv\"]}")),
            new PreExecuteArgs("export_segment_csv"));

        result.Should().Be(new AccessResult(false, "tool is hidden"));
        judge.Calls.Should().Be(0);
    }

    [Fact]
    public async Task B12_ANameOutsideTheAllowedSetIsDeniedWithoutTheJudge()
    {
        var judge = new CountingJudge();
        var result = await Plain(judge).PreExecuteAsync(
            Signed(JudgedPolicy("{\"allowedTools\":[\"query_patients\"]}")),
            new PreExecuteArgs("Query_Patients"));

        result.Should().Be(new AccessResult(false, "tool not in allowed set"));
        judge.Calls.Should().Be(0);
    }

    [Fact]
    public void C9_FilterToolsNeverCallsTheJudge()
    {
        var judge = new CountingJudge();
        var kept = Plain(judge).FilterTools(
            Signed(JudgedPolicy("{\"hiddenTools\":[\"export_segment_csv\"]}")),
            new[] { "query_patients", "export_segment_csv" });

        kept.Should().Equal("query_patients");
        judge.Calls.Should().Be(0);
    }

    // =======================================================================
    // B13 / C8: history
    // =======================================================================

    [Fact]
    public async Task B13_AHiddenToolDenialIsRecordedByPreExecuteAsync()
    {
        var history = new ToolCallHistory(maxSize: 8);
        var result = await Plain(history: history).PreExecuteAsync(
            Signed(HiddenExport()), new PreExecuteArgs("export_segment_csv", ObjectName: "segments"));

        result.Should().Be(new AccessResult(false, "tool is hidden"));
        history.GetRecent().Should().Equal("export_segment_csv(object=segments)");
    }

    [Fact]
    public async Task B13_RecordedExactlyLikeAnExistingCanQueryDenial()
    {
        var toolHistory = new ToolCallHistory(maxSize: 8);
        var queryHistory = new ToolCallHistory(maxSize: 8);
        var args = new PreExecuteArgs("export_segment_csv", Fields: new[] { "email" });

        var toolDenial = await Plain(history: toolHistory).PreExecuteAsync(Signed(HiddenExport()), args);
        var queryDenial = await Plain(history: queryHistory).PreExecuteAsync(
            Signed(PolicyFrom("{\"permissions\":{\"canQuery\":false}}")), args);

        toolDenial.Reason.Should().Be("tool is hidden");
        queryDenial.Reason.Should().Be("query not permitted");
        toolHistory.GetRecent().Should().Equal(queryHistory.GetRecent());
        toolHistory.Count.Should().Be(1);
    }

    [Fact]
    public void B13_SyncPreExecuteRecordsNeitherDenial_AsToday()
    {
        var history = new ToolCallHistory(maxSize: 8);
        var w = Plain(history: history);
        w.PreExecute(Signed(HiddenExport()), new PreExecuteArgs("export_segment_csv")).Allowed.Should().BeFalse();
        w.PreExecute(Signed(PolicyFrom("{\"permissions\":{\"canQuery\":false}}")), new PreExecuteArgs("q"))
            .Allowed.Should().BeFalse();
        history.Count.Should().Be(0);
    }

    [Fact]
    public void C8_FilterToolsRecordsNothing()
    {
        var history = new ToolCallHistory(maxSize: 8);
        history.Record("earlier()");
        var w = Plain(history: history);

        w.FilterTools(Signed(HiddenExport()), new[] { "query_patients", "export_segment_csv" })
            .Should().Equal("query_patients");
        w.FilterTools(Signed(HiddenExport(), "expired"), new[] { "query_patients" }).Should().BeEmpty();

        history.GetRecent().Should().Equal("earlier()");
    }

    // =======================================================================
    // C7 and FilterTools' input/output contract
    // =======================================================================

    [Fact]
    public void C7_TheInputListIsNotMutated()
    {
        var input = new List<string> { "export_segment_csv", "query_patients", "export_segment_csv" };
        var copy = input.ToList();

        Plain().FilterTools(Signed(HiddenExport()), input).Should().Equal("query_patients");
        input.Should().Equal(copy);
    }

    [Fact]
    public void C7_TheResultIsANewListEvenWhenNothingIsDropped()
    {
        var input = new List<string> { "a", "b" };
        var result = Plain().FilterTools(Signed(PolicyFrom("{\"permissions\":{\"canQuery\":true}}")), input);

        result.Should().Equal("a", "b");
        result.Should().NotBeSameAs(input);
        input.Add("c");
        result.Should().Equal("a", "b");
    }

    [Fact]
    public void C7_AnInvalidContextReturnsEmptyAndLeavesTheInputAlone()
    {
        var input = new[] { "query_patients" };
        Plain().FilterTools(Signed(HiddenExport(), "wrongKey"), input).Should().BeEmpty();
        input.Should().Equal("query_patients");
    }

    [Fact]
    public void FilterTools_AContextWithNoPolicyListsNothing()
    {
        var ctx = SecurityContextSigner.Sign(
            SecurityContextBuilder.Build("u", "t", Array.Empty<EffectivePolicy>()), Key);
        Plain().FilterTools(ctx, new[] { "query_patients" }).Should().BeEmpty();
    }

    [Fact]
    public void FilterTools_PreservesInputOrder()
    {
        Plain().FilterTools(Signed(PolicyFrom("{\"permissions\":{\"canQuery\":true}}")), new[] { "zeta", "alpha", "mid" })
            .Should().Equal("zeta", "alpha", "mid");
    }

    [Fact]
    public void FilterTools_PreservesOrderWhileDropping()
    {
        var ctx = Signed(PolicyFrom(
            "{\"permissions\":{\"canQuery\":true},\"objectRules\":{\"toolRules\":{" +
            "\"allowedTools\":[\"zeta\",\"alpha\",\"mid\"],\"hiddenTools\":[\"ALPHA\"]}}}"));
        Plain().FilterTools(ctx, new[] { "zeta", "beta", "alpha", "mid", "zeta" })
            .Should().Equal("zeta", "mid", "zeta");
    }

    [Fact]
    public void FilterTools_AppliesNoGrammarWhenThePolicyHasNoToolRules()
    {
        var names = new[] { "export_segment_csv ", "export/segment", "Kill_switch", "" };
        Plain().FilterTools(Signed(PolicyFrom("{\"permissions\":{\"canQuery\":true}}")), names)
            .Should().Equal(names);
    }

    [Fact]
    public void FilterTools_AppliesTheGrammarWhenToolRulesArePresent_EvenEmpty()
    {
        var names = new[] { "export_segment_csv ", "export/segment", "Kill_switch", "", "ok_tool" };
        Plain().FilterTools(Signed(PolicyFrom("{\"permissions\":{\"canQuery\":true},\"objectRules\":{\"toolRules\":{}}}")), names)
            .Should().Equal("ok_tool");
    }

    [Fact]
    public void FilterTools_DoesNotApplyObjectFieldOrEndpointRules()
    {
        // Every data rule here would deny some call, but listing has no call arguments to
        // judge, so nothing is dropped for them. canQuery is false but canInsert is granted, so
        // the policy is write-only rather than deny-all (which lists nothing).
        var ctx = Signed(PolicyFrom(
            "{\"permissions\":{\"canQuery\":false,\"canInsert\":true},\"objectRules\":{" +
            "\"allowedObjects\":[],\"hiddenObjects\":[\"query_patients\"]," +
            "\"fieldRules\":{\"allowedFields\":[]}," +
            "\"endpointRules\":{\"allowedEndpoints\":[]}}}"));
        Plain().FilterTools(ctx, new[] { "query_patients", "count_patients" })
            .Should().Equal("query_patients", "count_patients");
    }

    [Fact]
    public void FilterTools_AppliesTheStaticListAndToolRulesTogether()
    {
        // The effective set is the intersection of the static list and the policy's.
        var ctx = Signed(PolicyFrom(
            "{\"permissions\":{\"canQuery\":true},\"objectRules\":{\"toolRules\":{\"allowedTools\":[\"a\",\"b\"]}}}"));
        Plain(allowedTools: new[] { "b", "c" }).FilterTools(ctx, new[] { "a", "b", "c" })
            .Should().Equal("b");
    }

    // =======================================================================
    // Mis-cased names reach the engine unchanged
    // =======================================================================

    private const string AllowQueryPatientsJson =
        "{\"permissions\":{\"canQuery\":true},\"objectRules\":{\"toolRules\":{\"allowedTools\":[\"query_patients\"]}}}";

    [Fact]
    public void MisCase_PreExecuteDeniesQuery_PatientsAgainstAllowedQueryPatients()
    {
        var ctx = Signed(PolicyFrom(AllowQueryPatientsJson));
        Plain().PreExecute(ctx, new PreExecuteArgs("Query_Patients"))
            .Should().Be(new AccessResult(false, "tool not in allowed set"));
        Plain().PreExecute(ctx, new PreExecuteArgs("QUERY_PATIENTS"))
            .Should().Be(new AccessResult(false, "tool not in allowed set"));
        Plain().PreExecute(ctx, new PreExecuteArgs("query_patients")).Allowed.Should().BeTrue();
    }

    [Fact]
    public void MisCase_AnUpperCasedAllowEntryDoesNotAdmitTheLowerCasedName()
    {
        // The other direction: a wrapper that lower-cased both sides would admit this.
        var ctx = Signed(PolicyFrom(
            "{\"permissions\":{\"canQuery\":true},\"objectRules\":{\"toolRules\":{\"allowedTools\":[\"QUERY_PATIENTS\"]}}}"));
        Plain().PreExecute(ctx, new PreExecuteArgs("query_patients"))
            .Should().Be(new AccessResult(false, "tool not in allowed set"));
        Plain().PreExecute(ctx, new PreExecuteArgs("QUERY_PATIENTS")).Allowed.Should().BeTrue();
    }

    [Fact]
    public void MisCase_FilterToolsDropsQuery_PatientsAndKeepsQuery_patients()
    {
        Plain().FilterTools(Signed(PolicyFrom(AllowQueryPatientsJson)), new[] { "Query_Patients", "query_patients" })
            .Should().Equal("query_patients");
    }

    [Fact]
    public void MisCase_AHiddenNameIsHiddenInAnyCase()
    {
        var ctx = Signed(HiddenExport());
        Plain().PreExecute(ctx, new PreExecuteArgs("Export_Segment_CSV"))
            .Should().Be(new AccessResult(false, "tool is hidden"));
        Plain().FilterTools(ctx, new[] { "Export_Segment_CSV", "EXPORT_SEGMENT_CSV", "query_patients" })
            .Should().Equal("query_patients");
    }

    [Fact]
    public void MisCase_TheStaticListStaysExactAndCaseSensitive()
    {
        // The static list's existing behaviour, unchanged: ordinal Contains.
        var ctx = Signed(PolicyFrom("{\"permissions\":{\"canQuery\":true}}"));
        var w = Plain(allowedTools: new[] { "query_patients" });
        w.PreExecute(ctx, new PreExecuteArgs("Query_Patients"))
            .Should().Be(new AccessResult(false, "tool not in allowed list"));
        w.FilterTools(ctx, new[] { "Query_Patients" }).Should().BeEmpty();
        w.FilterTools(ctx, new[] { "QUERY_PATIENTS", "query_patients" }).Should().Equal("query_patients");
    }

    // =======================================================================
    // FilterTools validates the context exactly as PreExecute does
    // =======================================================================

    private static SecurityContext SignedWithChain(EffectivePolicy policy, DelegationHop[] chain) =>
        SecurityContextSigner.Sign(
            SecurityContextBuilder.Build("tool-user", "tool-tenant", new[] { policy }, delegationChain: chain),
            Key);

    [Fact]
    public void Delegation_AProperlySignedContextWithABrokenMultiHopChain_ListsNothingAndIsDenied()
    {
        // Signed with the right key and unexpired: only the chain is wrong (hop 2 widens hop 1).
        // A FilterTools that checked the signature and expiry alone would list both tools.
        var chain = new[]
        {
            new DelegationHop("analyst@example.test", PrincipalType.User, DeclaredPurpose: "campaign-x"),
            new DelegationHop("agent-1", PrincipalType.Agent, DeclaredPurpose: "campaign-x-segment-a"),
            new DelegationHop("agent-2", PrincipalType.Agent, DeclaredPurpose: "campaign-xyz-evil"),
        };
        var ctx = SignedWithChain(HiddenExport(), chain);
        SecurityContextSigner.Validate(ctx, Key).Should().BeTrue("the seal is intact");
        SecurityContextSigner.ValidateExpiry(ctx).Should().BeNull("the context is live");

        Plain().FilterTools(ctx, new[] { "query_patients", "run_report" }).Should().BeEmpty();
        var denied = Plain().PreExecute(ctx, new PreExecuteArgs("query_patients"));
        denied.Allowed.Should().BeFalse();
        denied.Reason.Should().Be(
            "delegation hop 2 purpose 'campaign-xyz-evil' is not within parent scope 'campaign-x-segment-a'");
    }

    [Fact]
    public void Delegation_Control_AValidMultiHopChainListsAndAllows()
    {
        var chain = new[]
        {
            new DelegationHop("analyst@example.test", PrincipalType.User, DeclaredPurpose: "campaign-x"),
            new DelegationHop("agent-1", PrincipalType.Agent, DeclaredPurpose: "campaign-x-segment-a"),
            new DelegationHop("agent-2", PrincipalType.Agent, DeclaredPurpose: "campaign-x-segment-a-q1"),
        };
        var ctx = SignedWithChain(HiddenExport(), chain);
        Plain().FilterTools(ctx, new[] { "query_patients", "export_segment_csv" }).Should().Equal("query_patients");
        Plain().PreExecute(ctx, new PreExecuteArgs("query_patients")).Should().Be(new AccessResult(true));
    }

    private static SecureContextToolWrapper OptedOut(bool enforceSignatures = true, bool enforceExpiry = true) =>
        new(new SecureContextWrapperOptions(
            SigningKey: Key, EnforceSignatures: enforceSignatures, EnforceExpiry: enforceExpiry));

    [Fact]
    public void OptOut_EnforceExpiryFalse_AnExpiredContextIsListedAndAllowed_TheyAgree()
    {
        var ctx = Signed(HiddenExport(), "expired");
        var w = OptedOut(enforceExpiry: false);
        w.FilterTools(ctx, new[] { "query_patients", "export_segment_csv" }).Should().Equal("query_patients");
        w.PreExecute(ctx, new PreExecuteArgs("query_patients")).Should().Be(new AccessResult(true));
        w.PreExecute(ctx, new PreExecuteArgs("export_segment_csv"))
            .Should().Be(new AccessResult(false, "tool is hidden"), "the tool rules still apply");

        // Control: with expiry enforced the same context lists nothing and is denied.
        var strict = OptedOut();
        strict.FilterTools(ctx, new[] { "query_patients" }).Should().BeEmpty();
        strict.PreExecute(ctx, new PreExecuteArgs("query_patients")).Allowed.Should().BeFalse();
    }

    [Fact]
    public void OptOut_EnforceSignaturesFalse_AWrongKeyContextIsListedAndAllowed_TheyAgree()
    {
        var ctx = Signed(HiddenExport(), "wrongKey");
        var w = OptedOut(enforceSignatures: false);
        w.FilterTools(ctx, new[] { "query_patients", "export_segment_csv" }).Should().Equal("query_patients");
        w.PreExecute(ctx, new PreExecuteArgs("query_patients")).Should().Be(new AccessResult(true));
        w.PreExecute(ctx, new PreExecuteArgs("export_segment_csv"))
            .Should().Be(new AccessResult(false, "tool is hidden"), "the tool rules still apply");

        var strict = OptedOut();
        strict.FilterTools(ctx, new[] { "query_patients" }).Should().BeEmpty();
        strict.PreExecute(ctx, new PreExecuteArgs("query_patients"))
            .Should().Be(new AccessResult(false, "invalid signature"));
    }

    // =======================================================================
    // A context carrying two policies: the first one governs. The SecurityContext constructor
    // refuses more than one policy (Models.cs; Python and TypeScript carry a single effective
    // policy), but a `with { Policies = ... }` expression goes through the init setter and
    // skips that check, so the shape is reachable. Pinned here is what the wrapper does with
    // it: Policies[0], the element PrepareSqlQuery and every other check read.
    // =======================================================================

    private static SecurityContext SignedTwo(EffectivePolicy first, EffectivePolicy second)
    {
        var one = SecurityContextBuilder.Build("tool-user", "tool-tenant", new[] { first });
        var two = one with { Policies = new[] { first, second } };
        two.Policies.Should().HaveCount(2, "the init setter does not re-run the constructor check");
        return SecurityContextSigner.Sign(two, Key);
    }

    private static EffectivePolicy NoToolRules() => PolicyFrom("{\"permissions\":{\"canQuery\":true}}");

    [Fact]
    public void TwoPolicies_TheFirstHidesTheToolAndTheSecondDoesNot_ItIsHidden()
    {
        var ctx = SignedTwo(HiddenExport(), NoToolRules());
        Plain().PreExecute(ctx, new PreExecuteArgs("export_segment_csv"))
            .Should().Be(new AccessResult(false, "tool is hidden"));
        Plain().FilterTools(ctx, new[] { "query_patients", "export_segment_csv" }).Should().Equal("query_patients");
    }

    [Fact]
    public void TwoPolicies_TheSecondHidesTheToolAndTheFirstDoesNot_ItIsAllowed()
    {
        // Pinned, not endorsed: the wrapper does not merge policies; merging is the store's job.
        var ctx = SignedTwo(NoToolRules(), HiddenExport());
        Plain().PreExecute(ctx, new PreExecuteArgs("export_segment_csv")).Should().Be(new AccessResult(true));
        Plain().FilterTools(ctx, new[] { "query_patients", "export_segment_csv" })
            .Should().Equal("query_patients", "export_segment_csv");
    }

    // =======================================================================
    // The gate holds on every execution path of the context wrapper
    // =======================================================================

    [Fact]
    public async Task ExecuteWithEnforcement_NeverInvokesAHiddenTool()
    {
        var invoked = false;
        var act = () => Plain().ExecuteWithEnforcementAsync(
            Signed(HiddenExport()), new PreExecuteArgs("export_segment_csv"),
            () => { invoked = true; return Task.FromResult<object?>(new List<Dictionary<string, object?>>()); });

        (await act.Should().ThrowAsync<UnauthorizedAccessException>()).WithMessage("*tool is hidden*");
        invoked.Should().BeFalse();
    }

    [Fact]
    public async Task ExecuteSqlWithEnforcement_NeverRunsAHiddenToolsQuery()
    {
        var invoked = false;
        var act = () => Plain().ExecuteSqlWithEnforcementAsync(
            Signed(HiddenExport()), new PreExecuteArgs("export_segment_csv"), "SELECT id FROM patients",
            _ => { invoked = true; return Task.FromResult<IReadOnlyList<Dictionary<string, object?>>>(new List<Dictionary<string, object?>>()); });

        (await act.Should().ThrowAsync<UnauthorizedAccessException>()).WithMessage("*tool is hidden*");
        invoked.Should().BeFalse();
    }

    [Fact]
    public void PrepareSqlQuery_RefusesAHiddenTool()
    {
        var prep = Plain().PrepareSqlQuery(
            Signed(HiddenExport()), new PreExecuteArgs("export_segment_csv"), "SELECT id FROM patients");
        prep.Allowed.Should().BeFalse();
        prep.DenialReason.Should().Be("tool is hidden");
    }

    [Fact]
    public void TheReasonNeverEchoesTheToolName()
    {
        var hidden = Plain().PreExecute(Signed(HiddenExport()), new PreExecuteArgs("export_segment_csv"));
        var notAllowed = Plain().PreExecute(Signed(PolicyFrom(AllowQueryPatientsJson)), new PreExecuteArgs("secret_tool"));
        var invalid = Plain().PreExecute(Signed(HiddenExport()), new PreExecuteArgs("bad name"));

        hidden.Reason.Should().Be("tool is hidden").And.NotContain("export");
        notAllowed.Reason.Should().Be("tool not in allowed set").And.NotContain("secret");
        invalid.Reason.Should().Be("invalid tool name").And.NotContain("bad");
    }

    // =======================================================================
    // B17: SecureToolFactory with default options
    // =======================================================================

    private sealed class UnusedHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
            => throw new InvalidOperationException("the factory must not perform requests");
    }

    [Fact]
    public void B17_TheFactoryWithDefaultOptions_DeniesAHiddenTool()
    {
        var factory = new SecureToolFactory(
            new SecureToolFactoryOptions(SigningKey: Key), new HttpClient(new UnusedHandler()));
        var ctx = Signed(HiddenExport("db:production:segments"));

        var tool = factory.CreateTool(ctx);
        tool.RecordTool.Should().NotBeNull();
        tool.RecordTool!.PreExecute(ctx, new PreExecuteArgs("export_segment_csv"))
            .Should().Be(new AccessResult(false, "tool is hidden"));
        tool.RecordTool.PreExecute(ctx, new PreExecuteArgs("query_patients")).Allowed.Should().BeTrue();

        var direct = factory.CreateRecordTool();
        direct.PreExecute(ctx, new PreExecuteArgs("export_segment_csv"))
            .Should().Be(new AccessResult(false, "tool is hidden"));
        direct.FilterTools(ctx, new[] { "export_segment_csv", "query_patients" })
            .Should().Equal("query_patients");
    }

    // =======================================================================
    // B18: 50 concurrent calls each get their own decision
    // =======================================================================

    private static string ToolFor(int i) => i % 2 == 0 ? "query_patients" : "export_segment_csv";

    [Fact]
    public async Task B18_PreExecuteAsync_InParallel_WithAJudgeOnOneWrapper()
    {
        // Real thread-pool parallelism. No shared ToolCallHistory here: that type wraps an
        // unsynchronized Queue and is not safe to Record into from several threads (a
        // pre-existing property of Tolap.Core, not of the tool gate).
        var judge = new CountingJudge();
        var w = Plain(judge);
        var ctx = Signed(JudgedPolicy("{\"hiddenTools\":[\"export_segment_csv\"]}"));

        var results = await Task.WhenAll(Enumerable.Range(0, 50).Select(i =>
            Task.Run(() => w.PreExecuteAsync(ctx, new PreExecuteArgs(ToolFor(i))))));

        results.Should().HaveCount(50);
        for (var i = 0; i < 50; i++)
        {
            results[i].Should().Be(i % 2 == 0
                ? new AccessResult(true)
                : new AccessResult(false, "tool is hidden"), $"call {i} ({ToolFor(i)})");
        }
        judge.Calls.Should().Be(25, "only the allowed calls reach the judge");
    }

    [Fact]
    public async Task B18_PreExecuteAsync_Sequential_WithAJudgeAndHistoryOnOneWrapper()
    {
        // Sequential, not interleaved: CountingJudge returns Task.FromResult, so each
        // PreExecuteAsync completes synchronously before Task.WhenAll sees the next one
        // (ToolCallHistory is not thread-safe, so no Task.Run here). What this pins is that
        // 50 calls on one wrapper with a judge and a history each get the right answer and
        // every call, allowed or hidden, is recorded.
        var judge = new CountingJudge();
        var history = new ToolCallHistory(maxSize: 64);
        var w = Plain(judge, history);
        var ctx = Signed(JudgedPolicy("{\"hiddenTools\":[\"export_segment_csv\"]}"));

        var results = await Task.WhenAll(Enumerable.Range(0, 50).Select(i =>
            w.PreExecuteAsync(ctx, new PreExecuteArgs(ToolFor(i)))));

        for (var i = 0; i < 50; i++)
        {
            results[i].Should().Be(i % 2 == 0
                ? new AccessResult(true)
                : new AccessResult(false, "tool is hidden"), $"call {i} ({ToolFor(i)})");
        }
        judge.Calls.Should().Be(25);
        history.Count.Should().Be(50);
        history.GetRecent().Count(h => h == "export_segment_csv()").Should().Be(25);
    }

    [Fact]
    public async Task B18_PreExecute_ThroughWhenAll_OnOneWrapper()
    {
        var w = Plain();
        var ctx = Signed(HiddenExport());

        var results = await Task.WhenAll(Enumerable.Range(0, 50).Select(i =>
            Task.Run(() => (i, w.PreExecute(ctx, new PreExecuteArgs(ToolFor(i)))))));

        results.Should().HaveCount(50);
        foreach (var (i, r) in results)
        {
            r.Should().Be(i % 2 == 0 ? new AccessResult(true) : new AccessResult(false, "tool is hidden"));
        }
    }

    [Fact]
    public async Task B18_StoreWrapper_ThroughWhenAll()
    {
        var w = await StoreWrapper(new ToolRules(HiddenTools: new[] { "export_segment_csv" }));

        var results = await Task.WhenAll(Enumerable.Range(0, 50).Select(i =>
            Task.Run(() => Execute(w, ToolFor(i)))));

        for (var i = 0; i < 50; i++)
        {
            results[i].Allowed.Should().Be(i % 2 == 0, $"call {i} ({ToolFor(i)})");
            results[i].DenialReason.Should().Be(i % 2 == 0 ? null : "tool is hidden");
        }
    }

    // =======================================================================
    // B14/B15/B16: the store-resolving SecureMcpToolWrapper
    // =======================================================================

    private static async Task<SecureMcpToolWrapper> StoreWrapper(
        ToolRules? toolRules,
        bool canQuery = true,
        EnforcementMode mode = EnforcementMode.Strict,
        PurposeProfile? purpose = null,
        IReadOnlyDictionary<string, string>? categories = null,
        string[]? allowedObjects = null)
    {
        var store = new InMemoryPolicyStore();
        await store.CreatePolicyAsync(new PolicyDefinition(
            Version: "1.0",
            Name: "tool-gate-policy",
            Permissions: new PolicyPermissions(CanQuery: canQuery),
            AppliesToAll: true,
            ObjectRules: new ObjectRules(
                AllowedObjects: allowedObjects ?? new[] { "patients" },
                FieldRules: new FieldRules(MaskedFields: new[] { new MaskingRule("ssn", MaskType.Redact) }),
                ToolRules: toolRules),
            PurposeProfile: purpose));
        await store.AssignPolicyAsync(new PolicyAssignment(
            "1.0", "tool-gate-policy", new Assignee(AssigneeType.User, "alice"),
            new AssignmentScope(), true, new AuditInfo("admin", DateTimeOffset.UtcNow, "test")));

        return new SecureMcpToolWrapper(new SecureMcpServerOptions(
            PolicyStore: store,
            IdentityResolver: new StaticIdentityResolver(),
            IdentityExtractor: new HeaderIdentityExtractor(),
            SigningKey: Key,
            EnforcementMode: mode,
            DeclaredPurpose: purpose?.PurposeId,
            ToolActionCategories: categories));
    }

    private static Dictionary<string, string> Headers() => new()
    {
        ["X-Tolap-User-Id"] = "alice",
        ["X-Tolap-Tenant-Id"] = "t",
    };

    private sealed class Invocations { public int Count; }

    private static Task<ToolExecutionResult> Execute(
        SecureMcpToolWrapper wrapper, string toolName, string objectName = "patients", Invocations? seen = null) =>
        wrapper.ExecuteWithEnforcementAsync(
            Headers(), toolName, objectName, "s",
            () =>
            {
                if (seen is not null) Interlocked.Increment(ref seen.Count);
                return Task.FromResult<object?>(new List<Dictionary<string, object?>>
                {
                    new() { ["name"] = "a", ["ssn"] = "111-22-3333" },
                });
            });

    [Fact]
    public async Task B14_AHiddenToolIsDeniedToolIsHidden_AheadOfCanQuery()
    {
        var seen = new Invocations();
        var w = await StoreWrapper(new ToolRules(HiddenTools: new[] { "export_segment_csv" }), canQuery: false);

        var result = await Execute(w, "export_segment_csv", seen: seen);

        result.Allowed.Should().BeFalse();
        result.DenialReason.Should().Be("tool is hidden");
        result.Result.Should().BeNull();
        seen.Count.Should().Be(0);
    }

    [Fact]
    public async Task B14_TheCanQueryDenialStillAppliesToAToolTheRulesAllow()
    {
        var w = await StoreWrapper(new ToolRules(HiddenTools: new[] { "export_segment_csv" }), canQuery: false);
        var result = await Execute(w, "query_patients");
        result.Allowed.Should().BeFalse();
        result.DenialReason.Should().Be("query permission denied");
    }

    [Fact]
    public async Task B15_PermissiveMode_TurnsAToolDenialIntoAnAllow_AndRecordsTheReason()
    {
        // Exactly the shape of the existing Permissive assertions in WrapperBranchCoverageTests:
        // Allowed, with the denial reason kept and prefixed so the bypass is visible.
        var w = await StoreWrapper(
            new ToolRules(HiddenTools: new[] { "export_segment_csv" }), canQuery: false, mode: EnforcementMode.Permissive);

        var result = await Execute(w, "export_segment_csv");

        result.Allowed.Should().BeTrue();
        result.DenialReason.Should().Be("[permissive] tool is hidden");
    }

    [Fact]
    public async Task B15_PermissiveMode_MatchesTheExistingCanQueryPermissiveShape()
    {
        var toolDenial = await Execute(await StoreWrapper(
            new ToolRules(AllowedTools: Array.Empty<string>()), mode: EnforcementMode.Permissive), "query_patients");
        var queryDenial = await Execute(await StoreWrapper(
            null, canQuery: false, mode: EnforcementMode.Permissive), "query_patients");

        toolDenial.Should().Be(new ToolExecutionResult(true, "[permissive] tool not in allowed set", queryDenial.Result));
        queryDenial.Should().Be(new ToolExecutionResult(true, "[permissive] query permission denied", null));
    }

    [Fact]
    public async Task B15_StrictMode_HasNoPermissivePrefix()
    {
        var result = await Execute(
            await StoreWrapper(new ToolRules(HiddenTools: new[] { "export_segment_csv" })), "export_segment_csv");
        result.Should().Be(new ToolExecutionResult(false, "tool is hidden", null));
    }

    [Fact]
    public async Task B16_APolicyWithoutToolRules_GivesTheCanQueryDenialItGivesToday()
    {
        var seen = new Invocations();
        var result = await Execute(await StoreWrapper(null, canQuery: false), "export_segment_csv", seen: seen);
        result.Should().Be(new ToolExecutionResult(false, "query permission denied", null));
        seen.Count.Should().Be(0);
    }

    [Fact]
    public async Task B16_APolicyWithoutToolRules_StillAllowsAndFiltersAsToday()
    {
        var seen = new Invocations();
        // A name the grammar would reject: with no toolRules no grammar applies.
        var result = await Execute(await StoreWrapper(null), "export segment csv ", seen: seen);

        result.Allowed.Should().BeTrue();
        result.DenialReason.Should().BeNull();
        seen.Count.Should().Be(1);
        var rows = result.Result.Should().BeAssignableTo<IEnumerable<Dictionary<string, object?>>>().Subject.ToList();
        rows.Should().ContainSingle();
        rows[0]["ssn"].Should().NotBe("111-22-3333", "the post-execution pipeline still masks");
    }

    [Fact]
    public async Task B16_APolicyWithoutToolRules_StillDeniesTheObjectAsToday()
    {
        var result = await Execute(await StoreWrapper(null), "query_patients", objectName: "billing");
        result.Allowed.Should().BeFalse();
        result.DenialReason.Should().Be("object not in allowed set");
    }

    [Fact]
    public async Task StoreWrapper_TheToolCheckRunsBeforeThePurposeAction()
    {
        var purpose = new PurposeProfile(
            PurposeId: "campaign-x-overlap",
            AllowedActions: new[] { "aggregate_overlap" },
            ProhibitedActions: new[] { "export_pii" });
        var categories = new Dictionary<string, string>
        {
            ["segment_overlap"] = "aggregate_overlap",
            ["export_csv"] = "export_pii",
        };

        var hidden = await StoreWrapper(new ToolRules(HiddenTools: new[] { "export_csv" }), purpose: purpose, categories: categories);
        (await Execute(hidden, "export_csv")).DenialReason.Should().Be("tool is hidden");

        // Control: without the tool rule the same call is refused by the purpose check, so the
        // assertion above is the ordering and not just any denial.
        var unhidden = await StoreWrapper(null, purpose: purpose, categories: categories);
        (await Execute(unhidden, "export_csv")).DenialReason
            .Should().Be("action 'export_pii' is prohibited under purpose 'campaign-x-overlap'");

        // An allowed tool still meets the purpose action.
        var allowedButProhibited = await StoreWrapper(
            new ToolRules(AllowedTools: new[] { "export_csv", "segment_overlap" }), purpose: purpose, categories: categories);
        (await Execute(allowedButProhibited, "export_csv")).DenialReason
            .Should().Be("action 'export_pii' is prohibited under purpose 'campaign-x-overlap'");
        (await Execute(allowedButProhibited, "segment_overlap")).Allowed.Should().BeTrue();
    }

    [Fact]
    public async Task StoreWrapper_AnAllowedToolStillMeetsTheObjectRules()
    {
        var w = await StoreWrapper(new ToolRules(AllowedTools: new[] { "query_patients" }));
        (await Execute(w, "query_patients", objectName: "billing")).DenialReason.Should().Be("object not in allowed set");
        (await Execute(w, "query_patients")).Allowed.Should().BeTrue();
    }

    [Fact]
    public async Task StoreWrapper_NotInTheAllowedSet_AndAnInvalidName_AreDenied()
    {
        var w = await StoreWrapper(new ToolRules(AllowedTools: new[] { "query_patients" }));
        (await Execute(w, "export_segment_csv")).Should().Be(new ToolExecutionResult(false, "tool not in allowed set", null));
        (await Execute(w, "query_patients ")).Should().Be(new ToolExecutionResult(false, "invalid tool name", null));
        (await Execute(w, "Kill_switch")).Should().Be(new ToolExecutionResult(false, "invalid tool name", null));
    }

    [Fact]
    public async Task StoreWrapper_MisCase_DeniesQuery_PatientsAgainstAllowedQueryPatients()
    {
        var seen = new Invocations();
        var w = await StoreWrapper(new ToolRules(AllowedTools: new[] { "query_patients" }));

        (await Execute(w, "Query_Patients", seen: seen))
            .Should().Be(new ToolExecutionResult(false, "tool not in allowed set", null));
        seen.Count.Should().Be(0);
        (await Execute(w, "query_patients", seen: seen)).Allowed.Should().BeTrue();
        seen.Count.Should().Be(1);
    }

    [Fact]
    public async Task StoreWrapper_MisCase_AHiddenNameIsHiddenInAnyCase()
    {
        var w = await StoreWrapper(new ToolRules(HiddenTools: new[] { "export_segment_csv" }));
        (await Execute(w, "Export_Segment_CSV")).DenialReason.Should().Be("tool is hidden");
    }

    // =======================================================================
    // No option was added
    // =======================================================================

    [Fact]
    public void NoWrapperExposesAToolRulesOption()
    {
        // The policy alone decides. An opt-in would let a deployment forget to switch it on.
        foreach (var t in new[] { typeof(SecureContextWrapperOptions), typeof(SecureMcpServerOptions), typeof(SecureToolFactoryOptions) })
        {
            t.GetProperties().Select(p => p.Name)
                .Should().NotContain(n => n.Contains("ToolRule", StringComparison.OrdinalIgnoreCase)
                                          || n.Contains("ToolGat", StringComparison.OrdinalIgnoreCase)
                                          || n.Contains("HiddenTools", StringComparison.OrdinalIgnoreCase), t.Name);
        }
    }
}
