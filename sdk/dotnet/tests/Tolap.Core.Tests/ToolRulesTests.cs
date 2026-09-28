using System.Text.Json;
using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// objectRules.toolRules: the pure check and the merge, driven from the shared fixtures so the
/// three SDKs are held to one table.
/// </summary>
/// <remarks>
/// Matrix rows owned here: A1-A25 (through the fixture, plus direct grammar units for the rows
/// .NET is most likely to get wrong), D1-D6 (one named test per merge fixture, plus a guard that
/// every <c>tool-rules-*.json</c> merge fixture is named), E1, E2, E4 and E8, and core-level
/// tamper checks F1-F4. F5 and F6 live in <see cref="SigningConformanceTests"/>.
/// </remarks>
public class ToolRulesTests
{
    private const string Fixture = "enforcement/validate-tool-access.json";

    private static JsonElement Cases() => FixtureHelper.ReadFixtureAsJson(Fixture).GetProperty("cases");

    /// <summary>
    /// (index, display name). The name is the matrix row where the case carries one, so a failing
    /// row reads "A24" in the test output rather than a bare index.
    /// </summary>
    public static TheoryData<int, string> FixtureCases()
    {
        var cases = Cases();
        var data = new TheoryData<int, string>();
        for (var i = 0; i < cases.GetArrayLength(); i++)
        {
            var c = cases[i];
            var name = c.TryGetProperty("name", out var n) && n.ValueKind == JsonValueKind.String
                ? n.GetString()!
                : (c.GetProperty("expected").GetProperty("allowed").GetBoolean() ? "allow-" : "deny-")
                  + c.GetProperty("toolName").GetString();
            data.Add(i, name);
        }
        return data;
    }

    private static EffectivePolicy PolicyFrom(string json) =>
        TolapJsonOptions.Deserialize<EffectivePolicy>(json);

    private static EffectivePolicy PolicyWithToolRules(string toolRulesJson, bool canQuery = true) =>
        PolicyFrom(
            $$$"""{"permissions":{"canQuery":{{{(canQuery ? "true" : "false")}}}},"objectRules":{"toolRules":{{{toolRulesJson}}}}}""");

    // -- A. The shared fixture --

    [Theory]
    [MemberData(nameof(FixtureCases))]
    public void ValidateToolAccess_MatchesTheSharedFixture(int index, string name)
    {
        var testCase = Cases()[index];
        var toolName = testCase.GetProperty("toolName").GetString()!;
        var policy = PolicyFrom(testCase.GetProperty("policy").GetRawText());
        var expected = testCase.GetProperty("expected");

        var result = EnforcementEngine.ValidateToolAccess(toolName, policy);

        result.Allowed.Should().Be(expected.GetProperty("allowed").GetBoolean(),
            "case {0} ({1})", index, name);
        var expectedReason = expected.TryGetProperty("reason", out var r) ? r.GetString() : null;
        result.Reason.Should().Be(expectedReason, "case {0} ({1})", index, name);
    }

    [Fact]
    public void TheFixtureExercisesBothOutcomes()
    {
        var outcomes = Cases().EnumerateArray()
            .Select(c => c.GetProperty("expected").GetProperty("allowed").GetBoolean())
            .Distinct()
            .ToList();
        outcomes.Should().BeEquivalentTo(new[] { true, false });
    }

    [Fact]
    public void EveryGrammarRowA1ToA25IsPresentInTheFixture()
    {
        // The theory is only as good as the rows it is given: a fixture that lost a row would
        // still pass. Pin the named rows so dropping one fails here.
        var names = Cases().EnumerateArray()
            .Where(c => c.TryGetProperty("name", out _))
            .Select(c => c.GetProperty("name").GetString())
            .ToList();

        // A list, not a set: a duplicated row (A7 twice, A8 missing) must fail too.
        names.Should().Equal(Enumerable.Range(1, 25).Select(i => $"A{i}"));
        names.Should().OnlyHaveUniqueItems();
    }

    [Fact]
    public void TheFixtureHasExactly12LegacyCasesPlus25GrammarRows()
    {
        // An exact total: an added or dropped case of either kind must be a deliberate change
        // here, not a silent change to what the theory covers.
        Cases().GetArrayLength().Should().Be(12 + 25);
        Cases().EnumerateArray().Count(c => !c.TryGetProperty("name", out _)).Should().Be(12);
    }

    [Fact]
    public void A24_TheFixtureRowReallyCarriesTheKelvinSign()
    {
        // If the fixture's escape were ever normalised to a plain 'K', A24 would still pass here
        // while no longer testing the fold at all.
        var a24 = Cases().EnumerateArray().Single(c =>
            c.TryGetProperty("name", out var n) && n.GetString() == "A24");
        var hidden = a24.GetProperty("policy").GetProperty("objectRules")
            .GetProperty("toolRules").GetProperty("hiddenTools")[0].GetString()!;

        hidden[0].Should().Be('\u212A');
        a24.GetProperty("toolName").GetString().Should().Be("kill_switch");
    }

    [Fact]
    public void A25_TheFixtureRowReallyCarriesTheLongS()
    {
        // The shared counterpart of the LONG S InlineData below: the row that catches a
        // ToUpperInvariant fold (and Python upper(), TS toUpperCase). If the escape were ever
        // normalised to a plain 's', A25 would pass while no longer testing the fold.
        var a25 = Cases().EnumerateArray().Single(c =>
            c.TryGetProperty("name", out var n) && n.GetString() == "A25");
        var hidden = a25.GetProperty("policy").GetProperty("objectRules")
            .GetProperty("toolRules").GetProperty("hiddenTools")[0].GetString()!;
        var toolName = a25.GetProperty("toolName").GetString()!;

        hidden[0].Should().Be('\u017F');
        hidden.ToUpperInvariant().Should().Be(toolName.ToUpperInvariant());
    }

    // -- A. Direct grammar units: the rows most at risk in .NET specifically --

    [Theory]
    [InlineData("x\n")]
    [InlineData("export_segment_csv\n")]
    [InlineData("export_segment_csv\r\n")]
    [InlineData("export_segment_csv\r")]
    [InlineData("\nexport_segment_csv")]
    public void A4_ATrailingOrLeadingNewlineIsAnInvalidName(string toolName)
    {
        // .NET's '$' matches before a final "\n", so "^...$" would accept "x\n". The grammar
        // must anchor with \z. The policy hides nothing that could match, so the ONLY way to
        // get this reason is the grammar.
        var policy = PolicyWithToolRules("""{"hiddenTools":["x"]}""");

        EnforcementEngine.ValidateToolAccess(toolName, policy)
            .Should().Be(new AccessResult(false, "invalid tool name"));
    }

    [Fact]
    public void A4_TheNewlineNameIsInvalidEvenWhenItsTrimmedFormIsAllowed()
    {
        // The dangerous shape: with '$' the name would pass the grammar and then miss the
        // exact allow-list, giving the wrong reason; worse, against a hide it would pass.
        var allowing = PolicyWithToolRules("""{"allowedTools":["x"]}""");
        EnforcementEngine.ValidateToolAccess("x\n", allowing).Reason.Should().Be("invalid tool name");

        var hiding = PolicyWithToolRules("""{"hiddenTools":["x"]}""");
        EnforcementEngine.ValidateToolAccess("x\n", hiding).Reason.Should().Be("invalid tool name");
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("a b")]
    [InlineData("a\tb")]
    [InlineData("a\u0000")]
    [InlineData("a/b")]
    [InlineData("a:b")]
    [InlineData("a*")]
    [InlineData("a?")]
    [InlineData("a@b")]
    [InlineData("\u212Aill_switch")]
    [InlineData("exp\u00F6rt")]
    [InlineData("\u0130d")] // LATIN CAPITAL LETTER I WITH DOT ABOVE
    [InlineData("\u0131d")] // LATIN SMALL LETTER DOTLESS I
    [InlineData("\uFF41")] // FULLWIDTH LATIN SMALL LETTER A
    [InlineData("a\u200B")] // ZERO WIDTH SPACE
    [InlineData("\u0661")] // ARABIC-INDIC DIGIT ONE: \d would match it; [0-9] must not
    public void Grammar_RejectsEveryCharacterOutsideTheAsciiClass(string toolName)
    {
        var policy = PolicyWithToolRules("{}");

        EnforcementEngine.ValidateToolAccess(toolName, policy)
            .Should().Be(new AccessResult(false, "invalid tool name"));
    }

    [Theory]
    [InlineData("a")]
    [InlineData("Z")]
    [InlineData("0")]
    [InlineData("_")]
    [InlineData(".")]
    [InlineData("-")]
    [InlineData("tools.query-v2_x")]
    [InlineData("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-")]
    public void Grammar_AcceptsEveryPermittedCharacter(string toolName)
    {
        EnforcementEngine.ValidateToolAccess(toolName, PolicyWithToolRules("{}"))
            .Should().Be(new AccessResult(true));
    }

    [Theory]
    [InlineData(1, true)]
    [InlineData(127, true)]
    [InlineData(128, true)]
    [InlineData(129, false)]
    [InlineData(10_000, false)]
    public void Grammar_LengthBoundaryIs128(int length, bool allowed)
    {
        var result = EnforcementEngine.ValidateToolAccess(new string('a', length), PolicyWithToolRules("{}"));

        result.Allowed.Should().Be(allowed);
        result.Reason.Should().Be(allowed ? null : "invalid tool name");
    }

    [Fact]
    public void Grammar_IsCheckedBeforeHidden()
    {
        // A2's shape: whitespace must not be allowed to slip past a hide, and the reason must
        // be the grammar's, not the hide's (which proves the order, not just the outcome).
        var policy = PolicyWithToolRules("""{"hiddenTools":["export_segment_csv "]}""");

        EnforcementEngine.ValidateToolAccess("export_segment_csv ", policy)
            .Reason.Should().Be("invalid tool name");
    }

    [Theory]
    [InlineData("export_segment_csv ")]
    [InlineData("x\n")]
    [InlineData("")]
    [InlineData("\u212Aill_switch")]
    public void A12_NoToolRulesMeansNoGrammar(string toolName)
    {
        // Absent toolRules: every decision is unchanged, including for names the grammar would
        // refuse. Covers both "no objectRules" and "objectRules without toolRules".
        var bare = PolicyFrom("""{"permissions":{"canQuery":true}}""");
        var withObjects = PolicyFrom(
            """{"permissions":{"canQuery":true},"objectRules":{"allowedObjects":["patients"]}}""");

        EnforcementEngine.ValidateToolAccess(toolName, bare).Should().Be(new AccessResult(true));
        EnforcementEngine.ValidateToolAccess(toolName, withObjects).Should().Be(new AccessResult(true));
    }

    [Fact]
    public void ANullToolNameIsDeniedRatherThanThrowing()
    {
        // Fail closed at the boundary: a caller that passes null has not named a valid tool.
        EnforcementEngine.ValidateToolAccess(null!, PolicyWithToolRules("{}"))
            .Should().Be(new AccessResult(false, "invalid tool name"));
    }

    // -- A. Folding and order --

    [Theory]
    [InlineData("EXPORT_SEGMENT_CSV", "export_segment_csv")]
    [InlineData("export_segment_csv", "EXPORT_SEGMENT_CSV")]
    [InlineData("Export_Segment_Csv", "eXPORT_sEGMENT_cSV")]
    public void A13_A14_HiddenFoldsAsciiCaseBothWays(string toolName, string hidden)
    {
        var policy = PolicyWithToolRules($$"""{"hiddenTools":["{{hidden}}"]}""");

        EnforcementEngine.ValidateToolAccess(toolName, policy)
            .Should().Be(new AccessResult(false, "tool is hidden"));
    }

    [Theory]
    [InlineData("kill_switch", "\u212Aill_switch")] // KELVIN SIGN: .NET ToLowerInvariant gives 'k'
    [InlineData("i", "\u0130")] // I WITH DOT ABOVE: unchanged by .NET invariant casing (see below)
    [InlineData("I", "\u0131")] // DOTLESS I: unchanged by .NET invariant casing (see below)
    [InlineData("s", "\u017F")] // LONG S: .NET ToUpperInvariant gives 'S'
    public void A24_TheHideFoldIsAsciiOnly(string toolName, string hidden)
    {
        // A non-ASCII entry that reached the SDK must not hide an ASCII name through a Unicode
        // fold; OrdinalIgnoreCase does not fold these, and only an ASCII fold agrees with Python
        // str.translate and the TS [A-Z] replace. Which row catches which .NET mutation
        // (measured, not assumed):
        //   - ToLowerInvariant fold: the KELVIN SIGN row (and fixture row A24).
        //   - ToUpperInvariant fold: the LONG S row (and fixture row A25).
        //   - InvariantCultureIgnoreCase: the KELVIN SIGN row (and fixture row A24).
        // .NET invariant casing leaves U+0130 and U+0131 unchanged, so those two rows catch no
        // .NET mutation; they stay as guards against a culture-specific (tr-TR) fold and for
        // parity with the Python and TS suites, where Unicode casing does map them.
        var policy = PolicyWithToolRules($$"""{"hiddenTools":["{{hidden}}"]}""");

        EnforcementEngine.ValidateToolAccess(toolName, policy).Should().Be(new AccessResult(true));
    }

    [Theory]
    [InlineData("query_patients", "QUERY_PATIENTS")]
    [InlineData("Query_Patients", "query_patients")]
    [InlineData("query_patients", "query_patientS")]
    public void A15_AllowedIsExactAndCaseSensitive(string toolName, string allowed)
    {
        var policy = PolicyWithToolRules($$"""{"allowedTools":["{{allowed}}"]}""");

        EnforcementEngine.ValidateToolAccess(toolName, policy)
            .Should().Be(new AccessResult(false, "tool not in allowed set"));
    }

    [Theory]
    [InlineData("query")]
    [InlineData("query_*")]
    [InlineData("*")]
    [InlineData("query_patient")]
    [InlineData("query_patients_x")]
    [InlineData("uery_patients")]
    public void A17_A18_AllowedIsNeitherAPrefixNorAGlob(string allowed)
    {
        var policy = PolicyWithToolRules($$"""{"allowedTools":["{{allowed}}"]}""");

        EnforcementEngine.ValidateToolAccess("query_patients", policy)
            .Should().Be(new AccessResult(false, "tool not in allowed set"));
    }

    [Theory]
    [InlineData("export")]
    [InlineData("export_*")]
    [InlineData("*")]
    [InlineData("segment")]
    public void A16_HiddenIsNeitherAPrefixNorAGlob(string hidden)
    {
        var policy = PolicyWithToolRules($$"""{"hiddenTools":["{{hidden}}"]}""");

        EnforcementEngine.ValidateToolAccess("export_segment_csv", policy).Should().Be(new AccessResult(true));
    }

    [Fact]
    public void A22_HiddenIsCheckedBeforeAllowed()
    {
        // Both lists deny; only the reason tells the order apart.
        var policy = PolicyWithToolRules(
            """{"allowedTools":["query_patients"],"hiddenTools":["export_segment_csv"]}""");

        EnforcementEngine.ValidateToolAccess("export_segment_csv", policy)
            .Should().Be(new AccessResult(false, "tool is hidden"));
    }

    [Fact]
    public void HiddenWinsEvenWhenTheToolIsAllowed()
    {
        var policy = PolicyWithToolRules(
            """{"allowedTools":["export_segment_csv"],"hiddenTools":["export_segment_csv"]}""");

        EnforcementEngine.ValidateToolAccess("export_segment_csv", policy)
            .Should().Be(new AccessResult(false, "tool is hidden"));
    }

    [Fact]
    public void A21_EmptyAllowedDeniesEveryToolAndEmptyHiddenHidesNothing()
    {
        EnforcementEngine.ValidateToolAccess("query_patients", PolicyWithToolRules("""{"allowedTools":[]}"""))
            .Should().Be(new AccessResult(false, "tool not in allowed set"));
        EnforcementEngine.ValidateToolAccess("query_patients", PolicyWithToolRules("""{"hiddenTools":[]}"""))
            .Should().Be(new AccessResult(true));
    }

    [Fact]
    public void ReasonsDoNotEchoTheToolName()
    {
        var hidden = EnforcementEngine.ValidateToolAccess(
            "secret_tool", PolicyWithToolRules("""{"hiddenTools":["secret_tool"]}"""));
        hidden.Reason.Should().Be("tool is hidden");

        var notAllowed = EnforcementEngine.ValidateToolAccess(
            "secret_tool", PolicyWithToolRules("""{"allowedTools":["other"]}"""));
        notAllowed.Reason.Should().Be("tool not in allowed set");

        var invalid = EnforcementEngine.ValidateToolAccess(
            "secret_tool ", PolicyWithToolRules("{}"));
        invalid.Reason.Should().Be("invalid tool name");

        new[] { hidden.Reason, notAllowed.Reason, invalid.Reason }
            .Should().OnlyContain(reason => !reason!.Contains("secret_tool", StringComparison.Ordinal));
    }

    [Fact]
    public void CanQueryIsNotConsulted()
    {
        // The wrapper checks canQuery after the tool gate; the pure check must not pre-empt it.
        var policy = PolicyWithToolRules("""{"allowedTools":["query_patients"]}""", canQuery: false);

        EnforcementEngine.ValidateToolAccess("query_patients", policy).Should().Be(new AccessResult(true));
    }

    // -- Null versus empty on the model and the wire --

    [Fact]
    public void Deserialization_KeepsEmptyDistinctFromAbsent()
    {
        var rules = PolicyWithToolRules("""{"allowedTools":[]}""").ObjectRules!.ToolRules!;

        rules.AllowedTools.Should().NotBeNull().And.BeEmpty();
        rules.HiddenTools.Should().BeNull();
    }

    [Fact]
    public void Deserialization_AnEmptyToolRulesObjectIsPresent()
    {
        // toolRules: {} is present (and so switches the grammar on, A8/A10), not absent.
        var rules = PolicyWithToolRules("{}").ObjectRules!.ToolRules;

        rules.Should().NotBeNull();
        rules!.AllowedTools.Should().BeNull();
        rules.HiddenTools.Should().BeNull();
    }

    [Fact]
    public void AbsentToolRules_IsOmittedFromCanonicalJson()
    {
        var rules = new ObjectRules(AllowedObjects: new[] { "patients" });
        CanonicalJson.Serialize(rules).Should().NotContain("toolRules");
        TolapJsonOptions.Serialize(rules).Should().NotContain("toolRules");
    }

    [Fact]
    public void EmptyToolLists_SerializeAsEmptyLists()
    {
        var rules = new ObjectRules(ToolRules: new ToolRules(Array.Empty<string>(), Array.Empty<string>()));

        CanonicalJson.Serialize(rules)
            .Should().Be("""{"toolRules":{"allowedTools":[],"hiddenTools":[]}}""");
    }

    [Fact]
    public void NullToolLists_AreOmittedNotEmittedAsNull()
    {
        var rules = new ObjectRules(ToolRules: new ToolRules(AllowedTools: new[] { "a" }));

        CanonicalJson.Serialize(rules).Should().Be("""{"toolRules":{"allowedTools":["a"]}}""");
    }

    [Fact]
    public void ToolRules_RoundTripsThroughTheTransportSerializer()
    {
        var policy = PolicyWithToolRules("""{"allowedTools":["b","a"],"hiddenTools":[]}""");
        var again = PolicyFrom(TolapJsonOptions.Serialize(policy));

        again.ObjectRules!.ToolRules!.AllowedTools.Should().Equal("b", "a");
        again.ObjectRules.ToolRules.HiddenTools.Should().NotBeNull().And.BeEmpty();
    }

    // -- E. Malformed input --

    [Theory]
    [InlineData("""{"allowedTools":"query_patients"}""")]
    [InlineData("""{"hiddenTools":"admin_reset"}""")]
    public void E1_AStringInsteadOfAnArrayThrows(string toolRules)
    {
        // Must throw rather than, say, iterate the characters into one-letter tool names.
        var act = () => PolicyWithToolRules(toolRules);
        act.Should().Throw<JsonException>();
    }

    [Theory]
    [InlineData("""{"allowedTools":[1]}""")]
    [InlineData("""{"allowedTools":["ok",1]}""")]
    [InlineData("""{"allowedTools":[true]}""")]
    [InlineData("""{"allowedTools":[{}]}""")]
    [InlineData("""{"allowedTools":[["x"]]}""")]
    [InlineData("""{"hiddenTools":[1]}""")]
    [InlineData("""{"hiddenTools":[false]}""")]
    [InlineData("""{"allowedTools":[null]}""")]
    [InlineData("""{"allowedTools":["ok",null]}""")]
    [InlineData("""{"hiddenTools":[null]}""")]
    [InlineData("""{"hiddenTools":["ok",null]}""")]
    [InlineData("""{"hiddenTools":["x",null]}""")]
    [InlineData("""{"hiddenTools":[null,"x"]}""")]
    public void E2_ANonStringEntryThrows(string toolRules)
    {
        var act = () => PolicyWithToolRules(toolRules);
        act.Should().Throw<JsonException>();
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("""["query_patients"]""")]
    [InlineData("\"query_patients\"")]
    [InlineData("1")]
    [InlineData("true")]
    public void E4_AToolRulesThatIsNotAnObjectThrows(string toolRules)
    {
        var act = () => PolicyWithToolRules(toolRules);
        act.Should().Throw<JsonException>();
    }

    [Theory]
    [InlineData("""{"allowedTools":[null]}""")]
    [InlineData("""{"allowedTools":["ok",null]}""")]
    [InlineData("""{"hiddenTools":[null]}""")]
    [InlineData("""{"hiddenTools":["ok",null]}""")]
    public void E2_ANullEntryThrowsOnThePolicyDefinitionPath(string toolRules)
    {
        // Python raises ValueError and TS denies "invalid tool rules": a null entry must never
        // deserialize into a policy that then gets merged and signed.
        var json = $$$"""{"version":"1.0","name":"p","permissions":{"canQuery":true},"objectRules":{"toolRules":{{{toolRules}}}}}""";
        var act = () => TolapJsonOptions.Deserialize<PolicyDefinition>(json);
        act.Should().Throw<JsonException>();
    }

    [Theory]
    [InlineData("""{"allowedTools":[null]}""")]
    [InlineData("""{"allowedTools":["ok",null]}""")]
    [InlineData("""{"hiddenTools":[null]}""")]
    [InlineData("""{"hiddenTools":["ok",null]}""")]
    public void E2_ANullEntryThrowsWhateverSerializerOptionsAreUsed(string toolRules)
    {
        // The converter is bound to the property, not registered in TolapJsonOptions, so a
        // caller deserializing with its own (or default) options gets the same rejection.
        var json = $$$"""{"permissions":{"canQuery":true},"objectRules":{"toolRules":{{{toolRules}}}}}""";
        var options = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
        var act = () => JsonSerializer.Deserialize<EffectivePolicy>(json, options);
        act.Should().Throw<JsonException>();
    }

    [Fact]
    public void E2_StrictListsStillReadEmptyAndStringLists()
    {
        var policy = PolicyWithToolRules("""{"allowedTools":[],"hiddenTools":["a","B"]}""");
        policy.ObjectRules!.ToolRules!.AllowedTools.Should().NotBeNull().And.BeEmpty();
        policy.ObjectRules.ToolRules.HiddenTools.Should().Equal("a", "B");
    }

    [Fact]
    public void E1_E2_E4_ThePolicyDefinitionPathRejectsTheSameShapes()
    {
        foreach (var toolRules in new[] { """{"allowedTools":"q"}""", """{"hiddenTools":[1]}""", "[]" })
        {
            var json = $$$"""{"version":"1.0","name":"p","permissions":{"canQuery":true},"objectRules":{"toolRules":{{{toolRules}}}}}""";
            var act = () => TolapJsonOptions.Deserialize<PolicyDefinition>(json);
            act.Should().Throw<JsonException>("toolRules {0} is malformed", toolRules);
        }
    }

    [Fact]
    public void E8_ANullToolRulesIsAbsent()
    {
        var policy = PolicyWithToolRules("null");

        policy.ObjectRules.Should().NotBeNull();
        policy.ObjectRules!.ToolRules.Should().BeNull();
        // Absent means no grammar either: A12's name passes.
        EnforcementEngine.ValidateToolAccess("export_segment_csv ", policy).Should().Be(new AccessResult(true));
        CanonicalJson.Serialize(policy).Should().NotContain("toolRules");
    }

    [Fact]
    public void E8_NullListsInsideToolRulesAreAbsent()
    {
        var rules = PolicyWithToolRules("""{"allowedTools":null,"hiddenTools":null}""").ObjectRules!.ToolRules!;

        rules.AllowedTools.Should().BeNull();
        rules.HiddenTools.Should().BeNull();
    }

    [Fact]
    public void E8_ANullToolRulesMergesAsAbsent()
    {
        var definition = TolapJsonOptions.Deserialize<PolicyDefinition>(
            """{"version":"1.0","name":"p","permissions":{"canQuery":true},"objectRules":{"allowedObjects":["patients"],"toolRules":null}}""");

        var merged = PolicyMerger.Merge(new[] { definition });

        merged.ObjectRules!.ToolRules.Should().BeNull();
        CanonicalJson.Serialize(merged).Should().NotContain("toolRules");
    }

    // -- D. Merge --

    /// <summary>
    /// Every tool-rules merge fixture, by matrix row. The guard below fails if a
    /// <c>tool-rules-*.json</c> file is added to the corpus without being named here.
    /// </summary>
    private static readonly (string Row, string Name)[] ToolRulesMergeFixtures =
    {
        ("D1", "tool-rules-intersect-and-union"),
        ("D2", "tool-rules-order-independent"),
        ("D3", "tool-rules-absent-everywhere"),
        ("D4", "tool-rules-absent-and-empty"),
        ("D5", "tool-rules-case-variants"),
        ("D6", "tool-rules-three-way"),
    };

    public static TheoryData<string, string> MergeFixtures()
    {
        var data = new TheoryData<string, string>();
        foreach (var (row, name) in ToolRulesMergeFixtures)
            data.Add(row, name);
        return data;
    }

    private static (EffectivePolicy Merged, JsonElement Expected) MergeFixture(string name)
    {
        var fixture = FixtureHelper.ReadFixtureAsJson($"merge-scenarios/{name}.json");
        var inputs = fixture.GetProperty("inputs").EnumerateArray()
            .Select(p => TolapJsonOptions.Deserialize<PolicyDefinition>(p.GetRawText()))
            .ToList();
        return (PolicyMerger.Merge(inputs), fixture.GetProperty("expected"));
    }

    /// <summary>
    /// Canonical bytes of a fixture's <c>expected.permissions</c>. The fixtures list only
    /// <c>canQuery</c> and <c>readOnly</c>; every SDK's merge emits the three write grants as an
    /// explicit AND result, and an absent grant ANDs as <c>false</c>. So an absent write flag is
    /// filled in as <c>false</c> here and nothing else is: an unknown key fails, a missing
    /// <c>canQuery</c>/<c>readOnly</c> fails, and the two sides are then compared byte-for-byte.
    /// </summary>
    private static string ExpectedMergedPermissions(JsonElement permissions)
    {
        var known = new[] { "canQuery", "canInsert", "canUpdate", "canDelete", "readOnly" };
        permissions.EnumerateObject().Select(p => p.Name).Should().BeSubsetOf(known);

        bool Flag(string name) =>
            permissions.TryGetProperty(name, out var v) && v.GetBoolean();

        var filled = new PolicyPermissions(
            CanQuery: permissions.GetProperty("canQuery").GetBoolean(),
            CanInsert: Flag("canInsert"),
            CanUpdate: Flag("canUpdate"),
            CanDelete: Flag("canDelete"),
            ReadOnly: permissions.GetProperty("readOnly").GetBoolean());
        return CanonicalJson.Serialize(filled);
    }

    [Fact]
    public void MergeRunnerGuard_EveryToolRulesMergeFixtureIsNamed()
    {
        var directory = Path.GetDirectoryName(
            FixtureHelper.GetFixturePath("merge-scenarios/tool-rules-intersect-and-union.json"))!;
        var onDisk = Directory.EnumerateFiles(directory, "tool-rules-*.json")
            .Select(Path.GetFileNameWithoutExtension)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

        var named = ToolRulesMergeFixtures.Select(f => f.Name).OrderBy(n => n, StringComparer.Ordinal).ToList();

        onDisk.Should().Equal(named);
        named.Should().HaveCount(6);
    }

    [Theory]
    [MemberData(nameof(MergeFixtures))]
    public void Merge_MatchesTheFixtureExpectedObjectRulesByteForByte(string row, string name)
    {
        // Canonical bytes, not structural equivalence: [] versus absent, and an emitted
        // toolRules:{} versus none, are exactly the differences equivalence assertions forgive.
        var (merged, expected) = MergeFixture(name);

        CanonicalJson.Serialize(merged.ObjectRules)
            .Should().Be(CanonicalJson.Canonicalize(expected.GetProperty("objectRules")), "row {0}", row);
        CanonicalJson.Serialize(merged.Permissions)
            .Should().Be(ExpectedMergedPermissions(expected.GetProperty("permissions")), "row {0}", row);
        merged.SourceProfiles.Should().Equal(
            expected.GetProperty("sourceProfiles").EnumerateArray().Select(e => e.GetString()));
    }

    [Fact]
    public void D1_Merge_ToolRulesIntersectAndUnion()
    {
        var rules = MergeFixture("tool-rules-intersect-and-union").Merged.ObjectRules!;

        // NotBeNull is the half that matters: disjoint allow-lists deny every tool, and a
        // collapse to null would silently mean unrestricted.
        rules.ToolRules.Should().NotBeNull();
        rules.ToolRules!.AllowedTools.Should().NotBeNull().And.BeEmpty();
        rules.ToolRules.HiddenTools.Should().Equal("admin_reset");
        rules.AllowedObjects.Should().Equal("patients");

        CanonicalJson.Serialize(rules).Should().Contain("\"allowedTools\":[]");
        EnforcementEngine.ValidateToolAccess("query_patients",
            MergeFixture("tool-rules-intersect-and-union").Merged)
            .Should().Be(new AccessResult(false, "tool not in allowed set"));
    }

    [Fact]
    public void D2_Merge_IsOrderIndependentForToolRules()
    {
        var forward = MergeFixture("tool-rules-intersect-and-union").Merged.ObjectRules!;
        var reversed = MergeFixture("tool-rules-order-independent").Merged.ObjectRules!;

        CanonicalJson.Serialize(reversed.ToolRules).Should().Be(CanonicalJson.Serialize(forward.ToolRules));
        reversed.ToolRules!.AllowedTools.Should().NotBeNull().And.BeEmpty();
        reversed.ToolRules.HiddenTools.Should().Equal("admin_reset");
    }

    [Fact]
    public void D3_Merge_AbsentEverywhereEmitsNoToolRulesKey()
    {
        var merged = MergeFixture("tool-rules-absent-everywhere").Merged;

        merged.ObjectRules!.ToolRules.Should().BeNull();
        CanonicalJson.Serialize(merged).Should().NotContain("toolRules");
        TolapJsonOptions.Serialize(merged).Should().NotContain("toolRules");
    }

    [Fact]
    public void D4_Merge_AbsentAndEmptyGivesEmpty()
    {
        var rules = MergeFixture("tool-rules-absent-and-empty").Merged.ObjectRules!.ToolRules!;

        rules.AllowedTools.Should().NotBeNull().And.BeEmpty();
        rules.HiddenTools.Should().Equal("x");
    }

    [Fact]
    public void D5_Merge_ComparesExactlyAndDoesNotFold()
    {
        var rules = MergeFixture("tool-rules-case-variants").Merged.ObjectRules!.ToolRules!;

        rules.AllowedTools.Should().NotBeNull().And.BeEmpty();
        // First-seen order, both spellings kept.
        rules.HiddenTools.Should().Equal("A", "a");
    }

    [Fact]
    public void D6_Merge_IntersectsAcrossEveryContributingPolicy()
    {
        var merged = MergeFixture("tool-rules-three-way").Merged;
        var rules = merged.ObjectRules!.ToolRules!;

        rules.AllowedTools.Should().Equal("c");
        rules.HiddenTools.Should().BeNull();
        CanonicalJson.Serialize(merged.ObjectRules).Should().Be("""{"toolRules":{"allowedTools":["c"]}}""");
    }

    [Fact]
    public void Merge_ATrueUnionOfAllowedWouldBeCaught()
    {
        // Pins the direction of each operation with lists that overlap partially, so a swap
        // (union allowed / intersect hidden) produces a different, visible result.
        var a = new PolicyDefinition("1.0", "a", new PolicyPermissions(CanQuery: true),
            ObjectRules: new ObjectRules(ToolRules: new ToolRules(new[] { "x", "y" }, new[] { "h1" })));
        var b = new PolicyDefinition("1.0", "b", new PolicyPermissions(CanQuery: true),
            ObjectRules: new ObjectRules(ToolRules: new ToolRules(new[] { "y", "z" }, new[] { "h2" })));

        var rules = PolicyMerger.Merge(new[] { a, b }).ObjectRules!.ToolRules!;

        rules.AllowedTools.Should().Equal("y");
        rules.HiddenTools.Should().Equal("h1", "h2");
    }

    [Fact]
    public void Merge_ATools_OnlyPolicyKeepsItsObjectRules()
    {
        // The all-null check in MergeObjectRules must count toolRules, or a policy whose only
        // object rule is a tool gate would lose objectRules entirely -- unrestricted.
        var only = new PolicyDefinition("1.0", "only-tools", new PolicyPermissions(CanQuery: true),
            ObjectRules: new ObjectRules(ToolRules: new ToolRules(HiddenTools: new[] { "admin_reset" })));

        var merged = PolicyMerger.Merge(new[] { only });

        merged.ObjectRules.Should().NotBeNull();
        merged.ObjectRules!.ToolRules!.HiddenTools.Should().Equal("admin_reset");
        merged.ObjectRules.ToolRules.AllowedTools.Should().BeNull();
        EnforcementEngine.ValidateToolAccess("admin_reset", merged).Reason.Should().Be("tool is hidden");
    }

    [Fact]
    public void Merge_ATools_OnlyAllowEmptyPolicyKeepsDenyAll()
    {
        var only = new PolicyDefinition("1.0", "deny-all-tools", new PolicyPermissions(CanQuery: true),
            ObjectRules: new ObjectRules(ToolRules: new ToolRules(AllowedTools: Array.Empty<string>())));

        var merged = PolicyMerger.Merge(new[] { only });

        merged.ObjectRules!.ToolRules!.AllowedTools.Should().NotBeNull().And.BeEmpty();
        EnforcementEngine.ValidateToolAccess("anything", merged).Allowed.Should().BeFalse();
    }

    [Fact]
    public void Merge_AnEmptyToolRulesObjectIsDropped()
    {
        // Accepted ruling, shared with Python and TS: toolRules {} merges away like an empty
        // endpointRules. (Enforcement-wise this only drops the grammar for a single-policy
        // merge; the three SDKs agree on it.)
        var empty = new PolicyDefinition("1.0", "empty-tools", new PolicyPermissions(CanQuery: true),
            ObjectRules: new ObjectRules(AllowedObjects: new[] { "patients" }, ToolRules: new ToolRules()));

        var merged = PolicyMerger.Merge(new[] { empty });

        merged.ObjectRules!.ToolRules.Should().BeNull();
        CanonicalJson.Serialize(merged).Should().NotContain("toolRules");
    }

    [Fact]
    public void Merge_APolicyWithNoObjectRulesAtAllContributesNothingToToolRules()
    {
        // Branch-coverage gap (Task 11): no other test merges a policy whose ObjectRules is null
        // alongside one carrying toolRules, so the `p.ObjectRules?` null arm in MergeToolRules
        // was never taken. Such a policy has no tool gate: it must neither widen the other
        // policy's gate (drop the hide, or the allow list) nor narrow it (read as
        // allowedTools [] and deny every tool), and must not throw. In both orders, because a
        // null in first position seeds the intersection differently from one in second.
        var bare = new PolicyDefinition("1.0", "bare", new PolicyPermissions(CanQuery: true));
        var gated = new PolicyDefinition("1.0", "gated", new PolicyPermissions(CanQuery: true),
            ObjectRules: new ObjectRules(ToolRules: new ToolRules(
                new[] { "query_patients" }, new[] { "export_segment_csv" })));

        foreach (var order in new[] { new[] { bare, gated }, new[] { gated, bare } })
        {
            var merged = PolicyMerger.Merge(order);

            CanonicalJson.Serialize(merged.ObjectRules).Should().Be(
                """{"toolRules":{"allowedTools":["query_patients"],"hiddenTools":["export_segment_csv"]}}""");
            EnforcementEngine.ValidateToolAccess("query_patients", merged)
                .Should().Be(new AccessResult(true));
            EnforcementEngine.ValidateToolAccess("export_segment_csv", merged)
                .Should().Be(new AccessResult(false, "tool is hidden"));
            EnforcementEngine.ValidateToolAccess("count_patients", merged)
                .Should().Be(new AccessResult(false, "tool not in allowed set"));
        }
    }

    // -- F1-F4 at the core: the signature covers toolRules --

    private const string Key = "tolap-test-signing-key-2026";

    private static SecurityContext ContextWith(ToolRules? toolRules)
    {
        var at = new DateTimeOffset(2026, 1, 15, 10, 0, 0, TimeSpan.Zero);
        var policy = new EffectivePolicy(
            Version: "1.0", UserId: "user-001", TenantId: "tenant", SourceConnectionId: null,
            ResolvedAt: at, ExpiresAt: at.AddHours(1),
            SourceProfiles: new[] { "p" },
            Permissions: new PolicyPermissions(CanQuery: true),
            ObjectRules: new ObjectRules(AllowedObjects: new[] { "patients" }, ToolRules: toolRules));
        return new SecurityContext("1.0", "user-001", "tenant", at, at.AddHours(1), new[] { policy });
    }

    private static SecurityContext Retool(SecurityContext signed, ToolRules? toolRules) => signed with
    {
        Policies = new[]
        {
            signed.Policies[0] with { ObjectRules = signed.Policies[0].ObjectRules! with { ToolRules = toolRules } }
        }
    };

    [Fact]
    public void F1_ClearingHiddenToolsBreaksTheSignature()
    {
        var signed = SecurityContextSigner.Sign(
            ContextWith(new ToolRules(new[] { "query_patients" }, new[] { "export_segment_csv" })), Key);
        SecurityContextSigner.Validate(signed, Key).Should().BeTrue();

        var tampered = Retool(signed, new ToolRules(new[] { "query_patients" }, Array.Empty<string>()));

        SecurityContextSigner.Validate(tampered, Key).Should().BeFalse();
    }

    [Fact]
    public void F2_RemovingToolRulesBreaksTheSignature()
    {
        var signed = SecurityContextSigner.Sign(
            ContextWith(new ToolRules(HiddenTools: new[] { "export_segment_csv" })), Key);

        SecurityContextSigner.Validate(Retool(signed, null), Key).Should().BeFalse();
    }

    [Fact]
    public void F3_AppendingAnAllowedToolBreaksTheSignature()
    {
        var signed = SecurityContextSigner.Sign(ContextWith(new ToolRules(new[] { "query_patients" })), Key);

        var tampered = Retool(signed, new ToolRules(new[] { "query_patients", "export_segment_csv" }));

        SecurityContextSigner.Validate(tampered, Key).Should().BeFalse();
    }

    [Fact]
    public void F4_AddingToolRulesToAContextSignedWithoutBreaksTheSignature()
    {
        var signed = SecurityContextSigner.Sign(ContextWith(null), Key);
        SecurityContextSigner.Validate(signed, Key).Should().BeTrue();

        // Even a narrowing edit breaks the seal.
        var tampered = Retool(signed, new ToolRules(AllowedTools: Array.Empty<string>()));

        SecurityContextSigner.Validate(tampered, Key).Should().BeFalse();
    }
}
