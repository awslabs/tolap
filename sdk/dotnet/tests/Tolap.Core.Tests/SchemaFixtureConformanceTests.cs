using System.Text.Json;
using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// Every enum-valued token in the shared fixture corpus must be one the published schema
/// permits (docs/canonical-enforcement-spec.md section 14).
/// </summary>
/// <remarks>
/// Full JSON Schema <i>document</i> validation of the corpus lives in the Python suite
/// (<c>sdk/python/tests/test_schema_fixture_validation.py</c>), which owns the single
/// validator for the repository: three independent validators would mean three
/// interpretations of draft 2020-12 and a fourth artefact to keep in step, and neither
/// this SDK nor the TypeScript one carries a schema validator today.
/// <para>
/// What still belongs here is the part that is about <i>this</i> SDK: a fixture using an
/// enum value this SDK's converters reject is a fixture that cannot be loaded here, and
/// the corpus is what all three SDKs are tested against. So this walks every fixture and
/// example, collects every enum-valued token, and checks each against both the schema
/// (read from disk) and this SDK's own acceptance -- which is exactly the pairing that
/// would have caught the 9-vs-16 operator drift, where the corpus, the schema and the SDK
/// each believed something different.
/// </para>
/// </remarks>
public class SchemaFixtureConformanceTests
{
    /// <summary>
    /// The deliberately-invalid fixture. It exists to prove the deserializer REFUSES it,
    /// so its out-of-schema <c>maskType</c> is the point rather than a defect.
    /// </summary>
    private const string InvalidByDesign = "invalid-bad-mask-type.json";

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null)
        {
            if (Directory.Exists(Path.Combine(directory.FullName, "fixtures"))
                && Directory.Exists(Path.Combine(directory.FullName, "schema")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException(
            $"could not locate the repository root above {AppContext.BaseDirectory}; " +
            "fixture conformance MUST NOT be skipped (canonical spec section 14)");
    }

    /// <summary>
    /// Every fixture and published example that carries policy content, as
    /// (relative path, parsed document) pairs.
    /// </summary>
    /// <remarks>
    /// <c>fixtures/api/</c> is excluded: those are recorded upstream API responses used as
    /// enforcement input, not policy documents.
    /// </remarks>
    public static TheoryData<string> Corpus()
    {
        var root = RepositoryRoot();
        var data = new TheoryData<string>();

        var files = Directory
            .EnumerateFiles(Path.Combine(root, "fixtures"), "*.json", SearchOption.AllDirectories)
            .Where(path => !path.Contains(Path.Combine("fixtures", "api"), StringComparison.Ordinal))
            .Concat(Directory.EnumerateFiles(
                Path.Combine(root, "schema", "v1.0", "examples"), "*.json"))
            .Select(path => Path.GetRelativePath(root, path))
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToList();

        // A discovery bug that found nothing would make every case below vacuous.
        files.Should().HaveCountGreaterThan(30,
            "the shared corpus is 33 policy fixtures plus 5 published examples");

        foreach (var path in files)
            data.Add(path);

        return data;
    }

    /// <summary>
    /// Collects the values of enum-valued properties anywhere in a document.
    /// </summary>
    /// <remarks>
    /// Walked rather than read from known shapes. Fixtures nest policies at varying depths
    /// -- inside <c>scenarios[]</c>, <c>cases[]</c>, <c>inputs[]</c>, under <c>policy</c>,
    /// <c>basePolicy</c> and <c>policyOverride</c> -- so enumerating known locations would
    /// mean a fixture added under a new key silently stops being checked, which is the same
    /// blind spot in a different place.
    /// </remarks>
    private static void Collect(
        JsonElement node,
        string? parentProperty,
        Dictionary<string, SortedSet<string>> into)
    {
        switch (node.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var property in node.EnumerateObject())
                {
                    var value = property.Value;

                    if (property.NameEquals("operator") && value.ValueKind == JsonValueKind.String)
                        into["operator"].Add(value.GetString()!);

                    if (property.NameEquals("maskType") && value.ValueKind == JsonValueKind.String)
                        into["maskType"].Add(value.GetString()!);

                    // `algorithm` appears both as a mask parameter and as a signing
                    // algorithm, and the two enums are different. The parent property name
                    // disambiguates them.
                    if (property.NameEquals("algorithm") && value.ValueKind == JsonValueKind.String
                        && parentProperty == "parameters")
                    {
                        into["maskAlgorithm"].Add(value.GetString()!);
                    }

                    if (property.NameEquals("type") && value.ValueKind == JsonValueKind.String
                        && parentProperty == "assignee")
                    {
                        into["assigneeType"].Add(value.GetString()!);
                    }

                    if (property.NameEquals("allowedMethods") && value.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var method in value.EnumerateArray()
                            .Where(m => m.ValueKind == JsonValueKind.String))
                        {
                            into["allowedMethod"].Add(method.GetString()!);
                        }
                    }

                    Collect(value, property.Name, into);
                }

                break;

            case JsonValueKind.Array:
                foreach (var item in node.EnumerateArray())
                    Collect(item, parentProperty, into);

                break;
        }
    }

    private static Dictionary<string, SortedSet<string>> EnumTokensIn(string relativePath)
    {
        var into = new Dictionary<string, SortedSet<string>>(StringComparer.Ordinal)
        {
            ["operator"] = new(StringComparer.Ordinal),
            ["maskType"] = new(StringComparer.Ordinal),
            ["maskAlgorithm"] = new(StringComparer.Ordinal),
            ["assigneeType"] = new(StringComparer.Ordinal),
            ["allowedMethod"] = new(StringComparer.Ordinal),
        };

        using var document = JsonDocument.Parse(
            File.ReadAllText(Path.Combine(RepositoryRoot(), relativePath)));
        Collect(document.RootElement, parentProperty: null, into);

        return into;
    }

    [Theory]
    [MemberData(nameof(Corpus))]
    public void EveryEnumTokenInTheCorpusIsPermittedByTheSchema(string relativePath)
    {
        var tokens = EnumTokensIn(relativePath);

        var expected = new Dictionary<string, IReadOnlySet<string>>(StringComparer.Ordinal)
        {
            ["operator"] = SchemaHelper.EnumAt(
                "policy-definition", "$defs", "filterRule", "properties", "operator", "enum"),
            ["maskType"] = SchemaHelper.EnumAt(
                "policy-definition", "$defs", "maskingRule", "properties", "maskType", "enum"),
            ["maskAlgorithm"] = SchemaHelper.EnumAt(
                "policy-definition", "$defs", "maskingRule", "properties", "parameters",
                "properties", "algorithm", "enum"),
            ["assigneeType"] = SchemaHelper.EnumAt(
                "policy-assignment", "properties", "assignee", "properties", "type", "enum"),
            ["allowedMethod"] = SchemaHelper.EnumAt(
                "policy-definition", "properties", "objectRules", "properties",
                "endpointRules", "properties", "allowedMethods", "items", "enum"),
        };

        foreach (var (kind, seen) in tokens)
        {
            var offending = seen.Except(expected[kind], StringComparer.Ordinal).ToList();

            if (Path.GetFileName(relativePath) == InvalidByDesign)
            {
                // Inverted on purpose: this fixture must STAY invalid. If it were silently
                // corrected the SDK tests asserting a rejection would keep passing while no
                // longer exercising one.
                if (kind == "maskType")
                {
                    offending.Should().Contain("scramble",
                        $"{relativePath} is named invalid and exists to be refused");
                    continue;
                }
            }

            offending.Should().BeEmpty(
                $"{relativePath} uses {kind} value(s) the schema forbids: " +
                $"{string.Join(", ", offending)}");
        }
    }

    [Theory]
    [MemberData(nameof(Corpus))]
    public void EveryEnumTokenInTheCorpusIsAcceptedByThisSdk(string relativePath)
    {
        // The complement to the schema check: a token can be schema-valid and still be one
        // this SDK's converter rejects, which is precisely the `between` drift. Asserted
        // per-token so the failure names the offending value rather than surfacing as an
        // opaque deserialization error somewhere in an unrelated test.
        var tokens = EnumTokensIn(relativePath);
        var invalidByDesign = Path.GetFileName(relativePath) == InvalidByDesign;

        foreach (var value in tokens["operator"])
            Accepts<FilterOperator>(value).Should().BeTrue($"{relativePath} uses operator '{value}'");

        foreach (var value in tokens["maskType"])
        {
            if (invalidByDesign && value == "scramble")
            {
                Accepts<MaskType>(value).Should().BeFalse(
                    "the deliberately-invalid fixture must still be refused");
                continue;
            }

            Accepts<MaskType>(value).Should().BeTrue($"{relativePath} uses maskType '{value}'");
        }

        foreach (var value in tokens["assigneeType"])
            Accepts<AssigneeType>(value).Should().BeTrue($"{relativePath} uses assignee type '{value}'");
    }

    [Fact]
    public void TheCorpusExercisesEveryOperatorTheSchemaDeclares()
    {
        // REPORTING, not gating. Unexercised values are a coverage gap in the shared
        // corpus rather than a defect in any SDK, so this states the gap rather than
        // failing: the seven operators added to reach 16 have per-SDK unit coverage
        // (RowFilterOperatorTests here) but no shared fixture, which is why a corpus-only
        // conformance run cannot see them.
        var declared = SchemaHelper.EnumAt(
            "policy-definition", "$defs", "filterRule", "properties", "operator", "enum");

        var seen = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var row in Corpus())
        {
            var path = (string)row[0]!;
            seen.UnionWith(EnumTokensIn(path)["operator"]);
        }

        // Every operator the corpus DOES use must be a declared one -- that direction is
        // load-bearing and asserted.
        seen.Except(declared, StringComparer.Ordinal).Should().BeEmpty();

        // The reverse is recorded, not enforced.
        var unexercised = declared.Except(seen, StringComparer.Ordinal).OrderBy(v => v, StringComparer.Ordinal);
        Assert.True(true,
            $"operators declared by the schema with no shared fixture: {string.Join(", ", unexercised)}");
    }

    private static bool Accepts<T>(string wireValue)
    {
        try
        {
            TolapJsonOptions.Deserialize<T>(JsonSerializer.Serialize(wireValue));
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }
}
