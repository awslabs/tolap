using System.Text.Json;
using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// The security-context envelope against its published schema
/// (docs/canonical-enforcement-spec.md sections 2, 14 and 15.3).
/// </summary>
/// <remarks>
/// <para>Separate from <see cref="SchemaConformanceTests"/> because it checks a different
/// kind of thing. That file compares native enums against the two <b>policy</b> schemas.
/// This one checks the <b>signed envelope</b> — a shape that, until
/// <c>security-context.schema.json</c> existed, had no published contract at all: it was
/// prose in §1-§2 plus two known-answer fixtures. That was survivable for <c>jti</c>, one
/// opaque string, but a delegation hop is a nested object with five fields and a closed
/// enumeration, and <see cref="PrincipalType"/> would otherwise be the only enum in the
/// model with nothing to compare itself against.</para>
/// <para>The schema describes the <b>canonical signing projection</b>, not this SDK's
/// <see cref="SecurityContext"/>. The three SDKs deliberately keep different native
/// models and converge only at the signed form, so the projection is the only shape all
/// three share — which is why the assertions below run against
/// <see cref="SecurityContextSigner.BuildCanonicalPayload"/> output rather than against a
/// serialized context object.</para>
/// </remarks>
public class SecurityContextSchemaConformanceTests
{
    private const string ContextSchema = "security-context";

    private static readonly string[] PrincipalTypePath =
        ["$defs", "delegationHop", "properties", "principalType", "enum"];

    private static IReadOnlySet<string> WireValues<T>() where T : struct, Enum =>
        Enum.GetValues<T>()
            .Select(value => JsonSerializer.Deserialize<string>(
                TolapJsonOptions.Serialize(value))!)
            .ToHashSet(StringComparer.Ordinal);

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

    // -- PrincipalType --

    [Fact]
    public void PrincipalType_MatchesTheSchemaExactly_InBothDirections()
    {
        var schemaValues = SchemaHelper.EnumAt(ContextSchema, PrincipalTypePath);
        var sdkValues = WireValues<PrincipalType>();

        sdkValues.Should().BeEquivalentTo(schemaValues,
            "a principal type the schema permits but this SDK cannot express makes a valid "
            + "delegation chain undeserializable, and one this SDK accepts but the schema "
            + "forbids reaches chain validation as a value no narrowing rule covers");
    }

    [Fact]
    public void PrincipalType_EverySchemaValueIsAcceptedOnDeserialization()
    {
        // Read and Write are separate switch arms in the converter, so one can gain a value
        // without the other. This is the direction that matters for a hop arriving over the
        // wire.
        foreach (var value in SchemaHelper.EnumAt(ContextSchema, PrincipalTypePath))
        {
            Accepts<PrincipalType>(value).Should().BeTrue(
                $"'{value}' is schema-valid, so a hop carrying it must deserialize");
        }
    }

    [Theory]
    [InlineData("daemon")]
    [InlineData("USER")]
    [InlineData("serviceAccount")]
    [InlineData("")]
    public void PrincipalType_AValueOutsideTheSchemaEnumIsRejected(string value)
    {
        // Fail closed at the boundary, as an unknown mask type or filter operator is. Note
        // `serviceAccount` is deliberately here: it is valid for AssigneeType and must NOT
        // be valid for a delegation hop, so the two closed sets cannot be confused.
        SchemaHelper.EnumAt(ContextSchema, PrincipalTypePath).Should().NotContain(value);

        Accepts<PrincipalType>(value).Should().BeFalse(
            $"'{value}' is outside the schema enum and must be refused at deserialization");
    }

    // -- The envelope's shape --

    private static (string Payload, JsonElement Fixture) CanonicalPayloadFor(string fixtureName)
    {
        var root = FixtureHelper.ReadFixtureAsJson($"signing/{fixtureName}.json");
        var policy = TolapJsonOptions.Deserialize<EffectivePolicy>(
            root.GetProperty("payload").GetRawText());

        var chain = root.TryGetProperty("delegationChain", out var chainJson)
            ? TolapJsonOptions.Deserialize<DelegationHop[]>(chainJson.GetRawText())
            : null;

        var context = new SecurityContext(
            Version: policy.Version,
            UserId: policy.UserId!,
            TenantId: policy.TenantId!,
            IssuedAt: policy.ResolvedAt!.Value,
            ExpiresAt: policy.ExpiresAt!.Value,
            Policies: new[] { policy },
            DeclaredPurpose: root.TryGetProperty("declaredPurpose", out var purpose)
                ? purpose.GetString()
                : null,
            DelegationChain: chain);

        return (SecurityContextSigner.BuildCanonicalPayload(context), root);
    }

    public static TheoryData<string> SigningFixtures() => new()
    {
        "hmac-sha256-known-answer",
        "hmac-sha256-subsecond",
        "hmac-sha256-purpose-bound"
    };

    [Theory]
    [MemberData(nameof(SigningFixtures))]
    public void CanonicalPayload_CarriesOnlyPropertiesTheSchemaDeclares(string fixtureName)
    {
        // The whole point of publishing the envelope schema. Before it existed a signing
        // fixture could carry any field at all and nothing would notice -- and a field
        // present in the payload but absent from the schema is either an unsigned field
        // someone believed was signed, or a signed one no other SDK knows to produce.
        var declared = SchemaHelper.Load(ContextSchema)
            .GetProperty("properties")
            .EnumerateObject()
            .Select(property => property.Name)
            .ToHashSet(StringComparer.Ordinal);

        var (payload, _) = CanonicalPayloadFor(fixtureName);
        using var document = JsonDocument.Parse(payload);

        var emitted = document.RootElement.EnumerateObject()
            .Select(property => property.Name)
            .ToList();

        emitted.Should().OnlyContain(name => declared.Contains(name),
            "every key in the canonical payload must be one security-context.schema.json declares");
    }

    [Theory]
    [MemberData(nameof(SigningFixtures))]
    public void CanonicalPayload_CarriesEveryRequiredProperty(string fixtureName)
    {
        var required = SchemaHelper.Load(ContextSchema)
            .GetProperty("required")
            .EnumerateArray()
            .Select(value => value.GetString()!)
            .ToList();

        var (payload, _) = CanonicalPayloadFor(fixtureName);
        using var document = JsonDocument.Parse(payload);

        foreach (var name in required)
        {
            document.RootElement.TryGetProperty(name, out _).Should().BeTrue(
                $"'{name}' is required by the envelope schema");
        }
    }

    [Fact]
    public void CanonicalPayload_OmitsTheOptionalPropertiesWhenAbsent()
    {
        // §2 rule 6, asserted against the schema's own list of optional properties rather
        // than a hardcoded three. A field emitted as null or "" would appear here, and would
        // also give one context two valid signatures.
        var declared = SchemaHelper.Load(ContextSchema).GetProperty("properties");
        var required = SchemaHelper.Load(ContextSchema).GetProperty("required")
            .EnumerateArray().Select(v => v.GetString()!).ToHashSet(StringComparer.Ordinal);

        var optional = declared.EnumerateObject()
            .Select(property => property.Name)
            .Where(name => !required.Contains(name) && name != "$schema")
            .ToList();

        optional.Should().NotBeEmpty("the envelope has optional fields; §2 rule 6 is about them");

        var (payload, _) = CanonicalPayloadFor("hmac-sha256-known-answer");
        using var document = JsonDocument.Parse(payload);

        foreach (var name in optional)
        {
            document.RootElement.TryGetProperty(name, out _).Should().BeFalse(
                $"'{name}' is absent from this context and must be omitted entirely, not "
                + "emitted as null -- that is what keeps the pre-existing signatures valid");
        }
    }

    [Fact]
    public void EveryDelegationHopInTheSharedCorpusMatchesTheSchemasShape()
    {
        // The hop shape is now published, so a fixture inventing a field would be caught.
        // Checked property-name-wise here; the Python suite owns full JSON Schema document
        // validation, since this repository deliberately has one validating runner (§14).
        var hopSchema = SchemaHelper.Load(ContextSchema)
            .GetProperty("$defs").GetProperty("delegationHop");

        var declared = hopSchema.GetProperty("properties")
            .EnumerateObject()
            .Select(property => property.Name)
            .ToHashSet(StringComparer.Ordinal);

        var required = hopSchema.GetProperty("required")
            .EnumerateArray()
            .Select(value => value.GetString()!)
            .ToList();

        var cases = FixtureHelper
            .ReadFixtureAsJson("purpose-binding/delegation-chains.json")
            .GetProperty("cases");

        var hopsSeen = 0;

        foreach (var testCase in cases.EnumerateArray())
        {
            var chain = testCase.GetProperty("chain");
            if (chain.ValueKind != JsonValueKind.Array)
                continue;

            foreach (var hop in chain.EnumerateArray())
            {
                hopsSeen++;
                var name = testCase.GetProperty("name").GetString();

                foreach (var property in hop.EnumerateObject())
                {
                    declared.Should().Contain(property.Name,
                        $"case '{name}' carries a hop property the schema does not declare");
                }

                foreach (var requiredName in required)
                {
                    hop.TryGetProperty(requiredName, out _).Should().BeTrue(
                        $"case '{name}' has a hop missing required '{requiredName}'");
                }
            }
        }

        // A discovery bug that found no hops would make the loop above vacuous.
        hopsSeen.Should().BeGreaterThan(20, "the shared chain corpus carries many hops");
    }

    [Fact]
    public void TheDeliberatelySchemaInvalidCaseIsStillMarkedAsSuch()
    {
        // One chain case carries a mis-cased purpose, which the schema's lowercase pattern
        // forbids and the chain validator must still refuse -- the SDK deserializers do not
        // enforce schema patterns, so a chain assembled in code can contain it.
        //
        // Asserted positively, in both halves: the marker must be present, AND the value it
        // describes must actually still violate the pattern. If the fixture were quietly
        // corrected, the rejection it exists to exercise would stop happening while every
        // test still passed.
        var cases = FixtureHelper
            .ReadFixtureAsJson("purpose-binding/delegation-chains.json")
            .GetProperty("cases");

        var marked = cases.EnumerateArray()
            .Where(c => c.TryGetProperty("schemaInvalidByDesign", out _))
            .ToList();

        marked.Should().HaveCount(1, "exactly one case is invalid by design");

        var pattern = SchemaHelper.Load(ContextSchema)
            .GetProperty("$defs").GetProperty("delegationHop")
            .GetProperty("properties").GetProperty("declaredPurpose")
            .GetProperty("pattern").GetString()!;

        var offending = marked[0].GetProperty("chain").EnumerateArray()
            .Select(hop => hop.TryGetProperty("declaredPurpose", out var p) ? p.GetString() : null)
            .Where(purpose => purpose is not null)
            .Where(purpose => !System.Text.RegularExpressions.Regex.IsMatch(purpose!, pattern))
            .ToList();

        offending.Should().NotBeEmpty(
            "the marked case must still contain a purpose the schema's pattern rejects");

        // And the behavioural half still holds: the validator denies it.
        var chain = TolapJsonOptions.Deserialize<DelegationHop[]>(
            marked[0].GetProperty("chain").GetRawText());

        DelegationChainValidator.Validate(chain).Allowed.Should().BeFalse(
            "a mis-cased purpose is denied by the validator, not merely by the schema");
    }

    [Fact]
    public void TheEnvelopeSchemaDoesNotUseACrossFileRef()
    {
        // Deliberate, and worth pinning: four validators read these files (Python's
        // jsonschema, the server's Ajv, and the two native SDK readers), each would need a
        // resolver configured with a local store, and one of them silently lacking it means
        // a schema that validates nothing while looking authoritative. No schema in
        // schema/v1.0 uses one; effective-policy duplicates maskingRule rather than
        // referencing policy-definition's. Section 14 handles the duplication with equality
        // tests instead.
        var raw = File.ReadAllText(
            Path.Combine(SchemaRootForAssertion(), "security-context.schema.json"));

        raw.Should().NotContain("https://tolap.dev/schema/v1.0/effective-policy.schema.json",
            "a cross-file $ref would need a resolver in all four validators");
    }

    [Fact]
    public void TheHopCeilingMatchesTheSchema()
    {
        // Spec section 15.3 states the ceiling twice -- once as `MaxHops`, once as `maxItems`
        // on `delegationChain` -- and section 14 requires the two to agree. Without this, one
        // could be raised and the other left behind: a chain the validator accepts and the
        // schema rejects, or worse, one the schema accepts and the validator walks.
        var raw = File.ReadAllText(
            Path.Combine(SchemaRootForAssertion(), "security-context.schema.json"));
        using var document = JsonDocument.Parse(raw);

        var maxItems = document.RootElement
            .GetProperty("properties")
            .GetProperty("delegationChain")
            .GetProperty("maxItems")
            .GetInt32();

        maxItems.Should().Be(DelegationChainValidator.MaxHops,
            "the validator's ceiling and the schema's maxItems are the same rule stated twice");
    }

    private static string SchemaRootForAssertion()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, "schema", "v1.0");
            if (Directory.Exists(candidate))
                return candidate;
            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("could not locate schema/v1.0");
    }
}
