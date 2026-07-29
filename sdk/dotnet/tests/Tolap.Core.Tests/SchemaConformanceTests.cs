using System.Text.Json;
using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// The native enums must match the published schema's enums, set for set
/// (docs/canonical-enforcement-spec.md section 14).
/// </summary>
/// <remarks>
/// <c>schema/v1.0/*.json</c> is the published contract. This SDK re-declares parts of it
/// as C# enums plus the switch arms in the <see cref="TolapJsonOptions"/> converters, and
/// those declarations drift silently unless something compares them -- which nothing in
/// this suite did before this file: no .NET test read <c>schema/v1.0/</c> at all.
/// <para>
/// Two drifts had already happened. The schema's row-filter operator enum grew to 16
/// values while Python and TypeScript declared 9, so a schema-valid
/// <c>{"operator": "between"}</c> policy threw an uncaught <c>KeyError</c> in Python,
/// silently dropped every row in TypeScript, and enforced correctly here -- passing
/// signature verification in all three, because the canonical payload covers the policy
/// verbatim, while producing three different access outcomes. And the mask
/// <c>parameters.algorithm</c> enum permits <c>sha256|sha512|blake2b</c> while this SDK
/// and Python hardcoded SHA-256 and ignored it, so one policy produced a different
/// pseudonym per language.
/// </para>
/// <para>
/// Three properties make this able to catch the next one. The expected values are read
/// from the schema file on disk, never restated here -- a copy in the test is a second
/// thing free to drift. Both directions are asserted: schema-to-SDK alone misses an SDK
/// that accepts what the schema forbids, and SDK-to-schema alone misses the
/// <c>between</c> case. And the assertions are unconditional, so a schema
/// reorganization fails loudly instead of skipping.
/// </para>
/// <para>
/// The wire spellings are obtained by round-tripping through the JSON converters rather
/// than from the enum member names, because the converters are this SDK's actual
/// acceptance surface: the integer-backed enums carry no wire value of their own, and a
/// converter missing an arm rejects a schema-valid policy no matter what the enum
/// declares.
/// </para>
/// </remarks>
public class SchemaConformanceTests
{
    private const string PolicyDefinition = "policy-definition";
    private const string EffectivePolicySchema = "effective-policy";
    private const string PolicyAssignment = "policy-assignment";

    // The keyword path to each enum in the published schema, held as data so a missing
    // path names the enum that moved rather than failing somewhere anonymous.
    private static readonly string[] OperatorPath =
        ["$defs", "filterRule", "properties", "operator", "enum"];

    private static readonly string[] MaskTypePath =
        ["$defs", "maskingRule", "properties", "maskType", "enum"];

    private static readonly string[] MaskAlgorithmPath =
        ["$defs", "maskingRule", "properties", "parameters", "properties", "algorithm", "enum"];

    private static readonly string[] AssigneeTypePath =
        ["properties", "assignee", "properties", "type", "enum"];

    private static readonly string[] SigningAlgorithmPath =
        ["properties", "integrity", "properties", "algorithm", "enum"];

    // The effective-policy schema restates the operator and mask enums inline rather than
    // through $defs, so its paths differ from the definition schema's.
    private static readonly string[] EffectiveOperatorPath =
    [
        "properties", "objectRules", "properties", "rowFilters", "items",
        "properties", "operator", "enum"
    ];

    private static readonly string[] EffectiveMaskTypePath =
    [
        "properties", "objectRules", "properties", "fieldRules", "properties",
        "maskedFields", "items", "properties", "maskType", "enum"
    ];

    private static readonly string[] EffectiveMaskAlgorithmPath =
    [
        "properties", "objectRules", "properties", "fieldRules", "properties",
        "maskedFields", "items", "properties", "parameters", "properties",
        "algorithm", "enum"
    ];

    private static readonly string[] AllowedMethodsPath =
    [
        "properties", "objectRules", "properties", "endpointRules", "properties",
        "allowedMethods", "items", "enum"
    ];

    private static readonly string[] EffectiveAllowedMethodsPath = AllowedMethodsPath;

    /// <summary>
    /// The JSON spellings this SDK EMITS for every member of an enum, read back out of the
    /// converter rather than assumed.
    /// </summary>
    private static IReadOnlySet<string> WireValues<T>() where T : struct, Enum =>
        Enum.GetValues<T>()
            .Select(value => JsonSerializer.Deserialize<string>(
                TolapJsonOptions.Serialize(value))!)
            .ToHashSet(StringComparer.Ordinal);

    /// <summary>
    /// Whether this SDK ACCEPTS a wire spelling on the way in. Read and Write are separate
    /// switch statements in every converter, so one can gain an arm without the other.
    /// </summary>
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

    // -- The locator must fail rather than skip, or the whole file proves nothing --

    [Fact]
    public void SchemaLocator_MissingPath_ThrowsRatherThanReturningAnEmptySet()
    {
        var act = () => SchemaHelper.EnumAt(PolicyDefinition, "$defs", "notARule", "enum");

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*is missing at segment 'notARule'*");
    }

    [Fact]
    public void SchemaLocator_PathThatIsNotAnEnumList_Throws()
    {
        var act = () => SchemaHelper.EnumAt(PolicyDefinition, "$defs", "filterRule");

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*not a non-empty enum list*");
    }

    [Fact]
    public void SchemaLocator_MissingSchemaFile_ThrowsRatherThanSkipping()
    {
        var act = () => SchemaHelper.Load("no-such-schema");

        act.Should().Throw<FileNotFoundException>().WithMessage("*MUST NOT be skipped*");
    }

    // -- FilterOperator: 16 operators, the drift this file exists for --

    [Fact]
    public void FilterOperator_MatchesTheSchemaExactly_InBothDirections()
    {
        var schemaValues = SchemaHelper.EnumAt(PolicyDefinition, OperatorPath);
        var sdkValues = WireValues<FilterOperator>();

        sdkValues.Should().BeEquivalentTo(schemaValues,
            "an operator the schema permits but this SDK cannot express passes signature " +
            "verification and then behaves differently here than in the other SDKs, and an " +
            "operator this SDK emits but the schema forbids would be rejected by a " +
            "schema-validating peer");
    }

    [Fact]
    public void FilterOperator_EverySchemaValueIsAcceptedOnDeserialization()
    {
        // The Read direction specifically: the converter's Read and Write are separate
        // switches, so an operator this SDK can emit is not automatically one it can load.
        foreach (var value in SchemaHelper.EnumAt(PolicyDefinition, OperatorPath))
        {
            Accepts<FilterOperator>(value).Should().BeTrue(
                $"'{value}' is schema-valid, so a policy carrying it must deserialize " +
                "rather than throwing out of the deserializer");
        }
    }

    [Fact]
    public void FilterOperator_AValueOutsideTheSchemaEnumIsRejected()
    {
        // The complement: acceptance must be an allowlist, not a pass-through. An
        // unrecognized operator that deserialized to some default would enforce a filter
        // the policy author never wrote.
        var schemaValues = SchemaHelper.EnumAt(PolicyDefinition, OperatorPath);

        foreach (var value in new[] { "scramble", "EQUALS", "equals ", "regex", "" })
        {
            schemaValues.Should().NotContain(value, "test case is no longer out-of-schema");
            Accepts<FilterOperator>(value).Should().BeFalse($"'{value}' is not in the schema enum");
        }
    }

    [Fact]
    public void FilterOperator_TheTwoSchemasDeclareTheSameEnum()
    {
        // An effective policy is the merged product of definitions, so every operator a
        // definition can express has to survive resolution. The enum is duplicated in the
        // two schema files and a reviewer noticing is otherwise the only guard.
        var definition = SchemaHelper.EnumAt(PolicyDefinition, OperatorPath);
        var effective = SchemaHelper.EnumAt(EffectivePolicySchema, EffectiveOperatorPath);

        effective.Should().BeEquivalentTo(definition);
    }

    // -- MaskType --

    [Fact]
    public void MaskType_MatchesTheSchemaExactly_InBothDirections()
    {
        var schemaValues = SchemaHelper.EnumAt(PolicyDefinition, MaskTypePath);
        var sdkValues = WireValues<MaskType>();

        sdkValues.Should().BeEquivalentTo(schemaValues);
    }

    [Fact]
    public void MaskType_EverySchemaValueIsAcceptedOnDeserialization()
    {
        foreach (var value in SchemaHelper.EnumAt(PolicyDefinition, MaskTypePath))
        {
            Accepts<MaskType>(value).Should().BeTrue(
                $"'{value}' is schema-valid, so a policy carrying it must deserialize");
        }
    }

    [Fact]
    public void MaskType_AValueOutsideTheSchemaEnumIsRejected()
    {
        var schemaValues = SchemaHelper.EnumAt(PolicyDefinition, MaskTypePath);

        foreach (var value in new[] { "scramble", "REDACT", "Null", "hash ", "" })
        {
            schemaValues.Should().NotContain(value, "test case is no longer out-of-schema");
            Accepts<MaskType>(value).Should().BeFalse($"'{value}' is not in the schema enum");
        }
    }

    [Fact]
    public void MaskType_TheTwoSchemasDeclareTheSameEnum()
    {
        var definition = SchemaHelper.EnumAt(PolicyDefinition, MaskTypePath);
        var effective = SchemaHelper.EnumAt(EffectivePolicySchema, EffectiveMaskTypePath);

        effective.Should().BeEquivalentTo(definition);
    }

    [Fact]
    public void MaskType_EverySchemaValueRanksBelowTheUnknownRank()
    {
        // Unknown types rank most-restrictive so a typo cannot be downgraded into a weaker
        // known type during a merge (spec section 6). That safety net becomes a bug if it
        // catches a LEGITIMATE value: the mask would win every merge it should have lost.
        const int unknownRestrictiveness = 6;

        foreach (var value in SchemaHelper.EnumAt(PolicyDefinition, MaskTypePath))
        {
            var maskType = TolapJsonOptions.Deserialize<MaskType>(
                JsonSerializer.Serialize(value));

            maskType.Restrictiveness().Should().BeLessThan(unknownRestrictiveness,
                $"'{value}' is schema-valid and must not be treated as unrecognized");
        }
    }

    // -- Mask parameters.algorithm: not a native enum, so it needs its own check --

    /// <summary>
    /// Applies a <c>hash</c> mask through the public enforcement entry point with the given
    /// <c>algorithm</c> parameter.
    /// </summary>
    /// <remarks>
    /// The hash mask exists to be a cross-service join key, which only holds if every SDK
    /// computes the same digest for the same policy. This SDK and Python previously
    /// hardcoded SHA-256 and ignored the parameter while TypeScript honoured it, so a
    /// policy asking for <c>sha512</c> produced two different pseudonyms for one value.
    /// The schema's enum -- read from disk -- is the authority for what must work.
    /// </remarks>
    private static object? Hashed(string? algorithm)
    {
        var rule = new MaskingRule("email", MaskType.Hash, new MaskingParameters(Algorithm: algorithm));
        return EnforcementEngine.ApplyMask("john.smith@example.com", rule);
    }

    [Fact]
    public void MaskAlgorithm_EverySchemaPermittedValueActuallyHashes()
    {
        // Schema-to-SDK. Redacting is the correct response to an algorithm the runtime
        // cannot provide, but applying it to a value the schema permits silently destroys
        // data the policy author asked to have pseudonymized.
        foreach (var algorithm in SchemaHelper.EnumAt(PolicyDefinition, MaskAlgorithmPath))
        {
            var result = Hashed(algorithm);

            result.Should().NotBe("[REDACTED]",
                $"'{algorithm}' is schema-valid but this SDK cannot compute it, so the " +
                "field is redacted instead of pseudonymized");

            var digest = result.Should().BeOfType<string>().Subject;
            // Lower-case hex truncated to 16 characters (spec section 6): the rendering is
            // part of the join-key contract, so a differently-rendered digest is still a
            // divergence.
            digest.Should().HaveLength(16);
            digest.Should().Be(digest.ToLowerInvariant());
            digest.Should().MatchRegex("^[0-9a-f]{16}$");
        }
    }

    [Fact]
    public void MaskAlgorithm_TheSchemaPermittedValuesProduceDistinctDigests()
    {
        // A substituted algorithm is worse than a refusal: the field would look like a
        // valid pseudonym while failing to join against a service that honoured the
        // parameter as written.
        var algorithms = SchemaHelper.EnumAt(PolicyDefinition, MaskAlgorithmPath);

        var digests = algorithms.Select(Hashed).ToList();

        digests.Should().OnlyHaveUniqueItems();
        digests.Should().HaveCount(algorithms.Count);
    }

    [Fact]
    public void MaskAlgorithm_AValueOutsideTheSchemaEnumFailsClosed()
    {
        // SDK-to-schema. Resolving the parameter through a general lookup would accept
        // anything the runtime offers -- md5 included -- plus spellings the other two SDKs
        // reject, which is the original divergence in a new form.
        var permitted = SchemaHelper.EnumAt(PolicyDefinition, MaskAlgorithmPath);

        foreach (var algorithm in new[] { "md5", "sha1", "sha3-256", "sha384", "blake2s", "SHA256", "" })
        {
            permitted.Should().NotContain(algorithm, "test case is no longer out-of-schema");
            Hashed(algorithm).Should().Be("[REDACTED]",
                $"'{algorithm}' is outside the schema's enum and must fail closed");
        }
    }

    [Fact]
    public void MaskAlgorithm_TheDefaultWhenAbsentIsSha256()
    {
        // Spec section 6 fixes the default, so all three SDKs agree when it is omitted.
        Hashed(null).Should().Be(Hashed("sha256"));
        EnforcementEngine.ApplyMask("john.smith@example.com", new MaskingRule("email", MaskType.Hash))
            .Should().Be(Hashed("sha256"));
    }

    [Fact]
    public void MaskAlgorithm_TheTwoSchemasDeclareTheSameEnum()
    {
        var definition = SchemaHelper.EnumAt(PolicyDefinition, MaskAlgorithmPath);
        var effective = SchemaHelper.EnumAt(EffectivePolicySchema, EffectiveMaskAlgorithmPath);

        effective.Should().BeEquivalentTo(definition);
    }

    // -- AssigneeType --

    [Fact]
    public void AssigneeType_MatchesTheSchemaExactly_InBothDirections()
    {
        var schemaValues = SchemaHelper.EnumAt(PolicyAssignment, AssigneeTypePath);
        var sdkValues = WireValues<AssigneeType>();

        sdkValues.Should().BeEquivalentTo(schemaValues,
            "an assignee type the schema permits but this SDK cannot express means an " +
            "administrator's grant silently resolves to nothing");
    }

    [Fact]
    public void AssigneeType_EverySchemaValueIsAcceptedOnDeserialization()
    {
        foreach (var value in SchemaHelper.EnumAt(PolicyAssignment, AssigneeTypePath))
        {
            Accepts<AssigneeType>(value).Should().BeTrue(
                $"'{value}' is schema-valid, so an assignment carrying it must deserialize");
        }
    }

    [Fact]
    public void AssigneeType_AValueOutsideTheSchemaEnumIsRejected()
    {
        var schemaValues = SchemaHelper.EnumAt(PolicyAssignment, AssigneeTypePath);

        foreach (var value in new[] { "service_account", "USER", "team", "" })
        {
            schemaValues.Should().NotContain(value, "test case is no longer out-of-schema");
            Accepts<AssigneeType>(value).Should().BeFalse($"'{value}' is not in the schema enum");
        }
    }

    // -- SigningAlgorithm, including the deliberate ed25519 case --

    [Fact]
    public void SigningAlgorithm_MatchesTheSchemaExactly_InBothDirections()
    {
        // Including ed25519, which this SDK carries in order to REFUSE it.
        var schemaValues = SchemaHelper.EnumAt(EffectivePolicySchema, SigningAlgorithmPath);
        var sdkValues = WireValues<SigningAlgorithm>();

        sdkValues.Should().BeEquivalentTo(schemaValues,
            "an algorithm this SDK cannot name is an algorithm it cannot refuse by name");
    }

    [Fact]
    public void SigningAlgorithm_EverySchemaValueIsAcceptedOnDeserialization()
    {
        // A context naming ed25519 must LOAD, so that the refusal happens at the
        // verification step with a message naming the algorithm, rather than as an opaque
        // deserialization failure that cannot distinguish it from malformed JSON.
        foreach (var value in SchemaHelper.EnumAt(EffectivePolicySchema, SigningAlgorithmPath))
        {
            Accepts<SigningAlgorithm>(value).Should().BeTrue(
                $"'{value}' is schema-valid, so a context carrying it must deserialize");
        }
    }

    [Fact]
    public void SigningAlgorithm_Ed25519IsPresentInTheEnumRatherThanOmitted()
    {
        // Asserted explicitly, not just as a by-product of the set comparison above.
        // Removing the member would make that comparison pass by narrowing the enum
        // instead of by fixing anything, and would replace an explicit refusal with an
        // unrecognized-value path.
        SchemaHelper.EnumAt(EffectivePolicySchema, SigningAlgorithmPath)
            .Should().Contain("ed25519");
        WireValues<SigningAlgorithm>().Should().Contain("ed25519");
        TolapJsonOptions.Serialize(SigningAlgorithm.Ed25519).Should().Be("\"ed25519\"");
    }

    [Fact]
    public void SigningAlgorithm_Ed25519FailsClosedAtSigningTime()
    {
        // Present in the enum, refused at use: two separate claims. Being nameable is what
        // lets the refusal say which algorithm it refused; the refusal itself is what stops
        // an unsigned context being treated as signed.
        var act = () => SecurityContextSigner.Sign(Context(), "key", SigningAlgorithm.Ed25519);

        act.Should().Throw<NotSupportedException>().WithMessage("*Ed25519*");
    }

    [Fact]
    public void SigningAlgorithm_Ed25519OnValidation_DeniesRatherThanThrowing()
    {
        // A regression guard over a divergence this test found and that has since been
        // fixed: Validate used to let NotSupportedException escape, so the same
        // schema-valid input was a crash here and a denial in TypeScript. An enforcement
        // wrapper without a try around its verification step would surface a 500 rather
        // than refusing the request, and spec section 5 requires unenforceable inputs to
        // be denied rather than to abort the pass.
        //
        // ed25519 is schema-valid, so a signed context naming it reaches Validate through
        // ordinary deserialization -- no malformed input required, which is what makes
        // this reachable rather than theoretical.
        var signed = SecurityContextSigner.Sign(Context(), "key");
        var claimingEd25519 = signed with
        {
            Integrity = new IntegrityBlock(SigningAlgorithm.Ed25519, signed.Integrity!.Signature)
        };

        var act = () => SecurityContextSigner.Validate(claimingEd25519, "key");

        act.Should().NotThrow<NotSupportedException>(
            "an algorithm this SDK cannot verify is a validation FAILURE, never an " +
            "exception escaping an enforcement check");
        act().Should().BeFalse();
    }

    [Fact]
    public void SigningAlgorithm_TheHmacAlgorithmsAreTheOnesThatDoWork()
    {
        // The complement: the refusal above must not be the behaviour for all three.
        foreach (var algorithm in new[] { SigningAlgorithm.HmacSha256, SigningAlgorithm.HmacSha512 })
        {
            var signed = SecurityContextSigner.Sign(Context(), "key", algorithm);

            signed.Integrity!.Signature.Should().NotBeEmpty();
            signed.Integrity.Algorithm.Should().Be(algorithm);
            SecurityContextSigner.Validate(signed, "key").Should().BeTrue();
        }
    }

    // -- allowedMethods: duplicated the same way, same reasoning --

    [Fact]
    public void AllowedMethods_TheTwoSchemasDeclareTheSameEnum()
    {
        var definition = SchemaHelper.EnumAt(PolicyDefinition, AllowedMethodsPath);
        var effective = SchemaHelper.EnumAt(EffectivePolicySchema, EffectiveAllowedMethodsPath);

        effective.Should().BeEquivalentTo(definition);
    }

    [Fact]
    public void AllowedMethods_EverySchemaMethodIsClassifiedByTheWriteMapping()
    {
        // allowedMethods is a string array rather than a native enum, so the drift shows up
        // as a method the schema permits that the write-classification switch does not
        // recognize -- which would decide a write's permission by falling through rather
        // than by the policy.
        var methods = SchemaHelper.EnumAt(PolicyDefinition, AllowedMethodsPath);

        methods.Should().BeEquivalentTo(
            new[] { "GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE" },
            "the read-only and write methods below partition this set, so a new method " +
            "must be classified rather than silently landing in neither group");

        foreach (var method in new[] { "GET", "HEAD", "OPTIONS" })
        {
            methods.Should().Contain(method);
            EnforcementEngine.WriteOperationForMethod(method).Should().BeNull(
                $"{method} is a read and must not require a write permission");
        }

        foreach (var method in new[] { "POST", "PUT", "PATCH", "DELETE" })
        {
            methods.Should().Contain(method);
            EnforcementEngine.WriteOperationForMethod(method).Should().NotBeNull(
                $"{method} mutates and must map onto a write permission");
        }
    }

    private static SecurityContext Context() => new(
        Version: "1.0",
        UserId: "user-001",
        TenantId: "tenant-001",
        IssuedAt: DateTimeOffset.UtcNow,
        ExpiresAt: DateTimeOffset.UtcNow.AddHours(1),
        Policies: [
            new EffectivePolicy(
                Version: "1.0",
                UserId: "user-001",
                TenantId: "tenant-001",
                SourceConnectionId: "db:production:x",
                ResolvedAt: DateTimeOffset.UtcNow,
                ExpiresAt: DateTimeOffset.UtcNow.AddHours(1),
                SourceProfiles: ["schema-conformance"],
                Permissions: new PolicyPermissions(CanQuery: true))
        ]);
}
