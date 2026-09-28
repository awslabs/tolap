using System.Text.Json;
using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

public class EnforcementEngineTests
{
    // -- ValidateAccess tests from fixture --

    [Fact]
    public void ValidateAccess_AllowedObject_ReturnsAllowed()
    {
        var policy = CreatePolicyWithObjectRules(
            allowedObjects: new[] { "patients", "encounters" },
            hiddenObjects: new[] { "audit_log" });

        var result = EnforcementEngine.ValidateAccess("patients", policy);

        result.Allowed.Should().BeTrue();
    }

    [Fact]
    public void ValidateAccess_HiddenObject_ReturnsDenied()
    {
        var policy = CreatePolicyWithObjectRules(
            allowedObjects: new[] { "patients", "encounters" },
            hiddenObjects: new[] { "audit_log" });

        var result = EnforcementEngine.ValidateAccess("audit_log", policy);

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be("object is hidden");
    }

    [Fact]
    public void ValidateAccess_UnlistedObject_ReturnsDenied()
    {
        var policy = CreatePolicyWithObjectRules(
            allowedObjects: new[] { "patients", "encounters" },
            hiddenObjects: null);

        var result = EnforcementEngine.ValidateAccess("medications", policy);

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be("object not in allowed set");
    }

    // -- ValidateFieldAccess tests from fixtures --

    private const string FieldAccessAllowedSetFixture = "enforcement/validate-field-access-allowed-set.json";

    /// <summary>Asserted so that a dropped case fails the suite rather than shrinking it quietly.</summary>
    private const int FieldAccessAllowedSetCaseCount = 16;

    private static IReadOnlyList<JsonElement> FieldAccessAllowedSetCases()
        => FixtureHelper.ReadFixtureAsJson(FieldAccessAllowedSetFixture).Clone()
            .GetProperty("cases").EnumerateArray().Select(c => c.Clone()).ToList();

    public static IEnumerable<object[]> FieldAccessAllowedSetCaseNames()
        => FieldAccessAllowedSetCases().Select(c => new object[] { c.GetProperty("name").GetString()! });

    [Fact]
    public void ValidateFieldAccess_AllowedSet_CarriesEveryCase()
    {
        var names = FieldAccessAllowedSetCases().Select(c => c.GetProperty("name").GetString()).ToList();

        names.Should().HaveCount(FieldAccessAllowedSetCaseCount);
        names.Distinct(StringComparer.Ordinal).Should().HaveCount(names.Count);
    }

    /// <summary>
    /// Shared with the Python and TypeScript runners. Order is part of the contract: both
    /// lists follow the input order.
    /// </summary>
    [Theory]
    [MemberData(nameof(FieldAccessAllowedSetCaseNames))]
    public void ValidateFieldAccess_AllowedSet_MatchesTheSharedCorpus(string caseName)
    {
        var testCase = FieldAccessAllowedSetCases().Single(c => c.GetProperty("name").GetString() == caseName);
        var input = testCase.GetProperty("input");
        var fields = input.GetProperty("fields").EnumerateArray().Select(f => f.GetString()!).ToArray();
        var objectName = input.TryGetProperty("objectName", out var o) ? o.GetString() : null;
        var policy = TolapJsonOptions.Deserialize<EffectivePolicy>(testCase.GetProperty("policy").GetRawText());

        var result = EnforcementEngine.ValidateFieldAccess(fields, policy, objectName);

        var expected = testCase.GetProperty("expected");
        result.Allowed.Should().Equal(
            expected.GetProperty("allowed").EnumerateArray().Select(f => f.GetString()), caseName);
        result.Denied.Should().Equal(
            expected.GetProperty("denied").EnumerateArray().Select(f => f.GetString()), caseName);
    }

    /// <summary>
    /// The original two-argument overload must keep its exact signature, so assemblies
    /// compiled against it still bind, and must behave as the three-argument overload with a
    /// null object name.
    /// </summary>
    [Fact]
    public void ValidateFieldAccess_TwoArgumentOverload_KeepsItsSignatureAndDelegatesWithNullObject()
    {
        var method = typeof(EnforcementEngine).GetMethod(
            nameof(EnforcementEngine.ValidateFieldAccess),
            new[] { typeof(string[]), typeof(EffectivePolicy) });
        method.Should().NotBeNull("the two-argument overload is part of the binary contract");
        method!.ReturnType.Should().Be(typeof(FieldAccessResult));
        method.IsStatic.Should().BeTrue();
        method.IsPublic.Should().BeTrue();

        var threeArg = typeof(EnforcementEngine).GetMethod(
            nameof(EnforcementEngine.ValidateFieldAccess),
            new[] { typeof(string[]), typeof(EffectivePolicy), typeof(string) });
        threeArg.Should().NotBeNull();
        threeArg!.GetParameters()[2].HasDefaultValue.Should().BeFalse(
            "the object-name overload is separate and has no default value");

        var policy = CreatePolicyWithFieldRules(
            allowedFields: new[] { "patients.name", "*.id" },
            hiddenFields: null);
        var fields = new[] { "name", "encounters.name", "id", "patients.id" };

        // Called directly: a bare 'name' stays bare, so 'patients.name' allows it.
        var result = EnforcementEngine.ValidateFieldAccess(fields, policy);
        var viaNull = EnforcementEngine.ValidateFieldAccess(fields, policy, null);

        result.Allowed.Should().Equal("name", "id");
        result.Denied.Should().Equal("encounters.name", "patients.id");
        result.Allowed.Should().Equal(viaNull.Allowed);
        result.Denied.Should().Equal(viaNull.Denied);
    }

    [Fact]
    public void ValidateFieldAccess_HiddenFields_DeniesHiddenFields()
    {
        var policy = CreatePolicyWithFieldRules(
            allowedFields: null,
            hiddenFields: new[] { "ssn", "date_of_birth" });

        var result = EnforcementEngine.ValidateFieldAccess(
            new[] { "name", "ssn", "region", "date_of_birth" }, policy);

        result.Allowed.Should().BeEquivalentTo(new[] { "name", "region" });
        result.Denied.Should().BeEquivalentTo(new[] { "ssn", "date_of_birth" });
    }

    // -- ApplyFieldMasking tests from fixture --

    [Fact]
    public void ApplyFieldMasking_AllMaskTypes_AppliesCorrectly()
    {
        var maskedFields = new MaskingRule[]
        {
            new("name", MaskType.Partial, new MaskingParameters(ShowFirst: 1, ShowLast: 0, MaskChar: '*')),
            new("email", MaskType.Hash, new MaskingParameters(Algorithm: "sha256")),
            new("phone", MaskType.Full, new MaskingParameters(MaskChar: '*')),
            new("ssn", MaskType.Null),
            new("notes", MaskType.Redact)
        };

        var policy = new EffectivePolicy(
            Version: "1.0", UserId: null, TenantId: null, SourceConnectionId: null,
            ResolvedAt: null, ExpiresAt: null,
            SourceProfiles: Array.Empty<string>(),
            Permissions: new PolicyPermissions(true),
            ObjectRules: new ObjectRules(
                FieldRules: new FieldRules(MaskedFields: maskedFields)));

        var record = new Dictionary<string, object?>
        {
            ["name"] = "John Smith",
            ["email"] = "john.smith@example.com",
            ["phone"] = "555-123-4567",
            ["ssn"] = "123-45-6789",
            ["notes"] = "Patient prefers morning appointments"
        };

        var result = EnforcementEngine.ApplyFieldMasking(record, policy);

        // Partial: show first 1 char, mask rest
        result["name"].Should().Be("J*********");

        // Hash: SHA256 hex truncated to 16 chars
        var emailHash = result["email"] as string;
        emailHash.Should().NotBeNull();
        emailHash!.Length.Should().Be(16);
        emailHash.Should().MatchRegex("^[0-9a-f]{16}$");

        // Full: all masked
        result["phone"].Should().Be("************");

        // Null: null
        result["ssn"].Should().BeNull();

        // Redact: [REDACTED]
        result["notes"].Should().Be("[REDACTED]");
    }

    [Fact]
    public void ApplyFieldMasking_NoRules_ReturnsOriginal()
    {
        var policy = new EffectivePolicy(
            Version: "1.0", UserId: null, TenantId: null, SourceConnectionId: null,
            ResolvedAt: null, ExpiresAt: null,
            SourceProfiles: Array.Empty<string>(),
            Permissions: new PolicyPermissions(true));

        var record = new Dictionary<string, object?>
        {
            ["name"] = "John Smith",
            ["email"] = "john@example.com"
        };

        var result = EnforcementEngine.ApplyFieldMasking(record, policy);

        result["name"].Should().Be("John Smith");
        result["email"].Should().Be("john@example.com");
    }

    // -- FilterByTags tests from fixture --

    [Fact]
    public void FilterByTags_AllowedAndDenied_FiltersCorrectly()
    {
        var policy = new EffectivePolicy(
            Version: "1.0", UserId: null, TenantId: null, SourceConnectionId: null,
            ResolvedAt: null, ExpiresAt: null,
            SourceProfiles: Array.Empty<string>(),
            Permissions: new PolicyPermissions(true),
            ObjectRules: new ObjectRules(
                TagRules: new TagRules(
                    AllowedTags: new[] { "public", "internal", "research", "clinical-summary" },
                    DeniedTags: new[] { "classified", "legal-hold" })));

        var results = new List<Dictionary<string, object?>>
        {
            new() { ["id"] = "doc-1", ["title"] = "Public Research Paper", ["tags"] = new[] { "public", "research" } },
            new() { ["id"] = "doc-2", ["title"] = "Internal Memo", ["tags"] = new[] { "internal", "research" } },
            new() { ["id"] = "doc-3", ["title"] = "Classified Report", ["tags"] = new[] { "classified", "research" } },
            new() { ["id"] = "doc-4", ["title"] = "Legal Hold Document", ["tags"] = new[] { "internal", "legal-hold" } },
            new() { ["id"] = "doc-5", ["title"] = "Clinical Summary", ["tags"] = new[] { "clinical-summary", "public" } }
        };

        var filtered = EnforcementEngine.FilterByTags(results, policy);

        filtered.Should().HaveCount(3);
        filtered.Select(r => r["id"]).Should().BeEquivalentTo(new[] { "doc-1", "doc-2", "doc-5" });
    }

    // -- ValidateEndpoint tests from fixture --

    [Fact]
    public void ValidateEndpoint_AllowedPathAndMethod_ReturnsAllowed()
    {
        var policy = CreatePolicyWithEndpointRules(
            allowedEndpoints: new[] { "/api/v1/patients", "/api/v1/patients/*" },
            hiddenEndpoints: new[] { "/api/v1/admin/*" },
            allowedMethods: new[] { "GET", "HEAD", "OPTIONS" });

        var result = EnforcementEngine.ValidateEndpoint("/api/v1/patients", "GET", policy);

        result.Allowed.Should().BeTrue();
    }

    [Fact]
    public void ValidateEndpoint_HiddenEndpoint_ReturnsDenied()
    {
        var policy = CreatePolicyWithEndpointRules(
            allowedEndpoints: new[] { "/api/v1/patients", "/api/v1/patients/*" },
            hiddenEndpoints: new[] { "/api/v1/admin/*" },
            allowedMethods: new[] { "GET", "HEAD", "OPTIONS" });

        var result = EnforcementEngine.ValidateEndpoint("/api/v1/admin/users", "GET", policy);

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be("endpoint is hidden");
    }

    [Fact]
    public void ValidateEndpoint_DisallowedMethod_ReturnsDenied()
    {
        var policy = CreatePolicyWithEndpointRules(
            allowedEndpoints: new[] { "/api/v1/patients" },
            hiddenEndpoints: null,
            allowedMethods: new[] { "GET", "HEAD", "OPTIONS" });

        var result = EnforcementEngine.ValidateEndpoint("/api/v1/patients", "POST", policy);

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be("method not allowed");
    }

    // -- ApplyResultLimit tests --

    [Fact]
    public void ApplyResultLimit_ExceedsLimit_Truncates()
    {
        var policy = new EffectivePolicy(
            Version: "1.0", UserId: null, TenantId: null, SourceConnectionId: null,
            ResolvedAt: null, ExpiresAt: null,
            SourceProfiles: Array.Empty<string>(),
            Permissions: new PolicyPermissions(true),
            Limits: new PolicyLimits(MaxResults: 2));

        var results = new List<string> { "a", "b", "c", "d", "e" };

        var limited = EnforcementEngine.ApplyResultLimit(results, policy);

        limited.Should().HaveCount(2);
        limited.Should().BeEquivalentTo(new[] { "a", "b" });
    }

    [Fact]
    public void ApplyResultLimit_WithinLimit_ReturnsAll()
    {
        var policy = new EffectivePolicy(
            Version: "1.0", UserId: null, TenantId: null, SourceConnectionId: null,
            ResolvedAt: null, ExpiresAt: null,
            SourceProfiles: Array.Empty<string>(),
            Permissions: new PolicyPermissions(true),
            Limits: new PolicyLimits(MaxResults: 100));

        var results = new List<string> { "a", "b", "c" };

        var limited = EnforcementEngine.ApplyResultLimit(results, policy);

        limited.Should().HaveCount(3);
    }

    // -- Helper methods --

    private static EffectivePolicy CreatePolicyWithObjectRules(
        string[]? allowedObjects,
        string[]? hiddenObjects)
    {
        return new EffectivePolicy(
            Version: "1.0", UserId: null, TenantId: null, SourceConnectionId: null,
            ResolvedAt: null, ExpiresAt: null,
            SourceProfiles: Array.Empty<string>(),
            Permissions: new PolicyPermissions(true),
            ObjectRules: new ObjectRules(
                AllowedObjects: allowedObjects,
                HiddenObjects: hiddenObjects));
    }

    private static EffectivePolicy CreatePolicyWithFieldRules(
        string[]? allowedFields,
        string[]? hiddenFields)
    {
        return new EffectivePolicy(
            Version: "1.0", UserId: null, TenantId: null, SourceConnectionId: null,
            ResolvedAt: null, ExpiresAt: null,
            SourceProfiles: Array.Empty<string>(),
            Permissions: new PolicyPermissions(true),
            ObjectRules: new ObjectRules(
                FieldRules: new FieldRules(
                    AllowedFields: allowedFields,
                    HiddenFields: hiddenFields)));
    }

    private static EffectivePolicy CreatePolicyWithEndpointRules(
        string[]? allowedEndpoints,
        string[]? hiddenEndpoints,
        string[]? allowedMethods)
    {
        return new EffectivePolicy(
            Version: "1.0", UserId: null, TenantId: null, SourceConnectionId: null,
            ResolvedAt: null, ExpiresAt: null,
            SourceProfiles: Array.Empty<string>(),
            Permissions: new PolicyPermissions(true),
            ObjectRules: new ObjectRules(
                EndpointRules: new EndpointRules(
                    AllowedEndpoints: allowedEndpoints,
                    HiddenEndpoints: hiddenEndpoints,
                    AllowedMethods: allowedMethods)));
    }
}
