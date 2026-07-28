using System.Text.Json;
using Tolap.Core;

namespace Tolap.Integration.Tests;

/// <summary>
/// Cross-SDK scenario loader for the .NET SDK.
/// Mirrors sdk/python/tests/integration/_scenarios.py and
/// sdk/typescript/packages/mcp/tests/integration/_scenarios.ts.
/// </summary>
public static class ScenarioHelpers
{
    public static readonly string RepoRoot = FindRepoRoot();
    public static readonly string ScenariosDir =
        Path.Combine(RepoRoot, "fixtures", "integration-scenarios");
    public static readonly string OpenFdaFixturesDir =
        Path.Combine(RepoRoot, "fixtures", "api", "openfda");
    public static readonly string SchemaSqlPath =
        Path.Combine(RepoRoot, "sdk", "python", "tests", "integration", "schema.sql");

    public static string LoadScenarioFile(string filename)
    {
        return File.ReadAllText(Path.Combine(ScenariosDir, filename));
    }

    public static EffectivePolicy PolicyFromJson(JsonElement element)
    {
        // Build a fully-populated EffectivePolicy from a partial scenario policy.
        // Required fields (UserId, TenantId, etc.) get scenario placeholders.
        var json = element.GetRawText();

        var partial = JsonSerializer.Deserialize<PartialPolicy>(json, TolapJsonOptions.Default)
                      ?? throw new InvalidOperationException("policy is null");

        var now = DateTimeOffset.UtcNow;
        return new EffectivePolicy(
            Version: partial.Version ?? "1.0",
            UserId: "scenario-user",
            TenantId: "scenario-tenant",
            SourceConnectionId: "scenario-source",
            ResolvedAt: now,
            ExpiresAt: now.AddHours(1),
            SourceProfiles: new[] { "scenario" },
            Permissions: partial.Permissions
                         ?? new PolicyPermissions(CanQuery: false),
            ObjectRules: partial.ObjectRules,
            Limits: partial.Limits,
            Integrity: null);
    }

    public static SecurityContext SignPolicy(EffectivePolicy policy, string signingKey, TimeSpan? ttl = null)
    {
        var ctx = SecurityContextBuilder.Build(
            "scenario-user", "scenario-tenant", new[] { policy }, ttl);
        return SecurityContextSigner.Sign(ctx, signingKey);
    }

    /// <summary>
    /// Shallow-merge a JSON override block into the base policy JSON.
    /// </summary>
    public static JsonElement MergePolicy(JsonElement basePolicy, JsonElement? overrideElement)
    {
        if (overrideElement is null) return basePolicy;
        var dict = new Dictionary<string, JsonElement>();
        foreach (var prop in basePolicy.EnumerateObject())
        {
            dict[prop.Name] = prop.Value;
        }
        foreach (var prop in overrideElement.Value.EnumerateObject())
        {
            dict[prop.Name] = prop.Value;
        }
        var json = JsonSerializer.Serialize(dict, TolapJsonOptions.Default);
        return JsonDocument.Parse(json).RootElement.Clone();
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (Directory.Exists(Path.Combine(dir.FullName, "fixtures", "integration-scenarios")))
            {
                return dir.FullName;
            }
            dir = dir.Parent;
        }
        throw new InvalidOperationException(
            "Could not locate repo root with fixtures/integration-scenarios.");
    }

    private sealed record PartialPolicy(
        string? Version,
        PolicyPermissions? Permissions,
        ObjectRules? ObjectRules = null,
        PolicyLimits? Limits = null);
}
