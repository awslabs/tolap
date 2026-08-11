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
    /// <summary>
    /// Fails the current test when a required backing service is unavailable.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Tests previously wrote <c>if (!_db.Ready) return;</c>, and an early return from a
    /// test body is a <b>PASS</b>, not a skip. Measured before this helper existed: with
    /// Postgres pointed at a dead port, the 82 Postgres integration tests reported
    /// <c>Passed: 82</c> — byte-identical to a run against a live database. For a
    /// policy-enforcement SDK that means a regression letting <c>patients.ssn</c> through
    /// could ship behind a green build. The AWS suites' genuine <c>Skipped: 41</c> shows
    /// the runner reports real skips plainly when it is given one.
    /// </para>
    /// <para>
    /// It also hid a live bug rather than a missing service. Three classes shared
    /// <c>MySqlFixture</c> via <c>IClassFixture</c>, so each built its own instance and
    /// each re-seeded the same tables in parallel; the losers failed with "Table 'patients'
    /// already exists" and 39 MySQL tests reported success while never touching MySQL —
    /// which was reachable the whole time. See <c>DatabaseCollection</c>.
    /// </para>
    /// <para>
    /// There is deliberately <b>no opt-out</b>. xUnit v2 has no dynamic-skip API
    /// (<c>Assert.Skip</c> is v3), so the only alternatives were to fail or to return —
    /// and returning is what produced the false green. An escape hatch was tried and
    /// removed: it could suppress this call but not the closed connection the test used
    /// two lines later, so 34 tests failed anyway with
    /// <c>Connection must be Open</c>. A half-working opt-out is worse than none, because
    /// it invites the reader to believe the suite degrades gracefully when it does not.
    /// Start the services (see <c>docs/local-testing.md</c>) or filter the run.
    /// </para>
    /// </remarks>
    public static void RequireService(bool ready, string service, string? detail = null)
    {
        if (ready) return;

        var because = detail is null ? service : $"{service} ({detail})";
        throw new InvalidOperationException(
            $"This integration test requires {because}, which is unavailable. "
            + "Start it (see docs/local-testing.md), or filter it out of the run "
            + "(dotnet test --filter). It must not be skipped silently: an early return "
            + "would be recorded as a pass, which is how 39 MySQL tests reported success "
            + "while never reaching MySQL.");
    }

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
