using System.Text.Json;
using FluentAssertions;
using Tolap.Core;
using Tolap.Store;
using Xunit;

namespace Tolap.Mcp.Tests;

/// <summary>
/// Cross-SDK conformance: the SQL pre-checks validate every table a query references.
/// </summary>
/// <remarks>
/// Driven by <c>fixtures/enforcement/sql-multi-table.json</c>, the corpus the Python runner
/// (<c>tests/test_sql_multi_table.py</c>) and the TypeScript core and MCP runners
/// (<c>sql-multi-table.test.ts</c>) also read. Every case runs through both wrappers'
/// <c>PrepareSqlQuery</c>, so neither entry point can validate less than the other.
/// </remarks>
public class SqlMultiTableTests
{
    private const string FixtureRelativePath = "enforcement/sql-multi-table.json";
    private const string SigningKey = "sql-multi-table-signing-key";

    /// <summary>Asserted so that a dropped case fails the suite rather than shrinking it quietly.</summary>
    private const int ExpectedCaseCount = 322;

    private static readonly Lazy<IReadOnlyList<JsonElement>> s_cases = new(LoadCases);

    private static IReadOnlyList<JsonElement> LoadCases()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "fixtures", FixtureRelativePath)))
            dir = dir.Parent;
        if (dir is null)
            throw new FileNotFoundException($"Fixture not found: {FixtureRelativePath}");
        var json = File.ReadAllText(Path.Combine(dir.FullName, "fixtures", FixtureRelativePath));
        return JsonDocument.Parse(json).RootElement.GetProperty("cases").EnumerateArray().ToList();
    }

    public static IEnumerable<object[]> CaseNames()
        => s_cases.Value.Select(c => new object[] { c.GetProperty("name").GetString()! });

    private static JsonElement Case(string name)
        => s_cases.Value.Single(c => c.GetProperty("name").GetString() == name);

    private static ObjectRules? RulesOf(JsonElement testCase)
        => testCase.GetProperty("policy").TryGetProperty("objectRules", out var rules)
            ? TolapJsonOptions.Deserialize<ObjectRules>(rules.GetRawText())
            : null;

    private static string? ObjectNameOf(JsonElement testCase)
        => testCase.TryGetProperty("objectName", out var name) ? name.GetString() : null;

    private static void AssertMatches(JsonElement testCase, bool allowed, string? reason)
    {
        var expected = testCase.GetProperty("expected");
        var name = testCase.GetProperty("name").GetString();
        allowed.Should().Be(expected.GetProperty("allowed").GetBoolean(), $"case {name}");
        if (expected.TryGetProperty("reason", out var expectedReason))
            reason.Should().Be(expectedReason.GetString(), $"case {name}");
    }

    [Fact]
    public void Corpus_CarriesTheExpectedCaseCount()
    {
        s_cases.Value.Should().HaveCount(ExpectedCaseCount);
    }

    [Fact]
    public void Corpus_HasUniqueNames()
    {
        var names = s_cases.Value.Select(c => c.GetProperty("name").GetString()).ToList();

        names.Should().OnlyHaveUniqueItems();
    }

    [Theory]
    [MemberData(nameof(CaseNames))]
    public void ContextWrapper_MatchesTheCorpus(string name)
    {
        var testCase = Case(name);
        var policy = new EffectivePolicy(
            Version: "1.0",
            UserId: "user-001",
            TenantId: "tenant-001",
            SourceConnectionId: "db:corpus:sql-multi-table",
            ResolvedAt: DateTimeOffset.UtcNow,
            ExpiresAt: DateTimeOffset.UtcNow.AddHours(1),
            SourceProfiles: new[] { "sql-multi-table" },
            Permissions: new PolicyPermissions(CanQuery: true),
            ObjectRules: RulesOf(testCase));
        var context = SecurityContextSigner.Sign(
            SecurityContextBuilder.Build("user-001", "tenant-001", new[] { policy }), SigningKey);

        var prep = new SecureContextToolWrapper(new SecureContextWrapperOptions(SigningKey))
            .PrepareSqlQuery(
                context,
                new PreExecuteArgs("sql-query", ObjectName: ObjectNameOf(testCase)),
                testCase.GetProperty("query").GetString()!);

        AssertMatches(testCase, prep.Allowed, prep.DenialReason);
    }

    [Theory]
    [MemberData(nameof(CaseNames))]
    public async Task McpWrapper_MatchesTheCorpus(string name)
    {
        var testCase = Case(name);
        var store = new InMemoryPolicyStore();
        await store.CreatePolicyAsync(new PolicyDefinition(
            Version: "1.0",
            Name: "sql-policy",
            Permissions: new PolicyPermissions(CanQuery: true),
            Priority: 10,
            AppliesToAll: true,
            ObjectRules: RulesOf(testCase)));
        await store.AssignPolicyAsync(new PolicyAssignment(
            Version: "1.0",
            PolicyName: "sql-policy",
            Assignee: new Assignee(AssigneeType.User, "user-001"),
            Scope: new AssignmentScope(TenantId: "tenant-001"),
            Active: true,
            Audit: new AuditInfo("admin", DateTimeOffset.UtcNow, "Test")));
        var wrapper = new SecureMcpToolWrapper(new SecureMcpServerOptions(
            PolicyStore: store,
            IdentityResolver: new StaticIdentityResolver(),
            IdentityExtractor: new HeaderIdentityExtractor(),
            SigningKey: SigningKey));
        var headers = new Dictionary<string, string>
        {
            ["X-Tolap-User-Id"] = "user-001",
            ["X-Tolap-Tenant-Id"] = "tenant-001"
        };

        var prep = await wrapper.PrepareSqlQueryAsync(
            headers, "db:corpus:sql-multi-table", testCase.GetProperty("query").GetString()!,
            objectName: ObjectNameOf(testCase));

        AssertMatches(testCase, prep.Allowed, prep.DenialReason);
    }
}
