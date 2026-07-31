using FluentAssertions;
using Tolap.Core;
using Tolap.Store;
using Xunit;

namespace Tolap.Mcp.Tests;

/// <summary>
/// Pre-execution SQL preparation on both wrappers.
/// </summary>
/// <remarks>
/// Preparation is an optional optimization layered in front of the mandatory post-execution
/// pipeline, so what matters is that it cannot be a way *around* that pipeline: every denial
/// the wrapper would have raised must still be raised here, before any query text is handed
/// back for execution.
/// </remarks>
public class SqlQueryPreparationTests
{
    private const string SigningKey = "test-key";

    // -----------------------------------------------------------------------
    // SecureMcpToolWrapper (identity -> policy store)
    // -----------------------------------------------------------------------

    private static async Task<SecureMcpToolWrapper> McpWrapperAsync(
        ObjectRules? objectRules = null,
        PolicyLimits? limits = null,
        bool canQuery = true,
        EnforcementMode mode = EnforcementMode.Strict)
    {
        var store = new InMemoryPolicyStore();
        await store.CreatePolicyAsync(new PolicyDefinition(
            Version: "1.0",
            Name: "sql-policy",
            Permissions: new PolicyPermissions(CanQuery: canQuery),
            Priority: 10,
            AppliesToAll: true,
            ObjectRules: objectRules,
            Limits: limits));

        await store.AssignPolicyAsync(new PolicyAssignment(
            Version: "1.0",
            PolicyName: "sql-policy",
            Assignee: new Assignee(AssigneeType.User, "user-001"),
            Scope: new AssignmentScope(TenantId: "tenant-001"),
            Active: true,
            Audit: new AuditInfo("admin", DateTimeOffset.UtcNow, "Test")));

        return new SecureMcpToolWrapper(new SecureMcpServerOptions(
            PolicyStore: store,
            IdentityResolver: new StaticIdentityResolver(),
            IdentityExtractor: new HeaderIdentityExtractor(),
            SigningKey: SigningKey,
            EnforcementMode: mode));
    }

    private static Dictionary<string, string> Headers() => new()
    {
        ["X-Tolap-User-Id"] = "user-001",
        ["X-Tolap-Tenant-Id"] = "tenant-001"
    };

    [Fact]
    public async Task Mcp_PushesRowFilterAndLimit()
    {
        var wrapper = await McpWrapperAsync(
            objectRules: new ObjectRules(
                RowFilters: new[] { new RowFilter("region", FilterOperator.Equals, "us-east") }),
            limits: new PolicyLimits(MaxResults: 50));

        var prep = await wrapper.PrepareSqlQueryAsync(
            Headers(), "db:pg:main", "SELECT id, region FROM patients");

        prep.Allowed.Should().BeTrue();
        prep.Rewritten.Should().BeTrue();
        prep.Query.Should().Be(
            "SELECT id, region FROM patients WHERE \"region\" = 'us-east' LIMIT 50");
        prep.FullyPushedDown.Should().BeTrue();
    }

    [Fact]
    public async Task Mcp_DeniesWhenQueryPermissionIsAbsent()
    {
        var wrapper = await McpWrapperAsync(canQuery: false);

        var prep = await wrapper.PrepareSqlQueryAsync(
            Headers(), "db:pg:main", "SELECT id FROM patients");

        prep.Allowed.Should().BeFalse();
        prep.DenialReason.Should().Be("query permission denied");
        prep.Query.Should().Be("SELECT id FROM patients");
    }

    [Fact]
    public async Task Mcp_ResolvesTheObjectFromTheQuery_WhenNoneIsNamed()
    {
        var wrapper = await McpWrapperAsync(
            objectRules: new ObjectRules(HiddenObjects: new[] { "audit_log" }));

        var prep = await wrapper.PrepareSqlQueryAsync(
            Headers(), "db:pg:main", "SELECT id FROM audit_log");

        prep.Allowed.Should().BeFalse();
        prep.DenialReason.Should().Be("object is hidden");
    }

    [Fact]
    public async Task Mcp_HonoursAnExplicitObjectName()
    {
        var wrapper = await McpWrapperAsync(
            objectRules: new ObjectRules(AllowedObjects: new[] { "patients" }));

        var denied = await wrapper.PrepareSqlQueryAsync(
            Headers(), "db:pg:main", "SELECT id FROM patients", objectName: "encounters");

        denied.Allowed.Should().BeFalse();
        denied.DenialReason.Should().Be("object not in allowed set");
    }

    [Fact]
    public async Task Mcp_AllowsAQueryWithNoResolvableTable()
    {
        // ExtractTableName returns null and no object name was given, so there is nothing to
        // check against allowedObjects; the field and filter checks still run.
        var wrapper = await McpWrapperAsync(
            objectRules: new ObjectRules(AllowedObjects: new[] { "patients" }));

        var prep = await wrapper.PrepareSqlQueryAsync(Headers(), "db:pg:main", "SELECT 1");

        prep.Allowed.Should().BeTrue();
    }

    [Fact]
    public async Task Mcp_DeniesAHiddenFieldReference()
    {
        var wrapper = await McpWrapperAsync(
            objectRules: new ObjectRules(FieldRules: new FieldRules(HiddenFields: new[] { "ssn" })));

        var prep = await wrapper.PrepareSqlQueryAsync(
            Headers(), "db:pg:main", "SELECT id, ssn FROM patients");

        prep.Allowed.Should().BeFalse();
        prep.DenialReason.Should().Contain("permission");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task Mcp_DeniesAnEmptyQuery(string? sql)
    {
        var wrapper = await McpWrapperAsync();

        var prep = await wrapper.PrepareSqlQueryAsync(Headers(), "db:pg:main", sql!);

        prep.Allowed.Should().BeFalse();
        prep.DenialReason.Should().Be("query is empty");
    }

    [Fact]
    public async Task Mcp_PermissiveMode_AllowsButDoesNotRewrite()
    {
        // Permissive mode's contract is "log, do not block". Narrowing the result set would
        // make rows disappear in a configuration documented as non-enforcing, so the query is
        // returned untouched.
        var wrapper = await McpWrapperAsync(
            objectRules: new ObjectRules(HiddenObjects: new[] { "audit_log" }),
            mode: EnforcementMode.Permissive);

        var prep = await wrapper.PrepareSqlQueryAsync(
            Headers(), "db:pg:main", "SELECT id FROM audit_log");

        prep.Allowed.Should().BeTrue();
        prep.DenialReason.Should().StartWith("[permissive]");
        prep.Query.Should().Be("SELECT id FROM audit_log");
        prep.Rewritten.Should().BeFalse();
    }

    [Fact]
    public async Task Mcp_ReportsUnpushableFilters()
    {
        var wrapper = await McpWrapperAsync(objectRules: new ObjectRules(
            RowFilters: new[] { new RowFilter("notes", FilterOperator.Matches, "public.*") }));

        var prep = await wrapper.PrepareSqlQueryAsync(
            Headers(), "db:pg:main", "SELECT id, notes FROM patients");

        prep.Allowed.Should().BeTrue();
        prep.FullyPushedDown.Should().BeFalse();
        prep.UnpushableFilters.Should().ContainSingle().Which.Field.Should().Be("notes");
        prep.Rewritten.Should().BeFalse();
    }

    [Fact]
    public async Task Mcp_HonoursTheSourceMapping()
    {
        var store = new InMemoryPolicyStore();
        await store.CreatePolicyAsync(new PolicyDefinition(
            Version: "1.0",
            Name: "mapped",
            Permissions: new PolicyPermissions(CanQuery: true),
            AppliesToAll: true,
            ObjectRules: new ObjectRules(
                RowFilters: new[] { new RowFilter("region", FilterOperator.Equals, "us-east") })));
        await store.AssignPolicyAsync(new PolicyAssignment(
            Version: "1.0",
            PolicyName: "mapped",
            Assignee: new Assignee(AssigneeType.User, "user-001"),
            Scope: new AssignmentScope(TenantId: "tenant-001"),
            Active: true,
            Audit: new AuditInfo("admin", DateTimeOffset.UtcNow, "Test")));

        var wrapper = new SecureMcpToolWrapper(new SecureMcpServerOptions(
            PolicyStore: store,
            IdentityResolver: new StaticIdentityResolver(),
            IdentityExtractor: new HeaderIdentityExtractor(),
            SigningKey: SigningKey,
            SourceMapping: new Dictionary<string, string> { ["alias"] = "db:pg:main" }));

        var prep = await wrapper.PrepareSqlQueryAsync(
            Headers(), "alias", "SELECT id, region FROM patients");

        prep.Allowed.Should().BeTrue();
        prep.Query.Should().Contain("\"region\" = 'us-east'");
    }

    [Fact]
    public async Task Mcp_UsesASuppliedRewriter()
    {
        var wrapper = await McpWrapperAsync(objectRules: new ObjectRules(
            RowFilters: new[] { new RowFilter("notes", FilterOperator.Contains, "x") }));

        var messages = new List<string>();
        var prep = await wrapper.PrepareSqlQueryAsync(
            Headers(), "db:pg:main", "SELECT id FROM patients",
            rewriter: new SqlQueryRewriter(messages.Add));

        prep.Allowed.Should().BeTrue();
        messages.Should().NotBeEmpty("the supplied rewriter's diagnostics must be reachable");
    }

    // -----------------------------------------------------------------------
    // SecureContextToolWrapper (signed context)
    // -----------------------------------------------------------------------

    private static EffectivePolicy ContextPolicy(
        ObjectRules? objectRules = null,
        PolicyLimits? limits = null,
        bool canQuery = true) => new(
        Version: "1.0",
        UserId: "user-001",
        TenantId: "tenant-001",
        SourceConnectionId: "db:pg:main",
        ResolvedAt: DateTimeOffset.UtcNow,
        ExpiresAt: DateTimeOffset.UtcNow.AddHours(1),
        SourceProfiles: new[] { "test" },
        Permissions: new PolicyPermissions(CanQuery: canQuery),
        ObjectRules: objectRules,
        Limits: limits);

    private static SecurityContext Sign(EffectivePolicy policy)
        => SecurityContextSigner.Sign(
            SecurityContextBuilder.Build("user-001", "tenant-001", new[] { policy }), SigningKey);

    private static SecureContextToolWrapper ContextWrapper()
        => new(new SecureContextWrapperOptions(SigningKey));

    [Fact]
    public void Context_PushesRowFilterAndLimit()
    {
        var prep = ContextWrapper().PrepareSqlQuery(
            Sign(ContextPolicy(
                objectRules: new ObjectRules(
                    RowFilters: new[] { new RowFilter("region", FilterOperator.Equals, "us-east") }),
                limits: new PolicyLimits(MaxResults: 50))),
            new PreExecuteArgs("pg-query"),
            "SELECT id, region FROM patients");

        prep.Allowed.Should().BeTrue();
        prep.Query.Should().Be(
            "SELECT id, region FROM patients WHERE \"region\" = 'us-east' LIMIT 50");
    }

    [Fact]
    public void Context_DeniesAnExpiredContext()
    {
        // The expiry check must precede rewriting: an expired context's policy must not be the
        // one pushed into a query.
        var expired = SecurityContextSigner.Sign(
            SecurityContextBuilder.Build(
                "user-001", "tenant-001", new[] { ContextPolicy() }, TimeSpan.FromHours(-1)),
            SigningKey);

        var prep = ContextWrapper().PrepareSqlQuery(
            expired, new PreExecuteArgs("pg-query"), "SELECT id FROM patients");

        prep.Allowed.Should().BeFalse();
    }

    [Fact]
    public void Context_DeniesATamperedContext()
    {
        var signed = Sign(ContextPolicy());
        var tampered = signed with { UserId = "someone-else" };

        var prep = ContextWrapper().PrepareSqlQuery(
            tampered, new PreExecuteArgs("pg-query"), "SELECT id FROM patients");

        prep.Allowed.Should().BeFalse();
        prep.DenialReason.Should().Be("invalid signature");
    }

    [Fact]
    public void Context_DeniesAToolOutsideTheAllowedList()
    {
        var wrapper = new SecureContextToolWrapper(
            new SecureContextWrapperOptions(SigningKey, AllowedTools: new[] { "approved" }));

        var prep = wrapper.PrepareSqlQuery(
            Sign(ContextPolicy()), new PreExecuteArgs("pg-query"), "SELECT id FROM patients");

        prep.Allowed.Should().BeFalse();
        prep.DenialReason.Should().Be("tool not in allowed list");
    }

    [Fact]
    public void Context_DeniesWhenQueryPermissionIsAbsent()
    {
        var prep = ContextWrapper().PrepareSqlQuery(
            Sign(ContextPolicy(canQuery: false)),
            new PreExecuteArgs("pg-query"),
            "SELECT id FROM patients");

        prep.Allowed.Should().BeFalse();
        prep.DenialReason.Should().Be("query not permitted");
    }

    [Fact]
    public void Context_ResolvesTheObjectFromTheQuery_WhenNoneIsNamed()
    {
        var prep = ContextWrapper().PrepareSqlQuery(
            Sign(ContextPolicy(new ObjectRules(HiddenObjects: new[] { "audit_log" }))),
            new PreExecuteArgs("pg-query"),
            "SELECT id FROM audit_log");

        prep.Allowed.Should().BeFalse();
        prep.DenialReason.Should().Be("object is hidden");
    }

    [Fact]
    public void Context_HonoursAnExplicitObjectName()
    {
        var prep = ContextWrapper().PrepareSqlQuery(
            Sign(ContextPolicy(new ObjectRules(AllowedObjects: new[] { "patients" }))),
            new PreExecuteArgs("pg-query", ObjectName: "encounters"),
            "SELECT id FROM patients");

        prep.Allowed.Should().BeFalse();
        prep.DenialReason.Should().Be("object not in allowed set");
    }

    [Fact]
    public void Context_DeniesAHiddenFieldReference()
    {
        var prep = ContextWrapper().PrepareSqlQuery(
            Sign(ContextPolicy(new ObjectRules(
                FieldRules: new FieldRules(HiddenFields: new[] { "ssn" })))),
            new PreExecuteArgs("pg-query"),
            "SELECT id FROM patients WHERE ssn = '1'");

        prep.Allowed.Should().BeFalse();
        prep.DenialReason.Should().Contain("permission");
    }

    [Fact]
    public void Context_DeniesAnEmptyQuery()
    {
        var prep = ContextWrapper().PrepareSqlQuery(
            Sign(ContextPolicy()), new PreExecuteArgs("pg-query"), "");

        prep.Allowed.Should().BeFalse();
        prep.DenialReason.Should().Be("query is empty");
    }

    [Fact]
    public void Context_DeniesAContextWithNoPolicy()
    {
        var empty = SecurityContextSigner.Sign(
            SecurityContextBuilder.Build("user-001", "tenant-001", Array.Empty<EffectivePolicy>()),
            SigningKey);

        var prep = ContextWrapper().PrepareSqlQuery(
            empty, new PreExecuteArgs("pg-query"), "SELECT id FROM patients");

        prep.Allowed.Should().BeFalse();
        prep.DenialReason.Should().Be("no policy in context");
    }

    [Fact]
    public void Context_ReportsAnUnchangedQueryAsNotRewritten()
    {
        const string sql = "SELECT id FROM patients";

        var prep = ContextWrapper().PrepareSqlQuery(
            Sign(ContextPolicy()), new PreExecuteArgs("pg-query"), sql);

        prep.Allowed.Should().BeTrue();
        prep.Rewritten.Should().BeFalse();
        prep.Query.Should().Be(sql);
        prep.FullyPushedDown.Should().BeTrue();
    }

    [Fact]
    public void Context_UsesASuppliedRewriter()
    {
        var messages = new List<string>();

        ContextWrapper().PrepareSqlQuery(
            Sign(ContextPolicy(new ObjectRules(
                FieldRules: new FieldRules(HiddenFields: new[] { "ssn" })))),
            new PreExecuteArgs("pg-query"),
            "SELECT * FROM patients",
            new SqlQueryRewriter(messages.Add));

        messages.Should().NotBeEmpty();
    }

    // -----------------------------------------------------------------------
    // ExecuteSqlWithEnforcementAsync
    // -----------------------------------------------------------------------

    [Fact]
    public async Task ExecuteSql_PassesTheRewrittenQueryAndStillRunsThePipeline()
    {
        var policy = ContextPolicy(
            objectRules: new ObjectRules(
                FieldRules: new FieldRules(
                    MaskedFields: new[] { new MaskingRule("email", MaskType.Redact) }),
                RowFilters: new[] { new RowFilter("region", FilterOperator.Equals, "us-east") }),
            limits: new PolicyLimits(MaxResults: 10));

        string? seen = null;

        var rows = await ContextWrapper().ExecuteSqlWithEnforcementAsync(
            Sign(policy),
            new PreExecuteArgs("pg-query"),
            "SELECT id, email, region FROM patients",
            sql =>
            {
                seen = sql;
                // A stand-in data source that ignores the WHERE clause, so the assertions
                // below show the post-fetch pass is still doing its job.
                return Task.FromResult<IReadOnlyList<Dictionary<string, object?>>>(new[]
                {
                    new Dictionary<string, object?>
                        { ["id"] = 1, ["email"] = "a@b.c", ["region"] = "us-east" },
                    new Dictionary<string, object?>
                        { ["id"] = 2, ["email"] = "d@e.f", ["region"] = "eu-west" }
                });
            });

        seen.Should().Be(
            "SELECT id, email, region FROM patients WHERE \"region\" = 'us-east' LIMIT 10");

        // The eu-west row was dropped post-fetch and the email masked -- neither of which the
        // rewrite alone would have done to this stand-in result.
        rows.Should().ContainSingle();
        rows[0]["region"].Should().Be("us-east");
        rows[0]["email"].Should().Be("[REDACTED]");
    }

    [Fact]
    public async Task ExecuteSql_ThrowsAndDoesNotInvokeTheDelegate_WhenDenied()
    {
        var invoked = false;

        var act = async () => await ContextWrapper().ExecuteSqlWithEnforcementAsync(
            Sign(ContextPolicy(canQuery: false)),
            new PreExecuteArgs("pg-query"),
            "SELECT id FROM patients",
            _ =>
            {
                invoked = true;
                return Task.FromResult<IReadOnlyList<Dictionary<string, object?>>>(
                    Array.Empty<Dictionary<string, object?>>());
            });

        await act.Should().ThrowAsync<UnauthorizedAccessException>()
            .WithMessage("*query not permitted*");
        invoked.Should().BeFalse("a denied query must never reach the data source");
    }

    [Fact]
    public async Task ExecuteSql_AcceptsASuppliedRewriter()
    {
        var messages = new List<string>();

        await ContextWrapper().ExecuteSqlWithEnforcementAsync(
            Sign(ContextPolicy(new ObjectRules(
                FieldRules: new FieldRules(HiddenFields: new[] { "ssn" })))),
            new PreExecuteArgs("pg-query"),
            "SELECT * FROM patients",
            _ => Task.FromResult<IReadOnlyList<Dictionary<string, object?>>>(
                Array.Empty<Dictionary<string, object?>>()),
            new SqlQueryRewriter(messages.Add));

        messages.Should().NotBeEmpty();
    }

    // -----------------------------------------------------------------------
    // Dialect pass-through (connector-spec.md section 5.1)
    // -----------------------------------------------------------------------
    //
    // The dialect is the integrator's to supply, because it is a property of THEIR
    // connection. The wrapper's job is to plumb it through; it must never infer one, and
    // must never read one from the policy.

    private static ObjectRules UsEastFilter()
        => new(RowFilters: new[] { new RowFilter("region", FilterOperator.Equals, "us-east") });

    [Fact]
    public void Context_PassesTheDialectThrough()
    {
        var prep = ContextWrapper().PrepareSqlQuery(
            Sign(ContextPolicy(objectRules: UsEastFilter())),
            new PreExecuteArgs("mysql-query"),
            "SELECT id, region FROM patients",
            rewriter: null,
            dialect: SqlDialect.MySql);

        prep.Allowed.Should().BeTrue();
        prep.Query.Should().Be("SELECT id, region FROM patients WHERE `region` = 'us-east'");
    }

    [Fact]
    public void Context_DeclinesToRewrite_ForAnUnrecognizedDialect()
    {
        var prep = ContextWrapper().PrepareSqlQuery(
            Sign(ContextPolicy(objectRules: UsEastFilter())),
            new PreExecuteArgs("pg-query"),
            "SELECT id, region FROM patients",
            rewriter: null,
            dialect: (SqlDialect)99);

        // Allowed, but nothing pushed down and every filter reported -- the post-execution
        // pass is left to enforce them, which it always was.
        prep.Allowed.Should().BeTrue();
        prep.Rewritten.Should().BeFalse();
        prep.Query.Should().Be("SELECT id, region FROM patients");
        prep.UnpushableFilters.Should().HaveCount(1);
        prep.FullyPushedDown.Should().BeFalse();
    }

    [Fact]
    public void Context_DecliningToRewrite_StillDeniesAHiddenField()
    {
        // Declining to rewrite must never relax a denial: the pre-execution checks are not
        // part of the rewrite.
        var prep = ContextWrapper().PrepareSqlQuery(
            Sign(ContextPolicy(
                objectRules: new ObjectRules(
                    FieldRules: new FieldRules(HiddenFields: new[] { "ssn" })))),
            new PreExecuteArgs("pg-query"),
            "SELECT ssn FROM patients",
            rewriter: null,
            dialect: (SqlDialect)99);

        prep.Allowed.Should().BeFalse();
    }

    [Fact]
    public async Task Context_PassesTheDialectThrough_ExecuteSqlWithEnforcement()
    {
        var seen = new List<string>();

        await ContextWrapper().ExecuteSqlWithEnforcementAsync(
            Sign(ContextPolicy(objectRules: UsEastFilter())),
            new PreExecuteArgs("mysql-query"),
            "SELECT id, region FROM patients",
            query =>
            {
                seen.Add(query);
                return Task.FromResult<IReadOnlyList<Dictionary<string, object?>>>(
                    new List<Dictionary<string, object?>>());
            },
            rewriter: null,
            dialect: SqlDialect.MySql);

        seen.Should().ContainSingle().Which.Should().Contain("`region`");
    }

    [Fact]
    public async Task Mcp_PassesTheDialectThrough()
    {
        var wrapper = await McpWrapperAsync(objectRules: UsEastFilter());

        var prep = await wrapper.PrepareSqlQueryAsync(
            Headers(), "db:pg:main", "SELECT id, region FROM patients",
            objectName: null, rewriter: null, dialect: SqlDialect.MySql);

        prep.Query.Should().Be("SELECT id, region FROM patients WHERE `region` = 'us-east'");
    }

    [Fact]
    public async Task Mcp_DeclinesToRewrite_ForAnUnrecognizedDialect()
    {
        var wrapper = await McpWrapperAsync(objectRules: UsEastFilter());

        var prep = await wrapper.PrepareSqlQueryAsync(
            Headers(), "db:pg:main", "SELECT id, region FROM patients",
            objectName: null, rewriter: null, dialect: (SqlDialect)99);

        prep.Allowed.Should().BeTrue();
        prep.Rewritten.Should().BeFalse();
        prep.UnpushableFilters.Should().HaveCount(1);
    }
}
