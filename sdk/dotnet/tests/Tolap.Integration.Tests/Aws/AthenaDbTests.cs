using Amazon;
using Amazon.Athena;
using Amazon.Athena.Model;
using Amazon.Glue;
using Amazon.Glue.Model;
using Amazon.S3;
using Amazon.S3.Model;
using FluentAssertions;
using Tolap.Core;
using Xunit;

// Both Amazon.Glue and Tolap.Core define FilterOperator, and both Amazon.Glue.Model and
// Amazon.Athena.Model define Column. Aliased rather than resolved by using-order, so a future
// reader cannot mistake which one is meant -- and so adding another AWS namespace here cannot
// silently change the binding.
using FilterOperator = Tolap.Core.FilterOperator;
using GlueColumn = Amazon.Glue.Model.Column;

namespace Tolap.Integration.Tests.Aws;

/// <summary>
/// Seeds S3 + a Glue table and yields Athena query context, deleted on teardown.
/// </summary>
public sealed class AthenaFixture : IAsyncLifetime
{
    public bool Available { get; private set; }

    /// <summary>Why the suite is skipped, surfaced to the runner instead of a silent pass.</summary>
    public string? SkipReason { get; private set; } = "AWS integration tests are opt-in; set TOLAP_TEST_AWS=1";
    public IAmazonAthena Athena { get; private set; } = null!;
    public string Database { get; private set; } = "";
    public string ResultsLocation { get; private set; } = "";

    private IAmazonS3 _s3 = null!;
    private IAmazonGlue _glue = null!;
    private string _bucket = "";

    /// <summary>The seeded rows: two regions, and one ssn column for field rules to act on.</summary>
    public static readonly string[][] Rows =
    {
        new[] { "1", "us-east", "Alice", "111-11-1111" },
        new[] { "2", "us-east", "Bob", "222-22-2222" },
        new[] { "3", "us-west", "Carol", "333-33-3333" },
        new[] { "4", "eu-west", "Dave", "444-44-4444" },
    };

    public async Task InitializeAsync()
    {
        if (Environment.GetEnvironmentVariable("TOLAP_TEST_AWS") != "1")
            return;

        SkipReason = null;

        var regionName = Environment.GetEnvironmentVariable("AWS_REGION") ?? "us-east-1";
        var region = RegionEndpoint.GetBySystemName(regionName);

        _s3 = new AmazonS3Client(region);
        _glue = new AmazonGlueClient(region);
        Athena = new AmazonAthenaClient(region);

        var suffix = Guid.NewGuid().ToString("N")[..10];
        _bucket = $"tolap-athena-{suffix}";
        Database = $"tolap_db_{suffix}";
        ResultsLocation = $"s3://{_bucket}/_results/";

        await _s3.PutBucketAsync(new PutBucketRequest
        {
            BucketName = _bucket,
            BucketRegionName = regionName == "us-east-1" ? null : regionName,
        });

        var body = string.Join("\n", Rows.Select(r => string.Join(",", r))) + "\n";
        await _s3.PutObjectAsync(new PutObjectRequest
        {
            BucketName = _bucket,
            Key = "patients/data.csv",
            ContentBody = body,
        });

        await _glue.CreateDatabaseAsync(new CreateDatabaseRequest
        {
            DatabaseInput = new DatabaseInput { Name = Database },
        });
        await _glue.CreateTableAsync(new CreateTableRequest
        {
            DatabaseName = Database,
            TableInput = new TableInput
            {
                Name = "patients",
                TableType = "EXTERNAL_TABLE",
                StorageDescriptor = new StorageDescriptor
                {
                    Columns = new List<GlueColumn>
                    {
                        new GlueColumn { Name = "id", Type = "string" },
                        new GlueColumn { Name = "region", Type = "string" },
                        new GlueColumn { Name = "full_name", Type = "string" },
                        new GlueColumn { Name = "ssn", Type = "string" },
                    },
                    Location = $"s3://{_bucket}/patients/",
                    InputFormat = "org.apache.hadoop.mapred.TextInputFormat",
                    OutputFormat = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                    SerdeInfo = new SerDeInfo
                    {
                        SerializationLibrary = "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                        Parameters = new Dictionary<string, string> { ["field.delim"] = "," },
                    },
                },
            },
        });

        Available = true;
    }

    public async Task DisposeAsync()
    {
        if (!Available)
            return;

        // Best-effort in order, so one failure does not leak the rest.
        try { await _glue.DeleteTableAsync(new DeleteTableRequest { DatabaseName = Database, Name = "patients" }); }
        catch { /* already gone */ }
        try { await _glue.DeleteDatabaseAsync(new DeleteDatabaseRequest { Name = Database }); }
        catch { /* already gone */ }

        var listed = await _s3.ListObjectsV2Async(new ListObjectsV2Request { BucketName = _bucket });
        if (listed.S3Objects.Count > 0)
        {
            await _s3.DeleteObjectsAsync(new DeleteObjectsRequest
            {
                BucketName = _bucket,
                Objects = listed.S3Objects.Select(o => new KeyVersion { Key = o.Key }).ToList(),
            });
        }
        await _s3.DeleteBucketAsync(_bucket);
    }
}

[CollectionDefinition(Name)]
public sealed class AthenaCollection : ICollectionFixture<AthenaFixture>
{
    public const string Name = "aws-athena";
}

/// <summary>
/// <c>db</c> enforcement against real Athena / Trino (connector-spec §5).
/// </summary>
/// <remarks>
/// <para>
/// The .NET counterpart of <c>test_athena_db.py</c>. The rewriter carries a <c>trino</c>
/// dialect profile — what Athena speaks — but every other test exercises it against Postgres
/// and MySQL. This is the category where a rewrite bug means the <b>database itself</b>
/// returns unauthorized rows, before post-fetch filtering gets a chance, and a
/// <c>WHERE</c>-clause fail-open was found in this rewriter once before by running the SQL
/// rather than reading it.
/// </para>
/// <para>
/// Two properties are checked separately because they fail differently: the rewritten query
/// must not return a row the policy excludes (pushdown), and the pipeline must still run
/// because the rewrite deliberately does not push everything down (completeness).
/// </para>
/// </remarks>
[Collection(AthenaCollection.Name)]
public class AthenaDbTests
{
    private readonly AthenaFixture _aws;

    public AthenaDbTests(AthenaFixture aws) => _aws = aws;


    private static EffectivePolicy Policy(
        bool canQuery = true,
        string[]? allowedObjects = null,
        FieldRules? fieldRules = null,
        RowFilter[]? rowFilters = null,
        PolicyLimits? limits = null)
    {
        var now = DateTimeOffset.UtcNow;
        return new EffectivePolicy(
            Version: "1.0",
            UserId: "athena-user",
            TenantId: "athena-tenant",
            SourceConnectionId: "db:analytics:patients",
            ResolvedAt: now,
            ExpiresAt: now.AddHours(1),
            SourceProfiles: new[] { "athena-test" },
            Permissions: new PolicyPermissions(CanQuery: canQuery, ReadOnly: true),
            ObjectRules: new ObjectRules(
                AllowedObjects: allowedObjects,
                FieldRules: fieldRules,
                RowFilters: rowFilters),
            Limits: limits);
    }

    /// <summary>
    /// What a compliant db wrapper does before executing: check the object, then rewrite.
    /// </summary>
    /// <remarks>
    /// The .NET rewriter exposes <see cref="SqlQueryRewriter.RewriteQuery"/> returning the SQL
    /// text, with the access decision coming from <see cref="EnforcementEngine.ValidateAccess"/>
    /// separately — unlike Python's single <c>prepare_sql_query</c>. Composing them here keeps
    /// the test asserting the same two-part contract in both SDKs rather than papering over the
    /// API difference.
    /// </remarks>
    private static (bool Allowed, string? DenialReason, string Query) Prepared(
        string sql, EffectivePolicy policy, string objectName = "patients")
    {
        var decision = EnforcementEngine.ValidateAccess(objectName, policy);
        if (!decision.Allowed)
            return (false, decision.Reason, sql);

        var rewriter = new SqlQueryRewriter(dialect: SqlDialect.Trino);
        return (true, null, rewriter.RewriteQuery(sql, policy));
    }

    /// <summary>Executes SQL on Athena and returns rows as dictionaries.</summary>
    private async Task<List<Dictionary<string, object?>>> RunQueryAsync(string sql)
    {
        var started = await _aws.Athena.StartQueryExecutionAsync(new StartQueryExecutionRequest
        {
            QueryString = sql,
            QueryExecutionContext = new QueryExecutionContext { Database = _aws.Database },
            ResultConfiguration = new ResultConfiguration { OutputLocation = _aws.ResultsLocation },
        });

        for (var attempt = 0; attempt < 60; attempt++)
        {
            var execution = await _aws.Athena.GetQueryExecutionAsync(
                new GetQueryExecutionRequest { QueryExecutionId = started.QueryExecutionId });
            var state = execution.QueryExecution.Status.State;
            if (state == QueryExecutionState.SUCCEEDED)
                break;
            if (state == QueryExecutionState.FAILED || state == QueryExecutionState.CANCELLED)
            {
                throw new InvalidOperationException(
                    $"Athena query {state}: "
                    + $"{execution.QueryExecution.Status.StateChangeReason}\nSQL: {sql}");
            }
            await Task.Delay(2000);
        }

        var result = await _aws.Athena.GetQueryResultsAsync(
            new GetQueryResultsRequest { QueryExecutionId = started.QueryExecutionId });
        var columns = result.ResultSet.ResultSetMetadata.ColumnInfo.Select(c => c.Name).ToList();

        var rows = new List<Dictionary<string, object?>>();
        foreach (var row in result.ResultSet.Rows)
        {
            var values = row.Data.Select(d => d.VarCharValue).ToList();
            // Athena's first row is the header when the SerDe has no skip.header setting.
            // Detected rather than assumed, so a header change cannot silently drop a data row.
            if (values.SequenceEqual(columns))
                continue;
            var record = new Dictionary<string, object?>();
            for (var i = 0; i < columns.Count && i < values.Count; i++)
                record[columns[i]] = values[i];
            rows.Add(record);
        }
        return rows;
    }

    // =======================================================================
    // Pushdown: the engine must not return rows the policy excludes
    // =======================================================================

    [AwsFact]
    public async Task Baseline_UnfilteredReturnsEveryRegion()
    {
        // Without this the filtered assertions could pass because the table is empty or the
        // SerDe misparsed the CSV.
        var rows = await RunQueryAsync("SELECT * FROM patients");

        rows.Select(r => (string?)r["region"]).Distinct()
            .Should().BeEquivalentTo(new[] { "us-east", "us-west", "eu-west" });
    }

    [AwsFact]
    public async Task RowFilter_IsPushedIntoTheSqlAndHonouredByAthena()
    {
        // The property a fixture cannot check: Athena's own parser applied our WHERE clause.
        var policy = Policy(
            allowedObjects: new[] { "patients" },
            rowFilters: new[] { new RowFilter("region", FilterOperator.Equals, Value: "us-east") });
        var prep = Prepared("SELECT * FROM patients", policy);
        prep.Allowed.Should().BeTrue();
        prep.Query.ToUpperInvariant().Should().Contain("WHERE", "the filter was not pushed down");

        var rows = await RunQueryAsync(prep.Query);

        rows.Should().NotBeEmpty("expected the us-east rows");
        rows.Select(r => (string?)r["region"]).Distinct().Should().Equal("us-east");
    }

    [AwsFact]
    public async Task InOperator_Pushdown()
    {
        var policy = Policy(
            allowedObjects: new[] { "patients" },
            rowFilters: new[]
            {
                new RowFilter("region", FilterOperator.In, Values: new object[] { "us-east", "eu-west" }),
            });

        var rows = await RunQueryAsync(Prepared("SELECT * FROM patients", policy).Query);

        rows.Select(r => (string?)r["region"]).Distinct()
            .Should().BeEquivalentTo(new[] { "us-east", "eu-west" });
    }

    [AwsFact]
    public async Task NotEquals_PushdownExcludesTheRegion()
    {
        // Negative operators are where this rewriter previously failed open, so the excluded
        // value is asserted ABSENT rather than only counting rows.
        var policy = Policy(
            allowedObjects: new[] { "patients" },
            rowFilters: new[] { new RowFilter("region", FilterOperator.NotEquals, Value: "us-west") });

        var rows = await RunQueryAsync(Prepared("SELECT * FROM patients", policy).Query);

        rows.Should().NotBeEmpty();
        rows.Select(r => (string?)r["region"]).Should().NotContain("us-west");
    }

    [AwsFact]
    public async Task MaxResults_IsPushedAsLimit()
    {
        var policy = Policy(allowedObjects: new[] { "patients" }, limits: new PolicyLimits(MaxResults: 2));
        var prep = Prepared("SELECT * FROM patients", policy);
        prep.Query.ToUpperInvariant().Should().Contain("LIMIT");

        (await RunQueryAsync(prep.Query)).Should().HaveCount(2);
    }

    // =======================================================================
    // Denials happen before any SQL is sent
    // =======================================================================

    [AwsFact]
    public void CanQueryFalse_YieldsNoExecutableSql()
    {
        var prep = Prepared("SELECT * FROM patients", Policy(canQuery: false, allowedObjects: new[] { "patients" }));

        prep.Allowed.Should().BeFalse();
        prep.DenialReason.Should().NotBeNullOrEmpty();
    }

    [AwsFact]
    public void TableOutsideAllowedObjects_IsRefused()
    {
        // The table exists in Glue, so a broken check would happily query it.
        Prepared("SELECT * FROM patients", Policy(allowedObjects: new[] { "encounters" }))
            .Allowed.Should().BeFalse();
    }

    [AwsFact]
    public async Task Control_PermittedTableProducesRunnableSql()
    {
        var prep = Prepared("SELECT * FROM patients", Policy(allowedObjects: new[] { "patients" }));

        prep.Allowed.Should().BeTrue();
        (await RunQueryAsync(prep.Query)).Should().NotBeEmpty();
    }

    // =======================================================================
    // Post-fetch completeness: the rewrite is not the whole control
    // =======================================================================

    [AwsFact]
    public async Task HiddenField_SurvivesTheRewriteAndIsRemovedAfter()
    {
        // SELECT * is deliberately NOT expanded, so ssn comes back from Athena and the post
        // pass removes it. This asserts the seam: if someone optimised the pipeline away,
        // it fails.
        var policy = Policy(
            allowedObjects: new[] { "patients" },
            fieldRules: new FieldRules(HiddenFields: new[] { "ssn" }));

        var raw = await RunQueryAsync(Prepared("SELECT * FROM patients", policy).Query);
        raw.Should().Contain(r => r.ContainsKey("ssn"),
            "Athena did not return ssn, so this would pass without the post pass doing anything");

        var enforced = (IReadOnlyList<Dictionary<string, object?>>)
            EnforcementEngine.ApplyResultPipeline(raw, policy)!;

        enforced.Should().NotBeEmpty();
        enforced.Should().OnlyContain(r => !r.ContainsKey("ssn"));
    }

    [AwsFact]
    public async Task Masking_AppliesToRealAthenaRows()
    {
        var policy = Policy(
            allowedObjects: new[] { "patients" },
            fieldRules: new FieldRules(MaskedFields: new[] { new MaskingRule("ssn", MaskType.Redact) }));

        var raw = await RunQueryAsync(Prepared("SELECT * FROM patients", policy).Query);
        var enforced = (IReadOnlyList<Dictionary<string, object?>>)
            EnforcementEngine.ApplyResultPipeline(raw, policy)!;

        enforced.Should().OnlyContain(r => (string?)r["ssn"] != "111-11-1111");
    }

    [AwsFact]
    public async Task AllowedFields_ProjectsAthenaRows()
    {
        var policy = Policy(
            allowedObjects: new[] { "patients" },
            fieldRules: new FieldRules(AllowedFields: new[] { "id", "region" }));

        var raw = await RunQueryAsync(Prepared("SELECT * FROM patients", policy).Query);
        var enforced = (IReadOnlyList<Dictionary<string, object?>>)
            EnforcementEngine.ApplyResultPipeline(raw, policy)!;

        foreach (var record in enforced)
            record.Keys.Should().BeSubsetOf(new[] { "id", "region" });
    }

    [AwsFact]
    public async Task PushdownAndPostPass_AgreeOnTheSamePolicy()
    {
        // The safety property, as for the kb pushdown: filtering in SQL must reach the same
        // verdict as filtering in the pipeline. A disagreement means the rewrite is not a
        // faithful translation of the policy.
        var policy = Policy(
            allowedObjects: new[] { "patients" },
            rowFilters: new[] { new RowFilter("region", FilterOperator.Equals, Value: "us-east") });

        var pushed = await RunQueryAsync(Prepared("SELECT * FROM patients", policy).Query);
        var everything = await RunQueryAsync("SELECT * FROM patients");
        var postOnly = (IReadOnlyList<Dictionary<string, object?>>)
            EnforcementEngine.ApplyResultPipeline(everything, policy)!;

        pushed.Select(r => (string?)r["id"]).Should().BeEquivalentTo(
            postOnly.Select(r => (string?)r["id"]),
            "the SQL rewrite and the post-execution pipeline disagreed on the same policy");
    }
}
