using Amazon.S3.Model;
using FluentAssertions;
using Tolap.Core;
using Xunit;

namespace Tolap.Integration.Tests.Aws;

/// <summary>
/// <c>storage</c> enforcement against real S3 (connector-spec §8).
/// </summary>
/// <remarks>
/// <para>
/// The .NET counterpart of <c>sdk/python/tests/integration/aws/test_s3_storage.py</c>, case
/// for case. TOLAP's guarantee is that one policy behaves identically in all three SDKs, so
/// AWS-backed proof for one SDK only would leave exactly the asymmetry that has produced
/// fail-open bugs in this repository before.
/// </para>
/// <para>
/// Two of §8's requirements cannot be checked against fixtures, and they are why this file
/// talks to a real service: a denied prefix must issue <b>no</b> provider call, and
/// <c>ListObjectsV2</c> genuinely returns no object tags. Both are asserted below.
/// </para>
/// <para>
/// Every denial has a paired control proving the same operation succeeds when permitted.
/// Without the control, a client that returns nothing at all passes every denial test here.
/// </para>
/// </remarks>
[Collection(S3StorageCollection.Name)]
public class S3StorageTests
{
    private readonly S3StorageFixture _aws;

    public S3StorageTests(S3StorageFixture aws) => _aws = aws;


    private static EffectivePolicy Policy(
        bool canQuery = true,
        bool? canInsert = null,
        bool? canUpdate = null,
        bool? canDelete = null,
        bool readOnly = true,
        string[]? allowedObjects = null,
        string[]? hiddenObjects = null,
        FieldRules? fieldRules = null,
        RowFilter[]? rowFilters = null,
        TagRules? tagRules = null,
        PolicyLimits? limits = null)
    {
        var now = DateTimeOffset.UtcNow;
        return new EffectivePolicy(
            Version: "1.0",
            UserId: "s3-user",
            TenantId: "s3-tenant",
            SourceConnectionId: "storage:archive:exports",
            ResolvedAt: now,
            ExpiresAt: now.AddHours(1),
            SourceProfiles: new[] { "s3-storage-test" },
            Permissions: new PolicyPermissions(
                CanQuery: canQuery, CanInsert: canInsert, CanUpdate: canUpdate,
                CanDelete: canDelete, ReadOnly: readOnly),
            ObjectRules: new ObjectRules(
                AllowedObjects: allowedObjects,
                HiddenObjects: hiddenObjects,
                FieldRules: fieldRules,
                RowFilters: rowFilters,
                TagRules: tagRules),
            Limits: limits);
    }

    /// <summary>
    /// Lists a prefix the way a compliant storage wrapper must: validate, then call.
    /// </summary>
    /// <remarks>
    /// The ordering is the point — <see cref="EnforcementEngine.ValidateAccess"/> runs before
    /// the request, so a denied prefix issues nothing. Returning early rather than filtering
    /// afterwards is what §8 requires, and the recorder tests prove this honours it.
    /// </remarks>
    private async Task<List<S3Object>> ListWithEnforcementAsync(string prefix, EffectivePolicy policy)
    {
        if (!EnforcementEngine.ValidateAccess(prefix, policy).Allowed)
            return new List<S3Object>();

        var response = await _aws.Client.ListObjectsV2Async(new ListObjectsV2Request
        {
            BucketName = _aws.Bucket,
            Prefix = prefix,
        });
        return response.S3Objects;
    }

    /// <summary>
    /// An S3 listing as the record shape the pipeline consumes: key, size, and user metadata.
    /// </summary>
    /// <remarks>
    /// §8 maps a storage Field to a metadata key and a Record to a listing entry or an
    /// object's metadata, so the metadata has to be fetched (HeadObject) for field rules to
    /// have anything to act on. This is the enrichment §8 prescribes; the tests then run the
    /// SHIPPED pipeline over these records rather than reimplementing enforcement.
    /// </remarks>
    private async Task<List<Dictionary<string, object?>>> ListingRecordsAsync(string prefix)
    {
        var records = new List<Dictionary<string, object?>>();
        foreach (var obj in await ListWithEnforcementAsync(prefix, Policy(allowedObjects: new[] { "exports/*" })))
        {
            var head = await _aws.Client.GetObjectMetadataAsync(_aws.Bucket, obj.Key);
            var record = new Dictionary<string, object?>
            {
                ["key"] = obj.Key,
                ["sizeBytes"] = obj.Size,
            };
            foreach (var name in head.Metadata.Keys)
            {
                // The SDK prefixes user metadata with x-amz-meta-; the policy names the bare key.
                var bare = name.StartsWith("x-amz-meta-", StringComparison.OrdinalIgnoreCase)
                    ? name["x-amz-meta-".Length..]
                    : name;
                record[bare] = head.Metadata[name];
            }
            records.Add(record);
        }
        return records;
    }

    // =======================================================================
    // §8: the requested prefix is validated BEFORE the provider call
    // =======================================================================

    [AwsFact]
    public async Task DeniedPrefix_IssuesNoListCall()
    {
        _aws.Calls.Clear();
        var policy = Policy(allowedObjects: new[] { "exports/public/*" });

        var results = await ListWithEnforcementAsync("exports/private/", policy);

        results.Should().BeEmpty();
        _aws.Calls.Should().NotContain("ListObjectsV2",
            "§8 requires validation before the call, so the request is never recorded as authorized");
    }

    [AwsFact]
    public async Task Control_PermittedPrefix_DoesIssueAListCall()
    {
        _aws.Calls.Clear();
        var policy = Policy(allowedObjects: new[] { "exports/public/*" });

        var results = await ListWithEnforcementAsync("exports/public/", policy);

        _aws.Calls.Should().Contain("ListObjectsV2",
            "the permitted prefix issued no call, so the denial test proves nothing");
        results.Select(o => o.Key).Should().Contain("exports/public/a.csv");
        results.Select(o => o.Key).Should().NotContain("exports/private/secret.csv");
    }

    [AwsFact]
    public async Task HiddenPrefix_AlsoIssuesNoCall()
    {
        _aws.Calls.Clear();
        // hiddenObjects takes precedence over allowedObjects (§3), and that precedence has to
        // apply before the call too -- otherwise hidden data is fetched then discarded, which
        // is the same audit-log problem.
        var policy = Policy(
            allowedObjects: new[] { "exports/*" },
            hiddenObjects: new[] { "exports/private/*" });

        var results = await ListWithEnforcementAsync("exports/private/", policy);

        results.Should().BeEmpty();
        _aws.Calls.Should().NotContain("ListObjectsV2");
    }

    // =======================================================================
    // §3.1 prefix globs, against real keys
    // =======================================================================

    [AwsFact]
    public async Task PrefixGlob_DescendsArbitrarily()
    {
        var policy = Policy(allowedObjects: new[] { "exports/public/*" });

        var keys = (await ListWithEnforcementAsync("exports/public/", policy)).Select(o => o.Key);

        keys.Should().Contain("exports/public/sub/deep.csv");
    }

    [AwsFact]
    public void BarePrefix_IsNotGrantedByItsOwnGlob()
    {
        // The boundary that makes "descends arbitrarily" safe to state.
        var policy = Policy(allowedObjects: new[] { "exports/public/*" });

        EnforcementEngine.ValidateAccess("exports/public", policy).Allowed.Should().BeFalse();
        EnforcementEngine.ValidateAccess("exports/public/a.csv", policy).Allowed.Should().BeTrue();
    }

    [AwsFact]
    public async Task EveryReturnedKey_SatisfiesThePolicy()
    {
        // A whole-bucket sweep: enumerate unfiltered, then assert the policy's decision for
        // every real key. Catches a glob that behaves differently on a shape the corpus did
        // not anticipate.
        var policy = Policy(allowedObjects: new[] { "exports/public/*" });
        var everything = await _aws.Client.ListObjectsV2Async(
            new ListObjectsV2Request { BucketName = _aws.Bucket });
        everything.S3Objects.Should().NotBeEmpty("the sweep would be vacuous");

        foreach (var obj in everything.S3Objects)
        {
            var expected = obj.Key.StartsWith("exports/public/", StringComparison.Ordinal);
            EnforcementEngine.ValidateAccess(obj.Key, policy).Allowed
                .Should().Be(expected, obj.Key);
        }
    }

    // =======================================================================
    // tagRules on a listing -- confirming §8's documented consequence
    // =======================================================================

    [AwsFact]
    public async Task ListObjects_ReturnsNoTags()
    {
        // The premise §8's warning rests on, checked against the service. Two seeded objects
        // carry classification tags; the listing exposes none.
        var listed = await _aws.Client.ListObjectsV2Async(new ListObjectsV2Request
        {
            BucketName = _aws.Bucket,
            Prefix = "exports/public/",
        });

        listed.S3Objects.Should().NotBeEmpty();
        // S3Object has no tag member at all -- the listing shape cannot carry one.
        typeof(S3Object).GetProperty("TagSet").Should().BeNull(
            "if a listing could carry tags, §8's enrichment requirement would be unnecessary");
    }

    [AwsFact]
    public async Task TagsAreOnlyAvailableViaGetObjectTagging()
    {
        var tagging = await _aws.Client.GetObjectTaggingAsync(new GetObjectTaggingRequest
        {
            BucketName = _aws.Bucket,
            Key = "exports/public/tagged-secret.csv",
        });

        tagging.Tagging.Should().ContainSingle()
            .Which.Should().Match<Tag>(t => t.Key == "classification" && t.Value == "secret");
    }

    [AwsFact]
    public async Task AllowedTags_OverABareListing_DropsEverything()
    {
        // The hazard §8 documents, end to end. Every entry is untagged as far as the pipeline
        // can see, and an allowlist drops what it cannot prove permitted -- so the result is
        // empty even though a permitted object exists. Fail-closed, and useless: an
        // implementation must enrich entries before filtering.
        var policy = Policy(tagRules: new TagRules(AllowedTags: new[] { "public" }));
        var entries = (await ListWithEnforcementAsync("exports/public/", Policy(allowedObjects: new[] { "exports/*" })))
            .Select(o => new Dictionary<string, object?> { ["key"] = o.Key, ["sizeBytes"] = o.Size })
            .ToList();
        entries.Should().NotBeEmpty();

        EnforcementEngine.FilterByTags(entries, policy).Should().BeEmpty();
    }

    [AwsFact]
    public async Task EnrichingEntriesWithTags_MakesTheAllowlistWork()
    {
        // The paired control, and the remedy §8 prescribes.
        var policy = Policy(tagRules: new TagRules(AllowedTags: new[] { "public" }));
        var entries = new List<Dictionary<string, object?>>();
        foreach (var obj in await ListWithEnforcementAsync("exports/public/", Policy(allowedObjects: new[] { "exports/*" })))
        {
            var tagging = await _aws.Client.GetObjectTaggingAsync(new GetObjectTaggingRequest
            {
                BucketName = _aws.Bucket,
                Key = obj.Key,
            });
            var record = new Dictionary<string, object?> { ["key"] = obj.Key, ["sizeBytes"] = obj.Size };
            // GetObjectTagging returns a NULL TagSet for an untagged object rather than an
            // empty list, so this cannot be a bare Count check. Leaving the key absent is
            // also the correct record shape: an untagged entry must look untagged to the
            // pipeline, which is what makes the allowlist drop it.
            var tags = tagging.Tagging;
            if (tags is { Count: > 0 })
                record["tags"] = tags.Select(t => (object?)t.Value).ToArray();
            entries.Add(record);
        }

        var surviving = EnforcementEngine.FilterByTags(entries, policy)
            .Select(e => (string)e["key"]!).ToHashSet();

        surviving.Should().Contain("exports/public/tagged-public.csv");
        surviving.Should().NotContain("exports/public/tagged-secret.csv");
    }

    [AwsFact]
    public async Task Denylist_KeepsUntaggedEntries()
    {
        // The other half of the asymmetry, and why it is not simply a bug: a pure denylist
        // keeps an untagged entry, because it matches no denied tag. Dropping it would
        // enforce a restriction the policy never stated.
        var policy = Policy(tagRules: new TagRules(DeniedTags: new[] { "secret" }));
        var entries = (await ListWithEnforcementAsync("exports/public/", Policy(allowedObjects: new[] { "exports/*" })))
            .Select(o => new Dictionary<string, object?> { ["key"] = o.Key, ["sizeBytes"] = o.Size })
            .ToList();

        EnforcementEngine.FilterByTags(entries, policy).Should().HaveCount(entries.Count);
    }

    // =======================================================================
    // Write path: canInsert / canUpdate / canDelete / readOnly (§4, §8)
    // =======================================================================

    [AwsFact]
    public async Task ReadOnlyPolicy_DeniesAPutBeforeItIsIssued()
    {
        _aws.Calls.Clear();
        var policy = Policy(readOnly: true, allowedObjects: new[] { "exports/*" });

        var decision = EnforcementEngine.ValidateWrite(
            WriteOperation.Insert, "exports/public/new.csv",
            new Dictionary<string, object?> { ["id"] = "9" }, policy);

        decision.Allowed.Should().BeFalse();
        if (decision.Allowed)
            await _aws.Client.PutObjectAsync(new PutObjectRequest
            { BucketName = _aws.Bucket, Key = "exports/public/new.csv", ContentBody = "x" });
        _aws.Calls.Should().NotContain("PutObject");
    }

    [AwsFact]
    public async Task Control_PermittedInsert_WritesAndReadsBack()
    {
        var policy = Policy(readOnly: false, canInsert: true, allowedObjects: new[] { "exports/*" });
        const string key = "exports/public/inserted-dotnet.csv";

        EnforcementEngine.ValidateWrite(
            WriteOperation.Insert, key,
            new Dictionary<string, object?> { ["id"] = "9" }, policy).Allowed.Should().BeTrue();

        await _aws.Client.PutObjectAsync(new PutObjectRequest
        { BucketName = _aws.Bucket, Key = key, ContentBody = "id\n9\n" });
        try
        {
            using var got = await _aws.Client.GetObjectAsync(_aws.Bucket, key);
            using var reader = new StreamReader(got.ResponseStream);
            (await reader.ReadToEndAsync()).Should().Be("id\n9\n");
        }
        finally
        {
            await _aws.Client.DeleteObjectAsync(_aws.Bucket, key);
        }
    }

    [AwsFact]
    public void Insert_DeniedWhenOnlyUpdateIsGranted()
    {
        // canInsert and canUpdate are distinct: granting only update must not permit creating
        // a new key.
        var policy = Policy(readOnly: false, canUpdate: true, allowedObjects: new[] { "exports/*" });
        var payload = new Dictionary<string, object?> { ["id"] = "1" };

        EnforcementEngine.ValidateWrite(WriteOperation.Insert, "exports/public/x.csv", payload, policy)
            .Allowed.Should().BeFalse();
        EnforcementEngine.ValidateWrite(WriteOperation.Update, "exports/public/a.csv", payload, policy,
            new WriteValidationOptions(TargetRow: new Dictionary<string, object?>()))
            .Allowed.Should().BeTrue();
    }

    [AwsFact]
    public void Delete_RequiresCanDelete()
    {
        var policy = Policy(readOnly: false, canInsert: true, allowedObjects: new[] { "exports/*" });

        EnforcementEngine.ValidateWrite(WriteOperation.Delete, "exports/public/a.csv", null, policy)
            .Allowed.Should().BeFalse();
    }

    [AwsFact]
    public void WriteToDeniedPrefix_IsRefused()
    {
        // allowedObjects governs the write target too, not only reads.
        var policy = Policy(readOnly: false, canInsert: true, allowedObjects: new[] { "exports/public/*" });

        EnforcementEngine.ValidateWrite(
            WriteOperation.Insert, "exports/private/x.csv",
            new Dictionary<string, object?> { ["id"] = "1" }, policy).Allowed.Should().BeFalse();
    }

    [AwsFact]
    public void WritingAReadOnlyMetadataField_IsRefused()
    {
        // readOnlyFields names metadata readable but not writable. A write whose payload sets
        // one is refused whole (§4.4: reject, never silently drop).
        var policy = Policy(
            readOnly: false, canUpdate: true, allowedObjects: new[] { "exports/*" },
            fieldRules: new FieldRules(ReadOnlyFields: new[] { "owner" }));
        var options = new WriteValidationOptions(TargetRow: new Dictionary<string, object?>());

        EnforcementEngine.ValidateWrite(WriteOperation.Update, "exports/public/a.csv",
            new Dictionary<string, object?> { ["owner"] = "attacker", ["note"] = "ok" }, policy, options)
            .Allowed.Should().BeFalse();
        EnforcementEngine.ValidateWrite(WriteOperation.Update, "exports/public/a.csv",
            new Dictionary<string, object?> { ["note"] = "ok" }, policy, options)
            .Allowed.Should().BeTrue();
    }

    // =======================================================================
    // The full post-execution pipeline over real object metadata (§4, §8)
    // =======================================================================

    [AwsFact]
    public async Task HiddenMetadataField_IsRemoved()
    {
        var records = await ListingRecordsAsync("exports/public/a.csv");
        records.Should().NotBeEmpty();
        records[0].Should().ContainKey("ssn", "seed regressed: expected an ssn metadata key");

        var policy = Policy(fieldRules: new FieldRules(HiddenFields: new[] { "ssn" }));
        var result = (IReadOnlyList<Dictionary<string, object?>>)
            EnforcementEngine.ApplyResultPipeline(records, policy)!;

        result.Should().OnlyContain(r => !r.ContainsKey("ssn"));
        result.Should().OnlyContain(r => r.ContainsKey("key"), "non-hidden fields must survive");
    }

    [AwsFact]
    public async Task MaskedMetadataField_IsMasked()
    {
        var records = await ListingRecordsAsync("exports/public/a.csv");
        var original = records.First(r => r.ContainsKey("ssn"))["ssn"];

        var policy = Policy(fieldRules: new FieldRules(
            MaskedFields: new[] { new MaskingRule("ssn", MaskType.Redact) }));
        var result = (IReadOnlyList<Dictionary<string, object?>>)
            EnforcementEngine.ApplyResultPipeline(records, policy)!;

        result.First(r => r.ContainsKey("ssn"))["ssn"].Should().NotBe(original);
    }

    [AwsFact]
    public async Task AllowedFields_ProjectsMetadata()
    {
        var records = await ListingRecordsAsync("exports/public/a.csv");

        var policy = Policy(fieldRules: new FieldRules(AllowedFields: new[] { "key", "owner" }));
        var result = (IReadOnlyList<Dictionary<string, object?>>)
            EnforcementEngine.ApplyResultPipeline(records, policy)!;

        foreach (var record in result)
        {
            record.Keys.Should().BeSubsetOf(new[] { "key", "owner" });
        }
    }

    [AwsFact]
    public async Task RowFilter_OverListingEntries()
    {
        // objectRules.rowFilters apply to listing entries (§2). Only a.csv has owner=analytics.
        var records = await ListingRecordsAsync("exports/public/");

        var policy = Policy(rowFilters: new[]
        {
            new RowFilter("owner", FilterOperator.Equals, Value: "analytics"),
        });
        var result = (IReadOnlyList<Dictionary<string, object?>>)
            EnforcementEngine.ApplyResultPipeline(records, policy)!;

        result.Select(r => (string)r["key"]!).Should().Equal("exports/public/a.csv");
    }

    [AwsFact]
    public async Task MaxObjectSize_DropsTheOversizeObject()
    {
        // large.csv is ~2 KiB; a 1 KiB ceiling drops it and keeps the rest.
        var records = await ListingRecordsAsync("exports/public/");
        records.Should().Contain(r => Convert.ToInt64(r["sizeBytes"]) > 1024,
            "seed regressed: no oversize object");

        var policy = Policy(limits: new PolicyLimits(MaxObjectSizeBytes: 1024));
        var result = (IReadOnlyList<Dictionary<string, object?>>)
            EnforcementEngine.ApplyResultPipeline(records, policy)!;

        result.Select(r => (string)r["key"]!).Should().NotContain("exports/public/large.csv");
    }

    [AwsFact]
    public async Task MaxResults_TruncatesTheListing()
    {
        var records = await ListingRecordsAsync("exports/public/");
        records.Count.Should().BeGreaterThan(2);

        var policy = Policy(limits: new PolicyLimits(MaxResults: 2));
        var result = (IReadOnlyList<Dictionary<string, object?>>)
            EnforcementEngine.ApplyResultPipeline(records, policy)!;

        result.Should().HaveCount(2);
    }
}
