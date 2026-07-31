using Amazon;
using Amazon.Runtime;
using Amazon.S3;
using Amazon.S3.Model;
using Xunit;

namespace Tolap.Integration.Tests.Aws;

/// <summary>
/// A bucket seeded with the shared storage corpus, deleted when the collection finishes.
/// </summary>
/// <remarks>
/// <para>
/// Opt-in: these tests hit <b>real AWS</b>, so without <c>TOLAP_TEST_AWS=1</c> the fixture
/// reports <see cref="Available"/> false and every test skips. That is the same distinction
/// the local test-API fixture draws — an absent dependency skips, a broken one fails — and it
/// is why missing credentials <i>after</i> opting in is an error rather than a silent pass.
/// </para>
/// <para>
/// The AWS SDK is a test-only dependency, matching Npgsql and MySqlConnector. No shipped
/// package references it: TOLAP never holds a connection, so the provider call belongs here
/// and the wrapper enforces on records the caller already retrieved.
/// </para>
/// <para>
/// Every run creates a uniquely-suffixed bucket and deletes only that bucket. The account is
/// shared, so a fixture that adopted an existing bucket — or cleaned up by prefix — could
/// destroy someone else's data. Teardown is unconditional so a failing assertion does not
/// leak a bucket.
/// </para>
/// <para>
/// Mirrors <c>sdk/python/tests/integration/aws/conftest.py</c>.
/// </para>
/// </remarks>
public sealed class S3StorageFixture : IAsyncLifetime
{
    public bool Available { get; private set; }
    public string? SkipReason { get; private set; }
    public IAmazonS3 Client { get; private set; } = null!;
    public string Bucket { get; private set; } = "";

    /// <summary>Records every S3 request, so a test can assert a call did NOT happen.</summary>
    public List<string> Calls { get; } = new();

    private readonly CallRecorder _recorder = new();

    public async Task InitializeAsync()
    {
        if (Environment.GetEnvironmentVariable("TOLAP_TEST_AWS") != "1")
        {
            SkipReason = "AWS integration tests are opt-in; set TOLAP_TEST_AWS=1";
            return;
        }

        var regionName = Environment.GetEnvironmentVariable("AWS_REGION")
            ?? Environment.GetEnvironmentVariable("AWS_DEFAULT_REGION")
            ?? "us-east-1";
        var region = RegionEndpoint.GetBySystemName(regionName);

        var config = new AmazonS3Config { RegionEndpoint = region };
        // The recorder lives in the SDK's runtime pipeline rather than wrapping each call, so
        // it sees every request actually issued -- including any a test did not make
        // directly. That is what makes "no ListObjectsV2 happened" trustworthy.
        _recorder.Sink = Calls;
        Client = RecordingS3Client.Create(config, _recorder);

        Bucket = $"tolap-test-{Guid.NewGuid():N}"[..24];

        try
        {
            await Client.PutBucketAsync(new PutBucketRequest
            {
                BucketName = Bucket,
                // us-east-1 rejects an explicit region constraint.
                BucketRegionName = regionName == "us-east-1" ? null : regionName,
            });
        }
        catch (AmazonServiceException exception)
        {
            // Opting in and then failing to reach AWS is a setup error the runner must see,
            // not a reason to report success.
            throw new InvalidOperationException(
                "TOLAP_TEST_AWS=1 but the S3 bucket could not be created. Assume a role "
                + "first (e.g. isengardcli assume <account>).", exception);
        }

        await SeedAsync();
        Available = true;
    }

    /// <remarks>
    /// The key layout is connector-spec §8's worked example, so the prefix-glob behaviour
    /// under test is the documented one. Two objects carry S3 object tags — the interesting
    /// part, because ListObjectsV2 does not return them — and one is deliberately oversize so
    /// <c>maxObjectSizeBytes</c> has a casualty as well as a survivor.
    /// </remarks>
    private async Task SeedAsync()
    {
        await PutAsync("exports/public/a.csv", "id,region\n1,us-east\n",
            metadata: new Dictionary<string, string> { ["owner"] = "analytics", ["ssn"] = "000-11-2222" });
        await PutAsync("exports/public/sub/deep.csv", "id,region\n2,us-west\n");
        await PutAsync("exports/private/secret.csv", "id,ssn\n3,000-00-0000\n");
        await PutAsync("exports/public/tagged-public.csv", "id\n4\n", tagging: ("classification", "public"));
        await PutAsync("exports/public/tagged-secret.csv", "id\n5\n", tagging: ("classification", "secret"));
        await PutAsync("exports/public/large.csv", new string('x', 2048));
    }

    private async Task PutAsync(
        string key,
        string body,
        (string Key, string Value)? tagging = null,
        Dictionary<string, string>? metadata = null)
    {
        var request = new PutObjectRequest
        {
            BucketName = Bucket,
            Key = key,
            ContentBody = body,
        };
        if (tagging is not null)
        {
            request.TagSet = new List<Tag> { new() { Key = tagging.Value.Key, Value = tagging.Value.Value } };
        }
        if (metadata is not null)
        {
            foreach (var (k, v) in metadata)
                request.Metadata.Add(k, v);
        }
        await Client.PutObjectAsync(request);
    }

    public async Task DisposeAsync()
    {
        if (!Available)
            return;

        // Scoped to this bucket only -- never a prefix sweep across a shared account.
        var listed = await Client.ListObjectsV2Async(new ListObjectsV2Request { BucketName = Bucket });
        if (listed.S3Objects.Count > 0)
        {
            await Client.DeleteObjectsAsync(new DeleteObjectsRequest
            {
                BucketName = Bucket,
                Objects = listed.S3Objects.Select(o => new KeyVersion { Key = o.Key }).ToList(),
            });
        }
        await Client.DeleteBucketAsync(Bucket);
    }
}

/// <summary>
/// Groups the AWS storage tests so they share one seeded bucket.
/// </summary>
[CollectionDefinition(Name)]
public sealed class S3StorageCollection : ICollectionFixture<S3StorageFixture>
{
    public const string Name = "aws-s3-storage";
}
