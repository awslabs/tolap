using Amazon.Runtime;
using Amazon.Runtime.Internal;
using Amazon.S3;

namespace Tolap.Integration.Tests.Aws;

/// <summary>
/// An S3 client that records every request it issues.
/// </summary>
/// <remarks>
/// <para>
/// The recorder has to be installed by overriding <see cref="CustomizeRuntimePipeline"/> —
/// the runtime pipeline is not reachable from <see cref="AmazonS3Config"/>. Subclassing is
/// the supported seam for adding a handler, and it keeps the recorder in the real request
/// path rather than wrapping individual calls, which is what makes "this call never
/// happened" a trustworthy assertion.
/// </para>
/// <para>
/// The recorder is held in a <c>static</c> passed through construction rather than an
/// instance field, because <see cref="CustomizeRuntimePipeline"/> is invoked from the
/// <b>base constructor</b> — before any derived field assignment has run. An instance field
/// is still null at that point, which the SDK reports as
/// <c>ArgumentNullException(handler)</c>. The lock makes the hand-off safe if two clients are
/// ever built concurrently.
/// </para>
/// </remarks>
public sealed class RecordingS3Client : AmazonS3Client
{
    private static readonly object ConstructionLock = new();
    private static CallRecorder? _pending;

    private RecordingS3Client(AmazonS3Config config) : base(config) { }

    public static RecordingS3Client Create(AmazonS3Config config, CallRecorder recorder)
    {
        lock (ConstructionLock)
        {
            _pending = recorder;
            try
            {
                return new RecordingS3Client(config);
            }
            finally
            {
                _pending = null;
            }
        }
    }

    protected override void CustomizeRuntimePipeline(RuntimePipeline pipeline)
    {
        base.CustomizeRuntimePipeline(pipeline);
        if (_pending is not null)
            pipeline.AddHandlerBefore<Amazon.Runtime.Internal.Marshaller>(_pending);
    }
}

/// <summary>
/// Records the name of every AWS request the client issues.
/// </summary>
/// <remarks>
/// <para>
/// connector-spec §8 requires the caller's requested prefix to be validated <i>before</i> the
/// provider call, "otherwise an unauthorized <c>list</c> is issued and merely filtered on
/// return, which is slower and records the request in the provider's audit log as though it
/// were authorized."
/// </para>
/// <para>
/// That requirement is about a call's <b>absence</b>, which no assertion on returned data can
/// demonstrate: a wrapper that lists everything and discards the denied rows returns exactly
/// what one that never asked returns. Sitting in the SDK's request pipeline is what separates
/// them — it observes what really went out, not what the test believes it asked for.
/// </para>
/// <para>
/// CloudTrail would be the authoritative view and is what an auditor consults, but it lags by
/// minutes and would make the suite slow and flaky for no additional signal here.
/// </para>
/// <para>
/// Mirrors the <c>call_recorder</c> fixture in the Python suite, which registers a botocore
/// <c>before-call</c> handler for the same purpose.
/// </para>
/// </remarks>
public sealed class CallRecorder : PipelineHandler
{
    /// <summary>Where request names are appended. Set by the fixture.</summary>
    public List<string>? Sink { get; set; }

    public override void InvokeSync(IExecutionContext executionContext)
    {
        Record(executionContext);
        base.InvokeSync(executionContext);
    }

    public override Task<T> InvokeAsync<T>(IExecutionContext executionContext)
    {
        Record(executionContext);
        return base.InvokeAsync<T>(executionContext);
    }

    private void Record(IExecutionContext executionContext)
    {
        if (Sink is null)
            return;

        // The request object's type name is the operation: ListObjectsV2Request ->
        // "ListObjectsV2". Read from the request rather than a marshalled header so it holds
        // regardless of how the SDK renders the wire call.
        var name = executionContext.RequestContext.OriginalRequest.GetType().Name;
        if (name.EndsWith("Request", StringComparison.Ordinal))
            name = name[..^"Request".Length];

        lock (Sink)
        {
            Sink.Add(name);
        }
    }
}
