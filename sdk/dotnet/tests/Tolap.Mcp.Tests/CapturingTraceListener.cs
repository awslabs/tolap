using System.Diagnostics;

namespace Tolap.Mcp.Tests;

/// <summary>
/// Captures <see cref="Trace"/> warnings emitted by the test that created it, matching
/// the channel the enforcement-mode and AllowUnenforceableShapes warnings write to.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Trace.Listeners"/> is process-global and xunit runs test classes in
/// parallel, so a listener that recorded every warning it saw also recorded warnings
/// from whatever unrelated test happened to be running concurrently. That made
/// single-warning assertions non-deterministic: the suite intermittently failed with two
/// copies of the permissive-mode warning, one of them emitted by a different test class
/// constructing its own permissive wrapper. A flaky assertion in a security suite is
/// indistinguishable from a real regression, so the isolation is part of the contract
/// rather than a convenience.
/// </para>
/// <para>
/// Warnings are attributed by an <see cref="AsyncLocal{T}"/> scope token. The token flows
/// into whatever the test calls — including across <c>await</c> — but not into a
/// concurrently running test on another thread, so each listener sees exactly the
/// warnings its own test provoked. The <see cref="Trace"/> registration itself is
/// serialized under a lock because <see cref="TraceListenerCollection"/> is not
/// thread-safe for concurrent mutation.
/// </para>
/// </remarks>
internal sealed class CapturingTraceListener : TraceListener
{
    private static readonly AsyncLocal<CapturingTraceListener?> ActiveScope = new();
    private static readonly object ListenersLock = new();

    private readonly CapturingTraceListener? _previousScope;

    public CapturingTraceListener()
    {
        _previousScope = ActiveScope.Value;
        ActiveScope.Value = this;

        lock (ListenersLock)
        {
            Trace.Listeners.Add(this);
        }
    }

    /// <summary>
    /// Warnings emitted within this listener's scope, in emission order.
    /// </summary>
    public List<string> Warnings { get; } = new();

    public override void Write(string? message) { }

    public override void WriteLine(string? message) { }

    public override void TraceEvent(
        TraceEventCache? eventCache,
        string source,
        TraceEventType eventType,
        int id,
        string? message)
    {
        // Only record what this listener's own test provoked; a warning raised by a
        // concurrently running test carries a different (or no) scope token.
        if (eventType != TraceEventType.Warning || message is null)
            return;
        if (!ReferenceEquals(ActiveScope.Value, this))
            return;

        lock (Warnings)
        {
            Warnings.Add(message);
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            ActiveScope.Value = _previousScope;

            lock (ListenersLock)
            {
                Trace.Listeners.Remove(this);
            }
        }

        base.Dispose(disposing);
    }
}
