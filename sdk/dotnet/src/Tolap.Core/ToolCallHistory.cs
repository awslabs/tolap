namespace Tolap.Core;

/// <summary>
/// A bounded, in-order record of recent tool calls, for supplying a judge its context
/// window (canonical-enforcement-spec.md section 15.4).
/// </summary>
/// <remarks>
/// <para>Purpose drift is a property of a sequence, not of a single call. An agent that asks
/// for one more field each turn is unremarkable at every individual step and obvious across
/// ten, so a judge given only the current call cannot see the thing it exists to notice.</para>
/// <para>Deliberately not persistent and not shared. It holds whatever the caller records,
/// which may include argument values, so a process-local buffer that dies with the session
/// is the narrowest thing that does the job. An integrator wanting durable history should
/// store it themselves, with the retention rules their data demands.</para>
/// <para>Not thread-safe. Guard it if a single conversation is driven from several threads;
/// the common case is one wrapper serving one conversation.</para>
/// </remarks>
public sealed class ToolCallHistory
{
    private readonly Queue<string> _entries = new();

    /// <summary>
    /// Creates a history retaining at most <paramref name="maxSize"/> entries.
    /// </summary>
    /// <param name="maxSize">
    /// How many calls to keep. Must be at least one: a zero-size window would make
    /// <see cref="Record"/> a no-op and hand the judge an empty history that looks like a
    /// fresh conversation, which is precisely the state a drifting agent would benefit from.
    /// </param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// When <paramref name="maxSize"/> is less than one.
    /// </exception>
    public ToolCallHistory(int maxSize = JudgeDispositions.DefaultHistoryWindow)
    {
        if (maxSize < 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maxSize), maxSize,
                "A tool-call history retains at least one entry; a zero-size window " +
                "silently hands the judge an empty conversation.");
        }

        MaxSize = maxSize;
    }

    /// <summary>The retention bound.</summary>
    public int MaxSize { get; }

    /// <summary>The number of entries currently retained.</summary>
    public int Count => _entries.Count;

    /// <summary>
    /// Records a call, evicting the oldest entry once the window is full.
    /// </summary>
    /// <exception cref="ArgumentNullException">When <paramref name="toolCall"/> is null.</exception>
    public void Record(string toolCall)
    {
        ArgumentNullException.ThrowIfNull(toolCall);

        _entries.Enqueue(toolCall);
        while (_entries.Count > MaxSize)
            _entries.Dequeue();
    }

    /// <summary>
    /// The retained calls, oldest first.
    /// </summary>
    /// <remarks>
    /// Oldest first because a judge reading a trajectory needs it in the order it happened.
    /// Returns a copy, so a caller holding the result cannot see it change underneath them
    /// on the next <see cref="Record"/>.
    /// </remarks>
    public string[] GetRecent() => _entries.ToArray();

    /// <summary>
    /// Discards every entry, for reuse across conversations.
    /// </summary>
    public void Clear() => _entries.Clear();
}
