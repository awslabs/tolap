using System.Security.Cryptography;
using System.Text;

namespace Tolap.Core;

/// <summary>
/// A tool's declaration that its result has already been policy-enforced.
/// </summary>
/// <remarks>
/// <para>
/// Some tools enforce at the data layer: an ORM adapter that applies the result pipeline
/// as it materializes rows, say. Running the pipeline again in the wrapper is not
/// harmless. <c>hash</c> masking is not idempotent, so a hashed field comes back hashed
/// twice, and a row filter on a field the data layer already hid fails closed and drops
/// every row.
/// </para>
/// <para>
/// Such a tool returns <see cref="EnforcedResult{T}"/> instead of the bare data. The
/// marker is bound to the signature of the signed context the pipeline was applied under,
/// and the context wrapper honours it only when that signature matches the current call's
/// verified context exactly, compared in constant time. Anything else (another context, a
/// tampered or empty signature, an unsigned context) is treated as though no marker were
/// present, and the full pipeline runs.
/// </para>
/// <para>
/// A marker is a type, never a dictionary key or a caller-supplied flag. A record with
/// <c>data</c> and <c>contextSignature</c> keys is ordinary data. The constructor is
/// <c>private protected</c> and <see cref="EnforcedResult{T}"/> is sealed, so no type
/// outside this assembly can pose as a marker.
/// </para>
/// </remarks>
public abstract class EnforcedResult
{
    private protected EnforcedResult(string contextSignature)
    {
        ContextSignature = contextSignature;
    }

    /// <summary>The signature of the context the data was enforced under.</summary>
    public string ContextSignature { get; }

    /// <summary>The carried data, untyped.</summary>
    public abstract object? UntypedData { get; }

    /// <summary>Binds <paramref name="data"/> to the signature of the context it was enforced under.</summary>
    /// <exception cref="ArgumentException">
    /// Thrown when the context is unsigned. An unbound marker could never be honoured, so
    /// building one is a mistake worth surfacing at the call site rather than as a silent
    /// second pass.
    /// </exception>
    public static EnforcedResult<T> For<T>(T data, SecurityContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        var signature = context.Integrity?.Signature;
        if (string.IsNullOrEmpty(signature))
        {
            throw new ArgumentException(
                "EnforcedResult needs a signed context: the marker is bound to the context "
                + "signature, and an unsigned context has none",
                nameof(context));
        }
        return new EnforcedResult<T>(data, signature);
    }

    /// <summary>
    /// Whether <paramref name="marker"/> names exactly the signature <paramref name="context"/>
    /// carries, compared in constant time over the UTF-8 bytes.
    /// </summary>
    /// <remarks>
    /// This proves only that the two strings match. The caller must separately have
    /// verified the context signature, or the match proves nothing: an unverified
    /// signature field is whatever the sender wrote.
    /// </remarks>
    public static bool IsBoundTo(EnforcedResult marker, SecurityContext context)
    {
        ArgumentNullException.ThrowIfNull(marker);
        ArgumentNullException.ThrowIfNull(context);
        var expected = context.Integrity?.Signature;
        var presented = marker.ContextSignature;
        if (string.IsNullOrEmpty(expected) || presented is null)
            return false;
        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(presented), Encoding.UTF8.GetBytes(expected));
    }

    /// <summary>Whether a marker appears anywhere in a record, list or tree.</summary>
    public static bool Contains(object? node) => Found(node);

    private static bool Found(object? node)
    {
        switch (node)
        {
            case EnforcedResult:
                return true;
            case IReadOnlyDictionary<string, object?> dict:
                return dict.Values.Any(Found);
            case IReadOnlyList<Dictionary<string, object?>> records:
                return records.Any(Found);
            case IReadOnlyList<object?> list:
                return list.Any(Found);
            default:
                return false;
        }
    }

    /// <summary>Replaces every marker in a tree with the data it carries.</summary>
    /// <remarks>
    /// Every pipeline step walks dictionaries and lists, and none of them looks inside an
    /// arbitrary object. A marker left in place would carry its data past the hidden-field
    /// strip and masking, and a serializer would then write it out whole. So an unhonoured
    /// marker is unwrapped before enforcement and its contents are enforced like any other
    /// data. Containers are rebuilt only when a marker was found beneath them. Lazy
    /// sequences are never enumerated; they are unenforceable shapes already.
    /// </remarks>
    public static object? Unwrap(object? node) => Unwrap(node, out _);

    private static object? Unwrap(object? node, out bool changed)
    {
        switch (node)
        {
            case EnforcedResult marker:
                changed = true;
                return Unwrap(marker.UntypedData, out _);

            case Dictionary<string, object?> dict:
                return UnwrapPairs(dict, dict, dict.Comparer, out changed);

            case IReadOnlyDictionary<string, object?> readOnly:
                return UnwrapPairs(readOnly, readOnly, null, out changed);

            case IReadOnlyList<Dictionary<string, object?>> records:
            {
                var any = false;
                var rebuilt = new List<Dictionary<string, object?>>(records.Count);
                foreach (var record in records)
                {
                    var value = Unwrap(record, out var c);
                    any |= c;
                    rebuilt.Add((Dictionary<string, object?>)value!);
                }
                changed = any;
                return any ? rebuilt : node;
            }

            case IReadOnlyList<object?> list:
            {
                var any = false;
                var rebuilt = new List<object?>(list.Count);
                foreach (var item in list)
                {
                    rebuilt.Add(Unwrap(item, out var c));
                    any |= c;
                }
                changed = any;
                return any ? rebuilt : node;
            }

            default:
                changed = false;
                return node;
        }
    }

    private static object UnwrapPairs(
        object original,
        IEnumerable<KeyValuePair<string, object?>> pairs,
        IEqualityComparer<string>? comparer,
        out bool changed)
    {
        var any = false;
        // The original comparer is kept, so a case-insensitive record stays one.
        var rebuilt = new Dictionary<string, object?>(comparer);
        foreach (var (key, value) in pairs)
        {
            rebuilt[key] = Unwrap(value, out var c);
            any |= c;
        }
        changed = any;
        return any ? rebuilt : original;
    }
}

/// <summary>
/// Tool output the data layer already ran the result pipeline over, bound to the
/// signature of the context it was enforced under.
/// </summary>
/// <typeparam name="T">The carried data's type.</typeparam>
public sealed class EnforcedResult<T> : EnforcedResult
{
    /// <summary>Creates a marker. Prefer <see cref="EnforcedResult.For{T}"/>.</summary>
    public EnforcedResult(T data, string contextSignature) : base(contextSignature)
    {
        Data = data;
    }

    /// <summary>The data the tool enforced.</summary>
    public T Data { get; }

    /// <inheritdoc />
    public override object? UntypedData => Data;

    /// <summary>Names the type only, so logging a marker does not log its records.</summary>
    public override string ToString() => "EnforcedResult { Data = [hidden] }";
}
