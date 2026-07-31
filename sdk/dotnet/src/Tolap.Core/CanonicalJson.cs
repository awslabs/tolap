using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace Tolap.Core;

/// <summary>
/// Produces the canonical JSON form used for signature computation.
/// </summary>
/// <remarks>
/// Per canonical-enforcement-spec.md section 1 the signed bytes are:
/// recursively key-sorted (byte-wise ascending), compact (no whitespace),
/// camelCase, nulls omitted, empty arrays preserved, and raw UTF-8 with no
/// <c>\uXXXX</c> or HTML escaping.
///
/// <see cref="TolapJsonOptions"/> alone cannot produce this: System.Text.Json's
/// default encoder escapes <c>&lt;</c>, <c>&amp;</c>, <c>+</c> and non-ASCII, it
/// emits properties in C# declaration order rather than sorted order, and
/// <see cref="MaskingParametersJsonConverter"/> elides <c>maskChar</c> when it
/// equals the type default. Any of the three breaks byte-for-byte agreement with
/// the Python and TypeScript SDKs, so the canonical writer re-serializes through a
/// sorted <see cref="JsonNode"/>-like walk with relaxed escaping and no default
/// elision.
/// </remarks>
public static class CanonicalJson
{
    private static readonly JsonSerializerOptions s_intermediateOptions = CreateIntermediateOptions();

    private static readonly JsonWriterOptions s_writerOptions = new()
    {
        Indented = false,
        // The default encoder escapes '<', '&', '+' and every non-ASCII rune, which
        // would make .NET's bytes differ from Python's ensure_ascii=False output.
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        SkipValidation = false
    };

    private static JsonSerializerOptions CreateIntermediateOptions()
    {
        // Same conventions as TolapJsonOptions, minus the converters that elide
        // explicitly-present values: the signed form must not depend on whether a
        // parameter happens to equal its type default.
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
            WriteIndented = false,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };
        options.Converters.Add(new FilterOperatorJsonConverter());
        options.Converters.Add(new MaskTypeJsonConverter());
        options.Converters.Add(new SigningAlgorithmJsonConverter());
        options.Converters.Add(new AssigneeTypeJsonConverter());
        options.Converters.Add(new CanonicalMaskingParametersJsonConverter());
        options.Converters.Add(new CanonicalTimestampJsonConverter());
        options.Converters.Add(new CanonicalNullableTimestampJsonConverter());
        return options;
    }

    /// <summary>
    /// Normalizes an instant to RFC 3339 in UTC with a <c>Z</c> suffix.
    /// </summary>
    /// <remarks>
    /// Signing must not distinguish <c>+00:00</c> from <c>Z</c>, so both fold to the
    /// same bytes (spec section 2 rule 4). Fractional seconds are <b>truncated to
    /// milliseconds</b> per spec section 2 rule 5 — omitted when zero, otherwise
    /// exactly three digits. Milliseconds are the greatest precision all three SDKs
    /// represent exactly: JavaScript's <c>Date</c> cannot hold sub-millisecond
    /// values, so signing at .NET's native tick precision would produce bytes
    /// TypeScript could never reproduce.
    /// </remarks>
    public static string NormalizeTimestamp(DateTimeOffset value)
    {
        var utc = value.ToUniversalTime();
        // Truncate, never round: rounding could move an expiry later than issued.
        var milliseconds = (int)(utc.Ticks % TimeSpan.TicksPerSecond / TimeSpan.TicksPerMillisecond);
        return milliseconds == 0
            ? utc.ToString("yyyy-MM-ddTHH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture)
            : utc.ToString("yyyy-MM-ddTHH:mm:ss.fff'Z'", System.Globalization.CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// Serializes a value into the canonical signing form.
    /// </summary>
    public static string Serialize<T>(T value)
    {
        // Round-trip through a JsonDocument so the sorted writer sees the projected
        // camelCase shape rather than the CLR type's declaration order.
        var intermediate = JsonSerializer.Serialize(value, s_intermediateOptions);
        using var document = JsonDocument.Parse(intermediate);
        return Canonicalize(document.RootElement);
    }

    /// <summary>
    /// Rewrites an already-parsed JSON element into the canonical signing form.
    /// </summary>
    public static string Canonicalize(JsonElement element)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, s_writerOptions))
        {
            WriteSorted(writer, element);
        }
        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static void WriteSorted(Utf8JsonWriter writer, JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                // Byte-wise ascending on the key string. StringComparer.Ordinal
                // matches Python's sort_keys and JavaScript's Array#sort default,
                // which culture-aware comparison would not.
                foreach (var property in element.EnumerateObject()
                             .Where(p => p.Value.ValueKind != JsonValueKind.Null)
                             .OrderBy(p => p.Name, StringComparer.Ordinal))
                {
                    writer.WritePropertyName(property.Name);
                    WriteSorted(writer, property.Value);
                }
                writer.WriteEndObject();
                break;

            case JsonValueKind.Array:
                // Empty arrays are preserved: [] is "deny everything", which is
                // semantically distinct from an absent allow-list.
                writer.WriteStartArray();
                foreach (var item in element.EnumerateArray())
                {
                    WriteSorted(writer, item);
                }
                writer.WriteEndArray();
                break;

            default:
                element.WriteTo(writer);
                break;
        }
    }
}

/// <summary>
/// Canonical-form converter for <see cref="MaskingParameters"/>: writes every
/// explicitly-present value, including a <c>maskChar</c> that equals the type
/// default.
/// </summary>
/// <remarks>
/// The transport converter (<see cref="MaskingParametersJsonConverter"/>) omits
/// <c>maskChar</c> when it is <c>'*'</c>. Default-value elision is forbidden in the
/// signed form (canonical-enforcement-spec.md section 1) because it makes the bytes
/// depend on whether a value coincides with a C# default that the other SDKs do
/// not share.
/// </remarks>
internal sealed class CanonicalMaskingParametersJsonConverter
    : System.Text.Json.Serialization.JsonConverter<MaskingParameters>
{
    public override MaskingParameters Read(
        ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => new MaskingParametersJsonConverter().Read(ref reader, typeToConvert, options);

    public override void Write(Utf8JsonWriter writer, MaskingParameters value, JsonSerializerOptions options)
    {
        writer.WriteStartObject();

        if (value.ShowFirst.HasValue)
            writer.WriteNumber("showFirst", value.ShowFirst.Value);

        if (value.ShowLast.HasValue)
            writer.WriteNumber("showLast", value.ShowLast.Value);

        writer.WriteString("maskChar", value.MaskChar.ToString());

        if (value.Algorithm is not null)
            writer.WriteString("algorithm", value.Algorithm);

        writer.WriteEndObject();
    }
}

/// <summary>
/// Writes a <see cref="DateTimeOffset"/> as UTC with a <c>Z</c> suffix for the
/// canonical signing form.
/// </summary>
internal sealed class CanonicalTimestampJsonConverter
    : System.Text.Json.Serialization.JsonConverter<DateTimeOffset>
{
    public override DateTimeOffset Read(
        ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => reader.GetDateTimeOffset();

    public override void Write(Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options)
        => writer.WriteStringValue(CanonicalJson.NormalizeTimestamp(value));
}

/// <summary>
/// Nullable counterpart to <see cref="CanonicalTimestampJsonConverter"/>.
/// </summary>
internal sealed class CanonicalNullableTimestampJsonConverter
    : System.Text.Json.Serialization.JsonConverter<DateTimeOffset?>
{
    public override DateTimeOffset? Read(
        ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => reader.TokenType == JsonTokenType.Null ? null : reader.GetDateTimeOffset();

    public override void Write(Utf8JsonWriter writer, DateTimeOffset? value, JsonSerializerOptions options)
    {
        if (value is null)
        {
            writer.WriteNullValue();
            return;
        }
        writer.WriteStringValue(CanonicalJson.NormalizeTimestamp(value.Value));
    }
}
