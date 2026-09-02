using System.Text.Json;
using System.Text.Json.Serialization;

namespace Tolap.Core;

/// <summary>
/// Pre-configured JSON serialization options and helpers for TOLAP types.
/// </summary>
public static class TolapJsonOptions
{
    private static readonly JsonSerializerOptions s_options = CreateOptions();

    /// <summary>
    /// Gets the shared, pre-configured serializer options.
    /// </summary>
    public static JsonSerializerOptions Default => s_options;

    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            WriteIndented = false,
            PropertyNameCaseInsensitive = true
        };
        options.Converters.Add(new FilterOperatorJsonConverter());
        options.Converters.Add(new MaskTypeJsonConverter());
        options.Converters.Add(new SigningAlgorithmJsonConverter());
        options.Converters.Add(new AssigneeTypeJsonConverter());
        options.Converters.Add(new PrincipalTypeJsonConverter());
        options.Converters.Add(new UtcAssumingDateTimeOffsetJsonConverter());
        options.Converters.Add(new UtcAssumingNullableDateTimeOffsetJsonConverter());
        options.Converters.Add(new MaskingParametersJsonConverter());
        return options;
    }

    /// <summary>
    /// Serializes a value to JSON using TOLAP conventions.
    /// </summary>
    public static string Serialize<T>(T value)
    {
        return JsonSerializer.Serialize(value, s_options);
    }

    /// <summary>
    /// Deserializes JSON to a typed value using TOLAP conventions.
    /// </summary>
    public static T Deserialize<T>(string json)
    {
        return JsonSerializer.Deserialize<T>(json, s_options)
            ?? throw new JsonException($"Failed to deserialize JSON to {typeof(T).Name}");
    }
}

/// <summary>
/// Reads a timestamp that carries no UTC offset as UTC rather than as local time.
/// </summary>
/// <remarks>
/// <para>System.Text.Json's default reader treats <c>"2026-09-01T09:58:00"</c> — an ISO 8601
/// string with no offset and no <c>Z</c> — as <b>local</b> time. That makes the deserialized
/// instant, and therefore the canonical signing bytes, depend on the host's timezone: the same
/// JSON signed to <c>09:58:00Z</c> on a UTC host, <c>13:58:00Z</c> on <c>EST5EDT</c> and
/// <c>16:58:00Z</c> on <c>America/Los_Angeles</c>. That is a divergence between two
/// <i>deployments of the same SDK</i>, which is worse than a cross-SDK one and which no
/// fixture pinning a single host could detect.</para>
/// <para>Python already assumed UTC, so assuming it here aligns .NET with the only
/// host-independent reading available. Spec section 2 rule 4 mandates normalizing to UTC
/// before signing but is silent on what an offset-less value means; this converter is what
/// makes the answer not depend on where the process happens to run.</para>
/// <para>A value that <i>does</i> carry an offset is unaffected — <c>+02:00</c> and <c>Z</c>
/// both parse to the instant they name, and rule 4 folds them to the same bytes. Writing is
/// left to the default writer, because transport bytes are not signed; only the reading side
/// could move an instant.</para>
/// </remarks>
public sealed class UtcAssumingDateTimeOffsetJsonConverter : JsonConverter<DateTimeOffset>
{
    public override DateTimeOffset Read(
        ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var text = reader.GetString()
                   ?? throw new JsonException("Expected a string for DateTimeOffset");

        // AssumeUniversal is the whole point; AdjustToUniversal keeps the returned offset at
        // zero so a later ToUniversalTime is a no-op rather than a second conversion.
        if (!DateTimeOffset.TryParse(
                text,
                System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.AssumeUniversal
                    | System.Globalization.DateTimeStyles.AdjustToUniversal,
                out var parsed))
        {
            throw new JsonException($"Could not parse timestamp: {text}");
        }

        return parsed;
    }

    public override void Write(
        Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options)
        => writer.WriteStringValue(value);
}

/// <inheritdoc cref="UtcAssumingDateTimeOffsetJsonConverter"/>
/// <remarks>
/// The nullable companion. Registered separately because System.Text.Json does not derive a
/// <c>T?</c> converter from a <c>T</c> one for value types, and every optional timestamp in the
/// model — <c>expiresAt</c>, <c>revokedAt</c>, <c>delegatedAt</c> — is nullable, so omitting
/// this would leave the bug in place for exactly the fields this feature added.
/// </remarks>
public sealed class UtcAssumingNullableDateTimeOffsetJsonConverter : JsonConverter<DateTimeOffset?>
{
    private static readonly UtcAssumingDateTimeOffsetJsonConverter Inner = new();

    public override DateTimeOffset? Read(
        ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => reader.TokenType == JsonTokenType.Null
            ? null
            : Inner.Read(ref reader, typeof(DateTimeOffset), options);

    public override void Write(
        Utf8JsonWriter writer, DateTimeOffset? value, JsonSerializerOptions options)
    {
        if (value is null) writer.WriteNullValue();
        else writer.WriteStringValue(value.Value);
    }
}

/// <summary>
/// Converts FilterOperator enum to/from camelCase JSON string values matching the schema.
/// </summary>
public sealed class FilterOperatorJsonConverter : JsonConverter<FilterOperator>
{
    public override FilterOperator Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var value = reader.GetString() ?? throw new JsonException("Expected a string for FilterOperator");
        return value switch
        {
            "equals" => FilterOperator.Equals,
            "notEquals" => FilterOperator.NotEquals,
            "in" => FilterOperator.In,
            "notIn" => FilterOperator.NotIn,
            "greaterThan" => FilterOperator.GreaterThan,
            "lessThan" => FilterOperator.LessThan,
            "contains" => FilterOperator.Contains,
            "startsWith" => FilterOperator.StartsWith,
            "matches" => FilterOperator.Matches,
            "greaterThanOrEqual" => FilterOperator.GreaterThanOrEqual,
            "lessThanOrEqual" => FilterOperator.LessThanOrEqual,
            "like" => FilterOperator.Like,
            "notLike" => FilterOperator.NotLike,
            "isNull" => FilterOperator.IsNull,
            "isNotNull" => FilterOperator.IsNotNull,
            "between" => FilterOperator.Between,
            _ => throw new JsonException($"Unknown FilterOperator value: {value}")
        };
    }

    public override void Write(Utf8JsonWriter writer, FilterOperator value, JsonSerializerOptions options)
    {
        var str = value switch
        {
            FilterOperator.Equals => "equals",
            FilterOperator.NotEquals => "notEquals",
            FilterOperator.In => "in",
            FilterOperator.NotIn => "notIn",
            FilterOperator.GreaterThan => "greaterThan",
            FilterOperator.LessThan => "lessThan",
            FilterOperator.Contains => "contains",
            FilterOperator.StartsWith => "startsWith",
            FilterOperator.Matches => "matches",
            FilterOperator.GreaterThanOrEqual => "greaterThanOrEqual",
            FilterOperator.LessThanOrEqual => "lessThanOrEqual",
            FilterOperator.Like => "like",
            FilterOperator.NotLike => "notLike",
            FilterOperator.IsNull => "isNull",
            FilterOperator.IsNotNull => "isNotNull",
            FilterOperator.Between => "between",
            _ => throw new JsonException($"Unknown FilterOperator: {value}")
        };
        writer.WriteStringValue(str);
    }
}

/// <summary>
/// Converts MaskType enum to/from lowercase JSON string values matching the schema.
/// </summary>
public sealed class MaskTypeJsonConverter : JsonConverter<MaskType>
{
    public override MaskType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var value = reader.GetString() ?? throw new JsonException("Expected a string for MaskType");
        return value switch
        {
            "full" => MaskType.Full,
            "partial" => MaskType.Partial,
            "hash" => MaskType.Hash,
            "null" => MaskType.Null,
            "redact" => MaskType.Redact,
            _ => throw new JsonException($"Unknown MaskType value: {value}")
        };
    }

    public override void Write(Utf8JsonWriter writer, MaskType value, JsonSerializerOptions options)
    {
        var str = value switch
        {
            MaskType.Full => "full",
            MaskType.Partial => "partial",
            MaskType.Hash => "hash",
            MaskType.Null => "null",
            MaskType.Redact => "redact",
            _ => throw new JsonException($"Unknown MaskType: {value}")
        };
        writer.WriteStringValue(str);
    }
}

/// <summary>
/// Converts SigningAlgorithm enum to/from JSON string values matching the schema.
/// </summary>
public sealed class SigningAlgorithmJsonConverter : JsonConverter<SigningAlgorithm>
{
    public override SigningAlgorithm Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var value = reader.GetString() ?? throw new JsonException("Expected a string for SigningAlgorithm");
        return value switch
        {
            "hmac-sha256" => SigningAlgorithm.HmacSha256,
            "hmac-sha512" => SigningAlgorithm.HmacSha512,
            "ed25519" => SigningAlgorithm.Ed25519,
            _ => throw new JsonException($"Unknown SigningAlgorithm value: {value}")
        };
    }

    public override void Write(Utf8JsonWriter writer, SigningAlgorithm value, JsonSerializerOptions options)
    {
        var str = value switch
        {
            SigningAlgorithm.HmacSha256 => "hmac-sha256",
            SigningAlgorithm.HmacSha512 => "hmac-sha512",
            SigningAlgorithm.Ed25519 => "ed25519",
            _ => throw new JsonException($"Unknown SigningAlgorithm: {value}")
        };
        writer.WriteStringValue(str);
    }
}

/// <summary>
/// Converts AssigneeType enum to/from JSON string values matching the schema.
/// </summary>
public sealed class AssigneeTypeJsonConverter : JsonConverter<AssigneeType>
{
    public override AssigneeType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var value = reader.GetString() ?? throw new JsonException("Expected a string for AssigneeType");
        return value switch
        {
            "user" => AssigneeType.User,
            "group" => AssigneeType.Group,
            "role" => AssigneeType.Role,
            "serviceAccount" => AssigneeType.ServiceAccount,
            _ => throw new JsonException($"Unknown AssigneeType value: {value}")
        };
    }

    public override void Write(Utf8JsonWriter writer, AssigneeType value, JsonSerializerOptions options)
    {
        var str = value switch
        {
            AssigneeType.User => "user",
            AssigneeType.Group => "group",
            AssigneeType.Role => "role",
            AssigneeType.ServiceAccount => "serviceAccount",
            _ => throw new JsonException($"Unknown AssigneeType: {value}")
        };
        writer.WriteStringValue(str);
    }
}

/// <summary>
/// Converts PrincipalType enum to/from the lowercase JSON string values a delegation hop
/// carries on the wire.
/// </summary>
/// <remarks>
/// Modelled on <see cref="AssigneeTypeJsonConverter"/>, and fail-closed for the same reason:
/// an unrecognized principal type throws at deserialization rather than arriving in
/// <see cref="DelegationChainValidator"/> as a value no narrowing rule covers. It must be
/// registered in <b>both</b> option factories — <see cref="TolapJsonOptions"/> for transport
/// and <see cref="CanonicalJson"/> for signing — because a converter missing from the
/// canonical writer produces bytes that disagree with the other two SDKs.
/// </remarks>
public sealed class PrincipalTypeJsonConverter : JsonConverter<PrincipalType>
{
    public override PrincipalType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var value = reader.GetString() ?? throw new JsonException("Expected a string for PrincipalType");
        return value switch
        {
            "user" => PrincipalType.User,
            "agent" => PrincipalType.Agent,
            "service" => PrincipalType.Service,
            _ => throw new JsonException($"Unknown PrincipalType value: {value}")
        };
    }

    public override void Write(Utf8JsonWriter writer, PrincipalType value, JsonSerializerOptions options)
    {
        var str = value switch
        {
            PrincipalType.User => "user",
            PrincipalType.Agent => "agent",
            PrincipalType.Service => "service",
            _ => throw new JsonException($"Unknown PrincipalType: {value}")
        };
        writer.WriteStringValue(str);
    }
}

/// <summary>
/// Custom converter for MaskingParameters that handles the maskChar as a string in JSON
/// but as a char in C#.
/// </summary>
public sealed class MaskingParametersJsonConverter : JsonConverter<MaskingParameters>
{
    public override MaskingParameters Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.StartObject)
            throw new JsonException("Expected StartObject for MaskingParameters");

        int? showFirst = null;
        int? showLast = null;
        char maskChar = '*';
        string? algorithm = null;

        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.EndObject)
                return new MaskingParameters(showFirst, showLast, maskChar, algorithm);

            if (reader.TokenType != JsonTokenType.PropertyName)
                throw new JsonException("Expected PropertyName");

            var propertyName = reader.GetString();
            reader.Read();

            switch (propertyName)
            {
                case "showFirst":
                    showFirst = reader.GetInt32();
                    break;
                case "showLast":
                    showLast = reader.GetInt32();
                    break;
                case "maskChar":
                    var maskStr = reader.GetString();
                    if (!string.IsNullOrEmpty(maskStr))
                        maskChar = maskStr[0];
                    break;
                case "algorithm":
                    algorithm = reader.GetString();
                    break;
                default:
                    reader.Skip();
                    break;
            }
        }

        throw new JsonException("Unexpected end of JSON for MaskingParameters");
    }

    public override void Write(Utf8JsonWriter writer, MaskingParameters value, JsonSerializerOptions options)
    {
        writer.WriteStartObject();

        if (value.ShowFirst.HasValue)
            writer.WriteNumber("showFirst", value.ShowFirst.Value);

        if (value.ShowLast.HasValue)
            writer.WriteNumber("showLast", value.ShowLast.Value);

        if (value.MaskChar != '*')
            writer.WriteString("maskChar", value.MaskChar.ToString());

        if (value.Algorithm is not null)
            writer.WriteString("algorithm", value.Algorithm);

        writer.WriteEndObject();
    }
}
