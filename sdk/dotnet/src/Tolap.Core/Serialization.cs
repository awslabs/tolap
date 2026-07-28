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
