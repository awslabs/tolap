using System.Text.Json;

namespace Tolap.Core.Tests;

/// <summary>
/// Loads the published JSON Schemas from <c>schema/v1.0</c> at test time.
/// </summary>
/// <remarks>
/// Reading the files from disk is the point. <c>schema/v1.0/*.json</c> is the published
/// contract and this SDK re-declares parts of it as C# enums plus the switch arms in
/// <see cref="TolapJsonOptions"/>'s converters; restating the schema's values in a test
/// would create a second copy free to drift exactly as the first one did. See
/// docs/canonical-enforcement-spec.md section 14.
/// <para>
/// Every accessor throws rather than returning a default or an empty set when a path is
/// absent. A schema conformance test that skips when it cannot find the schema restores
/// the blind spot it exists to close: the SDK keeps whatever values it has while nothing
/// compares them to anything.
/// </para>
/// </remarks>
public static class SchemaHelper
{
    private static readonly string SchemaRoot = LocateSchemaRoot();

    private static readonly Dictionary<string, JsonDocument> Cache = new();

    private static string LocateSchemaRoot()
    {
        // The test binary runs from bin/<config>/<tfm>/, so walk up looking for the
        // repository's schema directory rather than hardcoding a depth that changes
        // with the build configuration.
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, "schema", "v1.0");
            if (Directory.Exists(candidate))
                return candidate;

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException(
            $"could not locate schema/v1.0 above {AppContext.BaseDirectory}; schema " +
            "conformance cannot be checked and MUST NOT be skipped (canonical spec section 14)");
    }

    /// <summary>
    /// Loads a published schema by bare name, for example <c>policy-definition</c>.
    /// </summary>
    public static JsonElement Load(string name)
    {
        lock (Cache)
        {
            if (!Cache.TryGetValue(name, out var document))
            {
                var path = Path.Combine(SchemaRoot, $"{name}.schema.json");
                if (!File.Exists(path))
                {
                    throw new FileNotFoundException(
                        $"published schema {path} is missing; schema conformance cannot be " +
                        "checked and MUST NOT be skipped (canonical spec section 14)");
                }

                document = JsonDocument.Parse(File.ReadAllText(path));
                Cache[name] = document;
            }

            return document.RootElement;
        }
    }

    /// <summary>
    /// Reads the <c>enum</c> list at a keyword path inside a loaded schema.
    /// </summary>
    /// <remarks>
    /// Throws when the path is absent. A missing path means the published enum moved or
    /// was renamed, which is itself the finding -- returning an empty set instead would
    /// make every comparison against it pass while checking nothing.
    /// </remarks>
    public static IReadOnlySet<string> EnumAt(string schemaName, params string[] path)
    {
        var node = Load(schemaName);

        for (var i = 0; i < path.Length; i++)
        {
            if (node.ValueKind != JsonValueKind.Object
                || !node.TryGetProperty(path[i], out var next))
            {
                throw new InvalidOperationException(
                    $"schema path {string.Join('.', path)} is missing at segment " +
                    $"'{path[i]}' (position {i}) in {schemaName}.schema.json; this SDK's " +
                    "native enum is no longer being compared to anything " +
                    "(canonical spec section 14)");
            }

            node = next;
        }

        if (node.ValueKind != JsonValueKind.Array || node.GetArrayLength() == 0)
        {
            throw new InvalidOperationException(
                $"schema path {string.Join('.', path)} in {schemaName}.schema.json is not " +
                $"a non-empty enum list (found {node.ValueKind})");
        }

        return node.EnumerateArray()
            .Select(value => value.GetString()
                ?? throw new InvalidOperationException("enum contains a non-string value"))
            .ToHashSet(StringComparer.Ordinal);
    }
}
