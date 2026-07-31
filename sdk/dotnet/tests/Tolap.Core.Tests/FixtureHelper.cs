using System.Text.Json;

namespace Tolap.Core.Tests;

/// <summary>
/// Helper for loading test fixtures from the shared fixtures directory.
/// </summary>
public static class FixtureHelper
{
    private static readonly string FixturesRoot;

    static FixtureHelper()
    {
        // Navigate from test project output directory to fixtures root
        // Output is in bin/Debug/net8.0/ relative to test project
        var testDir = AppContext.BaseDirectory;
        var fixturesPath = Path.GetFullPath(Path.Combine(testDir, "..", "..", "..", "..", "..", "fixtures"));

        if (!Directory.Exists(fixturesPath))
        {
            // Try alternative path for different build configurations
            fixturesPath = Path.GetFullPath(Path.Combine(testDir, "..", "..", "..", "..", "..", "..", "..", "fixtures"));
        }

        FixturesRoot = fixturesPath;
    }

    public static string GetFixturePath(string relativePath)
    {
        var fullPath = Path.Combine(FixturesRoot, relativePath);
        if (!File.Exists(fullPath))
            throw new FileNotFoundException($"Fixture not found: {fullPath}");
        return fullPath;
    }

    public static string ReadFixture(string relativePath)
    {
        return File.ReadAllText(GetFixturePath(relativePath));
    }

    public static JsonElement ReadFixtureAsJson(string relativePath)
    {
        var json = ReadFixture(relativePath);
        return JsonDocument.Parse(json).RootElement;
    }

    public static T ReadFixtureAs<T>(string relativePath)
    {
        var json = ReadFixture(relativePath);
        return TolapJsonOptions.Deserialize<T>(json);
    }
}
