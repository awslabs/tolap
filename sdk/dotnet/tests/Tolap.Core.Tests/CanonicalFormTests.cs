using System.Globalization;
using System.Text.Json;
using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// The two canonical-form rules a cross-SDK parity audit found all three SDKs getting wrong
/// (spec sections 1, 2 rule 4, and 14).
/// </summary>
/// <remarks>
/// <para>Neither rule is observable through an access decision: both produce identical
/// enforcement and differ only in the <b>signed bytes</b>. So no test comparing what a policy
/// permits could have caught either, and the only thing that did was comparing bytes across
/// the three languages — which is exactly what section 14 recommends, and why.</para>
/// <para>Driven from <c>fixtures/canonical-form/number-and-timestamp-forms.json</c> so all
/// three SDKs are held to one table.</para>
/// </remarks>
public class CanonicalFormTests
{
    private const string Fixture = "canonical-form/number-and-timestamp-forms.json";

    private static JsonElement Rule(string name) =>
        FixtureHelper.ReadFixtureAsJson(Fixture).GetProperty("rules")
            .EnumerateArray()
            .Single(r => r.GetProperty("rule").GetString() == name);

    // -- Whole-number floats render as integers --

    public static TheoryData<string, string> NumberCases()
    {
        var data = new TheoryData<string, string>();
        foreach (var c in Rule("whole-number-floats-render-as-integers").GetProperty("cases").EnumerateArray())
            data.Add(c.GetProperty("input").GetRawText(), c.GetProperty("canonical").GetString()!);
        return data;
    }

    [Theory]
    [MemberData(nameof(NumberCases))]
    public void CanonicalJson_RendersNumbersInTheSharedForm(string rawInput, string expected)
    {
        // .NET was already correct here; Python emitted `1.0`. Asserted anyway, because "the
        // one that was right" is exactly the SDK where a later refactor would reintroduce the
        // divergence unnoticed.
        var value = double.Parse(rawInput, CultureInfo.InvariantCulture);

        CanonicalJson.Serialize(value).Should().Be(expected);
    }

    [Fact]
    public void CanonicalJson_KeepsBooleansAsBooleans()
    {
        // The trap in the fix rather than in the bug: a numeric coercion that shortens whole
        // numbers must not turn `true` into `1`. Trivially true in .NET's type system and
        // asserted so the shared table means the same thing in all three languages.
        CanonicalJson.Serialize(true).Should().Be("true");
        CanonicalJson.Serialize(false).Should().Be("false");
    }

    [Fact]
    public void CanonicalPayload_RendersAWholeNumberThresholdAsAnInteger()
    {
        var policy = new EffectivePolicy(
            "1.0", "u", "t", "db:m:s",
            DateTimeOffset.Parse("2026-09-01T10:00:00Z", CultureInfo.InvariantCulture),
            DateTimeOffset.Parse("2026-09-01T11:00:00Z", CultureInfo.InvariantCulture),
            new[] { "p" },
            new PolicyPermissions(CanQuery: true, ReadOnly: true),
            PurposeProfile: new PurposeProfile(
                "campaign-x-overlap",
                Judge: new JudgeConfig(Enabled: true, ConfidenceThreshold: 1.0, EscalationThreshold: 0.0)));

        var payload = SecurityContextSigner.BuildCanonicalPayload(new SecurityContext(
            "1.0", "u", "t",
            DateTimeOffset.Parse("2026-09-01T10:00:00Z", CultureInfo.InvariantCulture),
            DateTimeOffset.Parse("2026-09-01T11:00:00Z", CultureInfo.InvariantCulture),
            new[] { policy }));

        payload.Should().Contain("\"confidenceThreshold\":1");
        payload.Should().NotContain("\"confidenceThreshold\":1.0");
        payload.Should().Contain("\"escalationThreshold\":0");
        payload.Should().Contain("\"enabled\":true", "a boolean survived as a boolean");
    }

    // -- Offset-less timestamps are UTC --

    public static TheoryData<string, string> TimestampCases()
    {
        var data = new TheoryData<string, string>();
        foreach (var c in Rule("offsetless-timestamps-are-utc").GetProperty("cases").EnumerateArray())
            data.Add(c.GetProperty("input").GetString()!, c.GetProperty("canonical").GetString()!);
        return data;
    }

    [Theory]
    [MemberData(nameof(TimestampCases))]
    public void Deserialization_ReadsAnOffsetlessTimestampAsUtc(string input, string expected)
    {
        // This is the bug, and it was .NET's: System.Text.Json read an offset-less value as
        // LOCAL time, so the same JSON signed to a different instant on every host. A
        // divergence between two deployments of one SDK, which no fixture pinned to a single
        // machine could detect.
        //
        // Asserted through DESERIALIZATION rather than by calling the normalizer directly,
        // because the normalizer was never the broken part — the instant was already wrong by
        // the time it arrived. A test that only exercised NormalizeTimestamp would have passed
        // throughout.
        var json = $"{{\"principalId\":\"p\",\"principalType\":\"user\",\"delegatedAt\":\"{input}\"}}";

        var hop = TolapJsonOptions.Deserialize<DelegationHop>(json);

        CanonicalJson.NormalizeTimestamp(hop.DelegatedAt!.Value).Should().Be(expected);
    }

    [Theory]
    [MemberData(nameof(TimestampCases))]
    public void Deserialization_IsIndependentOfTheHostTimezone(string input, string expected)
    {
        // The property that actually matters, and the reason the fixture lists timezones.
        // `TimeZoneInfo.ClearCachedData` plus a swapped `TZ` is the closest a single process
        // can get to running on another host; the fixture's timezone list is what CI's
        // UTC-only run cannot cover, so the values are exercised here instead.
        var original = Environment.GetEnvironmentVariable("TZ");
        var zones = Rule("offsetless-timestamps-are-utc").GetProperty("timezones")
            .EnumerateArray().Select(z => z.GetString()!).ToList();

        zones.Should().NotBeEmpty("the fixture must name the timezones to vary");

        try
        {
            foreach (var zone in zones)
            {
                Environment.SetEnvironmentVariable("TZ", zone);
                TimeZoneInfo.ClearCachedData();

                var json = $"{{\"principalId\":\"p\",\"principalType\":\"user\",\"delegatedAt\":\"{input}\"}}";
                var hop = TolapJsonOptions.Deserialize<DelegationHop>(json);

                CanonicalJson.NormalizeTimestamp(hop.DelegatedAt!.Value)
                    .Should().Be(expected, "TZ={0} must not change the signed instant", zone);
            }
        }
        finally
        {
            Environment.SetEnvironmentVariable("TZ", original);
            TimeZoneInfo.ClearCachedData();
        }
    }

    [Fact]
    public void Deserialization_RefusesAnUnparseableTimestamp()
    {
        // Fail closed at the boundary. A value that cannot be read must not become a default
        // instant, which for `expiresAt` would be DateTimeOffset.MinValue and therefore an
        // already-expired context — safe by luck rather than by design.
        var act = () => TolapJsonOptions.Deserialize<DelegationHop>(
            "{\"principalId\":\"p\",\"principalType\":\"user\",\"delegatedAt\":\"not-a-date\"}");

        act.Should().Throw<JsonException>();
    }
}
