using FluentAssertions;
using Xunit;

namespace Tolap.Integration.Tests.Aws;

/// <summary>
/// The AWS opt-in gate reports <b>skipped</b>, not passed, and opens when opted in.
/// </summary>
/// <remarks>
/// <para>
/// These are deliberately plain <c>[Fact]</c>s: a test that verifies the gate cannot be behind
/// the gate. That is exactly how the defect they guard against survived — the guard and the
/// guarded were the same mechanism, so a broken gate had no symptom.
/// </para>
/// <para>
/// The original bug was <c>if (Skip) return;</c> at the top of all 41 AWS test bodies. xunit
/// records an early return as a pass, so without credentials the run reported
/// <c>Passed: 307, Skipped: 0</c> — identical to a full run against real AWS. A suite built to
/// catch fail-open bugs was failing open about whether it had executed. Python's suite had the
/// same class of defect by a different route (a <c>pytestmark</c> in a <c>conftest.py</c>, which
/// pytest ignores), which is why both now carry a guard rather than a comment.
/// </para>
/// </remarks>
public class AwsGateTests
{
    /// <summary>Runs an action with an environment variable set, restoring it afterwards.</summary>
    private static T WithEnv<T>(string name, string? value, Func<T> body)
    {
        var original = Environment.GetEnvironmentVariable(name);
        Environment.SetEnvironmentVariable(name, value);
        try
        {
            return body();
        }
        finally
        {
            Environment.SetEnvironmentVariable(name, original);
        }
    }

    [Fact]
    public void GateSkipsWhenNotOptedIn()
    {
        WithEnv("TOLAP_TEST_AWS", null, () => new AwsFactAttribute().Skip)
            .Should().Be(AwsGate.OptInReason,
                "an AWS test must report skipped rather than passed without credentials");
    }

    [Fact]
    public void GateOpensWhenOptedIn()
    {
        // The half that a hardcoded skip would still satisfy: opting in must actually run them.
        WithEnv("TOLAP_TEST_AWS", "1", () => new AwsFactAttribute().Skip)
            .Should().BeNull("TOLAP_TEST_AWS=1 must not skip the suite it opts in to");
    }

    [Fact]
    public void TheoryGateMatchesTheFactGate()
    {
        // Two attribute classes, one condition. They drifted apart once already: the theory
        // cases were gated on TOLAP_TEST_AWS while the facts also required a KB id.
        WithEnv("TOLAP_TEST_AWS", null, () => new AwsTheoryAttribute().Skip)
            .Should().Be(new AwsFactAttribute().Skip);
    }

    [Fact]
    public void KbGateRequiresBothCredentialsAndAKnowledgeBase()
    {
        // Independent conditions, asserted independently -- collapsing them would silently skip
        // the filter-shape probes, which need credentials but no provisioned KB.
        WithEnv("TOLAP_TEST_AWS", null, () => WithEnv("TOLAP_TEST_KB_ID", "KB123", () =>
            new KbFactAttribute().Skip)).Should().Be(AwsGate.OptInReason);

        WithEnv("TOLAP_TEST_AWS", "1", () => WithEnv("TOLAP_TEST_KB_ID", null, () =>
            new KbFactAttribute().Skip)).Should().Be(AwsGate.NoKbReason);

        WithEnv("TOLAP_TEST_AWS", "1", () => WithEnv("TOLAP_TEST_KB_ID", "KB123", () =>
            new KbFactAttribute().Skip)).Should().BeNull();
    }

    [Fact]
    public void EveryAwsTestCarriesAGateAttribute()
    {
        // The gate is per-attribute, so a new test written with a plain [Fact] would run
        // unconditionally and fail without credentials. This catches that at build time rather
        // than in someone's first clean checkout.
        var ungated = typeof(AwsGateTests).Assembly.GetTypes()
            .Where(t => t.Namespace == typeof(AwsGateTests).Namespace && t != typeof(AwsGateTests))
            .SelectMany(t => t.GetMethods())
            .Where(m => m.GetCustomAttributes(typeof(FactAttribute), inherit: false).Length > 0)
            .Where(m => m.GetCustomAttributes(typeof(AwsFactAttribute), false).Length == 0
                     && m.GetCustomAttributes(typeof(AwsTheoryAttribute), false).Length == 0
                     && m.GetCustomAttributes(typeof(KbFactAttribute), false).Length == 0)
            .Select(m => $"{m.DeclaringType!.Name}.{m.Name}")
            .ToList();

        ungated.Should().BeEmpty(
            "an AWS test with a bare [Fact] runs without the opt-in gate and will fail on a "
            + "machine with no credentials; use [AwsFact], [AwsTheory] or [KbFact]");
    }

    [Fact]
    public void TheGateActuallyCoversTests()
    {
        // Without this, EveryAwsTestCarriesAGateAttribute would pass vacuously if the reflection
        // query matched nothing -- a renamed namespace, say.
        var gated = typeof(AwsGateTests).Assembly.GetTypes()
            .Where(t => t.Namespace == typeof(AwsGateTests).Namespace)
            .SelectMany(t => t.GetMethods())
            .Count(m => m.GetCustomAttributes(typeof(AwsFactAttribute), false).Length > 0
                     || m.GetCustomAttributes(typeof(AwsTheoryAttribute), false).Length > 0
                     || m.GetCustomAttributes(typeof(KbFactAttribute), false).Length > 0);

        gated.Should().BeGreaterThan(30,
            "expected the S3 (23), Athena (12) and Bedrock (8) suites to be discovered");
    }
}
