using Xunit;

namespace Tolap.Integration.Tests.Aws;

/// <summary>
/// Opt-in gates for the AWS-backed tests that report <b>skipped</b> rather than passed.
/// </summary>
/// <remarks>
/// <para>
/// These replace an <c>if (Skip) return;</c> guard that opened all 41 AWS test bodies. xunit
/// records an early <c>return</c> as a <b>pass</b>, so on a machine without credentials the
/// summary read <c>Passed: 307, Skipped: 0</c> — byte-identical to a run where every AWS test
/// had actually executed and asserted. A suite whose whole purpose is to catch fail-open bugs
/// was itself failing open about whether it had run.
/// </para>
/// <para>
/// The gate lives in the attribute rather than the test body because xunit evaluates
/// <see cref="FactAttribute.Skip"/> during discovery, which is what produces a real skip
/// report. <c>Assert.Skip</c> would be the direct spelling but is xunit v3 only, and migrating
/// four test projects to v3 for a reporting fix is the wrong trade.
/// </para>
/// <para>
/// Environment variables are read per instance, not cached in a static, so a test run can set
/// them programmatically — the reporting-guard tests in <c>AwsGateTests</c> rely on that.
/// </para>
/// </remarks>
public sealed class AwsFactAttribute : FactAttribute
{
    public AwsFactAttribute() => Skip = AwsGate.SkipReason();
}

/// <inheritdoc cref="AwsFactAttribute"/>
public sealed class AwsTheoryAttribute : TheoryAttribute
{
    public AwsTheoryAttribute() => Skip = AwsGate.SkipReason();
}

/// <summary>
/// As <see cref="AwsFactAttribute"/>, and additionally requires a provisioned Knowledge Base.
/// </summary>
/// <remarks>
/// Separate from <see cref="AwsFactAttribute"/> because the two conditions are independent: the
/// Bedrock filter-shape probes need credentials but no KB, while end-to-end retrieval needs
/// both. Collapsing them would silently skip the shape probes whenever no KB happened to be up.
/// </remarks>
public sealed class KbFactAttribute : FactAttribute
{
    public KbFactAttribute() => Skip = AwsGate.SkipReason() ?? AwsGate.KbSkipReason();
}

/// <summary>The opt-in conditions, in one place so the reasons cannot drift apart.</summary>
public static class AwsGate
{
    public const string OptInReason = "AWS integration tests are opt-in; set TOLAP_TEST_AWS=1";
    public const string NoKbReason = "needs a provisioned KB; set TOLAP_TEST_KB_ID";

    /// <summary>Null when the AWS tests are opted in, otherwise the reason to skip.</summary>
    public static string? SkipReason()
        => Environment.GetEnvironmentVariable("TOLAP_TEST_AWS") == "1" ? null : OptInReason;

    /// <summary>Null when a KB id is present, otherwise the reason to skip.</summary>
    public static string? KbSkipReason()
        => string.IsNullOrEmpty(Environment.GetEnvironmentVariable("TOLAP_TEST_KB_ID"))
            ? NoKbReason
            : null;
}
