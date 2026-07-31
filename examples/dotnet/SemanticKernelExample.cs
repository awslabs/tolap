using System.ComponentModel;
using Microsoft.SemanticKernel;

namespace Tolap.Examples;

/// <summary>
/// TOLAP enforcement inside a Semantic Kernel plugin.
/// </summary>
/// <remarks>
/// <para>
/// A plugin is a class whose methods carry <c>[KernelFunction]</c>. TOLAP goes inside the method,
/// so the kernel's function metadata and planner behaviour are unchanged. Register it the usual
/// way: <c>kernel.Plugins.AddFromType&lt;PatientsPlugin&gt;()</c>.
/// </para>
/// <para>
/// The plugin holds no policy state and takes no credential. That is deliberate: a plugin instance
/// is typically registered once on a long-lived kernel and shared across requests, so caching a
/// user's context on it would leak one caller's permissions into the next caller's request.
/// <see cref="TolapSetup.EnforcedQuery"/> resolves and verifies per call instead.
/// </para>
/// <para>Verified against Microsoft.SemanticKernel 1.78.</para>
/// </remarks>
public sealed class SemanticKernelExample
{
    [KernelFunction("query_patients")]
    [Description("Query a patient table. Returns only what the caller's policy permits.")]
    public List<Dictionary<string, object?>> QueryPatients(string table)
        => TolapSetup.EnforcedQuery(table);
}
