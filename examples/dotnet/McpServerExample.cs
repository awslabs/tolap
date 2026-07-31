using System.ComponentModel;
using ModelContextProtocol.Server;

namespace Tolap.Examples;

/// <summary>
/// A real MCP server tool that is TOLAP-enforced.
/// </summary>
/// <remarks>
/// <para>
/// Read this one first, because it is the case the packages are named after and the one most
/// likely to be misunderstood. <b>TOLAP is not an MCP server and does not speak the MCP wire
/// protocol.</b> It ships no JSON-RPC, no stdio transport, no <c>tools/list</c> handler, and
/// declares no MCP dependency. What it provides is enforcement <i>around the function your MCP
/// server already exposes as a tool</i>.
/// </para>
/// <para>
/// So: build your server with the official SDK exactly as you would anyway, and have the tool body
/// call <see cref="TolapSetup.EnforcedQuery"/> instead of the data source. The protocol layer is
/// entirely the MCP SDK's; the policy layer is entirely TOLAP's; neither knows about the other,
/// which is what lets an existing server adopt enforcement without changing its tool schema or
/// transport.
/// </para>
/// <para>
/// Wire it up as usual — <c>builder.Services.AddMcpServer().WithStdioServerTransport()
/// .WithToolsFromAssembly()</c> — and the agent connects unaware a policy is being applied.
/// </para>
/// <para>Verified against ModelContextProtocol 2.0.</para>
/// </remarks>
[McpServerToolType]
public static class McpServerExample
{
    [McpServerTool(Name = "query_patients")]
    [Description("Query a patient table. Returns only what the caller's policy permits.")]
    public static List<Dictionary<string, object?>> QueryPatients(
        [Description("The table to query.")] string table)
    {
        // The MCP SDK marshals arguments and results; TOLAP decides what the result may contain.
        return TolapSetup.EnforcedQuery(table);
    }
}
