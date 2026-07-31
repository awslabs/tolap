/**
 * A real MCP server whose tool is TOLAP-enforced.
 *
 * Read this one first, because it is the case the packages are named after and the one most
 * likely to be misunderstood. **TOLAP is not an MCP server and does not speak the MCP wire
 * protocol.** It ships no JSON-RPC, no stdio transport, no `tools/list` handler, and declares no
 * MCP dependency. What it provides is enforcement *around the function your MCP server already
 * exposes as a tool*.
 *
 * So: build your server with the official SDK exactly as you would anyway, and have the tool body
 * call `enforcedQuery` instead of the data source. The protocol layer is entirely the MCP SDK's;
 * the policy layer is entirely TOLAP's; neither knows about the other, which is what lets an
 * existing server adopt enforcement without changing its tool schema or transport.
 *
 * Verified against @modelcontextprotocol/sdk 1.30.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import { enforcedQuery } from "./tolap-setup.js";

export const server = new McpServer({ name: "tolap-example", version: "1.0.0" });

server.registerTool(
  "query_patients",
  {
    description: "Query a patient table. Returns only what the caller's policy permits.",
    inputSchema: { table: z.string() },
  },
  async ({ table }: { table: string }) => {
    // The MCP SDK marshals arguments and results; TOLAP decides what the result may contain.
    const rows = enforcedQuery(table);
    return { content: [{ type: "text" as const, text: JSON.stringify(rows) }] };
  },
);

/** Exposed so the test can drive the enforced path without a transport. */
export function queryPatients(table: string): Record<string, unknown>[] {
  return enforcedQuery(table);
}

// In a real deployment: await server.connect(new StdioServerTransport()) — and the agent
// connects as usual, unaware that a policy is being applied.
