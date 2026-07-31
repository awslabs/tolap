"""A real MCP server whose tool is TOLAP-enforced.

This is the example worth reading first, because it is the case the packages are named after --
and the one most likely to be misunderstood. **TOLAP is not an MCP server and does not speak the
MCP wire protocol.** It ships no JSON-RPC, no stdio transport and no `tools/list` handler, and it
declares no MCP dependency. What it provides is enforcement *around the function your MCP server
already exposes as a tool*.

So the integration is: build your MCP server with the official SDK exactly as you would anyway,
and have the tool body call :func:`enforced_query` instead of the data source. The protocol layer
is entirely the MCP SDK's; the policy layer is entirely TOLAP's; neither knows about the other.

    python mcp_server_example.py          # runs the assertions below
    # in a real deployment: mcp.run() over stdio, and the agent connects as usual

Verified against mcp 1.29.x.
"""

from __future__ import annotations

import asyncio

from mcp.server.fastmcp import FastMCP

from tolap_setup import enforced_query

mcp = FastMCP("tolap-example")


@mcp.tool()
def query_patients(table: str) -> list[dict]:
    """Query a patient table. Returns only what the caller's policy permits."""
    # The MCP SDK marshals arguments and results; TOLAP decides what the result may contain.
    # Keeping them separate is what lets an existing MCP server adopt enforcement without
    # changing its tool schema, its transport, or how clients call it.
    return enforced_query(table)


async def main() -> None:
    # Drive the server through its own tool registry, which is what a connected MCP client
    # ultimately reaches -- so this exercises the real path rather than calling the function.
    tools = await mcp.list_tools()
    print(f"tools exposed   : {[t.name for t in tools]}")

    result = await mcp.call_tool("query_patients", {"table": "patients"})
    rows = result[1]["result"] if isinstance(result, tuple) else result
    print(f"permitted table -> {rows}")

    # A denial must reach the client as an error, not as an empty result: an agent that cannot
    # distinguish "no rows matched" from "you may not read this" will retry forever, and an
    # auditor cannot tell the two apart either.
    try:
        await mcp.call_tool("query_patients", {"table": "encounters"})
        raise AssertionError("expected the denied table to raise")
    except Exception as exc:
        print(f"denied table    -> {type(exc).__name__}: {str(exc)[:70]}")


if __name__ == "__main__":
    asyncio.run(main())
