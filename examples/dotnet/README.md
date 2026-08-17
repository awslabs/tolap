# TOLAP integration examples — .NET

Two agent frameworks, one policy, identical enforcement. Each example registers a tool the way its
framework expects and routes data access through the same method
([`TolapSetup.cs`](TolapSetup.cs)) — because that is the whole integration.

| Example | Framework | Integration point |
| --- | --- | --- |
| [`McpServerExample.cs`](McpServerExample.cs) | `ModelContextProtocol` 2.0 | `[McpServerTool]` method |
| [`SemanticKernelExample.cs`](SemanticKernelExample.cs) | `Microsoft.SemanticKernel` 1.78 | `[KernelFunction]` method |

## Not a framework integration: choosing where enforcement happens

[`EnforcementModeExample.cs`](EnforcementModeExample.cs) is the one example here that is not about a framework. It shows
`SqlEnforcementMode`, the choice of *where* a database policy is applied:

- **`RewriteAndPost`** (the default) pushes row filters into `WHERE`, the limit into `LIMIT`, and
  hidden columns out of `SELECT`, so the database returns less data.
- **`PostOnly`** leaves your query byte for byte untouched and enforces entirely on the rows
  returned -- for a statement the rewriter's parser does not handle, a stored procedure, an ORM
  that owns its own SQL, or a reviewer who needs the query that ran to be the query they wrote.

Run it and both modes print the **same single row**, from a database that returned 2 rows in one
mode and 4 in the other. That equality is the reason the choice is safe to expose: the mode changes
how much data the source produces, never what the caller may see.

The same example exists in all three languages with the same policy and the same output, so a
divergence between SDKs shows up as a different result rather than hiding behind
separately-written expectations.

## Read this before the code

**TOLAP is not an MCP server, and it does not speak the MCP protocol.** It ships no JSON-RPC, no
stdio transport, no `tools/list`, and declares no MCP dependency. `Tolap.Mcp` provides enforcement
*around the function your tool layer already calls*.

Register either example exactly as you would without TOLAP:

```csharp
// MCP
builder.Services.AddMcpServer().WithStdioServerTransport().WithToolsFromAssembly();

// Semantic Kernel
kernel.Plugins.AddFromType<SemanticKernelExample>("patients");
```

## What the shared policy does

The fake source returns **4 rows and 5 columns**; both frameworks return **2 rows and 4 columns**
with `ssn` hidden, `dob` redacted, `eu-west` filtered, capped at 2, and `encounters` refused before
any query runs.

## Running

```bash
dotnet test      # 12 assertions across both frameworks
```

## Why the tests are parametrised across frameworks

A per-framework test would pass if one integration quietly returned the raw rows — nothing would
compare it against the other. [`ExamplesTests.cs`](ExamplesTests.cs) drives both through their own
entry points and requires the same enforced output. One extra test registers the Semantic Kernel
plugin with a real `Kernel` and asserts the function is discoverable, because a plugin whose
function is never found would pass every other assertion while being invisible to the planner.

Mutation-verified: bypassing enforcement in `TolapSetup.cs` fails **8 of 12** assertions. The 4
survivors are the paired control and the registration test — correctly insensitive to that change.

The expected output is identical to the Python and TypeScript suites', so a cross-language
divergence surfaces as a different result rather than hiding behind separately-written expectations.
