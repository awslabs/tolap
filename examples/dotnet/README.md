# TOLAP integration examples — .NET

Four examples: two agent framework integrations, one policy, identical enforcement — plus two
examples that are not about a framework at all. Each framework example registers a tool the way its
framework expects and routes data access through the same method
([`TolapSetup.cs`](TolapSetup.cs)) — because that is the whole integration.

| Example | Framework | Integration point |
| --- | --- | --- |
| [`McpServerExample.cs`](McpServerExample.cs) | `ModelContextProtocol` 2.0 | `[McpServerTool]` method |
| [`SemanticKernelExample.cs`](SemanticKernelExample.cs) | `Microsoft.SemanticKernel` 1.78 | `[KernelFunction]` method |

## Not a framework integration: choosing where enforcement happens

[`EnforcementModeExample.cs`](EnforcementModeExample.cs) is the first of **two** examples here that are not framework integrations (the other is the purpose-binding example below). It shows
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

## Not a framework integration: binding a policy to a *reason*

[`PurposeBindingExample.cs`](PurposeBindingExample.cs) answers the question the rest of this
directory does not. The other three examples ask "what may this identity see?"; this one asks "and
for what?". A signed context binds identity, tenant, source and expiry — but not the reason the data is
being read, so an agent holding a perfectly legitimate context may use it for anything its policy
happens to permit, and one that has drifted off-task is indistinguishable from one that has not.

It walks the four controls of [spec §15](../../docs/canonical-enforcement-spec.md#15-purpose-binding) in the order a
call meets them, and shows each **both allowing and denying** — a demo that only refuses teaches
nothing about whether legitimate work still passes:

```
15.1  resolution filtering  the declared purpose selects which policies resolve at all
15.3  delegation chain      a chain may narrow at every hop and never widen
15.2  action validation     the action category is deployment configuration, never a caller argument
15.4  the semantic judge    an optional model check that can only *subtract*
```

It closes by signing a context, rewriting the declared purpose, and showing verification fail — the
purpose and the chain are inside the signature, which is what makes a captured context
non-repurposable. The judge is a stub `IJudge` with fixed verdicts rather than a live model call, so
the example needs no credential and its dispositions are pinned.

Two details in there are the ones that catch implementations out. `campaign-x` admits
`campaign-x-overlap` but refuses `campaign-xyz-evil`, because a plain prefix test — the obvious
implementation — accepts both; and `escalate` is a **denial** unless an escalation handler is wired,
or "escalate to human review" silently means "permit" in every deployment that never built the
review step.

Note which wrapper carries the action-category map: `SecureContextToolWrapper`, not
`SecureMcpServerOptions`. The identity-driven MCP wrapper has no such option, so wiring the map
there would leave the control permanently inert.

The same example exists in all three languages with byte-identical printed output. This project has
no `Program.cs` — it *is* the test project — so the example runs from
[`ExamplesTests.cs`](ExamplesTests.cs), which captures its console output and asserts the printed
lines verbatim.

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
dotnet test      # 36 assertions: 12 across both frameworks, 5 for the enforcement modes,
                 # 19 for purpose binding
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
