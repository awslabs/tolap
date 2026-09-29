# TOLAP integration examples — .NET

Five examples: two agent framework integrations, one policy, identical enforcement — plus three
examples that are not about a framework at all. Each framework example registers a tool the way its
framework expects and routes data access through the same method
([`TolapSetup.cs`](TolapSetup.cs)) — because that is the whole integration.

| Example | Framework | Integration point |
| --- | --- | --- |
| [`McpServerExample.cs`](McpServerExample.cs) | `ModelContextProtocol` 2.0 | `[McpServerTool]` method |
| [`SemanticKernelExample.cs`](SemanticKernelExample.cs) | `Microsoft.SemanticKernel` 1.78 | `[KernelFunction]` method |

## Not a framework integration: choosing where enforcement happens

[`EnforcementModeExample.cs`](EnforcementModeExample.cs) is the first of **six** examples here that are not framework integrations (the others are the purpose-binding, tool-access, policy-tour, query-safety and HTTP and knowledge-base examples below). It shows
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
directory does not. The framework and enforcement-mode examples ask "what may this identity see?"; this one asks "and
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

## Not a framework integration: which tools an identity may call

[`ToolAccessExample.cs`](ToolAccessExample.cs) covers the layer between "may this agent reach the server?", which your
host or gateway answers once for everyone, and "what may this call return?", which the other examples
answer. A policy that carries `objectRules.toolRules` gives each identity its own tool list:

```
allowedTools   the only tools this identity may call   matched exactly
hiddenTools    tools this identity may never call      matched case-insensitively
```

One server registers four tools. Three identities hold three signed policies — an analyst with
`allowedTools`, a support user with `hiddenTools`, and an auditor with no `toolRules` at all — and
for each the example prints what a `tools/list` handler would show (`FilterTools`), calls every tool
anyway through `PreExecute`, and prints the refusals with the SDK's own reasons. A permitted
call still meets the data rules, which are the same in all three policies so that `toolRules` is
the only variable.

Two details in there are the ones that catch implementations out. A mis-cased name is refused by
both lists, but for different reasons: `allowedTools` matches exactly, so `Query_Patients` is not on
it, and `hiddenTools` matches case-insensitively, so `Delete_Patient` cannot slip past the hide. And
`allowedTools: []` is not "unrestricted" — it denies every tool. The policy with no `toolRules` lists
and admits every tool, leaving tool gating with the host exactly as before; there is no switch in
the code, only in the policy.

The same example exists in all three languages with byte-identical printed output. Like the other
two, it runs from [`ExamplesTests.cs`](ExamplesTests.cs) (`ToolAccessExampleTests`), which captures
its console output and asserts the printed lines verbatim:

```bash
dotnet test --filter ToolAccessExampleTests
```

## Not a framework integration: every policy rule, one at a time

[`PolicyTourExample.cs`](PolicyTourExample.cs) holds the integration constant and changes the policy instead, so each
rule is seen on its own against data that shows what it did:

```
masks          full, partial, hash (sha256 / sha512 / blake2b), null, redact
fields         allowedFields next to hiddenFields
objects        allowedObjects next to hiddenObjects, a refused call for each
row filters    each operator on its own, over the same six rows
permissions    canQuery false, readOnly refusing a write, the write checks that remain
limits         minSimilarityScore, maxObjectSizeBytes, maxResults
merging        a user policy and a group policy, the most restrictive rule winning
```

Every masked value and every verdict is the SDK's, printed next to the raw value it replaced. The
merge section resolves two assigned policies through the SDK's resolver and prints the rule each
field of the merged policy came from: allowed objects intersected, hidden fields unioned, the
stricter mask, the lower `maxResults`, and a write grant only where every policy grants it.

The same example exists in all three languages with byte-identical printed output. It runs
from [`PolicyTourExampleTests.cs`](PolicyTourExampleTests.cs) (`PolicyTourExampleTests`), which captures its console output and asserts the
printed lines verbatim:

```bash
dotnet test --filter PolicyTourExampleTests
```

## Not a framework integration: queries that span tables

[`QuerySafetyExample.cs`](QuerySafetyExample.cs) shows what 1.2.0 changed about joins and about results enforced
twice, in three sections:

1. **The SQL pre-check reads every table.** A joined, comma-joined or derived table reaching
   `billing_internal` is refused before the source runs, a subquery in `WHERE` is refused as a
   construct the check cannot resolve, and a column is resolved through its alias to the table it
   belongs to.
2. **Qualified names stay with their object.** A row filter on `patients.region` no longer reads
   `encounters.region`, and `allowedFields` entry `patients.name` no longer lets `encounters.name`
   through.
3. **A tool can declare its result already enforced** with `EnforcedResult.For`. A hash-masked field is
   then hashed once, not twice. A marker bound to another context is ignored, and a tool that
   returns a marker without enforcing shows why the marker is a claim, not proof.

The same example exists in all three languages with byte-identical printed output. It runs
from [`QuerySafetyExampleTests.cs`](QuerySafetyExampleTests.cs) (`QuerySafetyExampleTests`), which captures its console output and asserts the
printed lines verbatim:

```bash
dotnet test --filter QuerySafetyExampleTests
```

## Not a framework integration: HTTP APIs, knowledge bases and `sourcePatterns`

[`HttpAndKbExample.cs`](HttpAndKbExample.cs) covers the two sources that are not a table. One identity holds two
policies, each with `sourcePatterns`, so resolution picks the API policy for the API, the
knowledge-base policy for the knowledge base, and deny-all for a source neither names.

Through `SecureHttpToolWrapper`, `endpointRules` refuses a hidden path, a path outside the
allowlist and a disallowed method before the request is sent. A `POST` that passes the endpoint
rules is still refused without `canInsert` — an endpoint allowlist is not a write grant — and the
JSON that comes back still meets the field, row and limit rules. For the knowledge base,
`tagRules` become a metadata filter the provider applies at retrieval (`KbFilter.Build` / `KbProviders.Render`), and
the post pass re-applies them with `minSimilarityScore`, catching a chunk tagged under a key the
provider never filters on.

The same example exists in all three languages with byte-identical printed output. It runs
from [`HttpAndKbExampleTests.cs`](HttpAndKbExampleTests.cs) (`HttpAndKbExampleTests`), which captures its console output and asserts the
printed lines verbatim:

```bash
dotnet test --filter HttpAndKbExampleTests
```

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
dotnet test      # 102 assertions: 12 across both frameworks, 5 for the enforcement modes,
                 # 19 for purpose binding, 13 for tool access, 27 for the policy tour,
                 # 18 for query safety, 8 for HTTP and knowledge bases
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
