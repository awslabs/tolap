# TOLAP integration examples

**Fourteen integrations across three languages, all enforcing one policy identically.**

| Language | Frameworks | Tests |
| --- | --- | --: |
| [Python](python/) | MCP SDK, Strands, LangChain, OpenAI Agents, Pydantic AI, Semantic Kernel, Bedrock Agents | 44 |
| [TypeScript](typescript/) | MCP SDK, LangChain.js, Vercel AI SDK, Mastra, OpenAI Agents JS | 33 |
| [.NET](dotnet/) | MCP SDK, Semantic Kernel | 17 |

Each language also carries an **enforcement-mode example**, which is not a framework integration:
it shows `SqlEnforcementMode` -- whether the policy is pushed into your SQL or applied only to the
results -- and proves the two produce identical rows. Same policy and same output in all three
languages. See the per-language READMEs.

## The one thing to understand

**TOLAP is not an MCP server and does not speak the MCP protocol.** No JSON-RPC, no stdio
transport, no `tools/list`, and no MCP dependency declared in any package. The `*-mcp` packages
provide enforcement *around the function your tool layer already calls*.

That is why the integration is the same substitution in all fourteen cases — call the enforced
function instead of the data source — and why none of them takes a credential. Your code fetches
the data; TOLAP decides what may leave.

## Every example makes the same claim

The fake source returns **4 rows and 5 columns**. Every framework, in every language, returns:

```
{ id: 1, name: "Alice Nguyen", region: "us-east", dob: "[REDACTED]" }
{ id: 2, name: "Bruno Sato",   region: "us-east", dob: "[REDACTED]" }
```

`ssn` hidden · `dob` redacted · `eu-west` filtered out · capped at 2 · `encounters` refused before
any query runs.

The expected output is written identically in all three test suites, on purpose. TOLAP's core
guarantee is that one signed policy behaves the same in .NET, Python and TypeScript — so a
cross-language divergence must surface as a *different result*, not hide behind separately-written
expectations.

## Why the tests are parametrised across frameworks

A per-framework test would pass if one integration quietly returned the raw rows, because nothing
would compare it to the others. Each suite drives every framework through *its own* invocation path
and requires the same enforced output, so a broken wiring stands out against its correct neighbours.

All three are mutation-verified — bypassing enforcement in the shared helper fails 30/42 (Python),
20/30 (TypeScript) and 8/12 (.NET). The survivors are the paired controls, which assert the
*source* returns more than the policy allows and are correctly insensitive to that change.

Those ratios count the framework suites. The enforcement-mode tests call the mode API rather than
the shared helper, so they were verified against the same mutation separately: bypassing
`apply_result_pipeline` fails 14/24 in Python — the 12 framework assertions plus 2 of the 3
enforcement-mode ones, which detect the bypass through the example's own output rather than merely
exercising it.

## The one framework that differs

Thirteen of the fourteen are in-process: the agent calls your function. **Bedrock Agents invokes a
Lambda**, so the signed context cannot be built locally — it arrives as a session attribute and the
handler verifies the signature before enforcing. A handler that fell back to "no policy" on a
missing attribute would be an unauthenticated read of the data source, so it returns `403`. That
case is tested.

## CI

These live in a [separate workflow](../.github/workflows/examples.yml) from the SDK gate. They
install fourteen third-party frameworks, and a breaking release in any of them must not block a
change to the SDK. It also runs weekly, so framework drift surfaces here rather than in an
integrator's first hour.
