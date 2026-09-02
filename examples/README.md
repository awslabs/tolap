# TOLAP integration examples

**Fourteen integrations across three languages, all enforcing one policy identically.**

| Language | Frameworks | Tests |
| --- | --- | --: |
| [Python](python/) | MCP SDK, Strands, LangChain, OpenAI Agents, Pydantic AI, Semantic Kernel, Bedrock Agents | 60 |
| [TypeScript](typescript/) | MCP SDK, LangChain.js, Vercel AI SDK, Mastra, OpenAI Agents JS | 49 |
| [.NET](dotnet/) | MCP SDK, Semantic Kernel | 36 |

Each language also carries two examples that are **not** framework integrations. Both exist in all
three languages with the same inputs and byte-identical printed output, so a cross-language
divergence shows up as a diff rather than as three separately-written expectations.

The **enforcement-mode example** shows `SqlEnforcementMode` -- whether the policy is pushed into
your SQL or applied only to the results -- and proves the two produce identical rows.

The **purpose-binding example** answers the question the rest of the set does not. Every other
example asks "what may this identity see?"; this one asks "and for what?". A signed context binds
identity, tenant, source and expiry but not the *reason* the data is being read, so an agent that
has drifted off-task is indistinguishable from one that has not. The example walks the four
controls of [spec §15](../docs/canonical-enforcement-spec.md#15-purpose-binding) in the order a call meets them --
resolution filtering, the delegation chain, action validation, and the optional judge -- and shows
each one both **allowing legitimate work and refusing the rest**, because a demo that only denies
teaches nothing about whether the real work still passes. It also signs a context, rewrites the
declared purpose, and shows verification failing: the purpose and the chain are inside the
signature, which is what makes a captured context non-repurposable. The judge is stubbed rather
than called, so the example needs no credential and its verdicts are pinned.

## The one thing to understand

**TOLAP is not an MCP server and does not speak the MCP protocol.** No JSON-RPC, no stdio
transport, no `tools/list`, and no MCP dependency declared in any package. The `*-mcp` packages
provide enforcement *around the function your tool layer already calls*.

That is why the integration is the same substitution in **thirteen** of the fourteen cases — call
the enforced function instead of the data source — and why none of them takes a credential. Your
code fetches the data; TOLAP decides what may leave.

The fourteenth is Bedrock Agents, and it is the exception precisely because it is *not* in-process:
the agent invokes a Lambda, so the context cannot be built locally and arrives as a session
attribute instead. See [The one framework that differs](#the-one-framework-that-differs).

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

Those ratios count the framework suites. The two non-framework examples call their own APIs rather
than the shared helper, so each was verified against its own mutation:

- Bypassing `apply_result_pipeline` fails **29 of the 44** Python tests in the framework and
  enforcement-mode suites: 28 of the 42 framework assertions, and one of the two enforcement-mode
  ones. The 14 framework survivors are the paired source controls and the pre-execution denials,
  which are correctly insensitive to a post-pass bypass. The one enforcement-mode survivor runs the
  example as a **subprocess**, so an in-process monkeypatch does not reach it — patch the source
  and it fails too. That caveat is §6's own rule: confirm the mutant is present before trusting
  that it survived.
- Removing `purposeProfile` from the purpose-binding example's own policy definitions fails 8 of
  its 16 Python tests. The 8 survivors are the delegation-chain, scope-narrowing, judge-disposition
  and signature-tamper cases, which validate a chain or a verdict independently of any policy and
  are correctly insensitive to that change.

## The one framework that differs

Thirteen of the fourteen are in-process: the agent calls your function. **Bedrock Agents invokes a
Lambda**, so the signed context cannot be built locally — it arrives as a session attribute and the
handler verifies the signature before enforcing. A handler that fell back to "no policy" on a
missing attribute would be an unauthenticated read of the data source, so it returns `403`. That
case is tested.

## CI

These live in a [separate workflow](../.github/workflows/examples.yml) from the SDK gate. Across
its three jobs it installs **thirteen** third-party framework packages — six Python, five npm, two
NuGet — covering the fourteen integrations, because Bedrock Agents installs nothing at all: it is a
plain Lambda handler that imports only `tolap_core`. A breaking release in any of the thirteen must
not block a change to the SDK. It also runs weekly, so framework drift surfaces here rather than in an
integrator's first hour.
