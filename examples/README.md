# TOLAP integration examples

**Fourteen integrations across three languages, all enforcing one policy identically.**

| Language | Frameworks | Tests |
| --- | --- | --: |
| [Python](python/) | MCP SDK, Strands, LangChain, OpenAI Agents, Pydantic AI, Semantic Kernel, Bedrock Agents | 126 |
| [TypeScript](typescript/) | MCP SDK, LangChain.js, Vercel AI SDK, Mastra, OpenAI Agents JS | 115 |
| [.NET](dotnet/) | MCP SDK, Semantic Kernel | 102 |

Each language also carries six examples that are **not** framework integrations. All six exist
in all three languages with the same inputs and byte-identical printed output, so a cross-language
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

The **tool-access example** shows `objectRules.toolRules`, the layer between "may this agent reach
the server?" and "what may this call return?". One server registers four tools and the host shows
every user the same list. Three identities hold three signed policies: an analyst with
`allowedTools`, a support user with `hiddenTools`, and one with no `toolRules` at all. For each the
example prints what a `tools/list` handler would show (`filter_tools` / `filterTools` /
`FilterTools`), calls every tool anyway and prints the refusals with the SDK's own reasons, and
shows a permitted call still meeting the data rules. It tries a mis-cased name too, because the two
lists match differently: `allowedTools` exactly, `hiddenTools` case-insensitively. The policy with
no `toolRules` lists and admits every tool, which is the point: tool gating then stays with the
host, exactly as before, and the policy alone picks the mode with no code change.

The **policy tour** holds the integration constant and changes the policy instead, so each rule is
seen on its own against data that shows what it did. It covers all five mask types (`full`,
`partial` with `showFirst`/`showLast`/`maskChar`, `hash` with each of `sha256`, `sha512` and
`blake2b`, `null` and `redact`), `allowedFields` next to `hiddenFields`, `allowedObjects` next to
`hiddenObjects` with a refused call for each, the row-filter operators one at a time over the same
six rows, `canQuery: false`, `readOnly` refusing a write and the write checks that still run once
writes are granted, the three limits, and a user policy and a group policy resolved into one, with
the most restrictive rule winning field by field.

The **query-safety example** shows what 1.2.0 changed for queries that span tables and for results
enforced twice. A joined, comma-joined or derived table reaching a hidden object is refused before
the source runs, and a construct the pre-check cannot resolve is refused rather than guessed at. A
join's rows are keyed by object, and the example shows a row filter on `patients.region` no longer
reading `encounters.region`, and `patients.name` no longer allowing `encounters.name`. Last, a tool
returns an `EnforcedResult`: a hash-masked field is hashed once instead of twice, a marker bound to
another context is ignored, and a false claim is shown for what it is, the tool's word rather than
proof.

The **HTTP and knowledge-base example** covers the two sources that are not a table, and policies
scoped to a source. Through the HTTP wrapper, `endpointRules` refuses a hidden path, a path outside
the allowlist and a disallowed method before the request leaves the process. A `POST` that passes
the endpoint rules is still refused without `canInsert`, and the rows that come back still meet the
field and row rules. For a knowledge base, `tagRules` become a metadata filter the provider applies
at retrieval, rendered for Bedrock, and the post pass re-applies them with `minSimilarityScore`,
catching a chunk the provider could not filter. Both policies carry `sourcePatterns`, so one
identity resolves to a different policy per source, and to deny-all for a source neither names.

## What each example covers

Every rule a policy can carry is enforced in at least one example, by the SDK rather than by the
script:

| Policy feature | Where it's shown |
| --- | --- |
| `permissions.canQuery`, `readOnly`, `canInsert` / `canUpdate` / `canDelete` | policy tour; `canInsert` also in HTTP and knowledge bases |
| `objectRules.allowedObjects`, `hiddenObjects` | policy tour; every framework example refuses `encounters` |
| `fieldRules.allowedFields`, `hiddenFields`, `readOnlyFields` | policy tour; qualified names in query safety |
| `maskedFields`: `full`, `partial`, `hash` (`sha256`, `sha512`, `blake2b`), `null`, `redact` | policy tour; `redact` in every framework example |
| `rowFilters`: `equals`, `notEquals`, `in`, `notIn`, `greaterThan`, `greaterThanOrEqual`, `lessThanOrEqual`, `between`, `contains`, `startsWith`, `like`, `matches`, `isNull`, `isNotNull` | policy tour (`greaterThanOrEqual` inside the merge) |
| `rowFilters`: `lessThan`, `notLike` | not run on their own; they mirror `lessThanOrEqual` and `like` |
| `limits.maxResults`, `minSimilarityScore`, `maxObjectSizeBytes` | policy tour; `maxResults` in every framework example |
| Merging assigned policies, most restrictive wins | policy tour |
| `objectRules.toolRules` | tool access |
| `purposeProfile`, delegation chain, judge | purpose binding |
| `objectRules.endpointRules`, `allowedMethods` | HTTP and knowledge bases |
| `objectRules.tagRules`, knowledge-base filter pushdown | HTTP and knowledge bases |
| `sourcePatterns` | HTTP and knowledge bases |
| `SqlEnforcementMode` | enforcement mode |
| SQL pre-check across joins and derived tables | query safety |
| `EnforcedResult` | query safety |
| Signing and verification | every example; a tampered context in purpose binding |

Not shown anywhere: hash masking with a salt or HMAC key, and upsert, whose checks are those of
insert and update.

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

Those ratios count the framework suites. The enforcement-mode, purpose-binding and tool-access
examples call their own APIs rather than the shared helper, so each was verified against its own
mutation:

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
- Making `validate_tool_access` ignore `toolRules` fails 8 of the 13 Python tool-access tests. The
  5 survivors are the policy with no `toolRules` (its listing and its calls) and the three
  data-rule checks, which do not depend on tool gating and are correctly insensitive to that
  change.

The policy tour, query-safety and HTTP and knowledge-base suites pin every printed result line
exactly, identically in all three languages, but have not yet been mutation-verified.

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
