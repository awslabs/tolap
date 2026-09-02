# TOLAP integration examples — TypeScript

Five agent frameworks, one policy, identical enforcement. Each example registers a tool the way its
framework expects and routes data access through the same function
([`tolap-setup.ts`](tolap-setup.ts)) — because that is the whole integration.

| Example | Framework | Integration point |
| --- | --- | --- |
| [`mcp-server-example.ts`](mcp-server-example.ts) | `@modelcontextprotocol/sdk` 1.30 | `registerTool` handler |
| [`langchain-example.ts`](langchain-example.ts) | `@langchain/core` 1.2 | `tool()` function |
| [`vercel-ai-example.ts`](vercel-ai-example.ts) | `ai` 7.0 | `tool({ execute })` |
| [`mastra-example.ts`](mastra-example.ts) | `@mastra/core` 1.55 | `createTool({ execute })` |
| [`openai-agents-example.ts`](openai-agents-example.ts) | `@openai/agents` 0.14 | `tool({ execute })` |

## Not a framework integration: choosing where enforcement happens

[`enforcement-mode-example.ts`](enforcement-mode-example.ts) is the first of **two** examples here that are not framework integrations (the other is the purpose-binding example below). It shows
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

[`purpose-binding-example.ts`](purpose-binding-example.ts) answers the question the rest of this
directory does not. Every other example asks "what may this identity see?"; this one asks "and for
what?". A signed context binds identity, tenant, source and expiry — but not the reason the data is
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
non-repurposable. The judge is a stub with fixed verdicts rather than a live model call, so the
example needs no credential and its dispositions are pinned.

Two details in there are the ones that catch implementations out. `campaign-x` admits
`campaign-x-overlap` but refuses `campaign-xyz-evil`, because a plain prefix test — the obvious
implementation — accepts both; and `escalate` is a **denial** unless an escalation handler is wired,
or "escalate to human review" silently means "permit" in every deployment that never built the
review step.

One thing to know when reading it alongside the Python version: the action-category map lives on
`SecureContextToolWrapper` here and in .NET, but on Python's `SecureMcpToolWrapper`. The printed
output is identical; only the wrapper the map hangs off differs.

The same example exists in all three languages with byte-identical printed output.

## Read this before the code

**TOLAP is not an MCP server, and it does not speak the MCP protocol.** It ships no JSON-RPC, no
stdio transport, no `tools/list`, and declares no MCP dependency. `@aws/tolap-mcp` provides enforcement
*around the function your tool layer already calls* — which is why the same substitution works
across five frameworks, and why nothing here takes a credential.

## What the shared policy does

The fake source returns **4 rows and 5 columns**; every framework returns **2 rows and 4 columns**:

```
{ id: 1, name: 'Alice Nguyen', region: 'us-east', dob: '[REDACTED]' }
{ id: 2, name: 'Bruno Sato',   region: 'us-east', dob: '[REDACTED]' }
```

`ssn` hidden, `dob` redacted, `eu-west` filtered, capped at 2, and `encounters` refused before any
query runs. The gap between raw and enforced is asserted, not described.

## Running

```bash
npm install
npm run typecheck
npm test        # 49 assertions: 30 across the five frameworks, 3 for the enforcement
                # modes, 16 for purpose binding
```

Nothing runs these files standalone in CI — the TypeScript job typechecks and tests — so both
non-framework examples are *executed* from `examples.test.ts` rather than merely imported. An
example that only ever compiles will drift.

## Why the tests are parametrised across frameworks

A per-framework test would pass if one integration quietly returned the raw rows — nothing would
compare it against the others. [`examples.test.ts`](examples.test.ts) drives all five through
*their own* invocation paths and requires the same enforced output.

Mutation-verified: bypassing enforcement in `tolap-setup.ts` fails **20 of 30** assertions. The 10
survivors are the paired controls (which assert the *source* returns more than the policy allows) —
correctly insensitive.

`EXPECTED` is byte-identical to the Python and .NET suites', so a cross-language divergence surfaces
as a different result rather than hiding behind separately-written expectations.

## A version note

`@openai/agents` requires **zod 4**, while some other frameworks are still on zod 3 ranges. The
pinned `zod@^4` here satisfies all five; if you install only one framework you can use whichever
major it prefers.
