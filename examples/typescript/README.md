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

## Read this before the code

**TOLAP is not an MCP server, and it does not speak the MCP protocol.** It ships no JSON-RPC, no
stdio transport, no `tools/list`, and declares no MCP dependency. `@tolap/mcp` provides enforcement
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
npm test        # 30 assertions across all five frameworks
```

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
