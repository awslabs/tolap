# TOLAP integration examples

One policy, seven agent frameworks, identical enforcement. Each example registers a tool the way
its framework expects and routes the actual data access through the same function
([`tolap_setup.py`](tolap_setup.py)) — because that is the whole integration.

| Example | Framework | Integration point |
| --- | --- | --- |
| [`mcp_server_example.py`](mcp_server_example.py) | Model Context Protocol SDK | `@mcp.tool()` body |
| [`strands_example.py`](strands_example.py) | AWS Strands Agents | `@tool` body |
| [`langchain_example.py`](langchain_example.py) | LangChain / LangGraph | `@tool` body |
| [`openai_agents_example.py`](openai_agents_example.py) | OpenAI Agents SDK | `@function_tool` body |
| [`pydantic_ai_example.py`](pydantic_ai_example.py) | Pydantic AI | `@agent.tool_plain` body |
| [`semantic_kernel_example.py`](semantic_kernel_example.py) | Semantic Kernel | `@kernel_function` body |
| [`bedrock_agent_example.py`](bedrock_agent_example.py) | Bedrock Agents | action-group Lambda handler |

## Not a framework integration: choosing where enforcement happens

[`enforcement_mode_example.py`](enforcement_mode_example.py) is the one example here that is not about a framework. It shows
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
stdio transport, no `tools/list`, and declares no MCP dependency. The `tolap-mcp` package provides
enforcement *around the function your tool layer already calls*.

That is why the same three lines work across seven frameworks, and why nothing here takes a
credential: your code fetches the data, TOLAP decides what may leave.

## What the shared policy does

```
allowedObjects: [patients]         -> `encounters` is refused before any query runs
hiddenFields:   [ssn]              -> never reaches the agent
maskedFields:   dob -> redact      -> becomes [REDACTED]
rowFilters:     region = us-east   -> eu-west rows dropped
maxResults:     2                  -> applied last
```

The fake source returns **4 rows and 5 columns**; every example returns **2 rows and 4 columns**:

```
{'id': 1, 'name': 'Alice Nguyen', 'region': 'us-east', 'dob': '[REDACTED]'}
{'id': 2, 'name': 'Bruno Sato',   'region': 'us-east', 'dob': '[REDACTED]'}
```

The gap between those two is the enforcement, and it is asserted rather than described.

## Running them

```bash
pip install -r requirements.txt
pip install -e ../../sdk/python/tolap-core -e ../../sdk/python/tolap-store -e ../../sdk/python/tolap-mcp

python mcp_server_example.py     # or any other
pytest test_examples.py          # 42 assertions across all seven
```

Each example skips cleanly if its framework is absent, so you can install only the one you need.

## Why the tests are parametrised across frameworks

A per-framework test would pass if one integration quietly returned the raw rows — nothing would
compare it against the others. [`test_examples.py`](test_examples.py) drives all seven through
*their own* invocation paths and requires the same enforced output from each, so a broken wiring
stands out against six correct ones.

Mutation-verified: bypassing enforcement in `tolap_setup.py` fails **30 of 42** assertions. The 12
that still pass are the paired controls (which assert the *source* returns more than the policy
allows) — correctly insensitive to the change.

## The one framework that differs

Six of these are in-process: the agent calls your function. **Bedrock Agents invokes a Lambda**,
so the signed context cannot be built locally — it must arrive with the request as a session
attribute, and the handler verifies the signature before enforcing. A handler that fell back to
"no policy" when the attribute was missing would be an unauthenticated read of the data source, so
the example returns `403` instead. That case is tested.
