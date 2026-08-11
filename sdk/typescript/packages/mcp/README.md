# @aws/tolap-mcp

Part of [TOLAP](https://github.com/awslabs/tolap) -- the Tool-Object Level Access Protocol.

Enforcement wrappers for the function your tool layer already calls -- MCP servers, agent-framework tools, Lambda handlers.

**This package is not an MCP server and speaks no MCP protocol.** It ships no JSON-RPC, no stdio transport and no `tools/list`, and declares no MCP dependency. Your code fetches the data; TOLAP decides what may leave.

## Build

Not distributed through a package registry -- build it from source:

```
git clone https://github.com/awslabs/tolap
cd tolap/sdk/typescript && npm ci
for p in core mcp; do (cd "packages/$p" && npx tsc -p tsconfig.json); done
```

`./tools/build-local.sh` builds and installs all nine packages in one step.

## What TOLAP does

When an AI agent queries a database or calls an API through a tool, IAM and OAuth decide
*whether the agent may invoke that tool*. Neither decides *which rows and columns this
particular user may see through it*. TOLAP moves enforcement inside the tool, at the
data-object level: column hiding, row filtering, field masking, tag-based access and
endpoint restrictions, applied before any data reaches the agent.

One policy schema covers databases, APIs, knowledge bases and object storage. Policies are
merged most-restrictive-wins, then HMAC-signed so they can cross process and network
boundaries tamper-evidently. A context signed by any one of the three SDKs verifies in the
other two.

## Documentation

- [Repository and full README](https://github.com/awslabs/tolap)
- [Architecture guide](https://github.com/awslabs/tolap/blob/main/docs/architecture.md)
- [Canonical enforcement specification](https://github.com/awslabs/tolap/blob/main/docs/canonical-enforcement-spec.md) -- normative cross-language behaviour
- [Threat model](https://github.com/awslabs/tolap/blob/main/docs/security/threat-model.md)
- [Integration examples](https://github.com/awslabs/tolap/tree/main/examples) -- fourteen agent frameworks, each CI-tested

## Security

Enforcement is non-bypassable *where the wrapper is the only path to the data source*. A
tool that reaches a source without going through a wrapper is outside the boundary. See
[known limitations](https://github.com/awslabs/tolap/blob/main/docs/canonical-enforcement-spec.md#13-known-limitations)
for the full list of what TOLAP does not guarantee, and
[SECURITY.md](https://github.com/awslabs/tolap/blob/main/SECURITY.md) to report an issue.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
