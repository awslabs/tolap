# Contributing to TOLAP

Thanks for your interest in contributing. TOLAP is protocol-agnostic and works
with MCP servers, Semantic Kernel plugins, LangChain tools, AWS Bedrock Agents,
or any tool-based AI agent architecture.

## Ground rules

- **Three languages, one behavior.** The .NET, Python, and TypeScript SDKs must
  behave identically. Shared behavior is pinned by the JSON fixtures in
  `fixtures/` — all three SDKs validate against them. If you change behavior,
  update the fixtures and all three implementations together.
- **Core stays dependency-free.** The core packages ship with zero third-party
  runtime dependencies. Do not add runtime dependencies to
  `Tolap.Core` / `tolap-core` / `@tolap/core`.
- **Security-sensitive changes** to signing, merging, identity extraction, or
  the enforcement pipeline require extra scrutiny. Note in your change which
  security properties it affects and how you validated them. See
  [`SECURITY.md`](SECURITY.md) for the security model and integrator obligations.

## Development

```bash
# .NET
cd sdk/dotnet && dotnet test

# Python
cd sdk/python && pytest

# TypeScript
cd sdk/typescript && npm install && npm test
```

## Before you open a change

1. All three SDKs build and their test suites pass.
2. New/changed behavior is covered by a shared fixture where applicable.
3. Run the dependency and SAST scans if you touched dependencies or logic
   (e.g. `dotnet list package --vulnerable`, `bandit -r`, `npm audit`).
4. No secrets, keys, or credentials in code, tests, or fixtures.

## Reporting security issues

Do **not** open a public issue. See [`SECURITY.md`](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the
Apache License 2.0. See [`LICENSE`](LICENSE).
