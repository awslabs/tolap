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
  `Tolap.Core` / `tolap-core` / `@aws/tolap-core`.
- **Security-sensitive changes** to signing, merging, identity extraction, or
  the enforcement pipeline require extra scrutiny. Note in your change which
  security properties it affects and how you validated them. See
  [`SECURITY.md`](SECURITY.md) for the security model and integrator obligations.

## Development

```bash
# .NET
cd sdk/dotnet && dotnet test Tolap.sln
```

```bash
# Python — install editable, so the code under test is the code you edited.
# A non-editable install in site-packages made a verified fix appear not to work
# (docs/testing-antipatterns.md §7).
cd sdk/python
pip install -e ./tolap-core -e ./tolap-store -e ./tolap-mcp
pip install pytest httpx "psycopg[binary]" PyMySQL jsonschema
python3 -m pytest tests/ -q
```

```bash
# TypeScript — there is no `scripts` block at sdk/typescript, so `npm test` there
# runs nothing. Build core first: store and mcp resolve @aws/tolap-core through
# packages/core/dist, so on a fresh clone typechecking them first fails with TS6305.
cd sdk/typescript
npm ci
(cd packages/core && npx tsc -p tsconfig.json)
for pkg in core store mcp; do (cd "packages/$pkg" && npx vitest run); done
```

For live Postgres/MySQL and the test-API server, see
[`docs/local-testing.md`](docs/local-testing.md).

## Before you open a change

1. All three SDKs build and their test suites pass.
2. New/changed behavior is covered by a shared fixture where applicable.
3. If you touched a **purpose-binding** module, the coverage gate still passes.
   [`tools/purpose-binding-coverage-gate.py`](tools/purpose-binding-coverage-gate.py) is a
   build-blocking CI step demanding 100% line *and* branch coverage on the sixteen files
   purpose binding added (six .NET, five Python, five TypeScript). It reads the Cobertura
   and lcov reports the test steps already emit, so run the suites with coverage on and
   pass it the reports — see the invocation in `.github/workflows/ci.yml`. Two things to
   know: the gate is scoped to those files *deliberately* and must not be widened
   repo-wide, and a gated file **missing** from every report fails rather than passes,
   because "stopped being measured" and "stopped being tested" are indistinguishable and
   the silent one is worse. The reasoning is in
   [`docs/testing-antipatterns.md`](docs/testing-antipatterns.md) §8.
4. Run the dependency and SAST scans if you touched dependencies or logic
   (e.g. `dotnet list package --vulnerable`, `bandit -r`, `npm audit`).
5. No secrets, keys, or credentials in code, tests, or fixtures.

## Reporting security issues

Do **not** open a public issue. See [`SECURITY.md`](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the
Apache License 2.0. See [`LICENSE`](LICENSE).
