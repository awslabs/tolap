# Running the test suites locally

The unit suites need nothing but a toolchain. The integration suites need Postgres
and MySQL, and **fail** without them rather than skipping.

That is deliberate, and it is a change. They used to return early when a database was
unreachable, and an early return from a test body is a *pass*: with the databases pointed
at dead ports, .NET reported `Passed: 273` and TypeScript `243 passed`, output
indistinguishable from a run that verified everything. Python alone reported an honest
`pytest.skip`.

Worse, it hid a live bug rather than a missing service. Three .NET classes shared
`MySqlFixture` through `IClassFixture`, so each built its own instance and each re-seeded
the same tables in parallel; the losers of that race failed with `Table 'patients' already
exists`, and 39 MySQL tests reported success while never reaching MySQL — which was running
the whole time. Both fixtures now hang off one `DatabaseCollection` so seeding happens once.

If you cannot run a database locally, filter those tests out of the run explicitly
(`dotnet test --filter`, `vitest run <path>`) rather than expecting the suite to
degrade quietly. There is no environment-variable escape hatch: one was tried and removed,
because it could suppress the guard but not the closed connection the test used two lines
later.

## Databases

Both suites expect a database named `tolap_integration_test`. The schemas are
loaded automatically by the test fixtures from
`sdk/python/tests/integration/schema.sql` and `schema_mysql.sql`.

```bash
# Postgres — the fixtures default to the current OS user with no password
createdb tolap_integration_test

# MySQL — the fixtures default to user "root" with no password
brew services start mysql
mysql -u root -e "CREATE DATABASE IF NOT EXISTS tolap_integration_test;"
```

Override the defaults with environment variables if your setup differs:

| Variable | Default | Used by |
| -------- | ------- | ------- |
| `TOLAP_TEST_DB_DSN` | `postgresql:///tolap_integration_test` (Python), `Host=localhost;Database=tolap_integration_test` (.NET) | Postgres |
| `TOLAP_TEST_MYSQL_HOST` | `127.0.0.1` | MySQL |
| `TOLAP_TEST_MYSQL_PORT` | `3306` | MySQL |
| `TOLAP_TEST_MYSQL_USER` | `root` | MySQL |
| `TOLAP_TEST_MYSQL_PASSWORD` | *(empty)* | MySQL |
| `TOLAP_TEST_MYSQL_DB` | `tolap_integration_test` | MySQL |
| `TOLAP_TEST_LIVE` | unset | Set to `1` only to re-record the openFDA fixtures from the real API. These tests overwrite files in `fixtures/api/openfda/`. |

## Test API server

For HTTP enforcement over a real socket rather than an in-process transport mock:

```bash
python3 tools/test-api/server.py --port 8888
```

See [`tools/test-api/README.md`](../tools/test-api/README.md) for the endpoints and
what each one is for.

## Before you trust a result — three ways a run lies

Each of these has cost hours, and each produced a *green* suite over code that was not being
tested.

**1. TypeScript mcp/store resolve `@aws/tolap-core` through `dist`, not source.** After changing
core, rebuild it or the other packages silently test a stale build:

```bash
cd sdk/typescript/packages/core && npx tsc -p tsconfig.json
```

`rm -rf dist` alone is not enough — delete `tsconfig.tsbuildinfo` too, or `tsc -p` sees nothing
to do and no-ops. A phantom type error that appears and vanishes is this.

**2. Confirm the package under test is the one you edited.** A non-editable copy in
site-packages has shadowed the repo, making a verified fix look broken:

```bash
cd sdk/python && python3 -c "import tolap_core, tolap_mcp, tolap_store
for m in (tolap_core, tolap_mcp, tolap_store): print(m.__name__, m.__file__)"
```

Every path must be inside this repository. If not: `python3 -m pip install -e tolap-core -e
tolap-mcp -e tolap-store --no-deps`.

**3. `dotnet test` is weaker than CI.** CI builds with `-warnaserror`, so a warning that is
invisible locally fails the pipeline — and because the .NET step runs first, a warning there
means the Python and TypeScript suites never execute at all. Run CI's exact build before
pushing:

```bash
find sdk/dotnet -type d \( -name obj -o -name bin \) -prune -exec rm -rf {} +
dotnet restore sdk/dotnet/Tolap.sln
dotnet build sdk/dotnet/Tolap.sln --no-restore -warnaserror
```

The clean is not optional: an incremental build skips compilation entirely and reports
`0 Warning(s)` in about two seconds without having looked at the changed file. If the build
finishes that fast, check the log actually lists all seven projects producing a `.dll`.

This has caught a real failure — `CS8620`, passing `object?[]` where the parameter is
`object[]`. `dotnet test` compiled it without complaint.

**4. Read the skip count, not just the exit status.** A suite that skips everything reports
success. Both the .NET and Python AWS suites once reported a fully-skipped run as *passed* —
see [`testing-antipatterns.md`](testing-antipatterns.md) §3 and §4. Expected skips are the
opt-in suites only: AWS (`TOLAP_TEST_AWS=1`), the provisioned-KB tests (`TOLAP_TEST_KB_ID`),
and the openFDA fixture-refresh tests (`TOLAP_TEST_LIVE=1`, which rewrite files in `fixtures/`
and call the real FDA API). Leave all three gated.

Two shell notes for macOS: `timeout` does not exist, and do not chain `dotnet build` with
`dotnet test` in one command — it has orphaned process trees. If `dotnet test` hangs at 0% CPU,
check `lsof -nP -iTCP -sTCP:LISTEN | grep 88` for stale test-API servers.

## Running

```bash
# .NET
cd sdk/dotnet && dotnet test Tolap.sln

# Python
cd sdk/python && python3 -m pytest tests/ -q

# TypeScript
cd sdk/typescript && npm ci
for pkg in core store mcp; do (cd "packages/$pkg" && npx vitest run); done
```

### Confirm the integration tests actually ran

Skips are the failure mode to watch for. Ask pytest to report their reasons:

```bash
cd sdk/python && python3 -m pytest tests/integration/ -q -rs
```

With both databases up, the Python integration suite runs 117 tests and skips 3
(the `TOLAP_TEST_LIVE` fixture-refresh tests). With neither database, all 120 skip
and the run still reports success.

## Coverage

```bash
# Python (statement + branch)
cd sdk/python
python3 -m coverage run --branch \
  --source=tolap-core/tolap_core,tolap-store/tolap_store,tolap-mcp/tolap_mcp \
  -m pytest tests/ -q
python3 -m coverage report --show-missing

# TypeScript
cd sdk/typescript/packages/core && npx vitest run --coverage

# .NET
cd sdk/dotnet && dotnet test Tolap.sln --collect:"XPlat Code Coverage"
```

Branch coverage is the number that matters for this codebase. Function coverage
sits near 100% while branches lag, and the untested branch is where the defects
were: a filter operator that failed open on a missing field, an unknown mask type
that returned the raw value, a revocation that returned success without revoking.
Each was reachable code with no test asserting the negative case.

## Cross-SDK conformance

The signing conformance tests are the ones that catch the three SDKs drifting
apart:

```bash
cd sdk/dotnet && dotnet test Tolap.sln --filter "FullyQualifiedName~SigningConformance"
cd sdk/python && python3 -m pytest tests/test_signer.py tests/test_signing_regressions.py -q
cd sdk/typescript/packages/core && npx vitest run tests/signing-regressions.test.ts
```

To verify those tests are actually asserting something, change one character of
`expectedSignature` in `fixtures/signing/hmac-sha256-known-answer.json` and confirm
all three suites fail. If they do not, the guarantee is not being checked — which
is precisely how the original divergence shipped.
