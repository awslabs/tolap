# Running the test suites locally

The unit suites need nothing but a toolchain. The integration suites need Postgres
and MySQL, and skip cleanly without them — which is worth knowing, because a green
run that skipped 120 tests looks identical to a green run that executed them.

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
