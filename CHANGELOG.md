# Changelog

All notable changes to the TOLAP SDK are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`tolap_core.enforcement.apply_row_filters`** — runtime application of
  `RowFilter` rules. Drops rows that fail any filter (filters AND together).
  Supports every `FilterOperator` variant: `equals`, `notEquals`, `in`,
  `notIn`, `greaterThan`, `lessThan`, `contains`, `startsWith`, `matches`.
  Rows missing the referenced field fail closed.
- **`tolap_mcp.http_wrapper.SecureHttpToolWrapper`** — the API counterpart to
  `SecureMcpToolWrapper`. Wraps an `httpx.Client` and enforces:
  - Pre-call: `validate_endpoint` (path + method) and signature/expiry.
  - Post-call: dotted-path field masking, hidden-field stripping, and
    `apply_result_limit` truncation of a configurable `collection_path`
    inside JSON bodies.
- Postgres integration tests under `sdk/python/tests/integration/`:
  - `test_postgres_enforcement.py` — 10 tests for object access, hidden fields,
    masking, result limits, and signature tampering against a real Postgres
    instance.
  - `test_row_filter_gap.py` — 12 tests covering every `FilterOperator` plus
    multi-filter AND semantics and missing-field fail-closed behavior. (This
    file was previously a strict `xfail` documenting the gap; it now passes.)
  - `schema.sql` — healthcare-style seed data (patients/encounters/diagnoses
    plus `billing_internal` and `audit_log` for hidden-object coverage).
- openFDA replay integration tests:
  - `test_openfda_enforcement.py` — 21 tests covering endpoint allow/deny,
    HTTP method enforcement, `can_query` short-circuit, nested-field masking,
    hidden-field stripping, result limits, signature tampering, expiry,
    wildcard matching with deny precedence, and a network-contract assertion
    that denied requests never invoke the transport.
  - `test_openfda_record.py` — opt-in (`TOLAP_TEST_LIVE=1`) harness that
    re-records the canonical openFDA responses to `fixtures/api/openfda/`.
- `fixtures/api/openfda/` — pre-recorded openFDA responses for
  `/drug/event.json`, `/drug/label.json`, `/food/enforcement.json`. Tests
  replay these via `httpx.MockTransport`, so CI runs offline.

### Changed

- **`tolap_mcp.wrapper.SecureMcpToolWrapper.post_execute`** — now applies row
  filters before masking and result limits. Behavior change: tool functions
  that previously returned rows excluded by `policy.object_rules.row_filters`
  will now have those rows dropped before the agent sees them. This is the
  documented policy behavior; tests that asserted the pre-fix leaky behavior
  have been updated.

### Fixed

- **Row-filter enforcement gap** (security): the architecture documented row
  filtering as a core capability and the schema modeled `row_filters` on
  `ObjectRules`, but the SDK never applied them at runtime. This was a
  silent enforcement gap — policies declaring row filters returned rows the
  policy disallowed. Closed by the additions above.

- **`fixtures/integration-scenarios/`** — declarative cross-SDK test cases
  (`postgres-row-filters.json`, `postgres-healthcare-analyst.json`,
  `openfda-api-enforcement.json`) so all three SDKs run the same matrix
  instead of three hand-written copies. The Python integration tests now
  consume these. Adding TS or .NET coverage means writing a thin scenario
  runner per language, not duplicating assertions.
- `fixtures/integration-scenarios/README.md` — documents the scenario schema.

### TypeScript SDK parity

- `applyRowFilters` ported to `packages/core/src/enforcement.ts` — covers all
  9 `FilterOperator` values with the same fail-closed semantics as Python.
- `SecureMcpToolWrapper.postExecute` (in `packages/mcp/src/wrapper.ts`) now
  applies row filters before masking and result limits.
- New `SecureContextToolWrapper` (`packages/mcp/src/context-wrapper.ts`) — a
  context-driven entry point matching Python's `execute_with_enforcement`.
- New `SecureHttpToolWrapper` (`packages/mcp/src/http-wrapper.ts`) — fetch-shaped
  enforcement with dotted-path masking, hidden-field stripping, and
  `collectionPath` truncation.
- Hash mask now truncates to 16 hex chars to match Python and .NET.
  (Pre-existing TS test updated to assert the new contract.)
- `applyFieldMasking` now strips dotted prefixes (e.g. `patients.full_name`
  matches a record key `full_name`) to match Python.
- New integration test files under `packages/mcp/tests/integration/`:
  `postgres-row-filters.test.ts` (11), `postgres-healthcare-analyst.test.ts`
  (9), `openfda.test.ts` (9). All consume the shared scenario JSON.

### .NET SDK parity

- `EnforcementEngine.ApplyRowFilters` added in
  `src/Tolap.Core/EnforcementEngine.cs` — all 9 operators, with `JsonElement`
  unwrapping so scenario-JSON values compare cleanly against DB values.
- `SecureMcpToolWrapper.ExecuteWithEnforcementAsync` (in
  `src/Tolap.Mcp/SecureMcpToolWrapper.cs`) now applies row filters before
  masking and result limits.
- New `SecureContextToolWrapper`
  (`src/Tolap.Mcp/SecureContextToolWrapper.cs`) — context-driven equivalent
  of the Python and TS wrappers.
- New `SecureHttpToolWrapper` (`src/Tolap.Mcp/SecureHttpToolWrapper.cs`) —
  HttpClient-shaped enforcement with the same dotted-path masking, hidden-field
  stripping, and `CollectionPath` truncation.
- New `tests/Tolap.Integration.Tests/` xUnit project (added to `Tolap.sln`)
  with `PostgresRowFiltersTests` (11), `PostgresHealthcareAnalystTests` (9),
  and `OpenFdaTests` (9). Consumes the shared scenario JSON.
- `Tolap.sln` updated.

### MySQL backend coverage (all three SDKs)

The Postgres scenarios proved enforcement against one engine. To prove TOLAP
is engine-agnostic, the same shared scenarios now run against a real MySQL
9.x backend in all three SDKs.

- `sdk/python/tests/integration/schema_mysql.sql` — MySQL-syntax port of the
  seed schema (`AUTO_INCREMENT`, `DATETIME`, backticked `status` column).
  Same 6/6/5/2/2 row counts as Postgres so the cross-SDK assertions match.
- Python session fixture (`mysql_conn`) connects via PyMySQL; auto-seeds.
- TypeScript suite uses `mysql2/promise`; auto-seeds; coerces BIGINT→Number.
- .NET suite uses `MySqlConnector` + a class-scoped `MySqlFixture`; auto-seeds.
- The same four scenario JSON files (`postgres-row-filters`,
  `postgres-healthcare-analyst`, `postgres-field-rules`, `permissions-and-limits`)
  drive both backends. Each SDK now runs **39 MySQL tests** mirroring its
  Postgres run for true engine-agnostic enforcement coverage.

### Schema-completeness coverage (all three SDKs)

Audit revealed roughly half the policy schema had no integration coverage.
Closed by adding three new shared scenario files covering field-rule
permutations, permission/limit values, and KB tag rules.

- **`fixtures/integration-scenarios/postgres-field-rules.json`** — 12 cases:
  `allowedFields` allow-list (positive + negative), glob in `hiddenFields`,
  glob in `allowedFields`, all 5 mask types (`full`/`partial`/`hash`/`null`/
  `redact`), `partial` with `showLast`, `partial` with `showFirst+showLast`,
  `partial` overflow returns original unchanged, custom `maskChar` (e.g. `#`),
  multi-rule masking on the same row.
- **`fixtures/integration-scenarios/permissions-and-limits.json`** — 7 cases:
  `canQuery=false` short-circuit, glob match in `allowedObjects`, glob
  non-match denial, `hiddenObjects` precedence over `allowedObjects`, omitted
  `objectRules`, `maxResults=1`, `maxResults > rowCount`.
- **`fixtures/integration-scenarios/knowledge-base-tag-rules.json`** —
  6 cases against an in-process document corpus: `allowedTags` single-tag,
  `deniedTags`, `deniedTags` precedence over `allowedTags`, untagged-doc
  fail-closed, no `tagRules` passes through, multi-tag union semantics.

### Real bug found and fixed: tag filtering was silently skipped

The new KB tag-rule scenarios surfaced that the **context-driven wrappers
in all three SDKs never applied `filterByTags` in `postExecute`**. Tag rules
were authored, signed, and merged, but the wrapper would return every
document untouched. A customer using TOLAP for KB classification
would have seen restricted docs reach the agent.

Fix in:
- `sdk/python/tolap-mcp/tolap_mcp/wrapper.py` — added `filter_by_tags` after
  row filters, before masking.
- `sdk/typescript/packages/mcp/src/context-wrapper.ts` — added `filterByTags`
  in the same position. (The MCP-flavored `SecureMcpToolWrapper` already had it.)
- `sdk/dotnet/src/Tolap.Mcp/SecureContextToolWrapper.cs` — added
  `EnforcementEngine.FilterByTags`. (The MCP-flavored
  `SecureMcpToolWrapper` already had it.)

The 25 new integration tests now run identically across Python, TypeScript,
and .NET via the shared scenario JSON.

### Adversarial / edge-case scenarios + HTTP-error tests (all three SDKs)

Added a deeper integration layer covering the corners that the happy-path
scenarios don't:

- **`fixtures/integration-scenarios/openfda-edge-cases.json`** — 11 new
  cross-SDK scenarios: hidden-and-masked overlap precedence; mask propagation
  through nested arrays at one level (`patient.reaction[*]`) and two levels
  (`patient.drug[*].medicinalproduct`); no-op behavior for hidden/masked
  paths that don't exist in the response; hashing a numeric field; empty
  `allowedEndpoints` denies; `allowedEndpoints ∩ hiddenEndpoints` favors
  hidden; case-insensitive HTTP methods; hidden field stripping must not
  damage the unrelated `meta` block.
- **HTTP-error path tests per SDK** (5 each, offline-only): 404/429/500
  upstream errors propagate after the policy passes; hidden-endpoint
  denials short-circuit before the transport is touched, even when the
  upstream is a guaranteed 500; method denials short-circuit identically.

### Real bug found and fixed (all three SDKs)

The new edge-case live run surfaced a genuine cross-SDK bug. The
`SecureHttpToolWrapper`s were passing the raw `path` argument straight
into `validateEndpoint`. In live mode the test had to embed `?limit=N` in
the path because the TS / .NET wrappers had no first-class query-param
parameter — and the query string then prevented glob patterns like
`/drug/*` from matching `/drug/event.json?limit=3`.

Result: a scenario where the policy explicitly hid an endpoint reported
"endpoint not in allowed set" instead of "endpoint is hidden." Same effect
in TS and .NET; Python was masked from the bug because Python's wrapper
already had a separate `params` argument and never put query strings in the
path.

Fix in all three SDKs: strip the query string before evaluating the
endpoint policy. See `http_wrapper.py:189`, `http-wrapper.ts:87`,
`SecureHttpToolWrapper.cs:55`.

### Live-network mode for openFDA (all three SDKs)

By default the openFDA scenarios run **offline** against pre-recorded responses
in `fixtures/api/openfda/` for fast, deterministic CI. Setting
`TOLAP_TEST_LIVE=1` flips every SDK into live mode:

1. A session/class fixture re-fetches each endpoint from `https://api.fda.gov`
   with the same `?limit=N` parameter the recordings used and overwrites the
   on-disk recording.
2. The same scenario assertions then run against the freshly-fetched live
   response — endpoint allow/deny, method enforcement, hidden-field
   stripping, sha256-16 hashing, redaction, and result-limit truncation all
   verified end-to-end against the real API.

Verified against `api.fda.gov` on each SDK during this change:

- Python: `TOLAP_TEST_LIVE=1 pytest tests/integration/test_openfda_scenarios.py` → 9/9 in ~15s
- TypeScript: `TOLAP_TEST_LIVE=1 npm test -w @tolap/mcp -- openfda` → 9/9 in ~13s
- .NET: `TOLAP_TEST_LIVE=1 dotnet test --filter OpenFda` → 9/9 in ~11s

Each SDK's test class gets its own session fixture, so a full live run
makes 3 GETs per SDK (9 total) — well within openFDA's no-auth quotas.

### Test coverage (all three SDKs)

| SDK | Offline total | Live API coverage | Detail |
|-----|------:|------:|--------|
| Python | 193 + 3 skipped | 20 against api.fda.gov | + 39 MySQL scenarios |
| TypeScript | 203 | 20 against api.fda.gov | + 39 MySQL scenarios |
| .NET | 207 | 20 against api.fda.gov | + 39 MySQL scenarios |
| **All** | **603 + 3 skipped** | **60 against api.fda.gov** | identical scenarios on Postgres + MySQL |

Line coverage on the Python SDK is **94%**; equivalent measurement is not
yet wired up for TS or .NET.
