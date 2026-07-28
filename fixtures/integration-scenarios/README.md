# Integration Scenarios

Cross-SDK declarative test cases. Each SDK (Python, TypeScript, .NET) loads
the same JSON and runs the cases against its own database and HTTP client, so
behavior across languages stays in lockstep.

## Files

| File | What it covers |
|------|----------------|
| `postgres-row-filters.json` | All 9 `FilterOperator` variants plus AND-of-filters and missing-field fail-closed semantics, run against the seeded `patients` table. |
| `postgres-healthcare-analyst.json` | Object-level allow/deny, hidden-field denial, masking, result limits, and signature tampering for the README's canonical `healthcare-analyst` policy. |
| `openfda-api-enforcement.json` | Endpoint allow/deny, HTTP method enforcement, nested-field masking, hidden-field stripping, result-limit truncation, and tamper rejection against pre-recorded openFDA responses. |

## Schema (informal)

Each file is `{ description, scenarios: [Scenario, ...] }`.

A `Scenario` has:
- `name` — human-readable label, used as the test id
- `policy` — an `EffectivePolicy` JSON object (camelCase, matching `schema/v1.0/effective-policy.schema.json`)
- one of:
  - `query` — `{ table, columns }` for SQL scenarios
  - `request` — `{ method, path, collectionPath? }` for API scenarios
- `expected` — `{ pass: bool, ... }` describing the assertion

`expected` shapes:
- `pass: false` requires `errorContains: string` — substring match against the raised PermissionError.
- `pass: true` may include:
  - `rowCount: int` — exact size of the returned collection
  - `regions: string[]` — multiset of `region` values (where applicable)
  - `idsIn: int[]` — every returned id must be in this set
  - `idsEqual: int[]` — returned ids must equal this set exactly
  - `maskedField: { field, mask }` — every row's `field` matches the masking expectation:
    - `mask: "sha256-16"` → first 16 hex chars of `sha256(originalValue)`
    - `mask: "redacted"` → exactly `"[REDACTED]"`
    - `mask: "partial-first-1"` → original[0] preserved, rest replaced with `*`
  - `hiddenField: string` — field name that must not appear anywhere in the response

## Determinism

The seeded database (`sdk/python/tests/integration/schema.sql`) and the
recorded openFDA fixtures (`fixtures/api/openfda/`) anchor every assertion.
If you change either, all three SDK suites will need to be re-validated.
