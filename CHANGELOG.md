# Changelog

All notable changes to the TOLAP SDK are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — policy server and console

`docs/architecture.md` has described a "Centralized Policy Store" and a "Policy
Service API" since the first release, in prose, with an endpoint table and a
caching design. None of it was implemented, so every adopter built persistence, an
admin surface, and policy distribution themselves — three times over, once per
language. [`server/`](server/) and [`console/`](console/) are that component.

- **`GET /v1/resolve`** returns a signed policy that **all three SDKs verify**.
  This needed a finding, not just plumbing: the SDKs do not verify the same
  artifact. Python and .NET check the `SecurityContext` envelope and read
  `issuedAt`; the TypeScript wrapper verifies a *bare* `EffectivePolicy` through
  `validatePolicy` and reads `resolvedAt`. Those are HMACs over two different byte
  strings, so a server signing only one works with one SDK and silently fails the
  others. The artifact carries both signatures — sound because the envelope
  projection strips `integrity` before hashing (canonical spec §2 rule 1) — plus
  both spellings of the same instant. `signContext` already produces both.
- **PostgreSQL store** implementing the SDK's `PolicyStore` interface, so the SDK's
  own `resolve()` does the merging. Policy bodies are opaque `jsonb`: §3 makes `[]`
  and `null` opposites for an allow-list, and a normalized table cannot represent
  "empty list" distinctly from "no rows". Regression tests assert the *enforcement
  decision* after a round trip, not just the JSON.
- **Immutable versions** with publish and rollback. Rollback appends a new version
  rather than mutating history, so "we rolled back" is its own audit event.
- **Central schema validation** in two modes — full document, and a fragment mode
  that relaxes only the top-level `required` so a half-authored draft still gets
  types, enums, bounds and nested `required`. Checked against the repository's own
  fixtures, including the two `invalid-` ones it must reject. Validation is central
  rather than per-SDK because the core packages stay dependency-free and three
  independent draft-2020-12 interpretations is exactly what §14 argues against.
- **Source catalog** (uploaded manifest, or imported from OpenAPI / SQL DDL) so the
  console offers real object and field names. This is the highest-value correctness
  feature here: `hiddenFields: ["ssn"]` protects nothing when the column is
  `ssn_number`, and *nothing in TOLAP can detect that* — the policy validates,
  signs, resolves and enforces perfectly while guarding a column that does not
  exist. The catalog is never an enforcement input.
- **Resolve preview**, returned unsigned, for the one thing TOLAP does not
  guarantee: that a policy says what its author meant.
- **Cognito admin auth** with two roles (`admin` writes, `auditor` reads).
  RS256 verified from the pool's JWKS with `node:crypto`, so a security-critical
  path takes no new dependency. Both auth paths follow §11: a credential presented
  and rejected fails, and is never downgraded to anonymous.
- **Per-install credentials** so the audit log names which install pulled which
  policy, and one install can be revoked without touching the others. Revocation
  denies rather than merely being recorded, per §12 — which mattered, because
  mutation testing showed the `revoked_at` filter is the *only* thing implementing
  §12: `PolicyAssignment` has no such field and the SDK resolver has never heard of
  revocation, so there is no backstop.

- **Group and role membership from Cognito.** An assignment attached to a group only
  resolves if the server can learn what a user belongs to. `/v1/resolve` is called by
  an *install* on behalf of a user named in the query string, so there is no user
  token to read `cognito:groups` from — the server asks the pool with
  `AdminListGroupsForUser` (one read-only IAM permission), cached 5 minutes, paginated
  because a truncated group list reads as "not a member" and denies granted access.
  A lookup failure returns **503, not a policy**: an empty group list would look
  exactly like "in no groups", every group-scoped grant would silently vanish, and
  because merge is most-restrictive-wins the result would be an invisible denial.
  `static` and `none` sources are also available; `none` must be chosen explicitly and
  is named in the startup log, because landing on it by accident produces grants that
  do nothing with no error anywhere.
- **Signing-key rotation with an overlap window.** This looked like it required a
  cross-SDK change, since no SDK has a `kid` or a key-resolution hook. It does not:
  the security-context envelope has **no JSON Schema**, so an extra top-level key is
  legal and every SDK ignores members it does not model. Verified against all three —
  an artifact carrying `kid` verifies in TypeScript, Python and .NET. `kid` sits
  outside the signed payload (§2 fixes the projection), so it cannot alter the signed
  bytes, which is both why it is safe to add and why it is only a hint: it selects
  which key to try, and a forged one selects a key under which the signature fails.
  Configure `TOLAP_SIGNING_KEYS="new:…,old:…"`, distribute both, flip
  `TOLAP_ACTIVE_KID`, drop the old key after one TTL. A single `TOLAP_SIGNING_KEY`
  still works and becomes the key `default`, so existing deployments need no change.

Two ports, so the policy-authoring surface can bind a private interface while
remote installs reach only `/v1/resolve` — §13 says policy authors are trusted
administrators, and a deployment that widens that has left the threat model.

Nothing in `sdk/`, `schema/` or `fixtures/` changed.

### Security

A security review of all three SDKs found that several policy controls were not
actually enforced on returned data, and that signed contexts were not
tamper-evident in the way the documentation claimed. All findings are fixed
across .NET, Python, and TypeScript, with a regression test per defect and a new
normative specification — [`docs/canonical-enforcement-spec.md`](docs/canonical-enforcement-spec.md)
— that all three SDKs implement and are tested against.

**Fail-opens found by testing against real services (2026-07-30):**

Each of these was a filter or limit that the service *accepted* while enforcing nothing, so no
unit test could distinguish it from a working one — the fixtures asserted the document we had
chosen to emit. All are fixed in .NET, Python and TypeScript, with mutation-verified regression
tests. [`docs/testing-antipatterns.md`](docs/testing-antipatterns.md) records why the existing
suites missed them.

- **`limits.maxResults` was not enforced when `collectionPath` was omitted.** A policy with
  `maxResults: 1` against a body shaped `{"results": [...]}` returned every record the upstream
  sent. `collectionPath` is optional, and the three record-level controls disagreed on its
  absence: `allowedFields` returned `{}` and `rowFilters` withheld the body — both fail-closed —
  while the limit failed open. Every existing test of `maxResults` supplied the argument, so the
  omitted branch was never executed in any SDK. The limit now enforces on a discoverable
  collection and raises the unenforceable-result error when a body has two candidates rather
  than guessing which to truncate. connector-spec §6 makes the absent-argument behaviour
  normative.
- **`kb` OpenSearch/Elasticsearch denylists returned every denied document.** The renderers
  emitted `key.keyword` unconditionally. A field mapped `keyword` directly has no such
  sub-field, so the clause matched nothing — and under `must_not`, a term matching nothing
  excludes nothing. Found against a real OpenSearch 2.19 domain; the allowlist arm of the same
  bug failed closed, which is why it went unnoticed. Renderers now match the bare field **and**
  the `.keyword` sub-field.
- **`kb` Vertex AI Search emitted an invalid multi-argument `NOT ANY()`.** Discovery Engine
  negates only a single-argument `ANY()`, so a two-tag denylist produced an expression the
  service would reject or misapply. Now split into one negated `ANY()` per value, ANDed. The
  positive form deliberately keeps its values in one `ANY()`, since there the multi-argument
  spelling is the disjunction an allowlist means.
- **.NET `EnforcementEngine.ValidateAccess` ignored `canQuery`.** Python and TypeScript both
  checked it, so one signed policy granted different access per language — a fail-open on the
  broadest permission in the model. Found by porting the Athena suite to .NET.

**Test-reporting defects (suites reported success without running):**

- **The .NET AWS suite reported 41 passes for tests that executed nothing.** Every test body
  opened with `if (Skip) return;`, which xunit records as a pass, so a run with no credentials
  was byte-identical to a full run against real AWS. Replaced with attribute-level gates that
  report *skipped*.
- **The Python AWS opt-in gate did not exist.** `pytestmark` was set in a `conftest.py`, where
  pytest ignores it, so a clean checkout produced 38 failures from a suite designed to skip.
  Replaced with a collection hook. Both gates now carry a guard test that is deliberately *not*
  behind the gate, since the original defect survived because guard and guarded were the same
  mechanism.

**Enforcement gaps (data could reach the agent in violation of policy):**

- **`hiddenFields` was never removed from results** on the database/MCP path in
  any language. It was only pre-checked against the field list a caller
  volunteered, so a tool returning undeclared columns (e.g. `SELECT *`) returned
  hidden fields in cleartext. Only the HTTP wrappers stripped them. Hidden-field
  removal is now part of the post-execution pipeline in every wrapper.
- **`allowedFields` was never enforced on results** in any wrapper. Results are
  now projected to the allow-list.
- **Single-record results skipped most enforcement.** The single-record branch
  applied masking only, bypassing row filters, tag filters, and the result limit
  — so a record excluded by `deniedTags` was still returned by a get-by-id tool.
  Single records now run the identical pipeline.
- **Unenforceable result shapes passed through unfiltered.** Shapes the engine
  cannot inspect are now denied by default, with an explicit, logged
  `allowUnenforceableShapes` opt-out (threat-model remediation R-3).
- **Negative row-filter operators failed open.** `notEquals`/`notIn` retained
  rows that were missing the filtered field entirely, contradicting the
  documented fail-closed contract. All operators now drop such rows.
- **Unknown mask types returned the raw value.** A typo'd or newer `maskType`
  silently disabled masking. Unknown types are now treated as `redact`.
- **`partial` masking returned the original value** when
  `showFirst + showLast >= len(value)`; it now degrades to a full mask.
- **Nested fields were not masked** on the MCP path (only top-level keys were
  matched). Masking and hidden-field removal now recurse, and field references
  match bare and table-qualified forms in both directions, case-insensitively.

**Merge correctness (policies could combine to grant *more* access):**

- **Intersecting two disjoint allow-lists granted unrestricted access**
  (Python). An empty intersection is the most restrictive possible outcome, but
  an emptiness check discarded the rule object, which enforcement then read as
  "no restriction". `null` (unrestricted) and `[]` (deny-all) are now distinct
  everywhere.
- **Mask restrictiveness was ranked inverted** in all three SDKs, so merging
  `null` with `partial` produced `partial` — disclosing real characters a policy
  had demanded be erased. Ranking is now by disclosure:
  `partial < hash < full < redact < null`.
- **Absent boolean permissions merged inconsistently** (Python vs .NET/TS):
  a policy silent on `readOnly` combined with `readOnly: false` yielded
  `false` in Python and `true` elsewhere. Absent values now take their schema
  default before folding in all three.

**Signing and replay:**

- **Context expiry was outside the signature** (Python, TypeScript). Because the
  HMAC covered only the policy, a captured context's `expiresAt` could be
  rewritten — or removed entirely — without the signing key, and it would still
  verify. Expiry was the only replay bound. The signature now covers the full
  envelope.
- **Invalid and missing expiry values were treated as "never expires."** An
  unparseable timestamp made every comparison false, granting an unbounded
  lifetime. Missing/unparseable expiry now rejects, in signed contexts and in
  stored assignment activity checks.
- **Revocation did nothing** (.NET). `RevokePolicyAsync` emitted a
  `PolicyRevoked` audit event and returned `true` without removing the
  assignment, so revoked principals kept resolving the policy while the audit
  trail reported success. Revocation now removes the assignment, and the test
  asserts access is gone rather than only that an event fired.

**Cross-SDK signing precision.** The canonical form now mandates timestamps
truncated to **millisecond** precision. Python and .NET natively serialized
microseconds while JavaScript's `Date` cannot represent them at all, so the same
instant signed in different languages produced different bytes and failed to
verify across SDKs. The whole-second known-answer fixture could not detect this,
so `fixtures/signing/hmac-sha256-subsecond.json` was added to pin it. Truncation
(never rounding) is specified so an expiry cannot be moved later than the issuer
intended.

**Identity extraction now fails loudly and identically.** .NET threw on an invalid
JWT while Python and TypeScript silently returned no identity, so the same expired
token produced a hard error in one SDK and an anonymous request — resolving
whatever a default assignment granted — in the other two. All three now distinguish
*absent* credentials (legitimately anonymous) from *presented and invalid*
(malformed, bad algorithm, `alg=none`, bad signature, expired, not-yet-valid, or
missing a required claim), and raise on the latter. `nbf` (not-before) is now
validated in all three; it was previously unchecked everywhere.

**Other hardening:** JWT `exp` with a floating-point value no longer skips the
expiry check (.NET); `matches` patterns are compiled as `^(?:…)$` so top-level
alternation cannot escape the anchors (TypeScript); regex evaluation and
comparison operators are bounded and fail closed instead of raising; masking no
longer aliases the caller's nested objects; prototype-polluting keys are skipped
when walking response bodies; a denylist-only `tagRules` policy no longer drops
untagged records.

### Changed — BREAKING

- **Version is now `2.0.0`** across all three SDKs, reflecting the wire-format and
  merge-semantics changes below. Inter-package dependencies were repinned
  (`tolap-core>=2.0.0`, `@tolap/core@2.0.0`) so a 1.x core cannot be resolved
  alongside a 2.x wrapper — mixing them across a signing boundary would fail every
  verification. The .NET projects now declare an explicit `<Version>`; previously
  they would have packed as `1.0.0` regardless of this file.
- **An invalid credential now raises instead of resolving as anonymous** in Python
  and TypeScript (see above). Integrators who relied on a rejected token silently
  falling through to a default/anonymous policy will now see an exception. This is
  the intended behavior: an authentication failure must not become an authorization
  decision.
- **Timestamps are truncated to milliseconds in the signed payload.** A context
  signed with sub-millisecond precision by an earlier build will not verify.
- **The signed-context wire format changed.** Signatures now cover the whole
  canonical envelope (`{version, userId, tenantId, issuedAt, expiresAt,
  policies[]}`) serialized in one canonical JSON form — recursively sorted keys,
  compact separators, no unicode escaping, null fields omitted. **Contexts signed
  by an earlier version will not verify, and vice versa.** Re-issue any
  long-lived signed contexts when upgrading. In exchange, a context signed by
  one SDK now verifies in the other two, which previously was not possible: the
  three implementations signed different payloads in different canonical forms.
- **`fixtures/signing/hmac-sha256-known-answer.json` now carries a real
  `expectedSignature`** (and the canonical byte string). Previously the fixture
  contained no expected value, and the .NET suite never loaded it at all, so the
  cross-language signature guarantee it documented was never actually asserted —
  which is why the divergence above went unnoticed. All three suites now assert
  against it byte-for-byte.
- **Mask restrictiveness ordering changed** (see above). Policies that relied on
  `partial`/`hash` winning a merge against `null`/`redact` will now resolve to
  the stricter mask.
- **Enforcement globs define `?` and treat bracket expressions as literal.** `*` and
  `?` are the only metacharacters (`?` matches exactly one character); `[abc]` and
  every other character are literal (connector-spec §3.1). This closes a cross-SDK
  divergence: `?` was a wildcard in Python and TypeScript but a literal in .NET, and
  `[abc]` was a character class in Python (via `fnmatch`) but literal in the other
  two — so a single signed `allowedObjects` entry granted different access per
  language. Literal brackets are the fail-closed reading, matching strictly fewer
  names than a character class would. Pinned by a shared cross-SDK fixture.

### Changed

- **Endpoint denial-reason precedence is now specified** (connector-spec §3.3).
  The reason string is contract, so which one wins when a request fails several
  checks has to be fixed rather than incidental: reasons are evaluated in a stated
  order and the first to deny is returned. In particular, because endpoint matching
  is case-insensitive, a path differing from an `allowedEndpoints` entry only by
  case matches the allow-list and is then judged on its method — so a denied method
  reports `method not allowed`, not `endpoint not in allowed set`. All three SDKs
  already behaved this way; the order is now documented and pinned by the cross-SDK
  endpoint parity corpus.

### Added

- **Secure Tool Factory** (`SecureToolFactory`) in all three SDKs — the composition root
  `architecture.md` §5 documented but no SDK implemented. An agent receives its tools from
  the factory and never constructs one, which is what makes §4's "the wrapper is the only
  path to the source" structural rather than a convention every call site must remember.
  It validates the signed context and then **refuses to produce a tool at all** when the
  context is forged, expired, policy-less, names an unparseable source, or has `canQuery`
  false — failing at composition time rather than handing back a wrapper that denies every
  call, which a caller can misread as a transient error and retry.

  Dispatch reads the **signed** category (the first segment of `sourceConnectionId`, §1):
  `db`/`kb`/`storage` get the record-shaped wrapper, `api` gets the HTTP wrapper. Taking
  the category from unsigned configuration instead would let a flipped `db` → `api` select
  the wrapper that enforces the *other* category's rules, and `endpointRules` do not
  constrain a SQL query.

  Two things it deliberately does **not** do, both departures from the reference
  implementation and from earlier drafts of the guides: it brokers **no credentials** (the
  SDK never holds a connection — the record wrapper returns rewritten SQL and the HTTP
  wrapper is handed its client, so nothing on the enforcement path takes a secret), and it
  stores **no context** (wrappers stay stateless and take the context per call; a context
  held on a shared wrapper can outlive its request and be reused for the next caller, who
  may be a different user). There is consequently no `setSecurityContext()`.
- **Provider-side `kb` metadata filters** in all three SDKs — the pushdown connector-spec §7
  says an SDK SHOULD emit, so `tagRules` is enforced *at the source* rather than only
  post-retrieval. A provider-neutral builder (`buildKbFilter` / `build_kb_filter` /
  `KbFilter.Build`) plus a renderer for each of six providers: Bedrock, OpenSearch,
  Elasticsearch, Azure AI Search, Vertex AI Search, and pgvector. Only the Bedrock shape has
  been exercised against the live service; the other five are written from published filter
  grammar and report themselves as `fromGrammar`, because "looks right" is not the evidence
  "observed to filter" is.

  The pushdown is **structurally weaker** than the post-retrieval pass and is designed around
  that: post-retrieval extraction reads tags from five key shapes at any depth, which no
  provider filter can express. A filter that matches nothing therefore costs efficiency and
  nothing else — the post pass is unconditional. The failure mode that *would* matter is the
  reverse, so a rule that cannot be expressed exactly is reported in `unpushedRules` rather
  than approximated, and the suites assert the property directly: everything the post pass
  permits also survives the simulated provider filter.

  Two cases are refused rather than approximated. `allowedTags: []` means deny-all, and no
  portable metadata predicate expresses match-nothing — rendering it as a no-op would fail
  open, so the result flags deny-all and the caller skips retrieval. A multi-key allow-list is
  a disjunction across keys; ANDing a positive clause per key would drop permitted chunks, so
  it is left to the post pass. Pinned by a shared cross-SDK fixture whose seven cases all
  three SDKs render byte-identically.
- **Source-identity parsing** (`parseSourceIdentity` / `parse_source_identity` /
  `SourceIdentityParser`) — `category:namespace:name` per connector-spec §1, with the
  category as a typed enum. Rejects a wrong segment count, an unknown category, and empty
  segments; an empty namespace or name would otherwise let `db::` match a `db:*:*` pattern
  while naming no real source. Returns null rather than throwing, and every caller in the
  SDK treats null as a refusal.
- **`docs/canonical-enforcement-spec.md`** — the normative cross-language
  specification for canonical signing, the enforcement pipeline and its order,
  null-vs-empty semantics, mask ranking, identity-failure semantics, timestamp
  precision, fail-closed rules, and known limitations.
- **Continuous integration** (`.github/workflows/ci.yml`). None of the fixes above
  were caught by automation because the repository had no CI at all. Every push and
  pull request now runs all three suites — with Postgres and MySQL service
  containers, so the database integration tests actually execute rather than
  skipping — plus a dedicated cross-SDK conformance job that verifies all three
  SDKs produce identical canonical signing bytes, and a guard that fails if a
  known-answer fixture ever loses its expected values. Also adds a pull-request
  template with a cross-SDK parity checklist.
- **`fixtures/signing/hmac-sha256-subsecond.json`** — known-answer fixture with
  microsecond input timestamps, pinning the millisecond-truncation rule.
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
