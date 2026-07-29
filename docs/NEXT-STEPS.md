# TOLAP — task plan and handoff

**Written:** 2026-07-29. **Repo:** `github.com/awslabs/tolap` (public).
**HEAD at hand-off:** `e5292f4`, working tree clean, all suites green.

This is a working document for the next session. It records verified state, the
tasks in priority order, and the decisions that are not mine to make. Delete or
rewrite it freely — it is scaffolding, not documentation.

---

## Verified baseline

Measured immediately before writing this, not recalled:

| SDK | Tests | Command |
| --- | --- | --- |
| .NET | 1,659 | `cd sdk/dotnet && dotnet test Tolap.sln` |
| Python | 1,751 passed, 3 skipped | `cd sdk/python && python3 -m pytest tests/ -q` |
| TypeScript | 1,814 (core 1213 / store 44 / mcp 557) | per package: `npx vitest run` |

Python is at 100% statement and branch coverage. `dotnet build Tolap.sln
-warnaserror` is clean from a `dotnet clean`; `npx tsc --noEmit` is clean in all
three TS packages.

The 3 Python skips are the `TOLAP_TEST_LIVE=1` openFDA fixture-refresh tests,
which rewrite files in `fixtures/` and hit the real FDA API. Leave them gated.

**Two environment gotchas that cost hours today:**

1. `packages/mcp` resolves `@tolap/core` through `packages/core/dist`, not source.
   After changing core, run `cd sdk/typescript/packages/core && npx tsc -p
   tsconfig.json` or mcp tests silently run against a stale build.
2. Do not chain `dotnet build`/`dotnet test` in one shell command. That orphaned
   process trees twice. If `dotnet test` hangs (0% CPU, no output), check
   `lsof -nP -iTCP -sTCP:LISTEN | grep 88` for stale test-API servers and kill them.
   Note `timeout` does not exist on macOS.

Databases for the integration suites: Postgres on 5432, MySQL on 3306 (user
`root`, no password), both database `tolap_integration_test`. See
[`local-testing.md`](local-testing.md).

---

## Task 1 — Re-enable CI (trimmed)

**Why this is first.** Every guarantee in this repo is currently verified by a
human running three suites by hand. The guarantees are *cross-SDK*, so they only
hold if something runs all three. Two of today's worst defects existed precisely
because nothing did:

- The row-filter operator enum drifted to 16 in the schema while Python and
  TypeScript had 9. A schema-valid `{"operator":"between"}` policy crashed Python
  with a `KeyError` and silently dropped every row in TypeScript, while .NET
  enforced it correctly — and the signature verified in all three, so it passed
  every integrity check while producing three different access outcomes.
- `notLike` dropped a present-null row in all three SDKs while its sibling
  negative operators kept it. It survived because the three *agreed with each
  other*; only a shared fixture asserting spec-derived expectations caught it.

Both are now detectable by tests. Neither is detected unless the tests run.

**State.** The workflow is written and preserved at
`.github/workflows-disabled/ci.yml.disabled`. There is no `.github/workflows/`
directory, so nothing runs. `.github/workflows-disabled/README.md` explains what
is unverified while it is off, and carries the manual commands.

**The complaint was noise, and the fix for noise is trimming, not disabling.** As
written it is 4 jobs × version matrices ≈ 7 runs per push, plus a duplicate
conformance job.

Suggested shape — one job, one run per push:

```
- all three suites (Postgres + MySQL service containers, so the ~120 Python
  integration tests actually execute rather than skipping)
- the cross-SDK signing conformance check
- the fixture expected-value guard
```

Drop: the Python 3.10/3.13 and Node 20/22 matrices, and the separate
`cross-sdk-conformance` job (fold its steps into the single job).

```bash
mkdir -p .github/workflows
git mv .github/workflows-disabled/ci.yml.disabled .github/workflows/ci.yml
# then trim the matrices and merge the conformance job
```

**Sanity-check the CI actually asserts something** before trusting it: change one
character of `expectedSignature` in
`fixtures/signing/hmac-sha256-known-answer.json` and confirm all three suites
fail. They did when I tried it. A conformance test that passes vacuously is how
the original signing divergence shipped.

---

## Task 2 — Bind port 0 in the .NET and TypeScript test fixtures

**The bug.** Both hard-code a TCP port for the local test API server:

| File | Port |
| --- | --- |
| `sdk/dotnet/tests/Tolap.Integration.Tests/TestApiFixture.cs` | `8890` (const, line ~39) |
| `sdk/typescript/packages/mcp/tests/integration/live-http-api.test.ts` | `8889` (env-overridable, line ~36) |

Python already does this correctly — copy the pattern from `_free_port()` in
`sdk/python/tests/integration/test_live_http_api.py` (~line 58): bind port 0, let
the OS assign, release, then start the server on it.

**Why it matters.** A fixed port is a process-wide resource. Today two orphaned
servers (28 and 43 minutes old) left `dotnet test` hanging indefinitely at 0% CPU
waiting on `/healthz`. Worse than the hang: the .NET fixture sets `Ready = false`
rather than throwing when it cannot bind, so the affected tests **silently skip**
and the suite still reports green. One run showed the live-API tests "passing"
with zero hits on the code under test.

While in there, consider whether `Ready = false` should skip or fail. Skipping is
right for "no Postgres installed"; it is wrong for "another copy of this suite is
already running", because that reads as success.

---

## ~~Task 3 — Fill in `.github/CODEOWNERS`~~ — DONE

Owner is **Phillip Spies (`pspies@amazon.com`, handle `@phspies`)**, set on
2026-07-29. The catch-all plus explicit per-path entries for the
security-critical surfaces are in place: the two normative specs, `schema/v1.0/`,
the signing and enforcement fixtures, the signers and canonical serializers,
`context.*`, `extractors.*`, `merger.*`, `enforcement.*`, `resolution.*`, the SQL
rewriters, and `.github/`.

The handle is the matching rule, not the email — GitHub only resolves an email if
it is verified on the account *and* that account has write access, and an
unresolvable owner silently produces no review request at all.

**Remaining follow-up, not blocking:** when a maintainer team exists, replace
`@phspies` with the team handle rather than adding a second individual. A team
survives someone changing roles; an individual does not. Note also that a
single-owner CODEOWNERS cannot satisfy a "second reviewer on security-critical
paths" rule — the per-path entries exist so that reviewer can be added to those
lines alone, without widening it to the whole repository.

---

## Task 4 — Decide the two advisory-only policy fields

Both are parsed, schema-validated, merged most-restrictively, and then read by no
enforcement code. Both are currently labelled `ADVISORY ONLY` in their schema
descriptions and listed in [`connector-spec.md`](connector-spec.md) §9:

| Field | Why unenforced |
| --- | --- |
| `permissions.canExport` | No SDK can define what "export" means for an arbitrary tool |
| `limits.maxQueryTimeSeconds` | The SDK never holds the connection, so it cannot set a statement timeout |

**The decision:** either they gain enforcement and leave §9, or they leave the
schema. Leaving them ambiguous is exactly how `minSimilarityScore` and
`maxObjectSizeBytes` sat parsed-and-ignored while the README advertised them as
security controls.

`fieldRules.readOnlyFields` was in this same position and is now specified and
enforced (connector-spec §4.3), so there is a worked precedent for the first
option.

---

## Decisions that need a human, not an agent

Two agents chose to **exclude rather than fix**, and flagged both. That was the
right call — the alternative was inventing semantics mid-task — but each leaves an
unspecified corner:

**1. `?` and `[abc]` in enforcement globs diverge three ways.**

| | `?` | `[abc]` |
| --- | --- | --- |
| Python (`fnmatch`) | wildcard | character class |
| .NET (`Regex.Escape`) | literal | literal |
| TypeScript (now) | wildcard, matching Python | literal, matching .NET |

The agent matched Python for `?` (spec §3.1 governs wildcards) and .NET for
brackets (a literal bracket is the fail-closed reading), and documented both in
code. Neither is specified. Pick one per construct and add it to §3.1, or state
explicitly that bracket expressions are not supported.

**2. A denial reason changed.** For a cased path with a denied method, the reason
went from `endpoint not in allowed set` to `method not allowed`. Reasons are
contract per connector-spec §3.3, so an integrator branching on the string sees a
behavioural change. Confirm this is acceptable, or restore the old precedence.

---

## Larger work, only if wanted

**Secure Tool Factory.** `architecture.md` §5 documents it as "component 5 of 5"
with a sequence diagram, and it exists in **no** SDK. Two honest options: port it,
or renumber to four components and describe it as an integration pattern with no
SDK artifact. I lean toward renumbering — the reference implementation's version is
largely credential brokering and config pinning, which are deployment concerns
rather than protocol.

**Per-source enforcement.** The reference implementation carries roughly 6,000
lines of source-specific enforcement (Bedrock KB metadata filters, DynamoDB,
Athena, Neptune, OpenSearch, object stores); this SDK has three generic wrappers
that enforce on returned records regardless of source. That is a legitimate design,
not a defect — but the highest-value piece to port is **provider-side metadata
filter construction** for `kb`, which would let `tagRules` be enforced *at the
source* rather than only post-retrieval. See connector-spec §7.

**A `formatVersion` discriminator on the signed envelope.** Today a canonical-form
change produces a signature failure indistinguishable from tampering. Deliberately
deferred (canonical-enforcement-spec §2, "Upgrading across a canonical-form
change") because conflating the two is the safer default — but if a second
format revision is ever needed, this is the time to add it.

---

## Ground rules that produced today's results

Worth keeping, because each one caught a real defect:

- **When a test fails, fix the code to match the spec — never weaken the test.**
  The exception is a test that encodes behaviour the spec forbids; correct those
  and cite the section. Several tests today *asserted* the buggy behaviour,
  including one whose name claimed the opposite of what it checked.
- **Shared fixtures over per-SDK tests** for anything cross-cutting. Demanding
  byte-identical output across three implementations forces every disagreement
  into the open. It caught a `WHERE`-clause fail-open that no single-SDK test had
  found in the entire history of the repo.
- **Derive fixture expectations from the spec, then verify against reality.** I
  hand-wrote 21 operator expectations from the spec and got 2 wrong — both about
  present-null semantics, both caught by running them against a real
  implementation and Postgres. Encoding either would have made pushdown and
  post-fetch disagree.
- **Mutation-test the guard.** Several agents neutered their own fix and confirmed
  the tests failed. One found its parity corpus passed 45/45 with the fail-open
  reinstated, and strengthened it.
- **Prove denials with paired controls.** Every "denied write leaves the database
  unchanged" test has a sibling proving the same write lands when permitted.
  Without the control, blocking everything passes.
