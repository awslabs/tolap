# Security scan results

Tool output for each SDK, captured **2026-08-04**.

The commit it was captured against is not in the repository: development history was
squashed into a single commit for the public release, so a SHA here would dangle. The
scan is reproducible instead — every command is in `## Reproducing` below, and the raw
output is committed so a reviewer can check the summary against what the tools said.

Raw output is committed rather than summarised away, so a reviewer can check the summary
below against what the tools actually said.

## Result

| SDK | Tool | Purpose | Result |
| --- | --- | --- | --- |
| all | [Semgrep](semgrep.txt) | SAST — 352 rules (`security-audit`, `secrets`, `owasp-top-ten`) | **0 findings** across 98 files |
| all | [Trivy](trivy.txt) | dependency vulns, secrets, misconfiguration | **0** for the SDKs; **1 Low** in the examples -- see below |
| .NET | [`dotnet list package --vulnerable`](dotnet/dotnet-vulnerable.txt) | known CVEs, incl. transitive | **0** across all 7 projects |
| .NET | [`dotnet list package --deprecated`](dotnet/dotnet-deprecated.txt) | deprecated packages | **1** — see below |
| Python | [Bandit](python/bandit.txt) | SAST | **1 Low**, a false positive — see below |
| Python | [pip-audit](python/pip-audit.txt) | dependency vulns | **0** attributable to TOLAP |
| TypeScript | [`npm audit`](typescript/npm-audit.txt) | dependency vulns (SDK) | **0 vulnerabilities** |
| TypeScript | [`npm audit`](typescript/npm-audit-examples.txt) | dependency vulns (examples) | **2 Low**, unfixable upstream -- see below |

## The example dependencies, and why they are separated from the SDK result

The `examples/` directory installs fourteen third-party agent frameworks so the integrations can be
CI-tested against the real thing. Those are **example-only, dev-time dependencies** -- no shipped
TOLAP package depends on any of them, which is why the SDK and example results are reported
separately rather than as one number.

Fixed on 2026-08-04:

| Finding | Severity | Action |
| --- | --- | --- |
| `vitest` / `vite` / `esbuild` / `@vitest/mocker` / `vite-node` | 1 Critical, 1 High, 3 Moderate | `vitest` 2.1 -> 4.1. All 30 example tests still pass. |
| `hono` CVE-2026-69207 (ReDoS in CORS middleware) | Moderate | `npm audit fix`; a transitive dep of `@modelcontextprotocol/sdk`. |

Remaining, and not fixable by us:

| Finding | Severity | Why it stays |
| --- | --- | --- |
| `@ai-sdk/provider-utils` CVE-2026-8769 (uncontrolled resource consumption) | Low | `@mastra/core@1.55.0` pins the affected `3.0.30` under the alias `@ai-sdk/provider-utils-v5` for multi-version support. No fixed version is published in the `<=3.0.97` range, and the pin is not overridable without dropping the Mastra example. `npm audit` counts it twice (once for the package, once for `@mastra/core`); Trivy counts it once. |

**No TOLAP package is affected.** `sdk/typescript` reports `found 0 vulnerabilities`, and the .NET
and Python SDKs declare no third-party runtime dependencies at all. An integrator installing
`@tolap/core`, `@tolap/store` or `@tolap/mcp` pulls none of the above.

The weekly [examples workflow](../.github/workflows/examples.yml) exists partly for this: framework
dependency drift surfaces there rather than in an integrator's first hour.

## Why the dependency results are thin, and why that is the point

TOLAP's core packages ship **zero runtime dependencies** — verified, not assumed:

- `tolap-core` declares none; `tolap-store` and `tolap-mcp` depend only on `tolap-core`
- `@tolap/core`, `@tolap/store`, `@tolap/mcp` declare no runtime dependencies
- the .NET core projects carry only framework references

So nearly everything a dependency scanner sees here is **test and build tooling**. That
still matters — it runs on developer and CI machines — but a clean dependency audit of this
repository is a much weaker statement than it would be for a project with a real runtime
dependency tree. The SAST results (Semgrep, Bandit) are the more meaningful signal.

## The two non-zero findings

### Bandit B107 — false positive

`sdk/python/tolap-mcp/tolap_mcp/extractors.py:94`, "Possible hardcoded password:
'Authorization'". Bandit matched the parameter *name* `token_header` and flagged its
default value, which is the name of an HTTP header, not a credential. No action.

### `xunit` 2.6.6 is deprecated

`dotnet list package --deprecated` reports `xunit` 2.6.6 as `Legacy`, with `xunit.v3` as the
successor. Present in `Tolap.Mcp.Tests` and `Tolap.Integration.Tests`.

Not a vulnerability — no CVE, and `--vulnerable` is clean. Migrating to xunit.v3 is a
test-framework change across 51 test files, which is real work for no current security
benefit. Recorded here so the decision is visible rather than forgotten.

## Known gaps — things these scans do NOT cover

Stated because a folder of green results invites more confidence than it earns.

- **Five of six `kb` provider filter renderers are unverified against a live service.**
  Only the Bedrock shape has been exercised; the rest are written from published filter
  grammar and report themselves as `fromGrammar`. See connector-spec §7.
- **No fuzzing.** The SQL rewriter and the glob matchers take author-supplied patterns from
  a signed policy. They are bounded against ReDoS by construction and by test, but nothing
  here fuzzes them.
- **No dependency-update monitoring.** The Dependabot config was removed deliberately (see
  its removal commit); nothing now watches the test toolchain or the GitHub Actions pins for
  new advisories. Re-running the tools in this folder is currently a manual act.
- **`FluentAssertions` is pinned at 6.12.0 (Apache-2.0) for licensing reasons**, not
  security ones. v8 moved to Xceed's Community License, whose non-commercial definition
  excludes use "by or for an organisation... that charges fees or earns revenues". No
  scanner flags this, because it is a licence question rather than a vulnerability.
- **CodeQL runs on this repository via GitHub default setup**, not a workflow in this tree,
  so its configuration is not reviewable here. Its own actions currently target the
  deprecated Node 20 runtime.

## Reproducing

```bash
# SAST, all three SDKs
semgrep scan --config=p/security-audit --config=p/secrets --config=p/owasp-top-ten \
  --exclude=node_modules --exclude=dist --exclude=bin --exclude=obj sdk/ tools/

# .NET
cd sdk/dotnet && dotnet list package --vulnerable --include-transitive
cd sdk/dotnet && dotnet list package --deprecated

# Python  (scoped to the shipped packages: tests are excluded because thousands of
# pytest `assert` statements trigger B101, which is what a test file is made of)
bandit -r sdk/python/tolap-core sdk/python/tolap-store sdk/python/tolap-mcp

# TypeScript
cd sdk/typescript && npm audit

# Cross-cutting
trivy fs --scanners vuln,secret,misconfig --skip-dirs node_modules .
```

Trivy needs a reachable vulnerability DB; behind a broken Docker credential helper, point
`DOCKER_CONFIG` at a directory containing `{}` as `config.json`.
