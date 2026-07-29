# Disabled workflows

GitHub Actions only runs workflow files under `.github/workflows/`. Anything in
this directory is inert. The configuration is kept rather than deleted so it can
be restored without rebuilding it.

## Re-enabling

```bash
mkdir -p .github/workflows
git mv .github/workflows-disabled/ci.yml.disabled .github/workflows/ci.yml
```

## What `ci.yml` did, and what is now unverified

It ran the full test suite for all three SDKs on every push and pull request,
with Postgres and MySQL service containers so the database integration tests
actually executed instead of skipping (roughly 120 Python tests skip without a
reachable database). It also ran a dedicated cross-SDK conformance job asserting
that .NET, Python, and TypeScript all produce byte-identical canonical signing
bytes, plus a guard that failed if a known-answer fixture ever lost its expected
values.

With it disabled, nothing automatically checks that:

- the three SDKs still agree on the canonical signing bytes — a context signed by
  one SDK verifying in the others is a documented guarantee
  (`docs/canonical-enforcement-spec.md` §2), and it silently broke once before
- the enforcement pipeline still strips hidden fields, projects allowed fields,
  and fails closed on unenforceable result shapes in every wrapper
- the shared fixtures still carry the expected values they exist to assert

Every one of those had a real defect that a fully green *local* test run did not
catch, because nothing was running the checks. Until CI is re-enabled, run the
commands below before merging anything that touches signing, merging, identity
extraction, or the enforcement pipeline.

## Manual verification

```bash
# .NET  (309 tests)
cd sdk/dotnet && dotnet test Tolap.sln --nologo

# Python  (213 passing; ~120 integration tests skip without a live DB)
cd sdk/python && python3 -m pytest tests/ -q

# TypeScript  (365 tests across three packages)
cd sdk/typescript && npm ci
for pkg in core store mcp; do (cd "packages/$pkg" && npx vitest run); done

# Cross-SDK signing conformance — the check that catches divergence
cd sdk/dotnet && dotnet test Tolap.sln --filter "FullyQualifiedName~SigningConformance"
cd sdk/python && python3 -m pytest tests/test_signer.py tests/test_signing_regressions.py -q
cd sdk/typescript/packages/core && npx vitest run tests/signing-regressions.test.ts
```

A useful sanity check on the conformance tests themselves: change one character of
`expectedSignature` in `fixtures/signing/hmac-sha256-known-answer.json` and
confirm all three suites fail. If they do not, the guarantee is not actually being
asserted — which is the exact failure mode that let the original divergence ship.
