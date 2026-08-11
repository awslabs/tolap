# Releasing TOLAP

Nine packages ship as a set at one version, across three registries:

| Registry | Packages |
|---|---|
| PyPI | `tolap-core`, `tolap-store`, `tolap-mcp` |
| npm | `@aws/tolap-core`, `@aws/tolap-store`, `@aws/tolap-mcp` |
| NuGet | `Tolap.Core`, `Tolap.Store`, `Tolap.Mcp` |

They are **not** independently versioned, deliberately. The guarantee these packages carry
is cross-package and cross-language: a context signed by `@aws/tolap-core` must verify in
`tolap-core` and `Tolap.Core`, and the shared fixtures in `fixtures/` demand byte-identical
output from all three. Versioning them separately would let a consumer assemble a
combination nothing ever tested.

The schema in `schema/v1.0/` is versioned separately, because it describes the on-the-wire
policy format rather than the packages that implement it.

---

## Publish to the registries BEFORE the repository is public

This is the one ordering rule that cannot be corrected afterwards, and it is the reverse of
the intuitive order. Amazon's guidance on both registries is explicit:

> Because PyPI is exclusively a global namespace, always publish to your desired name on
> PyPI before making your code public to avoid namesquatting.
> — [PublishingToPyPI](https://w.amazon.com/bin/view/Open_Source/Open_Sourcing/Uploading/PublishingToPyPI)

> Make sure that you publish your NPM package BEFORE exposing any documentation including
> your package name on the public Internet (such as on GitHub). Otherwise your package name
> may be squatted and replaced with malicious code.
> — [PublishingToNPM](https://w.amazon.com/bin/view/Open_Source/Open_Sourcing/Uploading/PublishingToNPM)

A public repository advertises the package names in its README before those names are
claimed. Someone can register them and publish malicious code that your own documentation
points users at. Package indexes are immutable in a way GitHub is not — the
[Uploading](https://w.amazon.com/bin/view/Open_Source/Open_Sourcing/Uploading/) page calls
this "Names are Forever."

So: claim the names on all three registries while the repository is still private, then make
it public.

## Prerequisites

### Legal approval and distribution review

Both wiki pages assume this is already done. Publishing to a package index does not grant
new permission — it is an additional distribution channel for code already approved for open
source, and the license is the one identified on the approval.

A [distribution review](https://w.amazon.com/bin/view/Open_Source/Distributions/) is
separately required if the release includes third-party open source components. The three
core packages have no runtime dependencies, so they are clean on that count; `server/`,
`console/`, `examples/` and `infra/` all carry third-party dependencies, so confirm with the
OSPO whether shipping them as source in the repository needs one.

### Namespaces are not free choices

**npm** — Amazon owns a fixed set of organizations (`@amzn`, `@amazon`, `@aws`, `@aws-sdk`,
`@aws-crypto`, `@cdklabs`, `@cloudscape-design`, and others). Guidance is to publish inside
one of them unless there is a good reason not to. These packages therefore use **`@aws`**,
listed as "General AWS components" — hence `@aws/tolap-core` rather than `@tolap/core`.
Request to join `@aws` with the OSPO's
[join ticket](https://t.corp.amazon.com/create/templates/cc0f844b-0b27-436c-b323-275f214880e6);
a differently-named org needs the
[new-org ticket](https://t.corp.amazon.com/create/templates/727b2c07-712c-4118-ae0e-8515df4a984f)
instead.

The workspace packages that are **not** published — `server/`, `console/`, `infra/` — use the
`@amzn/` namespace, which is the documented convention for anything not going to the public
registry.

**PyPI** has one global namespace with no org concept, so `tolap-core` and its siblings are
claimed by first upload.

**NuGet** prefixes `AWS.*` and `Amazon.*` are reserved by the .NET SDK team. `Tolap.*` is
neither, so establish in the access ticket below whether their key covers it or a prefix
reservation is needed.

### Accounts

**npm** — personal accounts are no longer invited into Amazon organizations. You need a
**shared team npm account** with 2FA enabled, which the OSPO invites into `@aws`. Register it
with a team alias, not an individual address. After the first publish, add **`amzn-oss`** as
an owner so access survives staff changes.

**PyPI** — create accounts on **both** [pypi.org](https://pypi.org/account/register/) and
[test.pypi.org](https://test.pypi.org/account/register/), using the same details on each, and
register with a team alias email. After the first publish, add **`osa-amazon`** as an owner
and [notify the open source team](https://t.corp.amazon.com/create/templates/1bcd445f-417e-42e1-a1b8-bf73fb01b1dd).

**NuGet** — you do not create this account. File the
[NuGet access ticket](https://t.corp.amazon.com/create/templates/528f1096-70bf-4a1a-852c-4757c78e8ee7)
against **AWS / SDKs and Tools / Nuget Access**. Two things gate it:

- **Authenticode signing is generally an AppSec requirement** for .NET packages, via AWS
  Signer. [Wallaby onboarding](https://w.amazon.com/bin/view/Wallaby/Onboarding/) takes
  longer than the key request, so **start it first** — this is the long-lead item in the
  whole release.
- The AWS account used to publish **must be marked Production in Isengard**.

The key arrives via Secrets Manager plus an IAM role, and the .NET SDK team **rotates it
quarterly**. If you copy it into a GitHub secret, as the workflow currently expects, that
copy must be refreshed after each rotation. Reading it from Secrets Manager at release time
via GitHub OIDC would remove that recurring step.

Consider **strong naming** as well. The .NET SDK team strong-names all their libraries
because it is viral: a strong-named application can only reference strong-named assemblies,
so not doing it excludes those consumers.

### Repository secrets

Once the accounts exist, add these under **Settings → Secrets and variables → Actions**:

| Secret | Source | Scope |
|---|---|---|
| `PYPI_API_TOKEN` | PyPI → API tokens | the three `tolap-*` projects |
| `TEST_PYPI_API_TOKEN` | test.pypi.org → API tokens | account-wide is fine |
| `NPM_TOKEN` | npm → granular token, **Automation** type | `@aws` scope, read+write |
| `NUGET_API_KEY` | the .NET SDK team's ticket | Push, scoped to your glob |

Use npm's **Automation** token type. A Publish token can demand a one-time password, which
no CI run can supply — the failure looks like an auth error rather than a missing OTP. npm
guidance is a separate granular token per actor per project, so that rotating one does not
disturb anything else.

> These are long-lived credentials. PyPI's
> [trusted publishing](https://blog.pypi.org/posts/2023-04-20-introducing-trusted-publishers/)
> is what the wiki actually recommends — a short-lived OIDC credential per run and no stored
> secret. Worth adopting once the release cadence justifies the setup; NuGet has no
> equivalent and keeps its key either way.

## Making a release

1. **Bump the version everywhere** — nine manifests plus `VERSION`:

   ```
   sdk/python/{tolap-core,tolap-store,tolap-mcp}/pyproject.toml    version = "X.Y.Z"
   sdk/typescript/packages/{core,store,mcp}/package.json            "version": "X.Y.Z"
   sdk/dotnet/src/Tolap.{Core,Store,Mcp}/*.csproj                   <Version>X.Y.Z</Version>
   VERSION
   ```

   Also bump the intra-project pins: `tolap-core>=X.Y.Z,<N+1` in the two dependent
   `pyproject.toml` files, and `"@aws/tolap-core": "^X.Y.Z"` in the two dependent
   `package.json` files. Then regenerate the lockfiles, which record workspace versions and
   fail `npm ci` when they disagree:

   ```
   cd sdk/typescript && npm install --package-lock-only
   cd ../../server && npm install --package-lock-only
   cd ../examples/typescript && npm install --package-lock-only
   ```

2. **Write the CHANGELOG section** for `## X.Y.Z`. The workflow refuses to publish a version
   with no matching heading.

3. **Rehearse on Test PyPI.** Actions → Publish → Run workflow, enter the version, and set
   *target* to `testpypi`. This is a real upload to a throwaway registry rather than a
   simulation, so it exercises the credential path and PyPI's own metadata validation.
   Test PyPI is also the one registry where a mistake costs nothing.

   ```
   pip install --index-url https://test.pypi.org/simple/ --no-deps tolap-core==X.Y.Z
   ```

4. **Dry run the rest.** Run the workflow again with *target* `dry-run` to build and validate
   all nine packages without publishing anything.

5. **Tag and push:**

   ```
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

6. **After the first release only** — add `osa-amazon` as a PyPI owner, add `amzn-oss` as an
   npm owner, notify the OSPO, and delete the "not yet published" note from the README.

7. **Then** make the repository public.

## What the workflow checks before it publishes

Registry releases are effectively immutable — PyPI will not replace a published version, npm
allows unpublish only within 72 hours and under narrow conditions, and NuGet delists rather
than deletes. Everything below runs *before* the first push:

- **Versions agree.** The tag, `VERSION`, all nine manifests, and a matching CHANGELOG
  heading. A tag saying `v1.0.0` against a manifest saying `1.0.1` stops the run.
- **The full suite passes at the release commit.** The workflow calls `ci.yml` rather than
  trusting an earlier green on `main`: a tag can be moved, or cut from a branch `main` never
  saw.
- **Every wheel carries `LICENSE` and `NOTICE`.** These resolve relative to each
  `pyproject.toml`, so a missing copy produces a license-less wheel with no build error.
- **Every npm tarball contains `dist/` and the license files only.** `files` in each manifest
  is an allowlist; before it existed, publishing `@aws/tolap-core` would have shipped 100
  files and 2.1 MB including the test suite.
- **Every NuGet package carries its declared dependencies.** `dotnet pack` converts
  `ProjectReference` into a package dependency, but that is SDK behaviour rather than
  something this repo controls, and getting it wrong ships a `Tolap.Mcp` that installs
  without `Tolap.Core` and fails at runtime.

## When a release partially fails

Three registries, three jobs, failing independently. The `summary` job fails the run whenever
any of them did not succeed, so a partial release never shows up as a green check.

**Re-run the workflow with the same version.** Every publish step skips what is already live:
`twine upload --skip-existing`, `dotnet nuget push --skip-duplicate`, and for npm an
`EPUBLISHCONFLICT` is treated as success because it means the package is on the registry at
the right version.

Do **not** bump the version to work around a partial failure. That strands the packages that
did publish at a version their siblings never reach — exactly the mismatched combination the
single-version rule exists to prevent.

## Verifying a release

```bash
pip download --no-deps tolap-core==X.Y.Z -d /tmp/verify
npm view @aws/tolap-core@X.Y.Z
curl -s https://api.nuget.org/v3-flatcontainer/tolap.core/index.json
```

Registry indexes are cached, so a package can take a few minutes to appear.

## Leaving the team

Access is tied to the shared team npm account rather than a personal login, so hand over that
account, transfer its 2FA device, and rotate the stored secrets. Do the same for the PyPI team
account. Keep `osa-amazon` and `amzn-oss` as owners throughout — they are the breakglass path
when an account is lost.

## Reference

- [Should you publish to a package index?](https://w.amazon.com/bin/view/Open_Source/Open_Sourcing/Uploading/) — support levels per registry, "Names are Forever"
- [PublishingToPyPI](https://w.amazon.com/bin/view/Open_Source/Open_Sourcing/Uploading/PublishingToPyPI)
- [PublishingToNPM](https://w.amazon.com/bin/view/Open_Source/Open_Sourcing/Uploading/PublishingToNPM) — namespaces, shared team accounts, granular tokens
- [NuGet & PowerShell Gallery](https://w.amazon.com/bin/view/AWSSDKsAndTools/NetSDK/NuGet) — external team key requests, signing, rotation
- [Wallaby onboarding](https://w.amazon.com/bin/view/Wallaby/Onboarding/) — Authenticode signing
