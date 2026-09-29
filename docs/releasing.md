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

## Names

The PyPI names are claimed. The npm names sit inside `@aws`, which Amazon owns, so they
cannot be squatted by an outsider. `Tolap.*` on NuGet is neither claimed nor reserved:
until it is, anyone can register it, so treat NuGet as the item to close first once a key
exists. The [Uploading](https://w.amazon.com/bin/view/Open_Source/Open_Sourcing/Uploading/)
page's rule applies throughout -- "Names are Forever."

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

### Credentials

| Registry | How the workflow authenticates | What you configure |
|---|---|---|
| PyPI, Test PyPI | [Trusted publishing](https://docs.pypi.org/trusted-publishers/) -- a short-lived OIDC credential per run, no stored secret | On each of the three projects, on both sites: *Publishing → Add a trusted publisher → GitHub*, owner `awslabs`, repository `tolap`, workflow `publish.yml`, environment `pypi` (or `testpypi` on test.pypi.org). A project that does not exist yet on a site takes a *pending* publisher from your account's Publishing page instead |
| npm | `NPM_TOKEN` secret -- the CI publisher token from the OSPO ticket. Every publish carries `--provenance` | The secret, in the `npm` environment |
| NuGet | `NUGET_API_KEY` secret | The secret in the `nuget` environment, then the repository variable `PUBLISH_NUGET` = `true` |

Store secrets on the **environment** (*Settings → Environments → npm / nuget*), not as
repository secrets, so only the approved upload job can read them.

Each upload job runs in a GitHub environment (`testpypi`, `pypi`, `npm`, `nuget`) with a
required reviewer, so every upload waits for a person to approve it in the run page, even
after the tag is pushed.

Use npm's **Automation** (or granular, 2FA-bypass) token type. A Publish token can demand
a one-time password, which no CI run can supply -- the failure looks like an auth error
rather than a missing OTP.

NuGet is opt-in. Until `PUBLISH_NUGET` is `true`, the three `.nupkg` files are still built
and validated on every run, and a live release publishes PyPI and npm only.

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
   *target* to `testpypi`, then approve the `testpypi` environment. This is a real upload to a throwaway registry rather than a
   simulation, so it exercises the credential path and PyPI's own metadata validation.
   Test PyPI is also the one registry where a mistake costs nothing.

   ```
   pip install --index-url https://test.pypi.org/simple/ --no-deps tolap-core==X.Y.Z
   ```

4. **Dry run the rest.** Run the workflow again with *target* `dry-run` to build and validate
   all nine packages without publishing anything.

5. **Tag and push**, then approve the `pypi` and `npm` environments when the run asks:

   ```
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

   For a version whose tag predates this workflow, run it by hand instead with *target*
   `live` and the version; the gates are the same.

6. **After the first release only** — add `osa-amazon` as a PyPI owner, add `amzn-oss` as an
   npm owner, and notify the OSPO.

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
`skip-existing` on the PyPI upload, `dotnet nuget push --skip-duplicate`, and for npm an
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

Access is tied to shared team accounts rather than personal logins. Hand over the npm and
PyPI team accounts, transfer their 2FA devices, and rotate the npm and NuGet secrets. PyPI
needs no rotation: trusted publishing stores nothing. Keep `osa-amazon` and `amzn-oss` as
owners throughout — they are the breakglass path when an account is lost.

## Reference

- [Should you publish to a package index?](https://w.amazon.com/bin/view/Open_Source/Open_Sourcing/Uploading/) — support levels per registry, "Names are Forever"
- [PublishingToPyPI](https://w.amazon.com/bin/view/Open_Source/Open_Sourcing/Uploading/PublishingToPyPI)
- [PublishingToNPM](https://w.amazon.com/bin/view/Open_Source/Open_Sourcing/Uploading/PublishingToNPM) — namespaces, shared team accounts, granular tokens
- [NuGet & PowerShell Gallery](https://w.amazon.com/bin/view/AWSSDKsAndTools/NetSDK/NuGet) — external team key requests, signing, rotation
- [Wallaby onboarding](https://w.amazon.com/bin/view/Wallaby/Onboarding/) — Authenticode signing
