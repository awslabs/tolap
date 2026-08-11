# Releasing TOLAP

Nine packages ship as a set at one version, across three registries:

| Registry | Packages |
|---|---|
| PyPI | `tolap-core`, `tolap-store`, `tolap-mcp` |
| npm | `@tolap/core`, `@tolap/store`, `@tolap/mcp` |
| NuGet | `Tolap.Core`, `Tolap.Store`, `Tolap.Mcp` |

They are **not** independently versioned, deliberately. The guarantee these packages carry
is cross-package and cross-language: a context signed by `@tolap/core` must verify in
`tolap-core` and `Tolap.Core`, and the shared fixtures in `fixtures/` demand byte-identical
output from all three. Versioning them separately would let a consumer assemble a
combination nothing ever tested.

The schema in `schema/v1.0/` is versioned separately, because it describes the on-the-wire
policy format rather than the packages that implement it.

## One-time setup

Nothing below is done by the workflow. Until all of it exists, a release run fails at the
publish step, which is the intended behaviour — it fails before pushing rather than half
way through.

### 1. Claim the namespaces

- **PyPI** — register `tolap-core`, `tolap-store`, `tolap-mcp`. Names are
  first-come-first-served and cannot be reclaimed from someone else.
- **npm** — create the `@tolap` organization and set it to allow public packages. Scoped
  packages are private by default; `publishConfig.access: "public"` in each manifest
  overrides that per package, but the org must exist first.
- **NuGet** — push the first `Tolap.Core` package, or reserve the `Tolap.*` ID prefix,
  which is worth doing because it stops anyone else publishing under the same prefix.

### 2. Add the repository secrets

In **Settings → Secrets and variables → Actions**:

| Secret | Where it comes from | Scope it to |
|---|---|---|
| `PYPI_API_TOKEN` | PyPI → Account settings → API tokens | the three `tolap-*` projects |
| `NPM_TOKEN` | npm → Access Tokens → Granular, **Automation** type | the `@tolap` scope, read+write |
| `NUGET_API_KEY` | NuGet.org → API Keys | Push, `Tolap.*` glob |

Scope each token to the packages it needs. An org-wide token in a public repository is a
much larger blast radius than the release it enables.

Two notes on the tokens themselves. Use npm's **Automation** token type, not Publish —
Publish tokens can require a one-time password, which no CI run can supply. And set an
expiry you will actually notice: a token that silently expires turns the next release into
a debugging session.

> These are long-lived credentials, which was a deliberate choice for simplicity. Both PyPI
> and npm support OIDC trusted publishing, which issues a short-lived credential per run and
> removes the stored secret entirely. If this project's release cadence grows, that is the
> upgrade worth making; NuGet has no OIDC equivalent and would keep its API key either way.

### 3. Confirm the release-notes section exists

The workflow refuses to publish a version with no matching `## <version>` heading in
`CHANGELOG.md`. Write the notes before tagging.

## Making a release

1. **Bump the version everywhere.** Nine manifests plus `VERSION`:

   ```
   sdk/python/{tolap-core,tolap-store,tolap-mcp}/pyproject.toml    version = "X.Y.Z"
   sdk/typescript/packages/{core,store,mcp}/package.json            "version": "X.Y.Z"
   sdk/dotnet/src/Tolap.{Core,Store,Mcp}/*.csproj                   <Version>X.Y.Z</Version>
   VERSION
   ```

   Also bump the intra-project pins: `tolap-core>=X.Y.Z,<N+1` in the two dependent
   `pyproject.toml` files, and `"@tolap/core": "^X.Y.Z"` in the two dependent
   `package.json` files.

   Then regenerate the TypeScript lockfile, which records workspace versions and will fail
   `npm ci` if it disagrees:

   ```
   cd sdk/typescript && npm install --package-lock-only
   ```

2. **Write the CHANGELOG section** for `## X.Y.Z`.

3. **Dry run.** Actions → Publish → Run workflow, enter the version, leave *dry run*
   checked. This builds and validates all nine packages and pushes nothing.

4. **Tag and push:**

   ```
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

   The tag triggers the real publish.

## What the workflow checks before it publishes

Registry releases are effectively immutable — PyPI will not let you replace a published
version, npm allows unpublish only within 72 hours and under narrow conditions, and NuGet
delists rather than deletes. Everything below therefore runs *before* the first push:

- **Versions agree.** The tag, `VERSION`, all nine manifests, and a matching CHANGELOG
  heading. A tag that says `v1.0.0` while a manifest says `1.0.1` stops the run.
- **The full suite passes at the release commit.** The workflow calls `ci.yml` rather than
  trusting an earlier green run on `main`: a tag can be moved, or cut from a branch `main`
  never saw.
- **Every wheel carries `LICENSE` and `NOTICE`.** These are resolved relative to each
  `pyproject.toml`, so a missing copy produces a license-less wheel with no build error.
  The check asserts the property instead.
- **Every npm tarball contains `dist/` and the license files only.** `files` in each
  manifest is an allowlist; before it existed, `npm publish` for `@tolap/core` would have
  shipped 100 files and 2.1 MB including the test suite.
- **Every NuGet package carries its declared dependencies.** `dotnet pack` converts
  `ProjectReference` into a package dependency, but that is SDK behaviour rather than
  something this repo controls, and getting it wrong ships a `Tolap.Mcp` that installs
  without `Tolap.Core` and fails at runtime.

## When a release partially fails

Three registries, three jobs, and they fail independently. The `summary` job fails the run
whenever any of them did not succeed, so a partial release does not show up as a green
check.

**Re-run the workflow with the same version.** Every publish step skips what is already
live: `twine upload --skip-existing`, `dotnet nuget push --skip-duplicate`, and for npm an
`EPUBLISHCONFLICT` is treated as success because it means the package is on the registry at
the right version. Re-running is safe and repairs the gap.

Do **not** bump the version to work around a partial failure. That strands the packages
that did publish at a version their siblings never reach, which is exactly the mismatched
combination the single-version rule exists to prevent.

## Verifying a release

```bash
pip download --no-deps tolap-core==X.Y.Z -d /tmp/verify
npm view @tolap/core@X.Y.Z
curl -s https://api.nuget.org/v3-flatcontainer/tolap.core/index.json
```

Registry indexes are cached, so a package can take a few minutes to appear after a
successful push.
