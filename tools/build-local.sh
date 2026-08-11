#!/usr/bin/env bash
#
# Builds the nine SDK packages and installs them into the current environment.
#
# TOLAP is not distributed through PyPI, npm or NuGet. This script is the supported
# way to consume it: it produces the same artifacts a registry would serve, from the
# source you can read, and installs them locally.
#
#   ./tools/build-local.sh              # all three languages
#   ./tools/build-local.sh python       # one language
#   ./tools/build-local.sh --artifacts  # build only, leave the files in dist/
#
# Each language is independent: a missing toolchain skips that language with a note
# rather than failing the run, because most integrators only want one of the three.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="$REPO_ROOT/dist"
ARTIFACTS_ONLY=0
LANGS=()

for arg in "$@"; do
  case "$arg" in
    --artifacts) ARTIFACTS_ONLY=1 ;;
    python|typescript|dotnet) LANGS+=("$arg") ;;
    -h|--help)
      sed -n '3,15p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "unknown argument: $arg (expected python, typescript, dotnet, or --artifacts)" >&2; exit 2 ;;
  esac
done
[ ${#LANGS[@]} -eq 0 ] && LANGS=(python typescript dotnet)

mkdir -p "$DIST"
FAILED=()
SKIPPED=()
BUILT=()

note() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }

build_python() {
  if ! command -v python3 >/dev/null; then SKIPPED+=("python (no python3)"); return; fi
  note "Python"
  python3 -m pip install --quiet --upgrade build 2>/dev/null
  for pkg in tolap-core tolap-store tolap-mcp; do
    echo "  building $pkg"
    if ! python3 -m build --outdir "$DIST/python" "$REPO_ROOT/sdk/python/$pkg" >/dev/null 2>&1; then
      FAILED+=("python:$pkg"); return
    fi
  done
  if [ "$ARTIFACTS_ONLY" -eq 1 ]; then
    BUILT+=("python wheels and sdists -> dist/python"); return
  fi
  # Installed from the built wheels rather than the source tree, so this exercises
  # the same path a registry install would take -- including whether each package
  # declares the dependencies it imports.
  echo "  installing the built wheels"
  if python3 -m pip install --quiet --force-reinstall \
       "$DIST"/python/tolap_core-*.whl "$DIST"/python/tolap_store-*.whl "$DIST"/python/tolap_mcp-*.whl; then
    BUILT+=("python (installed: tolap-core, tolap-store, tolap-mcp)")
  else
    FAILED+=("python install")
  fi
}

build_typescript() {
  if ! command -v npm >/dev/null; then SKIPPED+=("typescript (no npm)"); return; fi
  note "TypeScript"
  cd "$REPO_ROOT/sdk/typescript" || { FAILED+=("typescript"); return; }
  echo "  npm ci"
  npm ci --silent >/dev/null 2>&1 || { FAILED+=("typescript npm ci"); return; }
  # core first: store and mcp resolve @aws/tolap-core through packages/core/dist, so
  # building them first fails with TS6305 on a clean clone.
  for pkg in core store mcp; do
    echo "  compiling @aws/tolap-$pkg"
    (cd "packages/$pkg" && npx tsc -p tsconfig.json) || { FAILED+=("typescript:$pkg"); return; }
  done
  mkdir -p "$DIST/npm"
  for pkg in core store mcp; do
    (cd "packages/$pkg" && npm pack --pack-destination "$DIST/npm" >/dev/null 2>&1) \
      || { FAILED+=("typescript pack:$pkg"); return; }
  done
  BUILT+=("typescript (tarballs -> dist/npm; compiled in place under packages/*/dist)")
  cd "$REPO_ROOT" || return
}

build_dotnet() {
  if ! command -v dotnet >/dev/null; then SKIPPED+=("dotnet (no dotnet SDK)"); return; fi
  note ".NET"
  for proj in Tolap.Core Tolap.Store Tolap.Mcp; do
    echo "  packing $proj"
    if ! dotnet pack "$REPO_ROOT/sdk/dotnet/src/$proj/$proj.csproj" \
         -c Release -o "$DIST/nuget" --nologo -v quiet >/dev/null 2>&1; then
      FAILED+=("dotnet:$proj"); return
    fi
  done
  if [ "$ARTIFACTS_ONLY" -eq 1 ]; then
    BUILT+=("dotnet packages -> dist/nuget"); return
  fi
  # A local feed is how .NET consumes packages off the filesystem. Adding it once
  # lets `dotnet add package Tolap.Core` resolve from dist/nuget in any project on
  # this machine.
  BUILT+=("dotnet (packages -> dist/nuget)")
  cat <<EOF

  To consume these from another project, register the output as a local feed:

      dotnet nuget add source "$DIST/nuget" --name tolap-local

  then reference them normally:

      dotnet add package Tolap.Core
EOF
}

for lang in "${LANGS[@]}"; do
  case "$lang" in
    python)     build_python ;;
    typescript) build_typescript ;;
    dotnet)     build_dotnet ;;
  esac
done

note "Summary"
for b in "${BUILT[@]:-}";   do [ -n "$b" ] && echo "  built   $b"; done
for s in "${SKIPPED[@]:-}"; do [ -n "$s" ] && echo "  skipped $s"; done
for f in "${FAILED[@]:-}";  do [ -n "$f" ] && echo "  FAILED  $f"; done

if [ ${#FAILED[@]} -gt 0 ] && [ -n "${FAILED[0]:-}" ]; then
  echo
  echo "Something failed above. Re-run the failing language on its own for full output,"
  echo "e.g. ./tools/build-local.sh python"
  exit 1
fi
echo
echo "Done. Artifacts are in dist/."
