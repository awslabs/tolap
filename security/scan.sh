#!/usr/bin/env bash
#
# Run the security scan set against the server, console and infrastructure.
#
# This exists because remembering four tools with four sets of flags does not survive
# contact with a deadline, and one of them was in fact forgotten. A high-severity ReDoS in
# the SQL importer reached a public pull request because Semgrep, Trivy and `npm audit` all
# passed it -- CodeQL was the only tool in the set that models super-linear regex
# backtracking, and it was not being run locally. It caught the defect on the PR instead of
# before it.
#
# So the point of this script is not convenience. It is that the scan set is now a list in
# one file rather than a habit, and adding a tool means adding it here where the next person
# will run it too.
#
#   ./security/scan.sh            # everything
#   ./security/scan.sh semgrep    # one tool
#   ./security/scan.sh codeql
#
# Exit status is non-zero if any tool reports findings, so this is usable in a pre-push
# hook. Findings that are known and accepted are documented in security/server/README.md
# with the reasoning -- read that before treating a non-zero exit as a new problem.

set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
REPO="$PWD"
ARTIFACTS="${TMPDIR:-/tmp}/tolap-scan"
mkdir -p "$ARTIFACTS"

FAILED=()
SKIPPED=()

step() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
note() { printf '   %s\n' "$1"; }

have() { command -v "$1" >/dev/null 2>&1; }

# Trivy's database download fails when ~/.docker/config.json names a credential helper that
# is not installed -- a stale `credsStore: "desktop"` after uninstalling Docker Desktop is
# the usual cause. The failure is FATAL but buried under INFO lines, so the scan looks like
# it passed while having scanned nothing. Point Trivy at an empty config instead of editing
# the user's.
prepare_trivy_config() {
  local dir="$ARTIFACTS/docker-config"
  mkdir -p "$dir"
  printf '{}' > "$dir/config.json"
  export DOCKER_CONFIG="$dir"
}

run_semgrep() {
  step "Semgrep — SAST"
  if ! have semgrep; then
    SKIPPED+=("semgrep (not installed: pipx install semgrep)")
    return
  fi
  semgrep scan \
    --config p/security-audit --config p/secrets --config p/owasp-top-ten \
    --exclude node_modules --exclude dist --exclude cdk.out --exclude coverage \
    --error \
    server/ console/ infra/ || FAILED+=("semgrep")
}

run_audit() {
  step "npm audit — every workspace with a lockfile"
  # Every workspace, not a chosen few. Auditing `server console infra` and skipping
  # `sdk/typescript` and `examples/typescript` is how a High in each of the latter two
  # reached the public default branch and was reported by Dependabot rather than here.
  # A scan whose scope silently excludes a workspace returns a clean result it has not
  # earned, which is worse than no scan because it is believed.
  local package
  for package in sdk/typescript server console infra examples/typescript; do
    note "$package (production)"
    # --omit=dev first: a devDependency advisory does not ship, so a real production
    # finding must not be lost in build-tool noise. This is the gating run.
    (cd "$package" && npm audit --omit=dev) || FAILED+=("npm audit ($package, production)")

    # Then the full tree, reported but NOT gating. Dev-only advisories still run on
    # developer and CI machines and still need triage -- being non-shipping is a reason
    # to rank them lower, not a reason never to see them.
    note "$package (including dev — informational)"
    (cd "$package" && npm audit) || true
  done
}

run_trivy() {
  step "Trivy — secrets, and IaC on the synthesized templates"
  if ! have trivy; then
    SKIPPED+=("trivy (not installed: brew install trivy)")
    return
  fi
  prepare_trivy_config

  # One path per invocation. `trivy fs` takes a single target: passing several prints usage
  # text and exits 0, which reads exactly like a clean scan.
  local target
  for target in server/src server/tests server/tools console/src infra/lib infra/bin; do
    note "secrets: $target"
    trivy fs --scanners secret --exit-code 1 --quiet "$target" || FAILED+=("trivy secrets ($target)")
  done

  # Synthesize first. Trivy reads emitted templates, and a stale cdk.out reports findings
  # for resources that no longer exist -- or misses ones that now do.
  if have node; then
    note "synthesizing infrastructure"
    (cd infra && rm -rf cdk.out && CDK_DOCKER="${CDK_DOCKER:-finch}" npx cdk synth --quiet >/dev/null 2>&1) \
      || note "synth failed; skipping IaC scan"
    if [ -d infra/cdk.out ]; then
      note "IaC: infra/cdk.out"
      # Not gated on exit code: every current finding is an accepted default or a false
      # positive, all documented in security/server/README.md. Printed so a NEW one is
      # visible, rather than failing the whole script on a known list.
      trivy config --severity HIGH,CRITICAL infra/cdk.out
      note "compare against the accepted list in security/server/README.md"
    fi
  fi
}

run_codeql() {
  step "CodeQL — the tool that caught what the others missed"
  if ! have codeql; then
    SKIPPED+=("codeql (bundle: github/codeql-action releases, codeql-bundle-<platform>)")
    return
  fi

  # Path filters are not cosmetic. Without them cdk.out and coverage/ are scanned too, and
  # every finding appears three times with two copies pointing at stale build output --
  # which is how a real finding gets dismissed as a duplicate.
  local config="$ARTIFACTS/codeql-paths.yml"
  cat > "$config" <<'YAML'
paths:
  - server/src
  - server/tools
  - console/src
  - infra/lib
  - infra/bin
paths-ignore:
  - "**/cdk.out"
  - "**/coverage"
  - "**/node_modules"
  - "**/dist"
YAML

  local db="$ARTIFACTS/db-js"
  rm -rf "$db"
  codeql database create "$db" \
    --language=javascript-typescript --source-root="$REPO" \
    --overwrite --codescanning-config="$config" >/dev/null || {
    FAILED+=("codeql (database create)")
    return
  }

  local sarif="$ARTIFACTS/codeql.sarif"
  codeql database analyze "$db" javascript-security-and-quality.qls \
    --format=sarif-latest --output="$sarif" --download >/dev/null || {
    FAILED+=("codeql (analyze)")
    return
  }

  # Summarize by rule and severity. `js/missing-rate-limiting` is expected and accepted --
  # every /v1/* route is reachable only through CloudFront, whose WAF rate-limits before the
  # managed rule groups. See security/server/README.md.
  node -e '
    const sarif = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
    const run = sarif.runs[0];
    const rules = new Map((run.tool.driver.rules ?? []).map((r) => [r.id, r]));
    const counts = new Map();
    for (const result of run.results ?? []) {
      const rule = rules.get(result.ruleId) ?? {};
      const severity = rule.properties?.["security-severity"];
      const key = `${severity ?? "-"}\t${result.ruleId}`;
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    if (counts.size === 0) { console.log("   no findings"); process.exit(0); }
    const rows = [...counts].sort((a, b) => parseFloat(b[0]) - parseFloat(a[0]));
    for (const [key, n] of rows) {
      const [severity, id] = key.split("\t");
      console.log(`   ${String(severity).padStart(4)}  ${id}  x${n}`);
    }
  ' "$sarif"
  note "full results: $sarif"
}

case "${1:-all}" in
  semgrep) run_semgrep ;;
  audit|npm) run_audit ;;
  trivy) run_trivy ;;
  codeql) run_codeql ;;
  all) run_semgrep; run_audit; run_trivy; run_codeql ;;
  *) echo "usage: $0 [all|semgrep|audit|trivy|codeql]" >&2; exit 2 ;;
esac

step "Summary"
for skipped in "${SKIPPED[@]:-}"; do
  [ -n "$skipped" ] && note "SKIPPED  $skipped"
done
if [ "${#FAILED[@]}" -gt 0 ] && [ -n "${FAILED[0]:-}" ]; then
  for failure in "${FAILED[@]}"; do note "FINDINGS $failure"; done
  note "check these against security/server/README.md before assuming they are new"
  exit 1
fi
note "no new findings from the tools that ran"
