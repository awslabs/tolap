#!/usr/bin/env bash
# Statement and branch coverage for the three shipped TOLAP .NET projects.
#
# Runs every test project with coverlet's XPlat collector, merges the four
# cobertura reports into one (a union: a line covered by any project counts as
# covered), and renders per-file line and branch numbers plus the exact
# uncovered lines and one-sided branches.
#
# Requires:
#   dotnet tool install --global dotnet-coverage
#   dotnet tool install --global dotnet-reportgenerator-globaltool   # optional, HTML/summary
#
# Usage:
#   ./coverage.sh          # run the whole suite and report
#   ./coverage.sh --html   # additionally write an HTML report to artifacts/coverage/html
set -euo pipefail

cd "$(dirname "$0")"

ARTIFACTS="artifacts/coverage"
RAW="$ARTIFACTS/raw"
MERGED="$ARTIFACTS/merged.cobertura.xml"
TOOLS="${DOTNET_TOOLS_PATH:-$HOME/.dotnet/tools}"

rm -rf "$RAW" "$MERGED"
mkdir -p "$RAW"

dotnet test Tolap.sln \
  --nologo \
  --collect:"XPlat Code Coverage" \
  --results-directory "$RAW" \
  -- DataCollectionRunSettings.DataCollectors.DataCollector.Configuration.Format=cobertura

"$TOOLS/dotnet-coverage" merge -o "$MERGED" -f cobertura "$RAW"/*/coverage.cobertura.xml

python3 coverage-report.py "$MERGED"

if [[ "${1:-}" == "--html" ]]; then
  "$TOOLS/reportgenerator" \
    "-reports:$MERGED" \
    "-targetdir:$ARTIFACTS/html" \
    "-reporttypes:Html;TextSummary" \
    "-filefilters:-*Tests*"
  echo "HTML report: $ARTIFACTS/html/index.html"
fi
