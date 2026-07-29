#!/usr/bin/env python3
"""Per-file statement and branch coverage for the three shipped TOLAP .NET projects.

Reads a merged cobertura report (see coverage.sh) and prints per-file line and
branch percentages plus the exact uncovered lines and partially-covered branches,
which is what a coverage gap review actually needs -- an aggregate percentage
hides which conditional has only one outcome exercised.

Usage:
    ./coverage.sh                      # collect, merge, and render
    python3 coverage-report.py merged.cobertura.xml
"""
from __future__ import annotations

import re
import sys
from collections import defaultdict
import xml.etree.ElementTree as ET

SHIPPED = ("Tolap.Core", "Tolap.Store", "Tolap.Mcp")


def normalize(filename: str) -> str:
    """Strip the varying source-root prefix so the four reports agree on a key."""
    for project in SHIPPED:
        marker = project + "/"
        if marker in filename:
            return filename[filename.index(marker):]
        if filename.count("/") == 0:
            # A report rooted at src/<Project>/ lists bare file names.
            return filename
    return filename


def main(path: str) -> int:
    root = ET.parse(path).getroot()

    # Reports rooted at src/<Project>/ carry bare filenames, so recover the
    # project from the <source> element when the filename does not carry it.
    source_roots = [s.text or "" for s in root.iter("source")]
    default_project = ""
    for src in source_roots:
        for project in SHIPPED:
            if src.rstrip("/").endswith(project):
                default_project = project + "/"

    # file -> line number -> [hits, branch total, branch covered]
    files: dict[str, dict[int, list[int]]] = defaultdict(lambda: defaultdict(lambda: [0, 0, 0]))

    for cls in root.iter("class"):
        raw = cls.get("filename", "")
        if "Tests" in raw:
            continue
        name = normalize(raw)
        if not name.startswith(SHIPPED):
            name = default_project + name
        if not name.startswith(SHIPPED):
            continue
        for line in cls.iter("line"):
            record = files[name][int(line.get("number", "0"))]
            record[0] = max(record[0], int(line.get("hits", "0")))
            if (line.get("branch") or "").lower() == "true":
                match = re.search(r"\((\d+)/(\d+)\)", line.get("condition-coverage", ""))
                if match:
                    covered, total = int(match.group(1)), int(match.group(2))
                    record[1] = max(record[1], total)
                    record[2] = max(record[2], covered)

    print(f"{'File':<44}{'Lines':>14}{'Line%':>9}{'Branches':>12}{'Branch%':>9}")
    print("-" * 88)

    totals = [0, 0, 0, 0]
    gaps: dict[str, tuple[list[int], list[str]]] = {}

    for name in sorted(files):
        entries = files[name]
        n_lines = len(entries)
        n_covered = sum(1 for r in entries.values() if r[0] > 0)
        n_branch = sum(r[1] for r in entries.values())
        n_branch_cov = sum(r[2] for r in entries.values())
        totals[0] += n_covered
        totals[1] += n_lines
        totals[2] += n_branch_cov
        totals[3] += n_branch

        line_pct = 100.0 * n_covered / n_lines if n_lines else 100.0
        branch_pct = 100.0 * n_branch_cov / n_branch if n_branch else 100.0
        print(f"{name:<44}{n_covered:>7}/{n_lines:<6}{line_pct:>8.2f}%"
              f"{n_branch_cov:>6}/{n_branch:<5}{branch_pct:>8.2f}%")

        uncovered = sorted(n for n, r in entries.items() if r[0] == 0)
        partial = [f"{n} ({r[2]}/{r[1]})" for n, r in sorted(entries.items())
                   if r[1] > 0 and r[2] < r[1]]
        if uncovered or partial:
            gaps[name] = (uncovered, partial)

    print("-" * 88)
    line_pct = 100.0 * totals[0] / totals[1] if totals[1] else 100.0
    branch_pct = 100.0 * totals[2] / totals[3] if totals[3] else 100.0
    print(f"{'TOTAL':<44}{totals[0]:>7}/{totals[1]:<6}{line_pct:>8.2f}%"
          f"{totals[2]:>6}/{totals[3]:<5}{branch_pct:>8.2f}%")

    if gaps:
        print("\n=== GAPS (uncovered lines / partially-covered branches) ===")
        for name, (uncovered, partial) in gaps.items():
            print(f"\n{name}")
            if uncovered:
                print(f"  uncovered lines:  {uncovered}")
            if partial:
                print(f"  partial branches: {', '.join(partial)}")
    else:
        print("\nNo uncovered lines and no partially-covered branches.")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "merged.cobertura.xml"))
