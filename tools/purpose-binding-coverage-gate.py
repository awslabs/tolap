#!/usr/bin/env python3
"""Fail the build when a purpose-binding module drops below 100% line and branch coverage.

Why a gate rather than a convention. Purpose binding is four access-control decisions
(canonical-enforcement-spec.md section 15), and every one of them has a fail-closed arm that
only runs on the path nobody exercises by hand: an unclassified tool, a widened delegation
hop, a malformed judge verdict, an empty allow-list. Those arms are the feature. A module that
silently drops to 96% has almost certainly dropped one of them, and the ordinary signal --
a falling repo-wide percentage -- is far too coarse to notice one branch in four thousand.

Scoped deliberately to the modules this feature added, not applied repo-wide. A blanket 100%
rule across a codebase this size produces pressure to write tests that reach lines rather than
tests that check behaviour, which is the failure `docs/testing-antipatterns.md` is entirely
about. These files are new, were written to this standard, and are small enough to hold it.

Reads the reports the existing CI test steps already produce, so it adds no second test run:

  --cobertura  .NET (coverlet XPlat) and Python (`pytest --cov --cov-branch --cov-report=xml`)
               both emit Cobertura; either may be passed more than once.
  --lcov       TypeScript (`vitest run --coverage`, provider v8, reporter lcov).

Exits non-zero with a per-file breakdown naming the uncovered lines and one-sided branches, so
a failure says which arm stopped being tested rather than only that a number moved.
"""

from __future__ import annotations

import argparse
import re
import sys
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass, field
from pathlib import Path

# The modules this feature added, keyed by **basename**.
#
# Matched on basename rather than on a path, because the three tools disagree about the root
# they report against and are not even self-consistent: coverlet emits a bare
# `JudgeGate.cs` for one project and a prefixed `Tolap.Mcp/BedrockJudge.cs` for another,
# pytest emits `tolap_core/judge.py`, and vitest emits an absolute path. Every basename below
# is unique across the sixteen, so there is nothing for the looser match to confuse -- and a
# per-tool prefix table would be a fourth thing to keep in step with three build systems.
#
# A file listed here and absent from every report is a FAILURE, not a pass -- see
# `_report_missing`. That is the point: a module that stopped being measured is
# indistinguishable from one that stopped being tested, and the silent version is worse.
GATED_FILES: tuple[str, ...] = (
    # .NET
    "DelegationChainValidator.cs",
    "PurposeActionResolver.cs",
    "JudgeGate.cs",
    "IJudge.cs",
    "ToolCallHistory.cs",
    "BedrockJudge.cs",
    # Python
    "delegation.py",
    "purpose_action.py",
    "judge.py",
    "history.py",
    "bedrock_judge.py",
    # TypeScript
    "delegation.ts",
    "purpose-action.ts",
    "judge.ts",
    "history.ts",
    "bedrock-judge.ts",
)



@dataclass
class FileCoverage:
    """Line and branch coverage for one file, accumulated across reports."""

    path: str
    uncovered_lines: set[int] = field(default_factory=set)
    partial_branches: dict[int, str] = field(default_factory=dict)
    covered_lines: set[int] = field(default_factory=set)

    @property
    def clean(self) -> bool:
        return not self.uncovered_lines and not self.partial_branches

    @property
    def measured(self) -> bool:
        """Whether the report carried any line data at all for this file.

        A file present in a report with zero measurable lines is treated as unmeasured rather
        than as trivially perfect, because that is what an instrumentation failure looks like.
        """
        return bool(self.covered_lines or self.uncovered_lines)


def _gated_key(path: str) -> str | None:
    """The gate entry this reported path belongs to, or None."""
    basename = path.replace("\\", "/").rsplit("/", 1)[-1]
    return basename if basename in GATED_FILES else None


def _merge(into: dict[str, FileCoverage], key: str, path: str) -> FileCoverage:
    return into.setdefault(key, FileCoverage(path=path))


def read_cobertura(report: Path, into: dict[str, FileCoverage]) -> None:
    """Cobertura, as emitted by coverlet and by coverage.py."""
    root = ElementTree.parse(report).getroot()

    for class_element in root.iter("class"):
        filename = class_element.get("filename")
        if filename is None:
            continue

        suffix = _gated_key(filename)
        if suffix is None:
            continue

        coverage = _merge(into, suffix, filename)

        for line in class_element.iter("line"):
            number_text = line.get("number")
            if number_text is None:
                continue
            number = int(number_text)

            # Merged across several test projects, so a line covered by ANY of them counts as
            # covered -- and must therefore be removed from an earlier report's uncovered set.
            if int(line.get("hits", "0")) > 0:
                coverage.covered_lines.add(number)
                coverage.uncovered_lines.discard(number)
            elif number not in coverage.covered_lines:
                coverage.uncovered_lines.add(number)

            if line.get("branch") != "true":
                continue

            condition = line.get("condition-coverage", "")
            match = re.search(r"\((\d+)/(\d+)\)", condition)
            if match is None:
                continue

            taken, total = int(match.group(1)), int(match.group(2))
            if taken >= total:
                coverage.partial_branches.pop(number, None)
            else:
                # Recorded unless a later report shows the branch complete, which the pop
                # above handles. Merged reports mean the last word wins in either direction.
                coverage.partial_branches[number] = f"{taken}/{total}"


def read_lcov(report: Path, into: dict[str, FileCoverage]) -> None:
    """LCOV, as emitted by vitest's v8 provider."""
    current: FileCoverage | None = None
    # BRDA lines report one arm at a time, so arms are tallied per (line, block) before a
    # verdict: a branch is one-sided only when at least one of its arms was never taken.
    branch_arms: dict[tuple[int, str], list[bool]] = {}

    def flush() -> None:
        if current is None:
            return
        for (line, _block), arms in branch_arms.items():
            if not all(arms):
                taken = sum(1 for arm in arms if arm)
                current.partial_branches[line] = f"{taken}/{len(arms)}"
        branch_arms.clear()

    for raw in report.read_text().splitlines():
        line = raw.strip()

        if line.startswith("SF:"):
            flush()
            path = line[3:]
            suffix = _gated_key(path)
            current = _merge(into, suffix, path) if suffix else None
            continue

        if line == "end_of_record":
            flush()
            current = None
            continue

        if current is None:
            continue

        if line.startswith("DA:"):
            number_text, _, hits_text = line[3:].partition(",")
            number = int(number_text)
            if int(hits_text or "0") > 0:
                current.covered_lines.add(number)
                current.uncovered_lines.discard(number)
            elif number not in current.covered_lines:
                current.uncovered_lines.add(number)

        elif line.startswith("BRDA:"):
            parts = line[5:].split(",")
            if len(parts) < 4:
                continue
            number, block, _branch, taken = parts[0], parts[1], parts[2], parts[3]
            # "-" means the branch was never reached at all, which is not taken.
            arms = branch_arms.setdefault((int(number), block), [])
            arms.append(taken not in ("-", "0"))

    flush()


def _report_missing(found: dict[str, FileCoverage]) -> list[str]:
    """Gated files with no usable coverage data.

    Reported as failures. A module that dropped out of instrumentation looks exactly like a
    module at 100% if absence is treated as success, and this gate exists precisely because
    that class of silence is what lets a fail-closed arm stop being tested.
    """
    return [
        suffix
        for suffix in GATED_FILES
        if suffix not in found or not found[suffix].measured
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cobertura",
        action="append",
        default=[],
        type=Path,
        help="Cobertura XML report (.NET coverlet or Python coverage.py). Repeatable.",
    )
    parser.add_argument(
        "--lcov",
        action="append",
        default=[],
        type=Path,
        help="LCOV report (TypeScript vitest). Repeatable.",
    )
    parser.add_argument(
        "--allow-missing",
        action="store_true",
        help=(
            "Do not fail on gated files absent from every report. For running the gate "
            "against a single language locally; CI must NOT pass this, or a language "
            "dropping out of coverage becomes invisible."
        ),
    )
    args = parser.parse_args()

    if not args.cobertura and not args.lcov:
        print("no coverage reports supplied; nothing to gate", file=sys.stderr)
        return 2

    found: dict[str, FileCoverage] = {}

    for report in args.cobertura:
        if not report.exists():
            print(f"coverage report not found: {report}", file=sys.stderr)
            return 2
        read_cobertura(report, found)

    for report in args.lcov:
        if not report.exists():
            print(f"coverage report not found: {report}", file=sys.stderr)
            return 2
        read_lcov(report, found)

    failures: list[str] = []
    verified = 0

    for suffix in GATED_FILES:
        coverage = found.get(suffix)
        if coverage is None or not coverage.measured:
            continue

        if coverage.clean:
            verified += 1
            print(f"  ok      {suffix}")
            continue

        detail = []
        if coverage.uncovered_lines:
            detail.append(
                "uncovered lines: " + ", ".join(str(n) for n in sorted(coverage.uncovered_lines))
            )
        if coverage.partial_branches:
            detail.append(
                "one-sided branches: "
                + ", ".join(
                    f"{line} ({ratio})" for line, ratio in sorted(coverage.partial_branches.items())
                )
            )
        failures.append(f"  FAIL    {suffix}\n            " + "\n            ".join(detail))

    missing = _report_missing(found)
    if missing and not args.allow_missing:
        for suffix in missing:
            failures.append(
                f"  MISSING {suffix}\n            "
                "no coverage data in any supplied report -- a module that stopped being "
                "measured is indistinguishable from one that stopped being tested"
            )
    elif missing:
        for suffix in missing:
            print(f"  skip    {suffix} (not in the supplied reports)")

    if failures:
        print()
        print("Purpose-binding coverage gate FAILED (canonical spec section 15):")
        print()
        print("\n".join(failures))
        print()
        print(
            "Every module above is an access-control decision whose fail-closed arms are the\n"
            "feature. If a branch is genuinely unreachable, delete it rather than leaving it\n"
            "uncovered -- unreachable defensive code reads as a handled case no test can\n"
            "exercise. See docs/testing-antipatterns.md section 8."
        )
        return 1

    print()
    print(f"Purpose-binding coverage gate passed: {verified} modules at 100% line and branch.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
