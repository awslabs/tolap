from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

SDK_ROOT = Path(__file__).parent.parent
FIXTURES_DIR = SDK_ROOT.parent.parent / "fixtures"

# Import the packages from this checkout, not from whatever `pip install -e`
# wired into site-packages. Without this the suite can silently exercise a
# different working tree, so a passing run proves nothing about these sources.
for _package_dir in ("tolap-core", "tolap-mcp", "tolap-store"):
    _path = str(SDK_ROOT / _package_dir)
    if _path in sys.path:
        sys.path.remove(_path)
    sys.path.insert(0, _path)


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES_DIR


def load_fixture(relative_path: str) -> dict:
    """Load a JSON fixture file relative to the fixtures directory."""
    path = FIXTURES_DIR / relative_path
    with open(path) as f:
        return json.load(f)


def load_all_fixtures(subdirectory: str) -> list[tuple[str, dict]]:
    """Load all JSON fixtures from a subdirectory, returning (filename, data) tuples."""
    directory = FIXTURES_DIR / subdirectory
    results = []
    for path in sorted(directory.glob("*.json")):
        with open(path) as f:
            results.append((path.stem, json.load(f)))
    return results
