from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent.parent.parent.parent / "fixtures"


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
