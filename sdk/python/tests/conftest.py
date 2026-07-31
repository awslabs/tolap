from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

SDK_ROOT = Path(__file__).parent.parent
REPO_ROOT = SDK_ROOT.parent.parent
FIXTURES_DIR = REPO_ROOT / "fixtures"
SCHEMA_DIR = REPO_ROOT / "schema" / "v1.0"

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


def load_schema(name: str) -> dict:
    """Load a published JSON Schema from ``schema/v1.0`` by bare name.

    ``schema/v1.0/*.json`` is the published contract; the SDK re-declares parts of
    it as native enums. Reading the file at test time is the point -- restating the
    schema's values in Python would just create a second copy free to drift the
    same way the first one did (canonical spec section 14).
    """
    path = SCHEMA_DIR / f"{name}.schema.json"
    if not path.is_file():
        raise AssertionError(
            f"published schema {path} is missing; schema conformance cannot be "
            "checked and MUST NOT be skipped (canonical spec section 14)"
        )
    with open(path) as f:
        return json.load(f)


def schema_enum_at(schema: dict, *path: str) -> list:
    """Read the ``enum`` list at a keyword path inside a loaded schema.

    Raises rather than returning a default when the path is absent. A missing path
    means the schema moved the enum, and a test that quietly skipped at that point
    would restore exactly the blind spot section 14 exists to close: the SDK would
    keep whatever values it had while nothing compared them to anything.
    """
    node: object = schema
    for index, key in enumerate(path):
        if not isinstance(node, dict) or key not in node:
            raise AssertionError(
                f"schema path {'.'.join(path)} is missing at segment "
                f"{key!r} (position {index}); the published enum moved or was "
                "renamed, so this SDK's native enum is no longer being compared "
                "to anything (canonical spec section 14)"
            )
        node = node[key]

    if not isinstance(node, list) or not node:
        raise AssertionError(
            f"schema path {'.'.join(path)} is not a non-empty enum list: {node!r}"
        )
    return node
