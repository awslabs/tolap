"""Live-network harness that re-records openFDA fixtures.

Disabled by default. Run with TOLOP_TEST_LIVE=1 to refresh recordings:

    TOLAP_TEST_LIVE=1 python3 -m pytest tests/integration/test_openfda_record.py -v

The harness hits api.fda.gov and writes the responses back into
fixtures/api/openfda/, which is what the offline replay tests read from.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import httpx
import pytest


pytestmark = pytest.mark.skipif(
    os.environ.get("TOLAP_TEST_LIVE") != "1",
    reason="Live network test; set TOLAP_TEST_LIVE=1 to enable",
)


FIXTURES_DIR = Path(__file__).parents[4] / "fixtures" / "api" / "openfda"

LIVE_CALLS = [
    ("drug_event_limit3.json", "/drug/event.json", {"limit": 3}),
    ("drug_label_limit3.json", "/drug/label.json", {"limit": 3}),
    ("food_enforcement_limit2.json", "/food/enforcement.json", {"limit": 2}),
]


@pytest.mark.parametrize("filename,path,params", LIVE_CALLS)
def test_record_live_response(filename: str, path: str, params: dict) -> None:
    with httpx.Client(
        base_url="https://api.fda.gov",
        timeout=15.0,
        headers={"User-Agent": "tolap-sdk-tests/1.0"},
    ) as client:
        response = client.get(path, params=params)

    assert response.status_code == 200, (
        f"openFDA returned {response.status_code} for {path}; "
        f"recordings cannot be refreshed right now."
    )
    body = response.json()
    assert "results" in body, f"Unexpected response shape for {path}: {sorted(body)}"
    assert len(body["results"]) == params["limit"]

    out = FIXTURES_DIR / filename
    out.write_text(json.dumps(body, indent=2))
