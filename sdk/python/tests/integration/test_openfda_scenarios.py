"""Cross-SDK openFDA API scenarios, executed by the Python SDK.

Cases are loaded from fixtures/integration-scenarios/openfda-api-enforcement.json.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from tolap_mcp.http_wrapper import SecureHttpToolWrapper
from tolap_mcp.options import SecureMcpServerOptions

from ._scenarios import (
    load_scenarios,
    policy_from_dict,
    sign_policy,
)


_DOC = load_scenarios("openfda-api-enforcement.json")
BASE_POLICY = _DOC["basePolicy"]
SCENARIOS = _DOC["scenarios"]

OPENFDA_FIXTURES = Path(__file__).parents[4] / "fixtures" / "api" / "openfda"

# In live mode we hit api.fda.gov; we MUST pass the same ?limit param the
# recordings used or the live response will have a different row order/count
# than the on-disk recording the masking assertions cross-reference.
LIVE_PARAMS_BY_PATH = {
    "/drug/event.json": {"limit": 3},
    "/drug/label.json": {"limit": 3},
    "/food/enforcement.json": {"limit": 2},
}


@pytest.fixture
def wrapper(openfda_replay_client, openfda_signing_key) -> SecureHttpToolWrapper:
    return SecureHttpToolWrapper(
        SecureMcpServerOptions(signing_key=openfda_signing_key),
        openfda_replay_client,
    )


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s["name"])
def test_openfda_scenario(scenario, wrapper, openfda_signing_key) -> None:
    ctx = sign_policy(policy_from_dict(BASE_POLICY), openfda_signing_key)
    request = scenario["request"]
    expected = scenario["expected"]

    params = LIVE_PARAMS_BY_PATH.get(request["path"])

    if not expected["pass"]:
        with pytest.raises(PermissionError, match=expected["errorContains"]):
            wrapper.request(
                ctx,
                request["method"],
                request["path"],
                params=params,
                collection_path=request.get("collectionPath"),
            )
        return

    body = wrapper.request(
        ctx,
        request["method"],
        request["path"],
        params=params,
        collection_path=request.get("collectionPath"),
    )
    _assert_pass(body, expected, request)


def _walk(node, parts):
    cursor = node
    for p in parts:
        if not isinstance(cursor, dict) or p not in cursor:
            return None
        cursor = cursor[p]
    return cursor


def _assert_pass(body, expected, request) -> None:
    collection_path = request.get("collectionPath")
    rows = _walk(body, collection_path.split(".")) if collection_path else None

    if "rowCount" in expected:
        assert isinstance(rows, list), f"expected list at {collection_path}, got {type(rows)}"
        assert len(rows) == expected["rowCount"]

    if "maskedField" in expected:
        spec = expected["maskedField"]
        cp = spec["collectionPath"]
        field_path = spec["field"].split(".")
        coll = _walk(body, cp.split("."))
        # Pull original recordings by index to recover the unmasked value.
        recording = json.loads(_recording_for(request).read_text())
        original_rows = _walk(recording, cp.split("."))
        for actual_row, raw_row in zip(coll, original_rows[: len(coll)], strict=True):
            actual_value = _walk(actual_row, field_path)
            original_value = _walk(raw_row, field_path)
            _assert_mask(actual_value, original_value, spec["mask"])

    if "hiddenField" in expected:
        spec = expected["hiddenField"]
        cp = spec["collectionPath"]
        field_path = spec["field"].split(".")
        coll = _walk(body, cp.split("."))
        for row in coll:
            assert _walk(row, field_path) is None, (
                f"hidden field {spec['field']} must not appear, got {row}"
            )


def _recording_for(request: dict) -> Path:
    # Map the path back to the recording filename. Mirrors OPENFDA_ROUTES in conftest.
    path = request["path"]
    name_map = {
        "/drug/event.json": "drug_event_limit3.json",
        "/drug/label.json": "drug_label_limit3.json",
        "/food/enforcement.json": "food_enforcement_limit2.json",
    }
    return OPENFDA_FIXTURES / name_map[path]


def _assert_mask(actual, original, mask: str) -> None:
    if mask == "sha256-16":
        assert actual == hashlib.sha256(str(original).encode()).hexdigest()[:16]
    elif mask == "redacted":
        assert actual == "[REDACTED]"
    else:
        raise AssertionError(f"unknown mask kind: {mask}")
