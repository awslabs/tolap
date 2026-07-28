"""Cross-SDK adversarial / edge-case scenarios for the openFDA wrapper.

Cases live in fixtures/integration-scenarios/openfda-edge-cases.json. Same
runner shape as test_openfda_scenarios.py but with assertion shapes for
deeper checks: nested-array masking propagation, response-shape preservation,
pattern matching on masked values, minimum result counts.
"""

from __future__ import annotations

import re

import pytest

from tolap_mcp.http_wrapper import SecureHttpToolWrapper
from tolap_mcp.options import SecureMcpServerOptions

from ._scenarios import load_scenarios, policy_from_dict, sign_policy


SCENARIOS = load_scenarios("openfda-edge-cases.json")["scenarios"]

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


def _walk(node, parts):
    cursor = node
    for p in parts:
        if not isinstance(cursor, dict) or p not in cursor:
            return None
        cursor = cursor[p]
    return cursor


def _walk_collect(node, parts):
    """Walk a path that may pass through arrays; return all leaves found."""
    if not parts:
        return [node]
    if isinstance(node, list):
        out = []
        for item in node:
            out.extend(_walk_collect(item, parts))
        return out
    if not isinstance(node, dict):
        return []
    head, *rest = parts
    if head not in node:
        return []
    return _walk_collect(node[head], rest)


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s["name"])
def test_openfda_edge_case(scenario, wrapper, openfda_signing_key) -> None:
    ctx = sign_policy(policy_from_dict(scenario["policy"]), openfda_signing_key)
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


def _assert_pass(body, expected, request) -> None:
    cp = request.get("collectionPath")

    if "rowCount" in expected:
        coll = _walk(body, cp.split(".")) if cp else None
        assert isinstance(coll, list)
        assert len(coll) == expected["rowCount"]

    if "minResultsCount" in expected:
        coll = _walk(body, cp.split(".")) if cp else None
        assert isinstance(coll, list)
        assert len(coll) >= expected["minResultsCount"]

    if "hiddenField" in expected:
        spec = expected["hiddenField"]
        coll = _walk(body, spec["collectionPath"].split("."))
        assert coll is not None, "collection must exist"
        for row in coll:
            leaf = _walk_collect(row, spec["field"].split("."))
            assert not leaf, f"hidden field {spec['field']} must not appear, got {leaf}"

    if "everyArrayElementMasked" in expected:
        spec = expected["everyArrayElementMasked"]
        arrays = _walk_collect(body, spec["arrayPath"].split("."))
        assert arrays, f"no arrays found at {spec['arrayPath']}"
        masked_count = 0
        for arr in arrays:
            assert isinstance(arr, list)
            for item in arr:
                if isinstance(item, dict) and spec["field"] in item:
                    assert item[spec["field"]] == spec["expectedValue"], (
                        f"element {item} not masked"
                    )
                    masked_count += 1
        assert masked_count > 0, "at least one element should have been masked"

    if "everyArrayElementMatchesPattern" in expected:
        spec = expected["everyArrayElementMatchesPattern"]
        rx = re.compile(spec["pattern"])
        items = _walk_collect(body, spec["arrayPath"].split("."))
        # items here is the collection itself (e.g. results array). Walk into
        # each row and find spec.field.
        if len(items) == 1 and isinstance(items[0], list):
            items = items[0]
        for row in items:
            value = _walk(row, spec["field"].split("."))
            if value is None:
                if spec.get("allowMissing"):
                    continue
                raise AssertionError(f"missing value at {spec['field']} in {row}")
            assert rx.fullmatch(str(value)), f"{value!r} does not match {spec['pattern']}"

    if "responseShape" in expected:
        spec = expected["responseShape"]
        if "topLevelKeys" in spec:
            assert isinstance(body, dict)
            actual = sorted(body.keys())
            wanted = sorted(spec["topLevelKeys"])
            for k in wanted:
                assert k in actual, f"top-level key {k} missing; got {actual}"
        if "minResultsCount" in spec and cp:
            coll = _walk(body, cp.split("."))
            assert isinstance(coll, list)
            assert len(coll) >= spec["minResultsCount"]
        if "metaMustContainKeys" in spec:
            meta = body.get("meta")
            assert isinstance(meta, dict), "meta must remain a dict"
            for k in spec["metaMustContainKeys"]:
                assert k in meta, f"meta lost key {k}"
