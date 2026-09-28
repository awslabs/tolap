"""A tool can declare its result already enforced (issue #33).

``hash`` masking is not idempotent: when a data layer has already run the result
pipeline, running it again in ``execute_with_enforcement`` hashes every hashed field a
second time. A tool opts out by returning :class:`EnforcedResult`, bound to the signed
context's signature. The wrapper honours the marker only on an exact, constant-time
match, and still re-applies the idempotent steps (hidden-field strip, allowed-field
projection, maxResults) as a backstop. Every other marker falls back to the full
pipeline.

The shared cases live in ``fixtures/enforcement/already-enforced-results.json`` so the
TypeScript and .NET SDKs are held to the same results.
"""

from __future__ import annotations

import copy
import dataclasses
import logging
from datetime import timedelta
from typing import Any

import pytest

from conftest import load_fixture
from tolap_core.context import build_security_context, sign_context
from tolap_core.enforced_result import EnforcedResult
from tolap_core.enforcement import apply_result_pipeline
from tolap_core.history import ToolCallHistory
from tolap_core.models import SecurityContext
from tolap_core.serialization import deserialize_effective_policy
from tolap_mcp.options import SecureMcpServerOptions
from tolap_mcp.wrapper import SecureMcpToolWrapper

FIXTURE = load_fixture("enforcement/already-enforced-results.json")
KEY = FIXTURE["signingKey"]
POLICY_A = FIXTURE["cases"][0]["policy"]
SIGNATURE_PLACEHOLDER = "$CONTEXT_SIGNATURE"


def _context(policy_json: dict, who: dict | None = None, *, jti: str | None = None) -> SecurityContext:
    who = who or FIXTURE["context"]
    policy = deserialize_effective_policy(policy_json)
    context = build_security_context(
        user_id=who["userId"],
        tenant_id=who["tenantId"],
        policies=[policy],
        ttl=timedelta(hours=1),
        jti=jti,
    )
    return sign_context(context, KEY)


def _tampered(signature: str) -> str:
    return signature[:-1] + ("0" if signature[-1] != "0" else "1")


def _substitute(node: Any, signature: str) -> Any:
    if isinstance(node, str):
        return signature if node == SIGNATURE_PLACEHOLDER else node
    if isinstance(node, list):
        return [_substitute(item, signature) for item in node]
    if isinstance(node, dict):
        return {key: _substitute(value, signature) for key, value in node.items()}
    return node


def _tool_result(case: dict, context: SecurityContext) -> Any:
    data = _substitute(copy.deepcopy(case["data"]), context.signature or "")
    marker = case["marker"]
    if marker is None:
        return data
    if marker == "context":
        return EnforcedResult.for_context(data, context)
    if marker == "otherContext":
        other = _context(case["policy"], FIXTURE["otherContext"])
        assert other.signature != context.signature
        return EnforcedResult.for_context(data, other)
    if marker == "tampered":
        return EnforcedResult(data=data, context_signature=_tampered(context.signature or ""))
    if marker == "empty":
        return EnforcedResult(data=data, context_signature="")
    raise AssertionError(f"unknown marker kind {marker!r}")


def _wrapper(**overrides: Any) -> SecureMcpToolWrapper:
    return SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=KEY, **overrides))


def _run(wrapper: SecureMcpToolWrapper, context: SecurityContext, result: Any) -> Any:
    return wrapper.execute_with_enforcement(
        context=context, tool_name="orm-query", tool_fn=lambda: result, tool_args={}
    )


@pytest.mark.parametrize("case", FIXTURE["cases"], ids=[c["name"] for c in FIXTURE["cases"]])
def test_shared_fixture(case: dict) -> None:
    context = _context(case["policy"])
    result = _tool_result(case, context)

    if case.get("expectDenied"):
        with pytest.raises(PermissionError):
            _run(_wrapper(), context, result)
        return

    assert _run(_wrapper(), context, result) == case["expected"]


class TestTheMarkerIsBoundToTheExactContext:
    def test_a_matching_marker_is_not_hashed_twice(self) -> None:
        context = _context(POLICY_A)
        once = apply_result_pipeline(
            [{"id": 1, "region": "us-east", "email": "a@example.com"}],
            context.effective_policy,
        )

        out = _run(_wrapper(), context, EnforcedResult.for_context(once, context))

        assert out == once

    def test_a_marker_from_a_context_with_the_same_policy_but_another_jti_is_not_honoured(
        self,
    ) -> None:
        # Same user, same policy, same key -- only the token identity differs. The
        # signature covers the whole envelope, so the marker does not carry over.
        context = _context(POLICY_A, jti="call-1")
        replayed_from = _context(POLICY_A, jti="call-0")
        once = apply_result_pipeline(
            [{"id": 1, "region": "us-east", "email": "a@example.com"}],
            context.effective_policy,
        )

        out = _run(_wrapper(), context, EnforcedResult.for_context(once, replayed_from))

        assert out == apply_result_pipeline(once, context.effective_policy)
        assert out != once

    def test_a_marker_is_not_honoured_when_the_context_itself_is_unsigned(self) -> None:
        # With signatures off the wrapper cannot prove the context is genuine, so a
        # marker matching the (attacker-writable) signature field proves nothing.
        context = _context(POLICY_A)
        once = apply_result_pipeline(
            [{"id": 1, "region": "us-east", "email": "a@example.com"}],
            context.effective_policy,
        )

        out = _run(
            _wrapper(enforce_signatures=False), context, EnforcedResult.for_context(once, context)
        )

        assert out == apply_result_pipeline(once, context.effective_policy)

    def test_a_marker_whose_signature_is_not_a_string_is_not_honoured(self) -> None:
        context = _context(POLICY_A)
        once = apply_result_pipeline(
            [{"id": 1, "region": "us-east", "email": "a@example.com"}],
            context.effective_policy,
        )
        marker = EnforcedResult(data=once, context_signature=None)  # type: ignore[arg-type]

        out = _run(_wrapper(), context, marker)

        assert out == apply_result_pipeline(once, context.effective_policy)

    def test_a_non_ascii_signature_is_a_mismatch_not_a_crash(self) -> None:
        # hmac.compare_digest raises TypeError on a non-ASCII str; that must not turn
        # a mismatch into an exception escaping enforcement.
        context = _context(POLICY_A)
        once = apply_result_pipeline(
            [{"id": 1, "region": "us-east", "email": "a@example.com"}],
            context.effective_policy,
        )
        marker = EnforcedResult(data=once, context_signature="é" * 64)

        out = _run(_wrapper(), context, marker)

        assert out == apply_result_pipeline(once, context.effective_policy)

    def test_a_context_re_signed_with_a_new_jti_invalidates_the_marker(
        self,
    ) -> None:
        # Bound to the signature, not to the Python object: changing the envelope and
        # re-signing yields a different signature, so the old marker no longer fits.
        context = _context(POLICY_A)
        once = apply_result_pipeline(
            [{"id": 1, "region": "us-east", "email": "a@example.com"}],
            context.effective_policy,
        )
        marker = EnforcedResult.for_context(once, context)
        context.jti = "rotated"
        sign_context(context, KEY)

        out = _run(_wrapper(), context, marker)

        assert out == apply_result_pipeline(once, context.effective_policy)

    def test_a_mismatched_marker_is_logged(self, caplog: pytest.LogCaptureFixture) -> None:
        context = _context(POLICY_A)
        marker = EnforcedResult(data=[], context_signature="not-the-signature")

        with caplog.at_level(logging.WARNING):
            _run(_wrapper(), context, marker)

        assert any("EnforcedResult" in record.getMessage() for record in caplog.records)


class TestOnlyTheTypedMarkerCounts:
    def test_a_dict_shaped_like_the_marker_is_data(self) -> None:
        context = _context(POLICY_A)
        lookalike = {
            "data": [{"id": 1, "region": "us-east", "email": "raw@example.com"}],
            "context_signature": context.signature,
        }

        # The lookalike has no region, so the region filter drops it: the raw
        # email never comes back.
        assert _run(_wrapper(), context, lookalike) is None

    def test_a_subclass_is_not_the_marker(self) -> None:
        # slots=True forbids adding fields, but subclassing is still possible; the
        # wrapper matches the exact type, so a subclass overriding behaviour is data.
        class Imposter(EnforcedResult):
            __slots__ = ()

        context = _context(POLICY_A)
        once = apply_result_pipeline(
            [{"id": 1, "region": "us-east", "email": "a@example.com"}],
            context.effective_policy,
        )

        out = _run(_wrapper(), context, Imposter(data=once, context_signature=context.signature))

        assert out == apply_result_pipeline(once, context.effective_policy)

    def test_the_marker_is_immutable(self) -> None:
        context = _context(POLICY_A)
        marker = EnforcedResult.for_context([], context)

        with pytest.raises(dataclasses.FrozenInstanceError):
            marker.context_signature = "x"  # type: ignore[misc]

    def test_the_marker_repr_does_not_leak_the_data(self) -> None:
        context = _context(POLICY_A)
        marker = EnforcedResult.for_context([{"ssn": "123-45-6789"}], context)

        assert "123-45-6789" not in repr(marker)

    def test_binding_to_an_unsigned_context_is_refused(self) -> None:
        context = build_security_context(
            user_id="u",
            tenant_id="t",
            policies=[deserialize_effective_policy(POLICY_A)],
        )

        with pytest.raises(ValueError):
            EnforcedResult.for_context([], context)


class TestNestedMarkersAreNeverHonoured:
    def test_a_marker_inside_a_list_is_unwrapped_and_fully_enforced(self) -> None:
        context = _context(POLICY_A)
        once = apply_result_pipeline(
            [{"id": 1, "region": "us-east", "email": "a@example.com"}],
            context.effective_policy,
        )
        nested = [EnforcedResult.for_context(once[0], context)]

        out = _run(_wrapper(), context, nested)

        assert out == apply_result_pipeline(once, context.effective_policy)

    def test_a_marker_inside_a_record_field_cannot_smuggle_hidden_fields(self) -> None:
        # strip_hidden_fields recurses into nested dicts, but not into an opaque
        # object. Left wrapped, the nested ssn would ride past it.
        context = _context(POLICY_A)
        record = {
            "region": "us-east",
            "patient": EnforcedResult.for_context({"ssn": "123-45-6789", "id": 7}, context),
        }

        out = _run(_wrapper(), context, record)

        assert out == {"region": "us-east", "patient": {"id": 7}}

    def test_a_marker_wrapping_a_marker_is_fully_enforced(self) -> None:
        context = _context(POLICY_A)
        once = apply_result_pipeline(
            [{"id": 1, "region": "us-east", "email": "a@example.com"}],
            context.effective_policy,
        )
        inner = EnforcedResult.for_context(once, context)
        outer = EnforcedResult.for_context(inner, context)

        out = _run(_wrapper(), context, outer)

        assert out == apply_result_pipeline(once, context.effective_policy)

    def test_an_honoured_marker_with_a_nested_marker_inside_is_fully_enforced(self) -> None:
        context = _context(POLICY_A)
        once = apply_result_pipeline(
            [{"id": 1, "region": "us-east", "email": "a@example.com"}],
            context.effective_policy,
        )
        outer = EnforcedResult.for_context(
            [once[0], EnforcedResult.for_context(once[0], context)], context
        )

        out = _run(_wrapper(), context, outer)

        assert out == apply_result_pipeline(once + once, context.effective_policy)

    def test_the_core_pipeline_unwraps_a_nested_marker(self) -> None:
        # Paths that never honour markers (the factory, any direct pipeline caller)
        # must still not pass one through opaque.
        policy = deserialize_effective_policy(POLICY_A)
        marker = EnforcedResult(data={"ssn": "1", "id": 2}, context_signature="whatever")

        out = apply_result_pipeline({"region": "us-east", "p": marker}, policy)

        assert out == {"region": "us-east", "p": {"id": 2}}

    def test_the_core_pipeline_unwraps_a_top_level_marker(self) -> None:
        policy = deserialize_effective_policy(POLICY_A)
        marker = EnforcedResult(
            data=[{"region": "us-east", "email": "a@example.com"}], context_signature="x"
        )

        out = apply_result_pipeline(marker, policy)

        assert out == apply_result_pipeline(
            [{"region": "us-east", "email": "a@example.com"}], policy
        )


class TestEveryOtherPostExecutionStepStillRuns:
    def test_history_is_recorded_for_an_honoured_marker(self) -> None:
        history = ToolCallHistory(max_size=4)
        context = _context(POLICY_A)

        _run(_wrapper(tool_call_history=history), context, EnforcedResult.for_context([], context))

        assert len(history) == 1

    def test_max_results_truncates_an_honoured_marker(self) -> None:
        context = _context(POLICY_A)
        rows = [{"id": i, "region": "us-east"} for i in range(5)]

        out = _run(_wrapper(), context, EnforcedResult.for_context(rows, context))

        assert out == rows[:2]

    def test_allowed_fields_projects_an_honoured_marker(self) -> None:
        policy = copy.deepcopy(POLICY_A)
        policy["objectRules"]["fieldRules"]["allowedFields"] = ["id"]
        context = _context(policy)

        out = _run(
            _wrapper(),
            context,
            EnforcedResult.for_context([{"id": 1, "internal": "x"}], context),
        )

        assert out == [{"id": 1}]

    def test_pre_execution_denial_still_raises_before_the_tool_runs(self) -> None:
        policy = copy.deepcopy(POLICY_A)
        policy["permissions"]["canQuery"] = False
        context = _context(policy)
        called = []

        def tool() -> EnforcedResult:
            called.append(True)
            return EnforcedResult.for_context([], context)

        with pytest.raises(PermissionError):
            _wrapper().execute_with_enforcement(
                context=context, tool_name="orm-query", tool_fn=tool, tool_args={}
            )
        assert called == []

    def test_an_unenforceable_shape_inside_an_honoured_marker_is_denied(self) -> None:
        context = _context(POLICY_A)

        with pytest.raises(PermissionError):
            _run(_wrapper(), context, EnforcedResult.for_context("a scalar", context))

    def test_an_unenforceable_shape_inside_an_honoured_marker_passes_when_opted_out(
        self,
    ) -> None:
        context = _context(POLICY_A)

        out = _run(
            _wrapper(allow_unenforceable_shapes=True),
            context,
            EnforcedResult.for_context("a scalar", context),
        )

        assert out == "a scalar"

    def test_post_execute_called_directly_honours_the_marker(self) -> None:
        context = _context(POLICY_A)
        once = apply_result_pipeline(
            [{"id": 1, "region": "us-east", "email": "a@example.com"}],
            context.effective_policy,
        )

        out = _wrapper().post_execute(context, EnforcedResult.for_context(once, context))

        assert out == once

    def test_an_unmarked_result_behaves_as_before(self) -> None:
        context = _context(POLICY_A)
        raw = [
            {"id": 1, "region": "us-east", "email": "a@example.com", "ssn": "1"},
            {"id": 2, "region": "eu-west", "email": "b@example.com"},
        ]

        out = _run(_wrapper(), context, copy.deepcopy(raw))

        assert out == apply_result_pipeline(raw, context.effective_policy)
