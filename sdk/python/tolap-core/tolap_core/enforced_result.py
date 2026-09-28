"""A tool's declaration that its result has already been policy-enforced.

Some tools enforce at the data layer -- an ORM adapter that applies the result
pipeline as it materializes rows, say. Running the pipeline again in the wrapper is
not harmless: ``hash`` masking is not idempotent, so a hashed field comes back hashed
twice, and a row filter on a field the data layer already hid fails closed and drops
every row.

Such a tool returns :class:`EnforcedResult` instead of the bare data. The marker is
bound to the signature of the signed context the pipeline was applied under, and the
wrapper honours it only when that signature matches the context of the current call
exactly (compared in constant time). Anything else -- another context, a tampered or
empty signature, an unsigned context -- is treated as though no marker were present,
and the full pipeline runs. Only ``SecureMcpToolWrapper.execute_with_enforcement``
honours a marker; every other path unwraps it and runs the full pipeline.

A marker is a type, never a dict key or a caller-supplied flag: a record with a
``data`` and a ``context_signature`` key is ordinary data, and model-controlled
arguments cannot reach a type the tool code has to construct.

What a marker is not: proof that the pipeline ran. It is a claim made by the tool
code, and the binding shows only which context the tool held when it made the claim.
Any code holding the context can build a marker over any data, and a marker stays
valid for every call made with that context for its whole TTL. An honoured marker
skips masking, so if the data layer did not really run the full pipeline under this
context's policy and hash salt, masked fields come back raw. SQL pushdown alone does
not qualify: it applies only the row filters it could express, and none of the
field-level steps.
"""

from __future__ import annotations

import hmac
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from tolap_core.models import SecurityContext


@dataclass(frozen=True, slots=True)
class EnforcedResult:
    """Tool output the data layer already ran the result pipeline over.

    Both fields are excluded from ``repr`` (and so from ``str``): logging a marker
    must not log the records it carries, nor the context signature, which is a
    credential.

    A pickle round trip yields an equal marker, which is honoured like the original:
    the marker is only as trustworthy as whatever code produced it.
    """

    data: Any = field(repr=False)
    context_signature: str = field(repr=False)

    @classmethod
    def for_context(cls, data: Any, context: SecurityContext) -> EnforcedResult:
        """Bind ``data`` to the signature of the context it was enforced under.

        Raises:
            ValueError: if the context is unsigned. An unbound marker could never be
                honoured, so building one is a mistake worth surfacing at the call
                site rather than as a silent second pass.
        """
        if not context.signature:
            raise ValueError(
                "EnforcedResult needs a signed context: the marker is bound to the "
                "context signature, and an unsigned context has none"
            )
        return cls(data=data, context_signature=context.signature)


def is_bound_to(marker: EnforcedResult, context: SecurityContext) -> bool:
    """Whether ``marker`` names exactly the signature ``context`` carries.

    Constant time over the signature bytes. Compared as UTF-8 bytes rather than
    ``str`` because ``hmac.compare_digest`` raises on a non-ASCII ``str``, and a
    mismatch must be ``False``, never an exception escaping enforcement.

    This proves only that the two strings match. The caller must separately have
    verified the context signature, or the match proves nothing: an unverified
    signature field is whatever the sender wrote.
    """
    expected = context.signature
    presented = marker.context_signature
    if not isinstance(expected, str) or not isinstance(presented, str) or not expected:
        return False
    return hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))


def contains_enforced_result(node: Any) -> bool:
    """Whether an ``EnforcedResult`` appears in a tree of mappings, lists and tuples.

    Only those containers are walked. A marker inside a ``set``, a dataclass or
    another custom object is not found.
    """
    if isinstance(node, EnforcedResult):
        return True
    if isinstance(node, Mapping):
        return any(contains_enforced_result(value) for value in node.values())
    if isinstance(node, (list, tuple)):
        return any(contains_enforced_result(item) for item in node)
    return False


def unwrap_enforced_results(node: Any) -> Any:
    """Replace every ``EnforcedResult`` in a tree with the data it carries.

    Every pipeline step walks dicts and lists, and none of them looks inside an
    arbitrary object. A marker left in place would carry its data past the
    hidden-field strip and masking, so an unhonoured marker is unwrapped before
    enforcement and its contents are enforced like any other data. Containers are
    rebuilt only when a marker was found beneath them, so unmarked data keeps its
    exact types. Walks mappings, lists and tuples only, like
    :func:`contains_enforced_result`.
    """
    return _unwrap(node)[0]


def _unwrap(node: Any) -> tuple[Any, bool]:
    """One pass: the unwrapped node, and whether anything beneath it changed."""
    if isinstance(node, EnforcedResult):
        return _unwrap(node.data)[0], True
    if isinstance(node, Mapping):
        pairs = [(key, _unwrap(value)) for key, value in node.items()]
        if not any(changed for _, (_, changed) in pairs):
            return node, False
        return {key: value for key, (value, _) in pairs}, True
    if isinstance(node, (list, tuple)):
        items = [_unwrap(item) for item in node]
        if not any(changed for _, changed in items):
            return node, False
        values = [value for value, _ in items]
        return (tuple(values) if isinstance(node, tuple) else values), True
    return node, False
