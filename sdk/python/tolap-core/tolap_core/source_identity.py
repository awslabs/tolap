"""Source identity -- parsing ``category:namespace:name`` (connector-spec section 1).

Every data source is identified by exactly three colon-separated segments. The first
is a fixed-set category; the other two are opaque to TOLAP.

The category matters beyond documentation: it decides which wrapper enforces a source,
and it is read from the **signed** ``source_connection_id`` rather than from a separate
registry field. That is deliberate -- a category taken from unsigned configuration
could disagree with the policy the context carries, and an attacker who could flip
``db`` to ``api`` would pick the wrapper that enforces the *other* category's rules
(``endpoint_rules`` do not constrain a SQL query). Inside the signed bytes, changing it
invalidates the signature.

Mirrors ``source-identity.ts`` and ``SourceIdentity.cs``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class SourceCategory(str, Enum):
    """The four connector categories (connector-spec section 1).

    A fixed set; adding one is a breaking change (section 10). Inherits ``str`` so a
    category compares equal to its wire form.
    """

    db = "db"
    """Relational and query-engine sources (section 5)."""

    api = "api"
    """HTTP-shaped services (section 6)."""

    kb = "kb"
    """Knowledge bases and vector stores (section 7)."""

    storage = "storage"
    """Object stores (section 8)."""


@dataclass(frozen=True)
class SourceIdentity:
    """The three parts of a source connection identifier."""

    category: SourceCategory
    namespace: str
    name: str


def parse_source_identity(source_connection_id: str | None) -> SourceIdentity | None:
    """Parse a ``category:namespace:name`` identifier, or ``None`` if it is not one.

    Returns ``None`` rather than raising so a caller can decide whether an
    unparseable identifier is a denial or a configuration error; every caller in this
    SDK treats it as a denial.

    Rejected: a wrong segment count (``db:production`` and ``db:a:b:c`` both), an
    unknown category, and an empty segment -- an empty namespace or name would let
    ``db::`` match a ``db:*:*`` pattern while naming no actual source.

    The category is compared case-insensitively and returned lower-cased, matching the
    case-insensitive ``source_patterns`` matching of enforcement spec section 10. The
    namespace and name are returned verbatim: they are opaque, and folding their case
    here would make this function lie about what the identifier says.
    """
    if not source_connection_id:
        return None

    segments = source_connection_id.split(":")
    if len(segments) != 3:
        return None
    if any(not segment for segment in segments):
        return None

    try:
        category = SourceCategory(segments[0].lower())
    except ValueError:
        return None

    return SourceIdentity(category=category, namespace=segments[1], name=segments[2])


def source_category(source_connection_id: str | None) -> SourceCategory | None:
    """The category of a source connection identifier, or ``None`` if unparseable.

    Convenience over :func:`parse_source_identity` for the common case: the wrapper a
    source needs depends only on its category.
    """
    identity = parse_source_identity(source_connection_id)
    return identity.category if identity is not None else None
