"""Provider renderers for ``kb`` metadata filters (connector-spec section 7).

:func:`build_kb_filter` produces provider-neutral clauses; these render them into each
provider's own filter syntax. Splitting the two keeps the semantics in one place: the
decision about *what* is safe to push (see ``kb_filter.py``) is made once, and a renderer
only translates. A renderer that cannot express a clause returns ``None``, which surfaces as
an unpushed rule rather than a silently weakened filter.

**Every renderer here is a pushdown, and the post-retrieval pass remains normative.** None
of them can reproduce TOLAP's tag extraction -- recursive, case-insensitive, across five key
shapes -- so a filter matching nothing is expected and harmless. See ``kb_filter.py`` for
why that direction is the safe one.

Only the Bedrock shape is exercised against a real service in the reference implementation;
the other five are written from each provider's published filter grammar. They are marked
accordingly, because "looks right" is not the same evidence as "observed to filter", and an
integrator deserves to know which they are relying on.

Mirrors ``kb-providers.ts`` and ``KbProviders.cs``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Sequence

from tolap_core.kb_filter import KbFilterClause, KbFilterOp, KbFilterResult, UnpushedRule


class KbProvider(str, Enum):
    """The providers a filter can be rendered for."""

    bedrock = "bedrock"
    """Amazon Bedrock Knowledge Bases ``retrievalConfiguration.filter``."""

    opensearch = "opensearch"
    """OpenSearch bool query filter clauses."""

    elasticsearch = "elasticsearch"
    """Elasticsearch -- same DSL as OpenSearch; kept distinct for intent."""

    azure_ai_search = "azureAiSearch"
    """Azure AI Search OData ``$filter``."""

    vertex_ai_search = "vertexAiSearch"
    """Vertex AI Search / Discovery Engine filter expression."""

    pgvector = "pgvector"
    """pgvector -- a SQL ``WHERE`` fragment over a metadata column."""


class KbFilterConfidence(str, Enum):
    """Whether a provider's filter has been exercised against the live service.

    Carried into :class:`RenderedKbFilter` so the distinction reaches the integrator rather
    than living only in a comment here.
    """

    verified = "verified"
    """Exercised against the real service."""

    from_grammar = "fromGrammar"
    """Written from published filter grammar; not exercised here."""


_CONFIDENCE: dict[KbProvider, KbFilterConfidence] = {
    KbProvider.bedrock: KbFilterConfidence.verified,
    KbProvider.opensearch: KbFilterConfidence.from_grammar,
    KbProvider.elasticsearch: KbFilterConfidence.from_grammar,
    KbProvider.azure_ai_search: KbFilterConfidence.from_grammar,
    KbProvider.vertex_ai_search: KbFilterConfidence.from_grammar,
    KbProvider.pgvector: KbFilterConfidence.from_grammar,
}

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass
class RenderedKbFilter:
    """A filter rendered for one provider."""

    provider: KbProvider
    filter: Any
    """The provider-native filter: a dict for Bedrock/OpenSearch, a string for OData and
    SQL. ``None`` when nothing could be rendered -- retrieve unfiltered and rely on the post
    pass."""

    denies_everything: bool
    """True when the policy denies every chunk; the caller MUST skip retrieval."""

    unpushed_rules: list[UnpushedRule]
    """Rules not represented in :attr:`filter`."""

    confidence: KbFilterConfidence


def _render_bedrock(clauses: Sequence[KbFilterClause]) -> Any:
    """Bedrock: ``{"in": {"key", "value"}}`` / ``{"notIn": ...}``, combined with ``andAll``.

    A single clause is emitted bare rather than wrapped in a one-element ``andAll``, because
    Bedrock rejects an ``andAll`` with fewer than two members.
    """
    if not clauses:
        return None

    rendered = [
        {
            ("in" if clause.op is KbFilterOp.in_ else "notIn"): {
                "key": clause.key,
                "value": list(clause.values),
            }
        }
        for clause in clauses
    ]
    return rendered[0] if len(rendered) == 1 else {"andAll": rendered}


def _render_opensearch(clauses: Sequence[KbFilterClause]) -> Any:
    """A ``bool`` query: ``terms`` under ``filter`` for a positive match, ``must_not`` for a
    negated one. ``filter`` rather than ``must`` because scoring is irrelevant to an access
    decision.

    Note ``.keyword``: a ``text``-mapped field is analyzed, and ``terms`` against an analyzed
    field matches unpredictably. The suffix assumes the conventional keyword sub-field. If a
    deployment maps its metadata differently the filter matches nothing -- the usual harmless
    miss.
    """
    if not clauses:
        return None

    positive: list[Any] = []
    negative: list[Any] = []
    for clause in clauses:
        terms = {"terms": {f"{clause.key}.keyword": list(clause.values)}}
        (positive if clause.op is KbFilterOp.in_ else negative).append(terms)

    bool_query: dict[str, Any] = {}
    if positive:
        bool_query["filter"] = positive
    if negative:
        bool_query["must_not"] = negative
    return {"bool": bool_query}


def _odata_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _render_azure(clauses: Sequence[KbFilterClause]) -> Any:
    """OData ``$filter`` over a collection: ``tags/any(t: search.in(t, '...'))``.

    ``search.in`` takes a comma-delimited list, so a tag containing a comma would corrupt the
    predicate. Rather than emit something that silently matches the wrong set, such a clause
    is refused -- ``None`` here becomes an unpushed rule.
    """
    if not clauses:
        return None

    parts: list[str] = []
    for clause in clauses:
        if any("," in value for value in clause.values):
            return None
        any_expr = f"{clause.key}/any(t: search.in(t, {_odata_literal(','.join(clause.values))}))"
        parts.append(any_expr if clause.op is KbFilterOp.in_ else f"not {any_expr}")

    return " and ".join(parts)


def _render_vertex(clauses: Sequence[KbFilterClause]) -> Any:
    """Discovery Engine expression: ``ANY("a", "b")`` / ``NOT ANY(...)``.

    A double quote inside a value would break the expression and the grammar offers no
    escape, so such a clause is refused rather than mangled.
    """
    if not clauses:
        return None

    parts: list[str] = []
    for clause in clauses:
        if any('"' in value for value in clause.values):
            return None
        values = ", ".join(f'"{value}"' for value in clause.values)
        any_expr = f"{clause.key}: ANY({values})"
        parts.append(any_expr if clause.op is KbFilterOp.in_ else f"NOT {any_expr}")

    return " AND ".join(parts)


def _sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _render_pgvector(clauses: Sequence[KbFilterClause], column: str) -> Any:
    """A ``WHERE`` fragment over a ``jsonb`` metadata column, using containment:
    ``metadata->'tags' ?| array[...]``.

    Rendered with literals rather than placeholders because the caller appends this to a
    query it owns; every value is a tag from a **signed** policy and is quote-escaped here,
    so it cannot introduce SQL the policy author did not write. Identifiers are validated
    rather than escaped, since a metadata key is deployment configuration and an unexpected
    one should be refused, not quoted into existence.
    """
    if not clauses:
        return None

    parts: list[str] = []
    for clause in clauses:
        if not _IDENTIFIER.match(clause.key):
            return None

        array = "array[" + ", ".join(_sql_literal(v) for v in clause.values) + "]"
        contains = f"{column}->'{clause.key}' ?| {array}"
        # NOT (...) alone would also drop a row whose key is absent, because the operator
        # yields NULL there and NOT NULL is not true -- that would discard untagged chunks
        # the policy permits. The IS NULL arm restores them.
        parts.append(
            contains
            if clause.op is KbFilterOp.in_
            else f"(NOT ({contains}) OR {column}->'{clause.key}' IS NULL)"
        )

    return " AND ".join(parts)


def render_kb_filter(
    result: KbFilterResult,
    provider: KbProvider,
    pgvector_column: str = "metadata",
) -> RenderedKbFilter:
    """Render a provider-neutral filter for one provider.

    A rule this provider cannot express is added to :attr:`RenderedKbFilter.unpushed_rules`
    rather than approximated, so the returned filter is never broader than the policy.
    """
    # Deny-all short-circuits: there is nothing to render, and the caller must skip
    # retrieval rather than read an absent filter as "unrestricted".
    if result.denies_everything:
        return RenderedKbFilter(
            provider=provider,
            filter=None,
            denies_everything=True,
            unpushed_rules=list(result.unpushed_rules),
            confidence=_CONFIDENCE[provider],
        )

    if provider is KbProvider.bedrock:
        rendered = _render_bedrock(result.clauses)
    elif provider in (KbProvider.opensearch, KbProvider.elasticsearch):
        rendered = _render_opensearch(result.clauses)
    elif provider is KbProvider.azure_ai_search:
        rendered = _render_azure(result.clauses)
    elif provider is KbProvider.vertex_ai_search:
        rendered = _render_vertex(result.clauses)
    else:
        rendered = _render_pgvector(result.clauses, pgvector_column)

    # A renderer that refused the clauses reports every rule it was given as unpushed: the
    # provider will return chunks the post pass has to discard, and saying so is the
    # difference between a missed optimization and a false sense of enforcement.
    unpushed = list(result.unpushed_rules)
    if rendered is None and result.clauses:
        unpushed.append(
            UnpushedRule(
                rule="deniedTags",
                reason=(
                    f"{provider.value} cannot express these tag values; "
                    "left to the post pass"
                ),
            )
        )

    return RenderedKbFilter(
        provider=provider,
        filter=rendered,
        denies_everything=False,
        unpushed_rules=unpushed,
        confidence=_CONFIDENCE[provider],
    )
