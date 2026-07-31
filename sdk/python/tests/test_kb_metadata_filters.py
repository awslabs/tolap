"""Provider-side kb metadata filters (connector-spec section 7).

Two distinct things are asserted here, and the second matters more than the first.

**1. Cross-SDK agreement**, driven by ``fixtures/enforcement/kb-metadata-filters.json``. The
.NET and TypeScript suites read the same file case-for-case, so a divergence in how a policy
renders for a provider fails somewhere.

**2. The safety property**, which no fixture can express: a pushdown must never exclude a
chunk the policy permits. Section 7 calls a provider filter "an optimization on the same
footing as SQL rewriting, never a replacement for the post pass", and the reason it can only
ever be advisory is structural -- post-retrieval extraction reads tags recursively,
case-insensitively, from ``tags``/``Tags``/``labels``/``classification``/``metadata.tags``,
and no provider filter reproduces that. It filters one indexed field.

So the asymmetry is deliberate: a filter matching *nothing* costs efficiency and nothing
else, because the post pass is unconditional. A filter matching *too little* is a correctness
bug. The final class simulates a provider applying our clause and asserts the first never
happens.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from tolap_core.enforcement import filter_by_tags
from tolap_core.kb_filter import (
    DEFAULT_KB_METADATA_KEYS,
    KbFilterOp,
    build_kb_filter,
)
from tolap_core.kb_providers import KbProvider, render_kb_filter
from tolap_core.models import (
    EffectivePolicy,
    ObjectRules,
    PolicyPermissions,
    TagRules,
)

FIXTURE = json.loads(
    (
        Path(__file__).parents[3] / "fixtures" / "enforcement" / "kb-metadata-filters.json"
    ).read_text()
)


def _policy(tag_rules: TagRules) -> EffectivePolicy:
    return EffectivePolicy(
        version="1.0",
        user_id="u",
        tenant_id="t",
        source_connection_id="kb:research:trials",
        source_profiles=[],
        permissions=PolicyPermissions(can_query=True),
        object_rules=ObjectRules(tag_rules=tag_rules),
    )


def _tag_rules_of(case: dict[str, Any]) -> TagRules:
    """The case's tagRules, read from its embedded policy.

    The fixture stores a real policy fragment rather than a bare tagRules block so the
    shared schema-validation walk covers it like every other fixture.
    """
    raw = case["policy"].get("objectRules", {}).get("tagRules", {})
    return TagRules(
        allowed_tags=raw.get("allowedTags"),
        denied_tags=raw.get("deniedTags"),
    )


# ---------------------------------------------------------------------------
# The shared corpus
# ---------------------------------------------------------------------------


class TestSharedCorpus:
    def test_the_corpus_carries_the_expected_case_count(self) -> None:
        # A case dropped from the fixture is coverage lost silently.
        assert len(FIXTURE["cases"]) == 7

    @pytest.mark.parametrize(
        "case", FIXTURE["cases"], ids=lambda c: c["name"] if isinstance(c, dict) else ""
    )
    def test_neutral_clauses_and_flags_match(self, case: dict[str, Any]) -> None:
        result = build_kb_filter(
            _policy(_tag_rules_of(case)), metadata_keys=case["metadataKeys"]
        )
        expected = case["expected"]

        assert [
            {"key": c.key, "op": c.op.value, "values": list(c.values)}
            for c in result.clauses
        ] == expected["clauses"], case["note"]
        assert result.denies_everything == expected["deniesEverything"], case["note"]
        assert [r.rule for r in result.unpushed_rules] == expected["unpushedRules"], case[
            "note"
        ]

    @pytest.mark.parametrize(
        "case", FIXTURE["cases"], ids=lambda c: c["name"] if isinstance(c, dict) else ""
    )
    def test_renders_identically_for_every_provider(self, case: dict[str, Any]) -> None:
        result = build_kb_filter(
            _policy(_tag_rules_of(case)), metadata_keys=case["metadataKeys"]
        )

        for provider in KbProvider:
            rendered = render_kb_filter(
                result, provider, pgvector_column=FIXTURE["pgvectorColumn"]
            )
            assert rendered.filter == case["expected"]["rendered"][provider.value], (
                f"{case['name']} / {provider.value}"
            )


# ---------------------------------------------------------------------------
# Deny-all must not render as "no restriction"
# ---------------------------------------------------------------------------


class TestEmptyAllowListDeniesEverything:
    def test_exploit_empty_allowed_tags_is_not_a_noop_filter(self) -> None:
        # The fail-open this guards. `allowed_tags: []` denies every chunk (spec section 3),
        # and no portable metadata predicate means match-nothing. Emitting an empty filter
        # and retrieving anyway would return everything, so the flag is the contract.
        result = build_kb_filter(_policy(TagRules(allowed_tags=[])))

        assert result.denies_everything is True
        assert result.clauses == []
        assert len(result.unpushed_rules) == 1

        for provider in KbProvider:
            rendered = render_kb_filter(result, provider)
            assert rendered.filter is None
            assert rendered.denies_everything is True

    def test_is_distinguishable_from_nothing_to_push(self) -> None:
        # An empty denied_tags also yields no clauses, but denies nothing. The two must not
        # be conflated: one means skip retrieval, the other means retrieve unfiltered.
        result = build_kb_filter(_policy(TagRules(denied_tags=[])))

        assert result.clauses == []
        assert result.denies_everything is False


# ---------------------------------------------------------------------------
# Normalization keeps the three SDKs byte-identical
# ---------------------------------------------------------------------------


class TestNormalization:
    def test_lower_cases_values(self) -> None:
        result = build_kb_filter(
            _policy(TagRules(denied_tags=["SECRET", "Restricted"])),
            metadata_keys=["classification"],
        )

        assert result.clauses[0].values == ("restricted", "secret")

    def test_deduplicates_and_sorts(self) -> None:
        # Unstable ordering would make the shared fixture fail for the wrong reason -- a
        # difference in iteration order rather than in semantics.
        result = build_kb_filter(
            _policy(TagRules(denied_tags=["b", "a", "B", "a"])),
            metadata_keys=["classification"],
        )

        assert result.clauses[0].values == ("a", "b")

    def test_defaults_to_the_documented_keys(self) -> None:
        result = build_kb_filter(_policy(TagRules(denied_tags=["secret"])))

        assert tuple(c.key for c in result.clauses) == DEFAULT_KB_METADATA_KEYS

    def test_no_tag_rules_yields_nothing(self) -> None:
        policy = _policy(TagRules())
        policy.object_rules.tag_rules = None

        result = build_kb_filter(policy)

        assert result.clauses == []
        assert result.denies_everything is False
        assert result.unpushed_rules == []

    def test_empty_metadata_keys_pushes_nothing_and_says_so(self) -> None:
        result = build_kb_filter(
            _policy(TagRules(denied_tags=["secret"])), metadata_keys=[]
        )

        assert result.clauses == []
        assert [r.rule for r in result.unpushed_rules] == ["deniedTags"]


# ---------------------------------------------------------------------------
# Renderers refuse what they cannot express
# ---------------------------------------------------------------------------


class TestRenderersRefuseRatherThanMangle:
    def test_azure_refuses_a_comma(self) -> None:
        # `search.in` is comma-delimited, so a comma inside a value would silently change
        # which set matches. Refusing yields an unpushed rule; the post pass still enforces.
        result = build_kb_filter(
            _policy(TagRules(denied_tags=["a,b"])), metadata_keys=["classification"]
        )
        rendered = render_kb_filter(result, KbProvider.azure_ai_search)

        assert rendered.filter is None
        assert len(rendered.unpushed_rules) > 0

    def test_vertex_refuses_a_double_quote(self) -> None:
        result = build_kb_filter(
            _policy(TagRules(denied_tags=['a"b'])), metadata_keys=["classification"]
        )
        rendered = render_kb_filter(result, KbProvider.vertex_ai_search)

        assert rendered.filter is None
        assert len(rendered.unpushed_rules) > 0

    def test_pgvector_refuses_a_non_identifier_key(self) -> None:
        # A key is deployment configuration, not policy data. An unexpected one is refused
        # rather than quoted into a query.
        result = build_kb_filter(
            _policy(TagRules(denied_tags=["secret"])),
            metadata_keys=["tags'; DROP TABLE chunks --"],
        )

        assert render_kb_filter(result, KbProvider.pgvector).filter is None

    def test_pgvector_escapes_a_quote_in_a_value(self) -> None:
        # Tag values come from a signed policy, so they are trusted content -- but still
        # escaped, so a value cannot terminate the literal.
        result = build_kb_filter(
            _policy(TagRules(denied_tags=["o'brien"])), metadata_keys=["tags"]
        )

        assert "'o''brien'" in render_kb_filter(result, KbProvider.pgvector).filter


# ---------------------------------------------------------------------------
# THE safety property: a pushdown never excludes what the policy permits
# ---------------------------------------------------------------------------


def _simulate_provider(
    chunks: list[dict[str, Any]], clauses: list[Any]
) -> list[dict[str, Any]]:
    """Apply clauses the way a provider would: one indexed key, top level, absent key means
    no match (so a negated clause keeps the chunk)."""
    out = []
    for chunk in chunks:
        keep = True
        for clause in clauses:
            raw = chunk.get(clause.key)
            present = raw is not None
            values = [
                v.lower() for v in (raw if isinstance(raw, list) else [raw]) if isinstance(v, str)
            ]
            hit = any(v in clause.values for v in values)
            if clause.op is KbFilterOp.in_:
                if not hit:
                    keep = False
                    break
            elif present and hit:
                keep = False
                break
        if keep:
            out.append(chunk)
    return out


CHUNKS: list[dict[str, Any]] = [
    {"id": "secret-indexed", "classification": "secret"},
    {"id": "public-indexed", "classification": "public"},
    {"id": "untagged"},
    {"id": "secret-other-key", "tags": ["secret"]},
    {"id": "secret-nested", "metadata": {"tags": ["secret"]}},
    {"id": "secret-cased", "classification": "SECRET"},
]


class TestPushdownNeverOverExcludes:
    def test_denylist_keeps_everything_the_post_pass_keeps(self) -> None:
        # The property that makes a pushdown safe. If this ever fails, the provider is
        # hiding chunks the policy allows and the SDK is silently over-restricting.
        policy = _policy(TagRules(denied_tags=["secret"]))
        result = build_kb_filter(policy, metadata_keys=["classification"])

        provided = {c["id"] for c in _simulate_provider(CHUNKS, result.clauses)}
        permitted = {c["id"] for c in filter_by_tags(CHUNKS, policy)}

        assert permitted <= provided

    def test_the_provider_misses_other_keys_and_nesting(self) -> None:
        # Documents the structural weakness with evidence rather than a comment: these two
        # chunks reach the client and are dropped post-retrieval. This is why section 7
        # forbids treating the filter as a replacement.
        policy = _policy(TagRules(denied_tags=["secret"]))
        result = build_kb_filter(policy, metadata_keys=["classification"])

        provided = {c["id"] for c in _simulate_provider(CHUNKS, result.clauses)}
        assert "secret-other-key" in provided
        assert "secret-nested" in provided

        permitted = {c["id"] for c in filter_by_tags(CHUNKS, policy)}
        assert "secret-other-key" not in permitted
        assert "secret-nested" not in permitted

    def test_allowlist_keeps_everything_the_post_pass_keeps(self) -> None:
        policy = _policy(TagRules(allowed_tags=["public"]))
        result = build_kb_filter(policy, metadata_keys=["classification"])

        provided = {c["id"] for c in _simulate_provider(CHUNKS, result.clauses)}
        permitted = {c["id"] for c in filter_by_tags(CHUNKS, policy)}

        assert permitted <= provided

    def test_multi_key_allowlist_pushes_nothing_so_cannot_over_restrict(self) -> None:
        # The case the builder refuses. ANDing a positive clause per key would drop chunks
        # carrying the allowed tag under only one key -- narrower than the policy.
        policy = _policy(TagRules(allowed_tags=["public"]))
        result = build_kb_filter(policy, metadata_keys=["tags", "classification"])

        assert result.clauses == []
        assert [r.rule for r in result.unpushed_rules] == ["allowedTags"]

        permitted = [c["id"] for c in filter_by_tags(CHUNKS, policy)]
        assert permitted == ["public-indexed"]


class TestNegatedClausesAcrossProviders:
    """Every provider's negated (denylist) form, checked as a class rather than one at a time.

    Two fail-opens shipped in these renderers and both had the same shape: a negated clause that
    matches nothing **excludes** nothing, so a denylist returns every denied document while the
    allowlist arm of the same bug fails harmlessly closed. OpenSearch emitted a ``.keyword``
    sub-field the index did not have; Vertex emitted a multi-argument ``NOT ANY()`` that
    Discovery Engine does not accept.

    Both were invisible to per-provider tests that asserted the document we had chosen to emit.
    These tests assert properties of the *negated form itself*, which is the thing that keeps
    going wrong.
    """

    def test_vertex_negation_is_split_into_single_argument_any(self) -> None:
        """Discovery Engine negates only a single-argument ``ANY()``.

        ``NOT key: ANY("a", "b")`` -- what this renderer emitted -- is not a valid expression per
        Google's documented grammar, so a two-tag denylist produced a filter the service would
        reject or misapply. Nothing caught it because the renderer was ``fromGrammar`` and had
        never been sent to the service.
        """
        rendered = _render(
            TagRules(denied_tags=["secret", "restricted"]), KbProvider.vertex_ai_search
        )

        assert rendered == (
            'NOT classification: ANY("restricted") AND NOT classification: ANY("secret")'
        )
        # The invariant, independent of value ordering: no negated ANY() carries two arguments.
        for negated in re.findall(r"NOT [^:]+: ANY\(([^)]*)\)", rendered):
            assert "," not in negated, f"multi-argument NOT ANY() is invalid: {negated}"

    def test_vertex_allowlist_keeps_values_in_one_any(self) -> None:
        """The paired control: the positive form is a disjunction and MUST stay combined.

        Splitting an allowlist into ``ANY("a") AND ANY("b")`` would require a chunk to carry
        *both* tags -- narrower than the policy, and a different bug in the opposite direction.
        """
        rendered = _render(
            TagRules(allowed_tags=["public", "internal"]), KbProvider.vertex_ai_search
        )

        assert rendered == 'classification: ANY("internal", "public")'
        assert " AND " not in rendered

    def test_opensearch_negation_covers_both_field_spellings(self) -> None:
        """The other fail-open, kept here so the two are asserted side by side."""
        rendered = _render(TagRules(denied_tags=["secret"]), KbProvider.opensearch)

        keys = {
            key
            for clause in rendered["bool"]["must_not"]
            for term in clause["bool"]["should"]
            for key in term["terms"]
        }
        assert keys == {"classification", "classification.keyword"}

    def test_pgvector_negation_admits_an_untagged_row(self) -> None:
        """pgvector was audited in the same pass and found correct; this pins why.

        ``NOT (... ?| ...)`` alone would drop a row whose key is absent, because the operator
        yields NULL and ``NOT NULL`` is not true -- discarding untagged chunks a denylist
        permits. The ``IS NULL`` arm is what keeps the pushdown in step with
        ``filter_by_tags``, which keeps untagged records under ``deniedTags``.

        Deliberately NOT extended to match numeric values: tag harvesting collects only
        strings, so ``{"classification": 3}`` carries no tag and a denylist keeps it. A
        ``->>``-cast arm was tried and reverted for making the pushdown stricter than the
        normative pass -- a divergence in the other direction.
        """
        rendered = _render(TagRules(denied_tags=["secret"]), KbProvider.pgvector)

        assert "IS NULL" in rendered

    def test_azure_places_not_outside_the_lambda(self) -> None:
        """Azure rejects ``any(t: not search.in(...))`` and accepts ``not any(t: search.in(...))``.

        The invalid spelling fails loudly rather than silently, so this is a guard against a
        plausible "simplification" rather than a fix for a live bug.
        """
        rendered = _render(TagRules(denied_tags=["secret"]), KbProvider.azure_ai_search)

        assert rendered.startswith("not classification/any(t: search.in(")
        assert "any(t: not" not in rendered

    def test_every_provider_renders_a_denylist_at_all(self) -> None:
        """A renderer returning None for a plain denylist would silently push nothing down.

        Vacuity guard for the tests above: each asserts the *shape* of a rendered filter, and
        would pass trivially if the renderer had stopped producing one.
        """
        for provider in KbProvider:
            rendered = _render(TagRules(denied_tags=["secret"]), provider)
            assert rendered is not None, f"{provider.value} rendered no filter for a denylist"


def _render(tag_rules: TagRules, provider: KbProvider):
    policy = EffectivePolicy(
        version="1.0",
        user_id="u",
        tenant_id="t",
        source_profiles=["s"],
        permissions=PolicyPermissions(can_query=True),
        object_rules=ObjectRules(tag_rules=tag_rules),
    )
    result = build_kb_filter(policy, metadata_keys=["classification"])
    return render_kb_filter(result, provider).filter
