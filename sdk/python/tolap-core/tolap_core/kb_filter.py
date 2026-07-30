"""Provider-side metadata filters for ``kb`` sources (connector-spec section 7).

**What this is for.** ``tag_rules`` is the whole knowledge-base confidentiality control --
a classification level *is* a tag (section 7). Post-retrieval, :func:`filter_by_tags`
enforces it on returned chunks. This module additionally emits a **provider-native filter**
so denied chunks are never retrieved in the first place, which section 7 puts "on the same
footing as SQL rewriting, never a replacement for the post pass".

That framing is the entire safety argument, so it is worth being explicit about why the
pushdown is *structurally* weaker than the post pass rather than merely redundant:

- Post-retrieval extraction reads tags from ``tags``, ``Tags``, ``labels``,
  ``classification`` and ``metadata.tags`` -- **at any depth**, matched with the same
  bidirectional case-insensitive glob matcher masking uses. A provider filter cannot
  express that. It filters on one concrete indexed metadata field, named up front.
- A chunk tagged ``secret`` under a key the provider does not index, or nested where the
  provider cannot reach, is invisible to the filter and caught only by the post pass.

So a filter that matches nothing is **useless, not unsafe** -- the post pass still runs and
still drops the chunk. The failure this module must avoid is the opposite one: emitting a
filter that causes the provider to return *more* than it should while something downstream
mistakenly treats the pushdown as sufficient. Two rules follow, and every renderer obeys
them:

1. **Never emit a filter broader than the rule it came from.** When a rule cannot be
   expressed exactly, it is reported as unpushed instead of approximated.
2. **Always report what was not pushed** (:attr:`KbFilterResult.unpushed_rules`), so a
   caller can never conclude "the provider filtered everything" from a partial filter.

Semantics preserved from :func:`filter_by_tags`:

===========================  ===============================================  ==========
Rule                         Meaning                                          Pushed?
===========================  ===============================================  ==========
``denied_tags: [a, b]``      drop chunks carrying any; **keep untagged**       yes
``denied_tags: []``          denies nothing                                   nothing to push
``allowed_tags: [a, b]``     keep only chunks carrying one; **drop untagged**  yes
``allowed_tags: []``         denies **everything**                            no -- reported
both                         denied wins                                      both, ANDed
===========================  ===============================================  ==========

The ``allowed_tags: []`` case most invites a mistake. It means deny-all, and there is no
metadata predicate meaning "match no document" that is portable across the six supported
providers -- an empty ``in`` list is variously an error, a no-op, or a match-nothing
depending on the engine. Rendering it as a no-op would be a fail-open, so it is refused:
:func:`build_kb_filter` returns ``denies_everything=True`` and no filter, and the caller
should skip retrieval altogether.

Mirrors ``kb-filter.ts`` and ``KbFilter.cs``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Sequence

from tolap_core.models import EffectivePolicy, TagRules

DEFAULT_KB_METADATA_KEYS: tuple[str, ...] = ("tags", "labels", "classification")
"""The metadata keys a provider filter may be built against.

Deliberately **not** the same list as post-retrieval extraction's, and deliberately
caller-overridable. Extraction's key set is fixed and unconfigurable because it decides what
counts as security metadata, and an unsigned knob must not influence a confidentiality
decision. This one is different in kind: it names which field the *provider* happens to
index, which is deployment knowledge the SDK cannot infer, and getting it wrong makes the
filter match nothing -- costing efficiency, never access.
"""


class KbFilterOp(str, Enum):
    """How a rule is combined into the provider filter."""

    in_ = "in"
    """Metadata value equals one of the listed values."""

    not_in = "notIn"
    """Metadata value equals none of the listed values."""


@dataclass(frozen=True)
class KbFilterClause:
    """One clause: a metadata key tested against tag values.

    Values are lower-cased, matching the case-insensitive comparison
    :func:`filter_by_tags` performs. Note the limitation this implies: a provider whose own
    matching is case-*sensitive* will fail to exclude a chunk tagged ``Secret`` when the
    clause says ``secret``. That is a pushdown miss, caught by the post pass -- and it is
    why :attr:`KbFilterResult.case_sensitivity_caveat` says so out loud rather than leaving
    an integrator to assume the provider did the whole job.
    """

    key: str
    op: KbFilterOp
    values: tuple[str, ...]


@dataclass(frozen=True)
class UnpushedRule:
    """A rule that could not be expressed as a provider filter, and why."""

    rule: str
    reason: str


@dataclass
class KbFilterResult:
    """A provider-neutral filter plus an honest account of its limits."""

    clauses: list[KbFilterClause] = field(default_factory=list)
    """Clauses to combine with AND. Empty means nothing could be pushed."""

    denies_everything: bool = False
    """True when the policy denies every chunk (``allowed_tags: []``).

    No filter can express this portably, so the caller MUST skip retrieval rather than treat
    empty :attr:`clauses` as "no restriction".
    """

    unpushed_rules: list[UnpushedRule] = field(default_factory=list)
    """Rules not represented in :attr:`clauses`.

    Non-empty means the provider will return chunks the post pass still has to discard.
    Never let a non-empty list be read as "filtered at the source".
    """

    case_sensitivity_caveat: bool = False
    """True whenever clauses were emitted.

    A standing reminder that tag comparison is case-insensitive in TOLAP but may not be in
    the provider, and that the provider sees only the configured keys at the depth it
    indexes them. The post pass remains normative.
    """


def _normalize(values: Sequence[str]) -> tuple[str, ...]:
    # Lower-cased, de-duplicated and sorted, matching filter_by_tags' comparison. Sorted so
    # the same policy renders byte-identically in all three SDKs -- the shared fixture
    # compares rendered output, and an unstable order would fail for the wrong reason.
    return tuple(sorted({value.lower() for value in values}))


def _unpushed_for(tag_rules: TagRules, reason: str) -> list[UnpushedRule]:
    out: list[UnpushedRule] = []
    if tag_rules.denied_tags:
        out.append(UnpushedRule(rule="deniedTags", reason=reason))
    if tag_rules.allowed_tags is not None:
        out.append(UnpushedRule(rule="allowedTags", reason=reason))
    return out


def build_kb_filter(
    policy: EffectivePolicy,
    metadata_keys: Sequence[str] | None = None,
) -> KbFilterResult:
    """Build a provider-neutral metadata filter from a policy's ``tag_rules`` (section 7).

    Returns clauses to AND together, plus what could not be pushed. A caller that ignores
    :attr:`KbFilterResult.unpushed_rules` still gets correct enforcement -- the post pass is
    unconditional -- but loses the ability to tell whether the provider did any of the work.
    """
    tag_rules = policy.object_rules.tag_rules if policy.object_rules else None
    if tag_rules is None:
        return KbFilterResult()

    keys = tuple(metadata_keys) if metadata_keys is not None else DEFAULT_KB_METADATA_KEYS
    if not keys:
        # No key to filter on. Reported rather than silently returning "no restriction".
        return KbFilterResult(
            unpushed_rules=_unpushed_for(
                tag_rules, "no metadata keys were supplied to filter on"
            )
        )

    clauses: list[KbFilterClause] = []
    unpushed: list[UnpushedRule] = []

    # Denied first, mirroring filter_by_tags' precedence. A denylist is the well-behaved
    # case: "value not in [...]" excludes exactly the denied tags and leaves an untagged
    # chunk alone, which is what the post pass does.
    if tag_rules.denied_tags:
        denied = _normalize(tag_rules.denied_tags)
        for key in keys:
            clauses.append(KbFilterClause(key=key, op=KbFilterOp.not_in, values=denied))
    # An empty denied_tags denies nothing: nothing to push, nothing unpushed.

    if tag_rules.allowed_tags is not None:
        if len(tag_rules.allowed_tags) == 0:
            # Deny-all. Not expressible portably (see the module docstring), and rendering
            # it as a no-op would be a fail-open, so it is refused loudly instead.
            return KbFilterResult(
                clauses=[],
                denies_everything=True,
                unpushed_rules=[
                    UnpushedRule(
                        rule="allowedTags",
                        reason=(
                            "an empty allowedTags denies every chunk; no portable metadata "
                            "filter expresses match-nothing, so skip retrieval entirely"
                        ),
                    )
                ],
            )

        # A positive match on ONE key only. This is the constraint that makes multi-key
        # allow-lists unpushable: the post pass admits a chunk tagged `public` under EITHER
        # `tags` OR `classification`, which is a disjunction across keys. ANDing a positive
        # clause per key would instead demand the tag be present under *every* key and drop
        # chunks the policy allows -- narrower than the policy, which is a correctness bug
        # even though it errs "safe". Emitting a single-key clause is exact when there is
        # one key; with several, the rule is reported unpushed rather than approximated in
        # either direction.
        if len(keys) == 1:
            clauses.append(
                KbFilterClause(
                    key=keys[0],
                    op=KbFilterOp.in_,
                    values=_normalize(tag_rules.allowed_tags),
                )
            )
        else:
            unpushed.append(
                UnpushedRule(
                    rule="allowedTags",
                    reason=(
                        "an allow-list spans multiple metadata keys as a disjunction; "
                        "ANDing per key would drop permitted chunks, so it is left to the "
                        "post pass"
                    ),
                )
            )

    return KbFilterResult(
        clauses=clauses,
        denies_everything=False,
        unpushed_rules=unpushed,
        case_sensitivity_caveat=bool(clauses),
    )
