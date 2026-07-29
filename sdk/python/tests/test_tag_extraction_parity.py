"""Cross-SDK parity for tag extraction (connector spec section 7).

One record corpus, one policy set, one outcome table, asserted with identical
expected outcomes in all three SDKs. The counterparts are:

- TypeScript: ``packages/core/tests/tag-extraction-parity.test.ts``
- .NET: ``tests/Tolap.Core.Tests/TagExtractionParityTests.cs``

Tag filtering is the whole knowledge-base confidentiality control: a
classification level **is** a tag and there is no separate classification
construct, so a gap here is a disclosure rather than a cosmetic difference. The
corpus is the set of shapes real providers emit -- a lower-case ``tags`` array, a
differently-cased key, tags nested in a metadata object, an alternate key name, a
scalar instead of an array, and a tag key inside an array of chunks -- because a
literal lower-case ``tags`` lookup found exactly one of them and disclosed the
other four.

Each shape is run against five policies rather than one, so the two halves of the
control are separable: a denylist must *drop* the carrier and an allow-list must
*not admit* it, and an SDK that extracts a tag for one purpose but not the other
fails a specific cell rather than passing on average.

The corpus also pins the boundaries the fix must not move: ``categories`` is
outside the recognized key set and is therefore ordinary data (an over-broad set
fails open, because an unrelated field whose value appears in ``allowedTags``
would admit a record the allow-list would otherwise have dropped), a non-string
tag value contributes no tag, and an untagged record is dropped under an
allow-list but kept under a denylist alone.
"""

from __future__ import annotations

import pytest

from tolap_core.enforcement import filter_by_tags
from tolap_core.models import (
    EffectivePolicy,
    ObjectRules,
    PolicyPermissions,
    TagRules,
)

# The shared record corpus, keyed by case id. Identical field-for-field in all
# three SDKs.
PARITY_RECORDS: dict[str, dict] = {
    # The five shapes measured as leaking: only "tags-list" was enforced.
    "tags-list": {"tags": ["secret"]},
    "cased-key": {"Tags": ["secret"]},
    "nested-metadata": {"metadata": {"tags": ["secret"]}},
    "labels-key": {"labels": ["secret"]},
    "scalar-classification": {"classification": "secret"},
    # Further provider shapes and case variants.
    "scalar-tags": {"tags": "secret"},
    "upper-value": {"tags": ["SECRET"]},
    "cased-key-and-value": {"CLASSIFICATION": "Secret"},
    "nested-labels": {"metadata": {"labels": ["secret"]}},
    "in-array": {"chunks": [{"tags": ["secret"]}]},
    # Boundaries the fix must not move.
    "public-tag": {"tags": ["public"]},
    "untagged": {"note": "no tags at all"},
    "empty-tags": {"tags": []},
    "non-string-tags": {"tags": 42},
    "unrecognized-key": {"categories": ["secret"]},
}

# The shared policy set, keyed by policy id. Identical in all three SDKs.
PARITY_TAG_RULES: dict[str, TagRules] = {
    "deny-secret": TagRules(denied_tags=["secret"]),
    "deny-Secret-cased": TagRules(denied_tags=["Secret"]),
    "allow-public": TagRules(allowed_tags=["public"]),
    "allow-secret": TagRules(allowed_tags=["secret"]),
    "allow-public-deny-secret": TagRules(allowed_tags=["public"], denied_tags=["secret"]),
}

# (record id, policy id, kept) -- the canonical table. True means the record
# survives the filter; False means it is dropped.
PARITY_TABLE: list[tuple[str, str, bool]] = [
    # Every shape carrying "secret", under every policy. A denylist drops it, an
    # allow-list of "public" does not admit it, an allow-list of "secret" does, and
    # denied beats allowed.
    *(
        entry
        for record_id in (
            "tags-list",
            "cased-key",
            "nested-metadata",
            "labels-key",
            "scalar-classification",
            "scalar-tags",
            "upper-value",
            "cased-key-and-value",
            "nested-labels",
            "in-array",
        )
        for entry in (
            (record_id, "deny-secret", False),
            (record_id, "deny-Secret-cased", False),
            (record_id, "allow-public", False),
            (record_id, "allow-secret", True),
            (record_id, "allow-public-deny-secret", False),
        )
    ),
    # A record carrying only an allowed tag.
    ("public-tag", "deny-secret", True),
    ("public-tag", "deny-Secret-cased", True),
    ("public-tag", "allow-public", True),
    ("public-tag", "allow-secret", False),
    ("public-tag", "allow-public-deny-secret", True),
    # Untagged, and the three shapes that are equivalent to untagged: no
    # recognizable tags means dropped under an allow-list, kept under a denylist
    # (canonical spec section 4).
    *(
        entry
        for record_id in ("untagged", "empty-tags", "non-string-tags", "unrecognized-key")
        for entry in (
            (record_id, "deny-secret", True),
            (record_id, "deny-Secret-cased", True),
            (record_id, "allow-public", False),
            (record_id, "allow-secret", False),
            (record_id, "allow-public-deny-secret", False),
        )
    ),
]


def _policy(tag_rules: TagRules) -> EffectivePolicy:
    return EffectivePolicy(
        version="1.0",
        user_id="parity-user",
        tenant_id="parity-tenant",
        source_profiles=["tag-extraction-parity"],
        permissions=PolicyPermissions(can_query=True, can_export=False, read_only=True),
        object_rules=ObjectRules(tag_rules=tag_rules),
    )


@pytest.mark.parametrize(("record_id", "policy_id", "kept"), PARITY_TABLE)
def test_tag_extraction_parity(record_id: str, policy_id: str, kept: bool) -> None:
    record = PARITY_RECORDS[record_id]
    policy = _policy(PARITY_TAG_RULES[policy_id])

    filtered = filter_by_tags([record], policy)

    assert filtered == ([record] if kept else [])


def test_the_corpus_and_table_stay_in_step() -> None:
    """Every corpus record has an outcome under every policy.

    A shape silently dropped from the table would look like a passing parity run
    while enforcing nothing, which is the failure mode this file exists to catch.
    """
    covered = {(record_id, policy_id) for record_id, policy_id, _ in PARITY_TABLE}

    assert covered == {
        (record_id, policy_id)
        for record_id in PARITY_RECORDS
        for policy_id in PARITY_TAG_RULES
    }
