"""Source identity parsing (connector-spec section 1).

``category:namespace:name``, where the category is one of a fixed set of four. The
parser exists because the category decides which wrapper enforces a source, and that
decision must be driven by the *signed* identifier rather than by unsigned configuration
-- a category that could be flipped from ``db`` to ``api`` would select the wrapper that
enforces the other category's rules, and ``endpoint_rules`` do not constrain a SQL query.

So the rejection cases below matter as much as the accepting ones: every one of them
yields ``None``, and every caller in this SDK treats ``None`` as a refusal to produce a
tool. A parser that guessed would guess a wrapper.

The TypeScript and .NET suites cover the same corpus (``source-identity.test.ts``,
``SourceIdentityTests.cs``).
"""

from __future__ import annotations

import pytest

from tolap_core.source_identity import (
    SourceCategory,
    SourceIdentity,
    parse_source_identity,
    source_category,
)


class TestTheFourCategories:
    @pytest.mark.parametrize(
        ("segment", "expected"),
        [
            ("db", SourceCategory.db),
            ("api", SourceCategory.api),
            ("kb", SourceCategory.kb),
            ("storage", SourceCategory.storage),
        ],
    )
    def test_accepts_each_category(
        self, segment: str, expected: SourceCategory
    ) -> None:
        assert parse_source_identity(f"{segment}:production:patients") == SourceIdentity(
            category=expected, namespace="production", name="patients"
        )

    def test_rejects_a_category_outside_the_fixed_set(self) -> None:
        # Section 1 calls the set fixed and section 10 makes adding one a breaking
        # change, so an unknown category is not a forward-compatible extension point --
        # it is a source no wrapper knows how to enforce.
        assert parse_source_identity("graph:production:people") is None
        assert parse_source_identity("DATABASE:production:patients") is None

    def test_matches_category_case_insensitively_and_lowercases_it(self) -> None:
        # Consistent with the case-insensitive source_patterns matching of enforcement
        # spec section 10: the same identifier must resolve to the same category
        # regardless of how it was cased upstream.
        parsed = parse_source_identity("DB:production:patients")
        assert parsed is not None and parsed.category is SourceCategory.db

        parsed = parse_source_identity("Api:internal:orders")
        assert parsed is not None and parsed.category is SourceCategory.api

    def test_leaves_namespace_and_name_verbatim(self) -> None:
        # Both are opaque to TOLAP (section 1). Folding their case here would make the
        # parser claim the identifier says something it does not.
        parsed = parse_source_identity("db:Production:Patient_Records")

        assert parsed is not None
        assert parsed.namespace == "Production"
        assert parsed.name == "Patient_Records"


class TestExactlyThreeSegments:
    def test_rejects_two_segments(self) -> None:
        # The documented authoring mistake in reverse: db:production is not a source.
        assert parse_source_identity("db:production") is None

    def test_rejects_one_segment(self) -> None:
        assert parse_source_identity("db") is None

    def test_rejects_four_or_more_segments(self) -> None:
        # Not silently truncated to the first three: an identifier carrying a fourth
        # segment means something the spec does not define, and treating it as a
        # three-segment source would enforce a policy the author did not write.
        assert parse_source_identity("db:production:patients:extra") is None

    @pytest.mark.parametrize(
        "identifier",
        ["db::", "db::patients", "db:production:", ":production:patients"],
    )
    def test_rejects_an_empty_segment(self, identifier: str) -> None:
        # `db::` has three segments but names no source, and it would match a `db:*:*`
        # pattern -- so a policy scoped to that pattern would appear to govern it.
        assert parse_source_identity(identifier) is None

    def test_rejects_empty_and_none(self) -> None:
        assert parse_source_identity("") is None
        assert parse_source_identity(None) is None


class TestSourceCategoryHelper:
    def test_returns_just_the_category(self) -> None:
        assert source_category("kb:research:trials") is SourceCategory.kb

    def test_returns_none_for_anything_the_parser_rejects(self) -> None:
        assert source_category("db:production") is None
        assert source_category("nope:a:b") is None
        assert source_category(None) is None
