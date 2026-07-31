"""Regression tests for merge widening defects.

Both defects here made merging *less* restrictive than either input policy,
which is the opposite of what a most-restrictive-wins merge must do.
"""

from __future__ import annotations

import pytest

from tolap_core.enforcement import validate_access, validate_endpoint, validate_field_access
from tolap_core.merger import merge
from tolap_core.models import (
    EndpointRules,
    FieldRules,
    ObjectRules,
    PolicyDefinition,
    PolicyPermissions,
    TagRules,
)
from tolap_core.enforcement import filter_by_tags


def _policy(name: str, *, permissions: PolicyPermissions | None = None, object_rules: ObjectRules | None = None) -> PolicyDefinition:
    return PolicyDefinition(
        version="1.0",
        name=name,
        permissions=permissions or PolicyPermissions(can_query=True),
        object_rules=object_rules,
    )


class TestDisjointAllowListsDeny:
    """Defect 3: [] was falsy, so the whole rules object was discarded.

    Intersecting two disjoint allow-lists yields [], the most restrictive
    possible outcome. Treating [] as "no rules" converted it into no
    restriction at all, so an object neither policy mentioned became readable.
    """

    def test_disjoint_allowed_objects_deny_everything(self) -> None:
        merged = merge([
            _policy("a", object_rules=ObjectRules(allowed_objects=["public_table"])),
            _policy("b", object_rules=ObjectRules(allowed_objects=["other_table"])),
        ])

        assert merged.object_rules is not None, "rules object was discarded, granting unrestricted access"
        assert merged.object_rules.allowed_objects == []

        # The proven escalation: a table neither policy allowed.
        result = validate_access("secret_patients_table", merged)
        assert result.allowed is False
        assert result.reason == "object not in allowed set"

    def test_disjoint_allowed_objects_deny_even_the_originally_allowed_ones(self) -> None:
        merged = merge([
            _policy("a", object_rules=ObjectRules(allowed_objects=["public_table"])),
            _policy("b", object_rules=ObjectRules(allowed_objects=["other_table"])),
        ])

        assert validate_access("public_table", merged).allowed is False
        assert validate_access("other_table", merged).allowed is False

    def test_disjoint_allowed_fields_deny_everything(self) -> None:
        merged = merge([
            _policy("a", object_rules=ObjectRules(field_rules=FieldRules(allowed_fields=["name"]))),
            _policy("b", object_rules=ObjectRules(field_rules=FieldRules(allowed_fields=["region"]))),
        ])

        assert merged.object_rules is not None
        assert merged.object_rules.field_rules is not None
        assert merged.object_rules.field_rules.allowed_fields == []

        result = validate_field_access(["name", "region", "ssn"], merged)
        assert result.allowed == []
        assert sorted(result.denied) == ["name", "region", "ssn"]

    def test_disjoint_allowed_endpoints_deny_everything(self) -> None:
        merged = merge([
            _policy("a", object_rules=ObjectRules(endpoint_rules=EndpointRules(allowed_endpoints=["/drug/*"]))),
            _policy("b", object_rules=ObjectRules(endpoint_rules=EndpointRules(allowed_endpoints=["/food/*"]))),
        ])

        assert merged.object_rules is not None
        assert merged.object_rules.endpoint_rules is not None
        assert merged.object_rules.endpoint_rules.allowed_endpoints == []

        result = validate_endpoint("/drug/event.json", "GET", merged)
        assert result.allowed is False
        assert result.reason == "endpoint not in allowed set"

    def test_disjoint_allowed_tags_deny_everything(self) -> None:
        merged = merge([
            _policy("a", object_rules=ObjectRules(tag_rules=TagRules(allowed_tags=["public"]))),
            _policy("b", object_rules=ObjectRules(tag_rules=TagRules(allowed_tags=["internal"]))),
        ])

        assert merged.object_rules is not None
        assert merged.object_rules.tag_rules is not None
        assert merged.object_rules.tag_rules.allowed_tags == []

        docs = [{"id": "d1", "tags": ["public"]}, {"id": "d2", "tags": ["internal"]}]
        assert filter_by_tags(docs, merged) == []

    def test_disjoint_allowed_methods_deny_everything(self) -> None:
        merged = merge([
            _policy("a", object_rules=ObjectRules(endpoint_rules=EndpointRules(allowed_methods=["GET"]))),
            _policy("b", object_rules=ObjectRules(endpoint_rules=EndpointRules(allowed_methods=["POST"]))),
        ])

        assert merged.object_rules is not None
        assert merged.object_rules.endpoint_rules is not None
        assert merged.object_rules.endpoint_rules.allowed_methods == []
        assert validate_endpoint("/anything", "GET", merged).allowed is False

    def test_absent_allow_lists_remain_unrestricted(self) -> None:
        """None must stay None: an unrestricted policy is not a deny-all one."""
        merged = merge([_policy("a"), _policy("b")])

        assert merged.object_rules is None
        assert validate_access("anything", merged).allowed is True


class TestPermissionMergeDefaults:
    """Defect 4: absent flags were excluded from the fold instead of defaulted."""

    def test_absent_read_only_defaults_to_true_before_folding(self) -> None:
        """Policy A silent on read_only + B read_only=False must yield True."""
        merged = merge([
            _policy("a", permissions=PolicyPermissions(can_query=True)),
            _policy("b", permissions=PolicyPermissions(can_query=True, read_only=False)),
        ])

        assert merged.permissions.read_only is True, "writes were allowed by a policy that never granted them"

    def test_all_policies_silent_yields_schema_defaults(self) -> None:
        merged = merge([_policy("a"), _policy("b")])

        assert merged.permissions.can_query is True
        assert merged.permissions.read_only is True

    def test_read_only_false_everywhere_stays_false(self) -> None:
        merged = merge([
            _policy("a", permissions=PolicyPermissions(can_query=True, read_only=False)),
            _policy("b", permissions=PolicyPermissions(can_query=True, read_only=False)),
        ])

        assert merged.permissions.read_only is False

    def test_can_query_false_still_wins(self) -> None:
        merged = merge([
            _policy("a", permissions=PolicyPermissions(can_query=True)),
            _policy("b", permissions=PolicyPermissions(can_query=False)),
        ])

        assert merged.permissions.can_query is False
