"""Resolving a call's action category from wrapper configuration (spec section 15.2).

Two lookups, because the two wrapper families identify a call differently. A named tool
has a name; an HTTP request has a method and a path and nothing else. A single name-keyed
map would have left action validation permanently inert for API sources -- a control the
configuration implies and that never runs, which is worse than no control at all.

The most important behaviour here is the unclassified case: what happens to a call no map
entry covers. Both directions are asserted, because getting it wrong in either produces a
silent failure -- deny-everything looks like a broken deployment, allow-everything looks
like a working one.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from tolap_core.models import EffectivePolicy, PolicyPermissions, PurposeProfile
from tolap_core.purpose_action import (
    UNDECLARED_CATEGORY_REASON,
    validate_http_action,
    validate_tool_action,
)


def _policy(profile: PurposeProfile | None) -> EffectivePolicy:
    now = datetime.now(timezone.utc)
    return EffectivePolicy(
        version="1.0",
        user_id="user-1",
        tenant_id="tenant-1",
        source_connection_id="db:marketing:customer_segments",
        resolved_at=now.isoformat().replace("+00:00", "Z"),
        expires_at=(now + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        source_profiles=["p"],
        permissions=PolicyPermissions(can_query=True, read_only=True),
        purpose_profile=profile,
    )


CONSTRAINED = PurposeProfile(
    purpose_id="campaign-x-overlap",
    allowed_actions=["aggregate_overlap", "count_segments"],
    prohibited_actions=["export_pii"],
)

TOOL_MAP = {
    "segment_overlap": "aggregate_overlap",
    "segment_count": "count_segments",
    "export_csv": "export_pii",
}

HTTP_MAP = {
    "GET /segments/overlap": "aggregate_overlap",
    "GET /segments/count": "count_segments",
    "POST /export/*": "export_pii",
}


class TestPurposeAgnosticPoliciesAreUntouched:
    """The backward-compatibility guarantee.

    A deployment that has not configured a map, and whose policies carry no purpose, must
    behave exactly as it did before this feature -- which is why the check short-circuits
    on the profile rather than on the map.
    """

    @pytest.mark.parametrize("configured", [True, False], ids=["with-map", "without-map"])
    def test_validate_tool_action_allows_whatever_the_map_says(self, configured: bool) -> None:
        result = validate_tool_action(
            _policy(None), "export_csv", TOOL_MAP if configured else None
        )

        assert result.allowed is True
        assert result.reason is None

    @pytest.mark.parametrize("configured", [True, False], ids=["with-map", "without-map"])
    def test_validate_http_action_allows_whatever_the_map_says(self, configured: bool) -> None:
        result = validate_http_action(
            _policy(None), "POST", "/export/all.csv", HTTP_MAP if configured else None
        )

        assert result.allowed is True


class TestTheToolNameLookup:
    def test_a_mapped_and_permitted_tool_is_allowed(self) -> None:
        assert validate_tool_action(
            _policy(CONSTRAINED), "segment_overlap", TOOL_MAP
        ).allowed is True

    def test_a_mapped_and_prohibited_tool_is_denied(self) -> None:
        result = validate_tool_action(_policy(CONSTRAINED), "export_csv", TOOL_MAP)

        assert result.allowed is False
        assert result.reason == (
            "action 'export_pii' is prohibited under purpose 'campaign-x-overlap'"
        ), (
            "the reason names the category, which is what the policy forbids -- not the "
            "tool, which is a deployment detail the policy author never saw"
        )

    def test_a_mapped_tool_outside_the_allow_list_is_denied(self) -> None:
        """The other denial path, which names the allow-list rather than a prohibition."""
        profile = PurposeProfile(
            purpose_id="campaign-x-overlap", allowed_actions=["aggregate_overlap"]
        )

        result = validate_tool_action(_policy(profile), "segment_count", TOOL_MAP)

        assert result.reason == (
            "action 'count_segments' not in allowed actions for purpose 'campaign-x-overlap'"
        )

    @pytest.mark.parametrize(
        ("tool_name", "map_configured"),
        [("segment_overlap", False), ("unmapped_tool", True)],
        ids=["no-map-at-all", "tool-not-in-map"],
    )
    def test_an_unclassified_tool_is_denied_under_a_constraining_purpose(
        self, tool_name: str, map_configured: bool
    ) -> None:
        # Fail closed. A tool the administrator did not classify cannot be shown to serve
        # the purpose, and the fix is to classify it rather than to widen the policy --
        # which is why the reason is phrased as a configuration problem.
        result = validate_tool_action(
            _policy(CONSTRAINED), tool_name, TOOL_MAP if map_configured else None
        )

        assert result.allowed is False
        assert result.reason == UNDECLARED_CATEGORY_REASON

    def test_tool_name_matching_is_case_sensitive(self) -> None:
        # A tool name is an identifier, matched as allowed_tools matches it. Two casings
        # are two tools, and the fail-closed consequence is a denial rather than a
        # surprise grant.
        result = validate_tool_action(_policy(CONSTRAINED), "Segment_Overlap", TOOL_MAP)

        assert result.reason == UNDECLARED_CATEGORY_REASON

    def test_an_empty_allow_list_denies_even_a_mapped_tool(self) -> None:
        no_actions = PurposeProfile(purpose_id="campaign-x-overlap", allowed_actions=[])

        assert validate_tool_action(
            _policy(no_actions), "segment_overlap", TOOL_MAP
        ).allowed is False


class TestTheUnclassifiedRule:
    def test_an_unconstrained_purpose_allows_an_unclassified_tool(self) -> None:
        # A purpose that constrains no actions has nothing for a category to violate, so
        # an unclassified tool is not a problem. Without this, every purpose-bound policy
        # would require a complete tool map before anything worked.
        unconstrained = PurposeProfile(purpose_id="campaign-x-overlap")

        assert validate_tool_action(
            _policy(unconstrained), "unmapped_tool", TOOL_MAP
        ).allowed is True

    def test_an_empty_deny_list_does_not_make_a_call_unclassifiable(self) -> None:
        # [] on a deny-list forbids nothing, so it does not constrain actions. The mirror
        # of the allow-list rule, where [] denies everything (spec section 3) -- the two
        # arrays read in opposite directions and this is the case that pins it.
        empty_deny_list = PurposeProfile(
            purpose_id="campaign-x-overlap", prohibited_actions=[]
        )

        assert validate_tool_action(
            _policy(empty_deny_list), "unmapped_tool", TOOL_MAP
        ).allowed is True

    def test_an_empty_allow_list_does_make_a_call_unclassifiable(self) -> None:
        """The paired asymmetry: ``[]`` on the ALLOW-list is the strictest value there is."""
        empty_allow_list = PurposeProfile(purpose_id="campaign-x-overlap", allowed_actions=[])

        assert validate_tool_action(
            _policy(empty_allow_list), "unmapped_tool", TOOL_MAP
        ).reason == UNDECLARED_CATEGORY_REASON

    def test_a_prohibition_only_purpose_still_denies_an_unclassified_tool(self) -> None:
        # The less obvious half of fail-closed, and the more important one. A purpose
        # declaring only prohibited_actions means "anything but this", and an unclassified
        # tool might be exactly the thing. Permitting the unclassified while forbidding the
        # classified cannot be what the author meant.
        deny_only = PurposeProfile(
            purpose_id="campaign-x-overlap", prohibited_actions=["export_pii"]
        )

        assert validate_tool_action(
            _policy(deny_only), "unmapped_tool", TOOL_MAP
        ).reason == UNDECLARED_CATEGORY_REASON

    def test_an_empty_map_is_unclassified_rather_than_unrestricted(self) -> None:
        # An empty map is a deployment that configured nothing, not one that permitted
        # everything. Asserted separately from a None map because a truthiness check on
        # the dictionary would be the natural way to get one of these two wrong.
        empty: dict[str, str] = {}

        assert validate_tool_action(
            _policy(CONSTRAINED), "x", empty
        ).reason == UNDECLARED_CATEGORY_REASON
        assert validate_http_action(
            _policy(CONSTRAINED), "GET", "/x", empty
        ).reason == UNDECLARED_CATEGORY_REASON

    def test_the_undeclared_reason_names_the_configuration_not_the_access(self) -> None:
        # Pinned as a literal because integrators branch on it, and because the phrasing
        # is the fix: the operator needs to add the tool to the map, not widen the policy.
        assert UNDECLARED_CATEGORY_REASON == "action category not declared for tool"


class TestTheHttpLookup:
    def test_a_mapped_and_permitted_path_is_allowed(self) -> None:
        assert validate_http_action(
            _policy(CONSTRAINED), "GET", "/segments/overlap", HTTP_MAP
        ).allowed is True

    def test_a_mapped_and_prohibited_path_is_denied(self) -> None:
        result = validate_http_action(
            _policy(CONSTRAINED), "POST", "/export/all.csv", HTTP_MAP
        )

        assert result.allowed is False
        assert result.reason == (
            "action 'export_pii' is prohibited under purpose 'campaign-x-overlap'"
        )

    @pytest.mark.parametrize("method", ["get", "GET", "Get"])
    def test_method_matching_is_case_insensitive(self, method: str) -> None:
        # Matching how allowed_methods is compared. An HTTP method is a protocol token,
        # not an identifier, and a deployment should not be able to bypass a category by
        # lower-casing one.
        assert validate_http_action(
            _policy(CONSTRAINED), method, "/segments/overlap", HTTP_MAP
        ).allowed is True

    def test_a_lower_cased_key_method_matches_too(self) -> None:
        """Insensitivity applies to the map's spelling, not only the request's."""
        assert validate_http_action(
            _policy(CONSTRAINED),
            "GET",
            "/segments/overlap",
            {"get /segments/overlap": "aggregate_overlap"},
        ).allowed is True

    def test_the_method_is_part_of_the_key(self) -> None:
        # GET /export/all.csv is not covered by "POST /export/*". The path alone is not
        # the key, because reading a report and generating one are different actions.
        assert validate_http_action(
            _policy(CONSTRAINED), "GET", "/export/all.csv", HTTP_MAP
        ).reason == UNDECLARED_CATEGORY_REASON

    @pytest.mark.parametrize("path", ["/export/all.csv", "/export/nested/deep.csv"])
    def test_the_path_glob_uses_the_endpoint_dialect(self, path: str) -> None:
        # The same dialect allowedEndpoints uses, where * crosses '/'. A deployment writes
        # one kind of endpoint pattern rather than two, and a pattern that behaved
        # differently here than in allowedEndpoints would be a trap.
        assert validate_http_action(_policy(CONSTRAINED), "POST", path, HTTP_MAP).allowed is False

    @pytest.mark.parametrize(
        ("path", "map_configured"),
        [("/segments/overlap", False), ("/segments/unmapped", True)],
        ids=["no-map-at-all", "path-not-in-map"],
    )
    def test_an_unclassified_path_is_denied_under_a_constraining_purpose(
        self, path: str, map_configured: bool
    ) -> None:
        result = validate_http_action(
            _policy(CONSTRAINED), "GET", path, HTTP_MAP if map_configured else None
        )

        assert result.allowed is False
        assert result.reason == UNDECLARED_CATEGORY_REASON

    def test_an_unconstrained_purpose_allows_an_unclassified_path(self) -> None:
        assert validate_http_action(
            _policy(PurposeProfile(purpose_id="campaign-x-overlap")),
            "GET",
            "/anything",
            HTTP_MAP,
        ).allowed is True

    def test_every_matching_entry_is_validated(self) -> None:
        # Overlapping entries are not resolved by specificity. Any specificity rule can be
        # gamed by adding a broader entry, so all matches are checked and the denial wins
        # -- making the outcome independent of how the map happens to be written.
        overlapping = {
            "GET /segments/*": "aggregate_overlap",
            "GET /segments/individuals": "enumerate_individuals",
        }
        profile = PurposeProfile(
            purpose_id="campaign-x-overlap", prohibited_actions=["enumerate_individuals"]
        )

        denied = validate_http_action(
            _policy(profile), "GET", "/segments/individuals", overlapping
        )
        allowed = validate_http_action(_policy(profile), "GET", "/segments/overlap", overlapping)

        assert denied.allowed is False, (
            "the narrow entry forbids this path even though the broad entry permits it"
        )
        assert allowed.allowed is True, "the paired control: the broad entry still works"

    def test_a_denial_is_independent_of_map_ordering(self) -> None:
        # Same two entries, inserted the other way round. Dict insertion order is not a
        # security boundary, so the resolver sorts before iterating.
        profile = PurposeProfile(
            purpose_id="campaign-x-overlap", prohibited_actions=["enumerate_individuals"]
        )
        forward = {
            "GET /segments/*": "aggregate_overlap",
            "GET /segments/individuals": "enumerate_individuals",
        }
        reverse = {
            "GET /segments/individuals": "enumerate_individuals",
            "GET /segments/*": "aggregate_overlap",
        }

        assert validate_http_action(
            _policy(profile), "GET", "/segments/individuals", forward
        ) == validate_http_action(
            _policy(profile), "GET", "/segments/individuals", reverse
        )

    @pytest.mark.parametrize(
        "key",
        [
            "GET",  # no space, so no pattern
            "GET ",  # empty pattern
            " /segments/overlap",  # empty method
            "",
        ],
    )
    def test_a_malformed_key_matches_nothing(self, key: str) -> None:
        # A misconfigured key that silently matched everything would be the worst possible
        # reading of one: the map exists to narrow. Matching nothing means the request
        # falls through to the unclassified rule and is denied.
        malformed = {key: "aggregate_overlap"}

        assert validate_http_action(
            _policy(CONSTRAINED), "GET", "/segments/overlap", malformed
        ).reason == UNDECLARED_CATEGORY_REASON

    def test_a_well_formed_key_with_a_bare_glob_still_matches(self) -> None:
        """The paired control for the malformed-key theory: ``"GET *"`` is legitimate."""
        assert validate_http_action(
            _policy(CONSTRAINED), "GET", "/segments/overlap", {"GET *": "aggregate_overlap"}
        ).allowed is True
