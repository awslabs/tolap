"""Delegation-chain narrowing (canonical-enforcement-spec.md section 15.3).

The shared fixture is the contract; the hand-written cases add what it cannot express --
that the substring hole is closed for every shape of near-miss, and that a pathological
glob denies rather than hanging.
"""

from __future__ import annotations

import time

import pytest
from conftest import load_fixture

from tolap_core.delegation import validate_delegation_chain
from tolap_core.enums import PrincipalType
from tolap_core.models import DelegationHop
from tolap_core.serialization import _deser_delegation_hop


FIXTURE = "purpose-binding/delegation-chains.json"
CASES = load_fixture(FIXTURE)["cases"]
CASES_BY_NAME = {case["name"]: case for case in CASES}


def _hop(
    principal_id: str,
    purpose: str | None = None,
    scopes: list[str] | None = None,
) -> DelegationHop:
    return DelegationHop(
        principal_id=principal_id,
        principal_type=PrincipalType.agent,
        declared_purpose=purpose,
        scope_narrowing=scopes,
    )


class TestTheSharedFixture:
    @pytest.mark.parametrize("name", sorted(CASES_BY_NAME), ids=lambda n: n)
    def test_validate_matches_the_shared_fixture(self, name: str) -> None:
        case = CASES_BY_NAME[name]
        raw_chain = case["chain"]
        # Mapped through the real deserializer rather than constructed field by field, so
        # this exercises the path an integrator's signed context actually takes.
        chain = (
            None if raw_chain is None else [_deser_delegation_hop(hop) for hop in raw_chain]
        )

        result = validate_delegation_chain(chain)

        assert result.allowed is case["expected"]["allowed"], f"case {name!r}"
        if "reason" in case["expected"]:
            assert result.reason == case["expected"]["reason"], f"case {name!r}"
        else:
            assert result.reason is None, "an allow carries no reason"

    def test_the_fixture_covers_both_outcomes(self) -> None:
        """Blocking every chain would satisfy the denial cases and prove nothing."""
        outcomes = {case["expected"]["allowed"] for case in CASES}

        assert outcomes == {True, False}

    def test_the_fixture_exercises_every_principal_type(self) -> None:
        """Otherwise a type this SDK refuses could sit unnoticed in the enum.

        ``PrincipalType`` is the one enum with no schema enum to compare against for most
        of this feature's life; the corpus is the other half of that check.
        """
        seen = {
            hop["principalType"]
            for case in CASES
            for hop in (case["chain"] or [])
        }

        assert seen == {member.value for member in PrincipalType}


class TestAbsentAndEmptyChains:
    def test_a_none_chain_is_allowed(self) -> None:
        # Absent is not suspicious: delegation is opt-in, so every context predating this
        # feature carries no chain and must keep resolving.
        assert validate_delegation_chain(None).allowed is True

    def test_an_empty_chain_is_allowed(self) -> None:
        assert validate_delegation_chain([]).allowed is True

    def test_a_single_hop_is_allowed(self) -> None:
        # No parent to widen against, so there is nothing to check -- however implausible
        # the purpose. A single hop declaring '*' is still just one hop.
        assert validate_delegation_chain([_hop("user-1", "*")]).allowed is True


class TestPurposeNarrowing:
    @pytest.mark.parametrize(
        ("parent", "child"),
        [
            # The hole a plain prefix test leaves open, in every shape it takes. Each of
            # these merely starts with the parent's characters and names an unrelated
            # purpose.
            ("campaign-x", "campaign-xyz-evil"),
            ("campaign-x", "campaign-xx"),
            ("campaign-x", "campaign-x2"),
            ("campaign", "campaigns-all"),
            ("fraud", "fraudulent-export"),
        ],
    )
    def test_a_mid_segment_extension_is_denied(self, parent: str, child: str) -> None:
        result = validate_delegation_chain([_hop("p", parent), _hop("c", child)])

        assert result.allowed is False, (
            f"{child!r} only starts with {parent!r}; it is not a narrowing of it"
        )
        assert result.reason == (
            f"delegation hop 1 purpose '{child}' is not within parent scope '{parent}'"
        )

    @pytest.mark.parametrize(
        ("parent", "child"),
        [
            # The paired direction: extension ON the boundary is the whole point of the
            # rule, so a validator that denied everything would fail here.
            ("campaign-x", "campaign-x-overlap"),
            ("campaign-x", "campaign-x-overlap-eu"),
            ("campaign", "campaign-x"),
        ],
    )
    def test_a_segment_boundary_extension_is_allowed(self, parent: str, child: str) -> None:
        assert validate_delegation_chain([_hop("p", parent), _hop("c", child)]).allowed

    @pytest.mark.parametrize(
        ("parent", "child"),
        [
            ("campaign-*", "campaign-x-overlap"),
            ("campaign-*", "campaign-x"),
            ("*", "anything-at-all"),
            ("campaign-x-*", "campaign-x-overlap"),
            # A glob with a literal tail, which the segment rule cannot express.
            ("campaign-*-eu", "campaign-x-eu"),
            # Two wildcards, so the matcher has to place an interior literal.
            ("campaign-*-*-eu", "campaign-x-overlap-eu"),
        ],
    )
    def test_a_parent_glob_admits_what_it_matches(self, parent: str, child: str) -> None:
        assert validate_delegation_chain([_hop("p", parent), _hop("c", child)]).allowed

    @pytest.mark.parametrize(
        ("parent", "child"),
        [
            ("campaign-*", "fraud-detection"),
            ("campaign-x-*", "campaign-y-overlap"),
            # The suffix is absent, so the trailing anchor fails.
            ("campaign-*-eu", "campaign-x-us"),
            # The interior literal is missing between the anchors.
            ("campaign-*overlap*-eu", "campaign-x-eu"),
            # The anchors overlap -- see TestOverlappingGlobAnchors below.
            ("campaign-*-x", "campaign-x"),
            ("campaign-*campaign-x", "campaign-x"),
        ],
    )
    def test_a_parent_glob_refuses_what_it_does_not_match(
        self, parent: str, child: str
    ) -> None:
        assert validate_delegation_chain([_hop("p", parent), _hop("c", child)]).allowed is False

    @pytest.mark.parametrize(
        ("parent", "child"),
        [
            ("campaign-x", "Campaign-X"),
            ("campaign-x", "CAMPAIGN-X-OVERLAP"),
            ("campaign-*", "Campaign-X-Overlap"),
        ],
    )
    def test_the_purpose_comparison_is_case_sensitive(self, parent: str, child: str) -> None:
        # Case-sensitive to match the purpose_id comparison at resolution, and unlike the
        # two glob helpers this borrows nothing from. Both existing helpers are
        # case-INsensitive, so a validator built on either would admit these.
        assert validate_delegation_chain([_hop("p", parent), _hop("c", child)]).allowed is False

    def test_an_exact_match_across_every_hop_is_allowed(self) -> None:
        chain = [
            _hop("user-1", "campaign-x-overlap"),
            _hop("orch-1", "campaign-x-overlap"),
            _hop("agent-1", "campaign-x-overlap"),
        ]

        assert validate_delegation_chain(chain).allowed is True

    @pytest.mark.parametrize(
        ("parent_purpose", "child_purpose"),
        [("campaign-x", None), (None, "fraud-detection"), (None, None)],
    )
    def test_a_purpose_absent_on_either_side_adds_no_constraint(
        self, parent_purpose: str | None, child_purpose: str | None
    ) -> None:
        # A hop declaring no purpose is not claiming one, so there is nothing to exceed.
        # Refusing an undeclared purpose is resolution's job (section 15.1), and doing it
        # here as well would deny every legitimate partial chain.
        chain = [_hop("p", parent_purpose), _hop("c", child_purpose)]

        assert validate_delegation_chain(chain).allowed is True

    @pytest.mark.parametrize(
        ("parent_purpose", "child_purpose"),
        [("campaign-x", ""), ("", "fraud-detection")],
    )
    def test_an_empty_purpose_string_is_treated_as_absent(
        self, parent_purpose: str, child_purpose: str
    ) -> None:
        # "" and omitted must not behave as two different declarations, matching how the
        # signing projection normalizes them.
        chain = [_hop("p", parent_purpose), _hop("c", child_purpose)]

        assert validate_delegation_chain(chain).allowed is True


class TestOverlappingGlobAnchors:
    """A pattern whose literal anchors claim the same characters must not match.

    ``campaign-*-x`` against ``campaign-x``: the prefix ``campaign-`` matches and the suffix
    ``-x`` matches, but they overlap -- the value is one character short of holding both, so
    no assignment of the wildcard covers it and the correct answer is a non-match.

    Worth its own class rather than one row in the theory above, because this is where a
    matcher that only checks its two ends goes wrong. Without the span guard the scan would
    run over a negative-width window, and on this code path a spurious match means admitting
    a delegation hop that widened its purpose -- the exact thing the chain exists to refuse.
    """

    def test_overlapping_anchors_are_a_non_match(self) -> None:
        chain = [_hop("p", "campaign-*-x"), _hop("c", "campaign-x")]

        result = validate_delegation_chain(chain)

        assert result.allowed is False
        assert result.reason == (
            "delegation hop 1 purpose 'campaign-x' is not within parent scope 'campaign-*-x'"
        )

    def test_the_same_pattern_matches_when_the_anchors_do_not_overlap(self) -> None:
        """The paired allow: the guard rejects the overlap, not every multi-anchor pattern."""
        chain = [_hop("p", "campaign-*-x"), _hop("c", "campaign-alpha-x")]

        assert validate_delegation_chain(chain).allowed is True

    def test_the_boundary_where_the_anchors_exactly_meet_matches(self) -> None:
        """``start == end`` is a zero-width wildcard, which ``*`` legitimately allows.

        Off by one here in the other direction would refuse a pattern whose wildcard matches
        the empty string, so the bound is asserted from both sides.
        """
        chain = [_hop("p", "campaign-*-x"), _hop("c", "campaign--x")]

        assert validate_delegation_chain(chain).allowed is True


class TestScopeNarrowing:
    def test_a_scope_subset_is_allowed_and_widening_is_not(self) -> None:
        narrowing = [_hop("p", scopes=["read", "aggregate"]), _hop("c", scopes=["read"])]
        widening = [_hop("p", scopes=["read"]), _hop("c", scopes=["read", "write"])]

        assert validate_delegation_chain(narrowing).allowed is True

        denied = validate_delegation_chain(widening)
        assert denied.allowed is False
        assert denied.reason == "delegation hop 1 scopes exceed parent delegation"

    def test_an_identical_scope_set_is_allowed(self) -> None:
        chain = [_hop("p", scopes=["read"]), _hop("c", scopes=["read"])]

        assert validate_delegation_chain(chain).allowed is True

    def test_an_empty_parent_scope_leaves_nothing_for_a_child_to_claim(self) -> None:
        # scope_narrowing lists the scopes still IN FORCE, not the ones removed, so an
        # empty parent set means nothing remains to pass on. Reading it the other way
        # round would make this the most permissive case rather than the strictest.
        chain = [_hop("p", scopes=[]), _hop("c", scopes=["read"])]

        assert validate_delegation_chain(chain).allowed is False

    def test_an_empty_child_scope_is_allowed(self) -> None:
        # The paired direction: a child may hold nothing. Only widening is refused.
        chain = [_hop("p", scopes=["read"]), _hop("c", scopes=[])]

        assert validate_delegation_chain(chain).allowed is True

    def test_two_empty_scope_sets_are_allowed(self) -> None:
        """[] is a subset of [], so nothing-to-nothing is not a widening."""
        chain = [_hop("p", scopes=[]), _hop("c", scopes=[])]

        assert validate_delegation_chain(chain).allowed is True

    @pytest.mark.parametrize(
        ("parent_has_scopes", "child_has_scopes"), [(True, False), (False, True)]
    )
    def test_a_scope_absent_on_either_side_adds_no_constraint(
        self, parent_has_scopes: bool, child_has_scopes: bool
    ) -> None:
        chain = [
            _hop("p", scopes=["read"] if parent_has_scopes else None),
            _hop("c", scopes=["read", "write", "admin"] if child_has_scopes else None),
        ]

        assert validate_delegation_chain(chain).allowed is True

    def test_scope_order_and_duplication_do_not_matter(self) -> None:
        """A subset comparison, not a sequence one: scopes are a set of grants."""
        chain = [
            _hop("p", scopes=["aggregate", "read"]),
            _hop("c", scopes=["read", "read", "aggregate"]),
        ]

        assert validate_delegation_chain(chain).allowed is True


class TestOrderingAndReporting:
    def test_it_denies_at_the_first_offending_hop_and_names_it(self) -> None:
        # The index is part of the reason string so an operator can find the hop.
        # Asserted on a chain where earlier hops are fine, or a validator that always
        # reported hop 1 would pass.
        chain = [
            _hop("user-1", "campaign-*"),
            _hop("orch-1", "campaign-x-*"),
            _hop("agent-1", "campaign-x-overlap"),
            _hop("agent-2", "campaign-y-export"),
        ]

        result = validate_delegation_chain(chain)

        assert result.allowed is False
        assert result.reason == (
            "delegation hop 3 purpose 'campaign-y-export' is not within parent scope "
            "'campaign-x-overlap'"
        )

    def test_purpose_is_checked_before_scope_so_the_specific_reason_wins(self) -> None:
        # Both rules are violated at the same hop. The purpose message names the
        # offending value; the scope message cannot, so purpose is reported.
        chain = [
            DelegationHop(
                principal_id="p",
                principal_type=PrincipalType.user,
                declared_purpose="campaign-x",
                scope_narrowing=["read"],
            ),
            DelegationHop(
                principal_id="c",
                principal_type=PrincipalType.agent,
                declared_purpose="fraud-detection",
                scope_narrowing=["read", "write"],
            ),
        ]

        assert "purpose" in validate_delegation_chain(chain).reason

    def test_principal_type_and_timestamps_are_ignored(self) -> None:
        # Narrowing is about purpose and scope. Whether a hop is a user, an agent or a
        # service does not change whether it widened, and neither does when it happened --
        # those fields exist for the audit trail. Pinned so a future rule keyed on
        # principal type is a deliberate change rather than a surprise.
        chain = [
            DelegationHop(
                principal_id="agent-1",
                principal_type=PrincipalType.agent,
                declared_purpose="campaign-x",
                delegated_at="2026-09-01T12:00:00Z",
            ),
            DelegationHop(
                principal_id="user-1",
                principal_type=PrincipalType.user,
                declared_purpose="campaign-x-overlap",
                delegated_at="2020-01-01T00:00:00Z",
            ),
        ]

        assert validate_delegation_chain(chain).allowed is True


class TestAPathologicalGlob:
    """Python has no regex match timeout, so the matcher must not be able to blow up.

    .NET bounds its purpose glob with a 100 ms ``Regex`` timeout and treats an expiry as
    a non-match. Python's ``re`` has no such bound, so this SDK deliberately does not use
    a regex here: the matcher locates each ``*``-separated literal once, left to right,
    and cannot backtrack at all.

    The input below is the one that matters -- a pattern of forty wildcards whose literal
    tail is ABSENT from the value. A backtracking engine explores every way the wildcards
    could split 200 characters before giving up; a pattern that merely has many wildcards
    and succeeds returns in microseconds and would leave the hazard untested.
    """

    PATTERN = "*a" * 40 + "-x"
    VALUE = "a" * 200

    # Both costs measured on this input rather than guessed, per
    # docs/testing-antipatterns.md section 6: the non-backtracking matcher refuses it in
    # 0.0008 ms, while `re.match` over the equivalent `^...$` pattern was still running
    # after 30 s. The bound below sits six orders of magnitude above the first and four
    # below the second, so it separates them instead of falling between them.
    BOUND_SECONDS = 1.0

    def test_it_denies_rather_than_raising(self) -> None:
        chain = [_hop("p", self.PATTERN), _hop("c", self.VALUE)]

        assert validate_delegation_chain(chain).allowed is False

    def test_it_answers_without_backtracking(self) -> None:
        chain = [_hop("p", self.PATTERN), _hop("c", self.VALUE)]

        started = time.perf_counter()
        validate_delegation_chain(chain)
        elapsed = time.perf_counter() - started

        assert elapsed < self.BOUND_SECONDS, (
            f"{elapsed:.3f}s to refuse a 40-wildcard pattern; a backtracking matcher "
            "would take tens of seconds, which is the regression this bound catches"
        )

    def test_the_same_pattern_still_matches_what_it_should(self) -> None:
        """The paired control: the matcher is fast because it is linear, not because it
        gave up. The value below ends in the pattern's literal tail, so it matches."""
        chain = [_hop("p", self.PATTERN), _hop("c", self.VALUE + "-x")]

        assert validate_delegation_chain(chain).allowed is True
