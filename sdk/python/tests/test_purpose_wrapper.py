"""Purpose-bound action validation as the wrappers actually run it (spec section 15.2).

``test_purpose_action_resolver.py`` covers the decision. This covers the wiring, which is
the part that silently does not exist if it is wrong: a resolver nobody calls passes all
its own tests. Every case here goes through ``pre_execute`` or ``request`` -- the calls an
integrator makes -- rather than through the resolver directly.

The two wrappers are keyed differently on purpose. An HTTP request has no tool name, so the
HTTP map is keyed by ``METHOD path-glob``. Testing only the MCP path would have left that
half unverified, which is how the gap was there to find in the first place.
"""

from __future__ import annotations

from datetime import timedelta

import httpx
import pytest

from tolap_core.context import build_security_context, sign_context
from tolap_core.enums import PrincipalType
from tolap_core.models import (
    DelegationHop,
    EffectivePolicy,
    EndpointRules,
    ObjectRules,
    PolicyPermissions,
    PurposeProfile,
    SecurityContext,
)
from tolap_core.purpose_action import UNDECLARED_CATEGORY_REASON
from tolap_mcp.http_wrapper import SecureHttpToolWrapper
from tolap_mcp.options import SecureMcpServerOptions
from tolap_mcp.wrapper import SecureMcpToolWrapper


KEY = "purpose-wrapper-key"
BASE = "https://purpose.test"

CONSTRAINED = PurposeProfile(
    purpose_id="campaign-x-overlap",
    description="Aggregate segment overlap only.",
    allowed_actions=["aggregate_overlap", "count_segments"],
    prohibited_actions=["export_pii"],
)

TOOL_MAP = {"segment_overlap": "aggregate_overlap", "export_csv": "export_pii"}
HTTP_MAP = {"GET /segments/*": "aggregate_overlap", "GET /export/*": "export_pii"}


def _policy(
    profile: PurposeProfile | None,
    object_rules: ObjectRules | None = None,
    *,
    can_query: bool = True,
) -> EffectivePolicy:
    return EffectivePolicy(
        version="1.0",
        user_id="purpose-user",
        tenant_id="purpose-tenant",
        source_connection_id="api:purpose:test",
        source_profiles=["purpose-wrapper"],
        permissions=PolicyPermissions(can_query=can_query, read_only=True),
        object_rules=object_rules,
        purpose_profile=profile,
    )


def _signed(policy: EffectivePolicy) -> SecurityContext:
    return sign_context(
        build_security_context(
            "purpose-user",
            "purpose-tenant",
            [policy],
            ttl=timedelta(hours=1),
            declared_purpose=(
                policy.purpose_profile.purpose_id if policy.purpose_profile else None
            ),
        ),
        KEY,
    )


def _all_get() -> EndpointRules:
    return EndpointRules(allowed_endpoints=["/*"], allowed_methods=["GET"])


class TestTheMcpWrapper:
    def _wrapper(self, tool_map: dict[str, str] | None) -> SecureMcpToolWrapper:
        return SecureMcpToolWrapper(
            SecureMcpServerOptions(signing_key=KEY, tool_action_categories=tool_map)
        )

    def test_a_prohibited_tool_is_denied(self) -> None:
        result = self._wrapper(TOOL_MAP).pre_execute(
            _signed(_policy(CONSTRAINED)), "export_csv"
        )

        assert result.allowed is False
        assert result.reason == (
            "action 'export_pii' is prohibited under purpose 'campaign-x-overlap'"
        )

    def test_a_permitted_tool_is_allowed(self) -> None:
        # The paired control. Without it, a wrapper that denied every call would satisfy the
        # case above and look correct.
        result = self._wrapper(TOOL_MAP).pre_execute(
            _signed(_policy(CONSTRAINED)), "segment_overlap"
        )

        assert result.allowed is True

    def test_an_unmapped_tool_is_denied_under_a_constraining_purpose(self) -> None:
        result = self._wrapper(TOOL_MAP).pre_execute(
            _signed(_policy(CONSTRAINED)), "some_other_tool"
        )

        assert result.reason == UNDECLARED_CATEGORY_REASON

    def test_no_map_configured_denies_every_call_under_a_constraining_purpose(self) -> None:
        # The deployment mistake worth failing loudly on: a purpose-bound policy reaches a
        # wrapper whose operator never classified the tools. Denying everything is noisy and
        # obvious; allowing everything would look like the feature working.
        result = self._wrapper(None).pre_execute(
            _signed(_policy(CONSTRAINED)), "segment_overlap"
        )

        assert result.reason == UNDECLARED_CATEGORY_REASON

    @pytest.mark.parametrize("configured", [True, False], ids=["with-map", "without-map"])
    def test_a_purpose_agnostic_policy_is_unaffected_by_the_map(self, configured: bool) -> None:
        # The backward-compatibility guarantee at the wrapper boundary: an existing
        # deployment with no purposes behaves identically whether or not a map is configured.
        agnostic = _signed(_policy(None))

        result = self._wrapper(TOOL_MAP if configured else None).pre_execute(
            agnostic, "export_csv"
        )

        assert result.allowed is True

    def test_the_action_is_checked_before_the_object_rules(self) -> None:
        # Both would deny. "This action does not serve the declared purpose" is the more
        # useful answer, and the ordering is asserted rather than left to whichever check
        # happens to run first after a refactor.
        policy = _policy(CONSTRAINED, ObjectRules(hidden_objects=["customer_segments"]))

        result = self._wrapper(TOOL_MAP).pre_execute(
            _signed(policy), "export_csv", object_name="customer_segments"
        )

        assert result.reason == (
            "action 'export_pii' is prohibited under purpose 'campaign-x-overlap'"
        )

    def test_the_object_rules_still_apply_when_the_action_is_permitted(self) -> None:
        """The paired control: the action check must not shadow the object check."""
        policy = _policy(CONSTRAINED, ObjectRules(hidden_objects=["customer_segments"]))

        result = self._wrapper(TOOL_MAP).pre_execute(
            _signed(policy), "segment_overlap", object_name="customer_segments"
        )

        assert result.reason == "object is hidden"

    def test_can_query_is_checked_before_the_action(self) -> None:
        # The other side of the ordering. A policy granting no reads should say so rather
        # than complain about a category, because the category is not the problem.
        no_reads = _policy(CONSTRAINED, can_query=False)

        result = self._wrapper(TOOL_MAP).pre_execute(_signed(no_reads), "export_csv")

        assert result.reason == "query not permitted"

    def test_the_allowed_tools_gate_is_checked_before_the_action(self) -> None:
        """A tool the wrapper does not serve at all is not an action-category problem."""
        wrapper = SecureMcpToolWrapper(
            SecureMcpServerOptions(
                signing_key=KEY,
                allowed_tools=["segment_overlap"],
                tool_action_categories=TOOL_MAP,
            )
        )

        result = wrapper.pre_execute(_signed(_policy(CONSTRAINED)), "export_csv")

        assert result.reason == "tool not in allowed list"

    def test_the_context_signature_is_checked_before_the_action(self) -> None:
        # A tampered context must report tampering. Reaching the action check first would let
        # an attacker learn which categories a forged policy permits.
        tampered = _signed(_policy(CONSTRAINED))
        tampered.declared_purpose = "fraud-detection"

        result = self._wrapper(TOOL_MAP).pre_execute(tampered, "segment_overlap")

        assert result.reason == "invalid signature"

    def test_execute_with_enforcement_raises_on_a_prohibited_action(self) -> None:
        """The other public entry point, so the check is not only on the pre_execute path."""
        wrapper = self._wrapper(TOOL_MAP)

        with pytest.raises(PermissionError, match="is prohibited under purpose"):
            wrapper.execute_with_enforcement(
                _signed(_policy(CONSTRAINED)),
                "export_csv",
                lambda: [{"id": 1}],
                {},
            )

    def test_execute_with_enforcement_runs_a_permitted_action(self) -> None:
        wrapper = self._wrapper(TOOL_MAP)

        rows = wrapper.execute_with_enforcement(
            _signed(_policy(CONSTRAINED)),
            "segment_overlap",
            lambda: [{"id": 1}],
            {},
        )

        assert rows == [{"id": 1}]


class _Handler:
    """A transport that answers 200 with a fixed body, optionally redirecting once."""

    def __init__(self, redirect_to: str | None = None) -> None:
        self._redirect_to = redirect_to
        self._redirected = False

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if self._redirect_to is not None and not self._redirected:
            self._redirected = True
            return httpx.Response(307, headers={"location": self._redirect_to})
        return httpx.Response(200, json={"count": 3})


class TestTheHttpWrapper:
    def _wrapper(
        self, http_map: dict[str, str] | None, redirect_to: str | None = None
    ) -> SecureHttpToolWrapper:
        client = httpx.Client(
            base_url=BASE, transport=httpx.MockTransport(_Handler(redirect_to))
        )
        return SecureHttpToolWrapper(
            SecureMcpServerOptions(signing_key=KEY, http_action_categories=http_map), client
        )

    def test_a_prohibited_path_is_denied(self) -> None:
        wrapper = self._wrapper(HTTP_MAP)
        context = _signed(_policy(CONSTRAINED, ObjectRules(endpoint_rules=_all_get())))

        with pytest.raises(PermissionError) as caught:
            wrapper.request(context, "GET", "/export/all.csv")

        assert "action 'export_pii' is prohibited under purpose 'campaign-x-overlap'" in str(
            caught.value
        )

    def test_a_permitted_path_succeeds(self) -> None:
        # The paired control, and the case that proves the HTTP map is consulted at all
        # rather than the wrapper simply refusing everything once a purpose is present.
        wrapper = self._wrapper(HTTP_MAP)
        context = _signed(_policy(CONSTRAINED, ObjectRules(endpoint_rules=_all_get())))

        body = wrapper.request(context, "GET", "/segments/overlap")

        assert body == {"count": 3}

    def test_an_unmapped_path_is_denied_under_a_constraining_purpose(self) -> None:
        wrapper = self._wrapper(HTTP_MAP)
        context = _signed(_policy(CONSTRAINED, ObjectRules(endpoint_rules=_all_get())))

        with pytest.raises(PermissionError, match=UNDECLARED_CATEGORY_REASON):
            wrapper.request(context, "GET", "/reports/monthly")

    def test_no_map_configured_denies_every_call_under_a_constraining_purpose(self) -> None:
        wrapper = self._wrapper(None)
        context = _signed(_policy(CONSTRAINED, ObjectRules(endpoint_rules=_all_get())))

        with pytest.raises(PermissionError, match=UNDECLARED_CATEGORY_REASON):
            wrapper.request(context, "GET", "/segments/overlap")

    @pytest.mark.parametrize("configured", [True, False], ids=["with-map", "without-map"])
    def test_a_purpose_agnostic_policy_is_unaffected(self, configured: bool) -> None:
        wrapper = self._wrapper(HTTP_MAP if configured else None)
        context = _signed(_policy(None, ObjectRules(endpoint_rules=_all_get())))

        body = wrapper.request(context, "GET", "/export/all.csv")

        assert body == {"count": 3}

    def test_the_category_is_checked_on_a_redirect_target(self) -> None:
        # The case that makes per-hop checking worth its complexity: the request that leaves
        # is an allowed aggregate, and the location it is sent to is an export. Checking only
        # the original request would let a redirect launder a prohibited action.
        wrapper = self._wrapper(HTTP_MAP, redirect_to="/export/all.csv")
        context = _signed(_policy(CONSTRAINED, ObjectRules(endpoint_rules=_all_get())))

        with pytest.raises(PermissionError) as caught:
            wrapper.request(context, "GET", "/segments/overlap")

        assert "action 'export_pii' is prohibited" in str(caught.value)
        assert "redirect target rejected" in str(caught.value)

    def test_a_redirect_to_a_permitted_path_still_succeeds(self) -> None:
        # Paired with the case above: per-hop checking must not refuse every redirect.
        permissive = dict(HTTP_MAP, **{"GET /counts/*": "count_segments"})
        wrapper = self._wrapper(permissive, redirect_to="/counts/segments")
        context = _signed(_policy(CONSTRAINED, ObjectRules(endpoint_rules=_all_get())))

        body = wrapper.request(context, "GET", "/segments/overlap")

        assert body == {"count": 3}

    def test_the_category_is_matched_with_the_query_string_stripped(self) -> None:
        # A category must not be dodged by appending a query, and equally must not be missed
        # because one was present. Matched on the same path the endpoint rules see.
        wrapper = self._wrapper(HTTP_MAP)
        context = _signed(_policy(CONSTRAINED, ObjectRules(endpoint_rules=_all_get())))

        with pytest.raises(PermissionError, match="action 'export_pii' is prohibited"):
            wrapper.request(context, "GET", "/export/all.csv?format=json")

    def test_a_permitted_path_with_a_query_string_still_succeeds(self) -> None:
        """The paired direction: stripping the query must not break a legitimate match."""
        wrapper = self._wrapper(HTTP_MAP)
        context = _signed(_policy(CONSTRAINED, ObjectRules(endpoint_rules=_all_get())))

        body = wrapper.request(context, "GET", "/segments/overlap?limit=5")

        assert body == {"count": 3}

    def test_the_action_is_checked_before_the_endpoint_rules(self) -> None:
        # Both deny. The action answer names what the agent tried to do; "endpoint is hidden"
        # names only where.
        policy = _policy(
            CONSTRAINED,
            ObjectRules(
                endpoint_rules=EndpointRules(
                    allowed_endpoints=["/*"],
                    hidden_endpoints=["/export/*"],
                    allowed_methods=["GET"],
                )
            ),
        )
        wrapper = self._wrapper(HTTP_MAP)

        with pytest.raises(PermissionError, match="action 'export_pii' is prohibited"):
            wrapper.request(_signed(policy), "GET", "/export/all.csv")

    def test_the_endpoint_rules_still_apply_when_the_action_is_permitted(self) -> None:
        """The paired control: the action check must not shadow the endpoint check."""
        policy = _policy(
            CONSTRAINED,
            ObjectRules(
                endpoint_rules=EndpointRules(
                    allowed_endpoints=["/*"],
                    hidden_endpoints=["/segments/*"],
                    allowed_methods=["GET"],
                )
            ),
        )
        wrapper = self._wrapper(HTTP_MAP)

        with pytest.raises(PermissionError, match="endpoint is hidden"):
            wrapper.request(_signed(policy), "GET", "/segments/overlap")

    def test_the_request_path_shape_is_checked_before_the_action(self) -> None:
        """A protocol-relative target is not a path, so no category applies to it."""
        wrapper = self._wrapper(HTTP_MAP)
        context = _signed(_policy(CONSTRAINED, ObjectRules(endpoint_rules=_all_get())))

        with pytest.raises(PermissionError, match="protocol-relative"):
            wrapper.request(context, "GET", "//evil.example/segments/overlap")

    def test_can_query_is_checked_before_the_action(self) -> None:
        wrapper = self._wrapper(HTTP_MAP)
        context = _signed(
            _policy(CONSTRAINED, ObjectRules(endpoint_rules=_all_get()), can_query=False)
        )

        with pytest.raises(PermissionError, match="query not permitted"):
            wrapper.request(context, "GET", "/export/all.csv")


class TestTheFactoryForwardsEveryOption:
    """A factory-built wrapper must be configured exactly like a hand-built one.

    In .NET and TypeScript the factory carried its own options record, and neither category
    map was on it -- so a factory-built wrapper denied every call under an
    action-constraining purpose, while the same wrapper constructed directly worked. Python
    is a different shape (one ``SecureMcpServerOptions`` for the factory and both wrappers),
    so it does not have that bug; these tests assert that rather than assuming it, because
    the failure is silent in one direction and total in the other.

    Asserted **reflectively** -- by identity, and by sweeping the dataclass's own fields --
    rather than against a hand-written list of option names. A hand-written list goes stale
    in the same commit as the code it is supposed to check.
    """

    def test_both_wrappers_receive_the_very_same_options_object(self) -> None:
        """The strongest form of the claim: nothing is copied, so nothing can be dropped."""
        options = SecureMcpServerOptions(
            signing_key=KEY,
            hash_salt="pepper",
            tool_action_categories=TOOL_MAP,
            http_action_categories=HTTP_MAP,
        )
        from tolap_mcp.factory import SecureToolFactory

        client = httpx.Client(base_url=BASE, transport=httpx.MockTransport(_Handler()))
        factory = SecureToolFactory(options, client)

        assert factory.create_record_tool()._options is options
        assert factory.create_http_tool()._options is options

    def test_every_declared_option_reaches_both_wrappers_with_its_value(self) -> None:
        """The sweep, over ``dataclasses.fields`` so a new option is covered on the day it
        is added rather than on the day someone remembers to extend a list."""
        import dataclasses

        from tolap_mcp.factory import SecureToolFactory

        from tolap_core.enums import SigningAlgorithm

        options = SecureMcpServerOptions(
            signing_key=KEY,
            signing_algorithm=SigningAlgorithm.hmac_sha512,
            enforce_signatures=False,
            enforce_expiry=False,
            allowed_tools=["segment_overlap"],
            hash_salt="pepper",
            allow_unenforceable_shapes=True,
            tool_action_categories=TOOL_MAP,
            http_action_categories=HTTP_MAP,
        )
        # Every field set to something distinguishable from its default, or a dropped option
        # would still compare equal.
        defaults = SecureMcpServerOptions(signing_key=KEY)
        for declared in dataclasses.fields(options):
            if declared.name == "signing_key":
                continue
            assert getattr(options, declared.name) != getattr(defaults, declared.name), (
                f"{declared.name} is at its default, so forwarding it cannot be observed"
            )

        client = httpx.Client(base_url=BASE, transport=httpx.MockTransport(_Handler()))
        factory = SecureToolFactory(options, client)

        for wrapper in (factory.create_record_tool(), factory.create_http_tool()):
            for declared in dataclasses.fields(options):
                assert getattr(wrapper._options, declared.name) == getattr(
                    options, declared.name
                ), f"{type(wrapper).__name__} lost {declared.name}"

    def test_the_hash_salt_reaches_a_factory_built_wrapper(self) -> None:
        """Asserted behaviourally as well, because this one fails *silently*.

        A dropped salt produces a plain digest where a keyed HMAC was configured: the call
        succeeds, the field looks masked, and every pseudonym is brute-forceable over a
        low-entropy input. Nothing in a response shape would show it, so the check has to be
        on the value.
        """
        from tolap_core.enums import MaskType
        from tolap_core.models import FieldRules, MaskingRule
        from tolap_mcp.factory import SecureToolFactory

        rules = ObjectRules(
            field_rules=FieldRules(
                masked_fields=[MaskingRule(field="ssn", mask_type=MaskType.hash)]
            )
        )
        policy = _policy(None, rules)
        policy.source_connection_id = "db:marketing:customer_segments"
        context = _signed(policy)

        salted = SecureToolFactory(
            SecureMcpServerOptions(signing_key=KEY, hash_salt="pepper")
        ).create_tool(context)
        unsalted = SecureToolFactory(
            SecureMcpServerOptions(signing_key=KEY)
        ).create_tool(context)

        row = [{"ssn": "111-22-3333"}]
        salted_digest = salted.post_execute(context, row)[0]["ssn"]
        unsalted_digest = unsalted.post_execute(context, row)[0]["ssn"]

        assert salted_digest != "111-22-3333", "the paired control: masking happened at all"
        assert salted_digest != unsalted_digest, (
            "the salt reached the wrapper; equal digests would mean it was dropped"
        )

    def test_a_record_tool_from_the_factory_enforces_the_tool_map(self) -> None:
        from tolap_mcp.factory import SecureToolFactory

        factory = SecureToolFactory(
            SecureMcpServerOptions(signing_key=KEY, tool_action_categories=TOOL_MAP)
        )
        policy = _policy(CONSTRAINED)
        policy.source_connection_id = "db:marketing:customer_segments"

        tool = factory.create_tool(_signed(policy))

        assert tool.pre_execute(_signed(policy), "export_csv").reason == (
            "action 'export_pii' is prohibited under purpose 'campaign-x-overlap'"
        )
        assert tool.pre_execute(_signed(policy), "segment_overlap").allowed is True

    def test_an_http_tool_from_the_factory_enforces_the_http_map(self) -> None:
        from tolap_mcp.factory import SecureToolFactory

        client = httpx.Client(base_url=BASE, transport=httpx.MockTransport(_Handler()))
        factory = SecureToolFactory(
            SecureMcpServerOptions(signing_key=KEY, http_action_categories=HTTP_MAP), client
        )
        policy = _policy(CONSTRAINED, ObjectRules(endpoint_rules=_all_get()))
        context = _signed(policy)

        tool = factory.create_tool(context)

        with pytest.raises(PermissionError, match="action 'export_pii' is prohibited"):
            tool.request(context, "GET", "/export/all.csv")
        assert tool.request(context, "GET", "/segments/overlap") == {"count": 3}


class TestTheDelegationChainIsCheckedNotMerelyCarried:
    """The chain is validated on the consuming side, in both wrappers (section 15.3).

    Through the wrappers, not the validator: a validator nobody calls passes all of its own
    tests while enforcing nothing (testing-antipatterns.md section 4). What is asserted here
    is that a context carrying a widened hop is actually refused at the point a call is made.
    """

    WIDENING = [
        DelegationHop(
            principal_id="analyst@example.test",
            principal_type=PrincipalType.user,
            declared_purpose="campaign-x",
        ),
        DelegationHop(
            principal_id="agent-1",
            principal_type=PrincipalType.agent,
            declared_purpose="campaign-xyz-evil",
        ),
    ]

    NARROWING = [
        DelegationHop(
            principal_id="analyst@example.test",
            principal_type=PrincipalType.user,
            declared_purpose="campaign-x",
        ),
        DelegationHop(
            principal_id="agent-1",
            principal_type=PrincipalType.agent,
            declared_purpose="campaign-x-overlap",
        ),
    ]

    def _context(
        self,
        chain: list[DelegationHop] | None,
        object_rules: ObjectRules | None = None,
    ) -> SecurityContext:
        return sign_context(
            build_security_context(
                "purpose-user",
                "purpose-tenant",
                [_policy(None, object_rules)],
                ttl=timedelta(hours=1),
                delegation_chain=chain,
            ),
            KEY,
        )

    def _mcp(self) -> SecureMcpToolWrapper:
        return SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=KEY))

    def test_a_widening_chain_is_denied(self) -> None:
        result = self._mcp().validate_security_context(self._context(self.WIDENING))

        assert result.allowed is False
        assert result.reason == (
            "delegation hop 1 purpose 'campaign-xyz-evil' "
            "is not within parent scope 'campaign-x'"
        )

    def test_a_narrowing_chain_is_allowed(self) -> None:
        # The paired control: a wrapper that rejected every chain would satisfy the case above.
        assert (
            self._mcp().validate_security_context(self._context(self.NARROWING)).allowed
            is True
        )

    def test_no_chain_is_allowed(self) -> None:
        # Backward compatibility as a test rather than a comment: every context issued before
        # this feature carries no chain, and none of them may start failing.
        assert self._mcp().validate_security_context(self._context(None)).allowed is True

    def test_pre_execute_denies_a_widening_chain(self) -> None:
        # Through the call an integrator actually makes, not just the validator they may forget.
        assert (
            self._mcp()
            .pre_execute(self._context(self.WIDENING), "segment_overlap")
            .allowed
            is False
        )

    def test_the_signature_is_checked_before_the_chain(self) -> None:
        # The ordering is the whole reason chain validation is worth doing. Validating an
        # unsigned chain checks the attacker's own arithmetic: anyone who can rewrite a hop can
        # rewrite it into something consistent. So a context with both a bad signature and a
        # widening chain must report the signature.
        tampered = self._context(self.NARROWING)
        tampered.delegation_chain = self.WIDENING

        assert (
            self._mcp().validate_security_context(tampered).reason == "invalid signature"
        )

    def test_the_http_wrapper_denies_a_widening_chain(self) -> None:
        # The HTTP wrapper validates contexts through its own path, so a fix applied only to
        # the MCP wrapper would leave ``api`` sources unguarded.
        client = httpx.Client(base_url=BASE, transport=httpx.MockTransport(_Handler()))
        wrapper = SecureHttpToolWrapper(SecureMcpServerOptions(signing_key=KEY), client)
        context = self._context(self.WIDENING, ObjectRules(endpoint_rules=_all_get()))

        with pytest.raises(PermissionError, match="is not within parent scope"):
            wrapper.request(context, "GET", "/segments/overlap")

    def test_the_http_wrapper_allows_a_narrowing_chain(self) -> None:
        client = httpx.Client(base_url=BASE, transport=httpx.MockTransport(_Handler()))
        wrapper = SecureHttpToolWrapper(SecureMcpServerOptions(signing_key=KEY), client)
        context = self._context(self.NARROWING, ObjectRules(endpoint_rules=_all_get()))

        assert wrapper.request(context, "GET", "/segments/overlap") == {"count": 3}
