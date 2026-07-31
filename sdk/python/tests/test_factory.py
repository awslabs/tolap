"""Secure Tool Factory (architecture.md section 5).

The factory's reason for existing is that the wrapper must be the only path to a data
source (architecture.md section 4). So the tests that matter are the ones asserting it
*refuses to hand back a tool* -- a factory that returns an unenforced tool, or the wrong
category's tool, defeats the guarantee it exists to provide.

Three properties are pinned here, and the TypeScript and .NET suites pin the same ones
case-for-case (``factory.test.ts``, ``SecureToolFactoryTests.cs``):

1. **A context that fails validation yields no tool at all**, rather than a tool that
   will deny later. A caller holding a tool reasonably assumes it is usable, and a
   per-call denial is easy to misread as a transient error and retry.
2. **Dispatch follows the SIGNED category.** The category is the first segment of
   ``source_connection_id`` (connector-spec section 1), which lives inside the signed
   bytes. Were it taken from unsigned configuration, flipping ``db`` to ``api`` would
   select the wrapper enforcing the other category's rules -- and ``endpoint_rules`` do
   not constrain a SQL query.
3. **Wrappers stay stateless.** The factory does not retain the context, so one user's
   context cannot outlive its request on a shared instance and be reused for the next
   caller.
"""

from __future__ import annotations

from datetime import timedelta

import httpx
import pytest

from tolap_core.context import build_security_context, sign_context
from tolap_core.models import (
    EffectivePolicy,
    ObjectRules,
    PolicyPermissions,
    SecurityContext,
)
from tolap_core.source_identity import SourceCategory
from tolap_mcp.factory import SecureToolFactory, ToolCreationError
from tolap_mcp.http_wrapper import SecureHttpToolWrapper
from tolap_mcp.options import SecureMcpServerOptions
from tolap_mcp.wrapper import SecureMcpToolWrapper

KEY = "factory-test-key"


def _policy(
    *,
    source_connection_id: str = "db:production:patients",
    can_query: bool = True,
    object_rules: ObjectRules | None = None,
    user_id: str = "user-001",
) -> EffectivePolicy:
    return EffectivePolicy(
        version="1.0",
        user_id=user_id,
        tenant_id="tenant-001",
        source_connection_id=source_connection_id,
        source_profiles=["factory-test"],
        permissions=PolicyPermissions(can_query=can_query, read_only=True),
        object_rules=object_rules,
    )


def _signed(
    policy: EffectivePolicy | None = None,
    ttl: timedelta = timedelta(hours=1),
) -> SecurityContext:
    p = policy if policy is not None else _policy()
    return sign_context(build_security_context(p.user_id, p.tenant_id, [p], ttl=ttl), KEY)


def _client() -> httpx.Client:
    """A transport that must never be used: these tests build tools, not requests."""

    def _fail(request: httpx.Request) -> httpx.Response:  # pragma: no cover - guard
        raise AssertionError("the factory must not perform requests")

    return httpx.Client(transport=httpx.MockTransport(_fail))


def _factory(**options) -> SecureToolFactory:
    return SecureToolFactory(
        SecureMcpServerOptions(signing_key=KEY, **options), client=_client()
    )


# ---------------------------------------------------------------------------
# Dispatch on the signed category
# ---------------------------------------------------------------------------


class TestDispatchFollowsTheSignedCategory:
    @pytest.mark.parametrize(
        "source_connection_id",
        ["db:production:patients", "kb:research:trials", "storage:archive:exports"],
    )
    def test_record_shaped_categories_yield_the_record_wrapper(
        self, source_connection_id: str
    ) -> None:
        # db, kb and storage all return records and share the post-execution pipeline.
        # Which policy fields are meaningful differs, but that is decided by the policy,
        # not the wrapper type (connector-spec section 2).
        tool = _factory().create_tool(
            _signed(_policy(source_connection_id=source_connection_id))
        )

        assert isinstance(tool, SecureMcpToolWrapper)

    def test_api_yields_the_http_wrapper(self) -> None:
        tool = _factory().create_tool(
            _signed(_policy(source_connection_id="api:internal:orders"))
        )

        assert isinstance(tool, SecureHttpToolWrapper)

    def test_exploit_category_cannot_be_changed_without_breaking_the_signature(
        self,
    ) -> None:
        # The whole reason dispatch reads the signed identifier. Swapping the category
        # post-signing would otherwise pick the wrapper that enforces a different
        # category's rules -- endpoint_rules do not constrain SQL, and vice versa.
        context = _signed(_policy(source_connection_id="db:production:patients"))
        context.effective_policy.source_connection_id = "api:internal:orders"

        with pytest.raises(ToolCreationError, match="invalid signature"):
            _factory().create_tool(context)

    def test_unparseable_identifier_yields_no_tool_rather_than_a_guess(self) -> None:
        # Two segments is the documented authoring mistake. There is no safe default
        # wrapper: guessing would enforce some category's rules on a source whose
        # category is unknown.
        context = _signed(_policy(source_connection_id="db:production"))

        with pytest.raises(ToolCreationError, match="category:namespace:name"):
            _factory().create_tool(context)

    def test_category_of_reports_without_building_a_tool(self) -> None:
        context = _signed(_policy(source_connection_id="kb:research:trials"))

        assert _factory().category_of(context) is SourceCategory.kb


# ---------------------------------------------------------------------------
# A context that fails validation yields NO tool
# ---------------------------------------------------------------------------


class TestFailClosed:
    def test_exploit_a_forged_signature_yields_no_tool(self) -> None:
        context = _signed()
        context.signature = "not-the-real-signature"

        with pytest.raises(ToolCreationError, match="invalid signature"):
            _factory().create_tool(context)

    def test_exploit_tampering_with_the_policy_yields_no_tool(self) -> None:
        # Escalating read_only on a signed context is the canonical tamper case.
        context = _signed()
        context.effective_policy.permissions.read_only = False

        with pytest.raises(ToolCreationError, match="invalid signature"):
            _factory().create_tool(context)

    def test_an_expired_context_yields_no_tool(self) -> None:
        context = _signed(ttl=timedelta(seconds=-1))

        with pytest.raises(ToolCreationError):
            _factory().create_tool(context)

    def test_signature_is_reported_before_expiry(self) -> None:
        # Matching the wrappers: a tampered context must not disclose that an
        # otherwise-valid context had merely expired.
        context = _signed(ttl=timedelta(seconds=-1))
        context.signature = "forged"

        with pytest.raises(ToolCreationError, match="invalid signature"):
            _factory().create_tool(context)

    def test_can_query_false_yields_no_tool(self) -> None:
        # The top-level read gate. Returning a wrapper that denies every call invites a
        # caller to treat the denial as transient and retry.
        context = _signed(_policy(can_query=False))

        with pytest.raises(ToolCreationError, match="query not permitted"):
            _factory().create_tool(context)

    def test_a_context_carrying_no_policy_yields_no_tool(self) -> None:
        # Simulates a payload whose policy went missing in transport. Signature
        # enforcement is off so the test reaches the policy check rather than stopping
        # at the signature the mutation invalidated.
        context = _signed()
        context.effective_policy = None  # type: ignore[assignment]

        factory = SecureToolFactory(
            SecureMcpServerOptions(
                signing_key=KEY, enforce_signatures=False, enforce_expiry=False
            ),
            client=_client(),
        )

        with pytest.raises(ToolCreationError, match="no effective policy"):
            factory.create_tool(context)


# ---------------------------------------------------------------------------
# The factory does not open connections
# ---------------------------------------------------------------------------


class TestNoConnectionsOrCredentials:
    def test_api_without_a_client_is_an_error_not_a_default_client(self) -> None:
        # Silently constructing a default httpx.Client would bypass the caller's proxy,
        # timeout and retry configuration while appearing to work.
        factory = SecureToolFactory(SecureMcpServerOptions(signing_key=KEY))
        context = _signed(_policy(source_connection_id="api:internal:orders"))

        with pytest.raises(ToolCreationError, match="client"):
            factory.create_tool(context)

    def test_record_categories_need_no_client(self) -> None:
        factory = SecureToolFactory(SecureMcpServerOptions(signing_key=KEY))

        assert isinstance(factory.create_tool(_signed()), SecureMcpToolWrapper)

    def test_building_a_tool_performs_no_request(self) -> None:
        # The mock transport raises if called, so reaching the assertion proves the
        # factory did not touch the transport while composing.
        tool = _factory().create_tool(
            _signed(_policy(source_connection_id="api:internal:orders"))
        )

        assert isinstance(tool, SecureHttpToolWrapper)


# ---------------------------------------------------------------------------
# Wrappers stay stateless and reusable
# ---------------------------------------------------------------------------


class TestWrappersAreStateless:
    def test_two_calls_yield_independent_wrappers(self) -> None:
        factory = _factory()

        assert factory.create_tool(_signed()) is not factory.create_tool(_signed())

    def test_exploit_a_tool_built_for_one_user_does_not_carry_that_users_policy(
        self,
    ) -> None:
        # The failure mode a stateful set_security_context() would introduce: a wrapper
        # holding user A's context, reused for user B. Because the context is supplied
        # per call, a wrapper built from A's context enforces B's policy when B calls
        # it.
        a_policy = _policy(
            user_id="user-A", object_rules=ObjectRules(allowed_objects=["patients"])
        )
        tool = _factory().create_tool(_signed(a_policy))
        assert isinstance(tool, SecureMcpToolWrapper)

        b_context = _signed(
            _policy(
                user_id="user-B", object_rules=ObjectRules(allowed_objects=["encounters"])
            )
        )

        assert tool.pre_execute(b_context, tool_name="q", object_name="encounters").allowed
        # And A's allow-list does not leak in to grant `patients` to B.
        assert not tool.pre_execute(b_context, tool_name="q", object_name="patients").allowed

    def test_the_built_wrapper_still_validates_on_every_call(self) -> None:
        # Composition-time validation is redundancy, not the gate: the wrapper is
        # reusable and the context arrives again with every request, so a forged
        # context presented later must still be refused.
        tool = _factory().create_tool(_signed())
        assert isinstance(tool, SecureMcpToolWrapper)

        forged = _signed()
        forged.signature = "forged"

        result = tool.pre_execute(forged, tool_name="q", object_name="patients")
        assert result.allowed is False
        assert result.reason == "invalid signature"


# ---------------------------------------------------------------------------
# Options forwarding
# ---------------------------------------------------------------------------


class TestOptionsReachTheWrapper:
    def test_allowed_tools_is_honoured(self) -> None:
        tool = _factory(allowed_tools=["permitted"]).create_tool(_signed())
        assert isinstance(tool, SecureMcpToolWrapper)

        assert tool.pre_execute(_signed(), tool_name="permitted").allowed
        denied = tool.pre_execute(_signed(), tool_name="other")
        assert denied.allowed is False
        assert denied.reason == "tool not in allowed list"

    def test_enforce_signatures_false_is_forwarded(self) -> None:
        # Asserted because it is a footgun worth being explicit about: the option exists
        # for migrations, and this documents that it really does disable the check
        # rather than being quietly ignored.
        context = _signed()
        context.signature = "forged"

        tool = _factory(enforce_signatures=False).create_tool(context)
        assert isinstance(tool, SecureMcpToolWrapper)
        assert tool.pre_execute(context, tool_name="q", object_name="patients").allowed
