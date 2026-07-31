"""Branch coverage for the MCP wrapper's context-validation switches.

`validate_security_context` gates every call, and its two switches are the
documented migration opt-outs. Each combination is asserted here because the
failure mode is silent: with a switch off, an unsigned or expired context is
accepted and nothing about the call site changes. The ordering assertion matters
too — the signature is checked first so a tampered context cannot learn whether a
valid context had merely expired (spec section 2).
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from tolap_core.context import build_security_context, sign_context
from tolap_core.models import (
    EffectivePolicy,
    ObjectRules,
    PolicyPermissions,
    SecurityContext,
    TagRules,
)
from tolap_mcp.options import SecureMcpServerOptions
from tolap_mcp.wrapper import SecureMcpToolWrapper, warn_if_enforcement_disabled


KEY = "mcp-branch-key"


def _policy(*, can_query: bool = True) -> EffectivePolicy:
    return EffectivePolicy(
        version="1.0",
        user_id="u",
        tenant_id="t",
        source_profiles=["mcp-branch"],
        permissions=PolicyPermissions(can_query=can_query, read_only=True),
    )


def _signed(ttl: timedelta = timedelta(hours=1)) -> SecurityContext:
    return sign_context(build_security_context("u", "t", [_policy()], ttl=ttl), KEY)


def _wrapper(**options) -> SecureMcpToolWrapper:
    return SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=KEY, **options))


class TestEnforcementSwitchCombinations:
    def test_both_enforced_accepts_a_valid_context(self) -> None:
        result = _wrapper().validate_security_context(_signed())

        assert result.allowed is True
        assert result.reason is None

    def test_both_enforced_rejects_an_expired_context(self) -> None:
        result = _wrapper().validate_security_context(_signed(ttl=timedelta(hours=-1)))

        assert result.allowed is False
        assert result.reason == "security context expired"

    def test_signature_is_checked_before_expiry(self) -> None:
        """A tampered context must not reveal that it was otherwise merely expired."""
        context = _signed(ttl=timedelta(hours=-1))
        context.signature = "forged"

        result = _wrapper().validate_security_context(context)

        assert result.reason == "invalid signature"

    def test_signatures_off_accepts_an_unsigned_context(self) -> None:
        context = build_security_context("u", "t", [_policy()], ttl=timedelta(hours=1))

        result = _wrapper(enforce_signatures=False).validate_security_context(context)

        assert result.allowed is True

    def test_signatures_off_still_enforces_expiry(self) -> None:
        """Disabling one switch must not disable the other."""
        context = build_security_context("u", "t", [_policy()], ttl=timedelta(hours=-1))

        result = _wrapper(enforce_signatures=False).validate_security_context(context)

        assert result.allowed is False
        assert result.reason == "security context expired"

    def test_expiry_off_accepts_an_expired_context(self) -> None:
        result = _wrapper(enforce_expiry=False).validate_security_context(
            _signed(ttl=timedelta(hours=-1))
        )

        assert result.allowed is True

    def test_expiry_off_still_enforces_the_signature(self) -> None:
        context = _signed(ttl=timedelta(hours=-1))
        context.signature = "forged"

        result = _wrapper(enforce_expiry=False).validate_security_context(context)

        assert result.allowed is False
        assert result.reason == "invalid signature"

    def test_both_switches_off_accepts_an_unsigned_expired_context(self) -> None:
        context = build_security_context("u", "t", [_policy()], ttl=timedelta(hours=-1))

        result = _wrapper(
            enforce_signatures=False, enforce_expiry=False
        ).validate_security_context(context)

        assert result.allowed is True

    def test_missing_expiry_is_denied_when_enforcing(self) -> None:
        context = sign_context(SecurityContext(effective_policy=_policy()), KEY)

        result = _wrapper().validate_security_context(context)

        assert result.reason == "security context has no expiry"

    def test_unparseable_expiry_is_denied_when_enforcing(self) -> None:
        context = _signed()
        context.expires_at = "never"
        context = sign_context(context, KEY)

        result = _wrapper().validate_security_context(context)

        assert result.reason == "invalid expiry format"


class TestWarnIfEnforcementDisabled:
    """The exported helper, called directly rather than via the constructor."""

    def test_all_three_opt_outs_are_named_in_one_warning(self, caplog) -> None:
        options = SecureMcpServerOptions(
            signing_key=KEY,
            enforce_signatures=False,
            enforce_expiry=False,
            allow_unenforceable_shapes=True,
        )

        with caplog.at_level("WARNING"):
            warn_if_enforcement_disabled(options)

        assert "allow_unenforceable_shapes" in caplog.text
        assert "enforce_signatures=False" in caplog.text
        assert "enforce_expiry=False" in caplog.text
        assert "MUST NOT be used in production" in caplog.text

    def test_secure_defaults_emit_nothing(self, caplog) -> None:
        """A warning on the safe default would train integrators to ignore it."""
        with caplog.at_level("WARNING"):
            warn_if_enforcement_disabled(SecureMcpServerOptions(signing_key=KEY))

        assert caplog.text == ""


class TestPreExecuteGating:
    def test_invalid_context_short_circuits_before_any_policy_check(self) -> None:
        context = _signed()
        context.signature = "forged"

        result = _wrapper().pre_execute(context, "any-tool")

        assert result.allowed is False
        assert result.reason == "invalid signature"

    def test_tool_outside_the_allow_list_is_denied(self) -> None:
        result = _wrapper(allowed_tools=["query-patients"]).pre_execute(_signed(), "drop-tables")

        assert result.allowed is False
        assert result.reason == "tool not in allowed list"

    def test_tool_in_the_allow_list_is_permitted(self) -> None:
        result = _wrapper(allowed_tools=["query-patients"]).pre_execute(
            _signed(), "query-patients"
        )

        assert result.allowed is True

    def test_empty_allow_list_does_not_restrict_tools(self) -> None:
        """An unset allowed_tools is the default; it must not deny everything."""
        assert _wrapper().pre_execute(_signed(), "any-tool").allowed is True

    def test_can_query_false_is_denied(self) -> None:
        context = sign_context(
            build_security_context("u", "t", [_policy(can_query=False)], ttl=timedelta(hours=1)),
            KEY,
        )

        result = _wrapper().pre_execute(context, "any-tool")

        assert result.reason == "query not permitted"

    def test_endpoint_method_defaults_to_get(self) -> None:
        from tolap_core.models import EndpointRules

        policy = _policy()
        policy.object_rules = ObjectRules(
            endpoint_rules=EndpointRules(allowed_endpoints=["/x"], allowed_methods=["POST"])
        )
        context = sign_context(
            build_security_context("u", "t", [policy], ttl=timedelta(hours=1)), KEY
        )

        result = _wrapper().pre_execute(context, "t", endpoint_path="/x")

        assert result.reason == "method not allowed"


class TestExecuteWithEnforcement:
    def test_denied_pre_check_raises_before_the_tool_runs(self) -> None:
        calls: list[int] = []

        def tool() -> list[dict]:
            calls.append(1)
            return [{"id": 1}]

        context = sign_context(
            build_security_context("u", "t", [_policy(can_query=False)], ttl=timedelta(hours=1)),
            KEY,
        )

        with pytest.raises(PermissionError, match="query not permitted"):
            _wrapper().execute_with_enforcement(context, "t", tool, {})

        assert calls == [], "the tool must not execute when the policy denies"

    def test_tool_arguments_are_forwarded(self) -> None:
        def tool(region: str) -> list[dict]:
            return [{"id": 1, "region": region}]

        result = _wrapper().execute_with_enforcement(
            _signed(), "t", tool, {"region": "us-east"}
        )

        assert result == [{"id": 1, "region": "us-east"}]

    def test_unenforceable_result_is_denied_by_default(self) -> None:
        """Spec section 5: a shape the policy cannot be applied to is denied."""
        with pytest.raises(PermissionError, match="cannot be policy-enforced"):
            _wrapper().execute_with_enforcement(_signed(), "t", lambda: "a scalar", {})

    def test_unenforceable_result_passes_through_when_opted_in(self, caplog) -> None:
        wrapper = _wrapper(allow_unenforceable_shapes=True)

        with caplog.at_level("WARNING"):
            result = wrapper.execute_with_enforcement(_signed(), "t", lambda: "a scalar", {})

        assert result == "a scalar"
        assert "enforcement bypassed" in caplog.text.lower()

    def test_opting_in_does_not_disable_enforcement_for_enforceable_shapes(self) -> None:
        """The opt-out covers only shapes the pipeline cannot handle."""
        policy = _policy()
        policy.object_rules = ObjectRules(tag_rules=TagRules(denied_tags=["secret"]))
        context = sign_context(
            build_security_context("u", "t", [policy], ttl=timedelta(hours=1)), KEY
        )

        result = _wrapper(allow_unenforceable_shapes=True).execute_with_enforcement(
            context, "t", lambda: [{"id": 1, "tags": ["secret"]}, {"id": 2, "tags": ["public"]}], {}
        )

        assert [r["id"] for r in result] == [2]
