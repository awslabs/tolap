from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

from tolap_core.context import validate_context
from tolap_core.enforcement import (
    AccessResult,
    apply_field_masking,
    apply_result_limit,
    apply_row_filters,
    filter_by_tags,
    validate_access,
    validate_endpoint,
    validate_field_access,
)
from tolap_core.models import EffectivePolicy, SecurityContext

from tolap_mcp.options import SecureMcpServerOptions


class SecureMcpToolWrapper:
    """Wraps MCP tool execution with TOLAP policy enforcement.

    Pre-execution: validates access, fields, endpoints.
    Post-execution: applies masking, result limits, tag filtering.
    """

    def __init__(self, options: SecureMcpServerOptions) -> None:
        self._options = options

    def validate_security_context(self, context: SecurityContext) -> AccessResult:
        """Validate signature and expiry of a security context."""
        # Validate signature
        if self._options.enforce_signatures:
            if not validate_context(context, self._options.signing_key):
                return AccessResult(allowed=False, reason="invalid signature")

        # Validate expiry
        if self._options.enforce_expiry and context.expires_at:
            try:
                expiry = datetime.fromisoformat(context.expires_at.replace("Z", "+00:00"))
                if expiry < datetime.now(timezone.utc):
                    return AccessResult(allowed=False, reason="security context expired")
            except ValueError:
                return AccessResult(allowed=False, reason="invalid expiry format")

        return AccessResult(allowed=True)

    def pre_execute(
        self,
        context: SecurityContext,
        tool_name: str,
        object_name: str | None = None,
        fields: list[str] | None = None,
        endpoint_path: str | None = None,
        endpoint_method: str | None = None,
    ) -> AccessResult:
        """Pre-execution enforcement check."""
        # Validate security context first
        ctx_result = self.validate_security_context(context)
        if not ctx_result.allowed:
            return ctx_result

        policy = context.effective_policy

        # Check if tool is in allowed list
        if self._options.allowed_tools and tool_name not in self._options.allowed_tools:
            return AccessResult(allowed=False, reason="tool not in allowed list")

        # Check query permission
        if not policy.permissions.can_query:
            return AccessResult(allowed=False, reason="query not permitted")

        # Object-level access check
        if object_name is not None:
            obj_result = validate_access(object_name, policy)
            if not obj_result.allowed:
                return obj_result

        # Field-level access check
        if fields is not None:
            field_result = validate_field_access(fields, policy)
            if field_result.denied:
                denied_str = ", ".join(field_result.denied)
                return AccessResult(allowed=False, reason=f"denied fields: {denied_str}")

        # Endpoint access check
        if endpoint_path is not None:
            method = endpoint_method or "GET"
            ep_result = validate_endpoint(endpoint_path, method, policy)
            if not ep_result.allowed:
                return ep_result

        return AccessResult(allowed=True)

    def post_execute(
        self,
        context: SecurityContext,
        results: list[dict],
    ) -> list[dict]:
        """Post-execution enforcement: row filters, tag filters, masking, result limit.

        Order matches TypeScript and .NET context wrappers:
          row filters -> tag filters -> field masking -> result limit.
        """
        policy = context.effective_policy

        filtered = apply_row_filters(results, policy)
        filtered = filter_by_tags(filtered, policy)
        masked = [apply_field_masking(record, policy) for record in filtered]
        limited = apply_result_limit(masked, policy)
        return limited

    def execute_with_enforcement(
        self,
        context: SecurityContext,
        tool_name: str,
        tool_fn: Callable[..., list[dict]],
        tool_args: dict[str, Any],
        object_name: str | None = None,
        fields: list[str] | None = None,
        endpoint_path: str | None = None,
        endpoint_method: str | None = None,
    ) -> list[dict]:
        """Execute a tool with full pre/post enforcement.

        Raises PermissionError if pre-execution check fails.
        """
        pre_result = self.pre_execute(
            context=context,
            tool_name=tool_name,
            object_name=object_name,
            fields=fields,
            endpoint_path=endpoint_path,
            endpoint_method=endpoint_method,
        )
        if not pre_result.allowed:
            raise PermissionError(f"Access denied: {pre_result.reason}")

        # Execute the tool
        raw_results = tool_fn(**tool_args)

        # Post-execution enforcement
        return self.post_execute(context, raw_results)
