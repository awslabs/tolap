from __future__ import annotations

import logging
from typing import Any, Callable

from tolap_core.context import validate_context, validate_expiry
from tolap_core.enforcement import (
    TARGET_ROW_UNKNOWN,
    AccessResult,
    apply_result_pipeline,
    classify_result_shape,
    describe_result_shape,
    validate_access,
    validate_endpoint,
    validate_field_access,
    validate_write,
)
from tolap_core.enums import WriteOperation
from tolap_core.models import EffectivePolicy, SecurityContext

from tolap_mcp.options import SecureMcpServerOptions


_LOG = logging.getLogger(__name__)


def warn_if_enforcement_disabled(options: SecureMcpServerOptions) -> None:
    """Warn at construction when the wrapper is configured so it cannot enforce.

    Threat-model remediation R-6. Python has no permissive *mode*; the equivalent
    opt-out is ``allow_unenforceable_shapes``, which returns results the policy
    could not be applied to. That path already logs when it actually passes
    something through, but a pass-through warning is absent from a service that
    has not yet returned an unenforceable shape -- so the misconfiguration ships
    unnoticed and only becomes visible on the request that leaks.

    Warned once per wrapper at construction, and separately per pass-through in
    :meth:`SecureMcpToolWrapper.post_execute`, so the mode is visible both at
    startup and at the point of impact.

    Signature/expiry enforcement can also be switched off; disabling either means
    an unsigned or expired context is accepted, so both warn as well.
    """
    disabled: list[str] = []
    if options.allow_unenforceable_shapes:
        disabled.append(
            "allow_unenforceable_shapes=True (results the policy cannot be applied "
            "to are returned unfiltered instead of denied)"
        )
    if not options.enforce_signatures:
        disabled.append(
            "enforce_signatures=False (a context with an absent or forged signature "
            "is accepted)"
        )
    if not options.enforce_expiry:
        disabled.append(
            "enforce_expiry=False (an expired context is accepted indefinitely)"
        )

    if not disabled:
        return

    _LOG.warning(
        "TOLAP enforcement is NOT fully enforcing: %s. This is intended for "
        "migration only and MUST NOT be used in production.",
        "; ".join(disabled),
    )


class SecureMcpToolWrapper:
    """Wraps MCP tool execution with TOLAP policy enforcement.

    Pre-execution: validates access, fields, endpoints.
    Post-execution: row filters, tag filters, hidden-field removal, allowed-field
    projection, masking, result limit.
    """

    def __init__(self, options: SecureMcpServerOptions) -> None:
        self._options = options
        warn_if_enforcement_disabled(options)

    def validate_security_context(self, context: SecurityContext) -> AccessResult:
        """Validate signature and expiry of a security context.

        Signature first: a tampered context must report a signature failure
        rather than reveal whether a valid context had merely expired.
        """
        # Validate signature
        if self._options.enforce_signatures:
            if not validate_context(context, self._options.signing_key):
                return AccessResult(allowed=False, reason="invalid signature")

        # Validate expiry. A missing or unparseable expiry is a denial, never a
        # skipped check.
        if self._options.enforce_expiry:
            expiry_reason = validate_expiry(context)
            if expiry_reason is not None:
                return AccessResult(allowed=False, reason=expiry_reason)

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

    def pre_write(
        self,
        context: SecurityContext,
        operation: WriteOperation | str,
        object_name: str | None = None,
        payload: Any = None,
        *,
        target_row: Any = TARGET_ROW_UNKNOWN,
        resource_fields: list[str] | None = None,
        full_replace: bool = False,
    ) -> AccessResult:
        """Validate a write before it is issued (connector spec section 4).

        The write counterpart to :meth:`pre_execute`. Validates the context, then
        runs the four required pre-write checks: the operation's permission and the
        ``readOnly`` ceiling, the target object, every field in the payload, and the
        policy's row filters against ``target_row``.

        Fails closed on the whole write: one unwritable field denies the operation
        rather than being stripped so the rest can proceed (section 4.4).

        Omitting ``target_row`` on an update or delete while the policy carries row
        filters yields ``write target unverifiable``, never an allow -- read the row
        first and pass it here, or push the filters into the statement's ``WHERE``.

        A permitted write that returns data is a *read* of that data: pass the
        response through :meth:`post_execute` (section 4.5).
        """
        ctx_result = self.validate_security_context(context)
        if not ctx_result.allowed:
            return ctx_result

        return validate_write(
            operation,
            object_name,
            payload,
            context.effective_policy,
            target_row=target_row,
            resource_fields=resource_fields,
            full_replace=full_replace,
        )

    def execute_write_with_enforcement(
        self,
        context: SecurityContext,
        operation: WriteOperation | str,
        write_fn: Callable[..., Any],
        write_args: dict[str, Any] | None = None,
        object_name: str | None = None,
        payload: Any = None,
        *,
        target_row: Any = TARGET_ROW_UNKNOWN,
        resource_fields: list[str] | None = None,
        full_replace: bool = False,
    ) -> Any:
        """Validate a write, issue it, and enforce the policy on anything it returns.

        Raises PermissionError before ``write_fn`` is called if the write is
        denied, so a refused write never reaches the source.

        Whatever the write returns is treated as a read of that data and goes
        through the full post-execution pipeline (section 4.5) -- a masked field
        comes back masked even though the caller just wrote it, and a hidden field
        does not appear at all. A write that returns nothing (``None``) is passed
        through as-is rather than being denied as an unenforceable shape: there is
        no data to enforce a policy over.
        """
        pre_result = self.pre_write(
            context,
            operation,
            object_name=object_name,
            payload=payload,
            target_row=target_row,
            resource_fields=resource_fields,
            full_replace=full_replace,
        )
        if not pre_result.allowed:
            raise PermissionError(f"Access denied: {pre_result.reason}")

        result = write_fn(**(write_args or {}))

        if result is None:
            return None
        return self.post_execute(context, result)

    def post_execute(
        self,
        context: SecurityContext,
        results: Any,
    ) -> Any:
        """Post-execution enforcement over a tool result.

        Applies the canonical pipeline in order:
          row filters -> tag filters -> hidden fields -> allowed fields ->
          masking -> result limit.

        Accepts a single record or a list of records; a single record runs the
        identical pipeline (a get-by-id tool must not skip row/tag filters).
        Any other shape is denied with PermissionError unless the wrapper was
        configured with allow_unenforceable_shapes.
        """
        policy = context.effective_policy

        if classify_result_shape(results) is None and self._options.allow_unenforceable_shapes:
            _LOG.warning(
                "TOLAP enforcement bypassed: allow_unenforceable_shapes is enabled and the "
                "tool returned %s, which is passed through unfiltered.",
                describe_result_shape(results),
            )
            return results

        return apply_result_pipeline(results, policy)

    def execute_with_enforcement(
        self,
        context: SecurityContext,
        tool_name: str,
        tool_fn: Callable[..., Any],
        tool_args: dict[str, Any],
        object_name: str | None = None,
        fields: list[str] | None = None,
        endpoint_path: str | None = None,
        endpoint_method: str | None = None,
    ) -> Any:
        """Execute a tool with full pre/post enforcement.

        Raises PermissionError if the pre-execution check fails or if the tool
        returns a shape the policy cannot be applied to.
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
