from __future__ import annotations

import logging
from typing import Any, Callable

from tolap_core.context import validate_context, validate_expiry
from tolap_core.delegation import validate_delegation_chain
from tolap_core.enforced_result import (
    EnforcedResult,
    contains_enforced_result,
    is_bound_to,
    unwrap_enforced_results,
)
from tolap_core.enforcement import (
    TARGET_ROW_UNKNOWN,
    AccessResult,
    apply_idempotent_result_steps,
    apply_result_pipeline,
    classify_result_shape,
    describe_result_shape,
    validate_access,
    validate_endpoint,
    validate_field_access,
    validate_tool_access,
    validate_write,
)
from tolap_core.enums import WriteOperation
from tolap_core.judge import JudgeDisposition, evaluate_judge
from tolap_core.models import EffectivePolicy, SecurityContext
from tolap_core.purpose_action import validate_tool_action
from tolap_mcp.tool_call import render_tool_call
from tolap_core.sql_rewriter import SqlDialect, SqlEnforcementMode

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


def _grants_any_operation(policy: EffectivePolicy) -> bool:
    """Whether the policy grants at least one of can_query, can_insert, can_update, can_delete."""
    perms = policy.permissions
    return (
        perms.can_query is True
        or perms.can_insert is True
        or perms.can_update is True
        or perms.can_delete is True
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

                # The delegation chain, if the context carries one (spec section 15.3).
        #
        # Validated here rather than in ``build_security_context``: a builder that validated
        # would have to either raise -- making issuing brittle -- or drop the chain, which
        # emits a context that looks delegated and is not. And the check is only meaningful
        # *after* the signature, since the signature proves the chain was not modified in
        # transit rather than that it is valid, and an unsigned chain can be rewritten by the
        # principal it constrains.
        #
        # Backward compatible: an absent chain, or a single hop, is allowed.
        chain_result = validate_delegation_chain(context.delegation_chain)
        if not chain_result.allowed:
            return chain_result

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
        """Pre-execution enforcement check, then the semantic judge if one is configured.

        The judge runs **only** if the deterministic checks allowed the call, so it can
        only ever withdraw an allowance -- it is never asked to permit something the rules
        refused. That is what makes prompt injection through the tool call survivable
        rather than critical: the worst a manipulated verdict achieves is an allow that was
        already granted.
        """
        deterministic = self._pre_execute_deterministic(
            context,
            tool_name,
            object_name,
            fields,
            endpoint_path,
            endpoint_method,
        )

        rendered = render_tool_call(
            tool_name, object_name, fields, endpoint_path, endpoint_method
        )
        # Recorded whether or not the call is permitted. A refused call is part of the
        # trajectory -- an agent probing for what it can reach is precisely the pattern the
        # judge is meant to notice, and a history that kept only successes would hide it.
        if self._options.tool_call_history is not None:
            self._options.tool_call_history.record(rendered)

        if not deterministic.allowed or self._options.judge is None:
            return deterministic

        return self._apply_judge(context, rendered)

    def filter_tools(self, context: SecurityContext, tool_names: list[str]) -> list[str]:
        """The names from ``tool_names``, in order, that ``pre_execute`` would not refuse by name.

        For a ``tools/list`` handler: an agent that never sees a tool is not steered into
        trying it. Applies the static ``allowed_tools`` list, the policy's ``toolRules`` and
        the purpose action check -- the checks that depend on the tool name alone. It does not
        apply ``can_query`` or object, field or endpoint rules (they depend on call arguments),
        record history or consult the judge: listing is not a call, and listing a tool is not
        permission to call it -- ``pre_execute`` re-checks every call.

        Returns a new list; ``tool_names`` is not modified. Duplicates are kept. An invalid
        context lists nothing, and so does a policy that grants none of ``can_query``,
        ``can_insert``, ``can_update`` and ``can_delete``. Null and non-string entries are
        dropped.
        """
        if not self.validate_security_context(context).allowed:
            return []
        policy = context.effective_policy
        # A policy that grants no operation at all makes every tool uncallable, so it lists
        # nothing. Any one grant is enough to list: can_query is not required, so a
        # write-only policy still lists its write tools (subject to toolRules).
        if not _grants_any_operation(policy):
            return []
        allowed: list[str] = []
        for name in tool_names:
            # A null or non-string entry is never a tool name, whether or not the policy
            # carries toolRules (whose grammar would reject it anyway).
            if not isinstance(name, str):
                continue
            if self._options.allowed_tools and name not in self._options.allowed_tools:
                continue
            if not validate_tool_access(name, policy).allowed:
                continue
            if not validate_tool_action(
                policy, name, self._options.tool_action_categories
            ).allowed:
                continue
            allowed.append(name)
        return allowed

    def _apply_judge(self, context: SecurityContext, rendered: str) -> AccessResult:
        """Consult the judge for a call the deterministic checks already allowed."""
        assert self._options.judge is not None  # guarded by the caller
        outcome = evaluate_judge(
            context.effective_policy,
            self._options.judge,
            rendered,
            self._options.tool_call_history,
        )

        if outcome.disposition is JudgeDisposition.allow:
            return AccessResult(allowed=True)

        # A review path exists, so the ambiguous case is its decision rather than a flat
        # denial. Only ``escalate`` is routed there: sending a confident block to a review
        # handler would let a deployment approve away the judge's clearest refusals.
        if (
            outcome.disposition is JudgeDisposition.escalate
            and self._options.escalation_handler is not None
        ):
            if self._options.escalation_handler(outcome):
                return AccessResult(allowed=True)

        return AccessResult(allowed=False, reason=outcome.reason)

    def _pre_execute_deterministic(
        self,
        context: SecurityContext,
        tool_name: str,
        object_name: str | None,
        fields: list[str] | None,
        endpoint_path: str | None,
        endpoint_method: str | None,
    ) -> AccessResult:
        """The checks that need no network call, in their required order."""
        # Validate security context first
        ctx_result = self.validate_security_context(context)
        if not ctx_result.allowed:
            return ctx_result

        policy = context.effective_policy

        # The static list, then per-identity tool gating (section 16). Before can_query:
        # "you may not call this tool" is the more specific answer when both would deny, and
        # a gate after the read gate would never be reached under a write-only policy.
        tool_result = self._tool_gate(policy, tool_name)
        if not tool_result.allowed:
            return tool_result

        # Check query permission
        if not policy.permissions.can_query:
            return AccessResult(allowed=False, reason="query not permitted")

        # Purpose-bound action validation, after the read gate and before the object
        # rules. The ordering matters in both directions: after can_query, because a
        # policy that grants no reads should say so rather than complain about a
        # category; before the object rules, because "this action does not serve the
        # declared purpose" is the more specific answer when both would deny, and it is
        # the one that tells an operator what actually went wrong.
        action_result = validate_tool_action(
            policy, tool_name, self._options.tool_action_categories
        )
        if not action_result.allowed:
            return action_result

        # Object-level access check
        if object_name is not None:
            obj_result = validate_access(object_name, policy)
            if not obj_result.allowed:
                return obj_result

        # Field-level access check
        if fields is not None:
            field_result = validate_field_access(fields, policy, object_name)
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

    def _tool_gate(self, policy: EffectivePolicy, tool_name: str) -> AccessResult:
        """The checks that depend on the tool name alone: the static list, then toolRules.

        Shared by :meth:`pre_execute` and :meth:`pre_write` so the two paths give the same
        denial reasons. Consults no permission flag -- in particular not ``can_query``, so a
        write-only policy can pass it.
        """
        if self._options.allowed_tools and tool_name not in self._options.allowed_tools:
            return AccessResult(allowed=False, reason="tool not in allowed list")
        return validate_tool_access(tool_name, policy)

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
        tool_name: str | None = None,
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

        ``tool_name`` is the MCP tool the write is made for. When it is given, the tool gate
        :meth:`pre_execute` uses runs first, after the context check and before any write
        check: the static ``allowed_tools`` list, then the policy's ``toolRules``
        (section 16), with the same denial reasons. It does not require ``can_query``, so it
        works under a write-only policy. When it is omitted, no tool-name check runs and the
        behaviour is unchanged -- which also means a ``hiddenTools`` entry is not enforced on
        that call, so pass it for every write tool.
        """
        ctx_result = self.validate_security_context(context)
        if not ctx_result.allowed:
            return ctx_result

        if tool_name is not None:
            tool_result = self._tool_gate(context.effective_policy, tool_name)
            if not tool_result.allowed:
                return tool_result

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
        tool_name: str | None = None,
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

        ``tool_name``, when given, runs the tool gate first; see :meth:`pre_write`.
        """
        pre_result = self.pre_write(
            context,
            operation,
            object_name=object_name,
            payload=payload,
            target_row=target_row,
            resource_fields=resource_fields,
            full_replace=full_replace,
            tool_name=tool_name,
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

        This method never honours an
        :class:`~tolap_core.enforced_result.EnforcedResult`: a marker in the
        mappings and lists of ``results`` is unwrapped and its data runs the full pipeline. Only
        :meth:`execute_with_enforcement` honours one. The SQL and write paths call
        this method, so a marker returned there is enforced in full too; on the SQL
        path that keeps a filter that could not be pushed down enforced.
        """
        return self._post_execute(context, results, honour_marker=False)

    def _post_execute(
        self, context: SecurityContext, results: Any, *, honour_marker: bool
    ) -> Any:
        """:meth:`post_execute`, optionally honouring a top-level marker.

        ``honour_marker`` is private on purpose: only :meth:`execute_with_enforcement`
        sets it. When set and the marker's binding verifies (see
        :meth:`_honours_enforced_result`), masking and the filters whose field
        masking or removal changes are skipped, so hashed fields are not hashed
        twice; see :func:`~tolap_core.enforcement.apply_idempotent_result_steps`.
        Any other marker is unwrapped and its data runs the full pipeline.
        """
        policy = context.effective_policy

        if isinstance(results, EnforcedResult):
            if not honour_marker:
                _LOG.warning(
                    "TOLAP: an EnforcedResult is honoured only by execute_with_enforcement; "
                    "applying the full result pipeline."
                )
            elif self._honours_enforced_result(context, results):
                return self._post_execute_already_enforced(results.data, policy)
            else:
                # Never names the signatures: they are credentials.
                _LOG.warning(
                    "TOLAP: the tool returned an EnforcedResult that is not bound to this "
                    "call's verified context signature; applying the full result pipeline."
                )

        results = unwrap_enforced_results(results)

        if classify_result_shape(results) is None and self._options.allow_unenforceable_shapes:
            _LOG.warning(
                "TOLAP enforcement bypassed: allow_unenforceable_shapes is enabled and the "
                "tool returned %s, which is passed through unfiltered.",
                describe_result_shape(results),
            )
            return results

        return apply_result_pipeline(results, policy, self._options.hash_salt)

    def _honours_enforced_result(self, context: SecurityContext, marker: EnforcedResult) -> bool:
        """Whether ``marker`` may skip the non-idempotent pipeline steps.

        Every condition must hold; each failure falls back to the full pipeline,
        which is always safe for data that is genuinely already enforced -- at worst
        a hash is hashed again -- whereas honouring a bad marker would return data
        nothing enforced.

        * exact type -- a subclass could override ``data`` or equality, so it is
          treated as data like any other object;
        * signatures enforced, and the context signature verifies under the
          signing key -- without that the signature field is whatever the sender
          wrote, and matching it proves nothing. Re-verified here, after the tool
          ran, because the tool holds the context object and could have changed it
          since ``pre_execute`` checked it;
        * the marker names that exact signature, compared in constant time. The
          signature covers the whole envelope (policy, expiry, jti, purpose,
          delegation chain), so a marker bound to any other context does not match.
          A marker bound to this context matches on every call made with it until
          it expires: the binding names the context, not the call;
        * no marker nested inside -- an inner marker's binding is not what was
          checked, so the whole result is enforced instead.
        """
        if type(marker) is not EnforcedResult:
            return False
        if not self._options.enforce_signatures or not context.signature:
            return False
        try:
            if not validate_context(context, self._options.signing_key):
                return False
        except (TypeError, ValueError):
            # A malformed context (a non-string signature, an unknown algorithm) is
            # a reason not to honour, never an exception escaping enforcement.
            return False
        if not is_bound_to(marker, context):
            return False
        return not contains_enforced_result(marker.data)

    def _post_execute_already_enforced(self, data: Any, policy: EffectivePolicy) -> Any:
        """The idempotent pipeline steps over data a verified marker carried.

        ``None`` is returned as is: it is what the pipeline itself yields for a single
        record it dropped, and it carries no data to enforce.
        """
        if data is None:
            return None

        if classify_result_shape(data) is None and self._options.allow_unenforceable_shapes:
            _LOG.warning(
                "TOLAP enforcement bypassed: allow_unenforceable_shapes is enabled and the "
                "tool returned %s, which is passed through unfiltered.",
                describe_result_shape(data),
            )
            return data

        return apply_idempotent_result_steps(data, policy)

    def execute_sql_with_enforcement(
        self,
        context: SecurityContext,
        sql: str,
        execute: Callable[[str], Any],
        *,
        object_name: str | None = None,
        dialect: SqlDialect | str | None = None,
        mode: SqlEnforcementMode | str | None = None,
    ) -> Any:
        """Run a SQL query under a policy, enforcing before and after execution.

        The SQL-aware counterpart to :meth:`execute_with_enforcement`, which is generic
        and never touches the query. Added so the enforcement mode is reachable the same
        way in every SDK: .NET has had ``ExecuteSqlWithEnforcementAsync`` since the first
        release, and its absence here was why the three SDKs disagreed about whether
        rewriting happens by default.

        ``execute`` receives the query to run -- rewritten or not, depending on ``mode``
        -- and returns its rows. TOLAP never holds a connection, so fetching stays yours:

            rows = wrapper.execute_sql_with_enforcement(
                ctx,
                "SELECT id, email FROM patients",
                lambda q: cursor.execute(q).fetchall(),
                dialect=SqlDialect.postgres,
            )

        ``mode`` selects where the policy is applied.
        :attr:`~tolap_core.SqlEnforcementMode.post_only` leaves your query byte-for-byte
        untouched and enforces entirely on the rows that come back; the default
        :attr:`~tolap_core.SqlEnforcementMode.rewrite_and_post` also pushes row filters,
        the limit and the projection into the SQL so the database returns less.

        **Both modes return the same rows.** The post-execution pipeline runs in both and
        is the enforcement boundary; rewriting only reduces what the database produces.

        Raises ``PermissionError`` if the query is denied -- which happens in either mode,
        since ``canQuery``, ``allowedObjects`` and the refusal of a query naming a hidden
        field are checked before the mode is consulted.
        """
        # Imported here rather than at module scope so `import tolap_mcp` does not pull
        # in the rewriter for the many integrators who never query SQL.
        from tolap_core.sql_rewriter import prepare_sql_query

        # The wrapper's own check, not the bare `validate_context`: this one carries the
        # signing key and honours `enforce_signatures` / `enforce_expiry`, so a deployment
        # that has deliberately relaxed either is not silently overridden here. Calling the
        # module-level function directly also fails outright -- it requires the key.
        ctx_result = self.validate_security_context(context)
        if not ctx_result.allowed:
            raise PermissionError(f"Access denied: {ctx_result.reason}")

        prep = prepare_sql_query(
            sql,
            context.effective_policy,
            object_name=object_name,
            dialect=dialect,
            mode=mode,
        )
        if not prep.allowed:
            raise PermissionError(f"Access denied: {prep.denial_reason}")

        return self.post_execute(context, execute(prep.query))

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

        A tool that enforces at its data layer returns
        ``EnforcedResult.for_context(data, context)``. This is the only method that
        honours such a marker: when its binding verifies, masking and the filters on
        fields that masking or removal changes are skipped, and every other step
        still runs. Pre-execution checks, history recording and the judge run
        either way. The marker is a claim by the tool code, not proof that the
        pipeline ran: return one only when the data layer really applied this
        context's full pipeline, with this wrapper's hash salt.
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

        # Post-execution enforcement. The one path that honours an EnforcedResult.
        return self._post_execute(context, raw_results, honour_marker=True)
