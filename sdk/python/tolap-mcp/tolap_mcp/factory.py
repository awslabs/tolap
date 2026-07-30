"""Secure Tool Factory -- the composition root for policy-enforced tools.

(architecture.md section 5.)

**What this exists for.** Enforcement is only non-bypassable if the wrapper is the
*sole* path to the data source (architecture.md section 4). A factory is how that
becomes structural rather than a convention: an agent receives its tools from here and
never constructs one, so there is no code path that reaches a source unwrapped. Wiring
each tool by hand at call sites works right up until one site forgets, and a forgotten
wrapper is indistinguishable from an enforced one until someone audits it.

**What it deliberately does NOT do.** The reference implementation's factory also
brokered credentials and pinned connection configuration. Neither belongs here, because
**this SDK never holds a connection**: the MCP wrapper hands back rewritten SQL for the
caller to execute, and :class:`SecureHttpToolWrapper` is given its ``httpx.Client`` by
the caller. Nothing on the enforcement path -- validate, rewrite, filter, mask, limit --
takes a secret as input, so accepting one would add secret-handling surface to a
security library that has no use for it. It is the same reasoning that removed
``limits.maxQueryTimeSeconds`` from the schema (connector-spec section 9): the SDK
cannot enforce what it does not own. Credentials belong to the layer that opens the
connection.

Nor does it hold a user's :class:`SecurityContext`. The documented API in the
implementation guides showed a ``set_security_context()`` call that made a wrapper
stateful; the shipped wrappers take the context **per call** instead. That is a safety
property, not an oversight -- a context stored on a shared instance can outlive the
request that supplied it and be reused for the next caller, who may be a different
user. Factory-produced wrappers are stateless and reusable for exactly that reason.

**Dispatch is on the signed category.** The wrapper a source needs is decided by the
``category`` segment of its ``source_connection_id`` (connector-spec section 1), read
from the **signed** policy rather than from unsigned configuration. A category taken
from a side channel could disagree with the policy the context carries: flipping ``db``
to ``api`` would select the wrapper that enforces the other category's rules, and
``endpoint_rules`` do not constrain a SQL query. Inside the signed bytes, changing it
breaks the signature.

Mirrors ``factory.ts`` and ``SecureToolFactory.cs``.
"""

from __future__ import annotations

from typing import Union

import httpx

from tolap_core.context import validate_context, validate_expiry
from tolap_core.models import SecurityContext
from tolap_core.source_identity import SourceCategory, source_category

from tolap_mcp.http_wrapper import SecureHttpToolWrapper
from tolap_mcp.options import SecureMcpServerOptions
from tolap_mcp.wrapper import SecureMcpToolWrapper

SecureTool = Union[SecureMcpToolWrapper, SecureHttpToolWrapper]
"""A tool the factory can produce."""


class ToolCreationError(Exception):
    """Raised when a tool cannot be produced.

    Never carries policy contents -- the message names the rule or the configuration
    gap, not the data (connector-spec section 3.3).
    """


class SecureToolFactory:
    """Creates policy-enforced tools from a signed :class:`SecurityContext`.

    One context governs one data source (architecture.md section 1), so this produces
    one tool per call rather than the multi-source tool *set* the guides once
    described. A caller holding contexts for several sources calls :meth:`create_tool`
    per context.

    Args:
        options: Forwarded to the produced wrapper, so signing key, expiry
            enforcement, and the allow-lists behave identically whether a wrapper was
            built here or by hand.
        client: Transport for ``api`` sources. Required only to produce an ``api``
            tool: the factory never opens a connection of its own, so the caller
            supplies the client. Requesting an ``api`` tool without one raises
            :class:`ToolCreationError` rather than constructing a default client,
            which would quietly bypass the caller's proxy, timeout, and retry
            configuration.
    """

    def __init__(
        self,
        options: SecureMcpServerOptions,
        client: httpx.Client | None = None,
    ) -> None:
        self._options = options
        self._client = client

    def create_tool(self, context: SecurityContext) -> SecureTool:
        """Produce the enforcing tool for the source this context governs.

        Raises :class:`ToolCreationError` when the context is not usable. Every
        rejection below is a *refusal to hand back a tool at all*, which is the
        fail-closed outcome: returning an unenforced tool for a context that failed
        validation would defeat the point of the factory.

        The context is validated here even though every wrapper re-validates it on
        each call. That is intentional redundancy: it turns "this context is forged"
        into an error at composition time, where it is attributable, rather than a
        denial on some later tool call. The per-call check remains the one that
        actually gates access, since a wrapper is reusable and the context arrives
        again with every request.
        """
        self._assert_usable_context(context)

        policy = context.effective_policy

        # can_query is the top-level read gate. A source the user cannot read produces
        # no tool: handing back a wrapper that denies every call invites a caller to
        # treat the denial as a transient error and retry.
        if not policy.permissions.can_query:
            raise ToolCreationError("query not permitted")

        category = source_category(policy.source_connection_id)
        if category is None:
            # Unparseable identifier -> no category -> no way to know which rules
            # apply. Guessing a wrapper here would enforce the wrong category's rules.
            raise ToolCreationError(
                "source_connection_id is not category:namespace:name "
                "(connector-spec section 1)"
            )

        if category is SourceCategory.api:
            return self.create_http_tool()

        # db, kb and storage all return records (rows, chunks, listing entries) and are
        # enforced by the record-shaped pipeline. They differ in which policy fields
        # are meaningful, and that is decided by the policy itself rather than by the
        # wrapper type -- an inert field is simply never consulted (connector-spec
        # section 2).
        return self.create_record_tool()

    def create_record_tool(self) -> SecureMcpToolWrapper:
        """The record-shaped wrapper for ``db``, ``kb`` and ``storage``.

        Takes no context: the context is supplied per call and validated there.
        """
        return SecureMcpToolWrapper(self._options)

    def create_http_tool(self) -> SecureHttpToolWrapper:
        """The HTTP wrapper for ``api`` sources. Requires a ``client``."""
        if self._client is None:
            raise ToolCreationError(
                "an api source needs a client; the factory does not open connections"
            )
        return SecureHttpToolWrapper(self._options, self._client)

    def category_of(self, context: SecurityContext) -> SourceCategory | None:
        """The category this context's source belongs to.

        ``None`` when the identifier is unparseable, letting a caller branch before
        requesting a tool.
        """
        policy = getattr(context, "effective_policy", None)
        if policy is None:
            return None
        return source_category(policy.source_connection_id)

    def _assert_usable_context(self, context: SecurityContext) -> None:
        # Signature before expiry, matching the wrappers: a tampered context must
        # report a signature failure rather than disclose that an otherwise-valid
        # context had merely expired.
        if self._options.enforce_signatures:
            if not validate_context(context, self._options.signing_key):
                raise ToolCreationError("invalid signature")

        if self._options.enforce_expiry:
            expiry_reason = validate_expiry(context)
            if expiry_reason is not None:
                raise ToolCreationError(expiry_reason)

        if getattr(context, "effective_policy", None) is None:
            raise ToolCreationError("context carries no effective policy")
