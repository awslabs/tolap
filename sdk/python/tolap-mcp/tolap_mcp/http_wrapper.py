"""TOLAP enforcement around an httpx-based HTTP client.

Counterpart to SecureMcpToolWrapper for REST/JSON APIs:

- Pre-call: validate_endpoint (path + method) and signature/expiry checks.
- Post-call: apply field masking and result limits to the response body.

Key difference from the DB wrapper: API responses are JSON trees, not flat
records. This wrapper supports dotted-path masking (e.g. "patient.patientonsetage")
and a configurable collection_path that points at the array of rows in the body
(e.g. openFDA returns its rows under "results"; ClinicalTrials.gov uses "studies").
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
from typing import Any

import httpx

from tolap_core.context import validate_context
from tolap_core.enforcement import (
    AccessResult,
    _apply_mask,
    apply_result_limit,
    validate_endpoint,
)
from tolap_core.models import EffectivePolicy, MaskingRule, SecurityContext

from tolap_mcp.options import SecureMcpServerOptions


def _walk_and_mask(node: Any, path_parts: list[str], rule: MaskingRule) -> None:
    """Recursively descend `node` along `path_parts`, masking the leaf in place.

    A path_parts of ["patient", "patientonsetage"] applies the rule to
    node["patient"]["patientonsetage"] for dicts, and to every element's
    ["patient"]["patientonsetage"] when traversing lists. Missing keys are
    silently skipped — masking is best-effort, never an error path.
    """
    if not path_parts:
        return

    if isinstance(node, list):
        for item in node:
            _walk_and_mask(item, path_parts, rule)
        return

    if not isinstance(node, dict):
        return

    head, *rest = path_parts
    if head not in node:
        return

    if not rest:
        node[head] = _apply_mask(node[head], rule)
    else:
        _walk_and_mask(node[head], rest, rule)


def _apply_masking_to_body(body: Any, policy: EffectivePolicy) -> Any:
    """Apply every masked_field rule to a (potentially nested) JSON body."""
    if not policy.object_rules or not policy.object_rules.field_rules:
        return body
    if not policy.object_rules.field_rules.masked_fields:
        return body

    masked = copy.deepcopy(body)
    for rule in policy.object_rules.field_rules.masked_fields:
        # "table.field" is the DB convention; for APIs we use dotted paths into JSON.
        # We treat both the same: split on '.', walk the tree.
        parts = rule.field.split(".")
        _walk_and_mask(masked, parts, rule)
    return masked


def _strip_hidden_fields_from_body(body: Any, policy: EffectivePolicy) -> Any:
    """Remove hidden fields from a JSON tree.

    Mirrors the SQL-side promise: a hidden field never reaches the agent. For
    APIs that return the field anyway (most of them), we drop it here.
    """
    if not policy.object_rules or not policy.object_rules.field_rules:
        return body
    hidden = policy.object_rules.field_rules.hidden_fields
    if not hidden:
        return body

    stripped = copy.deepcopy(body)
    for pattern in hidden:
        parts = pattern.split(".")
        _walk_and_drop(stripped, parts)
    return stripped


def _walk_and_drop(node: Any, path_parts: list[str]) -> None:
    if not path_parts:
        return
    if isinstance(node, list):
        for item in node:
            _walk_and_drop(item, path_parts)
        return
    if not isinstance(node, dict):
        return
    head, *rest = path_parts
    if head not in node:
        return
    if not rest:
        node.pop(head, None)
    else:
        _walk_and_drop(node[head], rest)


def _limit_collection(body: Any, collection_path: str | None, policy: EffectivePolicy) -> Any:
    """Truncate the array at `collection_path` to policy.limits.max_results."""
    if not policy.limits or policy.limits.max_results is None:
        return body
    if collection_path is None:
        # Treat the body itself as the collection if it's already a list.
        if isinstance(body, list):
            return apply_result_limit(body, policy)
        return body

    parts = collection_path.split(".")
    cursor = body
    for part in parts[:-1]:
        if not isinstance(cursor, dict) or part not in cursor:
            return body
        cursor = cursor[part]
    leaf = parts[-1]
    if isinstance(cursor, dict) and isinstance(cursor.get(leaf), list):
        cursor[leaf] = apply_result_limit(cursor[leaf], policy)
    return body


class SecureHttpToolWrapper:
    """Enforces TOLAP policy around an httpx.Client.

    Usage:
        client = httpx.Client(base_url="https://api.fda.gov", transport=transport)
        wrapper = SecureHttpToolWrapper(options, client)
        body = wrapper.request(context, "GET", "/drug/event.json",
                               params={"limit": 5}, collection_path="results")
    """

    def __init__(self, options: SecureMcpServerOptions, client: httpx.Client) -> None:
        self._options = options
        self._client = client

    def validate_security_context(self, context: SecurityContext) -> AccessResult:
        if self._options.enforce_signatures:
            if not validate_context(context, self._options.signing_key):
                return AccessResult(allowed=False, reason="invalid signature")
        if self._options.enforce_expiry and context.expires_at:
            try:
                expiry = datetime.fromisoformat(context.expires_at.replace("Z", "+00:00"))
                if expiry < datetime.now(timezone.utc):
                    return AccessResult(allowed=False, reason="security context expired")
            except ValueError:
                return AccessResult(allowed=False, reason="invalid expiry format")
        return AccessResult(allowed=True)

    def request(
        self,
        context: SecurityContext,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any = None,
        headers: dict[str, str] | None = None,
        collection_path: str | None = None,
    ) -> Any:
        """Make an HTTP request with full pre/post enforcement.

        Returns the parsed JSON body with masking, hidden-field stripping, and
        result limits already applied. Raises PermissionError if the policy
        denies the call before it leaves the process.
        """
        ctx_result = self.validate_security_context(context)
        if not ctx_result.allowed:
            raise PermissionError(f"Access denied: {ctx_result.reason}")

        policy = context.effective_policy
        if not policy.permissions.can_query:
            raise PermissionError("Access denied: query not permitted")

        # Strip any query string before policy evaluation; policy patterns are
        # written against paths, not URLs.
        policy_path = path.split("?", 1)[0]
        ep_result = validate_endpoint(policy_path, method, policy)
        if not ep_result.allowed:
            raise PermissionError(f"Access denied: {ep_result.reason}")

        response = self._client.request(method, path, params=params, json=json, headers=headers)
        response.raise_for_status()
        body = response.json()

        body = _strip_hidden_fields_from_body(body, policy)
        body = _apply_masking_to_body(body, policy)
        body = _limit_collection(body, collection_path, policy)
        return body
