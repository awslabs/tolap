"""TOLAP enforcement around an httpx-based HTTP client.

Counterpart to SecureMcpToolWrapper for REST/JSON APIs:

- Pre-call: validate_endpoint (path + method) and signature/expiry checks.
- Post-call: strip hidden fields, project to allowed fields, apply field masking,
  and apply result limits to the response body.

Key difference from the DB wrapper: API responses are JSON trees, not flat
records. This wrapper supports dotted-path masking (e.g. "patient.patientonsetage")
and a configurable collection_path that points at the array of rows in the body
(e.g. openFDA returns its rows under "results"; ClinicalTrials.gov uses "studies").
"""

from __future__ import annotations

import copy
from typing import Any

import httpx

from tolap_core.context import validate_context, validate_expiry
from tolap_core.enforcement import (
    AccessResult,
    apply_masking,
    apply_object_size_ceiling,
    apply_result_limit,
    apply_row_filters,
    apply_similarity_floor,
    filter_by_tags,
    project_allowed_fields,
    strip_hidden_fields,
    validate_endpoint,
)
from tolap_core.models import EffectivePolicy, SecurityContext

from tolap_mcp.options import SecureMcpServerOptions


def _apply_masking_to_body(body: Any, policy: EffectivePolicy) -> Any:
    """Apply every masked_field rule to a (potentially nested) JSON body.

    Delegates to the shared core implementation, for the same reason the
    hidden-field path does: a separate dotted-path walk here drifted from core and
    under-masked. It anchored each rule at the root of the body, so a bare rule
    such as ``ssn`` reached only a top-level key -- the identical policy masked
    ``{"demographics": {"ssn": ...}}`` through the MCP wrapper and disclosed it
    through this one. The core walk recurses into nested dicts and lists and
    matches a rule's bare and dotted forms against a key's bare and dotted forms,
    so both ``results.patient.ssn`` and ``ssn`` reach a nested ``ssn`` key
    (spec section 4).
    """
    return apply_masking(body, policy)


def _strip_hidden_fields_from_body(body: Any, policy: EffectivePolicy) -> Any:
    """Remove hidden fields from a JSON tree.

    Mirrors the SQL-side promise: a hidden field never reaches the agent. For
    APIs that return the field anyway (most of them), we drop it here.

    Delegates to the shared core implementation so the HTTP and MCP paths cannot
    drift; the core walks nested dicts and lists and matches a rule's bare and
    dotted forms against a key's bare and dotted forms, so "results.patient.ssn"
    still reaches a nested ``ssn`` key.
    """
    return strip_hidden_fields(body, policy)


def _project_allowed_fields_in_body(
    body: Any,
    collection_path: str | None,
    policy: EffectivePolicy,
) -> Any:
    """Project the response's records down to allowedFields.

    Projection targets the records themselves — the array at `collection_path`,
    or the body when the body *is* the collection — rather than the transport
    envelope, so an API's `meta`/paging block survives while a record returning
    columns the policy never listed is trimmed. When no allowedFields is set
    (None) the body is returned untouched; an empty allow-list denies every
    field.
    """
    if not policy.object_rules or not policy.object_rules.field_rules:
        return body
    if policy.object_rules.field_rules.allowed_fields is None:
        return body

    if collection_path is None:
        if isinstance(body, (list, dict)):
            return project_allowed_fields(body, policy)
        return body

    parts = collection_path.split(".")
    projected = copy.deepcopy(body)
    cursor = projected
    for part in parts[:-1]:
        if not isinstance(cursor, dict) or part not in cursor:
            return projected
        cursor = cursor[part]
    leaf = parts[-1]
    if isinstance(cursor, dict) and isinstance(cursor.get(leaf), list):
        cursor[leaf] = project_allowed_fields(cursor[leaf], policy)
    return projected


def _filter_records_in_body(
    body: Any,
    collection_path: str | None,
    policy: EffectivePolicy,
) -> Any:
    """Apply steps 1-4 of the canonical pipeline to the response's records.

    Row filters, tag filters, the relevance floor, and the size ceiling -- every
    record-dropping step in spec section 4, which binds "every wrapper, in every
    language".

    Row and tag filtering were absent from this wrapper, so a policy that excluded
    rows by ``rowFilters`` or by ``deniedTags``/``allowedTags`` was silently a
    no-op over HTTP. The relevance floor and size ceiling were absent too: with
    ``minSimilarityScore`` and ``maxObjectSizeBytes`` both set, a body carrying a
    0.2-scoring 1GB record and a 0.99-scoring 10-byte record returned *both*.

    Filtering runs before hidden-field stripping so a filter may reference a field
    the policy then removes; the pre-execution endpoint check cannot substitute,
    because it never inspects the rows that come back.

    Only the records are filtered -- the array at ``collection_path``, or the body
    when the body itself is the collection -- so an API's ``meta``/paging envelope
    survives, matching the projection and limit steps.
    """
    has_record_filters = bool(
        policy.object_rules
        and (policy.object_rules.row_filters or policy.object_rules.tag_rules)
    )
    has_numeric_limits = bool(
        policy.limits
        and (
            policy.limits.min_similarity_score is not None
            or policy.limits.max_object_size_bytes is not None
        )
    )
    if not has_record_filters and not has_numeric_limits:
        return body

    def _filter(records: list) -> list:
        # Non-record entries cannot be policy-evaluated; a list of scalars is not
        # a result set this step can filter, so it is left to the shape rules.
        if not all(isinstance(item, dict) for item in records):
            return records
        kept = filter_by_tags(apply_row_filters(records, policy), policy)
        kept = apply_similarity_floor(kept, policy)
        return apply_object_size_ceiling(kept, policy)

    if collection_path is None:
        if isinstance(body, list):
            return _filter(body)
        if isinstance(body, dict):
            # A single-record body is one record, not an envelope, so it runs the
            # identical pipeline (spec section 4, "Single records"). Returning it
            # untouched disclosed the excluded record outright: a policy with
            # `status != deleted` handed back `{"id": 1, "status": "deleted"}`.
            # A dropped single record becomes None rather than {} -- an empty
            # record would imply the row existed but had no visible fields, which
            # is a different statement from "this row is not available to you".
            kept = _filter([body])
            return kept[0] if kept else None
        return body

    parts = collection_path.split(".")
    filtered = copy.deepcopy(body)
    cursor = filtered
    for part in parts[:-1]:
        if not isinstance(cursor, dict) or part not in cursor:
            return filtered
        cursor = cursor[part]
    leaf = parts[-1]
    if isinstance(cursor, dict) and isinstance(cursor.get(leaf), list):
        cursor[leaf] = _filter(cursor[leaf])
    return filtered


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
        """Validate signature then expiry; a missing expiry is a denial."""
        if self._options.enforce_signatures:
            if not validate_context(context, self._options.signing_key):
                return AccessResult(allowed=False, reason="invalid signature")
        if self._options.enforce_expiry:
            expiry_reason = validate_expiry(context)
            if expiry_reason is not None:
                return AccessResult(allowed=False, reason=expiry_reason)
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

        Returns the parsed JSON body with hidden-field stripping, allowed-field
        projection, masking, and result limits already applied, in the canonical
        pipeline order. Raises PermissionError if the policy denies the call
        before it leaves the process.
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

        # Canonical pipeline order (spec section 4): row filters, tag filters,
        # hidden fields, allowed fields, masking, result limit. Filtering precedes
        # field removal so a filter may reference a field the policy then hides,
        # and the limit runs last so filtering never yields fewer rows than
        # maxResults when more qualifying rows exist.
        body = _filter_records_in_body(body, collection_path, policy)
        body = _strip_hidden_fields_from_body(body, policy)
        body = _project_allowed_fields_in_body(body, collection_path, policy)
        body = _apply_masking_to_body(body, policy)
        body = _limit_collection(body, collection_path, policy)
        return body
