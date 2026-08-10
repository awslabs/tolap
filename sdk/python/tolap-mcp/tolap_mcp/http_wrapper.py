"""TOLAP enforcement around an httpx-based HTTP client.

Counterpart to SecureMcpToolWrapper for REST/JSON APIs:

- Pre-call: validate_endpoint (path + method) and signature/expiry checks.
- Post-call: strip hidden fields, project to allowed fields, apply field masking,
  and apply result limits to the response body.

Key difference from the DB wrapper: API responses are JSON trees, not flat
records. This wrapper supports dotted-path masking (e.g. "patient.patientonsetage")
and a configurable collection_path that points at the array of rows in the body
(e.g. openFDA returns its rows under "results"; ClinicalTrials.gov uses "studies").

Two connector spec section 6 requirements shape the request loop rather than the
body pipeline:

- **Error bodies are enforced.** A 4xx/5xx payload carries the same fields as a
  success payload, so it runs the identical pipeline and surfaces as
  :class:`UpstreamHttpError` carrying the *enforced* body. ``raise_for_status``
  is deliberately not called: it raises ``httpx.HTTPStatusError``, whose
  ``.response`` hands the caller the raw unenforced payload.
- **Redirects are re-validated.** Automatic following is switched off per request
  and each hop is re-checked against the endpoint rules, because a permitted
  endpoint that 302s to a denied one otherwise bypasses the check entirely.
"""

from __future__ import annotations

import copy
from typing import Any

import httpx

from tolap_core.context import validate_context, validate_expiry
from tolap_core.enforcement import (
    TARGET_ROW_UNKNOWN,
    AccessResult,
    apply_masking,
    apply_object_size_ceiling,
    apply_result_limit,
    apply_row_filters,
    apply_similarity_floor,
    filter_by_tags,
    project_allowed_fields,
    strip_hidden_fields,
    UnenforceableResultError,
    validate_access,
    validate_http_write,
)
from tolap_core.models import EffectivePolicy, SecurityContext

from tolap_mcp.options import SecureMcpServerOptions


MAX_REDIRECTS = 5
"""How many redirect hops a single request may take before it is denied.

Explicit, and identical in all three SDKs, precisely because every client's own
default differs -- httpx allows 20, .NET's ``HttpClientHandler`` 50, ``fetch`` 20.
Inheriting whichever number the transport happened to pick is how the redirect
gap arose in the first place. Five is the historical HTTP recommendation and is
far more than any legitimate API needs; a chain longer than that is a loop or a
misconfiguration, and either way the caller learns rather than hangs.
"""

# The 3xx codes that carry the original method and body to the new location.
# 301/302/303 are downgraded to GET, matching what every browser and HTTP client
# does in practice -- and the downgraded request is itself re-validated, so the
# downgrade cannot smuggle a write past the method rules either.
_METHOD_PRESERVING_REDIRECTS = frozenset({307, 308})


class UpstreamHttpError(Exception):
    """A non-2xx response, carrying the policy-enforced body.

    Raised in place of ``httpx.HTTPStatusError`` for a reason that is the whole
    point of connector spec section 6's "error bodies are enforced" requirement:
    ``HTTPStatusError`` exposes ``.response``, and a caller reaching through it --
    entirely normal control flow for anyone logging a failure -- read the raw
    payload with every ``hiddenFields`` entry intact. With
    ``hiddenFields: ["error"]`` and a ``GET /status/500``, ``e.response.text``
    disclosed the field in cleartext while the success path removed it.

    :attr:`body` is the error payload after the full pipeline
    (canonical-enforcement-spec.md section 4) has run over it, or ``None`` when
    the payload was not JSON and therefore could not be enforced at all. A body
    that cannot have policy applied to it is withheld rather than passed through
    (canonical-enforcement-spec.md section 5); the status code still tells the
    caller what happened.
    """

    def __init__(self, status_code: int, body: Any, url: str) -> None:
        super().__init__(f"HTTP {status_code} from {url}")
        self.status_code = status_code
        self.body = body
        self.url = url


def _apply_masking_to_body(
    body: Any, policy: EffectivePolicy, hash_salt: str | bytes | None = None
) -> Any:
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
    return apply_masking(body, policy, hash_salt)


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


def _implicit_collection_key(body: Any) -> str | None:
    """The single record-collection key in an envelope, or None if it is not unambiguous.

    Used only when the caller gave no ``collection_path``. Returns a key only when the body has
    **exactly one** value that is a non-empty list of objects, so a body with two candidate
    collections is never guessed at -- guessing the wrong one would enforce the limit on the
    wrong array and read as success.
    """
    if not isinstance(body, dict):
        return None
    candidates = [
        key
        for key, value in body.items()
        if isinstance(value, list) and value and all(isinstance(item, dict) for item in value)
    ]
    return candidates[0] if len(candidates) == 1 else None


def _limit_collection(body: Any, collection_path: str | None, policy: EffectivePolicy) -> Any:
    """Truncate the array at `collection_path` to policy.limits.max_results."""
    if not policy.limits or policy.limits.max_results is None:
        return body
    if collection_path is None:
        # Treat the body itself as the collection if it's already a list.
        if isinstance(body, list):
            return apply_result_limit(body, policy)
        # An envelope with no collection_path used to return unchanged, which meant
        # `maxResults: 1` handed back every record the upstream sent -- a fail-open, and the only
        # one of the three record-level controls that behaved this way: the projection returned
        # `{}` and the row filter returned `None`, both fail-closed. Silently disagreeing on the
        # same missing argument is worse than any single choice, so the limit now enforces on an
        # unambiguously-identifiable collection too. Ambiguous bodies raise rather than guess.
        implicit = _implicit_collection_key(body)
        if implicit is not None:
            limited = dict(body)
            limited[implicit] = apply_result_limit(body[implicit], policy)
            return limited
        if isinstance(body, dict) and any(
            isinstance(value, list) and value and all(isinstance(item, dict) for item in value)
            for value in body.values()
        ):
            raise UnenforceableResultError(
                "limits.maxResults cannot be enforced: the response body has more than one "
                "candidate record collection and no collection_path was supplied. Pass "
                "collection_path to name the one the limit applies to."
            )
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


def _same_origin(current: httpx.URL, target: httpx.URL) -> bool:
    """Whether a redirect target stays on the origin that issued the redirect.

    Scheme, host and port must all match. ``httpx.URL`` normalizes a default port
    away (``http://a.test:80`` and ``http://a.test`` both report ``port is None``),
    so the comparison does not treat an explicit default port as a different
    origin. An http->https upgrade *is* a different origin and is refused: the
    policy was resolved for one source, and silently moving to another scheme is
    a decision for the integrator, not for this wrapper.
    """
    return (
        current.scheme == target.scheme
        and current.host == target.host
        and current.port == target.port
    )


def _run_pipeline(
    body: Any,
    collection_path: str | None,
    policy: EffectivePolicy,
    hash_salt: str | bytes | None = None,
) -> Any:
    """Run the full canonical pipeline over a parsed response body.

    Canonical pipeline order (canonical-enforcement-spec.md section 4): row
    filters, tag filters, the relevance floor, the size ceiling, hidden fields,
    the allowedFields projection, masking, then the result limit. Filtering
    precedes field removal so a filter may reference a field the policy then
    hides, and the limit runs last so filtering never yields fewer rows than
    ``maxResults`` when more qualifying rows exist.

    Shared by the success and the 4xx/5xx paths, because an error payload is not
    a different kind of data: connector spec section 6 requires it to carry the
    same enforcement as a success payload, since it carries the same fields.
    """
    body = _filter_records_in_body(body, collection_path, policy)
    body = _strip_hidden_fields_from_body(body, policy)
    body = _project_allowed_fields_in_body(body, collection_path, policy)
    body = _apply_masking_to_body(body, policy, hash_salt)
    return _limit_collection(body, collection_path, policy)


class SecureHttpToolWrapper:
    """Enforces TOLAP policy around an httpx.Client.

    Usage:
        client = httpx.Client(base_url="https://api.fda.gov", transport=transport)
        wrapper = SecureHttpToolWrapper(options, client)
        body = wrapper.request(context, "GET", "/drug/event.json",
                               params={"limit": 5}, collection_path="results")

    Automatic redirect following is switched **off** for every request this wrapper
    issues, whatever the client was constructed with, and each hop is re-validated
    instead -- see :meth:`request`.
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

    def _validate_hop(
        self,
        method: str,
        path: str,
        payload: Any,
        policy: EffectivePolicy,
        *,
        object_name: str | None,
        target_row: Any,
        resource_fields: list[str] | None,
    ) -> AccessResult:
        """Run every pre-request check for one request, initial hop or redirect.

        Factored out of :meth:`request` so a redirect hop cannot be validated more
        weakly than the request that produced it: the identical function decides
        both. Connector spec section 6 requires a redirect to be "re-validated
        against the endpoint rules before being followed", and a 307/308 preserves
        the method and body, so the write checks have to be re-run too rather than
        just the path.

        The query string is cut before evaluation because policy patterns are
        written against paths, not URLs, so ``?`` parameters cannot smuggle a path
        past a glob.
        """
        policy_path = path.split("?", 1)[0]

        # Endpoint rules and, for a write method, the section 4 write checks. Both
        # halves run: an endpoint allow-list is not a write grant, and a write
        # permission does not make a path reachable.
        decision = validate_http_write(
            method,
            policy_path,
            payload,
            policy,
            object_name=object_name,
            target_row=target_row,
            resource_fields=resource_fields,
        )
        if not decision.allowed:
            return decision

        # allowedObjects/hiddenObjects on the HTTP path are honoured only when the
        # integrator names the object (connector spec section 6, last bullet). No
        # resource name is *derived* from the path -- guessing one would be
        # unspecified inference, and the spec is explicit that an author "MUST
        # express API restrictions as endpointRules". But a caller who does know
        # the resource behind a route should not have the control silently ignored,
        # which is what happened before: object_name was accepted, forwarded to the
        # write checks, and therefore consulted on a POST while a GET to the same
        # route skipped it entirely.
        #
        # Runs after the endpoint decision so a hidden endpoint keeps reporting
        # itself as such, and re-checks the write path's object rules with the
        # identical outcome rather than branching on the method.
        if object_name is not None:
            return validate_access(object_name, policy)

        return decision

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
        object_name: str | None = None,
        target_row: Any = TARGET_ROW_UNKNOWN,
        resource_fields: list[str] | None = None,
    ) -> Any:
        """Make an HTTP request with full pre/post enforcement.

        Returns the parsed JSON body with hidden-field stripping, allowed-field
        projection, masking, and result limits already applied, in the canonical
        pipeline order. Raises PermissionError if the policy denies the call
        before it leaves the process.

        A write method is additionally validated per connector spec section 4
        before the request leaves the process: the operation's permission
        (``POST``->``canInsert``, ``PUT``/``PATCH``->``canUpdate``,
        ``DELETE``->``canDelete``), the ``readOnly`` ceiling, ``object_name``
        against the object rules, every field in the ``json`` body against
        ``hiddenFields``/``readOnlyFields``/``allowedFields``, and the policy's row
        filters against ``target_row``. Method and permission must both agree:
        ``allowedMethods: ["POST"]`` says nothing about ``canInsert``.

        A ``PUT`` is treated as replacing the whole resource, so every field the
        policy protects is checked as though the body had named it -- omitting a
        ``readOnlyFields`` field from a replace is still an attempt to overwrite it.
        Supply ``resource_fields`` when the policy also sets ``allowedFields``.

        The response body runs the same post-execution pipeline as a read, because
        a write's response *is* a read of the data it returns (section 4.5). That
        includes a **4xx/5xx** body: an error payload carries the same fields as a
        success payload -- a validation error echoing a rejected value is the
        common leak -- so it is enforced and then raised as
        :class:`UpstreamHttpError` with the enforced body attached (section 6).

        A **redirect is never followed blind** (section 6). Automatic following is
        disabled for the underlying call regardless of how the client was built,
        and each hop's target is re-validated against the endpoint rules before it
        is requested. A cross-host redirect is refused outright, and the chain is
        bounded by :data:`MAX_REDIRECTS`.

        ``object_name`` is honoured on every method when supplied, not just on a
        write, so ``allowedObjects``/``hiddenObjects`` are usable over HTTP for an
        integrator who knows the resource behind a route. Nothing is inferred from
        the path itself.
        """
        ctx_result = self.validate_security_context(context)
        if not ctx_result.allowed:
            raise PermissionError(f"Access denied: {ctx_result.reason}")

        policy = context.effective_policy
        if not policy.permissions.can_query:
            raise PermissionError("Access denied: query not permitted")

        hop_result = self._validate_hop(
            method,
            path,
            json,
            policy,
            object_name=object_name,
            target_row=target_row,
            resource_fields=resource_fields,
        )
        if not hop_result.allowed:
            raise PermissionError(f"Access denied: {hop_result.reason}")

        # The redirect chain. `follow_redirects=False` is passed explicitly on
        # every hop: httpx's own default is False today, so the wrapper was safe
        # only by luck -- an integrator constructing
        # `httpx.Client(follow_redirects=True)`, which is common and reasonable,
        # silently bypassed every endpoint check on a 302. A per-request override
        # takes precedence over the client's setting, so the caller's choice cannot
        # reintroduce the bypass.
        hop_method = method
        hop_payload = json
        target: str | httpx.URL = path
        request_params = params
        for _ in range(MAX_REDIRECTS + 1):
            response = self._client.request(
                hop_method,
                target,
                params=request_params,
                json=hop_payload,
                headers=headers,
                follow_redirects=False,
            )
            if not response.has_redirect_location:
                break

            location = response.headers["location"]
            # Resolves a relative Location ("/admin/audit", "../v2/x") against the
            # URL actually requested, and leaves an absolute one alone.
            next_url = response.request.url.join(location)
            if not _same_origin(response.request.url, next_url):
                # A cross-origin redirect is refused rather than re-globbed. An
                # absolute URL to another host is outside the policy's frame of
                # reference entirely: `allowedEndpoints: ["/*"]` describes paths on
                # the source this policy was resolved for, and matching that glob
                # against a path on attacker.example would "permit" a host the
                # author never considered.
                raise PermissionError(
                    "Access denied: redirect crosses origin to "
                    f"{next_url.scheme}://{next_url.netloc.decode('ascii')}"
                )

            # 301/302/303 downgrade to GET and drop the body, as every browser and
            # HTTP client does; 307/308 preserve both. The downgraded method is
            # re-validated too, so the downgrade cannot smuggle a request past the
            # method rules in either direction.
            if response.status_code not in _METHOD_PRESERVING_REDIRECTS:
                hop_method = "GET"
                hop_payload = None

            hop_result = self._validate_hop(
                hop_method,
                next_url.path,
                hop_payload,
                policy,
                object_name=object_name,
                target_row=target_row,
                resource_fields=resource_fields,
            )
            if not hop_result.allowed:
                raise PermissionError(
                    f"Access denied: redirect target rejected: {hop_result.reason}"
                )

            target = next_url
            # The Location carries its own query string; re-appending the original
            # `params` would corrupt it.
            request_params = None
        else:
            # Exhausted the hop budget with a redirect still pending. Denied rather
            # than followed: /redirect-loop points at itself, and a wrapper that
            # trusts the transport's own limit spins for as many hops as that
            # client happens to allow.
            raise PermissionError(
                f"Access denied: too many redirects (limit {MAX_REDIRECTS})"
            )

        if response.is_success:
            return _run_pipeline(
                response.json(), collection_path, policy, self._options.hash_salt
            )

        # A 4xx/5xx body is enforced first and raised second. `raise_for_status` is
        # deliberately not used: it raises httpx.HTTPStatusError, and `.response`
        # on that exception hands the caller the raw payload with every
        # hiddenFields entry intact.
        try:
            error_body = _run_pipeline(
                response.json(), collection_path, policy, self._options.hash_salt
            )
        except ValueError:
            # Not JSON, so the pipeline cannot walk it and no field rule can be
            # applied. Withheld rather than passed through
            # (canonical-enforcement-spec.md section 5) -- the status code still
            # tells the caller what happened.
            error_body = None
        raise UpstreamHttpError(response.status_code, error_body, str(response.request.url))
