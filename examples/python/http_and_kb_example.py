"""HTTP endpoints and knowledge bases: the two non-SQL sources, and policies scoped to a source.

The framework examples all read a table. Two other kinds of source get their own rules, and this
script shows both, enforced by the SDK rather than described:

* **An HTTP API**, called through ``SecureHttpToolWrapper``. ``objectRules.endpointRules`` decides
  which paths and methods may be requested, *before* the request leaves the process, and the
  field and row rules still apply to the JSON that comes back.
* **A knowledge base.** ``tagRules`` are turned into a metadata filter the provider applies at
  retrieval (``build_kb_filter`` / ``render_kb_filter``), and the post pass then re-applies them,
  together with ``minSimilarityScore``, over whatever the provider returned. The pushdown is an
  optimisation; the post pass is the enforcement.

Both policies carry ``sourcePatterns``, so each applies only to the sources it names. One identity
holds both, and resolution picks per source: the API policy for the API, the KB policy for the KB,
and nothing at all -- deny-all -- for a source neither names.

Run it::

    python3 examples/python/http_and_kb_example.py

Deliberately mirrors ``examples/typescript/http-and-kb-example.ts`` and
``examples/dotnet/HttpAndKbExample.cs`` -- same policies, same fake API, same chunks,
byte-identical printed output. A divergence between the languages then shows up as a different
result rather than hiding behind separately-written expectations.
"""

from __future__ import annotations

from typing import Any, NamedTuple

import httpx

from tolap_core import (
    Assignee,
    AssigneeType,
    AssignmentScope,
    AuditInfo,
    EffectivePolicy,
    EndpointRules,
    FieldRules,
    FilterOperator,
    KbFilterOp,
    KbProvider,
    MaskType,
    MaskingRule,
    ObjectRules,
    PolicyAssignment,
    PolicyDefinition,
    PolicyLimits,
    PolicyPermissions,
    RowFilter,
    SecurityContext,
    TagRules,
    build_kb_filter,
    build_security_context,
    render_kb_filter,
    resolve,
    sign_context,
)
from tolap_mcp.http_wrapper import SecureHttpToolWrapper
from tolap_mcp.options import SecureMcpServerOptions
from tolap_mcp.wrapper import SecureMcpToolWrapper

SIGNING_KEY = "example-signing-key-do-not-use-in-production"

USER = "analyst-001"
TENANT = "hospital-001"

API_SOURCE = "api:clinical:patients"
KB_SOURCE = "kb:clinical:guidelines"
#: An API source neither policy names. Same category, same endpoint, different namespace.
UNMATCHED_SOURCE = "api:research:patients"

BASE_URL = "https://clinical-api.example"

#: What the API returns for ``GET /patients``: more rows and more fields than the policy permits.
FAKE_ROWS: list[dict[str, Any]] = [
    {"id": 1, "name": "Alice Nguyen", "region": "us-east", "ssn": "111-22-3333", "dob": "1979-04-12"},
    {"id": 2, "name": "Bruno Sato", "region": "us-east", "ssn": "222-33-4444", "dob": "1985-11-02"},
    {"id": 3, "name": "Carol Diaz", "region": "us-east", "ssn": "333-44-5555", "dob": "1990-01-30"},
    {"id": 4, "name": "Dan Meyer", "region": "eu-west", "ssn": "444-55-6666", "dob": "1972-08-19"},
]

#: The order columns are printed in, so the output does not depend on a runtime's map ordering.
COLUMNS = ["id", "name", "region", "ssn", "dob"]


class Chunk(NamedTuple):
    id: str
    title: str
    tags: list[str]
    #: A second classification the provider does not index; ``None`` when absent.
    classification: str | None
    score: float


#: What the knowledge base holds. The provider indexes ``tags`` only; ``classification`` is
#: metadata it stores but was never asked to filter on.
CHUNKS = [
    Chunk("doc-1", "Sepsis screening protocol", ["clinical"], None, 0.91),
    Chunk("doc-2", "Ward 4 incident review", ["clinical", "restricted"], None, 0.88),
    Chunk("doc-3", "Visitor hours", ["public"], None, 0.42),
    Chunk("doc-4", "Staff rota, week 39", ["hr"], None, 0.80),
    Chunk("doc-5", "Medication error log", ["clinical"], "restricted", 0.86),
    Chunk("doc-6", "Hand hygiene guideline", ["public"], None, 0.77),
]


def _audit(reason: str) -> AuditInfo:
    return AuditInfo(granted_by="admin-jane-doe", granted_at="2026-09-01T09:00:00Z", reason=reason)


def api_definition() -> PolicyDefinition:
    """The API policy. Applies only to ``api:clinical:*``.

    ``allowedMethods`` admits GET and POST, and ``readOnly`` is false, so a POST passes the
    endpoint check -- and is still refused, because no ``canInsert`` is granted. An endpoint
    allow-list is not a write grant.
    """
    return PolicyDefinition(
        version="1.0",
        name="patients-api-reader",
        permissions=PolicyPermissions(can_query=True, read_only=False),
        priority=10,
        source_patterns=["api:clinical:*"],
        object_rules=ObjectRules(
            endpoint_rules=EndpointRules(
                allowed_endpoints=["/patients", "/patients/*"],
                hidden_endpoints=["/patients/*/notes"],
                allowed_methods=["GET", "POST"],
            ),
            field_rules=FieldRules(
                hidden_fields=["ssn"],
                masked_fields=[MaskingRule(field="dob", mask_type=MaskType.redact)],
            ),
            row_filters=[
                RowFilter(field="region", operator=FilterOperator.equals, value="us-east")
            ],
        ),
        limits=PolicyLimits(max_results=2),
    )


def kb_definition() -> PolicyDefinition:
    """The KB policy. Applies only to ``kb:clinical:*``."""
    return PolicyDefinition(
        version="1.0",
        name="clinical-kb-reader",
        permissions=PolicyPermissions(can_query=True, read_only=True),
        priority=10,
        source_patterns=["kb:clinical:*"],
        object_rules=ObjectRules(
            tag_rules=TagRules(allowed_tags=["clinical", "public"], denied_tags=["restricted"]),
        ),
        limits=PolicyLimits(max_results=5, min_similarity_score=0.5),
    )


DEFINITIONS = [api_definition(), kb_definition()]


def resolve_for(source: str) -> EffectivePolicy:
    """Resolve exactly as a store would: the same identity and assignments, one source.

    ``sourcePatterns`` is applied before the merge, so a definition that does not name the
    source contributes nothing. When none does, the set is empty and resolution returns deny-all.
    """
    assignments = [
        PolicyAssignment(
            version="1.0",
            policy_name=d.name,
            assignee=Assignee(type=AssigneeType.user, identifier=USER),
            scope=AssignmentScope(tenant_id=TENANT),
            active=True,
            audit=_audit(f"granted for the HTTP and KB example: {d.name}"),
        )
        for d in DEFINITIONS
    ]
    return resolve(
        USER,
        TENANT,
        source,
        assignments,
        {d.name: d for d in DEFINITIONS},
        lambda _: [],
        lambda _: [],
    )


def signed_context(source: str) -> SecurityContext:
    return sign_context(build_security_context(USER, TENANT, [resolve_for(source)]), SIGNING_KEY)


# --------------------------------------------------------------------------------------------
# The HTTP API.
# --------------------------------------------------------------------------------------------


class FakeApi:
    """Stands in for the clinical API. Returns everything, and counts what reached it."""

    def __init__(self) -> None:
        self.hits: list[str] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.hits.append(f"{request.method} {request.url.path}")
        if request.method == "GET" and request.url.path == "/patients":
            return httpx.Response(200, json={"results": [dict(row) for row in FAKE_ROWS]})
        return httpx.Response(200, json={"results": []})

    def client(self) -> httpx.Client:
        return httpx.Client(base_url=BASE_URL, transport=httpx.MockTransport(self.handle))


class HttpCall(NamedTuple):
    allowed: bool
    reason: str
    rows: list[dict[str, Any]] | None


def call_api(api: FakeApi, context: SecurityContext, method: str, path: str) -> HttpCall:
    """One request through the wrapper. A refusal is raised before the request is sent."""
    body = {"name": "Eve Park", "region": "us-east"} if method == "POST" else None
    with api.client() as client:
        http = SecureHttpToolWrapper(SecureMcpServerOptions(signing_key=SIGNING_KEY), client)
        try:
            response = http.request(context, method, path, json=body, collection_path="results")
        except PermissionError as denied:
            return HttpCall(False, str(denied).removeprefix("Access denied: "), None)
    return HttpCall(True, "", response["results"])


#: The requests the agent makes, in order.
REQUESTS = [
    ("GET", "/patients"),
    ("GET", "/patients/1/notes"),
    ("GET", "/billing/invoices"),
    ("DELETE", "/patients/1"),
    ("POST", "/patients"),
]


# --------------------------------------------------------------------------------------------
# The knowledge base.
# --------------------------------------------------------------------------------------------


def fake_kb_retrieve(clauses: list[Any]) -> list[dict[str, Any]]:
    """Stands in for the provider. Applies the pushed-down clauses to ``tags``, and only there.

    A chunk passes ``notIn`` when none of its tags is listed, and ``in`` when at least one is --
    the list-attribute semantics of the providers the renderers target. It never looks at
    ``classification``, because it was never asked to.
    """
    retrieved = []
    for chunk in CHUNKS:
        tags = {tag.lower() for tag in chunk.tags}
        keep = True
        for clause in clauses:
            listed = bool(tags & set(clause.values))
            if (clause.op is KbFilterOp.in_ and not listed) or (
                clause.op is KbFilterOp.not_in and listed
            ):
                keep = False
        if keep:
            record: dict[str, Any] = {"id": chunk.id, "title": chunk.title, "tags": list(chunk.tags)}
            if chunk.classification is not None:
                record["classification"] = chunk.classification
            record["score"] = chunk.score
            retrieved.append(record)
    return retrieved


def to_json(value: Any) -> str:
    """Compact JSON, written out by hand so every language prints the same bytes."""
    if isinstance(value, dict):
        return "{" + ",".join(f'"{k}":{to_json(v)}' for k, v in value.items()) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(to_json(v) for v in value) + "]"
    return f'"{value}"'


# --------------------------------------------------------------------------------------------
# Printing. Every line below is byte-identical to the TypeScript and .NET examples.
# --------------------------------------------------------------------------------------------

LABEL_WIDTH = 24
VERDICT_WIDTH = 8
SOURCE_WIDTH = 26
PROFILE_WIDTH = 22


def _access(label: str, allowed: bool, detail: str = "") -> str:
    verdict = "ALLOW" if allowed else "DENY"
    return f"  {label:<{LABEL_WIDTH}}{verdict:<{VERDICT_WIDTH}}{detail}".rstrip()


def _rule(title: str) -> str:
    return f"--- {title} " + "-" * max(0, 70 - 5 - len(title))


def _format_row(row: dict[str, Any]) -> str:
    return "  ".join(f"{column}={row[column]}" for column in COLUMNS if column in row)


def _op(op: KbFilterOp) -> str:
    return "in" if op is KbFilterOp.in_ else "notIn"


#: Why the post pass dropped a chunk the provider returned. Printed only for a chunk the SDK
#: actually dropped; ``main`` refuses to run if the SDK's drops differ from these.
POST_PASS_DROPS = {
    "doc-3": "score 0.42 is below minSimilarityScore 0.5",
    "doc-5": "classification restricted, a key the provider never saw",
}


def main() -> None:
    print("=" * 70)
    print("HTTP endpoints and knowledge bases: one identity, three sources")
    print("=" * 70)
    print()
    print(f"{USER} holds two policy definitions. Each carries sourcePatterns, so it")
    print("applies only to the sources it names:")
    for definition in DEFINITIONS:
        patterns = ", ".join(definition.source_patterns or [])
        print(f"    {definition.name:<{PROFILE_WIDTH}}sourcePatterns [{patterns}]")

    # ---------------------------------------------------------------- sourcePatterns
    print()
    print(_rule("sourcePatterns: one identity resolved for three sources"))
    for source in (API_SOURCE, KB_SOURCE, UNMATCHED_SOURCE):
        policy = resolve_for(source)
        profiles = ", ".join(policy.source_profiles) or "(none)"
        can_query = "true" if policy.permissions.can_query else "false"
        print(f"  {source:<{SOURCE_WIDTH}}{profiles:<{PROFILE_WIDTH}}canQuery={can_query}")
    print()
    print(f"{UNMATCHED_SOURCE} matches neither pattern, so nothing resolves and the")
    print("result is deny-all -- not the API policy borrowed from a similar name.")

    # ---------------------------------------------------------------- HTTP
    api = FakeApi()
    context = signed_context(API_SOURCE)

    print()
    print(_rule(f"endpointRules through the HTTP wrapper ({API_SOURCE})"))
    print(f"The fake API returns all {len(FAKE_ROWS)} patients, with ssn and dob, for GET /patients.")
    print("allowedEndpoints [/patients, /patients/*], hiddenEndpoints [/patients/*/notes],")
    print("allowedMethods [GET, POST], no canInsert:")
    print()

    rows: list[dict[str, Any]] | None = None
    for method, path in REQUESTS:
        call = call_api(api, context, method, path)
        print(_access(f"{method} {path}", call.allowed, call.reason))
        if call.allowed:
            rows = call.rows

    if api.hits != ["GET /patients"]:
        raise SystemExit(f"A REFUSED REQUEST REACHED THE API. It saw: {api.hits}")
    if rows is None or any("ssn" in row for row in rows):
        raise SystemExit("ssn LEAKED. A permitted request must still meet the field rules.")

    print()
    print(f"The fake API was reached {len(api.hits)} time. The four refused requests never")
    print("left the process. POST passed the endpoint rules and was refused by the")
    print("missing canInsert: an endpoint allow-list is not a write grant.")
    print()
    print("GET /patients, after the row, field and limit rules:")
    for row in rows:
        print("    " + _format_row(row))

    print()
    print(f"The same GET /patients under a context resolved for {UNMATCHED_SOURCE}:")
    unmatched = call_api(api, signed_context(UNMATCHED_SOURCE), "GET", "/patients")
    print(_access("GET /patients", unmatched.allowed, unmatched.reason))
    if unmatched.allowed or len(api.hits) != 1:
        raise SystemExit("THE UNMATCHED SOURCE WAS SERVED. sourcePatterns must scope the policy.")

    # ---------------------------------------------------------------- KB
    kb_policy = resolve_for(KB_SOURCE)
    kb_filter = build_kb_filter(kb_policy, metadata_keys=["tags"])
    rendered = render_kb_filter(kb_filter, KbProvider.bedrock)

    print()
    print(_rule(f"tagRules on a knowledge base ({KB_SOURCE})"))
    print("allowedTags [clinical, public], deniedTags [restricted], minSimilarityScore 0.5.")
    print()
    print('The filter built from the policy for the metadata key "tags":')
    for clause in kb_filter.clauses:
        print(f"    {clause.key} {_op(clause.op)} [{', '.join(clause.values)}]")
    print("Rendered for Bedrock:")
    print("    " + to_json(rendered.filter))
    unpushed = ", ".join(rule.rule for rule in kb_filter.unpushed_rules) or "none"
    print(f"Unpushed rules: {unpushed}")

    print()
    print(f"The fake KB holds {len(CHUNKS)} chunks and filters on tags only:")
    for chunk in CHUNKS:
        extra = f"  classification={chunk.classification}" if chunk.classification else ""
        print(f"  {chunk.id}  {chunk.title:<28}score={chunk.score:.2f}  tags={','.join(chunk.tags)}{extra}")

    retrieved = fake_kb_retrieve(kb_filter.clauses)
    retrieved_ids = [record["id"] for record in retrieved]
    print()
    print(f"The provider returned {len(retrieved)} of {len(CHUNKS)}: {', '.join(retrieved_ids)}")

    kb_context = signed_context(KB_SOURCE)
    wrapper = SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=SIGNING_KEY))
    decision = wrapper.pre_execute(kb_context, "search_guidelines")
    if not decision.allowed:
        raise SystemExit(f"THE KB SEARCH WAS REFUSED: {decision.reason}")
    enforced = wrapper.post_execute(kb_context, retrieved)
    kept_ids = [record["id"] for record in enforced]

    dropped = [doc_id for doc_id in retrieved_ids if doc_id not in kept_ids]
    if sorted(dropped) != sorted(POST_PASS_DROPS):
        raise SystemExit(f"THE POST PASS DROPPED {dropped}, expected {sorted(POST_PASS_DROPS)}.")

    print("The post pass, over what the provider returned:")
    for doc_id in retrieved_ids:
        if doc_id in kept_ids:
            print(f"  {doc_id}  KEEP")
        else:
            print(f"  {doc_id}  DROP  {POST_PASS_DROPS[doc_id]}")

    print()
    print("The pushdown removed doc-2 (restricted) and doc-4 (hr) at the provider, so")
    print("they were never retrieved. doc-5 carries restricted under a key the provider")
    print("does not filter on, and the post pass caught it. The pushdown is an")
    print("optimisation; the post pass is the enforcement.")

    print()
    print("=" * 70)
    print("One identity, one set of assignments. sourcePatterns picked the policy per")
    print("source, endpointRules refused requests before they were sent, and tagRules")
    print("filtered the knowledge base twice: at the provider, then in the SDK.")
    print("=" * 70)


if __name__ == "__main__":
    main()
