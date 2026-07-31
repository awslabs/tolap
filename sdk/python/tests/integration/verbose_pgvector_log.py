"""Verifies the `pgvector` kb filter renderer against real pgvector, with real vector search.

The third of six `kb` renderers to be exercised against a live engine, and the only one of the
remaining three that can be: Azure AI Search and Vertex AI Search need a paid subscription,
while pgvector is a PostgreSQL extension already present locally.

Two questions a fixture we wrote ourselves cannot answer:

1. **Does PostgreSQL accept the fragment?** The renderer emits a raw ``WHERE`` fragment for the
   caller to splice into a query it owns. A malformed fragment is a syntax error for every
   integrator, and our unit tests only compare it to a string we chose.
2. **Does it exclude anything once a real ANN search is involved?** This is the part that
   matters and the part a fixture structurally cannot reach. The filter has to survive being
   combined with ``ORDER BY embedding <=> query`` and ``LIMIT`` -- the shape every vector search
   actually takes.

The corpus is adversarial on purpose. Embeddings are chosen so the two ``secret`` chunks are the
**nearest neighbours** to the query vector, so an unfiltered top-2 search returns nothing but
secrets. A filter that silently matched nothing would therefore be obvious here, rather than
hiding behind a result set that happened to look plausible. That is exactly how the
OpenSearch ``.keyword`` fail-open stayed invisible: a denylist that excluded nothing still
returned documents.

Run against the local database (see docs/local-testing.md):

    python3 tests/integration/verbose_pgvector_log.py
"""

from __future__ import annotations

import sys
from typing import Any

import psycopg
from psycopg.rows import dict_row

from tolap_core.enforcement import filter_by_tags
from tolap_core.kb_filter import build_kb_filter
from tolap_core.kb_providers import KbProvider, render_kb_filter
from tolap_core.models import (
    EffectivePolicy,
    ObjectRules,
    PolicyPermissions,
    TagRules,
)

TABLE = "tolap_kb_chunks"
QUERY_VECTOR = "[1.0,0.0,0.0]"

#: Two public, two secret, one untagged -- mirroring the Bedrock and OpenSearch corpora so the
#: three verified `kb` backends are compared on the same data. The embeddings put both secret
#: chunks nearest the query vector.
CORPUS = [
    (1, "Q3 public roadmap", '{"classification":"public"}', "[0.9,0.1,0.0]"),
    (2, "Published financials", '{"classification":"public"}', "[0.8,0.2,0.0]"),
    (3, "Acquisition analysis", '{"classification":"secret"}', "[1.0,0.0,0.0]"),
    (4, "Margin breakdown", '{"classification":"secret"}', "[0.99,0.01,0.0]"),
    (5, "Untagged appendix", '{"other":"x"}', "[0.7,0.3,0.0]"),
]

FAILURES: list[str] = []


def heading(text: str) -> None:
    print(f"\n{'=' * 78}\n{text}\n{'=' * 78}")


def control(name: str, rule: str) -> None:
    print(f"\n--- {name}\n    policy: {rule}")


def check(claim: str, condition: bool) -> None:
    print(f"    {'OK  ' if condition else 'FAIL'} {claim}")
    if not condition:
        FAILURES.append(claim)


def policy(tag_rules: TagRules) -> EffectivePolicy:
    return EffectivePolicy(
        version="1.0",
        user_id="kb-user",
        tenant_id="kb-tenant",
        source_connection_id="kb:research:chunks",
        source_profiles=["pgvector-e2e"],
        permissions=PolicyPermissions(can_query=True),
        object_rules=ObjectRules(tag_rules=tag_rules),
    )


def fragment(tag_rules: TagRules) -> str | None:
    result = build_kb_filter(policy(tag_rules), metadata_keys=["classification"])
    return render_kb_filter(result, KbProvider.pgvector).filter


def seed(conn: psycopg.Connection) -> None:
    with conn.cursor() as cur:
        cur.execute("CREATE EXTENSION IF NOT EXISTS vector")
        cur.execute(f"DROP TABLE IF EXISTS {TABLE}")
        cur.execute(
            f"""CREATE TABLE {TABLE} (
                   id int PRIMARY KEY,
                   content text NOT NULL,
                   metadata jsonb NOT NULL,
                   embedding vector(3) NOT NULL)"""
        )
        cur.executemany(
            f"INSERT INTO {TABLE} VALUES (%s, %s, %s::jsonb, %s::vector)", CORPUS
        )
    conn.commit()


def search(conn: psycopg.Connection, where: str | None, limit: int | None = None) -> list[dict]:
    """An ANN search with the policy fragment spliced in, exactly as an integrator would.

    The fragment is interpolated rather than parameterised because that is what the renderer is
    *for*: it emits SQL text for a caller assembling a query it owns. Every value inside it came
    from a signed policy and was quote-escaped by the renderer.
    """
    # `metadata` is selected as jsonb, NOT via `->>`. That cast turns a JSON number into the
    # text "3", which would hand the post pass a *string* tag the database never stored -- an
    # earlier draft did exactly that and manufactured a pushdown/post-pass disagreement that
    # existed only in the test harness. `classification` is derived separately for display.
    sql = f"SELECT id, content, metadata FROM {TABLE}"
    if where:
        sql += f" WHERE {where}"
    sql += f" ORDER BY embedding <=> '{QUERY_VECTOR}'"
    if limit is not None:
        sql += f" LIMIT {limit}"
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(sql)  # noqa: S608 - fragment is renderer output over a signed policy
        rows = []
        for row in cur.fetchall():
            record = {"id": row["id"], "content": row["content"], **row["metadata"]}
            rows.append(record)
        return rows


def show(label: str, rows: list[dict]) -> None:
    print(f"    {label}: {len(rows)} row(s)")
    for row in rows:
        value = row.get("classification")
        print(f"        id={row['id']} classification={'(untagged)' if value is None else repr(value)}")


def transcribe(conn: psycopg.Connection) -> None:
    heading("pgvector: the adversarial baseline -- secrets are the NEAREST neighbours")
    nearest = search(conn, None)
    show("unfiltered, by distance", nearest)
    check(
        "the two nearest chunks are both secret, so a filter that excluded nothing would be "
        "obvious rather than hidden behind a plausible-looking result set",
        [r.get("classification") for r in nearest[:2]] == ["secret", "secret"],
    )
    top2 = search(conn, None, limit=2)
    check(
        "an unfiltered top-2 ANN search returns ONLY secret chunks -- this is what the pushdown "
        "has to prevent",
        all(r.get("classification") == "secret" for r in top2),
    )

    heading("pgvector: the generated fragment, spliced into a real ANN query")
    control("deniedTags: [secret]", "tagRules.deniedTags=[secret]")
    deny = fragment(TagRules(denied_tags=["secret"]))
    print(f"    fragment: {deny}")
    denied = search(conn, deny, limit=2)
    show("top 2 with the filter", denied)
    check("PostgreSQL ACCEPTED the fragment (no syntax error)", deny is not None)
    check(
        "no secret chunk survived, even though both were nearer than every permitted chunk",
        all(r.get("classification") != "secret" for r in denied),
    )
    check("permitted chunks were still returned -- the filter excluded, it did not match nothing",
          len(denied) > 0)

    control("allowedTags: [public]", "tagRules.allowedTags=[public]")
    allow = fragment(TagRules(allowed_tags=["public"]))
    print(f"    fragment: {allow}")
    allowed = search(conn, allow, limit=2)
    show("top 2 with the filter", allowed)
    check("only public chunks are returned",
          bool(allowed) and all(r.get("classification") == "public" for r in allowed))

    heading("pgvector: untagged chunks, where the two directions differ")
    control("deniedTags MUST KEEP an untagged chunk", "spec section 7")
    denied_all = search(conn, fragment(TagRules(denied_tags=["secret"])))
    show("all rows", denied_all)
    # `NOT (... ?| ...)` alone would drop this row: the operator yields NULL for an absent key
    # and NOT NULL is not true. The renderer's `IS NULL` arm is what restores it.
    check(
        "the untagged chunk survives a denylist -- it carries no denied tag, so nothing denies it",
        5 in {r["id"] for r in denied_all},
    )

    control("allowedTags MUST DROP an untagged chunk", "spec section 7")
    allowed_all = search(conn, fragment(TagRules(allowed_tags=["public"])))
    show("all rows", allowed_all)
    check(
        "the untagged chunk is dropped by an allowlist -- it carries no proof of allowance",
        5 not in {r["id"] for r in allowed_all},
    )

    heading("pgvector: the pushdown and the normative post pass must agree")
    for label, tag_rules in [
        ("deniedTags=[secret]", TagRules(denied_tags=["secret"])),
        ("allowedTags=[public]", TagRules(allowed_tags=["public"])),
    ]:
        control(label, "pushdown vs filter_by_tags over the same corpus")
        pushed = search(conn, fragment(tag_rules))
        everything = search(conn, None)
        post_only = filter_by_tags(everything, policy(tag_rules))
        print(f"    pushdown : ids={sorted(r['id'] for r in pushed)}")
        print(f"    post-pass: ids={sorted(r['id'] for r in post_only)}")
        check(
            "identical verdicts -- the property that makes a pushdown safe rather than merely "
            "faster, and the one a stricter-than-normative filter would break",
            sorted(r["id"] for r in pushed) == sorted(r["id"] for r in post_only),
        )

    heading("pgvector: numeric metadata is deliberately NOT matched")
    control("classification is the NUMBER 3, denied tag is the string '3'", "deniedTags=['3']")
    with conn.cursor() as cur:
        cur.execute(
            f"INSERT INTO {TABLE} VALUES (6, 'numeric level', '{{\"classification\":3}}'::jsonb, "
            "'[0.5,0.5,0.0]'::vector)"
        )
    conn.commit()
    numeric = fragment(TagRules(denied_tags=["3"]))
    print(f"    fragment: {numeric}")
    kept = {r["id"] for r in search(conn, numeric)}
    post = {
        r["id"]
        for r in filter_by_tags(search(conn, None), policy(TagRules(denied_tags=["3"])))
    }
    print(f"    pushdown keeps id 6: {6 in kept}    post-pass keeps id 6: {6 in post}")
    # Tag harvesting collects only strings: stringifying a non-string differs per language
    # (`str(True)` is "True" in Python, "true" in JavaScript) and a confidentiality decision must
    # not depend on host formatting. So a numeric value carries no tag and a denylist keeps it.
    # A `->>`-cast arm was tried and reverted for making the pushdown STRICTER than the post pass.
    check(
        "the pushdown and post pass agree that a numeric value carries no tag -- matching it "
        "would make the pushdown stricter than the normative pass, a divergence in the other "
        "direction",
        (6 in kept) == (6 in post),
    )
    with conn.cursor() as cur:
        cur.execute(f"DELETE FROM {TABLE} WHERE id = 6")
    conn.commit()

    heading("pgvector: a refused clause is reported, never approximated")
    control("metadata key that is not a plain identifier", "key = 'bad-key; DROP TABLE'")
    result = build_kb_filter(
        policy(TagRules(denied_tags=["secret"])), metadata_keys=["bad-key; DROP TABLE"]
    )
    rendered = render_kb_filter(result, KbProvider.pgvector)
    print(f"    filter        : {rendered.filter}")
    print(f"    unpushedRules : {len(rendered.unpushed_rules)}")
    check(
        "an unexpected identifier is REFUSED rather than quoted into existence, and reported as "
        "unpushed so the post pass still enforces the rule",
        rendered.filter is None,
    )


def main() -> int:
    try:
        conn = psycopg.connect("dbname=tolap_integration_test")
    except psycopg.Error as exc:
        print(f"PostgreSQL not reachable: {exc}", file=sys.stderr)
        return 2

    with conn:
        with conn.cursor() as cur:
            cur.execute("SELECT version()")
            version = cur.fetchone()[0]
            cur.execute("CREATE EXTENSION IF NOT EXISTS vector")
            conn.commit()
            cur.execute("SELECT extversion FROM pg_extension WHERE extname = 'vector'")
            row = cur.fetchone()
            vector_version = row[0] if row else "unavailable"

        print(f"Engine  : {version.split(' on ')[0]}")
        print(f"pgvector: {vector_version}")
        print("Source  : sdk/python/tests/integration/verbose_pgvector_log.py")
        print(
            "\nEvery fragment below was produced by the shipped renderer and spliced into a real\n"
            "ANN query. The corpus is adversarial: the secret chunks are the NEAREST neighbours,\n"
            "so a filter that enforced nothing could not hide. Claims are checked as they print;\n"
            "a FAIL exits non-zero, so a broken transcript cannot be recorded as evidence."
        )

        seed(conn)
        try:
            transcribe(conn)
        finally:
            with conn.cursor() as cur:
                cur.execute(f"DROP TABLE IF EXISTS {TABLE}")
            conn.commit()

    print(f"\n{'=' * 78}")
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} claim(s) did not hold")
        for failure in FAILURES:
            print(f"  - {failure}")
        return 1
    print("All claims held against live PostgreSQL + pgvector.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
