# Local-engine and `api` enforcement evidence

Test output from the engines that run on a developer machine and in CI — PostgreSQL, MySQL, and a
real HTTP server on loopback — plus the verbose transcripts that show *what enforcement did* rather
than only that an assertion held. The AWS-backed evidence (S3, Athena, Bedrock, OpenSearch,
Elasticsearch) is in [`../aws/`](../aws/).

## Why a transcript and not just a test count

`53 passed` proves 53 assertions held. It does not show the SQL that was sent, the rows the engine
returned, or which values a masking rule rewrote — so a reviewer has to trust the test names. The
`verbose-*` files print the policy rule, the exact statement, the rows before, and the rows after,
for every control.

Each transcript **checks as it prints** and exits non-zero on a false claim, so a broken transcript
cannot be recorded as passing evidence. That is not decoration: the first MySQL run produced two
`FAIL` lines and caught a real defect (below).

| File | Contents |
| --- | --- |
| `verbose-enforcement-postgres.txt` | 26 controls, real PostgreSQL 17.5 |
| `verbose-enforcement-mysql.txt` | 26 controls, real MySQL 9.6 |
| `verbose-enforcement-api.txt` | 24 controls, real HTTP server over a socket |
| `postgres-run-python.txt` | `pytest -v`, 53 tests |
| `mysql-run-python.txt` | `pytest -v`, 70 tests |
| `openfda-live-run-python.txt` | 3 real GETs against `api.fda.gov` |
| `verbose-pgvector.txt` | 12 checks, real PostgreSQL 17 + pgvector 0.8.1, real ANN search |

The `api` transcript runs against `tools/test-api/server.py` on loopback rather than
`httpx.MockTransport`. A mock never puts bytes on a socket, so it cannot reach a real status code,
a server-framed body, a redirect, or query-string handling.

## What the transcripts found

Neither of these was visible in a `PASSED` line.

### A dialect mismatch that failed open (MySQL)

The first MySQL run returned the `deleted` row that a `status != deleted` filter was supposed to
exclude. Cause: the transcript called `rewrite_query()` without a `dialect`, so it got Postgres
identifier quoting. In MySQL `"status"` is a **string literal**, not a column reference, so
`"status" <> 'deleted'` is `'status' <> 'deleted'` — always true, every row returned. The engine
accepted the SQL and reported success.

This was a bug in the transcript, not the SDK; the SDK renders `` `status` `` correctly when told
the dialect. But it is the exact shape of a real integrator error, it fails **open**, and it is
silent — so the transcript now asserts identifier quoting matches the engine before anything else
runs, and names the consequence. Mutation-verified: removing the `dialect` argument reproduces the
two failures.

### `maxResults` silently not enforced (`api`, all three SDKs)

A policy with `limits.maxResults: 1` against a body shaped `{"results": [...]}` returned **every
record the upstream sent**. Fixed in .NET, Python and TypeScript.

`collectionPath` — the optional argument naming the record array inside an envelope — was passed by
**every** existing test of `maxResults`, because that is what the implementation wanted. The branch
taken when it is omitted was never executed by any test in any SDK. An integrator has no reason to
pass it: it is optional, the spec says the pipeline runs "over the body, walking nested
structures," and nothing warns you.

What made it dangerous rather than merely surprising is that the three record-level controls
disagreed on the same missing argument:

| Control | `collectionPath` omitted | Direction |
| --- | --- | --- |
| `allowedFields` | returned `{}` | fail-closed |
| `rowFilters` | returned `None` | fail-closed |
| **`limits.maxResults`** | **every record** | **fail-OPEN** |

Each had passing tests. None compared them, so the disagreement was invisible — and the outlier was
the unsafe one.

The fix enforces on an unambiguously-identifiable collection and **raises**
`UnenforceableResultError` (a `PermissionError` subclass, so callers already denying on permission
errors fail closed) when a body has two candidate collections. It refuses to guess: enforcing a
limit on the wrong array would look like success.

Regression coverage is a **permutation grid** — 5 record controls × {argument given, omitted} —
parameterised so a control added later cannot skip the without-argument half. Under the restored
bug it fails exactly one cell and the other nine stay green. Line coverage would have called this
path covered, because tests for *other* controls executed it; coverage counts lines reached, not
argument combinations exercised. The pattern is written up in
[`../../docs/testing-antipatterns.md`](../../docs/testing-antipatterns.md).

### `pgvector` verified, and Redshift needed no cluster

`pgvector` is the fourth of six `kb` renderers to be exercised against a live engine, and the
only one of the remaining three that could be — Azure AI Search and Vertex AI Search need paid
subscriptions, while pgvector is a PostgreSQL extension.

The corpus is adversarial on purpose: embeddings place both `secret` chunks as the **nearest
neighbours**, so an unfiltered top-2 ANN search returns nothing but secrets. That matters because
of how the OpenSearch fail-open hid — a denylist that excluded nothing still returned documents,
which looked fine. Here it could not. The transcript shows the generated `WHERE` fragment spliced
into `ORDER BY embedding <=> query LIMIT 2`, both secrets excluded, and the pushdown reaching the
same verdict as `filter_by_tags` on every case including the untagged chunk. Mutation-verified:
breaking the fragment so it matches nothing fails 4 of the 12 checks.

**Redshift needed no cluster, because there is no Redshift dialect.** An earlier version of this
file said "the rewriter carries the dialect and has unit coverage" — that was wrong. The
`SqlDialect` enum is `ansi`, `postgres`, `trino`, `mysql`, `sqlserver`; Redshift is a Postgres
fork and uses the `postgres` profile, which is already exercised against real PostgreSQL 17. The
generated SQL is byte-identical under both `postgres` and `ansi`:

```sql
SELECT id, region FROM patients WHERE ("region" <> 'us-west' OR "region" IS NULL) LIMIT 2
```

Double-quoted identifiers and `LIMIT n` are exactly what Redshift accepts. A cluster would have
re-verified the Postgres profile at real standing cost and told us nothing new. What *would* be
worth testing is a Redshift-specific behaviour the rewriter does not currently model — and it
models none, which is the honest reason this is not a gap rather than an untested claim.

## Reproducing

Both engines must be reachable; the suites skip cleanly when they are not.

```
cd sdk/python
python3 -m pytest tests/integration/test_postgres_query_rewriting.py -v
python3 -m pytest tests/integration/test_mysql_scenarios.py tests/integration/test_dialect_query_rewriting.py -v

python3 tests/integration/verbose_enforcement_log.py postgres
python3 tests/integration/verbose_enforcement_log.py mysql
python3 tests/integration/verbose_api_log.py
python3 tests/integration/verbose_pgvector_log.py   # needs CREATE EXTENSION vector
```

`TOLAP_TEST_LIVE=1` re-records `fixtures/api/openfda/*.json` from `api.fda.gov` as a side effect.
The recordings were reverted after the run captured here — refreshing them was not the intent, and
committing drifted fixtures alongside unrelated work would make the diff lie about what changed.

## Not covered here

- **Two of six `kb` renderers.** `azure_ai_search` and `vertex_ai_search` remain
  `fromGrammar` — written from the published grammar, never accepted by the service. Treat that as
  unproven rather than probably-fine: promoting `opensearch` and `elasticsearch` out of that state
  immediately exposed a fail-open (see [`../aws/`](../aws/)).
- **The verbose transcripts are Python-only.** The *assertions* they narrate run in all three SDKs;
  what is single-SDK is the narration.
