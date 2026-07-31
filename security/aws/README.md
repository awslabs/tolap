# AWS-backed integration test results

Enforcement tested against **real AWS services**, not fixtures. Run output is committed so
the findings below can be checked against what the tests actually did.

Account `<ACCOUNT_ID>` (Isengard sandbox), `us-east-1`, **2026-07-30**.

The account number is redacted rather than recorded. The repository is private today, so this
is not a disclosure fix — it is so that flipping visibility later needs no history rewrite.
Everything needed to interpret or reproduce the runs (sandbox, region, date, KB id) is here.

## Why these exist

Before this, per-category integration coverage was uneven:

| Category | Backend under test | Status before |
| --- | --- | --- |
| `db` | real Postgres + MySQL | well covered |
| `api` | real HTTP socket (`tools/test-api/server.py`) + recorded openFDA | well covered |
| `kb` | hand-built dicts with a `tags` list | **never touched a vector store** |
| `storage` | — | **no integration test existed at all** |

All three gaps are now closed against real services -- S3 for `storage`, Bedrock Knowledge
Bases for `kb`, Athena (the `trino` dialect) for the `db` engines the rewriter claimed to
support but never executed against -- and each is covered **in all three SDKs**:

| Category | Backend | Python | .NET | TypeScript |
| --- | --- | --: | --: | --: |
| `storage` | S3 | 23 | 23 | 23 |
| `db` | Athena / Trino | 12 | 12 | 12 |
| `kb` | Bedrock Knowledge Bases | 8 | 8 | 8 |

**129 AWS-backed tests.** Single-SDK coverage would have been the weaker claim: TOLAP's
guarantee is that one policy behaves identically in each, so a suite existing in one SDK
cannot demonstrate it. Porting earned its keep immediately -- see "What porting found".

Several spec requirements are **unprovable against fixtures** -- they are assertions about
what a real service does, or does not do -- and they are the reason this work was worth doing
rather than adding more unit tests.

## Findings

### 1. A denied prefix never reaches the provider — confirmed

connector-spec §8 requires the caller's requested prefix to be validated *before* the
provider call, "otherwise an unauthorized `list` is issued and merely filtered on return,
which is slower and records the request in the provider's audit log as though it were
authorized."

That is an assertion about a call's **absence**. No fixture can make it: a wrapper that lists
everything and discards denied rows returns exactly what one that never asked returns. The
test counts botocore `before-call` events and asserts zero `ListObjectsV2` for a denied
prefix — with a paired control proving the permitted prefix *does* call, so the denial test
cannot pass vacuously.

**Result:** holds for both `allowedObjects` misses and `hiddenObjects` matches.

### 2. `tagRules` on an S3 listing — inference confirmed by the service

§8 documents that `ListObjectsV2` returns no object tags, so an `allowedTags` policy over a
bare listing drops every entry as untagged. **That claim was originally written from reading
the filter code, not from observing S3.** It is now confirmed against the service:

- `ListObjectsV2` response carries no tag data — verified on objects that genuinely have tags
- `GetObjectTagging` returns them, so the gap is the listing API rather than the seed
- `allowedTags` over the bare listing → **everything dropped** (fail-closed, and useless)
- the same policy over tag-enriched entries → works as an author expects
- a pure `deniedTags` policy → **keeps** untagged entries, because they match no denied tag

Both halves are the safe reading, but together they mean an implementation that means to
enforce tags on `storage` **must** enrich entries before filtering. §8 now says so.

### 3. The `kb` metadata-filter pushdown enforces at the source — confirmed end to end

Six provider renderers were shipped with only Bedrock marked `Verified`, and even that rested
on a fixture *we* wrote. A real Knowledge Base was provisioned (OpenSearch Serverless
collection + vector index + IAM role + S3 data source + ingestion) and seeded with four
documents, two `classification=public` and two `classification=secret`.

Against the live `Retrieve` API:

- **Baseline** — unfiltered retrieval returns both classifications, so exclusions below are
  the filter's doing and not a query that simply missed the secret chunks
- **Denylist** — our generated `notIn` filter excludes every secret chunk *at the source*
- **Allowlist** — our generated `in` filter returns only public chunks
- **The safety property** — what the source filter left is identical to what the shipped
  `filter_by_tags` keeps from the unfiltered set. The pushdown optimises the same decision
  rather than masking a divergence from the normative post-retrieval pass.
- **Syntax acceptance** — all three filter forms (`notIn`, `in`, `andAll`) are accepted by
  Bedrock, with a malformed-filter negative control proving the acceptance test is not
  vacuous.

### 4. The SQL rewriter's Trino dialect executes correctly on Athena — confirmed

The rewriter carries a `trino` profile, which is what Athena speaks, but every prior test
exercised it against Postgres and MySQL. This is the category where a rewrite bug means **the
database itself returns unauthorized rows**, before post-fetch filtering gets a chance — and
a `WHERE`-clause fail-open was found in this rewriter once before, by running the SQL rather
than reading it.

Against a Glue table on seeded S3 data, executing the SQL the shipped rewriter produced:

- **Baseline** — the unfiltered table returns all three regions, so the filtered assertions
  are not passing because the table is empty or the SerDe misparsed the CSV
- **`equals` / `in` / `notEquals` pushdown** — Athena's own parser honours each. `notEquals`
  is asserted by the *absence* of the excluded value, not a row count, because negative
  operators are the class that previously failed open
- **`maxResults`** — pushed as `LIMIT` and obeyed
- **Denials precede execution** — `canQuery: false` and a table outside `allowedObjects`
  produce no runnable SQL at all, with a control proving the permitted table does
- **Post-fetch is still required** — `SELECT *` is deliberately *not* expanded, so `ssn`
  comes back from Athena and the pipeline removes it. The test asserts Athena really returned
  it first, so it cannot pass if someone optimised the post pass away
- **The safety property** — filtering in SQL reaches the same verdict as filtering in the
  pipeline over the same table. A disagreement would mean the rewrite is not a faithful
  translation of the policy

## Control coverage

Every control connector-spec §2 marks applicable to `storage` is exercised through the
**shipped SDK entry point** (`validate_access`, `validate_write`, `apply_result_pipeline`)
over data S3 actually returned — not reimplemented in the test.

| Control | How it is tested |
| --- | --- |
| `canQuery`, `allowedObjects`, `hiddenObjects` | prefix validation + the no-call proof above |
| `canInsert` / `canUpdate` / `canDelete` / `readOnly` | real PUT/GET/DELETE, paired controls, insert-vs-update kept distinct |
| `readOnlyFields` | a PUT whose metadata payload sets one is refused whole (§4.4) |
| `hiddenFields` / `allowedFields` / `maskedFields` | over real object user-metadata from `HeadObject` (§8 maps Field → metadata key) |
| `rowFilters` | over real listing entries |
| `maxObjectSizeBytes` | drops a genuinely ~2 KiB object under a 1 KiB ceiling |
| `maxResults` | truncates a real listing |
| `tagRules` | the asymmetry in finding 2, both directions |

## Files

| File | Contents |
| --- | --- |
| `s3-storage-run.txt` | Python, 23 tests |
| `s3-storage-run-dotnet.txt` | .NET, 23 tests |
| `s3-storage-run-typescript.txt` | TypeScript, 23 tests |
| `athena-db-run.txt` | Python, 12 tests |
| `athena-db-run-dotnet.txt` | .NET, 12 tests |
| `athena-db-run-typescript.txt` | TypeScript, 12 tests |
| `bedrock-kb-run.txt` | Python, 8 tests (e2e + syntax) |
| `bedrock-kb-run-dotnet.txt` | .NET, 8 tests |
| `bedrock-kb-run-typescript.txt` | TypeScript, 8 tests |
| `kb-search-filters-run.txt` | OpenSearch 2.19 + Elasticsearch 7.10, 20 checks (post-fix) |
| `bedrock-kb-provisioning.log` | the successful KB provisioning run |
| `bedrock-kb-provisioning-first-attempt-failure.log` | the first attempt, kept deliberately — see below |

## What porting found

Cross-SDK porting is not ceremony. Replicating these suites surfaced defects that
single-SDK testing had not, including one in shipped enforcement code:

- **A fail-open in .NET `EnforcementEngine.ValidateAccess`.** It did not check
  `Permissions.CanQuery`, while Python's `validate_access` and TypeScript's `validateAccess`
  both did -- so a policy with `canQuery: false` had its object check **pass** in .NET alone.
  A fail-open on the broadest permission in the model, and one signed policy granting
  different access per language. It hid because the MCP wrapper checks the gate on a separate
  path before calling in; but `ValidateAccess` is public API, and §8 requires a `storage`
  wrapper to call it *directly* to validate a prefix before the provider call. A caller doing
  exactly what the spec says got no gate. Fixed, with a regression test and its paired
  control, mutation-verified. The identical omission had been fixed in `ValidateEndpoint`
  earlier and survived here because nothing asserted it.
- **A pipeline handler installed from a base constructor.** The .NET call recorder was added
  in `CustomizeRuntimePipeline`, which the AWS SDK invokes from the *base* constructor --
  before derived field assignment. Every test failed in ~1ms with
  `ArgumentNullException(handler)`.
- **`GetObjectTagging` returns a null `TagSet`**, not an empty list, for untagged objects.
- **Guessed NuGet versions.** `AWSSDK.*` 3.7.x does not exist; NuGet silently substituted
  (`NU1603`), which would have failed CI under `-warnaserror`. The real majors are 4.x.
- **Both opt-in gates were broken, in the same direction, by different mechanisms.** The AWS
  suites are meant to skip unless `TOLAP_TEST_AWS=1`. Neither Python nor .NET actually did:
  - **Python** set `pytestmark = pytest.mark.skipif(...)` in a **`conftest.py`**. pytest only
    reads that name from test *modules*, so the gate silently did not exist -- a clean checkout
    produced 35 errors and 3 failures from a suite designed to skip. Replaced with a
    `pytest_collection_modifyitems` hook.
  - **.NET** opened all 41 test bodies with `if (Skip) return;`. xunit records an early return
    as a **pass**, so with no credentials the run reported `Passed: 307, Skipped: 0` --
    byte-identical to a full run against real AWS. Replaced with `[AwsFact]`/`[AwsTheory]`/
    `[KbFact]`, which set `FactAttribute.Skip` at discovery. Now `264 passed, 41 skipped`.

  TypeScript's `ctx.skip()` was correct throughout, and its honest `43 skipped` is what made
  the other two visibly wrong. Worth stating plainly: **a suite whose purpose is catching
  fail-open bugs was itself failing open about whether it had run.** Both gates now carry a
  guard test that is deliberately *not* behind the gate -- the defect survived precisely
  because guard and guarded were the same mechanism -- and each was mutation-verified in both
  directions, since a hardcoded skip would satisfy a guard that only checks for skipping.

## The failure worth keeping

The first provisioning attempt crashed calling `StartIngestionJob` on a KB still in
`CREATING`, and **printed its resource ids only on success** — so the crash left an S3
bucket and an IAM role orphaned with no record of their names. They had to be found by
prefix and deleted by hand.

Both bugs are fixed in `provision_bedrock_kb.py`: a `_wait_kb_active` before ingestion, and
a `--state` file written as each resource is created so a mid-run failure is always
recoverable with `down --from <state>`. The failure log is kept because the lesson —
**persist resource ids the instant they exist, not when you finish** — is the kind that gets
re-learned expensively.

## Reproducing

These are opt-in and skip by default, and they do not run in CI. The repository is currently
**private**, so the fork-PR credential-exposure problem does not apply today — but the gating
is deliberate regardless: these tests create real, billable AWS resources, and a suite that
provisions an OpenSearch Serverless collection on every push is a cost and cleanup hazard
whoever owns the account will not thank you for. If CI ever runs them, it should be on a
schedule or a manual dispatch against a dedicated account via OIDC, never on every PR.

```bash
# storage and db/Athena — need only credentials
#   (Athena creates a Glue database + table over seeded S3 data, deleted on teardown)
isengardcli run --account <acct> --region us-east-1 -- \
  env TOLAP_TEST_AWS=1 pytest sdk/python/tests/integration/aws/test_s3_storage.py \
                              sdk/python/tests/integration/aws/test_athena_db.py -v

# kb — provision, test, tear down. The KB costs money while it exists.
cd sdk/python/tests/integration/aws
isengardcli run --account <acct> --region us-east-1 -- \
  python3 provision_bedrock_kb.py up --state kb.env      # several minutes
isengardcli run --account <acct> --region us-east-1 -- \
  env TOLAP_TEST_AWS=1 TOLAP_TEST_KB_ID=<KB_ID from kb.env> \
  pytest test_bedrock_kb_e2e.py test_bedrock_kb_filter.py -v
isengardcli run --account <acct> --region us-east-1 -- \
  python3 provision_bedrock_kb.py down --from kb.env      # ALWAYS run this
```

`boto3` and `opensearch-py` are **test-only** dependencies. No shipped package declares an
AWS SDK and none should: TOLAP never holds a connection, so the AWS call belongs in the test
and the wrapper enforces on records the caller retrieved. That is what preserves the
zero-runtime-dependency property.

## Not covered

- **Five of six `kb` renderers remain unverified against their services.** Only Bedrock has
  been exercised; OpenSearch, Elasticsearch, Azure AI Search, Vertex AI Search and pgvector
  are written from published grammar and report themselves `fromGrammar`.
- **Redshift is not a gap, and the earlier note calling it "untested" was wrong.** There is no
  Redshift dialect to test: `SqlDialect` is `ansi`, `postgres`, `trino`, `mysql`, `sqlserver`, and
  Redshift is a Postgres fork handled by the `postgres` profile — already exercised against real
  PostgreSQL 17. The rewritten SQL is byte-identical under `postgres` and `ansi`, and
  double-quoted identifiers with `LIMIT n` are what Redshift accepts. A cluster would have
  re-verified the Postgres profile at real standing cost. See `../databases/README.md`.
- **CloudTrail** is not asserted against. The `before-call` event count is a faithful proxy
  for "no request was issued" and is fast; CloudTrail would be the auditor's own view but
  lags minutes and would make the suite slow and flaky.
- **`opensearch` and `elasticsearch` are now verified, and verifying them found a fail-open.**
  Standing up a real OpenSearch 2.19 domain and an Elasticsearch 7.10 domain promoted two of the
  six `kb` renderers out of `fromGrammar` -- and immediately exposed a defect no unit test could
  have seen. The renderer emitted `classification.keyword` unconditionally. A field mapped `text`
  carries a `.keyword` sub-field by convention; a field mapped `keyword` **directly does not**, so
  the clause matched nothing. Under `must_not`, a term matching nothing **excludes** nothing:

  | Policy | Expected | Actual |
  | --- | --- | --- |
  | `deniedTags: [secret]` | 2 public docs | **all 4, both secrets returned** |
  | `allowedTags: [public]` | 2 public docs | 0 docs |

  The allowlist arm failed *closed* and the denylist arm failed *open*, on the same mapping and the
  same missing sub-field -- and **the engine accepted the query both times**, so nothing looked
  wrong. The code's own comment called a mapping mismatch "the usual harmless miss", reasoning that
  holds only for a positive match. Each clause now matches the bare field **and** the `.keyword`
  sub-field, which is correct under either mapping. Fixed in all three SDKs, the shared fixture
  regenerated, and .NET and TypeScript independently reproduce the new rendering byte-for-byte.
  Evidence: `kb-search-filters-run.txt` (20 checks, post-fix). The pre-fix run is not retained;
  the failure is reproducible by reverting `_render_opensearch` to emit `.keyword` alone, and the
  numbers it produced are in the table above.

  `pgvector` was verified separately against real PostgreSQL + pgvector 0.8.1 with a real ANN
  search — see `../databases/verbose-pgvector.txt`. Two renderers remain `fromGrammar`:
  `azure_ai_search` and `vertex_ai_search`, both needing a paid subscription.

- **Provisioning is shared, not ported.** The Bedrock KB is stood up by the Python
  `provision_bedrock_kb.py` for all three SDKs. That is deliberate: provisioning is test
  infrastructure, not SDK behaviour, and building the same chain three times would triple the
  maintenance for no extra signal. The *enforcement* assertions do run independently per SDK,
  which is the part that has to.
