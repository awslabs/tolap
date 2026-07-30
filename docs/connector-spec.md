# TOLAP Connector Specification

**Status:** Normative. [`canonical-enforcement-spec.md`](canonical-enforcement-spec.md)
defines the mechanics that are identical everywhere — canonical signing, pipeline order,
fail-closed rules, merge semantics. **This** document defines what those mechanics *mean*
per data-source category, which policy fields are meaningful for each, and how writes are
governed.

**Why this document exists.** The policy schema is deliberately source-agnostic: one shape
covers databases, APIs, knowledge bases, and object storage. That is a strength, but
nothing said which fields apply to which source, what a "row" or "object" is per category,
or what an integrator must check before a call. The consequences were documented controls
with no implementation ("prefix allow/deny", "file type restrictions"), fields parsed and
merged but never enforced (`minSimilarityScore`, `maxObjectSizeBytes`), enforcement that
silently differed between a database wrapper and an HTTP wrapper, and a `readOnlyFields`
field nobody could implement because its meaning was never defined.

---

## 1. Source identity

Every data source has a connection identifier of exactly three colon-separated segments:

```
category:namespace:name
```

| Segment | Meaning | Constraints |
| --- | --- | --- |
| `category` | One of `db`, `api`, `kb`, `storage` | Fixed set. Adding one is a breaking change; see §10. |
| `namespace` | Deployment-defined grouping — environment, tenant, team, or account | Opaque to TOLAP |
| `name` | The specific source within that namespace | Opaque to TOLAP |

`sourcePatterns` matches this identifier with globs where `*` matches **within a segment
and never crosses a `:`** (enforcement spec §10). Consequences worth stating plainly:

| Pattern | `db:production:patients` | `db:production:patient_labs` | `api:internal:patients` |
| --- | :--: | :--: | :--: |
| `db:production:*` | match | match | no |
| `db:production:patient*` | match | match | no |
| `db:*` | **no** | **no** | no |
| `db:*:*` | match | match | no |
| `*:*:patients` | match | no | match |

`db:*` matching nothing is the most common authoring mistake: a two-segment pattern cannot
match a three-segment identifier. Use `db:*:*`.

## 2. Field applicability matrix

A field not marked applicable for a category is **inert** there: still parsed, still
merged, still carried in the signed policy — but no enforcement step reads it. Setting one
is not an error, and it is not protection.

| Policy field | `db` | `api` | `kb` | `storage` |
| --- | :--: | :--: | :--: | :--: |
| `permissions.canQuery` | ✅ | ✅ | ✅ | ✅ |
| `permissions.canInsert` | ✅ | ✅ | ✅ | ✅ |
| `permissions.canUpdate` | ✅ | ✅ | ✅ | ✅ |
| `permissions.canDelete` | ✅ | ✅ | ✅ | ✅ |
| `permissions.readOnly` | ✅ | ✅ | ✅ | ✅ |
| `objectRules.allowedObjects` | ✅ tables/views | ⚠️ resource names | ➖ | ✅ key prefixes |
| `objectRules.hiddenObjects` | ✅ tables/views | ⚠️ resource names | ➖ | ✅ key prefixes |
| `fieldRules.allowedFields` | ✅ columns | ✅ response fields | ➖ | ✅ metadata keys |
| `fieldRules.hiddenFields` | ✅ columns | ✅ response fields | ➖ | ✅ metadata keys |
| `fieldRules.maskedFields` | ✅ columns | ✅ response fields | ✅ chunk fields | ✅ metadata keys |
| `fieldRules.readOnlyFields` | ✅ writes (§4) | ✅ writes (§4) | ✅ writes (§4) | ✅ writes (§4) |
| `objectRules.rowFilters` | ✅ rows | ✅ collection items | ✅ chunk metadata | ✅ listing entries |
| `objectRules.tagRules` | ➖ | ➖ | ✅ classifications | ⚠️ object tags |
| `objectRules.endpointRules` | ➖ | ✅ paths + methods | ➖ | ➖ |
| `limits.maxResults` | ✅ | ✅ | ✅ | ✅ |
| `limits.minSimilarityScore` | ➖ | ➖ | ✅ | ➖ |
| `limits.maxObjectSizeBytes` | ➖ | ➖ | ➖ | ✅ |

✅ enforced · ➖ not applicable

## 3. Shared semantics

These apply to every category. They are specified here because per-category text below
depends on them and because each has a measured, non-obvious behavior.

### 3.1 Glob matching

Two different glob behaviors exist and the difference is load-bearing:

| Context | `*` behavior |
| --- | --- |
| `sourcePatterns` (resolution) | Stays **within** a `:` segment |
| Objects, fields, endpoints, prefixes (enforcement) | Crosses **all** separators, including `/` and `.` |

Measured consequences an author must anticipate:

```
allowedEndpoints: ["/api/v1/patients/*"]
  /api/v1/patients/123          -> allowed
  /api/v1/patients/123/labs     -> allowed     <-- nested resource, also granted
  /api/v1/patients              -> DENIED      <-- the collection itself is not

allowedObjects: ["exports/public/*"]
  exports/public/a.csv          -> allowed
  exports/public/sub/deep.csv   -> allowed     <-- descends arbitrarily
  exports/private/a.csv         -> denied
```

To grant a collection *and* its members, list both (`/api/v1/patients`,
`/api/v1/patients/*`). To restrict a prefix to one level, an SDK offers no mechanism —
use `hiddenObjects` to carve out what must not be reachable.

All enforcement matching is **case-insensitive** and platform-independent. An
implementation MUST NOT use a matcher whose case folding depends on the host OS
(`fnmatch.fnmatch` in Python applies `os.path.normcase`, which made
`hiddenObjects: ["Billing"]` deny on Windows and allow on Linux for the same signed
policy).

#### The complete set of metacharacters

`*` and `?` are the **only** metacharacters. Every other character in a pattern is
literal, and an implementation MUST NOT assign a special meaning to any of them:

| Construct | Meaning | Notes |
| --- | --- | --- |
| `*` | Any run of characters, including empty | Crosses every separator (above). `**` is an alias for `*`; runs of stars collapse to one |
| `?` | Exactly **one** character | Also crosses separators, so `/a?c` matches `/a/c` |
| `[abc]`, `[!a]`, `[a-z]` | **Literal characters** | NOT a character class. `[abc]` matches the four-character text `[abc]` |
| `.` `+` `^` `$` `(` `)` `{` `}` `\|` `\` | Literal | A pattern is a glob, never a regex |

Bracket expressions are literal because that is the fail-closed reading: a literal
`[abc]` matches strictly fewer names than a character class would, so an
`allowedObjects` entry cannot silently reach objects the administrator never spelled
out. An implementation MUST NOT use a matcher that treats them as classes —
`fnmatch`/`fnmatchcase` in Python does, and MUST therefore be escaped or replaced.

Since neither construct is a wildcard, a pattern that needs a literal `*` or `?`
cannot express it. That is a known limitation; use a broader pattern plus
`hiddenObjects`.

```
allowedObjects: ["report?"]
  reports              -> allowed     <-- ? matched the single trailing 's'
  report               -> denied      <-- ? requires exactly one character
  reports2             -> denied

allowedObjects: ["log[abc]"]
  log[abc]             -> allowed     <-- the brackets are literal text
  loga                 -> DENIED      <-- NOT a character class
```

`sourcePatterns` (resolution, §10) uses the same metacharacter set, with the single
difference already noted above: its `*` does not cross `:`.

### 3.2 Field-name matching

A policy field reference and a record key may each be bare (`ssn`) or qualified
(`patients.ssn`), and they need not agree. Matching succeeds in **both** directions,
case-insensitively, recursing into nested objects and arrays:

| Rule | Matches key |
| --- | --- |
| `patients.ssn` | `ssn`, `patients.ssn`, `PATIENTS.SSN` |
| `ssn` | `ssn`, `patients.ssn`, nested `{"patient": {"ssn": …}}` |
| `patients.*` | any key on a projected patients row |

### 3.3 Denial reasons

The reason string is part of the contract; integrators log and branch on it. These exact
values are produced:

| Reason | Cause |
| --- | --- |
| `query not permitted` | `canQuery` is false |
| `object is hidden` | Target matched `hiddenObjects` |
| `object not in allowed set` | `allowedObjects` specified and target did not match |
| `endpoint is hidden` | Path matched `hiddenEndpoints` |
| `endpoint not in allowed set` | `allowedEndpoints` specified and path did not match |
| `method not allowed` | Method not in `allowedMethods` (or its read-only default) |
| `method not allowed on a read-only policy` | A write method while `readOnly` is true |

**Precedence.** When a request fails more than one check, the reason is the first that
denies, evaluated in this order: `query not permitted` → `endpoint is hidden` →
`endpoint not in allowed set` → `method not allowed` → `method not allowed on a read-only
policy`. The order is contract, not just the set of strings: an integrator branching on the
reason sees exactly one, and which one is fixed. In particular, because endpoint matching is
case-insensitive (§3.1), a path that differs from an `allowedEndpoints` entry only by case
*matches* the allow-list and is then judged on its method — so a denied method yields
`method not allowed`, not `endpoint not in allowed set`.

Write denials add the reasons in §4.4. Reasons are deliberately coarse: they name the rule
that denied, not the data. A reason MUST NOT disclose a value, a row count, or whether a
hidden object exists beyond what the rule name implies.

### 3.4 Masking semantics

Mask types, most restrictive first: `null` > `redact` > `full` > `hash` > `partial`
(enforcement spec §6). Measured behavior for `partial` over `alice@example.com`:

| Parameters | Result |
| --- | --- |
| `showFirst: 1` | `a****************` |
| `showLast: 4` | `*************.com` |
| `showFirst: 2, showLast: 2` | `al*************om` |
| `showFirst: 100, showLast: 100` | `*****************` (degrades to full; never returns the original) |

`maskChar` defaults to `*`. `hash` honours `algorithm` (`sha256` default, `sha512`,
`blake2b`), lower-case hex truncated to 16 characters, identical across all SDKs — it is a
**pseudonymous join key**, not confidentiality, and is brute-forceable for low-entropy
values like SSNs.

## 4. Write operations

Reads filter what comes back. Writes must be validated **before** they reach the source,
because there is nothing to filter afterwards — the damage is already committed.

### 4.1 Permissions

| Permission | Governs | Merge |
| --- | --- | --- |
| `canQuery` | Reads: select, get, search, list | AND |
| `canInsert` | Creating new records or objects | AND |
| `canUpdate` | Modifying existing records or objects | AND |
| `canDelete` | Removing records or objects | AND |
| `readOnly` | Ceiling over all three write permissions | OR |

All three write permissions default to **`false`** when absent. This is deliberately the
opposite of `canQuery`, which defaults to `true`: a policy written before writes existed
must not silently grant them, and an author who omits a write permission has not asked for
write access.

`readOnly` is a **ceiling, not a peer**. When true, every write is denied regardless of
`canInsert`/`canUpdate`/`canDelete`. It is OR-folded on merge (any policy can impose it)
while the write permissions are AND-folded (every policy must grant them), so both
directions compose most-restrictively.

### 4.2 Required pre-write validation

Every write MUST pass all of these before the operation is issued. Order matters only in
that the cheapest checks come first; all must pass.

1. **Operation permission** — the matching `canInsert`/`canUpdate`/`canDelete`, then
   `readOnly`.
2. **Target object** — `allowedObjects`/`hiddenObjects` against the table, resource, or
   key being written. A hidden object is not writable.
3. **Every field in the payload** must be writable:
   - in `hiddenFields` → denied. A field the caller cannot read, it cannot write.
   - in `readOnlyFields` → denied. This is what that field means (see §4.3).
   - `allowedFields` specified and field absent from it → denied.
4. **Row filters must match the target row** for an update or delete. A caller MUST NOT be
   able to modify a row it could not have selected. Where the SDK cannot evaluate the
   filters against the target — because it has not read the row — the integrator MUST
   either read-then-verify or push the filters into the statement's `WHERE`. An
   unverifiable update MUST be refused.

### 4.3 `readOnlyFields`

`readOnlyFields` names fields that are **readable but not writable**. It has no effect on
reads: a field listed here is returned normally, subject to hidden/allowed/masking rules
like any other. It denies only on the write path.

This is the field's first specification. It has existed in the schema and all three
mergers since the beginning, was never read by any code, and its intended meaning was
undefined — two doc comments in the reference implementation contradicted each other. It
is specified now because writes make it meaningful.

Union on merge, like every other deny-list: any policy can make a field read-only.

### 4.4 Fail closed — reject the whole write

If any field in a payload is not writable, **the entire write is rejected**. An
implementation MUST NOT silently drop the offending fields and proceed.

This is the one place where filtering — the correct answer on the read path — is the wrong
answer. A caller that submits `{status, ssn}` and receives success has been told its write
applied. Silently persisting only `status` leaves the caller's model of the data wrong in a
way it cannot detect, and for a two-field update where the second field mattered, that is a
correctness failure the caller will act on. Denial is recoverable; silent partial success
is not.

Write denial reasons:

| Reason | Cause |
| --- | --- |
| `insert not permitted` | `canInsert` false |
| `update not permitted` | `canUpdate` false |
| `delete not permitted` | `canDelete` false |
| `read-only policy` | `readOnly` true and the operation is a write |
| `field is hidden: <field>` | Payload field in `hiddenFields` |
| `field is read-only: <field>` | Payload field in `readOnlyFields` |
| `field not in allowed set: <field>` | `allowedFields` specified, payload field absent |
| `target row not permitted` | Row filters do not match the update/delete target |
| `write target unverifiable` | Filters exist but could not be evaluated against the target |

Naming the field is intentional and safe: the caller supplied it, so the reason discloses
nothing it did not already know. Reasons for *row* denials MUST NOT name values.

### 4.5 Post-write results

A write that returns data — `INSERT … RETURNING`, a `201` body, an updated object's
metadata — is a **read of that data** and the full post-execution pipeline (enforcement
spec §4) applies to it. A masked field must come back masked even when the caller just
wrote it, and a hidden field must not appear in a write response.

## 5. `db` — relational and query-engine sources

**Covers** PostgreSQL, MySQL, SQL Server, Athena, BigQuery, Redshift, Snowflake — anything
addressed by a query language returning tabular rows.

| Concept | Maps to |
| --- | --- |
| Object | Table or view |
| Field | Column; `ssn` and `patients.ssn` are the same column (§3.2) |
| Record | One row, as a map of column name to value |
| Write | `INSERT` / `UPDATE` / `DELETE` |

### Read path

**Pre-execution (integrator MUST call):** `canQuery`; `validateAccess` for every table the
query touches; `validateFieldAccess` for every column it *references* — not merely those it
projects. A query naming a hidden column MUST be **refused, not filtered**: a `WHERE`,
`ORDER BY`, `GROUP BY`, or `HAVING` over a hidden column lets its values determine which
rows return even when the column never appears in the output.

**Post-execution:** the full pipeline over returned rows. Always runs; this is the boundary.

**Optional rewriting:** row filters into `WHERE`, `maxResults` into `LIMIT`, hidden columns
out of `SELECT`. A resource optimization governed by enforcement spec §4 — never a
replacement for the post pass.

### Write path

- `readOnly` MUST block mutating **statements**, not merely mutating HTTP methods. A tool
  accepting arbitrary SQL MUST reject non-`SELECT` statements when `readOnly` is set. The
  SDK cannot see the statement text unless it is handed to a rewriter or validator.
- An `UPDATE`/`DELETE` MUST carry the policy's row filters in its `WHERE`, or the target
  row must be read and verified first. An unqualified `DELETE FROM patients` under a
  region-scoped policy MUST be refused, not executed and hoped over.
- Column names in the payload are matched with §3.2 semantics, so a `readOnlyFields` entry
  of `patients.created_at` blocks a payload key of `created_at`.

### Category requirements

- **No statement batching.** One statement per call. Batching defeats per-object
  validation: the first statement is checked and the rest ride along.
- **`maxResults` is per call, not a pagination budget.** N paginated calls return up to
  N × `maxResults`; an integrator paginating MUST track the total itself.
- **Introspection is governed.** `list tables` and `describe table` MUST be filtered through
  the same object and field rules. Returning a hidden table's name discloses its existence.

### 5.1 SQL dialects

There is no portable SQL. A rewriter that emits one dialect's syntax against another
engine produces a query that is wrong, and the failure is silent because the engine
accepts it.

**Measured example.** The rewriter emitted Postgres-style `WHERE "region" = 'us-east'`.
MySQL without `ANSI_QUOTES` reads `"region"` as a *string literal*, so it evaluated
`'region' = 'us-east'` — false for every row. Against a 6-row table the policy-filtered
query returned **0 rows**; with backticks it correctly returned 2. The engine reported no
error either way.

The direction of that failure is worth stating: it fails **closed**, so it is a
correctness and availability defect rather than a disclosure — the post-execution pass
remains the security boundary (enforcement spec §4). But an integrator sees empty results
and concludes the product is broken.

#### Dialect profiles

A rewriter MUST accept the dialect as an **explicit parameter**, supplied by the
integrator. The dialect is a property of their connection, which only they know — the
integrator already chose `psycopg` or `pymysql`. It MUST NOT be inferred, and it MUST NOT
be carried in the policy: a signed security artifact must not depend on deployment detail,
and `sourceConnectionId`'s `db` category deliberately does not distinguish engines.

| Profile | Identifier | Row limit | `\` escapes in strings |
| --- | --- | --- | :--: |
| `ansi` (default) | `"col"` | `LIMIT n` | no |
| `postgres` | `"col"` | `LIMIT n` | no |
| `trino` (Athena, Presto) | `"col"` | `LIMIT n` | no |
| `mysql` (MariaDB) | `` `col` `` | `LIMIT n` | **yes** |
| `sqlserver` | `[col]` | `TOP n` | no |

Rules:

1. **An omitted dialect selects `ansi`** — the strict intersection. It is not a guess at
   the engine; it is the subset most engines accept.
2. **An unrecognized dialect MUST NOT be rewritten.** Decline and report every filter as
   unpushable, leaving the post-execution pass to enforce them. Guessing a profile is how
   the MySQL defect above happened.
3. **A profile MUST NOT be approximated.** If `TOP n` cannot be placed correctly in a
   given statement shape, the limit is not pushed — it is not rendered as `LIMIT n` and
   hoped over.
4. **An identifier containing the profile's own quote character MUST be declined**, never
   escaped by doubling. Declining costs an optimization; mis-escaping emits attacker- or
   author-controlled text into the statement.
5. Values carrying a backslash are refused for **every** profile, not only `mysql`. The
   refusal is uniform so a policy behaves identically across engines, and because a single
   profile treating `\` as an escape is enough to make escaping unsafe to generalize.

#### What is unaffected by dialect

Only the *emitted text* is dialect-specific. The policy, the enforcement pipeline, the
fail-closed rules, and the set of pushable operators are identical everywhere — a filter
unpushable in one profile is unpushable in all of them, so enabling rewriting never
changes which rows a policy admits, only where the work happens.

## 6. `api` — HTTP and RPC services

**Covers** REST, GraphQL, SOAP, FHIR, gRPC-over-HTTP.

| Concept | Maps to |
| --- | --- |
| Endpoint | Request path, glob-matched (§3.1) |
| Field | A field in the request or response body, at any depth |
| Record | An item in a response collection, located by `collectionPath` |
| Write | `POST` / `PUT` / `PATCH` / `DELETE` |

### Read path

**Pre-request:** `canQuery`; `validateEndpoint` for path **and** method. The path MUST be
evaluated **without its query string**, so `?` parameters cannot smuggle a path past a
glob. Method matching is case-insensitive.

**Post-response:** the full pipeline over the body, walking nested structures.
`collectionPath` locates a wrapped collection so row filters, tag filters and the limit
apply to the items rather than the envelope.

### Write path

Method and permission MUST agree; both are checked:

| Method | Permission | Read method |
| --- | --- | :--: |
| `GET`, `HEAD`, `OPTIONS` | `canQuery` | yes |
| `POST` | `canInsert` | no |
| `PUT`, `PATCH` | `canUpdate` | no |
| `DELETE` | `canDelete` | no |

`readOnly` denies every non-read method. An absent `allowedMethods` defaults to the read
methods only (enforcement spec §9) — the sole exception to §3's null-means-unrestricted
rule, because a missing method list is far more likely an oversight than an intentional
grant of `DELETE`.

The **request body** is validated per §4.2 before the call: every field in the payload must
be writable. `PUT` semantics deserve care — a full-resource replace that omits a
`readOnlyFields` field is still attempting to overwrite it with absent, so an
implementation MUST treat a `PUT` payload as writing every field of the resource, not only
the keys present.

### Category requirements

- **Error bodies are enforced.** A 4xx/5xx payload carries the same fields as a success
  payload; a validation error echoing a rejected value is a common leak.
- **Headers are not fields.** Masking does not reach them. Strip sensitive headers
  explicitly.
- **Redirects are re-validated** against the endpoint rules before being followed, or not
  followed. A permitted endpoint that 302s to a denied one otherwise bypasses the check.
- `allowedObjects`/`hiddenObjects` are ⚠️ for this category: no wrapper currently derives a
  resource name from a path. An author MUST express API restrictions as `endpointRules`,
  and documentation MUST NOT imply object rules cover HTTP paths.

## 7. `kb` — knowledge bases and vector stores

**Covers** Bedrock Knowledge Bases, OpenSearch, Elasticsearch, Azure AI Search, Vertex AI
Search, pgvector — anything returning scored chunks.

| Concept | Maps to |
| --- | --- |
| Object | The index or knowledge base; normally governed by `sourcePatterns`, not `allowedObjects` |
| Record | One retrieved chunk: text, metadata, score |
| Tag | A classification or label on a chunk |
| Write | Ingesting, re-indexing, or deleting a document |

### Classification is expressed as tags

There is no `classificationRules` construct. A classification level **is** a tag: the
shipped example denies `classified`, `restricted`, `legal-hold`, `pii-raw` and allows
`public`, `internal`, `research`, `clinical-summary`. Documentation referring to
"classification restrictions" means exactly this mechanism and nothing more.

### Read path

**Pre-retrieval:** `canQuery`. Where the provider supports server-side metadata filtering,
an SDK SHOULD additionally emit a provider-native filter from `tagRules` so denied chunks
are never retrieved — an optimization on the same footing as SQL rewriting, never a
replacement for the post pass.

**Post-retrieval:** the full pipeline, including the relevance floor.

#### Provider-side filters — implemented, and deliberately weaker

All three SDKs build these (`buildKbFilter` / `build_kb_filter` / `KbFilter.Build`, then a
renderer per provider: Bedrock, OpenSearch, Elasticsearch, Azure AI Search, Vertex AI
Search, pgvector). Only the Bedrock shape has been exercised against the live service; the
other five are written from published filter grammar and report themselves as such, because
"looks right" is not the same evidence as "observed to filter".

The pushdown is **structurally** weaker than the post pass, not merely redundant, and the
asymmetry is what makes it safe:

- Post-retrieval extraction reads tags from `tags`, `Tags`, `labels`, `classification` and
  `metadata.tags` — at any depth, matched with the §3.2 matcher. A provider filter cannot
  express that; it tests one indexed field.
- So a filter that matches nothing costs efficiency and nothing else. The post pass is
  unconditional and still drops the chunk.
- The failure to avoid is the reverse: a filter that excludes a chunk the policy *permits*.
  An implementation MUST NOT approximate a rule it cannot express exactly — it reports the
  rule as unpushed and leaves it to the post pass.

Two consequences worth stating, because both invite a wrong implementation:

| Situation | Required behaviour |
| --- | --- |
| `allowedTags: []` (deny-all) | No portable metadata predicate means "match no document" — an empty `in` list is variously an error, a no-op, or match-nothing. An implementation MUST NOT render it as a no-op filter, which would fail open. It reports deny-all and the caller **skips retrieval**. |
| `allowedTags` with several candidate metadata keys | The post pass admits a chunk carrying an allowed tag under **any** key — a disjunction. ANDing a positive clause per key would demand it under *every* key and drop permitted chunks. Report unpushed instead. |

The metadata key a filter targets is **deployment configuration**, supplied per source, and
is not the same thing as the fixed tag-key set extraction uses. Extraction's set decides
what counts as security metadata and so must stay outside integrator control; a filter key
only names what the provider happens to index, and a wrong one yields no filter rather than
wrong access.

### Category requirements

- **Tag extraction MUST be robust.** Tags appear under differently-cased keys, nested in a
  metadata object, as a scalar rather than an array, or under provider-specific names. Tag
  matching MUST use the same bidirectional, case-insensitive, recursive matching as §3.2. A
  literal lower-case `tags` array lookup silently fails to enforce the control on most real
  providers — of five chunks tagged `secret` under `tags`, `Tags`, `metadata.tags`,
  `labels`, and a scalar `classification`, a naive lookup drops one.
- **Tag values compare case-insensitively.** `deniedTags: ["Secret"]` MUST drop `secret`.
- **An untagged chunk is dropped when `allowedTags` is specified**, kept under a
  denylist-only policy. Classification that cannot be established cannot be shown permitted.
- **`minSimilarityScore` is a confidentiality control**, not a relevance nicety — its
  purpose is stopping weak matches from surfacing sensitive content. Fails closed: an
  unscored chunk is dropped.
- **Masking cannot redact prose.** Chunk text is unstructured; masking a *field* will not
  remove a value appearing inside free text. An integrator relying on masking for PII in
  document bodies MUST be told it does not work — use `deniedTags` on the source documents.

### Write path

Ingestion is `canInsert`; re-indexing an existing document is `canUpdate`; removal is
`canDelete`. A document MUST NOT be ingested carrying tags the writer's own policy denies —
otherwise a restricted-tag document can be introduced by someone forbidden to read it, and
`deniedTags` becomes a read-side illusion.

## 8. `storage` — object stores

**Covers** S3, Azure Blob Storage, Google Cloud Storage, filesystem-backed stores.

| Concept | Maps to |
| --- | --- |
| Object | A key or key prefix — this is what "prefix allow/deny" means |
| Record | One listing entry, or one object's metadata |
| Field | A **metadata key**, never object content |
| Write | `PUT` / copy / delete of an object |

### Read path

**Pre-access:** `canQuery`, then `validateAccess` on the requested key or prefix. The
**caller's requested prefix** MUST be validated before the provider call, not only after —
otherwise an unauthorized `list` is issued and merely filtered on return, which is slower
and records the request in the provider's audit log as though it were authorized.

**Post-access:** the full pipeline over listing entries or metadata.

### Category requirements

- **Object bodies are not enforced.** TOLAP governs which objects are reachable and what
  metadata is visible. It does not inspect or redact object *contents* — a permitted object
  is returned whole. Field rules apply to metadata only.
- **`maxObjectSizeBytes` SHOULD be checked before transfer.** Applying it to a listing is
  correct but weak; where a metadata-only call (`HEAD`) exists, check size before issuing a
  download so the limit prevents the transfer rather than discarding it afterwards. Fails
  closed: an entry whose size cannot be established is dropped.
- **There are no file-type rules.** TOLAP has no `fileTypes` field. Restrict extensions with
  globs: `hiddenObjects: ["*.bak", "*.sql"]`.
- **Prefix globs descend arbitrarily** (§3.1). `exports/public/*` reaches
  `exports/public/sub/deep.csv`.

### Write path

`canInsert` for a new key, `canUpdate` for overwriting an existing one, `canDelete` for
removal. An implementation that cannot distinguish create from overwrite MUST require
**both** `canInsert` and `canUpdate` — the safe intersection, since an unconditional `PUT`
may do either.

`maxObjectSizeBytes` applies to writes as well as reads: an object exceeding the ceiling
MUST NOT be uploaded.

## 9. No advisory fields

Every field the schema carries is enforced by at least one SDK (see the §2 matrix).
There are deliberately **no** parsed-but-unenforced fields, and a new one MUST NOT be
added: a field that is schema-validated, signed, and merged, and then read by no
enforcement step, reads as a control while being none. That is how an integrator comes to
rely on a guarantee the SDK never made.

So a proposed field must clear one bar before it enters the schema — **some SDK enforces
it.** A capability the SDK cannot reach is not a policy field. Two disqualifying shapes
in particular:

- **The concept has no meaning at the tool boundary.** If no SDK has an operation to
  gate, there is nothing for the field to deny.
- **The SDK does not own the resource.** Enforcement it cannot perform belongs to the
  layer that holds the connection, the process, or the credential — not to a field here
  that merely describes a wish.

Either case is an **integrator-layer concern**, documented as such, rather than a schema
field that looks like a control.

`fieldRules.readOnlyFields` is the worked precedent for the other direction: it sat
unenforced for a time, and was resolved by *gaining* enforcement (§4.3) rather than by
staying advisory.

## 10. Adding a connector category

The four categories are the complete set. Adding one is a schema change and a breaking
change, and requires all of the following **before any code**:

1. An entry in §2 — every existing policy field gets a verdict.
2. The concept mapping: object, field, record, write, plus any category-specific notion.
3. Pre- and post-execution enforcement points for both read and write paths.
4. Every fail-closed decision: what happens when a value a rule depends on is absent,
   malformed, or of an unexpected type.
5. Shared fixtures under `fixtures/` that all three SDKs validate against, including the
   fail-closed cases.
6. A section in this document, reviewed before implementation begins.

Implementing a connector before its specification existed is what produced the defects
described at the top of this document.
