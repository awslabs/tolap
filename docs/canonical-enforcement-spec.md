# TOLAP Canonical Enforcement & Signing Specification

**Status:** Normative. All three SDKs (.NET, Python, TypeScript) MUST implement this
document identically. Where an implementation disagrees with this spec, the
implementation is wrong.

**Why this document exists.** TOLAP's value proposition is that one policy is
enforced identically everywhere and that a signed policy is tamper-evident across
process, network, and account boundaries. Those guarantees only hold if every
implementation agrees on (a) exactly which bytes are signed and (b) exactly which
enforcement steps run, in what order. Divergence between implementations is a
security defect, not a stylistic difference.

---

## 1. Canonical JSON form (for signing)

All signature computation uses this form and only this form:

| Property        | Rule                                                        |
| --------------- | ----------------------------------------------------------- |
| Key ordering    | Recursively sorted, byte-wise ascending on the key string   |
| Separators      | Compact: `,` between items, `:` between key and value       |
| Whitespace      | None                                                        |
| Property naming | `camelCase`                                                 |
| Null values     | Omitted entirely (a null field is indistinguishable from absent) |
| Empty arrays    | **Preserved.** `[]` is semantically distinct from absent — see §3 |
| Unicode         | Emitted as raw UTF-8. No `\uXXXX` escaping, no HTML escaping |
| Encoding        | UTF-8 bytes fed to the HMAC                                 |

Two further rules, each added after a cross-SDK audit found all three implementations
disagreeing. Neither is observable through an access decision — both produce identical
enforcement and differ only in the signed bytes — so only a byte comparison across
languages surfaced them, which is the practice §14 recommends for exactly this reason.
`fixtures/canonical-form/number-and-timestamp-forms.json` pins both.

| Property | Rule |
| -------- | ---- |
| Whole-number floats | Rendered as integers: `1.0` emits `1`, `0.0` emits `0`. `0.85` is unaffected. A boolean MUST NOT be shortened into a number. |
| Offset-less timestamps | An ISO 8601 date-time with no offset and no `Z` means **UTC**, never the host's local time. |

Python emitted `1.0` where .NET and TypeScript emitted `1`, so a policy setting
`confidenceThreshold: 1.0` or `minSimilarityScore: 0.0` — both schema-valid — signed
different bytes there. Note the boolean caveat is about the *fix*, not the bug: Python's
`bool` is a subclass of `int`, so a numeric coercion that does not exclude it turns `true`
into `1`, which would change the bytes of every policy carrying a permission flag.

The timestamp rule is the sharper of the two. .NET's `System.Text.Json` and JavaScript's
`Date` both read an offset-less value as **local** time, so the same JSON signed to
`09:58:00Z` on a UTC host, `13:58:00Z` on `EST5EDT` and `16:58:00Z` on
`America/Los_Angeles`. That is a divergence between two deployments of the *same* SDK —
worse than a cross-SDK one, and invisible to any conformance fixture pinned to a single
host. A suite that only ever runs in UTC, as CI does, cannot detect it; an implementation
asserting this rule MUST vary the timezone explicitly. A value that *does* carry an offset
is unaffected: `+02:00` and `Z` each name their instant, and rule 4 folds them to the same
bytes.

Implementation notes, per language, to satisfy the above:

- **Python** — `json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False)`.
  `ensure_ascii=False` is required; the default `True` escapes non-ASCII and breaks
  cross-language agreement.
- **TypeScript** — recursive key sort, then `JSON.stringify`. Explicit `null`
  values must be dropped during the sort walk, not passed through.
- **.NET** — `JsonSerializerOptions` with a sorted-property canonical writer and
  `JavaScriptEncoder.UnsafeRelaxedJsonEscaping` (the default encoder escapes `<`,
  `&`, `+` and non-ASCII, which breaks agreement). No default-value elision:
  a masking parameter that is explicitly present must be serialized even when it
  equals the type default.

## 2. Signed payload = the whole envelope

The HMAC MUST cover the entire security-context envelope, not just the policy.

Each implementation projects its native context type into this canonical shape
before signing. The projection — not the native model — defines the signed bytes,
so the three SDKs keep their existing public APIs while producing identical
signatures.

```
{
  "version":         string,
  "userId":          string,
  "tenantId":        string,
  "issuedAt":        string,   // RFC 3339 / ISO 8601, UTC, "Z" suffix
  "expiresAt":       string,   // RFC 3339 / ISO 8601, UTC, "Z" suffix
  "policies":        [ EffectivePolicy, ... ],  // integrity block stripped from each
  "jti":             string,          // optional; omitted when absent (§13.1)
  "declaredPurpose": string,          // optional; omitted when absent (§15.1)
  "delegationChain": [ DelegationHop ] // optional; omitted when absent or empty (§15.3)
}
```

Rules:

1. The `signature` / `integrity` block is excluded from the payload (it cannot
   sign itself). Strip it from the envelope **and** from every policy inside it.
2. `expiresAt` and `issuedAt` are **inside** the signed payload. Rewriting either
   MUST invalidate the signature. (Before this spec, Python and TypeScript signed
   only the policy, leaving expiry unauthenticated and replayable.)
3. Single-policy implementations project to a one-element `policies` array.
4. Timestamps are normalized to UTC with a `Z` suffix before signing so that
   `+00:00` and `Z` do not produce different bytes.
5. **Timestamps are truncated to millisecond precision.** Sub-second digits are
   truncated (never rounded) to exactly three, and the fractional part is omitted
   entirely when those digits are zero:

   | Input                          | Canonical form              |
   | ------------------------------ | --------------------------- |
   | `2026-01-15T10:00:00Z`         | `2026-01-15T10:00:00Z`      |
   | `2026-01-15T10:00:00+00:00`    | `2026-01-15T10:00:00Z`      |
   | `2026-01-15T10:00:00.000Z`     | `2026-01-15T10:00:00Z`      |
   | `2026-01-15T10:00:00.123Z`     | `2026-01-15T10:00:00.123Z`  |
   | `2026-01-15T10:00:00.123456Z`  | `2026-01-15T10:00:00.123Z`  |
   | `2026-01-15T10:00:00.1239Z`    | `2026-01-15T10:00:00.123Z`  |

   Milliseconds are the greatest precision all three runtimes represent exactly:
   JavaScript's `Date` cannot hold sub-millisecond values, while Python's
   `datetime` and .NET's `DateTimeOffset` both carry microseconds or finer.
   Without a mandated precision the same instant serializes to different bytes
   per language and the signature fails to verify across SDKs — a defect that a
   whole-second conformance fixture cannot detect, so the fixture MUST include a
   sub-second case (§14).

   Truncation is specified rather than rounding because rounding can move an
   expiry *later* than the issuer intended, and because truncation is
   representable identically in every runtime without floating-point concerns.

   The rule applies to **every** timestamp in the payload, including
   `delegationChain[].delegatedAt`, which is nested inside an array of objects
   rather than at the envelope's top level. `hmac-sha256-purpose-bound.json` pins
   that case specifically, because a normalizer applied only to the fields it was
   written for passes the older fixtures unchanged.
6. **Optional fields are omitted entirely when absent**, per the null rule in §1.
   This is what makes each of them a backward-compatible addition: a context
   carrying no `jti`, no `declaredPurpose` and no `delegationChain` signs to
   byte-identical bytes to the pre-`jti` form, so the known-answer fixtures and
   cross-SDK agreement survive. An empty string normalizes to absent for the two
   string fields, and an empty array normalizes to absent for `delegationChain`,
   so a single context cannot have two valid signatures.

   Note this is the **opposite** of the null-versus-empty rule in §3. There, `[]`
   on an allow-list is a meaningful deny-all and MUST be preserved. Here, an empty
   delegation chain carries no hops and therefore asserts nothing, so it is
   indistinguishable from having none. The distinction is that §3 concerns *rules*,
   where emptiness is a restriction, and this concerns *claims*, where emptiness is
   the absence of one.

### Upgrading across a canonical-form change

A change to the canonical form changes the signed bytes, so contexts signed by an
older SDK fail verification with a generic signature error that looks identical to
tampering. When upgrading:

1. Re-issue signed contexts rather than migrating them; they are short-lived by
   design (default TTL one hour).
2. Do not run mixed SDK versions across a signing/verifying boundary during the
   rollout — the verifier will reject every context the older signer produces.
3. To diagnose a suspected mismatch, compare the canonical payload **bytes**, not
   the signatures. Each SDK exposes its canonical projection for this purpose
   (`BuildCanonicalPayload` in .NET, `_canonical_payload` in Python, the
   canonicalizer in TypeScript), and the known-answer fixtures carry the expected
   byte string so a diverging implementation is identifiable directly.

The envelope's `version` field carries the **schema** version and is inside the
signed payload; it does not distinguish canonical-form revisions. If a future
change to the canonical form needs to be detectable at runtime rather than by
byte comparison, add an explicit format discriminator at that time — a signature
failure alone cannot tell a verifier "this was signed by an older SDK" apart from
"this was tampered with", and conflating the two is the safer default.

### Expiry validation

- Missing/empty `expiresAt` → **reject**. Never treat absent expiry as "never expires".
- Unparseable `expiresAt` → **reject**. An invalid date must not silently skip the
  check. (`new Date("never") <= new Date()` is `false` in JS, which previously
  granted an unbounded lifetime.)
- Comparison is `expiresAt <= now` in UTC → expired.
- Signature is verified **before** expiry, so a tampered context reports a
  signature failure rather than leaking whether a valid context merely expired.

## 3. `null` vs empty array — the deny/unrestricted distinction

This distinction is load-bearing and MUST NOT be collapsed by truthiness checks:

| Value       | Meaning for an *allow*-list                     |
| ----------- | ----------------------------------------------- |
| `null`/absent | Unrestricted — this policy adds no restriction |
| `[]`        | **Deny everything** — the allow-list is empty    |

Consequence for merging: intersecting two disjoint allow-lists yields `[]`, which
means deny-all. An implementation that treats `[]` as falsy and discards the rule
object converts *the most restrictive possible outcome* into *no restriction at
all*. Retention checks MUST test for `null`, not for emptiness.

The rule applies to **deny**-lists too, where the stakes look lower and are not. Union
MUST return `[]` when at least one policy contributed a list and every one was empty,
and `null` only when no policy contributed at all — which is a "did any policy
contribute" flag, not a truthiness test on the result. On a deny-list `[]` and `null`
are genuinely indistinguishable to *enforcement*: neither hides anything. They are not
indistinguishable to *signing*, because §1 omits a null field and preserves an empty
array, so collapsing one into the other changes the canonical bytes.

That is not hypothetical. Python's union used `return result if result else None` while
.NET and TypeScript retained the empty array, so a policy authoring an explicitly empty
`hiddenObjects`, `deniedTags`, `readOnlyFields` or `hiddenEndpoints` produced different
signed bytes in Python than in the other two, and a context signed by one would not
verify in the others. No test comparing access outcomes could see it — the access was
identical — which is why it survived until someone ported a new feature and compared
bytes. `fixtures/merge-scenarios/union-of-empty-lists-stays-empty.json` pins it in all
three languages now.

The asymmetry is worth stating once: emitting `[]` for a field **no** policy mentioned
would be the opposite error, and a much broader one, since it would change the bytes of
every policy that never mentioned the field. Absent in, absent out; empty in, empty out.

## 4. Enforcement pipeline (post-execution)

Every wrapper, in every language, applies these steps in exactly this order:

```
1. row filters      drop rows the policy excludes
2. tag filters      drop records by allowedTags / deniedTags
3. relevance floor  drop records scoring below minSimilarityScore
4. size ceiling     drop records larger than maxObjectSizeBytes
5. hidden fields    REMOVE hiddenFields from every record
6. allowed fields   PROJECT to allowedFields when specified (drop everything else)
7. masking          apply maskedFields transformations
8. result limit     truncate to maxResults
```

Steps 5 and 6 are mandatory and were previously absent from every
database/MCP wrapper (present only in the HTTP wrappers). `hiddenFields` and
`allowedFields` are **not** satisfied by a pre-execution check: the pre-check only
inspects the field list a caller volunteers, so any tool returning undeclared
columns (e.g. `SELECT *`) leaks them.

Ordering rationale: every record-dropping step precedes every field-level step, so
work is not spent masking a record that is about to be discarded. Hidden/allowed
removal precedes masking so that a field which is both hidden and masked is removed
rather than returned in masked form. The limit is applied last so that filtering
never yields fewer rows than `maxResults` when more qualifying rows exist.

### Relevance floor — `minSimilarityScore` (step 3)

A record whose similarity score is **below** `minSimilarityScore` is dropped. The
score is read from the first present of `score`, `similarity`, `similarityScore`,
or `_score` (case-insensitive), which covers the common vector-store response
shapes.

Fail-closed rules:

- A record carrying **no** recognizable score field is **dropped** when
  `minSimilarityScore` is set. A record whose relevance cannot be established
  cannot be shown to satisfy the floor.
- A non-numeric or unparseable score is **dropped**.
- The comparison is `score < minSimilarityScore` → drop. A score exactly equal to
  the floor is kept.

This is a confidentiality control, not a relevance nicety: the documented purpose
is to stop low-relevance vector hits from surfacing sensitive content, so an
unscored record must not slip through.

### Size ceiling — `maxObjectSizeBytes` (step 4)

A record whose size **exceeds** `maxObjectSizeBytes` is dropped. The size is read
from the first present of `size`, `sizeBytes`, `contentLength`, or `objectSize`
(case-insensitive), covering the common object-storage response shapes.

Fail-closed rules mirror the relevance floor: a record with no recognizable size
field, or a non-numeric size, is **dropped** when `maxObjectSizeBytes` is set. The
comparison is `size > maxObjectSizeBytes` → drop; a size exactly equal to the
ceiling is kept.

Both limits were previously parsed, validated, and merged most-restrictively — and
then never applied to any result, in all three SDKs. Because the merge and
round-trip paths *were* tested, statement and branch coverage reached 100% while
neither control did anything: coverage measures whether written code runs, never
whether required code was written.

### The post-execution pass is mandatory; query rewriting is an optimization

Every record-dropping and field-level step above is applied to results **after** the
tool executes. That pass is the enforcement boundary and it is **never optional**.

An SDK MAY additionally offer SQL query rewriting, which pushes row filters into a
`WHERE` clause, the result limit into a `LIMIT`, and projects hidden columns out of
the `SELECT` before the query runs. Rewriting is a **resource optimization, not an
enforcement mechanism**:

**The choice is named `SqlEnforcementMode` and has exactly two values.** All three SDKs
expose it with the same wire values and the same default:

| Value | Behaviour |
|---|---|
| `rewriteAndPost` | Rewrite, then run the post-execution pipeline. **The default in every SDK.** |
| `postOnly` | Return the caller's query unchanged, byte for byte; the post-execution pipeline does all the work. |

An SDK MUST NOT offer a third value that skips the post-execution pass. Masking has no SQL
form, so a masked field would be returned in clear text, and the unpushable operators below
would stop being enforced entirely. An enum with no name for that option cannot select it by
accident.

Both modes MUST return **identical results** for the same policy and the same data. An
implementation whose results differ by mode has made the mode an access-control setting,
which is the divergence this section exists to prevent; this MUST be tested by comparing the
two modes against each other rather than by asserting each in isolation.

`postOnly` skips the *rewrite*, not the *checks*. `canQuery`, the `allowedObjects` and
`hiddenObjects` decision, and the refusal of a query naming a hidden or non-allowed field
MUST all still apply. Declining to rewrite MUST NOT relax a denial.

In `postOnly` an SDK MUST report **every** row filter as unpushed, not merely the ones it
could not express: none of them reached the database, and a caller checking whether filters
were pushed before executing a large query would otherwise be told they were.

An unrecognized mode MUST fail loudly rather than selecting the default. This is the opposite
of an unrecognized *dialect*, which declines to rewrite: for a dialect, "push nothing" is a
safe reading, whereas silently rewriting for a caller who asked that their SQL not be touched
is the exact surprise `postOnly` exists to prevent.

- The post-execution pipeline MUST still run on the results, unchanged. An
  integrator who rewrites a query and skips the post pass is unprotected, because a
  rewriter cannot express every filter (see below) and cannot know whether the query
  it was handed is the query that ran.
- A rewriter MUST report which filters it could not push down. Operators with no
  portable SQL form — `contains`, `startsWith`, `matches` — are not pushed, and the
  post pass is what actually enforces them.
- A rewriter MUST fail closed. If it cannot safely render a value or an identifier,
  it declines to push that filter and leaves it to the post pass. It MUST NOT emit a
  predicate it is unsure of, and MUST NOT emit a neutral predicate such as `1=1` in
  place of one it failed to build.
- **A filter on a hidden field depends on the projection, not on the hiding.** Row
  filters are step 1 and hidden-field removal is step 5, so a filter on a hidden field
  works correctly whenever the tool returns that column: the rows are filtered, then the
  column is stripped. `SELECT *` with `hiddenFields: ["region"]` and a `region` filter
  filters and then hides, exactly as intended.

  It fails closed only once the projection omits the field — then step 1 sees no value
  to test and drops every row (§7). This is the surprising direction: *narrowing* a
  query's `SELECT` list can empty the result set. An integrator whose policy filters on
  a field MUST keep projecting it, or push that filter into the query so the source
  applies it.

Without rewriting, the consequence is a resource bound rather than a disclosure: a
large result set is fetched and materialized before being trimmed (threat-model D2).
That is why rewriting is worth offering — but a document or integrator must never
describe it as the thing that makes the policy safe.

**Negative operators need an `IS NULL` arm when pushed down.** SQL `col <> 'x'` is
unknown-therefore-false for a null `col`, so the database drops a row the
post-execution pass would keep (§7 drops rows whose field is *absent*, not rows whose
value is null). A pushed-down negative filter MUST therefore be rendered as
`(col <> 'x' OR col IS NULL)` so both paths select the same rows. Without this, the
same policy returns fewer rows when the optimization is enabled — a silent
behavioral difference between two paths that are supposed to be equivalent.

This applies to **every** negative operator, without exception:
`notEquals`, `notIn`, and `notLike`. `NULL NOT LIKE 'x'` is unknown for exactly the
same reason `NULL <> 'x'` is, so `notLike` needs the arm as much as the other two. An
implementation that adds it to some negatives and not others is inconsistent with
itself: the same policy's rows then depend on which operator the author happened to
choose, which is not a distinction the policy expresses. This was a real defect —
both rewriters emitted the arm for `notEquals` and `notIn` and omitted it for
`notLike`, and the two post-execution passes disagreed with each other about the same
case.

Correspondingly in the post-execution pass (§7): all three negative operators **keep**
a row whose field is present with a null value, and **drop** a row whose field is
absent. The two rules exist for different reasons — the first keeps pushdown and
post-fetch equivalent, the second is the fail-closed rule for a value that cannot be
established — and both apply to all three operators alike.

**`like` and `notLike` MUST NOT be pushed down unless the dialect guarantees a
case-sensitive comparison.** The post-execution pass compares case-sensitively (§7) and
is engine-independent, but a pushed-down `LIKE` inherits the *column's collation*:

| Engine | `'ALICE JONES' LIKE 'alice%'` |
| --- | --- |
| Postgres | false — `LIKE` is case-sensitive |
| MySQL, default `utf8mb4_0900_ai_ci` | **true** — the collation is case- and accent-insensitive |

So on MySQL the two paths select different **real** rows, not merely an edge-case null:
a policy filtering `name notLike 'alice%'` drops `'ALICE JONES'` when pushed down and
keeps it when applied post-fetch. That is strictly worse than the null asymmetry above,
because it silently changes which records a user sees.

A `COLLATE` clause can force the comparison (`… LIKE 'alice%' COLLATE utf8mb4_0900_as_cs`
returns false, as does `BINARY`), so this is technically emittable. It is nonetheless
**not** the required behavior: the correct collation name depends on the column's
character set, which a rewriter holding only a policy and a query string does not know,
and guessing wrong either fails the query or silently changes the comparison again.

Therefore:

- The `postgres` and `trino` profiles MAY push `like`/`notLike` — their `LIKE` is
  case-sensitive.
- The `mysql`, `sqlserver`, and `ansi` profiles MUST NOT. `ansi` is included because it
  is the strict intersection and makes no collation promise; `sqlserver` because its
  default collation is also case-insensitive.
- A declined filter is reported as unpushable and enforced by the post-execution pass, so
  the policy is still applied — only the optimization is skipped.

This is the same principle as refusing a value containing a backslash: where an
implementation cannot guarantee the pushed-down form means exactly what the
post-execution form means, it declines to push rather than emitting something that
usually agrees.

**Escaping is not sufficient; refusal is.** Doubling `'` does not make arbitrary text
safe: MySQL treats `\` as a string escape by default, so `\'` leaves the literal
open, and a NUL or newline can truncate a statement or terminate a `--` comment. A
rewriter MUST refuse to push a value containing a backslash or control character and
MUST validate identifiers against a conservative pattern rather than merely quoting
them.

### Single records

A tool returning one record MUST run the identical pipeline. Previously the
single-record branch applied masking only, skipping row filters, tag filters and
limits — so a `deniedTags` record returned by a get-by-id tool was disclosed.

When the pipeline drops that single record, the result is the language's null value
(`null` in .NET and TypeScript, `None` in Python) — **not** an empty record. An
empty record would imply the row existed but had no visible fields, which is a
different statement from "this row is not available to you."

### Field-name matching

Field references match both bare and table-qualified forms, in both directions:
a rule `patients.ssn` matches a key `ssn`, and a rule `ssn` matches a key
`patients.ssn`. Matching is case-insensitive. Masking and hidden-field removal
recurse into nested objects and arrays.

## 5. Result shapes — fail closed

| Shape                              | Behavior            |
| ---------------------------------- | ------------------- |
| Record (dict/map/object)            | Full pipeline       |
| List of records                     | Full pipeline       |
| Nested JSON body (HTTP)             | Full pipeline, walked recursively |
| Anything else — POCO/DTO, scalar, stream, unmaterialized iterator | **DENY** |

Unenforceable shapes are denied with an actionable error naming the observed
shape. Integrators mid-migration may opt out explicitly per wrapper via
`allowUnenforceableShapes` (`allow_unenforceable_shapes` in Python), which MUST
be off by default and SHOULD be logged when enabled. This implements threat-model
remediation R-3 and resolves the contradiction where `SECURITY.md` conceded that
enforcement "may pass results through unfiltered" while `README.md` promised
enforcement was non-bypassable.

## 6. Masking

### Restrictiveness ranking

Ranked by how much of the original value is disclosed, most-restrictive wins:

| Rank | Mask type | Disclosure                                |
| ---- | --------- | ----------------------------------------- |
| 5    | `null`    | Nothing — value and its length both gone   |
| 4    | `redact`  | Nothing — fixed placeholder                |
| 3    | `full`    | Length only                                |
| 2    | `hash`    | Irreversible, but stable/joinable          |
| 1    | `partial` | Real characters of the original value      |

The previous ranking placed `null` and `redact` *lowest*, so merging
`ssn: null` with `ssn: partial` produced `partial` — disclosing real SSN digits
that one policy had demanded be erased entirely.

### `hash` masking is a cross-language join key

The `hash` mask exists so the same input yields the same pseudonym everywhere, which
makes it usable as a join key across services. That only holds if every SDK computes
the same digest, so the algorithm is part of the contract:

- The `algorithm` parameter MUST be honoured. Permitted values are those in the
  schema: `sha256` (the default when absent), `sha512`, and `blake2b`.
- The digest is rendered lower-case hexadecimal and truncated to the first **16**
  characters.
- `blake2b` means BLAKE2b-512. Runtimes spell this differently — Node requires
  `blake2b512` while `blake2b` throws — so each SDK maps the schema value to its
  runtime's name rather than passing it through.
- An algorithm the runtime cannot provide MUST NOT abort the result pass and MUST NOT
  disclose the original value. Fail closed by treating the field as `redact`.

This was previously divergent: Python and .NET hardcoded SHA-256 and ignored
`algorithm` entirely, while TypeScript honoured it. A policy specifying `sha512`
therefore produced `01a54629efb95228` in Python and `fbe47783b1d59d46` in
TypeScript for the same SSN — two different pseudonyms for one value, so any
cross-service join on the masked column silently failed while both sides looked
correct in isolation.

### Unknown mask types fail closed

An unrecognized `maskType` MUST NOT return the raw value. It is treated as
`redact`. A typo or a mask type from a newer schema version must not silently
disable masking. When merging, an unknown type is ranked most-restrictive so it
cannot be beaten by a weaker known type.

### Partial masking

`showFirst + showLast >= len(value)` MUST NOT return the unmasked value; it
degrades to a full mask.

## 7. Row filters — fail closed

When the referenced field is absent from a row, the row is **dropped**, for every
operator including the negative ones (`notEquals`, `notIn`).

Previously the negative operators failed *open*: a missing field yields
`undefined != "x"` → true, so a filter written to exclude classified rows
retained every row that simply lacked the column.

Additional requirements:

- `matches` compiles as `^(?:pattern)$`. The non-capturing group is required:
  `^hr|finance$` binds `^` to `hr` only and matches `hr_secret_internal`.
- Regex evaluation is bounded by a timeout (ReDoS guard) and a regex error is a
  non-match, never an exception that aborts the result pass.
- Comparison operators guard against type mismatch: a non-comparable value is a
  non-match (row dropped), never a raised exception.
- `equals`/`notEquals` do not conflate booleans with numbers (`1` != `true`).

### `like` and `notLike`

SQL `LIKE` semantics: `%` matches any sequence, `_` matches any single character, `\`
escapes either. The pattern is anchored as a full match, and every other character is
literal — a `like` pattern is **not** a regex back door, so an implementation MUST escape
regex metacharacters when translating.

**Matching is case-SENSITIVE.** This is the one string operator that is, and it is
deliberate: `LIKE` is case-sensitive in Postgres (`'alice' LIKE 'ALICE%'` is false), and a
`like` filter may be pushed into a `WHERE` clause as a literal `LIKE`. If the
post-execution pass matched case-insensitively, the same policy would select different
rows depending on whether the optional rewriting was enabled — the divergence class this
document exists to prevent. Use `matches` with an inline flag, or `contains`, when
case-insensitive matching is wanted.

Note this differs from *field-name* and *tag-value* matching, which are case-insensitive
(§4). Names are identifiers, where case is incidental; `like` compares data, where the
database's own semantics govern.

`notLike` drops a row whose value is null, matching SQL's three-valued logic
(`NULL NOT LIKE 'x'` is unknown, therefore not retained).

Both are bounded by the same length limits as `matches` (ReDoS guard).

## 8. Permission merging

Absent boolean permissions take their schema default *before* folding:
`canQuery` → `true`, the write permissions (`canInsert`/`canUpdate`/`canDelete`)
→ `false`, `readOnly` → `true`. Then fold: `canQuery` and the write permissions
AND, `readOnly` OR.

Excluding absent fields from the fold instead of defaulting them inverts the
result: policy A silent on `readOnly` plus policy B with `readOnly: false` must
yield `true` (restrictive), not `false`.

## 9. Write protection — `readOnly` and `allowedMethods`

Two controls gate mutating operations, and both previously failed **open**.

### `readOnly`

`permissions.readOnly` means what the schema says: "only read operations are
permitted. Write, update, and delete operations are blocked." It MUST be enforced,
not merely merged.

When `readOnly` is true, a request whose method is not a read method is **denied**,
regardless of `allowedMethods`. Read methods are `GET`, `HEAD`, and `OPTIONS`.
`readOnly` is a ceiling: listing `DELETE` in `allowedMethods` does not lift it, since
the two must compose most-restrictively like every other pair of rules.

Previously `readOnly` was OR-folded during merge and then never read, so a policy
with `readOnly: true` and `allowedMethods: ["GET", "DELETE"]` permitted `DELETE`.
An administrator could set the flag, see it survive resolution, and still have writes
allowed.

### `allowedMethods` when omitted

An **absent** `allowedMethods` defaults to the read methods `GET`, `HEAD`, `OPTIONS`
— not to "unrestricted". This is the reading the schema documents, and it is the
safe one: the field exists to constrain methods, so its absence must not be the most
permissive possible setting.

This is a deliberate exception to §3's `null`-means-unrestricted rule, and the only
one. It exists because an omitted method list on an endpoint rule is far more likely
to be an oversight than an intentional grant of `DELETE`. An integrator who genuinely
wants every method must say so explicitly.

An **empty** `allowedMethods` (`[]`) denies every method, per §3.

## 10. Policy resolution — `sourcePatterns`

A policy definition's `sourcePatterns` declares **which data sources the policy
applies to**, using globs in `category:namespace:pattern` form (for example
`db:production:patient_*`, `api:internal:*`, `kb:*:*`). Resolution MUST use it as
a filter:

| `sourcePatterns` | Behavior during resolution                                   |
| ---------------- | ------------------------------------------------------------ |
| absent or `[]`   | The policy applies to **every** data source                   |
| non-empty        | The policy applies only when one pattern matches the resolved `sourceConnectionId` |

A definition whose patterns do not match the source being resolved is **excluded**
before merging. Ignoring the field means a policy scoped to `db:production:*` also
governs an unrelated API or knowledge-base source, so the effective policy for a
source is assembled from rules that were never intended to apply to it. Whether
that widens or narrows access depends on the policies involved — a rule intended
for one source can leak permissions into another, or an unrelated restriction can
deny a source it was never meant to cover. Either way the resolved policy is not
the one the administrator authored.

Matching is glob-based and case-insensitive; `*` matches within a segment and does
not cross the `:` separator. Absent patterns defaulting to "applies to all"
preserves the common case of a policy that is genuinely source-agnostic.

This section exists because the three SDKs disagreed: .NET filtered on
`sourcePatterns` while Python and TypeScript ignored it entirely, so the same
policy set resolved to different effective access per language. The spec was
silent, which is how the divergence survived.

## 11. Identity extraction failures

An identity extractor either returns a trustworthy principal or it fails. It MUST
NOT return "no identity" for a token that was *presented and rejected*, because a
caller that treats a null principal as anonymous converts an authentication
failure into an authorization decision — the request proceeds and resolves
whatever an anonymous or default assignment happens to grant.

Required behavior, identical in all three SDKs:

| Situation                                                     | Behavior            |
| ------------------------------------------------------------- | ------------------- |
| No credential presented at all                                | Return no identity  |
| Credential presented but malformed, wrong algorithm, `alg=none`, bad signature, expired, or missing required claims | **Raise/throw**     |

The distinction is *presented and invalid* versus *absent*. Absent is a legitimate
anonymous request the integrator may choose to allow; invalid is an attack or a
misconfiguration and must be loud. Errors MUST NOT disclose whether a token merely
expired versus failed verification beyond what the integrator logs.

`nbf` (not-before), when present, is validated with the same leeway as `exp`.
A token presented before its `nbf` is invalid, not anonymous.

## 12. Revocation

Revoking an assignment MUST make it stop resolving. Emitting a `PolicyRevoked`
audit event while leaving the assignment active is a fail-open control with a
misleading audit trail. Tests MUST assert that access is gone after revocation,
not merely that an audit event fired.

`PolicyAssignment.revokedAt` is the revocation tombstone, and the SDK resolver
enforces it: an assignment whose `revokedAt` is set and not future-dated MUST NOT
resolve, regardless of `active` or `expiresAt`. The rules:

- Revocation is checked **before** `active` and `expiresAt`, and overrides both. A
  revoked assignment does not become live again by being marked active.
- A **future-dated** `revokedAt` is not yet in effect, mirroring `expiresAt`. This
  keeps a scheduled revocation expressible rather than making the field a boolean
  in disguise.
- An **unparseable or empty** `revokedAt` MUST NOT resolve — the fail-closed
  direction. A revocation that cannot be read is honoured, because the alternative
  keeps a revoked grant silently alive. Note this is the opposite of a truthiness
  check, which would read `""` as "never revoked".

  The *mechanism* differs by language, and both are acceptable because both deny.
  Python and TypeScript model the field as a string and treat an unreadable value as
  revoked inside the resolver; .NET types it as `DateTimeOffset?`, so a malformed
  value is rejected at deserialization with a `JsonException` before the resolver
  runs. What MUST hold everywhere is that no such value produces a *resolving*
  assignment.
- `revokedAt` is separate from `active` deliberately, so deactivating cannot be
  mistaken for revoking, and the grant stays visible to auditors after revocation.

A store that filters revoked rows in its own query (as the reference server does
with `revoked_at IS NULL`) is doing defence in depth, not the only enforcement.
Before this field existed, that filter *was* the only thing implementing this
section, so a store that omitted it failed open with nothing to catch it.

## 13. Known limitations

These are deliberate, documented gaps rather than defects. They are recorded here
so integrators can compensate and so nobody mistakes them for guarantees.

- **A signed context is replayable for its full TTL unless a replay guard is
  wired up.** Contexts carry a `jti` (§13.1) and every SDK accepts an optional
  `ReplayGuard` at deserialization, which makes a context single-use. Detection is
  opt-in because the state it needs — a shared record of consumed identifiers —
  is something the SDK cannot assume. With no guard, expiry remains the only
  replay bound: keep TTLs short (the default is one hour), use TLS on every hop,
  and treat a context as a bearer credential.
- **`hash` masking is only a confidentiality control when salted.** Unsalted it is
  a truncated digest — stable, so it works as a pseudonymous join key, and
  therefore brute-forceable for low-entropy values (SSNs, dates of birth, small
  enumerations). Configure a `hashSalt` (§13.2) to make it a keyed HMAC, or use
  `redact`/`null` when the value must not be derivable at all. Truncation length is
  16 hex characters in every form and every SDK.
- **ReDoS mitigation differs by mechanism.** .NET applies a regex match timeout;
  Python and TypeScript bound pattern and input length (their runtimes have no
  regex timeout). All three refuse the same inputs and treat a regex failure as a
  non-match, but the point at which a pathological pattern is stopped is not
  identical across languages.
- **Policy authors are trusted.** Policies are authored by administrators, not by
  agents or end users. A deliberately malicious policy (for example a pathological
  regex) is outside the threat model, though the bounds above limit the damage.
- **Purpose is caller-asserted.** TOLAP checks that a declared purpose matches a
  policy (§15.1) and that a delegation chain is internally consistent (§15.3). It
  cannot check that the caller was honest about its purpose in the first place. An
  integrator that declares `campaign-x-overlap` and then does something else gets
  whatever that policy grants. Purpose binding constrains a cooperative agent that
  drifts, and narrows the blast radius of one that is compromised mid-task; it is not
  a defence against a lying integrator. The control it does provide is real: the
  purpose is inside the signature, so a *captured* context cannot be repurposed.
- **`security-context.schema.json` describes the signed projection, not any SDK's
  native context type.** The three SDKs deliberately keep different public models —
  .NET carries a `policies` array, Python and TypeScript a single effective policy —
  and converge only at the canonical form. So the schema validates a canonical
  payload and cannot validate a deserialized native object, and it does not constrain
  `signature`/`algorithm`, which sit outside the signed bytes by construction. It also
  does not `$ref` `effective-policy.schema.json`: no schema here uses a cross-file
  `$ref`, because the four validators in this repository would each need a resolver
  configured with a local store and one of them silently lacking it would mean a
  schema validating nothing. Each `policies` entry must therefore be validated
  against `effective-policy.schema.json` separately, in fragment mode.
- **The judge is non-deterministic and advisory.** Its verdict cannot be pinned by
  the shared fixture corpus the way every other behaviour here is, so cross-SDK
  agreement covers the disposition mapping (§15.4) and not the verdict. It is
  strictly subtractive by design, so a manipulated or malfunctioning judge cannot
  widen access — but neither can it be relied on to catch a given case. Treat it as a
  detection layer over the deterministic three, never as one of them.
- **HMAC signing only.** Every verifier holds a key that can also sign, so a
  compromised verifier can mint contexts. `ed25519` is in the schema's algorithm
  enum and unimplemented in all three SDKs; selecting it fails loudly rather than
  falling back (a silent downgrade to HMAC would be worse than an error). Asymmetric
  signing needs a third-party dependency in at least one runtime, which the
  zero-runtime-dependency rule for `core` currently forbids.

### 13.1 Replay detection — `jti`

`SecurityContext.jti` is a unique context identifier. The rules:

- It is **inside the signed payload** when present. Stripping or swapping it MUST
  invalidate the signature — otherwise a guard is trivially bypassed by removing
  the field, and a test that only replays an unmodified context would not notice.
- It is **omitted from the canonical payload entirely when absent**, so a context
  without a `jti` produces byte-identical bytes to the pre-`jti` form. This keeps
  the known-answer fixtures and cross-SDK agreement intact. An empty string MUST
  normalize to absent, so `""` and omitted cannot yield two different signatures.
- Context builders mint one by default (UUID in Python/TypeScript, GUID in .NET), so
  contexts are replay-checkable without the caller opting in.
- A `ReplayGuard` records consumed identifiers. Implementations MUST be atomic:
  check-then-register as two steps lets concurrent replays both succeed, under
  exactly the load an attacker generates.
- When a guard is active, a context carrying **no** `jti` MUST be rejected rather
  than passed through — silently skipping the check is the failure mode the guard
  exists to prevent.
- The replay check MUST run **after** signature and expiry validation. Checking
  earlier lets an attacker consume the identifier of a context that was going to be
  rejected anyway, denying the legitimate holder its first use.

### 13.2 Salted `hash` masking — `hashSalt`

When a salt is configured, `hash` masking computes `HMAC(salt, value)` instead of a
bare digest, truncated to the same 16 hex characters.

- The salt is a **deployment secret**, configured on the wrapper, and MUST NOT be a
  policy field: policies are readable by every administrator and auditor, which
  would defeat the point.
- `blake2b` uses the **RFC 2104 HMAC construction** over BLAKE2b-512, not BLAKE2b's
  native keyed mode. The two produce different digests; RFC 2104 is what Python's
  `hmac` and Node's `createHmac("blake2b512")` compute, and all three SDKs MUST
  agree byte-for-byte or the pseudonym stops joining across services.
- An absent or empty salt MUST reproduce the unsalted digest exactly, so existing
  join keys survive an upgrade.
- Salting MUST NOT change the fail-closed behaviour for an unsupported `algorithm`;
  it still degrades to `redact`.
- The same salt yields the same pseudonym everywhere, which is what preserves the
  join-key property — and why changing it changes every masked value.

## 14. Conformance

### Signing known-answer

`fixtures/signing/hmac-sha256-known-answer.json` carries an `expectedSignature`
computed per this spec, `hmac-sha256-subsecond.json` pins the millisecond
truncation rule, and `hmac-sha256-purpose-bound.json` pins the two envelope fields
§15 adds — a `declaredPurpose`, a three-hop `delegationChain` whose last hop carries
microsecond input, and a policy carrying a `purposeProfile`. All three SDKs MUST load
all three fixtures and assert their computed signature equals the expected value
byte-for-byte.

The first two fixtures MUST remain byte-identical after any change to the envelope,
which is what demonstrates §2 rule 6 rather than merely claiming it: a context
carrying none of the optional fields still signs to its pre-existing bytes. Assert
that directly as well, by comparing the canonical payload of a context whose optional
fields are null against one whose are empty strings and empty arrays — an
implementation that emitted `""` would pass the older fixtures and still give one
context two valid signatures. A determinism-only assertion
(sign twice, compare to itself) is insufficient — it passes even when every
implementation disagrees with the others, which is how the divergence in §1/§2
went unnoticed. Assertions MUST be unconditional: a test that skips when the
expected value is absent restores the same blind spot.

### Schema conformance

`schema/v1.0/*.json` is the published contract, and each SDK re-declares parts of
it in native types (enums, records, interfaces). Those declarations drift silently
unless something compares them.

Every SDK MUST have a test asserting that its native enumerations match the schema
enumerations exactly — no value the schema permits that the SDK rejects, and no
value the SDK accepts that the schema forbids. At minimum this covers
`FilterOperator`, `MaskType`, `AssigneeType`, and `SigningAlgorithm`.

The operator enumeration is duplicated in `policy-definition.schema.json` and
`effective-policy.schema.json`; the two MUST stay identical, because an effective
policy is the merged product of definitions, so any operator a definition can
express has to survive resolution. A test SHOULD assert the two enumerations are
equal rather than relying on reviewers to notice.

Every fixture under `fixtures/` MUST validate against the relevant schema. This is
how a fixture that quietly uses an unsupported operator, or a schema field no SDK
reads, becomes visible.

The `purposeProfile` subschema is duplicated between the same two files for the
same reason, and MUST likewise stay identical: the merger carries a profile from
definition into effective policy, so anything a definition may express has to be
expressible in the resolved document. It is compared in full rather than field by
field, so adding a property to one side and not the other fails.

`PrincipalType` is declared in `security-context.schema.json` under
`$defs/delegationHop`, and gets the same both-directions enumeration check as the
other four. Every `principalType` token appearing in `fixtures/` MUST additionally be
one each SDK accepts — the corpus check catches a fixture the schema would permit but
a deserializer refuses, which is a different failure from the two enumerations
disagreeing.

The canonical payload of every `fixtures/signing/*.json` MUST validate against
`security-context.schema.json`, and each of its `policies` entries against
`effective-policy.schema.json` in fragment mode. That is what makes the envelope's
shape checked rather than merely described: before this schema existed, a signing
fixture could carry any field at all and nothing would notice.

A fixture may be **deliberately** schema-invalid to prove a rejection — a delegation
hop carrying a mis-cased purpose, for instance, which the chain validator must refuse
even though no schema-valid context could contain one (the SDK deserializers do not
enforce schema patterns, so a chain assembled in code can). Such a case MUST carry an
explicit marker and a validator MUST assert **positively** that it stays invalid, on
the same reasoning as `invalid-bad-mask-type.json`: a fixture that silently became
valid would stop exercising a rejection while every test still passed.

## 15. Purpose binding

TOLAP's other sections answer "what may this identity see?". This one answers "and
for what?". A signed context binds identity, tenant, source and expiry, but not the
reason the data is being read — so an agent holding a legitimate context may use it
for any purpose its policy happens to permit. An agent that drifts off-task is
indistinguishable from one that has not.

Purpose binding makes the declared reason an input to resolution and part of the
signed bytes. It is **opt-in and additive**: a policy with no `purposeProfile`, and
a caller declaring no purpose, behave exactly as they did before this section
existed, down to the signed bytes (§2 rule 6).

There are three deterministic enforcement points and one optional non-deterministic
one. The deterministic three have no external dependencies and MUST be implemented
in all three SDKs. The judge (§15.4) is optional, advisory, and strictly
subtractive.

**What this does not do.** Purpose is *asserted* by the caller. TOLAP verifies that
the assertion matches a policy, and that a delegation chain is internally
consistent, but it cannot verify that the caller was honest about its purpose. This
constrains a cooperative-but-drifting agent, not a lying integrator. See §13.

### 15.1 Resolution-time purpose filtering

A definition's `purposeProfile.purposeId` declares **which purpose the policy serves**.
Resolution MUST use it as a filter:

| `purposeProfile` | `declaredPurpose` | Behavior during resolution |
| ---------------- | ----------------- | -------------------------- |
| absent           | anything          | The policy applies. This is what keeps every pre-purpose policy resolving unchanged. |
| present          | absent or empty   | The policy is **excluded**. A purpose-scoped policy is not a default grant. |
| present          | equal to `purposeId` | The policy applies. |
| present          | anything else     | The policy is **excluded**. |

The comparison is **exact and case-sensitive**. It is deliberately *not* the glob
matching used for `sourcePatterns` (§10) or for chain narrowing (§15.3): those match
authored patterns against a family of values, whereas this compares one asserted
identifier against one declared identifier. A glob comparison here would let a
caller declaring `*` resolve every purpose-scoped policy in the store, and a
case-insensitive one would let `Campaign-X` resolve a policy written for
`campaign-x`.

Filtering MUST run **before** the merge, alongside the `sourcePatterns` filter and
for the identical reason: a definition that does not apply must not fold its rules
into the effective policy at all. Filtering afterwards means the rules have already
merged, and whether that widens or narrows access depends on the policies
involved — either way the resolved policy is not the one the administrator authored.

When every candidate is purpose-scoped and no matching purpose is declared, the
filtered set is empty and resolution returns the same deny-all it returns for any
empty set. No separate deny path is needed, and adding one would be a second place
for the fail-closed behaviour to drift.

The filter MUST be applied **per candidate**, not as a set operation. The same
definition can be reached by two assignments and therefore appear twice; a
de-duplicating filter changes which rules merge.

### 15.2 Action validation

`allowedActions` and `prohibitedActions` name semantic action categories — what an
operation *does*, as distinct from which object it touches. A tool call carrying a
category MUST be validated against the resolved policy's profile:

```
validateAction(actionCategory, purposeProfile) -> AccessResult

  IF prohibitedActions contains actionCategory  -> DENY
     "action '{c}' is prohibited under purpose '{p}'"
  IF allowedActions is not null
     AND allowedActions does not contain actionCategory -> DENY
     "action '{c}' not in allowed actions for purpose '{p}'"
  ELSE -> ALLOW
```

Prohibited is checked first, so a category in both lists is denied and reports the
more specific reason — the same ordering §9 uses for hidden before allowed.

`allowedActions` follows §3: absent is unrestricted, `[]` denies every action. Absence
is a genuine grant here rather than an oversight, because a purpose may legitimately
constrain only what is *forbidden*. This is unlike `allowedMethods` (§9), where
absence defaults to the read methods.

Category comparison is **case-insensitive** — the opposite of the `purposeId`
comparison in §15.1. Both choices point the same way, which is the property that
matters: a mis-cased purpose resolves nothing, and a mis-cased category is still
caught by a prohibition. A case-sensitive comparison here would let `EXPORT_PII`
walk past a prohibition on `export_pii`. The reason string echoes the category **as
supplied**, not normalized, so a log shows what was attempted.

#### Where the category comes from

The category MUST come from administrator-supplied wrapper configuration, never
from the caller. A caller that can name its own action category can name a
permitted one, which reduces the check to a formality.

The two wrapper families key that configuration differently, because they identify
a call differently:

| Wrapper | Key | Example |
| ------- | --- | ------- |
| MCP / context | tool name, matched exactly and case-sensitively | `segment_overlap` → `aggregate_overlap` |
| HTTP / API | `"METHOD path-glob"`, method case-insensitive, path matched with the endpoint glob dialect of [connector-spec §3.1](connector-spec.md#31-glob-matching) | `GET /segments/*` → `aggregate_overlap` |

An HTTP request has no tool name, so a name-keyed map would leave this enforcement
point permanently inert for `api` sources. A control the configuration implies and
that never runs is worse than no control, because nothing looks wrong.

For the HTTP wrapper the check MUST run **per hop**, so a redirect target is
classified too — a 307 to `/export/all.csv` is a different action from the `GET`
that began the chain. The path is matched with the query string stripped, so a
category can be neither dodged by appending a query nor missed because one was
present.

When several HTTP entries match one request, **all** matching categories are
validated and any denial wins. Resolving by specificity would need a precedence
rule, and any such rule can be gamed by adding a broader entry; evaluating every
match makes the outcome independent of map ordering.

**Fail closed on an unclassified call.** When no entry matches and the resolved
profile constrains actions at all — a non-null `allowedActions`, or a non-empty
`prohibitedActions` — the call MUST be denied:

```
"action category not declared for tool"
```

The deny-list half is the less obvious and more important one. A purpose declaring
only `prohibitedActions: ["export_pii"]` means "anything but exporting PII", and an
unclassified tool might be exactly that. Permitting the unclassified while
forbidding the classified cannot be what the author meant. An **empty**
`prohibitedActions` restricts nothing and so does not make a call unclassifiable —
the two arrays read in opposite directions, per §3.

The reason is phrased as a configuration fault rather than an access fault because
that is what it is: the fix is to classify the tool, not to widen the policy.

### 15.3 Delegation chain narrowing

`SecurityContext.delegationChain` records how authority reached the principal making
a call — a human delegates to an agent, which delegates to a sub-agent. Each hop
carries a `principalId`, a `principalType` (`user`, `agent`, `service`), and
optionally a `declaredPurpose`, a `delegatedAt` and a `scopeNarrowing`.

The invariant: **a chain may narrow at every hop and never widen.**

```
validateDelegationChain(chain) -> AccessResult

  IF chain is absent, empty, or a single hop -> ALLOW
  FOR each adjacent (parent, child):
    IF both declare a purpose AND child is not within parent's scope -> DENY
       "delegation hop {i} purpose '{child}' is not within parent scope '{parent}'"
    IF both declare scopeNarrowing AND child is not a subset of parent -> DENY
       "delegation hop {i} scopes exceed parent delegation"
  ALLOW
```

`{i}` is the child hop's index, so a denial names the offending hop.

An absent chain is not treated as suspicious: delegation is opt-in, and every
context predating this section carries none. A single hop has no parent to widen
against, so there is nothing to check however implausible its purpose.

Either side of a comparison being absent adds no constraint. A hop declaring no
purpose is not claiming one, so there is nothing to exceed; refusing an undeclared
purpose is §15.1's job, and doing it here as well would deny every legitimate
partial chain.

#### Purpose narrowing

A child purpose is **within** its parent's scope when any of these holds:

1. It equals the parent exactly. Delegation without narrowing.
2. The parent contains a wildcard that matches it, so `campaign-*` admits
   `campaign-x-overlap`. This is how a parent expresses "any purpose in this family".
3. It extends the parent on a `-` **segment boundary**, so `campaign-x` admits
   `campaign-x-overlap`.

| Parent       | Child                | Verdict | Why |
| ------------ | -------------------- | ------- | --- |
| `campaign-x` | `campaign-x`         | allow   | exact |
| `campaign-*` | `campaign-x-overlap` | allow   | parent glob |
| `campaign-x` | `campaign-x-overlap` | allow   | segment boundary |
| `campaign-x` | `campaign-xyz-evil`  | **DENY** | mid-segment |
| `campaign-x` | `campaign-x2`        | **DENY** | mid-segment |
| `campaign-*` | `fraud-detection`    | **DENY** | outside the family |
| `campaign-x` | `Campaign-X`         | **DENY** | case-sensitive |

Rule 3's boundary requirement is load-bearing. A plain `startsWith` test — the
obvious implementation — accepts `campaign-xyz-evil` under `campaign-x`. The two
purposes are unrelated; one merely begins with the other's characters. Requiring the
boundary makes the prefix mean what a reader assumes it means.

Comparison is **case-sensitive**, matching §15.1. Note that both existing glob
helpers in every SDK are case-*insensitive*, so an implementation that reuses one
directly will admit `Campaign-X` under `campaign-x`. A dedicated matcher is
required; the rule in [connector-spec §3.1](connector-spec.md#31-glob-matching) that the
enforcement and source-pattern dialects must not be unified applies here as a third
dialect.

An unusable pattern is a **non-match**, which denies the hop. Same fail-closed
direction as §7 and §10.

#### Scope narrowing

`scopeNarrowing` lists the scopes still **in force** at a hop — *not* the scopes the
hop removed. Each hop's set MUST be a subset of its parent's. The field is named for
its effect rather than its contents; the subset rule is what fixes the reading.

An **empty** parent set therefore leaves nothing for a child to claim, and any child
scope exceeds it. That follows §3: on a set of what remains permitted, `[]` is the
most restrictive value, not the least.

#### Why the chain must be signed

`declaredPurpose` and `delegationChain` are inside the signed payload (§2). This is
not defence in depth; it is the precondition for validating the chain at all. An
unsigned chain can be rewritten by the principal it constrains, so a validator would
be checking the attacker's own arithmetic. Appending a hop, mutating a hop's purpose
or scopes, or reordering hops MUST all invalidate the signature — reordering
included, because hop 0 is the delegator and reversing a chain makes the sub-agent
the root.

#### Where the chain MUST be validated

An implementation's context validation — the step that verifies the signature and the
expiry before any call is permitted — MUST also validate the delegation chain, and MUST
do so **after** signature verification, for the reason above. A context whose chain
widens MUST be refused there, not merely refusable by a caller who remembers to ask.

A context **builder** MUST NOT validate the chain it is given: it records the chain, and
a builder that silently dropped an invalid one would emit a context that looked delegated
and was not. Issuers MAY call the validator themselves to fail early; that is an
optimization, not the control.

An absent, empty, or single-hop chain is allowed: there is no parent to widen against.
This is what makes the requirement backward compatible — every context predating this
section carries no chain.

A chain MUST carry at most **10 hops**, and an implementation MUST refuse a longer one on
its length **before** walking its hops, so an oversized structure costs one comparison
rather than a traversal. The same ceiling is declared as `maxItems` on `delegationChain` in
`security-context.schema.json`; the two MUST agree, and §14 checks that they do. Ten is
chosen because delegation depth is a property of a deployment's topology rather than of a
request, and real topologies are shallow — a human delegates to an agent, which delegates to
a sub-agent — so ten leaves room for an orchestrator or two while still bounding what an
issuer can put in a signed context.

A hop's shape is pinned by a published schema:
[`security-context.schema.json`](../schema/v1.0/security-context.schema.json) declares
`$defs/delegationHop`, and the `principalType` enumeration inside it gets the same
both-directions check against every SDK's native enum as the other four (§14). What
that schema does *not* do is described in §13 — it constrains the **canonical signing
projection** rather than any SDK's native context type, and it does not `$ref`
`effective-policy.schema.json`.

`$defs/delegationHop` is validated hop by hop against
`fixtures/purpose-binding/delegation-chains.json`, so the fixtures and the schema
check each other rather than one standing in for the other.

`fixtures/purpose-binding/` is **not** excluded from the fixture validator as a
directory. Two individual files in it are — `judge-dispositions.json` and
`judge-prompt-fencing.json` — because a verdict-to-disposition decision table and a
prompt-construction table carry neither a policy nor an envelope, so nothing in
`schema/v1.0/` describes them. Excluding files one at a time rather than the directory
is deliberate: `delegation-chains.json` is their neighbour and *is* validated, and a
directory-level exclusion would have taken it with them.

### 15.4 The semantic judge

An optional LLM check on whether a call *plausibly serves* its declared purpose.
Drift is a property of a sequence rather than of one call: an agent asking for one
more field each turn is unremarkable at every individual step and obvious across
ten. The deterministic checks cannot see that; a judge can.

Three properties are mandatory:

1. **Strictly subtractive.** A judge runs only after §15.1-§15.3 have already
   allowed a call, and can only take that allowance away. It is never consulted to
   permit something they denied. This is what makes prompt injection survivable: the
   worst a manipulated verdict achieves is an allow the deterministic rules had
   already granted. A judge that could widen access would make a persuasive prompt a
   privilege escalation.
2. **The rubric is administrator-controlled.** The prompt template is set where the
   wrapper is deployed, never in a policy and never by a caller. A policy is
   writable by administrators, and a caller-supplied template would let the subject
   of the check write its own rubric. Agent-influenced text — the tool call and the
   history — MUST be fenced and labelled as data.
3. **Escalate is not allow.** See the disposition table below.

#### Disposition

```
getDisposition(result, config) -> allow | block | escalate

  IF confidence is NaN, or outside [0, 1]      -> ESCALATE
  IF escalationThreshold > confidenceThreshold -> ESCALATE
  IF confidence < escalationThreshold          -> ESCALATE
  IF confidence < confidenceThreshold          -> ESCALATE
  IF aligned                                   -> ALLOW
  ELSE                                         -> BLOCK
```

Defaults when unconfigured: `confidenceThreshold` 0.85, `escalationThreshold` 0.60,
`maxLatencyMs` 2000, `historyWindow` 10. These match the schema's `default`
annotations, which are advisory to a validator and therefore not enforced by one — so
a test SHOULD assert the two agree, or a policy author configures against numbers the
SDK does not use.

The unusable-input checks come **first**, so a malformed result cannot reach a
threshold comparison and win one:

- A confidence outside `[0, 1]` means the judge has malfunctioned. Comparing `1.5`
  against a threshold would grant a broken answer more authority than a correct one,
  since it clears every bar. It MUST NOT be clamped: clamping launders it into a
  confident allow.
- Inverted thresholds have no reading to act on. Merging two judge configs can
  produce them, because both thresholds take the maximum independently.
- `NaN` fails every comparison and would otherwise fall through to whichever branch
  happened to be last.

A timeout, a transport failure, and an unparseable response MUST all produce
escalation rather than an exception or a guess. An exception escaping into the
authorization path invites a `catch` at the call site that returns "allow", which is
the failure mode worth designing out.

**`escalate` MUST be treated as a denial unless an escalation handler is wired.**
Otherwise "escalate to human review" silently means "permit" in every deployment
that never built the review step — a fail-open on precisely the ambiguous cases the
judge exists to surface.

#### The policy's judge configuration must actually apply

`purposeProfile.judge` names a `model`, a `historyWindow`, a `maxLatencyMs` and two
thresholds. Every one of them MUST be read from the resolved policy. Left to each
integrator's own glue, the predictable outcome is a judge running with a window and
thresholds nobody chose while the policy's `model` is quietly ignored — the
configuration implying a control that never runs.

The `model` field in particular MUST be verified: an implementation MUST expose which
model it invokes, and a mismatch against the policy's `model` MUST escalate
(`"judge model mismatch"`) **before** the call is made. Invoking the wrong model and
noticing afterwards has already spent the tokens and, worse, produced a verdict that
reads as authoritative in an audit log. Comparison is exact and case-sensitive:
`claude-sonnet` and `claude-sonnet-5` are different models, and a prefix rule would
let a deployment satisfy a policy demanding one by wiring the other. A policy naming
no model accepts any judge, since model ids differ per account and region.

Two policies naming different models cannot be merged and resolve to deny-all
(§15.5): a verdict is only meaningful against the model that produced it.

#### Where the judge MUST be invoked

An implementation MUST offer an enforcement entry point that, when a judge is configured,
runs the deterministic checks of §15.1–§15.3 and then the judge, applying the resolved
policy's judge configuration. The judge MUST NOT be reachable only through glue an
integrator writes: a control whose effect depends on every integration re-deriving the same
sequence is a control the configuration implies and that does not reliably run.

The sequence is normative. The judge MUST be consulted **only** for a call the deterministic
checks allowed, and its verdict MUST NOT be able to permit one they refused. Consulting it
about a refused call would make a persuasive prompt a privilege escalation, since the tool
call and the history are agent-influenced text.

Whether a judge is configured at all is a **deployment** decision, not a policy one: a policy
that asks for a judge where none is wired MUST resolve to the deterministic verdict rather
than an error, because those checks have already run and a judge could only have subtracted.
A judge MUST NOT be invoked for a policy whose profile does not ask for one, so enabling a
judge for one policy does not begin judging every other.

Ownership of tool-call history MUST remain with the integrator: a call can carry the arguments
a caller sent, so retention is theirs to decide. An implementation MUST accept a history
rather than creating one it keeps.

#### Conformance

The judge is the one component here that **cannot** be pinned by the shared fixture
corpus, because its answer is not a function of its input. `judge-dispositions.json`
pins the deterministic part — the verdict-to-disposition mapping — exhaustively. A
live check against a real model verifies only that a real response parses and that a
plainly off-purpose call is not confidently allowed; it MUST NOT assert a specific
confidence value, or the suite fails on a model update rather than on a defect. Live
tests belong in the credential-gated tier and MUST report as skipped, not passed,
when credentials are absent.

### 15.5 Merging purpose profiles

A purpose profile is carried from definition into `EffectivePolicy` by the merger,
because every enforcement entry point takes an effective policy. Without that, a
`purposeProfile` would be authorable and unenforceable. It also means the purpose
travels inside the signed bytes with no change to the signing projection — the policy
is already part of the signed envelope.

| Field | Rule |
| ----- | ---- |
| `purposeId` | All non-null profiles MUST agree. Disagreement → **deny-all** |
| `allowedActions` | Intersection. Disjoint lists yield `[]`, which denies every action (§3) |
| `prohibitedActions` | Union |
| `description` | First non-null, by ascending priority |
| `judge.enabled` | OR, preserving the three states absent / `false` / `true` |
| `judge.model` | MUST agree; disagreement → **deny-all** |
| `judge.historyWindow` | Maximum — more context helps a judge notice drift |
| `judge.confidenceThreshold` | Maximum — a higher bar sends more calls to review |
| `judge.escalationThreshold` | Maximum — escalate more |
| `judge.maxLatencyMs` | Minimum |

A purpose-agnostic policy merged with a purpose-scoped one yields the scoped
profile: a policy carrying no profile contributes no action restriction and MUST NOT
erase one.

Disagreeing `purposeId`s cannot arise *through* resolution, since §15.1 leaves a
single purpose. But the merger is a public entry point and MUST NOT depend on its
caller having filtered first. Refusing is the only safe answer: picking one profile
applies rules authored for a purpose the caller did not declare, and dropping the
profile turns a purpose-scoped policy into an unscoped one.

Every `judge` field is optional with no default value materialized at merge time.
Concrete defaults would serialize unconditionally — .NET's canonical writer does no
default-value elision — and so would change the signed bytes of every purpose-bound
policy.
