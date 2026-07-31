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
  "version":   string,
  "userId":    string,
  "tenantId":  string,
  "issuedAt":  string,   // RFC 3339 / ISO 8601, UTC, "Z" suffix
  "expiresAt": string,   // RFC 3339 / ISO 8601, UTC, "Z" suffix
  "policies":  [ EffectivePolicy, ... ]   // integrity block stripped from each
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

## 13. Known limitations

These are deliberate, documented gaps rather than defects. They are recorded here
so integrators can compensate and so nobody mistakes them for guarantees.

- **A valid signed context is replayable for its full TTL.** Contexts carry no
  nonce or `jti` and are not single-use, so expiry is the only replay bound. A
  captured context is usable until it expires. Keep TTLs short (the default is one
  hour), use TLS on every hop so contexts are not capturable in transit, and treat
  a context as a bearer credential. Single-use enforcement requires server-side
  state the SDK deliberately does not assume.
- **`hash` masking is not a confidentiality control.** It is an unsalted,
  truncated SHA-256 digest — stable, so it works as a pseudonymous join key, and
  therefore brute-forceable for low-entropy values (SSNs, dates of birth, small
  enumerations). Use `redact` or `null` when the value must actually be secret.
  Truncation length is 16 hex characters in all three SDKs.
- **ReDoS mitigation differs by mechanism.** .NET applies a regex match timeout;
  Python and TypeScript bound pattern and input length (their runtimes have no
  regex timeout). All three refuse the same inputs and treat a regex failure as a
  non-match, but the point at which a pathological pattern is stopped is not
  identical across languages.
- **Policy authors are trusted.** Policies are authored by administrators, not by
  agents or end users. A deliberately malicious policy (for example a pathological
  regex) is outside the threat model, though the bounds above limit the damage.

## 14. Conformance

### Signing known-answer

`fixtures/signing/hmac-sha256-known-answer.json` carries an `expectedSignature`
computed per this spec, and `hmac-sha256-subsecond.json` pins the millisecond
truncation rule. All three SDKs MUST load both fixtures and assert their computed
signature equals the expected value byte-for-byte. A determinism-only assertion
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
