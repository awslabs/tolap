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
   sub-second case (§12).

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
3. hidden fields    REMOVE hiddenFields from every record
4. allowed fields   PROJECT to allowedFields when specified (drop everything else)
5. masking          apply maskedFields transformations
6. result limit     truncate to maxResults
```

Steps 3 and 4 are mandatory and were previously absent from every
database/MCP wrapper (present only in the HTTP wrappers). `hiddenFields` and
`allowedFields` are **not** satisfied by a pre-execution check: the pre-check only
inspects the field list a caller volunteers, so any tool returning undeclared
columns (e.g. `SELECT *`) leaks them.

Ordering rationale: hidden/allowed removal precedes masking so that a field which
is both hidden and masked is removed rather than returned in masked form. The
limit is applied last so that filtering never yields fewer rows than `maxResults`
when more qualifying rows exist.

### Single records

A tool returning one record MUST run the identical pipeline. Previously the
single-record branch applied masking only, skipping row filters, tag filters and
limits — so a `deniedTags` record returned by a get-by-id tool was disclosed.

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

## 8. Permission merging

Absent boolean permissions take their schema default *before* folding:
`canQuery` → `true`, `canExport` → `false`, `readOnly` → `true`. Then fold:
`canQuery` AND, `canExport` AND, `readOnly` OR.

Excluding absent fields from the fold instead of defaulting them inverts the
result: policy A silent on `readOnly` plus policy B with `readOnly: false` must
yield `true` (restrictive), not `false`.

## 9. Identity extraction failures

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

## 10. Revocation

Revoking an assignment MUST make it stop resolving. Emitting a `PolicyRevoked`
audit event while leaving the assignment active is a fail-open control with a
misleading audit trail. Tests MUST assert that access is gone after revocation,
not merely that an audit event fired.

## 11. Known limitations

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

## 12. Conformance

`fixtures/signing/hmac-sha256-known-answer.json` carries an `expectedSignature`
computed per this spec. All three SDKs MUST load that fixture and assert their
computed signature equals it byte-for-byte. A determinism-only assertion (sign
twice, compare to itself) is insufficient — it passes even when every
implementation disagrees with the others, which is how the divergence in §1/§2
went unnoticed.
