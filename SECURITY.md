# Security Policy

## Reporting a vulnerability

If you discover a security issue in the TOLAP SDK, please report it privately.
**Do not open a public issue for security vulnerabilities.**

- Contact the maintainers directly (see repository owners) or file a
  confidential security ticket through your organization's standard process.
- Include: affected package(s) and language(s), version/commit, a description
  of the issue, and a proof-of-concept or reproduction steps if available.

We will acknowledge receipt, investigate, and coordinate a fix and disclosure
timeline with the reporter.

## Enforcement guarantees

The normative behavior every SDK implements is specified in
[`docs/canonical-enforcement-spec.md`](docs/canonical-enforcement-spec.md).
The guarantees that matter most:

- **Post-execution enforcement is complete.** Every wrapper applies row filters,
  tag filters, hidden-field removal, allowed-field projection, masking, and the
  result limit — in that order — to every result, including single records.
  Hidden and allowed fields are enforced on the **returned data**, not only
  pre-checked against a caller-declared field list.
- **Signatures cover the whole context.** The HMAC covers the full envelope
  including `expiresAt`/`issuedAt`, so a captured context's lifetime cannot be
  extended without the signing key.
- **One canonical form across languages.** All three SDKs sign byte-identical
  canonical JSON, so a context signed by one SDK verifies in the others. This is
  asserted against a shared known-answer fixture
  (`fixtures/signing/hmac-sha256-known-answer.json`) by all three test suites.
- **Ambiguity fails closed.** Missing/unparseable expiry, an unknown mask type,
  a row missing a filtered field, and an unenforceable result shape all deny
  rather than pass data through.

## Security-relevant usage guidance

TOLAP is a library embedded inside your tools/MCP servers. Some security
properties are a **shared responsibility** between the SDK and the integrator.
The following are the most important integrator obligations (see the threat
model for the full list):

- **Verify identity before trusting it.** `JwtIdentityExtractor` **verifies the
  HMAC signature, `exp`, and `nbf` by default** and fails closed on a
  bad/expired/`none` token. Construct it with a signing `secret`. Only pass the
  explicit unverified opt-in (`allow_unverified` / `CreateUnverified`) when a
  trusted upstream layer has already validated the JWT. For asymmetric algorithms
  (RS/ES), plug in an extractor that verifies with the issuer's public key.
  *(Threat S1 / remediation R-1 — resolved.)*
- **A rejected credential is an error, not an anonymous request.** All three SDKs
  distinguish *no credential presented* (which returns no identity, and which your
  application may legitimately treat as anonymous) from *a credential presented and
  found invalid* (which raises). Do not catch the latter and fall back to a default
  or anonymous policy — that converts an authentication failure into an
  authorization decision.
- **Protect the HMAC signing key.** Store the `SecurityContextSigner` key in a
  secrets manager / KMS. Never commit it or log it. Compromise of the key
  defeats tamper-evidence on signed contexts.
- **Salt `hash` masking, or do not rely on it for secrecy.** Unsalted, the `hash`
  mask is a truncated digest: a fine pseudonymous join key, but brute-forceable for
  low-entropy PII (SSN, DOB, small enumerations) because the input space is small
  enough to enumerate. Set `hashSalt` / `hash_salt` on the wrapper to make it a
  keyed HMAC, and treat that salt like the signing key — secrets manager or KMS,
  never in the policy JSON, which every admin and auditor can read. The same salt
  must be configured everywhere the pseudonym is joined. Use `redact` or `null`
  when the value must not be derivable at all. *(Threat I2 / remediation R-2 —
  resolved.)*
- **Unenforceable result shapes are denied.** The secure wrappers enforce over
  record-, record-list-, and nested-body-shaped results. A shape enforcement
  cannot inspect (a class instance/DTO, scalar, stream, or unmaterialized
  iterator) is **denied by default** rather than passed through unfiltered.
  Integrators mid-migration may opt out explicitly per wrapper with
  `allowUnenforceableShapes` / `allow_unenforceable_shapes`, which is off by
  default and logs a warning whenever it lets a result through — do not enable
  it in production. *(Threat I4 / remediation R-3 — resolved.)*
- **`Permissive` enforcement mode disables denials.** Use it only for staged
  rollout/observability, never in production. *(Threat I5.)*
- **Use a real, access-controlled policy store in production.** The in-memory
  store is for development and testing only.
- **Use TLS** on every network hop (policy store, signed-context transport,
  data source).
- **Wire up a replay guard, or treat a signed context as a bearer credential.**
  Each context carries a signed `jti`, and `deserializeContext` /
  `deserialize_context` / `SecurityContextSigner.Deserialize` accept an optional
  `ReplayGuard` that makes it single-use. Detection is opt-in because it needs a
  record of consumed identifiers the SDK cannot assume — the bundled in-memory
  guard is process-local, so anything multi-process needs a shared store (Redis,
  DynamoDB, a table). Without a guard, expiry is the only replay bound: keep TTLs
  short (the default is one hour). *(Threat T5 / spec §13.1.)*
- **Revocation is enforced by the SDK, not only by your store.** Setting
  `revokedAt` on an assignment stops it resolving, overriding `active` and
  `expiresAt`, and an unreadable value fails closed. If you implement your own
  store you should still filter revoked rows in your query, but that filter is no
  longer the only thing standing between a revoked grant and a resolved policy.
  *(Threat E2a / spec §12.)*

## Known limitations

Documented gaps, not guarantees — see
[the specification](docs/canonical-enforcement-spec.md) §13 for the full list and the
reasoning behind each:

- **HMAC signing only.** Every verifier holds a key that can also sign, so a
  compromised verifier can mint contexts. `ed25519` is in the schema enum and
  unimplemented; selecting it fails loudly rather than silently downgrading.
  Implementing it needs a third-party dependency in at least one runtime, which the
  zero-runtime-dependency rule for `core` forbids.
- **Replay detection and salted masking are opt-in.** Both mechanisms ship, but a
  deployment that configures neither gets the previous behaviour: TTL-bounded replay
  and pseudonymous-only `hash`. They are opt-in because each needs state or a secret
  the SDK cannot invent.
- **ReDoS mitigation differs by mechanism.** .NET uses a regex match timeout; Python
  and TypeScript bound pattern and input length, because their runtimes have no
  timeout. All three refuse the same inputs; the point at which a pathological
  pattern stops differs.
- **Policy authors are trusted.** Policies come from administrators, not agents or
  end users, and TOLAP enforces the policy you wrote rather than judging whether it
  is correct — `hiddenFields: ["ssn"]` protects nothing when the column is
  `ssn_number`.
- **One deployment of the reference server serves one tenant.** Any authenticated
  administrator sees every policy; `scope.tenantId` narrows which assignments apply,
  not who can read them.

## Supported versions

Schema version **v1.0**. Security fixes are applied to the latest release line.
