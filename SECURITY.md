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
- **`hash` masking is not confidentiality.** The `hash` mask is an unsalted,
  truncated SHA-256 digest suitable as a pseudonymous join key. For low-entropy
  PII (SSN, DOB, small enumerations) it is brute-forceable — use `redact` or
  `null` when true secrecy is required. *(Threat I2 / remediation R-2.)*
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
- **A signed context is a bearer credential.** It carries no nonce and is not
  single-use, so a captured context is replayable until it expires. Keep TTLs
  short (the default is one hour).

## Known limitations

Documented gaps, not guarantees — see
[the specification](docs/canonical-enforcement-spec.md) §11 for the full list:
full-TTL replay of a valid context, `hash` masking being a pseudonymous key rather
than a confidentiality control, ReDoS mitigation differing by mechanism across
languages, and the assumption that policy authors are trusted.

## Supported versions

Schema version **v1.0**. Security fixes are applied to the latest release line.
