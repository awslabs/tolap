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

## Security-relevant usage guidance

TOLAP is a library embedded inside your tools/MCP servers. Some security
properties are a **shared responsibility** between the SDK and the integrator.
The following are the most important integrator obligations (see the threat
model for the full list):

- **Verify identity before trusting it.** `JwtIdentityExtractor` **verifies the
  HMAC signature and `exp` by default** and fails closed on a bad/expired/`none`
  token. Construct it with a signing `secret`. Only pass the explicit
  unverified opt-in (`allow_unverified` / `CreateUnverified`) when a trusted
  upstream layer has already validated the JWT. For asymmetric algorithms
  (RS/ES), plug in an extractor that verifies with the issuer's public key.
  *(Threat S1 / remediation R-1 — resolved.)*
- **Protect the HMAC signing key.** Store the `SecurityContextSigner` key in a
  secrets manager / KMS. Never commit it or log it. Compromise of the key
  defeats tamper-evidence on signed contexts.
- **`hash` masking is not confidentiality.** The `hash` mask is an unsalted,
  truncated SHA-256 digest suitable as a pseudonymous join key. For low-entropy
  PII (SSN, DOB, small enumerations) it is brute-forceable — use `redact` or
  `null` when true secrecy is required. *(Threat I2 / remediation R-2.)*
- **Enforce over the result shapes you actually return.** The secure wrappers
  apply masking/filtering to record- and record-list-shaped results. Confirm
  your tool returns a supported shape, or enforcement may pass results through
  unfiltered. Prefer failing closed on unrecognized shapes. *(Threat I4 / R-3.)*
- **`Permissive` enforcement mode disables denials.** Use it only for staged
  rollout/observability, never in production. *(Threat I5.)*
- **Use a real, access-controlled policy store in production.** The in-memory
  store is for development and testing only.
- **Use TLS** on every network hop (policy store, signed-context transport,
  data source).

## Supported versions

Schema version **v1.0**. Security fixes are applied to the latest release line.
