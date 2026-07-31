# Changelog

All notable changes to TOLAP are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 2.0.0 — first public release

This is the initial public release, so there is no prior version to diff against and no
"unreleased" section. What follows describes the state of the code rather than a set of
changes.

Development history before this point is not in the repository: it was squashed into a
single commit for the public release, so this file — not `git log` — is the record of
what the pre-release work established. The rest of this entry is therefore written as
findings rather than as a list of commits.

### What ships

Three SDKs — .NET, Python, TypeScript — each with `core`, `store` and `mcp` packages, one
policy schema (`schema/v1.0/`) covering databases, APIs, knowledge bases and object
storage, and a normative specification in
[`docs/canonical-enforcement-spec.md`](docs/canonical-enforcement-spec.md).

A reference policy server (`server/`) with a PostgreSQL store, immutable versions with
publish and rollback, an audit trail, Cognito-authenticated admin access, and a
`GET /v1/resolve` endpoint returning a signed policy all three SDKs verify. An authoring
console (`console/`) and CDK to deploy both (`infra/`).

### Findings that shaped the design

These are recorded because each one changed a decision, and because several were true of
the code while the test suite reported success.

**The SDKs did not verify the same artifact.** Python and .NET check the `SecurityContext`
envelope and read `issuedAt`; the TypeScript wrapper verifies a bare `EffectivePolicy` via
`validatePolicy` and reads `resolvedAt`. Those are HMACs over different byte strings, so a
server signing one silently fails the others. The artifact carries both signatures and both
timestamp spellings — sound because the canonical projection strips `integrity` before
hashing (§2), so the policy-level signature cannot perturb the envelope bytes. Verified
through each SDK's real entry point.

**`[]` and `null` are opposite policies.** For an allow-list, absent means unrestricted
while an empty list denies everything (§3), so coercing either into the other is a
fail-open that converts the most restrictive policy expressible into no restriction at all.
Policy bodies are stored as opaque `jsonb` because a normalized table cannot represent
"empty list" distinctly from "no rows". `sourcePatterns` is the one documented exception
(§10), where absent and `[]` both mean "every source".

**Several controls were accepted and enforced nothing.** A security review of all three
SDKs found policy controls that were not applied to returned data, and signed contexts that
were not tamper-evident in the way the documentation claimed. Each is fixed in all three
languages with a regression test per defect. The class that recurred: a filter or limit the
service *accepted* while enforcing nothing, which no unit test could distinguish from a
working one because the fixtures asserted the document the SDK had chosen to emit. Live
services, not fixtures, caught those.

**Revocation has no backstop in the SDK.** `PolicyAssignment` carries no revocation field
and no SDK resolver models one, so the server's `revoked_at IS NULL` filter is the *only*
thing implementing §12. Established by mutation testing rather than assumed.

**Signing-key rotation needed no SDK change.** The security-context envelope has no JSON
Schema, so an extra top-level `kid` is legal and every SDK ignores members it does not
model. It sits outside the signed projection, so it cannot alter the signed bytes — which
is both why it is safe and why it is only a hint: it selects which key to try, and a forged
one selects a key under which the signature fails.

**Six super-linear parser paths in the catalog importers**, each measured before and after,
all reachable from an uploaded document within the request body limit. The worst was not
bounded by that limit at all: an OpenAPI document well under 1 KB, whose schemas reference
each other, cost close to a second — the depth bound bounded *depth* rather than work, so
the cost grew with the sixth power of the fan-out. The sixth path survived the sweep that
fixed the other five, because the test guarding that function fed it input which never
reached the offending loop.

**Testing failures are recorded as patterns, not as fixed bugs.**
[`docs/testing-antipatterns.md`](docs/testing-antipatterns.md) lists seven defects that
shipped here while the suite was green, with the smell to grep for in each. Three of them
were rediscovered during the final review — including tests that passed against the very
defect they were written to catch, which is why time-based assertions are now sized from a
measured mutation run rather than chosen by intuition.

### Deliberately not in this release

Each of these is a decision with a stated reason, not an oversight:

- **`ed25519`** is in the schema's algorithm enum but unimplemented in all three SDKs.
- **Asymmetric signing.** HMAC means every verifier holds a key that can also sign.
- **Replay prevention.** §13 notes that single-use enforcement needs server-side state the
  SDK deliberately does not assume; short TTLs are the answer, capped at one hour.
- **Multi-tenant isolation of the admin surface.** One deployment serves one tenant and any
  authenticated administrator sees every policy. Assignment `scope.tenantId` narrows which
  assignments apply; it does not isolate the console.
- **Offline policy bundles.** Distributing them would mean distributing the signing key,
  which defeats the trust model the server exists to provide.

See [`security/`](security/) for scan evidence, including findings accepted with their
reasoning, and [`SECURITY.md`](SECURITY.md) for how to report a vulnerability.
