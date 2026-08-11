# Changelog

All notable changes to TOLAP are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.0.0

First public release. There is no prior published version, so this entry describes what
ships rather than a diff.

The schema is versioned separately and stays at **v1.0** (`schema/v1.0/`): it describes the
on-the-wire policy format, not the packages that implement it, and the two move
independently.

### Added

**Three SDKs** — .NET, Python and TypeScript — each with `core`, `store` and `mcp`
packages. One policy schema (`schema/v1.0/`) covers databases, APIs, knowledge bases and
object storage; there are no category-specific schemas.

**A normative specification**, [`docs/canonical-enforcement-spec.md`](docs/canonical-enforcement-spec.md).
Where an implementation disagrees with it, the implementation is wrong. Cross-language
behaviour is pinned by shared fixtures in `fixtures/` rather than by three independent
readings of prose.

**A reference policy server** (`server/`) — PostgreSQL store, schema validation, immutable
versions with publish and rollback, an audit trail, Cognito-authenticated admin access with
`admin` and `auditor` roles, per-install credentials, and signing-key rotation with an
overlap window. `GET /v1/resolve` returns a signed policy that all three SDKs verify. See
[`docs/policy-server.md`](docs/policy-server.md).

**An authoring console** (`console/`) with catalog-backed pickers for every rule in the
policy model, source import from OpenAPI and SQL DDL, schema validation as you type, and an
unsigned resolve preview.

**Deployment** (`infra/`) — CDK for CloudFront, WAF, Aurora Serverless v2 and Fargate.
Neither load balancer is internet-facing; the edge reaches them over VPC origins.

**A local build** (`tools/build-local.sh`) producing all nine SDK packages — wheels, npm
tarballs and `.nupkg` files — and installing them into the current environment. The nine
share one version because their guarantee is cross-package: a context signed by one must
verify in the other two, and the shared fixtures demand byte-identical output across all
three languages.

### Distribution

TOLAP is distributed as source. There are no packages on PyPI, npm or NuGet — build from
this repository with `tools/build-local.sh`, or reference the projects directly. CI asserts
that each built artifact carries its license and imports with only the dependencies it
declares, so a local build produces the same thing a registry would have served.

### Known limitations

Each of these is a design decision with a stated reason, not an oversight. The linked
sections explain the reasoning.

- **Replay detection is opt-in.** Every artifact carries a signed `jti` and every SDK
  accepts an optional `ReplayGuard`, which together make a context single-use (§13.1).
  Detection is opt-in rather than automatic because it needs a shared record of consumed
  identifiers that the SDK cannot assume — the bundled guard is process-local. Configure
  none and expiry is again the only bound, which is why the server still caps TTL at one
  hour.
- **Salted `hash` masking is opt-in.** Set `hashSalt` and `hash` becomes a keyed HMAC
  (§13.2); leave it unset and the pseudonym is the plain digest it always was, which is
  brute-forceable for low-entropy values. Opt-in because the salt is a deployment secret
  the SDK cannot invent, and because changing it changes every masked value.
- **One deployment serves one tenant.** Any authenticated administrator sees every policy.
  Assignment `scope.tenantId` narrows which assignments apply; it does not isolate the admin
  surface.
- **HMAC signing only.** Every verifier holds a key that can also sign. `ed25519` is in the
  schema's algorithm enum but unimplemented in all three SDKs — selecting it fails loudly
  rather than silently downgrading. Implementing it needs a third-party dependency in at
  least one runtime, which the zero-runtime-dependency rule for `core` forbids.
- **No offline policy bundles.** Distributing them would mean distributing the signing key,
  which defeats the trust model.
- **TOLAP does not judge whether your policy is correct.** An overly permissive policy is
  enforced faithfully; `hiddenFields: ["ssn"]` protects nothing when the column is
  `ssn_number`.

### Security

The SDKs and server were reviewed and scanned before release; findings, the reasoning for
each accepted one, and the raw tool output are in [`security/`](security/). Report a
vulnerability per [`SECURITY.md`](SECURITY.md) — please do not open a public issue.

Three mechanisms close gaps that earlier revisions of this project documented as
limitations rather than fixing. Each is normative in the spec and covered by tests in all
three SDKs:

- **Revocation is enforced by the SDK resolver** (§12). `PolicyAssignment.revokedAt` stops
  an assignment resolving, overriding `active` and `expiresAt`, and an unreadable value
  fails closed. Previously a store's own `revoked_at IS NULL` filter was the only thing
  implementing this, so a store that omitted it failed open with nothing to catch it; that
  filter is now defence in depth.
- **Replay is detectable** (§13.1). The `jti` sits *inside* the signed payload, so it
  cannot be stripped or swapped to dodge a guard — the property that makes the guard worth
  having. The check runs after signature and expiry so a rejected context cannot consume a
  live identifier.
- **`hash` masking can be a confidentiality control** (§13.2). Salted it is a keyed HMAC —
  RFC 2104 over the chosen digest, byte-pinned across the three SDKs so the pseudonym still
  joins.

Two properties are worth knowing before you build against this, both specified normatively:

- For an allow-list, **absent means unrestricted and `[]` means deny everything** (§3).
  They are opposite policies, so a store that coerces one into the other is a fail-open.
  `sourcePatterns` is the one documented exception (§10).
- **Identity extraction fails closed** (§11). A credential presented and rejected is never
  downgraded to anonymous.

### Notes

Development history is not in the repository — it was squashed into a single commit for
this release. Design rationale lives in [`docs/`](docs/), not in commit messages:
[`architecture.md`](docs/architecture.md) for the model,
[`canonical-enforcement-spec.md`](docs/canonical-enforcement-spec.md) for normative
behaviour, and [`testing-antipatterns.md`](docs/testing-antipatterns.md) for the test
failures this project has actually shipped and what to grep for.
