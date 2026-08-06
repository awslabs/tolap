# TOLAP Policy Server

The reference implementation of the Policy Service described in
[`architecture.md`](architecture.md#policy-service-api): a central place to author
policy, and one endpoint remote TOLAP installs call to get a signed policy they can
enforce.

It exists because the SDKs resolve policy **in-process** against a pluggable store,
and the only store that ships is `InMemoryPolicyStore`. Without a server, every
adopter builds persistence, an admin surface, and policy distribution themselves —
three times over, once per language.

## What it is responsible for

| Does | Does not |
| --- | --- |
| Store policy definitions and assignments | Hold data-source credentials |
| Resolve and **sign** a policy per user per source | Enforce policy (the SDK wrapper does that, at the tool) |
| Validate policy against the v1.0 JSON Schema | Decide whether a policy is *wise* — see [Getting policy wrong](#getting-policy-wrong) |
| Version, publish, roll back, and audit | Rotate signing keys (see [Not in v1](#not-in-v1)) |

The server never connects to a governed data source. That is deliberate and it is
the same property the SDKs have: nothing on the enforcement path takes a secret as
input, so this server has no data-source secret store to compromise. The source
catalog exists so the console can offer dropdowns, and it is populated by upload or
import — never by the server dialing a database.

## Two ports, on purpose

```
 administrators ──HTTPS──> :8080  admin API + console      (Cognito JWT)
 remote installs ─HTTPS──> :8081  GET /v1/resolve          (install credential)
```

`docs/canonical-enforcement-spec.md` §13 states plainly that **policy authors are
trusted administrators** and that a deliberately malicious policy is outside the
threat model. A deployment that widens write access past that assumption has left
the model the SDKs were designed against.

Splitting the listeners lets you bind the authoring surface to a private subnet or
a restricted security group while remote installs reach only the resolve port. It
is defense in depth, not the control itself — the route guards are the control, and
a single-interface deployment is still safe.

## Administrator authentication — Amazon Cognito

The server holds **no** user table and **no** password hashes. Cognito is the
identity provider; the server validates tokens and maps a group claim to a role.

### Roles

| Role | Cognito group | Can |
| --- | --- | --- |
| `admin` | `TOLAP_ADMIN_GROUP` | Author, assign, publish, roll back, register and revoke installs |
| `auditor` | `TOLAP_AUDITOR_GROUP` | Read policies, run resolve-preview, read the audit log. **No writes.** |

The roles are nested: an admin satisfies an auditor requirement. A token in neither
group is **rejected**, not admitted with no role — a principal that carries no role
puts the burden on every route to remember to check, and one forgotten check is a
privilege escalation.

Two roles rather than one because the compliance reviewer is a real persona for this
software, and making a reviewer take write access in order to *look* is how least
privilege gets abandoned in practice.

### Setting up the user pool

```bash
POOL_ID=$(aws cognito-idp create-user-pool \
  --pool-name tolap-policy-server \
  --query 'UserPool.Id' --output text)

aws cognito-idp create-group --user-pool-id "$POOL_ID" --group-name tolap-admin
aws cognito-idp create-group --user-pool-id "$POOL_ID" --group-name tolap-auditor

# Public client: the console is a browser app, so it uses authorization-code +
# PKCE and holds no client secret. Never configure implicit flow — it returns
# tokens in the URL fragment, where they land in history and referrer headers.
aws cognito-idp create-user-pool-client \
  --user-pool-id "$POOL_ID" \
  --client-name tolap-console \
  --no-generate-secret \
  --allowed-o-auth-flows code \
  --allowed-o-auth-scopes openid email profile \
  --allowed-o-auth-flows-user-pool-client \
  --callback-urls https://policy.example.internal/auth/callback \
  --supported-identity-providers COGNITO
```

Federating a corporate IdP (Entra, Okta, or any SAML/OIDC provider) into the pool is
supported and changes nothing here: the server still validates a Cognito-issued
token, and group membership can be mapped from the upstream directory.

### What the server checks on every admin request

All of these must hold, and any failure is a flat `401`:

- `alg` is `RS256`, taken from an allow-list. `alg: none` and every HMAC algorithm
  are refused — an HMAC algorithm is the algorithm-confusion attack, where a
  verifier might use the *public* key as a shared secret.
- Signature verifies against a key published in the pool's JWKS, fetched and cached
  (concurrent first use collapses into one fetch; an unknown `kid` triggers exactly
  one refetch to tolerate an early rotation, then refuses).
- `iss` equals the configured issuer. Without this, a token from *any* Cognito pool
  in *any* AWS account authenticates here.
- `aud` (id token) or `client_id` (access token) matches the configured client.
- `token_use` is `id` or `access` — never a refresh token.
- `exp` is present and in the future; a missing `exp` is not "never expires".
- `nbf`, when present, has passed. Both use 60s leeway.

Rejections deliberately do not distinguish expired from invalid beyond what the
server logs, per §11.

### Fail closed, always

Both auth paths follow §11 exactly:

| Situation | Result |
| --- | --- |
| No credential at all | `401` |
| Credential presented but malformed, wrong algorithm, bad signature, expired, wrong issuer/audience, or missing claims | `401` |
| Valid credential, insufficient role | `403` |

The distinction that matters is *presented and invalid* versus *absent* — and
neither is ever treated as anonymous on this surface. A caller that treats "no
identity" as "public" has converted an authentication failure into an authorization
decision.

`403` is separated from `401` for the console's benefit: an auditor hitting a write
route needs to be told their role is insufficient, not sent through a login loop
that cannot fix anything.

## Remote install authentication

Each install registers once and receives a credential shown **exactly once**:

```
tolap_ik_<installId>.<32 random bytes, base64url>
```

Only a SHA-256 hash is stored, so a database disclosure yields nothing usable
against the resolve port. Plain SHA-256 rather than a password KDF is deliberate:
this is a 256-bit random value, not a human-chosen password, so there is no
dictionary to slow down — and a KDF would burn CPU on every resolve call.

Registration per install, rather than one shared secret, buys two things: the audit
log can say *which* install pulled which policy, and one install can be revoked
without disturbing the rest.

Every resolve failure is an identical `401`. Whether an install exists, whether it
was revoked, and whether the secret was wrong are indistinguishable to the caller,
and the comparison runs even for unknown installs so timing does not leak
existence — otherwise the resolve port becomes an enumeration oracle.

A revoked install is **denied**, not merely recorded. Same rule as §12 for
assignments.

## Configuration

| Variable | Required | Notes |
| --- | --- | --- |
| `DATABASE_URL` | yes | PostgreSQL connection string |
| `TOLAP_SIGNING_KEY` | yes | ≥32 chars. **No default** — see below |
| `TOLAP_TTL_SECONDS` | no | Artifact lifetime, default 900, hard max 3600 |
| `COGNITO_ISSUER` | yes | `https://cognito-idp.<region>.amazonaws.com/<poolId>` |
| `COGNITO_AUDIENCE` | yes | App client id |
| `TOLAP_ADMIN_GROUP` | no | Default `tolap-admin` |
| `TOLAP_AUDITOR_GROUP` | no | Default `tolap-auditor` |
| `PORT` / `RESOLVE_PORT` | no | Default 8080 / 8081 |

**The signing key has no development default and the server refuses to start
without one.** A default would be shared by every deployment that forgot to set
one, making every artifact those servers issue forgeable by anyone who has read the
source. Load it from Secrets Manager or SSM Parameter Store; never commit it.

**TTL is capped at one hour** because a signed artifact is replayable for its entire
lifetime — TOLAP has no `jti` and no single-use enforcement (§13), so expiry is the
*only* bound on a captured artifact. A day-long TTL is a day-long replay window,
which is why this is a hard ceiling rather than advice.

## The artifact `/v1/resolve` returns

```
GET /v1/resolve?userId=…&tenantId=…&sourceConnectionId=db:analytics:patients
Authorization: Bearer tolap_ik_…
```

```json
{
  "effectivePolicy": { "...": "...", "integrity": { "algorithm": "hmac-sha256", "signature": "…" } },
  "issuedAt":   "2026-08-06T21:00:00Z",
  "resolvedAt": "2026-08-06T21:00:00Z",
  "expiresAt":  "2026-08-06T21:15:00Z",
  "signature": "…",
  "algorithm": "hmac-sha256"
}
```

One artifact, verifiable by all three SDKs. That took discovering something the
SDKs do not advertise: **they do not verify the same thing.**

| SDK | verifies | envelope instant | signature location |
| --- | --- | --- | --- |
| Python | the `SecurityContext` envelope | `issuedAt` | flat `signature` |
| TypeScript | the **bare** `EffectivePolicy` | `resolvedAt` | `integrity{}` |
| .NET | the `SecurityContext` envelope | `issuedAt` | `Integrity{}` |

Those are HMACs over two different byte strings. The artifact carries both
signatures — which works because the envelope projection strips `integrity` before
hashing (§2 rule 1), so the two coexist — and emits both spellings of the same
instant. `signContext` in `@tolap/core` produces both signatures in one call.

Consumers do not need to know any of this: deserialize with your own SDK's function
and it verifies.

```python
from tolap_core.context import deserialize_context
context = deserialize_context(base64_artifact, SIGNING_KEY)
```

One artifact governs **one source**. A user reaching three sources resolves three
times — `sourceConnectionId` is inside the signature precisely so a policy resolved
for one source cannot be replayed against another.

## Getting policy wrong

TOLAP guarantees it will enforce the policy you wrote. It does not guarantee the
policy is correct — `architecture.md` says so directly: *"if a policy is overly
permissive, TOLAP will faithfully enforce that permissiveness."*

Three features exist for that specific risk:

- **Schema validation** on save, in two modes — full document, and a fragment mode
  (top-level `required` relaxed) so a half-authored draft still gets type, enum,
  bound and `additionalProperties` checking. All errors are returned, not just the
  first.
- **Resolve preview**: pick a user, tenant and source and see the merged effective
  policy *before* publishing, with the contributing definitions listed. Merge is
  most-restrictive-wins and non-obvious — an allow-list intersects while a hidden
  list unions — so previewing beats reasoning.
- **Source catalog** so the console offers real object and field names. This is the
  highest-value correctness feature here: `hiddenFields: ["ssn"]` protects nothing
  if the column is actually `ssn_number`, and *nothing in TOLAP can detect that
  typo*. A signed, faithfully-enforced policy that names a column which does not
  exist is the quietest possible failure.

The catalog is authoring convenience **only**. Enforcement reads the signed policy
and never the catalog — a catalog that could influence an access decision would be
a new trust dependency, and a stale one would silently change what a policy means.

## Storage notes worth knowing

Policy bodies are stored as opaque `jsonb` and never decomposed into columns,
because §3 makes `[]` and `null` opposites for an allow-list: absent/`null` is
*unrestricted*, `[]` **denies everything**. A normalized child table cannot
represent "empty list" distinctly from "no rows", and collapsing them turns the most
restrictive policy expressible into no restriction at all — silently, with nothing
in the audit log.

If you replace this store, that is the property to test first, and test it through
enforcement rather than by inspecting the JSON.

Revocation is a tombstone so the grant stays visible to auditors, and every read
path filters it out. §12 requires that revoking make an assignment *stop resolving*;
recording a revocation while continuing to resolve it is "a fail-open control with a
misleading audit trail." Note that revocation is a **server-only** concept — the SDK
resolver has never heard of it — so those filters are the only thing implementing
§12. There is no backstop.

## Running it

```bash
cd server
npm install
DATABASE_URL=postgres:///tolap npm run migrate
DATABASE_URL=postgres:///tolap \
TOLAP_SIGNING_KEY="$(openssl rand -base64 32)" \
COGNITO_ISSUER=https://cognito-idp.us-east-1.amazonaws.com/us-east-1_xxx \
COGNITO_AUDIENCE=your-client-id \
  npm run dev
```

Tests:

```bash
npm test                                        # unit + cross-SDK
TOLAP_TEST_DB_DSN=postgres:///tolap_test npm test   # adds the store suites
```

The store suites **skip** without a DSN rather than failing, and each carries a
guard test that is not itself behind the skip. The cross-SDK suite shells out to
`python3` and `dotnet` and skips likewise. A suite that silently disables itself and
reports success is a defect this repo has already shipped once — see the
CHANGELOG's "Test-reporting defects".

## Not in v1

Each of these is left out for a reason, not an oversight:

- **Signing-key rotation / `kid`.** No SDK has a key-id concept or a
  key-resolution hook anywhere. Adding one is a cross-SDK change to all three
  signing paths, not a server feature. Today, rotating means re-keying the server
  and its consumers together.
- **`ed25519`.** In the schema's algorithm enum but unimplemented in all three
  SDKs — Python raises, .NET throws, and both then fail closed to a validation
  failure rather than an exception.
- **Replay prevention.** §13 says single-use enforcement "requires server-side
  state the SDK deliberately does not assume." Short TTLs are the v1 answer; a
  `jti` store is the obvious follow-on and this server is the right place for it.
- **Caching.** `architecture.md` designs a TTL-and-invalidate layer. Correctness
  first; a 15-minute artifact TTL already bounds resolve traffic.
- **Offline policy bundles.** Would require distributing the signing key to every
  install, which defeats the point of the server holding it.
