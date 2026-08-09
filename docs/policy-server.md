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
| Version, publish, roll back, and audit | Store data-source schemas as truth (the catalog is authoring-only) |
| Rotate signing keys with an overlap window | Sign asymmetrically (see [Not in v1](#not-in-v1)) |

The server never connects to a governed data source. That is deliberate and it is
the same property the SDKs have: nothing on the enforcement path takes a secret as
input, so this server has no data-source secret store to compromise. The source
catalog exists so the console can offer dropdowns, and it is populated by upload or
import — never by the server dialing a database.

## Single tenant, by design

One deployment serves **one tenant**, and any authenticated administrator sees every
policy. Policy definitions carry no tenant id, so this is a deliberate property rather
than a gap — run a second deployment for a second tenant.

Assignment `scope.tenantId` still exists and is honored at resolve time: it narrows
*which assignments apply* to a principal. What it does not do is isolate the admin
surface, so do not read it as cross-tenant separation.

## Two listeners, one public edge

The server binds two ports, and in the reference deployment neither is publicly
routable:

```
 administrators ─┐                        ┌─ :8080  admin API   (Cognito JWT)
                 ├─ HTTPS ─ CloudFront ───┤
 remote installs ┘   (managed TLS, WAF)   └─ :8081  /v1/resolve (install credential)
```

Both load balancers are **internal**; CloudFront reaches them over VPC origins. See
[`infra/README.md`](../infra/README.md) for the topology and why it is arranged that
way — in short, it gets trusted TLS with no certificate to manage and leaves nothing
in the VPC internet-facing.

`docs/canonical-enforcement-spec.md` §13 states plainly that **policy authors are
trusted administrators** and that a deliberately malicious policy is outside the
threat model. A deployment that widens write access past that assumption has left the
model the SDKs were designed against.

Splitting the listeners is what lets the edge route `/v1/resolve` to the
machine-facing service and everything else to the authoring surface, and it lets a
non-CloudFront deployment bind them to different interfaces. It is defense in depth,
not the control itself — the route guards are the control, and a single-interface
deployment is still safe.

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
| `TOLAP_SIGNING_KEY` | yes\* | A single secret, ≥32 chars. **No default** — see below |
| `TOLAP_SIGNING_KEYS` | yes\* | `kid:secret` pairs for rotation, first active. Replaces the above |
| `TOLAP_ACTIVE_KID` | no | Sign with this key instead of the first |
| `TOLAP_TTL_SECONDS` | no | Artifact lifetime, default 900, hard max 3600 |
| `COGNITO_ISSUER` | yes | `https://cognito-idp.<region>.amazonaws.com/<poolId>` |
| `COGNITO_AUDIENCE` | yes | App client id |
| `COGNITO_USER_POOL_ID` | see below | Enables group lookup for policy resolution |
| `TOLAP_IDENTITY_SOURCE` | no | `cognito` \| `static` \| `none`. Defaults to `cognito` when a pool id is set |
| `TOLAP_ROLE_PREFIX` | no | Cognito groups with this prefix resolve as TOLAP *roles* |
| `TOLAP_IDENTITY_CACHE_SECONDS` | no | Default 300, max 3600 |
| `TOLAP_STATIC_GROUPS` | with `static` | `alice=analysts,clinicians;bob=analysts` |
| `TOLAP_ADMIN_GROUP` | no | Default `tolap-admin` |
| `TOLAP_AUDITOR_GROUP` | no | Default `tolap-auditor` |
| `PORT` / `RESOLVE_PORT` | no | Default 8080 / 8081. Must differ |
| `HOST` / `RESOLVE_HOST` | no | Default `127.0.0.1` |
| `LOG_LEVEL` | no | Default `info`. One of `fatal`/`error`/`warn`/`info`/`debug`/`trace`/`silent`. An unrecognized value is rejected rather than defaulted |

\* One of the two signing forms is required.

**The signing key has no development default and the server refuses to start
without one.** A default would be shared by every deployment that forgot to set
one, making every artifact those servers issue forgeable by anyone who has read the
source. Load it from Secrets Manager or SSM Parameter Store; never commit it.

**TTL is capped at one hour** because a signed artifact is replayable for its entire
lifetime — TOLAP has no `jti` and no single-use enforcement (§13), so expiry is the
*only* bound on a captured artifact. A day-long TTL is a day-long replay window,
which is why this is a hard ceiling rather than advice.

## Group and role membership

An assignment can be attached to a **group** or a **role** rather than a person.
Those only resolve if the server can learn what a user belongs to — otherwise the
grant sits in the database contributing nothing, and the access an administrator
believes they gave does not exist.

`/v1/resolve` is called by an *install* on behalf of a user named in the query
string, so there is no user token to read `cognito:groups` from. The server asks the
pool directly with `AdminListGroupsForUser`:

```bash
COGNITO_USER_POOL_ID=us-east-1_abc123   # enables it; this is the default when set
TOLAP_ROLE_PREFIX=role:                 # optional: `role:clinician` becomes the role `clinician`
```

The task role needs exactly one permission, and it is read-only:

```json
{ "Effect": "Allow",
  "Action": "cognito-idp:AdminListGroupsForUser",
  "Resource": "arn:aws:cognito-idp:us-east-1:<account>:userpool/us-east-1_abc123" }
```

Cognito has one flat group namespace; TOLAP distinguishes `group` from `role`
assignees. `TOLAP_ROLE_PREFIX` splits them. Leave it unset and everything is a group.

Lookups are cached for `TOLAP_IDENTITY_CACHE_SECONDS` (default 300). That cache is
also the delay on a membership *removal* taking effect, which is why it is capped at
an hour.

**A lookup failure returns 503, it does not return a policy.** This is the important
part. If a Cognito outage produced an empty group list, resolution would succeed and
hand back a narrower policy with every group-scoped grant silently missing. Because
merge is most-restrictive-wins the result is denial rather than disclosure — safe,
but invisible: nothing in the response, the policy, or the audit log would say the
server had guessed. A visible denial beats an invisible one.

Alternatives if your groups do not live in Cognito:

| `TOLAP_IDENTITY_SOURCE` | Behavior |
| --- | --- |
| `cognito` | Query the user pool (default when `COGNITO_USER_POOL_ID` is set) |
| `static` | Read `TOLAP_STATIC_GROUPS`. For development, or groups managed elsewhere |
| `none` | Nobody is in any group. **Group- and role-scoped assignments will not resolve** |

`none` has to be chosen explicitly, and the server prints the active source at
startup, because a deployment that lands on it by accident gets grants that do
nothing and no error anywhere.

## Rotating the signing key

Rotation works, and it needed no SDK change — which was not obvious, because none of
the three SDKs has a `kid` concept or a key-resolution hook; every signing API takes
a bare `secretKey: string`.

The opening is that **the security-context envelope has no JSON Schema**, so an extra
top-level key is legal, and all three SDKs ignore members they do not model. The
artifact therefore carries `kid` alongside the signature. Verified against the real
SDKs rather than assumed: an artifact with `kid` verifies in TypeScript
(`validateContext` and `validatePolicy`), deserializes and verifies in Python, and
verifies in .NET.

`kid` sits *outside* the signed payload — which the canonical projection fixes to
`{version,userId,tenantId,issuedAt,expiresAt,policies[]}` (§2) — so it cannot change
the signed bytes. That is exactly why it is safe to add, and exactly why it must
never be trusted:

> **`kid` is a hint, not an authority.** It is unsigned, so anyone can rewrite it.
> That is harmless because it only selects *which key to try*, and a wrong `kid`
> leads to a key under which the signature fails. What a consumer must never do is
> fall back to trying every key it holds when a `kid` is unknown — that turns the
> field into an oracle for which keys a server has.

To rotate:

```bash
# 1. Add the new key. The old one stays first, so it stays active.
TOLAP_SIGNING_KEYS="2026-05:<old secret>,2026-08:<new secret>"

# 2. Distribute both to consumers as a kid -> key map, and let them update.

# 3. Flip the active key. New artifacts are signed with it; artifacts already
#    issued under the old one keep verifying.
TOLAP_SIGNING_KEYS="2026-05:<old secret>,2026-08:<new secret>"
TOLAP_ACTIVE_KID=2026-08

# 4. After one TTL (at most an hour), every old artifact has expired. Drop the key.
TOLAP_SIGNING_KEYS="2026-08:<new secret>"
```

The overlap is what removes the flag day: both keys verify throughout, so installs
update on their own schedule. The server logs the active `kid` and the others it
still verifies at startup.

A single `TOLAP_SIGNING_KEY` still works and becomes the key `default`, so an
existing deployment upgrades without any configuration change — its artifacts gain
`"kid":"default"` and are otherwise byte-identical.

Consumer side, for a Python install:

```python
KEYS = {"2026-08": new_secret, "2026-05": old_secret}
artifact = json.loads(base64.b64decode(blob))
secret = KEYS.get(artifact["kid"])
if secret is None:
    raise ValueError("unknown signing key")   # do NOT try the others
context = deserialize_context(blob, secret)
```

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

### What the console's rule editors guard

Every rule in the policy model is editable in the console, each control backed by the
imported catalog. They are worth describing individually, because most of them exist to
make one specific quiet failure loud — and in every case the failure is *silent* rather
than an error an author would notice.

- **Masked fields.** Mask types are listed most- to least-restrictive, which is also the
  spec's merge order (least-revealing wins), so the trade-off is visible while choosing
  rather than looked up afterwards. `partial` is marked as revealing real characters and
  `hash` as **not a confidentiality control** — an unsalted truncated digest is
  brute-forceable for SSNs, dates of birth and small enumerations, so it is a pseudonym
  and a join key, not protection.

  `partial` also takes `showFirst` / `showLast` / `maskChar`, and `hash` takes
  `algorithm`. Without those controls "reveal the last four of an SSN" is not expressible
  at all: `partial` with no parameters reveals nothing and degrades to a full mask. That
  degradation is safe, but it is not what the author asked for.

- **Row filters.** These are the *only* way TOLAP selects records — there is no record-id
  concept anywhere in the policy model, so "which rows may this user see" is always a
  predicate over a field. All 16 operators are offered, grouped by the value shape they
  take, and changing operator drops the value that no longer applies (a stale `value`
  alongside `values` is not what `in` means, and the schema rejects it).

  A field name outside the catalog is flagged with its consequence spelled out: filters
  fail closed, so a record missing the referenced field is dropped, and a typo therefore
  denies **every** record rather than none. The author experiences that as "the agent
  returns nothing", which does not point at the policy.

- **Endpoints and methods.** The OpenAPI importer has already rewritten `/patients/{id}`
  to `/patients/*`, so picking from the list yields a pattern that matches at enforcement
  time instead of a literal `{id}` that never matches anything. Methods are per-policy
  because that is what the schema models; the methods each endpoint actually offers are
  shown beside it, so granting a verb the API does not expose is visible.

  Absent `allowedMethods` means the schema default (read-only) while `[]` **denies every
  request** — two opposite policies that both render as "nothing ticked" in a checkbox
  grid, so the two states are distinguished explicitly.

- **Tags** (`kb` sources). The asymmetry is stated inline because getting it backwards
  produces a policy that reads as restrictive and returns everything: `deniedTags` takes
  precedence over `allowedTags`, and a document needs only **one** allowed tag to pass. An
  allow-list is narrower than it looks; a deny-list is absolute.

Two rules hold across all of them. A value the catalog does not contain is **flagged, not
rejected** — the catalog is an aid, and one that could refuse a value would become an
authority on what a policy may say, so a stale manifest would start blocking legitimate
policies. And nothing is flagged before a source is imported, since warning on every value
with nothing to compare against trains the author to ignore the warning that matters.

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
TOLAP_SIGNING_KEYS="2026-08:$(openssl rand -base64 32)" \
COGNITO_ISSUER=https://cognito-idp.us-east-1.amazonaws.com/us-east-1_xxx \
COGNITO_AUDIENCE=your-client-id \
COGNITO_USER_POOL_ID=us-east-1_xxx \
  npm run dev
```

Startup prints the two things that fail silently if they are wrong — which identity
source is active, and which key is signing:

```
admin API + console  http://127.0.0.1:8080
resolve API          http://127.0.0.1:8081
identity source      cognito
signing keys         active=2026-08
```

Without `COGNITO_USER_POOL_ID` that third line reads
`none  (group- and role-scoped assignments will NOT resolve)`.

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

## Operating it

### What the logs contain, and what they deliberately do not

Both listeners log requests at `info` by default. Two things are withheld on purpose,
because enabling logging on *this* server is not a free action:

- **The `Authorization` header is never written.** It is a live credential on every
  route — a Cognito ID token on the admin port, and on the resolve port an install
  credential that mints signed policy artifacts. Pino's default serializer already omits
  headers; `redact` states it explicitly so it survives someone later adding header
  logging, and censors rather than removes, so a line still shows a credential *was*
  presented.
- **The resolve query string is dropped, and the path kept.**
  `?userId=&tenantId=&sourceConnectionId=` is who was resolved for and against which
  source. The audit log records exactly that, deliberately, with access control and
  retention chosen for it. A log line is a second copy in a place with weaker controls,
  so the log answers *is it slow, is it erroring, on which route* and cannot answer *for
  whom*. Correlation goes through the audit trail.

The route **pattern** is logged (`/v1/policies/:name`) rather than the concrete path, so
latency aggregates per route instead of splintering across every policy name ever
fetched.

`LOG_LEVEL=silent` disables the request hooks entirely rather than formatting lines and
discarding them. That is what the test suite uses.

### Alarms

`infra/lib/observability.ts` creates eight alarms and a dashboard. The shape follows two
properties of this deployment:

**One task serves both listeners.** The admin API and `/v1/resolve` are two Fastify
instances in one Node process, so admin-side CPU cost delays policy resolution for every
install. Resolve therefore gets the tighter threshold — p99 above **1s** for 3 minutes,
against **5s** for admin. A resolve call is one indexed query plus an HMAC; healthy is
single-digit milliseconds, so a second means a stalled event loop or a saturated pool.

**Failing to resolve does not fail open.** An install that cannot fetch a policy gets no
access rather than no restrictions, so an outage here looks like a broad, confusing
denial inside someone else's service. That is why the resolve path is alarmed first.

| Alarm | Fires when |
|---|---|
| `ResolveLatencyP99` | p99 > 1s for 3 min |
| `ResolveServerErrors` | > 5 target 5xx in 5 min |
| `ResolveUnhealthyTargets` | any unhealthy target for 2 min |
| `AdminLatencyP99` | p99 > 5s for 5 min |
| `AdminServerErrors` | > 5 target 5xx in 5 min |
| `NoRunningTasks` | running tasks < 1 for 3 min |
| `TaskCpuHigh` | CPU > 80% for 15 min |
| `TaskMemoryHigh` | memory > 85% for 15 min |

Two details worth knowing before changing any of them:

- **401 and 403 are not alarmed.** They are the guards working. Alarming on them would
  fire on every expired console session. Only target 5xx counts — the server failing to
  produce an artifact it should have produced.
- **`treatMissingData` is set explicitly on every alarm**, because the CDK default
  (`MISSING`) is wrong for most of them: a metric that stops arriving because the service
  is gone would leave the alarm in `INSUFFICIENT_DATA`, which reads as healthy. The
  latency alarms use `NOT_BREACHING` (no traffic is a quiet period, not a fault) and
  `NoRunningTasks` uses `BREACHING` (nothing left to report it). `NoRunningTasks` reads an
  `ECS/ContainerInsights` metric and so depends on Container Insights, which the cluster
  enables.

### Where alarms go

Every alarm publishes to one SNS topic, on **both** the ALARM and the OK transition. The
action is attached in one place rather than per alarm, so a new alarm cannot be added
without notification — the failure that produces is a monitoring gap nobody notices,
because the dashboard still shows the alarm and it still turns red. OK actions are included
because an incident channel that records alerts and never records recoveries makes "is it
still broken?" a question you answer by going to look.

Subscribe at deploy time rather than committing an address:

```bash
cdk deploy TolapServer -c alarmEmail=ops@example.com
```

With no address the topic is still created and its ARN is a stack output, so subscribing
later needs no redeploy of the service — and the output description says **NO SUBSCRIBERS**
rather than leaving that to be discovered during an incident. Note that an email
subscription stays in `PendingConfirmation` and delivers nothing until the confirmation
link is clicked.

The topic requires TLS in transit: an alarm body carries the metric, threshold and reason,
which describes the shape of a production incident to anyone who can read it.

## Not in v1

Each of these is left out for a reason, not an oversight:

- **`ed25519`.** In the schema's algorithm enum but unimplemented in all three
  SDKs — Python raises, .NET throws, and both then fail closed to a validation
  failure rather than an exception.
- **Asymmetric signing.** HMAC means every verifier holds a key that can also
  *sign*. Asymmetric keys would let installs verify without being able to forge,
  which is the right shape for a large deployment — but it depends on `ed25519`
  above, so it waits on the SDKs.
- **Replay prevention.** §13 says single-use enforcement "requires server-side
  state the SDK deliberately does not assume." Short TTLs are the v1 answer; a
  `jti` store is the obvious follow-on and this server is the right place for it.
- **Caching.** `architecture.md` designs a TTL-and-invalidate layer. Correctness
  first; a 15-minute artifact TTL already bounds resolve traffic.
- **Offline policy bundles.** Would require distributing the signing key to every
  install, which defeats the point of the server holding it.
