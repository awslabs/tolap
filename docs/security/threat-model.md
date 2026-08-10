# TOLAP SDK — Threat Model

> **Revision 2026-08-09.** Every remediation this document raised is now closed in code
> except **R-8** (asymmetric signing), which is blocked on a stated dependency constraint and
> fails loudly rather than silently. This revision closes **R-2** (`hash` masking is now
> optionally a keyed HMAC), adds SDK-level enforcement of **revocation** (E2a) and
> **replay detection** (T5), and corrects entries that described the code as it was before
> the fail-open sweep recorded in §6.

**Scope:** Core (policy models, merge, HMAC signing, enforcement engine), Store (policy store interface + in-memory impl), MCP (secure tool wrappers) across .NET, Python, and TypeScript.
**Methodology:** STRIDE, applied per trust boundary. Data-flow diagram below.

> This document models the **SDK as shipped**. TOLAP is a library that customers embed inside their own tools/MCP servers. Several threats are therefore **shared responsibility**: the SDK provides a mechanism, and the integrator must operate it correctly. Those are called out explicitly as **[Integrator responsibility]**.

---

## 1. System overview

TOLAP moves access-control enforcement *inside the tool*, at the data-object level. The security-relevant lifecycle:

1. **Define** declarative JSON policies (objects, fields, rows, tags, endpoints, masking, limits).
2. **Assign** policies to a user/group/role/service-account with scope, expiry, and mandatory audit metadata.
3. **Resolve** all applicable policies for a `(userId, tenantId, dataSourceId)` tuple and **merge** them most-restrictive-wins into an `EffectivePolicy`.
4. **Sign** the effective policy / security context with an HMAC so it can cross process/network/cloud boundaries tamper-evidently.
5. **Enforce** at the tool wrapper: validate access pre-execution, then mask/filter/limit results post-execution before anything reaches the agent.

### Trust boundaries and data flow

```
                    ┌──────────────────────────────────────────────────────┐
                    │  Integrator's process (tool / MCP server / Lambda)     │
                    │                                                        │
 [Agent/LLM] ──req──┼─▶ (TB1) Identity Extractor ── userId, tenantId        │
                    │        (JWT / header / static)                         │
                    │            │                                           │
                    │            ▼                                           │
                    │      (TB2) Policy Store ◀── policies + assignments     │──▶ [Policy DB]
                    │        resolveEffectivePolicy()                        │   (TB3)
                    │            │                                           │
                    │            ▼                                           │
                    │      Policy Merger (most-restrictive-wins)             │
                    │            │                                           │
                    │            ▼                                           │
                    │   (opt) SecurityContextSigner ── HMAC sign/verify      │──▶ [cross-boundary
                    │            │                                           │   transport] (TB4)
                    │            ▼                                           │
                    │      EnforcementEngine  ── pre: validateAccess         │
                    │            │              post: mask/filter/limit      │
                    │            ▼                                           │
                    │      execute() ─────────────────────────────────────  │──▶ [Data source]
                    │            │                                           │   (TB5)
 [Agent/LLM] ◀─resp─┼────────────┘  (only authorized data leaves)           │
                    └──────────────────────────────────────────────────────┘
```

| ID  | Trust boundary           | Crosses from → to                                                                |
| --- | ------------------------ | -------------------------------------------------------------------------------- |
| TB1 | Agent → tool             | Untrusted agent/LLM input enters the tool; identity must be established here     |
| TB2 | Tool → Policy Store      | In-process (in-memory) or network (DB/REST) call to fetch policies               |
| TB3 | Policy Store → Policy DB | Query into a backing store the integrator implements                             |
| TB4 | Signed context transport | Effective policy/context serialized across process/network/cloud                 |
| TB5 | Tool → Data source       | The one path to data; enforcement must complete before this returns to the agent |

### Assets

- **A1 — Sensitive source data** (PII/PHI/financial; the healthcare examples make this concrete). Primary asset.
- **A2 — HMAC signing key(s)** used by `SecurityContextSigner`. Compromise defeats tamper-evidence.
- **A3 — Policy definitions & assignments** (integrity of the rules themselves).
- **A4 — Audit trail** (who granted what, when, why).
- **A5 — Identity assertions** (userId/tenantId used to resolve policy).

### Primary security property (the one to protect)

> **The tool never returns data the resolved policy does not authorize.** Every threat below is ultimately measured against this invariant.

---

## 2. STRIDE analysis

Severity uses the qualitative scale L / M / H / Critical. "Status" is one of: **Mitigated** (in SDK), **Partial** (mechanism present, residual risk), **Integrator responsibility**, **Open** (needs work in this repo).

### S — Spoofing

| #   | Threat                                                                                           | Affected | Severity     | Mitigation                                                                                                                                                                                       | Status                                                                                                               |
| --- | ------------------------------------------------------------------------------------------------ | -------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------- |
| S1  | Agent forges/alters the identity claim (userId/tenantId) so a more permissive policy resolves.   | TB1, A5  | **Critical** | **RESOLVED (2026-08-04).** `JwtIdentityExtractor` now verifies the HMAC signature before reading any claim, rejects `alg: none`, and enforces a caller-supplied algorithm allow-list rather than trusting the token header. Temporal claims (`exp`/`nbf`) are checked. Unverified parsing is opt-in only, via an explicit `allowUnverified` flag for callers whose gateway already validated the token. Python and TypeScript ship no JWT extractor at all, so there is nothing to verify there. Evidence: `sdk/dotnet/src/Tolap.Mcp/JwtIdentityExtractor.cs`. |
| S2  | Spoofed *service* identity to the Policy Store (TB2/TB3) reads/writes another tenant's policies. | TB2/TB3  | H            | Store interface is integrator-implemented; no auth baked in.                                                                                                                                     | **Integrator responsibility** — document required authN on the store.                                                |
| S3  | Forged signed context presented as a valid `EffectivePolicy`.                                    | TB4, A2  | H            | HMAC signature over canonical JSON; `Validate()` recomputes and compares. Forgery requires A2.                                                                                                   | **Mitigated** (given key secrecy).                                                                                   |

### T — Tampering

| #   | Threat                                                                                                                                               | Affected        | Severity     | Mitigation                                                                                                                                                                | Status                                                                                                         |
| --- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | --------------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| T1  | Tamper with a signed context in transit (relax a limit, remove a hidden field).                                                                      | TB4, A1         | **Critical** | HMAC-SHA256/512 over the context with `Integrity` block stripped before signing; `FixedTimeEquals` constant-time compare on verify. Any change invalidates the signature. | **Mitigated.**                                                                                                 |
| T2  | Tamper with policy rows/assignments in the backing DB.                                                                                               | TB3, A3         | H            | No integrity protection on stored policies (only on the *derived* signed context).                                                                                        | **Integrator responsibility** — DB access control + audit; consider signing stored policies. Note as residual. |
| T3  | Canonicalization mismatch: signer serializes differently than verifier, letting a semantically-equal-but-different payload pass or a valid one fail. | TB4             | M            | All three SDKs share fixtures (`fixtures/signing`) and a single `TolapJsonOptions` serializer to keep byte-for-byte canonical form aligned.                               | **Partial** — cross-language canonical-form is fixture-tested; keep fixtures authoritative.                    |
| T4  | Masking bypass via dotted-vs-bare field name mismatch (`patients.ssn` vs `ssn`) causing a masked/hidden field to slip through unmasked.              | Enforcement, A1 | H            | Both hidden-field and masking logic normalize dotted notation; row filters **fail closed** when the referenced field is absent.                                           | **Mitigated** (verified by enforcement fixtures); regression-guard required (§4 R-4).                          |

| T5  | Captured signed context replayed until it expires — it is a bearer credential, valid for its whole TTL.                                               | TB4, A1         | M            | `jti` inside the signed payload (so it cannot be stripped or swapped) plus an optional `ReplayGuard` that makes a context single-use. Detection is opt-in because the shared state it needs is not something the SDK can assume; the guard runs after signature and expiry so a rejected context cannot burn a live id. | **Mitigated when a guard is wired up** (spec §13.1); TTL-bounded otherwise.                                     |

### R — Repudiation

| #   | Threat                                                                    | Affected    | Severity | Mitigation                                                                                                                                                      | Status                                                              |
| --- | ------------------------------------------------------------------------- | ----------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| R1  | Admin grants access and later denies it.                                  | A4          | M        | Assignment schema makes `grantedBy`/`grantedAt`/`reason` **mandatory** audit fields.                                                                            | **Mitigated** (schema-enforced).                                    |
| R2  | No record of enforcement *decisions* (what was denied/masked at runtime). | Enforcement | M        | SDK returns a structured denial reason and the TypeScript wrapper emits `onEnforcementDecision`; persisting decisions is still the integrator's. | **Integrator responsibility** — wire decision logging to your own sink. |

### I — Information disclosure

| #   | Threat                                                                                                                                                                                                                    | Affected        | Severity     | Mitigation                                                                                                                                                      | Status                                                                                                                                     |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------- | ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| I1  | **The core threat TOLAP exists to stop:** agent receives unauthorized columns/rows/fields.                                                                                                                                | TB5, A1         | **Critical** | Post-execution pipeline: row filters → tag filters → masking → limit, applied before results return. `validateAccess`/`validateFieldAccess` gate pre-execution. | **Mitigated** (this is the product). Depends on correct integrator wiring (I4).                                                            |
| I2  | Weak masking gives false assurance — an unsalted `hash` of a low-entropy value (SSN, DOB, small enums) is recoverable by brute force / rainbow table.                                                                      | A1              | H            | An optional deployment-secret `hashSalt` makes `hash` a keyed HMAC (spec §13.2), defeating rainbow tables while keeping the cross-service join key. Unsalted remains the default so existing pseudonyms survive an upgrade. | **Mitigated when salted / documented otherwise.** Set `hashSalt`, or use `redact`/`null` when the value must not be derivable at all. See §4 R-2 (closed).      |
| I3  | Denial reasons / error messages leak schema or data existence (e.g. "object is hidden" reveals the object exists).                                                                                                        | Enforcement     | L            | Reasons are coarse strings, but "hidden" vs "not in allowed set" is distinguishable.                                                                            | **Partial** — acceptable; note as low residual.                                                                                            |
| I4  | Enforcement silently no-ops on an unhandled result shape — a tool returning a nested DTO, stream or scalar returns **unfiltered**.                                                                                        | TB5, A1         | **H**        | An unenforceable shape is **denied**, not passed through (spec §5). Pass-through requires the named `allowUnenforceableShapes` opt-in, which logs every time it lets a result through.                     | **Mitigated** (fails closed; opt-out is explicit and logged).                                                                              |
| I5  | Permissive enforcement mode returns `Allowed=true` on a denial. If shipped to prod by mistake, all enforcement is off.                                                                                                    | Enforcement, A1 | H            | .NET's `EnforcementMode.Permissive` is opt-in and warns at construction and at the point of impact. Python ships no such mode at all, pinned by a test.        | **Partial (by design)** — staged-rollout only; every opt-out is named and warns.                                                            |
| I6  | HMAC secret key logged, committed, or embedded.                                                                                                                                                                           | A2              | H            | SDK takes the key as a parameter; never logs it. Secret grep of the repo is clean.                                                                              | **Mitigated in SDK / Integrator responsibility** for key storage (use a secrets manager/KMS).                                              |

### D — Denial of service

| #   | Threat                                                                                                            | Affected    | Severity | Mitigation                                                                                                                            | Status                                                                                         |
| --- | ----------------------------------------------------------------------------------------------------------------- | ----------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| D1  | Catastrophic-backtracking regex in a `matches` row filter (ReDoS) supplied via a policy.                          | Enforcement | M        | .NET applies a regex match timeout; Python and TypeScript bound pattern and input length (no regex timeout in those runtimes). A regex failure is a non-match. | **Mitigated** — bounded in all three; the stopping mechanism differs by runtime (spec §13). |
| D2  | Very large result set exhausts memory before `maxResults` limit is applied (limit is applied *after* fetch/mask). | Enforcement | M        | `maxResults` bounds what is *returned*, not what is fetched.                                                                          | **Integrator responsibility** — push limits into the query where possible.                     |
| D3  | Unbounded policy set for a user makes merge expensive.                                                            | Merger      | L        | Most-restrictive merge is linear; realistic assignment counts are small.                                                              | Accepted.                                                                                      |

### E — Elevation of privilege

| #   | Threat                                                                                                                                      | Affected    | Severity     | Mitigation                                                                                                                                                       | Status                                                                                                                 |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------- | ----------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| E1  | Merge logic error lets a *less* restrictive policy win, widening access.                                                                    | Merger, A1  | **Critical** | Documented most-restrictive-wins matrix: sets intersect/union, booleans AND, maxima min, minima max, masks pick most restrictive. Cross-language merge fixtures. | **Mitigated** — but this is the highest-value correctness target; keep fixture coverage exhaustive.                    |
| E2  | Expired assignment/context still honored → stale elevated access.                                                                           | TB4         | H            | Signed context carries `ExpiresAt`; `Deserialize` rejects expired. Store resolution filters `expires_at > now()`.                                                | **Mitigated** (both layers).                                                                                           |
| E2a | Revoked assignment still resolves because the store forgot its own revocation filter → access survives revocation. | Store, A1   | H            | `PolicyAssignment.revokedAt` is enforced by the SDK resolver itself (spec §12), overriding `active`/`expiresAt` and failing closed on an unreadable value. A store's own `revoked_at IS NULL` filter is now defence in depth rather than the only control. | **Mitigated** (two independent layers).                                                                                |
| E3  | Empty/absent `objectRules` interpreted as "allow all".                                                                                      | Enforcement | H            | `validateAccess` returns **allow** when `objectRules` is null and no allowed-set is specified — a permissive default.                                            | **Partial (by design).** Document that an empty policy is permissive; recommend a deny-by-default assignment baseline. |
| E4  | Ed25519 signing silently unavailable — integrator selects it expecting stronger asym signing and gets an exception (or, worse, a fallback). | Signer, A2  | M            | Selecting `ed25519` fails loudly in all three SDKs; a silent downgrade to HMAC would be worse than an error. Unimplemented because it needs a third-party dependency `core` does not allow. | **Mitigated** (fails loud). Asymmetric signing tracked as roadmap (spec §13).                                          |

---

## 3. Assumptions & out-of-scope

- **Trusted policy authors.** Policy definitions/assignments are authored by trusted administrators, not by the agent or end user. Malicious *policies* (e.g. ReDoS regex) are largely out of scope but noted (D1).
- **Integrator owns identity, transport, and storage.** TLS on TB2–TB5, authN to the store, and secret management for A2 are the integrator's responsibility; the SDK provides the mechanisms.
- **In-memory store is dev/test only.** `InMemoryPolicyStore` is not durable, not shared, not access-controlled. Production must use a real backend with the recommended `expires_at`/`active` filtering (as shown in the README examples).
- **Signing is optional but recommended** whenever the effective policy crosses a process/network boundary. In-process enforcement (compute + enforce in one call) does not require it.

---

## 4. Prioritized remediations (this repo)

| ID  | Priority | Action                                                                                                                                                                                                                             | Where                              |
| --- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------- |
| R-1 | ~~P0~~ **CLOSED** | ~~Make JWT identity verify signatures.~~ **Done 2026-08-04**: HMAC verified, `alg: none` rejected, algorithm allow-list enforced, temporal claims checked. | `JwtIdentityExtractor.cs` (.NET; the other two SDKs ship no JWT extractor) |
| R-2 | ~~P1~~ **CLOSED** | ~~Document that `hash` masking is unsalted.~~ **Done**: optional deployment-secret `hashSalt` makes `hash` a keyed HMAC in all three SDKs (RFC 2104 over the chosen digest, cross-language byte-pinned), unsalted default preserved, spec §13.2 normative. | `enforcement.*` (all langs), wrapper options |
| R-3 | ~~P1~~ **CLOSED** | ~~Document supported result shapes and recommend fail-closed.~~ **Done**: an unenforceable shape is denied (spec §5); pass-through is a named opt-in that logs on every use. | MCP wrappers (all langs)           |
| R-4 | **P1**   | Add explicit regression fixtures for dotted-vs-bare masking bypass (T4) and empty-policy defaults (E3).                                                                                                                            | `fixtures/enforcement`             |
| R-5 | **P2**   | Emit optional structured enforcement-decision audit events (deny/mask/limit) for R2 uniformly across all three SDKs; today only the TypeScript wrapper has the hook.                                                              | Enforcement engine                 |
| R-6 | ~~P2~~ **CLOSED** | ~~Add a startup warning when `Permissive` is active.~~ **Done**: every enforcement opt-out warns at construction and at the point of impact.                                                                                | MCP wrappers                       |
| R-7 | ~~P2~~ **CLOSED** | ~~Consider regex complexity/timeout guard on `matches` filters.~~ **Done**: .NET uses a match timeout; Python and TypeScript bound pattern and input length.                                                                | Enforcement engine                 |
| R-8 | **P2**   | Asymmetric (`ed25519`) signing, so a verifier cannot also sign. Blocked on the zero-runtime-dependency rule for `core` — Python's stdlib has no Ed25519. Selecting it fails loudly meanwhile.                                     | Signer (all langs)                 |

## 5. Scanner coverage

See [`security/`](../../security/) for the evidence trail — raw SAST, dependency and secret-scanning
output, commit-pinned, plus live-service test transcripts under `security/aws/` and
`security/databases/`.

---

## 6. Defects found and fixed since revision 1

Recorded here because each one refines the threat model: all four were **fail-opens** — a control
that appeared to be applied while enforcing nothing — and three were invisible to unit tests because
the service *accepted* the malformed request.

| ID | Defect | How it failed open | Detection |
| --- | --- | --- | --- |
| F-1 | `limits.maxResults` unenforced when `collectionPath` omitted | Returned every record the upstream sent. The other two record-level controls fail *closed* on the same missing argument, so only this one was unsafe — and no test compared them. | Found by running the `api` pipeline the way an integrator would, without the optional argument every existing test supplied. |
| F-2 | `kb` OpenSearch/Elasticsearch denylist returned every denied document | Renderer emitted a `.keyword` sub-field the index did not have. Under `must_not`, a term matching nothing **excludes** nothing. The allowlist arm of the same bug failed closed, which is why it went unnoticed. | Only detectable against a live OpenSearch 2.19 domain: the engine accepted the query and reported success. |
| F-3 | `kb` Vertex AI Search emitted invalid multi-argument `NOT ANY()` | Discovery Engine negates only single-argument `ANY()`, so a multi-tag denylist produced an expression the service would reject or misapply. | Documentation audit of the remaining `fromGrammar` renderers, prompted by F-2. |
| F-4 | .NET `ValidateAccess` ignored `canQuery` | A fail-open on the broadest permission in the model. One signed policy granted different access per language — the property this SDK exists to guarantee. | Found by **porting** the Athena suite to .NET; invisible from inside any single SDK. |

### What this changes about the threat model

- **T (Tampering) / E (Elevation):** the highest-risk defects in practice were not attacks on the
  signed envelope — that held throughout — but **enforcement logic that silently did nothing**. The
  signature is necessary and was never the weak point.
- **Negated conditions are the dangerous asymmetry.** A filter that matches nothing is harmless in a
  positive clause and a **complete bypass** in a negated one. `docs/connector-spec.md` §7 now states
  this normatively and requires a negated clause to match under every field spelling a deployment
  might use.
- **A pushdown that is *stricter* than the normative post pass is also a defect**, not a safe
  over-correction. One proposed fix to the pgvector renderer was reverted for exactly this.
- **Verification confidence is now explicit in the API.** Each `kb` renderer reports `verified`
  (exercised against the live service) or `fromGrammar` (written from published documentation, never
  accepted by a service). Promoting two renderers out of `fromGrammar` exposed one fail-open each, so
  the marker has a demonstrated track record and `fromGrammar` should be read as unproven.

Current state: `bedrock`, `opensearch`, `elasticsearch` and `pgvector` are `verified`;
`azureAiSearch` and `vertexAiSearch` remain `fromGrammar` (both require paid subscriptions to
verify). Evidence: `security/aws/`, `security/databases/`.
