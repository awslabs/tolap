# TOLAP SDK — Threat Model

> **Revision 2026-09-01.** Five of the eight remediations in §4 are closed in code. **Three
> remain open: R-4** (regression fixtures for the dotted-vs-bare masking bypass and
> empty-policy defaults — **P1, the highest remaining priority**, and T4's "Mitigated" status
> depends on it), **R-5** (uniform enforcement-decision audit events; today only the
> TypeScript wrapper has the hook), and **R-8** (asymmetric signing, blocked on a stated
> dependency constraint and failing loudly rather than silently).
>
> This revision adds the purpose-binding analysis — **E5** (a valid context reused for work it
> was not issued for), **E6** (a sub-agent widening its delegation chain), **E7** (a
> prompt-injected or malfunctioning judge), **D5** (the judge's cost, latency and
> availability profile) — plus the outbound trust boundary **TB6** the judge introduces and
> asset **A6**, the judge's model credential.
>
> An earlier revision claimed everything was closed except R-8, which was wrong in the
> direction that matters: it undercounted the open work and misranked it, since R-4 is a
> higher priority than R-8. Note also that §2's status taxonomy names an **Open** label that
> no row uses; roughly half the rows are not fully closed in code and are distributed across
> *Partial*, *Integrator responsibility*, *Accepted* and the two conditional mitigations
> instead. Read a status, not a colour.

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
                    │            │                                           │
                    │   (opt) JudgeGate ── tool call + ToolCallHistory ───   │──▶ [3rd-party LLM]
                    │            │         (agent-influenced text, fenced)   │   (TB6, A6)
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
| TB6 | Tool → third-party model (**outbound**) | Only when the optional judge (§15.4) is enabled. The one boundary in this model that carries data **out** of the integrator's process to a party that is neither the agent nor the data source. What crosses it is agent-influenced text — the rendered tool call and up to `historyWindow` prior calls — so it is simultaneously an egress path and an injection surface. Every `<` in that text is neutralised to U+2039 before interpolation so a fence cannot be forged (E7), but the *content* still leaves: if a tool call is rendered with argument values, those argument values reach the model provider. Absent when no judge is configured, which is the default. |

### Assets

- **A1 — Sensitive source data** (PII/PHI/financial; the healthcare examples make this concrete). Primary asset.
- **A2 — HMAC signing key(s)** used by `SecurityContextSigner`. Compromise defeats tamper-evidence.
- **A3 — Policy definitions & assignments** (integrity of the rules themselves).
- **A4 — Audit trail** (who granted what, when, why).
- **A5 — Identity assertions** (userId/tenantId used to resolve policy).
- **A6 — The judge's model credential** (and the billing account behind it). Only present when
  the optional judge is enabled. Distinct from A2: it is not a TOLAP secret and compromising it
  cannot forge a context or widen access — the judge is strictly subtractive — but it is a
  spendable credential reachable from the enforcement path, and an attacker holding it can
  exhaust a budget or, by denying the judge service, force every judged call to escalate. It is
  the integrator's to store (secrets manager / KMS) and scope: the SDKs take a one-method
  transport seam and never handle a credential themselves, which is why no package gained an AWS
  SDK dependency.

### Primary security property (the one to protect)

> **The tool never returns data the resolved policy does not authorize.** Every threat below is ultimately measured against this invariant.

---

## 2. STRIDE analysis

Severity uses the qualitative scale L / M / H / Critical. "Status" is one of: **Mitigated** (in SDK), **Partial** (mechanism present, residual risk), **Integrator responsibility**, **Open** (needs work in this repo).

### S — Spoofing

| #   | Threat                                                                                           | Affected | Severity     | Mitigation                                                                                                                                                                                       | Status                                                                                                               |
| --- | ------------------------------------------------------------------------------------------------ | -------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------- |
| S1  | Agent forges/alters the identity claim (userId/tenantId) so a more permissive policy resolves.   | TB1, A5  | **Critical** | **RESOLVED (2026-08-04).** `JwtIdentityExtractor` now verifies the HMAC signature before reading any claim, rejects `alg: none`, and enforces a caller-supplied algorithm allow-list rather than trusting the token header. Temporal claims (`exp`/`nbf`) are checked. Unverified parsing is opt-in only, via an explicit `allowUnverified` flag for callers whose gateway already validated the token. Python and TypeScript ship no JWT extractor at all, so there is nothing to verify there. Evidence: `sdk/dotnet/src/Tolap.Mcp/JwtIdentityExtractor.cs`. | **Mitigated** (resolved 2026-08-04; see §4 R-1). Unverified parsing remains available as a named opt-in for callers whose gateway already validated the token. |
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
| D4  | Unbounded request rate against the policy server: a flood on either listener starves the shared Node process and connection pool, so an install that cannot resolve gets no access at all. On `/v1/resolve` specifically, an unbounded rate also sets how fast a stolen install credential can harvest signed policy — each artifact being replayable for its whole TTL absent a `ReplayGuard`. | Policy server | M | Two independent bounds. In-process per-IP ceilings on both listeners (`TOLAP_ADMIN_RATE_LIMIT` 300/min, `TOLAP_RESOLVE_RATE_LIMIT` 60/min), so a deployment behind any ingress has one; plus a WAF rate-based rule at the edge in the reference deployment (2000/5min per IP), which sheds a flood before it reaches the process. `/health` exempt on both so a health check cannot rate-limit a working task out of service. | **Mitigated** — both layers, and neither is a defense against a distributed source: per-IP counting cannot be. See [docs/policy-server.md](../policy-server.md#rate-limiting-sits-in-two-places-and-both-matter). |
| D5  | **The judge is a synchronous, paid, third-party round trip on the authorization path.** With a judge enabled, every tool call that the deterministic checks allow blocks on a model invocation before the call proceeds. Four properties compound: there is **no result cache** (an identical call re-evaluated re-invokes the model), **no retry cap** (nothing in the SDK bounds how many times a call site may re-attempt an escalation), **no per-session or per-context ceiling** on invocations, and `historyWindow` merges to the **maximum** across contributing policies (§15.5) — so adding a purpose-bound policy enlarges every prompt, and therefore the token cost and the latency, without anyone editing a judge config. The exposures are (a) **cost**: an agent in a loop bills a model call per iteration against A6; (b) **latency**: `maxLatencyMs` defaults to 2000, so a judged tool becomes up to two seconds slower per call, and merging takes the **minimum** of the configured budgets rather than the maximum; (c) **availability**: if the model is slow or unreachable every judged call escalates, and escalation denies with no review handler wired — so a third-party outage becomes a **deny-all** on judged calls. | Judge (§15.4), TB6, A6 | M | Bounded, not solved. `maxLatencyMs` is read from the resolved policy and enforced by the gate, so a hung provider cannot hang the call indefinitely; a timeout, transport failure or unparseable response escalates rather than throwing. Enabling the judge is opt-in and per policy, so the default deployment has none of this exposure. Everything else is the integrator's: the judge is deliberately a helper rather than wrapper-integrated, precisely because a cache, a retry policy, a spend ceiling and a rate limit are decisions a wrapper cannot make on your behalf. | **Integrator responsibility.** Set a spend/rate limit on the model credential (A6), cache or debounce at the call site if your traffic repeats, cap re-attempts, and decide deliberately whether a judge outage should deny (the default, and the safe reading) or degrade to the deterministic checks alone — the latter is a conscious weakening, and the former is a denial-of-service surface. Do not enable a judge on a hot path without measuring it first. |

### E — Elevation of privilege

| #   | Threat                                                                                                                                      | Affected    | Severity     | Mitigation                                                                                                                                                       | Status                                                                                                                 |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------- | ----------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| E1  | Merge logic error lets a *less* restrictive policy win, widening access.                                                                    | Merger, A1  | **Critical** | Documented most-restrictive-wins matrix: sets intersect/union, booleans AND, maxima min, minima max, masks pick most restrictive. Cross-language merge fixtures. | **Mitigated** — but this is the highest-value correctness target; keep fixture coverage exhaustive.                    |
| E2  | Expired assignment/context still honored → stale elevated access.                                                                           | TB4         | H            | Signed context carries `ExpiresAt`; `Deserialize` rejects expired. Store resolution filters `expires_at > now()`.                                                | **Mitigated** (both layers).                                                                                           |
| E2a | Revoked assignment still resolves because the store forgot its own revocation filter → access survives revocation. | Store, A1   | H            | `PolicyAssignment.revokedAt` is enforced by the SDK resolver itself (spec §12), overriding `active`/`expiresAt` and failing closed on an unreadable value. A store's own `revoked_at IS NULL` filter is now defence in depth rather than the only control. | **Mitigated** (two independent layers).                                                                                |
| E3  | Empty/absent `objectRules` interpreted as "allow all".                                                                                      | Enforcement | H            | `validateAccess` returns **allow** when `objectRules` is null and no allowed-set is specified — a permissive default.                                            | **Partial (by design).** Document that an empty policy is permissive; recommend a deny-by-default assignment baseline. |
| E4  | Ed25519 signing silently unavailable — integrator selects it expecting stronger asym signing and gets an exception (or, worse, a fallback). | Signer, A2  | M            | Selecting `ed25519` fails loudly in all three SDKs; a silent downgrade to HMAC would be worse than an error. Unimplemented because it needs a third-party dependency `core` does not allow. | **Mitigated** (fails loud). Asymmetric signing tracked as roadmap (spec §13).                                          |
| E5  | A valid context is reused for work it was not issued for — an agent that has drifted off-task, or been talked off it, presents an entirely legitimate context. | Resolver, TB4 | H | Optional purpose binding (spec §15): a policy carrying a `purposeProfile` resolves only for a matching declared purpose, and the purpose is inside the signature so a **captured** context cannot be repurposed. Action categories bound to the purpose come from administrator configuration, never the caller. | **Partial (opt-in).** Bounds a drifting or mid-task-compromised agent. Purpose is caller-*asserted*, so it does not constrain a dishonest integrator — see the assumption below. |
| E6  | A sub-agent grants itself wider authority than it was delegated, by rewriting or extending the chain it presents. | Delegation, TB4 | H | `DelegationChainValidator` requires each hop to narrow: a child purpose must equal its parent, be matched by a parent glob, or extend it on a `-` segment boundary — a plain prefix test would let `campaign-x` authorize `campaign-xyz-evil`. The chain is inside the signed payload, so appending, mutating or reordering hops invalidates the signature. | **Mitigated.** Every wrapper's context validation calls the validator, after the signature check and before any call is permitted — the context wrapper, the HTTP wrapper and anything `SecureToolFactory` builds, in all three SDKs. An earlier revision of this document listed E6 as *integrator responsibility*, correctly at the time: the validator was fixture-pinned and correct but had **no call site outside its own tests**, which made it a gate that silently did not exist. The context *builders* still only *record* a chain, because a builder that silently dropped an invalid one would produce a context that looked delegated and was not; the check belongs on the consuming side, where the chain is inside the signed bytes. Ordering is load-bearing: the signature is verified first, since validating an unsigned chain checks the attacker's own arithmetic. One residual: chain **depth is unbounded** — no cap in the validator, the model, or `security-context.schema.json` — so an integrator whose hop count is influenced by anything untrusted must bound it. |
| E7  | A prompt-injected or malfunctioning LLM judge widens access. | Judge (§15.4) | M | Two separate mitigations, and the distinction matters. **Structural:** the judge runs only *after* the deterministic checks have allowed a call and can only withdraw that allowance, so a manipulated verdict cannot escalate — this holds unconditionally. Every unusable verdict (out-of-range confidence, `NaN`, inverted thresholds, timeout, transport failure) escalates, and `escalate` denies with no review handler wired. **Structural, second layer:** every `<` in the tool call and history is replaced with U+2039 before interpolation, so agent-influenced text cannot close a fence or open a forged `<purpose>` block. | **Mitigated for escalation; bounded for evasion.** A manipulated verdict cannot widen access — that is structural. It *can* suppress a detection, and the adversary who controls the text is exactly the drifting agent the judge exists to catch, so the fence neutralisation is load-bearing rather than defence in depth. The rubric's "treat fenced content as data" instruction is a behavioural backstop only; it was the sole protection until the neutralisation was added, and a forged block placed outside the fences was not covered by it. |

---

## 3. Assumptions & out-of-scope

- **Trusted policy authors.** Policy definitions/assignments are authored by trusted administrators, not by the agent or end user. Malicious *policies* (e.g. ReDoS regex) are largely out of scope but noted (D1).
- **A declared purpose is asserted, not proved.** TOLAP checks that a declared purpose matches a policy and that a delegation chain is internally consistent; it cannot check that the caller was honest about its purpose in the first place (spec §13). Purpose binding (E5, E6) therefore raises the cost of an agent drifting or being compromised mid-task, and bounds what a stolen context is good for — it is not a control against an integrator that declares one purpose and pursues another. That case is already covered by the trusted-author assumption above: an integrator able to lie about its purpose is an integrator able to author the policy that permits it.
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
