# Purpose binding: making the reason part of the decision

## The problem

TOLAP answers "what may this identity see?". A signed context binds identity, tenant,
source and expiry. It does not bind the *reason* the data is being read.

That gap matters more for an agent than for a person. A human analyst with database access
is bounded by what they are trying to do; an agent with the same access is bounded only by
its prompt, and a prompt is not a security control. An agent that has drifted off-task —
or been talked off it — presents an identical, entirely valid context to the wrapper. There
is nothing in the model for the wrapper to compare its behaviour against.

Concretely: an agent authorized to compute segment overlap for one marketing campaign holds
a context that also permits every other read its policy allows. Nothing distinguishes
`aggregate_overlap(campaign-x)` from `export_csv(customer_segments, [email, ssn])` if both
touch permitted objects and fields.

## What this does not change

Everything that exists today keeps working, unchanged, including its bytes.

- A policy with no `purposeProfile` resolves exactly as before.
- A caller declaring no purpose resolves exactly as before.
- A context with no `declaredPurpose` and no `delegationChain` signs to **byte-identical**
  bytes. The two older signing fixtures are untouched by this change, which is the
  demonstration rather than the claim.
- No existing test was modified to accommodate this feature. Two assertions were *widened*
  (the corpus-size floor and the example count) because the shared corpus grew.

The `additionalProperties: false` on both schemas means the new field had to be declared
before any fixture could use it, so there is no window in which a fixture validated against
nothing.

## Design

Three deterministic enforcement points and one non-deterministic one. The deterministic
three have zero external dependencies and are implemented identically in all three SDKs,
pinned by shared fixtures. The judge is optional and strictly subtractive.

Full normative detail is [canonical-enforcement-spec.md §15](../../canonical-enforcement-spec.md#15-purpose-binding).
What follows is the reasoning behind the decisions that were not obvious.

### The profile has to survive the merge

The original design put `purposeProfile` on `PolicyDefinition` and defined
`validateAction(actionCategory, purposeProfile)`.

But every enforcement entry point in every SDK takes an `EffectivePolicy`, never a
`PolicyDefinition`. There was no path from a signed context to a `PurposeProfile`, so
`validateAction` was unreachable from the wrappers — a function an integrator could call
only by obtaining the profile out-of-band, which nothing offered.

So the profile is carried through the merge onto `EffectivePolicy`, and into
`effective-policy.schema.json`. That has a second benefit that cost nothing: the policy is
already inside the signed `policies[]` array, so the purpose is covered by the HMAC with
**no change to the signing projection at all**.

Merging needed rules, which the original design was silent on. Two policies bound to
different purposes have no most-restrictive combination — picking one applies rules authored
for a purpose the caller did not declare, and dropping the profile turns a purpose-scoped
policy into an unscoped one. Both are worse than refusing, so it resolves to deny-all.
Resolution can never produce that input, having filtered to a single purpose already, but
`merge()` is public and must not depend on its caller having filtered first.

### Case sensitivity points two different ways, on purpose

`purposeId` comparison is **case-sensitive**. Action-category comparison is
**case-insensitive**. That looks inconsistent and is deliberate: both choices deny rather
than admit a mis-cased value.

- A mis-cased purpose resolves *nothing*. `Campaign-X` does not reach a policy written for
  `campaign-x`.
- A mis-cased category is still *caught*. `EXPORT_PII` does not walk past a prohibition on
  `export_pii`.

Consistency for its own sake would have to pick one, and either choice opens a hole in the
other direction. The rule that generalises is "fail closed", not "compare uniformly".

### Prefix matching is not narrowing

The original chain rule was: a child purpose is within its parent's scope if it
`startsWith` the parent's.

That accepts `campaign-x` → `campaign-xyz-evil`. The two purposes are unrelated; one merely
begins with the other's characters. A sub-agent could pick any string sharing a prefix with
what it was delegated.

The rule is now: exact match, or the parent is a glob that matches, or the child extends the
parent **on a `-` segment boundary**. `campaign-x` admits `campaign-x-overlap` and refuses
`campaign-xyz-evil`.

None of the three existing glob helpers could be reused. Both are case-insensitive, which
would readmit `Campaign-X`; one expands `*` to `[^:]*` for colon-delimited source triples;
one is `internal`. Purpose ids are hyphen-delimited and must compare case-sensitively, so
this is a fourth dialect. The spec's existing rule that the dialects must not be unified
applies unchanged.

### `scopeNarrowing` was named for its effect, and documented as its opposite

The field's original comment said "scopes removed at this hop". The validation rule said a
child's set must be a **subset** of its parent's — which only makes sense if the field lists
what *remains*. Under a removals reading, narrowing would require a superset.

The rule is right and the comment was wrong: `scopeNarrowing` lists the scopes still in
force. An empty parent set therefore leaves nothing for a child to claim, which follows §3
(on a set of what remains permitted, `[]` is the most restrictive value).

### Two action-category maps, because the wrappers have different keys

The action category must come from administrator configuration, never from the caller: an
agent that can name its own category can name a permitted one.

The first design keyed that map by tool name. But `HttpRequestArgs` carries a method and a
path and **no tool name**, so on the `api` path the map could never match and action
validation would have been permanently inert — while the configuration implied otherwise.
That is the `testing-antipatterns.md §4` failure, "a gate that silently does not exist", and
it is worse than having no gate because nothing looks wrong.

So there are two maps: tool name for MCP-style wrappers, `"METHOD path-glob"` for HTTP, the
latter using the same glob dialect `allowedEndpoints` already uses. The HTTP check runs
**per hop**, so a 307 to `/export/all.csv` is classified rather than laundered through a
redirect.

Where several HTTP entries match, all are validated and any denial wins. A specificity rule
would be gameable by adding a broader entry.

### Unclassified calls deny, including under a deny-list-only purpose

If no map entry classifies a call and the purpose constrains actions, the call is denied.

The allow-list half is obvious. The deny-list half is the one worth stating: a purpose
declaring only `prohibitedActions: ["export_pii"]` means "anything but exporting PII", and
an unclassified tool might be exactly that. Permitting the unclassified while forbidding the
classified cannot be the author's intent.

An **empty** `prohibitedActions` restricts nothing, so it does not make a call
unclassifiable. The two arrays read in opposite directions, per §3.

### The chain is validated where it is used, not where it is built

A validator that nothing calls is `testing-antipatterns.md` §4 — a gate that silently does
not exist — and it is the worst version of it, because its own tests all pass and nothing
looks wrong. So the question of *where* the call goes is part of the design rather than a
detail left to the integrator.

The check goes into every wrapper's context validation, beside the signature and expiry
checks, rather than into the builder. Two reasons, pulling the same way:

- A builder that validated would have to do something with an invalid chain. Throwing makes
  issuing brittle; dropping the chain emits a context that looks delegated and is not. So the
  builder records, and §15.3 now says it MUST.
- The check is only worth anything after the signature. An unsigned chain can be rewritten by
  the principal it constrains, so validating one checks the attacker's own arithmetic. Only
  the consuming side has a verified chain to check.

Backward compatible because an absent, empty or single-hop chain has no parent to widen
against and is allowed — so every context predating the feature is unaffected. Asserted as a
test in each SDK rather than argued in a comment.

The mutation check is what makes the wiring tests worth having: disabling the call fails
exactly three tests in each of the three SDKs, and the four allow-cases keep passing. A
wrapper that denied every chain would satisfy the denial tests alone.

Threat-model **E6** is *Mitigated* on this basis, with no residual: depth is capped at ten
hops in the validator and as `maxItems` in the envelope schema, and the length is checked
before the hops are walked. Ten is a topology property rather than a request property, so a
fixed ceiling is the right shape of limit — an unbounded one would leave the size of a signed
context as the only constraint, and that is not a security boundary.

### The judge can only subtract

The judge runs after the deterministic three have allowed a call, and can only withdraw
that allowance. It is never consulted to permit something they denied.

This is what makes prompt injection survivable rather than critical. The tool call and the
history are agent-influenced text that reaches a model, so injection is possible; the worst
a manipulated verdict achieves is an allow the deterministic rules had already granted. A
judge that could widen access would make a persuasive prompt a privilege escalation.

`escalate` is **not** an allow. A wrapper with no review handler must deny, or "escalate to
human review" silently means "permit" in every deployment that never built the review step —
a fail-open on exactly the ambiguous cases the judge exists to surface.

Every unusable input escalates rather than reaching a threshold comparison: a confidence
outside `[0, 1]`, `NaN`, and inverted thresholds. A judge reporting `1.5` has malfunctioned,
and `1.5` clears every bar — clamping it to `1.0` would launder a broken answer into a
confident allow.

### The policy's judge block has to actually apply

`purposeProfile.judge` names a `model`, a `historyWindow`, a `maxLatencyMs` and two
thresholds. Declaring them is not the same as applying them: without something that reads
them, the model would come from whatever client a deployment injected and the rest would take
effect only if the integrator's own glue happened to pass them through. A policy author could
configure a judge in full and get a judge configured entirely differently, with no error —
the same shape of problem as a tool-name-keyed HTTP map.

So `IJudge` declares the model it invokes, and a mismatch against the policy's `model`
escalates **before** the call. Invoking the wrong model and noticing afterwards has already
spent the tokens and produced a verdict that reads as authoritative in an audit log. The
comparison is exact: `claude-sonnet` and `claude-sonnet-5` are different models, and a
prefix rule would let a deployment satisfy a policy demanding one by wiring the other.

A gate helper reads `historyWindow`, `maxLatencyMs` and the thresholds from the resolved
policy, and the wrappers call it: `PreExecuteAsync` / `pre_execute` / `preExecuteAsync` run
the deterministic checks and then the gate. The judge client, the tool-call history and an
escalation handler are wrapper options, inert when unset — the same shape as `hashSalt` and the
action-category maps, which is the argument against the earlier "a wrapper cannot assume a
network client": it does not have to assume one, it takes one.

Retention stays the integrator's: `ToolCallHistory` is an instance *they* own and pass in,
because a tool call can carry the arguments a caller sent and how long that lives is not a
decision a wrapper should make. `escalate` still denies unless a handler is wired.

### The envelope got the schema it never had

`jti`, and now `declaredPurpose` and `delegationChain`, live on the SecurityContext
envelope — which had no published JSON schema at all. It was prose in §1-§2 plus two
known-answer fixtures. That was survivable for `jti`, a single opaque string, but a
delegation hop is a nested object with five fields and a closed enumeration, and
`PrincipalType` would have been the only enumeration in the model with nothing to compare
itself against.

So `security-context.schema.json` now exists, describing the **canonical signing
projection** rather than any SDK's native context type — the three models deliberately
differ and converge only at the signed form, so the projection is the only shape all three
share. It gives `delegationHop` and `PrincipalType` a published contract, and it means
every `fixtures/signing/*.json` canonical payload is now schema-checked rather than merely
described. Before it, a signing fixture could carry any field at all and nothing would
notice.

It does **not** `$ref` `effective-policy.schema.json` for its `policies` entries, even
though that is the obvious modelling. No schema in this directory uses a cross-file `$ref`;
four separate validators read these files (Python's `jsonschema`, the server's Ajv, and the
two native SDK readers), each would need a resolver with a local store, and one of them
silently lacking it means a schema that validates nothing while looking authoritative.
Duplication handled by an equality test — the convention §14 already establishes for the
operator enum — is the cheaper failure mode.

### No AWS SDK dependency

`Tolap.Mcp` and `@aws/tolap-mcp` have no third-party runtime dependencies, and
`tolap-mcp` has only `httpx`. An optional semantic check is a poor reason to put the AWS SDK
behind every consumer of a security package.

So `BedrockJudge` takes a one-method transport seam that also reports its model id. The
parts worth shipping and testing — prompt construction, response parsing, the timeout, the
fail-closed mapping — live in the package. The dozen lines that call `Converse` are the
integrator's, and are demonstrated in the doc comment and exercised by the live tests.

## The invariants, and how they are tested

**A policy carrying no `purposeProfile`, resolved without a declared purpose, produces
byte-identical signed bytes.** This is the whole backward-compatibility argument. Tested
directly — a context with null optional fields compared against one with empty strings and
empty arrays — as well as by the two pre-existing signing fixtures remaining green
unchanged. An implementation emitting `""` would pass the fixtures and still give one
context two valid signatures.

**A purpose-scoped policy's rules never reach an effective policy for a different purpose.**
Filtering runs before the merge, so this is structural. Asserted on the *access consequence*
(a limit, a masked field, an action list) rather than on the profile's absence, because the
rules could merge while the profile was dropped — which is precisely what filtering after
the merge produces.

Also tested:

- The substring hole is closed for five shapes of near-miss, paired with three shapes of
  legitimate boundary extension — so a validator that denied everything fails.
- Every denial has a paired allow proving the same call succeeds when permitted.
- `null` and `[]` are distinguished everywhere an action list appears, in both directions.
- Every fail-closed path asserts its **reason string** as a literal, since integrators
  branch on them.
- The judge's disposition mapping is exhaustive over the confidence/alignment/threshold
  cross-product, including both boundaries and every unusable input.
- Live judge tests against a real model cover the injection case and a drift trajectory, and
  deliberately assert no specific confidence — pinning one would fail on a model update
  rather than on a defect.
- Cross-SDK: one shared fixture corpus drives all three SDKs, including a new signing
  known-answer whose third delegation hop carries microsecond input, pinning millisecond
  truncation for a timestamp nested inside an array of objects — a place the existing
  sub-second fixture does not reach.

Reaching 100% line and branch coverage on the new code meant **deleting** two defensive
branches that turned out to be unreachable: an `ArgumentException` catch around a regex built
from `Regex.Escape` output, and a `ValueKind` check after a brace-delimited JSON slice.
Unreachable defensive code reads as a handled case that no test can exercise, which is worse
than not having it.

## Documentation

Eighteen markdown files changed. Listing them all rather than the highlights, because a
feature documented in four places and a feature documented in eighteen are different claims,
and the earlier draft of this section named four.

**Normative:**

- **canonical-enforcement-spec §15** — the normative section, plus §2 (the envelope's three
  optional fields and the omit-when-absent rule), §13 (three new stated limitations, including
  what `security-context.schema.json` deliberately does *not* describe), §14 (the new
  conformance fixtures, the `PrincipalType` enumeration check, and the rule that every
  signing fixture's canonical payload must validate against the envelope schema).
- **connector-spec** — four rows in the applicability matrix and six in the denial-reason
  table. A field with no row is "parsed but ignored" by that document's own rule.

**Entry points:**

- **README** — a purpose-binding section, four merge-rule rows including the two that resolve
  to deny-all, one security property, and `security-context.schema.json` as a fourth schema
  layer.
- **SECURITY.md** — two enforcement guarantees (the purpose-scoped policy inside the
  envelope, and the fail-closed unclassified call) and two integrator obligations (configure
  the action-category maps; bound the depth of a delegation chain you do not control).
- **CHANGELOG** — the 1.1.0 entry, including the five cross-SDK signed-bytes divergences the
  parity audit found.
- **CONTRIBUTING** — the coverage gate as a pre-review step.

**Guides and reference:**

- **Three implementation guides** — the feature in each language's idiom, plus the
  limitations that had no home: the delegation-chain depth ceiling, the validator having no
  wrapper call site, `ToolCallHistory`'s retention properties, and the unenforceable-shape
  denial and its named opt-out.
- **architecture.md** — the envelope's real field set (an earlier revision showed a
  `userEmail` and `roles` that no SDK ever carried and that the new schema now rejects), the
  store interface per language, and the four shipped components that are not on the
  enforcement path.
- **policy-server.md** — the `PurposeProfileEditor`, the `declaredPurpose` query parameter on
  `GET /v1/resolve`, and the stated limitation that `GET /v1/resolve/preview` passes no
  purpose and therefore cannot see a purpose-scoped policy at all.
- **testing-antipatterns.md §8** — the coverage-artefact section, the three treatments for
  unreachable defensive code, and the coverage gate.
- **security/threat-model.md** — E5, E6, E7 and D5, the outbound trust boundary TB6, and
  asset A6 (the judge's model credential).
- **local-testing.md** — measured suite counts.
- **Four example READMEs** — the purpose-binding example in each language, and the
  arithmetic that changed when a second non-framework example appeared.

## Out of scope

- **Verifying that a declared purpose is honest.** Out of reach by construction: the caller
  asserts it. What is in reach, and done, is making the assertion tamper-evident and checking
  it against the policy set.
- **A judge on by default.** Wiring is a deployment decision: a judge adds a paid,
  third-party round trip to the authorization path, so the wrapper runs one only when a
  `judge` is configured *and* the policy asks for it. What is **not** out of scope any more is
  the wiring itself — `JudgeGate` had no wrapper call site, which made a policy's judge block
  depend on every integrator writing the same glue correctly.
- **Inferring an action category from a path or a tool name.** The same reasoning
  connector-spec §6 gives for refusing to derive a resource name from a route: unspecified
  inference in an access-control decision. An administrator states the mapping.
