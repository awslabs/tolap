# Tool rules: per-identity MCP tool gating, driven by the policy alone

## The problem

TOLAP gates *what a tool returns*. Whether a given user may call a given tool at all is left
to one of three things, none of which is per-identity:

- `allowed_tools` / `AllowedTools` / `allowedTools` on the signed-context wrapper's options.
  This is one static list per wrapper instance. Every caller gets the same list whatever their
  signed context says, and an empty list means *unrestricted*.
- `purposeProfile.allowedActions` / `prohibitedActions` through a tool-to-category map. This is
  per-policy, but it only exists under a purpose profile. It also answers a different question:
  "does this tool serve the declared purpose?", not "may this identity call this tool?".
- The gateway or MCP host in front of the server (IAM, OAuth scopes, Cedar on a gateway).

So a policy cannot say "analysts may call `query_patients` but not `export_segment_csv`"
without inventing a purpose to hang it on, or running a separate wrapper per role.

## What this adds

This adds one policy field, `objectRules.toolRules`, which sits next to `endpointRules`:

```json
"objectRules": {
  "toolRules": {
    "allowedTools": ["query_patients", "count_patients"],
    "hiddenTools": ["export_segment_csv"]
  }
}
```

**The policy alone decides.** There is no constructor option. Every MCP wrapper that knows the
tool name evaluates `toolRules` whenever the policy carries it:

| SDK | Wrappers |
|---|---|
| Python | `SecureMcpToolWrapper` (and so `SecureToolFactory`) |
| TypeScript | `SecureContextToolWrapper`, `SecureToolFactory`, `SecureMcpToolWrapper` (store-resolving) |
| .NET | `SecureContextToolWrapper`, `SecureToolFactory`, `SecureMcpToolWrapper` (store-resolving) |

So a deployment can switch between data-only, tools-and-data, and tools-only gating without
touching code or redeploying:

| Policy carries | Effect |
|---|---|
| no `toolRules` | Data access only. Tool gating stays with the host or gateway, exactly as today. |
| `toolRules` and data rules | Both layers narrow. |
| `toolRules`, no data rules | Tool access only. Absent data rules mean unrestricted data. |

This makes TOLAP's tool gating an *additional* layer on top of traditional MCP tool control. A
deployment that controls tools at the gateway writes no `toolRules`, and nothing changes. Only
the policy author decides, through the signed policy. A caller or the agent never can.

### Why policy-only and not a constructor toggle

An earlier draft put enforcement behind an off-by-default constructor toggle. That was dropped
for three reasons:

- **No inert rules.** With a toggle, a policy could carry `toolRules` that a wrapper silently
  ignored. That is the "configured control that never runs" failure from threat model R-6, and
  it needed a warn-once workaround. Policy-only has no such state: if the rule is there, it
  runs.
- **No code change to adopt.** Enabling tool gating becomes a policy edit, which is signed,
  reviewed, per-identity and reversible from the console, not a code change and redeploy.
- **Nothing changes for existing deployments.** No existing policy carries `toolRules`, so
  adding the field changes no current decision. That was the only thing the toggle protected.

## What this does not change

- A policy with no `toolRules` resolves, merges, serializes, signs and enforces exactly as
  before. `toolRules` is omitted when absent, so existing signatures and signing fixtures are
  untouched.
- The static `allowed_tools` list keeps its current semantics, including "empty means
  unrestricted". It becomes a ceiling that `toolRules` narrows further.
- The HTTP wrapper is unaffected. An HTTP request has a method and a path but no tool name, and
  `endpointRules` already gates it.
- The schema stays at v1.0. `toolRules` is an optional property.

## Design decisions

### Where the field lives: `objectRules.toolRules`

A tool is not a data object, but neither is an endpoint, and `endpointRules` already lives in
`objectRules`. Putting `toolRules` there reuses, in all three SDKs, the existing plumbing for:

- merge
- serialization
- signing
- has-rules checks

It also fits the console's "rule editors" model. A top-level field would need all of that
written a second time, for no behavioural gain.

### Matching: exact for allow, case-insensitive for hide

`allowedTools` matches **exactly and case-sensitively**, as `allowed_tools` and the
tool-to-category maps already do. A tool name is an identifier, not a pattern.

`hiddenTools` matches **case-insensitively**, following the purpose-binding design's rule to
fail closed rather than compare uniformly:

- An allow-list denies a mis-cased name, because that name isn't listed.
- A deny-list compared case-sensitively would let a mis-cased name through. An MCP server that
  dispatches case-insensitively would then run `Export_Segment_CSV` past a hide on
  `export_segment_csv`.

Both choices deny the mis-cased value, which is the direction that matters.

### Tool-name grammar and an ASCII-only fold

When a policy carries `toolRules`, including `toolRules: {}`, the tool name must match
`^[A-Za-z0-9_.-]{1,128}$`. These are MCP's recommended tool-name characters, and the match
anchors at the true end of the string, so a trailing newline fails. Any other name is denied
with `invalid tool name`, before the hide is checked. A policy without `toolRules` applies no
grammar, so no existing decision changes.

This is what makes the case-insensitive hide agree across SDKs. Unicode case folds do not
agree: U+212A KELVIN SIGN folds to `k` under Python `str.lower()` and JS `toLowerCase()`, but
not under .NET `OrdinalIgnoreCase`. So `"\u212Aill_switch"` would be hidden in two SDKs and pass
in the third, failing open. Without the grammar, whitespace would also slip past a hide
(`"export_segment_csv "`). Once names are restricted to ASCII, every SDK uses an ASCII-only
fold (Python `str.translate`, a TS `[A-Z]` replace, .NET `OrdinalIgnoreCase`), and all three
are identical. The existing `containsIgnoreCase` helper is **not** used, because it folds with
`toLowerCase`.

Globs are out of scope.

### Malformed rules

Python and .NET reject a malformed `toolRules` when deserializing: a string instead of an
array, non-string entries, or an array instead of an object. Python raises `ValueError`; .NET
throws `JsonException`. TypeScript has no deserializer, so `validateToolAccess` denies a
malformed shape with `invalid tool rules` instead of half-applying it (for example, running
`includes` on a string). JSON `null` means absent everywhere. The policy server rejects all of
these at write time via the schema (`pattern`, `uniqueItems`, `additionalProperties: false`).

### Null versus empty (canonical spec §3)

| `allowedTools` | Meaning |
|---|---|
| absent | Unrestricted: this policy adds no tool restriction |
| `[]` | **Deny every tool** |

For `hiddenTools`, absent means nothing is hidden. `hiddenTools: []` also hides nothing, but
merge retains it as `[]` (§3: "empty in, empty out").

This is the opposite of the static `allowed_tools` option, where empty means unrestricted. That
is deliberate. The static option predates §3 and keeps its semantics for compatibility, while
the policy field follows §3 like every other policy allow-list. The docs state the contrast in
both places.

### Merging

`allowedTools` intersects and `hiddenTools` unions (retaining empty), exactly like
`allowedEndpoints` and `hiddenEndpoints`. Disjoint allow-lists intersect to `[]`, which denies
every tool. That is the most restrictive result, so it is correct.

### Check order inside `pre_execute` / `preExecute`

```
validate_security_context      (signature, expiry, delegation chain)
static allowed_tools           "tool not in allowed list"          (existing)
tool-name grammar              "invalid tool name"                 (NEW, only with toolRules)
toolRules.hiddenTools          "tool is hidden"                    (NEW)
toolRules.allowedTools         "tool not in allowed set"           (NEW)
canQuery                       "query not permitted"               (existing)
purpose action                 (existing)
object / fields / endpoint     (existing)
judge                          (existing, async/judge path only)
```

A tool denial never reaches the judge. The denied call is still recorded in the tool-call
history, as every other denial is, so the judge sees refused attempts on later calls.

Tool rules come **before** `canQuery` for two reasons:

- "You may not call this tool" is the more specific answer when both checks would deny.
- A tool gate that ran only after the read gate would be skipped by a write-only policy, one
  that grants no reads.

Hidden is checked before allowed, as it is everywhere else (§9, §15.2).

The write pre-checks (`pre_write` / `preWrite` / `PreWrite` and the execute-write helpers)
take an optional tool name. When it is passed, context validity, the static list and
`toolRules` run in that order before any write check, with the same reasons; the gate does not
require `canQuery`. When it is omitted, the write path is unchanged.

The reason strings follow the object and endpoint families (`object is hidden` /
`object not in allowed set`, and the same for endpoints). Like them, they do not echo the name.

In the store-resolving wrappers (.NET and TS `SecureMcpToolWrapper`), the check is the first
policy check. It runs before `canQuery` in .NET and before the purpose action in TS, which keeps
the same relative order. .NET routes the denial through `HandleDenial`, so `Permissive` mode
applies to it as it does to every other denial there.

### Filtering the tool list

Enforcing at call time stops a denied call, but the agent can still see the tool, reason about
it, be steered into trying it, and waste turns on denials. So the signed-context wrappers gain a
pure function over a list of names:

- Python: `SecureMcpToolWrapper.filter_tools(context, tool_names) -> list[str]`
- TypeScript: `SecureContextToolWrapper.filterTools(context, toolNames): string[]`
- .NET: `SecureContextToolWrapper.FilterTools(SecurityContext context, IEnumerable<string> toolNames) : IReadOnlyList<string>`

It returns, in input order, the names that `pre_execute`'s tool-name checks would not deny:

1. If `validate_security_context` fails, it returns `[]`. It fails closed: an invalid context
   lists nothing.
2. The static `allowed_tools` list.
3. `toolRules`.
4. The purpose action check (`validate_tool_action`). It depends on the tool name alone, and a
   tool it denies can never succeed.

It deliberately does not evaluate `canQuery` on its own, or object, field or endpoint rules.
Those depend on call arguments, not on the tool name, and a write tool is legitimately listable
under a policy that grants no reads. A policy that grants none of `canQuery`, `canInsert`,
`canUpdate` and `canDelete` lists nothing, since every call it could make is denied. Null and
non-string entries are dropped, whether or not the policy carries `toolRules`. It doesn't record into `tool_call_history` or consult the judge, because
listing is not a call.

An integrator calls it in their `tools/list` handler. Listing a tool is still not permission to
call it: `pre_execute` re-checks every call.

The store-resolving TS `SecureMcpToolWrapper.listTools()` is **not** changed. It takes no
request, so it has no identity to filter by (see Out of scope).

### No new signing work

The effective policy is signed whole: Python and TS canonicalize the policy, and .NET signs
`EffectivePolicy[]` with only `Integrity` nulled. So the signature covers `toolRules`
automatically. A tamper test in each SDK pins this, because "automatically" is only a claim
until something asserts it.

### Version skew

A wrapper built from an SDK older than this change does not know `toolRules`. Its deserializer
drops the field, so the rules are silently not enforced there. Two things limit this:

- The policy server validates against the schema with `additionalProperties: false`. An older
  server therefore **rejects** a policy carrying `toolRules` at write time, rather than storing
  something its fleet can't enforce.
- The docs state the minimum SDK version that enforces `toolRules` (threat model R-9).

The residual risk is a new policy server in front of an older wrapper fleet. That is a
deployment-ordering problem, documented as "upgrade the wrappers before authoring `toolRules`".

## Invariants and how they are tested

| Invariant | Pinned by |
|---|---|
| `validateToolAccess` agrees across SDKs | `fixtures/enforcement/validate-tool-access.json`, read by all three |
| Wrapper-level order agrees across SDKs | `fixtures/enforcement/tool-gate-wrapper.json`, read by all three wrapper suites |
| Merge: intersect/union, `[]` retained, disjoint → `[]` | `fixtures/merge-scenarios/tool-rules-intersect-and-union.json` |
| Schema accepts `toolRules` identically in both documents | Python `test_schema_fixture_validation.py`, server `console-policy-shapes.test.ts` |
| A policy without `toolRules` gets byte-identical decisions | The `no-tool-rules-unchanged` fixture row, plus the existing suites passing unchanged |
| Store-resolving wrappers enforce with no option set | Per-SDK store-wrapper tests |
| `toolRules` is inside the signature | Per-SDK tamper test |
| Stored `[]` survives the policy server | `server/tests/store-null-vs-empty.test.ts` |
| Grammar and ASCII fold agree across SDKs, Unicode and whitespace included | `validate-tool-access.json` rows A1–A23 |
| Canonical bytes and signatures with `toolRules` agree across SDKs | `fixtures/signing/hmac-sha256-tool-rules.json`, computed independently |
| A tool denial never calls the judge, and is still recorded in history | Per-SDK wrapper tests (plan matrix B12, B13) |
| Malformed `toolRules` is rejected, never half-applied | Per-SDK deserialization / shape tests, and server 422s (plan matrix E) |
| The tests actually detect regressions | Plan Task 11: nine mutations per SDK, plus branch coverage of the new functions |

## Out of scope

- **Glob patterns** in `toolRules` (e.g. `read_*`). They can be added later without breaking
  exact names, but they need a decision on whether to use the object glob dialect.
- **Filtering in the store-resolving TS `SecureMcpToolWrapper.listTools()`.** It has no request
  or identity. A `listToolsFor(request)` would need identity resolution and is its own change.
- **A tool catalog in the source manifest for the console.** The console editor takes free-text
  names.
- **`toolRules` on the HTTP wrapper.** There is no tool name there.
- **A switch to turn data enforcement off.** Data access is always evaluated, and tools-only
  gating is reached through the policy, by leaving out the data rules.
