# Testing anti-patterns that produced green suites over real bugs

Every entry below is a defect that **shipped** in this repository while the test suite reported
success. They are recorded as patterns rather than as fixed bugs because the fix is cheap and the
pattern is what recurs: each one was found by accident, not by the suite that was supposed to
cover it.

The through-line: **a passing test proves an assertion held, not that the code is correct.** An
assertion can hold because the code works, or because the test never reached the code.

---

## 1. Testing the call the code wants, not the call an integrator makes

**The bug.** `maxResults` was silently not enforced. A policy with `limits.maxResults: 1` against
an API returning `{"results": [...]}` handed back **every record the upstream sent**. Present in
all three SDKs.

**Why 66 `api` tests missed it.** `collectionPath` is an *optional* argument that names the array
of records inside a response envelope. Every existing test of `maxResults` passed it:

```python
body = wrapper.request(context, "GET", "/patients", collection_path="results")  # every test
body = wrapper.request(context, "GET", "/patients")                            # every integrator
```

The tests were written by reading the implementation, so they supplied what the implementation
wanted. The branch taken when the argument is *omitted* was never executed by any test in any SDK.

An integrator has no reason to pass it. It is optional, the spec says the post-response pipeline
runs "over the body, walking nested structures," and nothing warns you. Their limit does nothing.

**The rule.** For every optional parameter, test the call **without** it. If the code needs an
argument to be correct, either the argument is not optional or the code must fail closed when it
is missing. "The test passes when I pass the right arguments" is not a claim about the SDK.

**Smell:** every test of a feature passes the same optional argument.

---

## 2. Controls tested individually, never against each other

**The bug, restated.** The same missing `collectionPath` produced *three different behaviours*:

| Control | `collectionPath` omitted | Direction |
| --- | --- | --- |
| `allowedFields` (projection) | returned `{}` | fail-closed |
| `rowFilters` | returned `None` | fail-closed |
| `limits.maxResults` | **returned every record** | **fail-OPEN** |

Three record-level controls, one shared argument, three answers. Each had its own passing tests.
None compared them, so the disagreement was invisible — and the outlier was the dangerous one.

**The rule.** When several controls act on the same input through the same code path, assert they
**agree**. A test that pins each one separately cannot see a divergence between them; the
cross-control assertion is a different claim, and it is the one that catches this class of bug.

**Smell:** N controls share a parameter and there are N tests, none of which mentions more than
one control.

---

## 3. An early `return` reported as a pass

**The bug.** All 41 AWS tests opened with `if (Skip) return;`. xunit records an early return as a
**pass**. With no credentials the run reported `Passed: 307, Skipped: 0` — byte-identical to a run
that had actually executed against real AWS.

A suite whose entire purpose is catching fail-open bugs was failing open about whether it had run.

**The rule.** A test that does not execute must report **skipped**, never passed. Use the
framework's real skip mechanism (`Assert.Skip`, `pytest.mark.skip`, `ctx.skip()`), not control
flow. And check that a suite's skip count is what you expect — TypeScript's honest `43 skipped` is
what made .NET's `Skipped: 0` visibly wrong.

**Smell:** a conditional `return` at the top of a test body.

---

## 4. A gate that silently does not exist

**The bug.** The Python AWS suite set `pytestmark = pytest.mark.skipif(...)` in a **`conftest.py`**.
pytest only honours that name in test *modules*. The gate did nothing, so a clean checkout
produced 35 errors and 3 failures from a suite designed to skip.

**Why nothing caught it.** A missing skip has no symptom on a machine that happens to have
credentials. The guard and the guarded were the same mechanism.

**The rule.** A test that verifies a gate must **not be behind that gate**. Assert the mechanism
from outside it.

**Smell:** framework magic (`pytestmark`, attributes, decorators) in a file the framework treats
differently from where you are used to putting it.

### The gate that is correct and still not enough

The server suite skips its database-backed tests when `TOLAP_TEST_DB_DSN` is unset, and it does
this *properly* — the skip condition is asserted from outside the skip, exactly as above. It is
still a hazard: **209 of 544 tests vanish**, including every §3 `[]`-versus-`null` persistence
assertion and every §12 revocation assertion. Those are the two properties the whole store design
exists to protect.

A correctly-implemented gate catches "the gate broke." It does not catch "the gate was never
opened," because a suite reporting `330 passed` looks like success rather than like a third of the
assertions having evaporated.

**What is done about it.** `.github/workflows/ci.yml` runs a `Policy server DB suites actually ran`
step that parses the JSON reporter and **fails the build** if any test whose name matches
`null vs empty`, `revocation`, `GET /v1/resolve` or `admin API` reports skipped. Asserting the
named suites executed is stronger than asserting the variable is set: it survives a rename of the
variable, a broken service container, and a skip introduced for an unrelated reason.

**The rule.** For a gate that can hide a security property, do not settle for the environment being
configured — assert in CI that the specific suites *ran*. A skip is right on a contributor's laptop
and wrong in the job that gates a merge, and only the second half of that needs machinery.

**Smell:** a passing run whose test count is materially lower than the last one, with nothing
drawing attention to the difference.

---

## 5. Asserting another runtime's behaviour without using that runtime's entry point

**The bug.** The policy server's signed artifact **did not deserialize in .NET at all**. .NET's
`SecurityContext` declares envelope-level `Version`, `UserId`, `TenantId`, `Policies[]` and
`Integrity{}`; the artifact carried none of them. `TolapJsonOptions.Deserialize<SecurityContext>`
produced an object of nulls with an empty policy array, then signed those nulls and rejected. Any
.NET consumer following the documented path was blocked outright.

**Why the cross-SDK suite missed it.** The test shelled out to real `dotnet` — which looks like
genuine interop — but **hand-built** the context from `JsonDocument` fields:

```csharp
var ctx = new SecurityContext(policy.Version, policy.UserId, /* ... */);   // the test
var ctx = TolapJsonOptions.Deserialize<SecurityContext>(json);            // every consumer
```

So it proved .NET's HMAC arithmetic works, which was never in doubt, rather than that .NET can
consume what the server emits. The Python arm called the real `deserialize_context` and was
correct — the same suite, the same day, one arm right and one wrong for exactly this reason.

This is #1 across a language boundary, and worth its own entry because the failure looks stronger
than a unit test rather than weaker: invoking another runtime feels like proof, so nobody asks
which of its functions was invoked.

**The rule.** A claim about another runtime must be asserted through that runtime's **real public
entry point** — the function a consumer calls, not an equivalent you assembled. If the test
constructs the object under test, it is testing your model of that runtime, not the runtime.

**Smell:** a cross-language test that builds the foreign type field by field, or that never calls
a `Deserialize`/`parse`/`load` function.

---

## 6. Mutation not verified in both directions

A guard that only checks "does it skip?" is satisfied by a hardcoded skip. A guard that only
checks "does it run?" is satisfied by a gate that never engages.

**The rule.** Mutate in **both** directions — always-on and always-off — and confirm the suite
fails each time. Every fix in this document was verified this way. Two of them initially appeared
to survive mutation; both times the mutation had not actually applied (a regex that did not match,
a `dist/` build that was not rebuilt). **Confirm the mutant is present before trusting that it
survived.**

### The corollary for time-based assertions: size the bound from the mutation run

When the defect *is* the time — a quadratic parser, a ReDoS — the vulnerable code returns the
**same answer**, just slowly. The assertion is therefore a threshold, and a threshold chosen by
intuition is usually wrong in the direction that hides the bug. Three tests in this repository
were written, passed, and were worth nothing:

| Test | Bound | Cost of the defect at that input | Verdict |
| --- | --- | --- | --- |
| `parseColumnDump` linearity, 50,000 columns | 2,000 ms | **1,678 ms** | passed against the bug |
| Pagination key-map, N = 2,000 | 2,000 ms | 456 ms | passed against the bug |
| Envelope/policy expiry agreement | — | fixture pre-set the value under test | passed against the bug |

Each looked generous. Each sat *under* the defect's cost, or asked a question the fixture had
already answered.

**The rule.** Run the mutant, **measure** it, then choose an input size where the two costs are
separated by an order of magnitude — and record both numbers in the test comment so the next
person can tell a flake from a regression. Resizing the first test above to 100,000 columns
separated 6,068 ms from 30 ms. Same assertion, same 2-second bound, now meaningful.

**Smell:** a `toBeLessThan(...)` whose threshold appears in no measurement, or a performance
fixture whose size is a round number nobody derived.

---

## 7. A pass that came from a stale artifact

Twice, results were not what they appeared:

- `tolap-mcp` was installed **non-editable** in site-packages, so edits to the repo were invisible
  and a verified fix appeared not to work.
- `rm -rf dist` left `tsconfig.tsbuildinfo`, so `tsc -p` no-op'd and a phantom error appeared.

**The rule.** Before concluding anything from a test result, confirm the code under test is the
code you edited. `python3 -c "import pkg; print(pkg.__file__)"` costs nothing.

---

## What "100% coverage" has to mean here

Line coverage would have reported these paths as covered. The `collectionPath is None` branch
*was* executed — by tests that passed an explicit path for the *other* controls. Coverage counts
lines reached, not argument combinations exercised.

For a policy-enforcement SDK, the coverage that matters is the **cross-product**:

1. **Every control × every argument state.** Each control, with and without each optional argument.
2. **Every control × every SDK.** Behaviour differences between .NET, Python and TypeScript are
   security defects — one signed policy must decide identically in all three. Porting found the
   `ValidateAccess` `canQuery` fail-open and this `maxResults` fail-open; neither was visible from
   inside a single SDK.
3. **Every denial paired with its control.** A denial test that passes because nothing was
   returned proves nothing without a paired case showing the same call *succeeds* when permitted.
4. **Every fail-closed path asserted, not assumed.** The `{}` and `None` returns above were
   correct — but nothing asserted them, so nothing noticed when a sibling disagreed.

Where the cross-product is genuinely covered, say so with a number. Where it is not, **say that
too** — `security/aws/README.md` names two of six `kb` renderers as grammar-only
rather than implying they are verified. An unstated gap reads as coverage.

---

## The practices that caught the real defects

The inverse of the list above. Each of these found a genuine bug in this repository.

- **When a test fails, fix the code to match the spec — never weaken the test.** The exception
  is a test encoding behaviour the spec forbids; correct those and cite the section. Several
  tests here have *asserted* buggy behaviour, including one whose name claimed the opposite of
  what it checked.
- **Shared fixtures over per-SDK tests** for anything cross-cutting. Demanding byte-identical
  output from three implementations forces every disagreement into the open. It caught a
  `WHERE`-clause fail-open that no single-SDK test had found in the repo's history.
- **Port across SDKs — it is not ceremony.** Porting found a missing `canQuery` check in .NET's
  `ValidateAccess` (a fail-open on the broadest permission in the model) and a `maxResults`
  fail-open in all three. A divergence is invisible from inside the SDK that has it.
- **Derive fixture expectations from the spec, then verify against reality.** 21 hand-written
  operator expectations, 2 wrong — both about present-null semantics, both caught by running
  them against a real implementation and Postgres. Encoding either would have made pushdown and
  post-fetch disagree.
- **Test against the real service, not only a fixture.** A fixture asserts the document *you*
  chose to emit. Two `kb` renderers emitted filters that the service **accepted** while
  enforcing nothing; only a live engine could tell the difference.
- **Prove denials with paired controls.** Every "denied write leaves the database unchanged"
  test has a sibling proving the same write lands when permitted. Without the control, blocking
  everything passes.
- **State gaps explicitly.** An unstated gap reads as coverage. `security/aws/README.md` names
  two of six `kb` renderers as grammar-only for that reason.
