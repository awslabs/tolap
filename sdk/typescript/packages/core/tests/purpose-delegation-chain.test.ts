/**
 * `validateDelegationChain` — a chain narrows at every hop and never widens
 * (canonical spec §15.3).
 *
 * `fixtures/purpose-binding/delegation-chains.json` is the cross-SDK contract and is
 * consumed case for case below. The local tests add the argument-state cross-product
 * the fixture cannot cheaply enumerate: `undefined` versus `[]` on each side of both
 * comparisons, and the mid-segment cases that separate a segment-boundary rule from a
 * plain prefix test.
 *
 * The mid-segment rule is the security-relevant one. A prefix test — the obvious
 * implementation — lets
 * `campaign-x` authorize `campaign-xyz-evil`, two unrelated purposes one of which
 * merely starts with the other's characters.
 */

import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { validateDelegationChain } from "../src/delegation.js";
import { PrincipalType, type DelegationHop } from "../src/types.js";

const purposeFixturesDir = path.resolve(
  __dirname,
  "../../../../../fixtures/purpose-binding",
);

interface ChainCase {
  name: string;
  chain: DelegationHop[] | null;
  expected: { allowed: boolean; reason?: string };
  /**
   * Marks a case whose chain deliberately violates `security-context.schema.json`
   * (a hop purpose with an upper-case letter). It is still an ordinary behavioural
   * case here — the validator must deny it — and the marker only tells the Python
   * schema-validating runner to expect a schema failure.
   */
  schemaInvalidByDesign?: boolean;
}

interface ChainFixture {
  description: string;
  action: string;
  cases: ChainCase[];
}

function loadFixture(): ChainFixture {
  const content = fs.readFileSync(
    path.join(purposeFixturesDir, "delegation-chains.json"),
    "utf-8",
  );
  return JSON.parse(content) as ChainFixture;
}

const fixture = loadFixture();

/**
 * A hop with only the fields a case names.
 *
 * `purpose` and `scopes` default to **absent**, never to `""` or `[]`: those are
 * different states with different meanings, and a helper that filled them in would
 * make every "absent adds no constraint" test assert something else.
 */
function hop(
  principalId: string,
  purpose?: string,
  scopes?: string[],
): DelegationHop {
  return {
    principalId,
    principalType: PrincipalType.Agent,
    ...(purpose === undefined ? {} : { declaredPurpose: purpose }),
    ...(scopes === undefined ? {} : { scopeNarrowing: scopes }),
  };
}

// ---------------------------------------------------------------------------
// The shared cross-SDK fixture
// ---------------------------------------------------------------------------

describe("validateDelegationChain matches the shared fixture", () => {
  it("declares itself as the delegation-chain corpus", () => {
    expect(fixture.action).toBe("validateDelegationChain");
    expect(fixture.cases.length).toBeGreaterThan(0);
  });

  it("covers both outcomes, so no arm is vacuous", () => {
    const outcomes = fixture.cases.map((c) => c.expected.allowed);
    expect(outcomes).toContain(true);
    expect(outcomes).toContain(false);
  });

  it("still carries the case-differing case as a behavioural case", () => {
    // That case is marked `schemaInvalidByDesign` for the Python schema runner. If a
    // future edit turned the marker into a reason to SKIP the case, the
    // case-sensitivity guarantee would stop being tested here -- which is exactly the
    // "gate that silently does not exist" shape (antipattern #4).
    const marked = fixture.cases.find((c) => c.name === "case-differing-purpose-denied");
    expect(marked).toBeDefined();
    expect(marked?.expected.allowed).toBe(false);
  });

  for (const testCase of fixture.cases) {
    it(`${testCase.name}`, () => {
      // `null` in JSON is the "no chain at all" case; the API takes `undefined`, and
      // the two must decide identically or a context deserialized from JSON behaves
      // differently from one built in code.
      const chain = testCase.chain === null ? undefined : testCase.chain;
      const result = validateDelegationChain(chain);

      expect(result.allowed).toBe(testCase.expected.allowed);
      if (testCase.expected.reason === undefined) {
        expect(result.reason).toBeUndefined();
      } else {
        expect(result.reason).toBe(testCase.expected.reason);
      }
    });
  }

  it("a JSON null and an omitted chain decide identically", () => {
    const asNull = fixture.cases.find((c) => c.name === "null-chain-allowed");
    expect(asNull?.chain).toBeNull();
    expect(validateDelegationChain(undefined)).toEqual(
      validateDelegationChain([]),
    );
  });
});

// ---------------------------------------------------------------------------
// Nothing to check
// ---------------------------------------------------------------------------

describe("a chain with no parent/child pair is allowed", () => {
  it("an absent chain is allowed", () => {
    // Delegation is opt-in: every context predating this feature has no chain, so an
    // absent one cannot be treated as suspicious.
    expect(validateDelegationChain(undefined).allowed).toBe(true);
  });

  it("an empty chain is allowed", () => {
    expect(validateDelegationChain([]).allowed).toBe(true);
  });

  it("a single hop is allowed, however broad its claim", () => {
    // There is no parent to widen against. This validates internal consistency; it
    // cannot establish that the first hop's purpose was honestly declared, which is
    // the stated limitation in spec §13.
    expect(validateDelegationChain([hop("user-1", "*")]).allowed).toBe(true);
    expect(
      validateDelegationChain([hop("user-1", "*", ["read", "write", "admin"])]).allowed,
    ).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Purpose narrowing -- the segment-boundary rule
// ---------------------------------------------------------------------------

describe("purpose narrowing: the segment-boundary rule", () => {
  const midSegment: Array<[string, string]> = [
    ["campaign-x", "campaign-xyz-evil"],
    ["campaign-x", "campaign-xx"],
    ["campaign-x", "campaign-x2"],
    ["campaign", "campaigns-all"],
    ["fraud", "fraudulent-export"],
  ];

  for (const [parent, child] of midSegment) {
    it(`denies '${child}' under '${parent}' (mid-segment extension)`, () => {
      const result = validateDelegationChain([hop("p", parent), hop("c", child)]);

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe(
        `delegation hop 1 purpose '${child}' is not within parent scope '${parent}'`,
      );
    });
  }

  const onBoundary: Array<[string, string]> = [
    ["campaign-x", "campaign-x-overlap"],
    ["campaign-x", "campaign-x-overlap-eu"],
    ["campaign", "campaign-x"],
  ];

  for (const [parent, child] of onBoundary) {
    it(`allows '${child}' under '${parent}' (segment-boundary extension)`, () => {
      // The paired control for the block above: the boundary rule is a real grant, so
      // the denials there are the boundary and not a refusal to extend at all.
      expect(
        validateDelegationChain([hop("p", parent), hop("c", child)]).allowed,
      ).toBe(true);
    });
  }

  it("allows an exact match at every hop", () => {
    expect(
      validateDelegationChain([
        hop("user-1", "campaign-x-overlap"),
        hop("orch-1", "campaign-x-overlap"),
        hop("agent-1", "campaign-x-overlap"),
      ]).allowed,
    ).toBe(true);
  });
});

describe("purpose narrowing: a parent glob", () => {
  const admitted: Array<[string, string]> = [
    ["campaign-*", "campaign-x-overlap"],
    ["campaign-*", "campaign-x"],
    ["*", "anything-at-all"],
    ["campaign-x-*", "campaign-x-overlap"],
  ];

  for (const [parent, child] of admitted) {
    it(`'${parent}' admits '${child}'`, () => {
      expect(
        validateDelegationChain([hop("p", parent), hop("c", child)]).allowed,
      ).toBe(true);
    });
  }

  const refused: Array<[string, string]> = [
    ["campaign-*", "fraud-detection"],
    ["campaign-x-*", "campaign-y-overlap"],
  ];

  for (const [parent, child] of refused) {
    it(`'${parent}' refuses '${child}'`, () => {
      expect(
        validateDelegationChain([hop("p", parent), hop("c", child)]).allowed,
      ).toBe(false);
    });
  }

  it("a glob's `*` crosses a hyphen, unlike a sourcePattern's across a colon", () => {
    // This is the third glob dialect in the SDK and it is documented as deliberately
    // separate. `sourcePatternMatch`'s `*` stops at `:`; here `*` crosses everything,
    // because purpose identifiers are hyphen-delimited.
    expect(
      validateDelegationChain([hop("p", "campaign-*"), hop("c", "campaign-x-overlap-eu")])
        .allowed,
    ).toBe(true);
  });

  it("a pattern's other metacharacters are literal, not regex", () => {
    // `campaign.x` must not match `campaign-x` via a regex `.`, and a `+` must not
    // quantify. A pattern that silently became a regex would widen every parent scope
    // that happened to contain punctuation.
    expect(
      validateDelegationChain([hop("p", "campaign.x*"), hop("c", "campaign-x-overlap")])
        .allowed,
    ).toBe(false);
    expect(
      validateDelegationChain([hop("p", "campaign.x*"), hop("c", "campaign.x-overlap")])
        .allowed,
    ).toBe(true);
  });
});

describe("purpose comparison is case-sensitive", () => {
  const cases: Array<[string, string]> = [
    ["campaign-x", "Campaign-X"],
    ["campaign-x", "CAMPAIGN-X-OVERLAP"],
    ["campaign-*", "Campaign-X-Overlap"],
  ];

  for (const [parent, child] of cases) {
    it(`denies '${child}' under '${parent}'`, () => {
      // Matching resolution's `purposeId` comparison, and deliberately unlike the two
      // existing glob helpers, which are both case-insensitive. Borrowing either would
      // admit here what resolution refuses -- one rule saying yes and the other no
      // about the same value.
      expect(
        validateDelegationChain([hop("p", parent), hop("c", child)]).allowed,
      ).toBe(false);
    });
  }

  it("the same pair in matching case is allowed", () => {
    expect(
      validateDelegationChain([hop("p", "campaign-x"), hop("c", "campaign-x-overlap")])
        .allowed,
    ).toBe(true);
  });
});

describe("an absent purpose on either side adds no constraint", () => {
  const combinations: Array<[string | undefined, string | undefined]> = [
    ["campaign-x", undefined],
    [undefined, "fraud-detection"],
    [undefined, undefined],
  ];

  for (const [parentPurpose, childPurpose] of combinations) {
    it(`parent=${String(parentPurpose)} child=${String(childPurpose)}`, () => {
      // A hop that declares no purpose is not claiming one, so there is nothing to
      // narrow and nothing to exceed. Refusing here would deny every legitimate
      // partial chain; refusing an UNDECLARED purpose is resolution's job.
      expect(
        validateDelegationChain([hop("p", parentPurpose), hop("c", childPurpose)]).allowed,
      ).toBe(true);
    });
  }

  it("an empty purpose string is treated as absent, on both sides", () => {
    // `""` normalizes to absent everywhere in this feature -- the signing projection,
    // the resolution filter -- so it must here too, or one context has two readings.
    expect(
      validateDelegationChain([hop("p", "campaign-x"), hop("c", "")]).allowed,
    ).toBe(true);
    expect(
      validateDelegationChain([hop("p", ""), hop("c", "fraud-detection")]).allowed,
    ).toBe(true);
  });

  it("but a declared pair that widens is still refused", () => {
    // The paired control: "absent adds no constraint" must not be reachable by simply
    // having a purpose.
    expect(
      validateDelegationChain([hop("p", "campaign-x"), hop("c", "fraud-detection")])
        .allowed,
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Scope narrowing -- subset, and [] means "nothing left to pass on"
// ---------------------------------------------------------------------------

describe("scope narrowing is a subset test", () => {
  it("a narrower set is allowed and a wider one is not", () => {
    expect(
      validateDelegationChain([
        hop("p", undefined, ["read", "aggregate"]),
        hop("c", undefined, ["read"]),
      ]).allowed,
    ).toBe(true);

    const widened = validateDelegationChain([
      hop("p", undefined, ["read"]),
      hop("c", undefined, ["read", "write"]),
    ]);
    expect(widened.allowed).toBe(false);
    expect(widened.reason).toBe("delegation hop 1 scopes exceed parent delegation");
  });

  it("an identical set is allowed -- narrowing is not required", () => {
    expect(
      validateDelegationChain([
        hop("p", undefined, ["read"]),
        hop("c", undefined, ["read"]),
      ]).allowed,
    ).toBe(true);
  });

  it("an empty CHILD set is allowed", () => {
    // A hop may give up everything.
    expect(
      validateDelegationChain([
        hop("p", undefined, ["read"]),
        hop("c", undefined, []),
      ]).allowed,
    ).toBe(true);
  });

  it("an empty PARENT set leaves nothing for a child to claim", () => {
    // The `undefined`-versus-`[]` distinction on the parent side, and the arm most
    // likely to be got wrong: `[]` is not "unrestricted" but "nothing left to pass
    // on", so any child scope exceeds it (spec §3).
    const result = validateDelegationChain([
      hop("p", undefined, []),
      hop("c", undefined, ["read"]),
    ]);
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("delegation hop 1 scopes exceed parent delegation");
  });

  it("empty parent with empty child is allowed", () => {
    // The paired case: an empty parent set is not a blanket denial, it just has
    // nothing to give.
    expect(
      validateDelegationChain([hop("p", undefined, []), hop("c", undefined, [])]).allowed,
    ).toBe(true);
  });

  it("an absent set on either side adds no constraint", () => {
    expect(
      validateDelegationChain([
        hop("p", undefined, ["read"]),
        hop("c", undefined, undefined),
      ]).allowed,
    ).toBe(true);
    expect(
      validateDelegationChain([
        hop("p", undefined, undefined),
        hop("c", undefined, ["read", "write", "admin"]),
      ]).allowed,
    ).toBe(true);
  });

  it("scope comparison is case-sensitive and exact", () => {
    // Scopes are identifiers a deployment mints, not globs. If `*` matched or case
    // were ignored, a child could claim `READ` under a parent holding `read` while a
    // peer SDK refused it.
    expect(
      validateDelegationChain([
        hop("p", undefined, ["read"]),
        hop("c", undefined, ["READ"]),
      ]).allowed,
    ).toBe(false);
    expect(
      validateDelegationChain([
        hop("p", undefined, ["read"]),
        hop("c", undefined, ["*"]),
      ]).allowed,
    ).toBe(false);
  });

  it("a repeated child scope present in the parent is still a subset", () => {
    expect(
      validateDelegationChain([
        hop("p", undefined, ["read"]),
        hop("c", undefined, ["read", "read"]),
      ]).allowed,
    ).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Multi-hop chains, ordering, and what is deliberately ignored
// ---------------------------------------------------------------------------

describe("multi-hop chains", () => {
  it("narrows across three hops", () => {
    expect(
      validateDelegationChain([
        hop("user-1", "campaign-*", ["read", "aggregate", "export"]),
        { ...hop("orch-1", "campaign-x-*", ["read", "aggregate"]), principalType: PrincipalType.Service },
        hop("agent-1", "campaign-x-overlap", ["read"]),
      ]).allowed,
    ).toBe(true);
  });

  it("denies at the first offending hop and names it by index", () => {
    // The index is part of the contract: an operator with a four-hop chain needs to
    // know which delegation was the problem.
    const result = validateDelegationChain([
      hop("user-1", "campaign-*"),
      hop("orch-1", "campaign-x-*"),
      hop("agent-1", "campaign-x-overlap"),
      hop("agent-2", "campaign-y-export"),
    ]);

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe(
      "delegation hop 3 purpose 'campaign-y-export' is not within parent scope " +
        "'campaign-x-overlap'",
    );
  });

  it("reports the purpose failure before the scope failure on the same hop", () => {
    // Both would deny. The purpose answer is the more specific one, and it is the one
    // an operator can act on.
    const result = validateDelegationChain([
      hop("p", "campaign-x", ["read"]),
      hop("c", "fraud-detection", ["read", "write"]),
    ]);

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("purpose");
  });

  it("checks every adjacent pair, not only the ends", () => {
    // A chain whose first and last hop are consistent can still widen in the middle.
    // An implementation comparing each hop against the ROOT would pass this.
    const result = validateDelegationChain([
      hop("user-1", "campaign-x"),
      hop("orch-1", "campaign-y"),
      hop("agent-1", "campaign-x-overlap"),
    ]);

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("delegation hop 1");
  });
});

describe("what chain validation deliberately ignores", () => {
  it("principalType and delegatedAt play no part", () => {
    // Neither is a narrowing rule. An agent appearing before a user, or a parent
    // timestamped after its child, is odd but is not a widening of authority -- and
    // inventing a rule here would deny legitimate chains an integrator has no way to
    // reorder.
    expect(
      validateDelegationChain([
        {
          principalId: "agent-1",
          principalType: PrincipalType.Agent,
          declaredPurpose: "campaign-x",
          delegatedAt: "2026-09-01T12:00:00Z",
        },
        {
          principalId: "user-1",
          principalType: PrincipalType.User,
          declaredPurpose: "campaign-x-overlap",
          delegatedAt: "2020-01-01T00:00:00Z",
        },
      ]).allowed,
    ).toBe(true);
  });

  it("an unrecognized principalType does not change the decision", () => {
    // TypeScript's types are erased, so a wire value outside the enum arrives here. No
    // narrowing rule reads the principal kind, so it cannot change an outcome -- which
    // is asserted rather than assumed.
    expect(
      validateDelegationChain([
        { principalId: "p", principalType: "daemon", declaredPurpose: "campaign-x" },
        { principalId: "c", principalType: "daemon", declaredPurpose: "campaign-xyz-evil" },
      ]).allowed,
    ).toBe(false);
    expect(
      validateDelegationChain([
        { principalId: "p", principalType: "daemon", declaredPurpose: "campaign-x" },
        { principalId: "c", principalType: "daemon", declaredPurpose: "campaign-x-overlap" },
      ]).allowed,
    ).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// ReDoS bound -- JavaScript has no regex timeout, so the inputs are bounded
// ---------------------------------------------------------------------------

describe("a pathological purpose glob is refused rather than evaluated", () => {
  it("an over-long pattern is a non-match, not a stall", () => {
    // .NET applies a regex match timeout; JavaScript's RegExp has none, so this SDK
    // bounds the inputs instead -- the split spec §13 records for ReDoS mitigation.
    // Measured: `("*a" x 40) + "-x"` against 200 `a`s with the bound removed does not
    // return within 60s, while the bounded form returns in under a millisecond. The
    // threshold below is therefore four orders of magnitude clear of the defect's cost
    // rather than a number chosen by intuition (antipattern #6).
    const parentPurpose = "*a".repeat(40) + "-x";
    const childPurpose = "a".repeat(200);

    const started = Date.now();
    const result = validateDelegationChain([
      hop("p", parentPurpose),
      hop("c", childPurpose),
    ]);
    const elapsed = Date.now() - started;

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("is not within parent scope");
    expect(elapsed).toBeLessThan(1000);
  });

  it("the bound refuses an over-long pattern and an over-long value alike", () => {
    // Both arms of the length guard. A pattern within the bound whose VALUE is over it
    // must also fail closed, or the guard only covers half of what makes a match
    // expensive.
    const longPattern = "a".repeat(2000) + "*";
    const longValue = "a".repeat(2000);

    expect(
      validateDelegationChain([hop("p", longPattern), hop("c", "a")]).allowed,
    ).toBe(false);
    expect(
      validateDelegationChain([hop("p", "a*"), hop("c", longValue)]).allowed,
    ).toBe(false);
  });

  it("a realistic purpose is nowhere near the bound", () => {
    // The paired control. A ceiling that refused legitimate values would be a
    // deny-all wearing a ReDoS guard's clothes; the schema caps a purposeId at 128
    // characters, so the bound is generous by an order of magnitude.
    expect(
      validateDelegationChain([
        hop("p", "campaign-*"),
        hop("c", `campaign-${"x".repeat(100)}`),
      ]).allowed,
    ).toBe(true);
  });
});
