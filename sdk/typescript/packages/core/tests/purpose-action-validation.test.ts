/**
 * `validateAction` — a call's action category against the purpose it runs under
 * (canonical spec §15.2).
 *
 * The shared fixture `fixtures/enforcement/validate-action.json` is the cross-SDK
 * contract; .NET and Python consume the same file. The local tests around it exist
 * because a fixture pins the cases somebody thought to write down, and the
 * argument-state cross-product (`undefined` versus `[]` on each of two lists) is what
 * this control gets wrong when it gets anything wrong.
 *
 * Every denial here is paired with a case proving the same call is allowed when the
 * purpose permits it, per `docs/testing-antipatterns.md`: a denial test that passes
 * because nothing came back proves nothing.
 */

import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { validateAction } from "../src/enforcement.js";
import type { EffectivePolicy, PurposeProfile } from "../src/types.js";

const enforcementFixturesDir = path.resolve(
  __dirname,
  "../../../../../fixtures/enforcement",
);

interface ValidateActionCase {
  actionCategory: string;
  policy: Partial<EffectivePolicy> & { purposeProfile: PurposeProfile };
  expected: { allowed: boolean; reason?: string };
}

interface ValidateActionFixture {
  description: string;
  action: string;
  cases: ValidateActionCase[];
}

function loadFixture(): ValidateActionFixture {
  const content = fs.readFileSync(
    path.join(enforcementFixturesDir, "validate-action.json"),
    "utf-8",
  );
  return JSON.parse(content) as ValidateActionFixture;
}

const fixture = loadFixture();

/** A purpose profile with only the fields a case names — nothing defaulted in. */
function profile(overrides: Partial<PurposeProfile> = {}): PurposeProfile {
  return { purposeId: "campaign-x-overlap", ...overrides };
}

// ---------------------------------------------------------------------------
// The shared cross-SDK fixture
// ---------------------------------------------------------------------------

describe("validateAction matches the shared fixture", () => {
  it("declares itself as the validateAction corpus", () => {
    // A fixture repointed at another control would otherwise pass every case below
    // while testing something else entirely.
    expect(fixture.action).toBe("validateAction");
    expect(fixture.cases.length).toBeGreaterThan(0);
  });

  it("covers both outcomes, so no arm is vacuous", () => {
    // A corpus of allows would let a deny-everything implementation fail loudly, and
    // a corpus of denials would let an allow-everything implementation pass silently.
    const outcomes = fixture.cases.map((c) => c.expected.allowed);
    expect(outcomes).toContain(true);
    expect(outcomes).toContain(false);
  });

  for (const [index, testCase] of fixture.cases.entries()) {
    const label =
      `case ${index}: '${testCase.actionCategory}' -> ` +
      `${testCase.expected.allowed ? "allow" : "deny"}`;

    it(label, () => {
      // Guard: every case in this fixture exists to exercise a purpose profile, so a
      // case that lost one would silently assert nothing.
      expect(testCase.policy.purposeProfile).toBeDefined();

      const result = validateAction(
        testCase.actionCategory,
        testCase.policy.purposeProfile,
      );

      expect(result.allowed).toBe(testCase.expected.allowed);
      if (testCase.expected.reason === undefined) {
        // An allow carries no reason. Asserted rather than ignored: a reason on an
        // allow is how an implementation ends up logging a denial that did not happen.
        expect(result.reason).toBeUndefined();
      } else {
        expect(result.reason).toBe(testCase.expected.reason);
      }
    });
  }
});

// ---------------------------------------------------------------------------
// null vs [] on each list -- the distinction spec §3 forbids collapsing
// ---------------------------------------------------------------------------

describe("allowedActions: absent is unrestricted, empty denies everything", () => {
  it("absent permits a category no list mentions", () => {
    expect(validateAction("anything-at-all", profile()).allowed).toBe(true);
  });

  it("empty denies a category, with the allow-list reason", () => {
    const result = validateAction("aggregate_overlap", profile({ allowedActions: [] }));

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe(
      "action 'aggregate_overlap' not in allowed actions for purpose " +
        "'campaign-x-overlap'",
    );
  });

  it("the two are not the same object state", () => {
    // The paired assertion, not two separate ones: a truthiness check reads `[]` as
    // falsy and produces the SAME answer for both, which is only visible when the two
    // are compared against each other (antipattern #2).
    const absent = validateAction("aggregate_overlap", profile());
    const empty = validateAction("aggregate_overlap", profile({ allowedActions: [] }));

    expect(absent.allowed).toBe(true);
    expect(empty.allowed).toBe(false);
  });

  it("a listed category is allowed and an unlisted one is not", () => {
    const constrained = profile({ allowedActions: ["aggregate_overlap"] });

    expect(validateAction("aggregate_overlap", constrained).allowed).toBe(true);
    const denied = validateAction("train_model", constrained);
    expect(denied.allowed).toBe(false);
    expect(denied.reason).toBe(
      "action 'train_model' not in allowed actions for purpose 'campaign-x-overlap'",
    );
  });
});

describe("prohibitedActions: absent and empty both restrict nothing", () => {
  it("absent permits a category", () => {
    expect(validateAction("export_pii", profile()).allowed).toBe(true);
  });

  it("empty permits a category", () => {
    // Deliberately the OPPOSITE reading from an empty allow-list, and the asymmetry is
    // the point: an empty deny-list forbids nothing, an empty allow-list permits
    // nothing. Both are the restrictive reading of their own list.
    expect(
      validateAction("export_pii", profile({ prohibitedActions: [] })).allowed,
    ).toBe(true);
  });

  it("a listed category is denied while an unlisted one is allowed", () => {
    const constrained = profile({ prohibitedActions: ["export_pii"] });

    const denied = validateAction("export_pii", constrained);
    expect(denied.allowed).toBe(false);
    expect(denied.reason).toBe(
      "action 'export_pii' is prohibited under purpose 'campaign-x-overlap'",
    );
    expect(validateAction("aggregate_overlap", constrained).allowed).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Precedence
// ---------------------------------------------------------------------------

describe("prohibited is checked before allowed", () => {
  it("a category in both lists is denied, with the prohibition reason", () => {
    const both = profile({
      allowedActions: ["export_pii", "aggregate_overlap"],
      prohibitedActions: ["export_pii"],
    });

    const denied = validateAction("export_pii", both);
    expect(denied.allowed).toBe(false);
    expect(denied.reason).toBe(
      "action 'export_pii' is prohibited under purpose 'campaign-x-overlap'",
    );

    // The paired control: the same profile still permits what it allows, so the
    // denial above is the prohibition and not a blanket refusal.
    expect(validateAction("aggregate_overlap", both).allowed).toBe(true);
  });

  it("an empty allow-list still reports the allow-list reason, not a prohibition", () => {
    // Ordering matters in this direction too: prohibited is consulted first, and an
    // absent deny-list must not short-circuit into it.
    const result = validateAction("export_pii", profile({ allowedActions: [] }));
    expect(result.reason).toContain("not in allowed actions");
  });
});

// ---------------------------------------------------------------------------
// Casing -- deliberately the opposite of the purposeId comparison
// ---------------------------------------------------------------------------

describe("category comparison is case-insensitive", () => {
  for (const category of ["EXPORT_PII", "Export_Pii", "export_PII", "eXpOrT_pIi"]) {
    it(`a prohibition catches '${category}'`, () => {
      const result = validateAction(
        category,
        profile({ prohibitedActions: ["export_pii"] }),
      );

      expect(result.allowed).toBe(false);
      // The reason echoes the category AS SUPPLIED, not normalized, so a log shows
      // what was attempted rather than what the rule was written as.
      expect(result.reason).toBe(
        `action '${category}' is prohibited under purpose 'campaign-x-overlap'`,
      );
    });
  }

  for (const category of ["AGGREGATE_OVERLAP", "Aggregate_Overlap"]) {
    it(`an allow-list matches '${category}'`, () => {
      expect(
        validateAction(category, profile({ allowedActions: ["aggregate_overlap"] }))
          .allowed,
      ).toBe(true);
    });
  }

  it("a mis-cased rule catches a lower-case category too", () => {
    // Both sides are lowered, not just the input: a rule written `EXPORT_PII` must
    // still catch `export_pii`, or the asymmetry becomes a bypass in the other
    // direction.
    const result = validateAction("export_pii", profile({ prohibitedActions: ["EXPORT_PII"] }));
    expect(result.allowed).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Edge inputs and the reason contract
// ---------------------------------------------------------------------------

describe("edge inputs", () => {
  it("an empty category is denied against an allow-list", () => {
    const result = validateAction("", profile({ allowedActions: ["aggregate_overlap"] }));

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe(
      "action '' not in allowed actions for purpose 'campaign-x-overlap'",
    );
  });

  it("an empty category is allowed by an unconstrained purpose", () => {
    // Paired with the case above: the empty string is not special-cased into a denial,
    // it is simply not in a list that exists.
    expect(validateAction("", profile()).allowed).toBe(true);
  });

  it("the reason names the purpose, not only the action", () => {
    // Two purposes forbidding the same category must produce distinguishable reasons,
    // or an operator reading a log cannot tell which policy denied the call.
    const campaign = validateAction(
      "export_pii",
      { purposeId: "campaign-x-overlap", prohibitedActions: ["export_pii"] },
    );
    const fraud = validateAction(
      "export_pii",
      { purposeId: "fraud-detection", prohibitedActions: ["export_pii"] },
    );

    expect(campaign.reason).toContain("campaign-x-overlap");
    expect(fraud.reason).toContain("fraud-detection");
    expect(campaign.reason).not.toBe(fraud.reason);
  });

  it("the category is matched exactly, not as a glob or a substring", () => {
    // A category is an identifier. If `*` or a prefix matched, an administrator's
    // `export_pii` prohibition would silently cover `export_pii_summary` -- or worse,
    // a caller-influenced category could be shaped to dodge one.
    const constrained = profile({ prohibitedActions: ["export_pii"] });

    expect(validateAction("*", constrained).allowed).toBe(true);
    expect(validateAction("export", constrained).allowed).toBe(true);
    expect(validateAction("export_pii_summary", constrained).allowed).toBe(true);
  });
});
