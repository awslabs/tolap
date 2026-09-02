/**
 * `getDisposition` — a judge's verdict onto an action (canonical spec §15.4).
 *
 * `fixtures/purpose-binding/judge-dispositions.json` is the cross-SDK contract.
 *
 * The load-bearing claim is that **every path that is not a confident verdict
 * escalates**, and that escalate is *not* an allow: a wrapper with no escalation
 * handler denies, or "escalate to human review" silently means "permit" in every
 * deployment that has not built the review step.
 *
 * The unusable-input arms are ordered first so a malformed result cannot reach a
 * threshold comparison and win one. In JavaScript that matters more than elsewhere:
 * `NaN < 0.6` and `NaN > 1` are both false, so a bare comparison chain falls through
 * to the confident arm.
 */

import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import {
  DEFAULT_CONFIDENCE_THRESHOLD,
  DEFAULT_ESCALATION_THRESHOLD,
  DEFAULT_HISTORY_WINDOW,
  DEFAULT_MAX_LATENCY_MS,
  JudgeDisposition,
  getDisposition,
  type JudgeResult,
} from "../src/judge.js";
import type { JudgeConfig } from "../src/types.js";

const purposeFixturesDir = path.resolve(
  __dirname,
  "../../../../../fixtures/purpose-binding",
);
const SCHEMA_DIR = path.resolve(__dirname, "../../../../../schema/v1.0");

interface DispositionCase {
  name: string;
  result: JudgeResult;
  config: JudgeConfig;
  expected: "allow" | "block" | "escalate";
}

interface DispositionFixture {
  description: string;
  action: string;
  cases: DispositionCase[];
}

function loadFixture(): DispositionFixture {
  const content = fs.readFileSync(
    path.join(purposeFixturesDir, "judge-dispositions.json"),
    "utf-8",
  );
  return JSON.parse(content) as DispositionFixture;
}

const fixture = loadFixture();

/** The wire string a fixture case names, as the enum member. */
function expectedDisposition(name: string): JudgeDisposition {
  switch (name) {
    case "allow":
      return JudgeDisposition.Allow;
    case "block":
      return JudgeDisposition.Block;
    case "escalate":
      return JudgeDisposition.Escalate;
    default:
      // Throws rather than defaulting: an unrecognized expectation silently mapped to
      // one of the three would make its case assert the wrong thing and pass.
      throw new Error(`unknown disposition '${name}' in judge-dispositions.json`);
  }
}

/** The standard threshold pair the fixture uses. */
const STANDARD: JudgeConfig = {
  confidenceThreshold: 0.85,
  escalationThreshold: 0.6,
};

function verdict(aligned: boolean, confidence: number): JudgeResult {
  return { aligned, confidence, reasoning: "test verdict" };
}

// ---------------------------------------------------------------------------
// The shared cross-SDK fixture
// ---------------------------------------------------------------------------

describe("getDisposition matches the shared fixture", () => {
  it("declares itself as the disposition corpus", () => {
    expect(fixture.action).toBe("getDisposition");
    expect(fixture.cases.length).toBeGreaterThan(0);
  });

  it("covers all three dispositions, so no arm is vacuous", () => {
    const outcomes = fixture.cases.map((c) => c.expected);
    expect(outcomes).toContain("allow");
    expect(outcomes).toContain("block");
    expect(outcomes).toContain("escalate");
  });

  for (const testCase of fixture.cases) {
    it(testCase.name, () => {
      expect(getDisposition(testCase.result, testCase.config)).toBe(
        expectedDisposition(testCase.expected),
      );
    });
  }

  it("the expectation mapper refuses an unknown disposition", () => {
    // The mapper is the only place a fixture typo could silently become a passing
    // assertion, so it is asserted from outside itself (antipattern #4).
    expect(() => expectedDisposition("permit")).toThrow(/unknown disposition 'permit'/);
  });
});

// ---------------------------------------------------------------------------
// The documented defaults
// ---------------------------------------------------------------------------

describe("the documented defaults", () => {
  it("match the published schema's `default` keywords", () => {
    // Read from disk rather than restated, for the same reason
    // `schema-conformance.test.ts` reads its enums from disk: a copy in a test is a
    // second thing free to drift. Defaults live in code because putting them on a
    // JudgeConfig would serialize values no author wrote and change the signed bytes.
    const schema = JSON.parse(
      fs.readFileSync(path.join(SCHEMA_DIR, "policy-definition.schema.json"), "utf-8"),
    ) as Record<string, unknown>;

    const judge = (
      (
        (schema["properties"] as Record<string, Record<string, unknown>>)[
          "purposeProfile"
        ]["properties"] as Record<string, Record<string, unknown>>
      )["judge"]["properties"] as Record<string, Record<string, unknown>>
    );

    // A missing path would otherwise read as "no default declared" and pass.
    for (const key of ["confidenceThreshold", "escalationThreshold", "maxLatencyMs", "historyWindow"]) {
      expect(judge[key], key).toBeDefined();
      expect(judge[key]["default"], key).toBeDefined();
    }

    expect(DEFAULT_CONFIDENCE_THRESHOLD).toBe(judge["confidenceThreshold"]["default"]);
    expect(DEFAULT_ESCALATION_THRESHOLD).toBe(judge["escalationThreshold"]["default"]);
    expect(DEFAULT_MAX_LATENCY_MS).toBe(judge["maxLatencyMs"]["default"]);
    expect(DEFAULT_HISTORY_WINDOW).toBe(judge["historyWindow"]["default"]);
  });

  it("the escalation floor sits below the confidence bar", () => {
    // If the defaults were themselves inverted, every unconfigured judge would escalate
    // everything and the feature would look broken rather than strict.
    expect(DEFAULT_ESCALATION_THRESHOLD).toBeLessThan(DEFAULT_CONFIDENCE_THRESHOLD);
  });

  it("an absent config uses them", () => {
    // The optional-argument case an integrator reaches by calling `getDisposition`
    // with one argument. Tested WITHOUT the parameter, not with `{}`.
    expect(getDisposition(verdict(true, 0.9))).toBe(JudgeDisposition.Allow);
    expect(getDisposition(verdict(true, 0.7))).toBe(JudgeDisposition.Escalate);
    expect(getDisposition(verdict(false, 0.9))).toBe(JudgeDisposition.Block);
  });

  it("an empty config uses them too, and agrees with an absent one", () => {
    // `{}` and absent must decide identically, or a caller that materializes an empty
    // config gets different answers from one that omits it.
    for (const confidence of [0.9, 0.7, 0.4]) {
      expect(getDisposition(verdict(true, confidence), {})).toBe(
        getDisposition(verdict(true, confidence)),
      );
    }
  });

  it("a config naming only one threshold defaults the other", () => {
    // `confidenceThreshold: 0.5` with no escalation floor uses the 0.6 default, which
    // is ABOVE it -- an inverted pair, so it escalates. That is the documented
    // behaviour and it is worth pinning: a partial config is the easy mistake.
    expect(getDisposition(verdict(true, 0.95), { confidenceThreshold: 0.5 })).toBe(
      JudgeDisposition.Escalate,
    );
    // Raising the bar above the default floor makes the same verdict an allow.
    expect(getDisposition(verdict(true, 0.95), { confidenceThreshold: 0.9 })).toBe(
      JudgeDisposition.Allow,
    );
    expect(getDisposition(verdict(true, 0.95), { escalationThreshold: 0.5 })).toBe(
      JudgeDisposition.Allow,
    );
  });
});

// ---------------------------------------------------------------------------
// Thresholds are inclusive at their bound
// ---------------------------------------------------------------------------

describe("the threshold bounds", () => {
  const boundary: Array<[number, JudgeDisposition]> = [
    [0.85, JudgeDisposition.Allow],
    [0.8499, JudgeDisposition.Escalate],
    [0.6, JudgeDisposition.Escalate],
    [0.5999, JudgeDisposition.Escalate],
  ];

  for (const [confidence, expected] of boundary) {
    it(`confidence ${confidence} -> ${expected}`, () => {
      expect(getDisposition(verdict(true, confidence), STANDARD)).toBe(expected);
    });
  }

  it("at the confidence bar the verdict is final in both directions", () => {
    expect(getDisposition(verdict(true, 0.85), STANDARD)).toBe(JudgeDisposition.Allow);
    expect(getDisposition(verdict(false, 0.85), STANDARD)).toBe(JudgeDisposition.Block);
  });

  it("exactly at the escalation floor is not below it -- and still escalates", () => {
    // Being above the floor is not being above the bar. Both comparisons are `<`, so
    // the floor is inclusive and the ambiguous band is `[floor, bar)`.
    expect(getDisposition(verdict(true, 0.6), STANDARD)).toBe(JudgeDisposition.Escalate);
    expect(getDisposition(verdict(false, 0.6), STANDARD)).toBe(JudgeDisposition.Escalate);
  });

  it("equal thresholds leave no ambiguous band", () => {
    const equal: JudgeConfig = { confidenceThreshold: 0.8, escalationThreshold: 0.8 };

    expect(getDisposition(verdict(true, 0.8), equal)).toBe(JudgeDisposition.Allow);
    expect(getDisposition(verdict(false, 0.8), equal)).toBe(JudgeDisposition.Block);
    expect(getDisposition(verdict(true, 0.79), equal)).toBe(JudgeDisposition.Escalate);
  });
});

// ---------------------------------------------------------------------------
// Alignment only decides the confident case
// ---------------------------------------------------------------------------

describe("alignment only decides the confident case", () => {
  it("an unsure verdict escalates whichever way it leans", () => {
    // This is what makes the judge subtractive rather than a second opinion: a
    // low-confidence "yes" buys nothing.
    expect(getDisposition(verdict(true, 0.3), STANDARD)).toBe(JudgeDisposition.Escalate);
    expect(getDisposition(verdict(false, 0.3), STANDARD)).toBe(JudgeDisposition.Escalate);
  });

  it("zero confidence escalates even when aligned", () => {
    // Zero is the value every unavailable-judge path reports, and it must escalate on
    // EVERY configuration rather than depending on how the thresholds happen to be set.
    expect(getDisposition(verdict(true, 0), STANDARD)).toBe(JudgeDisposition.Escalate);
    expect(getDisposition(verdict(true, 0), { confidenceThreshold: 0, escalationThreshold: 0 })).toBe(
      JudgeDisposition.Allow,
    );
  });

  it("full confidence is decisive in both directions", () => {
    expect(getDisposition(verdict(false, 1), STANDARD)).toBe(JudgeDisposition.Block);
    expect(getDisposition(verdict(true, 1), STANDARD)).toBe(JudgeDisposition.Allow);
  });
});

// ---------------------------------------------------------------------------
// Unusable input -- checked FIRST
// ---------------------------------------------------------------------------

describe("an unusable confidence escalates", () => {
  const unusable = [
    -0.1,
    1.5,
    Number.POSITIVE_INFINITY,
    Number.NEGATIVE_INFINITY,
    Number.NaN,
  ];

  for (const confidence of unusable) {
    it(`confidence ${String(confidence)} escalates when aligned`, () => {
      // A judge reporting 1.5 has malfunctioned. Comparing it against a threshold would
      // grant it MORE authority than a correct answer.
      expect(getDisposition(verdict(true, confidence), STANDARD)).toBe(
        JudgeDisposition.Escalate,
      );
    });

    it(`confidence ${String(confidence)} escalates when misaligned too`, () => {
      // Not a block: a malformed result is no verdict at all, and reporting it as a
      // confident refusal would put words in the judge's mouth.
      expect(getDisposition(verdict(false, confidence), STANDARD)).toBe(
        JudgeDisposition.Escalate,
      );
    });
  }

  it("the range check runs before the threshold comparisons", () => {
    // With thresholds of zero, 1.5 would satisfy every `<` comparison and reach the
    // confident arm. The only thing stopping it is the ordering.
    expect(
      getDisposition(verdict(true, 1.5), { confidenceThreshold: 0, escalationThreshold: 0 }),
    ).toBe(JudgeDisposition.Escalate);
  });

  it("the range bounds are inclusive", () => {
    // Paired with the block above: 0 and 1 are legal values, so the guard must not
    // refuse the endpoints it is meant to admit.
    expect(getDisposition(verdict(true, 1), STANDARD)).toBe(JudgeDisposition.Allow);
    expect(
      getDisposition(verdict(true, 0), { confidenceThreshold: 0, escalationThreshold: 0 }),
    ).toBe(JudgeDisposition.Allow);
  });
});

describe("inverted thresholds escalate rather than guessing", () => {
  const inverted: JudgeConfig = {
    confidenceThreshold: 0.6,
    escalationThreshold: 0.9,
  };

  it("escalates a verdict that would otherwise allow", () => {
    expect(getDisposition(verdict(true, 0.95), inverted)).toBe(JudgeDisposition.Escalate);
  });

  it("escalates a verdict that would otherwise block", () => {
    // Deliberately not a block. There is no reading of the configuration to act on, so
    // escalating is the only answer that does not pick a bound arbitrarily -- and a
    // block would look like a judgement the judge never made.
    expect(getDisposition(verdict(false, 0.95), inverted)).toBe(JudgeDisposition.Escalate);
  });

  it("escalates at every confidence, not only the high ones", () => {
    for (const confidence of [0, 0.5, 0.7, 0.95, 1]) {
      expect(getDisposition(verdict(true, confidence), inverted)).toBe(
        JudgeDisposition.Escalate,
      );
    }
  });

  it("the un-inverted pair is what makes the same verdicts decisive", () => {
    // Paired control: swapping the two values back turns the escalations above into a
    // real allow and a real block, so the inversion is what caused them.
    const corrected: JudgeConfig = {
      confidenceThreshold: 0.9,
      escalationThreshold: 0.6,
    };

    expect(getDisposition(verdict(true, 0.95), corrected)).toBe(JudgeDisposition.Allow);
    expect(getDisposition(verdict(false, 0.95), corrected)).toBe(JudgeDisposition.Block);
  });
});

// ---------------------------------------------------------------------------
// The enum's wire values
// ---------------------------------------------------------------------------

describe("JudgeDisposition", () => {
  it("has exactly three members with the fixture's wire spellings", () => {
    // The fixture names them as strings, so the enum's values are part of the
    // cross-SDK contract even though no schema declares them.
    expect(Object.values(JudgeDisposition).sort()).toEqual([
      "allow",
      "block",
      "escalate",
    ]);
  });

  it("escalate is a distinct value from allow", () => {
    // Stated as an assertion because the whole design rests on it: a wrapper treating
    // escalate as an allow is the failure mode the third member exists to prevent.
    expect(JudgeDisposition.Escalate).not.toBe(JudgeDisposition.Allow);
  });
});
