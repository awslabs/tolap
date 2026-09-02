/**
 * Purpose-profile merging (canonical spec §15.2).
 *
 * The four shared scenarios under `fixtures/merge-scenarios/purpose-profile-*.json`
 * are the cross-SDK contract. The local tests around them cover the fold rules
 * field by field, and in particular the two refusals — a purposeId disagreement and a
 * judge-model disagreement — which are the only places in the merger where a
 * combination of two *valid* policies has no most-restrictive answer and must
 * therefore be deny-all.
 *
 * The `undefined`-versus-`[]` distinction is asserted on every list, because the merge
 * is where it is easiest to lose: intersecting two disjoint allow-lists yields `[]`,
 * and an implementation that reads `[]` as falsy converts the most restrictive
 * possible outcome into no restriction at all (spec §3).
 */

import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { merge } from "../src/merger.js";
import { validateAction } from "../src/enforcement.js";
import type {
  JudgeConfig,
  PolicyDefinition,
  PurposeProfile,
} from "../src/types.js";

const mergeFixturesDir = path.resolve(
  __dirname,
  "../../../../../fixtures/merge-scenarios",
);

interface PurposeMergeFixture {
  description: string;
  inputs: PolicyDefinition[];
  expected: {
    sourceProfiles: string[];
    permissions: { canQuery: boolean; readOnly?: boolean };
    limits?: Record<string, unknown>;
    purposeProfile?: PurposeProfile;
  };
}

const SCENARIOS = [
  "purpose-profile-carried-through",
  "purpose-profile-actions-merge",
  "purpose-profile-conflicting-ids-deny-all",
  "purpose-profile-disjoint-allowed-denies-every-action",
] as const;

function loadScenario(name: string): PurposeMergeFixture {
  const content = fs.readFileSync(
    path.join(mergeFixturesDir, `${name}.json`),
    "utf-8",
  );
  return JSON.parse(content) as PurposeMergeFixture;
}

/** A minimal purpose-bound definition. */
function withProfile(
  name: string,
  profile?: PurposeProfile,
  priority = 10,
): PolicyDefinition {
  return {
    version: "1.0",
    name,
    priority,
    permissions: { canQuery: true, readOnly: true },
    ...(profile === undefined ? {} : { purposeProfile: profile }),
  };
}

/** A definition whose only purpose content is a judge block. */
function withJudge(name: string, judge: JudgeConfig, priority = 10): PolicyDefinition {
  return withProfile(name, { purposeId: "campaign-x-overlap", judge }, priority);
}

// ---------------------------------------------------------------------------
// The shared cross-SDK scenarios
// ---------------------------------------------------------------------------

describe("merge matches the shared purpose scenarios", () => {
  it("finds all four scenario files", () => {
    // A discovery bug that found nothing would make every case below vacuous.
    const present = fs
      .readdirSync(mergeFixturesDir)
      .filter((f) => f.startsWith("purpose-profile-") && f.endsWith(".json"));

    expect(present.sort()).toEqual(SCENARIOS.map((s) => `${s}.json`).sort());
  });

  for (const name of SCENARIOS) {
    it(name, () => {
      const fixture = loadScenario(name);
      const result = merge(fixture.inputs);

      expect(result.sourceProfiles).toEqual(fixture.expected.sourceProfiles);
      expect(result.permissions.canQuery).toBe(fixture.expected.permissions.canQuery);
      if (fixture.expected.permissions.readOnly !== undefined) {
        expect(result.permissions.readOnly).toBe(fixture.expected.permissions.readOnly);
      }
      if (fixture.expected.limits !== undefined) {
        expect(result.limits).toEqual(fixture.expected.limits);
      }

      if (fixture.expected.purposeProfile === undefined) {
        // Asserted, not skipped: the deny-all scenario's whole point is that the
        // profile is GONE, and a test that only checked the populated cases would pass
        // against a merger that carried a conflicting profile through.
        expect(result.purposeProfile).toBeUndefined();
        return;
      }

      const expectedProfile = fixture.expected.purposeProfile;
      const actual = result.purposeProfile;
      expect(actual).toBeDefined();
      expect(actual?.purposeId).toBe(expectedProfile.purposeId);
      if (expectedProfile.description !== undefined) {
        expect(actual?.description).toBe(expectedProfile.description);
      }

      // Set-equivalent rather than order-equivalent for the two action lists (a union
      // and an intersection have no natural order), but ABSENT is distinguished from
      // EMPTY on both.
      expectActionList(actual?.allowedActions, expectedProfile.allowedActions);
      expectActionList(actual?.prohibitedActions, expectedProfile.prohibitedActions);

      if (expectedProfile.judge === undefined) {
        expect(actual?.judge).toBeUndefined();
      } else {
        expect(actual?.judge).toEqual(expectedProfile.judge);
      }
    });
  }

  it("the scenarios cover both a successful merge and a refusal", () => {
    const outcomes = SCENARIOS.map((name) => loadScenario(name).expected.permissions.canQuery);
    expect(outcomes).toContain(true);
    expect(outcomes).toContain(false);
  });
});

/**
 * Compare an action list against a fixture's expectation.
 *
 * An expectation that omits the key means the merged list must be **absent**; one that
 * spells `[]` means it must be present and empty. Collapsing those two would hide the
 * exact defect spec §3 warns about.
 */
function expectActionList(
  actual: string[] | undefined,
  expected: string[] | undefined,
): void {
  if (expected === undefined) {
    expect(actual).toBeUndefined();
    return;
  }
  expect(actual).toBeDefined();
  expect([...(actual ?? [])].sort()).toEqual([...expected].sort());
}

// ---------------------------------------------------------------------------
// Carrying the profile through at all
// ---------------------------------------------------------------------------

describe("the profile is carried onto the merged result", () => {
  it("no contributing policy carries one -> the result carries none", () => {
    const result = merge([withProfile("a"), withProfile("b")]);

    expect(result.purposeProfile).toBeUndefined();
    expect(result.permissions.canQuery).toBe(true);
  });

  it("a purpose-agnostic policy merged with a scoped one keeps the scoped profile", () => {
    // Without this, `purposeProfile` would be readable on a definition and invisible
    // to enforcement, which only ever sees a merged policy.
    const result = merge([
      withProfile("scoped", {
        purposeId: "campaign-x-overlap",
        allowedActions: ["aggregate_overlap"],
      }),
      withProfile("agnostic", undefined, 50),
    ]);

    expect(result.purposeProfile?.purposeId).toBe("campaign-x-overlap");
    expect(result.purposeProfile?.allowedActions).toEqual(["aggregate_overlap"]);
  });

  it("a single policy's profile passes through unchanged", () => {
    const profile: PurposeProfile = {
      purposeId: "campaign-x-overlap",
      description: "Identify overlapping segments.",
      allowedActions: ["aggregate_overlap"],
      prohibitedActions: ["export_pii"],
      judge: { enabled: true, model: "claude-sonnet" },
    };

    expect(merge([withProfile("only", profile)]).purposeProfile).toEqual(profile);
  });

  it("the description comes from the highest-precedence policy that has one", () => {
    // Priority ascending is highest precedence first, and `merge` sorts before folding,
    // so the description a reader sees is the most specific one rather than whichever
    // definition the caller happened to list first.
    const result = merge([
      withProfile("low", { purposeId: "campaign-x-overlap", description: "the low one" }, 50),
      withProfile("high", { purposeId: "campaign-x-overlap", description: "the high one" }, 10),
    ]);

    expect(result.purposeProfile?.description).toBe("the high one");
  });

  it("a description is picked up from a lower-priority policy when the first has none", () => {
    const result = merge([
      withProfile("high", { purposeId: "campaign-x-overlap" }, 10),
      withProfile("low", { purposeId: "campaign-x-overlap", description: "the only one" }, 20),
    ]);

    expect(result.purposeProfile?.description).toBe("the only one");
  });

  it("no policy names a description -> the field stays absent", () => {
    // Absent, not `""`. An empty description would serialize and change the canonical
    // bytes of a policy whose author wrote none.
    const result = merge([
      withProfile("a", { purposeId: "campaign-x-overlap" }),
      withProfile("b", { purposeId: "campaign-x-overlap" }, 20),
    ]);

    expect(result.purposeProfile).toBeDefined();
    expect(result.purposeProfile?.description).toBeUndefined();
    expect("description" in (result.purposeProfile as object)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Refusal 1: two different purposes
// ---------------------------------------------------------------------------

describe("conflicting purposeIds are deny-all", () => {
  it("returns the deny-all merge result", () => {
    // Not "pick one" and not "drop the profile": picking one would silently apply rules
    // authored for a purpose the caller did not declare, and dropping the profile would
    // turn a purpose-scoped policy into an unscoped one.
    const result = merge([
      withProfile("overlap", { purposeId: "campaign-x-overlap" }),
      withProfile("fraud", { purposeId: "fraud-detection" }, 20),
    ]);

    expect(result.permissions.canQuery).toBe(false);
    expect(result.permissions.readOnly).toBe(true);
    expect(result.sourceProfiles).toEqual([]);
    expect(result.purposeProfile).toBeUndefined();
    expect(result.objectRules).toBeUndefined();
    expect(result.limits).toBeUndefined();
  });

  it("the refusal is byte-identical to the empty-policy-set deny-all", () => {
    // Two paths reach deny-all and they must be the same deny-all. A refusal that
    // returned a subtly different shape — say, keeping the source profiles — would let
    // a caller distinguish "no policies applied" from "policies conflicted" and act on
    // the difference.
    expect(
      merge([
        withProfile("overlap", { purposeId: "campaign-x-overlap" }),
        withProfile("fraud", { purposeId: "fraud-detection" }, 20),
      ]),
    ).toEqual(merge([]));
  });

  it("the comparison is case-sensitive", () => {
    // Two spellings of the same intent are two different purposes as far as this SDK is
    // concerned, matching the resolution-time comparison. Saying so loudly beats
    // quietly treating them as one.
    expect(
      merge([
        withProfile("a", { purposeId: "campaign-x-overlap" }),
        withProfile("b", { purposeId: "Campaign-X-Overlap" }, 20),
      ]).permissions.canQuery,
    ).toBe(false);
  });

  it("agreeing purposeIds merge normally", () => {
    // The paired control. Without it, a merger that refused every purpose-bound pair
    // would pass the block above.
    const result = merge([
      withProfile("a", { purposeId: "campaign-x-overlap" }),
      withProfile("b", { purposeId: "campaign-x-overlap" }, 20),
    ]);

    expect(result.permissions.canQuery).toBe(true);
    expect(result.purposeProfile?.purposeId).toBe("campaign-x-overlap");
  });

  it("three policies, one dissenting, is still deny-all", () => {
    expect(
      merge([
        withProfile("a", { purposeId: "campaign-x-overlap" }),
        withProfile("b", { purposeId: "campaign-x-overlap" }, 20),
        withProfile("c", { purposeId: "fraud-detection" }, 30),
      ]).permissions.canQuery,
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Action lists
// ---------------------------------------------------------------------------

describe("allowedActions intersect", () => {
  it("disjoint lists yield [] -- and [] denies every action", () => {
    // Asserted through `validateAction`, not only by shape: the reason `[]` must not
    // collapse to absent is that it is the deny-all, and the only way to prove the
    // merge preserved that meaning is to make a decision with it.
    const result = merge([
      withProfile("a", { purposeId: "p-x", allowedActions: ["aggregate_overlap"] }),
      withProfile("b", { purposeId: "p-x", allowedActions: ["inspect_account"] }, 20),
    ]);

    expect(result.purposeProfile?.allowedActions).toBeDefined();
    expect(result.purposeProfile?.allowedActions).toEqual([]);
    expect(
      validateAction("aggregate_overlap", result.purposeProfile as PurposeProfile).allowed,
    ).toBe(false);
    expect(
      validateAction("inspect_account", result.purposeProfile as PurposeProfile).allowed,
    ).toBe(false);
  });

  it("overlapping lists yield the intersection", () => {
    const result = merge([
      withProfile("a", {
        purposeId: "p-x",
        allowedActions: ["aggregate_overlap", "count_segments", "inspect_account"],
      }),
      withProfile("b", {
        purposeId: "p-x",
        allowedActions: ["aggregate_overlap", "count_segments", "train_model"],
      }, 20),
    ]);

    expect([...(result.purposeProfile?.allowedActions ?? [])].sort()).toEqual([
      "aggregate_overlap",
      "count_segments",
    ]);
  });

  it("an ABSENT list on one side does not widen the other", () => {
    // `undefined` means "this policy adds no restriction", so the other policy's list
    // survives intact. Reading it as "everything" and intersecting would produce the
    // same answer here but the wrong one when both sides are absent.
    const result = merge([
      withProfile("a", { purposeId: "p-x", allowedActions: ["aggregate_overlap"] }),
      withProfile("b", { purposeId: "p-x" }, 20),
    ]);

    expect(result.purposeProfile?.allowedActions).toEqual(["aggregate_overlap"]);
  });

  it("an EMPTY list on one side narrows the other to empty", () => {
    // The `[]`-versus-`undefined` pair, asserted against each other. A truthiness
    // filter would drop the empty side and produce `["aggregate_overlap"]`.
    const result = merge([
      withProfile("a", { purposeId: "p-x", allowedActions: ["aggregate_overlap"] }),
      withProfile("b", { purposeId: "p-x", allowedActions: [] }, 20),
    ]);

    expect(result.purposeProfile?.allowedActions).toEqual([]);
  });

  it("absent on BOTH sides stays absent", () => {
    const result = merge([
      withProfile("a", { purposeId: "p-x" }),
      withProfile("b", { purposeId: "p-x" }, 20),
    ]);

    expect(result.purposeProfile?.allowedActions).toBeUndefined();
  });
});

describe("prohibitedActions union", () => {
  it("every policy's denials survive", () => {
    const result = merge([
      withProfile("a", { purposeId: "p-x", prohibitedActions: ["export_pii"] }),
      withProfile("b", { purposeId: "p-x", prohibitedActions: ["train_model"] }, 20),
    ]);

    expect([...(result.purposeProfile?.prohibitedActions ?? [])].sort()).toEqual([
      "export_pii",
      "train_model",
    ]);
  });

  it("a category prohibited by one policy and allowed by another is denied", () => {
    // The cross-control assertion: `allowedActions` intersects and
    // `prohibitedActions` unions, and both fold most-restrictively, so the two rules
    // must not disagree about a category that appears in both.
    const result = merge([
      withProfile("a", {
        purposeId: "p-x",
        allowedActions: ["aggregate_overlap", "count_segments"],
      }),
      withProfile("b", { purposeId: "p-x", prohibitedActions: ["count_segments"] }, 20),
    ]);

    const merged = result.purposeProfile as PurposeProfile;
    expect(validateAction("count_segments", merged).allowed).toBe(false);
    expect(validateAction("aggregate_overlap", merged).allowed).toBe(true);
  });

  it("absent on both sides stays absent, and duplicates collapse", () => {
    expect(
      merge([
        withProfile("a", { purposeId: "p-x" }),
        withProfile("b", { purposeId: "p-x" }, 20),
      ]).purposeProfile?.prohibitedActions,
    ).toBeUndefined();

    expect(
      merge([
        withProfile("a", { purposeId: "p-x", prohibitedActions: ["export_pii"] }),
        withProfile("b", { purposeId: "p-x", prohibitedActions: ["export_pii"] }, 20),
      ]).purposeProfile?.prohibitedActions,
    ).toEqual(["export_pii"]);
  });

  it("an empty list on one side does not erase the other's denials", () => {
    // Union, so `[]` contributes nothing — the opposite direction from the allow-list,
    // and both are the restrictive reading of their own list.
    expect(
      merge([
        withProfile("a", { purposeId: "p-x", prohibitedActions: ["export_pii"] }),
        withProfile("b", { purposeId: "p-x", prohibitedActions: [] }, 20),
      ]).purposeProfile?.prohibitedActions,
    ).toEqual(["export_pii"]);
  });
});

// ---------------------------------------------------------------------------
// Judge configuration
// ---------------------------------------------------------------------------

describe("judge merging folds toward more escalation", () => {
  it("enabled ORs", () => {
    expect(
      merge([
        withJudge("a", { enabled: false }),
        withJudge("b", { enabled: true }, 20),
      ]).purposeProfile?.judge?.enabled,
    ).toBe(true);
  });

  it("an explicit false everywhere stays explicitly false", () => {
    expect(
      merge([
        withJudge("a", { enabled: false }),
        withJudge("b", { enabled: false }, 20),
      ]).purposeProfile?.judge?.enabled,
    ).toBe(false);
  });

  it("absent everywhere stays ABSENT, not false", () => {
    // The three-state distinction. Materializing `false` would serialize a value no
    // author wrote and change the signed bytes of every purpose-bound policy that
    // configured a window but not the switch.
    const judge = merge([
      withJudge("a", { historyWindow: 5 }),
      withJudge("b", { historyWindow: 7 }, 20),
    ]).purposeProfile?.judge;

    expect(judge?.enabled).toBeUndefined();
    expect("enabled" in (judge as object)).toBe(false);
    expect(judge?.historyWindow).toBe(7);
  });

  it("thresholds and the history window take the maximum; latency the minimum", () => {
    const judge = merge([
      withJudge("a", {
        confidenceThreshold: 0.8,
        escalationThreshold: 0.5,
        historyWindow: 5,
        maxLatencyMs: 2500,
      }),
      withJudge("b", {
        confidenceThreshold: 0.9,
        escalationThreshold: 0.7,
        historyWindow: 12,
        maxLatencyMs: 1500,
      }, 20),
    ]).purposeProfile?.judge;

    // A higher confidence bar sends MORE calls to review rather than letting them
    // through, and a higher escalation floor does the same; more history is the
    // direction that helps a judge notice drift; a shorter budget fails sooner, and a
    // timeout escalates.
    expect(judge?.confidenceThreshold).toBe(0.9);
    expect(judge?.escalationThreshold).toBe(0.7);
    expect(judge?.historyWindow).toBe(12);
    expect(judge?.maxLatencyMs).toBe(1500);
  });

  it("the max/min folds are not commutative accidents", () => {
    // Reversing the priority order must not change the fold, or "maximum" is really
    // "whichever came second".
    const forward = merge([
      withJudge("a", { confidenceThreshold: 0.8, maxLatencyMs: 2500 }, 10),
      withJudge("b", { confidenceThreshold: 0.9, maxLatencyMs: 1500 }, 20),
    ]).purposeProfile?.judge;
    const reverse = merge([
      withJudge("b", { confidenceThreshold: 0.9, maxLatencyMs: 1500 }, 10),
      withJudge("a", { confidenceThreshold: 0.8, maxLatencyMs: 2500 }, 20),
    ]).purposeProfile?.judge;

    expect(forward?.confidenceThreshold).toBe(reverse?.confidenceThreshold);
    expect(forward?.maxLatencyMs).toBe(reverse?.maxLatencyMs);
  });

  it("a field absent on one side takes the other's value", () => {
    const judge = merge([
      withJudge("a", { enabled: true, confidenceThreshold: 0.9 }),
      withJudge("b", { enabled: true, maxLatencyMs: 1500 }, 20),
    ]).purposeProfile?.judge;

    expect(judge?.confidenceThreshold).toBe(0.9);
    expect(judge?.maxLatencyMs).toBe(1500);
  });

  it("a field absent on BOTH sides stays absent", () => {
    // The documented defaults are applied when a field is READ, never stored here.
    const judge = merge([
      withJudge("a", { enabled: true }),
      withJudge("b", { enabled: true }, 20),
    ]).purposeProfile?.judge;

    expect(judge?.confidenceThreshold).toBeUndefined();
    expect(judge?.escalationThreshold).toBeUndefined();
    expect(judge?.historyWindow).toBeUndefined();
    expect(judge?.maxLatencyMs).toBeUndefined();
    expect(judge?.model).toBeUndefined();
    expect(judge).toEqual({ enabled: true });
  });

  it("no policy configures a judge -> the block stays absent", () => {
    const result = merge([
      withProfile("a", { purposeId: "p-x" }),
      withProfile("b", { purposeId: "p-x" }, 20),
    ]);

    expect(result.purposeProfile).toBeDefined();
    expect(result.purposeProfile?.judge).toBeUndefined();
  });

  it("one policy configures a judge and the other does not -> it survives", () => {
    const result = merge([
      withProfile("scoped", {
        purposeId: "p-x",
        judge: { enabled: true, model: "claude-sonnet" },
      }),
      withProfile("agnostic", { purposeId: "p-x" }, 20),
    ]);

    expect(result.purposeProfile?.judge).toEqual({
      enabled: true,
      model: "claude-sonnet",
    });
  });
});

// ---------------------------------------------------------------------------
// Refusal 2: two different judge models
// ---------------------------------------------------------------------------

describe("conflicting judge models are deny-all", () => {
  it("returns the deny-all merge result", () => {
    // A verdict is only meaningful against the model that produced it, so there is no
    // most-restrictive combination of two models. Same refusal shape as a purposeId
    // conflict.
    const result = merge([
      withJudge("a", { model: "claude-sonnet" }),
      withJudge("b", { model: "some-other-model" }, 20),
    ]);

    expect(result.permissions.canQuery).toBe(false);
    expect(result.purposeProfile).toBeUndefined();
    expect(result).toEqual(merge([]));
  });

  it("the comparison is case-sensitive", () => {
    expect(
      merge([
        withJudge("a", { model: "claude-sonnet" }),
        withJudge("b", { model: "Claude-Sonnet" }, 20),
      ]).permissions.canQuery,
    ).toBe(false);
  });

  it("one side naming no model keeps the named one", () => {
    // The field is optional. Requiring both sides to name it would make a
    // judge-enabled policy fail the moment a second policy applied.
    const result = merge([
      withJudge("a", { model: "claude-sonnet" }),
      withJudge("b", { enabled: true }, 20),
    ]);

    expect(result.permissions.canQuery).toBe(true);
    expect(result.purposeProfile?.judge?.model).toBe("claude-sonnet");
  });

  it("agreeing models merge normally", () => {
    // The paired control for the refusal above.
    const result = merge([
      withJudge("a", { model: "claude-sonnet", enabled: true }),
      withJudge("b", { model: "claude-sonnet", historyWindow: 5 }, 20),
    ]);

    expect(result.permissions.canQuery).toBe(true);
    expect(result.purposeProfile?.judge).toEqual({
      enabled: true,
      model: "claude-sonnet",
      historyWindow: 5,
    });
  });

  it("neither side naming a model leaves it absent", () => {
    const judge = merge([
      withJudge("a", { enabled: true }),
      withJudge("b", { enabled: true }, 20),
    ]).purposeProfile?.judge;

    expect(judge?.model).toBeUndefined();
    expect("model" in (judge as object)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// The rest of the merge is unaffected
// ---------------------------------------------------------------------------

describe("purpose merging composes with the pre-existing folds", () => {
  it("limits, permissions and object rules still fold as before", () => {
    const result = merge([
      {
        ...withProfile("scoped", {
          purposeId: "campaign-x-overlap",
          allowedActions: ["aggregate_overlap"],
        }),
        limits: { maxResults: 10_000 },
        objectRules: { allowedObjects: ["customer_segments", "campaign_assignments"] },
      },
      {
        ...withProfile("agnostic", undefined, 50),
        limits: { maxResults: 2000 },
        objectRules: { allowedObjects: ["customer_segments"] },
      },
    ]);

    expect(result.limits?.maxResults).toBe(2000);
    expect(result.objectRules?.allowedObjects).toEqual(["customer_segments"]);
    expect(result.purposeProfile?.purposeId).toBe("campaign-x-overlap");
  });

  it("a purpose conflict discards the object rules and limits too", () => {
    // Deny-all means deny-all. Retaining rules from policies whose combination was
    // refused would leave a caller enforcing half a decision.
    const result = merge([
      {
        ...withProfile("a", { purposeId: "campaign-x-overlap" }),
        limits: { maxResults: 10 },
        objectRules: { allowedObjects: ["x"] },
      },
      {
        ...withProfile("b", { purposeId: "fraud-detection" }, 20),
        limits: { maxResults: 20 },
      },
    ]);

    expect(result.limits).toBeUndefined();
    expect(result.objectRules).toBeUndefined();
  });

  it("an empty policy set is still the deny-all it always was", () => {
    expect(merge([])).toEqual({
      sourceProfiles: [],
      permissions: { canQuery: false, readOnly: true },
    });
  });
});
