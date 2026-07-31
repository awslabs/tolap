/** TypeScript KB tag-rule scenarios. */

import { describe, expect, it } from "vitest";

import { SecureContextToolWrapper } from "../../src/context-wrapper.js";
import { loadScenarios, policyFromDict, signPolicy } from "./_scenarios.js";

const SIGNING_KEY = "integration-test-signing-key";
const DOC = loadScenarios("knowledge-base-tag-rules.json");
const CORPUS = (DOC as any).corpus as Array<Record<string, unknown>>;
const SCENARIOS = DOC.scenarios;

describe("knowledge-base tag rules", () => {
  for (const scenario of SCENARIOS) {
    it(scenario.name, async () => {
      const policy = policyFromDict(scenario.policy);
      const ctx = signPolicy(policy, SIGNING_KEY);
      const wrapper = new SecureContextToolWrapper({ signingKey: SIGNING_KEY });

      const docs = await wrapper.executeWithEnforcement(
        ctx,
        { toolName: "kb-search" },
        () => JSON.parse(JSON.stringify(CORPUS)) as Array<Record<string, unknown>>,
      );

      if ("idsEqual" in scenario.expected) {
        const actual = docs.map((d) => d.id as string).sort();
        const want = [...scenario.expected.idsEqual].sort();
        expect(actual).toEqual(want);
      }
      if ("idMustNotInclude" in scenario.expected) {
        const actual = new Set(docs.map((d) => d.id));
        for (const forbidden of scenario.expected.idMustNotInclude) {
          expect(actual.has(forbidden)).toBe(false);
        }
      }
    });
  }
});
