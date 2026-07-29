import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { merge } from "../src/merger.js";
import type { PolicyDefinition, MergeResult } from "../src/index.js";

const fixturesDir = path.resolve(__dirname, "../../../../../fixtures/merge-scenarios");

interface MergeFixture {
  description: string;
  inputs: PolicyDefinition[];
  expected: {
    sourceProfiles: string[];
    permissions: {
      canQuery: boolean;
      canInsert?: boolean;
      canUpdate?: boolean;
      canDelete?: boolean;
      canExport?: boolean;
      readOnly?: boolean;
    };
    objectRules?: Record<string, unknown>;
    limits?: Record<string, unknown>;
  };
}

function loadFixture(filename: string): MergeFixture {
  const content = fs.readFileSync(path.join(fixturesDir, filename), "utf-8");
  return JSON.parse(content) as MergeFixture;
}

/**
 * The fixture's expected permissions, with the three write flags filled in.
 *
 * The shared merge fixtures predate write permissions and name none of them, so
 * their `expected.permissions` blocks cover only `canQuery`/`canExport`/`readOnly`.
 * Rather than loosen these assertions to a subset match — which would stop noticing
 * a stray key entirely — the write flags are computed here straight from the
 * fixture's own inputs under connector spec §4.1: absent defaults to false, then
 * AND-fold. A merger that leaked a write permission the inputs did not grant, or
 * dropped one they did, still fails.
 */
function expectedPermissions(fixture: MergeFixture): Record<string, boolean> {
  const andFold = (read: (p: PolicyDefinition) => boolean | undefined): boolean =>
    fixture.inputs.every((p) => (read(p) ?? false) === true);

  return {
    canInsert: andFold((p) => p.permissions.canInsert),
    canUpdate: andFold((p) => p.permissions.canUpdate),
    canDelete: andFold((p) => p.permissions.canDelete),
    ...fixture.expected.permissions,
  };
}

function fixtureFiles(): string[] {
  return fs.readdirSync(fixturesDir).filter((f) => f.endsWith(".json"));
}

describe("Policy Merger", () => {
  describe("empty-produces-deny-all", () => {
    it("should return deny-all for empty policy set", () => {
      const fixture = loadFixture("empty-produces-deny-all.json");
      const result = merge(fixture.inputs);

      expect(result.sourceProfiles).toEqual(fixture.expected.sourceProfiles);
      expect(result.permissions.canQuery).toBe(false);
      expect(result.permissions.canExport).toBe(false);
      expect(result.permissions.readOnly).toBe(true);
    });
  });

  describe("single-policy-passthrough", () => {
    it("should pass through a single policy unchanged", () => {
      const fixture = loadFixture("single-policy-passthrough.json");
      const result = merge(fixture.inputs);

      expect(result.sourceProfiles).toEqual(fixture.expected.sourceProfiles);
      expect(result.permissions).toEqual(expectedPermissions(fixture));
      expect(result.objectRules).toEqual(fixture.expected.objectRules);
      expect(result.limits).toEqual(fixture.expected.limits);
    });
  });

  describe("can-query-false-wins", () => {
    it("should AND canQuery across policies (false wins)", () => {
      const fixture = loadFixture("can-query-false-wins.json");
      const result = merge(fixture.inputs);

      expect(result.sourceProfiles).toEqual(fixture.expected.sourceProfiles);
      expect(result.permissions.canQuery).toBe(false);
      expect(result.permissions.canExport).toBe(true);
      expect(result.permissions.readOnly).toBe(false);
    });
  });

  describe("intersection-allowed-fields", () => {
    it("should intersect allowed objects and fields", () => {
      const fixture = loadFixture("intersection-allowed-fields.json");
      const result = merge(fixture.inputs);

      expect(result.sourceProfiles).toEqual(fixture.expected.sourceProfiles);
      expect(result.permissions).toEqual(expectedPermissions(fixture));

      // Allowed objects: intersection
      const allowedObjects = result.objectRules?.allowedObjects ?? [];
      const expectedObjects =
        (fixture.expected.objectRules?.allowedObjects as string[]) ?? [];
      expect(allowedObjects.sort()).toEqual(expectedObjects.sort());

      // Allowed fields: intersection
      const allowedFields =
        result.objectRules?.fieldRules?.allowedFields ?? [];
      const expectedFields =
        ((fixture.expected.objectRules?.fieldRules as Record<string, unknown>)
          ?.allowedFields as string[]) ?? [];
      expect(allowedFields.sort()).toEqual(expectedFields.sort());

      // Limits
      expect(result.limits).toEqual(fixture.expected.limits);
    });
  });

  describe("hidden-wins-over-allowed", () => {
    it("should union hidden sets across policies", () => {
      const fixture = loadFixture("hidden-wins-over-allowed.json");
      const result = merge(fixture.inputs);

      expect(result.sourceProfiles).toEqual(fixture.expected.sourceProfiles);
      expect(result.permissions.canQuery).toBe(true);

      // Hidden objects: union
      const hiddenObjects = result.objectRules?.hiddenObjects ?? [];
      const expectedHidden =
        (fixture.expected.objectRules?.hiddenObjects as string[]) ?? [];
      expect(hiddenObjects.sort()).toEqual(expectedHidden.sort());

      // Hidden fields: union
      const hiddenFields =
        result.objectRules?.fieldRules?.hiddenFields ?? [];
      const expectedHiddenFields =
        ((fixture.expected.objectRules?.fieldRules as Record<string, unknown>)
          ?.hiddenFields as string[]) ?? [];
      expect(hiddenFields.sort()).toEqual(expectedHiddenFields.sort());

      // Allowed fields should be present from the policy that defines them
      const allowedFields =
        result.objectRules?.fieldRules?.allowedFields ?? [];
      const expectedAllowed =
        ((fixture.expected.objectRules?.fieldRules as Record<string, unknown>)
          ?.allowedFields as string[]) ?? [];
      expect(allowedFields.sort()).toEqual(expectedAllowed.sort());
    });
  });

  describe("masked-fields-most-restrictive", () => {
    it("should pick the most restrictive mask type per field", () => {
      const fixture = loadFixture("masked-fields-most-restrictive.json");
      const result = merge(fixture.inputs);

      expect(result.sourceProfiles).toEqual(fixture.expected.sourceProfiles);

      const maskedFields = result.objectRules?.fieldRules?.maskedFields ?? [];
      const expectedMasked =
        ((fixture.expected.objectRules?.fieldRules as Record<string, unknown>)
          ?.maskedFields as Array<Record<string, unknown>>) ?? [];

      expect(maskedFields.length).toBe(expectedMasked.length);

      for (const expected of expectedMasked) {
        const actual = maskedFields.find(
          (m) => m.field === expected["field"],
        );
        expect(actual).toBeDefined();
        expect(actual?.maskType).toBe(expected["maskType"]);
        if (expected["parameters"]) {
          expect(actual?.parameters).toEqual(expected["parameters"]);
        }
      }
    });
  });

  describe("row-filters-concatenate", () => {
    it("should concatenate row filters from all policies", () => {
      const fixture = loadFixture("row-filters-concatenate.json");
      const result = merge(fixture.inputs);

      expect(result.sourceProfiles).toEqual(fixture.expected.sourceProfiles);

      const rowFilters = result.objectRules?.rowFilters ?? [];
      const expectedFilters =
        (fixture.expected.objectRules?.rowFilters as Array<Record<string, unknown>>) ??
        [];

      expect(rowFilters.length).toBe(expectedFilters.length);
      expect(rowFilters).toEqual(expectedFilters);
    });
  });

  describe("min-max-limits", () => {
    it("should apply min for maxima and max for minima", () => {
      const fixture = loadFixture("min-max-limits.json");
      const result = merge(fixture.inputs);

      expect(result.sourceProfiles).toEqual(fixture.expected.sourceProfiles);
      expect(result.limits).toEqual(fixture.expected.limits);
    });
  });

  describe("all fixtures produce valid merge results", () => {
    for (const file of fixtureFiles()) {
      it(`should process ${file}`, () => {
        const fixture = loadFixture(file);
        const result = merge(fixture.inputs);
        expect(result.sourceProfiles).toBeDefined();
        expect(result.permissions).toBeDefined();
      });
    }
  });
});
