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
 * their `expected.permissions` blocks cover only `canQuery`/`readOnly`.
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

  // -------------------------------------------------------------------------
  // union-of-empty-lists-stays-empty (canonical spec §3, §14)
  // -------------------------------------------------------------------------
  //
  // A pin rather than a fix: TypeScript's `unionArrays` already returns `[]` here, as
  // does .NET's `UnionNullable`. Python's used a truthiness retention check
  // (`return result if result else None`) and returned `None`.
  //
  // On a deny-list the two are indistinguishable to ENFORCEMENT -- neither hides
  // anything -- so no test comparing access outcomes could see the divergence. They
  // are not indistinguishable to SIGNING: the canonical form omits an absent field and
  // emits `[]`, so a policy authoring an explicitly empty deny-list signed differently
  // in Python than in the other two, and a context signed by one would not verify in
  // the others. §14 calls that a security defect rather than a stylistic difference.
  //
  // The sweep below picks the fixture up automatically but only asserts
  // `sourceProfiles` and `permissions` are defined, so it could not catch a regression
  // here. Hence a dedicated case.

  describe("union-of-empty-lists-stays-empty", () => {
    const FIXTURE = "union-of-empty-lists-stays-empty.json";

    /**
     * Assert a list is **present** and empty.
     *
     * Both halves, deliberately. `expect(x ?? []).toEqual([])` and a bare "is empty"
     * check both pass against `undefined`, which is the same collapse relocated into
     * the test — and a test that cannot fail against the bug is the thing this fixture
     * exists to prevent.
     */
    function expectPresentAndEmpty(value: unknown, label: string): void {
      expect(value, `${label} collapsed to absent`).toBeDefined();
      expect(value, `${label} collapsed to null`).not.toBeNull();
      expect(Array.isArray(value), `${label} is not an array`).toBe(true);
      expect(value, `${label} is not empty`).toEqual([]);
    }

    it("keeps every explicitly-empty deny-list present and empty", () => {
      const fixture = loadFixture(FIXTURE);
      const result = merge(fixture.inputs);

      // Guard: the inputs must actually spell the empty lists, or the assertions below
      // are about a fixture that stopped exercising the case.
      for (const input of fixture.inputs) {
        expect(input.objectRules?.hiddenObjects, input.name).toEqual([]);
        expect(input.objectRules?.tagRules?.deniedTags, input.name).toEqual([]);
      }

      const rules = result.objectRules;
      expect(rules).toBeDefined();

      // One shared helper produced all five, so all five are checked together: fixing
      // the collapse for one and not the others is the shape §14 warns about.
      expectPresentAndEmpty(rules?.hiddenObjects, "hiddenObjects");
      expectPresentAndEmpty(rules?.fieldRules?.hiddenFields, "fieldRules.hiddenFields");
      expectPresentAndEmpty(rules?.fieldRules?.readOnlyFields, "fieldRules.readOnlyFields");
      expectPresentAndEmpty(rules?.tagRules?.deniedTags, "tagRules.deniedTags");
      expectPresentAndEmpty(
        rules?.endpointRules?.hiddenEndpoints,
        "endpointRules.hiddenEndpoints",
      );
    });

    it("matches the fixture's expected objectRules exactly", () => {
      // The whole-shape comparison as well as the field-by-field one: `toEqual`
      // distinguishes a missing key and an `undefined` value from `[]`, so it catches a
      // collapse in any field the fixture names, including one added later.
      const fixture = loadFixture(FIXTURE);
      const result = merge(fixture.inputs);

      expect(result.sourceProfiles).toEqual(fixture.expected.sourceProfiles);
      expect(result.permissions).toEqual(expectedPermissions(fixture));
      expect(result.objectRules).toEqual(fixture.expected.objectRules);
    });

    it("a UNION field no policy mentions stays absent", () => {
      // The paired direction, and the reason the correct fix is a "did any policy
      // contribute" flag rather than "always return an array". Emitting `[]` for a field
      // nobody mentioned would change the canonical bytes of every policy that never
      // mentioned it — a far larger blast radius than the bug.
      //
      // The fields exercised here are the ones the UNION helper produces, and neither
      // input names them. Asserting the intersection fields instead would leave this
      // test passing against an "always return an array" union, since the two helpers
      // are separate: the mutant has to be aimed at the code the test covers.
      const result = merge([
        {
          version: "1.0",
          name: "allow-only-a",
          priority: 10,
          permissions: { canQuery: true, readOnly: true },
          objectRules: {
            allowedObjects: ["customer_segments"],
            fieldRules: { allowedFields: ["segment_id"] },
            tagRules: { allowedTags: ["public"] },
            endpointRules: { allowedEndpoints: ["/segments/*"] },
          },
        },
        {
          version: "1.0",
          name: "allow-only-b",
          priority: 20,
          permissions: { canQuery: true, readOnly: true },
          objectRules: {
            allowedObjects: ["customer_segments"],
            fieldRules: { allowedFields: ["segment_id"] },
            tagRules: { allowedTags: ["public"] },
            endpointRules: { allowedEndpoints: ["/segments/*"] },
          },
        },
      ]);

      const rules = result.objectRules;
      expect(rules).toBeDefined();

      // Every union-produced field, unmentioned by both inputs.
      expect(rules?.hiddenObjects).toBeUndefined();
      expect(rules?.fieldRules?.hiddenFields).toBeUndefined();
      expect(rules?.fieldRules?.readOnlyFields).toBeUndefined();
      expect(rules?.tagRules?.deniedTags).toBeUndefined();
      expect(rules?.endpointRules?.hiddenEndpoints).toBeUndefined();

      // Absent rather than present-and-undefined: a key that is never written cannot be
      // sorted into the canonical bytes at all, whereas §1's null-dropping is a second
      // line of defence.
      expect("hiddenObjects" in (rules as object)).toBe(false);
      expect("deniedTags" in (rules?.tagRules as object)).toBe(false);
      expect("hiddenFields" in (rules?.fieldRules as object)).toBe(false);
      expect("readOnlyFields" in (rules?.fieldRules as object)).toBe(false);
      expect("hiddenEndpoints" in (rules?.endpointRules as object)).toBe(false);

      // The paired half: what the inputs DID name survived, so the absences above are
      // "nobody contributed" rather than "the merge dropped everything".
      expect(rules?.allowedObjects).toEqual(["customer_segments"]);
      expect(rules?.tagRules?.allowedTags).toEqual(["public"]);
    });

    it("a policy mentioning NO list at all yields no objectRules", () => {
      // The outermost arm of the same rule: when nothing contributes, the whole block
      // is absent rather than an empty object.
      const result = merge([
        {
          version: "1.0",
          name: "no-rules-a",
          priority: 10,
          permissions: { canQuery: true, readOnly: true },
        },
        {
          version: "1.0",
          name: "no-rules-b",
          priority: 20,
          permissions: { canQuery: true, readOnly: true },
        },
      ]);

      expect(result.objectRules).toBeUndefined();
      expect(result.limits).toBeUndefined();
    });

    it("one empty and one populated deny-list unions to the populated one", () => {
      // The middle case between the two above: `[]` contributes nothing to a union, so
      // it neither erases the other side nor is erased by it.
      const result = merge([
        {
          version: "1.0",
          name: "empty",
          priority: 10,
          permissions: { canQuery: true, readOnly: true },
          objectRules: { hiddenObjects: [] },
        },
        {
          version: "1.0",
          name: "populated",
          priority: 20,
          permissions: { canQuery: true, readOnly: true },
          objectRules: { hiddenObjects: ["billing_internal"] },
        },
      ]);

      expect(result.objectRules?.hiddenObjects).toEqual(["billing_internal"]);
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
