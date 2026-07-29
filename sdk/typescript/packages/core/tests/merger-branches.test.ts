/**
 * Branch coverage for merger.ts, asserting the SPEC-mandated merge outcome of each
 * conditional.
 *
 * Merging is where "most restrictive wins" is actually decided, and two of its
 * branches are load-bearing in a way a truthiness check silently breaks:
 *
 *  - An empty intersection is `[]`, which means DENY EVERYTHING (spec §3). Treating
 *    it as falsy and discarding the rule turns the most restrictive possible
 *    outcome into no restriction at all.
 *  - An absent boolean permission takes its schema default BEFORE folding (spec §8).
 *    Excluding it from the fold inverts the result.
 */

import { describe, expect, it } from "vitest";
import { merge } from "../src/merger.js";
import type { PolicyDefinition } from "../src/types.js";

function definition(
  name: string,
  extra: Partial<PolicyDefinition> = {},
): PolicyDefinition {
  return {
    version: "1.0",
    name,
    permissions: { canQuery: true, canExport: false, readOnly: true },
    ...extra,
  };
}

const sorted = (values: string[] | undefined) => [...(values ?? [])].sort();

// ---------------------------------------------------------------------------
// Permission folding (spec §8)
// ---------------------------------------------------------------------------

describe("§8: permissions default before folding", () => {
  it("an empty policy list is deny-all", () => {
    expect(merge([])).toEqual({
      sourceProfiles: [],
      permissions: { canQuery: false, canExport: false, readOnly: true },
    });
  });

  it("canQuery ANDs: one false wins", () => {
    expect(
      merge([
        definition("a", { permissions: { canQuery: true } }),
        definition("b", { permissions: { canQuery: false } }),
      ]).permissions.canQuery,
    ).toBe(false);
    expect(
      merge([
        definition("a", { permissions: { canQuery: true } }),
        definition("b", { permissions: { canQuery: true } }),
      ]).permissions.canQuery,
    ).toBe(true);
  });

  it("canExport ANDs and defaults to false when absent", () => {
    // An absent canExport is the restrictive default, so a policy silent on export
    // cannot grant it.
    expect(
      merge([definition("a", { permissions: { canQuery: true } })]).permissions.canExport,
    ).toBe(false);
    expect(
      merge([
        definition("a", { permissions: { canQuery: true, canExport: true } }),
        definition("b", { permissions: { canQuery: true } }),
      ]).permissions.canExport,
    ).toBe(false);
    expect(
      merge([
        definition("a", { permissions: { canQuery: true, canExport: true } }),
        definition("b", { permissions: { canQuery: true, canExport: true } }),
      ]).permissions.canExport,
    ).toBe(true);
  });

  it("EXPLOIT: readOnly ORs and an ABSENT readOnly defaults to true", () => {
    // The §8 inversion: policy A silent on readOnly plus policy B with
    // readOnly: false must yield TRUE. Excluding the absent flag from the fold
    // would yield false and grant write access nobody authored.
    expect(
      merge([
        definition("silent", { permissions: { canQuery: true } }),
        definition("writable", { permissions: { canQuery: true, readOnly: false } }),
      ]).permissions.readOnly,
    ).toBe(true);
  });

  it("readOnly is false only when every policy says so explicitly", () => {
    expect(
      merge([
        definition("a", { permissions: { canQuery: true, readOnly: false } }),
        definition("b", { permissions: { canQuery: true, readOnly: false } }),
      ]).permissions.readOnly,
    ).toBe(false);
    expect(
      merge([
        definition("a", { permissions: { canQuery: true, readOnly: false } }),
        definition("b", { permissions: { canQuery: true, readOnly: true } }),
      ]).permissions.readOnly,
    ).toBe(true);
  });

  it("a single policy with every flag absent yields the schema defaults", () => {
    const result = merge([
      { version: "1.0", name: "bare", permissions: {} } as unknown as PolicyDefinition,
    ]);
    // canQuery is REQUIRED by the schema, so its absence is a malformed policy
    // rather than a default -- and folding `undefined` yields a falsy canQuery,
    // which is the fail-closed reading.
    expect(result.permissions.canQuery).toBeFalsy();
    expect(result.permissions.canExport).toBe(false);
    expect(result.permissions.readOnly).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Priority ordering
// ---------------------------------------------------------------------------

describe("priority determines sourceProfiles order", () => {
  it("lower priority sorts first", () => {
    expect(
      merge([
        definition("late", { priority: 50 }),
        definition("early", { priority: 10 }),
      ]).sourceProfiles,
    ).toEqual(["early", "late"]);
  });

  it("an absent priority defaults to 100 and sorts after an explicit lower one", () => {
    expect(
      merge([definition("no-priority"), definition("explicit", { priority: 10 })])
        .sourceProfiles,
    ).toEqual(["explicit", "no-priority"]);
  });

  it("an absent priority sorts before an explicitly higher one", () => {
    expect(
      merge([definition("explicit", { priority: 500 }), definition("no-priority")])
        .sourceProfiles,
    ).toEqual(["no-priority", "explicit"]);
  });

  it("merge does not reorder the caller's array", () => {
    const input = [definition("b", { priority: 50 }), definition("a", { priority: 10 })];
    merge(input);
    expect(input.map((d) => d.name)).toEqual(["b", "a"]);
  });
});

// ---------------------------------------------------------------------------
// Allowed-set intersection -- including the load-bearing empty result
// ---------------------------------------------------------------------------

describe("§3: allow-list intersection retains an empty result", () => {
  it("all-undefined stays undefined (unrestricted)", () => {
    expect(merge([definition("a"), definition("b")]).objectRules).toBeUndefined();
  });

  it("a single defined set is copied, not aliased", () => {
    const source = ["patients"];
    const result = merge([
      definition("a", { objectRules: { allowedObjects: source } }),
      definition("b", { objectRules: {} }),
    ]);
    expect(result.objectRules?.allowedObjects).toEqual(["patients"]);
    expect(result.objectRules?.allowedObjects).not.toBe(source);
  });

  it("an undefined set does not widen a defined one", () => {
    // "Unrestricted" from one policy must not lift the other's restriction.
    expect(
      merge([
        definition("a", { objectRules: { allowedObjects: ["patients"] } }),
        definition("b", { objectRules: { hiddenObjects: ["billing"] } }),
      ]).objectRules?.allowedObjects,
    ).toEqual(["patients"]);
  });

  it("EXPLOIT: two disjoint allow-lists intersect to [] and that [] is RETAINED", () => {
    // [] is deny-all (spec §3). Discarding it as falsy converts the most
    // restrictive possible outcome into no restriction at all.
    const result = merge([
      definition("a", { objectRules: { allowedObjects: ["patients"] } }),
      definition("b", { objectRules: { allowedObjects: ["billing"] } }),
    ]);

    expect(result.objectRules?.allowedObjects).toEqual([]);
    expect(result.objectRules?.allowedObjects).not.toBeUndefined();
  });

  it("an explicitly empty allow-list survives the merge", () => {
    expect(
      merge([definition("a", { objectRules: { allowedObjects: [] } })]).objectRules
        ?.allowedObjects,
    ).toEqual([]);
  });

  it("a three-way intersection keeps only the common members", () => {
    expect(
      sorted(
        merge([
          definition("a", { objectRules: { allowedObjects: ["x", "y", "z"] } }),
          definition("b", { objectRules: { allowedObjects: ["y", "z"] } }),
          definition("c", { objectRules: { allowedObjects: ["z", "w"] } }),
        ]).objectRules?.allowedObjects,
      ),
    ).toEqual(["z"]);
  });

  it("allowedFields, allowedTags, and allowedMethods all intersect to []", () => {
    const result = merge([
      definition("a", {
        objectRules: {
          fieldRules: { allowedFields: ["id"] },
          tagRules: { allowedTags: ["public"] },
          endpointRules: { allowedMethods: ["GET"] },
        },
      }),
      definition("b", {
        objectRules: {
          fieldRules: { allowedFields: ["name"] },
          tagRules: { allowedTags: ["internal"] },
          endpointRules: { allowedMethods: ["POST"] },
        },
      }),
    ]);

    expect(result.objectRules?.fieldRules?.allowedFields).toEqual([]);
    expect(result.objectRules?.tagRules?.allowedTags).toEqual([]);
    expect(result.objectRules?.endpointRules?.allowedMethods).toEqual([]);
  });

  it("allowedEndpoints intersects and retains []", () => {
    expect(
      merge([
        definition("a", { objectRules: { endpointRules: { allowedEndpoints: ["/a"] } } }),
        definition("b", { objectRules: { endpointRules: { allowedEndpoints: ["/b"] } } }),
      ]).objectRules?.endpointRules?.allowedEndpoints,
    ).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Union of hidden/denied sets
// ---------------------------------------------------------------------------

describe("hidden and denied sets union", () => {
  it("all-undefined stays undefined", () => {
    expect(
      merge([definition("a", { objectRules: {} })]).objectRules,
    ).toBeUndefined();
  });

  it("hiddenObjects, hiddenFields, hiddenEndpoints, deniedTags, readOnlyFields all union", () => {
    const result = merge([
      definition("a", {
        objectRules: {
          hiddenObjects: ["o1"],
          fieldRules: { hiddenFields: ["f1"], readOnlyFields: ["r1"] },
          tagRules: { deniedTags: ["t1"] },
          endpointRules: { hiddenEndpoints: ["/e1"] },
        },
      }),
      definition("b", {
        objectRules: {
          hiddenObjects: ["o2"],
          fieldRules: { hiddenFields: ["f2"], readOnlyFields: ["r2"] },
          tagRules: { deniedTags: ["t2"] },
          endpointRules: { hiddenEndpoints: ["/e2"] },
        },
      }),
    ]);

    expect(sorted(result.objectRules?.hiddenObjects)).toEqual(["o1", "o2"]);
    expect(sorted(result.objectRules?.fieldRules?.hiddenFields)).toEqual(["f1", "f2"]);
    expect(sorted(result.objectRules?.fieldRules?.readOnlyFields)).toEqual(["r1", "r2"]);
    expect(sorted(result.objectRules?.tagRules?.deniedTags)).toEqual(["t1", "t2"]);
    expect(sorted(result.objectRules?.endpointRules?.hiddenEndpoints)).toEqual([
      "/e1",
      "/e2",
    ]);
  });

  it("a union de-duplicates", () => {
    expect(
      merge([
        definition("a", { objectRules: { hiddenObjects: ["x", "y"] } }),
        definition("b", { objectRules: { hiddenObjects: ["y", "z"] } }),
      ]).objectRules?.hiddenObjects?.sort(),
    ).toEqual(["x", "y", "z"]);
  });

  it("an empty hidden set unions to [] rather than becoming undefined", () => {
    expect(
      merge([definition("a", { objectRules: { hiddenObjects: [] } })]).objectRules
        ?.hiddenObjects,
    ).toEqual([]);
  });

  it("an undefined set contributes nothing to the union", () => {
    expect(
      merge([
        definition("a", { objectRules: { hiddenObjects: ["x"] } }),
        definition("b", { objectRules: { allowedObjects: ["y"] } }),
      ]).objectRules?.hiddenObjects,
    ).toEqual(["x"]);
  });
});

// ---------------------------------------------------------------------------
// Masked-field merging
// ---------------------------------------------------------------------------

describe("masked fields: most restrictive per field wins", () => {
  it("all-undefined stays undefined", () => {
    expect(
      merge([definition("a", { objectRules: { fieldRules: {} } })]).objectRules
        ?.fieldRules,
    ).toBeUndefined();
  });

  it("an empty maskedFields array from every policy yields undefined", () => {
    // Nothing to mask means no masking rule, not an empty rule set.
    expect(
      merge([definition("a", { objectRules: { fieldRules: { maskedFields: [] } } })])
        .objectRules?.fieldRules?.maskedFields,
    ).toBeUndefined();
  });

  it("the first rule for a field is taken, then only beaten by a stricter one", () => {
    const stricterSecond = merge([
      definition("a", {
        objectRules: { fieldRules: { maskedFields: [{ field: "ssn", maskType: "partial" }] } },
      }),
      definition("b", {
        objectRules: { fieldRules: { maskedFields: [{ field: "ssn", maskType: "null" }] } },
      }),
    ]);
    const weakerSecond = merge([
      definition("a", {
        objectRules: { fieldRules: { maskedFields: [{ field: "ssn", maskType: "null" }] } },
      }),
      definition("b", {
        objectRules: { fieldRules: { maskedFields: [{ field: "ssn", maskType: "partial" }] } },
      }),
    ]);

    expect(stricterSecond.objectRules?.fieldRules?.maskedFields?.[0].maskType).toBe("null");
    // Order must not decide the outcome -- otherwise a policy's disclosure level
    // depends on its priority number rather than on restrictiveness.
    expect(weakerSecond.objectRules?.fieldRules?.maskedFields?.[0].maskType).toBe("null");
  });

  it("an equally restrictive duplicate does not replace the incumbent", () => {
    const result = merge([
      definition("a", {
        objectRules: {
          fieldRules: {
            maskedFields: [{ field: "ssn", maskType: "full", parameters: { maskChar: "#" } }],
          },
        },
      }),
      definition("b", {
        objectRules: {
          fieldRules: {
            maskedFields: [{ field: "ssn", maskType: "full", parameters: { maskChar: "@" } }],
          },
        },
      }),
    ]);

    expect(result.objectRules?.fieldRules?.maskedFields).toHaveLength(1);
    expect(result.objectRules?.fieldRules?.maskedFields?.[0].parameters?.maskChar).toBe("#");
  });

  it("distinct fields are kept separately", () => {
    const masked = merge([
      definition("a", {
        objectRules: {
          fieldRules: {
            maskedFields: [
              { field: "ssn", maskType: "null" },
              { field: "email", maskType: "hash" },
            ],
          },
        },
      }),
    ]).objectRules?.fieldRules?.maskedFields;

    expect(masked).toHaveLength(2);
    expect(masked?.find((m) => m.field === "email")?.maskType).toBe("hash");
  });

  it("the winning rule is copied, so mutating the result cannot alter the input", () => {
    const input = definition("a", {
      objectRules: {
        fieldRules: { maskedFields: [{ field: "ssn", maskType: "null" }] },
      },
    });
    const result = merge([input]);
    const rule = result.objectRules!.fieldRules!.maskedFields![0];
    rule.maskType = "partial";

    expect(input.objectRules?.fieldRules?.maskedFields?.[0].maskType).toBe("null");
  });

  it("an unknown mask type beats every known type", () => {
    expect(
      merge([
        definition("a", {
          objectRules: { fieldRules: { maskedFields: [{ field: "ssn", maskType: "null" }] } },
        }),
        definition("b", {
          objectRules: {
            fieldRules: { maskedFields: [{ field: "ssn", maskType: "tokenize-v2" }] },
          },
        }),
      ]).objectRules?.fieldRules?.maskedFields?.[0].maskType,
    ).toBe("tokenize-v2");
  });
});

// ---------------------------------------------------------------------------
// Row-filter concatenation
// ---------------------------------------------------------------------------

describe("row filters concatenate (AND semantics)", () => {
  it("all-undefined stays undefined", () => {
    expect(
      merge([definition("a", { objectRules: {} })]).objectRules?.rowFilters,
    ).toBeUndefined();
  });

  it("empty arrays from every policy yield undefined", () => {
    expect(
      merge([definition("a", { objectRules: { rowFilters: [] } })]).objectRules
        ?.rowFilters,
    ).toBeUndefined();
  });

  it("filters from several policies are all retained, duplicates included", () => {
    // Concatenation, not de-duplication: filters AND together, so keeping a
    // duplicate is harmless while dropping one would relax the policy.
    const filters = merge([
      definition("a", {
        objectRules: { rowFilters: [{ field: "region", operator: "equals", value: "us" }] },
      }),
      definition("b", {
        objectRules: {
          rowFilters: [
            { field: "region", operator: "equals", value: "us" },
            { field: "status", operator: "equals", value: "active" },
          ],
        },
      }),
    ]).objectRules?.rowFilters;

    expect(filters).toHaveLength(3);
  });

  it("one policy's empty array does not discard another's filters", () => {
    expect(
      merge([
        definition("a", { objectRules: { rowFilters: [] } }),
        definition("b", {
          objectRules: { rowFilters: [{ field: "x", operator: "equals", value: 1 }] },
        }),
      ]).objectRules?.rowFilters,
    ).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Limits -- min for maxima, max for minima
// ---------------------------------------------------------------------------

describe("limits: min for maxima, max for minima", () => {
  it("all-undefined stays undefined", () => {
    expect(merge([definition("a")]).limits).toBeUndefined();
  });

  it("an empty limits object from every policy yields undefined", () => {
    expect(merge([definition("a", { limits: {} })]).limits).toBeUndefined();
  });

  it("maxResults, maxQueryTimeSeconds, and maxObjectSizeBytes all take the minimum", () => {
    const limits = merge([
      definition("a", {
        limits: { maxResults: 100, maxQueryTimeSeconds: 60, maxObjectSizeBytes: 5000 },
      }),
      definition("b", {
        limits: { maxResults: 10, maxQueryTimeSeconds: 30, maxObjectSizeBytes: 1000 },
      }),
    ]).limits;

    expect(limits).toEqual({
      maxResults: 10,
      maxQueryTimeSeconds: 30,
      maxObjectSizeBytes: 1000,
    });
  });

  it("minSimilarityScore takes the maximum (the stricter floor)", () => {
    expect(
      merge([
        definition("a", { limits: { minSimilarityScore: 0.5 } }),
        definition("b", { limits: { minSimilarityScore: 0.9 } }),
      ]).limits?.minSimilarityScore,
    ).toBe(0.9);
  });

  it("an undefined limit does not relax a defined one", () => {
    expect(
      merge([
        definition("a", { limits: { maxResults: 10 } }),
        definition("b", { limits: { maxQueryTimeSeconds: 30 } }),
      ]).limits,
    ).toEqual({ maxResults: 10, maxQueryTimeSeconds: 30 });
  });

  it("maxResults 0 survives rather than being dropped as falsy", () => {
    // 0 is the most restrictive possible limit; a truthiness filter would discard
    // it and return every row.
    expect(
      merge([
        definition("a", { limits: { maxResults: 0 } }),
        definition("b", { limits: { maxResults: 10 } }),
      ]).limits?.maxResults,
    ).toBe(0);
  });

  it("minSimilarityScore 0 survives rather than being dropped as falsy", () => {
    expect(
      merge([definition("a", { limits: { minSimilarityScore: 0 } })]).limits
        ?.minSimilarityScore,
    ).toBe(0);
  });

  it("only the limits that were set appear on the result", () => {
    const limits = merge([definition("a", { limits: { maxResults: 5 } })]).limits;
    expect(Object.keys(limits ?? {})).toEqual(["maxResults"]);
  });
});

// ---------------------------------------------------------------------------
// objectRules presence
// ---------------------------------------------------------------------------

describe("objectRules and its sub-objects are omitted when empty", () => {
  it("policies with no objectRules produce none", () => {
    expect(merge([definition("a"), definition("b")]).objectRules).toBeUndefined();
  });

  it("an objectRules whose every sub-rule is empty produces none", () => {
    expect(
      merge([
        definition("a", {
          objectRules: { fieldRules: {}, tagRules: {}, endpointRules: {}, rowFilters: [] },
        }),
      ]).objectRules,
    ).toBeUndefined();
  });

  it("only the populated sub-objects appear", () => {
    const result = merge([
      definition("a", { objectRules: { fieldRules: { hiddenFields: ["ssn"] } } }),
    ]);

    expect(Object.keys(result.objectRules ?? {})).toEqual(["fieldRules"]);
    expect(result.objectRules?.tagRules).toBeUndefined();
    expect(result.objectRules?.endpointRules).toBeUndefined();
    expect(result.objectRules?.rowFilters).toBeUndefined();
  });

  it("each sub-object appears independently when populated", () => {
    const result = merge([
      definition("a", {
        objectRules: {
          allowedObjects: ["o"],
          fieldRules: { hiddenFields: ["f"] },
          rowFilters: [{ field: "x", operator: "equals", value: 1 }],
          tagRules: { deniedTags: ["t"] },
          endpointRules: { hiddenEndpoints: ["/e"] },
        },
      }),
    ]);

    expect(Object.keys(result.objectRules ?? {}).sort()).toEqual([
      "allowedObjects",
      "endpointRules",
      "fieldRules",
      "rowFilters",
      "tagRules",
    ]);
  });
});
