/**
 * Per-identity MCP tool gating: `objectRules.toolRules` (canonical-enforcement-spec.md §16).
 *
 * The shared fixtures are the cross-SDK contract: `validate-tool-access.json` (the 12
 * original cases plus matrix rows A1-A25) and the six `tool-rules-*.json` merge
 * scenarios (D1-D6). Python and .NET run the same files.
 *
 * The hand-written blocks cover what a fixture cannot express in this SDK: TypeScript
 * has no deserializer, so a malformed `toolRules` reaches `validateToolAccess` as-is and
 * the check itself must fail closed (E1, E2, E4), and a non-string tool name can reach it
 * through an untyped caller.
 */

import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { merge } from "../src/merger.js";
import { resolve } from "../src/resolution.js";
import { validateToolAccess } from "../src/index.js";
import type {
  EffectivePolicy,
  PolicyDefinition,
  ToolRules,
} from "../src/index.js";

const fixturesRoot = path.resolve(__dirname, "../../../../../fixtures");
const mergeDir = path.join(fixturesRoot, "merge-scenarios");

function load(rel: string): Record<string, unknown> {
  return JSON.parse(
    fs.readFileSync(path.join(fixturesRoot, rel), "utf-8"),
  ) as Record<string, unknown>;
}

/** Copied from `enforcement.test.ts` so the required envelope fields match. */
function toEffectivePolicy(partial: Record<string, unknown>): EffectivePolicy {
  return {
    version: "1.0",
    userId: "test-user",
    tenantId: "test-tenant",
    sourceConnectionId: "test-source",
    resolvedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    sourceProfiles: [],
    integrity: { algorithm: "none", signature: "" },
    ...partial,
  } as EffectivePolicy;
}

/** A policy whose `objectRules.toolRules` is exactly `toolRules`, untyped on purpose. */
function withToolRules(toolRules: unknown, canQuery = true): EffectivePolicy {
  return toEffectivePolicy({
    permissions: { canQuery },
    objectRules: { toolRules },
  });
}

// ---------------------------------------------------------------------------
// A1-A25 and the original 12 cases: the shared fixture
// ---------------------------------------------------------------------------

interface ToolAccessCase {
  name?: string;
  toolName: string;
  policy: Record<string, unknown>;
  expected: { allowed: boolean; reason?: string };
}

const accessCases = load("enforcement/validate-tool-access.json")[
  "cases"
] as ToolAccessCase[];

describe("validateToolAccess (fixtures/enforcement/validate-tool-access.json)", () => {
  it("exercises both outcomes", () => {
    expect(new Set(accessCases.map((c) => c.expected.allowed))).toEqual(
      new Set([true, false]),
    );
  });

  it("carries every matrix row A1-A25, once each", () => {
    // A row that silently disappears from the fixture would otherwise stop being tested
    // with no failure anywhere.
    const names = accessCases.map((c) => c.name).filter((n) => n !== undefined);
    const expected = Array.from({ length: 25 }, (_, i) => `A${i + 1}`);
    expect([...names].sort()).toEqual([...expected].sort());
    expect(accessCases.length).toBe(12 + 25);
  });

  it("A6 and A24 really carry U+212A KELVIN SIGN (the JSON escape survived)", () => {
    const a6 = accessCases.find((c) => c.name === "A6")!;
    const a24 = accessCases.find((c) => c.name === "A24")!;
    expect(a6.toolName.codePointAt(0)).toBe(0x212a);
    const hidden = (
      (a24.policy["objectRules"] as Record<string, unknown>)["toolRules"] as ToolRules
    ).hiddenTools!;
    expect(hidden[0].codePointAt(0)).toBe(0x212a);
    // The mutation A24 exists to catch: Unicode lowercase maps U+212A to "k".
    expect(hidden[0].toLowerCase()).toBe("kill_switch");
  });

  it("A25 really carries U+017F LATIN SMALL LETTER LONG S (the JSON escape survived)", () => {
    const a25 = accessCases.find((c) => c.name === "A25")!;
    const hidden = (
      (a25.policy["objectRules"] as Record<string, unknown>)["toolRules"] as ToolRules
    ).hiddenTools!;
    expect(hidden[0].codePointAt(0)).toBe(0x017f);
    // The mutation A25 exists to catch: toLowerCase leaves U+017F alone (A24 covers that),
    // but an upper-case fold maps it to "S".
    expect(hidden[0].toUpperCase()).toBe(a25.toolName.toUpperCase());
  });

  accessCases.forEach((tc, i) => {
    const label = tc.name ?? `case ${i}`;
    it(`${label} ${JSON.stringify(tc.toolName).slice(0, 40)}: ${
      tc.expected.allowed ? "allowed" : `denied "${tc.expected.reason}"`
    }`, () => {
      const result = validateToolAccess(tc.toolName, toEffectivePolicy(tc.policy));
      // The whole result, so a stray reason on an allow (or a missing one on a deny)
      // fails too.
      expect(result).toStrictEqual(
        tc.expected.allowed
          ? { allowed: true }
          : { allowed: false, reason: tc.expected.reason },
      );
    });
  });
});

// ---------------------------------------------------------------------------
// Hand-written adversarial checks beyond the fixture
// ---------------------------------------------------------------------------

describe("validateToolAccess: matching", () => {
  it("never echoes the tool name in a reason", () => {
    const name = "export_segment_csv";
    for (const rules of [
      { hiddenTools: [name] },
      { allowedTools: ["query_patients"] },
    ]) {
      const result = validateToolAccess(name, withToolRules(rules));
      expect(result.allowed).toBe(false);
      expect(result.reason).not.toContain(name);
    }
    const bad = validateToolAccess(`${name} `, withToolRules({}));
    expect(bad.reason).toBe("invalid tool name");
    expect(bad.reason).not.toContain(name);
  });

  it("does not consult canQuery (the wrapper checks it after)", () => {
    const denied = validateToolAccess(
      "export_segment_csv",
      withToolRules({ allowedTools: ["query_patients"] }, false),
    );
    expect(denied).toStrictEqual({ allowed: false, reason: "tool not in allowed set" });
    expect(
      validateToolAccess("query_patients", withToolRules({ allowedTools: ["query_patients"] }, false)),
    ).toStrictEqual({ allowed: true });
  });

  it("folds only ASCII letters: U+212A in the name is refused by the grammar, not folded", () => {
    // A Unicode fold would map both directions to "kill_switch"; the ASCII fold maps
    // neither, and the grammar has already refused the non-ASCII name.
    expect(
      validateToolAccess("\u212Aill_switch", withToolRules({ hiddenTools: ["kill_switch"] })),
    ).toStrictEqual({ allowed: false, reason: "invalid tool name" });
    expect(
      validateToolAccess("kill_switch", withToolRules({ hiddenTools: ["\u212Aill_switch"] })),
    ).toStrictEqual({ allowed: true });
  });

  it("folds every ASCII letter A-Z, including the boundaries", () => {
    const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const lower = "abcdefghijklmnopqrstuvwxyz";
    expect(validateToolAccess(lower, withToolRules({ hiddenTools: [upper] }))).toStrictEqual({
      allowed: false,
      reason: "tool is hidden",
    });
    expect(validateToolAccess(upper, withToolRules({ hiddenTools: [lower] }))).toStrictEqual({
      allowed: false,
      reason: "tool is hidden",
    });
  });

  it("does not fold characters outside A-Z (a too-wide range such as [A-_] or [A-z])", () => {
    // "_" is 95; +32 is DEL (127). A fold range that ran past "Z" would turn the valid
    // name "a_b" into "a\x7fb" and match this (invalid, but reachable) hidden entry.
    expect(
      validateToolAccess("a_b", withToolRules({ hiddenTools: ["a\u007fb"] })),
    ).toStrictEqual({ allowed: true });
  });

  it("does not treat digits, '.', '-' or '_' as interchangeable", () => {
    for (const [tool, hidden] of [
      ["tool.a", "tool-a"],
      ["tool_a", "tool-a"],
      ["tool1", "tool2"],
    ]) {
      expect(validateToolAccess(tool, withToolRules({ hiddenTools: [hidden] }))).toStrictEqual({
        allowed: true,
      });
    }
  });

  it("hidden is not a substring or suffix match", () => {
    expect(
      validateToolAccess("export_segment_csv", withToolRules({ hiddenTools: ["segment_csv"] })),
    ).toStrictEqual({ allowed: true });
    expect(
      validateToolAccess("export", withToolRules({ hiddenTools: ["export_segment_csv"] })),
    ).toStrictEqual({ allowed: true });
  });

  it("allowed is not a superstring match", () => {
    expect(
      validateToolAccess("query", withToolRules({ allowedTools: ["query_patients"] })),
    ).toStrictEqual({ allowed: false, reason: "tool not in allowed set" });
  });

  it("names that shadow Object.prototype members are plain names", () => {
    // A lookup built on an object map rather than an array would find these on the
    // prototype and allow them.
    for (const name of ["constructor", "toString", "__proto__", "hasOwnProperty", "valueOf"]) {
      expect(validateToolAccess(name, withToolRules({ allowedTools: [] }))).toStrictEqual({
        allowed: false,
        reason: "tool not in allowed set",
      });
      expect(validateToolAccess(name, withToolRules({ allowedTools: ["query_patients"] }))).toStrictEqual({
        allowed: false,
        reason: "tool not in allowed set",
      });
    }
  });

  it("a hidden entry in the allowed list is still hidden, whichever list comes first", () => {
    const rules = { hiddenTools: ["b"], allowedTools: ["a", "b"] };
    expect(validateToolAccess("b", withToolRules(rules))).toStrictEqual({
      allowed: false,
      reason: "tool is hidden",
    });
    expect(validateToolAccess("a", withToolRules(rules))).toStrictEqual({ allowed: true });
  });

  it("the grammar applies to T = {} but not to an absent T", () => {
    expect(validateToolAccess("a b", withToolRules({}))).toStrictEqual({
      allowed: false,
      reason: "invalid tool name",
    });
    expect(validateToolAccess("a b", toEffectivePolicy({ permissions: { canQuery: true } }))).toStrictEqual({
      allowed: true,
    });
    expect(
      validateToolAccess("a b", toEffectivePolicy({ permissions: { canQuery: true }, objectRules: {} })),
    ).toStrictEqual({ allowed: true });
  });

  it("the grammar rejects every other ASCII punctuation and whitespace character", () => {
    const permitted = new Set("_.-");
    for (let code = 0; code < 128; code++) {
      const ch = String.fromCharCode(code);
      if (/[A-Za-z0-9]/.test(ch) || permitted.has(ch)) {
        expect(validateToolAccess(`t${ch}t`, withToolRules({})), `code ${code}`).toStrictEqual({
          allowed: true,
        });
      } else {
        expect(validateToolAccess(`t${ch}t`, withToolRules({})), `code ${code}`).toStrictEqual({
          allowed: false,
          reason: "invalid tool name",
        });
      }
    }
  });

  it("the grammar is anchored at both ends, including before a trailing CR/LF", () => {
    for (const name of ["ok\n", "ok\r\n", "\nok", "ok ", "ok\t", "ok "]) {
      expect(validateToolAccess(name, withToolRules({})), JSON.stringify(name)).toStrictEqual({
        allowed: false,
        reason: "invalid tool name",
      });
    }
  });

  it("the grammar is checked before hidden and allowed", () => {
    // Both lists would deny the name; the grammar reason wins.
    expect(
      validateToolAccess(" x", withToolRules({ hiddenTools: [" x"], allowedTools: [] })),
    ).toStrictEqual({ allowed: false, reason: "invalid tool name" });
    // ...and an invalid name is not rescued by being listed as allowed.
    expect(
      validateToolAccess("a/b", withToolRules({ allowedTools: ["a/b"] })),
    ).toStrictEqual({ allowed: false, reason: "invalid tool name" });
  });

  it("does not mutate the policy's lists", () => {
    const rules = { allowedTools: ["Query", "b"], hiddenTools: ["A", "b"] };
    const snapshot = JSON.parse(JSON.stringify(rules));
    validateToolAccess("a", withToolRules(rules));
    validateToolAccess("Query", withToolRules(rules));
    expect(rules).toStrictEqual(snapshot);
  });
});

describe("validateToolAccess: non-string tool names from an untyped caller", () => {
  // `RegExp.test` coerces its argument: `undefined` becomes "undefined" and
  // `["query_patients"]` becomes "query_patients", both grammar-valid. Only an explicit
  // type check keeps them out.
  const inputs: Array<[string, unknown]> = [
    ["undefined", undefined],
    ["null", null],
    ["a number", 123],
    ["a one-element array", ["query_patients"]],
    ["an object with toString", { toString: () => "query_patients" }],
    ["a String object", new String("query_patients")],
  ];
  for (const [label, value] of inputs) {
    it(`${label} is an invalid tool name, never a match`, () => {
      const rules = { allowedTools: ["query_patients", "undefined", "null", "123"] };
      expect(validateToolAccess(value as string, withToolRules(rules))).toStrictEqual({
        allowed: false,
        reason: "invalid tool name",
      });
      expect(
        validateToolAccess(value as string, withToolRules({ hiddenTools: ["query_patients"] })),
      ).toStrictEqual({ allowed: false, reason: "invalid tool name" });
    });
  }
});

// ---------------------------------------------------------------------------
// E1, E2, E4, E8: malformed toolRules must fail closed (TS has no deserializer)
// ---------------------------------------------------------------------------

describe("validateToolAccess: malformed toolRules", () => {
  const INVALID = { allowed: false, reason: "invalid tool rules" };

  it("E1: allowedTools as a bare string is refused, never searched by substring", () => {
    // `"query_patients".includes("query")` is true: a string treated as a list would
    // allow every substring of it.
    for (const tool of ["query_patients", "query", "q", "patients"]) {
      expect(validateToolAccess(tool, withToolRules({ allowedTools: "query_patients" }))).toStrictEqual(
        INVALID,
      );
    }
  });

  it("E1: hiddenTools as a bare string is refused, not treated as unrestricted", () => {
    for (const tool of ["export_segment_csv", "other_tool"]) {
      expect(validateToolAccess(tool, withToolRules({ hiddenTools: "export_segment_csv" }))).toStrictEqual(
        INVALID,
      );
    }
  });

  it("E2: a non-string entry in either list is refused", () => {
    const bad: unknown[] = [[1], [null], [undefined], [{}], [["query_patients"]], ["ok", 2], [true]];
    for (const entries of bad) {
      expect(
        validateToolAccess("query_patients", withToolRules({ allowedTools: entries })),
        `allowedTools ${JSON.stringify(entries)}`,
      ).toStrictEqual(INVALID);
      expect(
        validateToolAccess("query_patients", withToolRules({ hiddenTools: entries })),
        `hiddenTools ${JSON.stringify(entries)}`,
      ).toStrictEqual(INVALID);
    }
  });

  it("E2: a sparse array (a hole where a name should be) is refused", () => {
    // `Array.prototype.every` skips holes, so an `every`-based check would pass this.
    // eslint-disable-next-line no-sparse-arrays
    const sparse = [, "query_patients"] as unknown as string[];
    expect(validateToolAccess("query_patients", withToolRules({ hiddenTools: sparse }))).toStrictEqual(
      INVALID,
    );
    expect(validateToolAccess("query_patients", withToolRules({ allowedTools: sparse }))).toStrictEqual(
      INVALID,
    );
  });

  it("E2: other non-array list values are refused", () => {
    for (const value of [0, 1, true, false, {}, { 0: "query_patients", length: 1 }, new Set(["query_patients"])]) {
      expect(validateToolAccess("query_patients", withToolRules({ allowedTools: value }))).toStrictEqual(
        INVALID,
      );
      expect(validateToolAccess("query_patients", withToolRules({ hiddenTools: value }))).toStrictEqual(
        INVALID,
      );
    }
  });

  it("E4: toolRules as an array, or any non-object, is refused", () => {
    for (const value of [[], ["query_patients"], "query_patients", "", 0, 1, true, false]) {
      expect(validateToolAccess("query_patients", withToolRules(value)), JSON.stringify(value)).toStrictEqual(
        INVALID,
      );
    }
  });

  it("the shape check runs before the grammar", () => {
    expect(validateToolAccess(" bad name", withToolRules({ allowedTools: "x" }))).toStrictEqual(INVALID);
  });

  it("one malformed list poisons the whole block, even when the other would deny", () => {
    expect(
      validateToolAccess("query_patients", withToolRules({ allowedTools: [], hiddenTools: "x" })),
    ).toStrictEqual(INVALID);
  });

  it("E8: toolRules null is absent (no grammar, no gate)", () => {
    expect(validateToolAccess("export_segment_csv ", withToolRules(null))).toStrictEqual({
      allowed: true,
    });
    expect(validateToolAccess("anything", withToolRules(null))).toStrictEqual({ allowed: true });
  });

  it("null lists are absent (A19/A20) and a null list beside a real one keeps the real one", () => {
    expect(
      validateToolAccess("query_patients", withToolRules({ allowedTools: null, hiddenTools: ["query_patients"] })),
    ).toStrictEqual({ allowed: false, reason: "tool is hidden" });
    expect(
      validateToolAccess("export_segment_csv", withToolRules({ allowedTools: ["query_patients"], hiddenTools: null })),
    ).toStrictEqual({ allowed: false, reason: "tool not in allowed set" });
  });

  it("unknown keys are ignored: a typo such as allowedTool is unrestricted (E3 is the schema's and server's)", () => {
    // Pinned deliberately. The SDK does not reject unknown toolRules keys; the schema's
    // additionalProperties:false and the server's 400 own E3. If this ever changes, it
    // must change in all three SDKs together.
    expect(
      validateToolAccess("query_patients", withToolRules({ allowedTool: ["x"] })),
    ).toStrictEqual({ allowed: true });
    expect(
      validateToolAccess("export_segment_csv", withToolRules({ hiddenTool: ["export_segment_csv"] })),
    ).toStrictEqual({ allowed: true });
    // ...but the block is still present, so the grammar still applies.
    expect(
      validateToolAccess("a b", withToolRules({ allowedTool: ["x"] })),
    ).toStrictEqual({ allowed: false, reason: "invalid tool name" });
  });

  it("objectRules null is absent", () => {
    expect(
      validateToolAccess("a b", toEffectivePolicy({ permissions: { canQuery: true }, objectRules: null })),
    ).toStrictEqual({ allowed: true });
  });
});

// ---------------------------------------------------------------------------
// D1-D6: the merge fixtures
// ---------------------------------------------------------------------------

interface MergeFixture {
  inputs: PolicyDefinition[];
  expected: {
    sourceProfiles: string[];
    objectRules?: Record<string, unknown>;
  };
}

function loadMerge(file: string): MergeFixture {
  return load(`merge-scenarios/${file}`) as unknown as MergeFixture;
}

/** Every tool-rules merge fixture, by matrix row. The name guard below keeps it complete. */
const TOOL_RULES_MERGE_FIXTURES: Record<string, string> = {
  D1: "tool-rules-intersect-and-union.json",
  D2: "tool-rules-order-independent.json",
  D3: "tool-rules-absent-everywhere.json",
  D4: "tool-rules-absent-and-empty.json",
  D5: "tool-rules-case-variants.json",
  D6: "tool-rules-three-way.json",
};

describe("merge: toolRules fixtures (D1-D6)", () => {
  it("names every tool-rules-*.json merge fixture (a new one cannot go unrun)", () => {
    const onDisk = fs
      .readdirSync(mergeDir)
      .filter((f) => f.startsWith("tool-rules-") && f.endsWith(".json"))
      .sort();
    expect(onDisk).toEqual(Object.values(TOOL_RULES_MERGE_FIXTURES).sort());
  });

  for (const [row, file] of Object.entries(TOOL_RULES_MERGE_FIXTURES)) {
    it(`${row} ${file}: objectRules and sourceProfiles match exactly`, () => {
      const fixture = loadMerge(file);
      const result = merge(fixture.inputs);
      expect(result.sourceProfiles).toEqual(fixture.expected.sourceProfiles);
      // toStrictEqual: a present-but-undefined key is a difference, unlike toEqual.
      expect(result.objectRules).toStrictEqual(fixture.expected.objectRules);
    });
  }

  it("D1: intersects allowedTools to [] (never absent) and unions hiddenTools", () => {
    const result = merge(loadMerge(TOOL_RULES_MERGE_FIXTURES.D1).inputs);
    const rules = result.objectRules?.toolRules;
    expect(rules, "toolRules collapsed").toBeDefined();
    expect(rules!.allowedTools, "allowedTools collapsed to absent").toBeDefined();
    expect(rules!.allowedTools).toEqual([]);
    expect(rules!.hiddenTools).toEqual(["admin_reset"]);
    expect(result.objectRules?.allowedObjects).toEqual(["patients"]);
  });

  it("D2: reversed priorities give the same toolRules as D1", () => {
    const d1 = merge(loadMerge(TOOL_RULES_MERGE_FIXTURES.D1).inputs);
    const d2 = merge(loadMerge(TOOL_RULES_MERGE_FIXTURES.D2).inputs);
    // Pinned first, so two equally-missing results cannot pass as "the same".
    expect(d1.objectRules?.toolRules).toStrictEqual({ allowedTools: [], hiddenTools: ["admin_reset"] });
    expect(d2.objectRules?.toolRules).toStrictEqual(d1.objectRules?.toolRules);
  });

  it("D3: no input has toolRules, so there is no toolRules key at all", () => {
    const result = merge(loadMerge(TOOL_RULES_MERGE_FIXTURES.D3).inputs);
    expect(result.objectRules).toBeDefined();
    expect("toolRules" in result.objectRules!).toBe(false);
    expect(JSON.stringify(result)).not.toContain("toolRules");
  });

  it("D4: absent intersected with [] is [] (deny-all survives)", () => {
    const rules = merge(loadMerge(TOOL_RULES_MERGE_FIXTURES.D4).inputs).objectRules?.toolRules;
    expect(rules).toStrictEqual({ allowedTools: [], hiddenTools: ["x"] });
  });

  it("D5: merge compares exactly; the union keeps both spellings in first-seen order", () => {
    const rules = merge(loadMerge(TOOL_RULES_MERGE_FIXTURES.D5).inputs).objectRules?.toolRules;
    expect(rules).toStrictEqual({ allowedTools: [], hiddenTools: ["A", "a"] });
  });

  it("D6: the intersection runs over all three inputs, and no hiddenTools key appears", () => {
    const rules = merge(loadMerge(TOOL_RULES_MERGE_FIXTURES.D6).inputs).objectRules?.toolRules;
    expect(rules).toStrictEqual({ allowedTools: ["c"] });
    expect("hiddenTools" in rules!).toBe(false);
  });
});

describe("merge: toolRules edge cases", () => {
  function def(name: string, priority: number, objectRules?: unknown): PolicyDefinition {
    return {
      version: "1.0",
      name,
      priority,
      permissions: { canQuery: true, readOnly: true },
      ...(objectRules === undefined ? {} : { objectRules }),
    } as PolicyDefinition;
  }

  it("a single policy's toolRules pass through, including hiddenTools []", () => {
    const result = merge([def("a", 10, { toolRules: { allowedTools: ["q"], hiddenTools: [] } })]);
    expect(result.objectRules).toStrictEqual({ toolRules: { allowedTools: ["q"], hiddenTools: [] } });
  });

  it("hiddenTools [] alone is retained (the union keeps an explicit empty list)", () => {
    const result = merge([
      def("a", 10, { toolRules: { hiddenTools: [] } }),
      def("b", 20, { toolRules: { hiddenTools: [] } }),
    ]);
    expect(result.objectRules).toStrictEqual({ toolRules: { hiddenTools: [] } });
  });

  it("allowedTools [] alone is retained (deny every tool is not unrestricted)", () => {
    const result = merge([def("a", 10, { toolRules: { allowedTools: [] } })]);
    expect(result.objectRules).toStrictEqual({ toolRules: { allowedTools: [] } });
  });

  it("a tools-only policy keeps its objectRules block", () => {
    const result = merge([def("a", 10, { toolRules: { hiddenTools: ["x"] } }), def("b", 20)]);
    expect(result.objectRules).toStrictEqual({ toolRules: { hiddenTools: ["x"] } });
  });

  it("toolRules {} is dropped at merge, like an empty endpointRules", () => {
    const only = merge([def("a", 10, { toolRules: {} })]);
    expect(only.objectRules).toBeUndefined();
    const beside = merge([def("a", 10, { toolRules: {}, allowedObjects: ["p"] })]);
    expect(beside.objectRules).toStrictEqual({ allowedObjects: ["p"] });
  });

  it("E8: toolRules null is absent at merge (no throw, no key)", () => {
    const result = merge([
      def("a", 10, { toolRules: null, allowedObjects: ["p"] }),
      def("b", 20, { toolRules: { allowedTools: ["q"] } }),
    ]);
    expect(result.objectRules).toStrictEqual({ allowedObjects: ["p"], toolRules: { allowedTools: ["q"] } });
    const allNull = merge([def("a", 10, { toolRules: null, allowedObjects: ["p"] })]);
    expect(allNull.objectRules).toStrictEqual({ allowedObjects: ["p"] });
  });

  it("null lists are absent at merge (A19/A20 shape), not an empty restriction", () => {
    const result = merge([
      def("a", 10, { toolRules: { allowedTools: null, hiddenTools: null } }),
      def("b", 20, { toolRules: { allowedTools: ["q"] } }),
    ]);
    expect(result.objectRules).toStrictEqual({ toolRules: { allowedTools: ["q"] } });
    const onlyNull = merge([def("a", 10, { toolRules: { allowedTools: null } })]);
    expect(onlyNull.objectRules).toBeUndefined();
  });

  it("the merged lists are copies: mutating them does not touch the inputs", () => {
    const allowed = ["q", "r"];
    const hidden = ["h"];
    const result = merge([def("a", 10, { toolRules: { allowedTools: allowed, hiddenTools: hidden } })]);
    result.objectRules!.toolRules!.allowedTools!.push("injected");
    result.objectRules!.toolRules!.hiddenTools!.push("injected");
    expect(allowed).toEqual(["q", "r"]);
    expect(hidden).toEqual(["h"]);
  });

  it("duplicates collapse in the merged lists (A23 tolerated upstream)", () => {
    const result = merge([
      def("a", 10, { toolRules: { allowedTools: ["q", "q"], hiddenTools: ["h", "h"] } }),
      def("b", 20, { toolRules: { allowedTools: ["q"], hiddenTools: ["h"] } }),
    ]);
    expect(result.objectRules?.toolRules).toStrictEqual({ allowedTools: ["q"], hiddenTools: ["h"] });
  });

  // Fix round 1: TS has no deserializer, and resolve() runs store documents through merge
  // before signing. A malformed toolRules must make merge throw (like Python's
  // ValueError at deserialization), never merge into a policy that restricts less.
  describe("malformed toolRules fail closed at merge (E1, E2, E4)", () => {
    const malformed: Array<[string, unknown]> = [
      ["E1 allowedTools as a string", { allowedTools: "query_patients" }],
      ["E1 hiddenTools as a string", { hiddenTools: "export_segment_csv" }],
      ["E2 allowedTools [1]", { allowedTools: [1] }],
      ["E2 hiddenTools [null]", { hiddenTools: [null] }],
      ["E2 allowedTools with a hole", { allowedTools: [, "q"] }],
      ["E2 allowedTools as an object", { allowedTools: { 0: "q", length: 1 } }],
      ["E4 toolRules []", []],
      ["E4 toolRules [\"q\"]", ["q"]],
      ["E4 toolRules a string", "x"],
      ["E4 toolRules a number", 1],
      ["E4 toolRules true", true],
    ];

    for (const [label, toolRules] of malformed) {
      it(`${label}: merge throws "invalid tool rules"`, () => {
        expect(() => merge([def("bad", 10, { toolRules })])).toThrow(/invalid tool rules/);
      });

      it(`${label}: throws even beside a well-formed policy, in either order`, () => {
        const good = def("good", 20, { toolRules: { allowedTools: ["q"] } });
        const bad = def("bad", 10, { toolRules });
        expect(() => merge([bad, good])).toThrow(/invalid tool rules/);
        expect(() => merge([good, { ...bad, priority: 30 }])).toThrow(/invalid tool rules/);
      });
    }

    it("null toolRules and null lists still merge as absent (E8 is not caught by the guard)", () => {
      expect(() => merge([def("a", 10, { toolRules: null })])).not.toThrow();
      expect(() =>
        merge([def("a", 10, { toolRules: { allowedTools: null, hiddenTools: null } })]),
      ).not.toThrow();
    });

    it("unknown keys do not throw at merge (E3 belongs to the schema and server)", () => {
      expect(merge([def("a", 10, { toolRules: { allowedTool: ["x"] } })]).objectRules).toBeUndefined();
    });

    it("through resolve(): a store document with a string allowedTools rejects", async () => {
      const assignment = {
        version: "1.0",
        policyName: "bad-tools",
        assignee: { type: "user", identifier: "user-001" },
        scope: { tenantId: "tenant-1" },
        active: true,
        audit: { grantedBy: "admin", grantedAt: "2026-01-15T10:00:00Z", reason: "test" },
      };
      const definitions = {
        "bad-tools": def("bad-tools", 10, { toolRules: { allowedTools: "query_patients" } }),
      };
      await expect(
        resolve("user-001", "tenant-1", "src-1", [assignment as never], definitions),
      ).rejects.toThrow(/invalid tool rules/);

      // Paired control: the same document well-formed resolves and gates.
      const ok = await resolve("user-001", "tenant-1", "src-1", [assignment as never], {
        "bad-tools": def("bad-tools", 10, { toolRules: { allowedTools: ["query_patients"] } }),
      });
      expect(validateToolAccess("q", ok)).toStrictEqual({ allowed: false, reason: "tool not in allowed set" });
      expect(validateToolAccess("query_patients", ok)).toStrictEqual({ allowed: true });
    });

    it("through resolve(): toolRules [] rejects rather than resolving unrestricted", async () => {
      const assignment = {
        version: "1.0",
        policyName: "bad-tools",
        assignee: { type: "user", identifier: "user-001" },
        scope: { tenantId: "tenant-1" },
        active: true,
        audit: { grantedBy: "admin", grantedAt: "2026-01-15T10:00:00Z", reason: "test" },
      };
      await expect(
        resolve("user-001", "tenant-1", "src-1", [assignment as never], {
          "bad-tools": def("bad-tools", 10, { toolRules: [] }),
        }),
      ).rejects.toThrow(/invalid tool rules/);
    });
  });

  it("a merged policy is decided by validateToolAccess as the fixture says", () => {
    // Merge and enforcement agree end to end: D4's merged [] denies every tool, and its
    // hidden "x" hides "X".
    const merged = merge(loadMerge(TOOL_RULES_MERGE_FIXTURES.D4).inputs);
    const policy = toEffectivePolicy({ ...merged });
    expect(validateToolAccess("anything", policy)).toStrictEqual({
      allowed: false,
      reason: "tool not in allowed set",
    });
    expect(validateToolAccess("X", policy)).toStrictEqual({ allowed: false, reason: "tool is hidden" });
  });
});
