/**
 * Regression tests for `sourcePatterns` filtering during policy resolution
 * (docs/canonical-enforcement-spec.md §9).
 *
 * A definition's `sourcePatterns` declares which data sources the policy applies
 * to. Resolution MUST use it as a filter: absent or `[]` applies to every source,
 * a non-empty list applies only when one pattern matches the resolved
 * `sourceConnectionId`, and a definition whose patterns do not match is excluded
 * before merging.
 *
 * TypeScript ignored the field entirely, so a policy scoped to `db:production:*`
 * also governed an unrelated API or knowledge-base source and the effective policy
 * for a source was assembled from rules never intended to apply to it. .NET already
 * filtered (PolicyResolutionEngine.MatchesSourcePatterns), so the same policy set
 * resolved to different effective access per language.
 *
 * Note the glob dialect: `*` matches within a segment and does NOT cross the `:`
 * separator, so `db:*` does not match `db:production:patients`. That is a different
 * dialect from the `/`-oriented `globMatch` used for object and endpoint patterns,
 * and mirrors .NET's PolicyResolutionEngine.GlobMatch (`[^:]*`) rather than its
 * EnforcementEngine.GlobMatch (`.*`).
 */

import { describe, it, expect } from "vitest";
import { resolve, sourcePatternMatch } from "../src/resolution.js";
import type { PolicyAssignment, PolicyDefinition } from "../src/types.js";

function assignment(policyName: string): PolicyAssignment {
  return {
    version: "1.0",
    policyName,
    assignee: { type: "user", identifier: "user-001" },
    scope: { tenantId: "tenant-001" },
    active: true,
    audit: {
      grantedBy: "admin",
      grantedAt: "2026-01-01T00:00:00Z",
      reason: "test",
    },
  };
}

function definition(
  name: string,
  sourcePatterns?: string[],
  extra: Partial<PolicyDefinition> = {},
): PolicyDefinition {
  return {
    version: "1.0",
    name,
    permissions: { canQuery: true, canExport: false, readOnly: true },
    ...(sourcePatterns !== undefined ? { sourcePatterns } : {}),
    ...extra,
  };
}

async function resolveFor(
  sourceConnectionId: string,
  definitions: PolicyDefinition[],
) {
  const defMap = new Map(definitions.map((d) => [d.name, d]));
  return resolve(
    "user-001",
    "tenant-001",
    sourceConnectionId,
    definitions.map((d) => assignment(d.name)),
    defMap,
  );
}

// ---------------------------------------------------------------------------
// The filter itself
// ---------------------------------------------------------------------------

describe("§9: sourcePatterns filters definitions before merging", () => {
  it("LEAK: a db-scoped policy does not govern an unrelated API source", async () => {
    const result = await resolveFor("api:internal:patients", [
      definition("db-only", ["db:production:*"]),
    ]);

    // Excluded before merging, so nothing is left to merge: deny-all.
    expect(result.sourceProfiles).toEqual([]);
    expect(result.permissions.canQuery).toBe(false);
  });

  it("the same policy DOES govern a source its patterns match", async () => {
    const result = await resolveFor("db:production:patients", [
      definition("db-only", ["db:production:*"]),
    ]);

    expect(result.sourceProfiles).toEqual(["db-only"]);
    expect(result.permissions.canQuery).toBe(true);
  });

  it("only the matching definition of several is merged", async () => {
    // The failure this prevents is subtle: without filtering, the API policy's
    // restrictions and the DB policy's restrictions fold together and the caller
    // gets an effective policy no administrator authored.
    const result = await resolveFor("db:production:patients", [
      definition("db-policy", ["db:production:*"]),
      definition("api-policy", ["api:internal:*"]),
      definition("kb-policy", ["kb:research:*"]),
    ]);

    expect(result.sourceProfiles).toEqual(["db-policy"]);
  });

  it("EXPLOIT: an unrelated policy's restriction cannot deny a source it never covered", async () => {
    // api-locked would deny every object; it must not apply to the DB source.
    const result = await resolveFor("db:production:patients", [
      definition("db-policy", ["db:production:*"], {
        objectRules: { allowedObjects: ["patients"] },
      }),
      definition("api-locked", ["api:internal:*"], {
        objectRules: { allowedObjects: [] },
      }),
    ]);

    // Intersecting with [] would have produced deny-all-objects.
    expect(result.objectRules?.allowedObjects).toEqual(["patients"]);
  });

  it("EXPLOIT: an unrelated policy's permission cannot leak into a source", async () => {
    const result = await resolveFor("db:production:patients", [
      definition("db-policy", ["db:production:*"], {
        permissions: { canQuery: true, canExport: false, readOnly: true },
      }),
      definition("api-exporter", ["api:internal:*"], {
        permissions: { canQuery: true, canExport: true, readOnly: false },
      }),
    ]);

    expect(result.sourceProfiles).toEqual(["db-policy"]);
    // canExport ANDs, readOnly ORs, so folding in api-exporter would be visible
    // only through sourceProfiles here -- but a readOnly:false policy leaking into
    // the fold is exactly the shape of the bug, so assert the flags too.
    expect(result.permissions.canExport).toBe(false);
    expect(result.permissions.readOnly).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Absent and empty both mean "applies to all"
// ---------------------------------------------------------------------------

describe("§9: absent or empty sourcePatterns applies to every source", () => {
  it("an absent sourcePatterns applies to any source", async () => {
    const source = "kb:anything:at-all";
    const result = await resolveFor(source, [definition("universal")]);

    expect(result.sourceProfiles).toEqual(["universal"]);
    expect(result.permissions.canQuery).toBe(true);
  });

  it("an EMPTY sourcePatterns applies to any source, not to none", async () => {
    // Unlike an allow-list, [] here is not deny-all: §9 gives absent and [] the
    // same "source-agnostic" meaning, so an empty list must not silently exclude
    // the policy from every source.
    const result = await resolveFor("kb:anything:at-all", [
      definition("universal", []),
    ]);

    expect(result.sourceProfiles).toEqual(["universal"]);
  });

  it("a universal policy merges alongside a matching scoped one", async () => {
    const result = await resolveFor("db:production:patients", [
      definition("scoped", ["db:production:*"], { priority: 10 }),
      definition("universal", undefined, { priority: 20 }),
    ]);

    expect(result.sourceProfiles.sort()).toEqual(["scoped", "universal"]);
  });

  it("a universal policy merges even when a scoped sibling is excluded", async () => {
    const result = await resolveFor("kb:research:trials", [
      definition("db-only", ["db:production:*"]),
      definition("universal"),
    ]);

    expect(result.sourceProfiles).toEqual(["universal"]);
  });
});

// ---------------------------------------------------------------------------
// Glob dialect: `*` does not cross `:`
// ---------------------------------------------------------------------------

describe("§9: sourcePattern globs match within a segment", () => {
  it("EXPLOIT: `db:*` does not match a three-segment source", async () => {
    // If `*` expanded to `.*`, a policy scoped to the `db` category alone would
    // capture every database source in every namespace -- including ones the
    // administrator deliberately left out.
    const result = await resolveFor("db:production:patients", [
      definition("one-segment-wildcard", ["db:*"]),
    ]);

    expect(result.sourceProfiles).toEqual([]);
  });

  it("`db:*:*` does match a three-segment source", async () => {
    const result = await resolveFor("db:production:patients", [
      definition("two-wildcards", ["db:*:*"]),
    ]);

    expect(result.sourceProfiles).toEqual(["two-wildcards"]);
  });

  it("a wildcard does not cross into a later segment", () => {
    expect(sourcePatternMatch("db:*", "db:production")).toBe(true);
    expect(sourcePatternMatch("db:*", "db:production:patients")).toBe(false);
    expect(sourcePatternMatch("db:production:*", "db:production:patients")).toBe(
      true,
    );
    expect(sourcePatternMatch("db:production:*", "db:staging:patients")).toBe(
      false,
    );
  });

  it("a partial-segment wildcard matches a prefix within that segment", () => {
    expect(
      sourcePatternMatch("db:production:patient_*", "db:production:patient_records"),
    ).toBe(true);
    expect(
      sourcePatternMatch("db:production:patient_*", "db:production:encounters"),
    ).toBe(false);
  });

  it("matching is case-insensitive", async () => {
    expect(sourcePatternMatch("DB:Production:*", "db:production:patients")).toBe(
      true,
    );

    const result = await resolveFor("DB:PRODUCTION:PATIENTS", [
      definition("mixed-case", ["db:production:*"]),
    ]);
    expect(result.sourceProfiles).toEqual(["mixed-case"]);
  });

  it("an exact pattern with no wildcard matches only that source", () => {
    expect(sourcePatternMatch("db:production:patients", "db:production:patients")).toBe(
      true,
    );
    expect(
      sourcePatternMatch("db:production:patients", "db:production:patients2"),
    ).toBe(false);
  });

  it("regex metacharacters in a pattern are literal, not operators", () => {
    // A pattern is a glob, not a regex: `.` and `+` must not match arbitrarily.
    expect(sourcePatternMatch("db:prod.uction:x", "db:prodXuction:x")).toBe(false);
    expect(sourcePatternMatch("db:prod.uction:x", "db:prod.uction:x")).toBe(true);
    expect(sourcePatternMatch("db:a+:x", "db:aaa:x")).toBe(false);
    expect(sourcePatternMatch("db:a+:x", "db:a+:x")).toBe(true);
  });

  it("a pattern matching several sources matches each of them", () => {
    for (const source of [
      "db:production:patient_records",
      "db:production:patient_notes",
    ]) {
      expect(sourcePatternMatch("db:production:patient_*", source)).toBe(true);
    }
  });

  it("any ONE matching pattern in the list is enough", async () => {
    const result = await resolveFor("api:internal:orders", [
      definition("multi", ["db:production:*", "api:internal:*", "kb:*:*"]),
    ]);

    expect(result.sourceProfiles).toEqual(["multi"]);
  });
});

// ---------------------------------------------------------------------------
// appliesToAll
// ---------------------------------------------------------------------------

describe("§9: appliesToAll bypasses the sourcePatterns filter", () => {
  it("appliesToAll: true applies even when the patterns do not match", async () => {
    // Matches .NET, which short-circuits on AppliesToAll before consulting the
    // patterns. The schema documents the two fields as alternatives, so a policy
    // asserting "all sources" must not be excluded by a leftover pattern list.
    const result = await resolveFor("api:internal:orders", [
      definition("everything", ["db:production:*"], { appliesToAll: true }),
    ]);

    expect(result.sourceProfiles).toEqual(["everything"]);
  });

  it("appliesToAll: false still consults the patterns", async () => {
    const denied = await resolveFor("api:internal:orders", [
      definition("db-only", ["db:production:*"], { appliesToAll: false }),
    ]);
    const allowed = await resolveFor("db:production:x", [
      definition("db-only", ["db:production:*"], { appliesToAll: false }),
    ]);

    expect(denied.sourceProfiles).toEqual([]);
    expect(allowed.sourceProfiles).toEqual(["db-only"]);
  });
});

// ---------------------------------------------------------------------------
// The shipped fixtures, which carry real sourcePatterns
// ---------------------------------------------------------------------------

describe("§9: the shipped fixture policies are source-scoped", () => {
  it("healthcare-analyst applies to its patient tables and not to an API source", async () => {
    // fixtures/policies/healthcare-analyst.json declares
    // ["db:production:patient_*", "db:production:encounter_*"].
    const patterns = ["db:production:patient_*", "db:production:encounter_*"];

    expect(sourcePatternMatch(patterns[0], "db:production:patient_records")).toBe(
      true,
    );
    expect(sourcePatternMatch(patterns[1], "db:production:encounter_log")).toBe(
      true,
    );
    for (const pattern of patterns) {
      expect(sourcePatternMatch(pattern, "api:internal:patients")).toBe(false);
      expect(sourcePatternMatch(pattern, "db:staging:patient_records")).toBe(false);
    }
  });
});
