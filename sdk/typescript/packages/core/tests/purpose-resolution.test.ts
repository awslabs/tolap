/**
 * Purpose filtering at resolution (canonical spec §15.1).
 *
 * Built on the four shared policy/assignment fixture pairs, so the scenarios are the
 * same ones .NET and Python resolve. Two of the four definitions share a purposeId and
 * two do not, which is what makes "a non-matching purpose is EXCLUDED rather than
 * merged" a statement the fixtures can actually demonstrate.
 *
 * The filter runs **before** the merge, and that ordering is the whole point: a policy
 * scoped to a purpose the caller did not declare must not fold its rules into the
 * effective policy at all. Filtering afterwards would mean the rules had already
 * merged, and whether that widens or narrows access depends on the policies involved —
 * either way the resolved policy is not the one the administrator authored.
 *
 * `declaredPurpose` is a **trailing** parameter, so the pre-feature 8-argument call
 * must behave exactly as it did. That is asserted, not assumed.
 */

import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { resolve } from "../src/resolution.js";
import type {
  EffectivePolicy,
  PolicyAssignment,
  PolicyDefinition,
} from "../src/types.js";

const policiesDir = path.resolve(__dirname, "../../../../../fixtures/policies");
const assignmentsDir = path.resolve(__dirname, "../../../../../fixtures/assignments");

const TENANT = "tenant-acme-retail";
const USER = "user-marketing-001";
const SOURCE = "db:marketing:customer_segments";
const CAMPAIGN_PURPOSE = "campaign-x-overlap";

function loadPolicy(name: string): PolicyDefinition {
  return JSON.parse(
    fs.readFileSync(path.join(policiesDir, `${name}.json`), "utf-8"),
  ) as PolicyDefinition;
}

function loadAssignment(name: string): PolicyAssignment {
  return JSON.parse(
    fs.readFileSync(path.join(assignmentsDir, `${name}.json`), "utf-8"),
  ) as PolicyAssignment;
}

const SCOPED = loadPolicy("purpose-campaign-overlap");
const FRAUD = loadPolicy("purpose-fraud-detection");
const AGNOSTIC = loadPolicy("purpose-agnostic-baseline");
const JUDGED = loadPolicy("purpose-judge-enabled");

const SCOPED_ASSIGNMENT = loadAssignment("purpose-campaign-overlap");
const FRAUD_ASSIGNMENT = loadAssignment("purpose-fraud-detection");
const AGNOSTIC_ASSIGNMENT = loadAssignment("purpose-agnostic-baseline");
const JUDGED_ASSIGNMENT = loadAssignment("purpose-judged");

function definitionMap(definitions: PolicyDefinition[]): Map<string, PolicyDefinition> {
  return new Map(definitions.map((d) => [d.name, d]));
}

async function resolveWith(
  definitions: PolicyDefinition[],
  assignments: PolicyAssignment[],
  declaredPurpose?: string,
  options: { sourceConnectionId?: string; groups?: string[] } = {},
): Promise<EffectivePolicy> {
  return resolve(
    USER,
    TENANT,
    options.sourceConnectionId ?? SOURCE,
    assignments,
    definitionMap(definitions),
    () => options.groups ?? [],
    () => [],
    3_600_000,
    declaredPurpose,
  );
}

// ---------------------------------------------------------------------------
// The fixtures must be what these tests assume
// ---------------------------------------------------------------------------

describe("the shared fixtures carry what these tests assume", () => {
  it("two definitions share a purpose, one differs, and one is agnostic", () => {
    // Without this, a fixture edit could make every assertion below trivially true —
    // e.g. if FRAUD's purposeId silently became campaign-x-overlap, the
    // "non-matching purpose is excluded" tests would pass by resolving both.
    expect(SCOPED.purposeProfile?.purposeId).toBe(CAMPAIGN_PURPOSE);
    expect(JUDGED.purposeProfile?.purposeId).toBe(CAMPAIGN_PURPOSE);
    expect(FRAUD.purposeProfile?.purposeId).toBe("fraud-detection");
    expect(AGNOSTIC.purposeProfile).toBeUndefined();
  });

  it("all four apply to the same source, so the purpose is what separates them", () => {
    // If they differed by `sourcePatterns`, the §10 filter would be doing the work and
    // the §15.1 filter would be untested.
    for (const definition of [SCOPED, FRAUD, AGNOSTIC, JUDGED]) {
      expect(definition.sourcePatterns).toContain("db:marketing:*");
    }
  });

  it("all four assignments are live and target the same user and tenant", () => {
    for (const assignment of [
      SCOPED_ASSIGNMENT,
      FRAUD_ASSIGNMENT,
      AGNOSTIC_ASSIGNMENT,
      JUDGED_ASSIGNMENT,
    ]) {
      expect(assignment.active).toBe(true);
      expect(assignment.revokedAt).toBeUndefined();
      expect(assignment.assignee.identifier).toBe(USER);
      expect(assignment.scope.tenantId).toBe(TENANT);
    }
  });
});

// ---------------------------------------------------------------------------
// Declaring no purpose
// ---------------------------------------------------------------------------

describe("with no purpose declared", () => {
  it("keeps only the purpose-agnostic policy", async () => {
    const result = await resolveWith(
      [SCOPED, AGNOSTIC],
      [SCOPED_ASSIGNMENT, AGNOSTIC_ASSIGNMENT],
      undefined,
    );

    expect(result.sourceProfiles).toEqual(["marketing-baseline"]);
    expect(result.purposeProfile).toBeUndefined();
    // The scoped policy's `maxResults: 10000` would have folded to `min(10000, 2000)`
    // = 2000 either way, so the limit alone cannot show exclusion. Its hidden fields
    // can: the agnostic baseline hides `date_of_birth` and the scoped policy does not.
    expect(result.limits?.maxResults).toBe(2000);
    expect(result.objectRules?.rowFilters).toBeUndefined();
  });

  it("excludes the scoped policy's rules, not merely its name", async () => {
    // A filter applied after the merge would leave the scoped policy's row filter and
    // masked fields in place while dropping its name from `sourceProfiles`. Asserting
    // the RULES is what distinguishes the two implementations.
    const withPurpose = await resolveWith(
      [SCOPED, AGNOSTIC],
      [SCOPED_ASSIGNMENT, AGNOSTIC_ASSIGNMENT],
      CAMPAIGN_PURPOSE,
    );
    const without = await resolveWith(
      [SCOPED, AGNOSTIC],
      [SCOPED_ASSIGNMENT, AGNOSTIC_ASSIGNMENT],
      undefined,
    );

    expect(withPurpose.objectRules?.rowFilters).toHaveLength(1);
    expect(without.objectRules?.rowFilters).toBeUndefined();
    expect(withPurpose.objectRules?.fieldRules?.maskedFields).toHaveLength(1);
    expect(without.objectRules?.fieldRules?.maskedFields).toBeUndefined();
  });

  it("is deny-all when every candidate is purpose-scoped", async () => {
    // Not "resolve everything" and not a crash: the candidate list is empty after
    // filtering and `merge` returns its deny-all.
    const result = await resolveWith(
      [SCOPED, FRAUD],
      [SCOPED_ASSIGNMENT, FRAUD_ASSIGNMENT],
      undefined,
    );

    expect(result.permissions.canQuery).toBe(false);
    expect(result.permissions.readOnly).toBe(true);
    expect(result.sourceProfiles).toEqual([]);
    expect(result.purposeProfile).toBeUndefined();
  });

  it("an empty purpose string is treated as no purpose", async () => {
    // `""` normalizes to absent, matching the signing projection: `""` and omitted must
    // not behave as two different declarations.
    const result = await resolveWith(
      [SCOPED, AGNOSTIC],
      [SCOPED_ASSIGNMENT, AGNOSTIC_ASSIGNMENT],
      "",
    );

    expect(result.sourceProfiles).toEqual(["marketing-baseline"]);
  });

  it("the trailing parameter omitted entirely behaves as before this feature", async () => {
    // The eight-argument call every existing integrator makes. If purpose filtering had
    // been inserted earlier in the signature, this call would now mean something else.
    const result = await resolve(
      USER,
      TENANT,
      SOURCE,
      [AGNOSTIC_ASSIGNMENT],
      definitionMap([AGNOSTIC]),
      () => [],
      () => [],
      3_600_000,
    );

    expect(result.permissions.canQuery).toBe(true);
    expect(result.purposeProfile).toBeUndefined();
    expect(result.sourceProfiles).toEqual(["marketing-baseline"]);
  });

  it("the default-argument call, with no ttl either, also still works", async () => {
    const result = await resolve(
      USER,
      TENANT,
      SOURCE,
      [AGNOSTIC_ASSIGNMENT],
      definitionMap([AGNOSTIC]),
    );

    expect(result.permissions.canQuery).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Declaring a matching purpose
// ---------------------------------------------------------------------------

describe("with a matching purpose declared", () => {
  it("includes the scoped policy alongside the agnostic one", async () => {
    const result = await resolveWith(
      [SCOPED, AGNOSTIC],
      [SCOPED_ASSIGNMENT, AGNOSTIC_ASSIGNMENT],
      CAMPAIGN_PURPOSE,
    );

    expect(result.sourceProfiles).toEqual([
      "campaign-x-overlap-agent",
      "marketing-baseline",
    ]);
    expect(result.purposeProfile?.purposeId).toBe(CAMPAIGN_PURPOSE);
    expect(result.purposeProfile?.prohibitedActions).toContain("export_pii");
    expect(result.limits?.maxResults).toBe(2000);
  });

  it("carries the merged profile onto the effective policy", async () => {
    // Enforcement only ever sees an effective policy, so this is the field
    // `validateAction` and the judge gate read. Without it the whole feature is
    // authorable and unenforceable.
    const result = await resolveWith([SCOPED], [SCOPED_ASSIGNMENT], CAMPAIGN_PURPOSE);

    expect(result.purposeProfile).toEqual(SCOPED.purposeProfile);
  });

  it("excludes a policy bound to a DIFFERENT purpose", async () => {
    // Both policies are assigned to the same user over the same source, so the purpose
    // is the only thing that can separate them.
    const result = await resolveWith(
      [SCOPED, FRAUD],
      [SCOPED_ASSIGNMENT, FRAUD_ASSIGNMENT],
      CAMPAIGN_PURPOSE,
    );

    expect(result.sourceProfiles).toEqual(["campaign-x-overlap-agent"]);
    expect(result.purposeProfile?.purposeId).toBe(CAMPAIGN_PURPOSE);
    // `inspect_account` is only in the fraud policy's allow-list. Had the two merged,
    // the intersection would have been empty and this would be a deny-all instead.
    expect(result.purposeProfile?.allowedActions).not.toContain("inspect_account");
    expect(result.limits?.maxResults).toBe(10_000);
  });

  it("the other purpose resolves the other policy", async () => {
    // The paired control. Without it, an implementation that excluded every scoped
    // policy would pass the test above.
    const result = await resolveWith(
      [SCOPED, FRAUD],
      [SCOPED_ASSIGNMENT, FRAUD_ASSIGNMENT],
      "fraud-detection",
    );

    expect(result.sourceProfiles).toEqual(["fraud-detection-agent"]);
    expect(result.purposeProfile?.purposeId).toBe("fraud-detection");
    expect(result.limits?.maxResults).toBe(500);
  });

  it("two policies sharing a purpose both resolve and merge", async () => {
    const result = await resolveWith(
      [SCOPED, JUDGED],
      [SCOPED_ASSIGNMENT, JUDGED_ASSIGNMENT],
      CAMPAIGN_PURPOSE,
    );

    expect(result.sourceProfiles).toEqual([
      "campaign-x-overlap-agent",
      "campaign-x-overlap-judged",
    ]);
    // Intersection of the two allow-lists, union of the two deny-lists.
    expect([...(result.purposeProfile?.allowedActions ?? [])].sort()).toEqual([
      "aggregate_overlap",
      "count_segments",
    ]);
    expect(result.purposeProfile?.prohibitedActions).toContain("export_pii");
    expect(result.purposeProfile?.prohibitedActions).toContain("train_model");
    expect(result.purposeProfile?.judge?.enabled).toBe(true);
    expect(result.purposeProfile?.judge?.model).toBe("claude-sonnet");
  });

  it("a purpose nothing declares resolves the agnostic policies normally", async () => {
    // Declaring a purpose is not a request that a purpose-bound policy exist. An
    // agnostic policy applies either way.
    const result = await resolveWith(
      [AGNOSTIC],
      [AGNOSTIC_ASSIGNMENT],
      "some-purpose-nothing-declares",
    );

    expect(result.permissions.canQuery).toBe(true);
    expect(result.sourceProfiles).toEqual(["marketing-baseline"]);
    expect(result.purposeProfile).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// The comparison is exact and case-sensitive, and is not a glob
// ---------------------------------------------------------------------------

describe("purpose matching is exact and case-sensitive", () => {
  for (const declared of [
    "Campaign-X-Overlap",
    "CAMPAIGN-X-OVERLAP",
    "campaign-X-overlap",
  ]) {
    it(`refuses '${declared}'`, async () => {
      // Deliberately unlike the chain-narrowing comparison's glob handling and unlike
      // the case-INsensitive action-category comparison. Both choices deny rather than
      // admit a mis-cased value, which is the direction that matters.
      const result = await resolveWith([SCOPED], [SCOPED_ASSIGNMENT], declared);
      expect(result.permissions.canQuery).toBe(false);
    });
  }

  it("accepts the exact spelling", async () => {
    const result = await resolveWith([SCOPED], [SCOPED_ASSIGNMENT], CAMPAIGN_PURPOSE);
    expect(result.permissions.canQuery).toBe(true);
  });

  for (const declared of ["*", "campaign-*", "campaign-x-overlap*", "campaign"]) {
    it(`treats '${declared}' as a literal, not a pattern`, async () => {
      // A glob comparison here would let a caller declaring `*` resolve every
      // purpose-scoped policy in the tenant. This compares one asserted identifier
      // against one declared identifier.
      const result = await resolveWith([SCOPED, FRAUD], [SCOPED_ASSIGNMENT, FRAUD_ASSIGNMENT], declared);
      expect(result.permissions.canQuery).toBe(false);
      expect(result.sourceProfiles).toEqual([]);
    });
  }

  it("a purpose that is a prefix of the policy's does not resolve it", async () => {
    // Unlike chain narrowing, resolution has no segment-boundary rule: a declared
    // purpose either is the policy's purpose or it is not.
    const result = await resolveWith([SCOPED], [SCOPED_ASSIGNMENT], "campaign-x");
    expect(result.permissions.canQuery).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Composition with the other resolution filters
// ---------------------------------------------------------------------------

describe("purpose filtering composes with the other filters", () => {
  it("does not rescue a policy whose sourcePatterns exclude the source", async () => {
    // Both filters must pass. A matching purpose is not a licence to apply a policy to
    // a source it was never authored for (spec §10).
    const matched = await resolveWith([SCOPED], [SCOPED_ASSIGNMENT], CAMPAIGN_PURPOSE);
    const wrongSource = await resolveWith(
      [SCOPED],
      [SCOPED_ASSIGNMENT],
      CAMPAIGN_PURPOSE,
      { sourceConnectionId: "db:production:patient_records" },
    );

    expect(matched.permissions.canQuery).toBe(true);
    expect(wrongSource.permissions.canQuery).toBe(false);
  });

  it("does not rescue a revoked assignment", async () => {
    // Revocation is checked before anything else and overrides everything (spec §12).
    // A revoked grant does not come back to life by declaring the right purpose.
    const revoked: PolicyAssignment = {
      ...SCOPED_ASSIGNMENT,
      revokedAt: new Date(Date.now() - 86_400_000).toISOString(),
    };

    expect(
      (await resolveWith([SCOPED], [revoked], CAMPAIGN_PURPOSE)).permissions.canQuery,
    ).toBe(false);
    // Paired: the same assignment without the tombstone does resolve.
    expect(
      (await resolveWith([SCOPED], [SCOPED_ASSIGNMENT], CAMPAIGN_PURPOSE)).permissions
        .canQuery,
    ).toBe(true);
  });

  it("does not rescue an inactive assignment", async () => {
    const inactive: PolicyAssignment = { ...SCOPED_ASSIGNMENT, active: false };

    expect(
      (await resolveWith([SCOPED], [inactive], CAMPAIGN_PURPOSE)).permissions.canQuery,
    ).toBe(false);
  });

  it("filters per assignment occurrence, not per definition", async () => {
    // The same definition reached by two assignments contributes twice; the purpose
    // filter runs on each occurrence. An implementation that de-duplicated definitions
    // before filtering would report one source profile where two applied.
    const viaGroup: PolicyAssignment = {
      ...SCOPED_ASSIGNMENT,
      assignee: { type: "group", identifier: "marketing-team" },
    };

    const matched = await resolveWith(
      [SCOPED],
      [SCOPED_ASSIGNMENT, viaGroup],
      CAMPAIGN_PURPOSE,
      { groups: ["marketing-team"] },
    );
    expect(matched.sourceProfiles).toHaveLength(2);
    expect(matched.permissions.canQuery).toBe(true);

    const excluded = await resolveWith(
      [SCOPED],
      [SCOPED_ASSIGNMENT, viaGroup],
      undefined,
      { groups: ["marketing-team"] },
    );
    expect(excluded.sourceProfiles).toEqual([]);
    expect(excluded.permissions.canQuery).toBe(false);
  });

  it("a definition an assignment names but the store lacks is still skipped", async () => {
    // The pre-existing lookup miss, re-asserted alongside the new filter so the two
    // conditions in the same `if` are both covered.
    const result = await resolveWith([], [SCOPED_ASSIGNMENT], CAMPAIGN_PURPOSE);
    expect(result.permissions.canQuery).toBe(false);
  });
});
