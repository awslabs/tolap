import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { resolve, globMatch, sourcePatternMatch } from "../src/resolution.js";
import type {
  PolicyDefinition,
  PolicyAssignment,
} from "../src/types.js";

const assignmentsDir = path.resolve(__dirname, "../../../../../fixtures/assignments");
const policiesDir = path.resolve(__dirname, "../../../../../fixtures/policies");

function loadAssignment(filename: string): PolicyAssignment {
  const content = fs.readFileSync(path.join(assignmentsDir, filename), "utf-8");
  return JSON.parse(content) as PolicyAssignment;
}

function loadPolicy(filename: string): PolicyDefinition {
  const content = fs.readFileSync(path.join(policiesDir, filename), "utf-8");
  return JSON.parse(content) as PolicyDefinition;
}

describe("globMatch", () => {
  it("should match exact strings", () => {
    expect(globMatch("patients", "patients")).toBe(true);
    expect(globMatch("patients", "encounters")).toBe(false);
  });

  // CORRECTED (spec §3.1): enforcement `*` crosses `/`. The old title and second
  // assertion ("not crossing /") encoded the divergence — Python allowed
  // `/api/v1/patients/123` under `/api/v1/patients/*` while TypeScript denied it.
  it("should match * wildcard (crossing /)", () => {
    expect(globMatch("/api/v1/*", "/api/v1/patients")).toBe(true);
    expect(globMatch("/api/v1/*", "/api/v1/patients/123")).toBe(true);
  });

  it("should match ** wildcard (an alias for *, also crossing /)", () => {
    expect(globMatch("/api/**", "/api/v1/patients")).toBe(true);
    expect(globMatch("/api/**", "/api/v1/patients/123")).toBe(true);
  });

  it("should match ? wildcard (single char)", () => {
    expect(globMatch("patient?", "patients")).toBe(true);
    expect(globMatch("patient?", "patient")).toBe(false);
  });

  it("should match case-insensitively (§3.1)", () => {
    expect(globMatch("patients", "PATIENTS")).toBe(true);
    expect(globMatch("PATIENTS", "patients")).toBe(true);
    expect(globMatch("/API/v1/*", "/api/v1/records")).toBe(true);
  });

  // `globMatch` is the enforcement dialect, so its `*` crosses `:` too. A
  // `sourcePatterns` glob must NOT — that is `sourcePatternMatch`, pinned in
  // resolution-source-patterns.test.ts. Kept here to document that these literal
  // source-shaped patterns behave the same under either dialect, and to name the
  // one case (`db:*`) where they do not.
  it("should match source-shaped literals, but with enforcement `*` semantics", () => {
    expect(globMatch("db:production:patient_*", "db:production:patient_records")).toBe(true);
    expect(globMatch("db:production:patient_*", "db:staging:patient_records")).toBe(false);
    expect(globMatch("api:internal:*", "api:internal:anything")).toBe(true);
    expect(globMatch("kb:*:*", "kb:research:clinical")).toBe(true);
    // The divergence between the two dialects, made explicit: enforcement `*`
    // crosses the `:` that source-pattern `*` stops at.
    expect(globMatch("db:*", "db:production:patients")).toBe(true);
    expect(sourcePatternMatch("db:*", "db:production:patients")).toBe(false);
  });
});

// Source connection IDs below are in the canonical `category:namespace:name`
// form and are chosen to fall inside each fixture policy's declared
// `sourcePatterns`. That matters since resolution filters on them (canonical spec
// §9): these cases exercise user/group/role matching, so they must use a source
// the policy under test actually claims to cover, or the definition is correctly
// excluded before merging and the case would be asserting nothing about identity.
const SOURCE_HEALTHCARE_DB = "db:production:patient_records"; // healthcare-analyst.json
const SOURCE_INTERNAL_API = "api:internal:patients"; // api-readonly.json
const SOURCE_DATALAKE = "storage:datalake:prod"; // storage-analyst.json
const SOURCE_RESEARCH_KB = "kb:research:trials"; // kb-researcher.json

describe("resolve", () => {
  it("should resolve a direct user assignment", async () => {
    const assignment = loadAssignment("user-direct.json");
    const policy = loadPolicy("healthcare-analyst.json");

    const definitions = new Map<string, PolicyDefinition>();
    definitions.set(policy.name, policy);

    const result = await resolve(
      "user-001",
      "tenant-midwest-health",
      SOURCE_HEALTHCARE_DB,
      [assignment],
      definitions,
    );

    expect(result.version).toBe("1.0");
    expect(result.userId).toBe("user-001");
    expect(result.tenantId).toBe("tenant-midwest-health");
    expect(result.sourceProfiles).toContain("healthcare-analyst-db");
    expect(result.permissions.canQuery).toBe(true);
    expect(result.permissions.readOnly).toBe(true);
  });

  it("should resolve a group assignment", async () => {
    const assignment = loadAssignment("group-assignment.json");
    const policy = loadPolicy("api-readonly.json");

    const definitions = new Map<string, PolicyDefinition>();
    definitions.set(policy.name, policy);

    const result = await resolve(
      "user-001",
      "tenant-midwest-health",
      SOURCE_INTERNAL_API,
      [assignment],
      definitions,
      () => ["research-analysts"],
      () => [],
    );

    expect(result.sourceProfiles).toContain("internal-api-readonly");
    expect(result.permissions.canQuery).toBe(true);
    expect(result.permissions.readOnly).toBe(true);
  });

  it("should resolve a role-based assignment", async () => {
    const assignment = loadAssignment("multi-scope.json");
    const policy = loadPolicy("storage-analyst.json");
    // multi-scope.json pins scope.sourceConnectionId to a legacy "ds-*" id, while
    // the policy it references declares sourcePatterns ["storage:datalake:*"]. The
    // assignment scope is an exact-match check and the policy patterns are globs
    // over the same identifier, so both have to name the same source for this case
    // to reach the role check it exists to test.
    assignment.scope.sourceConnectionId = SOURCE_DATALAKE;

    const definitions = new Map<string, PolicyDefinition>();
    definitions.set(policy.name, policy);

    const result = await resolve(
      "user-001",
      "tenant-midwest-health",
      SOURCE_DATALAKE,
      [assignment],
      definitions,
      () => [],
      () => ["data-analyst"],
    );

    expect(result.sourceProfiles).toContain("data-lake-analyst");
    expect(result.permissions.canExport).toBe(true);
  });

  it("should not resolve an assignment for the wrong tenant", async () => {
    const assignment = loadAssignment("user-direct.json");
    const policy = loadPolicy("healthcare-analyst.json");

    const definitions = new Map<string, PolicyDefinition>();
    definitions.set(policy.name, policy);

    const result = await resolve(
      "user-001",
      "tenant-different",
      SOURCE_HEALTHCARE_DB,
      [assignment],
      definitions,
    );

    // No matching assignments -> deny-all
    expect(result.permissions.canQuery).toBe(false);
    expect(result.sourceProfiles).toEqual([]);
  });

  it("should not resolve an inactive assignment", async () => {
    const assignment = loadAssignment("user-direct.json");
    assignment.active = false;
    const policy = loadPolicy("healthcare-analyst.json");

    const definitions = new Map<string, PolicyDefinition>();
    definitions.set(policy.name, policy);

    const result = await resolve(
      "user-001",
      "tenant-midwest-health",
      SOURCE_HEALTHCARE_DB,
      [assignment],
      definitions,
    );

    expect(result.permissions.canQuery).toBe(false);
    expect(result.sourceProfiles).toEqual([]);
  });

  it("should not resolve an expired assignment", async () => {
    const assignment = loadAssignment("time-bound.json");
    // Set expiry in the past
    assignment.expiresAt = "2020-01-01T00:00:00Z";
    const policy = loadPolicy("kb-researcher.json");

    const definitions = new Map<string, PolicyDefinition>();
    definitions.set(policy.name, policy);

    const result = await resolve(
      "user-002",
      "tenant-midwest-health",
      SOURCE_RESEARCH_KB,
      [assignment],
      definitions,
    );

    expect(result.permissions.canQuery).toBe(false);
    expect(result.sourceProfiles).toEqual([]);
  });

  it("should merge multiple matching policies", async () => {
    const assignment1 = loadAssignment("user-direct.json");
    // Create a second assignment for the same user
    const assignment2: PolicyAssignment = {
      version: "1.0",
      policyName: "internal-api-readonly",
      assignee: { type: "user", identifier: "user-001" },
      scope: { tenantId: "tenant-midwest-health" },
      active: true,
      audit: {
        grantedBy: "admin",
        grantedAt: "2026-01-01T00:00:00Z",
        reason: "test",
      },
    };

    const policy1 = loadPolicy("healthcare-analyst.json");
    const policy2 = loadPolicy("api-readonly.json");
    // These two fixtures are scoped to disjoint source categories
    // (db:production:patient_* vs api:internal:*), so no real source can match
    // both and resolution would correctly exclude one before merging (spec §9).
    // This case is about the permission fold, not about scoping, so both loaded
    // copies are declared source-agnostic. The empty list is the §9 spelling of
    // "applies to every source" and is set on the in-memory copies only.
    policy1.sourcePatterns = [];
    policy2.sourcePatterns = [];

    const definitions = new Map<string, PolicyDefinition>();
    definitions.set(policy1.name, policy1);
    definitions.set(policy2.name, policy2);

    const result = await resolve(
      "user-001",
      "tenant-midwest-health",
      "db:production:patient_records",
      [assignment1, assignment2],
      definitions,
    );

    expect(result.sourceProfiles.length).toBe(2);
    expect(result.permissions.canQuery).toBe(true);
    // AND: both are false for canExport
    expect(result.permissions.canExport).toBe(false);
    // OR: both are true for readOnly
    expect(result.permissions.readOnly).toBe(true);
  });

  it("should accept definitions as a plain object", async () => {
    const assignment = loadAssignment("user-direct.json");
    const policy = loadPolicy("healthcare-analyst.json");

    const definitions: Record<string, PolicyDefinition> = {
      [policy.name]: policy,
    };

    const result = await resolve(
      "user-001",
      "tenant-midwest-health",
      SOURCE_HEALTHCARE_DB,
      [assignment],
      definitions,
    );

    expect(result.sourceProfiles).toContain("healthcare-analyst-db");
  });
});
