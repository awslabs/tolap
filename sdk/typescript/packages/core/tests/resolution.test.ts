import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { resolve, globMatch } from "../src/resolution.js";
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

  it("should match * wildcard (not crossing /)", () => {
    expect(globMatch("/api/v1/*", "/api/v1/patients")).toBe(true);
    expect(globMatch("/api/v1/*", "/api/v1/patients/123")).toBe(false);
  });

  it("should match ** wildcard (crossing /)", () => {
    expect(globMatch("/api/**", "/api/v1/patients")).toBe(true);
    expect(globMatch("/api/**", "/api/v1/patients/123")).toBe(true);
  });

  it("should match ? wildcard (single char)", () => {
    expect(globMatch("patient?", "patients")).toBe(true);
    expect(globMatch("patient?", "patient")).toBe(false);
  });

  it("should match source patterns", () => {
    expect(globMatch("db:production:patient_*", "db:production:patient_records")).toBe(true);
    expect(globMatch("db:production:patient_*", "db:staging:patient_records")).toBe(false);
    expect(globMatch("api:internal:*", "api:internal:anything")).toBe(true);
    expect(globMatch("kb:*:*", "kb:research:clinical")).toBe(true);
  });
});

describe("resolve", () => {
  it("should resolve a direct user assignment", async () => {
    const assignment = loadAssignment("user-direct.json");
    const policy = loadPolicy("healthcare-analyst.json");

    const definitions = new Map<string, PolicyDefinition>();
    definitions.set(policy.name, policy);

    const result = await resolve(
      "user-001",
      "tenant-midwest-health",
      "ds-postgres-healthcare",
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
      "ds-api-internal",
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

    const definitions = new Map<string, PolicyDefinition>();
    definitions.set(policy.name, policy);

    const result = await resolve(
      "user-001",
      "tenant-midwest-health",
      "ds-s3-datalake-prod",
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
      "ds-postgres-healthcare",
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
      "ds-postgres-healthcare",
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
      "ds-kb-research",
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

    const definitions = new Map<string, PolicyDefinition>();
    definitions.set(policy1.name, policy1);
    definitions.set(policy2.name, policy2);

    const result = await resolve(
      "user-001",
      "tenant-midwest-health",
      "ds-test",
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
      "ds-postgres-healthcare",
      [assignment],
      definitions,
    );

    expect(result.sourceProfiles).toContain("healthcare-analyst-db");
  });
});
