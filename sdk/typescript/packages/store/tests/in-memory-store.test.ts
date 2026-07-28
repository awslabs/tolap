import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { InMemoryPolicyStore } from "../src/in-memory-store.js";
import { StaticIdentityResolver } from "../src/static-identity-resolver.js";
import type { PolicyAuditEvent } from "../src/types.js";
import type {
  PolicyDefinition,
  PolicyAssignment,
} from "@tolap/core";

const policiesDir = path.resolve(__dirname, "../../../../../fixtures/policies");
const assignmentsDir = path.resolve(__dirname, "../../../../../fixtures/assignments");

function loadPolicy(filename: string): PolicyDefinition {
  const content = fs.readFileSync(path.join(policiesDir, filename), "utf-8");
  return JSON.parse(content) as PolicyDefinition;
}

function loadAssignment(filename: string): PolicyAssignment {
  const content = fs.readFileSync(path.join(assignmentsDir, filename), "utf-8");
  return JSON.parse(content) as PolicyAssignment;
}

describe("InMemoryPolicyStore", () => {
  // -----------------------------------------------------------------------
  // Definition CRUD
  // -----------------------------------------------------------------------

  describe("definitions", () => {
    it("should put and get a definition", async () => {
      const store = new InMemoryPolicyStore();
      const policy = loadPolicy("healthcare-analyst.json");

      await store.putDefinition(policy);
      const retrieved = await store.getDefinition(policy.name);

      expect(retrieved).toBeDefined();
      expect(retrieved?.name).toBe(policy.name);
      expect(retrieved?.permissions.canQuery).toBe(true);
    });

    it("should return undefined for missing definitions", async () => {
      const store = new InMemoryPolicyStore();
      const result = await store.getDefinition("nonexistent");
      expect(result).toBeUndefined();
    });

    it("should list all definitions", async () => {
      const store = new InMemoryPolicyStore();
      const p1 = loadPolicy("healthcare-analyst.json");
      const p2 = loadPolicy("api-readonly.json");

      await store.putDefinition(p1);
      await store.putDefinition(p2);

      const all = await store.listDefinitions();
      expect(all.length).toBe(2);
      const names = all.map((p) => p.name);
      expect(names).toContain(p1.name);
      expect(names).toContain(p2.name);
    });

    it("should delete a definition", async () => {
      const store = new InMemoryPolicyStore();
      const policy = loadPolicy("healthcare-analyst.json");

      await store.putDefinition(policy);
      const deleted = await store.deleteDefinition(policy.name);
      expect(deleted).toBe(true);

      const retrieved = await store.getDefinition(policy.name);
      expect(retrieved).toBeUndefined();
    });

    it("should return false when deleting a non-existent definition", async () => {
      const store = new InMemoryPolicyStore();
      const deleted = await store.deleteDefinition("nonexistent");
      expect(deleted).toBe(false);
    });

    it("should overwrite an existing definition", async () => {
      const store = new InMemoryPolicyStore();
      const policy = loadPolicy("healthcare-analyst.json");

      await store.putDefinition(policy);

      // Modify and re-put
      const modified = { ...policy, description: "Updated description" };
      await store.putDefinition(modified);

      const retrieved = await store.getDefinition(policy.name);
      expect(retrieved?.description).toBe("Updated description");

      const all = await store.listDefinitions();
      expect(all.length).toBe(1);
    });
  });

  // -----------------------------------------------------------------------
  // Assignment CRUD
  // -----------------------------------------------------------------------

  describe("assignments", () => {
    it("should put and list assignments", async () => {
      const store = new InMemoryPolicyStore();
      const assignment = loadAssignment("user-direct.json");

      await store.putAssignment(assignment);
      const all = await store.listAssignments();
      expect(all.length).toBe(1);
      expect(all[0].policyName).toBe(assignment.policyName);
    });

    it("should filter assignments by assignee identifier", async () => {
      const store = new InMemoryPolicyStore();
      const a1 = loadAssignment("user-direct.json");
      const a2 = loadAssignment("group-assignment.json");

      await store.putAssignment(a1);
      await store.putAssignment(a2);

      const userAssignments = await store.listAssignments("user-001");
      expect(userAssignments.length).toBe(1);
      expect(userAssignments[0].assignee.identifier).toBe("user-001");

      const groupAssignments = await store.listAssignments("research-analysts");
      expect(groupAssignments.length).toBe(1);
    });

    it("should delete an assignment", async () => {
      const store = new InMemoryPolicyStore();
      const assignment = loadAssignment("user-direct.json");

      await store.putAssignment(assignment);
      const deleted = await store.deleteAssignment(
        assignment.policyName,
        assignment.assignee.identifier,
      );
      expect(deleted).toBe(true);

      const all = await store.listAssignments();
      expect(all.length).toBe(0);
    });

    it("should return false when deleting a non-existent assignment", async () => {
      const store = new InMemoryPolicyStore();
      const deleted = await store.deleteAssignment("no-policy", "no-user");
      expect(deleted).toBe(false);
    });

    it("should replace assignment for same policy+assignee", async () => {
      const store = new InMemoryPolicyStore();
      const assignment = loadAssignment("user-direct.json");

      await store.putAssignment(assignment);

      const updated: PolicyAssignment = {
        ...assignment,
        active: false,
      };
      await store.putAssignment(updated);

      const all = await store.listAssignments();
      expect(all.length).toBe(1);
      expect(all[0].active).toBe(false);
    });
  });

  // -----------------------------------------------------------------------
  // Policy Resolution
  // -----------------------------------------------------------------------

  describe("resolvePolicy", () => {
    it("should resolve an effective policy", async () => {
      const resolver = new StaticIdentityResolver();
      const store = new InMemoryPolicyStore(resolver);

      const policy = loadPolicy("healthcare-analyst.json");
      const assignment = loadAssignment("user-direct.json");

      await store.putDefinition(policy);
      await store.putAssignment(assignment);

      const effective = await store.resolvePolicy(
        "user-001",
        "tenant-midwest-health",
        "ds-postgres-healthcare",
      );

      expect(effective.userId).toBe("user-001");
      expect(effective.tenantId).toBe("tenant-midwest-health");
      expect(effective.sourceProfiles).toContain("healthcare-analyst-db");
      expect(effective.permissions.canQuery).toBe(true);
    });

    it("should resolve with group-based assignment", async () => {
      const resolver = new StaticIdentityResolver();
      resolver.setGroups("user-001", ["research-analysts"]);

      const store = new InMemoryPolicyStore(resolver);

      const policy = loadPolicy("api-readonly.json");
      const assignment = loadAssignment("group-assignment.json");

      await store.putDefinition(policy);
      await store.putAssignment(assignment);

      const effective = await store.resolvePolicy(
        "user-001",
        "tenant-midwest-health",
        "ds-api-internal",
      );

      expect(effective.sourceProfiles).toContain("internal-api-readonly");
    });

    it("should return deny-all when no assignments match", async () => {
      const store = new InMemoryPolicyStore();
      const policy = loadPolicy("healthcare-analyst.json");
      await store.putDefinition(policy);

      const effective = await store.resolvePolicy(
        "user-999",
        "tenant-other",
        "ds-test",
      );

      expect(effective.permissions.canQuery).toBe(false);
      expect(effective.sourceProfiles).toEqual([]);
    });
  });

  // -----------------------------------------------------------------------
  // Audit Events
  // -----------------------------------------------------------------------

  describe("audit events", () => {
    it("should emit audit events for definition operations", async () => {
      const store = new InMemoryPolicyStore();
      const events: PolicyAuditEvent[] = [];
      store.onAudit((e) => events.push(e));

      const policy = loadPolicy("healthcare-analyst.json");

      await store.putDefinition(policy);
      expect(events.length).toBe(1);
      expect(events[0].action).toBe("definition.put");

      await store.deleteDefinition(policy.name);
      expect(events.length).toBe(2);
      expect(events[1].action).toBe("definition.delete");
    });

    it("should emit audit events for assignment operations", async () => {
      const store = new InMemoryPolicyStore();
      const events: PolicyAuditEvent[] = [];
      store.onAudit((e) => events.push(e));

      const assignment = loadAssignment("user-direct.json");

      await store.putAssignment(assignment);
      expect(events.length).toBe(1);
      expect(events[0].action).toBe("assignment.put");

      await store.deleteAssignment(
        assignment.policyName,
        assignment.assignee.identifier,
      );
      expect(events.length).toBe(2);
      expect(events[1].action).toBe("assignment.delete");
    });

    it("should emit audit event on policy resolution", async () => {
      const store = new InMemoryPolicyStore();
      const events: PolicyAuditEvent[] = [];
      store.onAudit((e) => events.push(e));

      await store.resolvePolicy("user-001", "tenant-001", "ds-001");

      const resolveEvents = events.filter(
        (e) => e.action === "policy.resolve",
      );
      expect(resolveEvents.length).toBe(1);
      expect(resolveEvents[0].details["userId"]).toBe("user-001");
    });
  });
});
