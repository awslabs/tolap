/**
 * Branch and public-API coverage for @tolap/store.
 *
 * The store is where an administrator's intent is recorded, so the assertions that
 * matter are about the DECISION a stored change produces, not about the bookkeeping.
 * Spec §11 is explicit: revoking an assignment must make it stop resolving, and a
 * test asserting only that an audit event fired would pass against a fail-open
 * control with a misleading audit trail.
 */

import { describe, expect, it } from "vitest";

import { InMemoryPolicyStore } from "../src/in-memory-store.js";
import { StaticIdentityResolver } from "../src/static-identity-resolver.js";
import type { IdentityResolver, PolicyAuditEvent, PolicyStore } from "../src/types.js";
import type { PolicyAssignment, PolicyDefinition } from "@tolap/core";

const TENANT = "tenant-001";
// Canonical `category:namespace:name` form: resolution filters definitions on their
// sourcePatterns (spec §9), so the source and the patterns have to agree.
const SOURCE = "db:production:patients";

function definition(
  name = "policy-a",
  extra: Partial<PolicyDefinition> = {},
): PolicyDefinition {
  return {
    version: "1.0",
    name,
    sourcePatterns: ["db:production:*"],
    permissions: { canQuery: true, canExport: false, readOnly: true },
    objectRules: { allowedObjects: ["patients"] },
    ...extra,
  };
}

function assignment(
  policyName = "policy-a",
  extra: Partial<PolicyAssignment> = {},
): PolicyAssignment {
  return {
    version: "1.0",
    policyName,
    assignee: { type: "user", identifier: "user-001" },
    scope: { tenantId: TENANT },
    active: true,
    audit: { grantedBy: "admin", grantedAt: "2026-01-01T00:00:00Z", reason: "test" },
    ...extra,
  };
}

// ---------------------------------------------------------------------------
// Interface conformance
// ---------------------------------------------------------------------------

describe("the exported interfaces are satisfied by the exported implementations", () => {
  // PolicyStore and IdentityResolver are type-only exports, so the meaningful
  // assertion is structural: the shipped classes are assignable to them, and every
  // declared method is callable through the interface. A method missing from an
  // implementation would be a compile error here (`npx tsc --noEmit` is part of the
  // suite's contract) and a runtime failure below.
  it("InMemoryPolicyStore is usable through the PolicyStore interface", async () => {
    const store: PolicyStore = new InMemoryPolicyStore();

    await store.putDefinition(definition());
    expect((await store.getDefinition("policy-a"))?.name).toBe("policy-a");
    expect(await store.listDefinitions()).toHaveLength(1);

    await store.putAssignment(assignment());
    expect(await store.listAssignments()).toHaveLength(1);
    expect(await store.listAssignments("user-001")).toHaveLength(1);

    expect((await store.resolvePolicy("user-001", TENANT, SOURCE)).permissions.canQuery).toBe(
      true,
    );

    expect(await store.deleteAssignment("policy-a", "user-001")).toBe(true);
    expect(await store.deleteDefinition("policy-a")).toBe(true);
  });

  it("StaticIdentityResolver is usable through the IdentityResolver interface", async () => {
    const concrete = new StaticIdentityResolver();
    concrete.setGroups("user-001", ["analysts"]);
    concrete.setRoles("user-001", ["data-analyst"]);

    const resolver: IdentityResolver = concrete;
    expect(await resolver.getGroups("user-001")).toEqual(["analysts"]);
    expect(await resolver.getRoles("user-001")).toEqual(["data-analyst"]);
  });

  it("a hand-written IdentityResolver is accepted by the store", async () => {
    // The interface exists so integrators can plug in their own directory; this is
    // the property that makes it worth exporting.
    const custom: IdentityResolver = {
      getGroups: async (userId) => (userId === "user-001" ? ["analysts"] : []),
      getRoles: async () => [],
    };
    const store = new InMemoryPolicyStore(custom);
    await store.putDefinition(definition());
    await store.putAssignment(
      assignment("policy-a", { assignee: { type: "group", identifier: "analysts" } }),
    );

    expect((await store.resolvePolicy("user-001", TENANT, SOURCE)).sourceProfiles).toEqual([
      "policy-a",
    ]);
    expect((await store.resolvePolicy("user-002", TENANT, SOURCE)).sourceProfiles).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// StaticIdentityResolver -- both setters and both defaults
// ---------------------------------------------------------------------------

describe("StaticIdentityResolver", () => {
  it("returns an empty list for an unknown user, for groups and roles alike", async () => {
    const resolver = new StaticIdentityResolver();
    expect(await resolver.getGroups("nobody")).toEqual([]);
    expect(await resolver.getRoles("nobody")).toEqual([]);
  });

  it("setGroups and setRoles are independent", async () => {
    const resolver = new StaticIdentityResolver();
    resolver.setGroups("user-001", ["analysts"]);
    resolver.setRoles("user-001", ["data-analyst"]);

    expect(await resolver.getGroups("user-001")).toEqual(["analysts"]);
    expect(await resolver.getRoles("user-001")).toEqual(["data-analyst"]);
    // Setting one must not populate the other.
    expect(await resolver.getGroups("user-002")).toEqual([]);
  });

  it("a later set replaces the earlier value rather than appending", async () => {
    // Replacement matters: appending would make a removed group impossible to
    // revoke through this API.
    const resolver = new StaticIdentityResolver();
    resolver.setGroups("user-001", ["analysts", "admins"]);
    resolver.setGroups("user-001", ["analysts"]);
    resolver.setRoles("user-001", ["a"]);
    resolver.setRoles("user-001", []);

    expect(await resolver.getGroups("user-001")).toEqual(["analysts"]);
    expect(await resolver.getRoles("user-001")).toEqual([]);
  });

  it("a ROLE assignment resolves only once the role is set", async () => {
    // setRoles had no test at all, so nothing proved a role-scoped policy could be
    // granted through it.
    const resolver = new StaticIdentityResolver();
    const store = new InMemoryPolicyStore(resolver);
    await store.putDefinition(definition());
    await store.putAssignment(
      assignment("policy-a", { assignee: { type: "role", identifier: "data-analyst" } }),
    );

    const before = await store.resolvePolicy("user-001", TENANT, SOURCE);
    expect(before.permissions.canQuery).toBe(false);

    resolver.setRoles("user-001", ["data-analyst"]);
    const after = await store.resolvePolicy("user-001", TENANT, SOURCE);
    expect(after.sourceProfiles).toEqual(["policy-a"]);
    expect(after.permissions.canQuery).toBe(true);
  });

  it("a GROUP assignment resolves only once the group is set", async () => {
    const resolver = new StaticIdentityResolver();
    const store = new InMemoryPolicyStore(resolver);
    await store.putDefinition(definition());
    await store.putAssignment(
      assignment("policy-a", { assignee: { type: "group", identifier: "analysts" } }),
    );

    expect((await store.resolvePolicy("user-001", TENANT, SOURCE)).permissions.canQuery).toBe(
      false,
    );

    resolver.setGroups("user-001", ["analysts"]);
    expect((await store.resolvePolicy("user-001", TENANT, SOURCE)).sourceProfiles).toEqual([
      "policy-a",
    ]);
  });

  it("removing the group STOPS the assignment resolving", async () => {
    // The revocation property applied to identity rather than to the assignment.
    const resolver = new StaticIdentityResolver();
    resolver.setGroups("user-001", ["analysts"]);
    const store = new InMemoryPolicyStore(resolver);
    await store.putDefinition(definition());
    await store.putAssignment(
      assignment("policy-a", { assignee: { type: "group", identifier: "analysts" } }),
    );

    expect((await store.resolvePolicy("user-001", TENANT, SOURCE)).permissions.canQuery).toBe(
      true,
    );

    resolver.setGroups("user-001", []);
    expect((await store.resolvePolicy("user-001", TENANT, SOURCE)).permissions.canQuery).toBe(
      false,
    );
  });
});

// ---------------------------------------------------------------------------
// The default resolver (no resolver supplied)
// ---------------------------------------------------------------------------

describe("InMemoryPolicyStore default identity resolver", () => {
  it("grants no groups and no roles, so only direct assignments resolve", async () => {
    const store = new InMemoryPolicyStore();
    await store.putDefinition(definition());
    await store.putAssignment(
      assignment("policy-a", { assignee: { type: "group", identifier: "analysts" } }),
    );

    expect((await store.resolvePolicy("user-001", TENANT, SOURCE)).permissions.canQuery).toBe(
      false,
    );

    await store.putAssignment(assignment("policy-a"));
    expect((await store.resolvePolicy("user-001", TENANT, SOURCE)).sourceProfiles).toEqual([
      "policy-a",
    ]);
  });
});

// ---------------------------------------------------------------------------
// Revocation must actually revoke (spec §11)
// ---------------------------------------------------------------------------

describe("§11: revocation makes an assignment stop resolving", () => {
  async function seeded() {
    const store = new InMemoryPolicyStore();
    await store.putDefinition(definition());
    await store.putAssignment(assignment());
    return store;
  }

  it("access is GONE after deleteAssignment, not merely audited", async () => {
    const store = await seeded();
    const events: PolicyAuditEvent[] = [];
    store.onAudit((e) => events.push(e));

    expect((await store.resolvePolicy("user-001", TENANT, SOURCE)).permissions.canQuery).toBe(
      true,
    );

    expect(await store.deleteAssignment("policy-a", "user-001")).toBe(true);

    const after = await store.resolvePolicy("user-001", TENANT, SOURCE);
    expect(after.permissions.canQuery).toBe(false);
    expect(after.sourceProfiles).toEqual([]);
    expect(after.objectRules).toBeUndefined();
    // The audit event is a bonus, not the assertion.
    expect(events.some((e) => e.action === "assignment.delete")).toBe(true);
  });

  it("access is GONE after the assignment is deactivated in place", async () => {
    const store = await seeded();
    await store.putAssignment(assignment("policy-a", { active: false }));

    expect((await store.resolvePolicy("user-001", TENANT, SOURCE)).permissions.canQuery).toBe(
      false,
    );
    // And the record is replaced, not duplicated.
    expect(await store.listAssignments()).toHaveLength(1);
  });

  it("access is GONE after the assignment is expired in place", async () => {
    const store = await seeded();
    await store.putAssignment(
      assignment("policy-a", { expiresAt: "2020-01-01T00:00:00Z" }),
    );

    expect((await store.resolvePolicy("user-001", TENANT, SOURCE)).permissions.canQuery).toBe(
      false,
    );
  });

  it("access is GONE after the DEFINITION is deleted, even with the assignment intact", async () => {
    const store = await seeded();
    expect(await store.deleteDefinition("policy-a")).toBe(true);

    const after = await store.resolvePolicy("user-001", TENANT, SOURCE);
    expect(after.permissions.canQuery).toBe(false);
    // The assignment still exists -- it simply resolves to nothing.
    expect(await store.listAssignments()).toHaveLength(1);
  });

  it("deleting one of two assignments revokes only that one", async () => {
    const store = await seeded();
    await store.putDefinition(definition("policy-b"));
    await store.putAssignment(assignment("policy-b"));

    expect(
      (await store.resolvePolicy("user-001", TENANT, SOURCE)).sourceProfiles.sort(),
    ).toEqual(["policy-a", "policy-b"]);

    await store.deleteAssignment("policy-a", "user-001");
    expect((await store.resolvePolicy("user-001", TENANT, SOURCE)).sourceProfiles).toEqual([
      "policy-b",
    ]);
  });

  it("deleting an assignment for a DIFFERENT assignee leaves this one resolving", async () => {
    const store = await seeded();
    await store.putAssignment(
      assignment("policy-a", { assignee: { type: "user", identifier: "user-002" } }),
    );

    await store.deleteAssignment("policy-a", "user-002");

    expect((await store.resolvePolicy("user-001", TENANT, SOURCE)).permissions.canQuery).toBe(
      true,
    );
    expect((await store.resolvePolicy("user-002", TENANT, SOURCE)).permissions.canQuery).toBe(
      false,
    );
  });

  it("a no-op delete reports false and emits no audit event", async () => {
    const store = await seeded();
    const events: PolicyAuditEvent[] = [];
    store.onAudit((e) => events.push(e));

    expect(await store.deleteAssignment("ghost", "user-001")).toBe(false);
    expect(await store.deleteDefinition("ghost")).toBe(false);
    // No event for something that did not happen -- a misleading audit trail is the
    // failure mode §11 calls out.
    expect(events).toEqual([]);
    // And the real assignment is untouched.
    expect((await store.resolvePolicy("user-001", TENANT, SOURCE)).permissions.canQuery).toBe(
      true,
    );
  });
});

// ---------------------------------------------------------------------------
// listAssignments filtering and audit fan-out
// ---------------------------------------------------------------------------

describe("listAssignments and audit fan-out", () => {
  it("returns a copy, so mutating the result cannot alter the store", async () => {
    const store = new InMemoryPolicyStore();
    await store.putAssignment(assignment());

    (await store.listAssignments()).length = 0;
    expect(await store.listAssignments()).toHaveLength(1);
  });

  it("filters by assignee identifier and returns [] for an unknown one", async () => {
    const store = new InMemoryPolicyStore();
    await store.putAssignment(assignment());
    await store.putAssignment(
      assignment("policy-a", { assignee: { type: "user", identifier: "user-002" } }),
    );

    expect(await store.listAssignments()).toHaveLength(2);
    expect(await store.listAssignments("user-001")).toHaveLength(1);
    expect(await store.listAssignments("nobody")).toEqual([]);
  });

  it("every registered listener receives every event", async () => {
    const store = new InMemoryPolicyStore();
    const first: string[] = [];
    const second: string[] = [];
    store.onAudit((e) => first.push(e.action));
    store.onAudit((e) => second.push(e.action));

    await store.putDefinition(definition());
    await store.putAssignment(assignment());
    await store.resolvePolicy("user-001", TENANT, SOURCE);

    expect(first).toEqual(["definition.put", "assignment.put", "policy.resolve"]);
    expect(second).toEqual(first);
  });

  it("audit events carry a parseable timestamp and the operation's details", async () => {
    const store = new InMemoryPolicyStore();
    const events: PolicyAuditEvent[] = [];
    store.onAudit((e) => events.push(e));

    await store.putAssignment(assignment());
    await store.resolvePolicy("user-001", TENANT, SOURCE);

    expect(Number.isNaN(new Date(events[0].timestamp).getTime())).toBe(false);
    expect(events[0].details).toEqual({ policyName: "policy-a", assignee: "user-001" });
    expect(events[1].details).toEqual({
      userId: "user-001",
      tenantId: TENANT,
      sourceConnectionId: SOURCE,
    });
  });

  it("with no listener registered, operations still succeed", async () => {
    const store = new InMemoryPolicyStore();
    await expect(store.putDefinition(definition())).resolves.toBeUndefined();
    await expect(store.resolvePolicy("u", "t", SOURCE)).resolves.toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// sourcePatterns scoping through the store (spec §9)
// ---------------------------------------------------------------------------

describe("§9: the store honours a definition's sourcePatterns", () => {
  it("a db-scoped policy does not resolve for an unrelated API source", async () => {
    const store = new InMemoryPolicyStore();
    await store.putDefinition(definition());
    await store.putAssignment(assignment());

    expect((await store.resolvePolicy("user-001", TENANT, SOURCE)).permissions.canQuery).toBe(
      true,
    );
    expect(
      (await store.resolvePolicy("user-001", TENANT, "api:internal:patients")).permissions
        .canQuery,
    ).toBe(false);
  });

  it("a source-agnostic policy resolves for any source", async () => {
    const store = new InMemoryPolicyStore();
    await store.putDefinition(definition("universal", { sourcePatterns: undefined }));
    await store.putAssignment(assignment("universal"));

    for (const source of [SOURCE, "api:internal:x", "kb:research:y"]) {
      expect(
        (await store.resolvePolicy("user-001", TENANT, source)).sourceProfiles,
        source,
      ).toEqual(["universal"]);
    }
  });
});

// ---------------------------------------------------------------------------
// Definition storage
// ---------------------------------------------------------------------------

describe("definition storage", () => {
  it("get returns undefined for a missing name and the record for a stored one", async () => {
    const store = new InMemoryPolicyStore();
    expect(await store.getDefinition("policy-a")).toBeUndefined();

    await store.putDefinition(definition());
    expect((await store.getDefinition("policy-a"))?.name).toBe("policy-a");
  });

  it("listDefinitions is empty before any put and reflects overwrites", async () => {
    const store = new InMemoryPolicyStore();
    expect(await store.listDefinitions()).toEqual([]);

    await store.putDefinition(definition());
    await store.putDefinition(definition("policy-a", { description: "updated" }));

    const all = await store.listDefinitions();
    expect(all).toHaveLength(1);
    expect(all[0].description).toBe("updated");
  });

  it("an overwritten definition changes what RESOLVES, not just what is stored", async () => {
    const store = new InMemoryPolicyStore();
    await store.putDefinition(definition());
    await store.putAssignment(assignment());

    expect(
      (await store.resolvePolicy("user-001", TENANT, SOURCE)).objectRules?.allowedObjects,
    ).toEqual(["patients"]);

    // Tighten the policy in place; the next resolve must reflect it.
    await store.putDefinition(
      definition("policy-a", { objectRules: { allowedObjects: [] } }),
    );
    expect(
      (await store.resolvePolicy("user-001", TENANT, SOURCE)).objectRules?.allowedObjects,
    ).toEqual([]);
  });
});
