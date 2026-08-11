/**
 * Section 12: revoking MUST make an assignment stop resolving.
 *
 * The spec names the anti-pattern directly -- emitting a revocation event while
 * leaving the assignment active is "a fail-open control with a misleading audit
 * trail" -- and adds that tests MUST assert access is *gone*, not merely that an
 * event fired. So every test here asserts the resolved policy, and the audit-log
 * assertions are secondary.
 *
 * This matters more for a server than for the in-memory store: revocation here is
 * a tombstone (the grant stays visible to auditors), so "revoked" and "still in
 * the table" are the normal state rather than a bug. Only the read filters keep
 * that safe.
 */

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { resolve, type PolicyAssignment, type PolicyDefinition } from "@aws/tolap-core";
import { PostgresPolicyStore, toAssignment } from "../src/db/store.ts";
import { ADMIN, HAVE_DB, staticIdentity, testDb, type TestDb } from "./helpers/db.ts";

const SOURCE = "db:analytics:patients";

const POLICY = {
  version: "1.0",
  name: "analyst",
  permissions: { canQuery: true, readOnly: true },
  objectRules: { allowedObjects: ["patients"] },
  limits: { maxResults: 100 },
} as unknown as PolicyDefinition;

function assignment(
  overrides: Partial<PolicyAssignment> = {},
): PolicyAssignment {
  return {
    version: "1.0",
    policyName: "analyst",
    assignee: { type: "user", identifier: "alice" },
    scope: { tenantId: "t1" },
    active: true,
    audit: { grantedBy: "admin-1", grantedAt: new Date().toISOString(), reason: "test" },
    ...overrides,
  } as PolicyAssignment;
}

describe("revocation (spec section 12)", () => {
  it("guard: the skip condition is a real boolean", () => {
    expect(typeof HAVE_DB).toBe("boolean");
  });

  describe.skipIf(!HAVE_DB)("against PostgreSQL", () => {
    let db: TestDb;
    let store: PostgresPolicyStore;

    beforeAll(async () => {
      db = await testDb("revocation");
    });

    afterAll(async () => {
      await db?.close();
    });

    beforeEach(async () => {
      await db.pool.query(
        "TRUNCATE tolap_audit, tolap_assignments, tolap_policies CASCADE",
      );
      store = new PostgresPolicyStore(
        db.pool,
        staticIdentity({ alice: ["analysts"] }, { alice: ["clinician"] }),
      );
      await store.putDefinitionAs(POLICY, ADMIN);
    });

    it("grants access while the assignment is live", async () => {
      await store.putAssignmentAs(assignment(), ADMIN);
      const policy = await store.resolvePolicy("alice", "t1", SOURCE);

      expect(policy.permissions.canQuery).toBe(true);
      expect(policy.sourceProfiles).toContain("analyst");
    });

    it("denies access after revocation", async () => {
      await store.putAssignmentAs(assignment(), ADMIN);
      expect((await store.resolvePolicy("alice", "t1", SOURCE)).permissions.canQuery).toBe(
        true,
      );

      const revoked = await store.revokeAssignment("analyst", "alice", ADMIN);
      expect(revoked).toBe(true);

      const after = await store.resolvePolicy("alice", "t1", SOURCE);
      // The assertion section 12 demands: access is actually gone. An empty merge
      // is a deny-all policy, not an absent one.
      expect(after.permissions.canQuery).toBe(false);
      expect(after.sourceProfiles).toEqual([]);
    });

    it("keeps the revoked grant in the record while denying it", async () => {
      await store.putAssignmentAs(assignment(), ADMIN);
      await store.revokeAssignment("analyst", "alice", ADMIN);

      // Tombstoned, not deleted -- an auditor can still see the grant happened.
      const { rows } = await db.pool.query(
        "SELECT revoked_at FROM tolap_assignments WHERE assignee_id = 'alice'",
      );
      expect(rows).toHaveLength(1);
      expect(rows[0].revoked_at).not.toBeNull();

      // But it no longer resolves, and it is absent from the live listing.
      expect(await store.listAssignments("alice")).toEqual([]);
    });

    it("revokes group-based access too", async () => {
      await store.putAssignmentAs(
        assignment({ assignee: { type: "group", identifier: "analysts" } }),
        ADMIN,
      );
      expect((await store.resolvePolicy("alice", "t1", SOURCE)).permissions.canQuery).toBe(
        true,
      );

      await store.revokeAssignment("analyst", "analysts", ADMIN);
      expect(
        (await store.resolvePolicy("alice", "t1", SOURCE)).permissions.canQuery,
      ).toBe(false);
    });

    it("revokes role-based access too", async () => {
      await store.putAssignmentAs(
        assignment({ assignee: { type: "role", identifier: "clinician" } }),
        ADMIN,
      );
      expect((await store.resolvePolicy("alice", "t1", SOURCE)).permissions.canQuery).toBe(
        true,
      );

      await store.revokeAssignment("analyst", "clinician", ADMIN);
      expect(
        (await store.resolvePolicy("alice", "t1", SOURCE)).permissions.canQuery,
      ).toBe(false);
    });

    it("revoking one route does not silently revoke another", async () => {
      // Alice reaches the policy directly and through her group. Revoking the
      // direct grant must leave the group grant working -- otherwise revocation
      // is over-broad, which is its own kind of wrong.
      await store.putAssignmentAs(assignment(), ADMIN);
      await store.putAssignmentAs(
        assignment({ assignee: { type: "group", identifier: "analysts" } }),
        ADMIN,
      );

      await store.revokeAssignment("analyst", "alice", ADMIN);

      const still = await store.resolvePolicy("alice", "t1", SOURCE);
      expect(still.permissions.canQuery).toBe(true);
    });

    it("reports false when there is nothing live to revoke", async () => {
      expect(await store.revokeAssignment("analyst", "nobody", ADMIN)).toBe(false);

      await store.putAssignmentAs(assignment(), ADMIN);
      expect(await store.revokeAssignment("analyst", "alice", ADMIN)).toBe(true);
      // Second revoke is a no-op rather than a spurious success.
      expect(await store.revokeAssignment("analyst", "alice", ADMIN)).toBe(false);
    });

    it("allows re-granting after revocation", async () => {
      await store.putAssignmentAs(assignment(), ADMIN);
      await store.revokeAssignment("analyst", "alice", ADMIN);
      await store.putAssignmentAs(assignment(), ADMIN);

      expect(
        (await store.resolvePolicy("alice", "t1", SOURCE)).permissions.canQuery,
      ).toBe(true);

      // The tombstone plus the new live row: history preserved, access restored.
      const { rows } = await db.pool.query(
        "SELECT revoked_at FROM tolap_assignments WHERE assignee_id = 'alice' ORDER BY granted_at",
      );
      expect(rows).toHaveLength(2);
      expect(rows.filter((r) => r.revoked_at === null)).toHaveLength(1);
    });

    it("an inactive assignment does not resolve", async () => {
      await store.putAssignmentAs(assignment({ active: false }), ADMIN);
      expect(
        (await store.resolvePolicy("alice", "t1", SOURCE)).permissions.canQuery,
      ).toBe(false);
    });

    it("an expired assignment does not resolve", async () => {
      await store.putAssignmentAs(
        assignment({ expiresAt: "2020-01-01T00:00:00Z" }),
        ADMIN,
      );
      // Expiry filtering is the SDK resolver's job; this asserts the server hands
      // it what it needs rather than pre-filtering incorrectly.
      expect(
        (await store.resolvePolicy("alice", "t1", SOURCE)).permissions.canQuery,
      ).toBe(false);
    });

    it("records the revocation in the audit log", async () => {
      await store.putAssignmentAs(assignment(), ADMIN);
      await store.revokeAssignment("analyst", "alice", ADMIN);

      const audit = await store.listAudit();
      const revocation = audit.find((e) => e.action === "assignment.revoke");
      expect(revocation).toBeDefined();
      expect(revocation!.actor).toBe("admin-1");
      expect(revocation!.actorKind).toBe("admin");
      // The event is a supplement to the denial, never a substitute for it.
      expect(
        (await store.resolvePolicy("alice", "t1", SOURCE)).permissions.canQuery,
      ).toBe(false);
    });

    it("deleting a policy revokes the access it granted", async () => {
      await store.putAssignmentAs(assignment(), ADMIN);
      expect((await store.resolvePolicy("alice", "t1", SOURCE)).permissions.canQuery).toBe(
        true,
      );

      expect(await store.deleteDefinitionAs("analyst", ADMIN)).toBe(true);

      // The assignment cascades away with the definition. Were it to survive
      // pointing at a missing policy, resolution would skip it anyway -- but
      // leaving dangling grants would misreport who has access.
      const after = await store.resolvePolicy("alice", "t1", SOURCE);
      expect(after.permissions.canQuery).toBe(false);
      expect(await store.listAssignments("alice")).toEqual([]);
    });

    it("the SDK resolver denies a revoked grant without the SQL filter", async () => {
      // The point of carrying `revokedAt` into the assignment: the `revoked_at IS
      // NULL` clause is no longer the only thing implementing section 12.
      //
      // This reads the revoked row deliberately *without* that filter — standing in
      // for a store that forgot it, which is exactly the case the SDK had no
      // backstop for — and feeds it to the SDK resolver. A deny here means the
      // guarantee no longer depends on every store implementation remembering.
      await store.putAssignmentAs(assignment(), ADMIN);
      await store.revokeAssignment("analyst", "alice", ADMIN);

      const { rows } = await db.pool.query(
        `SELECT * FROM tolap_assignments WHERE policy_name = $1 AND assignee_id = $2`,
        ["analyst", "alice"],
      );
      expect(rows).toHaveLength(1);
      expect(rows[0].revoked_at).not.toBeNull();

      const leaked = toAssignment(rows[0]);
      expect(leaked.revokedAt).toBeDefined();

      const resolved = await resolve(
        "alice",
        "t1",
        SOURCE,
        [leaked],
        { analyst: POLICY },
        () => [],
        () => [],
      );

      expect(resolved.permissions.canQuery).toBe(false);
      expect(resolved.sourceProfiles).toEqual([]);
    });
  });
});
