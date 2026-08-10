/**
 * Revocation is enforced by the SDK resolver (spec §12).
 *
 * Before `revokedAt` existed in the model, revocation had no SDK backstop: a
 * store that forgot its own `revoked_at IS NULL` filter kept resolving a revoked
 * grant with nothing in the SDK to catch it. These tests assert the resolver
 * itself refuses a revoked assignment.
 *
 * The assertions are about resolved access, not about a flag or an audit event —
 * the spec names emitting a `PolicyRevoked` event while leaving access intact as
 * the fail-open to avoid.
 */

import { describe, it, expect } from "vitest";
import { resolve } from "../src/resolution.js";
import type { PolicyDefinition, PolicyAssignment } from "../src/types.js";

const policy: PolicyDefinition = {
  version: "1.0",
  name: "analyst",
  permissions: { canQuery: true, readOnly: true },
  priority: 100,
  appliesToAll: true,
  objectRules: { allowedObjects: ["patients"] },
};

function assignment(
  overrides: Partial<PolicyAssignment> = {},
): PolicyAssignment {
  return {
    version: "1.0",
    policyName: "analyst",
    assignee: { type: "user", identifier: "user-001" },
    scope: { tenantId: "tenant-001" },
    active: true,
    audit: {
      grantedBy: "test-admin",
      grantedAt: "2026-01-01T00:00:00Z",
      reason: "Test assignment",
    },
    ...overrides,
  };
}

function resolveOne(a: PolicyAssignment) {
  return resolve(
    "user-001",
    "tenant-001",
    "ds-postgres-001",
    [a],
    { analyst: policy },
    () => [],
    () => [],
  );
}

function iso(offsetMs: number): string {
  return new Date(Date.now() + offsetMs).toISOString();
}

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

describe("§12: revocation stops resolution", () => {
  it("grants access when not revoked (baseline)", async () => {
    // Without this, the suite could pass by denying everything.
    const result = await resolveOne(assignment());
    expect(result.permissions.canQuery).toBe(true);
    expect(result.sourceProfiles).toEqual(["analyst"]);
  });

  it("does not resolve a revoked assignment", async () => {
    const result = await resolveOne(
      assignment({ revokedAt: iso(-5 * MINUTE) }),
    );
    expect(result.permissions.canQuery).toBe(false);
    expect(result.sourceProfiles).toEqual([]);
  });

  it("overrides active: true", async () => {
    const result = await resolveOne(
      assignment({ active: true, revokedAt: iso(-MINUTE) }),
    );
    expect(result.permissions.canQuery).toBe(false);
  });

  it("overrides a far-future expiresAt", async () => {
    const result = await resolveOne(
      assignment({
        expiresAt: iso(365 * 24 * HOUR),
        revokedAt: iso(-1000),
      }),
    );
    expect(result.permissions.canQuery).toBe(false);
  });
});

describe("§12: revocation edge cases", () => {
  it("treats a future revokedAt as not yet in effect", async () => {
    // Mirrors expiry rather than behaving as a boolean flag.
    const result = await resolveOne(assignment({ revokedAt: iso(HOUR) }));
    expect(result.permissions.canQuery).toBe(true);
  });

  it.each(["", "not-a-timestamp", "2026-13-45T99:99:99Z", "yesterday"])(
    "fails closed on an unparseable revokedAt (%j)",
    async (value) => {
      // Treating an unreadable tombstone as absent would keep a revoked grant
      // silently alive — the failure mode this field exists to remove.
      const result = await resolveOne(assignment({ revokedAt: value }));
      expect(result.permissions.canQuery).toBe(false);
    },
  );

  it("treats an absent revokedAt as not revoked", async () => {
    const result = await resolveOne(assignment({ revokedAt: undefined }));
    expect(result.permissions.canQuery).toBe(true);
  });

  it("honours a revocation carried on a JSON-parsed assignment", async () => {
    // Assignments arrive as parsed JSON, not hand-built objects.
    const parsed = JSON.parse(
      JSON.stringify(assignment({ revokedAt: "2026-01-02T00:00:00Z" })),
    ) as PolicyAssignment;
    const result = await resolveOne(parsed);
    expect(result.permissions.canQuery).toBe(false);
  });
});
