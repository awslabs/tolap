/**
 * Regression tests for assignment-expiry validation during resolution.
 *
 * Defect 5 (second half) in docs/canonical-enforcement-spec.md §2:
 * `isAssignmentActive` compared `new Date(expiresAt) <= new Date()` with no
 * parseability check. `new Date("never") <= new Date()` is `false` in
 * JavaScript, so a malformed expiry resolved as "not expired" -- an immortal
 * assignment. Unlike a security context, a policy assignment carries no
 * signature at all, so its expiry string is whatever the store hands back.
 */

import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { resolve } from "../src/resolution.js";
import type { PolicyAssignment, PolicyDefinition } from "../src/types.js";

const assignmentsDir = path.resolve(
  __dirname,
  "../../../../../fixtures/assignments",
);
const policiesDir = path.resolve(__dirname, "../../../../../fixtures/policies");

function loadAssignment(filename: string): PolicyAssignment {
  return JSON.parse(
    fs.readFileSync(path.join(assignmentsDir, filename), "utf-8"),
  ) as PolicyAssignment;
}

function loadPolicy(filename: string): PolicyDefinition {
  return JSON.parse(
    fs.readFileSync(path.join(policiesDir, filename), "utf-8"),
  ) as PolicyDefinition;
}

async function resolveWithExpiry(expiresAt: string | undefined) {
  const assignment = loadAssignment("time-bound.json");
  if (expiresAt === undefined) {
    delete assignment.expiresAt;
  } else {
    assignment.expiresAt = expiresAt;
  }
  const policy = loadPolicy("kb-researcher.json");

  const definitions = new Map<string, PolicyDefinition>();
  definitions.set(policy.name, policy);

  return resolve(
    "user-002",
    "tenant-midwest-health",
    // Inside kb-researcher.json's declared sourcePatterns (["kb:research:*",
    // "kb:clinical:*"]). Resolution filters on those (canonical spec §9), so a
    // source outside them would be excluded before merging and every case here
    // would report deny-all regardless of the expiry under test.
    "kb:research:trials",
    [assignment],
    definitions,
  );
}

describe("defect 5: assignment expiry fails closed", () => {
  it("EXPLOIT: an unparseable expiry does not grant an immortal assignment", async () => {
    for (const bad of ["never", "not-a-date", "2026-13-45T99:99:99Z", "soon"]) {
      // The old comparison-only check's verdict: "not expired".
      expect(new Date(bad) <= new Date()).toBe(false);

      const result = await resolveWithExpiry(bad);

      expect(
        result.permissions.canQuery,
        `expiresAt=${bad} must not resolve`,
      ).toBe(false);
      expect(result.sourceProfiles).toEqual([]);
    }
  });

  it("an empty expiry string does not resolve", async () => {
    const result = await resolveWithExpiry("");

    expect(result.permissions.canQuery).toBe(false);
    expect(result.sourceProfiles).toEqual([]);
  });

  it("an expiry exactly at now does not resolve", async () => {
    const result = await resolveWithExpiry(new Date().toISOString());

    expect(result.permissions.canQuery).toBe(false);
    expect(result.sourceProfiles).toEqual([]);
  });

  it("a past expiry still does not resolve", async () => {
    const result = await resolveWithExpiry("2020-01-01T00:00:00Z");

    expect(result.permissions.canQuery).toBe(false);
    expect(result.sourceProfiles).toEqual([]);
  });

  it("a valid future expiry still resolves", async () => {
    const result = await resolveWithExpiry(
      new Date(Date.now() + 86_400_000).toISOString(),
    );

    expect(result.permissions.canQuery).toBe(true);
    expect(result.sourceProfiles.length).toBeGreaterThan(0);
  });

  it("an absent expiry still resolves (no expiry means no time bound)", async () => {
    const result = await resolveWithExpiry(undefined);

    expect(result.permissions.canQuery).toBe(true);
    expect(result.sourceProfiles.length).toBeGreaterThan(0);
  });
});
