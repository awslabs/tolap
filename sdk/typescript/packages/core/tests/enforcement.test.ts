import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import {
  validateAccess,
  validateFieldAccess,
  applyFieldMasking,
  filterByTags,
  validateEndpoint,
  applyResultLimit,
} from "../src/enforcement.js";
import type { EffectivePolicy } from "../src/types.js";

const fixturesDir = path.resolve(__dirname, "../../../../../fixtures/enforcement");

function loadFixture(filename: string): Record<string, unknown> {
  const content = fs.readFileSync(path.join(fixturesDir, filename), "utf-8");
  return JSON.parse(content) as Record<string, unknown>;
}

/**
 * Build a minimal EffectivePolicy from a fixture's partial policy.
 */
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

// ---------------------------------------------------------------------------
// Object Access
// ---------------------------------------------------------------------------

describe("validateAccess (object access)", () => {
  const fixture = loadFixture("validate-object-access.json");
  const cases = fixture["cases"] as Array<{
    objectName: string;
    policy: Record<string, unknown>;
    expected: { allowed: boolean; reason?: string };
  }>;

  for (const tc of cases) {
    it(`${tc.objectName}: ${tc.expected.allowed ? "allowed" : "denied"}`, () => {
      const policy = toEffectivePolicy(tc.policy);
      const result = validateAccess(tc.objectName, policy);
      expect(result.allowed).toBe(tc.expected.allowed);
      if (tc.expected.reason) {
        expect(result.reason).toBe(tc.expected.reason);
      }
    });
  }
});

// ---------------------------------------------------------------------------
// Field Access -- allowed set
// ---------------------------------------------------------------------------

describe("validateFieldAccess (allowed set)", () => {
  const fixture = loadFixture("validate-field-access-allowed-set.json");
  const input = fixture["input"] as { fields: string[] };
  const policy = toEffectivePolicy(fixture["policy"] as Record<string, unknown>);
  const expected = fixture["expected"] as { allowed: string[]; denied: string[] };

  it("should allow fields in the allowed set and deny others", () => {
    const result = validateFieldAccess(input.fields, policy);
    expect(result.allowed.sort()).toEqual(expected.allowed.sort());
    expect(result.denied.sort()).toEqual(expected.denied.sort());
  });
});

// ---------------------------------------------------------------------------
// Field Access -- hidden fields
// ---------------------------------------------------------------------------

describe("validateFieldAccess (hidden fields)", () => {
  const fixture = loadFixture("validate-field-access-hidden.json");
  const input = fixture["input"] as { fields: string[] };
  const policy = toEffectivePolicy(fixture["policy"] as Record<string, unknown>);
  const expected = fixture["expected"] as { allowed: string[]; denied: string[] };

  it("should deny hidden fields", () => {
    const result = validateFieldAccess(input.fields, policy);
    expect(result.allowed.sort()).toEqual(expected.allowed.sort());
    expect(result.denied.sort()).toEqual(expected.denied.sort());
  });
});

// ---------------------------------------------------------------------------
// Field Masking
// ---------------------------------------------------------------------------

describe("applyFieldMasking", () => {
  const fixture = loadFixture("apply-field-masking.json");
  const input = fixture["input"] as { record: Record<string, unknown> };
  const policy = toEffectivePolicy(fixture["policy"] as Record<string, unknown>);

  it("should apply partial mask (showFirst=1)", () => {
    const result = applyFieldMasking(input.record, policy);
    // "John Smith" -> "J*********" (1 shown, 9 masked)
    expect(result["name"]).toBe("J*********");
  });

  it("should apply hash mask (sha256, truncated to 16 chars)", () => {
    const result = applyFieldMasking(input.record, policy);
    // Hashes are truncated to 16 hex chars to match Python and .NET SDKs.
    const email = result["email"] as string;
    expect(email).toMatch(/^[a-f0-9]{16}$/);
  });

  it("should apply full mask", () => {
    const result = applyFieldMasking(input.record, policy);
    const phone = result["phone"] as string;
    // "555-123-4567" -> 12 asterisks
    expect(phone).toBe("************");
  });

  it("should apply null mask", () => {
    const result = applyFieldMasking(input.record, policy);
    expect(result["ssn"]).toBeNull();
  });

  it("should apply redact mask", () => {
    const result = applyFieldMasking(input.record, policy);
    expect(result["notes"]).toBe("[REDACTED]");
  });
});

// ---------------------------------------------------------------------------
// Tag Filtering
// ---------------------------------------------------------------------------

describe("filterByTags", () => {
  const fixture = loadFixture("filter-by-tags.json");
  const input = fixture["input"] as {
    results: Array<Record<string, unknown>>;
  };
  const policy = toEffectivePolicy(fixture["policy"] as Record<string, unknown>);
  const expected = fixture["expected"] as {
    results: Array<Record<string, unknown>>;
  };

  it("should filter results by allowed and denied tags", () => {
    const result = filterByTags(input.results, policy);
    expect(result.length).toBe(expected.results.length);

    const resultIds = result.map((r) => r["id"]);
    const expectedIds = expected.results.map((r) => r["id"]);
    expect(resultIds).toEqual(expectedIds);
  });
});

// ---------------------------------------------------------------------------
// Endpoint Validation
// ---------------------------------------------------------------------------

describe("validateEndpoint", () => {
  const fixture = loadFixture("validate-endpoint-access.json");
  const cases = fixture["cases"] as Array<{
    path: string;
    method: string;
    policy: Record<string, unknown>;
    expected: { allowed: boolean; reason?: string };
  }>;

  for (const tc of cases) {
    it(`${tc.method} ${tc.path}: ${tc.expected.allowed ? "allowed" : "denied"}`, () => {
      const policy = toEffectivePolicy(tc.policy);
      const result = validateEndpoint(tc.path, tc.method, policy);
      expect(result.allowed).toBe(tc.expected.allowed);
      if (tc.expected.reason) {
        expect(result.reason).toBe(tc.expected.reason);
      }
    });
  }
});

// ---------------------------------------------------------------------------
// Result Limiting
// ---------------------------------------------------------------------------

describe("applyResultLimit", () => {
  it("should truncate results to maxResults", () => {
    const items = Array.from({ length: 100 }, (_, i) => ({ id: i }));
    const policy = toEffectivePolicy({
      permissions: { canQuery: true },
      limits: { maxResults: 10 },
    });
    const result = applyResultLimit(items, policy);
    expect(result.length).toBe(10);
    expect(result[0]).toEqual({ id: 0 });
  });

  it("should return all results when under the limit", () => {
    const items = [{ id: 1 }, { id: 2 }];
    const policy = toEffectivePolicy({
      permissions: { canQuery: true },
      limits: { maxResults: 100 },
    });
    const result = applyResultLimit(items, policy);
    expect(result.length).toBe(2);
  });

  it("should return all results when no limit is set", () => {
    const items = Array.from({ length: 50 }, (_, i) => ({ id: i }));
    const policy = toEffectivePolicy({
      permissions: { canQuery: true },
    });
    const result = applyResultLimit(items, policy);
    expect(result.length).toBe(50);
  });
});
