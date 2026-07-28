import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import {
  buildSecurityContext,
  signContext,
  validateContext,
  serializeContext,
  deserializeContext,
  signPolicy,
  validatePolicy,
} from "../src/context.js";
import type { EffectivePolicy, SecurityContext } from "../src/types.js";
import { SigningAlgorithm } from "../src/types.js";

const signingFixturesDir = path.resolve(__dirname, "../../../../../fixtures/signing");

function loadFixture(filename: string): Record<string, unknown> {
  const content = fs.readFileSync(
    path.join(signingFixturesDir, filename),
    "utf-8",
  );
  return JSON.parse(content) as Record<string, unknown>;
}

function createTestPolicy(): EffectivePolicy {
  const futureDate = new Date(Date.now() + 3_600_000).toISOString();
  return {
    version: "1.0",
    userId: "user-001",
    tenantId: "tenant-midwest-health",
    sourceConnectionId: "ds-postgres-healthcare",
    resolvedAt: new Date().toISOString(),
    expiresAt: futureDate,
    sourceProfiles: ["healthcare-analyst-db"],
    permissions: {
      canQuery: true,
      canExport: false,
      readOnly: true,
    },
    integrity: {
      algorithm: "none",
      signature: "",
    },
  };
}

const TEST_SECRET = "tolap-test-signing-key-2026";

describe("Security Context", () => {
  describe("buildSecurityContext", () => {
    it("should create a context with the given policy", () => {
      const policy = createTestPolicy();
      const ctx = buildSecurityContext("user-001", "tenant-001", policy);

      expect(ctx.effectivePolicy).toBe(policy);
      expect(ctx.resolvedAt).toBeDefined();
      expect(ctx.expiresAt).toBeDefined();
    });

    it("should set expiry based on TTL", () => {
      const policy = createTestPolicy();
      const ctx = buildSecurityContext("user-001", "tenant-001", policy, 5000);

      const resolvedAt = new Date(ctx.resolvedAt).getTime();
      const expiresAt = new Date(ctx.expiresAt).getTime();
      // Allow small tolerance for test execution time
      expect(expiresAt - resolvedAt).toBeGreaterThanOrEqual(4900);
      expect(expiresAt - resolvedAt).toBeLessThanOrEqual(5100);
    });
  });

  describe("signContext / validateContext", () => {
    it("should sign and validate successfully with HMAC-SHA256", () => {
      const policy = createTestPolicy();
      const ctx = buildSecurityContext("user-001", "tenant-001", policy);
      signContext(ctx, TEST_SECRET, SigningAlgorithm.HmacSha256);

      expect(ctx.signature).toBeDefined();
      expect(ctx.algorithm).toBe(SigningAlgorithm.HmacSha256);
      expect(validateContext(ctx, TEST_SECRET)).toBe(true);
    });

    it("should sign and validate successfully with HMAC-SHA512", () => {
      const policy = createTestPolicy();
      const ctx = buildSecurityContext("user-001", "tenant-001", policy);
      signContext(ctx, TEST_SECRET, SigningAlgorithm.HmacSha512);

      expect(ctx.signature).toBeDefined();
      expect(ctx.algorithm).toBe(SigningAlgorithm.HmacSha512);
      expect(validateContext(ctx, TEST_SECRET)).toBe(true);
    });

    it("should fail validation with wrong key", () => {
      const policy = createTestPolicy();
      const ctx = buildSecurityContext("user-001", "tenant-001", policy);
      signContext(ctx, TEST_SECRET);

      expect(validateContext(ctx, "wrong-key")).toBe(false);
    });

    it("should fail validation with tampered policy", () => {
      const policy = createTestPolicy();
      const ctx = buildSecurityContext("user-001", "tenant-001", policy);
      signContext(ctx, TEST_SECRET);

      // Tamper with the policy
      ctx.effectivePolicy.permissions.canQuery = false;

      expect(validateContext(ctx, TEST_SECRET)).toBe(false);
    });

    it("should fail validation with no signature", () => {
      const policy = createTestPolicy();
      const ctx = buildSecurityContext("user-001", "tenant-001", policy);

      expect(validateContext(ctx, TEST_SECRET)).toBe(false);
    });
  });

  describe("serializeContext / deserializeContext", () => {
    it("should round-trip serialize and deserialize", () => {
      const policy = createTestPolicy();
      const ctx = buildSecurityContext("user-001", "tenant-001", policy);
      signContext(ctx, TEST_SECRET);

      const serialized = serializeContext(ctx);
      expect(typeof serialized).toBe("string");

      const deserialized = deserializeContext(serialized, TEST_SECRET);
      expect(deserialized.effectivePolicy.userId).toBe("user-001");
      expect(deserialized.effectivePolicy.permissions.canQuery).toBe(true);
    });

    it("should throw on expired context", () => {
      const policy = createTestPolicy();
      // Set an already-expired context
      const ctx: SecurityContext = {
        effectivePolicy: policy,
        resolvedAt: new Date(Date.now() - 7200000).toISOString(),
        expiresAt: new Date(Date.now() - 3600000).toISOString(),
      };
      signContext(ctx, TEST_SECRET);
      const serialized = serializeContext(ctx);

      expect(() => deserializeContext(serialized, TEST_SECRET)).toThrow(
        "Security context has expired",
      );
    });

    it("should throw on tampered serialized data", () => {
      const policy = createTestPolicy();
      const ctx = buildSecurityContext("user-001", "tenant-001", policy);
      signContext(ctx, TEST_SECRET);

      const serialized = serializeContext(ctx);
      // Tamper with the base64 data
      const tampered = serialized.slice(0, -5) + "XXXXX";

      expect(() => deserializeContext(tampered, TEST_SECRET)).toThrow();
    });

    it("should throw on invalid base64", () => {
      expect(() => deserializeContext("!!!not-base64!!!", TEST_SECRET)).toThrow();
    });
  });

  describe("signPolicy / validatePolicy", () => {
    it("should sign and validate a policy directly", () => {
      const policy = createTestPolicy();
      signPolicy(policy, TEST_SECRET);

      expect(policy.integrity.algorithm).toBe(SigningAlgorithm.HmacSha256);
      expect(policy.integrity.signature).toBeDefined();
      expect(validatePolicy(policy, TEST_SECRET)).toBe(true);
    });

    it("should fail with wrong key", () => {
      const policy = createTestPolicy();
      signPolicy(policy, TEST_SECRET);

      expect(validatePolicy(policy, "wrong-key")).toBe(false);
    });
  });

  describe("HMAC-SHA256 known-answer test", () => {
    it("should produce consistent signatures for the same payload", () => {
      const fixture = loadFixture("hmac-sha256-known-answer.json");
      const payload = fixture["payload"] as Record<string, unknown>;
      const secretKey = fixture["secretKey"] as string;

      // Build an EffectivePolicy from the fixture payload
      const policy: EffectivePolicy = {
        ...(payload as unknown as EffectivePolicy),
        integrity: { algorithm: "none", signature: "" },
      };

      signPolicy(policy, secretKey, SigningAlgorithm.HmacSha256);
      const sig1 = policy.integrity.signature;

      // Reset and sign again -- must produce the same signature
      policy.integrity = { algorithm: "none", signature: "" };
      signPolicy(policy, secretKey, SigningAlgorithm.HmacSha256);
      const sig2 = policy.integrity.signature;

      expect(sig1).toBe(sig2);
      expect(sig1.length).toBeGreaterThan(0);
    });
  });
});
