import { createHmac } from "node:crypto";
import { describe, it, expect } from "vitest";
import { SecureMcpToolWrapper } from "../src/wrapper.js";
import { EnforcementMode } from "../src/types.js";
import {
  HeaderIdentityExtractor,
  IdentityExtractionError,
  JwtIdentityExtractor,
} from "../src/extractors.js";
import type { EffectivePolicy } from "@tolap/core";
import type { McpToolDefinition, EnforcementDecision } from "../src/types.js";

function createTestPolicy(overrides?: Partial<EffectivePolicy>): EffectivePolicy {
  return {
    version: "1.0",
    userId: "user-001",
    tenantId: "tenant-001",
    sourceConnectionId: "ds-test",
    resolvedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    sourceProfiles: ["test-policy"],
    permissions: {
      canQuery: true,
      readOnly: true,
    },
    integrity: { algorithm: "none", signature: "" },
    ...overrides,
  };
}

function createEchoTool(name: string = "echo"): McpToolDefinition {
  return {
    name,
    description: "Echo tool for testing",
    objectName: "test-object",
    execute: async (args) => args,
  };
}

describe("SecureMcpToolWrapper", () => {
  describe("tool registration", () => {
    it("should register and list tools", () => {
      const wrapper = new SecureMcpToolWrapper();
      const tool = createEchoTool();
      wrapper.registerTool(tool);

      const tools = wrapper.listTools();
      expect(tools.length).toBe(1);
      expect(tools[0].name).toBe("echo");
    });

    it("should throw for unknown tools", async () => {
      const wrapper = new SecureMcpToolWrapper();
      await expect(
        wrapper.executeTool({
          toolName: "nonexistent",
          headers: {},
        }),
      ).rejects.toThrow("Unknown tool");
    });
  });

  describe("disabled mode", () => {
    it("should execute without enforcement in disabled mode", async () => {
      const wrapper = new SecureMcpToolWrapper({
        mode: EnforcementMode.Disabled,
      });
      wrapper.registerTool(createEchoTool());

      const result = await wrapper.executeTool({
        toolName: "echo",
        arguments: { message: "hello" },
      });

      expect(result).toEqual({ message: "hello" });
    });
  });

  describe("strict mode enforcement", () => {
    it("should deny access when identity is missing", async () => {
      const wrapper = new SecureMcpToolWrapper({
        mode: EnforcementMode.Strict,
        identityExtractor: new HeaderIdentityExtractor(),
        resolvePolicy: async () => createTestPolicy(),
      });
      wrapper.registerTool(createEchoTool());

      await expect(
        wrapper.executeTool({
          toolName: "echo",
          headers: {},
        }),
      ).rejects.toThrow("Access denied");
    });

    it("should allow access when policy permits", async () => {
      const policy = createTestPolicy({
        objectRules: {
          allowedObjects: ["test-object"],
        },
      });

      const wrapper = new SecureMcpToolWrapper({
        mode: EnforcementMode.Strict,
        identityExtractor: new HeaderIdentityExtractor(),
        resolvePolicy: async () => policy,
      });
      wrapper.registerTool(createEchoTool());

      const result = await wrapper.executeTool({
        toolName: "echo",
        headers: {
          "x-user-id": "user-001",
          "x-tenant-id": "tenant-001",
        },
        arguments: { data: "test" },
      });

      expect(result).toEqual({ data: "test" });
    });

    it("should deny access when object is hidden", async () => {
      const policy = createTestPolicy({
        objectRules: {
          hiddenObjects: ["test-object"],
        },
      });

      const wrapper = new SecureMcpToolWrapper({
        mode: EnforcementMode.Strict,
        identityExtractor: new HeaderIdentityExtractor(),
        resolvePolicy: async () => policy,
      });
      wrapper.registerTool(createEchoTool());

      await expect(
        wrapper.executeTool({
          toolName: "echo",
          headers: {
            "x-user-id": "user-001",
            "x-tenant-id": "tenant-001",
          },
        }),
      ).rejects.toThrow("object is hidden");
    });

    it("should deny when canQuery is false", async () => {
      const policy = createTestPolicy({
        permissions: { canQuery: false },
      });

      const wrapper = new SecureMcpToolWrapper({
        mode: EnforcementMode.Strict,
        identityExtractor: new HeaderIdentityExtractor(),
        resolvePolicy: async () => policy,
      });
      wrapper.registerTool(createEchoTool());

      await expect(
        wrapper.executeTool({
          toolName: "echo",
          headers: {
            "x-user-id": "user-001",
            "x-tenant-id": "tenant-001",
          },
        }),
      ).rejects.toThrow("query not permitted");
    });

    it("should deny when policy is expired", async () => {
      const policy = createTestPolicy({
        expiresAt: new Date(Date.now() - 3600000).toISOString(),
      });

      const wrapper = new SecureMcpToolWrapper({
        mode: EnforcementMode.Strict,
        identityExtractor: new HeaderIdentityExtractor(),
        resolvePolicy: async () => policy,
      });
      wrapper.registerTool(createEchoTool());

      await expect(
        wrapper.executeTool({
          toolName: "echo",
          headers: {
            "x-user-id": "user-001",
            "x-tenant-id": "tenant-001",
          },
        }),
      ).rejects.toThrow("policy has expired");
    });
  });

  describe("post-execution enforcement", () => {
    it("should apply field masking to results", async () => {
      const policy = createTestPolicy({
        objectRules: {
          allowedObjects: ["test-object"],
          fieldRules: {
            maskedFields: [
              { field: "secret", maskType: "redact" },
            ],
          },
        },
      });

      const tool: McpToolDefinition = {
        name: "fetch",
        objectName: "test-object",
        execute: async () => ({ name: "visible", secret: "sensitive" }),
      };

      const wrapper = new SecureMcpToolWrapper({
        mode: EnforcementMode.Strict,
        identityExtractor: new HeaderIdentityExtractor(),
        resolvePolicy: async () => policy,
      });
      wrapper.registerTool(tool);

      const result = await wrapper.executeTool({
        toolName: "fetch",
        headers: {
          "x-user-id": "user-001",
          "x-tenant-id": "tenant-001",
        },
      });

      const record = result as Record<string, unknown>;
      expect(record["name"]).toBe("visible");
      expect(record["secret"]).toBe("[REDACTED]");
    });

    it("should apply result limits to array results", async () => {
      const policy = createTestPolicy({
        objectRules: { allowedObjects: ["test-object"] },
        limits: { maxResults: 2 },
      });

      const tool: McpToolDefinition = {
        name: "list",
        objectName: "test-object",
        execute: async () => [
          { id: 1 },
          { id: 2 },
          { id: 3 },
          { id: 4 },
        ],
      };

      const wrapper = new SecureMcpToolWrapper({
        mode: EnforcementMode.Strict,
        identityExtractor: new HeaderIdentityExtractor(),
        resolvePolicy: async () => policy,
      });
      wrapper.registerTool(tool);

      const result = await wrapper.executeTool({
        toolName: "list",
        headers: {
          "x-user-id": "user-001",
          "x-tenant-id": "tenant-001",
        },
      });

      expect(Array.isArray(result)).toBe(true);
      expect((result as unknown[]).length).toBe(2);
    });
  });

  describe("enforcement decisions", () => {
    it("should emit enforcement decisions", async () => {
      const decisions: EnforcementDecision[] = [];
      const policy = createTestPolicy({
        objectRules: { allowedObjects: ["test-object"] },
      });

      const wrapper = new SecureMcpToolWrapper({
        mode: EnforcementMode.Strict,
        identityExtractor: new HeaderIdentityExtractor(),
        resolvePolicy: async () => policy,
        onEnforcementDecision: (d) => decisions.push(d),
      });
      wrapper.registerTool(createEchoTool());

      await wrapper.executeTool({
        toolName: "echo",
        headers: {
          "x-user-id": "user-001",
          "x-tenant-id": "tenant-001",
        },
      });

      expect(decisions.length).toBe(1);
      expect(decisions[0].allowed).toBe(true);
      expect(decisions[0].toolName).toBe("echo");
    });
  });
});

describe("HeaderIdentityExtractor", () => {
  it("should extract identity from default headers", () => {
    const extractor = new HeaderIdentityExtractor();
    const request = {
      toolName: "test",
      headers: {
        "X-User-Id": "user-123",
        "X-Tenant-Id": "tenant-456",
      },
    };

    expect(extractor.extractUserId(request)).toBe("user-123");
    expect(extractor.extractTenantId(request)).toBe("tenant-456");
  });

  it("should extract identity from custom headers", () => {
    const extractor = new HeaderIdentityExtractor("x-custom-user", "x-custom-tenant");
    const request = {
      toolName: "test",
      headers: {
        "x-custom-user": "user-abc",
        "x-custom-tenant": "tenant-xyz",
      },
    };

    expect(extractor.extractUserId(request)).toBe("user-abc");
    expect(extractor.extractTenantId(request)).toBe("tenant-xyz");
  });

  it("should return undefined for missing headers", () => {
    const extractor = new HeaderIdentityExtractor();
    const request = { toolName: "test" };

    expect(extractor.extractUserId(request)).toBeUndefined();
    expect(extractor.extractTenantId(request)).toBeUndefined();
  });
});

describe("JwtIdentityExtractor", () => {
  const SECRET = "test-signing-secret-value";

  function signJwt(
    payload: Record<string, unknown>,
    secret: string,
    alg = "HS256",
  ): string {
    const algMap: Record<string, string> = {
      HS256: "sha256",
      HS384: "sha384",
      HS512: "sha512",
    };
    const header = Buffer.from(
      JSON.stringify({ alg, typ: "JWT" }),
    ).toString("base64url");
    const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
    const signature = createHmac(algMap[alg], secret)
      .update(`${header}.${body}`)
      .digest("base64url");
    return `${header}.${body}.${signature}`;
  }

  it("should extract identity from a validly signed JWT", () => {
    const extractor = new JwtIdentityExtractor({ secret: SECRET });
    const token = signJwt(
      { sub: "user-jwt-001", tenant_id: "tenant-jwt-001" },
      SECRET,
    );
    const request = {
      toolName: "test",
      headers: { Authorization: `Bearer ${token}` },
    };

    expect(extractor.extractUserId(request)).toBe("user-jwt-001");
    expect(extractor.extractTenantId(request)).toBe("tenant-jwt-001");
  });

  it("should throw when constructed without a secret or opt-in", () => {
    expect(() => new JwtIdentityExtractor()).toThrow(/secret/);
  });

  // A credential that was PRESENTED and found invalid must throw, not resolve as
  // anonymous (canonical spec §9). Returning undefined here would let a caller
  // treat an authentication failure as an anonymous request and resolve whatever a
  // default assignment grants -- the divergence that had .NET throwing while
  // Python and TypeScript silently degraded on the very same token.

  it("should throw on a tampered signature", () => {
    const extractor = new JwtIdentityExtractor({ secret: SECRET });
    const token = signJwt(
      { sub: "attacker", tenant_id: "victim" },
      "wrong-secret",
    );
    const request = {
      toolName: "test",
      headers: { Authorization: `Bearer ${token}` },
    };

    expect(() => extractor.extractUserId(request)).toThrow(
      IdentityExtractionError,
    );
    expect(() => extractor.extractTenantId(request)).toThrow(/signature/);
  });

  it("should throw on the 'none' algorithm", () => {
    const extractor = new JwtIdentityExtractor({ secret: SECRET });
    const header = Buffer.from(
      JSON.stringify({ alg: "none", typ: "JWT" }),
    ).toString("base64url");
    const body = Buffer.from(
      JSON.stringify({ sub: "attacker", tenant_id: "victim" }),
    ).toString("base64url");
    const request = {
      toolName: "test",
      headers: { Authorization: `Bearer ${header}.${body}.` },
    };

    expect(() => extractor.extractUserId(request)).toThrow(
      /algorithm not allowed/,
    );
  });

  it("should throw on an expired token", () => {
    const extractor = new JwtIdentityExtractor({ secret: SECRET });
    const token = signJwt(
      { sub: "user-001", tenant_id: "tenant-001", exp: 1 },
      SECRET,
    );
    const request = {
      toolName: "test",
      headers: { Authorization: `Bearer ${token}` },
    };

    expect(() => extractor.extractUserId(request)).toThrow(/expired/);
  });

  it("should skip verification in explicit unverified mode", () => {
    const extractor = new JwtIdentityExtractor({ allowUnverified: true });
    const token = signJwt(
      { sub: "user-jwt-001", tenant_id: "tenant-jwt-001" },
      "any-key",
    );
    const request = {
      toolName: "test",
      headers: { Authorization: `Bearer ${token}` },
    };

    expect(extractor.extractUserId(request)).toBe("user-jwt-001");
  });

  it("should return undefined for missing Authorization header", () => {
    const extractor = new JwtIdentityExtractor({ secret: SECRET });
    const request = { toolName: "test", headers: {} };

    expect(extractor.extractUserId(request)).toBeUndefined();
    expect(extractor.extractTenantId(request)).toBeUndefined();
  });

  it("should throw for a malformed JWT", () => {
    // Presented but structurally invalid: an attacker sending garbage must not be
    // treated the same as a caller sending no credential at all.
    const extractor = new JwtIdentityExtractor({ secret: SECRET });
    const request = {
      toolName: "test",
      headers: { Authorization: "Bearer invalid" },
    };

    expect(() => extractor.extractUserId(request)).toThrow(/Invalid JWT format/);
  });
});
