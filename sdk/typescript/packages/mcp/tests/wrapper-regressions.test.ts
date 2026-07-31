/**
 * Regression tests for post-execution enforcement in every wrapper.
 *
 * One describe block per confirmed defect in docs/canonical-enforcement-spec.md.
 * These cover the wrapper surfaces specifically: SecureMcpToolWrapper (MCP tool
 * discovery + identity), SecureContextToolWrapper (signed-context callers), and
 * SecureHttpToolWrapper (JSON bodies). The core-level pipeline behaviour is
 * covered in @tolap/core's enforcement-pipeline tests.
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import {
  buildSecurityContext,
  signContext,
  UnenforceableResultError,
  type EffectivePolicy,
  type SecurityContext,
} from "@tolap/core";
import {
  SecureMcpToolWrapper,
  warnIfEnforcementDisabled,
} from "../src/wrapper.js";
import { SecureContextToolWrapper } from "../src/context-wrapper.js";
import { SecureHttpToolWrapper, type FetchLike } from "../src/http-wrapper.js";
import { EnforcementMode, type McpToolDefinition } from "../src/types.js";
import { HeaderIdentityExtractor } from "../src/extractors.js";

const SIGNING_KEY = "wrapper-regression-key";
const HEADERS = { "x-user-id": "user-001", "x-tenant-id": "tenant-001" };

function createPolicy(overrides?: Partial<EffectivePolicy>): EffectivePolicy {
  return {
    version: "1.0",
    userId: "user-001",
    tenantId: "tenant-001",
    sourceConnectionId: "ds-test",
    resolvedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    sourceProfiles: ["regression-test"],
    permissions: { canQuery: true, readOnly: true },
    integrity: { algorithm: "none", signature: "" },
    ...overrides,
  };
}

function signed(policy: EffectivePolicy): SecurityContext {
  const ctx = buildSecurityContext(policy.userId, policy.tenantId, policy);
  return signContext(ctx, SIGNING_KEY);
}

function mcpWrapper(
  policy: EffectivePolicy,
  tool: McpToolDefinition,
  extra: Record<string, unknown> = {},
): SecureMcpToolWrapper {
  const wrapper = new SecureMcpToolWrapper({
    mode: EnforcementMode.Strict,
    identityExtractor: new HeaderIdentityExtractor(),
    resolvePolicy: async () => policy,
    ...extra,
  });
  wrapper.registerTool(tool);
  return wrapper;
}

afterEach(() => {
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// Defect 1: hiddenFields were never stripped by the MCP / context wrappers
// ---------------------------------------------------------------------------

describe("defect 1: MCP wrapper strips hiddenFields from results", () => {
  it("LEAK: an array result no longer discloses a hidden column", () => {
    const policy = createPolicy({
      objectRules: {
        allowedObjects: ["patients"],
        fieldRules: { hiddenFields: ["ssn"] },
      },
    });
    const wrapper = mcpWrapper(policy, {
      name: "list-patients",
      objectName: "patients",
      execute: async () => [
        { id: 1, name: "John Smith", ssn: "111-22-3333" },
        { id: 2, name: "Jane Doe", ssn: "222-33-4444" },
      ],
    });

    return wrapper
      .executeTool({ toolName: "list-patients", headers: HEADERS })
      .then((result) => {
        const rows = result as Array<Record<string, unknown>>;
        expect(rows).toEqual([
          { id: 1, name: "John Smith" },
          { id: 2, name: "Jane Doe" },
        ]);
      });
  });

  it("LEAK: a single-record result no longer discloses a hidden column", async () => {
    const policy = createPolicy({
      objectRules: {
        allowedObjects: ["patients"],
        fieldRules: { hiddenFields: ["ssn"] },
      },
    });
    const wrapper = mcpWrapper(policy, {
      name: "get-patient",
      objectName: "patients",
      execute: async () => ({ id: 1, name: "John Smith", ssn: "111-22-3333" }),
    });

    const result = await wrapper.executeTool({
      toolName: "get-patient",
      headers: HEADERS,
    });

    expect(result).toEqual({ id: 1, name: "John Smith" });
  });

  it("the context wrapper strips hiddenFields too", () => {
    const policy = createPolicy({
      objectRules: { fieldRules: { hiddenFields: ["ssn"] } },
    });
    const wrapper = new SecureContextToolWrapper({ signingKey: SIGNING_KEY });

    const rows = wrapper.postExecute(signed(policy), [
      { id: 1, ssn: "111-22-3333" },
    ]);

    expect(rows).toEqual([{ id: 1 }]);
  });
});

// ---------------------------------------------------------------------------
// Defect 2: allowedFields were never enforced on results
// ---------------------------------------------------------------------------

describe("defect 2: wrappers project results to allowedFields", () => {
  it("LEAK: the MCP wrapper drops columns outside the allow-list", async () => {
    const policy = createPolicy({
      objectRules: {
        allowedObjects: ["patients"],
        fieldRules: { allowedFields: ["patients.id", "patients.name"] },
      },
    });
    const wrapper = mcpWrapper(policy, {
      name: "list-patients",
      objectName: "patients",
      execute: async () => [
        { id: 1, name: "John Smith", ssn: "111-22-3333", salary: 90_000 },
      ],
    });

    const result = await wrapper.executeTool({
      toolName: "list-patients",
      headers: HEADERS,
    });

    expect(result).toEqual([{ id: 1, name: "John Smith" }]);
  });

  it("the context wrapper projects to allowedFields", () => {
    const policy = createPolicy({
      objectRules: { fieldRules: { allowedFields: ["id"] } },
    });
    const wrapper = new SecureContextToolWrapper({ signingKey: SIGNING_KEY });

    const rows = wrapper.postExecute(signed(policy), [{ id: 1, ssn: "x" }]);

    expect(rows).toEqual([{ id: 1 }]);
  });

  it("the HTTP wrapper projects records while preserving the envelope", async () => {
    const policy = createPolicy({
      objectRules: {
        endpointRules: { allowedEndpoints: ["/drug/*"], allowedMethods: ["GET"] },
        fieldRules: { allowedFields: ["safetyreportid"] },
      },
    });
    const fetchFn: FetchLike = async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        meta: { disclaimer: "d", results: { total: 1 } },
        results: [{ safetyreportid: "1", patient: { patientsex: "2" } }],
      }),
    });
    const wrapper = new SecureHttpToolWrapper(
      { signingKey: SIGNING_KEY, baseUrl: "https://api.fda.gov" },
      fetchFn,
    );

    const body = (await wrapper.request(signed(policy), {
      method: "GET",
      path: "/drug/event.json",
      collectionPath: "results",
    })) as Record<string, any>;

    expect(body.results).toEqual([{ safetyreportid: "1" }]);
    expect(body.meta.disclaimer).toBe("d");
  });
});

// ---------------------------------------------------------------------------
// Defect 3: a single object result skipped row filters and tag filtering
// ---------------------------------------------------------------------------

describe("defect 3: a single object result runs the full pipeline", () => {
  it("LEAK: a get-by-id tool returning a denied-tag record is denied", async () => {
    // Previously the single-object branch applied applyFieldMasking only, so a
    // record tagged 'classified' under deniedTags: ['classified'] was returned
    // to the agent unfiltered.
    const policy = createPolicy({
      objectRules: {
        allowedObjects: ["documents"],
        tagRules: { deniedTags: ["classified"] },
      },
    });
    const wrapper = mcpWrapper(policy, {
      name: "get-document",
      objectName: "documents",
      execute: async () => ({
        id: "doc-3",
        title: "Classified Report",
        body: "top secret",
        tags: ["classified"],
      }),
    });

    const result = await wrapper.executeTool({
      toolName: "get-document",
      headers: HEADERS,
    });

    expect(result).toBeNull();
  });

  it("LEAK: a single record failing a row filter is denied", async () => {
    const policy = createPolicy({
      objectRules: {
        allowedObjects: ["patients"],
        rowFilters: [{ field: "region", operator: "equals", value: "us-east" }],
      },
    });
    const wrapper = mcpWrapper(policy, {
      name: "get-patient",
      objectName: "patients",
      execute: async () => ({ id: 5, region: "eu-west" }),
    });

    const result = await wrapper.executeTool({
      toolName: "get-patient",
      headers: HEADERS,
    });

    expect(result).toBeNull();
  });

  it("a single record that passes every filter is returned masked", async () => {
    const policy = createPolicy({
      objectRules: {
        allowedObjects: ["patients"],
        rowFilters: [{ field: "region", operator: "equals", value: "us-east" }],
        fieldRules: {
          hiddenFields: ["ssn"],
          maskedFields: [{ field: "email", maskType: "redact" }],
        },
      },
    });
    const wrapper = mcpWrapper(policy, {
      name: "get-patient",
      objectName: "patients",
      execute: async () => ({
        id: 1,
        region: "us-east",
        ssn: "111-22-3333",
        email: "john@example.com",
      }),
    });

    const result = await wrapper.executeTool({
      toolName: "get-patient",
      headers: HEADERS,
    });

    expect(result).toEqual({
      id: 1,
      region: "us-east",
      email: "[REDACTED]",
    });
  });
});

// ---------------------------------------------------------------------------
// Defect 6: unknown maskType failed open in the HTTP wrapper
// ---------------------------------------------------------------------------

describe("defect 6: the HTTP wrapper redacts an unknown maskType", () => {
  it("LEAK: an unrecognized maskType no longer returns the raw value", async () => {
    const policy = createPolicy({
      objectRules: {
        endpointRules: { allowedEndpoints: ["/drug/*"], allowedMethods: ["GET"] },
        fieldRules: {
          maskedFields: [{ field: "results.safetyreportid", maskType: "tokenize-v2" }],
        },
      },
    });
    const fetchFn: FetchLike = async () => ({
      ok: true,
      status: 200,
      json: async () => ({ results: [{ safetyreportid: "SECRET-1" }] }),
    });
    const wrapper = new SecureHttpToolWrapper(
      { signingKey: SIGNING_KEY, baseUrl: "https://api.fda.gov" },
      fetchFn,
    );

    const body = (await wrapper.request(signed(policy), {
      method: "GET",
      path: "/drug/event.json",
      collectionPath: "results",
    })) as Record<string, any>;

    expect(body.results[0].safetyreportid).toBe("[REDACTED]");
  });

  it("EXPLOIT: HTTP partial masking that would show everything degrades to a full mask", async () => {
    const policy = createPolicy({
      objectRules: {
        endpointRules: { allowedEndpoints: ["/drug/*"], allowedMethods: ["GET"] },
        fieldRules: {
          maskedFields: [
            {
              field: "results.safetyreportid",
              maskType: "partial",
              parameters: { showFirst: 100, showLast: 100 },
            },
          ],
        },
      },
    });
    const fetchFn: FetchLike = async () => ({
      ok: true,
      status: 200,
      json: async () => ({ results: [{ safetyreportid: "12345" }] }),
    });
    const wrapper = new SecureHttpToolWrapper(
      { signingKey: SIGNING_KEY, baseUrl: "https://api.fda.gov" },
      fetchFn,
    );

    const body = (await wrapper.request(signed(policy), {
      method: "GET",
      path: "/drug/event.json",
      collectionPath: "results",
    })) as Record<string, any>;

    expect(body.results[0].safetyreportid).toBe("*****");
  });
});

// ---------------------------------------------------------------------------
// Defect 5: expiry fails closed in every wrapper
// ---------------------------------------------------------------------------

describe("defect 5: wrapper expiry checks fail closed", () => {
  it("EXPLOIT: an unparseable expiry is denied by the context wrapper", () => {
    const policy = createPolicy();
    const ctx = signContext(
      {
        effectivePolicy: policy,
        resolvedAt: new Date().toISOString(),
        expiresAt: "never",
      },
      SIGNING_KEY,
    );
    const wrapper = new SecureContextToolWrapper({ signingKey: SIGNING_KEY });

    // The malformed expiry is inside the HMAC, so the signature is valid and
    // the expiry check is the only control that stops it.
    const result = wrapper.validateSecurityContext(ctx);
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("invalid expiry format");
  });

  it("a missing expiry is denied by the context wrapper", () => {
    const ctx = signContext(
      { effectivePolicy: createPolicy(), resolvedAt: new Date().toISOString() } as SecurityContext,
      SIGNING_KEY,
    );
    const wrapper = new SecureContextToolWrapper({ signingKey: SIGNING_KEY });

    expect(wrapper.validateSecurityContext(ctx).reason).toBe(
      "security context has no expiry",
    );
  });

  it("a missing expiry is denied by the HTTP wrapper", async () => {
    const policy = createPolicy({
      objectRules: {
        endpointRules: { allowedEndpoints: ["/drug/*"], allowedMethods: ["GET"] },
      },
    });
    const ctx = signContext(
      { effectivePolicy: policy, resolvedAt: new Date().toISOString() } as SecurityContext,
      SIGNING_KEY,
    );
    const calls: string[] = [];
    const fetchFn: FetchLike = async ({ url }) => {
      calls.push(url);
      return { ok: true, status: 200, json: async () => ({}) };
    };
    const wrapper = new SecureHttpToolWrapper(
      { signingKey: SIGNING_KEY, baseUrl: "https://api.fda.gov" },
      fetchFn,
    );

    await expect(
      wrapper.request(ctx, { method: "GET", path: "/drug/event.json" }),
    ).rejects.toThrow(/has no expiry/);
    expect(calls).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Defect 10: undeclared columns leaked past the static accessedFields pre-check
// ---------------------------------------------------------------------------

describe("defect 10: undeclared columns cannot leak past the pre-check", () => {
  it("LEAK: a tool declaring accessedFields:['name'] but returning ssn has ssn stripped", async () => {
    // The pre-check inspects only the fields the tool volunteers, so this tool
    // passes it. Post-execution stripping is what closes the leak.
    const policy = createPolicy({
      objectRules: {
        allowedObjects: ["patients"],
        fieldRules: { hiddenFields: ["ssn"] },
      },
    });
    const decisions: boolean[] = [];
    const wrapper = mcpWrapper(
      policy,
      {
        name: "select-star",
        objectName: "patients",
        accessedFields: ["name"], // declared
        execute: async () => [{ name: "John Smith", ssn: "111-22-3333" }], // returned
      },
      { onEnforcementDecision: (d: { allowed: boolean }) => decisions.push(d.allowed) },
    );

    const result = await wrapper.executeTool({
      toolName: "select-star",
      headers: HEADERS,
    });

    expect(decisions).toEqual([true]); // pre-check allowed the call
    expect(result).toEqual([{ name: "John Smith" }]); // ssn still stripped
  });
});

// ---------------------------------------------------------------------------
// Defect 12: prototype pollution surface in the HTTP body walkers
// ---------------------------------------------------------------------------

describe("defect 12: the HTTP walkers skip dangerous keys", () => {
  type MaskedFields = NonNullable<
    NonNullable<EffectivePolicy["objectRules"]>["fieldRules"]
  >["maskedFields"];

  async function requestWith(
    maskedFields: MaskedFields,
    body: unknown,
  ): Promise<unknown> {
    const policy = createPolicy({
      objectRules: {
        endpointRules: { allowedEndpoints: ["/drug/*"], allowedMethods: ["GET"] },
        fieldRules: { maskedFields },
      },
    });
    const fetchFn: FetchLike = async () => ({
      ok: true,
      status: 200,
      json: async () => body,
    });
    const wrapper = new SecureHttpToolWrapper(
      { signingKey: SIGNING_KEY, baseUrl: "https://api.fda.gov" },
      fetchFn,
    );
    return wrapper.request(signed(policy), {
      method: "GET",
      path: "/drug/event.json",
      collectionPath: "results",
    });
  }

  it("EXPLOIT: a __proto__ masking rule no longer reassigns an object's prototype", async () => {
    // Pre-fix the walker did `node["__proto__"] = applyMask(...)`. With
    // maskType 'null' that is `node.__proto__ = null`, which strips the
    // prototype of every record it walks -- the record stops being an ordinary
    // object mid-pipeline. The key is now skipped instead.
    const result = (await requestWith(
      [{ field: "results.__proto__", maskType: "null" }],
      { results: [{ id: 1 }] },
    )) as Record<string, any>;

    expect(Object.getPrototypeOf(result.results[0])).toBe(Object.prototype);
  });

  it("EXPLOIT: a constructor masking rule no longer shadows the constructor", async () => {
    const result = (await requestWith(
      [{ field: "results.constructor", maskType: "null" }],
      { results: [{ id: 1 }] },
    )) as Record<string, any>;

    expect(
      Object.prototype.hasOwnProperty.call(result.results[0], "constructor"),
    ).toBe(false);
    expect(result.results[0].constructor).toBe(Object);
  });

  it("a hostile __proto__ payload key does not pollute Object.prototype", async () => {
    const result = (await requestWith(
      [{ field: "__proto__.polluted", maskType: "redact" }],
      JSON.parse('{"results":[{"id":1}],"__proto__":{"polluted":"yes"}}'),
    )) as Record<string, any>;

    expect(({} as Record<string, unknown>)["polluted"]).toBeUndefined();
    expect(Object.prototype).not.toHaveProperty("polluted");
    expect(result.results).toEqual([{ id: 1 }]);
  });
});

// ---------------------------------------------------------------------------
// Defect 13: result shapes fail closed
// ---------------------------------------------------------------------------

describe("defect 13: unenforceable result shapes are denied by the wrappers", () => {
  const badResults: Array<[string, unknown]> = [
    ["scalar-string", "just a string"],
    ["scalar-number", 42],
    ["scalar-boolean", false],
    ["null", null],
    ["undefined", undefined],
    ["array-of-scalars", [1, 2, 3]],
    ["mixed-array", [{ a: 1 }, "not a record"]],
  ];

  for (const [label, bad] of badResults) {
    it(`the MCP wrapper denies ${label}`, async () => {
      const policy = createPolicy({
        objectRules: {
          allowedObjects: ["patients"],
          fieldRules: { hiddenFields: ["ssn"] },
        },
      });
      const wrapper = mcpWrapper(policy, {
        name: "odd-tool",
        objectName: "patients",
        execute: async () => bad,
      });

      await expect(
        wrapper.executeTool({ toolName: "odd-tool", headers: HEADERS }),
      ).rejects.toThrow(/cannot be policy-enforced/);
    });
  }

  it("the denial names the observed shape", async () => {
    const policy = createPolicy({ objectRules: { allowedObjects: ["patients"] } });
    const wrapper = mcpWrapper(policy, {
      name: "scalar-tool",
      objectName: "patients",
      execute: async () => "a string",
    });

    await expect(
      wrapper.executeTool({ toolName: "scalar-tool", headers: HEADERS }),
    ).rejects.toThrow(/string \(not a record or array of records\)/);
  });

  it("the context wrapper denies an unenforceable shape", () => {
    const wrapper = new SecureContextToolWrapper({ signingKey: SIGNING_KEY });
    const ctx = signed(createPolicy());

    expect(() => wrapper.postExecute(ctx, "a string")).toThrow(
      UnenforceableResultError,
    );
  });

  it("allowUnenforceableShapes defaults to off", async () => {
    const policy = createPolicy({ objectRules: { allowedObjects: ["patients"] } });
    const wrapper = mcpWrapper(policy, {
      name: "scalar-tool",
      objectName: "patients",
      execute: async () => "a string",
    });

    await expect(
      wrapper.executeTool({ toolName: "scalar-tool", headers: HEADERS }),
    ).rejects.toThrow(/Access denied/);
  });

  it("allowUnenforceableShapes passes the shape through and logs a warning", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const policy = createPolicy({
      objectRules: {
        allowedObjects: ["patients"],
        fieldRules: { hiddenFields: ["ssn"] },
      },
    });
    const wrapper = mcpWrapper(
      policy,
      {
        name: "scalar-tool",
        objectName: "patients",
        execute: async () => "a string",
      },
      { allowUnenforceableShapes: true },
    );

    const result = await wrapper.executeTool({
      toolName: "scalar-tool",
      headers: HEADERS,
    });

    expect(result).toBe("a string");
    expect(warn).toHaveBeenCalledOnce();
    expect(warn.mock.calls[0][0]).toContain("allowUnenforceableShapes");
  });

  it("the context wrapper honours allowUnenforceableShapes and logs", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const wrapper = new SecureContextToolWrapper({
      signingKey: SIGNING_KEY,
      allowUnenforceableShapes: true,
    });

    expect(wrapper.postExecute(signed(createPolicy()), 42)).toBe(42);
    expect(warn).toHaveBeenCalledOnce();
  });

  it("an empty array is enforceable and passes through", async () => {
    const policy = createPolicy({
      objectRules: {
        allowedObjects: ["patients"],
        fieldRules: { hiddenFields: ["ssn"] },
      },
    });
    const wrapper = mcpWrapper(policy, {
      name: "empty-tool",
      objectName: "patients",
      execute: async () => [],
    });

    await expect(
      wrapper.executeTool({ toolName: "empty-tool", headers: HEADERS }),
    ).resolves.toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Threat-model R-6: a wrapper that cannot deny must warn at startup
// ---------------------------------------------------------------------------

describe("threat-model R-6: non-enforcing modes warn loudly", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("Disabled mode warns when a wrapper is constructed", () => {
    // EnforcementMode.Disabled skips enforcement entirely, so a deployment that
    // reaches production still carrying it has no enforcement at all while
    // continuing to look configured. Warned at construction rather than on the
    // first denial: a service whose policies happen not to deny anything during a
    // smoke test would otherwise ship silently.
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

    new SecureMcpToolWrapper({ mode: EnforcementMode.Disabled });

    expect(warn).toHaveBeenCalledOnce();
    expect(warn.mock.calls[0][0]).toContain("NOT enforcing");
    expect(warn.mock.calls[0][0]).toContain("MUST NOT be used in production");
  });

  it("AuditOnly mode warns when a wrapper is constructed", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

    new SecureMcpToolWrapper({ mode: EnforcementMode.AuditOnly });

    expect(warn).toHaveBeenCalledOnce();
    expect(warn.mock.calls[0][0]).toContain("NOT enforcing");
  });

  it("Strict mode does not warn", () => {
    // The warning must stay silent on the safe default, or it becomes noise that
    // integrators filter out and then miss when it matters.
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

    new SecureMcpToolWrapper({ mode: EnforcementMode.Strict });
    // The default is Strict too, so an options-free construction is also silent.
    new SecureMcpToolWrapper();

    expect(warn).not.toHaveBeenCalled();
  });

  it("warnIfEnforcementDisabled names the mode it is warning about", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

    warnIfEnforcementDisabled(EnforcementMode.Disabled);

    expect(warn.mock.calls[0][0]).toContain(EnforcementMode.Disabled);
  });
});
