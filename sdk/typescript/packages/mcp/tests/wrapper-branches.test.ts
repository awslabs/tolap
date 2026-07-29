/**
 * Branch coverage for wrapper.ts and context-wrapper.ts.
 *
 * These two classes are the gate every MCP tool call passes through, so each
 * conditional below is driven from both sides and asserted against the spec's
 * required decision -- allow, or deny with a reason -- rather than merely reached.
 */

import { readFile } from "node:fs/promises";
import { describe, expect, it, vi } from "vitest";

import {
  buildSecurityContext,
  signContext,
  signPolicy,
  type EffectivePolicy,
  type SecurityContext,
} from "@tolap/core";
import { SecureMcpToolWrapper, warnIfEnforcementDisabled } from "../src/wrapper.js";
import { SecureContextToolWrapper } from "../src/context-wrapper.js";
import { HeaderIdentityExtractor } from "../src/extractors.js";
import { EnforcementMode } from "../src/types.js";
import type {
  EnforcementDecision,
  McpRequestContext,
  McpToolDefinition,
} from "../src/types.js";

const KEY = "wrapper-branch-key";

function policy(overrides: Partial<EffectivePolicy> = {}): EffectivePolicy {
  const now = new Date();
  return {
    version: "1.0",
    userId: "user-001",
    tenantId: "tenant-001",
    sourceConnectionId: "db:production:x",
    resolvedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 3_600_000).toISOString(),
    sourceProfiles: ["wrapper-branches"],
    permissions: { canQuery: true, canExport: false, readOnly: true },
    integrity: { algorithm: "none", signature: "" },
    ...overrides,
  };
}

const IDENTITY_HEADERS = { "x-user-id": "user-001", "x-tenant-id": "tenant-001" };

function request(overrides: Partial<McpRequestContext> = {}): McpRequestContext {
  return { toolName: "echo", headers: { ...IDENTITY_HEADERS }, ...overrides };
}

function tool(overrides: Partial<McpToolDefinition> = {}): McpToolDefinition {
  return {
    name: "echo",
    objectName: "test-object",
    execute: async (args) => args,
    ...overrides,
  };
}

function strictWrapper(
  resolved: EffectivePolicy,
  options: Partial<ConstructorParameters<typeof SecureMcpToolWrapper>[0]> = {},
  toolDef: McpToolDefinition = tool(),
) {
  const wrapper = new SecureMcpToolWrapper({
    mode: EnforcementMode.Strict,
    identityExtractor: new HeaderIdentityExtractor(),
    resolvePolicy: async () => resolved,
    ...options,
  });
  wrapper.registerTool(toolDef);
  return wrapper;
}

/** A policy that allows the default test object. */
const allowObject = () => policy({ objectRules: { allowedObjects: ["test-object"] } });

// ---------------------------------------------------------------------------
// warnIfEnforcementDisabled (threat-model R-6)
// ---------------------------------------------------------------------------

describe("warnIfEnforcementDisabled: every mode arm", () => {
  it("Strict does not warn", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    warnIfEnforcementDisabled(EnforcementMode.Strict);
    expect(warn).not.toHaveBeenCalled();
    warn.mockRestore();
  });

  it("Disabled warns that results are returned UNFILTERED", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    warnIfEnforcementDisabled(EnforcementMode.Disabled);
    expect(warn).toHaveBeenCalledOnce();
    // The message must say what is actually lost, not just that a mode is set.
    expect(warn.mock.calls[0][0]).toMatch(/unfiltered/);
    expect(warn.mock.calls[0][0]).toMatch(/disabled/);
    expect(warn.mock.calls[0][0]).toMatch(/MUST NOT be used in production/);
    warn.mockRestore();
  });

  it("AuditOnly warns that violations are logged but ALLOWED", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    warnIfEnforcementDisabled(EnforcementMode.AuditOnly);
    expect(warn).toHaveBeenCalledOnce();
    expect(warn.mock.calls[0][0]).toMatch(/access is allowed/);
    expect(warn.mock.calls[0][0]).toMatch(/audit-only/);
    warn.mockRestore();
  });

  it("the warning fires at CONSTRUCTION, not on the first denial", () => {
    // A service whose policies happen not to deny anything during a smoke test
    // would otherwise ship silently.
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    new SecureMcpToolWrapper({ mode: EnforcementMode.Disabled });
    expect(warn).toHaveBeenCalledOnce();
    warn.mockRestore();
  });

  it("the default mode is Strict, so a bare constructor does not warn", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    new SecureMcpToolWrapper();
    new SecureMcpToolWrapper({});
    expect(warn).not.toHaveBeenCalled();
    warn.mockRestore();
  });
});

// ---------------------------------------------------------------------------
// Tool registry
// ---------------------------------------------------------------------------

describe("tool registry", () => {
  it("registers, lists, and overwrites by name", () => {
    const wrapper = new SecureMcpToolWrapper();
    wrapper.registerTool(tool({ name: "a" }));
    wrapper.registerTool(tool({ name: "b" }));
    expect(wrapper.listTools().map((t) => t.name)).toEqual(["a", "b"]);

    wrapper.registerTool(tool({ name: "a", description: "replaced" }));
    expect(wrapper.listTools()).toHaveLength(2);
    expect(wrapper.listTools().find((t) => t.name === "a")?.description).toBe("replaced");
  });

  it("an empty registry lists nothing", () => {
    expect(new SecureMcpToolWrapper().listTools()).toEqual([]);
  });

  it("an unknown tool throws before any enforcement runs", async () => {
    const wrapper = new SecureMcpToolWrapper();
    await expect(wrapper.executeTool(request({ toolName: "ghost" }))).rejects.toThrow(
      "Unknown tool: ghost",
    );
  });
});

// ---------------------------------------------------------------------------
// Disabled mode
// ---------------------------------------------------------------------------

describe("Disabled mode bypasses enforcement entirely", () => {
  it("executes without identity, policy, or post-filtering", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const wrapper = new SecureMcpToolWrapper({ mode: EnforcementMode.Disabled });
    wrapper.registerTool(tool({ execute: async () => ({ ssn: "111-22-3333" }) }));

    // No headers, no resolvePolicy -- and the raw ssn comes straight back. This is
    // the documented behavior of the mode, which is exactly why it warns.
    expect(await wrapper.executeTool({ toolName: "echo" })).toEqual({
      ssn: "111-22-3333",
    });
    warn.mockRestore();
  });

  it("passes an absent arguments object through as {}", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const wrapper = new SecureMcpToolWrapper({ mode: EnforcementMode.Disabled });
    wrapper.registerTool(tool({ execute: async (args) => args }));

    expect(await wrapper.executeTool({ toolName: "echo" })).toEqual({});
    warn.mockRestore();
  });
});

// ---------------------------------------------------------------------------
// Identity resolution
// ---------------------------------------------------------------------------

describe("identity resolution: every missing-identity path", () => {
  const cases: Array<[string, McpRequestContext]> = [
    ["no headers at all", { toolName: "echo" }],
    ["empty headers", { toolName: "echo", headers: {} }],
    ["user id only", { toolName: "echo", headers: { "x-user-id": "user-001" } }],
    ["tenant id only", { toolName: "echo", headers: { "x-tenant-id": "tenant-001" } }],
    [
      "empty user id",
      { toolName: "echo", headers: { "x-user-id": "", "x-tenant-id": "tenant-001" } },
    ],
    [
      "empty tenant id",
      { toolName: "echo", headers: { "x-user-id": "user-001", "x-tenant-id": "" } },
    ],
  ];

  for (const [label, req] of cases) {
    it(`denies with ${label}`, async () => {
      const wrapper = strictWrapper(allowObject());
      await expect(wrapper.executeTool(req)).rejects.toThrow(/missing identity context/);
    });
  }

  it("denies when no identityExtractor is configured at all", async () => {
    const wrapper = new SecureMcpToolWrapper({
      mode: EnforcementMode.Strict,
      resolvePolicy: async () => allowObject(),
    });
    wrapper.registerTool(tool());

    await expect(wrapper.executeTool(request())).rejects.toThrow(
      /missing identity context/,
    );
  });

  it("allows when both identity headers are present", async () => {
    const wrapper = strictWrapper(allowObject());
    expect(await wrapper.executeTool(request({ arguments: { a: 1 } }))).toEqual({ a: 1 });
  });

  it("throws a configuration error when resolvePolicy is missing", async () => {
    // A configuration error, not a denial: the deployment is broken rather than the
    // caller being unauthorized.
    const wrapper = new SecureMcpToolWrapper({
      mode: EnforcementMode.Strict,
      identityExtractor: new HeaderIdentityExtractor(),
    });
    wrapper.registerTool(tool());

    await expect(wrapper.executeTool(request())).rejects.toThrow(
      /resolvePolicy function must be provided/,
    );
  });

  it("an absent sourceConnectionId is passed to resolvePolicy as an empty string", async () => {
    const seen: string[] = [];
    const wrapper = strictWrapper(allowObject(), {
      resolvePolicy: async (_u, _t, source) => {
        seen.push(source);
        return allowObject();
      },
    });

    await wrapper.executeTool(request());
    await wrapper.executeTool(request({ sourceConnectionId: "db:production:x" }));

    expect(seen).toEqual(["", "db:production:x"]);
  });
});

// ---------------------------------------------------------------------------
// Policy signature verification
// ---------------------------------------------------------------------------

describe("policy signature verification: both sides of the signingKey guard", () => {
  it("with no signingKey, an unsigned policy is accepted", async () => {
    const wrapper = strictWrapper(allowObject());
    expect(await wrapper.executeTool(request({ arguments: { a: 1 } }))).toEqual({ a: 1 });
  });

  it("with a signingKey, a correctly signed policy is accepted", async () => {
    const signedPolicy = signPolicy(allowObject(), KEY);
    const wrapper = strictWrapper(signedPolicy, { signingKey: KEY });

    expect(await wrapper.executeTool(request({ arguments: { a: 1 } }))).toEqual({ a: 1 });
  });

  it("with a signingKey, an UNSIGNED policy is denied", async () => {
    const wrapper = strictWrapper(allowObject(), { signingKey: KEY });
    await expect(wrapper.executeTool(request())).rejects.toThrow(
      /policy signature validation failed/,
    );
  });

  it("with a signingKey, a policy signed with the WRONG key is denied", async () => {
    const wrapper = strictWrapper(signPolicy(allowObject(), "other-key"), {
      signingKey: KEY,
    });
    await expect(wrapper.executeTool(request())).rejects.toThrow(
      /policy signature validation failed/,
    );
  });

  it("EXPLOIT: a tampered signed policy is denied", async () => {
    const tampered = signPolicy(allowObject(), KEY);
    tampered.permissions.canExport = true;
    const wrapper = strictWrapper(tampered, { signingKey: KEY });

    await expect(wrapper.executeTool(request())).rejects.toThrow(
      /policy signature validation failed/,
    );
  });

  it("a policy signed with an unimplemented algorithm is DENIED, not a crash", async () => {
    // ed25519 is in the schema's algorithm enum but unimplemented, so this is
    // reachable from a schema-valid policy. It must be a denial rather than an
    // exception escaping the enforcement check.
    const p = signPolicy(allowObject(), KEY);
    p.integrity.algorithm = "ed25519";
    const wrapper = strictWrapper(p, { signingKey: KEY });

    await expect(wrapper.executeTool(request())).rejects.toThrow(
      /policy signature validation failed/,
    );
  });
});

// ---------------------------------------------------------------------------
// Policy expiry -- fails closed on all three non-future forms
// ---------------------------------------------------------------------------

describe("policy expiry fails closed (spec §2)", () => {
  it("a future expiry is accepted", async () => {
    const wrapper = strictWrapper(allowObject());
    expect(await wrapper.executeTool(request({ arguments: { a: 1 } }))).toEqual({ a: 1 });
  });

  it("a past expiry is denied", async () => {
    const wrapper = strictWrapper(
      policy({
        objectRules: { allowedObjects: ["test-object"] },
        expiresAt: new Date(Date.now() - 3_600_000).toISOString(),
      }),
    );
    await expect(wrapper.executeTool(request())).rejects.toThrow(/policy has expired/);
  });

  it("EXPLOIT: an UNPARSEABLE expiry is denied, not silently skipped", async () => {
    // `new Date("never") <= new Date()` is `false` in JavaScript, so a bare
    // comparison granted an unbounded lifetime to any policy carrying a malformed
    // timestamp -- and the tool result came back unfiltered.
    for (const bad of ["never", "not-a-date", "2026-13-45T99:99:99Z", "soon"]) {
      expect(new Date(bad) <= new Date()).toBe(false); // the old verdict: "valid"

      const wrapper = strictWrapper(
        policy({ objectRules: { allowedObjects: ["test-object"] }, expiresAt: bad }),
        {},
        tool({ execute: async () => ({ ssn: "111-22-3333" }) }),
      );

      await expect(
        wrapper.executeTool(request()),
        `expiresAt=${bad} must be denied`,
      ).rejects.toThrow(/invalid expiry format/);
    }
  });

  it("EXPLOIT: a MISSING or empty expiry is denied, never 'never expires'", async () => {
    for (const missing of ["", undefined]) {
      const wrapper = strictWrapper(
        policy({
          objectRules: { allowedObjects: ["test-object"] },
          expiresAt: missing as unknown as string,
        }),
        {},
        tool({ execute: async () => ({ ssn: "111-22-3333" }) }),
      );

      await expect(
        wrapper.executeTool(request()),
        `expiresAt=${String(missing)} must be denied`,
      ).rejects.toThrow(/policy has no expiry/);
    }
  });

  it("an expiry exactly at now is expired (the comparison is <=)", async () => {
    const wrapper = strictWrapper(
      policy({
        objectRules: { allowedObjects: ["test-object"] },
        expiresAt: new Date().toISOString(),
      }),
    );
    await expect(wrapper.executeTool(request())).rejects.toThrow(/policy has expired/);
  });
});

// ---------------------------------------------------------------------------
// Pre-execution checks -- each optional tool field, present and absent
// ---------------------------------------------------------------------------

describe("pre-execution checks: each tool field, both ways", () => {
  it("a tool with NO objectName skips the object check", async () => {
    const wrapper = strictWrapper(
      policy({ objectRules: { allowedObjects: ["something-else"] } }),
      {},
      tool({ objectName: undefined }),
    );
    // The object check is what would have denied it, so skipping it must allow.
    expect(await wrapper.executeTool(request({ arguments: { a: 1 } }))).toEqual({ a: 1 });
  });

  it("a hidden object is denied and never executes the tool", async () => {
    let executed = false;
    const wrapper = strictWrapper(
      policy({ objectRules: { hiddenObjects: ["test-object"] } }),
      {},
      tool({
        execute: async () => {
          executed = true;
          return {};
        },
      }),
    );

    await expect(wrapper.executeTool(request())).rejects.toThrow(/object is hidden/);
    expect(executed).toBe(false);
  });

  it("an object outside the allow-list is denied", async () => {
    const wrapper = strictWrapper(
      policy({ objectRules: { allowedObjects: ["other"] } }),
    );
    await expect(wrapper.executeTool(request())).rejects.toThrow(
      /object not in allowed set/,
    );
  });

  it("canQuery: false is denied through the object check", async () => {
    const wrapper = strictWrapper(
      policy({
        permissions: { canQuery: false },
        objectRules: { allowedObjects: ["test-object"] },
      }),
    );
    await expect(wrapper.executeTool(request())).rejects.toThrow(/query not permitted/);
  });

  it("absent and EMPTY accessedFields both skip the PRE-execution field check", async () => {
    // The pre-check only inspects fields a caller volunteers, so declaring none
    // skips it -- and the tool still runs. Post-execution projection is what
    // actually protects the data here (spec §4): the result is projected to the
    // allow-list, which matches nothing, so it comes back empty rather than the
    // undeclared `a` leaking. That is the whole point of steps 5-6 existing.
    for (const accessedFields of [undefined, []]) {
      let executed = false;
      const wrapper = strictWrapper(
        policy({
          objectRules: {
            allowedObjects: ["test-object"],
            fieldRules: { allowedFields: ["nothing-matches"] },
          },
        }),
        {},
        tool({
          accessedFields,
          execute: async (args) => {
            executed = true;
            return args;
          },
        }),
      );

      // No denial: the pre-check was skipped.
      const result = await wrapper.executeTool(request({ arguments: { a: 1 } }));
      expect(executed, `accessedFields=${String(accessedFields)}`).toBe(true);
      // But the undeclared field does not survive the projection.
      expect(result).toEqual({});
    }
  });

  it("a declared-and-allowed field survives the projection", async () => {
    const wrapper = strictWrapper(
      policy({
        objectRules: {
          allowedObjects: ["test-object"],
          fieldRules: { allowedFields: ["a"] },
        },
      }),
      {},
      tool({ accessedFields: ["a"], execute: async (args) => args }),
    );

    expect(await wrapper.executeTool(request({ arguments: { a: 1 } }))).toEqual({ a: 1 });
  });

  it("a denied accessed field is refused and names the field", async () => {
    const wrapper = strictWrapper(
      policy({
        objectRules: {
          allowedObjects: ["test-object"],
          fieldRules: { hiddenFields: ["ssn"] },
        },
      }),
      {},
      tool({ accessedFields: ["id", "ssn"] }),
    );

    await expect(wrapper.executeTool(request())).rejects.toThrow(/denied fields: ssn/);
  });

  it("accessed fields that are all allowed pass the check", async () => {
    const wrapper = strictWrapper(
      policy({
        objectRules: {
          allowedObjects: ["test-object"],
          fieldRules: { allowedFields: ["id", "name"] },
        },
      }),
      {},
      tool({ accessedFields: ["id"], execute: async () => ({ id: 1 }) }),
    );

    expect(await wrapper.executeTool(request())).toEqual({ id: 1 });
  });

  it("a tool with NO endpointPath skips the endpoint check", async () => {
    const wrapper = strictWrapper(
      policy({
        objectRules: {
          allowedObjects: ["test-object"],
          endpointRules: { allowedEndpoints: ["/nothing"] },
        },
      }),
      {},
      tool({ endpointPath: undefined }),
    );

    expect(await wrapper.executeTool(request({ arguments: { a: 1 } }))).toEqual({ a: 1 });
  });

  it("an endpointPath outside the allow-list is denied", async () => {
    const wrapper = strictWrapper(
      policy({
        objectRules: {
          allowedObjects: ["test-object"],
          endpointRules: { allowedEndpoints: ["/allowed"] },
        },
      }),
      {},
      tool({ endpointPath: "/denied" }),
    );

    await expect(wrapper.executeTool(request())).rejects.toThrow(
      /endpoint not in allowed set/,
    );
  });

  it("endpointMethod defaults to GET when absent", async () => {
    // Denied under a POST-only policy precisely because the default is GET.
    // readOnly must also be false for the explicit POST to be permitted:
    // canonical spec §9 makes readOnly a ceiling over allowedMethods.
    const postOnly = policy({
      permissions: { canQuery: true, canExport: false, readOnly: false },
      objectRules: {
        allowedObjects: ["test-object"],
        endpointRules: { allowedEndpoints: ["/x"], allowedMethods: ["POST"] },
      },
    });

    const defaulted = strictWrapper(postOnly, {}, tool({ endpointPath: "/x" }));
    await expect(defaulted.executeTool(request())).rejects.toThrow(/method not allowed/);

    const explicit = strictWrapper(
      postOnly,
      {},
      tool({ endpointPath: "/x", endpointMethod: "POST", execute: async () => ({ ok: 1 }) }),
    );
    expect(await explicit.executeTool(request())).toEqual({ ok: 1 });
  });

  it("all three checks together allow a fully compliant call", async () => {
    const wrapper = strictWrapper(
      policy({
        objectRules: {
          allowedObjects: ["test-object"],
          fieldRules: { allowedFields: ["id"] },
          endpointRules: { allowedEndpoints: ["/x"], allowedMethods: ["GET"] },
        },
      }),
      {},
      tool({
        accessedFields: ["id"],
        endpointPath: "/x",
        endpointMethod: "GET",
        execute: async () => ({ id: 1 }),
      }),
    );

    expect(await wrapper.executeTool(request())).toEqual({ id: 1 });
  });
});

// ---------------------------------------------------------------------------
// Post-execution enforcement and the allowUnenforceableShapes opt-out
// ---------------------------------------------------------------------------

describe("post-execution enforcement", () => {
  const withResult = (result: unknown, options = {}) =>
    strictWrapper(
      policy({
        objectRules: {
          allowedObjects: ["test-object"],
          fieldRules: { hiddenFields: ["ssn"] },
        },
      }),
      options,
      tool({ execute: async () => result }),
    );

  it("runs the pipeline over a record and over an array of records", async () => {
    expect(await withResult({ id: 1, ssn: "x" }).executeTool(request())).toEqual({ id: 1 });
    expect(await withResult([{ id: 1, ssn: "x" }]).executeTool(request())).toEqual([
      { id: 1 },
    ]);
  });

  it("denies an unenforceable shape by default", async () => {
    for (const bad of ["a string", 42, null, undefined, [1, 2]]) {
      await expect(
        withResult(bad).executeTool(request()),
        `${String(bad)} must be denied`,
      ).rejects.toThrow(/cannot be policy-enforced/);
    }
  });

  it("allowUnenforceableShapes passes the shape through AND logs a warning", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const result = await withResult("a raw string", {
      allowUnenforceableShapes: true,
    }).executeTool(request());

    expect(result).toBe("a raw string");
    expect(warn).toHaveBeenCalledOnce();
    expect(warn.mock.calls[0][0]).toMatch(/enforcement bypassed/);
    expect(warn.mock.calls[0][0]).toMatch(/string/);
    warn.mockRestore();
  });

  it("allowUnenforceableShapes still ENFORCES an enforceable shape", async () => {
    // The opt-out is for shapes the pipeline cannot handle -- it must not become a
    // blanket bypass for records it can.
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    expect(
      await withResult({ id: 1, ssn: "x" }, { allowUnenforceableShapes: true }).executeTool(
        request(),
      ),
    ).toEqual({ id: 1 });
    expect(warn).not.toHaveBeenCalled();
    warn.mockRestore();
  });

  it("an empty array is enforceable and passes through", async () => {
    expect(await withResult([]).executeTool(request())).toEqual([]);
  });

  it("the tool receives {} when arguments are absent", async () => {
    const seen: unknown[] = [];
    const wrapper = strictWrapper(
      allowObject(),
      {},
      tool({
        execute: async (args) => {
          seen.push(args);
          return { ok: 1 };
        },
      }),
    );

    await wrapper.executeTool(request());
    expect(seen).toEqual([{}]);
  });
});

// ---------------------------------------------------------------------------
// Enforcement-decision callback
// ---------------------------------------------------------------------------

describe("enforcement decisions", () => {
  const collect = () => {
    const decisions: EnforcementDecision[] = [];
    return { decisions, onEnforcementDecision: (d: EnforcementDecision) => decisions.push(d) };
  };

  it("emits an allow decision carrying identity and mode", async () => {
    const { decisions, onEnforcementDecision } = collect();
    const wrapper = strictWrapper(allowObject(), { onEnforcementDecision });

    await wrapper.executeTool(request());

    expect(decisions).toHaveLength(1);
    expect(decisions[0]).toMatchObject({
      toolName: "echo",
      allowed: true,
      userId: "user-001",
      tenantId: "tenant-001",
      mode: EnforcementMode.Strict,
    });
    expect(decisions[0].reason).toBeUndefined();
    expect(Number.isNaN(new Date(decisions[0].timestamp).getTime())).toBe(false);
  });

  it("emits a deny decision carrying the reason and identity", async () => {
    const { decisions, onEnforcementDecision } = collect();
    const wrapper = strictWrapper(
      policy({ objectRules: { hiddenObjects: ["test-object"] } }),
      { onEnforcementDecision },
    );

    await expect(wrapper.executeTool(request())).rejects.toThrow();

    expect(decisions).toHaveLength(1);
    expect(decisions[0]).toMatchObject({
      allowed: false,
      reason: "object is hidden",
      userId: "user-001",
      tenantId: "tenant-001",
    });
  });

  it("a missing-identity denial emits a decision with no identity attached", async () => {
    const { decisions, onEnforcementDecision } = collect();
    const wrapper = strictWrapper(allowObject(), { onEnforcementDecision });

    await expect(wrapper.executeTool({ toolName: "echo", headers: {} })).rejects.toThrow();

    expect(decisions[0].allowed).toBe(false);
    expect(decisions[0].reason).toBe("missing identity context");
    expect(decisions[0].userId).toBeUndefined();
    expect(decisions[0].tenantId).toBeUndefined();
  });

  it("no callback configured is not an error", async () => {
    const wrapper = strictWrapper(allowObject());
    await expect(wrapper.executeTool(request())).resolves.toBeDefined();
  });

  it("the decision records the configured mode", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const { decisions, onEnforcementDecision } = collect();
    const wrapper = strictWrapper(allowObject(), {
      mode: EnforcementMode.AuditOnly,
      onEnforcementDecision,
    });

    await wrapper.executeTool(request());
    expect(decisions[0].mode).toBe(EnforcementMode.AuditOnly);
    warn.mockRestore();
  });

  it("AuditOnly still THROWS on a denial rather than allowing the call", async () => {
    // The enum USED to document AuditOnly as "log violations but allow access" while
    // the implementation denied exactly like Strict. Pinning the ACTUAL behavior was
    // the safe direction: loosening it to match the doc-comment would convert a denial
    // into an allow, which is precisely the fail-open shape this whole hardening effort
    // exists to remove. Resolved by correcting the comment, not the code -- the enum now
    // states that AuditOnly denies and does not grant access (spec §6 / threat-model
    // R-6). This test is what keeps that true.
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const wrapper = strictWrapper(
      policy({ objectRules: { hiddenObjects: ["test-object"] } }),
      { mode: EnforcementMode.AuditOnly },
    );

    await expect(wrapper.executeTool(request())).rejects.toThrow(/object is hidden/);
    warn.mockRestore();
  });

  it("AuditOnly denies for the same reasons Strict does, and still emits the decision", async () => {
    // The observable difference between the modes is the warning at construction and
    // the `mode` field on the emitted decision -- not whether access is granted.
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const { decisions, onEnforcementDecision } = collect();

    for (const mode of [EnforcementMode.Strict, EnforcementMode.AuditOnly]) {
      const wrapper = strictWrapper(
        policy({ permissions: { canQuery: false } }),
        { mode, onEnforcementDecision },
      );
      await expect(wrapper.executeTool(request())).rejects.toThrow(/query not permitted/);
    }

    expect(decisions.map((d) => d.mode)).toEqual([
      EnforcementMode.Strict,
      EnforcementMode.AuditOnly,
    ]);
    expect(decisions.every((d) => d.allowed === false)).toBe(true);
    warn.mockRestore();
  });

  it("a denial with no reason still produces a message", async () => {
    // validateAccess always supplies a reason, so this drives the `?? "unknown
    // reason"` fallback through a resolver that denies without one.
    const wrapper = strictWrapper(
      policy({ objectRules: { allowedObjects: ["other"] } }),
    );
    await expect(wrapper.executeTool(request())).rejects.toThrow(
      /Access denied for tool "echo":/,
    );
  });

  it("the AuditOnly doc-comment does not claim it allows access", async () => {
    // The behavioral tests above pin what AuditOnly DOES; this pins what the enum
    // SAYS, because the defect was a documentation lie rather than a code bug. The
    // comment read "Log violations but allow access", so an integrator could
    // reasonably have shipped it as a soft-launch mode -- and anyone who then "fixed"
    // the code to match would have converted every denial into an allow.
    //
    // Asserted against the source text because a doc-comment has no runtime
    // representation, and a comment nothing checks is exactly what drifted.
    const source = await readFile(
      new URL("../src/types.ts", import.meta.url),
      "utf8",
    );
    const auditOnly = source.slice(
      source.indexOf("Strict = \"strict\""),
      source.indexOf("AuditOnly ="),
    );

    expect(auditOnly).toMatch(/does \*\*NOT\*\* grant access|does not grant access/i);
    expect(auditOnly).toMatch(/den(y|ies)/i);
    // The original wording, and any paraphrase of it, must not come back.
    expect(auditOnly).not.toMatch(/but allow access/i);
  });
});

// ---------------------------------------------------------------------------
// SecureContextToolWrapper
// ---------------------------------------------------------------------------

describe("SecureContextToolWrapper: preExecute gates", () => {
  const signed = (p: EffectivePolicy, ttlMs = 3_600_000): SecurityContext =>
    signContext(buildSecurityContext(p.userId, p.tenantId, p, ttlMs), KEY);

  const wrapper = (options: Record<string, unknown> = {}) =>
    new SecureContextToolWrapper({ signingKey: KEY, ...options });

  it("allows a valid context and tool", () => {
    expect(wrapper().preExecute(signed(policy()), { toolName: "t" })).toEqual({
      allowed: true,
    });
  });

  it("denies an unsigned context on the signature", () => {
    expect(
      wrapper().preExecute(buildSecurityContext("u", "t", policy(), 3_600_000), {
        toolName: "t",
      }),
    ).toEqual({ allowed: false, reason: "invalid signature" });
  });

  it("enforceSignatures: false accepts an unsigned context", () => {
    expect(
      wrapper({ enforceSignatures: false }).preExecute(
        buildSecurityContext("u", "t", policy(), 3_600_000),
        { toolName: "t" },
      ),
    ).toEqual({ allowed: true });
  });

  it("denies an expired context, and enforceExpiry: false accepts it", () => {
    expect(wrapper().preExecute(signed(policy(), -1000), { toolName: "t" })).toEqual({
      allowed: false,
      reason: "security context expired",
    });
    expect(
      wrapper({ enforceExpiry: false }).preExecute(signed(policy(), -1000), {
        toolName: "t",
      }),
    ).toEqual({ allowed: true });
  });

  it("a missing or unparseable expiry is a denial", () => {
    for (const [expiresAt, reason] of [
      ["", "security context has no expiry"],
      ["never", "invalid expiry format"],
    ] as const) {
      const ctx: SecurityContext = {
        effectivePolicy: policy(),
        resolvedAt: new Date().toISOString(),
        expiresAt,
      };
      signContext(ctx, KEY);
      expect(wrapper().preExecute(ctx, { toolName: "t" })).toEqual({
        allowed: false,
        reason,
      });
    }
  });

  it("allowedTools: absent and EMPTY both mean unrestricted", () => {
    // An empty list here is "no tool allow-list configured", matching Python's
    // `if self._options.allowed_tools and ...`.
    expect(wrapper().preExecute(signed(policy()), { toolName: "anything" })).toEqual({
      allowed: true,
    });
    expect(
      wrapper({ allowedTools: [] }).preExecute(signed(policy()), { toolName: "anything" }),
    ).toEqual({ allowed: true });
  });

  it("a non-empty allowedTools admits a listed tool and refuses an unlisted one", () => {
    const w = wrapper({ allowedTools: ["allowed"] });
    expect(w.preExecute(signed(policy()), { toolName: "allowed" })).toEqual({
      allowed: true,
    });
    expect(w.preExecute(signed(policy()), { toolName: "other" })).toEqual({
      allowed: false,
      reason: "tool not in allowed list",
    });
  });

  it("canQuery: false is denied", () => {
    expect(
      wrapper().preExecute(signed(policy({ permissions: { canQuery: false } })), {
        toolName: "t",
      }),
    ).toEqual({ allowed: false, reason: "query not permitted" });
  });

  it("objectName is checked when present and skipped when absent", () => {
    const scoped = policy({ objectRules: { allowedObjects: ["patients"] } });
    expect(
      wrapper().preExecute(signed(scoped), { toolName: "t", objectName: "patients" }),
    ).toEqual({ allowed: true });
    expect(
      wrapper().preExecute(signed(scoped), { toolName: "t", objectName: "billing" }),
    ).toEqual({ allowed: false, reason: "object not in allowed set" });
    // Absent objectName skips the check that would otherwise have denied.
    expect(wrapper().preExecute(signed(scoped), { toolName: "t" })).toEqual({
      allowed: true,
    });
  });

  it("fields are checked when non-empty and skipped when absent or empty", () => {
    const hidden = policy({
      objectRules: { fieldRules: { hiddenFields: ["ssn"] } },
    });
    expect(
      wrapper().preExecute(signed(hidden), { toolName: "t", fields: ["ssn"] }),
    ).toEqual({ allowed: false, reason: "denied fields: ssn" });
    expect(
      wrapper().preExecute(signed(hidden), { toolName: "t", fields: ["id"] }),
    ).toEqual({ allowed: true });
    expect(wrapper().preExecute(signed(hidden), { toolName: "t", fields: [] })).toEqual({
      allowed: true,
    });
  });

  it("endpointPath is checked when present, and endpointMethod defaults to GET", () => {
    // readOnly false so the explicit POST is reachable: canonical spec §9 makes
    // readOnly a ceiling that allowedMethods cannot lift.
    const postOnly = policy({
      permissions: { canQuery: true, canExport: false, readOnly: false },
      objectRules: {
        endpointRules: { allowedEndpoints: ["/x"], allowedMethods: ["POST"] },
      },
    });
    expect(
      wrapper().preExecute(signed(postOnly), { toolName: "t", endpointPath: "/x" }),
    ).toEqual({ allowed: false, reason: "method not allowed" });
    expect(
      wrapper().preExecute(signed(postOnly), {
        toolName: "t",
        endpointPath: "/x",
        endpointMethod: "POST",
      }),
    ).toEqual({ allowed: true });
    // Absent endpointPath skips the check entirely.
    expect(wrapper().preExecute(signed(postOnly), { toolName: "t" })).toEqual({
      allowed: true,
    });
  });
});

describe("SecureContextToolWrapper: postExecute and executeWithEnforcement", () => {
  const signed = (p: EffectivePolicy, ttlMs = 3_600_000): SecurityContext =>
    signContext(buildSecurityContext(p.userId, p.tenantId, p, ttlMs), KEY);

  const hidesSsn = () =>
    policy({ objectRules: { fieldRules: { hiddenFields: ["ssn"] } } });

  it("postExecute runs the pipeline over records and a single record", () => {
    const w = new SecureContextToolWrapper({ signingKey: KEY });
    const ctx = signed(hidesSsn());

    expect(w.postExecute(ctx, [{ id: 1, ssn: "x" }])).toEqual([{ id: 1 }]);
    expect(w.postExecute(ctx, { id: 1, ssn: "x" } as unknown)).toEqual({ id: 1 });
  });

  it("postExecute denies an unenforceable shape by default", () => {
    const w = new SecureContextToolWrapper({ signingKey: KEY });
    expect(() => w.postExecute(signed(hidesSsn()), "a string")).toThrow(
      /cannot be policy-enforced/,
    );
  });

  it("postExecute honours allowUnenforceableShapes and logs", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const w = new SecureContextToolWrapper({
      signingKey: KEY,
      allowUnenforceableShapes: true,
    });

    expect(w.postExecute(signed(hidesSsn()), 42)).toBe(42);
    expect(warn).toHaveBeenCalledOnce();
    expect(warn.mock.calls[0][0]).toMatch(/enforcement bypassed/);
    warn.mockRestore();
  });

  it("executeWithEnforcement runs the tool and filters its result", async () => {
    const w = new SecureContextToolWrapper({ signingKey: KEY });
    const out = await w.executeWithEnforcement(
      signed(hidesSsn()),
      { toolName: "t" },
      async () => [{ id: 1, ssn: "x" }],
    );

    expect(out).toEqual([{ id: 1 }]);
  });

  it("executeWithEnforcement accepts a SYNCHRONOUS tool function", async () => {
    const w = new SecureContextToolWrapper({ signingKey: KEY });
    const out = await w.executeWithEnforcement(signed(hidesSsn()), { toolName: "t" }, () => [
      { id: 1, ssn: "x" },
    ]);

    expect(out).toEqual([{ id: 1 }]);
  });

  it("executeWithEnforcement throws on a pre-execution denial and never runs the tool", async () => {
    const w = new SecureContextToolWrapper({ signingKey: KEY });
    let ran = false;

    await expect(
      w.executeWithEnforcement(
        signed(policy({ permissions: { canQuery: false } })),
        { toolName: "t" },
        async () => {
          ran = true;
          return [];
        },
      ),
    ).rejects.toThrow(/Access denied: query not permitted/);
    expect(ran).toBe(false);
  });

  it("a denial with no reason still yields an actionable message", async () => {
    const w = new SecureContextToolWrapper({ signingKey: KEY });
    await expect(
      w.executeWithEnforcement(
        buildSecurityContext("u", "t", policy(), 3_600_000),
        { toolName: "t" },
        async () => [],
      ),
    ).rejects.toThrow(/Access denied: invalid signature/);
  });
});
