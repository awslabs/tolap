/**
 * A tool can declare its result already enforced (issue #33).
 *
 * `hash` masking is not idempotent: when a data layer has already run the result
 * pipeline, running it again in `executeWithEnforcement` hashes every hashed field a
 * second time. A tool opts out by returning `EnforcedResult`, bound to the signed
 * context's signature. Only `executeWithEnforcement` honours the marker, and only on
 * an exact, constant-time match. It still re-applies the steps that are no-ops over
 * enforced output: filters on visible fields, the hidden-field strip, the
 * allowed-field projection and maxResults. Every other marker, and every marker on
 * another path, falls back to the full pipeline.
 *
 * The shared cases in `fixtures/enforcement/already-enforced-results.json` hold the
 * Python and .NET SDKs to the same results.
 */

import fs from "node:fs";
import path from "node:path";
import { inspect } from "node:util";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  EnforcedResult,
  ToolCallHistory,
  applyResultPipeline,
  buildSecurityContext,
  signContext,
  type EffectivePolicy,
  type SecurityContext,
} from "@aws/tolap-core";
import { SecureContextToolWrapper } from "../src/context-wrapper.js";
import { HeaderIdentityExtractor } from "../src/extractors.js";
import { EnforcementMode } from "../src/types.js";
import { SecureMcpToolWrapper } from "../src/wrapper.js";

type Row = Record<string, unknown>;

interface Case {
  name: string;
  policy: Row;
  marker: "context" | "otherContext" | "tampered" | "empty" | null;
  data: unknown;
  expected?: unknown;
  expectDenied?: boolean;
}

interface Fixture {
  signingKey: string;
  context: { userId: string; tenantId: string };
  otherContext: { userId: string; tenantId: string };
  cases: Case[];
}

const FIXTURE = JSON.parse(
  fs.readFileSync(
    path.resolve(
      __dirname,
      "../../../../../fixtures/enforcement/already-enforced-results.json",
    ),
    "utf-8",
  ),
) as Fixture;
const KEY = FIXTURE.signingKey;
const POLICY_A = FIXTURE.cases[0].policy;
const PLACEHOLDER = "$CONTEXT_SIGNATURE";

function toPolicy(partial: Row, who = FIXTURE.context): EffectivePolicy {
  return {
    userId: who.userId,
    tenantId: who.tenantId,
    sourceConnectionId: "test-source",
    resolvedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    sourceProfiles: [],
    ...structuredClone(partial),
  } as EffectivePolicy;
}

function makeContext(partial: Row, who = FIXTURE.context, jti?: string): SecurityContext {
  return signContext(
    buildSecurityContext(who.userId, who.tenantId, toPolicy(partial, who), 3_600_000, jti),
    KEY,
  );
}

function tampered(signature: string): string {
  return signature.slice(0, -1) + (signature.endsWith("0") ? "1" : "0");
}

function substitute(node: unknown, signature: string): unknown {
  if (node === PLACEHOLDER) return signature;
  if (Array.isArray(node)) return node.map((item) => substitute(item, signature));
  if (node !== null && typeof node === "object") {
    return Object.fromEntries(
      Object.entries(node).map(([key, value]) => [key, substitute(value, signature)]),
    );
  }
  return node;
}

function toolResult(testCase: Case, context: SecurityContext): unknown {
  const data = substitute(structuredClone(testCase.data), context.signature ?? "");
  switch (testCase.marker) {
    case null:
      return data;
    case "context":
      return EnforcedResult.forContext(data, context);
    case "otherContext": {
      const other = makeContext(testCase.policy, FIXTURE.otherContext);
      expect(other.signature).not.toBe(context.signature);
      return EnforcedResult.forContext(data, other);
    }
    case "tampered":
      return new EnforcedResult(data, tampered(context.signature ?? ""));
    case "empty":
      return new EnforcedResult(data, "");
  }
}

const wrapper = (options: Partial<ConstructorParameters<typeof SecureContextToolWrapper>[0]> = {}) =>
  new SecureContextToolWrapper({ signingKey: KEY, ...options });

const run = (w: SecureContextToolWrapper, context: SecurityContext, result: unknown) =>
  w.executeWithEnforcement(context, { toolName: "orm-query" }, () => result);

/** The pipeline applied once, as a data layer would have. */
function enforcedOnce(context: SecurityContext, rows: Row[]): Row[] {
  return applyResultPipeline(rows, context.effectivePolicy) as Row[];
}

const RAW: Row[] = [{ id: 1, region: "us-east", email: "a@example.com" }];

afterEach(() => {
  vi.restoreAllMocks();
});

describe("shared fixture: already-enforced-results.json", () => {
  it("the corpus carries the expected case count", () => {
    // A case dropped from the fixture is coverage lost silently.
    expect(FIXTURE.cases).toHaveLength(39);
  });

  for (const testCase of FIXTURE.cases) {
    it(testCase.name, async () => {
      const context = makeContext(testCase.policy);
      const result = toolResult(testCase, context);

      if (testCase.expectDenied) {
        await expect(run(wrapper(), context, result)).rejects.toThrow();
        return;
      }
      expect(await run(wrapper(), context, result)).toEqual(testCase.expected);
    });
  }
});

describe("the marker is bound to the exact context", () => {
  it("a matching marker is not hashed twice", async () => {
    const context = makeContext(POLICY_A);
    const once = enforcedOnce(context, RAW);

    expect(await run(wrapper(), context, EnforcedResult.forContext(once, context))).toEqual(
      once,
    );
  });

  it("a marker from a context with the same policy but another jti is not honoured", async () => {
    const context = makeContext(POLICY_A, FIXTURE.context, "call-1");
    const replayedFrom = makeContext(POLICY_A, FIXTURE.context, "call-0");
    const once = enforcedOnce(context, RAW);

    const out = await run(wrapper(), context, EnforcedResult.forContext(once, replayedFrom));

    expect(out).toEqual(applyResultPipeline(once, context.effectivePolicy));
    expect(out).not.toEqual(once);
  });

  it("a marker is not honoured when signatures are not enforced", async () => {
    // Without verification the signature field is whatever the sender wrote, so
    // matching it proves nothing.
    const context = makeContext(POLICY_A);
    const once = enforcedOnce(context, RAW);

    const out = await run(
      wrapper({ enforceSignatures: false }),
      context,
      EnforcedResult.forContext(once, context),
    );

    expect(out).toEqual(applyResultPipeline(once, context.effectivePolicy));
  });

  it("a context whose signature does not verify never honours a marker", async () => {
    // A tool can change the context it was handed. A forged context plus a marker
    // copying its forged signature must not skip anything.
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const context = makeContext(POLICY_A);
    const forged = { ...context, signature: tampered(context.signature ?? "") };
    const once = enforcedOnce(context, RAW);

    const out = wrapper().postExecute(forged, EnforcedResult.forContext(once, forged));
    const viaRun = await wrapper({ enforceSignatures: true }).executeWithEnforcement(
      context,
      { toolName: "orm-query" },
      () => {
        context.signature = forged.signature;
        return EnforcedResult.forContext(once, context);
      },
    );

    expect(viaRun).toEqual(applyResultPipeline(once, context.effectivePolicy));

    expect(out).toEqual(applyResultPipeline(once, context.effectivePolicy));
  });

  it("a marker whose signature is not a string is not honoured", async () => {
    const context = makeContext(POLICY_A);
    const once = enforcedOnce(context, RAW);
    const marker = new EnforcedResult(once, undefined as unknown as string);

    expect(await run(wrapper(), context, marker)).toEqual(
      applyResultPipeline(once, context.effectivePolicy),
    );
  });

  it("a signature differing only past the ASCII range is a mismatch, not a crash", async () => {
    const context = makeContext(POLICY_A);
    const once = enforcedOnce(context, RAW);
    const marker = new EnforcedResult(once, "é".repeat(32));

    expect(await run(wrapper(), context, marker)).toEqual(
      applyResultPipeline(once, context.effectivePolicy),
    );
  });

  it("a context re-signed with a new jti invalidates the marker", async () => {
    const context = makeContext(POLICY_A);
    const once = enforcedOnce(context, RAW);
    const marker = EnforcedResult.forContext(once, context);
    context.jti = "rotated";
    signContext(context, KEY);

    expect(await run(wrapper(), context, marker)).toEqual(
      applyResultPipeline(once, context.effectivePolicy),
    );
  });

  it("a mismatched marker is logged without the signatures", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const context = makeContext(POLICY_A);

    await run(wrapper(), context, new EnforcedResult([], "not-the-signature"));

    const messages = warn.mock.calls.map((call) => String(call[0]));
    expect(messages.some((m) => m.includes("EnforcedResult"))).toBe(true);
    expect(messages.some((m) => m.includes(context.signature ?? "--"))).toBe(false);
    expect(messages.some((m) => m.includes("not-the-signature"))).toBe(false);
  });
});

describe("only the marker class counts", () => {
  it("an object shaped like the marker is data", async () => {
    const context = makeContext(POLICY_A);
    const lookalike = {
      data: [{ id: 1, region: "us-east", email: "raw@example.com" }],
      contextSignature: context.signature,
    };

    // No region field, so the region filter drops it: the raw email never returns.
    expect(await run(wrapper(), context, lookalike)).toBeNull();
  });

  it("an object built from the prototype without the constructor is not honoured", async () => {
    const context = makeContext(POLICY_A);
    const once = enforcedOnce(context, RAW);
    const forged = Object.create(EnforcedResult.prototype, {
      data: { value: once, enumerable: true },
      contextSignature: { value: context.signature, enumerable: true },
    }) as EnforcedResult;

    // It passes instanceof and has the exact prototype, but the constructor never
    // ran on it, so it lacks the private brand: unwrapped and fully enforced.
    expect(forged instanceof EnforcedResult).toBe(true);
    expect(await run(wrapper(), context, forged)).toEqual(
      applyResultPipeline(once, context.effectivePolicy),
    );
    const parsed = JSON.parse(JSON.stringify(forged)) as unknown;
    expect(await run(wrapper(), context, parsed)).toBeNull();
  });

  it("a Proxy is not honoured, even over a real marker", async () => {
    const context = makeContext(POLICY_A);
    const once = enforcedOnce(context, RAW);
    const overReal = new Proxy(EnforcedResult.forContext(once, context), {});
    const lying = new Proxy(
      {},
      {
        getPrototypeOf: () => EnforcedResult.prototype,
        get: (_target, key) =>
          key === "data" ? once : key === "contextSignature" ? context.signature : undefined,
      },
    );
    const fully = applyResultPipeline(once, context.effectivePolicy);

    expect(await run(wrapper(), context, overReal)).toEqual(fully);
    expect(await run(wrapper(), context, lying)).toEqual(fully);
  });

  it("a subclass is not honoured", async () => {
    class Imposter<T> extends EnforcedResult<T> {}
    const context = makeContext(POLICY_A);
    const once = enforcedOnce(context, RAW);

    expect(
      await run(wrapper(), context, new Imposter(once, context.signature ?? "")),
    ).toEqual(applyResultPipeline(once, context.effectivePolicy));
  });

  it("the marker is frozen", () => {
    const context = makeContext(POLICY_A);
    const marker = EnforcedResult.forContext([], context);

    expect(Object.isFrozen(marker)).toBe(true);
    expect(() => {
      (marker as { contextSignature: string }).contextSignature = "x";
    }).toThrow();
  });

  it("inspecting the marker does not print its data", () => {
    const context = makeContext(POLICY_A);
    const marker = EnforcedResult.forContext([{ ssn: "123-45-6789" }], context);

    expect(inspect(marker)).not.toContain("123-45-6789");
  });

  it("binding to an unsigned context is refused", () => {
    const unsigned = buildSecurityContext("u", "t", toPolicy(POLICY_A));

    expect(() => EnforcedResult.forContext([], unsigned)).toThrow();
  });
});

describe("nested markers are never honoured", () => {
  it("a marker inside an array is unwrapped and fully enforced", async () => {
    const context = makeContext(POLICY_A);
    const once = enforcedOnce(context, RAW);

    const out = await run(wrapper(), context, [EnforcedResult.forContext(once[0], context)]);

    expect(out).toEqual(applyResultPipeline(once, context.effectivePolicy));
  });

  it("a marker inside a record field cannot smuggle hidden fields", async () => {
    const context = makeContext(POLICY_A);
    const record = {
      region: "us-east",
      patient: EnforcedResult.forContext({ ssn: "123-45-6789", id: 7 }, context),
    };

    const out = await run(wrapper(), context, record);

    expect(out).toEqual({ region: "us-east", patient: { id: 7 } });
    expect(JSON.stringify(out)).not.toContain("123-45-6789");
  });

  it("a marker wrapping a marker is fully enforced", async () => {
    const context = makeContext(POLICY_A);
    const once = enforcedOnce(context, RAW);
    const outer = EnforcedResult.forContext(EnforcedResult.forContext(once, context), context);

    expect(await run(wrapper(), context, outer)).toEqual(
      applyResultPipeline(once, context.effectivePolicy),
    );
  });

  it("an honoured marker with a nested marker inside is fully enforced", async () => {
    const context = makeContext(POLICY_A);
    const once = enforcedOnce(context, RAW);
    const outer = EnforcedResult.forContext(
      [once[0], EnforcedResult.forContext(once[0], context)],
      context,
    );

    expect(await run(wrapper(), context, outer)).toEqual(
      applyResultPipeline([...once, ...once], context.effectivePolicy),
    );
  });
});

describe("every other post-execution step still runs", () => {
  it("history is recorded on the async path, which does not honour a marker", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const history = new ToolCallHistory(4);
    const w = wrapper({ toolCallHistory: history });
    const context = makeContext(POLICY_A);
    const once = enforcedOnce(context, RAW);

    const pre = await w.preExecuteAsync(context, { toolName: "orm-query" });
    const out = w.postExecute(context, EnforcedResult.forContext(once, context));

    expect(pre.allowed).toBe(true);
    expect(out).toEqual(applyResultPipeline(once, context.effectivePolicy));
    expect(history.count).toBe(1);
  });

  it("a marker does not change what executeWithEnforcement records", async () => {
    const marked = new ToolCallHistory(4);
    const unmarked = new ToolCallHistory(4);
    const context = makeContext(POLICY_A);
    const once = enforcedOnce(context, RAW);

    await run(wrapper({ toolCallHistory: marked }), context, EnforcedResult.forContext(once, context));
    await run(wrapper({ toolCallHistory: unmarked }), context, once);

    expect(marked.count).toBe(unmarked.count);
  });

  it("maxResults truncates an honoured marker", async () => {
    const context = makeContext(POLICY_A);
    const rows = [0, 1, 2, 3, 4].map((id) => ({ id, region: "us-east" }));

    expect(await run(wrapper(), context, EnforcedResult.forContext(rows, context))).toEqual(
      rows.slice(0, 2),
    );
  });

  it("allowedFields projects an honoured marker", async () => {
    const policy = structuredClone(POLICY_A) as {
      objectRules: { fieldRules: { allowedFields?: string[] } };
    };
    policy.objectRules.fieldRules.allowedFields = ["id"];
    const context = makeContext(policy as unknown as Row);

    const out = await run(
      wrapper(),
      context,
      EnforcedResult.forContext([{ id: 1, internal: "x" }], context),
    );

    expect(out).toEqual([{ id: 1 }]);
  });

  it("a pre-execution denial still throws before the tool runs", async () => {
    const policy = structuredClone(POLICY_A) as { permissions: { canQuery: boolean } };
    policy.permissions.canQuery = false;
    const context = makeContext(policy as unknown as Row);
    const tool = vi.fn(() => EnforcedResult.forContext([], context));

    await expect(
      wrapper().executeWithEnforcement(context, { toolName: "orm-query" }, tool),
    ).rejects.toThrow(/Access denied/);
    expect(tool).not.toHaveBeenCalled();
  });

  it("an unenforceable shape inside an honoured marker is denied", async () => {
    const context = makeContext(POLICY_A);

    await expect(
      run(wrapper(), context, EnforcedResult.forContext("a scalar", context)),
    ).rejects.toThrow();
  });

  it("an unenforceable shape inside an honoured marker passes when opted out", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const context = makeContext(POLICY_A);

    expect(
      await run(
        wrapper({ allowUnenforceableShapes: true }),
        context,
        EnforcedResult.forContext("a scalar", context),
      ),
    ).toBe("a scalar");
  });

  it("an async tool returning a marker is honoured", async () => {
    const context = makeContext(POLICY_A);
    const once = enforcedOnce(context, RAW);

    const out = await wrapper().executeWithEnforcement(
      context,
      { toolName: "orm-query" },
      async () => EnforcedResult.forContext(once, context),
    );

    expect(out).toEqual(once);
  });

  it("an unmarked result behaves as before", async () => {
    const context = makeContext(POLICY_A);
    const raw: Row[] = [
      { id: 1, region: "us-east", email: "a@example.com", ssn: "1" },
      { id: 2, region: "eu-west", email: "b@example.com" },
    ];

    expect(await run(wrapper(), context, structuredClone(raw))).toEqual(
      applyResultPipeline(raw, context.effectivePolicy),
    );
  });
});

describe("only executeWithEnforcement honours a marker", () => {
  const WRITE_POLICY = {
    ...structuredClone(POLICY_A),
    permissions: { canQuery: true, canInsert: true, readOnly: false },
  } as Row;

  it("executeWithEnforcement honours it", async () => {
    const context = makeContext(POLICY_A);
    const once = enforcedOnce(context, RAW);

    expect(await run(wrapper(), context, EnforcedResult.forContext(once, context))).toEqual(
      once,
    );
  });

  it("postExecute called directly unwraps it and runs the full pipeline", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const context = makeContext(POLICY_A);
    const once = enforcedOnce(context, RAW);

    const out = wrapper().postExecute(context, EnforcedResult.forContext(once, context));

    expect(out).toEqual(applyResultPipeline(once, context.effectivePolicy));
    const messages = warn.mock.calls.map((call) => String(call[0]));
    expect(messages.some((m) => m.includes("executeWithEnforcement"))).toBe(true);
    expect(messages.some((m) => m.includes(context.signature ?? "--"))).toBe(false);
  });

  it("the SQL path unwraps it and runs the full pipeline", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const context = makeContext(POLICY_A);
    const once = enforcedOnce(context, RAW);

    const out = await wrapper().executeSqlWithEnforcement(
      context,
      { toolName: "sql-query" },
      "SELECT id, region, email FROM patients",
      () => EnforcedResult.forContext(once, context) as unknown as Row[],
    );

    expect(out).toEqual(applyResultPipeline(once, context.effectivePolicy));
  });

  it("the SQL path still enforces a filter on a visible field", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const context = makeContext(POLICY_A);
    const leaky = [{ id: 2, region: "eu-west", email: "b@example.com" }];

    const out = await wrapper().executeSqlWithEnforcement(
      context,
      { toolName: "sql-query" },
      "SELECT id, region, email FROM patients",
      () => EnforcedResult.forContext(leaky, context) as unknown as Row[],
    );

    expect(out).toEqual([]);
  });

  it("the write path unwraps it and runs the full pipeline", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const context = makeContext(WRITE_POLICY);
    const once = enforcedOnce(context, RAW);

    const out = await wrapper().executeWriteWithEnforcement(
      context,
      "insert",
      () => EnforcedResult.forContext(once, context),
      "patients",
      { region: "us-east" },
    );

    expect(out).toEqual(applyResultPipeline(once, context.effectivePolicy));
    expect(out).not.toEqual(once);
  });
});

describe("an honoured marker still runs the filters on visible fields", () => {
  it("a row filter on a visible field drops the row the data layer let through", async () => {
    const context = makeContext(POLICY_A);
    const rows = [
      { id: 1, region: "us-east", email: "h1" },
      { id: 2, region: "eu-west", email: "h2" },
    ];

    expect(await run(wrapper(), context, EnforcedResult.forContext(rows, context))).toEqual([
      rows[0],
    ]);
  });

  it("a row filter on a masked field is skipped", async () => {
    const policy = {
      version: "1.0",
      permissions: { canQuery: true },
      objectRules: {
        fieldRules: { maskedFields: [{ field: "email", maskType: "hash" }] },
        rowFilters: [{ field: "email", operator: "equals", value: "a@example.com" }],
      },
    };
    const context = makeContext(policy);
    const rows = [{ id: 1, email: "already-hashed" }];

    expect(await run(wrapper(), context, EnforcedResult.forContext(rows, context))).toEqual(
      rows,
    );
  });
});

describe("the registry wrapper never honours a marker", () => {
  // `tool.execute` never sees a signed context, so nothing can be bound to one.
  const registry = (allowUnenforceableShapes: boolean, result: unknown) => {
    const w = new SecureMcpToolWrapper({
      mode: EnforcementMode.Strict,
      identityExtractor: new HeaderIdentityExtractor(),
      resolvePolicy: async () => toPolicy(POLICY_A),
      allowUnenforceableShapes,
    });
    w.registerTool({
      name: "orm-query",
      description: "returns a marker",
      execute: async () => result,
    });
    return w.executeTool({
      toolName: "orm-query",
      headers: { "x-user-id": "user-1", "x-tenant-id": "tenant-1" },
    });
  };

  it("unwraps and fully enforces a marker", async () => {
    const context = makeContext(POLICY_A);
    const once = enforcedOnce(context, RAW);

    expect(await registry(false, EnforcedResult.forContext(once, context))).toEqual(
      applyResultPipeline(once, context.effectivePolicy),
    );
  });

  it("does not let allowUnenforceableShapes pass a marker's data through whole", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const leaky = new EnforcedResult(
      [{ id: 1, region: "us-east", email: "raw@example.com", ssn: "123-45-6789" }],
      "any",
    );

    const out = await registry(true, leaky);

    expect(JSON.stringify(out)).not.toContain("123-45-6789");
    expect(JSON.stringify(out)).not.toContain("raw@example.com");
  });
});
