/**
 * Secure Tool Factory (architecture.md §5).
 *
 * The factory's reason for existing is that the wrapper must be the only path to a
 * data source (architecture.md §4). So the tests that matter are the ones asserting
 * it *refuses to hand back a tool* — a factory that returns an unenforced tool, or
 * the wrong category's tool, defeats the guarantee it exists to provide.
 *
 * Three properties are pinned here:
 *
 *  1. **A context that fails validation yields no tool at all**, rather than a tool
 *     that will deny later. A caller holding a tool reasonably assumes it is usable,
 *     and a per-call denial is easy to misread as a transient error and retry.
 *  2. **Dispatch follows the SIGNED category.** The category is the first segment of
 *     `sourceConnectionId` (connector-spec §1), which lives inside the signed bytes.
 *     Were it taken from unsigned configuration, flipping `db` to `api` would select
 *     the wrapper enforcing the other category's rules — and `endpointRules` do not
 *     constrain a SQL query.
 *  3. **Wrappers stay stateless.** The factory does not retain the context, so one
 *     user's context cannot outlive its request on a shared instance and be reused
 *     for the next caller.
 */

import { describe, expect, it } from "vitest";

import {
  buildSecurityContext,
  signContext,
  SourceCategory,
  type EffectivePolicy,
  type SecurityContext,
} from "@aws/tolap-core";

import {
  SecureToolFactory,
  ToolCreationError,
} from "../src/factory.js";
import { SecureContextToolWrapper } from "../src/context-wrapper.js";
import { SecureHttpToolWrapper, type FetchLike } from "../src/http-wrapper.js";

const KEY = "factory-test-key";

/** A transport that must never be called: these tests build tools, not requests. */
const unusedFetch: FetchLike = async () => {
  throw new Error("the factory must not perform requests");
};

function policy(overrides: Partial<EffectivePolicy> = {}): EffectivePolicy {
  const now = new Date();
  return {
    version: "1.0",
    userId: "user-001",
    tenantId: "tenant-001",
    sourceConnectionId: "db:production:patients",
    resolvedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 3_600_000).toISOString(),
    sourceProfiles: ["factory-test"],
    permissions: { canQuery: true, readOnly: true },
    integrity: { algorithm: "none", signature: "" },
    ...overrides,
  };
}

function signed(p: EffectivePolicy = policy(), ttlMs = 3_600_000): SecurityContext {
  return signContext(buildSecurityContext(p.userId, p.tenantId, p, ttlMs), KEY);
}

function factory(overrides: Record<string, unknown> = {}): SecureToolFactory {
  return new SecureToolFactory({
    signingKey: KEY,
    fetchFn: unusedFetch,
    ...overrides,
  });
}

// ---------------------------------------------------------------------------
// Dispatch on the signed category
// ---------------------------------------------------------------------------

describe("dispatch follows the signed category (§1)", () => {
  it.each([
    ["db", "db:production:patients"],
    ["kb", "kb:research:trials"],
    ["storage", "storage:archive:exports"],
  ])("%s yields the record-shaped wrapper", (_label, sourceConnectionId) => {
    // db, kb and storage all return records and share the post-execution pipeline.
    // Which policy fields are meaningful differs, but that is decided by the policy,
    // not the wrapper type (connector-spec §2).
    const tool = factory().createTool(signed(policy({ sourceConnectionId })));
    expect(tool).toBeInstanceOf(SecureContextToolWrapper);
  });

  it("api yields the HTTP wrapper", () => {
    const tool = factory().createTool(signed(policy({ sourceConnectionId: "api:internal:orders" })));
    expect(tool).toBeInstanceOf(SecureHttpToolWrapper);
  });

  it("EXPLOIT: the category cannot be changed without breaking the signature", () => {
    // The whole reason dispatch reads the signed identifier. Swapping the category
    // post-signing would otherwise pick the wrapper that enforces a different
    // category's rules -- endpointRules do not constrain SQL, and vice versa.
    const ctx = signed(policy({ sourceConnectionId: "db:production:patients" }));
    ctx.effectivePolicy.sourceConnectionId = "api:internal:orders";

    expect(() => factory().createTool(ctx)).toThrow(ToolCreationError);
    expect(() => factory().createTool(ctx)).toThrow(/invalid signature/);
  });

  it("an unparseable identifier yields no tool rather than a guessed one", () => {
    // Two segments is the documented authoring mistake. There is no safe default
    // wrapper: guessing would enforce some category's rules on a source whose
    // category is unknown.
    const ctx = signed(policy({ sourceConnectionId: "db:production" }));
    expect(() => factory().createTool(ctx)).toThrow(/category:namespace:name/);
  });

  it("categoryOf reports the category without building a tool", () => {
    expect(factory().categoryOf(signed(policy({ sourceConnectionId: "kb:research:trials" }))))
      .toBe(SourceCategory.Kb);
  });
});

// ---------------------------------------------------------------------------
// A context that fails validation yields NO tool
// ---------------------------------------------------------------------------

describe("fail closed: no tool for an unusable context", () => {
  it("EXPLOIT: a forged signature yields no tool", () => {
    const ctx = signed();
    ctx.signature = "not-the-real-signature";

    expect(() => factory().createTool(ctx)).toThrow(/invalid signature/);
  });

  it("EXPLOIT: tampering with the policy inside the envelope yields no tool", () => {
    // Escalating readOnly on a signed context is the canonical tamper case.
    const ctx = signed(policy({ permissions: { canQuery: true, readOnly: true } }));
    ctx.effectivePolicy.permissions.readOnly = false;

    expect(() => factory().createTool(ctx)).toThrow(/invalid signature/);
  });

  it("an expired context yields no tool", () => {
    const ctx = signed(policy(), -1_000);
    expect(() => factory().createTool(ctx)).toThrow(ToolCreationError);
  });

  it("signature is reported before expiry", () => {
    // Matching the wrappers: a tampered context must not disclose that an otherwise
    // valid context had merely expired.
    const ctx = signed(policy(), -1_000);
    ctx.signature = "forged";

    expect(() => factory().createTool(ctx)).toThrow(/invalid signature/);
  });

  it("canQuery false yields no tool", () => {
    // The top-level read gate. Returning a wrapper that denies every call invites a
    // caller to treat the denial as transient and retry.
    const ctx = signed(policy({ permissions: { canQuery: false, readOnly: true } }));
    expect(() => factory().createTool(ctx)).toThrow(/query not permitted/);
  });

  it("a context carrying no policy yields no tool", () => {
    const ctx = signed();
    // Simulates a JSON payload whose policy went missing in transport. Signature
    // enforcement is off here so the test reaches the policy check rather than
    // stopping at the signature the mutation invalidated.
    delete (ctx as unknown as Record<string, unknown>)["effectivePolicy"];

    expect(() =>
      factory({ enforceSignatures: false, enforceExpiry: false }).createTool(ctx),
    ).toThrow(/no effective policy/);
  });
});

// ---------------------------------------------------------------------------
// The factory does not open connections
// ---------------------------------------------------------------------------

describe("the factory holds no connection and no credentials", () => {
  it("an api source without a transport is an error, not a fallback to global fetch", () => {
    // Silently defaulting to global `fetch` would bypass the caller's proxy,
    // timeout and retry policy while appearing to work.
    const bare = new SecureToolFactory({ signingKey: KEY });
    const ctx = signed(policy({ sourceConnectionId: "api:internal:orders" }));

    expect(() => bare.createTool(ctx)).toThrow(/fetchFn/);
  });

  it("db, kb and storage need no transport", () => {
    const bare = new SecureToolFactory({ signingKey: KEY });
    expect(bare.createTool(signed())).toBeInstanceOf(SecureContextToolWrapper);
  });

  it("building a tool performs no request", async () => {
    // `unusedFetch` throws if called, so reaching this assertion proves the factory
    // did not touch the transport while composing.
    const tool = factory().createTool(signed(policy({ sourceConnectionId: "api:internal:orders" })));
    expect(tool).toBeInstanceOf(SecureHttpToolWrapper);
  });
});

// ---------------------------------------------------------------------------
// Wrappers stay stateless and reusable
// ---------------------------------------------------------------------------

describe("wrappers are stateless: no context is retained", () => {
  it("two calls yield independent wrappers", () => {
    const f = factory();
    expect(f.createTool(signed())).not.toBe(f.createTool(signed()));
  });

  it("EXPLOIT: a tool built for one user does not carry that user's policy", async () => {
    // The failure mode a stateful `setSecurityContext()` would introduce: a wrapper
    // holding user A's context, reused for user B. Because the context is supplied
    // per call, a wrapper built from A's context enforces B's policy when B calls it
    // -- and enforces nothing at all with no context.
    const restrictive = policy({
      userId: "user-A",
      objectRules: { allowedObjects: ["patients"] },
    });
    const tool = factory().createTool(signed(restrictive)) as SecureContextToolWrapper;

    // B's own signed context governs B's call, regardless of who the tool was built for.
    const bContext = signed(
      policy({ userId: "user-B", objectRules: { allowedObjects: ["encounters"] } }),
    );

    expect(tool.preExecute(bContext, { toolName: "q", objectName: "encounters" }).allowed).toBe(true);
    // And A's allow-list does not leak in to grant `patients` to B.
    expect(tool.preExecute(bContext, { toolName: "q", objectName: "patients" }).allowed).toBe(false);
  });

  it("the factory-built wrapper still validates the context on every call", () => {
    // Composition-time validation is redundancy, not the gate: the wrapper is
    // reusable and the context arrives again with every request, so a forged
    // context presented later must still be refused.
    const tool = factory().createTool(signed()) as SecureContextToolWrapper;
    const forged = signed();
    forged.signature = "forged";

    const result = tool.preExecute(forged, { toolName: "q", objectName: "patients" });
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("invalid signature");
  });
});

// ---------------------------------------------------------------------------
// Options forwarding
// ---------------------------------------------------------------------------

describe("options reach the wrapper", () => {
  it("allowedTools is honoured by the produced wrapper", () => {
    const tool = factory({ allowedTools: ["permitted"] }).createTool(signed()) as SecureContextToolWrapper;

    expect(tool.preExecute(signed(), { toolName: "permitted" }).allowed).toBe(true);
    const denied = tool.preExecute(signed(), { toolName: "other" });
    expect(denied.allowed).toBe(false);
    expect(denied.reason).toBe("tool not in allowed list");
  });

  it("enforceSignatures: false is forwarded, so an unsigned context is accepted", () => {
    // Asserted because it is a footgun worth being explicit about: the option exists
    // for migrations, and this test documents that it really does disable the check
    // rather than being quietly ignored.
    const f = factory({ enforceSignatures: false });
    const ctx = signed();
    ctx.signature = "forged";

    const tool = f.createTool(ctx) as SecureContextToolWrapper;
    expect(tool.preExecute(ctx, { toolName: "q", objectName: "patients" }).allowed).toBe(true);
  });
});
