/**
 * Core halves of the already-enforced result marker (issue #33): the constant-time
 * binding check, the nested-marker unwrap every pipeline run performs, and the
 * idempotent subset of the pipeline an honoured marker still gets. The wrapper-level
 * behaviour, and the shared fixture, are covered in the mcp package.
 */

import { describe, expect, it } from "vitest";

import {
  EnforcedResult,
  containsEnforcedResult,
  isBoundTo,
  isExactEnforcedResult,
  unwrapEnforcedResults,
} from "../src/enforced-result.js";
import { applyIdempotentResultSteps, applyResultPipeline } from "../src/enforcement.js";
import type { EffectivePolicy, SecurityContext } from "../src/types.js";

const POLICY = {
  version: "1.0",
  userId: "u",
  tenantId: "t",
  sourceConnectionId: "s",
  resolvedAt: new Date().toISOString(),
  expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
  sourceProfiles: [],
  permissions: { canQuery: true },
  objectRules: {
    fieldRules: {
      hiddenFields: ["ssn"],
      maskedFields: [{ field: "email", maskType: "hash" }],
    },
    rowFilters: [{ field: "region", operator: "equals", value: "us-east" }],
  },
  limits: { maxResults: 2 },
} as unknown as EffectivePolicy;

const contextWith = (signature?: string) => ({ signature }) as unknown as SecurityContext;

describe("isBoundTo", () => {
  it("matches the exact signature only", () => {
    const marker = new EnforcedResult([], "abc123");

    expect(isBoundTo(marker, contextWith("abc123"))).toBe(true);
    expect(isBoundTo(marker, contextWith("abc124"))).toBe(false);
    expect(isBoundTo(marker, contextWith("abc1234"))).toBe(false);
  });

  it("never matches an empty or absent context signature", () => {
    expect(isBoundTo(new EnforcedResult([], ""), contextWith(""))).toBe(false);
    expect(isBoundTo(new EnforcedResult([], ""), contextWith(undefined))).toBe(false);
  });

  it("rejects a non-string marker signature", () => {
    const marker = new EnforcedResult([], 42 as unknown as string);

    expect(isBoundTo(marker, contextWith("42"))).toBe(false);
  });
});

describe("isExactEnforcedResult", () => {
  it("accepts the class and rejects subclasses and lookalikes", () => {
    class Sub extends EnforcedResult {}

    expect(isExactEnforcedResult(new EnforcedResult(1, "s"))).toBe(true);
    expect(isExactEnforcedResult(new Sub(1, "s"))).toBe(false);
    expect(isExactEnforcedResult({ data: 1, contextSignature: "s" })).toBe(false);
    expect(isExactEnforcedResult(null)).toBe(false);
  });
});

describe("unwrapEnforcedResults", () => {
  it("returns unmarked data by identity", () => {
    const data = [{ a: 1, nested: { b: [1, 2] } }];

    expect(unwrapEnforcedResults(data)).toBe(data);
    expect(containsEnforcedResult(data)).toBe(false);
  });

  it("unwraps markers at any depth, including subclasses", () => {
    class Sub<T> extends EnforcedResult<T> {}
    const data = {
      top: new EnforcedResult({ inner: [new Sub({ deep: 1 }, "x")] }, "y"),
    };

    expect(containsEnforcedResult(data)).toBe(true);
    expect(unwrapEnforcedResults(data)).toEqual({ top: { inner: [{ deep: 1 }] } });
  });

  it("does not let a __proto__ key rewrite the prototype when rebuilding", () => {
    const data = JSON.parse('{"__proto__": {"polluted": true}, "m": 1}') as Record<
      string,
      unknown
    >;
    data.m = new EnforcedResult(2, "s");

    const out = unwrapEnforcedResults(data) as Record<string, unknown>;

    expect(Object.getPrototypeOf(out)).toBe(Object.prototype);
    expect(out.m).toBe(2);
  });
});

describe("the pipeline never honours a marker", () => {
  it("unwraps a top-level marker and enforces it in full", () => {
    const rows = [{ region: "us-east", email: "a@example.com" }];

    expect(applyResultPipeline(new EnforcedResult(rows, "s"), POLICY)).toEqual(
      applyResultPipeline(rows, POLICY),
    );
  });

  it("unwraps a nested marker so hidden fields inside it are stripped", () => {
    const record = { region: "us-east", p: new EnforcedResult({ ssn: "1", id: 2 }, "s") };

    expect(applyResultPipeline(record, POLICY)).toEqual({ region: "us-east", p: { id: 2 } });
  });
});

describe("applyIdempotentResultSteps", () => {
  it("strips hidden fields and truncates, but neither filters nor masks", () => {
    const rows = [
      { region: "eu-west", email: "already-hashed", ssn: "1" },
      { region: "us-east", email: "already-hashed" },
      { region: "us-east", email: "already-hashed" },
    ];

    expect(applyIdempotentResultSteps(rows, POLICY)).toEqual([
      { region: "eu-west", email: "already-hashed" },
      { region: "us-east", email: "already-hashed" },
    ]);
  });

  it("is idempotent", () => {
    const once = applyResultPipeline(
      [
        { region: "us-east", email: "a@example.com", ssn: "1" },
        { region: "us-east", email: "b@example.com" },
      ],
      POLICY,
    );

    expect(applyIdempotentResultSteps(once, POLICY)).toEqual(once);
    expect(applyIdempotentResultSteps(applyIdempotentResultSteps(once, POLICY), POLICY)).toEqual(
      once,
    );
  });

  it("keeps a single record a single record, and null when limited away", () => {
    const zero = { ...POLICY, limits: { maxResults: 0 } } as EffectivePolicy;

    expect(applyIdempotentResultSteps({ id: 1, ssn: "x" }, POLICY)).toEqual({ id: 1 });
    expect(applyIdempotentResultSteps({ id: 1 }, zero)).toBeNull();
  });

  it("denies an unenforceable shape", () => {
    expect(() => applyIdempotentResultSteps("scalar", POLICY)).toThrow();
  });
});
