/**
 * Cross-SDK signing conformance for `objectRules.toolRules` (matrix F1-F6).
 *
 * Modelled on `purpose-signing-parity.test.ts`. `toolRules` needs no serializer change in
 * this SDK -- the canonical form is a generic sorted-key, null-dropping walk -- so these
 * tests pin that the generic walk puts `toolRules` inside the signed bytes (F5), that a
 * policy without it signs exactly as before (F6), and that every edit to it breaks the
 * seal (F1-F4).
 *
 * The literals are duplicated here as well as read from the fixture, deliberately: a
 * "fix" that rewrites the fixture trips the literal, and a canonicaliser change trips the
 * fixture comparison.
 */

import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { createHmac } from "node:crypto";
import { signContext, validateContext } from "../src/context.js";
import {
  SigningAlgorithm,
  type DelegationHop,
  type EffectivePolicy,
  type SecurityContext,
} from "../src/types.js";

const signingFixturesDir = path.resolve(__dirname, "../../../../../fixtures/signing");

interface SigningFixture {
  secretKey: string;
  payload: Record<string, unknown>;
  declaredPurpose?: string;
  delegationChain?: DelegationHop[];
  canonicalPayload: string;
  expectedSignature: string;
  expectedSignatureSha512: string;
}

function loadFixture(filename: string): SigningFixture {
  return JSON.parse(
    fs.readFileSync(path.join(signingFixturesDir, filename), "utf-8"),
  ) as SigningFixture;
}

const TOOL_RULES_FIXTURE = "hmac-sha256-tool-rules.json";
const fixture = loadFixture(TOOL_RULES_FIXTURE);

// Computed outside every SDK (see the fixture's notes).
const EXPECTED_SHA256 = "5e03btrOvmw9B7bh4EyMcWPW37kHOFbU83akZnKtJy4=";
const EXPECTED_SHA512 =
  "3VFZJTH0d/jO1toQAosmZNoNjMsqRqFYHl+j2LzapRg5vmc2XiFiESh3SjxM9DnhGFl6TnXnr5bTlFbfS8EhGw==";

/** A deep copy of a fixture projected into this SDK's context shape. */
function contextFrom(f: SigningFixture): SecurityContext {
  const policy: EffectivePolicy = {
    ...(JSON.parse(JSON.stringify(f.payload)) as EffectivePolicy),
    integrity: { algorithm: "none", signature: "" },
  };
  return {
    effectivePolicy: policy,
    resolvedAt: policy.resolvedAt,
    expiresAt: policy.expiresAt,
    ...(f.declaredPurpose === undefined ? {} : { declaredPurpose: f.declaredPurpose }),
    ...(f.delegationChain === undefined
      ? {}
      : { delegationChain: f.delegationChain.map((hop) => ({ ...hop })) }),
  };
}

function hmac(payload: string, key: string, alg: "sha256" | "sha512"): string {
  return createHmac(alg, key).update(payload, "utf8").digest("base64");
}

function signed(f: SigningFixture = fixture): SecurityContext {
  const ctx = contextFrom(f);
  signContext(ctx, f.secretKey);
  return ctx;
}

function toolRulesOf(ctx: SecurityContext) {
  return ctx.effectivePolicy.objectRules!.toolRules!;
}

// ---------------------------------------------------------------------------
// F5: the tool-rules fixture
// ---------------------------------------------------------------------------

describe("F5: fixtures/signing/hmac-sha256-tool-rules.json", () => {
  it("carries toolRules with a non-empty allowedTools and an empty hiddenTools", () => {
    const rules = (fixture.payload["objectRules"] as Record<string, unknown>)["toolRules"];
    expect(rules).toStrictEqual({
      allowedTools: ["query_patients", "count_patients"],
      hiddenTools: [],
    });
  });

  it("agrees with the literals pinned in this file", () => {
    expect(fixture.expectedSignature).toBe(EXPECTED_SHA256);
    expect(fixture.expectedSignatureSha512).toBe(EXPECTED_SHA512);
  });

  it("the fixture is self-consistent: its canonical bytes HMAC to its signatures", () => {
    expect(hmac(fixture.canonicalPayload, fixture.secretKey, "sha256")).toBe(EXPECTED_SHA256);
    expect(hmac(fixture.canonicalPayload, fixture.secretKey, "sha512")).toBe(EXPECTED_SHA512);
  });

  it("signs toolRules inside policies[], hiddenTools [] as [], allowedTools unsorted", () => {
    expect(fixture.canonicalPayload).toContain(
      '"toolRules":{"allowedTools":["query_patients","count_patients"],"hiddenTools":[]}',
    );
  });

  it("HMAC-SHA256 matches the cross-SDK expected signature", () => {
    const ctx = contextFrom(fixture);
    signContext(ctx, fixture.secretKey, SigningAlgorithm.HmacSha256);
    expect(ctx.signature).toBe(EXPECTED_SHA256);
  });

  it("HMAC-SHA512 matches the cross-SDK expected signature", () => {
    const ctx = contextFrom(fixture);
    signContext(ctx, fixture.secretKey, SigningAlgorithm.HmacSha512);
    expect(ctx.signature).toBe(EXPECTED_SHA512);
  });

  it("verifies, and a context signed elsewhere with the fixture signature verifies here", () => {
    expect(validateContext(signed(), fixture.secretKey)).toBe(true);
    const foreign = contextFrom(fixture);
    foreign.signature = fixture.expectedSignature;
    foreign.algorithm = SigningAlgorithm.HmacSha256;
    expect(validateContext(foreign, fixture.secretKey)).toBe(true);
  });

  it("key order inside toolRules does not change the bytes", () => {
    const reordered = contextFrom(fixture);
    reordered.effectivePolicy.objectRules!.toolRules = {
      hiddenTools: [],
      allowedTools: ["query_patients", "count_patients"],
    };
    signContext(reordered, fixture.secretKey);
    expect(reordered.signature).toBe(EXPECTED_SHA256);
  });
});

// ---------------------------------------------------------------------------
// F6: the existing signing fixtures are unchanged
// ---------------------------------------------------------------------------

describe("F6: the pre-existing signing fixtures still sign to their known answers", () => {
  const PRE_EXISTING = [
    "hmac-sha256-known-answer.json",
    "hmac-sha256-subsecond.json",
    "hmac-sha256-purpose-bound.json",
  ];

  it("the signing fixture directory holds exactly those three plus the tool-rules one", () => {
    const onDisk = fs.readdirSync(signingFixturesDir).filter((f) => f.endsWith(".json")).sort();
    expect(onDisk).toEqual([...PRE_EXISTING, TOOL_RULES_FIXTURE].sort());
  });

  for (const file of PRE_EXISTING) {
    it(`${file}: no toolRules in the bytes, both signatures unchanged`, () => {
      const f = loadFixture(file);
      expect(f.canonicalPayload).not.toContain("toolRules");
      expect(JSON.stringify(f.payload)).not.toContain("toolRules");

      const sha256 = contextFrom(f);
      signContext(sha256, f.secretKey, SigningAlgorithm.HmacSha256);
      expect(sha256.signature).toBe(f.expectedSignature);

      const sha512 = contextFrom(f);
      signContext(sha512, f.secretKey, SigningAlgorithm.HmacSha512);
      expect(sha512.signature).toBe(f.expectedSignatureSha512);
    });
  }
});

// ---------------------------------------------------------------------------
// F1-F4: tampering with toolRules breaks the seal
// ---------------------------------------------------------------------------

describe("F1-F4: the signature covers toolRules", () => {
  it("control: the untampered context verifies", () => {
    expect(validateContext(signed(), fixture.secretKey)).toBe(true);
  });

  it("F1: signed with a non-empty hiddenTools, then set to []", () => {
    const ctx = contextFrom(fixture);
    toolRulesOf(ctx).hiddenTools = ["export_segment_csv"];
    signContext(ctx, fixture.secretKey);
    expect(validateContext(ctx, fixture.secretKey)).toBe(true);
    toolRulesOf(ctx).hiddenTools = [];
    expect(validateContext(ctx, fixture.secretKey)).toBe(false);
  });

  it("F1 variant: an empty hiddenTools removed, or nulled, is a different policy", () => {
    // [] is signed; absent and null are not. Dropping the empty list is an edit.
    const removed = signed();
    delete toolRulesOf(removed).hiddenTools;
    expect(validateContext(removed, fixture.secretKey)).toBe(false);

    const nulled = signed();
    (toolRulesOf(nulled) as Record<string, unknown>).hiddenTools = null;
    expect(validateContext(nulled, fixture.secretKey)).toBe(false);
  });

  it("F2: toolRules removed entirely", () => {
    const ctx = signed();
    delete ctx.effectivePolicy.objectRules!.toolRules;
    expect(validateContext(ctx, fixture.secretKey)).toBe(false);
  });

  it("F2 variant: allowedTools removed (deny-some becomes unrestricted)", () => {
    const ctx = signed();
    delete toolRulesOf(ctx).allowedTools;
    expect(validateContext(ctx, fixture.secretKey)).toBe(false);
  });

  it("F3: a tool appended to allowedTools", () => {
    const ctx = signed();
    toolRulesOf(ctx).allowedTools!.push("export_segment_csv");
    expect(validateContext(ctx, fixture.secretKey)).toBe(false);
  });

  it("F3 variant: allowedTools reordered, or an entry re-cased", () => {
    const reordered = signed();
    toolRulesOf(reordered).allowedTools!.reverse();
    expect(validateContext(reordered, fixture.secretKey)).toBe(false);

    const recased = signed();
    toolRulesOf(recased).allowedTools![0] = "Query_patients";
    expect(validateContext(recased, fixture.secretKey)).toBe(false);
  });

  it("F4: signed without toolRules, then toolRules added (even a narrowing edit)", () => {
    const f = loadFixture("hmac-sha256-known-answer.json");
    const ctx = signed(f);
    expect(validateContext(ctx, f.secretKey)).toBe(true);
    ctx.effectivePolicy.objectRules = { toolRules: { allowedTools: [] } };
    expect(validateContext(ctx, f.secretKey)).toBe(false);
  });

  it("F4 variant: an empty toolRules {} added is also an edit", () => {
    // `{}` is not null, so the canonical form keeps it and the bytes change.
    const f = loadFixture("hmac-sha256-known-answer.json");
    const ctx = signed(f);
    ctx.effectivePolicy.objectRules = { toolRules: {} };
    expect(validateContext(ctx, f.secretKey)).toBe(false);
  });
});
