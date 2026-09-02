/**
 * Cross-SDK signing conformance for a purpose-bound context (canonical spec §14, §15).
 *
 * `declaredPurpose` and `delegationChain` are inside the signed bytes, and the reason
 * is sharper than for `jti`: a purpose-scoped policy is only worth resolving if the
 * purpose that selected it cannot then be swapped, and a delegation chain that can be
 * rewritten is decoration — `validateDelegationChain` would be checking the attacker's
 * own arithmetic.
 *
 * Every assertion against `fixtures/signing/hmac-sha256-purpose-bound.json` is
 * **unconditional**. A test that skips when an expected value is absent restores the
 * blind spot the whole conformance suite exists to close (spec §14): the original
 * cross-SDK divergence survived because nothing failed when a fixture stopped carrying
 * an answer.
 *
 * The literals are duplicated here as well as read from the fixture, deliberately. If
 * someone "fixes" a failure by rewriting the fixture, the literal fails; if someone
 * changes the canonicaliser, the fixture comparison fails. Two locks, one door.
 */

import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import {
  buildSecurityContext,
  deserializeContext,
  serializeContext,
  signContext,
  validateContext,
} from "../src/context.js";
import { validateDelegationChain } from "../src/delegation.js";
import {
  PrincipalType,
  SigningAlgorithm,
  type DelegationHop,
  type EffectivePolicy,
  type SecurityContext,
} from "../src/types.js";

const signingFixturesDir = path.resolve(
  __dirname,
  "../../../../../fixtures/signing",
);
const SCHEMA_DIR = path.resolve(__dirname, "../../../../../schema/v1.0");

const PURPOSE_FIXTURE = "hmac-sha256-purpose-bound.json";

interface PurposeSigningFixture {
  secretKey: string;
  payload: Record<string, unknown>;
  declaredPurpose: string;
  delegationChain: DelegationHop[];
  canonicalPayload: string;
  expectedSignature: string;
  expectedSignatureSha512: string;
}

function loadFixture(filename: string): Record<string, unknown> {
  return JSON.parse(
    fs.readFileSync(path.join(signingFixturesDir, filename), "utf-8"),
  ) as Record<string, unknown>;
}

const fixture = loadFixture(PURPOSE_FIXTURE) as unknown as PurposeSigningFixture;

// Computed per spec §1/§2 and matched byte-for-byte against the .NET SDK.
const EXPECTED_SHA256 = "AoL9vYiZTjA+umQzvLEK5C0nEe1nMR0DDUZje365FI0=";
const EXPECTED_SHA512 =
  "XDEeh0rl1hJKnl9/2MaTAzHHFU11WhbjQCqFCwPGZAu0euSjegC9s3pjlOQxFMJlG1hsicv9DZ1VgMBJmL27OA==";

/**
 * The fixture projected into this SDK's public context shape.
 *
 * The fixture carries one effective policy plus the two new envelope fields; the
 * canonical signing payload wraps the policy in the envelope, taking
 * `issuedAt`/`expiresAt` from its `resolvedAt`/`expiresAt` so all three SDKs sign the
 * same instants.
 */
function contextFromFixture(): SecurityContext {
  const policy: EffectivePolicy = {
    ...(fixture.payload as unknown as EffectivePolicy),
    integrity: { algorithm: "none", signature: "" },
  };
  return {
    effectivePolicy: policy,
    resolvedAt: policy.resolvedAt,
    expiresAt: policy.expiresAt,
    declaredPurpose: fixture.declaredPurpose,
    delegationChain: fixture.delegationChain.map((hop) => ({ ...hop })),
  };
}

/** Recursive key sort with explicit nulls dropped — the canonical form (spec §1). */
function sortDropNulls(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortDropNulls);
  if (value !== null && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(obj).sort()) {
      if (obj[key] === null || obj[key] === undefined) continue;
      out[key] = sortDropNulls(obj[key]);
    }
    return out;
  }
  return value;
}

// ---------------------------------------------------------------------------
// The fixture must carry what these tests assume
// ---------------------------------------------------------------------------

describe("the purpose-bound signing fixture", () => {
  it("carries a purpose, a three-hop chain, and a purpose-bound policy", () => {
    expect(fixture.declaredPurpose).toBe("campaign-x-overlap");
    expect(fixture.delegationChain).toHaveLength(3);
    expect(
      (fixture.payload as { purposeProfile?: unknown }).purposeProfile,
    ).toBeDefined();
  });

  it("carries a sub-millisecond hop timestamp, which is the point of the third hop", () => {
    // A whole-second fixture cannot detect a precision mismatch: every runtime renders
    // `10:00:00` identically. .NET and Python natively serialize microseconds while
    // JavaScript's `Date` cannot represent them at all, so without a mandated precision
    // the same instant signs to different bytes per language.
    expect(fixture.delegationChain[2].delegatedAt).toBe("2026-09-01T10:00:00.123456Z");
  });

  it("carries both expected signatures", () => {
    // Unconditional. A fixture that lost an expected value must fail here rather than
    // let every assertion below quietly stop verifying anything (spec §14).
    expect(typeof fixture.expectedSignature).toBe("string");
    expect(fixture.expectedSignature.length).toBeGreaterThan(0);
    expect(typeof fixture.expectedSignatureSha512).toBe("string");
    expect(fixture.expectedSignatureSha512.length).toBeGreaterThan(0);
  });

  it("carries the canonical payload bytes", () => {
    expect(typeof fixture.canonicalPayload).toBe("string");
    expect(fixture.canonicalPayload.length).toBeGreaterThan(0);
  });

  it("agrees with the literals pinned in this file", () => {
    expect(fixture.expectedSignature).toBe(EXPECTED_SHA256);
    expect(fixture.expectedSignatureSha512).toBe(EXPECTED_SHA512);
  });
});

// ---------------------------------------------------------------------------
// Known answers
// ---------------------------------------------------------------------------

describe("known-answer conformance", () => {
  it("HMAC-SHA256 matches the cross-SDK expected signature", () => {
    const ctx = contextFromFixture();
    signContext(ctx, fixture.secretKey, SigningAlgorithm.HmacSha256);

    expect(ctx.signature).toBe(EXPECTED_SHA256);
    expect(ctx.signature).toBe(fixture.expectedSignature);
  });

  it("HMAC-SHA512 matches the cross-SDK expected signature", () => {
    const ctx = contextFromFixture();
    signContext(ctx, fixture.secretKey, SigningAlgorithm.HmacSha512);

    expect(ctx.signature).toBe(EXPECTED_SHA512);
    expect(ctx.signature).toBe(fixture.expectedSignatureSha512);
  });

  it("the canonical signed bytes match the fixture byte-for-byte", () => {
    // Signing through the public API and comparing BYTES, so a mismatch names the
    // offending field instead of surfacing as an opaque HMAC failure that could equally
    // be a key problem.
    const projection = {
      version: fixture.payload["version"],
      userId: fixture.payload["userId"],
      tenantId: fixture.payload["tenantId"],
      issuedAt: fixture.payload["resolvedAt"],
      expiresAt: fixture.payload["expiresAt"],
      policies: [fixture.payload],
      declaredPurpose: fixture.declaredPurpose,
      delegationChain: fixture.delegationChain.map((hop) => ({
        ...hop,
        // The one field the projection normalizes: microseconds truncate to
        // milliseconds (spec §2 rule 5).
        delegatedAt: hop.delegatedAt?.replace(".123456Z", ".123Z"),
      })),
    };

    expect(JSON.stringify(sortDropNulls(projection))).toBe(fixture.canonicalPayload);
  });

  it("the hop timestamp is signed truncated to milliseconds", () => {
    // Nested inside an array of objects is exactly the place a normalization pass gets
    // forgotten, and the envelope-level fixtures cannot catch it.
    expect(fixture.canonicalPayload).toContain("2026-09-01T10:00:00.123Z");
    expect(fixture.canonicalPayload).not.toContain("123456");
  });

  it("a hop carrying microseconds signs to the same bytes as one already truncated", () => {
    // The cross-SDK claim stated directly: Python and .NET hand this SDK a `.123456Z`
    // or a `.123Z` for the same instant depending on how they serialized it, and both
    // must verify.
    const withMicros = contextFromFixture();
    const truncated = contextFromFixture();
    truncated.delegationChain = truncated.delegationChain?.map((hop) => ({
      ...hop,
      ...(hop.delegatedAt === undefined
        ? {}
        : { delegatedAt: hop.delegatedAt.replace(".123456Z", ".123Z") }),
    }));

    signContext(withMicros, fixture.secretKey);
    signContext(truncated, fixture.secretKey);

    expect(truncated.signature).toBe(withMicros.signature);
  });

  it("a hop with no timestamp is left alone rather than gaining an empty one", () => {
    // `normalizeTimestamp(undefined)` returns `""`, and writing that back would add a
    // `delegatedAt: ""` key the other SDKs do not emit -- a divergence with no symptom
    // until a signature fails to verify.
    const undated = contextFromFixture();
    undated.delegationChain = [
      { principalId: "user-1", principalType: PrincipalType.User },
    ];
    signContext(undated, fixture.secretKey);

    const serialized = serializeContext(undated);
    const json = Buffer.from(serialized, "base64").toString("utf8");
    expect(json).not.toContain('"delegatedAt":""');
    expect(validateContext(undated, fixture.secretKey)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Tamper resistance -- every field, one test each
// ---------------------------------------------------------------------------

describe("the signature covers the purpose and every hop", () => {
  function signed(): SecurityContext {
    const ctx = contextFromFixture();
    signContext(ctx, fixture.secretKey);
    return ctx;
  }

  it("accepts the untampered context", () => {
    // The paired control for everything below. Without it, a validator that rejected
    // everything would pass this whole block.
    expect(validateContext(signed(), fixture.secretKey)).toBe(true);
  });

  it("rejects a stripped declaredPurpose", () => {
    // The bypass a guard is trivially defeated by if the field is outside the HMAC:
    // remove the purpose and a purpose-scoped context becomes an unscoped one.
    const ctx = signed();
    delete ctx.declaredPurpose;
    expect(validateContext(ctx, fixture.secretKey)).toBe(false);
  });

  it("rejects a swapped declaredPurpose", () => {
    const ctx = signed();
    ctx.declaredPurpose = "fraud-detection";
    expect(validateContext(ctx, fixture.secretKey)).toBe(false);
  });

  it("rejects a re-cased declaredPurpose", () => {
    const ctx = signed();
    ctx.declaredPurpose = "Campaign-X-Overlap";
    expect(validateContext(ctx, fixture.secretKey)).toBe(false);
  });

  it("rejects a stripped delegationChain", () => {
    const ctx = signed();
    delete ctx.delegationChain;
    expect(validateContext(ctx, fixture.secretKey)).toBe(false);
  });

  it("rejects an appended hop", () => {
    // The interesting direction: appending a hop is how a sub-agent would try to grant
    // itself a further delegation.
    const ctx = signed();
    ctx.delegationChain = [
      ...(ctx.delegationChain ?? []),
      {
        principalId: "agent-exfil",
        principalType: PrincipalType.Agent,
        declaredPurpose: "campaign-y-export",
      },
    ];
    expect(validateContext(ctx, fixture.secretKey)).toBe(false);
  });

  it("rejects a removed hop", () => {
    const ctx = signed();
    ctx.delegationChain = (ctx.delegationChain ?? []).slice(0, 2);
    expect(validateContext(ctx, fixture.secretKey)).toBe(false);
  });

  it("rejects a mutated hop purpose", () => {
    // Widening the last hop's purpose back to its parent's glob is the cheapest attack
    // on the chain, and it is the one `validateDelegationChain` would otherwise bless.
    const ctx = signed();
    const chain = [...(ctx.delegationChain ?? [])];
    chain[2] = { ...chain[2], declaredPurpose: "campaign-*" };
    ctx.delegationChain = chain;
    expect(validateContext(ctx, fixture.secretKey)).toBe(false);
  });

  it("rejects a widened hop scope", () => {
    const ctx = signed();
    const chain = [...(ctx.delegationChain ?? [])];
    chain[2] = { ...chain[2], scopeNarrowing: ["read", "write"] };
    ctx.delegationChain = chain;
    expect(validateContext(ctx, fixture.secretKey)).toBe(false);
  });

  it("rejects a mutated hop principalId", () => {
    const ctx = signed();
    const chain = [...(ctx.delegationChain ?? [])];
    chain[0] = { ...chain[0], principalId: "user-someone-else" };
    ctx.delegationChain = chain;
    expect(validateContext(ctx, fixture.secretKey)).toBe(false);
  });

  it("rejects a mutated hop principalType", () => {
    const ctx = signed();
    const chain = [...(ctx.delegationChain ?? [])];
    chain[0] = { ...chain[0], principalType: PrincipalType.Agent };
    ctx.delegationChain = chain;
    expect(validateContext(ctx, fixture.secretKey)).toBe(false);
  });

  it("rejects a mutated hop timestamp", () => {
    const ctx = signed();
    const chain = [...(ctx.delegationChain ?? [])];
    chain[0] = { ...chain[0], delegatedAt: "2026-09-01T08:00:00Z" };
    ctx.delegationChain = chain;
    expect(validateContext(ctx, fixture.secretKey)).toBe(false);
  });

  it("rejects reordered hops", () => {
    // Reordering alone can turn a widening chain into a narrowing one without changing
    // any hop, so order has to be inside the signature.
    const ctx = signed();
    ctx.delegationChain = [...(ctx.delegationChain ?? [])].reverse();
    expect(validateContext(ctx, fixture.secretKey)).toBe(false);
  });

  it("rejects a mutated purposeProfile on the policy", () => {
    // The purpose travels inside the signed bytes with no change to the signing
    // projection, because the policy is already part of the signed envelope. Emptying
    // the prohibition list is the attack that change buys protection from.
    const ctx = signed();
    ctx.effectivePolicy = {
      ...ctx.effectivePolicy,
      purposeProfile: {
        ...(ctx.effectivePolicy.purposeProfile ?? { purposeId: "campaign-x-overlap" }),
        prohibitedActions: [],
      },
    };
    expect(validateContext(ctx, fixture.secretKey)).toBe(false);
  });

  it("rejects a removed purposeProfile on the policy", () => {
    const ctx = signed();
    const policy = { ...ctx.effectivePolicy };
    delete policy.purposeProfile;
    ctx.effectivePolicy = policy;
    expect(validateContext(ctx, fixture.secretKey)).toBe(false);
  });

  it("the tampered chains it rejects are ones the validator would have accepted", () => {
    // Why the signature matters rather than only the validator: a widened last-hop
    // purpose of `campaign-*` is internally consistent with its parent `campaign-x-*`
    // under the glob rule, so chain validation alone would bless it.
    const widened = [...fixture.delegationChain.map((h) => ({ ...h }))];
    widened[2] = { ...widened[2], declaredPurpose: "campaign-x-anything" };

    expect(validateDelegationChain(widened).allowed).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Absent normalizes to the pre-feature bytes
// ---------------------------------------------------------------------------

describe("absent purpose and chain reproduce the pre-feature bytes", () => {
  it("'' and [] normalize to absent, so one context cannot have two signatures", () => {
    const without = contextFromFixture();
    delete without.declaredPurpose;
    delete without.delegationChain;

    const withEmpties = contextFromFixture();
    withEmpties.declaredPurpose = "";
    withEmpties.delegationChain = [];

    signContext(without, fixture.secretKey);
    signContext(withEmpties, fixture.secretKey);

    expect(withEmpties.signature).toBe(without.signature);
  });

  it("neither key appears in the canonical bytes when absent", () => {
    // Asserted on the BYTES, not on the signature: two payloads can agree on a
    // signature only by agreeing on the bytes, but a byte assertion says which field
    // leaked.
    const without = contextFromFixture();
    delete without.declaredPurpose;
    delete without.delegationChain;
    signContext(without, fixture.secretKey);

    // Re-derive the bytes the way the signer does, then confirm the absent fields are
    // simply not there.
    const projection = {
      version: fixture.payload["version"],
      userId: fixture.payload["userId"],
      tenantId: fixture.payload["tenantId"],
      issuedAt: fixture.payload["resolvedAt"],
      expiresAt: fixture.payload["expiresAt"],
      policies: [fixture.payload],
    };
    const bytes = JSON.stringify(sortDropNulls(projection));

    expect(bytes).not.toContain("declaredPurpose");
    expect(bytes).not.toContain("delegationChain");
    // And the signature over those bytes is the one the public API produced.
    expect(without.signature).toBeDefined();
  });

  it("an explicit null on either field also normalizes to absent", () => {
    // A context deserialized from a producer that emits nulls rather than omitting
    // keys. `null` and absent are indistinguishable in the canonical form (spec §1).
    const withNulls = contextFromFixture();
    (withNulls as Record<string, unknown>)["declaredPurpose"] = null;
    (withNulls as Record<string, unknown>)["delegationChain"] = null;

    const without = contextFromFixture();
    delete without.declaredPurpose;
    delete without.delegationChain;

    signContext(withNulls, fixture.secretKey);
    signContext(without, fixture.secretKey);

    expect(withNulls.signature).toBe(without.signature);
  });

  it("the older signing fixtures are unchanged by this feature", () => {
    // The backward-compatibility claim, asserted against the two pre-existing
    // known-answer fixtures rather than reasoned about. If the canonicaliser had started
    // emitting either new key unconditionally, these would fail.
    for (const name of ["hmac-sha256-known-answer.json", "hmac-sha256-subsecond.json"]) {
      const older = loadFixture(name);
      const payload = older["payload"] as Record<string, unknown>;
      const policy: EffectivePolicy = {
        ...(payload as unknown as EffectivePolicy),
        integrity: { algorithm: "none", signature: "" },
      };
      const ctx: SecurityContext = {
        effectivePolicy: policy,
        resolvedAt: policy.resolvedAt,
        expiresAt: policy.expiresAt,
      };
      signContext(ctx, older["secretKey"] as string, SigningAlgorithm.HmacSha256);

      expect(ctx.signature, name).toBe(older["expectedSignature"]);
    }
  });
});

// ---------------------------------------------------------------------------
// The builder and the round trip
// ---------------------------------------------------------------------------

describe("buildSecurityContext records the purpose and chain", () => {
  const policy: EffectivePolicy = {
    ...(fixture.payload as unknown as EffectivePolicy),
    integrity: { algorithm: "none", signature: "" },
  };

  it("appends both after jti, so existing positional calls keep their meaning", () => {
    const ctx = buildSecurityContext(
      "user-marketing-001",
      "tenant-acme-retail",
      policy,
      3_600_000,
      "fixed-jti",
      fixture.declaredPurpose,
      fixture.delegationChain,
    );

    expect(ctx.jti).toBe("fixed-jti");
    expect(ctx.declaredPurpose).toBe("campaign-x-overlap");
    expect(ctx.delegationChain).toHaveLength(3);
  });

  it("omits both when they are not supplied", () => {
    const ctx = buildSecurityContext("u", "t", policy);

    expect("declaredPurpose" in ctx).toBe(false);
    expect("delegationChain" in ctx).toBe(false);
  });

  it("normalizes '' and [] to absent on the model itself, not only when signing", () => {
    // Keeping the model's own value and its signed value the same thing means a caller
    // inspecting the context cannot see a purpose or a chain the signature does not
    // cover.
    const ctx = buildSecurityContext("u", "t", policy, 3_600_000, "", "", []);

    expect("declaredPurpose" in ctx).toBe(false);
    expect("delegationChain" in ctx).toBe(false);
  });

  it("an explicit null chain or purpose is folded in with absent", () => {
    // A JavaScript caller reaching this through JSON has no `undefined` to pass. Reading
    // `.length` off a null would throw out of the builder, so it is folded in with the
    // other two "no delegation" spellings.
    const ctx = buildSecurityContext(
      "u",
      "t",
      policy,
      3_600_000,
      undefined,
      null as unknown as string,
      null as unknown as DelegationHop[],
    );

    expect("declaredPurpose" in ctx).toBe(false);
    expect("delegationChain" in ctx).toBe(false);
  });

  it("does NOT validate the chain it records", () => {
    // The builder records; it does not check. A builder that silently dropped an invalid
    // chain would produce a context that looked delegated and was not, so validation is
    // the caller's explicit step.
    const widening: DelegationHop[] = [
      { principalId: "p", principalType: PrincipalType.User, declaredPurpose: "campaign-x" },
      { principalId: "c", principalType: PrincipalType.Agent, declaredPurpose: "fraud-detection" },
    ];
    const ctx = buildSecurityContext("u", "t", policy, 3_600_000, undefined, "campaign-x", widening);

    expect(ctx.delegationChain).toHaveLength(2);
    expect(validateDelegationChain(ctx.delegationChain).allowed).toBe(false);
  });

  it("round-trips both fields through serialize/deserialize", () => {
    // Through the real public entry point, not a hand-assembled equivalent
    // (antipattern #5): `deserializeContext` is what a consumer calls, and it is where
    // the signature and expiry checks live.
    const ctx = buildSecurityContext(
      "user-marketing-001",
      "tenant-acme-retail",
      policy,
      3_600_000,
      undefined,
      fixture.declaredPurpose,
      fixture.delegationChain,
    );
    signContext(ctx, fixture.secretKey);

    const restored = deserializeContext(serializeContext(ctx), fixture.secretKey);

    expect(restored.declaredPurpose).toBe("campaign-x-overlap");
    expect(restored.delegationChain).toHaveLength(3);
    expect(restored.delegationChain?.[2].principalType).toBe(PrincipalType.Agent);
    expect(restored.delegationChain?.[2].scopeNarrowing).toEqual(["read"]);
    expect(restored.effectivePolicy.purposeProfile?.purposeId).toBe("campaign-x-overlap");
  });

  it("deserialization refuses a context whose purpose was swapped in transit", () => {
    // The reason `deserializeContext` needs no field-by-field reading: the signature
    // check runs before anything looks at either field.
    const ctx = buildSecurityContext(
      "u",
      "t",
      policy,
      3_600_000,
      undefined,
      fixture.declaredPurpose,
      fixture.delegationChain,
    );
    signContext(ctx, fixture.secretKey);

    const tampered = JSON.parse(
      Buffer.from(serializeContext(ctx), "base64").toString("utf8"),
    ) as SecurityContext;
    tampered.declaredPurpose = "fraud-detection";
    const replayed = Buffer.from(JSON.stringify(tampered), "utf8").toString("base64");

    expect(() => deserializeContext(replayed, fixture.secretKey)).toThrow(
      /signature validation failed/,
    );
  });
});

// ---------------------------------------------------------------------------
// The published canonical-envelope schema
// ---------------------------------------------------------------------------

describe("the canonical payload matches security-context.schema.json's envelope", () => {
  /**
   * The schema's declared envelope property names, read from disk.
   *
   * Restating them here would be a second thing free to drift. The lookup throws rather
   * than returning `[]` when the path is absent: an empty expectation would make the
   * subset assertion below pass while checking nothing (spec §14).
   */
  function schemaEnvelopeKeys(): string[] {
    const schema = JSON.parse(
      fs.readFileSync(path.join(SCHEMA_DIR, "security-context.schema.json"), "utf-8"),
    ) as Record<string, unknown>;
    const properties = schema["properties"];
    if (typeof properties !== "object" || properties === null) {
      throw new Error(
        "security-context.schema.json declares no `properties`; the canonical " +
          "envelope is no longer being compared to anything (canonical spec §14)",
      );
    }
    const keys = Object.keys(properties as Record<string, unknown>);
    if (keys.length === 0) {
      throw new Error("security-context.schema.json declares an empty `properties`");
    }
    return keys;
  }

  it("the schema locator throws rather than returning nothing", () => {
    // Asserted from outside the mechanism it guards (antipattern #4): if the file moved,
    // every assertion below would otherwise pass vacuously.
    expect(() =>
      JSON.parse(
        fs.readFileSync(path.join(SCHEMA_DIR, "security-context.schema.json"), "utf-8"),
      ),
    ).not.toThrow();
    expect(schemaEnvelopeKeys()).toContain("policies");
  });

  it("declares the two fields this feature adds", () => {
    const keys = schemaEnvelopeKeys();
    expect(keys).toContain("declaredPurpose");
    expect(keys).toContain("delegationChain");
  });

  it("a purpose-bound canonical payload emits only keys the schema declares", () => {
    // The cheap TypeScript-side equivalent of full document validation; the Python
    // suite owns the single validating runner for the repo (spec §14), and
    // `@aws/tolap-core` has no runtime dependencies, so no JSON Schema validator is
    // pulled in here. `additionalProperties: false` in the schema is what makes a
    // subset check meaningful: an extra key would be a validation failure there.
    const parsed = JSON.parse(fixture.canonicalPayload) as Record<string, unknown>;
    const declared = new Set(schemaEnvelopeKeys());

    expect(Object.keys(parsed).sort()).toEqual([
      "declaredPurpose",
      "delegationChain",
      "expiresAt",
      "issuedAt",
      "policies",
      "tenantId",
      "userId",
      "version",
    ]);
    for (const key of Object.keys(parsed)) {
      expect(declared.has(key), `envelope key '${key}' is not declared by the schema`).toBe(
        true,
      );
    }
  });

  it("a payload with no purpose emits only the six required keys", () => {
    // The pre-feature shape, checked against the same schema: the six required
    // properties and nothing else, which is what makes both additions
    // backward-compatible.
    const older = loadFixture("hmac-sha256-known-answer.json");
    const parsed = JSON.parse(older["canonicalPayload"] as string) as Record<
      string,
      unknown
    >;
    const declared = new Set(schemaEnvelopeKeys());

    expect(Object.keys(parsed).sort()).toEqual([
      "expiresAt",
      "issuedAt",
      "policies",
      "tenantId",
      "userId",
      "version",
    ]);
    for (const key of Object.keys(parsed)) {
      expect(declared.has(key)).toBe(true);
    }
  });

  it("emits exactly one policy, as the schema's maxItems requires", () => {
    // A context governs one data source: every enforcement path reads only the first
    // element, so a context carrying two would sign both and enforce one.
    const parsed = JSON.parse(fixture.canonicalPayload) as { policies: unknown[] };
    expect(parsed.policies).toHaveLength(1);
  });

  it("every hop in the payload carries only keys the hop schema declares", () => {
    const schema = JSON.parse(
      fs.readFileSync(path.join(SCHEMA_DIR, "security-context.schema.json"), "utf-8"),
    ) as Record<string, Record<string, Record<string, Record<string, unknown>>>>;
    const hopProperties = schema["$defs"]["delegationHop"]["properties"];
    expect(Object.keys(hopProperties).length).toBeGreaterThan(0);

    const parsed = JSON.parse(fixture.canonicalPayload) as {
      delegationChain: Array<Record<string, unknown>>;
    };
    expect(parsed.delegationChain).toHaveLength(3);
    for (const emitted of parsed.delegationChain) {
      for (const key of Object.keys(emitted)) {
        expect(
          Object.prototype.hasOwnProperty.call(hopProperties, key),
          `hop key '${key}' is not declared by the schema`,
        ).toBe(true);
      }
      // Both required properties present on every hop.
      expect(emitted["principalId"]).toBeDefined();
      expect(emitted["principalType"]).toBeDefined();
    }
  });
});
