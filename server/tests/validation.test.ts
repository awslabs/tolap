/**
 * Schema validation.
 *
 * The load-bearing assertion here is the fixture sweep: the server's validator
 * must agree with every fixture the repository already ships, *including* the two
 * `invalid-` ones it must reject. A validator that accepts everything would pass a
 * suite of hand-written valid cases and fail only in production, so the negative
 * fixtures are what make this meaningful.
 */

import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import {
  SchemaValidationError,
  assertValidDefinition,
  validateSchema,
} from "../src/validation.ts";

const REPO = path.resolve(__dirname, "../..");

const readJson = (file: string): unknown =>
  JSON.parse(readFileSync(file, "utf8"));

const MINIMAL = {
  version: "1.0",
  name: "minimal-policy",
  permissions: { canQuery: true },
};

describe("document validation", () => {
  it("accepts a minimal valid definition", () => {
    expect(validateSchema(MINIMAL, "policy-definition")).toEqual({
      valid: true,
      errors: [],
    });
  });

  it("reports every error, not just the first", () => {
    const bad = { version: "2.0", name: "Bad Name", permissions: {} };
    const result = validateSchema(bad, "policy-definition");

    expect(result.valid).toBe(false);
    // Three independent problems: wrong version const, name pattern, missing
    // canQuery. An author should see all of them at once.
    const paths = result.errors.map((e) => e.path);
    expect(paths).toContain("/version");
    expect(paths).toContain("/name");
    expect(paths).toContain("/permissions");
  });

  it("rejects unknown properties", () => {
    // The schemas set additionalProperties: false throughout. A typo'd key that
    // silently persisted would be a rule the author believes is in force and
    // which enforces nothing.
    const result = validateSchema(
      { ...MINIMAL, objectRulez: { allowedObjects: ["x"] } },
      "policy-definition",
    );
    expect(result.valid).toBe(false);
  });

  it("names the document root as '/' rather than an empty string", () => {
    const result = validateSchema({ version: "1.0" }, "policy-definition");
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.path === "/")).toBe(true);
  });

  it("returns a stable error order", () => {
    const bad = { version: "9", name: "X X", permissions: {}, bogus: 1 };
    const a = validateSchema(bad, "policy-definition");
    const b = validateSchema(bad, "policy-definition");
    expect(a.errors).toEqual(b.errors);
  });

  it("validates assignments too", () => {
    expect(
      validateSchema({ version: "1.0" }, "policy-assignment").valid,
    ).toBe(false);
  });
});

describe("fragment validation", () => {
  it("accepts a partially authored draft", () => {
    // The console validates as someone types; demanding a complete document on the
    // first keystroke would make live validation useless.
    expect(
      validateSchema({ name: "draft-policy" }, "policy-definition", {
        fragment: true,
      }).valid,
    ).toBe(true);
  });

  it("still enforces types, patterns and enums", () => {
    const draft = { name: "Bad Name" };
    expect(
      validateSchema(draft, "policy-definition", { fragment: true }).valid,
    ).toBe(false);

    expect(
      validateSchema(
        { limits: { maxResults: -5 } },
        "policy-definition",
        { fragment: true },
      ).valid,
    ).toBe(false);
  });

  it("still enforces nested required properties", () => {
    // A masking rule missing maskType is a mistake even in a draft, so only the
    // *top-level* required list is relaxed.
    const draft = {
      objectRules: { fieldRules: { maskedFields: [{ field: "ssn" }] } },
    };
    const result = validateSchema(draft, "policy-definition", {
      fragment: true,
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.message.includes("maskType"))).toBe(true);
  });

  it("still rejects unknown properties", () => {
    expect(
      validateSchema({ nonsense: true }, "policy-definition", {
        fragment: true,
      }).valid,
    ).toBe(false);
  });

  it("does not leak its relaxation into document mode", () => {
    // The two validators share a loaded schema object; the fragment build must
    // deep-clone before deleting `required`.
    validateSchema({ name: "x" }, "policy-definition", { fragment: true });
    expect(validateSchema({ name: "x" }, "policy-definition").valid).toBe(false);
  });
});

describe("agreement with the repository fixtures", () => {
  const policyFixtures = readdirSync(path.join(REPO, "fixtures/policies"));

  it("finds fixtures to check", () => {
    // A glob that matched nothing would make the sweep below vacuous.
    expect(policyFixtures.length).toBeGreaterThan(0);
    expect(policyFixtures.some((f) => f.startsWith("invalid-"))).toBe(true);
  });

  it.each(policyFixtures)("agrees on fixtures/policies/%s", (file) => {
    const data = readJson(path.join(REPO, "fixtures/policies", file));
    const shouldBeInvalid = file.startsWith("invalid-");
    const result = validateSchema(data, "policy-definition");

    expect(
      result.valid,
      shouldBeInvalid
        ? `${file} must be rejected but was accepted`
        : `${file} must be accepted but was rejected: ${JSON.stringify(result.errors)}`,
    ).toBe(!shouldBeInvalid);
  });

  const examples = readdirSync(path.join(REPO, "schema/v1.0/examples"));

  it.each(examples)("accepts schema/v1.0/examples/%s", (file) => {
    const data = readJson(path.join(REPO, "schema/v1.0/examples", file));
    const result = validateSchema(data, "policy-definition");
    expect(result.valid, JSON.stringify(result.errors)).toBe(true);
  });

  const assignments = readdirSync(path.join(REPO, "fixtures/assignments"));

  it.each(assignments)("accepts fixtures/assignments/%s", (file) => {
    const data = readJson(path.join(REPO, "fixtures/assignments", file));
    const result = validateSchema(data, "policy-assignment");
    expect(result.valid, JSON.stringify(result.errors)).toBe(true);
  });
});

describe("assertValidDefinition", () => {
  it("passes a valid definition", () => {
    expect(() => assertValidDefinition(MINIMAL)).not.toThrow();
  });

  it("throws with every error attached", () => {
    try {
      assertValidDefinition({ version: "2.0", permissions: {} });
      throw new Error("expected a validation failure");
    } catch (error) {
      expect(error).toBeInstanceOf(SchemaValidationError);
      const failure = error as SchemaValidationError;
      expect(failure.errors.length).toBeGreaterThan(1);
      // The message must name the problems; a bare "invalid policy" would send
      // the author back to the schema to guess.
      expect(failure.message).toContain("/version");
    }
  });
});

describe("empty-array handling (spec section 3)", () => {
  it("accepts an empty allow-list, which means deny everything", () => {
    // The validator must not treat [] as a missing value: it is the most
    // restrictive policy expressible and has to survive validation to be saved.
    const policy = {
      ...MINIMAL,
      objectRules: { allowedObjects: [], fieldRules: { allowedFields: [] } },
    };
    expect(validateSchema(policy, "policy-definition").valid).toBe(true);
  });

  it("accepts sourcePatterns: [] which means every source (section 10)", () => {
    expect(
      validateSchema({ ...MINIMAL, sourcePatterns: [] }, "policy-definition")
        .valid,
    ).toBe(true);
  });

  it("accepts maxResults: 0, a coherent deny-all", () => {
    // The schema documents zero as valid precisely because a minimum of 1 would
    // make "return nothing" inexpressible.
    expect(
      validateSchema({ ...MINIMAL, limits: { maxResults: 0 } }, "policy-definition")
        .valid,
    ).toBe(true);
  });
});
