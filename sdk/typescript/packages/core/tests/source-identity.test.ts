/**
 * Source identity parsing (connector-spec §1).
 *
 * `category:namespace:name`, where the category is one of a fixed set of four. The
 * parser exists because the category decides which wrapper enforces a source, and
 * that decision must be driven by the *signed* identifier rather than by unsigned
 * configuration — a category that could be flipped from `db` to `api` would select
 * the wrapper that enforces the other category's rules, and `endpointRules` do not
 * constrain a SQL query.
 *
 * So the rejection cases below matter as much as the accepting ones: every one of
 * them yields `undefined`, and every caller in this SDK treats `undefined` as a
 * refusal to produce a tool. A parser that guessed would guess a wrapper.
 */

import { describe, expect, it } from "vitest";
import {
  SourceCategory,
  parseSourceIdentity,
  sourceCategory,
} from "../src/source-identity.js";

describe("parseSourceIdentity: the four categories", () => {
  it.each([
    ["db", SourceCategory.Db],
    ["api", SourceCategory.Api],
    ["kb", SourceCategory.Kb],
    ["storage", SourceCategory.Storage],
  ])("accepts %s", (segment, expected) => {
    const parsed = parseSourceIdentity(`${segment}:production:patients`);
    expect(parsed).toEqual({
      category: expected,
      namespace: "production",
      name: "patients",
    });
  });

  it("rejects a category outside the fixed set", () => {
    // §1 calls the set fixed and §10 makes adding one a breaking change, so an
    // unknown category is not a forward-compatible extension point -- it is a
    // source no wrapper knows how to enforce.
    expect(parseSourceIdentity("graph:production:people")).toBeUndefined();
    expect(parseSourceIdentity("DATABASE:production:patients")).toBeUndefined();
  });

  it("matches the category case-insensitively and returns it lower-cased", () => {
    // Consistent with the case-insensitive `sourcePatterns` matching of enforcement
    // spec §10: the same identifier must resolve to the same category regardless of
    // how it was cased upstream.
    expect(parseSourceIdentity("DB:production:patients")?.category).toBe(SourceCategory.Db);
    expect(parseSourceIdentity("Api:internal:orders")?.category).toBe(SourceCategory.Api);
  });

  it("leaves namespace and name verbatim, including their case", () => {
    // Both are opaque to TOLAP (§1). Folding their case here would make the parser
    // claim the identifier says something it does not.
    const parsed = parseSourceIdentity("db:Production:Patient_Records");
    expect(parsed?.namespace).toBe("Production");
    expect(parsed?.name).toBe("Patient_Records");
  });
});

describe("parseSourceIdentity: exactly three segments", () => {
  it("rejects two segments", () => {
    // The documented authoring mistake in reverse: `db:production` is not a source.
    expect(parseSourceIdentity("db:production")).toBeUndefined();
  });

  it("rejects one segment", () => {
    expect(parseSourceIdentity("db")).toBeUndefined();
  });

  it("rejects four or more segments", () => {
    // Not silently truncated to the first three: an identifier carrying a fourth
    // segment means something the spec does not define, and treating it as a
    // three-segment source would enforce a policy the author did not write.
    expect(parseSourceIdentity("db:production:patients:extra")).toBeUndefined();
  });

  it("rejects an empty segment", () => {
    // `db::` has three segments but names no source, and it would match a
    // `db:*:*` pattern -- so a policy scoped to that pattern would appear to
    // govern it.
    expect(parseSourceIdentity("db::")).toBeUndefined();
    expect(parseSourceIdentity("db::patients")).toBeUndefined();
    expect(parseSourceIdentity("db:production:")).toBeUndefined();
    expect(parseSourceIdentity(":production:patients")).toBeUndefined();
  });

  it("rejects the empty string and undefined", () => {
    expect(parseSourceIdentity("")).toBeUndefined();
    expect(parseSourceIdentity(undefined)).toBeUndefined();
  });
});

describe("sourceCategory", () => {
  it("returns just the category for a valid identifier", () => {
    expect(sourceCategory("kb:research:trials")).toBe(SourceCategory.Kb);
  });

  it("returns undefined for anything the parser rejects", () => {
    expect(sourceCategory("db:production")).toBeUndefined();
    expect(sourceCategory("nope:a:b")).toBeUndefined();
    expect(sourceCategory(undefined)).toBeUndefined();
  });
});
