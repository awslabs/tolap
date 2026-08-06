/**
 * Section 3: `[]` and `null` mean opposite things, and persistence must not
 * blur them.
 *
 * For an allow-list, absent/`null` means *unrestricted* and `[]` means *deny
 * everything*. A datastore that coerces one into the other converts the most
 * restrictive policy expressible into no restriction at all -- silently, with no
 * error and nothing in the audit log. That is the single most dangerous bug
 * available in this layer, which is why it gets its own suite asserted against a
 * real database rather than a fake.
 *
 * The tests deliberately go further than "the JSON round-trips": they feed the
 * stored policy through the SDK's real enforcement engine and assert the
 * *decision*, because a body that round-trips but enforces wrongly is the failure
 * that matters.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { PolicyDefinition } from "@tolap/core";
import { validateFieldAccess } from "@tolap/core";
import { PostgresPolicyStore } from "../src/db/store.ts";
import { ADMIN, HAVE_DB, staticIdentity, testDb, type TestDb } from "./helpers/db.ts";

describe("null vs empty array (spec section 3)", () => {
  it("guard: the skip condition is a real boolean", () => {
    // Not behind the skip. If HAVE_DB were undefined-y in a way that made
    // `skipIf` always skip, every assertion below would vacuously pass and this
    // suite would be decoration.
    expect(typeof HAVE_DB).toBe("boolean");
  });

  describe.skipIf(!HAVE_DB)("against PostgreSQL", () => {
    let db: TestDb;
    let store: PostgresPolicyStore;

    beforeAll(async () => {
      db = await testDb("nullempty");
      store = new PostgresPolicyStore(db.pool, staticIdentity());
    });

    afterAll(async () => {
      await db?.close();
    });

    const define = (
      name: string,
      fieldRules: Record<string, unknown>,
    ): PolicyDefinition =>
      ({
        version: "1.0",
        name,
        permissions: { canQuery: true, readOnly: true },
        objectRules: { fieldRules },
      }) as PolicyDefinition;

    it("preserves an empty allowedFields array", async () => {
      await store.putDefinitionAs(define("deny-all-fields", { allowedFields: [] }), ADMIN);
      const loaded = await store.getDefinition("deny-all-fields");

      const allowed = loaded?.objectRules?.fieldRules?.allowedFields;
      expect(Array.isArray(allowed)).toBe(true);
      expect(allowed).toEqual([]);
      // The distinction that matters: it must not have become null or absent.
      expect(allowed).not.toBeNull();
      expect(allowed).not.toBeUndefined();
    });

    it("an empty allowedFields still denies every field after a round trip", async () => {
      await store.putDefinitionAs(define("deny-all-2", { allowedFields: [] }), ADMIN);
      const loaded = await store.getDefinition("deny-all-2");

      const result = validateFieldAccess(["name", "email"], {
        objectRules: loaded!.objectRules,
      } as never);

      // This is the assertion the whole suite exists for. If persistence had
      // coerced [] to null, every field would be allowed here.
      expect(result.denied).toEqual(expect.arrayContaining(["name", "email"]));
      expect(result.allowed).toEqual([]);
    });

    it("preserves absent allowedFields as unrestricted", async () => {
      await store.putDefinitionAs(
        define("unrestricted", { hiddenFields: ["ssn"] }),
        ADMIN,
      );
      const loaded = await store.getDefinition("unrestricted");

      expect(loaded?.objectRules?.fieldRules?.allowedFields).toBeUndefined();

      const result = validateFieldAccess(["name", "ssn"], {
        objectRules: loaded!.objectRules,
      } as never);
      // Absent allow-list means unrestricted, so `name` passes -- while the
      // hidden list still bites.
      expect(result.allowed).toContain("name");
      expect(result.denied).toContain("ssn");
    });

    it("keeps [] and absent distinguishable when stored side by side", async () => {
      await store.putDefinitionAs(define("empty-list", { allowedFields: [] }), ADMIN);
      await store.putDefinitionAs(define("no-list", {}), ADMIN);

      const empty = await store.getDefinition("empty-list");
      const absent = await store.getDefinition("no-list");

      expect(empty?.objectRules?.fieldRules?.allowedFields).toEqual([]);
      expect(absent?.objectRules?.fieldRules?.allowedFields).toBeUndefined();
    });

    it("preserves empty arrays nested several levels deep", async () => {
      const policy = {
        version: "1.0",
        name: "nested-empties",
        permissions: { canQuery: true },
        objectRules: {
          allowedObjects: [],
          fieldRules: { allowedFields: [], hiddenFields: [], maskedFields: [] },
          tagRules: { allowedTags: [], deniedTags: [] },
          endpointRules: { allowedEndpoints: [], allowedMethods: [] },
          rowFilters: [],
        },
      } as unknown as PolicyDefinition;

      await store.putDefinitionAs(policy, ADMIN);
      const loaded = await store.getDefinition("nested-empties");

      // Every one of these is an allow-list whose emptiness means deny-all.
      expect(loaded?.objectRules?.allowedObjects).toEqual([]);
      expect(loaded?.objectRules?.fieldRules?.allowedFields).toEqual([]);
      expect(loaded?.objectRules?.fieldRules?.hiddenFields).toEqual([]);
      expect(loaded?.objectRules?.tagRules?.allowedTags).toEqual([]);
      expect(loaded?.objectRules?.endpointRules?.allowedEndpoints).toEqual([]);
      expect(loaded?.objectRules?.rowFilters).toEqual([]);
    });

    it("preserves sourcePatterns: [] which means every source (section 10)", async () => {
      // The one documented place `[]` is NOT deny-all: section 10 scope
      // declaration. Storage must not "fix" this into consistency with section 3.
      const policy = {
        version: "1.0",
        name: "all-sources",
        permissions: { canQuery: true },
        sourcePatterns: [],
      } as unknown as PolicyDefinition;

      await store.putDefinitionAs(policy, ADMIN);
      const loaded = await store.getDefinition("all-sources");
      expect(loaded?.sourcePatterns).toEqual([]);
    });

    it("preserves non-ASCII text and false booleans", async () => {
      const policy = {
        version: "1.0",
        name: "unicode-and-false",
        description: "café ✓ 日本語 — em dash",
        // `false` is the other value a truthiness check silently loses.
        permissions: { canQuery: false, readOnly: false },
      } as unknown as PolicyDefinition;

      await store.putDefinitionAs(policy, ADMIN);
      const loaded = await store.getDefinition("unicode-and-false");

      expect(loaded?.description).toBe("café ✓ 日本語 — em dash");
      expect(loaded?.permissions.canQuery).toBe(false);
      expect(loaded?.permissions.readOnly).toBe(false);
    });

    it("survives the version history path too", async () => {
      // saveDraft/publish take a different code path than putDefinition, so the
      // same guarantee is asserted there rather than assumed.
      const policy = define("versioned-empty", { allowedFields: [] });
      const versionNo = await store.saveDraft(policy, ADMIN, "initial");
      await store.publish("versioned-empty", versionNo, ADMIN);

      const published = await store.getDefinition("versioned-empty");
      expect(published?.objectRules?.fieldRules?.allowedFields).toEqual([]);

      const versions = await store.listVersions("versioned-empty");
      expect(versions[0].policy.objectRules?.fieldRules?.allowedFields).toEqual([]);
    });
  });
});
