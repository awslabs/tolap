/**
 * Regression tests for mask-restrictiveness ranking during a merge.
 *
 * Defect 7 in docs/canonical-enforcement-spec.md §6: the previous ranking put
 * `null` and `redact` *lowest*, so merging `ssn: null` with `ssn: partial`
 * produced `partial` -- disclosing real SSN digits that one policy had demanded
 * be erased entirely.
 */

import { describe, it, expect } from "vitest";
import { merge } from "../src/merger.js";
import { MASK_RESTRICTIVENESS, maskRestrictiveness } from "../src/types.js";
import type { PolicyDefinition } from "../src/types.js";

function definition(
  name: string,
  maskedFields: Array<Record<string, unknown>>,
  priority = 10,
): PolicyDefinition {
  return {
    version: "1.0",
    name,
    priority,
    permissions: { canQuery: true },
    objectRules: {
      fieldRules: { maskedFields: maskedFields as never },
    },
  };
}

describe("defect 7: merging picks the least-disclosing mask type", () => {
  it("EXPLOIT: null beats partial, so real SSN digits are not disclosed", () => {
    const result = merge([
      definition("erase-ssn", [{ field: "ssn", maskType: "null" }], 10),
      definition(
        "show-last-4",
        [
          {
            field: "ssn",
            maskType: "partial",
            parameters: { showLast: 4, maskChar: "*" },
          },
        ],
        20,
      ),
    ]);

    const rule = result.objectRules?.fieldRules?.maskedFields?.find(
      (m) => m.field === "ssn",
    );
    expect(rule?.maskType).toBe("null");
  });

  it("redact beats hash and full", () => {
    const result = merge([
      definition("hash-email", [{ field: "email", maskType: "hash" }], 10),
      definition("redact-email", [{ field: "email", maskType: "redact" }], 20),
      definition("full-email", [{ field: "email", maskType: "full" }], 30),
    ]);

    const rule = result.objectRules?.fieldRules?.maskedFields?.find(
      (m) => m.field === "email",
    );
    expect(rule?.maskType).toBe("redact");
  });

  it("full beats hash, and hash beats partial", () => {
    const fullVsHash = merge([
      definition("a", [{ field: "x", maskType: "hash" }], 10),
      definition("b", [{ field: "x", maskType: "full" }], 20),
    ]);
    const hashVsPartial = merge([
      definition("a", [{ field: "y", maskType: "partial" }], 10),
      definition("b", [{ field: "y", maskType: "hash" }], 20),
    ]);

    expect(
      fullVsHash.objectRules?.fieldRules?.maskedFields?.[0].maskType,
    ).toBe("full");
    expect(
      hashVsPartial.objectRules?.fieldRules?.maskedFields?.[0].maskType,
    ).toBe("hash");
  });

  it("an unknown mask type wins over every known type", () => {
    // A typo or a type from a newer schema version must not be downgraded into a
    // weaker known type just because this SDK does not recognize it.
    const result = merge([
      definition("unknown", [{ field: "ssn", maskType: "tokenize-v2" }], 10),
      definition("weak", [{ field: "ssn", maskType: "null" }], 20),
    ]);

    expect(
      result.objectRules?.fieldRules?.maskedFields?.[0].maskType,
    ).toBe("tokenize-v2");
    expect(maskRestrictiveness("tokenize-v2")).toBeGreaterThan(
      Math.max(...Object.values(MASK_RESTRICTIVENESS)),
    );
  });

  it("the ranking is strictly ordered by disclosure", () => {
    const ordered = ["partial", "hash", "full", "redact", "null"];
    const ranks = ordered.map((m) => MASK_RESTRICTIVENESS[m]);

    for (let i = 1; i < ranks.length; i++) {
      expect(ranks[i]).toBeGreaterThan(ranks[i - 1]);
    }
  });
});
