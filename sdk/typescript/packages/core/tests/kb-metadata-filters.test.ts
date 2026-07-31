/**
 * Provider-side kb metadata filters (connector-spec §7).
 *
 * Two distinct things are asserted here, and the second matters more than the first.
 *
 * **1. Cross-SDK agreement**, driven by
 * `fixtures/enforcement/kb-metadata-filters.json`. The Python and .NET suites read the same
 * file case-for-case, so a divergence in how a policy renders for a provider fails
 * somewhere.
 *
 * **2. The safety property**, which no fixture can express: a pushdown must never exclude a
 * chunk the policy permits. §7 calls a provider filter "an optimization on the same footing
 * as SQL rewriting, never a replacement for the post pass", and the reason it can only ever
 * be advisory is structural — post-retrieval extraction reads tags recursively,
 * case-insensitively, from `tags`/`Tags`/`labels`/`classification`/`metadata.tags`, and no
 * provider filter reproduces that. It filters one indexed field.
 *
 * So the asymmetry is deliberate: a filter matching *nothing* costs efficiency and nothing
 * else, because the post pass is unconditional. A filter matching *too little* is a
 * correctness bug. The final describe block simulates a provider applying our clause and
 * asserts the first never happens.
 */

import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";

import { buildKbFilter, filterByTags } from "../src/enforcement.js";
import {
  DEFAULT_KB_METADATA_KEYS,
  KbFilterOp,
  buildKbFilter as buildFromFilterModule,
} from "../src/kb-filter.js";
import { KbProvider, renderKbFilter } from "../src/kb-providers.js";
import type { EffectivePolicy, TagRules } from "../src/types.js";

const fixturePath = path.resolve(
  __dirname,
  "../../../../../fixtures/enforcement/kb-metadata-filters.json",
);

interface FixtureCase {
  name: string;
  note: string;
  /** A real policy fragment, so the shared schema-validation walk covers it too. */
  policy: { objectRules?: { tagRules?: TagRules } };
  metadataKeys: string[];
  expected: {
    clauses: Array<{ key: string; op: string; values: string[] }>;
    deniesEverything: boolean;
    unpushedRules: string[];
    rendered: Record<string, unknown>;
  };
}

const fixture = JSON.parse(fs.readFileSync(fixturePath, "utf-8")) as {
  cases: FixtureCase[];
  pgvectorColumn: string;
};

function policy(tagRules: TagRules): EffectivePolicy {
  return {
    version: "1.0",
    userId: "u",
    tenantId: "t",
    sourceConnectionId: "kb:research:trials",
    resolvedAt: "2026-01-01T00:00:00Z",
    expiresAt: "2027-01-01T00:00:00Z",
    sourceProfiles: [],
    permissions: { canQuery: true },
    objectRules: { tagRules },
    integrity: { algorithm: "none", signature: "" },
  };
}

// ---------------------------------------------------------------------------
// The shared corpus
// ---------------------------------------------------------------------------

describe("§7 parity: the shared corpus renders identically", () => {
  it("the corpus carries the expected case count", () => {
    // A case dropped from the fixture is coverage lost silently.
    expect(fixture.cases).toHaveLength(7);
  });

  for (const testCase of fixture.cases) {
    describe(testCase.name, () => {
      const result = buildFromFilterModule(
        policy(testCase.policy.objectRules?.tagRules ?? {}),
        { metadataKeys: testCase.metadataKeys },
      );

      it(`neutral clauses match (${testCase.note.slice(0, 60)}…)`, () => {
        expect(result.clauses).toEqual(testCase.expected.clauses);
      });

      it("deniesEverything matches", () => {
        expect(result.deniesEverything).toBe(testCase.expected.deniesEverything);
      });

      it("the unpushed rules match", () => {
        expect(result.unpushedRules.map((r) => r.rule)).toEqual(
          testCase.expected.unpushedRules,
        );
      });

      for (const provider of Object.values(KbProvider)) {
        it(`renders for ${provider}`, () => {
          const rendered = renderKbFilter(result, provider, {
            pgvectorColumn: fixture.pgvectorColumn,
          });
          expect(rendered.filter).toEqual(testCase.expected.rendered[provider]);
        });
      }
    });
  }
});

// ---------------------------------------------------------------------------
// Deny-all must not render as "no restriction"
// ---------------------------------------------------------------------------

describe("EXPLOIT: an empty allowedTags must not become a no-op filter", () => {
  it("reports deniesEverything and renders no filter", () => {
    // The fail-open this guards. `allowedTags: []` denies every chunk (spec §3), and no
    // portable metadata predicate means match-nothing. Emitting an empty filter and
    // retrieving anyway would return everything, so the flag is the contract: skip
    // retrieval.
    const result = buildFromFilterModule(policy({ allowedTags: [] }));

    expect(result.deniesEverything).toBe(true);
    expect(result.clauses).toEqual([]);
    expect(result.unpushedRules).toHaveLength(1);

    for (const provider of Object.values(KbProvider)) {
      const rendered = renderKbFilter(result, provider);
      expect(rendered.filter).toBeNull();
      expect(rendered.deniesEverything).toBe(true);
    }
  });

  it("is distinguishable from 'nothing to push'", () => {
    // An empty deniedTags also yields no clauses, but denies nothing. The two must not be
    // conflated: one means skip retrieval, the other means retrieve unfiltered.
    const nothingToPush = buildFromFilterModule(policy({ deniedTags: [] }));

    expect(nothingToPush.clauses).toEqual([]);
    expect(nothingToPush.deniesEverything).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Values are normalized so the three SDKs agree byte-for-byte
// ---------------------------------------------------------------------------

describe("value normalization", () => {
  it("lower-cases tag values, matching filterByTags", () => {
    const result = buildFromFilterModule(policy({ deniedTags: ["SECRET", "Restricted"] }), {
      metadataKeys: ["classification"],
    });

    expect(result.clauses[0].values).toEqual(["restricted", "secret"]);
  });

  it("de-duplicates and sorts, so rendering is stable across SDKs", () => {
    // Unstable ordering would make the shared fixture fail for the wrong reason — a
    // difference in iteration order rather than in semantics.
    const result = buildFromFilterModule(
      policy({ deniedTags: ["b", "a", "B", "a"] }),
      { metadataKeys: ["classification"] },
    );

    expect(result.clauses[0].values).toEqual(["a", "b"]);
  });

  it("defaults to the documented metadata keys", () => {
    const result = buildFromFilterModule(policy({ deniedTags: ["secret"] }));

    expect(result.clauses.map((c) => c.key)).toEqual([...DEFAULT_KB_METADATA_KEYS]);
  });

  it("no tagRules yields nothing at all", () => {
    const bare = policy({});
    delete (bare.objectRules as Record<string, unknown>)["tagRules"];

    const result = buildFromFilterModule(bare);
    expect(result.clauses).toEqual([]);
    expect(result.deniesEverything).toBe(false);
    expect(result.unpushedRules).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Renderers refuse values they cannot express, rather than mangling them
// ---------------------------------------------------------------------------

describe("a renderer refuses what it cannot express", () => {
  it("Azure refuses a tag containing a comma", () => {
    // `search.in` is comma-delimited, so a comma inside a value would silently change
    // which set matches. Refusing yields an unpushed rule; the post pass still enforces.
    const result = buildFromFilterModule(policy({ deniedTags: ["a,b"] }), {
      metadataKeys: ["classification"],
    });
    const rendered = renderKbFilter(result, KbProvider.AzureAiSearch);

    expect(rendered.filter).toBeNull();
    expect(rendered.unpushedRules.length).toBeGreaterThan(0);
  });

  it("Vertex refuses a tag containing a double quote", () => {
    const result = buildFromFilterModule(policy({ deniedTags: ['a"b'] }), {
      metadataKeys: ["classification"],
    });
    const rendered = renderKbFilter(result, KbProvider.VertexAiSearch);

    expect(rendered.filter).toBeNull();
    expect(rendered.unpushedRules.length).toBeGreaterThan(0);
  });

  it("pgvector refuses a metadata key that is not a plain identifier", () => {
    // A key is deployment configuration, not policy data. An unexpected one is refused
    // rather than quoted into a query.
    const result = buildFromFilterModule(policy({ deniedTags: ["secret"] }), {
      metadataKeys: ["tags'; DROP TABLE chunks --"],
    });
    const rendered = renderKbFilter(result, KbProvider.Pgvector);

    expect(rendered.filter).toBeNull();
  });

  it("pgvector escapes a quote in a tag value rather than refusing", () => {
    // Tag values come from a signed policy, so they are trusted content — but still
    // escaped, so a value cannot terminate the literal.
    const result = buildFromFilterModule(policy({ deniedTags: ["o'brien"] }), {
      metadataKeys: ["tags"],
    });
    const rendered = renderKbFilter(result, KbProvider.Pgvector) as { filter: string };

    expect(rendered.filter).toContain("'o''brien'");
  });

  it("an empty metadata key list pushes nothing and says so", () => {
    const result = buildFromFilterModule(policy({ deniedTags: ["secret"] }), {
      metadataKeys: [],
    });

    expect(result.clauses).toEqual([]);
    expect(result.unpushedRules.map((r) => r.rule)).toEqual(["deniedTags"]);
  });
});

// ---------------------------------------------------------------------------
// THE safety property: a pushdown never excludes what the policy permits
// ---------------------------------------------------------------------------

/**
 * Apply a neutral clause the way a provider would: on one indexed key, at the top level,
 * with an absent key meaning "no match" (so a negated clause keeps the chunk).
 */
function simulateProvider(
  chunks: Array<Record<string, unknown>>,
  clauses: ReadonlyArray<{ key: string; op: KbFilterOp; values: string[] }>,
): Array<Record<string, unknown>> {
  return chunks.filter((chunk) =>
    clauses.every((clause) => {
      const raw = chunk[clause.key];
      const present = raw !== undefined && raw !== null;
      const values = (Array.isArray(raw) ? raw : [raw])
        .filter((v): v is string => typeof v === "string")
        .map((v) => v.toLowerCase());
      const hit = values.some((v) => clause.values.includes(v));

      return clause.op === KbFilterOp.In ? hit : !present || !hit;
    }),
  );
}

describe("the pushdown never excludes a chunk the policy permits", () => {
  const chunks = [
    { id: "secret-indexed", classification: "secret" },
    { id: "public-indexed", classification: "public" },
    { id: "untagged" },
    { id: "secret-other-key", tags: ["secret"] },
    { id: "secret-nested", metadata: { tags: ["secret"] } },
    { id: "secret-cased", classification: "SECRET" },
  ];

  it("denylist: everything the post pass keeps also survives the provider filter", () => {
    // The property that makes a pushdown safe. If this ever fails, the provider is hiding
    // rows the policy allows and the SDK is silently over-restricting.
    const pol = policy({ deniedTags: ["secret"] });
    const result = buildFromFilterModule(pol, { metadataKeys: ["classification"] });

    const provided = simulateProvider(chunks, result.clauses);
    const permitted = filterByTags(chunks, pol);

    for (const kept of permitted) {
      expect(provided.map((c) => c.id)).toContain(kept.id);
    }
  });

  it("the provider misses tags under other keys and nested ones — the post pass catches them", () => {
    // Documents the structural weakness with evidence rather than a comment: these two
    // chunks reach the client and are dropped post-retrieval. This is why §7 forbids
    // treating the filter as a replacement.
    const pol = policy({ deniedTags: ["secret"] });
    const result = buildFromFilterModule(pol, { metadataKeys: ["classification"] });

    const provided = simulateProvider(chunks, result.clauses).map((c) => c.id);
    expect(provided).toContain("secret-other-key");
    expect(provided).toContain("secret-nested");

    const permitted = filterByTags(chunks, pol).map((c) => c.id);
    expect(permitted).not.toContain("secret-other-key");
    expect(permitted).not.toContain("secret-nested");
  });

  it("allowlist: nothing the post pass keeps is excluded by the provider filter", () => {
    const pol = policy({ allowedTags: ["public"] });
    const result = buildFromFilterModule(pol, { metadataKeys: ["classification"] });

    const provided = simulateProvider(chunks, result.clauses);
    const permitted = filterByTags(chunks, pol);

    for (const kept of permitted) {
      expect(provided.map((c) => c.id)).toContain(kept.id);
    }
  });

  it("a multi-key allow-list pushes nothing, so it cannot over-restrict", () => {
    // The case the builder refuses. ANDing a positive clause per key would drop
    // `secret-other-key`-shaped chunks that carry the allowed tag under only one key —
    // narrower than the policy. Reporting it unpushed is the correct outcome.
    const pol = policy({ allowedTags: ["public"] });
    const result = buildFromFilterModule(pol, { metadataKeys: ["tags", "classification"] });

    expect(result.clauses).toEqual([]);
    expect(result.unpushedRules.map((r) => r.rule)).toEqual(["allowedTags"]);

    // With no clauses the provider returns everything, and the post pass is the only gate.
    const permitted = filterByTags(chunks, pol).map((c) => c.id);
    expect(permitted).toEqual(["public-indexed"]);
  });
});

// ---------------------------------------------------------------------------
// The enforcement entry point re-exports the builder
// ---------------------------------------------------------------------------

describe("buildKbFilter is reachable from the enforcement surface", () => {
  it("is the same function", () => {
    expect(buildKbFilter).toBe(buildFromFilterModule);
  });
});

// ---------------------------------------------------------------------------
// Negated (denylist) clauses, checked as a class across every provider
// ---------------------------------------------------------------------------

/**
 * Two fail-opens shipped in these renderers and both had the same shape: a negated clause that
 * matches nothing **excludes** nothing, so a denylist returns every denied document while the
 * allowlist arm of the same bug fails harmlessly closed. OpenSearch emitted a `.keyword`
 * sub-field the index did not have; Vertex emitted a multi-argument `NOT ANY()` that Discovery
 * Engine does not accept.
 *
 * Both were invisible to per-provider tests asserting the document we had chosen to emit. These
 * assert properties of the negated form itself, which is the thing that keeps going wrong.
 */
describe("negated clauses across providers", () => {
  const renderFor = (tagRules: Parameters<typeof policy>[0], provider: KbProvider) =>
    renderKbFilter(buildFromFilterModule(policy(tagRules), { metadataKeys: ["classification"] }), provider)
      .filter;

  it("Vertex negation is split into single-argument ANY()", () => {
    // `NOT key: ANY("a", "b")` — what this renderer emitted — is not valid per Google's
    // documented grammar, so a two-tag denylist produced a filter the service would reject or
    // misapply. Nothing caught it because the renderer was `fromGrammar`.
    const rendered = renderFor(
      { deniedTags: ["secret", "restricted"] },
      KbProvider.VertexAiSearch,
    ) as string;

    expect(rendered).toBe(
      'NOT classification: ANY("restricted") AND NOT classification: ANY("secret")',
    );
    // The invariant, independent of value ordering: no negated ANY() carries two arguments.
    for (const [, args] of rendered.matchAll(/NOT [^:]+: ANY\(([^)]*)\)/g)) {
      expect(args, "multi-argument NOT ANY() is invalid").not.toContain(",");
    }
  });

  it("CONTROL: a Vertex allowlist keeps its values in one ANY()", () => {
    // Splitting a disjunction would require a chunk to carry BOTH tags — narrower than the
    // policy, and a different bug in the opposite direction.
    const rendered = renderFor(
      { allowedTags: ["public", "internal"] },
      KbProvider.VertexAiSearch,
    ) as string;

    expect(rendered).toBe('classification: ANY("internal", "public")');
    expect(rendered).not.toContain(" AND ");
  });

  it("OpenSearch negation covers both field spellings", () => {
    const rendered = renderFor({ deniedTags: ["secret"] }, KbProvider.OpenSearch) as {
      bool: { must_not: Array<{ bool: { should: Array<{ terms: Record<string, unknown> }> } }> };
    };

    const keys = new Set(
      rendered.bool.must_not.flatMap((clause) =>
        clause.bool.should.flatMap((term) => Object.keys(term.terms)),
      ),
    );
    expect(keys).toEqual(new Set(["classification", "classification.keyword"]));
  });

  it("pgvector negation admits an untagged row", () => {
    // `NOT (... ?| ...)` alone would drop a row whose key is absent — the operator yields NULL
    // and `NOT NULL` is not true — discarding untagged chunks a denylist permits. Deliberately
    // NOT extended to match numeric values: tag harvesting collects only strings, so a `->>`
    // arm would make the pushdown stricter than the normative post pass.
    expect(renderFor({ deniedTags: ["secret"] }, KbProvider.Pgvector)).toContain("IS NULL");
  });

  it("Azure places not OUTSIDE the lambda", () => {
    // Azure rejects `any(t: not search.in(...))` and accepts `not any(t: search.in(...))`. The
    // invalid spelling fails loudly, so this guards against a plausible "simplification".
    const rendered = renderFor({ deniedTags: ["secret"] }, KbProvider.AzureAiSearch) as string;

    expect(rendered.startsWith("not classification/any(t: search.in(")).toBe(true);
    expect(rendered).not.toContain("any(t: not");
  });

  it("every provider renders a denylist at all", () => {
    // Vacuity guard: each test above asserts the shape of a rendered filter and would pass
    // trivially if the renderer had stopped producing one.
    for (const provider of Object.values(KbProvider)) {
      expect(
        renderFor({ deniedTags: ["secret"] }, provider),
        `${provider} rendered no filter for a denylist`,
      ).not.toBeNull();
    }
  });
});
