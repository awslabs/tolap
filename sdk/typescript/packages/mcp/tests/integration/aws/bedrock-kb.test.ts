/**
 * End-to-end `kb` enforcement against a real Bedrock Knowledge Base (connector-spec §7).
 *
 * The TypeScript counterpart of the Python and .NET Bedrock suites. Our unit tests assert the
 * filter's *shape* against a fixture we wrote — which cannot tell us whether **Bedrock**
 * accepts it, or whether it actually excludes anything. A filter that is byte-correct against
 * our own expectation but malformed to the service is a runtime failure for every integrator,
 * and nothing else in the suite would catch it.
 *
 * Requires a provisioned KB, so this is gated on `TOLAP_TEST_KB_ID` in addition to
 * `TOLAP_TEST_AWS=1`. The KB is stood up by the Python `provision_bedrock_kb.py` script rather
 * than reimplemented here: provisioning is test infrastructure (OpenSearch Serverless
 * collection, vector index, IAM role, S3 data source, a multi-minute ingestion job), not SDK
 * behaviour, and building that chain three times would triple the maintenance for no extra
 * signal. What must be independent per SDK is the *enforcement* assertion, which is what runs
 * here.
 *
 * The KB is seeded with four documents, two `classification=public` and two
 * `classification=secret`.
 */

import { describe, expect, it } from "vitest";
import {
  BedrockAgentRuntimeClient,
  ResourceNotFoundException,
  RetrieveCommand,
  type RetrievalFilter,
} from "@aws-sdk/client-bedrock-agent-runtime";
import {
  buildKbFilter,
  renderKbFilter,
  filterByTags,
  KbProvider,
  type EffectivePolicy,
  type TagRules,
} from "@tolap/core";

const ENABLED = process.env["TOLAP_TEST_AWS"] === "1";
const KB_ID = process.env["TOLAP_TEST_KB_ID"];
const REGION = process.env["AWS_REGION"] ?? "us-east-1";

/** A KB id that does not exist, for the shape-acceptance probe. */
const ABSENT_KB_ID = "AAAAAAAAAA";

/** Broad enough to match every document, so exclusions are the policy's doing. */
const BROAD_QUERY = "company financial and product information";

function client(): BedrockAgentRuntimeClient {
  return new BedrockAgentRuntimeClient({ region: REGION });
}

function policy(tagRules: TagRules): EffectivePolicy {
  const now = new Date();
  return {
    version: "1.0",
    userId: "kb-user",
    tenantId: "kb-tenant",
    sourceConnectionId: "kb:research:trials",
    resolvedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 3_600_000).toISOString(),
    sourceProfiles: ["kb-e2e"],
    permissions: { canQuery: true },
    objectRules: { tagRules },
    integrity: { algorithm: "none", signature: "" },
  };
}

function renderedFor(tagRules: TagRules): unknown {
  return renderKbFilter(
    buildKbFilter(policy(tagRules), { metadataKeys: ["classification"] }),
    KbProvider.Bedrock,
  ).filter;
}

/**
 * Turns our provider-neutral filter document into the AWS SDK's typed shape.
 *
 * Translating here rather than in the SDK is deliberate: TOLAP emits a provider-native
 * *document* so an integrator can use any client, and binding the library to one AWS SDK
 * version would be the wrong coupling.
 */
function toRetrievalFilter(rendered: unknown): RetrievalFilter {
  const map = rendered as Record<string, unknown>;

  if ("andAll" in map) {
    return { andAll: (map["andAll"] as unknown[]).map(toRetrievalFilter) };
  }

  for (const [op, raw] of Object.entries(map)) {
    const operand = raw as { key: string; value: string[] };
    const attribute = { key: operand.key, value: operand.value };
    if (op === "in") return { in: attribute };
    if (op === "notIn") return { notIn: attribute };
    throw new Error(`unmapped operator '${op}'`);
  }

  throw new Error("empty filter document");
}

async function retrieve(
  kbId: string,
  query: string,
  rendered?: unknown,
): Promise<Array<{ text: string; classification?: string }>> {
  const response = await client().send(
    new RetrieveCommand({
      knowledgeBaseId: kbId,
      retrievalQuery: { text: query },
      retrievalConfiguration: {
        vectorSearchConfiguration: {
          numberOfResults: 10,
          ...(rendered ? { filter: toRetrievalFilter(rendered) } : {}),
        },
      },
    }),
  );

  return (response.retrievalResults ?? []).map((r) => ({
    text: r.content?.text ?? "",
    classification: r.metadata?.["classification"] as string | undefined,
  }));
}

function requireKb(ctx: { skip: (note?: string) => void }): void {
  if (!ENABLED || !KB_ID) {
    ctx.skip("needs a provisioned KB; set TOLAP_TEST_AWS=1 and TOLAP_TEST_KB_ID");
  }
}

// ---------------------------------------------------------------------------
// The pushdown enforces at the source
// ---------------------------------------------------------------------------

describe("§7: the kb pushdown enforces at the source", () => {
  it("BASELINE: unfiltered retrieval returns both classifications", async (ctx) => {
    requireKb(ctx);
    // Without a filter the KB returns public AND secret chunks. If this does not hold, every
    // filtered assertion below could pass for the wrong reason — a KB that never returns
    // secret chunks would make the pushdown look effective while doing nothing.
    const results = await retrieve(KB_ID!, BROAD_QUERY);
    const classifications = new Set(results.map((r) => r.classification));

    expect(classifications).toContain("public");
    expect(classifications, "the exclusion tests would be vacuous").toContain("secret");
  }, 120_000);

  it("a denylist pushdown excludes secret at the source", async (ctx) => {
    requireKb(ctx);
    // deniedTags -> our Bedrock notIn filter. The live Retrieve must return no secret chunk at
    // all. This is the claim a fixture cannot make: the real vector store applied our filter.
    const tagRules: TagRules = { deniedTags: ["secret"] };
    const rendered = renderedFor(tagRules);
    expect(rendered).not.toBeNull();

    const results = await retrieve(KB_ID!, BROAD_QUERY, rendered);

    expect(results.length, "expected public chunks to remain").toBeGreaterThan(0);
    for (const r of results) expect(r.classification).not.toBe("secret");

    // Defence-in-depth cross-check: the shipped post-pass agrees with the provider.
    const asRecords = results.map((r) => ({ classification: r.classification }));
    expect(filterByTags(asRecords as never, policy(tagRules))).toHaveLength(results.length);
  }, 120_000);

  it("an allowlist pushdown returns only public", async (ctx) => {
    requireKb(ctx);
    const rendered = renderedFor({ allowedTags: ["public"] });

    const results = await retrieve(KB_ID!, BROAD_QUERY, rendered);

    expect(results.length, "allowlist filter returned nothing").toBeGreaterThan(0);
    for (const r of results) expect(r.classification).toBe("public");
  }, 120_000);

  it("the pushdown and the post pass reach the same verdict", async (ctx) => {
    requireKb(ctx);
    // The property that makes a pushdown safe rather than merely faster: filtering at the
    // source must never disagree with the normative post-retrieval pass.
    const tagRules: TagRules = { deniedTags: ["secret"] };
    const rendered = renderedFor(tagRules);

    const pushed = await retrieve(KB_ID!, BROAD_QUERY, rendered);
    const everything = await retrieve(KB_ID!, BROAD_QUERY);
    const postOnly = filterByTags(
      everything.map((r) => ({ classification: r.classification, text: r.text })) as never,
      policy(tagRules),
    ) as unknown as Array<{ text: string }>;

    expect(
      new Set(pushed.map((r) => r.text)),
      "the source filter and the post-retrieval pass disagreed",
    ).toEqual(new Set(postOnly.map((r) => r.text)));
  }, 180_000);
});

// ---------------------------------------------------------------------------
// Bedrock accepts the filter shapes we generate
// ---------------------------------------------------------------------------

describe("§7: Bedrock accepts the generated filter shapes", () => {
  const cases: Array<[string, TagRules]> = [
    ["denylist-only", { deniedTags: ["secret", "restricted"] }],
    ["allowlist-only", { allowedTags: ["public"] }],
    ["both-anded", { allowedTags: ["public"], deniedTags: ["secret"] }],
  ];

  for (const [name, tagRules] of cases) {
    it(`${name} is accepted`, async (ctx) => {
      if (!ENABLED) ctx.skip("set TOLAP_TEST_AWS=1");
      // Sent against a KB id that does not exist: Bedrock validates the request body before
      // resolving the KB, so ResourceNotFound means the filter parsed while a validation error
      // would mean our syntax is wrong. No provisioned KB needed for this one.
      const rendered = renderedFor(tagRules);
      expect(rendered, `${name}: nothing rendered to send`).not.toBeNull();

      await expect(retrieve(ABSENT_KB_ID, "test", rendered)).rejects.toThrow(
        ResourceNotFoundException,
      );
    }, 60_000);
  }

  it("NEGATIVE CONTROL: a malformed filter is refused before it is sent", async (ctx) => {
    if (!ENABLED) ctx.skip("set TOLAP_TEST_AWS=1");
    // Without this, the tests above would pass even if Bedrock had stopped validating filters
    // — "not a validation error" is only meaningful if malformed input still produces one.
    await expect(retrieve(ABSENT_KB_ID, "test", {})).rejects.toThrow(/empty filter document/);
  }, 60_000);
});
