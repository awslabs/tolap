/**
 * `storage` enforcement against real S3 (connector-spec §8).
 *
 * The TypeScript counterpart of the Python and .NET suites, case for case. TOLAP's guarantee
 * is that one policy behaves identically in all three SDKs, so AWS-backed proof for one or
 * two of them leaves exactly the asymmetry that has produced fail-open bugs here before:
 * three implementations agreeing with themselves while disagreeing with each other.
 *
 * Two of §8's requirements cannot be checked against fixtures, and they are why this talks to
 * a real service:
 *
 *  1. **A denied prefix must issue no provider call.** §8: validate the requested prefix
 *     *before* the call, "otherwise an unauthorized `list` is issued and merely filtered on
 *     return, which is slower and records the request in the provider's audit log as though
 *     it were authorized." That is an assertion about a call's *absence* — a wrapper that
 *     lists everything and discards denied rows returns exactly what one that never asked
 *     returns. Only observing real requests separates them.
 *  2. **`ListObjectsV2` returns no object tags**, so an `allowedTags` policy over a bare
 *     listing drops everything until entries are enriched.
 *
 * Every denial has a paired control proving the same operation succeeds when permitted.
 * Without the control, a client that returns nothing at all passes every denial test here.
 *
 * Opt-in: needs `TOLAP_TEST_AWS=1` and credentials. The AWS SDK is a devDependency only — no
 * shipped package declares one, because TOLAP never holds a connection.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  S3Client,
  CreateBucketCommand,
  DeleteBucketCommand,
  DeleteObjectCommand,
  DeleteObjectsCommand,
  GetObjectCommand,
  GetObjectTaggingCommand,
  HeadObjectCommand,
  ListObjectsV2Command,
  PutObjectCommand,
} from "@aws-sdk/client-s3";
import {
  applyResultPipeline,
  filterByTags,
  validateAccess,
  validateWrite,
  WriteOperation,
  FilterOperator,
  MaskType,
  type EffectivePolicy,
} from "@tolap/core";

const ENABLED = process.env["TOLAP_TEST_AWS"] === "1";
const REGION = process.env["AWS_REGION"] ?? process.env["AWS_DEFAULT_REGION"] ?? "us-east-1";

/** Records every S3 command issued, so a test can assert a call did NOT happen. */
const calls: string[] = [];

let client: S3Client;
let bucket = "";

/**
 * A middleware in the client's own stack, rather than a wrapper around each call, so it
 * observes what actually goes out. That is what makes "no ListObjectsV2 was issued" a
 * trustworthy assertion rather than a restatement of what the test believes it asked for.
 *
 * CloudTrail would be the auditor's view, but it lags minutes and would make this slow and
 * flaky for no extra signal.
 */
function installRecorder(c: S3Client): void {
  c.middlewareStack.add(
    (next, context) => async (args) => {
      calls.push(String(context.commandName ?? "").replace(/Command$/, ""));
      return next(args);
    },
    { step: "initialize", name: "tolapCallRecorder" },
  );
}

function policy(overrides: Partial<EffectivePolicy> = {}): EffectivePolicy {
  const now = new Date();
  return {
    version: "1.0",
    userId: "s3-user",
    tenantId: "s3-tenant",
    sourceConnectionId: "storage:archive:exports",
    resolvedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 3_600_000).toISOString(),
    sourceProfiles: ["s3-storage-test"],
    permissions: { canQuery: true, readOnly: true },
    integrity: { algorithm: "none", signature: "" },
    ...overrides,
  };
}

beforeAll(async () => {
  if (!ENABLED) return;

  client = new S3Client({ region: REGION });
  installRecorder(client);

  bucket = `tolap-test-${Math.random().toString(16).slice(2, 14)}`;
  await client.send(
    new CreateBucketCommand({
      Bucket: bucket,
      // us-east-1 rejects an explicit location constraint.
      ...(REGION === "us-east-1"
        ? {}
        : { CreateBucketConfiguration: { LocationConstraint: REGION as never } }),
    }),
  );

  // The key layout is §8's worked example. Two objects carry tags — the interesting part,
  // since a listing does not return them — and one is deliberately oversize so
  // maxObjectSizeBytes has a casualty as well as a survivor.
  const seed: Array<[string, string, string | undefined, Record<string, string> | undefined]> = [
    ["exports/public/a.csv", "id,region\n1,us-east\n", undefined, { owner: "analytics", ssn: "000-11-2222" }],
    ["exports/public/sub/deep.csv", "id,region\n2,us-west\n", undefined, undefined],
    ["exports/private/secret.csv", "id,ssn\n3,000-00-0000\n", undefined, undefined],
    ["exports/public/tagged-public.csv", "id\n4\n", "classification=public", undefined],
    ["exports/public/tagged-secret.csv", "id\n5\n", "classification=secret", undefined],
    ["exports/public/large.csv", "x".repeat(2048), undefined, undefined],
  ];
  for (const [Key, Body, Tagging, Metadata] of seed) {
    await client.send(
      new PutObjectCommand({
        Bucket: bucket,
        Key,
        Body,
        ...(Tagging ? { Tagging } : {}),
        ...(Metadata ? { Metadata } : {}),
      }),
    );
  }
}, 120_000);

afterAll(async () => {
  if (!ENABLED || !bucket) return;
  // Scoped to this bucket only — never a prefix sweep across a shared account.
  const listed = await client.send(new ListObjectsV2Command({ Bucket: bucket }));
  if (listed.Contents?.length) {
    await client.send(
      new DeleteObjectsCommand({
        Bucket: bucket,
        Delete: { Objects: listed.Contents.map((o) => ({ Key: o.Key! })) },
      }),
    );
  }
  await client.send(new DeleteBucketCommand({ Bucket: bucket }));
}, 120_000);

/** Every test here needs the bucket; skip cleanly when AWS is not enabled. */
function requireAws(ctx: { skip: (note?: string) => void }): void {
  if (!ENABLED) ctx.skip("AWS integration tests are opt-in; set TOLAP_TEST_AWS=1");
}

/**
 * Lists a prefix the way a compliant storage wrapper must: validate, then call.
 *
 * The ordering is the point — `validateAccess` runs *before* the request, so a denied prefix
 * issues nothing. Returning early rather than filtering afterwards is what §8 requires.
 */
async function listWithEnforcement(prefix: string, p: EffectivePolicy) {
  if (!validateAccess(prefix, p).allowed) return [];
  const res = await client.send(new ListObjectsV2Command({ Bucket: bucket, Prefix: prefix }));
  return res.Contents ?? [];
}

/**
 * An S3 listing as the record shape the pipeline consumes: key, size, and user metadata.
 *
 * §8 maps a storage Field to a metadata key, so the metadata has to be fetched for field
 * rules to act on anything. This is the enrichment §8 prescribes; the tests then run the
 * SHIPPED pipeline over these records rather than reimplementing enforcement.
 */
async function listingRecords(prefix: string): Promise<Array<Record<string, unknown>>> {
  const out: Array<Record<string, unknown>> = [];
  for (const obj of await listWithEnforcement(prefix, policy({ objectRules: { allowedObjects: ["exports/*"] } }))) {
    const head = await client.send(new HeadObjectCommand({ Bucket: bucket, Key: obj.Key! }));
    out.push({ key: obj.Key, sizeBytes: obj.Size, ...(head.Metadata ?? {}) });
  }
  return out;
}

// ---------------------------------------------------------------------------
// §8: the requested prefix is validated BEFORE the provider call
// ---------------------------------------------------------------------------

describe("§8: a denied prefix never reaches S3", () => {
  it("a denied prefix issues no list call", async (ctx) => {
    requireAws(ctx);
    calls.length = 0;
    const p = policy({ objectRules: { allowedObjects: ["exports/public/*"] } });

    const results = await listWithEnforcement("exports/private/", p);

    expect(results).toEqual([]);
    expect(calls).not.toContain("ListObjectsV2");
  });

  it("CONTROL: a permitted prefix does issue a list call", async (ctx) => {
    requireAws(ctx);
    calls.length = 0;
    const p = policy({ objectRules: { allowedObjects: ["exports/public/*"] } });

    const results = await listWithEnforcement("exports/public/", p);

    expect(calls).toContain("ListObjectsV2");
    const keys = results.map((o) => o.Key);
    expect(keys).toContain("exports/public/a.csv");
    expect(keys).not.toContain("exports/private/secret.csv");
  });

  it("a hidden prefix also issues no call", async (ctx) => {
    requireAws(ctx);
    calls.length = 0;
    // hiddenObjects takes precedence over allowedObjects (§3), and that precedence must
    // apply before the call too — otherwise hidden data is fetched then discarded, which is
    // the same audit-log problem.
    const p = policy({
      objectRules: { allowedObjects: ["exports/*"], hiddenObjects: ["exports/private/*"] },
    });

    expect(await listWithEnforcement("exports/private/", p)).toEqual([]);
    expect(calls).not.toContain("ListObjectsV2");
  });
});

// ---------------------------------------------------------------------------
// §3.1 prefix globs, against real keys
// ---------------------------------------------------------------------------

describe("§3.1 prefix globs against real keys", () => {
  it("a prefix glob descends arbitrarily", async (ctx) => {
    requireAws(ctx);
    const p = policy({ objectRules: { allowedObjects: ["exports/public/*"] } });

    const keys = (await listWithEnforcement("exports/public/", p)).map((o) => o.Key);

    expect(keys).toContain("exports/public/sub/deep.csv");
  });

  it("the bare prefix is NOT granted by its own glob", (ctx) => {
    requireAws(ctx);
    // The boundary that makes "descends arbitrarily" safe to state.
    const p = policy({ objectRules: { allowedObjects: ["exports/public/*"] } });

    expect(validateAccess("exports/public", p).allowed).toBe(false);
    expect(validateAccess("exports/public/a.csv", p).allowed).toBe(true);
  });

  it("every returned key satisfies the policy", async (ctx) => {
    requireAws(ctx);
    // A whole-bucket sweep: enumerate unfiltered, then check the policy's decision for every
    // real key. Catches a glob that behaves differently on a shape the corpus did not
    // anticipate.
    const p = policy({ objectRules: { allowedObjects: ["exports/public/*"] } });
    const everything = await client.send(new ListObjectsV2Command({ Bucket: bucket }));
    expect(everything.Contents?.length).toBeGreaterThan(0);

    for (const obj of everything.Contents!) {
      const expected = obj.Key!.startsWith("exports/public/");
      expect(validateAccess(obj.Key!, p).allowed, obj.Key).toBe(expected);
    }
  });
});

// ---------------------------------------------------------------------------
// tagRules on a listing — confirming §8's documented consequence
// ---------------------------------------------------------------------------

describe("tagRules on a listing", () => {
  it("ListObjectsV2 returns no tags", async (ctx) => {
    requireAws(ctx);
    // The premise §8's warning rests on, checked against the service. Two seeded objects
    // carry classification tags; the listing exposes none.
    const listed = await client.send(
      new ListObjectsV2Command({ Bucket: bucket, Prefix: "exports/public/" }),
    );

    expect(listed.Contents?.length).toBeGreaterThan(0);
    for (const obj of listed.Contents!) {
      expect(obj).not.toHaveProperty("TagSet");
      expect(obj).not.toHaveProperty("Tagging");
    }
  });

  it("tags are only available via GetObjectTagging", async (ctx) => {
    requireAws(ctx);
    const tagging = await client.send(
      new GetObjectTaggingCommand({ Bucket: bucket, Key: "exports/public/tagged-secret.csv" }),
    );

    expect(tagging.TagSet).toEqual([{ Key: "classification", Value: "secret" }]);
  });

  it("EXPLOIT: allowedTags over a bare listing drops everything", async (ctx) => {
    requireAws(ctx);
    // The hazard §8 documents, end to end. Every entry is untagged as far as the pipeline can
    // see, and an allowlist drops what it cannot prove permitted — so the result is empty even
    // though a permitted object exists. Fail-closed, and useless: enrich first.
    const p = policy({ objectRules: { tagRules: { allowedTags: ["public"] } } });
    const entries = (
      await listWithEnforcement("exports/public/", policy({ objectRules: { allowedObjects: ["exports/*"] } }))
    ).map((o) => ({ key: o.Key, sizeBytes: o.Size }));
    expect(entries.length).toBeGreaterThan(0);

    expect(filterByTags(entries as never, p)).toEqual([]);
  });

  it("CONTROL: enriching entries with tags makes the allowlist work", async (ctx) => {
    requireAws(ctx);
    const p = policy({ objectRules: { tagRules: { allowedTags: ["public"] } } });
    const entries: Array<Record<string, unknown>> = [];
    for (const obj of await listWithEnforcement(
      "exports/public/",
      policy({ objectRules: { allowedObjects: ["exports/*"] } }),
    )) {
      const tagging = await client.send(
        new GetObjectTaggingCommand({ Bucket: bucket, Key: obj.Key! }),
      );
      const record: Record<string, unknown> = { key: obj.Key, sizeBytes: obj.Size };
      // An untagged object must LOOK untagged to the pipeline — that is what makes the
      // allowlist drop it — so the key is left absent rather than set to [].
      if (tagging.TagSet?.length) record["tags"] = tagging.TagSet.map((t) => t.Value);
      entries.push(record);
    }

    const surviving = filterByTags(entries as never, p).map((e) => (e as never as { key: string }).key);

    expect(surviving).toContain("exports/public/tagged-public.csv");
    expect(surviving).not.toContain("exports/public/tagged-secret.csv");
  });

  it("a denylist keeps untagged entries", async (ctx) => {
    requireAws(ctx);
    // The other half of the asymmetry, and why it is not simply a bug: a pure denylist keeps
    // an untagged entry, because it matches no denied tag. Dropping it would enforce a
    // restriction the policy never stated.
    const p = policy({ objectRules: { tagRules: { deniedTags: ["secret"] } } });
    const entries = (
      await listWithEnforcement("exports/public/", policy({ objectRules: { allowedObjects: ["exports/*"] } }))
    ).map((o) => ({ key: o.Key, sizeBytes: o.Size }));

    expect(filterByTags(entries as never, p)).toHaveLength(entries.length);
  });
});

// ---------------------------------------------------------------------------
// Write path: canInsert / canUpdate / canDelete / readOnly (§4, §8)
// ---------------------------------------------------------------------------

describe("write path", () => {
  it("a read-only policy denies a PUT before it is issued", async (ctx) => {
    requireAws(ctx);
    calls.length = 0;
    const p = policy({
      permissions: { canQuery: true, readOnly: true },
      objectRules: { allowedObjects: ["exports/*"] },
    });

    const decision = validateWrite(WriteOperation.Insert, "exports/public/new.csv", { id: "9" }, p);

    expect(decision.allowed).toBe(false);
    if (decision.allowed) {
      await client.send(
        new PutObjectCommand({ Bucket: bucket, Key: "exports/public/new.csv", Body: "x" }),
      );
    }
    expect(calls).not.toContain("PutObject");
  });

  it("CONTROL: a permitted insert writes and reads back", async (ctx) => {
    requireAws(ctx);
    const p = policy({
      permissions: { canQuery: true, canInsert: true, readOnly: false },
      objectRules: { allowedObjects: ["exports/*"] },
    });
    const key = "exports/public/inserted-ts.csv";

    expect(validateWrite(WriteOperation.Insert, key, { id: "9" }, p).allowed).toBe(true);

    await client.send(new PutObjectCommand({ Bucket: bucket, Key: key, Body: "id\n9\n" }));
    try {
      const got = await client.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
      expect(await got.Body!.transformToString()).toBe("id\n9\n");
    } finally {
      await client.send(new DeleteObjectCommand({ Bucket: bucket, Key: key }));
    }
  });

  it("insert is denied when only update is granted", (ctx) => {
    requireAws(ctx);
    // canInsert and canUpdate are distinct: granting only update must not permit creating a
    // new key.
    const p = policy({
      permissions: { canQuery: true, canUpdate: true, readOnly: false },
      objectRules: { allowedObjects: ["exports/*"] },
    });

    expect(validateWrite(WriteOperation.Insert, "exports/public/x.csv", { id: "1" }, p).allowed).toBe(false);
    expect(
      validateWrite(WriteOperation.Update, "exports/public/a.csv", { id: "1" }, p, { targetRow: {} }).allowed,
    ).toBe(true);
  });

  it("delete requires canDelete", (ctx) => {
    requireAws(ctx);
    const p = policy({
      permissions: { canQuery: true, canInsert: true, readOnly: false },
      objectRules: { allowedObjects: ["exports/*"] },
    });

    expect(validateWrite(WriteOperation.Delete, "exports/public/a.csv", null, p).allowed).toBe(false);
  });

  it("a write to a denied prefix is refused", (ctx) => {
    requireAws(ctx);
    // allowedObjects governs the write target too, not only reads.
    const p = policy({
      permissions: { canQuery: true, canInsert: true, readOnly: false },
      objectRules: { allowedObjects: ["exports/public/*"] },
    });

    expect(validateWrite(WriteOperation.Insert, "exports/private/x.csv", { id: "1" }, p).allowed).toBe(false);
  });

  it("writing a read-only metadata field is refused", (ctx) => {
    requireAws(ctx);
    // readOnlyFields names metadata readable but not writable. A write whose payload sets one
    // is refused whole (§4.4: reject, never silently drop).
    const p = policy({
      permissions: { canQuery: true, canUpdate: true, readOnly: false },
      objectRules: {
        allowedObjects: ["exports/*"],
        fieldRules: { readOnlyFields: ["owner"] },
      },
    });

    expect(
      validateWrite(WriteOperation.Update, "exports/public/a.csv", { owner: "attacker", note: "ok" }, p, {
        targetRow: {},
      }).allowed,
    ).toBe(false);
    expect(
      validateWrite(WriteOperation.Update, "exports/public/a.csv", { note: "ok" }, p, { targetRow: {} }).allowed,
    ).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// The full post-execution pipeline over real object metadata (§4, §8)
// ---------------------------------------------------------------------------

describe("post-execution pipeline over real object metadata", () => {
  it("a hidden metadata field is removed", async (ctx) => {
    requireAws(ctx);
    const records = await listingRecords("exports/public/a.csv");
    expect(records[0]).toHaveProperty("ssn");

    const p = policy({ objectRules: { fieldRules: { hiddenFields: ["ssn"] } } });
    const out = applyResultPipeline(records as never, p) as Array<Record<string, unknown>>;

    for (const r of out) {
      expect(r).not.toHaveProperty("ssn");
      expect(r).toHaveProperty("key");
    }
  });

  it("a masked metadata field is masked", async (ctx) => {
    requireAws(ctx);
    const records = await listingRecords("exports/public/a.csv");
    const original = records.find((r) => "ssn" in r)!["ssn"];

    const p = policy({
      objectRules: { fieldRules: { maskedFields: [{ field: "ssn", maskType: MaskType.Redact }] } },
    });
    const out = applyResultPipeline(records as never, p) as Array<Record<string, unknown>>;

    expect(out.find((r) => "ssn" in r)!["ssn"]).not.toBe(original);
    expect(JSON.stringify(out)).not.toContain("000-11-2222");
  });

  it("allowedFields projects metadata", async (ctx) => {
    requireAws(ctx);
    const records = await listingRecords("exports/public/a.csv");

    const p = policy({ objectRules: { fieldRules: { allowedFields: ["key", "owner"] } } });
    const out = applyResultPipeline(records as never, p) as Array<Record<string, unknown>>;

    for (const r of out) {
      expect(Object.keys(r).every((k) => k === "key" || k === "owner")).toBe(true);
    }
  });

  it("a row filter applies to listing entries", async (ctx) => {
    requireAws(ctx);
    // objectRules.rowFilters apply to listing entries (§2). Only a.csv has owner=analytics.
    const records = await listingRecords("exports/public/");

    const p = policy({
      objectRules: {
        rowFilters: [{ field: "owner", operator: FilterOperator.Equals, value: "analytics" }],
      },
    });
    const out = applyResultPipeline(records as never, p) as Array<Record<string, unknown>>;

    expect(out.map((r) => r["key"])).toEqual(["exports/public/a.csv"]);
  });

  it("maxObjectSizeBytes drops the oversize object", async (ctx) => {
    requireAws(ctx);
    // large.csv is ~2 KiB; a 1 KiB ceiling drops it and keeps the rest.
    const records = await listingRecords("exports/public/");
    expect(records.some((r) => Number(r["sizeBytes"]) > 1024)).toBe(true);

    const p = policy({ limits: { maxObjectSizeBytes: 1024 } });
    const out = applyResultPipeline(records as never, p) as Array<Record<string, unknown>>;

    expect(out.map((r) => r["key"])).not.toContain("exports/public/large.csv");
  });

  it("maxResults truncates the listing", async (ctx) => {
    requireAws(ctx);
    const records = await listingRecords("exports/public/");
    expect(records.length).toBeGreaterThan(2);

    const p = policy({ limits: { maxResults: 2 } });
    const out = applyResultPipeline(records as never, p) as Array<Record<string, unknown>>;

    expect(out).toHaveLength(2);
  });
});
