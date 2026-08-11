/**
 * `db` enforcement against real Athena / Trino (connector-spec §5).
 *
 * The TypeScript counterpart of the Python and .NET Athena suites. The rewriter carries a
 * `trino` dialect profile — what Athena speaks — but every other test exercises it against
 * Postgres and MySQL. This is the category where a rewrite bug means the **database itself**
 * returns unauthorized rows, before post-fetch filtering gets a chance, and a `WHERE`-clause
 * fail-open was found in this rewriter once before by running the SQL rather than reading it.
 *
 * Porting is not ceremony: the .NET version of this suite exposed a missing `canQuery` gate in
 * that SDK's `ValidateAccess` — a fail-open that three years of unit tests had not caught
 * because the wrapper checked the gate on a different path.
 *
 * Two properties are asserted separately because they fail differently:
 *
 * - **Pushdown correctness** — the rewritten query must not return a row the policy excludes.
 *   If Athena parses our `WHERE` differently than Postgres does, this is where it shows.
 * - **Post-fetch completeness** — the rewriter deliberately does not push everything down
 *   (`SELECT *` stays `*`), so the pipeline must still run. The test proves Athena really
 *   returned the hidden column first, so it cannot pass if the post pass were removed.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  AthenaClient,
  GetQueryExecutionCommand,
  GetQueryResultsCommand,
  StartQueryExecutionCommand,
} from "@aws-sdk/client-athena";
import {
  GlueClient,
  CreateDatabaseCommand,
  CreateTableCommand,
  DeleteDatabaseCommand,
  DeleteTableCommand,
} from "@aws-sdk/client-glue";
import {
  S3Client,
  CreateBucketCommand,
  DeleteBucketCommand,
  DeleteObjectsCommand,
  ListObjectsV2Command,
  PutObjectCommand,
} from "@aws-sdk/client-s3";
import {
  applyResultPipeline,
  validateAccess,
  SqlQueryRewriter,
  SqlDialect,
  FilterOperator,
  MaskType,
  type EffectivePolicy,
} from "@aws/tolap-core";

const ENABLED = process.env["TOLAP_TEST_AWS"] === "1";
const REGION = process.env["AWS_REGION"] ?? process.env["AWS_DEFAULT_REGION"] ?? "us-east-1";

/** Two regions and an ssn column, so filters, field rules and limits each have work to do. */
const ROWS = [
  ["1", "us-east", "Alice", "111-11-1111"],
  ["2", "us-east", "Bob", "222-22-2222"],
  ["3", "us-west", "Carol", "333-33-3333"],
  ["4", "eu-west", "Dave", "444-44-4444"],
];

let s3: S3Client;
let glue: GlueClient;
let athena: AthenaClient;
let bucket = "";
let database = "";
let resultsLocation = "";

function policy(overrides: Partial<EffectivePolicy> = {}): EffectivePolicy {
  const now = new Date();
  return {
    version: "1.0",
    userId: "athena-user",
    tenantId: "athena-tenant",
    sourceConnectionId: "db:analytics:patients",
    resolvedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 3_600_000).toISOString(),
    sourceProfiles: ["athena-test"],
    permissions: { canQuery: true, readOnly: true },
    integrity: { algorithm: "none", signature: "" },
    ...overrides,
  };
}

beforeAll(async () => {
  if (!ENABLED) return;

  s3 = new S3Client({ region: REGION });
  glue = new GlueClient({ region: REGION });
  athena = new AthenaClient({ region: REGION });

  const suffix = Math.random().toString(16).slice(2, 12);
  bucket = `tolap-athena-${suffix}`;
  database = `tolap_db_${suffix}`;
  resultsLocation = `s3://${bucket}/_results/`;

  await s3.send(
    new CreateBucketCommand({
      Bucket: bucket,
      ...(REGION === "us-east-1"
        ? {}
        : { CreateBucketConfiguration: { LocationConstraint: REGION as never } }),
    }),
  );
  await s3.send(
    new PutObjectCommand({
      Bucket: bucket,
      Key: "patients/data.csv",
      Body: ROWS.map((r) => r.join(",")).join("\n") + "\n",
    }),
  );

  await glue.send(new CreateDatabaseCommand({ DatabaseInput: { Name: database } }));
  await glue.send(
    new CreateTableCommand({
      DatabaseName: database,
      TableInput: {
        Name: "patients",
        TableType: "EXTERNAL_TABLE",
        StorageDescriptor: {
          Columns: [
            { Name: "id", Type: "string" },
            { Name: "region", Type: "string" },
            { Name: "full_name", Type: "string" },
            { Name: "ssn", Type: "string" },
          ],
          Location: `s3://${bucket}/patients/`,
          InputFormat: "org.apache.hadoop.mapred.TextInputFormat",
          OutputFormat: "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
          SerdeInfo: {
            SerializationLibrary: "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
            Parameters: { "field.delim": "," },
          },
        },
      },
    }),
  );
}, 180_000);

afterAll(async () => {
  if (!ENABLED || !bucket) return;
  // Best-effort in order, so one failure does not leak the rest.
  try {
    await glue.send(new DeleteTableCommand({ DatabaseName: database, Name: "patients" }));
  } catch {
    /* already gone */
  }
  try {
    await glue.send(new DeleteDatabaseCommand({ Name: database }));
  } catch {
    /* already gone */
  }
  const listed = await s3.send(new ListObjectsV2Command({ Bucket: bucket }));
  if (listed.Contents?.length) {
    await s3.send(
      new DeleteObjectsCommand({
        Bucket: bucket,
        Delete: { Objects: listed.Contents.map((o) => ({ Key: o.Key! })) },
      }),
    );
  }
  await s3.send(new DeleteBucketCommand({ Bucket: bucket }));
}, 180_000);

function requireAws(ctx: { skip: (note?: string) => void }): void {
  if (!ENABLED) ctx.skip("AWS integration tests are opt-in; set TOLAP_TEST_AWS=1");
}

/** Executes SQL on Athena and returns rows as objects. Throws on query failure. */
async function runQuery(sql: string): Promise<Array<Record<string, string | undefined>>> {
  const started = await athena.send(
    new StartQueryExecutionCommand({
      QueryString: sql,
      QueryExecutionContext: { Database: database },
      ResultConfiguration: { OutputLocation: resultsLocation },
    }),
  );
  const id = started.QueryExecutionId!;

  for (let attempt = 0; attempt < 60; attempt++) {
    const execution = await athena.send(new GetQueryExecutionCommand({ QueryExecutionId: id }));
    const state = execution.QueryExecution?.Status?.State;
    if (state === "SUCCEEDED") break;
    if (state === "FAILED" || state === "CANCELLED") {
      throw new Error(
        `Athena query ${state}: ${execution.QueryExecution?.Status?.StateChangeReason}\nSQL: ${sql}`,
      );
    }
    await new Promise((r) => setTimeout(r, 2000));
  }

  const result = await athena.send(new GetQueryResultsCommand({ QueryExecutionId: id }));
  const columns = (result.ResultSet?.ResultSetMetadata?.ColumnInfo ?? []).map((c) => c.Name!);
  const rows: Array<Record<string, string | undefined>> = [];
  for (const row of result.ResultSet?.Rows ?? []) {
    const values = (row.Data ?? []).map((d) => d.VarCharValue);
    // Athena's first row is the header when the SerDe has no skip.header setting. Detected
    // rather than assumed, so a header change cannot silently drop a data row.
    if (values.length === columns.length && values.every((v, i) => v === columns[i])) continue;
    const record: Record<string, string | undefined> = {};
    columns.forEach((c, i) => (record[c] = values[i]));
    rows.push(record);
  }
  return rows;
}

/**
 * What a compliant db wrapper does before executing: check the object, then rewrite.
 *
 * Core exposes `validateAccess` and `SqlQueryRewriter.rewriteQuery` separately — the combined
 * `prepareSqlQuery` lives on the MCP wrapper and needs a signed context, which is more
 * machinery than this test needs. Composing the two mirrors the .NET suite, so both assert the
 * same two-part contract; composing them is also what exposed .NET's missing canQuery gate.
 */
function prepared(
  sql: string,
  p: EffectivePolicy,
  objectName = "patients",
): { allowed: boolean; denialReason?: string; query: string } {
  const decision = validateAccess(objectName, p);
  if (!decision.allowed) {
    return { allowed: false, denialReason: decision.reason, query: sql };
  }
  const rewriter = new SqlQueryRewriter({ dialect: SqlDialect.Trino });
  return { allowed: true, query: rewriter.rewriteQuery(sql, p).query };
}

// ---------------------------------------------------------------------------
// Pushdown: the engine must not return rows the policy excludes
// ---------------------------------------------------------------------------

describe("row-filter pushdown honoured by Athena", () => {
  it("BASELINE: unfiltered returns every region", async (ctx) => {
    requireAws(ctx);
    // Without this the filtered assertions could pass because the table is empty or the SerDe
    // misparsed the CSV.
    const rows = await runQuery("SELECT * FROM patients");

    expect(new Set(rows.map((r) => r["region"]))).toEqual(
      new Set(["us-east", "us-west", "eu-west"]),
    );
  }, 120_000);

  it("a row filter is pushed into the SQL and honoured by Athena", async (ctx) => {
    requireAws(ctx);
    // The property a fixture cannot check: Athena's own parser applied our WHERE clause.
    const p = policy({
      objectRules: {
        allowedObjects: ["patients"],
        rowFilters: [{ field: "region", operator: FilterOperator.Equals, value: "us-east" }],
      },
    });
    const prep = prepared("SELECT * FROM patients", p);
    expect(prep.allowed).toBe(true);
    expect(prep.query.toUpperCase()).toContain("WHERE");

    const rows = await runQuery(prep.query);

    expect(rows.length).toBeGreaterThan(0);
    expect(new Set(rows.map((r) => r["region"]))).toEqual(new Set(["us-east"]));
  }, 120_000);

  it("the in operator pushes down", async (ctx) => {
    requireAws(ctx);
    const p = policy({
      objectRules: {
        allowedObjects: ["patients"],
        rowFilters: [
          { field: "region", operator: FilterOperator.In, values: ["us-east", "eu-west"] },
        ],
      },
    });

    const rows = await runQuery(prepared("SELECT * FROM patients", p).query);

    expect(new Set(rows.map((r) => r["region"]))).toEqual(new Set(["us-east", "eu-west"]));
  }, 120_000);

  it("notEquals pushdown excludes the region", async (ctx) => {
    requireAws(ctx);
    // Negative operators are where this rewriter previously failed open, so the excluded value
    // is asserted ABSENT rather than only counting rows.
    const p = policy({
      objectRules: {
        allowedObjects: ["patients"],
        rowFilters: [{ field: "region", operator: FilterOperator.NotEquals, value: "us-west" }],
      },
    });

    const rows = await runQuery(prepared("SELECT * FROM patients", p).query);

    expect(rows.length).toBeGreaterThan(0);
    expect(rows.map((r) => r["region"])).not.toContain("us-west");
  }, 120_000);

  it("maxResults is pushed as LIMIT", async (ctx) => {
    requireAws(ctx);
    const p = policy({
      objectRules: { allowedObjects: ["patients"] },
      limits: { maxResults: 2 },
    });
    const prep = prepared("SELECT * FROM patients", p);
    expect(prep.query.toUpperCase()).toContain("LIMIT");

    expect(await runQuery(prep.query)).toHaveLength(2);
  }, 120_000);
});

// ---------------------------------------------------------------------------
// Denials happen before any SQL is sent
// ---------------------------------------------------------------------------

describe("denials precede execution", () => {
  it("canQuery false yields no executable SQL", (ctx) => {
    requireAws(ctx);
    const p = policy({
      permissions: { canQuery: false, readOnly: true },
      objectRules: { allowedObjects: ["patients"] },
    });

    const prep = prepared("SELECT * FROM patients", p);

    expect(prep.allowed).toBe(false);
    expect(prep.denialReason).toBeTruthy();
  });

  it("a table outside allowedObjects is refused", (ctx) => {
    requireAws(ctx);
    // The table exists in Glue, so a broken check would happily query it.
    const p = policy({ objectRules: { allowedObjects: ["encounters"] } });

    expect(prepared("SELECT * FROM patients", p).allowed).toBe(false);
  });

  it("CONTROL: a permitted table produces runnable SQL", async (ctx) => {
    requireAws(ctx);
    const p = policy({ objectRules: { allowedObjects: ["patients"] } });
    const prep = prepared("SELECT * FROM patients", p);

    expect(prep.allowed).toBe(true);
    expect((await runQuery(prep.query)).length).toBeGreaterThan(0);
  }, 120_000);
});

// ---------------------------------------------------------------------------
// Post-fetch completeness: the rewrite is not the whole control
// ---------------------------------------------------------------------------

describe("post-fetch pipeline over real Athena rows", () => {
  it("a hidden field survives the rewrite and is removed after", async (ctx) => {
    requireAws(ctx);
    // SELECT * is deliberately NOT expanded, so ssn comes back from Athena and the post pass
    // removes it. This asserts the seam: if someone optimised the pipeline away, it fails.
    const p = policy({
      objectRules: { allowedObjects: ["patients"], fieldRules: { hiddenFields: ["ssn"] } },
    });

    const raw = await runQuery(prepared("SELECT * FROM patients", p).query);
    expect(raw.some((r) => "ssn" in r)).toBe(true);

    const enforced = applyResultPipeline(raw as never, p) as Array<Record<string, unknown>>;

    expect(enforced.length).toBeGreaterThan(0);
    for (const r of enforced) expect(r).not.toHaveProperty("ssn");
  }, 120_000);

  it("masking applies to real Athena rows", async (ctx) => {
    requireAws(ctx);
    const p = policy({
      objectRules: {
        allowedObjects: ["patients"],
        fieldRules: { maskedFields: [{ field: "ssn", maskType: MaskType.Redact }] },
      },
    });

    const raw = await runQuery(prepared("SELECT * FROM patients", p).query);
    const enforced = applyResultPipeline(raw as never, p) as Array<Record<string, unknown>>;

    expect(JSON.stringify(enforced)).not.toContain("111-11-1111");
  }, 120_000);

  it("allowedFields projects Athena rows", async (ctx) => {
    requireAws(ctx);
    const p = policy({
      objectRules: {
        allowedObjects: ["patients"],
        fieldRules: { allowedFields: ["id", "region"] },
      },
    });

    const raw = await runQuery(prepared("SELECT * FROM patients", p).query);
    const enforced = applyResultPipeline(raw as never, p) as Array<Record<string, unknown>>;

    for (const r of enforced) {
      expect(Object.keys(r).every((k) => k === "id" || k === "region")).toBe(true);
    }
  }, 120_000);

  it("the pushdown and the post pass agree on the same policy", async (ctx) => {
    requireAws(ctx);
    // The safety property, as for the kb pushdown: filtering in SQL must reach the same verdict
    // as filtering in the pipeline. A disagreement means the rewrite is not a faithful
    // translation of the policy.
    const p = policy({
      objectRules: {
        allowedObjects: ["patients"],
        rowFilters: [{ field: "region", operator: FilterOperator.Equals, value: "us-east" }],
      },
    });

    const pushed = await runQuery(prepared("SELECT * FROM patients", p).query);
    const everything = await runQuery("SELECT * FROM patients");
    const postOnly = applyResultPipeline(everything as never, p) as Array<Record<string, unknown>>;

    expect(new Set(pushed.map((r) => r["id"]))).toEqual(new Set(postOnly.map((r) => r["id"])));
  }, 180_000);
});
