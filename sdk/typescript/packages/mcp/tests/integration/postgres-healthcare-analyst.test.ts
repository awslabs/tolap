/**
 * TypeScript SDK healthcare-analyst scenarios, against real Postgres.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client } from "pg";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { SecureContextToolWrapper } from "../../src/context-wrapper.js";
import {
  loadScenarios,
  mergePolicy,
  policyFromDict,
  signPolicy,
  requireService,
} from "./_scenarios.js";

const SCHEMA_PATH = resolve(
  __dirname,
  "..",
  "..",
  "..",
  "..",
  "..",
  "python",
  "tests",
  "integration",
  "schema.sql",
);
const DSN = process.env.TOLAP_TEST_DB_DSN ?? "postgresql:///tolap_integration_test";
const SIGNING_KEY = "integration-test-signing-key";

const DOC = loadScenarios("postgres-healthcare-analyst.json");
const BASE = DOC.basePolicy as Record<string, unknown>;
const SCENARIOS = DOC.scenarios;

let client: Client;
let dbReady = false;
let dbSkipReason: string | undefined;

beforeAll(async () => {
  client = new Client({ connectionString: DSN });
  try {
    await client.connect();
    await client.query(readFileSync(SCHEMA_PATH, "utf8"));
    dbReady = true;
  } catch (err) {
    dbSkipReason = String(err);
    console.warn(`Postgres not reachable at ${DSN}; skipping`, err);
  }
});

afterAll(async () => {
  if (client) await client.end().catch(() => {});
});

async function runQuery(table: string, columns: string[]) {
  const sql = `SELECT ${columns.join(", ")} FROM ${table} ORDER BY id`;
  const result = await client.query(sql);
  return result.rows as Record<string, unknown>[];
}

describe("postgres healthcare-analyst", () => {
  for (const scenario of SCENARIOS) {
    it(scenario.name, async () => {
      requireService(dbReady, "a local database", dbSkipReason);

      const merged = mergePolicy(BASE, scenario.policyOverride);
      const policy = policyFromDict(merged);
      const ctx = signPolicy(policy, SIGNING_KEY);
      const wrapper = new SecureContextToolWrapper({ signingKey: SIGNING_KEY });

      const fields = scenario.query.columns.map(
        (c: string) => `${scenario.query.table}.${c}`,
      );
      const exec = () =>
        wrapper.executeWithEnforcement(
          ctx,
          { toolName: "pg-query", objectName: scenario.query.table, fields },
          () => runQuery(scenario.query.table, scenario.query.columns),
        );

      if (!scenario.expected.pass) {
        await expect(exec()).rejects.toThrow(
          new RegExp(scenario.expected.errorContains),
        );
        return;
      }

      const rows = await exec();
      await assertPass(rows, scenario.expected, scenario.query.table);
    });
  }
});

async function assertPass(
  rows: Record<string, unknown>[],
  expected: any,
  table: string,
): Promise<void> {
  if ("rowCount" in expected) expect(rows).toHaveLength(expected.rowCount);
  if ("idsEqual" in expected) {
    const actual = rows.map((r) => r.id as number).sort((a, b) => a - b);
    const want = [...expected.idsEqual].sort((a: number, b: number) => a - b);
    expect(actual).toEqual(want);
  }
  if ("regions" in expected) {
    const actual = rows.map((r) => r.region as string).sort();
    expect(actual).toEqual([...expected.regions].sort());
  }
  if ("maskedField" in expected) {
    const spec = expected.maskedField;
    const ids = rows.map((r) => r.id as number);
    const sql = `SELECT id, ${spec.field} AS val FROM ${table} WHERE id = ANY($1) ORDER BY id`;
    const raw = await client.query(sql, [ids]);
    const originals = new Map(
      raw.rows.map((r: any) => [r.id as number, r.val]),
    );
    for (const row of rows) {
      const original = originals.get(row.id as number);
      assertMask(row[spec.field], original, spec.mask);
    }
  }
}

function assertMask(actual: unknown, original: unknown, mask: string): void {
  if (mask === "sha256-16") {
    const expected = createHash("sha256")
      .update(String(original))
      .digest("hex")
      .slice(0, 16);
    expect(actual).toBe(expected);
  } else if (mask === "redacted") {
    expect(actual).toBe("[REDACTED]");
  } else if (mask === "partial-first-1") {
    const orig = String(original);
    expect(String(actual)[0]).toBe(orig[0]);
    expect(String(actual).slice(1)).toBe("*".repeat(orig.length - 1));
  } else {
    throw new Error(`unknown mask kind: ${mask}`);
  }
}
