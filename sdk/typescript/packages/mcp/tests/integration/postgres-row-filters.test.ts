/**
 * TypeScript SDK row-filter scenarios, against real Postgres.
 * Cases are loaded from the shared fixtures/integration-scenarios JSON.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client } from "pg";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { SecureContextToolWrapper } from "../../src/context-wrapper.js";
import { loadScenarios, policyFromDict, signPolicy } from "./_scenarios.js";

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

const SCENARIOS = loadScenarios("postgres-row-filters.json").scenarios;

let client: Client;
let dbReady = false;

beforeAll(async () => {
  client = new Client({ connectionString: DSN });
  try {
    await client.connect();
    await client.query(readFileSync(SCHEMA_PATH, "utf8"));
    dbReady = true;
  } catch (err) {
    console.warn(`Postgres not reachable at ${DSN}; skipping integration tests.`, err);
  }
});

afterAll(async () => {
  if (client) await client.end().catch(() => {});
});

async function runQuery(table: string, columns: string[]): Promise<Record<string, unknown>[]> {
  const sql = `SELECT ${columns.join(", ")} FROM ${table} ORDER BY id`;
  const result = await client.query(sql);
  return result.rows as Record<string, unknown>[];
}

describe("postgres row filters", () => {
  for (const scenario of SCENARIOS) {
    it(scenario.name, async () => {
      if (!dbReady) {
        console.warn(`skipping ${scenario.name}: db not ready`);
        return;
      }

      const policy = policyFromDict(scenario.policy);
      const ctx = signPolicy(policy, SIGNING_KEY);
      const wrapper = new SecureContextToolWrapper({ signingKey: SIGNING_KEY });

      const expected = scenario.expected;
      const exec = () =>
        wrapper.executeWithEnforcement(
          ctx,
          { toolName: "pg-query", objectName: scenario.query.table },
          () => runQuery(scenario.query.table, scenario.query.columns),
        );

      if (!expected.pass) {
        await expect(exec()).rejects.toThrow(new RegExp(expected.errorContains));
        return;
      }

      const rows = await exec();
      assertPass(rows, expected);
    });
  }
});

function assertPass(rows: Record<string, unknown>[], expected: any): void {
  if ("rowCount" in expected) {
    expect(rows).toHaveLength(expected.rowCount);
  }
  if ("regions" in expected) {
    const actual = rows.map((r) => r.region as string).sort();
    const want = [...expected.regions].sort();
    expect(actual).toEqual(want);
  }
  if ("idsEqual" in expected) {
    const actual = rows.map((r) => r.id as number).sort((a, b) => a - b);
    const want = [...expected.idsEqual].sort((a: number, b: number) => a - b);
    expect(actual).toEqual(want);
  }
  if ("idsIn" in expected) {
    const allowed = new Set(expected.idsIn);
    for (const r of rows) {
      expect(allowed.has(r.id as number)).toBe(true);
    }
  }
}
