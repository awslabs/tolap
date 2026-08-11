/** TypeScript permission/limit scenarios. Mirrors the Python suite. */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client } from "pg";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { SecureContextToolWrapper } from "../../src/context-wrapper.js";
import { loadScenarios, policyFromDict, signPolicy, requireService } from "./_scenarios.js";

const SCHEMA_PATH = resolve(
  __dirname, "..", "..", "..", "..", "..", "..", "sdk", "python", "tests", "integration", "schema.sql",
);
const DSN = process.env.TOLAP_TEST_DB_DSN ?? "postgresql:///tolap_integration_test";
const SIGNING_KEY = "integration-test-signing-key";
const SCENARIOS = loadScenarios("permissions-and-limits.json").scenarios;

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
    console.warn(`Postgres not reachable; skipping`, err);
  }
});

afterAll(async () => {
  if (client) await client.end().catch(() => {});
});

async function runQuery(table: string, columns: string[]) {
  const sql = `SELECT ${columns.join(", ")} FROM ${table} ORDER BY id`;
  const r = await client.query(sql);
  return r.rows as Record<string, unknown>[];
}

describe("postgres permissions and limits", () => {
  for (const scenario of SCENARIOS) {
    it(scenario.name, async () => {
      requireService(dbReady, "a local database", dbSkipReason);
      const policy = policyFromDict(scenario.policy);
      const ctx = signPolicy(policy, SIGNING_KEY);
      const wrapper = new SecureContextToolWrapper({ signingKey: SIGNING_KEY });
      const args = {
        toolName: "pg-query",
        objectName: scenario.query.table,
        fields: scenario.fields,
      };
      const exec = () =>
        wrapper.executeWithEnforcement(ctx, args, () =>
          runQuery(scenario.query.table, scenario.query.columns),
        );

      if (!scenario.expected.pass) {
        await expect(exec()).rejects.toThrow(new RegExp(scenario.expected.errorContains));
        return;
      }
      const rows = await exec();
      if ("rowCount" in scenario.expected) {
        expect(rows).toHaveLength(scenario.expected.rowCount);
      }
    });
  }
});
