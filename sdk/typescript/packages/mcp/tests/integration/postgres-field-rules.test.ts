/**
 * TypeScript SDK field-rule scenarios. Cases come from
 * fixtures/integration-scenarios/postgres-field-rules.json.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client } from "pg";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { SecureContextToolWrapper } from "../../src/context-wrapper.js";
import { loadScenarios, policyFromDict, signPolicy, requireService } from "./_scenarios.js";

const SCHEMA_PATH = resolve(
  __dirname, "..", "..", "..", "..", "..", "..", "sdk", "python", "tests", "integration", "schema.sql",
);
const DSN = process.env.TOLAP_TEST_DB_DSN ?? "postgresql:///tolap_integration_test";
const SIGNING_KEY = "integration-test-signing-key";
const SCENARIOS = loadScenarios("postgres-field-rules.json").scenarios;

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

describe("postgres field rules", () => {
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

  if ("maskedField" in expected) {
    const spec = expected.maskedField;
    const ids = rows.map((r) => r.id as number);
    const sql = `SELECT id, ${spec.field} AS val FROM ${table} WHERE id = ANY($1) ORDER BY id`;
    const raw = await client.query(sql, [ids]);
    const originals = new Map(raw.rows.map((r: any) => [r.id as number, r.val]));
    for (const row of rows) {
      assertMask(row[spec.field], originals.get(row.id as number), spec.mask);
    }
  }

  if ("everyRowField" in expected) {
    for (const row of rows) {
      for (const spec of expected.everyRowField) {
        expect(row[spec.field]).toBe(spec.equals);
      }
    }
  }
}

function assertMask(actual: unknown, original: unknown, mask: string): void {
  switch (mask) {
    case "full-stars": {
      const s = String(original ?? "");
      expect(actual).toBe("*".repeat(s.length));
      break;
    }
    case "is-null":
      expect(actual).toBeNull();
      break;
    case "redacted":
      expect(actual).toBe("[REDACTED]");
      break;
    case "partial-last-4": {
      const s = String(original);
      expect(String(actual).endsWith(s.slice(-4))).toBe(true);
      expect(String(actual).slice(0, -4)).toBe("*".repeat(s.length - 4));
      break;
    }
    case "partial-first-2-last-2": {
      const s = String(original);
      expect(String(actual).slice(0, 2)).toBe(s.slice(0, 2));
      expect(String(actual).slice(-2)).toBe(s.slice(-2));
      expect(String(actual).slice(2, -2)).toBe("*".repeat(s.length - 4));
      break;
    }
    case "unchanged":
      expect(String(actual)).toBe(String(original));
      break;
    case "partial-first-1-hash": {
      const s = String(original);
      expect(String(actual)[0]).toBe(s[0]);
      expect(String(actual).slice(1)).toBe("#".repeat(s.length - 1));
      break;
    }
    case "sha256-16": {
      const expected = createHash("sha256").update(String(original)).digest("hex").slice(0, 16);
      expect(actual).toBe(expected);
      break;
    }
    default:
      throw new Error(`unknown mask kind ${mask}`);
  }
}
