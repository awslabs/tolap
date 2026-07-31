/**
 * Cross-SDK scenarios executed against real MySQL.
 *
 * Same shared JSON the Postgres tests use; running them through MySQL proves
 * TOLAP enforcement is engine-agnostic.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createConnection, type Connection } from "mysql2/promise";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { SecureContextToolWrapper } from "../../src/context-wrapper.js";
import {
  loadScenarios,
  mergePolicy,
  policyFromDict,
  signPolicy,
} from "./_scenarios.js";

const SCHEMA_PATH = resolve(
  __dirname, "..", "..", "..", "..", "..", "..", "sdk", "python", "tests", "integration", "schema_mysql.sql",
);
const SIGNING_KEY = "integration-test-signing-key";

const HEALTHCARE_DOC = loadScenarios("postgres-healthcare-analyst.json");
const HEALTHCARE_BASE = HEALTHCARE_DOC.basePolicy as Record<string, unknown>;
const HEALTHCARE_SCENARIOS = HEALTHCARE_DOC.scenarios;
const ROW_FILTER_SCENARIOS = loadScenarios("postgres-row-filters.json").scenarios;
const FIELD_RULE_SCENARIOS = loadScenarios("postgres-field-rules.json").scenarios;
const PERMISSION_SCENARIOS = loadScenarios("permissions-and-limits.json").scenarios;

const RESERVED = new Set(["status"]);
const quote = (c: string) => (RESERVED.has(c) ? `\`${c}\`` : c);

let conn: Connection | null = null;
let dbReady = false;

beforeAll(async () => {
  try {
    conn = await createConnection({
      host: process.env.TOLAP_TEST_MYSQL_HOST ?? "127.0.0.1",
      user: process.env.TOLAP_TEST_MYSQL_USER ?? "root",
      password: process.env.TOLAP_TEST_MYSQL_PASSWORD ?? "",
      database: process.env.TOLAP_TEST_MYSQL_DB ?? "tolap_integration_test",
      port: Number(process.env.TOLAP_TEST_MYSQL_PORT ?? 3306),
      multipleStatements: true,
    });
    const sql = readFileSync(SCHEMA_PATH, "utf8");
    const cleaned = sql
      .split("\n")
      .filter((ln) => !ln.trim().startsWith("--"))
      .join("\n");
    await conn.query(cleaned);
    dbReady = true;
  } catch (err) {
    console.warn("MySQL not reachable; skipping integration tests.", err);
  }
});

afterAll(async () => {
  if (conn) await conn.end().catch(() => {});
});

async function runQuery(table: string, columns: string[]): Promise<Record<string, unknown>[]> {
  const cols = columns.map(quote).join(", ");
  const [rows] = await conn!.query(`SELECT ${cols} FROM ${table} ORDER BY id`);
  return (rows as any[]).map((r) => {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(r)) {
      // mysql2 returns BIGINTs as strings by default; coerce id to number.
      if (k === "id" && typeof r[k] === "string") out[k] = Number(r[k]);
      else out[k] = r[k];
    }
    return out;
  });
}

function wrapper() {
  return new SecureContextToolWrapper({ signingKey: SIGNING_KEY });
}

// ---------- healthcare-analyst on MySQL ----------

describe("MySQL: healthcare-analyst", () => {
  for (const scenario of HEALTHCARE_SCENARIOS) {
    it(scenario.name, async () => {
      if (!dbReady) return;
      const merged = mergePolicy(HEALTHCARE_BASE, scenario.policyOverride);
      const ctx = signPolicy(policyFromDict(merged), SIGNING_KEY);
      const fields = scenario.query.columns.map((c: string) => `${scenario.query.table}.${c}`);

      const exec = () =>
        wrapper().executeWithEnforcement(
          ctx,
          { toolName: "mysql-query", objectName: scenario.query.table, fields },
          () => runQuery(scenario.query.table, scenario.query.columns),
        );

      if (!scenario.expected.pass) {
        await expect(exec()).rejects.toThrow(new RegExp(scenario.expected.errorContains));
        return;
      }
      const rows = await exec();
      await assertHealthcarePass(rows, scenario.expected, scenario.query.table);
    });
  }
});

async function assertHealthcarePass(
  rows: Record<string, unknown>[],
  expected: any,
  table: string,
) {
  if ("rowCount" in expected) expect(rows).toHaveLength(expected.rowCount);
  if ("idsEqual" in expected) {
    const a = rows.map((r) => Number(r.id)).sort((x, y) => x - y);
    expect(a).toEqual([...expected.idsEqual].sort((x: number, y: number) => x - y));
  }
  if ("regions" in expected) {
    const a = rows.map((r) => r.region).sort();
    expect(a).toEqual([...expected.regions].sort());
  }
  if ("maskedField" in expected) {
    const spec = expected.maskedField;
    const ids = rows.map((r) => Number(r.id));
    if (ids.length === 0) return;
    const placeholders = ids.map(() => "?").join(", ");
    const [raw] = await conn!.query(
      `SELECT id, ${quote(spec.field)} AS val FROM ${table} WHERE id IN (${placeholders}) ORDER BY id`,
      ids,
    );
    const originals = new Map((raw as any[]).map((r) => [Number(r.id), r.val]));
    for (const row of rows) {
      assertMask(row[spec.field], originals.get(Number(row.id)), spec.mask);
    }
  }
}

function assertMask(actual: unknown, original: unknown, mask: string) {
  switch (mask) {
    case "sha256-16": {
      expect(actual).toBe(createHash("sha256").update(String(original)).digest("hex").slice(0, 16));
      break;
    }
    case "redacted":
      expect(actual).toBe("[REDACTED]");
      break;
    case "partial-first-1": {
      const s = String(original);
      expect(String(actual)[0]).toBe(s[0]);
      expect(String(actual).slice(1)).toBe("*".repeat(s.length - 1));
      break;
    }
    case "full-stars":
      expect(actual).toBe("*".repeat(String(original ?? "").length));
      break;
    case "is-null":
      expect(actual).toBeNull();
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
    default:
      throw new Error(`unknown mask ${mask}`);
  }
}

// ---------- row filters on MySQL ----------

describe("MySQL: row filters", () => {
  for (const scenario of ROW_FILTER_SCENARIOS) {
    it(scenario.name, async () => {
      if (!dbReady) return;
      const ctx = signPolicy(policyFromDict(scenario.policy), SIGNING_KEY);
      const exec = () =>
        wrapper().executeWithEnforcement(
          ctx,
          { toolName: "mysql-query", objectName: scenario.query.table },
          () => runQuery(scenario.query.table, scenario.query.columns),
        );
      if (!scenario.expected.pass) {
        await expect(exec()).rejects.toThrow(new RegExp(scenario.expected.errorContains));
        return;
      }
      const rows = await exec();
      if ("rowCount" in scenario.expected) expect(rows).toHaveLength(scenario.expected.rowCount);
      if ("regions" in scenario.expected) {
        expect(rows.map((r) => r.region).sort()).toEqual([...scenario.expected.regions].sort());
      }
      if ("idsEqual" in scenario.expected) {
        const a = rows.map((r) => Number(r.id)).sort((x, y) => x - y);
        expect(a).toEqual([...scenario.expected.idsEqual].sort((x: number, y: number) => x - y));
      }
    });
  }
});

// ---------- field rules on MySQL ----------

describe("MySQL: field rules", () => {
  for (const scenario of FIELD_RULE_SCENARIOS) {
    it(scenario.name, async () => {
      if (!dbReady) return;
      const ctx = signPolicy(policyFromDict(scenario.policy), SIGNING_KEY);
      const exec = () =>
        wrapper().executeWithEnforcement(
          ctx,
          {
            toolName: "mysql-query",
            objectName: scenario.query.table,
            fields: scenario.fields,
          },
          () => runQuery(scenario.query.table, scenario.query.columns),
        );
      if (!scenario.expected.pass) {
        await expect(exec()).rejects.toThrow(new RegExp(scenario.expected.errorContains));
        return;
      }
      const rows = await exec();
      if ("rowCount" in scenario.expected) expect(rows).toHaveLength(scenario.expected.rowCount);
      if ("maskedField" in scenario.expected) {
        const spec = scenario.expected.maskedField;
        const ids = rows.map((r) => Number(r.id));
        if (ids.length === 0) return;
        const placeholders = ids.map(() => "?").join(", ");
        const [raw] = await conn!.query(
          `SELECT id, ${quote(spec.field)} AS val FROM ${scenario.query.table} WHERE id IN (${placeholders}) ORDER BY id`,
          ids,
        );
        const originals = new Map((raw as any[]).map((r) => [Number(r.id), r.val]));
        for (const row of rows) {
          assertMask(row[spec.field], originals.get(Number(row.id)), spec.mask);
        }
      }
      if ("everyRowField" in scenario.expected) {
        for (const row of rows) {
          for (const spec of scenario.expected.everyRowField) {
            expect(row[spec.field]).toBe(spec.equals);
          }
        }
      }
    });
  }
});

// ---------- permissions/limits on MySQL ----------

describe("MySQL: permissions and limits", () => {
  for (const scenario of PERMISSION_SCENARIOS) {
    it(scenario.name, async () => {
      if (!dbReady) return;
      const ctx = signPolicy(policyFromDict(scenario.policy), SIGNING_KEY);
      const exec = () =>
        wrapper().executeWithEnforcement(
          ctx,
          {
            toolName: "mysql-query",
            objectName: scenario.query.table,
            fields: scenario.fields,
          },
          () => runQuery(scenario.query.table, scenario.query.columns),
        );
      if (!scenario.expected.pass) {
        await expect(exec()).rejects.toThrow(new RegExp(scenario.expected.errorContains));
        return;
      }
      const rows = await exec();
      if ("rowCount" in scenario.expected) expect(rows).toHaveLength(scenario.expected.rowCount);
    });
  }
});
