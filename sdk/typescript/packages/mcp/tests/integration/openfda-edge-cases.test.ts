/**
 * Cross-SDK adversarial / edge-case scenarios for the openFDA wrapper.
 *
 * Same JSON file the Python and .NET SDKs consume:
 *   fixtures/integration-scenarios/openfda-edge-cases.json
 */

import { beforeAll, describe, expect, it } from "vitest";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  SecureHttpToolWrapper,
  type FetchLike,
} from "../../src/http-wrapper.js";
import {
  OPENFDA_FIXTURES,
  loadScenarios,
  policyFromDict,
  signPolicy,
} from "./_scenarios.js";

const SIGNING_KEY = "openfda-integration-key";
const SCENARIOS = loadScenarios("openfda-edge-cases.json").scenarios;
const LIVE_MODE = process.env.TOLAP_TEST_LIVE === "1";

const ROUTES: Record<string, string> = {
  "GET /drug/event.json": "drug_event_limit3.json",
  "GET /drug/label.json": "drug_label_limit3.json",
  "GET /food/enforcement.json": "food_enforcement_limit2.json",
};
const LIVE_LIMITS: Record<string, number> = {
  "/drug/event.json": 3,
  "/drug/label.json": 3,
  "/food/enforcement.json": 2,
};

function pathWithLimit(path: string): string {
  const limit = LIVE_LIMITS[path];
  return limit ? `${path}?limit=${limit}` : path;
}

function makeReplayFetch(): FetchLike {
  return async ({ method, url }) => {
    const noQuery = url.replace(/\?.*$/, "");
    const path = noQuery.replace(/^https?:\/\/[^/]+/, "");
    const key = `${method.toUpperCase()} ${path}`;
    const fixture = ROUTES[key];
    if (!fixture) {
      return { ok: false, status: 404, json: async () => ({ error: `no fixture for ${key}` }) };
    }
    const body = JSON.parse(readFileSync(resolve(OPENFDA_FIXTURES, fixture), "utf8"));
    return { ok: true, status: 200, json: async () => body };
  };
}

function makeLiveFetch(): FetchLike {
  return async ({ method, url, headers }) => {
    const response = await fetch(url, {
      method,
      headers: { "User-Agent": "tolap-sdk-tests/1.0", ...(headers ?? {}) },
    });
    const body = await response.json();
    return { ok: response.ok, status: response.status, json: async () => body };
  };
}

async function refreshRecordings(): Promise<void> {
  for (const [routeKey, fixture] of Object.entries(ROUTES)) {
    const path = routeKey.split(" ")[1];
    const url = `https://api.fda.gov${pathWithLimit(path)}`;
    const response = await fetch(url, { headers: { "User-Agent": "tolap-sdk-tests/1.0" } });
    if (!response.ok) throw new Error(`refresh failed: ${response.status} ${url}`);
    writeFileSync(resolve(OPENFDA_FIXTURES, fixture), await response.text());
  }
}

function walk(node: any, parts: string[]): any {
  let cur = node;
  for (const p of parts) {
    if (cur == null || typeof cur !== "object" || Array.isArray(cur) || !(p in cur)) return undefined;
    cur = cur[p];
  }
  return cur;
}

function walkCollect(node: any, parts: string[]): any[] {
  if (parts.length === 0) return [node];
  if (Array.isArray(node)) return node.flatMap((item) => walkCollect(item, parts));
  if (node == null || typeof node !== "object") return [];
  const [head, ...rest] = parts;
  if (!(head in node)) return [];
  return walkCollect(node[head], rest);
}

describe(`openFDA edge cases (${LIVE_MODE ? "LIVE" : "offline"})`, () => {
  beforeAll(async () => {
    if (LIVE_MODE) await refreshRecordings();
  }, 30_000);

  for (const scenario of SCENARIOS) {
    it(scenario.name, async () => {
      const policy = policyFromDict(scenario.policy);
      const ctx = signPolicy(policy, SIGNING_KEY);
      const wrapper = new SecureHttpToolWrapper(
        { signingKey: SIGNING_KEY, baseUrl: "https://api.fda.gov" },
        LIVE_MODE ? makeLiveFetch() : makeReplayFetch(),
      );

      const path = LIVE_MODE ? pathWithLimit(scenario.request.path) : scenario.request.path;
      const exec = () =>
        wrapper.request(ctx, {
          method: scenario.request.method,
          path,
          collectionPath: scenario.request.collectionPath,
        });

      if (!scenario.expected.pass) {
        await expect(exec()).rejects.toThrow(new RegExp(scenario.expected.errorContains));
        return;
      }

      const body = await exec();
      assertPass(body, scenario.expected, scenario.request);
    });
  }
});

function assertPass(body: any, expected: any, request: any): void {
  const cp = request.collectionPath as string | undefined;

  if ("rowCount" in expected) {
    const coll = cp ? walk(body, cp.split(".")) : null;
    expect(Array.isArray(coll)).toBe(true);
    expect(coll).toHaveLength(expected.rowCount);
  }

  if ("minResultsCount" in expected) {
    const coll = cp ? walk(body, cp.split(".")) : null;
    expect(Array.isArray(coll)).toBe(true);
    expect(coll.length).toBeGreaterThanOrEqual(expected.minResultsCount);
  }

  if ("hiddenField" in expected) {
    const spec = expected.hiddenField;
    const coll = walk(body, spec.collectionPath.split("."));
    expect(coll).toBeDefined();
    for (const row of coll) {
      const found = walkCollect(row, spec.field.split("."));
      expect(found).toEqual([]);
    }
  }

  if ("everyArrayElementMasked" in expected) {
    const spec = expected.everyArrayElementMasked;
    const arrays = walkCollect(body, spec.arrayPath.split("."));
    expect(arrays.length).toBeGreaterThan(0);
    let maskedCount = 0;
    for (const arr of arrays) {
      expect(Array.isArray(arr)).toBe(true);
      for (const item of arr) {
        if (item && typeof item === "object" && spec.field in item) {
          expect(item[spec.field]).toBe(spec.expectedValue);
          maskedCount++;
        }
      }
    }
    expect(maskedCount).toBeGreaterThan(0);
  }

  if ("everyArrayElementMatchesPattern" in expected) {
    const spec = expected.everyArrayElementMatchesPattern;
    const re = new RegExp(spec.pattern);
    let items = walkCollect(body, spec.arrayPath.split("."));
    if (items.length === 1 && Array.isArray(items[0])) items = items[0];
    for (const row of items) {
      const value = walk(row, spec.field.split("."));
      if (value === undefined) {
        if (spec.allowMissing) continue;
        throw new Error(`missing ${spec.field}`);
      }
      expect(String(value)).toMatch(re);
    }
  }

  if ("responseShape" in expected) {
    const spec = expected.responseShape;
    if ("topLevelKeys" in spec) {
      expect(typeof body).toBe("object");
      for (const k of spec.topLevelKeys) {
        expect(body).toHaveProperty(k);
      }
    }
    if ("minResultsCount" in spec && cp) {
      const coll = walk(body, cp.split("."));
      expect(Array.isArray(coll)).toBe(true);
      expect(coll.length).toBeGreaterThanOrEqual(spec.minResultsCount);
    }
    if ("metaMustContainKeys" in spec) {
      const meta = body.meta;
      expect(typeof meta).toBe("object");
      for (const k of spec.metaMustContainKeys) {
        expect(meta).toHaveProperty(k);
      }
    }
  }
}
