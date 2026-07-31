/**
 * TypeScript SDK openFDA scenarios.
 *
 * Default mode: replay against pre-recorded responses in fixtures/api/openfda/.
 * Live mode (TOLAP_TEST_LIVE=1): refresh the recordings from api.fda.gov once
 * per session, then run the SAME enforcement assertions against the real
 * responses. Each live session = 3 actual GETs to api.fda.gov plus full TOLAP
 * enforcement coverage on the responses.
 */

import { beforeAll, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
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
const DOC = loadScenarios("openfda-api-enforcement.json");
const BASE = DOC.basePolicy as Record<string, unknown>;

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
    // Strip any query string before matching against the route table — the
    // ?limit= we attach for live calls is harmless to the offline replay.
    const noQuery = url.replace(/\?.*$/, "");
    const path = noQuery.replace(/^https?:\/\/[^/]+/, "");
    const key = `${method.toUpperCase()} ${path}`;
    const fixture = ROUTES[key];
    if (!fixture) {
      return {
        ok: false,
        status: 404,
        json: async () => ({ error: `no fixture for ${key}` }),
      };
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
    return {
      ok: response.ok,
      status: response.status,
      json: async () => body,
    };
  };
}

async function refreshRecordingsFromLive(): Promise<void> {
  for (const [routeKey, fixture] of Object.entries(ROUTES)) {
    const [, path] = routeKey.split(" ");
    const url = `https://api.fda.gov${pathWithLimit(path)}`;
    const response = await fetch(url, {
      headers: { "User-Agent": "tolap-sdk-tests/1.0" },
    });
    if (!response.ok) {
      throw new Error(`Live recording failed: ${response.status} on ${url}`);
    }
    const text = await response.text();
    writeFileSync(resolve(OPENFDA_FIXTURES, fixture), text);
  }
}

function recordingFor(path: string): unknown {
  const fixture = ROUTES[`GET ${path}`];
  return JSON.parse(readFileSync(resolve(OPENFDA_FIXTURES, fixture), "utf8"));
}

function walk(node: any, parts: string[]): any {
  let cursor = node;
  for (const p of parts) {
    if (cursor == null || typeof cursor !== "object" || !(p in cursor)) {
      return undefined;
    }
    cursor = cursor[p];
  }
  return cursor;
}

describe(`openFDA API enforcement (${LIVE_MODE ? "LIVE" : "offline replay"})`, () => {
  beforeAll(async () => {
    if (LIVE_MODE) {
      await refreshRecordingsFromLive();
    }
  }, 30_000);

  for (const scenario of DOC.scenarios) {
    it(scenario.name, async () => {
      const policy = policyFromDict(BASE);
      const ctx = signPolicy(policy, SIGNING_KEY);
      const fetchFn = LIVE_MODE ? makeLiveFetch() : makeReplayFetch();
      const wrapper = new SecureHttpToolWrapper(
        { signingKey: SIGNING_KEY, baseUrl: "https://api.fda.gov" },
        fetchFn,
      );

      // In live mode pass ?limit=N so the wrapper's response matches the
      // recording row count (the recording was just refreshed with the same N).
      const path = LIVE_MODE
        ? pathWithLimit(scenario.request.path)
        : scenario.request.path;

      const exec = () =>
        wrapper.request(ctx, {
          method: scenario.request.method,
          path,
          collectionPath: scenario.request.collectionPath,
        });

      if (!scenario.expected.pass) {
        await expect(exec()).rejects.toThrow(
          new RegExp(scenario.expected.errorContains),
        );
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
  if ("maskedField" in expected) {
    const spec = expected.maskedField;
    const cpath = spec.collectionPath as string;
    const fp = (spec.field as string).split(".");
    const coll = walk(body, cpath.split("."));
    const original = walk(recordingFor(request.path), cpath.split("."));
    for (let i = 0; i < coll.length; i++) {
      const actual = walk(coll[i], fp);
      const orig = walk(original[i], fp);
      assertMask(actual, orig, spec.mask);
    }
  }
  if ("hiddenField" in expected) {
    const spec = expected.hiddenField;
    const cpath = spec.collectionPath as string;
    const fp = (spec.field as string).split(".");
    const coll = walk(body, cpath.split("."));
    for (const row of coll) {
      expect(walk(row, fp)).toBeUndefined();
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
  } else {
    throw new Error(`unknown mask: ${mask}`);
  }
}
