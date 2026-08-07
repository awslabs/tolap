/**
 * Every policy shape the console's rule editors can emit, validated against the real
 * schema.
 *
 * The console builds policy JSON by hand and the server validates it on save, so nothing
 * connects the two at build time -- a rule editor can emit a shape the schema rejects and
 * the only symptom is an author losing their work at the save button. This file is that
 * connection.
 *
 * It earned its place immediately: it caught the masking editor emitting an invented
 * `parameters` key, because the schema closes `parameters` to exactly four names.
 *
 * When a rule editor gains a control, add the shape it produces here.
 */

import { describe, expect, it } from "vitest";
import { validateSchema } from "../src/validation.ts";

function base(objectRules: unknown, limits?: unknown) {
  return {
    version: "1.0",
    name: "builder-emitted",
    priority: 100,
    sourcePatterns: ["db:analytics:*"],
    permissions: { canQuery: true, readOnly: true },
    objectRules,
    ...(limits ? { limits } : {}),
  };
}

const CASES: Array<[string, unknown]> = [
  ["masking: every mask type", base({ fieldRules: { maskedFields: [
    { field: "a", maskType: "null" }, { field: "b", maskType: "redact" },
    { field: "c", maskType: "full" }, { field: "d", maskType: "hash" },
    { field: "e", maskType: "partial" },
  ] } })],
  ["masking: partial with showFirst/showLast/maskChar", base({ fieldRules: { maskedFields: [
    { field: "ssn", maskType: "partial", parameters: { showFirst: 1, showLast: 4, maskChar: "#" } },
  ] } })],
  ["masking: full with maskChar", base({ fieldRules: { maskedFields: [
    { field: "ssn", maskType: "full", parameters: { maskChar: "#" } },
  ] } })],
  ["masking: hash with each algorithm", base({ fieldRules: { maskedFields: [
    { field: "a", maskType: "hash", parameters: { algorithm: "sha256" } },
    { field: "b", maskType: "hash", parameters: { algorithm: "sha512" } },
    { field: "c", maskType: "hash", parameters: { algorithm: "blake2b" } },
  ] } })],
  ["masking: no parameters key at all", base({ fieldRules: { maskedFields: [
    { field: "ssn", maskType: "partial" },
  ] } })],
  ["readOnlyFields", base({ fieldRules: { readOnlyFields: ["id", "created_at"] } })],
  ["rowFilters: single-value operators", base({ rowFilters: [
    { field: "region", operator: "equals", value: "west" },
    { field: "n", operator: "greaterThanOrEqual", value: 5 },
    { field: "s", operator: "like", value: "we%" },
    { field: "s", operator: "matches", value: "^we" },
  ] })],
  ["rowFilters: multi-value operators", base({ rowFilters: [
    { field: "region", operator: "in", values: ["west", "east"] },
    { field: "n", operator: "between", values: ["1", "9"] },
  ] })],
  ["rowFilters: no-value operators", base({ rowFilters: [
    { field: "discharged_at", operator: "isNull" },
    { field: "x", operator: "isNotNull" },
  ] })],
  ["endpointRules: allowed + methods", base({ endpointRules: {
    allowedEndpoints: ["/api/v1/patients", "/api/v1/patients/*/labs"],
    allowedMethods: ["GET", "POST", "DELETE"],
  } })],
  ["endpointRules: empty allowlist (deny-all)", base({ endpointRules: { allowedEndpoints: [] } })],
  ["endpointRules: empty methods (deny-all)", base({ endpointRules: { allowedMethods: [] } })],
  ["endpointRules: methods absent (schema default)", base({ endpointRules: { allowedEndpoints: ["/x"] } })],
  ["tagRules: allow and deny", base({ tagRules: { allowedTags: ["deidentified"], deniedTags: ["phi"] } })],
  ["tagRules: empty allow (deny-all)", base({ tagRules: { allowedTags: [] } })],
  ["limits: kb minSimilarityScore", base({ tagRules: { allowedTags: ["x"] } }, { minSimilarityScore: 0.7 })],
  ["limits: storage maxObjectSizeBytes", base({}, { maxObjectSizeBytes: 1048576 })],
  ["limits: maxResults", base({}, { maxResults: 100 })],
];

describe("shapes the expanded policy builder emits", () => {
  for (const [name, doc] of CASES) {
    it(name, () => {
      const r = validateSchema(doc, "policy-definition");
      expect(r.errors, `${name}: ${JSON.stringify(r.errors)}`).toEqual([]);
      expect(r.valid).toBe(true);
    });
  }
});
