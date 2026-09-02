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

/**
 * A policy carrying a purpose profile.
 *
 * Separate from `base` because `purposeProfile` is a top-level sibling of `objectRules`
 * rather than a rule inside it -- it decides whether the policy resolves at all, not what
 * it returns.
 */
function purposeBound(purposeProfile: unknown, objectRules: unknown = {}) {
  return { ...base(objectRules), purposeProfile };
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

  // -- Purpose binding -----------------------------------------------------
  //
  // `purposeProfile` closes to five keys and `judge` to six, so the same class of bug
  // the masking editor had -- an invented parameter name that only fails at the save
  // button -- is available here twice over. The empty-array and absent cases below are
  // the ones that matter most: `allowedActions: []` denies every action and an absent
  // `allowedActions` permits every action, so both spellings have to be things the
  // schema accepts or the editor cannot express one of the two.
  ["purpose: the minimum the editor can emit", purposeBound({ purposeId: "fraud-detection" })],
  ["purpose: with a description", purposeBound({
    purposeId: "fraud-detection",
    description: "Investigating a flagged transaction on behalf of the fraud desk.",
  })],
  ["purpose: allowedActions empty (denies every action)", purposeBound({
    purposeId: "fraud-detection", allowedActions: [],
  })],
  ["purpose: allowedActions absent, deny-list only (unrestricted allow)", purposeBound({
    purposeId: "fraud-detection", prohibitedActions: ["export_pii"],
  })],
  ["purpose: prohibitedActions empty (restricts nothing)", purposeBound({
    purposeId: "fraud-detection", prohibitedActions: [],
  })],
  ["purpose: both lists empty", purposeBound({
    purposeId: "fraud-detection", allowedActions: [], prohibitedActions: [],
  })],
  ["purpose: category spellings the pattern permits", purposeBound({
    purposeId: "campaign-x-overlap",
    // Underscores, hyphens, digits and a single character are all legal for a category
    // and only the first is legal for a purposeId -- one shared validator would reject
    // `export_pii`, the spec's own example.
    allowedActions: ["aggregate_overlap", "read-only", "read2", "x", "0"],
    prohibitedActions: ["export_pii"],
  })],
  ["purpose: a category in both lists (prohibited wins, but valid)", purposeBound({
    purposeId: "fraud-detection",
    allowedActions: ["aggregate_overlap", "export_pii"],
    prohibitedActions: ["export_pii"],
  })],
  ["purpose: purposeId and a category at the 128-character ceiling", purposeBound({
    purposeId: "a".repeat(128), allowedActions: ["b".repeat(128)],
  })],
  ["purpose: judge just switched on", purposeBound({
    purposeId: "fraud-detection", judge: { enabled: true },
  })],
  ["purpose: judge configured but off, keeping its model", purposeBound({
    purposeId: "fraud-detection", judge: { enabled: false, model: "claude-sonnet" },
  })],
  ["purpose: judge with every key set", purposeBound({
    purposeId: "fraud-detection",
    judge: {
      enabled: true,
      model: "claude-sonnet",
      historyWindow: 25,
      confidenceThreshold: 0.9,
      escalationThreshold: 0.7,
      maxLatencyMs: 5000,
    },
  })],
  ["purpose: judge at every bound the schema allows", purposeBound({
    purposeId: "fraud-detection",
    judge: {
      historyWindow: 1,
      confidenceThreshold: 1,
      escalationThreshold: 0,
      maxLatencyMs: 100,
    },
  })],
  ["purpose: judge with inverted thresholds", purposeBound({
    // The editor warns about this and must still be able to save it: the inversion is a
    // merge-reachable state (both thresholds take the maximum independently), so a schema
    // that rejected it would make a mergeable policy unauthorable.
    purposeId: "fraud-detection",
    judge: { enabled: true, confidenceThreshold: 0.5, escalationThreshold: 0.9 },
  })],
  ["purpose: an empty judge object, as loaded and saved untouched", purposeBound({
    // Not something the editor authors from scratch -- ticking the box writes
    // `{ enabled: true }` -- but a policy edited elsewhere can carry it, and the editor
    // round-trips what it was given rather than normalising it.
    purposeId: "fraud-detection", judge: {},
  })],
  ["purpose: alongside object rules and limits", {
    ...purposeBound(
      {
        allowedObjects: ["patients"],
        fieldRules: { allowedFields: [], maskedFields: [{ field: "ssn", maskType: "redact" }] },
        rowFilters: [{ field: "region", operator: "equals", value: "west" }],
      },
    ),
    purposeProfile: {
      purposeId: "fraud-detection",
      description: "Investigating a flagged transaction.",
      allowedActions: ["aggregate_overlap"],
      prohibitedActions: ["export_pii"],
      judge: { enabled: true, model: "claude-sonnet", historyWindow: 5 },
    },
    limits: { maxResults: 0 },
  }],
];

/**
 * The shapes the purpose-profile editor had to be *constrained* not to emit.
 *
 * The rest of this file proves the editor cannot author a policy the server rejects.
 * These prove the constraints doing that work are load-bearing rather than decorative --
 * if the schema were to start accepting any of them, an inline warning in the editor
 * would be enforcing a rule nothing else does, and could quietly be dropped.
 */
// The scope checkbox. Added when `appliesToAll` gained a control -- before that the flag
// round-tripped through the console with no UI, so no shape it could emit was ever checked
// here either.
CASES.push(
  ["scope: appliesToAll on, with patterns kept", { ...base({}), appliesToAll: true }],
  [
    "scope: appliesToAll on and sourcePatterns absent",
    (() => {
      const doc = { ...base({}), appliesToAll: true } as Record<string, unknown>;
      delete doc.sourcePatterns;
      return doc;
    })(),
  ],
  ["scope: appliesToAll explicitly off", { ...base({}), appliesToAll: false }],
);

const REJECTED: Array<[string, unknown]> = [
  // Why "Remove purpose profile" deletes the key instead of blanking the fields.
  ["a profile with no purposeId", purposeBound({ allowedActions: [] })],
  // Why a blank purpose id blocks the save rather than merely reading oddly.
  ["a blank purposeId", purposeBound({ purposeId: "" })],
  // Why the purposeId warning exists: resolution is case-sensitive, and the schema
  // refuses the value outright rather than leaving it to resolve for nobody.
  ["an uppercase purposeId", purposeBound({ purposeId: "Fraud-Detection" })],
  ["a single-character purposeId", purposeBound({ purposeId: "f" })],
  ["a trailing hyphen in purposeId", purposeBound({ purposeId: "fraud-" })],
  // Why action categories are validated as they are typed.
  ["an uppercase action category", purposeBound({
    purposeId: "fraud-detection", allowedActions: ["EXPORT_PII"],
  })],
  ["an empty-string action category", purposeBound({
    purposeId: "fraud-detection", prohibitedActions: [""],
  })],
  // Why `judge` is a spelled-out interface rather than an open record, and why the
  // editor never invents a key.
  ["an invented judge key", purposeBound({
    purposeId: "fraud-detection", judge: { enabled: true, temperature: 0.2 },
  })],
  ["an invented profile key", purposeBound({
    purposeId: "fraud-detection", deniedActions: ["export_pii"],
  })],
  // Why the thresholds carry min/max attributes and the numeric fields are typed.
  ["a confidence threshold above 1", purposeBound({
    purposeId: "fraud-detection", judge: { confidenceThreshold: 1.5 },
  })],
  ["a history window of zero", purposeBound({
    purposeId: "fraud-detection", judge: { historyWindow: 0 },
  })],
  ["a latency budget below the 100ms floor", purposeBound({
    purposeId: "fraud-detection", judge: { maxLatencyMs: 50 },
  })],
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

describe("shapes the purpose-profile editor is constrained not to emit", () => {
  for (const [name, doc] of REJECTED) {
    it(name, () => {
      // Fragment mode as well as document mode: the console validates drafts as
      // `?fragment=true`, and fragment mode only drops the *top-level* `required`. If one
      // of these were accepted there, the editor's Save button would stay enabled and the
      // author would lose the draft at the server instead.
      expect(validateSchema(doc, "policy-definition").valid).toBe(false);
      expect(
        validateSchema(doc, "policy-definition", { fragment: true }).valid,
      ).toBe(false);
    });
  }
});
