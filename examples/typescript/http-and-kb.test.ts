/**
 * Asserts the HTTP and KB example enforces, not merely that it prints.
 *
 * The expected lines are byte-identical to `examples/python/test_http_and_kb.py` and
 * `examples/dotnet/HttpAndKbExampleTests.cs`. The reason strings are the SDK's own, so a
 * divergence between the SDKs surfaces as a different line.
 */

import { describe, expect, it } from "vitest";
import { KbFilterOp, buildKbFilter } from "@aws/tolap-core";

import * as ex from "./http-and-kb-example.js";

const EXPECTED_LINES = [
  // sourcePatterns: the same identity, a different policy per source, deny-all for neither.
  "  api:clinical:patients     patients-api-reader   canQuery=true",
  "  kb:clinical:guidelines    clinical-kb-reader    canQuery=true",
  "  api:research:patients     (none)                canQuery=false",
  // endpointRules, checked before the request is sent.
  "  GET /patients           ALLOW",
  "  GET /patients/1/notes   DENY    endpoint is hidden",
  "  GET /billing/invoices   DENY    endpoint not in allowed set",
  "  DELETE /patients/1      DENY    method not allowed",
  "  POST /patients          DENY    insert not permitted",
  "The fake API was reached 1 time. The four refused requests never",
  // The row, field and limit rules, still applied to the JSON response.
  "    id=1  name=Alice Nguyen  region=us-east  dob=[REDACTED]",
  "    id=2  name=Bruno Sato  region=us-east  dob=[REDACTED]",
  // The unmatched source is deny-all.
  "  GET /patients           DENY    query not permitted",
  // tagRules, pushed down to the provider.
  "    tags notIn [restricted]",
  "    tags in [clinical, public]",
  '    {"andAll":[{"notIn":{"key":"tags","value":["restricted"]}},{"in":{"key":"tags","value":["clinical","public"]}}]}',
  "Unpushed rules: none",
  "The provider returned 4 of 6: doc-1, doc-3, doc-5, doc-6",
  // And re-applied, with minSimilarityScore, in the post pass.
  "  doc-1  KEEP",
  "  doc-3  DROP  score 0.42 is below minSimilarityScore 0.5",
  "  doc-5  DROP  classification restricted, a key the provider never saw",
  "  doc-6  KEEP",
];

describe("HTTP and KB example", () => {
  it.each([
    ["GET", "/patients/1/notes", "endpoint is hidden"],
    ["GET", "/billing/invoices", "endpoint not in allowed set"],
    ["DELETE", "/patients/1", "method not allowed"],
    ["POST", "/patients", "insert not permitted"],
  ])("%s %s is refused before it reaches the API", async (method, path, reason) => {
    const api = new ex.FakeApi();

    const call = await ex.callApi(api, await ex.signedContext(ex.API_SOURCE), method, path);

    expect(call.allowed).toBe(false);
    expect(call.reason).toBe(reason);
    expect(api.hits).toEqual([]);
  });

  it("a permitted request still meets the row, field and limit rules", async () => {
    const api = new ex.FakeApi();

    const call = await ex.callApi(api, await ex.signedContext(ex.API_SOURCE), "GET", "/patients");

    expect(call.allowed).toBe(true);
    expect(api.hits).toEqual(["GET /patients"]);
    expect(call.rows!.map((row) => row.name)).toEqual(["Alice Nguyen", "Bruno Sato"]);
    for (const row of call.rows!) {
      expect(row).not.toHaveProperty("ssn");
      expect(row.dob).toBe("[REDACTED]");
    }
  });

  it("an unmatched source resolves to deny-all", async () => {
    const policy = await ex.resolveFor(ex.UNMATCHED_SOURCE);
    expect(policy.sourceProfiles).toEqual([]);
    expect(policy.permissions.canQuery).toBe(false);

    const api = new ex.FakeApi();
    const call = await ex.callApi(
      api,
      await ex.signedContext(ex.UNMATCHED_SOURCE),
      "GET",
      "/patients",
    );

    expect(call.allowed).toBe(false);
    expect(call.reason).toBe("query not permitted");
    expect(api.hits).toEqual([]);
  });

  it("the KB filter is built from the resolved tag rules", async () => {
    const filter = buildKbFilter(await ex.resolveFor(ex.KB_SOURCE), { metadataKeys: ["tags"] });

    expect(filter.clauses.map((c) => [c.key, c.op, c.values.join(",")])).toEqual([
      ["tags", KbFilterOp.NotIn, "restricted"],
      ["tags", KbFilterOp.In, "clinical,public"],
    ]);
    expect(ex.fakeKbRetrieve(filter.clauses).map((r) => r.id)).toEqual([
      "doc-1",
      "doc-3",
      "doc-5",
      "doc-6",
    ]);
  });

  it("runs clean and prints the lines the other two languages print", async () => {
    // main throws if a refused request reached the API, if ssn leaks, if the unmatched source is
    // served, or if the post pass drops other chunks, so this covers those paths too.
    const lines: string[] = [];
    const original = console.log;
    console.log = (...args: unknown[]) => {
      lines.push(args.map(String).join(" "));
    };
    try {
      await ex.main();
    } finally {
      console.log = original;
    }

    for (const expected of EXPECTED_LINES) {
      expect(lines, `missing line: ${expected}`).toContain(expected);
    }
    expect(lines.join("\n")).not.toContain("111-22-3333");
  });
});
