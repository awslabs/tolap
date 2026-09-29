/**
 * Asserts the query-safety example actually enforces, not merely that it runs.
 *
 * Each assertion is an outcome — which query was refused and with what reason, whether the source
 * was reached, which row and which columns survived the pipeline, how many times a field was
 * hashed — so an example that printed plausible verdicts while enforcing nothing would fail here.
 */

import { describe, expect, it } from "vitest";

import * as ex from "./query-safety-example.js";

/**
 * The lines the query-safety example must print, byte for byte.
 *
 * Repeated verbatim in the Python and .NET suites: a divergence between the SDKs has to surface as
 * a *different line*. The reason strings and the hashes are the SDK's own, not the example's.
 */
const EXPECTED_LINES = [
  // 1. Every table a query reads is checked; a construct the check cannot resolve is refused.
  "  join an allowed table    ALLOW   the source ran",
  "  join a hidden table      DENY    object is hidden",
  "  comma join               DENY    object is hidden",
  "  derived table            DENY    object is hidden",
  "  subquery in WHERE        DENY    query uses a construct the pre-execution check cannot resolve: subquery",
  "  hidden field via alias   DENY    query references fields you do not have permission to access",
  "  other object's column    DENY    query references fields you do not have permission to access",
  "  bare column in a join    DENY    query references fields you do not have permission to access",
  // 2. The qualified filter reads patients.region only; encounters.name is projected out.
  "    patients.id=2  patients.name=Bruno Sato  patients.region=us-east  encounters.code=I10",
  "  name from patients       ALLOW",
  "  name from encounters     DENY    denied fields: name",
  "  code from encounters     ALLOW",
  // 3. Hashed once, hashed twice, and a marker honoured, ignored or taken on trust.
  "  plain rows               the wrapper enforces",
  "    id=1  name=Alice Nguyen  email=06c3aada7ffedc44  region=us-east",
  "  enforced, unmarked       hashed twice",
  "    id=1  name=Alice Nguyen  email=60d6b623948861a8  region=us-east",
  "  enforced, marked         marker honoured",
  "  marked for another user  marker ignored",
  "  marked, not enforced     a false claim",
  "    id=1  name=Alice Nguyen  email=alice@example.com  region=us-east",
];

/** What one enforcement of PATIENT_ROWS returns: Dan's eu-west row filtered, ssn hidden, email hashed. */
const HASHED_ONCE = { id: 1, name: "Alice Nguyen", email: "06c3aada7ffedc44", region: "us-east" };

describe("query-safety example", () => {
  it.each([1, 2, 3, 4, 5, 6, 7])("never lets refused query %i reach the source", async (index) => {
    const { reason, reached } = await ex.runQuery(ex.signedContext(), ex.QUERIES[index].sql);

    expect(reason).toBeDefined();
    expect(reached).toBe(false);
  });

  it("lets the allowed join reach the source", async () => {
    // Paired allow: the refusals above are the policy, not a check that refuses every join.
    const { reason, reached } = await ex.runQuery(ex.signedContext(), ex.QUERIES[0].sql);

    expect(reason).toBeUndefined();
    expect(reached).toBe(true);
  });

  it("reads a qualified row filter from its own object only", () => {
    const rows = ex.wrapper().postExecute(
      ex.signedContext(),
      ex.JOIN_ROWS.map((r) => ({ ...r })),
    );

    // Alice's encounters.region is us-east; only her patients.region may decide.
    expect(rows).toEqual([
      {
        "patients.id": 2,
        "patients.name": "Bruno Sato",
        "patients.region": "us-east",
        "encounters.code": "I10",
      },
    ]);
  });

  it.each([
    ["patients", "name", true],
    ["encounters", "name", false],
    ["encounters", "code", true],
  ] as const)("field pre-check on %s.%s allows: %s", (objectName, field, allowed) => {
    const decision = ex.wrapper().preExecute(ex.signedContext(), {
      toolName: "query_patients",
      objectName,
      fields: [field],
    });

    expect(decision.allowed).toBe(allowed);
  });

  it.each([
    ["plain rows", "06c3aada7ffedc44"],
    ["enforced, unmarked", "60d6b623948861a8"],
    ["enforced, marked", "06c3aada7ffedc44"],
    ["marked for another user", "06c3aada7ffedc44"],
    ["marked, not enforced", "alice@example.com"],
  ])("tool '%s' returns email %s", async (label, expectedEmail) => {
    const tool = ex.TOOLS.find((t) => t.label === label);
    if (tool === undefined) throw new Error(`no tool ${label}`);

    const rows = await ex.callTool(ex.signedContext(), tool);

    // Hidden-field removal and the row filter run whether or not the marker is honoured.
    expect(rows).toEqual([{ ...HASHED_ONCE, email: expectedEmail }]);
  });

  it("prints every expected line", async () => {
    // The example throws if a refused query reached the source, if a column the policy does not
    // allow came back, or if ssn leaked, so this covers those paths too.
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
    // The honoured marker and the ignored one both match the wrapper's own enforcement.
    const hashedOnce = "    id=1  name=Alice Nguyen  email=06c3aada7ffedc44  region=us-east";
    expect(lines.filter((l) => l === hashedOnce)).toHaveLength(3);
    // The only ssn values printed are the two raw join rows shown before enforcement.
    expect(lines.filter((l) => l.includes("ssn="))).toHaveLength(2);
    expect(lines.join("\n")).not.toContain("444-55-6666");
  });
});
