/**
 * `SqlEnforcementMode`: the two enforcement points must agree on what the caller sees.
 *
 * The mode decides how much data the database produces — `RewriteAndPost` pushes filters,
 * the limit and the projection into the SQL; `PostOnly` leaves the query untouched — and
 * if the two ever returned *different rows*, the mode would be an access-control setting
 * wearing a performance setting's clothes. That is the divergence class
 * canonical-enforcement-spec §4 exists to prevent.
 *
 * So these assert equality *between* the modes rather than correctness of each alone. A
 * per-mode test would pass if `PostOnly` quietly returned an extra row, because nothing
 * would compare the two. The live-database version of this is Python's
 * `test_enforcement_mode_parity.py`; here the "database" is a filter over fixture rows,
 * which is enough to pin the contract without a container.
 */

import { describe, expect, it } from "vitest";
import {
  DEFAULT_ENFORCEMENT_MODE,
  SqlDialect,
  SqlEnforcementMode,
  applyResultPipeline,
  fullyPushedDown,
  prepareSqlQuery,
  resolveEnforcementMode,
} from "../src/index.js";
import type { EffectivePolicy, RowFilter } from "../src/types.js";
import { FilterOperator } from "../src/types.js";

const SQL = "SELECT id, full_name, email, region, status FROM patients ORDER BY id";

/** The rows a database would hold. `PostOnly` sees all of these; a rewrite sees fewer. */
const ROWS = [
  { id: 1, full_name: "John Smith", email: "j@x.com", region: "us-east", status: "active" },
  { id: 2, full_name: "Jane Doe", email: "jane@x.com", region: "us-west", status: "active" },
  { id: 3, full_name: "Mary Johnson", email: "m@x.com", region: "us-east", status: "active" },
  { id: 4, full_name: "Carl Davis", email: "c@x.com", region: "us-west", status: "deleted" },
];

function policy(objectRules: Partial<EffectivePolicy["objectRules"]> = {}, maxResults?: number) {
  return {
    version: "1.0",
    sourceConnectionId: "db:analytics:patients",
    permissions: { canQuery: true, readOnly: true },
    objectRules: { allowedObjects: ["patients"], ...objectRules },
    limits: maxResults === undefined ? {} : { maxResults },
  } as unknown as EffectivePolicy;
}

/**
 * Stand in for the database: apply only what the emitted SQL would have applied.
 *
 * Crude on purpose — it honours the pushed `WHERE` for `equals`/`notEquals` and the
 * pushed `LIMIT`, which is exactly the subset `rewrite_and_post` pushes for these cases.
 * The point is to feed the post pass a *different, larger or smaller* input per mode, so
 * that equality of the final output is a real claim rather than a tautology.
 */
function fakeDatabase(query: string): Record<string, unknown>[] {
  let rows = [...ROWS];
  const eq = /"(\w+)" = '([^']*)'/.exec(query);
  if (eq) rows = rows.filter((r) => String(r[eq[1] as keyof typeof r]) === eq[2]);
  const ne = /\("(\w+)" <> '([^']*)' OR "\w+" IS NULL\)/.exec(query);
  if (ne) rows = rows.filter((r) => String(r[ne[1] as keyof typeof r]) !== ne[2]);
  const limit = /LIMIT (\d+)/i.exec(query);
  if (limit) rows = rows.slice(0, Number(limit[1]));
  return rows;
}

function runMode(p: EffectivePolicy, mode: SqlEnforcementMode) {
  const prep = prepareSqlQuery(SQL, p, { dialect: SqlDialect.Postgres, mode });
  expect(prep.allowed).toBe(true);
  return applyResultPipeline(fakeDatabase(prep.query), p);
}

const CASES: Record<string, EffectivePolicy> = {
  "pushable equals": policy({
    rowFilters: [{ field: "region", operator: FilterOperator.Equals, value: "us-east" }] as RowFilter[],
  }),
  // No portable SQL form, so neither mode pushes it and the post pass does the work.
  "unpushable startsWith": policy({
    rowFilters: [{ field: "full_name", operator: FilterOperator.StartsWith, value: "J" }] as RowFilter[],
  }),
  // Half pushed, half not: the database applies one filter, the post pass the other, and
  // the result must equal post-only applying both.
  "mixed pushable and not": policy({
    rowFilters: [
      { field: "region", operator: FilterOperator.Equals, value: "us-east" },
      { field: "full_name", operator: FilterOperator.StartsWith, value: "J" },
    ] as RowFilter[],
  }),
  // Needs the `IS NULL` arm when pushed, or the database drops a row the post pass keeps.
  "negative operator": policy({
    rowFilters: [{ field: "status", operator: FilterOperator.NotEquals, value: "deleted" }] as RowFilter[],
  }),
  // Masking has no SQL form at all, so it is post-pass work in both modes.
  "masked field": policy({
    fieldRules: { maskedFields: [{ field: "email", maskType: "redact" }] },
  }),
  // Hidden on a column the query does NOT name. A query that *does* name a hidden column
  // is refused outright in both modes rather than silently narrowed -- asserted below --
  // so it cannot appear in a parity case: there is no result to compare.
  "hidden field not projected": policy({ fieldRules: { hiddenFields: ["ssn"] } }),
  "result limit": policy({}, 2),
};

describe("both modes return identical results", () => {
  for (const [name, p] of Object.entries(CASES)) {
    it(name, () => {
      const rewritten = runMode(p, SqlEnforcementMode.RewriteAndPost);
      const postOnly = runMode(p, SqlEnforcementMode.PostOnly);
      expect(postOnly).toEqual(rewritten);
    });
  }
});

describe("the modes really do differ in what they ask the database", () => {
  it("emits different SQL, and PostOnly is byte-identical to the input", () => {
    // Guards the guard: every equality assertion above would also pass if `mode` were
    // ignored and both calls took the same path.
    const p = CASES["pushable equals"];
    const rewritten = prepareSqlQuery(SQL, p, {
      dialect: SqlDialect.Postgres,
      mode: SqlEnforcementMode.RewriteAndPost,
    });
    const postOnly = prepareSqlQuery(SQL, p, {
      dialect: SqlDialect.Postgres,
      mode: SqlEnforcementMode.PostOnly,
    });

    expect(rewritten.rewritten).toBe(true);
    expect(rewritten.query).toContain("WHERE");
    expect(postOnly.rewritten).toBe(false);
    // An integrator choosing PostOnly is choosing "the query that ran is the query I
    // wrote". A rewrite of any size, including a cosmetic one, breaks that promise.
    expect(postOnly.query).toBe(SQL);
  });

  it("reports every filter as unpushed in PostOnly", () => {
    // `fullyPushedDown` is what an integrator checks before running a query whose result
    // set may be large. Reporting only the inexpressible operators would tell a
    // PostOnly caller their filters were pushed when the database never saw them.
    const prep = prepareSqlQuery(SQL, CASES["mixed pushable and not"], {
      dialect: SqlDialect.Postgres,
      mode: SqlEnforcementMode.PostOnly,
    });
    expect(prep.unpushableFilters).toHaveLength(2);
    expect(fullyPushedDown(prep)).toBe(false);
  });
});

describe("PostOnly skips the rewrite, not the checks", () => {
  const bothModes = [SqlEnforcementMode.RewriteAndPost, SqlEnforcementMode.PostOnly];

  it.each(bothModes)("denies a query naming a hidden field (%s)", (mode) => {
    // The property that makes PostOnly safe to offer. If this refusal only lived on the
    // rewrite path, choosing PostOnly would hand the agent a column the policy hides.
    const prep = prepareSqlQuery("SELECT id, ssn FROM patients", policy({
      fieldRules: { hiddenFields: ["ssn"] },
    }), { dialect: SqlDialect.Postgres, mode });
    expect(prep.allowed).toBe(false);
    expect(prep.denialReason).toContain("permission");
  });

  it.each(bothModes)("denies a disallowed object (%s)", (mode) => {
    const prep = prepareSqlQuery("SELECT id FROM encounters", policy(), {
      dialect: SqlDialect.Postgres,
      mode,
    });
    expect(prep.allowed).toBe(false);
  });

  it.each(bothModes)("denies when canQuery is false (%s)", (mode) => {
    const p = { ...policy(), permissions: { canQuery: false } } as unknown as EffectivePolicy;
    const prep = prepareSqlQuery(SQL, p, { dialect: SqlDialect.Postgres, mode });
    expect(prep.allowed).toBe(false);
    expect(prep.denialReason).toBe("query not permitted");
  });

  it.each(bothModes)("denies an empty query (%s)", (mode) => {
    expect(prepareSqlQuery("   ", policy(), { mode }).allowed).toBe(false);
  });
});

describe("mode resolution", () => {
  it("defaults to rewriting, and the default is the cross-SDK contract", () => {
    // Not a tautology: .NET has always rewritten by default and TypeScript had no
    // prepare function at all, which is the divergence this enum closes. Changing the
    // default has to break this test.
    expect(DEFAULT_ENFORCEMENT_MODE).toBe(SqlEnforcementMode.RewriteAndPost);
    expect(resolveEnforcementMode(undefined)).toBe(SqlEnforcementMode.RewriteAndPost);
    expect(prepareSqlQuery(SQL, CASES["pushable equals"], {
      dialect: SqlDialect.Postgres,
    }).rewritten).toBe(true);
  });

  it("accepts the wire strings, so a mode can come from configuration", () => {
    expect(resolveEnforcementMode("postOnly")).toBe(SqlEnforcementMode.PostOnly);
    expect(resolveEnforcementMode("rewriteAndPost")).toBe(SqlEnforcementMode.RewriteAndPost);
  });

  it.each(["post-only", "postonly", "PostOnly", "rewrite", ""])(
    "throws on %s rather than falling back to the default",
    (bad) => {
      // A typo silently selecting the default would rewrite SQL for an integrator who
      // explicitly asked that it not be touched. `"PostOnly"` is in this list on purpose:
      // the wire value is `"postOnly"`, and accepting near-misses case-insensitively
      // would make the accepted set unclear.
      expect(() => resolveEnforcementMode(bad)).toThrow(/unrecognized SQL enforcement mode/);
    },
  );

  it("throws before doing any work", () => {
    // Resolved first in prepareSqlQuery, so a bad mode cannot rewrite a query on its way
    // to reporting the error.
    expect(() =>
      prepareSqlQuery(SQL, CASES["pushable equals"], { mode: "nope" }),
    ).toThrow(/unrecognized SQL enforcement mode/);
  });
});
