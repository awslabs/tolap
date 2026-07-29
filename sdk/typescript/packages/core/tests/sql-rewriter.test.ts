/**
 * SQL query rewriting.
 *
 * The first block ports all 23 tests from the Prism reference implementation
 * (`SqlQueryRewriterTests.cs`) so the behavioral contract carries over verbatim
 * where it was correct. The blocks after it pin the places where Prism was WRONG --
 * each names the defect -- plus SQL-injection defences and the operator coverage.
 *
 * Everything here is about a resource optimization, not the enforcement boundary
 * (canonical spec §4). `applyResultPipeline` still runs over the results, so a
 * rewrite that declines to act costs transfer and never disclosure. Several tests
 * assert exactly that: the rewriter narrows the query or leaves it alone, and never
 * widens it.
 */

import { describe, expect, it } from "vitest";
import {
  SqlQueryRewriter,
  SqlDialect,
  DEFAULT_DIALECT,
  MAX_QUERY_LENGTH,
} from "../src/sql-rewriter.js";
import { applyRowFilters, applyResultPipeline } from "../src/enforcement.js";
import { FilterOperator } from "../src/types.js";
import type {
  EffectivePolicy,
  FieldRules,
  MaskingRule,
  ObjectRules,
  PolicyLimits,
  RowFilter,
} from "../src/types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** The TOLAP analogue of Prism's `CreatePolicy` test helper. */
function createPolicy(opts: {
  allowedFields?: string[];
  hiddenFields?: string[];
  maskedFields?: MaskingRule[];
  rowFilters?: RowFilter[];
  maxResults?: number;
  canQuery?: boolean;
} = {}): EffectivePolicy {
  const fieldRules: FieldRules = {};
  if (opts.allowedFields !== undefined) fieldRules.allowedFields = opts.allowedFields;
  if (opts.hiddenFields !== undefined) fieldRules.hiddenFields = opts.hiddenFields;
  if (opts.maskedFields !== undefined) fieldRules.maskedFields = opts.maskedFields;

  const objectRules: ObjectRules = {};
  if (Object.keys(fieldRules).length > 0) objectRules.fieldRules = fieldRules;
  if (opts.rowFilters !== undefined) objectRules.rowFilters = opts.rowFilters;

  const limits: PolicyLimits = {};
  if (opts.maxResults !== undefined) limits.maxResults = opts.maxResults;

  return {
    version: "1.0",
    userId: "user-001",
    tenantId: "tenant-001",
    sourceConnectionId: "db:production:patients",
    resolvedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    sourceProfiles: ["rewriter"],
    permissions: {
      canQuery: opts.canQuery ?? true,
      canExport: false,
      readOnly: true,
    },
    ...(Object.keys(objectRules).length > 0 ? { objectRules } : {}),
    ...(Object.keys(limits).length > 0 ? { limits } : {}),
    integrity: { algorithm: "none", signature: "" },
  };
}

const rewriter = new SqlQueryRewriter();

/** The rewritten query text, for the common case. */
function rewrite(query: string, policy: EffectivePolicy): string {
  return rewriter.rewriteQuery(query, policy).query;
}

/** The rewritten query text for a given dialect. */
function rewrite2(
  query: string,
  policy: EffectivePolicy,
  dialect: SqlDialect | string,
): string {
  return rewriter.rewriteQuery(query, policy, dialect).query;
}

/** A rewriter that records every decline explanation it is given. */
function withDiagnostics(): { rw: SqlQueryRewriter; messages: string[] } {
  const messages: string[] = [];
  return {
    rw: new SqlQueryRewriter({ diagnostics: (m) => messages.push(m) }),
    messages,
  };
}

// ===========================================================================
// The 23 ported Prism tests
// ===========================================================================

describe("ported from Prism SqlQueryRewriterTests", () => {
  // 1
  it("adds a WHERE clause for a row filter", () => {
    const result = rewrite(
      "SELECT id, name FROM patients",
      createPolicy({
        rowFilters: [
          { field: "region", operator: FilterOperator.Equals, value: "US" },
        ],
      }),
    );

    expect(result).toContain("WHERE");
    expect(result).toContain('"region"');
    expect(result).toContain("'US'");
  });

  // 2
  it("removes hidden columns from an explicit SELECT", () => {
    const result = rewrite(
      "SELECT id, name, ssn, date_of_birth FROM patients",
      createPolicy({ hiddenFields: ["ssn", "date_of_birth"] }),
    );

    expect(result).not.toContain("ssn");
    expect(result).not.toContain("date_of_birth");
    expect(result).toContain("id");
    expect(result).toContain("name");
  });

  // 3 -- the one that is easy to get wrong
  it("does NOT remove masked columns from the SELECT", () => {
    // Masking happens AFTER the fetch, so a masked column must survive into the
    // executed query or there is nothing left to mask: the field would silently
    // vanish from the result instead of appearing masked. Removing it would also be
    // a behavior change the policy never asked for -- `maskedFields` says "show a
    // transformed value", not "do not return this column".
    const result = rewrite(
      "SELECT id, name, email, phone FROM patients",
      createPolicy({
        maskedFields: [
          { field: "email", maskType: "partial", parameters: { showLast: 4 } },
          { field: "phone", maskType: "full" },
        ],
      }),
    );

    expect(result).toContain("email");
    expect(result).toContain("phone");
    expect(result).toContain("id");
    expect(result).toContain("name");
  });

  // 4
  it("expands SELECT * to the allowed columns minus the hidden ones", () => {
    const result = rewrite(
      "SELECT * FROM patients",
      createPolicy({
        allowedFields: ["id", "name", "ssn", "email"],
        hiddenFields: ["ssn"],
      }),
    );

    expect(result).not.toContain("*");
    expect(result).toContain('"id"');
    expect(result).toContain('"name"');
    expect(result).toContain('"email"');
    expect(result).not.toContain('"ssn"');
  });

  // 5
  it("returns the original query when the policy imposes no restriction", () => {
    const query = "SELECT id, name, email FROM patients";
    const result = rewriter.rewriteQuery(query, createPolicy());

    expect(result.query).toBe(query);
    expect(result.rewritten).toBe(false);
  });

  // 6
  it("filters columns correctly across multiple tables", () => {
    const result = rewrite(
      "SELECT p.id, p.name, p.ssn, d.diagnosis FROM patients p JOIN diagnoses d ON p.id = d.patient_id",
      createPolicy({ hiddenFields: ["ssn"] }),
    );

    expect(result).not.toContain("p.ssn");
    expect(result).toContain("p.id");
    expect(result).toContain("p.name");
    expect(result).toContain("d.diagnosis");
  });

  // 7
  it("preserves existing WHERE conditions", () => {
    const result = rewrite(
      "SELECT id, name FROM patients WHERE status = 'active'",
      createPolicy({
        rowFilters: [
          { field: "region", operator: FilterOperator.Equals, value: "US" },
        ],
      }),
    );

    expect(result).toContain('"region"');
    expect(result).toContain("'US'");
    expect(result).toContain("status = 'active'");
    expect(result).toContain("AND");
  });

  // 8-10 (Prism's [Theory] over null/empty/whitespace)
  it.each([["" as string], ["   "]])(
    "returns the original for an empty or whitespace query (%j)",
    (query) => {
      const policy = createPolicy({
        rowFilters: [{ field: "col", operator: FilterOperator.Equals, value: "val" }],
      });
      expect(rewriter.rewriteQuery(query, policy).query).toBe(query);
    },
  );

  it("returns the original for a non-string query without throwing", () => {
    // Prism's [InlineData(null)] case. TS types forbid it, but a JS caller or an
    // untyped JSON boundary can still hand one over, and the rewriter must not throw
    // on the security path.
    const policy = createPolicy({
      rowFilters: [{ field: "col", operator: FilterOperator.Equals, value: "val" }],
    });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const result = rewriter.rewriteQuery(null as any, policy);
    expect(result.query).toBeNull();
    expect(result.rewritten).toBe(false);
    // Nothing was pushed, so every filter is reported unpushable.
    expect(result.unpushableFilters).toHaveLength(1);
  });

  // 11
  it("applies the maxResults limit when there is no existing LIMIT", () => {
    expect(
      rewrite("SELECT id, name FROM patients", createPolicy({ maxResults: 500 })),
    ).toContain("LIMIT 500");
  });

  // 12
  it("uses the minimum when the existing LIMIT is larger", () => {
    const result = rewrite(
      "SELECT id, name FROM patients LIMIT 10000",
      createPolicy({ maxResults: 500 }),
    );
    expect(result).toContain("LIMIT 500");
    expect(result).not.toContain("LIMIT 10000");
  });

  // 13
  it("preserves an existing LIMIT smaller than maxResults", () => {
    expect(
      rewrite(
        "SELECT id, name FROM patients LIMIT 100",
        createPolicy({ maxResults: 500 }),
      ),
    ).toContain("LIMIT 100");
  });

  // 14
  it("validateQuery is false when the query references a hidden column", () => {
    expect(
      rewriter.validateQuery(
        "SELECT id, ssn FROM patients",
        createPolicy({ hiddenFields: ["ssn"] }),
      ),
    ).toBe(false);
  });

  // 15
  it("validateQuery is true when the query references only allowed columns", () => {
    expect(
      rewriter.validateQuery(
        "SELECT id, name FROM patients",
        createPolicy({ allowedFields: ["id", "name", "email"] }),
      ),
    ).toBe(true);
  });

  // 16
  it("validateQuery is false for an empty query", () => {
    const policy = createPolicy();
    expect(rewriter.validateQuery("", policy)).toBe(false);
    expect(rewriter.validateQuery("   ", policy)).toBe(false);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(rewriter.validateQuery(null as any, policy)).toBe(false);
  });

  // 17-19 (Prism's [Theory] over table-name forms)
  it.each([
    ["SELECT * FROM patients", "patients"],
    ["SELECT * FROM public.patients", "patients"],
    ['SELECT * FROM "my_schema.my_table"', "my_table"],
    ['SELECT * FROM "my_schema"."my_table"', "my_table"],
  ])("extractTableName(%j) is %j", (query, expected) => {
    expect(rewriter.extractTableName(query)).toBe(expected);
  });

  // 20
  it("extractTableName is undefined with no FROM clause", () => {
    expect(rewriter.extractTableName("SHOW TABLES")).toBeUndefined();
  });

  // 21
  it("buildWhereClause generates a correct equals condition", () => {
    const clause = rewriter.buildWhereClause([
      { field: "department", operator: FilterOperator.Equals, value: "cardiology" },
    ]);
    expect(clause).toContain('"department"');
    expect(clause).toContain("'cardiology'");
  });

  // 22
  it("buildWhereClause combines multiple filters with AND", () => {
    const clause = rewriter.buildWhereClause([
      { field: "region", operator: FilterOperator.Equals, value: "US" },
      { field: "active", operator: FilterOperator.Equals, value: "true" },
    ]);
    expect(clause).toContain("AND");
    expect(clause).toContain('"region"');
    expect(clause).toContain('"active"');
  });

  // 23
  it("buildWhereClause is empty for no filters", () => {
    expect(rewriter.buildWhereClause([])).toBe("");
  });

  // 24
  it("handles an IN-operator row filter", () => {
    const result = rewrite(
      "SELECT id, name FROM patients",
      createPolicy({
        rowFilters: [
          { field: "region", operator: FilterOperator.In, values: ["US", "CA", "UK"] },
        ],
      }),
    );

    expect(result).toContain("IN");
    expect(result).toContain("'US'");
    expect(result).toContain("'CA'");
    expect(result).toContain("'UK'");
  });

  // 25
  it("SELECT * with hidden but no allowed columns leaves the query intact", () => {
    // Prism's conservative behavior, kept: without an allowedFields list the set of
    // columns the table HAS is unknown, so hidden columns cannot be subtracted from
    // `*` without schema access the SDK deliberately does not assume.
    const query = "SELECT * FROM patients";
    const result = rewrite(query, createPolicy({ hiddenFields: ["ssn"] }));

    expect(result).toContain("SELECT");
    expect(result).toContain("FROM patients");
    expect(result).toBe(query);
  });

  // 26
  it("inserts WHERE before ORDER BY when there is no existing WHERE", () => {
    const result = rewrite(
      "SELECT id, name FROM patients ORDER BY name",
      createPolicy({
        rowFilters: [
          { field: "active", operator: FilterOperator.Equals, value: "true" },
        ],
      }),
    );

    const whereIndex = result.toUpperCase().indexOf("WHERE");
    const orderByIndex = result.toUpperCase().indexOf("ORDER BY");
    expect(whereIndex).toBeGreaterThanOrEqual(0);
    expect(whereIndex).toBeLessThan(orderByIndex);
  });

  // 27
  it("allowedFields restricts an explicit SELECT list", () => {
    const result = rewrite(
      "SELECT id, name, email, phone FROM patients",
      createPolicy({ allowedFields: ["id", "name"] }),
    );

    expect(result).toContain("id");
    expect(result).toContain("name");
    expect(result).not.toContain("email");
    expect(result).not.toContain("phone");
  });
});

// ===========================================================================
// The SELECT * limitation, stated loudly
// ===========================================================================

describe("SELECT * with hiddenFields but no allowedFields", () => {
  it("explains the limitation through diagnostics", () => {
    const { rw, messages } = withDiagnostics();
    rw.rewriteQuery("SELECT * FROM patients", createPolicy({ hiddenFields: ["ssn"] }));

    const joined = messages.join("\n");
    expect(joined).toContain("SELECT *");
    expect(joined).toContain("allowedFields");
    // The integrator must learn the actual consequence: it is not a disclosure, it
    // is a transfer cost, and there are two concrete ways to avoid it.
    expect(joined).toContain("cross the wire");
  });

  it("the hidden column is still removed by the post pass, so nothing leaks", () => {
    // The whole reason the conservative behavior is acceptable: SELECT * is left
    // alone, the DB returns ssn, and step 5 of the pipeline strips it before the
    // agent ever sees it. Only the transfer was wasted.
    const policy = createPolicy({ hiddenFields: ["ssn"] });
    const rows = [{ id: 1, name: "John", ssn: "111-22-3333" }];

    expect(applyResultPipeline(rows, policy)).toEqual([{ id: 1, name: "John" }]);
  });

  it("a wildcard allowedFields entry is also declined, not expanded", () => {
    // A glob has no column list to expand to, and dropping the entries it stands for
    // would narrow the projection below what the policy GRANTS -- breaking a valid
    // query rather than protecting anything.
    const query = "SELECT * FROM patients";
    const { rw, messages } = withDiagnostics();
    const result = rw.rewriteQuery(
      query,
      createPolicy({ allowedFields: ["id", "name_*"], hiddenFields: ["ssn"] }),
    );

    expect(result.query).toBe(query);
    expect(messages.join("\n")).toContain("wildcard");
  });

  it("an empty allowedFields projects a constant rather than nothing", () => {
    // An EMPTY allow-list denies every field (spec §3). "SELECT  FROM t" would be a
    // syntax error, so a constant keeps the statement valid and matches the
    // post-fetch outcome, where each surviving row has no fields.
    const result = rewrite(
      "SELECT * FROM patients",
      createPolicy({ allowedFields: [] }),
    );
    expect(result).toBe("SELECT 1 FROM patients");
  });

  it("an explicit list emptied by the rules also projects a constant", () => {
    const result = rewrite(
      "SELECT ssn, date_of_birth FROM patients",
      createPolicy({ hiddenFields: ["ssn", "date_of_birth"] }),
    );
    expect(result).toBe("SELECT 1 FROM patients");
  });
});

// ===========================================================================
// Prism defects deliberately NOT reproduced
// ===========================================================================

describe("Prism defect: HAVING max(ssn) > '1' passed validation", () => {
  it("rejects a hidden field wrapped in an aggregate", () => {
    // The token left of `>` is `)`, so Prism's comparison patterns extracted no
    // field at all and the query passed. That is a real disclosure: the aggregate's
    // VALUE is revealed by which rows come back, even though ssn never appears in
    // the projection. Fields are now extracted from function arguments too.
    expect(
      rewriter.validateQuery(
        "SELECT region, max(ssn) FROM patients GROUP BY region HAVING max(ssn) > '1'",
        createPolicy({ hiddenFields: ["ssn"] }),
      ),
    ).toBe(false);
  });

  it("rejects a hidden field inside an aggregate in the SELECT list", () => {
    expect(
      rewriter.validateQuery(
        "SELECT count(ssn) FROM patients",
        createPolicy({ hiddenFields: ["ssn"] }),
      ),
    ).toBe(false);
  });

  it("rejects a hidden field inside a nested call", () => {
    expect(
      rewriter.validateQuery(
        "SELECT region FROM patients WHERE length(ssn) > 5",
        createPolicy({ hiddenFields: ["ssn"] }),
      ),
    ).toBe(false);
  });

  it("does not mistake a string literal's contents for a field name", () => {
    // Literals are stripped before the function-argument scan, so `concat('ssn', x)`
    // is not read as a reference to the ssn column.
    expect(
      rewriter.validateQuery(
        "SELECT concat('ssn', name) FROM patients",
        createPolicy({ hiddenFields: ["ssn"] }),
      ),
    ).toBe(true);
  });
});

describe("Prism defect: round(1.5) and CAST(id AS text) were falsely rejected", () => {
  it("accepts a numeric literal inside a call expression", () => {
    // Prism split the entry on the LAST dot, so `round(1.5)` yielded `5)` as a
    // "column", which matched no allow-list entry. A false denial pushes integrators
    // toward turning validation off, which is worse than the bug.
    expect(
      rewriter.validateQuery(
        "SELECT round(1.5) FROM patients",
        createPolicy({ allowedFields: ["id", "name"] }),
      ),
    ).toBe(true);
  });

  it("accepts a CAST to a SQL type name", () => {
    // `text` was extracted as a column and rejected. SQL type names are now in the
    // keyword denylist.
    expect(
      rewriter.validateQuery(
        "SELECT cast(id AS text) FROM patients",
        createPolicy({ allowedFields: ["id"] }),
      ),
    ).toBe(true);
  });

  it.each([
    "SELECT cast(id AS varchar) FROM patients",
    "SELECT cast(id AS bigint) FROM patients",
    "SELECT cast(id AS timestamp) FROM patients",
    "SELECT cast(id AS boolean) FROM patients",
    "SELECT cast(id AS numeric) FROM patients",
    "SELECT cast(id AS double precision) FROM patients",
  ])("accepts %j", (query) => {
    expect(rewriter.validateQuery(query, createPolicy({ allowedFields: ["id"] }))).toBe(
      true,
    );
  });

  it("accepts a numeric second argument to a function", () => {
    expect(
      rewriter.validateQuery(
        "SELECT round(price, 2) FROM patients",
        createPolicy({ allowedFields: ["price"] }),
      ),
    ).toBe(true);
  });

  it("still rejects a genuinely non-allowed field inside a call", () => {
    // The false-negative fix must not become a false positive: the allow-list check
    // still has to see the real field references.
    expect(
      rewriter.validateQuery(
        "SELECT round(salary, 2) FROM patients",
        createPolicy({ allowedFields: ["price"] }),
      ),
    ).toBe(false);
  });
});

describe("Prism defect: subquery injection targeted the wrong WHERE", () => {
  it("injects into the OUTER WHERE, not the subquery's", () => {
    // Prism replaced the FIRST `WHERE`. For a query whose first WHERE is inside a
    // subquery, that filtered the subquery and left the outer result set completely
    // unrestricted -- a total bypass of the row filter.
    const result = rewrite(
      "SELECT id FROM patients WHERE id IN (SELECT patient_id FROM encounters WHERE status = 'active')",
      createPolicy({
        rowFilters: [
          { field: "region", operator: FilterOperator.Equals, value: "us-east" },
        ],
      }),
    );

    const outerWhere = result.toUpperCase().indexOf("WHERE");
    const subqueryStart = result.indexOf("(");
    // The injected condition sits at the OUTER WHERE, before the subquery opens.
    expect(outerWhere).toBeLessThan(subqueryStart);
    expect(result).toContain(`WHERE ("region" = 'us-east') AND (id IN (`);
    // The subquery's own WHERE survives untouched.
    expect(result).toContain("WHERE status = 'active'");
  });

  it("a WHERE that exists only inside a subquery still gets an outer one", () => {
    // No top-level WHERE at all, so the injection must ADD one rather than
    // hijacking the subquery's.
    const result = rewrite(
      "SELECT id FROM patients p JOIN (SELECT patient_id FROM encounters WHERE status = 'active') e ON p.id = e.patient_id",
      createPolicy({
        rowFilters: [
          { field: "region", operator: FilterOperator.Equals, value: "us-east" },
        ],
      }),
    );

    expect(result).toContain("WHERE status = 'active'");
    expect(result.trimEnd()).toMatch(/WHERE "region" = 'us-east'$/);
  });

  it("the word WHERE inside a string literal is not a WHERE clause", () => {
    const result = rewrite(
      "SELECT id FROM patients WHERE note = 'see WHERE clause'",
      createPolicy({
        rowFilters: [{ field: "region", operator: FilterOperator.Equals, value: "us" }],
      }),
    );

    // Exactly one injection, at the real clause.
    expect(result.toUpperCase().split("WHERE").length - 1).toBe(2);
    expect(result).toContain(`WHERE ("region" = 'us') AND (note = 'see WHERE clause')`);
  });

  it("a parenthesis inside a string literal does not shift the depth", () => {
    const result = rewrite(
      "SELECT id FROM patients WHERE note = 'a ( b'",
      createPolicy({ maxResults: 10 }),
    );
    expect(result).toBe("SELECT id FROM patients WHERE note = 'a ( b' LIMIT 10");
  });

  it("a doubled quote inside a literal does not end it", () => {
    const result = rewrite(
      "SELECT id FROM patients WHERE note = 'it''s WHERE'",
      createPolicy({ maxResults: 10 }),
    );
    expect(result).toBe("SELECT id FROM patients WHERE note = 'it''s WHERE' LIMIT 10");
  });

  it("a doubled quote inside a quoted identifier does not end it", () => {
    const result = rewrite(
      'SELECT id FROM patients WHERE "odd""name" = 1',
      createPolicy({ maxResults: 10 }),
    );
    expect(result).toBe('SELECT id FROM patients WHERE "odd""name" = 1 LIMIT 10');
  });

  it("an unbalanced parenthesis cannot drive the depth negative", () => {
    // Otherwise an inner keyword would look top-level and be injected into.
    expect(() =>
      rewrite("SELECT id FROM patients) WHERE x = 1", createPolicy({ maxResults: 5 })),
    ).not.toThrow();
  });

  it("clamps the LAST top-level LIMIT, not an operand's", () => {
    // An earlier top-level LIMIT belongs to a set operand; clamping it would change
    // which rows that operand contributes rather than how many the caller receives.
    const result = rewrite(
      "SELECT id FROM a LIMIT 5 UNION SELECT id FROM b LIMIT 10000",
      createPolicy({ maxResults: 500 }),
    );
    expect(result).toContain("LIMIT 5 UNION");
    expect(result).toContain("LIMIT 500");
  });

  it("does not clamp a LIMIT inside a subquery", () => {
    const result = rewrite(
      "SELECT id FROM (SELECT id FROM patients LIMIT 10000) t",
      createPolicy({ maxResults: 500 }),
    );
    expect(result).toContain("LIMIT 10000) t");
    expect(result).toMatch(/LIMIT 500$/);
  });
});

describe("Prism defect: injected conditions were not parenthesised", () => {
  it("parenthesises the ORIGINAL condition, not just the injected one", () => {
    // Prism emitted `WHERE (filters) AND <original>`. With an original of `a OR b`,
    // AND binds tighter than OR, so the statement became
    // `(filters AND a) OR b` -- every row matching b came back with the security
    // filter bypassed entirely. This is a complete row-filter bypass triggered by an
    // ordinary agent query.
    const result = rewrite(
      "SELECT id FROM patients WHERE status = 'active' OR status = 'pending'",
      createPolicy({
        rowFilters: [
          { field: "region", operator: FilterOperator.Equals, value: "us-east" },
        ],
      }),
    );

    expect(result).toBe(
      "SELECT id FROM patients WHERE (\"region\" = 'us-east') AND " +
        "(status = 'active' OR status = 'pending')",
    );
  });

  it("multiple filters are ANDed inside the injected group", () => {
    const result = rewrite(
      "SELECT id FROM patients WHERE a = 1 OR b = 2",
      createPolicy({
        rowFilters: [
          { field: "region", operator: FilterOperator.Equals, value: "us" },
          { field: "status", operator: FilterOperator.Equals, value: "active" },
        ],
      }),
    );

    expect(result).toContain(
      `WHERE ("region" = 'us' AND "status" = 'active') AND (a = 1 OR b = 2)`,
    );
  });
});

describe("Prism defect: WHERE insert point was chosen by pattern order", () => {
  it("inserts before GROUP BY when GROUP BY comes first", () => {
    // Prism iterated a fixed list [ORDER BY, GROUP BY, HAVING, LIMIT] and returned
    // the first PATTERN that matched anywhere, so this query inserted before
    // `ORDER BY` and emitted `GROUP BY region WHERE ... ORDER BY n` -- syntactically
    // invalid SQL that fails at the database.
    const result = rewrite(
      "SELECT region, count(*) AS n FROM patients GROUP BY region ORDER BY n",
      createPolicy({
        rowFilters: [{ field: "status", operator: FilterOperator.Equals, value: "a" }],
      }),
    );

    expect(result).toBe(
      "SELECT region, count(*) AS n FROM patients WHERE \"status\" = 'a' " +
        "GROUP BY region ORDER BY n",
    );
  });

  it.each([
    ["ORDER BY name", "ORDER BY"],
    ["GROUP BY region", "GROUP BY"],
    ["LIMIT 10", "LIMIT"],
    ["OFFSET 5", "OFFSET"],
    ["UNION SELECT id FROM other", "UNION"],
    ["INTERSECT SELECT id FROM other", "INTERSECT"],
    ["EXCEPT SELECT id FROM other", "EXCEPT"],
  ])("inserts WHERE before a trailing %j", (tail, keyword) => {
    const result = rewrite(
      `SELECT id FROM patients ${tail}`,
      createPolicy({
        rowFilters: [{ field: "status", operator: FilterOperator.Equals, value: "a" }],
      }),
    );

    const whereIndex = result.toUpperCase().indexOf("WHERE");
    const keywordIndex = result.toUpperCase().indexOf(keyword);
    expect(whereIndex).toBeGreaterThanOrEqual(0);
    expect(whereIndex).toBeLessThan(keywordIndex);
  });

  it("inserts before HAVING and keeps the GROUP BY intact", () => {
    const result = rewrite(
      "SELECT region FROM patients GROUP BY region HAVING count(*) > 1",
      createPolicy({
        rowFilters: [{ field: "status", operator: FilterOperator.Equals, value: "a" }],
      }),
    );
    expect(result).toBe(
      "SELECT region FROM patients WHERE \"status\" = 'a' " +
        "GROUP BY region HAVING count(*) > 1",
    );
  });

  it("does not strand the original separator or lose a space", () => {
    // Inserting AT the clause offset (rather than backing up over the whitespace
    // first) stranded the original separator on the left and left none on the right:
    // "FROM patients   WHERE ...GROUP BY region", where GROUP BY is welded to the
    // injected condition. Backing up puts the injected text's own leading space
    // immediately after `patients` and leaves the original run intact before GROUP BY.
    const result = rewrite(
      "SELECT id FROM patients   GROUP BY region",
      createPolicy({
        rowFilters: [{ field: "s", operator: FilterOperator.Equals, value: "a" }],
      }),
    );
    expect(result).toBe(
      "SELECT id FROM patients WHERE \"s\" = 'a'   GROUP BY region",
    );
    // The two tokens that must never be welded together.
    expect(result).not.toMatch(/patients\s*WHERE\s*$/);
    expect(result).not.toMatch(/'GROUP/);
  });

  it("appends at the end when there is no trailing clause", () => {
    const result = rewrite(
      "SELECT id FROM patients",
      createPolicy({
        rowFilters: [{ field: "s", operator: FilterOperator.Equals, value: "a" }],
      }),
    );
    expect(result).toBe(`SELECT id FROM patients WHERE "s" = 'a'`);
  });

  it("inserts before a trailing semicolon rather than after it", () => {
    const result = rewrite(
      "SELECT id FROM patients;",
      createPolicy({
        rowFilters: [{ field: "s", operator: FilterOperator.Equals, value: "a" }],
      }),
    );
    expect(result).toBe(`SELECT id FROM patients WHERE "s" = 'a';`);
  });

  it("keeps a trailing semicolon after an appended LIMIT", () => {
    expect(rewrite("SELECT id FROM patients;", createPolicy({ maxResults: 5 }))).toBe(
      "SELECT id FROM patients LIMIT 5;",
    );
  });
});

describe("Prism defect: negative operators dropped null-valued rows", () => {
  // Spec §7 drops rows whose field is ABSENT, not rows whose value is null. SQL
  // `col <> 'x'` is unknown-therefore-false for a null col, so without an IS NULL
  // arm the database drops a row the post pass KEEPS -- the same policy returns
  // fewer rows when the optimization is on. That is a silent behavioral difference
  // between two paths that are meant to be equivalent.

  it("notEquals gets an IS NULL arm", () => {
    expect(
      rewriter.buildWhereClause([
        { field: "region", operator: FilterOperator.NotEquals, value: "eu-west" },
      ]),
    ).toBe(`("region" <> 'eu-west' OR "region" IS NULL)`);
  });

  it("notIn gets an IS NULL arm", () => {
    expect(
      rewriter.buildWhereClause([
        { field: "region", operator: FilterOperator.NotIn, values: ["eu-west", "apac"] },
      ]),
    ).toBe(`("region" NOT IN ('eu-west', 'apac') OR "region" IS NULL)`);
  });

  it("the SQL and the post pass agree that a null-valued row is KEPT", () => {
    // The property the IS NULL arm exists to preserve.
    const policy = createPolicy({
      rowFilters: [
        { field: "region", operator: FilterOperator.NotEquals, value: "eu-west" },
      ],
    });
    expect(applyRowFilters([{ id: 1, region: null }], policy)).toHaveLength(1);
    expect(rewriter.buildWhereClause(policy.objectRules!.rowFilters!)).toContain(
      "IS NULL",
    );
  });

  it("notLike needs NO IS NULL arm -- both paths drop a null-valued row", () => {
    // SQL `NULL NOT LIKE 'x'` is unknown, which drops the row; the post pass also
    // drops it (a null is not "unlike" a pattern, it is incomparable). Adding an arm
    // here would make the pushed-down path KEEP a row the post pass discards, which
    // is the wrong direction.
    expect(
      rewriter.buildWhereClause([
        { field: "name", operator: FilterOperator.NotLike, value: "internal-%" },
      ]),
    ).toBe(`"name" NOT LIKE 'internal-%'`);

    const policy = createPolicy({
      rowFilters: [
        { field: "name", operator: FilterOperator.NotLike, value: "internal-%" },
      ],
    });
    expect(applyRowFilters([{ id: 1, name: null }], policy)).toEqual([]);
  });

  it("equals against null renders IS NULL, not `= NULL`", () => {
    // `col = NULL` is unknown for EVERY row, so it would match nothing where the
    // post pass matches the null-valued rows.
    expect(
      rewriter.buildWhereClause([
        { field: "deleted_at", operator: FilterOperator.Equals, value: null },
      ]),
    ).toBe(`"deleted_at" IS NULL`);
    expect(
      rewriter.buildWhereClause([
        { field: "deleted_at", operator: FilterOperator.Equals },
      ]),
    ).toBe(`"deleted_at" IS NULL`);
  });

  it("notEquals against null renders IS NOT NULL", () => {
    expect(
      rewriter.buildWhereClause([
        { field: "deleted_at", operator: FilterOperator.NotEquals, value: null },
      ]),
    ).toBe(`"deleted_at" IS NOT NULL`);
  });

  it("a null entry in an IN list is declined rather than emitted", () => {
    // SQL `NOT IN (NULL, ...)` is never true, so it would drop rows the post pass
    // keeps. Declining leaves the filter entirely to the post pass, where the two
    // paths cannot disagree.
    const { rw, messages } = withDiagnostics();
    expect(
      rw.buildWhereClause([
        { field: "region", operator: FilterOperator.NotIn, values: ["us", null] },
      ]),
    ).toBe("");
    expect(messages.join("\n")).toContain("null entry");
  });
});

describe("Prism defect: fail-open neutral predicates", () => {
  it("never emits 1=1 for a filter it failed to build", () => {
    // Prism emitted `1=1` for a malformed BETWEEN, converting the most restrictive
    // possible outcome into NO restriction at all. A filter that cannot be built is
    // omitted so the post pass enforces it; a neutral predicate would grant access.
    const malformed: RowFilter[] = [
      { field: "age", operator: FilterOperator.Between, values: [] },
      { field: "age", operator: FilterOperator.Between, values: [1] },
      { field: "age", operator: FilterOperator.Between },
    ];

    for (const filter of malformed) {
      const clause = rewriter.buildWhereClause([filter]);
      expect(clause, JSON.stringify(filter)).not.toContain("1 = 1");
      // A malformed range is satisfiable by NO row post-fetch, so `1 = 0` is the
      // faithful rendering -- restrictive, not neutral.
      expect(clause).toBe("1 = 0");
      expect(applyRowFilters([{ age: 5 }], createPolicy({ rowFilters: [filter] })))
        .toEqual([]);
    }
  });

  it("an unpushable filter contributes nothing, not a neutral predicate", () => {
    expect(
      rewriter.buildWhereClause([
        { field: "note", operator: FilterOperator.Contains, value: "x" },
      ]),
    ).toBe("");
  });

  it("a mix of pushable and unpushable filters emits only the pushable ones", () => {
    const clause = rewriter.buildWhereClause([
      { field: "region", operator: FilterOperator.Equals, value: "us" },
      { field: "note", operator: FilterOperator.Matches, value: ".*" },
      { field: "status", operator: FilterOperator.Equals, value: "active" },
    ]);
    expect(clause).toBe(`"region" = 'us' AND "status" = 'active'`);
    expect(clause).not.toContain("1 = 1");
  });

  it("a query with ONLY unpushable filters is not given a vacuous WHERE", () => {
    const query = "SELECT id FROM patients";
    expect(
      rewrite(
        query,
        createPolicy({
          rowFilters: [{ field: "note", operator: FilterOperator.Contains, value: "x" }],
        }),
      ),
    ).toBe(query);
  });
});

// ===========================================================================
// Reporting what could not be pushed down (spec §4, normative)
// ===========================================================================

describe("unpushableFilters", () => {
  it("reports the three operators with no portable SQL form", () => {
    const filters: RowFilter[] = [
      { field: "note", operator: FilterOperator.Contains, value: "x" },
      { field: "note", operator: FilterOperator.StartsWith, value: "x" },
      { field: "note", operator: FilterOperator.Matches, value: ".*" },
    ];
    const result = rewriter.rewriteQuery(
      "SELECT id FROM patients",
      createPolicy({ rowFilters: filters }),
    );

    expect(result.unpushableFilters).toEqual(filters);
  });

  it("is empty when every filter reached the database", () => {
    const result = rewriter.rewriteQuery(
      "SELECT id FROM patients",
      createPolicy({
        rowFilters: [
          { field: "region", operator: FilterOperator.Equals, value: "us" },
          { field: "age", operator: FilterOperator.Between, values: [18, 65] },
        ],
      }),
    );
    expect(result.unpushableFilters).toEqual([]);
  });

  it("is empty for a policy with no filters at all", () => {
    expect(rewriter.unpushableFilters(createPolicy())).toEqual([]);
    expect(rewriter.unpushableFilters(createPolicy({ rowFilters: [] }))).toEqual([]);
  });

  it("reports a filter declined for an unsafe field name", () => {
    const filters: RowFilter[] = [
      { field: 'region"; DROP TABLE x --', operator: FilterOperator.Equals, value: "us" },
    ];
    const result = rewriter.rewriteQuery(
      "SELECT id FROM patients",
      createPolicy({ rowFilters: filters }),
    );
    expect(result.unpushableFilters).toEqual(filters);
  });

  it("reports a filter declined for an unrenderable value", () => {
    const filters: RowFilter[] = [
      { field: "note", operator: FilterOperator.Equals, value: "back\\slash" },
    ];
    expect(rewriter.unpushableFilters(createPolicy({ rowFilters: filters }))).toEqual(
      filters,
    );
  });

  it("reports every filter when the query was too long to parse", () => {
    const filters: RowFilter[] = [
      { field: "region", operator: FilterOperator.Equals, value: "us" },
    ];
    const huge = `SELECT id FROM patients WHERE ${"x".repeat(MAX_QUERY_LENGTH)}`;
    const result = rewriter.rewriteQuery(huge, createPolicy({ rowFilters: filters }));

    expect(result.query).toBe(huge);
    expect(result.rewritten).toBe(false);
    expect(result.unpushableFilters).toEqual(filters);
  });

  it("reports an unrecognized operator as unpushable", () => {
    const filters: RowFilter[] = [{ field: "a", operator: "gte-typo", value: 1 }];
    expect(rewriter.unpushableFilters(createPolicy({ rowFilters: filters }))).toEqual(
      filters,
    );
  });
});

// ===========================================================================
// SQL injection
// ===========================================================================

describe("SQL injection: values", () => {
  // Policy authors are trusted (spec §12), but this is a security boundary that
  // builds SQL text, so defence in depth applies. The rule throughout: refuse what
  // cannot be rendered identically in every target dialect, rather than escape it
  // and hope.

  it("a classic `' OR 1=1 --` payload is escaped, not executable", () => {
    const clause = rewriter.buildWhereClause([
      { field: "region", operator: FilterOperator.Equals, value: "' OR 1=1 --" },
    ]);

    // The payload's quote is doubled, so it stays inside the literal.
    expect(clause).toBe(`"region" = ''' OR 1=1 --'`);
    // The literal is balanced: an even number of quote characters.
    expect((clause.match(/'/g) ?? []).length % 2).toBe(0);
    // The payload sits entirely INSIDE the literal: everything from the first quote
    // to the last is one string, so `OR 1=1` and `--` are data, not syntax. Asserted
    // structurally rather than by pattern-matching the text, because a regex over the
    // output cannot tell a literal's interior from statement text -- which is the very
    // distinction being tested.
    const firstQuote = clause.indexOf("'");
    const lastQuote = clause.lastIndexOf("'");
    expect(clause.slice(firstQuote + 1, lastQuote)).toBe("'' OR 1=1 --");
    // Nothing follows the closing quote, so no injected tail escaped the literal.
    expect(clause.slice(lastQuote + 1)).toBe("");
    // And the condition is still exactly one comparison on the intended column.
    expect(clause.slice(0, firstQuote)).toBe('"region" = ');
  });

  it("a bare single quote is doubled", () => {
    expect(
      rewriter.buildWhereClause([
        { field: "name", operator: FilterOperator.Equals, value: "O'Brien" },
      ]),
    ).toBe(`"name" = 'O''Brien'`);
  });

  it("a semicolon stays inside the literal", () => {
    const clause = rewriter.buildWhereClause([
      { field: "note", operator: FilterOperator.Equals, value: "a; DROP TABLE t" },
    ]);
    expect(clause).toBe(`"note" = 'a; DROP TABLE t'`);
    // The scanner agrees the semicolon is inside a literal, so it cannot terminate
    // a statement.
    expect((clause.match(/'/g) ?? []).length).toBe(2);
  });

  it("a BACKSLASH is refused outright, not escaped", () => {
    // The important one. Doubling `'` is correct ANSI escaping but insufficient:
    // MySQL treats `\` as a string escape by default, so `'\''` leaves the literal
    // OPEN and everything after it becomes statement text. Rather than emit a
    // dialect-conditional escape, the value is refused and the post pass enforces
    // the filter.
    const { rw, messages } = withDiagnostics();
    expect(
      rw.buildWhereClause([
        { field: "note", operator: FilterOperator.Equals, value: "a\\' OR 1=1 --" },
      ]),
    ).toBe("");
    expect(messages.join("\n")).toContain("backslash");
  });

  it("a NUL byte is refused", () => {
    // NUL truncates the statement for some client libraries, so text after it would
    // silently vanish -- including the rest of the security condition.
    expect(
      rewriter.buildWhereClause([
        { field: "note", operator: FilterOperator.Equals, value: "a b" },
      ]),
    ).toBe("");
  });

  it("a newline or carriage return is refused", () => {
    // A newline terminates a `--` comment, so the tail of a value becomes code.
    for (const value of ["a\nb", "a\rb", "a\r\n-- x"]) {
      expect(
        rewriter.buildWhereClause([
          { field: "note", operator: FilterOperator.Equals, value },
        ]),
        JSON.stringify(value),
      ).toBe("");
    }
  });

  it("a tab and other control characters are refused", () => {
    for (const value of ["a\tb", "ab", "ab", "ab", "ab"]) {
      expect(
        rewriter.buildWhereClause([
          { field: "note", operator: FilterOperator.Equals, value },
        ]),
        JSON.stringify(value),
      ).toBe("");
    }
  });

  it("a refused value in an IN list declines the WHOLE condition", () => {
    // Emitting the other entries would silently WIDEN the filter: `IN ('a')` admits
    // fewer rows than `IN ('a', 'b')`, but a partially-rendered NOT IN admits MORE.
    expect(
      rewriter.buildWhereClause([
        { field: "region", operator: FilterOperator.NotIn, values: ["us", "e\\u"] },
      ]),
    ).toBe("");
  });

  it("a refused BETWEEN bound declines the whole condition", () => {
    expect(
      rewriter.buildWhereClause([
        { field: "code", operator: FilterOperator.Between, values: ["a\\", "z"] },
      ]),
    ).toBe("");
  });

  it("a LIKE pattern with a backslash escape is declined", () => {
    // `like '100\%'` means "literal percent" post-fetch, but the backslash's meaning
    // in a SQL literal is dialect-dependent, so pushing it down could make the two
    // paths disagree. The post pass handles it.
    expect(
      rewriter.buildWhereClause([
        { field: "code", operator: FilterOperator.Like, value: "100\\%" },
      ]),
    ).toBe("");
  });

  it("a plain LIKE pattern passes through with its wildcards intact", () => {
    // The pattern is already SQL LIKE syntax, so `%` and `_` must NOT be escaped.
    expect(
      rewriter.buildWhereClause([
        { field: "region", operator: FilterOperator.Like, value: "us-%" },
      ]),
    ).toBe(`"region" LIKE 'us-%'`);
  });
});

describe("SQL injection: identifiers", () => {
  it("a field name containing a quote is REFUSED, not quoted", () => {
    // Quoting alone relies on the doubling of `"` being correct in every dialect and
    // on the name containing nothing else structural. Validating against a
    // conservative pattern means such a name never reaches the emitted SQL at all.
    const { rw, messages } = withDiagnostics();
    expect(
      rw.buildWhereClause([
        {
          field: 'region"; DROP TABLE patients; --',
          operator: FilterOperator.Equals,
          value: "us",
        },
      ]),
    ).toBe("");
    expect(messages.join("\n")).toContain("not a plain identifier");
  });

  it.each([
    ['a"b', "a bare double quote"],
    ["a`b", "a backtick"],
    ["a b", "a space"],
    ["a-b", "a hyphen"],
    ["a;b", "a semicolon"],
    ["a'b", "a single quote"],
    ["a(b)", "parentheses"],
    ["a\nb", "a newline"],
    ["a b", "a NUL"],
    ["1abc", "a leading digit"],
    ["", "an empty name"],
    ["   ", "whitespace only"],
    ["*", "a wildcard"],
    ["a*", "a trailing wildcard"],
    ["a+b", "a plus"],
    ["a/*b*/", "a comment"],
    ["a--b", "a comment marker"],
  ])("refuses the field name %j (%s)", (field) => {
    expect(
      rewriter.buildWhereClause([
        { field, operator: FilterOperator.Equals, value: "us" },
      ]),
    ).toBe("");
  });

  it("accepts and quotes a plain identifier", () => {
    expect(
      rewriter.buildWhereClause([
        { field: "region_1", operator: FilterOperator.Equals, value: "us" },
      ]),
    ).toBe(`"region_1" = 'us'`);
  });

  it("accepts a non-ASCII letter, which is a legal SQL identifier", () => {
    expect(
      rewriter.buildWhereClause([
        { field: "región", operator: FilterOperator.Equals, value: "us" },
      ]),
    ).toBe(`"región" = 'us'`);
  });

  it("a DOTTED field name is reduced to its leaf, not emitted as a qualifier", () => {
    // TOLAP field matching already treats `patients.region` and `region` as the same
    // field (spec §4), and a qualifier naming the TABLE would not resolve against a
    // query that aliases it (`FROM patients p`). A bare column resolves under either
    // spelling.
    expect(
      rewriter.buildWhereClause([
        { field: "patients.region", operator: FilterOperator.Equals, value: "us" },
      ]),
    ).toBe(`"region" = 'us'`);
  });

  it("a dotted name whose leaf is unsafe is still refused", () => {
    expect(
      rewriter.buildWhereClause([
        { field: 'patients."ev il"', operator: FilterOperator.Equals, value: "us" },
      ]),
    ).toBe("");
  });

  it("a non-string field is refused without throwing", () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(() => rewriter.buildWhereClause([{ field: 42 as any, operator: "equals" }]))
      .not.toThrow();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(rewriter.buildWhereClause([{ field: 42 as any, operator: "equals" }])).toBe(
      "",
    );
  });

  it("an unsafe name in allowedFields cannot reach an expanded SELECT *", () => {
    const result = rewrite(
      "SELECT * FROM patients",
      createPolicy({ allowedFields: ["id", 'ev"il', "name"] }),
    );
    expect(result).toBe('SELECT "id", "name" FROM patients');
    expect(result).not.toContain("ev");
  });
});

// ===========================================================================
// Numeric and temporal literals
// ===========================================================================

describe("literal rendering", () => {
  const clause = (value: unknown) =>
    rewriter.buildWhereClause([
      { field: "n", operator: FilterOperator.Equals, value },
    ]);

  it("renders integers and finite decimals", () => {
    expect(clause(42)).toBe('"n" = 42');
    expect(clause(-7)).toBe('"n" = -7');
    expect(clause(0)).toBe('"n" = 0');
    expect(clause(1.5)).toBe('"n" = 1.5');
    expect(clause(-0.25)).toBe('"n" = -0.25');
  });

  it("renders -0 honestly rather than as 0", () => {
    // `String(-0)` is "0", silently discarding the sign. SQL has no signed zero so
    // the two compare equal there anyway, but the emitted text should be a faithful
    // transcription of what the policy said.
    expect(clause(-0)).toBe('"n" = -0.0');
  });

  it("refuses a number that renders in exponent form", () => {
    // `String(1e21)` is "1e+21", which is not a portable numeric literal, and the
    // value was already imprecise before it arrived.
    for (const value of [1e21, -1e21, 1e-7, 5e-324]) {
      expect(clause(value), String(value)).toBe("");
    }
  });

  it("refuses an integer outside the exactly-representable range", () => {
    expect(clause(2 ** 53)).toBe("");
    expect(clause(-(2 ** 53))).toBe("");
    expect(clause(Number.MAX_SAFE_INTEGER)).toBe('"n" = 9007199254740991');
  });

  it("refuses NaN and the infinities", () => {
    for (const value of [Number.NaN, Infinity, -Infinity]) {
      expect(clause(value), String(value)).toBe("");
    }
  });

  it("renders a bigint exactly", () => {
    expect(clause(123456789012345678901234567890n)).toBe(
      '"n" = 123456789012345678901234567890',
    );
  });

  it("renders booleans as TRUE and FALSE", () => {
    expect(clause(true)).toBe('"n" = TRUE');
    expect(clause(false)).toBe('"n" = FALSE');
  });

  it("renders a Date as a UTC timestamp literal, independent of the host timezone", () => {
    expect(clause(new Date("2026-01-15T09:30:00.000Z"))).toBe(
      `"n" = '2026-01-15 09:30:00.000'`,
    );
  });

  it("refuses an Invalid Date", () => {
    expect(clause(new Date("not-a-date"))).toBe("");
  });

  it("refuses a non-scalar comparand", () => {
    const { rw, messages } = withDiagnostics();
    for (const value of [{ a: 1 }, [1, 2], () => 1, Symbol("s"), new Map()]) {
      expect(
        rw.buildWhereClause([{ field: "n", operator: FilterOperator.Equals, value }]),
        String(value?.toString?.() ?? value),
      ).toBe("");
    }
    expect(messages.join("\n")).toContain("no known SQL literal form");
  });
});

// ===========================================================================
// Every operator, as generated SQL
// ===========================================================================

describe("generated SQL for every operator", () => {
  const c = (filter: RowFilter) => rewriter.buildWhereClause([filter]);

  it("equals / notEquals", () => {
    expect(c({ field: "a", operator: FilterOperator.Equals, value: "x" })).toBe(
      `"a" = 'x'`,
    );
    expect(c({ field: "a", operator: FilterOperator.NotEquals, value: "x" })).toBe(
      `("a" <> 'x' OR "a" IS NULL)`,
    );
  });

  it("greaterThan / greaterThanOrEqual / lessThan / lessThanOrEqual", () => {
    expect(c({ field: "a", operator: FilterOperator.GreaterThan, value: 10 })).toBe(
      '"a" > 10',
    );
    expect(
      c({ field: "a", operator: FilterOperator.GreaterThanOrEqual, value: 10 }),
    ).toBe('"a" >= 10');
    expect(c({ field: "a", operator: FilterOperator.LessThan, value: 10 })).toBe(
      '"a" < 10',
    );
    expect(c({ field: "a", operator: FilterOperator.LessThanOrEqual, value: 10 })).toBe(
      '"a" <= 10',
    );
  });

  it("an ordering comparison against null renders 1 = 0, matching the post pass", () => {
    // `rowPassesFilter` returns false for a null operand, so no row satisfies it.
    // `1 = 0` is the faithful rendering -- restrictive, not neutral.
    expect(c({ field: "a", operator: FilterOperator.GreaterThan, value: null })).toBe(
      "1 = 0",
    );
    expect(c({ field: "a", operator: FilterOperator.LessThanOrEqual })).toBe("1 = 0");
    expect(applyRowFilters([{ a: 5 }], createPolicy({
      rowFilters: [{ field: "a", operator: FilterOperator.GreaterThan, value: null }],
    }))).toEqual([]);
  });

  it("in / notIn", () => {
    expect(c({ field: "a", operator: FilterOperator.In, values: ["x", "y"] })).toBe(
      `"a" IN ('x', 'y')`,
    );
    expect(c({ field: "a", operator: FilterOperator.NotIn, values: ["x"] })).toBe(
      `("a" NOT IN ('x') OR "a" IS NULL)`,
    );
  });

  it("in / notIn degenerate cases mirror the post pass exactly", () => {
    // `in` against nothing matches nothing; `notIn` nothing excludes nothing. Both
    // sides must agree or turning the optimization on changes the result.
    for (const values of [undefined, []] as Array<unknown[] | undefined>) {
      const inFilter: RowFilter = {
        field: "a",
        operator: FilterOperator.In,
        ...(values === undefined ? {} : { values }),
      };
      const notInFilter: RowFilter = {
        field: "a",
        operator: FilterOperator.NotIn,
        ...(values === undefined ? {} : { values }),
      };

      expect(c(inFilter)).toBe("1 = 0");
      expect(c(notInFilter)).toBe("1 = 1");
      // And the post pass agrees.
      expect(
        applyRowFilters([{ a: 1 }], createPolicy({ rowFilters: [inFilter] })),
      ).toEqual([]);
      expect(
        applyRowFilters([{ a: 1 }], createPolicy({ rowFilters: [notInFilter] })),
      ).toHaveLength(1);
    }
  });

  it("like / notLike", () => {
    expect(c({ field: "a", operator: FilterOperator.Like, value: "us-%" })).toBe(
      `"a" LIKE 'us-%'`,
    );
    expect(c({ field: "a", operator: FilterOperator.NotLike, value: "us-%" })).toBe(
      `"a" NOT LIKE 'us-%'`,
    );
  });

  it("a null like/notLike pattern renders 1 = 0", () => {
    expect(c({ field: "a", operator: FilterOperator.Like, value: null })).toBe("1 = 0");
    expect(c({ field: "a", operator: FilterOperator.NotLike })).toBe("1 = 0");
  });

  it("isNull / isNotNull", () => {
    expect(c({ field: "a", operator: FilterOperator.IsNull })).toBe('"a" IS NULL');
    expect(c({ field: "a", operator: FilterOperator.IsNotNull })).toBe(
      '"a" IS NOT NULL',
    );
  });

  it("isNull/isNotNull ignore a stray value", () => {
    expect(
      c({ field: "a", operator: FilterOperator.IsNull, value: "ignored" }),
    ).toBe('"a" IS NULL');
  });

  it("between is inclusive and emits the bounds IN THE ORDER WRITTEN", () => {
    expect(c({ field: "a", operator: FilterOperator.Between, values: [18, 65] })).toBe(
      '"a" BETWEEN 18 AND 65',
    );
    // Inverted: SQL BETWEEN 10 AND 1 matches nothing, exactly as the post pass does.
    // Reordering would turn a typo into a WIDER grant than the policy states.
    expect(c({ field: "a", operator: FilterOperator.Between, values: [10, 1] })).toBe(
      '"a" BETWEEN 10 AND 1',
    );
  });

  it("between ignores extra bounds beyond the first two", () => {
    expect(
      c({ field: "a", operator: FilterOperator.Between, values: [1, 10, 999] }),
    ).toBe('"a" BETWEEN 1 AND 10');
  });

  it("a null between bound renders 1 = 0", () => {
    expect(
      c({ field: "a", operator: FilterOperator.Between, values: [null, 10] }),
    ).toBe("1 = 0");
    expect(
      c({ field: "a", operator: FilterOperator.Between, values: [1, null] }),
    ).toBe("1 = 0");
  });

  it("between over strings and Dates", () => {
    expect(
      c({ field: "a", operator: FilterOperator.Between, values: ["a", "z"] }),
    ).toBe(`"a" BETWEEN 'a' AND 'z'`);
    expect(
      c({
        field: "a",
        operator: FilterOperator.Between,
        values: [new Date("2026-01-01T00:00:00Z"), new Date("2026-12-31T00:00:00Z")],
      }),
    ).toBe(`"a" BETWEEN '2026-01-01 00:00:00.000' AND '2026-12-31 00:00:00.000'`);
  });

  it("contains / startsWith / matches are declined, with a reason", () => {
    const { rw, messages } = withDiagnostics();
    for (const operator of [
      FilterOperator.Contains,
      FilterOperator.StartsWith,
      FilterOperator.Matches,
    ]) {
      expect(rw.buildWhereClause([{ field: "a", operator, value: "x" }])).toBe("");
    }
    expect(messages.join("\n")).toContain("no portable SQL form");
  });

  it("an unrecognized operator is declined, with a reason", () => {
    const { rw, messages } = withDiagnostics();
    expect(rw.buildWhereClause([{ field: "a", operator: "gte", value: 1 }])).toBe("");
    expect(messages.join("\n")).toContain("unrecognized operator");
  });
});

// ===========================================================================
// LIMIT clamping
// ===========================================================================

describe("LIMIT clamping", () => {
  it("does nothing when the policy sets no maxResults", () => {
    const query = "SELECT id FROM patients LIMIT 10";
    expect(rewrite(query, createPolicy())).toBe(query);
  });

  it("maxResults of 0 emits LIMIT 0", () => {
    // Zero means "no rows", which is a real restriction and must not be read as
    // "unset" -- the same null-vs-empty distinction as spec §3.
    expect(rewrite("SELECT id FROM patients", createPolicy({ maxResults: 0 }))).toBe(
      "SELECT id FROM patients LIMIT 0",
    );
    expect(
      rewrite("SELECT id FROM patients LIMIT 100", createPolicy({ maxResults: 0 })),
    ).toBe("SELECT id FROM patients LIMIT 0");
  });

  it("declines a negative or non-integer maxResults rather than emitting nonsense", () => {
    // `LIMIT -1` is a syntax error in Postgres and unbounded in some engines, so
    // guessing would either break the query or lift the cap. applyResultLimit still
    // truncates the result.
    for (const maxResults of [-1, 1.5, Number.NaN]) {
      const query = "SELECT id FROM patients";
      const { rw, messages } = withDiagnostics();
      expect(rw.rewriteQuery(query, createPolicy({ maxResults })).query).toBe(query);
      expect(messages.join("\n")).toContain("not a non-negative integer");
    }
  });

  it("the policy limit wins over an existing LIMIT too large to parse exactly", () => {
    const result = rewrite(
      "SELECT id FROM patients LIMIT 99999999999999999999",
      createPolicy({ maxResults: 500 }),
    );
    expect(result).toBe("SELECT id FROM patients LIMIT 500");
  });

  it("is case-insensitive about the keyword", () => {
    expect(
      rewrite("select id from patients limit 10000", createPolicy({ maxResults: 500 })),
    ).toBe("select id from patients limit 500".replace("limit 500", "LIMIT 500"));
  });

  it("preserves an OFFSET that follows the LIMIT", () => {
    expect(
      rewrite("SELECT id FROM patients LIMIT 10000 OFFSET 20", createPolicy({ maxResults: 500 })),
    ).toBe("SELECT id FROM patients LIMIT 500 OFFSET 20");
  });

  it("appends after an ORDER BY rather than before it", () => {
    expect(
      rewrite("SELECT id FROM patients ORDER BY name", createPolicy({ maxResults: 5 })),
    ).toBe("SELECT id FROM patients ORDER BY name LIMIT 5");
  });
});

// ===========================================================================
// validateQuery field extraction
// ===========================================================================

describe("validateQuery field extraction", () => {
  const hidesSsn = createPolicy({ hiddenFields: ["ssn"] });

  it("extracts from the SELECT list", () => {
    expect(rewriter.validateQuery("SELECT ssn FROM patients", hidesSsn)).toBe(false);
  });

  it("extracts from the WHERE clause", () => {
    expect(
      rewriter.validateQuery("SELECT id FROM patients WHERE ssn = '1'", hidesSsn),
    ).toBe(false);
  });

  it("extracts from a table-qualified WHERE reference", () => {
    expect(
      rewriter.validateQuery("SELECT id FROM patients p WHERE p.ssn = '1'", hidesSsn),
    ).toBe(false);
  });

  it("extracts from a QUOTED qualified WHERE reference", () => {
    expect(
      rewriter.validateQuery('SELECT id FROM patients WHERE "p"."ssn" = \'1\'', hidesSsn),
    ).toBe(false);
  });

  it("extracts from ORDER BY", () => {
    expect(
      rewriter.validateQuery("SELECT id FROM patients ORDER BY ssn", hidesSsn),
    ).toBe(false);
  });

  it("extracts from ORDER BY with ASC/DESC and NULLS suffixes", () => {
    for (const suffix of ["ASC", "DESC", "DESC NULLS LAST", "ASC NULLS FIRST"]) {
      expect(
        rewriter.validateQuery(`SELECT id FROM patients ORDER BY ssn ${suffix}`, hidesSsn),
        suffix,
      ).toBe(false);
    }
  });

  it("extracts from GROUP BY", () => {
    expect(
      rewriter.validateQuery("SELECT count(*) FROM patients GROUP BY ssn", hidesSsn),
    ).toBe(false);
  });

  it("extracts from HAVING", () => {
    expect(
      rewriter.validateQuery(
        "SELECT region FROM patients GROUP BY region HAVING ssn = '1'",
        hidesSsn,
      ),
    ).toBe(false);
  });

  it("extracts from an aliased SELECT entry", () => {
    expect(
      rewriter.validateQuery("SELECT ssn AS s FROM patients", hidesSsn),
    ).toBe(false);
    // Lowercase `as` too.
    expect(
      rewriter.validateQuery("SELECT ssn as s FROM patients", hidesSsn),
    ).toBe(false);
  });

  it("does not confuse an ALIAS for the field it aliases", () => {
    // The alias `ssn` names the output column, but the field read is `name`. The
    // extractor takes the left side of AS, which is the field that is actually read.
    expect(
      rewriter.validateQuery("SELECT name AS ssn FROM patients", hidesSsn),
    ).toBe(true);
  });

  it("SQL keywords are never mistaken for field names", () => {
    // Without the keyword denylist, `NOT`, `IS`, and `NULL` are all `\w+` tokens
    // sitting left of a comparison operator.
    expect(
      rewriter.validateQuery(
        "SELECT id FROM patients WHERE id IS NOT NULL AND status = 'a'",
        createPolicy({ allowedFields: ["id", "status"] }),
      ),
    ).toBe(true);
  });

  it("a wildcard SELECT * passes an allow-list check", () => {
    // `*` discloses nothing by itself: rewriteSelectList narrows it and the post
    // pass projects. Rejecting it would deny the single most common agent query.
    expect(
      rewriter.validateQuery(
        "SELECT * FROM patients",
        createPolicy({ allowedFields: ["id"] }),
      ),
    ).toBe(true);
  });

  it("but a hidden field is still caught in a SELECT * query's WHERE", () => {
    expect(
      rewriter.validateQuery("SELECT * FROM patients WHERE ssn = '1'", hidesSsn),
    ).toBe(false);
  });

  it("is true with no field rules at all", () => {
    expect(
      rewriter.validateQuery("SELECT anything FROM patients", createPolicy()),
    ).toBe(true);
  });

  it("an EMPTY allowedFields denies every field (spec §3)", () => {
    // Tested for undefined, not emptiness: `[]` is the most restrictive possible
    // allow-list and must not be read as "no restriction".
    expect(
      rewriter.validateQuery(
        "SELECT id FROM patients",
        createPolicy({ allowedFields: [] }),
      ),
    ).toBe(false);
  });

  it("hidden takes precedence over allowed", () => {
    expect(
      rewriter.validateQuery(
        "SELECT ssn FROM patients",
        createPolicy({ allowedFields: ["ssn"], hiddenFields: ["ssn"] }),
      ),
    ).toBe(false);
  });

  it("field matching is case-insensitive and bidirectional (spec §4)", () => {
    expect(rewriter.validateQuery("SELECT SSN FROM patients", hidesSsn)).toBe(false);
    expect(
      rewriter.validateQuery(
        "SELECT ssn FROM patients",
        createPolicy({ hiddenFields: ["patients.ssn"] }),
      ),
    ).toBe(false);
    expect(
      rewriter.validateQuery("SELECT p.ssn FROM patients p", hidesSsn),
    ).toBe(false);
  });

  it("honours a glob in hiddenFields", () => {
    expect(
      rewriter.validateQuery(
        "SELECT ssn_last4 FROM patients",
        createPolicy({ hiddenFields: ["ssn*"] }),
      ),
    ).toBe(false);
  });

  it("refuses a query too long to parse rather than passing it", () => {
    // A query that cannot be validated cannot be shown to reference only allowed
    // fields, so it is refused.
    const { rw, messages } = withDiagnostics();
    expect(
      rw.validateQuery(`SELECT ${"x".repeat(MAX_QUERY_LENGTH)} FROM t`, hidesSsn),
    ).toBe(false);
    expect(messages.join("\n")).toContain("cannot be validated");
  });

  it("does not throw on a query with no SELECT or FROM", () => {
    expect(() => rewriter.validateQuery("SHOW TABLES", hidesSsn)).not.toThrow();
    expect(() => rewriter.validateQuery("SELECT 1", hidesSsn)).not.toThrow();
    expect(() => rewriter.validateQuery("garbage ((( ", hidesSsn)).not.toThrow();
  });
});

// ===========================================================================
// .NET-to-JS regex translation
// ===========================================================================

describe("regex translation from the .NET reference", () => {
  it("the negative lookbehind keeps a qualified reference from yielding a bare name", () => {
    // Prism's `(?<![."'`\w])` -- Node 22 (V8) supports lookbehind natively, so this
    // translates directly. `p.region` must yield `region` ONLY through the qualified
    // pattern, not also as a bare token, or the two would disagree about which name
    // was seen.
    const allowsRegionOnly = createPolicy({ allowedFields: ["region"] });
    expect(
      rewriter.validateQuery("SELECT id FROM t WHERE p.region = 'us'", allowsRegionOnly),
    ).toBe(false); // `id` is not allowed
    expect(
      rewriter.validateQuery("SELECT region FROM t WHERE p.region = 'us'", allowsRegionOnly),
    ).toBe(true);
  });

  it("the lookbehind excludes a name preceded by a quote", () => {
    // The `'` and `"` in the lookbehind class stop a literal's or an identifier's
    // interior from being read as a bare column name.
    expect(
      rewriter.validateQuery(
        "SELECT id FROM t WHERE note = 'ssn=1'",
        createPolicy({ hiddenFields: ["ssn"], allowedFields: ["id", "note"] }),
      ),
    ).toBe(true);
  });

  it("RegexOptions.Singleline maps to [\\s\\S], so a clause spans newlines", () => {
    // .NET's Singleline makes `.` match `\n`. JS `s` does the same for `.`, but the
    // clause-body patterns use `[\s\S]` explicitly so the behavior does not depend
    // on a flag being carried through.
    expect(
      rewriter.validateQuery("SELECT id\nFROM patients\nWHERE ssn = '1'", createPolicy({ hiddenFields: ["ssn"] })),
    ).toBe(false);
  });

  it("IgnoreCase maps to the i flag on every keyword pattern", () => {
    const policy = createPolicy({
      rowFilters: [{ field: "s", operator: FilterOperator.Equals, value: "a" }],
      maxResults: 5,
    });
    for (const query of [
      "select id from patients",
      "SELECT id FROM patients",
      "Select Id From Patients",
    ]) {
      const result = rewrite(query, policy);
      expect(result, query).toContain("WHERE");
      expect(result).toContain("LIMIT 5");
    }
  });

  it("a global pattern does not leak lastIndex between calls", () => {
    // Module-level global regexes are shared. Reusing one without cloning makes a
    // result depend on call order -- the kind of bug that only shows up in the
    // second test to run.
    const policy = createPolicy({
      rowFilters: [{ field: "s", operator: FilterOperator.Equals, value: "a" }],
    });
    const expected = `SELECT id FROM patients WHERE "s" = 'a'`;
    for (let i = 0; i < 5; i++) {
      expect(rewrite("SELECT id FROM patients", policy)).toBe(expected);
    }
  });

  it("bounds the input as a ReDoS guard, since JS has no regex timeout", () => {
    // Consistent with how enforcement.ts guards `matches`: bound the work rather
    // than hope. Over-long input is declined (and reported) rather than scanned.
    const huge = "SELECT " + "a,".repeat(MAX_QUERY_LENGTH) + "b FROM t";
    const start = Date.now();
    const result = rewriter.rewriteQuery(huge, createPolicy({ maxResults: 5 }));
    expect(Date.now() - start).toBeLessThan(1000);
    expect(result.query).toBe(huge);
  });
});

// ===========================================================================
// The rewriter never widens
// ===========================================================================

describe("the rewriter narrows or leaves alone, never widens", () => {
  it("a policy with no rules leaves every query byte-identical", () => {
    const policy = createPolicy();
    for (const query of [
      "SELECT id FROM patients",
      "SELECT * FROM patients WHERE a = 1 ORDER BY b LIMIT 10",
      "SELECT a, b FROM t JOIN u ON t.id = u.id GROUP BY a HAVING count(*) > 1",
      "WITH x AS (SELECT 1) SELECT * FROM x",
      "SHOW TABLES",
    ]) {
      expect(rewriter.rewriteQuery(query, policy).query, query).toBe(query);
    }
  });

  it("declines a CTE rather than mangling it", () => {
    // A `WITH` clause puts a SELECT before the statement's own; the scanner finds
    // the first top-level SELECT, which belongs to the CTE. Rather than rewrite the
    // wrong projection, the outcome must at minimum stay valid and never widen.
    const query = "WITH recent AS (SELECT id FROM encounters) SELECT id, ssn FROM patients";
    const result = rewrite(query, createPolicy({ hiddenFields: ["ssn"] }));
    // Whatever it does, the hidden column must not survive as a projected field --
    // and if the rewriter cannot be sure, validateQuery has already refused the
    // query outright.
    expect(rewriter.validateQuery(query, createPolicy({ hiddenFields: ["ssn"] }))).toBe(
      false,
    );
    expect(typeof result).toBe("string");
  });

  it("never throws for any malformed input", () => {
    const policy = createPolicy({
      allowedFields: ["id"],
      hiddenFields: ["ssn"],
      rowFilters: [{ field: "region", operator: FilterOperator.Equals, value: "us" }],
      maxResults: 10,
    });

    for (const query of [
      "",
      "   ",
      "SELECT",
      "SELECT FROM",
      "FROM patients",
      "SELECT ((((",
      "SELECT ''''",
      'SELECT """"',
      "SELECT * FROM",
      ";;;",
      "SELECT 'unterminated",
      'SELECT "unterminated',
      "SELECT * FROM t WHERE",
      " ",
    ]) {
      expect(() => rewriter.rewriteQuery(query, policy), JSON.stringify(query)).not.toThrow();
      expect(() => rewriter.validateQuery(query, policy)).not.toThrow();
      expect(() => rewriter.extractTableName(query)).not.toThrow();
    }
  });

  it("extractTableName handles the odd shapes without throwing", () => {
    expect(rewriter.extractTableName("")).toBeUndefined();
    expect(rewriter.extractTableName("   ")).toBeUndefined();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(rewriter.extractTableName(null as any)).toBeUndefined();
    expect(rewriter.extractTableName("x".repeat(MAX_QUERY_LENGTH + 1))).toBeUndefined();
    expect(rewriter.extractTableName("SELECT * FROM a.b.c")).toBe("c");
    expect(rewriter.extractTableName('SELECT * FROM "a"."b"."c"')).toBe("c");
  });
});

// ===========================================================================
// Structural edge cases
// ===========================================================================

describe("structural edge cases", () => {
  it("deduplicates allowedFields that share a leaf when expanding SELECT *", () => {
    // `patients.region` and `region` are the same field (spec §4), so emitting both
    // would produce `SELECT "region", "region"` -- valid but duplicated, and a
    // duplicate column name breaks some drivers' row-to-object mapping.
    expect(
      rewrite(
        "SELECT * FROM patients",
        createPolicy({ allowedFields: ["id", "patients.region", "region", "REGION"] }),
      ),
    ).toBe('SELECT "id", "region" FROM patients');
  });

  it("leaves an explicit SELECT byte-identical when nothing was removed", () => {
    // Returning the original rather than a reassembled list means an entry's own
    // spacing survives, so a rewrite that changes nothing changes nothing.
    const query = "SELECT  id ,   name  FROM patients";
    expect(
      rewrite(query, createPolicy({ allowedFields: ["id", "name"] })),
    ).toBe(query);
  });

  it("declines notEquals entirely when the value cannot be rendered", () => {
    // The IS NULL arm must not be emitted around a condition that was never built:
    // `( OR "a" IS NULL)` is both invalid and, if it parsed, a widening.
    expect(
      rewriter.buildWhereClause([
        { field: "a", operator: FilterOperator.NotEquals, value: "back\\slash" },
      ]),
    ).toBe("");
  });

  it("names a class instance's constructor in the decline message", () => {
    const { rw, messages } = withDiagnostics();
    class CustomType {}
    rw.buildWhereClause([
      { field: "a", operator: FilterOperator.Equals, value: new CustomType() },
    ]);
    expect(messages.join("\n")).toContain("CustomType");
  });

  it("names a prototype-less bag as an object", () => {
    const { rw, messages } = withDiagnostics();
    rw.buildWhereClause([
      {
        field: "a",
        operator: FilterOperator.Equals,
        value: Object.create(null) as object,
      },
    ]);
    expect(messages.join("\n")).toContain("no known SQL literal form");
  });

  it("an empty field token in a clause is skipped, not recorded", () => {
    // A quoted-empty entry trims to "", which must not become a field named "".
    expect(() =>
      rewriter.validateQuery(
        `SELECT '' FROM patients ORDER BY ''`,
        createPolicy({ allowedFields: ["id"] }),
      ),
    ).not.toThrow();
  });

  it("a trailing comma in ORDER BY or GROUP BY does not create an empty field", () => {
    for (const query of [
      "SELECT id FROM patients ORDER BY name, ",
      "SELECT id FROM patients GROUP BY region, ",
    ]) {
      expect(() =>
        rewriter.validateQuery(query, createPolicy({ hiddenFields: ["ssn"] })),
        query,
      ).not.toThrow();
      // The real fields are still seen.
      expect(
        rewriter.validateQuery(query, createPolicy({ hiddenFields: ["name", "region"] })),
      ).toBe(false);
    }
  });

  it("splits a select list on top-level commas only", () => {
    // A function call's own arguments must not be split apart, or `round(price, 2)`
    // becomes two entries and the second is read as a field named "2)".
    expect(
      rewrite(
        "SELECT id, round(price, 2), ssn FROM patients",
        createPolicy({ hiddenFields: ["ssn"] }),
      ),
    ).toBe("SELECT id, round(price, 2) FROM patients");
  });

  it("handles a single-entry select list with no comma at all", () => {
    expect(
      rewrite("SELECT ssn FROM patients", createPolicy({ hiddenFields: ["ssn"] })),
    ).toBe("SELECT 1 FROM patients");
  });

  it("a select list ending in a comma does not produce a phantom entry", () => {
    expect(() =>
      rewrite("SELECT id, FROM patients", createPolicy({ hiddenFields: ["ssn"] })),
    ).not.toThrow();
  });
});

// ===========================================================================
// The documented footgun
// ===========================================================================

describe("footgun: a pushed-down filter on an unprojected field returns zero rows", () => {
  it("the DB filters correctly, then the post pass drops everything", () => {
    // Not a security bug -- it fails CLOSED -- but it is surprising, so it is pinned.
    // The query projects only `id`, so the returned rows have no `region` key, and
    // spec §7 drops a row whose filtered field is ABSENT. The result is empty even
    // though the database returned the right rows.
    const policy = createPolicy({
      rowFilters: [
        { field: "region", operator: FilterOperator.Equals, value: "us-east" },
      ],
    });

    const rewritten = rewrite("SELECT id FROM patients", policy);
    expect(rewritten).toBe(`SELECT id FROM patients WHERE "region" = 'us-east'`);

    // What the DB would return for that query: correctly filtered, but with no
    // region column.
    const fromDatabase = [{ id: 1 }, { id: 3 }];
    expect(applyRowFilters(fromDatabase, policy)).toEqual([]);

    // Projecting the filtered field fixes it.
    expect(
      applyRowFilters([{ id: 1, region: "us-east" }], policy),
    ).toHaveLength(1);
  });

  it("a filter on a HIDDEN field still works, as long as the tool RETURNS the field", () => {
    // Spec §4 says "A hidden field cannot be projected, so the post pass has no
    // value to test and fails closed." That is only half right, and the pipeline
    // order is why: row filters are step 1 and hidden-field removal is step 5, so
    // the filter sees the value BEFORE it is stripped. A `SELECT *` whose result
    // carries the hidden column filters correctly and then hides it.
    const policy = createPolicy({
      hiddenFields: ["region"],
      rowFilters: [
        { field: "region", operator: FilterOperator.Equals, value: "us-east" },
      ],
    });

    // The filter reaches the database...
    expect(rewriter.buildWhereClause(policy.objectRules!.rowFilters!)).toContain(
      '"region" = \'us-east\'',
    );

    // ...and the post pass ALSO enforces it, then removes the column.
    expect(
      applyResultPipeline(
        [
          { id: 1, region: "us-east" },
          { id: 2, region: "eu-west" },
        ],
        policy,
      ),
    ).toEqual([{ id: 1 }]);
  });

  it("but it fails closed once the projection omits the hidden field", () => {
    // This is the case spec §4 is really describing, and it is the same footgun as
    // above: the rewriter cannot ADD `region` to the projection (it is hidden), so a
    // query selecting only `id` yields rows with no `region` key and step 1 drops
    // every one. Fail-closed, and unavoidable -- which is why such a policy must not
    // rely on rewriting alone.
    const policy = createPolicy({
      hiddenFields: ["region"],
      rowFilters: [
        { field: "region", operator: FilterOperator.Equals, value: "us-east" },
      ],
    });

    expect(applyResultPipeline([{ id: 1 }, { id: 2 }], policy)).toEqual([]);
  });
});

// ===========================================================================
// Dialect profiles (connector spec §5.1)
// ===========================================================================

/** The `region = 'US'` filter these blocks push, in every profile. */
const US_FILTER: RowFilter = {
  field: "region",
  operator: FilterOperator.Equals,
  value: "US",
};

describe("dialect profiles", () => {
  /**
   * The bug these fix was measured, not theorised: the rewriter emitted
   * Postgres-style `WHERE "region" = 'us-east'` for every engine, and MySQL without
   * ANSI_QUOTES reads `"region"` as a *string literal*, so it evaluated
   * `'region' = 'us-east'` — false for every row, with no error reported. Against the
   * six-row integration fixture the policy-filtered query returned 0 rows where
   * backticks return 2.
   */
  it.each([
    [SqlDialect.Ansi, '"region"'],
    [SqlDialect.Postgres, '"region"'],
    [SqlDialect.Trino, '"region"'],
    [SqlDialect.MySql, "`region`"],
    [SqlDialect.SqlServer, "[region]"],
  ])("quotes identifiers the %s way", (dialect, expected) => {
    const result = rewrite2("SELECT a FROM t", createPolicy({ rowFilters: [US_FILTER] }), dialect);

    expect(result).toBe(`SELECT a FROM t WHERE ${expected} = 'US'`);
  });

  it.each([
    [SqlDialect.Ansi, `SELECT a FROM t WHERE "region" = 'US' LIMIT 10`],
    [SqlDialect.Postgres, `SELECT a FROM t WHERE "region" = 'US' LIMIT 10`],
    [SqlDialect.Trino, `SELECT a FROM t WHERE "region" = 'US' LIMIT 10`],
    [SqlDialect.MySql, "SELECT a FROM t WHERE `region` = 'US' LIMIT 10"],
    [SqlDialect.SqlServer, "SELECT TOP 10 a FROM t WHERE [region] = 'US'"],
  ])("spells the row limit the %s way", (dialect, expected) => {
    const result = rewrite2(
      "SELECT a FROM t",
      createPolicy({ rowFilters: [US_FILTER], maxResults: 10 }),
      dialect,
    );

    expect(result).toBe(expected);
  });

  it("selects ansi when the dialect is omitted", () => {
    // Not a guess at the engine -- the subset most engines accept.
    expect(DEFAULT_DIALECT).toBe(SqlDialect.Ansi);

    const policy = createPolicy({ rowFilters: [US_FILTER], maxResults: 10 });

    expect(rewrite("SELECT a FROM t", policy)).toBe(
      rewrite2("SELECT a FROM t", policy, SqlDialect.Ansi),
    );
  });

  it("accepts a dialect named by its string form", () => {
    // So an integrator can plumb a config value straight through.
    const result = rewrite2("SELECT a FROM t", createPolicy({ rowFilters: [US_FILTER] }), "mysql");

    expect(result).toBe("SELECT a FROM t WHERE `region` = 'US'");
  });

  it("takes the dialect from the constructor when no per-call one is given", () => {
    const rw = new SqlQueryRewriter({ dialect: SqlDialect.MySql });

    const result = rw.rewriteQuery(
      "SELECT a FROM t",
      createPolicy({ rowFilters: [US_FILTER] }),
    ).query;

    expect(result).toBe("SELECT a FROM t WHERE `region` = 'US'");
  });

  it("lets a per-call dialect override the constructor's", () => {
    const rw = new SqlQueryRewriter({ dialect: SqlDialect.MySql });

    const result = rw.rewriteQuery(
      "SELECT a FROM t",
      createPolicy({ rowFilters: [US_FILTER] }),
      SqlDialect.SqlServer,
    ).query;

    expect(result).toBe("SELECT a FROM t WHERE [region] = 'US'");
  });

  it("quotes an expanded SELECT * for the profile", () => {
    const result = rewrite2(
      "SELECT * FROM patients",
      createPolicy({ allowedFields: ["id", "region"], hiddenFields: ["ssn"] }),
      SqlDialect.MySql,
    );

    expect(result).toBe("SELECT `id`, `region` FROM patients");
  });
});

describe("an unrecognized dialect declines entirely", () => {
  /**
   * Rule 2. Guessing a profile is how the MySQL backtick defect happened. Throwing
   * would turn a deployment typo into an outage on a path that is only ever an
   * optimization, so the query is returned untouched and the post pass — which was
   * always the enforcement boundary (spec §4) — does the whole job.
   */
  it("rewrites nothing", () => {
    const query = "SELECT a FROM t";

    const result = rewrite2(
      query,
      createPolicy({ rowFilters: [US_FILTER], maxResults: 10 }),
      "oracle",
    );

    expect(result).toBe(query);
  });

  it("builds no WHERE clause", () => {
    expect(rewriter.buildWhereClause([US_FILTER], "oracle")).toBe("");
  });

  it("reports every filter as unpushable", () => {
    const filters: RowFilter[] = [
      US_FILTER,
      { field: "status", operator: FilterOperator.NotEquals, value: "deleted" },
    ];
    const policy = createPolicy({ rowFilters: filters });

    expect(rewriter.unpushableFilters(policy, "oracle")).toEqual(filters);
    // ...where a recognized profile pushes both.
    expect(rewriter.unpushableFilters(policy, SqlDialect.MySql)).toEqual([]);
  });

  it("reports every filter from rewriteQuery too", () => {
    const policy = createPolicy({ rowFilters: [US_FILTER] });

    const result = rewriter.rewriteQuery("SELECT a FROM t", policy, "oracle");

    expect(result.rewritten).toBe(false);
    expect(result.unpushableFilters).toEqual([US_FILTER]);
  });

  it("does not throw", () => {
    expect(() =>
      rewriter.rewriteQuery(
        "SELECT a FROM t",
        createPolicy({ rowFilters: [US_FILTER] }),
        "nonsense",
      ),
    ).not.toThrow();
  });

  it("explains itself through diagnostics", () => {
    const { rw, messages } = withDiagnostics();

    rw.rewriteQuery("SELECT a FROM t", createPolicy({ rowFilters: [US_FILTER] }), "oracle");

    expect(messages.some((m) => m.includes("unrecognized SQL dialect 'oracle'"))).toBe(true);
  });

  it("still enforces the declined filters after the fetch", () => {
    // The whole reason declining is safe: rewriting was only ever an optimization,
    // so the rows a caller ends up with are still correct.
    const policy = createPolicy({ rowFilters: [US_FILTER] });

    const result = rewriter.rewriteQuery("SELECT id, region FROM t", policy, "oracle");
    expect(result.query).toBe("SELECT id, region FROM t");

    const rows = [
      { id: 1, region: "US" },
      { id: 2, region: "EU" },
      { id: 3, region: "US" },
    ];

    expect(applyResultPipeline(rows, policy)).toEqual([
      { id: 1, region: "US" },
      { id: 3, region: "US" },
    ]);
  });
});

describe("an identifier carrying the profile's own quote is declined", () => {
  /**
   * Rule 4: declined, never escaped by doubling. Declining costs an optimization;
   * mis-escaping emits author-controlled text into the statement, and the doubling
   * rule is not even the same in every engine.
   */
  it.each([
    [SqlDialect.Ansi, 'reg"ion'],
    [SqlDialect.Postgres, 'reg"ion'],
    [SqlDialect.Trino, 'reg"ion'],
    [SqlDialect.MySql, "reg`ion"],
    [SqlDialect.SqlServer, "reg[ion"],
    [SqlDialect.SqlServer, "reg]ion"],
  ])("declines %s field %s", (dialect, field) => {
    const policy = createPolicy({
      rowFilters: [{ field, operator: FilterOperator.Equals, value: "x" }],
    });

    const result = rewriter.rewriteQuery("SELECT a FROM t", policy, dialect);

    expect(result.query).toBe("SELECT a FROM t");
    expect(result.query).not.toContain("WHERE");
    expect(result.unpushableFilters).toHaveLength(1);
  });

  it("emits no doubled quote anywhere", () => {
    const policy = createPolicy({
      rowFilters: [{ field: 'reg"ion', operator: FilterOperator.Equals, value: "x" }],
    });

    const result = rewrite2("SELECT a FROM t", policy, SqlDialect.Ansi);

    expect(result).not.toContain('""');
  });

  it("still unwraps a wrapping quote and accepts the name", () => {
    // The delimiters a policy wrote *around* a name are not part of it. Only a quote
    // character surviving *inside* the name is a decline.
    const policy = createPolicy({
      rowFilters: [{ field: "[region]", operator: FilterOperator.Equals, value: "x" }],
    });

    expect(rewrite2("SELECT a FROM t", policy, SqlDialect.SqlServer)).toBe(
      "SELECT a FROM t WHERE [region] = 'x'",
    );
    expect(rewrite2("SELECT a FROM t", policy, SqlDialect.MySql)).toBe(
      "SELECT a FROM t WHERE `region` = 'x'",
    );
  });
});

describe("a backslash value is refused under every profile", () => {
  /**
   * Rule 5: uniform, so a policy behaves identically across engines. MySQL treats
   * `\` as a string escape by default and Postgres does not, so the same text would
   * mean different things in the two engines. Refusing everywhere keeps a filter
   * unpushable on one engine unpushable on all of them — and one profile treating `\`
   * as an escape is enough to make escaping unsafe to generalize.
   */
  const EVERY_PROFILE = [
    SqlDialect.Ansi,
    SqlDialect.Postgres,
    SqlDialect.Trino,
    SqlDialect.MySql,
    SqlDialect.SqlServer,
  ];

  it.each(EVERY_PROFILE)("refuses a backslash under %s", (dialect) => {
    const policy = createPolicy({
      rowFilters: [
        { field: "region", operator: FilterOperator.Equals, value: "us-east\\' OR 1=1 --" },
      ],
    });

    const result = rewriter.rewriteQuery("SELECT a FROM t", policy, dialect);

    expect(result.query).toBe("SELECT a FROM t");
    expect(result.query).not.toContain("\\");
    expect(result.unpushableFilters).toHaveLength(1);
  });

  it.each(EVERY_PROFILE)("refuses a control character under %s", (dialect) => {
    const policy = createPolicy({
      rowFilters: [
        { field: "region", operator: FilterOperator.Equals, value: "us east" },
      ],
    });

    const result = rewriter.rewriteQuery("SELECT a FROM t", policy, dialect);

    expect(result.query).toBe("SELECT a FROM t");
    expect(result.unpushableFilters).toHaveLength(1);
  });

  it.each(EVERY_PROFILE)("still doubles a plain single quote under %s", (dialect) => {
    // The refusal is specific to backslashes and control characters. Ordinary ANSI
    // quote doubling is correct in every profile and stays.
    const policy = createPolicy({
      rowFilters: [{ field: "region", operator: FilterOperator.Equals, value: "it's" }],
    });

    const result = rewriter.rewriteQuery("SELECT a FROM t", policy, dialect);

    expect(result.query).toContain("'it''s'");
    expect(result.unpushableFilters).toHaveLength(0);
  });
});

describe("sqlserver TOP placement", () => {
  /**
   * Rule 3: a profile is never approximated. `TOP n` goes after SELECT (and after
   * DISTINCT/ALL), not at the end, so this is a structural placement rather than a
   * token swap. Where it cannot be placed correctly the limit is simply **not
   * pushed** — never rendered as `LIMIT n` instead. An unpushed limit costs a
   * transfer that `applyResultLimit` trims; a misplaced one is a broken statement or
   * a wrong row count.
   */
  const ss = (query: string, maxResults = 10): string =>
    rewrite2(query, createPolicy({ maxResults }), SqlDialect.SqlServer);

  it("places TOP after SELECT, not at the end", () => {
    expect(ss("SELECT a FROM t")).toBe("SELECT TOP 10 a FROM t");
    expect(ss("SELECT a FROM t")).not.toContain("LIMIT");
  });

  it("places TOP after DISTINCT", () => {
    // `SELECT DISTINCT TOP 5` is a syntax error, and `SELECT TOP 5 DISTINCT` would
    // count rows before duplicates are removed.
    expect(ss("SELECT DISTINCT a FROM t")).toBe("SELECT DISTINCT TOP 10 a FROM t");
  });

  it("places TOP after ALL", () => {
    expect(ss("SELECT ALL a FROM t")).toBe("SELECT ALL TOP 10 a FROM t");
  });

  it("clamps an existing larger TOP", () => {
    expect(ss("SELECT TOP 50 a FROM t")).toBe("SELECT TOP 10 a FROM t");
  });

  it("keeps an existing smaller TOP", () => {
    expect(ss("SELECT TOP 3 a FROM t")).toBe("SELECT TOP 3 a FROM t");
  });

  it("clamps the parenthesised TOP form", () => {
    expect(ss("SELECT TOP (50) a FROM t")).toBe("SELECT TOP 10 a FROM t");
  });

  it.each([
    // A TOP on the first operand limits that operand, not the union, so the caller
    // would receive MORE rows than the policy allows.
    "SELECT a FROM t UNION SELECT b FROM u",
    "SELECT a FROM t INTERSECT SELECT b FROM u",
    "SELECT a FROM t EXCEPT SELECT b FROM u",
    // T-SQL forbids TOP alongside OFFSET ... FETCH.
    "SELECT a FROM t ORDER BY a OFFSET 5 ROWS",
    "SELECT a FROM t ORDER BY a FETCH FIRST 5 ROWS ONLY",
    // A percentage is not a row count; WITH TIES returns more rows than given.
    "SELECT TOP 5 PERCENT a FROM t",
    "SELECT TOP 5 WITH TIES a FROM t ORDER BY a",
    // Already not valid T-SQL; clamping around a clause this profile does not emit
    // would be guessing at what the caller meant.
    "SELECT a FROM t LIMIT 50",
  ])("declines rather than approximating for %s", (query) => {
    const result = ss(query);

    expect(result).toBe(query);
    expect(result).not.toContain("TOP 10");
    expect(result).not.toContain("LIMIT 10");
  });

  it("still enforces a declined limit after the fetch", () => {
    // The limit not reaching the statement costs transfer, not correctness.
    const policy = createPolicy({ maxResults: 2 });
    const query = "SELECT a FROM t UNION SELECT b FROM u";

    expect(rewrite2(query, policy, SqlDialect.SqlServer)).toBe(query);
    expect(applyResultPipeline([{ a: 1 }, { a: 2 }, { a: 3 }, { a: 4 }], policy)).toEqual([
      { a: 1 },
      { a: 2 },
    ]);
  });

  it.each(["DELETE FROM t", "UPDATE t SET a = 1"])(
    "declines a statement with no top-level SELECT: %s",
    (query) => {
      // There is nowhere to place a TOP. A non-SELECT statement should not reach a
      // read-path rewriter at all -- `readOnly` blocks it earlier (connector spec §4)
      // -- but if one does, it is returned untouched rather than mangled.
      expect(ss(query)).toBe(query);
    },
  );

  it("still pushes a row filter when the limit is declined", () => {
    // The two pushdowns are independent: declining the limit must not cost the WHERE.
    const result = rewrite2(
      "SELECT a FROM t LIMIT 50",
      createPolicy({ rowFilters: [US_FILTER], maxResults: 10 }),
      SqlDialect.SqlServer,
    );

    expect(result).toBe("SELECT a FROM t WHERE [region] = 'US' LIMIT 50");
  });
});
