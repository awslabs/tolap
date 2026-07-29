/**
 * Cross-SDK emitted-SQL parity for the dialect profiles.
 *
 * **The same query + policy + profile must produce the SAME SQL text in Python,
 * TypeScript, and .NET.** This corpus is duplicated verbatim in all three SDKs:
 *
 * - `sdk/python/tests/test_sql_dialect_parity.py`
 * - `sdk/typescript/packages/core/tests/sql-dialect-parity.test.ts` (this file)
 * - `sdk/dotnet/tests/Tolap.Core.Tests/SqlDialectParityTests.cs`
 *
 * Every row is the exact string all three emit. A change to any one SDK's output fails
 * that SDK's copy and names the case, which is the point: three implementations of one
 * spec drift silently otherwise, and drift here means the same policy behaves
 * differently depending on which SDK an integrator picked.
 *
 * Building this corpus found two real divergences the per-SDK suites had missed, both
 * in the WHERE-injection path and both since fixed:
 *
 * - **.NET** left the original WHERE body unparenthesised, emitting
 *   `WHERE (filters) AND a = 1 OR b = 2`. AND binds tighter than OR, so that parses as
 *   `((filters) AND a = 1) OR b = 2` and admits every row matching `b` — the prior implementation's
 *   fail-open, which .NET's own test had *pinned* as expected.
 * - **TypeScript** took the WHERE body to the end of the statement, pulling trailing
 *   clauses inside the added parentheses and emitting
 *   `WHERE (f) AND (status = 'active' ORDER BY a)` — rejected outright as a syntax
 *   error by both Postgres and MySQL.
 *
 * Neither was a dialect bug. Both were found only because parity was asserted across
 * SDKs on a shared corpus.
 */

import { describe, expect, it } from "vitest";
import { SqlQueryRewriter } from "../src/sql-rewriter.js";
import { FilterOperator } from "../src/types.js";
import type {
  EffectivePolicy,
  FieldRules,
  ObjectRules,
  PolicyLimits,
  RowFilter,
} from "../src/types.js";

/** The policy each corpus row names, built identically in all three SDKs. */
function policyFor(spec: string): EffectivePolicy {
  let rowFilters: RowFilter[] | undefined;
  let maxResults: number | undefined;
  let fieldRules: FieldRules | undefined;

  const eq = (field: string, value: unknown): RowFilter[] => [
    { field, operator: FilterOperator.Equals, value },
  ];

  switch (spec) {
    case "us_filter":
      rowFilters = eq("region", "us-east");
      break;
    case "limit10":
      maxResults = 10;
      break;
    case "us_filter_limit10":
      rowFilters = eq("region", "us-east");
      maxResults = 10;
      break;
    case "fields":
      fieldRules = { allowedFields: ["id", "region"], hiddenFields: ["ssn"] };
      break;
    case "not_deleted":
      rowFilters = [
        { field: "status", operator: FilterOperator.NotEquals, value: "deleted" },
      ];
      break;
    case "in_regions":
      rowFilters = [
        { field: "region", operator: FilterOperator.In, values: ["us-east", "us-west"] },
      ];
      break;
    case "notin_regions":
      rowFilters = [
        { field: "region", operator: FilterOperator.NotIn, values: ["eu-west"] },
      ];
      break;
    case "between":
      rowFilters = [{ field: "age", operator: FilterOperator.Between, values: [18, 65] }];
      break;
    case "isnull":
      rowFilters = [{ field: "deleted_at", operator: FilterOperator.IsNull }];
      break;
    case "like":
      rowFilters = [{ field: "region", operator: FilterOperator.Like, value: "us-%" }];
      break;
    case "backslash":
      rowFilters = eq("region", "us\\' OR 1=1 --");
      break;
    case "quote_in_field_backtick":
      rowFilters = eq("reg`ion", "x");
      break;
    case "quote_in_field_dquote":
      rowFilters = eq('reg"ion', "x");
      break;
    case "quote_in_field_bracket":
      rowFilters = eq("reg[ion", "x");
      break;
    case "apostrophe":
      rowFilters = eq("region", "it's");
      break;
    case "wrapped_field":
      rowFilters = eq("[region]", "x");
      break;
    case "dotted_field":
      rowFilters = eq("patients.region", "x");
      break;
    case "contains":
      rowFilters = [{ field: "region", operator: FilterOperator.Contains, value: "us" }];
      break;
    default:
      throw new Error(`unknown policy spec: ${spec}`);
  }

  const objectRules: ObjectRules = {};
  if (fieldRules !== undefined) objectRules.fieldRules = fieldRules;
  if (rowFilters !== undefined) objectRules.rowFilters = rowFilters;

  const limits: PolicyLimits = {};
  if (maxResults !== undefined) limits.maxResults = maxResults;

  return {
    version: "1.0",
    userId: "u",
    tenantId: "t",
    sourceConnectionId: "db:parity:main",
    resolvedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    sourceProfiles: ["parity"],
    permissions: { canQuery: true, canExport: false, readOnly: true },
    ...(Object.keys(objectRules).length > 0 ? { objectRules } : {}),
    ...(Object.keys(limits).length > 0 ? { limits } : {}),
    integrity: { algorithm: "none", signature: "" },
  };
}

/** [case id, query, policy spec, dialect, the SQL all three SDKs must emit]. */
const PARITY_CORPUS: Array<[string, string, string, string, string]> = [
  [
    "filter-ansi",
    "SELECT id, region FROM patients",
    "us_filter",
    "ansi",
    "SELECT id, region FROM patients WHERE \"region\" = 'us-east'",
  ],
  [
    "filter-postgres",
    "SELECT id, region FROM patients",
    "us_filter",
    "postgres",
    "SELECT id, region FROM patients WHERE \"region\" = 'us-east'",
  ],
  [
    "filter-trino",
    "SELECT id, region FROM patients",
    "us_filter",
    "trino",
    "SELECT id, region FROM patients WHERE \"region\" = 'us-east'",
  ],
  [
    "filter-mysql",
    "SELECT id, region FROM patients",
    "us_filter",
    "mysql",
    "SELECT id, region FROM patients WHERE `region` = 'us-east'",
  ],
  [
    "filter-sqlserver",
    "SELECT id, region FROM patients",
    "us_filter",
    "sqlserver",
    "SELECT id, region FROM patients WHERE [region] = 'us-east'",
  ],
  [
    "filter-unknown",
    "SELECT id, region FROM patients",
    "us_filter",
    "oracle",
    "SELECT id, region FROM patients",
  ],
  [
    "limit-ansi",
    "SELECT a FROM t",
    "limit10",
    "ansi",
    "SELECT a FROM t LIMIT 10",
  ],
  [
    "limit-mysql",
    "SELECT a FROM t",
    "limit10",
    "mysql",
    "SELECT a FROM t LIMIT 10",
  ],
  [
    "limit-sqlserver",
    "SELECT a FROM t",
    "limit10",
    "sqlserver",
    "SELECT TOP 10 a FROM t",
  ],
  [
    "limit-clamp-ansi",
    "SELECT a FROM t LIMIT 900",
    "limit10",
    "ansi",
    "SELECT a FROM t LIMIT 10",
  ],
  [
    "limit-clamp-mysql",
    "SELECT a FROM t LIMIT 900",
    "limit10",
    "mysql",
    "SELECT a FROM t LIMIT 10",
  ],
  [
    "both-ansi",
    "SELECT a FROM t",
    "us_filter_limit10",
    "ansi",
    "SELECT a FROM t WHERE \"region\" = 'us-east' LIMIT 10",
  ],
  [
    "both-mysql",
    "SELECT a FROM t",
    "us_filter_limit10",
    "mysql",
    "SELECT a FROM t WHERE `region` = 'us-east' LIMIT 10",
  ],
  [
    "both-sqlserver",
    "SELECT a FROM t",
    "us_filter_limit10",
    "sqlserver",
    "SELECT TOP 10 a FROM t WHERE [region] = 'us-east'",
  ],
  [
    "star-ansi",
    "SELECT * FROM patients",
    "fields",
    "ansi",
    "SELECT \"id\", \"region\" FROM patients",
  ],
  [
    "star-mysql",
    "SELECT * FROM patients",
    "fields",
    "mysql",
    "SELECT `id`, `region` FROM patients",
  ],
  [
    "star-sqlserver",
    "SELECT * FROM patients",
    "fields",
    "sqlserver",
    "SELECT [id], [region] FROM patients",
  ],
  [
    "existing-where-ansi",
    "SELECT a FROM t WHERE x = 1 OR y = 2",
    "us_filter",
    "ansi",
    "SELECT a FROM t WHERE (\"region\" = 'us-east') AND (x = 1 OR y = 2)",
  ],
  [
    "existing-where-mysql",
    "SELECT a FROM t WHERE x = 1 OR y = 2",
    "us_filter",
    "mysql",
    "SELECT a FROM t WHERE (`region` = 'us-east') AND (x = 1 OR y = 2)",
  ],
  [
    "existing-where-orderby-mysql",
    "SELECT a FROM t WHERE status = 'active' ORDER BY a",
    "us_filter_limit10",
    "mysql",
    "SELECT a FROM t WHERE (`region` = 'us-east') AND (status = 'active') ORDER BY a LIMIT 10",
  ],
  [
    "distinct-sqlserver",
    "SELECT DISTINCT a FROM t",
    "limit10",
    "sqlserver",
    "SELECT DISTINCT TOP 10 a FROM t",
  ],
  [
    "all-sqlserver",
    "SELECT ALL a FROM t",
    "limit10",
    "sqlserver",
    "SELECT ALL TOP 10 a FROM t",
  ],
  [
    "existing-top-sqlserver",
    "SELECT TOP 50 a FROM t",
    "limit10",
    "sqlserver",
    "SELECT TOP 10 a FROM t",
  ],
  [
    "existing-top-paren-sqlserver",
    "SELECT TOP (50) a FROM t",
    "limit10",
    "sqlserver",
    "SELECT TOP 10 a FROM t",
  ],
  [
    "existing-top-smaller-sqlserver",
    "SELECT TOP 3 a FROM t",
    "limit10",
    "sqlserver",
    "SELECT TOP 3 a FROM t",
  ],
  [
    "top-percent-sqlserver",
    "SELECT TOP 5 PERCENT a FROM t",
    "limit10",
    "sqlserver",
    "SELECT TOP 5 PERCENT a FROM t",
  ],
  [
    "top-withties-sqlserver",
    "SELECT TOP 5 WITH TIES a FROM t ORDER BY a",
    "limit10",
    "sqlserver",
    "SELECT TOP 5 WITH TIES a FROM t ORDER BY a",
  ],
  [
    "union-sqlserver",
    "SELECT a FROM t UNION SELECT b FROM u",
    "limit10",
    "sqlserver",
    "SELECT a FROM t UNION SELECT b FROM u",
  ],
  [
    "offset-sqlserver",
    "SELECT a FROM t ORDER BY a OFFSET 5 ROWS",
    "limit10",
    "sqlserver",
    "SELECT a FROM t ORDER BY a OFFSET 5 ROWS",
  ],
  [
    "limitkw-sqlserver",
    "SELECT a FROM t LIMIT 50",
    "limit10",
    "sqlserver",
    "SELECT a FROM t LIMIT 50",
  ],
  [
    "nonselect-sqlserver",
    "DELETE FROM t",
    "limit10",
    "sqlserver",
    "DELETE FROM t",
  ],
  [
    "groupby-mysql",
    "SELECT region, count(*) FROM t GROUP BY region",
    "us_filter",
    "mysql",
    "SELECT region, count(*) FROM t WHERE `region` = 'us-east' GROUP BY region",
  ],
  [
    "subquery-mysql",
    "SELECT a FROM t WHERE id IN (SELECT id FROM u WHERE x = 1)",
    "us_filter",
    "mysql",
    "SELECT a FROM t WHERE (`region` = 'us-east') AND (id IN (SELECT id FROM u WHERE x = 1))",
  ],
  [
    "notequals-mysql",
    "SELECT a FROM t",
    "not_deleted",
    "mysql",
    "SELECT a FROM t WHERE (`status` <> 'deleted' OR `status` IS NULL)",
  ],
  [
    "notequals-sqlserver",
    "SELECT a FROM t",
    "not_deleted",
    "sqlserver",
    "SELECT a FROM t WHERE ([status] <> 'deleted' OR [status] IS NULL)",
  ],
  [
    "in-mysql",
    "SELECT a FROM t",
    "in_regions",
    "mysql",
    "SELECT a FROM t WHERE `region` IN ('us-east', 'us-west')",
  ],
  [
    "notin-mysql",
    "SELECT a FROM t",
    "notin_regions",
    "mysql",
    "SELECT a FROM t WHERE (`region` NOT IN ('eu-west') OR `region` IS NULL)",
  ],
  [
    "between-mysql",
    "SELECT a FROM t",
    "between",
    "mysql",
    "SELECT a FROM t WHERE `age` BETWEEN 18 AND 65",
  ],
  [
    "isnull-mysql",
    "SELECT a FROM t",
    "isnull",
    "mysql",
    "SELECT a FROM t WHERE `deleted_at` IS NULL",
  ],
  [
    "like-mysql",
    "SELECT a FROM t",
    "like",
    "mysql",
    "SELECT a FROM t WHERE `region` LIKE 'us-%'",
  ],
  [
    "backslash-mysql",
    "SELECT a FROM t",
    "backslash",
    "mysql",
    "SELECT a FROM t",
  ],
  [
    "backslash-ansi",
    "SELECT a FROM t",
    "backslash",
    "ansi",
    "SELECT a FROM t",
  ],
  [
    "backslash-sqlserver",
    "SELECT a FROM t",
    "backslash",
    "sqlserver",
    "SELECT a FROM t",
  ],
  [
    "quotefield-mysql",
    "SELECT a FROM t",
    "quote_in_field_backtick",
    "mysql",
    "SELECT a FROM t",
  ],
  [
    "quotefield-ansi",
    "SELECT a FROM t",
    "quote_in_field_dquote",
    "ansi",
    "SELECT a FROM t",
  ],
  [
    "quotefield-sqlserver",
    "SELECT a FROM t",
    "quote_in_field_bracket",
    "sqlserver",
    "SELECT a FROM t",
  ],
  [
    "apostrophe-mysql",
    "SELECT a FROM t",
    "apostrophe",
    "mysql",
    "SELECT a FROM t WHERE `region` = 'it''s'",
  ],
  [
    "wrapped-field-mysql",
    "SELECT a FROM t",
    "wrapped_field",
    "mysql",
    "SELECT a FROM t WHERE `region` = 'x'",
  ],
  [
    "wrapped-field-sqlserver",
    "SELECT a FROM t",
    "wrapped_field",
    "sqlserver",
    "SELECT a FROM t WHERE [region] = 'x'",
  ],
  [
    "dotted-field-mysql",
    "SELECT a FROM t",
    "dotted_field",
    "mysql",
    "SELECT a FROM t WHERE `region` = 'x'",
  ],
  [
    "unpushable-op-mysql",
    "SELECT a FROM t",
    "contains",
    "mysql",
    "SELECT a FROM t",
  ],
];

describe("cross-SDK emitted-SQL parity", () => {
  const rewriter = new SqlQueryRewriter();

  it.each(PARITY_CORPUS)(
    "%s emits the cross-SDK corpus text",
    (_caseId, query, spec, dialect, expected) => {
      expect(rewriter.rewriteQuery(query, policyFor(spec), dialect).query).toBe(expected);
    },
  );

  it("covers every profile and both decline paths", () => {
    // A guard on the corpus itself, so it cannot quietly stop covering a profile.
    const dialects = new Set(PARITY_CORPUS.map((row) => row[3]));

    for (const d of ["ansi", "postgres", "trino", "mysql", "sqlserver"]) {
      expect(dialects.has(d)).toBe(true);
    }
    // The unrecognized-dialect path is part of the contract and must stay covered.
    expect(dialects.has("oracle")).toBe(true);
  });

  it("has a unique id per case", () => {
    const ids = PARITY_CORPUS.map((row) => row[0]);

    expect(new Set(ids).size).toBe(ids.length);
  });
});
