/**
 * SQL query rewriting — pushing a policy's restrictions into the query text so the
 * database never produces a row or column the policy excludes.
 *
 * ## This is an optimization, not the enforcement boundary
 *
 * The post-execution pipeline (`applyResultPipeline`) is what makes a policy safe,
 * and it is **never optional** (canonical spec §4). Rewriting changes the *resource*
 * outcome, not the *security* outcome: without it every matching row is fetched and
 * materialized before being discarded, which is threat-model D2. With it, the
 * database does the discarding.
 *
 * A caller MUST still run the post pass over whatever the rewritten query returns:
 *
 * - A rewriter cannot express every filter. `contains`, `startsWith`, and `matches`
 *   have no portable SQL form and are never pushed; {@link unpushableFilters}
 *   reports them.
 * - A rewriter cannot know whether the query it was handed is the query that ran.
 *
 * ## Dialect
 *
 * **There is no portable SQL, so the dialect is an explicit parameter.** An earlier
 * version of this module claimed to target "the ANSI-ish intersection of Postgres,
 * MySQL, and Athena/Trino: double-quoted identifiers". That intersection does not
 * exist. MySQL's default identifier quote is the backtick, and without `ANSI_QUOTES`
 * it reads `"region"` as a *string literal* — so the emitted
 * `WHERE "region" = 'us-east'` evaluated `'region' = 'us-east'` and matched no row at
 * all, with no error reported by the engine. Against the six-row integration fixture
 * the policy-filtered query returned 0 rows where backticks return 2.
 *
 * Callers therefore name their engine with {@link SqlDialect} (connector spec §5.1).
 * The dialect is *never* inferred and is *never* read from the policy: a signed
 * security artifact must not depend on deployment detail, and `sourceConnectionId`'s
 * `db` category deliberately does not distinguish engines. An omitted dialect selects
 * {@link DEFAULT_DIALECT} — not a guess at the engine, but the subset most engines
 * accept. An *unrecognized* dialect is not guessed at either: nothing is rewritten and
 * every filter is reported unpushable, because guessing a profile is how the MySQL
 * defect above happened.
 *
 * Only the emitted *text* is dialect-specific. The set of pushable operators, the
 * fail-closed rules, and the post pass are identical under every profile, so choosing
 * a profile never changes which rows a policy admits — only where the work happens.
 *
 * ## Parsing
 *
 * Regular-expression and depth-scan based, not a full SQL grammar. Keyword matches
 * are restricted to parenthesis depth zero and skip over string literals and quoted
 * identifiers, so a subquery's `WHERE` or `LIMIT` is not mistaken for the
 * statement's own. Constructs beyond that are recognised well enough to be
 * *declined*, not to be rewritten. Every path is built so that a construct the
 * rewriter cannot handle leaves the query narrower or unchanged, never wider.
 *
 * Zero runtime dependencies, like the rest of `@tolap/core`.
 */

import type {
  EffectivePolicy,
  RowFilter,
} from "./types.js";
import { FilterOperator } from "./types.js";
import { fieldNameMatches } from "./enforcement.js";

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

/**
 * A sink for messages explaining why a rewrite step declined to act.
 *
 * A plain callback rather than a logger interface: `@tolap/core` ships zero runtime
 * dependencies and that must not change. Messages may embed policy field names and
 * fragments of the query, so route them with the same handling as query logs.
 */
export type RewriteDiagnostics = (message: string) => void;

/**
 * The engine a rewritten statement is destined for (connector spec §5.1).
 *
 * Supplied by the integrator, because the dialect is a property of *their* connection
 * and only they know it — they already chose `pg` or `mysql2`. It is deliberately not
 * derivable from the policy.
 */
export enum SqlDialect {
  /**
   * The strict intersection: double-quoted identifiers, `LIMIT n`. The default,
   * chosen when no dialect is named. Not a guess at the engine — the subset most
   * engines accept.
   */
  Ansi = "ansi",
  /** PostgreSQL, and the Redshift/Greenplum forks that share its quoting. */
  Postgres = "postgres",
  /** Trino, Presto, and Athena. */
  Trino = "trino",
  /**
   * MySQL and MariaDB. Backtick identifiers, because `"region"` is a string literal
   * here unless `ANSI_QUOTES` is set.
   */
  MySql = "mysql",
  /**
   * Microsoft SQL Server and Azure SQL. Bracket identifiers, and `TOP n` after
   * `SELECT` rather than `LIMIT n` at the end.
   */
  SqlServer = "sqlserver",
}

/** What an omitted dialect selects. */
export const DEFAULT_DIALECT = SqlDialect.Ansi;

/**
 * How a profile spells its row limit. `LIMIT n` is a suffix; `TOP n` is an infix that
 * binds to a single `SELECT`, which is a structural difference rather than a token
 * swap — see {@link SqlQueryRewriter.clampLimitTop}.
 */
type RowLimitForm = "limit" | "top";

/**
 * The emitted-text rules for one engine.
 *
 * Only *text* lives here. Which operators are pushable, which values are refused, and
 * every fail-closed rule are profile-independent by design (connector spec §5.1): a
 * filter unpushable in one profile is unpushable in all of them, so selecting a
 * profile never changes which rows a policy admits.
 */
interface DialectProfile {
  readonly dialect: SqlDialect;
  readonly quoteOpen: string;
  readonly quoteClose: string;
  readonly rowLimit: RowLimitForm;
}

const DIALECT_PROFILES: Readonly<Record<SqlDialect, DialectProfile>> = {
  [SqlDialect.Ansi]: {
    dialect: SqlDialect.Ansi, quoteOpen: '"', quoteClose: '"', rowLimit: "limit",
  },
  [SqlDialect.Postgres]: {
    dialect: SqlDialect.Postgres, quoteOpen: '"', quoteClose: '"', rowLimit: "limit",
  },
  [SqlDialect.Trino]: {
    dialect: SqlDialect.Trino, quoteOpen: '"', quoteClose: '"', rowLimit: "limit",
  },
  [SqlDialect.MySql]: {
    dialect: SqlDialect.MySql, quoteOpen: "`", quoteClose: "`", rowLimit: "limit",
  },
  [SqlDialect.SqlServer]: {
    dialect: SqlDialect.SqlServer, quoteOpen: "[", quoteClose: "]", rowLimit: "top",
  },
};

/**
 * The characters a profile uses to delimit an identifier.
 *
 * An identifier containing one of them is *declined* rather than escaped by doubling
 * (connector spec §5.1 rule 4). Declining costs an optimization; mis-escaping emits
 * author-controlled text into a statement.
 */
function quoteChars(profile: DialectProfile): string[] {
  return profile.quoteOpen === profile.quoteClose
    ? [profile.quoteOpen]
    : [profile.quoteOpen, profile.quoteClose];
}

/**
 * The profile for a dialect, or undefined when it is not recognized.
 *
 * `undefined`/omitted means {@link DEFAULT_DIALECT}. An **unrecognized** dialect
 * returns undefined *without throwing*, and every caller treats that as "do not
 * rewrite at all" (connector spec §5.1 rule 2). Neither guessing a profile nor
 * throwing is acceptable: guessing is how the MySQL backtick defect happened, and
 * throwing would turn a deployment typo into an outage on a path that is only ever an
 * optimization.
 */
function resolveProfile(dialect: SqlDialect | string | undefined): DialectProfile | undefined {
  if (dialect === undefined) return DIALECT_PROFILES[DEFAULT_DIALECT];
  // A plain string index rather than an enum lookup, so a config value passed
  // straight through resolves and an unknown one lands on undefined.
  return (DIALECT_PROFILES as Record<string, DialectProfile | undefined>)[dialect];
}

export interface SqlRewriterOptions {
  /** Optional sink for decline explanations. */
  diagnostics?: RewriteDiagnostics;
  /**
   * The engine this rewriter emits for. Omitted selects {@link DEFAULT_DIALECT}; an
   * unrecognized value declines to rewrite anything.
   *
   * Settable per rewriter *and* per call ({@link SqlQueryRewriter.rewriteQuery}), so an
   * integrator with one connection can construct one rewriter and an integrator
   * fanning out across engines can pass it per query.
   */
  dialect?: SqlDialect | string;
}

/**
 * Bounds on the query text a rewriter will parse.
 *
 * JavaScript's RegExp has no evaluation timeout, so the work a pattern can be asked
 * to do is bounded instead — the same mechanism `enforcement.ts` uses to guard
 * `matches`. Over-long input is declined (the query is returned unchanged and every
 * filter is reported unpushable) rather than scanned; the post pass still enforces
 * the policy in full, so declining costs transfer and never disclosure.
 */
export const MAX_QUERY_LENGTH = 100_000;

/** The result of rewriting a query. */
export interface RewriteResult {
  /**
   * The query to execute. Identical to the input when nothing could be pushed down.
   */
  query: string;
  /** Whether {@link query} differs from the caller's original text. */
  rewritten: boolean;
  /**
   * Row filters that could not be expressed in portable SQL, and are therefore
   * enforced *only* by the post-execution pipeline.
   *
   * Non-empty means the database will return rows the post pass still has to
   * discard. An integrator whose result sets are large enough that post-fetch
   * filtering is not an acceptable fallback should assert this is empty.
   */
  unpushableFilters: RowFilter[];
}

// ---------------------------------------------------------------------------
// Keyword patterns
// ---------------------------------------------------------------------------
//
// Each is matched against the whole query and then filtered to occurrences at
// parenthesis depth zero and outside string literals, so a subquery cannot supply
// the match that governs the outer statement.

const SELECT_KEYWORD = /\bSELECT\b/gi;
const FROM_KEYWORD = /\bFROM\b/gi;
const WHERE_KEYWORD = /\bWHERE\b/gi;
const LIMIT_CLAUSE = /\bLIMIT\s+(\d+)/gi;

// -- sqlserver TOP placement --
//
// Individually matched keywords, so the shapes in which `TOP n` cannot be placed
// correctly can be recognised and declined rather than approximated.

const LIMIT_KEYWORD = /\bLIMIT\b/gi;
const OFFSET_KEYWORD = /\bOFFSET\b/gi;
const FETCH_KEYWORD = /\bFETCH\b/gi;
const UNION_KEYWORD = /\bUNION\b/gi;
const INTERSECT_KEYWORD = /\bINTERSECT\b/gi;
const EXCEPT_KEYWORD = /\bEXCEPT\b/gi;

/**
 * `SELECT DISTINCT`/`SELECT ALL`: `TOP` goes *after* the quantifier, since
 * `SELECT DISTINCT TOP 5` is a syntax error and `SELECT TOP 5 DISTINCT` would count
 * rows before duplicates are removed.
 */
const SELECT_QUANTIFIER = /^\s+(?:DISTINCT|ALL)\b/i;

/**
 * An existing `TOP n` or `TOP (n)`, with the modifiers that make it not a plain row
 * count. `PERCENT` is a proportion rather than a count and `WITH TIES` returns more
 * rows than the number given, so neither can be clamped to a row limit.
 *
 * The count alternatives are separate branches rather than one `\(?\s*(\d+)\s*\)?`: a
 * trailing `\s*` would swallow the space before `PERCENT` and hide the modifier, which
 * makes `TOP 5 PERCENT` look like a plain `TOP 5`.
 */
const TOP_CLAUSE =
  /^\s+TOP\s*(?:\(\s*(\d+)\s*\)|(\d+))(\s+PERCENT\b|\s+WITH\s+TIES\b)?/i;

/**
 * Clauses that may follow the `FROM`/join list. An injected `WHERE` goes before
 * whichever of them appears earliest *by position* — not by the order of this list.
 *
 * A prior implementation iterated a fixed pattern list and returned the first pattern that matched
 * anywhere, so `SELECT ... GROUP BY region ORDER BY n` inserted before `ORDER BY`
 * (the third pattern) and produced `GROUP BY region WHERE ... ORDER BY n` — invalid
 * SQL. The clause that comes first in the text is the only correct answer.
 */
const POST_FROM_CLAUSES: RegExp[] = [
  /\bGROUP\s+BY\b/gi,
  /\bHAVING\b/gi,
  /\bWINDOW\b/gi,
  /\bORDER\s+BY\b/gi,
  /\bLIMIT\b/gi,
  /\bOFFSET\b/gi,
  /\bFETCH\b/gi,
  /\bUNION\b/gi,
  /\bINTERSECT\b/gi,
  /\bEXCEPT\b/gi,
];

/** The table reference immediately after `FROM`: a bare, dotted, or quoted name. */
const FROM_TABLE_PATTERN = /\bFROM\s+((?:"[^"]+"|\w+)(?:\.(?:"[^"]+"|\w+))*)/i;

// -- Clause-body patterns, used only by validateQuery's field extraction --

const WHERE_CLAUSE_PATTERN =
  /\bWHERE\s+([\s\S]+?)(?:\bORDER\s+BY\b|\bGROUP\s+BY\b|\bHAVING\b|\bLIMIT\b|\bOFFSET\b|\bUNION\b|;|$)/i;

const ORDER_BY_CLAUSE_PATTERN =
  /\bORDER\s+BY\s+([\s\S]+?)(?:\bLIMIT\b|\bOFFSET\b|\bUNION\b|;|$)/i;

const GROUP_BY_CLAUSE_PATTERN =
  /\bGROUP\s+BY\s+([\s\S]+?)(?:\bHAVING\b|\bORDER\s+BY\b|\bLIMIT\b|\bOFFSET\b|\bUNION\b|;|$)/i;

const HAVING_CLAUSE_PATTERN =
  /\bHAVING\s+([\s\S]+?)(?:\bORDER\s+BY\b|\bLIMIT\b|\bOFFSET\b|\bUNION\b|;|$)/i;

/**
 * Unqualified field references on the left of a comparison operator.
 *
 * The negative lookbehind is what keeps `t.region` from also yielding a bare
 * `region`, and keeps a quoted string's contents out of the field set. Node 22
 * supports lookbehind natively (V8 has since Node 8.3), so this is a direct
 * translation of the original .NET `(?<![."'`\w])` with identical semantics — verified
 * by `sql-rewriter.test.ts`, which asserts both the qualified and quoted cases.
 */
const COLUMN_COMPARISON_PATTERN =
  /(?<![."'`\w])(\w+)\s*(?:=|!=|<>|<=|>=|<|>|\bLIKE\b|\bIN\b|\bIS\b|\bBETWEEN\b|\bNOT\s+LIKE\b|\bNOT\s+IN\b)/gi;

/** Table-qualified field references on the left of a comparison operator. */
const QUALIFIED_COLUMN_COMPARISON_PATTERN =
  /(?:"[^"]+"|\w+)\.(?:"([^"]+)"|(\w+))\s*(?:=|!=|<>|<=|>=|<|>|\bLIKE\b|\bIN\b|\bIS\b|\bBETWEEN\b|\bNOT\s+LIKE\b|\bNOT\s+IN\b)/gi;

/**
 * A function call and its argument list, used to reach field references that are
 * not on the left of a comparison operator.
 *
 * Without this, `HAVING max(ssn) > '1'` yields no field name at all — the token
 * left of `>` is `)` — and a hidden field is used to choose which rows come back
 * while passing validation. The aggregate's value is disclosed by the row set even
 * though the field never appears in the projection.
 */
const FUNCTION_CALL_PATTERN = /\b(\w+)\s*\(([^()]*)\)/g;

/** A bare word token, for pulling field names out of a function's arguments. */
const WORD_PATTERN = /\w+/g;

/** A quoted string literal, whose contents are values rather than field names. */
const STRING_LITERAL_PATTERN = /'(?:[^']|'')*'/g;

const ORDER_BY_SUFFIX_PATTERN = /\s+(ASC|DESC)(\s+NULLS\s+(FIRST|LAST))?\s*$/i;

/**
 * A field name safe to emit as a quoted SQL identifier.
 *
 * A letter or underscore followed by letters, digits, underscores, or dollars.
 * Deliberately excludes quote characters, dots, whitespace, and control characters,
 * so a name that could alter the statement's structure is **declined rather than
 * escaped and hoped for**. A prior implementation quoted identifiers without validating them, which
 * relies entirely on the doubling of `"` being correct in every dialect and on the
 * name containing nothing else structural.
 */
const SAFE_IDENTIFIER_PATTERN = /^[\p{L}_][\p{L}\p{N}_$]*$/u;

/**
 * Keywords that must never be mistaken for a field name during extraction.
 *
 * Extends the original list with SQL **type names**. A prior implementation rejected `CAST(id AS text)`
 * because `text` was extracted as a column and matched no allow-list entry — a
 * false denial that pushes integrators toward disabling validation.
 */
const SQL_KEYWORDS = new Set(
  [
    "SELECT", "FROM", "WHERE", "AND", "OR", "NOT", "IN", "IS", "NULL",
    "LIKE", "BETWEEN", "EXISTS", "HAVING", "ORDER", "BY", "GROUP",
    "ASC", "DESC", "LIMIT", "OFFSET", "UNION", "ALL", "DISTINCT",
    "AS", "ON", "JOIN", "LEFT", "RIGHT", "INNER", "OUTER", "CROSS",
    "FULL", "CASE", "WHEN", "THEN", "ELSE", "END", "CAST", "TRUE",
    "FALSE", "INSERT", "UPDATE", "DELETE", "SET", "VALUES", "INTO",
    "CREATE", "ALTER", "DROP", "TABLE", "INDEX", "WITH", "RECURSIVE",
    "OVER", "PARTITION", "ROW", "ROWS", "RANGE", "UNBOUNDED",
    "PRECEDING", "FOLLOWING", "CURRENT", "FETCH", "FIRST", "LAST",
    "NEXT", "ONLY", "NULLS", "FILTER", "WITHIN", "ARRAY", "ANY",
    "SOME", "EVERY", "ESCAPE", "ILIKE", "SIMILAR", "TO",
    // Type names, reachable through CAST(x AS type) and ::type.
    "TEXT", "VARCHAR", "CHAR", "NCHAR", "NVARCHAR", "INT", "INTEGER",
    "SMALLINT", "BIGINT", "TINYINT", "DECIMAL", "NUMERIC", "REAL",
    "FLOAT", "DOUBLE", "PRECISION", "BOOLEAN", "BOOL", "DATE", "TIME",
    "TIMESTAMP", "TIMESTAMPTZ", "INTERVAL", "JSON", "JSONB", "UUID",
    "BYTEA", "BLOB", "CLOB", "BINARY", "VARBINARY", "SERIAL", "MONEY",
    "BIT", "YEAR", "DATETIME", "SIGNED", "UNSIGNED", "ZONE",
  ].map((k) => k.toUpperCase()),
);

/** A condition that admits every row, for a filter that restricts nothing. */
const ALWAYS_TRUE = "1 = 1";

/** A condition that admits no row, for a filter that can never be satisfied. */
const ALWAYS_FALSE = "1 = 0";

// ---------------------------------------------------------------------------
// SqlQueryRewriter
// ---------------------------------------------------------------------------

/**
 * Pushes a TOLAP policy's field and row restrictions into a SQL query.
 *
 * ```ts
 * const rewriter = new SqlQueryRewriter({
 *   // The engine YOU connected to. Omitted selects "ansi".
 *   dialect: SqlDialect.MySql,
 *   diagnostics: (m) => log.debug(m),
 * });
 *
 * // 1. Resolve the table the query actually reads, and check object access.
 * const table = rewriter.extractTableName(sql);
 *
 * // 2. Refuse a query that names a field the policy hides, rather than silently
 * //    narrowing it -- an agent that asked for a forbidden column should be told.
 * if (!rewriter.validateQuery(sql, policy)) throw new Error("Access denied: ...");
 *
 * // 3. Push what can be pushed.
 * const { query, unpushableFilters } = rewriter.rewriteQuery(sql, policy);
 * const rows = await db.query(query);
 *
 * // 4. ALWAYS run the post pass. This is the enforcement boundary (spec §4);
 * //    step 3 only reduced how much data crossed the wire.
 * return applyResultPipeline(rows, policy);
 * ```
 */
export class SqlQueryRewriter {
  private readonly diagnostics?: RewriteDiagnostics;

  /**
   * The dialect every call defaults to, as given to the constructor. Retained
   * unresolved so an unrecognized value declines at each call site with a
   * diagnostic, rather than throwing during construction.
   */
  private readonly dialect: SqlDialect | string | undefined;

  constructor(options: SqlRewriterOptions = {}) {
    this.diagnostics = options.diagnostics;
    this.dialect = options.dialect;
  }

  /**
   * Resolve a per-call dialect against the rewriter's own, or undefined when the
   * result is unrecognized (in which case nothing is rewritten).
   */
  private profileFor(dialect: SqlDialect | string | undefined): DialectProfile | undefined {
    const requested = dialect ?? this.dialect;
    const profile = resolveProfile(requested);
    if (profile === undefined) {
      this.diagnose(
        `unrecognized SQL dialect '${String(requested)}': nothing is pushed down and ` +
          "the post-execution pass enforces the policy in full",
      );
    }
    return profile;
  }

  // -----------------------------------------------------------------------
  // rewriteQuery
  // -----------------------------------------------------------------------

  /**
   * Rewrite a query to carry the policy's field restrictions, row filters, and
   * result limit.
   *
   * Never throws for a malformed query: a construct that cannot be handled is left
   * alone and reported through {@link RewriteResult.unpushableFilters}. Never throws
   * for an unrecognized `dialect` either — that declines to rewrite at all and reports
   * every filter (connector spec §5.1 rule 2).
   *
   * @param dialect The engine to emit for, overriding the constructor's.
   */
  rewriteQuery(
    originalQuery: string,
    policy: EffectivePolicy,
    dialect?: SqlDialect | string,
  ): RewriteResult {
    if (typeof originalQuery !== "string" || originalQuery.trim() === "") {
      return {
        query: originalQuery,
        rewritten: false,
        unpushableFilters: this.allFilters(policy),
      };
    }

    const profile = this.profileFor(dialect);
    if (profile === undefined) {
      return {
        query: originalQuery,
        rewritten: false,
        unpushableFilters: this.allFilters(policy),
      };
    }

    if (originalQuery.length > MAX_QUERY_LENGTH) {
      // ReDoS guard. Declining leaves the whole policy to the post pass, which is
      // the fail-closed direction: it costs transfer, never disclosure.
      this.diagnose(
        `query is ${originalQuery.length} characters, over the ${MAX_QUERY_LENGTH} ` +
          "parse bound; nothing is pushed down and the post-execution pass enforces " +
          "the policy in full",
      );
      return {
        query: originalQuery,
        rewritten: false,
        unpushableFilters: this.allFilters(policy),
      };
    }

    let query = originalQuery.trim();

    query = this.rewriteSelectList(query, policy, profile);
    query = this.injectRowFilters(query, policy, profile);
    query = this.clampLimit(query, policy, profile);

    return {
      query,
      rewritten: query !== originalQuery,
      unpushableFilters: this.unpushableFilters(policy, dialect),
    };
  }

  /**
   * Row filters this rewriter cannot express in SQL for the given policy and dialect.
   *
   * These are enforced *only* by the post-execution pipeline (spec §4). An
   * unrecognized `dialect` reports **every** filter, since nothing is rewritten at all
   * in that case.
   */
  unpushableFilters(policy: EffectivePolicy, dialect?: SqlDialect | string): RowFilter[] {
    const filters = policy.objectRules?.rowFilters;
    if (!filters || filters.length === 0) return [];

    const profile = resolveProfile(dialect ?? this.dialect);
    if (profile === undefined) return [...filters];

    return filters.filter((f) => this.buildCondition(f, profile) === undefined);
  }

  private allFilters(policy: EffectivePolicy): RowFilter[] {
    return [...(policy.objectRules?.rowFilters ?? [])];
  }

  /**
   * Expand `SELECT *` to the permitted fields, or remove hidden and non-allowed
   * fields from an explicit select list.
   */
  private rewriteSelectList(
    query: string,
    policy: EffectivePolicy,
    profile: DialectProfile,
  ): string {
    const fieldRules = policy.objectRules?.fieldRules;
    const allowed = fieldRules?.allowedFields;
    const hidden = fieldRules?.hiddenFields;

    // Nothing to do: an absent allow-list is unrestricted (spec §3) and there is
    // nothing to hide. Tested for undefined, not for emptiness -- an EMPTY
    // allowedFields denies every field and must still be acted on.
    if (allowed === undefined && (hidden === undefined || hidden.length === 0)) {
      return query;
    }

    const span = findSelectListSpan(query);
    if (span === undefined) {
      this.diagnose(
        "select list not located; the projection is left to the post-execution pass",
      );
      return query;
    }

    const selectList = query.slice(span.start, span.start + span.length);

    const replacement =
      selectList.trim() === "*"
        ? this.expandSelectStar(allowed, hidden, profile)
        : this.filterSelectList(selectList, allowed, hidden);

    if (replacement === undefined) return query;

    return (
      query.slice(0, span.start) + replacement + query.slice(span.start + span.length)
    );
  }

  /**
   * The explicit field list replacing `*`, or undefined when it cannot be
   * determined.
   *
   * Requires `allowedFields`: without it the set of columns the table actually has
   * is unknown, so hidden fields cannot be subtracted from `*` without schema
   * access the SDK deliberately does not assume.
   *
   * **This is the limitation to understand loudly.** In that case `*` is left alone
   * and `stripHiddenFields` removes the hidden columns *after* the fetch. The
   * disclosure outcome is identical — the agent never sees a hidden column either
   * way — but the hidden column crosses the wire, so a policy hiding a large or
   * sensitive column from a `SELECT *` gains nothing from rewriting. An integrator
   * who needs the column to never leave the database must either enumerate
   * `allowedFields` in the policy or not write `SELECT *`.
   */
  private expandSelectStar(
    allowed: string[] | undefined,
    hidden: string[] | undefined,
    profile: DialectProfile,
  ): string | undefined {
    if (allowed === undefined) {
      this.diagnose(
        "SELECT * with hiddenFields but no allowedFields: the table's column list " +
          "is unknown, so SELECT * is left as-is and the hidden columns are removed " +
          "AFTER the fetch. They still cross the wire. Enumerate allowedFields in " +
          "the policy, or avoid SELECT *, to keep them in the database.",
      );
      return undefined;
    }

    // A glob cannot be emitted as an identifier, and dropping the entries it stands
    // for would narrow the projection below what the policy grants.
    if (allowed.some((a) => a.includes("*") || a.includes("?"))) {
      this.diagnose(
        "SELECT * not expanded: allowedFields contains a wildcard pattern, which " +
          "has no column list to expand to",
      );
      return undefined;
    }

    const seen = new Set<string>();
    const columns: string[] = [];
    for (const entry of allowed) {
      if (hidden?.some((h) => fieldNameMatches(h, entry))) continue;
      const leaf = leafIdentifier(entry, profile);
      if (leaf === undefined) continue;
      const key = leaf.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      columns.push(leaf);
    }

    if (columns.length === 0) {
      // No field is permitted. Selecting a constant keeps the statement valid and
      // matches the post-fetch outcome, where projecting to an empty allow-list
      // leaves each surviving row with no fields.
      this.diagnose("no field is permitted after filtering; projecting a constant");
      return "1";
    }

    return columns.map((c) => quoteIdentifier(c, profile)).join(", ");
  }

  /**
   * Remove hidden and non-allowed entries from an explicit select list, or return
   * undefined to leave the list alone.
   *
   * **Masked fields are deliberately NOT removed.** Masking happens after the
   * fetch, so a masked column must survive into the executed query or there is
   * nothing left to mask — the field would silently vanish from the result instead
   * of appearing masked. `maskedFields` is not consulted here at all, which is the
   * point: nothing in this method can remove a column for being masked.
   */
  private filterSelectList(
    selectList: string,
    allowed: string[] | undefined,
    hidden: string[] | undefined,
  ): string | undefined {
    const entries = splitTopLevel(selectList);
    const kept: string[] = [];

    for (const entry of entries) {
      const name = extractFieldName(entry);

      if (hidden?.some((h) => fieldNameMatches(h, name))) {
        this.diagnose(`removing hidden field from the select list: ${name}`);
        continue;
      }

      if (allowed !== undefined && !allowed.some((a) => fieldNameMatches(a, name))) {
        this.diagnose(`removing non-allowed field from the select list: ${name}`);
        continue;
      }

      kept.push(entry.trim());
    }

    if (kept.length === entries.length) return undefined;

    if (kept.length === 0) {
      this.diagnose("every selected field was removed; projecting a constant");
      return "1";
    }

    return kept.join(", ");
  }

  /** Inject the policy's row filters as a `WHERE` condition. */
  private injectRowFilters(
    query: string,
    policy: EffectivePolicy,
    profile: DialectProfile,
  ): string {
    const filters = policy.objectRules?.rowFilters;
    if (!filters || filters.length === 0) return query;

    const clause = this.buildWhereClause(filters, profile.dialect);
    if (clause === "") return query;

    const scan = new SqlScan(query);

    const existing = scan.firstTopLevel(WHERE_KEYWORD);
    if (existing !== undefined) {
      // The original WHERE body ends at the next top-level clause, NOT at the end of
      // the statement. Taking the rest of the text pulls ORDER BY/GROUP BY/LIMIT inside
      // the parentheses added below and emits invalid SQL: both Postgres and MySQL
      // reject `WHERE (f) AND (status = 'active' ORDER BY a)` outright.
      const bodyStart = existing.index + existing.length;
      let bodyEnd = query.trimEnd().replace(/;\s*$/, "").trimEnd().length;
      for (const pattern of POST_FROM_CLAUSES) {
        const match = scan.firstTopLevelAfter(pattern, bodyStart);
        if (match !== undefined && match.index < bodyEnd) bodyEnd = match.index;
      }

      // Both sides are parenthesised. A prior implementation emitted `WHERE (filters) AND <original>`
      // and left the original bare, so an original of `a OR b` produced
      // `(filters) AND a OR b` -- which, because AND binds tighter than OR, admits
      // EVERY row matching b, with the security filter bypassed entirely.
      //
      // Back up over the whitespace so the tail keeps its own separator; the
      // parenthesised body is trimmed, so otherwise `) ORDER BY` would run together as
      // `)ORDER BY`.
      while (bodyEnd > bodyStart && /\s/.test(query[bodyEnd - 1]!)) bodyEnd--;

      const original = query.slice(bodyStart, bodyEnd).trim();
      return (
        query.slice(0, existing.index) +
        `WHERE (${clause}) AND (${original})` +
        query.slice(bodyEnd)
      );
    }

    const insertAt = findWhereInsertPoint(query, scan);
    return query.slice(0, insertAt) + ` WHERE ${clause}` + query.slice(insertAt);
  }

  /**
   * Push `maxResults` into the statement's row limit, in the profile's own form.
   */
  private clampLimit(
    query: string,
    policy: EffectivePolicy,
    profile: DialectProfile,
  ): string {
    const maxResults = policy.limits?.maxResults;
    if (maxResults === undefined || maxResults === null) return query;

    if (!Number.isInteger(maxResults) || maxResults < 0) {
      this.diagnose(
        `maxResults (${maxResults}) is not a non-negative integer and cannot be a ` +
          "row limit; the query is left alone and applyResultLimit truncates the result",
      );
      return query;
    }

    return profile.rowLimit === "top"
      ? this.clampLimitTop(query, maxResults)
      : this.clampLimitSuffix(query, maxResults);
  }

  /** Clamp or append a trailing `LIMIT n`. */
  private clampLimitSuffix(query: string, maxResults: number): string {
    const scan = new SqlScan(query);

    // The statement's own LIMIT is the LAST one at top level. An earlier top-level
    // LIMIT belongs to a set operand ("... UNION SELECT ... LIMIT 5"), and clamping
    // that would alter which rows the operand contributes rather than how many the
    // caller receives.
    const match = scan.lastTopLevel(LIMIT_CLAUSE);
    if (match === undefined) {
      const trimmed = query.trimEnd();
      const hadSemicolon = trimmed.endsWith(";");
      const body = hadSemicolon ? trimmed.slice(0, -1).trimEnd() : trimmed;
      return `${body} LIMIT ${maxResults}${hadSemicolon ? ";" : ""}`;
    }

    // Group 1 is the digit run, always present when LIMIT_CLAUSE matches.
    const digits = match.groups[1]!;
    // A literal too large for an exact JS integer is certainly larger than any
    // policy limit. Parsing it with Number would lose precision silently, so the
    // policy limit simply wins.
    const existing = Number(digits);
    const effective =
      Number.isSafeInteger(existing) && existing < maxResults ? existing : maxResults;

    return (
      query.slice(0, match.index) +
      `LIMIT ${effective}` +
      query.slice(match.index + match.length)
    );
  }

  /**
   * Clamp or insert a `TOP n`, or return the query unchanged.
   *
   * `TOP n` is **not a token swap for `LIMIT n`**: it sits immediately after `SELECT`
   * (and after `DISTINCT`/`ALL`), not at the end of the statement, and it binds to one
   * `SELECT` rather than to the statement's final result. So this is a structural
   * placement, and where it cannot be placed *correctly* the limit is simply **not
   * pushed** — never rendered as `LIMIT n` instead (connector spec §5.1 rule 3). An
   * unpushed limit costs a transfer that `applyResultLimit` then trims; a misplaced or
   * mis-spelled one is a broken statement or a wrong row count.
   *
   * Declined shapes, each for a reason that is not a parser limitation:
   *
   * - **A top-level set operation.** In `SELECT ... UNION SELECT ...`, a `TOP` on the
   *   first operand limits that operand, not the union, so the caller would receive
   *   more rows than the policy allows.
   * - **`OFFSET`/`FETCH`.** T-SQL rejects `TOP` combined with `OFFSET ... FETCH`.
   * - **An existing `TOP n PERCENT` or `WITH TIES`.** A percentage is not a row count,
   *   and `WITH TIES` returns more rows than the number given.
   * - **An existing top-level `LIMIT`.** The statement is already not valid T-SQL;
   *   clamping around a clause this profile does not emit would be guessing.
   */
  private clampLimitTop(query: string, maxResults: number): string {
    const scan = new SqlScan(query);

    const declineOn: Array<[RegExp, string]> = [
      [UNION_KEYWORD, "a top-level set operation, where TOP would bind to one operand"],
      [INTERSECT_KEYWORD, "a top-level set operation, where TOP would bind to one operand"],
      [EXCEPT_KEYWORD, "a top-level set operation, where TOP would bind to one operand"],
      [OFFSET_KEYWORD, "an OFFSET clause, which T-SQL forbids alongside TOP"],
      [FETCH_KEYWORD, "a FETCH clause, which T-SQL forbids alongside TOP"],
      [LIMIT_KEYWORD, "a LIMIT clause, which is not valid T-SQL to begin with"],
    ];

    for (const [pattern, reason] of declineOn) {
      if (scan.firstTopLevel(pattern) !== undefined) {
        this.diagnose(
          `the row limit is not pushed as TOP: the statement contains ${reason}; ` +
            "applyResultLimit truncates the result instead",
        );
        return query;
      }
    }

    const select = scan.firstTopLevel(SELECT_KEYWORD);
    if (select === undefined) {
      this.diagnose(
        "the row limit is not pushed as TOP: there is no top-level SELECT to place it " +
          "after; applyResultLimit truncates the result instead",
      );
      return query;
    }

    const afterSelect = select.index + select.length;
    const tail = query.slice(afterSelect);

    const existingTop = TOP_CLAUSE.exec(tail);
    if (existingTop !== null) {
      const modifier = existingTop[3];
      if (modifier !== undefined) {
        this.diagnose(
          `the row limit is not pushed as TOP: the statement already uses ` +
            `TOP ...${modifier}, which is not a plain row count; applyResultLimit ` +
            "truncates the result instead",
        );
        return query;
      }
      // One of the two count branches always matches when TOP_CLAUSE does.
      const written = Number(existingTop[1] ?? existingTop[2]!);
      const effective =
        Number.isSafeInteger(written) && written < maxResults ? written : maxResults;
      return (
        query.slice(0, afterSelect) +
        ` TOP ${effective}` +
        tail.slice(existingTop[0].length)
      );
    }

    // DISTINCT and ALL bind to the SELECT, so TOP goes after them: `SELECT DISTINCT
    // TOP 5` is a syntax error where `SELECT TOP 5 DISTINCT` changes which rows are
    // counted -- TOP would apply before duplicates are removed.
    const quantifier = SELECT_QUANTIFIER.exec(tail);
    const insertAt = afterSelect + (quantifier === null ? 0 : quantifier[0].length);

    return query.slice(0, insertAt) + ` TOP ${maxResults}` + query.slice(insertAt);
  }

  // -----------------------------------------------------------------------
  // validateQuery
  // -----------------------------------------------------------------------

  /**
   * Whether the query references only fields the policy permits.
   *
   * Refusing beats silently narrowing: an agent that asked for a field it cannot
   * read should be told, not handed a result that quietly omits the column. Returns
   * false for an empty query.
   */
  validateQuery(query: string, policy: EffectivePolicy): boolean {
    if (typeof query !== "string" || query.trim() === "") return false;
    if (query.length > MAX_QUERY_LENGTH) {
      // A query too long to parse cannot be shown to reference only allowed fields.
      this.diagnose(
        `query is ${query.length} characters, over the ${MAX_QUERY_LENGTH} parse ` +
          "bound; it cannot be validated and is refused",
      );
      return false;
    }

    const fieldRules = policy.objectRules?.fieldRules;
    const hidden = fieldRules?.hiddenFields;
    const allowed = fieldRules?.allowedFields;

    if (hidden === undefined && allowed === undefined) return true;

    const referenced = extractReferencedFields(query);

    for (const field of referenced) {
      if (hidden?.some((h) => fieldNameMatches(h, field))) {
        this.diagnose(`query references hidden field: ${field}`);
        return false;
      }
    }

    // Tested for undefined, not for emptiness: an EMPTY allow-list denies every
    // field (spec §3), so treating it as "no restriction" would invert the rule.
    if (allowed !== undefined) {
      for (const field of referenced) {
        // A wildcard discloses nothing by itself and an aggregate has no single
        // field name; both are settled by the post-fetch projection.
        if (field === "*" || field.includes("(")) continue;

        if (!allowed.some((a) => fieldNameMatches(a, field))) {
          this.diagnose(`query references non-allowed field: ${field}`);
          return false;
        }
      }
    }

    return true;
  }

  // -----------------------------------------------------------------------
  // extractTableName
  // -----------------------------------------------------------------------

  /**
   * The table a query reads, or undefined when there is no `FROM` clause.
   *
   * Handles `table`, `schema.table`, `"schema"."table"`, and the `"schema.table"`
   * form where the whole dotted name sits inside one pair of quotes. Returns the
   * leaf name, which is what an `allowedObjects` rule is written against.
   */
  extractTableName(query: string): string | undefined {
    if (typeof query !== "string" || query.trim() === "") return undefined;
    if (query.length > MAX_QUERY_LENGTH) return undefined;

    const match = FROM_TABLE_PATTERN.exec(query);
    if (match === null) return undefined;

    // Group 1 is the table reference, always present when the pattern matches.
    const reference = match[1]!;

    // "schema"."table": split on the quote-dot-quote seam so a dot INSIDE either
    // identifier is not mistaken for the separator.
    if (reference.includes('"."')) {
      const parts = reference.split('"."');
      return trimChars(parts[parts.length - 1]!, "\"' ");
    }

    const name = trimChars(reference, "\"' ");

    if (name.includes(".")) {
      const parts = name.split(".");
      return parts[parts.length - 1];
    }

    return name;
  }

  // -----------------------------------------------------------------------
  // Row filter conditions
  // -----------------------------------------------------------------------

  /**
   * Build a `WHERE` clause body (without the `WHERE` keyword) from row filters.
   *
   * Filters AND together, matching {@link applyRowFilters}. A filter with no SQL form
   * contributes nothing rather than a neutral predicate. An unrecognized `dialect`
   * yields the empty string, since no filter is pushed at all.
   */
  buildWhereClause(filters: readonly RowFilter[], dialect?: SqlDialect | string): string {
    const profile = resolveProfile(dialect ?? this.dialect);
    if (profile === undefined) return "";

    const conditions: string[] = [];
    for (const filter of filters) {
      const condition = this.buildCondition(filter, profile);
      if (condition !== undefined) conditions.push(condition);
    }
    return conditions.join(" AND ");
  }

  /**
   * Render one row filter as a SQL condition, or undefined when it cannot be
   * pushed.
   *
   * Every condition is built to mean **exactly** what `applyRowFilters` means,
   * including where SQL's three-valued logic would otherwise differ. The negative
   * operators are the important case: post-fetch, a field present with a null value
   * satisfies `notEquals 'x'` and the row is KEPT, whereas plain SQL `col <> 'x'`
   * evaluates to unknown and DROPS it. An explicit `OR col IS NULL` keeps the two
   * paths agreeing, so pushing a filter down never changes which rows a caller
   * sees. (Spec §7 drops rows whose field is *absent*, not rows whose value is
   * null — those are different statements.)
   *
   * Returns undefined — leaving the filter to the post-fetch pass — for a field
   * name that is not a safe identifier, a value with no portable literal form, and
   * the operators with no portable SQL form. That is the safe direction: an omitted
   * condition costs transfer, never disclosure.
   *
   * It NEVER returns a neutral predicate for a filter it failed to build. a prior implementation
   * emitted `1=1` for a malformed `BETWEEN`, converting the most restrictive
   * possible outcome into no restriction at all — a fail-open. Where `1 = 0` or
   * `1 = 1` IS emitted here, it is the correct rendering of a filter whose meaning
   * is genuinely "no row" or "every row", matching the post pass exactly.
   */
  private buildCondition(
    filter: RowFilter,
    profile: DialectProfile,
  ): string | undefined {
    const leaf = leafIdentifier(filter.field, profile);
    if (leaf === undefined) {
      this.diagnose(
        `row filter on '${filter.field}' is not pushed into SQL: the field name is ` +
          "not a plain identifier for the " +
          `${profile.dialect} dialect; it is enforced after the fetch instead`,
      );
      return undefined;
    }

    const column = quoteIdentifier(leaf, profile);

    switch (filter.operator) {
      case FilterOperator.Equals: {
        // A null comparison value means "the field is null" post-fetch, but SQL
        // `col = NULL` is unknown for every row.
        if (filter.value === undefined || filter.value === null) {
          return `${column} IS NULL`;
        }
        return this.compare(column, "=", filter.value);
      }

      case FilterOperator.NotEquals: {
        if (filter.value === undefined || filter.value === null) {
          return `${column} IS NOT NULL`;
        }
        const base = this.compare(column, "<>", filter.value);
        if (base === undefined) return undefined;
        return `(${base} OR ${column} IS NULL)`;
      }

      case FilterOperator.GreaterThan:
        return this.compare(column, ">", filter.value);
      case FilterOperator.GreaterThanOrEqual:
        return this.compare(column, ">=", filter.value);
      case FilterOperator.LessThan:
        return this.compare(column, "<", filter.value);
      case FilterOperator.LessThanOrEqual:
        return this.compare(column, "<=", filter.value);

      case FilterOperator.In:
        return this.buildInCondition(column, filter, false);
      case FilterOperator.NotIn:
        return this.buildInCondition(column, filter, true);

      case FilterOperator.Like:
        return this.buildLikeCondition(column, filter.value, false);
      case FilterOperator.NotLike:
        return this.buildLikeCondition(column, filter.value, true);

      case FilterOperator.IsNull:
        return `${column} IS NULL`;
      case FilterOperator.IsNotNull:
        return `${column} IS NOT NULL`;

      case FilterOperator.Between:
        return this.buildBetweenCondition(column, filter);

      case FilterOperator.Contains:
      case FilterOperator.StartsWith:
      case FilterOperator.Matches:
        // contains/startsWith compare a value's STRING form regardless of its
        // declared type; the SQL equivalent needs a cast whose spelling differs by
        // engine ("AS TEXT" vs "AS CHAR"), and getting it wrong makes the query fail
        // rather than over-return. matches has no portable regex operator at all
        // (Postgres "~", MySQL "REGEXP", Trino "regexp_like") and its pattern
        // dialect differs even where an operator exists.
        this.diagnose(
          `row filter on '${filter.field}' with operator ${filter.operator} has no ` +
            "portable SQL form; it is enforced after the fetch instead",
        );
        return undefined;

      default:
        // An operator from a newer schema version. Declining to push it leaves
        // enforcement to the post-fetch pass, which fails closed (and warns) on an
        // operator it does not recognise.
        this.diagnose(
          `row filter on '${filter.field}' uses unrecognized operator ` +
            `${String(filter.operator)}; it is enforced after the fetch instead`,
        );
        return undefined;
    }
  }

  /**
   * Render a binary comparison, declining when the operand has no portable literal
   * form.
   */
  private compare(column: string, op: string, value: unknown): string | undefined {
    if (value === undefined || value === null) {
      // Post-fetch, an ordering comparison against null is not satisfiable by any
      // row (`rowPassesFilter` returns false), so this IS the faithful rendering.
      return ALWAYS_FALSE;
    }

    const literal = this.formatLiteral(value);
    if (literal === undefined) return undefined;

    return `${column} ${op} ${literal}`;
  }

  /**
   * Render an `IN` or `NOT IN` condition from `values`.
   *
   * Mirrors the post-fetch pass exactly, including its degenerate cases: an absent
   * `values` array admits no row for `in` and every row for `notIn`, and an empty
   * array behaves the same. A list containing null is declined, because SQL
   * `NOT IN (NULL, ...)` is never true and would drop rows the post pass keeps.
   */
  private buildInCondition(
    column: string,
    filter: RowFilter,
    negated: boolean,
  ): string | undefined {
    const values = filter.values;

    if (values === undefined || values.length === 0) {
      return negated ? ALWAYS_TRUE : ALWAYS_FALSE;
    }

    const literals: string[] = [];
    for (const value of values) {
      if (value === undefined || value === null) {
        this.diagnose(
          `row filter on '${filter.field}' is not pushed into SQL: a null entry in ` +
            "values has no SQL IN equivalent; it is enforced after the fetch instead",
        );
        return undefined;
      }
      const literal = this.formatLiteral(value);
      if (literal === undefined) return undefined;
      literals.push(literal);
    }

    const list = literals.join(", ");
    return negated
      // NOT IN drops a null-valued row; the post-fetch pass keeps it.
      ? `(${column} NOT IN (${list}) OR ${column} IS NULL)`
      : `${column} IN (${list})`;
  }

  /**
   * Render a `LIKE` or `NOT LIKE` condition.
   *
   * The pattern is already a SQL `LIKE` pattern, so it passes through as a literal
   * with no wildcard translation. A pattern containing a backslash is declined by
   * {@link formatLiteral}: MySQL treats one as a string escape by default while
   * Postgres does not, so the same text would mean different things in the two
   * engines. That also declines the escape form `like '100\%'`, which is correct —
   * the post pass handles it, and emitting text whose meaning is dialect-dependent
   * would make the two paths disagree.
   */
  private buildLikeCondition(
    column: string,
    value: unknown,
    negated: boolean,
  ): string | undefined {
    if (value === undefined || value === null) {
      // Post-fetch, a null pattern is a non-match for both like and notLike.
      return ALWAYS_FALSE;
    }

    const literal = this.formatLiteral(value);
    if (literal === undefined) return undefined;

    // NOT LIKE needs no IS NULL arm: SQL and the post pass agree that a
    // null-valued row is dropped.
    return negated ? `${column} NOT LIKE ${literal}` : `${column} LIKE ${literal}`;
  }

  /**
   * Render an inclusive `BETWEEN` from the first two entries of `values`.
   *
   * Bounds are emitted in the order written. An inverted range matches nothing, in
   * SQL and post-fetch alike; silently reordering it would turn an author's typo
   * into a wider grant than the policy states.
   */
  private buildBetweenCondition(
    column: string,
    filter: RowFilter,
  ): string | undefined {
    const values = filter.values;

    if (values === undefined || values.length < 2) {
      // A malformed range is satisfiable by no row post-fetch, so `1 = 0` is the
      // faithful rendering. A prior implementation emitted `1=1` here -- a neutral predicate that
      // turned a filter it failed to build into no restriction at all.
      this.diagnose(
        `row filter on '${filter.field}' uses between with fewer than two bounds; ` +
          "no row can satisfy it",
      );
      return ALWAYS_FALSE;
    }

    const [low, high] = values;
    if (low === undefined || low === null || high === undefined || high === null) {
      return ALWAYS_FALSE;
    }

    const lowLiteral = this.formatLiteral(low);
    const highLiteral = this.formatLiteral(high);
    if (lowLiteral === undefined || highLiteral === undefined) return undefined;

    return `${column} BETWEEN ${lowLiteral} AND ${highLiteral}`;
  }

  // -----------------------------------------------------------------------
  // Literals
  // -----------------------------------------------------------------------

  /**
   * Render a policy value as a SQL literal, or undefined when it has no safe
   * portable form.
   *
   * **Escaping is not sufficient; refusal is.** Doubling `'` is correct ANSI
   * escaping but not sufficient on its own: MySQL by default also treats `\` as an
   * escape inside a string literal, so `'\''` leaves the literal open and the rest
   * of the policy value becomes statement text. Rather than emit a
   * dialect-conditional escape, a string containing a backslash is refused outright
   * and the filter falls back to the post-fetch pass. Control characters —
   * including NUL, which truncates the statement for some client libraries, and
   * newlines, which end a `--` comment — are refused for the same reason.
   *
   * Numbers are rendered explicitly rather than by coercion. `String(1e21)` is
   * `"1e+21"`, which is not a portable numeric literal, and `String(-0)` is `"0"`,
   * which silently changes the value's sign. Both are refused/normalised here
   * rather than emitted.
   */
  private formatLiteral(value: unknown): string | undefined {
    // Unreachable from the current callers: compare, buildInCondition, and
    // buildBetweenCondition each handle null before getting here, because SQL needs
    // IS NULL rather than "= NULL". Retained so a future caller cannot emit the
    // string "null" as a value.
    /* c8 ignore next */
    if (value === null || value === undefined) return "NULL";

    switch (typeof value) {
      case "string":
        return this.formatStringLiteral(value);

      case "boolean":
        return value ? "TRUE" : "FALSE";

      case "number":
        return this.formatNumberLiteral(value);

      case "bigint":
        // An arbitrary-precision integer always has an exact decimal form.
        return value.toString();

      default:
        break;
    }

    if (value instanceof Date) {
      const time = value.getTime();
      if (Number.isNaN(time)) {
        this.diagnose(
          "an Invalid Date has no SQL literal form; the filter is left to the " +
            "post-fetch pass",
        );
        return undefined;
      }
      // ISO-8601 with a space separator and no timezone suffix: the form every
      // target engine parses as a timestamp. `toISOString` is always UTC, so this
      // does not depend on the host's timezone.
      return `'${value.toISOString().replace("T", " ").replace("Z", "")}'`;
    }

    // A plain object, array, function, or symbol is not a scalar comparand. Its
    // string form is not known to be a valid literal in any dialect, so it is not
    // guessed at.
    this.diagnose(
      `a value of type ${describeValueType(value)} has no known SQL literal form; ` +
        "the filter is left to the post-fetch pass",
    );
    return undefined;
  }

  /**
   * Render a string as a quoted literal, or undefined when it contains a character
   * that cannot be escaped identically across dialects.
   *
   * **The refusal is uniform across every profile, including the ones where `\` is not
   * an escape** (connector spec §5.1 rule 5). Two reasons: a policy must behave
   * identically on every engine, so a filter unpushable on MySQL must be unpushable on
   * Postgres too; and a single profile treating `\` as an escape is enough to make
   * escaping unsafe to generalize. The profile is deliberately not a parameter here.
   */
  private formatStringLiteral(value: string): string | undefined {
    for (const ch of value) {
      const code = ch.codePointAt(0)!;
      // Backslash: a string escape in MySQL by default, a literal in Postgres.
      // C0/C1 control characters: NUL truncates a statement for some clients, and
      // \n or \r terminates a `--` comment, turning the tail of a value into code.
      if (ch === "\\" || code < 0x20 || (code >= 0x7f && code <= 0x9f)) {
        this.diagnose(
          "a string value is refused as a SQL literal: it contains a backslash or " +
            "a control character, which do not escape identically across engines; " +
            "the filter is left to the post-fetch pass",
        );
        return undefined;
      }
    }

    // Correct ANSI escaping, applied only to text already shown to contain nothing
    // else structural.
    return `'${value.replaceAll("'", "''")}'`;
  }

  /** Render a number as a portable SQL numeric literal, or undefined. */
  private formatNumberLiteral(value: number): string | undefined {
    if (!Number.isFinite(value)) {
      // NaN and +/-Infinity have no portable literal (Postgres accepts
      // 'NaN'::float, MySQL does not) and post-fetch NaN compares as a non-match.
      this.diagnose(
        `the numeric value ${String(value)} has no portable SQL literal form; the ` +
          "filter is left to the post-fetch pass",
      );
      return undefined;
    }

    // -0 must not be rendered as "0": String(-0) === "0" silently discards the sign.
    // SQL has no signed zero, so the two are equal there anyway -- but rendering it
    // as "-0.0" keeps the emitted text an honest transcription of the input.
    if (Object.is(value, -0)) return "-0.0";

    if (Number.isInteger(value)) {
      // Integers outside the exactly-representable range print in exponent form
      // (String(1e21) === "1e+21"), which is not a portable numeric literal, and the
      // value was already imprecise before it got here. Refuse rather than emit a
      // number that is not the one the policy author wrote.
      if (!Number.isSafeInteger(value)) {
        this.diagnose(
          `the integer ${String(value)} is outside the exactly-representable range ` +
            "and has no portable literal form; the filter is left to the post-fetch " +
            "pass",
        );
        return undefined;
      }
      return value.toString();
    }

    // A finite non-integer. `toString` uses exponent form below 1e-6 and at or
    // above 1e21; neither is portable, so those are refused too.
    const rendered = value.toString();
    if (rendered.includes("e") || rendered.includes("E")) {
      this.diagnose(
        `the number ${rendered} renders in exponent form, which is not a portable ` +
          "SQL literal; the filter is left to the post-fetch pass",
      );
      return undefined;
    }
    return rendered;
  }

  private diagnose(message: string): void {
    this.diagnostics?.(message);
  }
}

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

/**
 * The unqualified, emit-safe form of a policy field reference, or undefined when it
 * is not a plain identifier.
 *
 * The qualifier is stripped rather than emitted as `"table"."column"`: TOLAP's own
 * field matching already treats `patients.region` and `region` as the same field
 * (spec §4), and a qualifier naming the table would not resolve against a query
 * that aliases it (`FROM patients p`). A bare column resolves under either
 * spelling, and is ambiguous only in a join — where the database reports the
 * ambiguity rather than silently filtering the wrong column.
 *
 * A *wrapping* quote character is unwrapped first, in any engine's style, so a policy
 * may spell a field as `"region"`, `` `region` `` or `[region]` and still resolve:
 * those characters are delimiters, not part of the name.
 *
 * What remains is then checked against the profile's **own** quote characters and
 * declined if it contains one (connector spec §5.1 rule 4). A name that is not a safe
 * identifier is **declined, not escaped** — a field named `region"; DROP TABLE x --`
 * cannot reach the emitted SQL at all.
 */
function leafIdentifier(field: unknown, profile: DialectProfile): string | undefined {
  if (typeof field !== "string" || field.trim() === "") return undefined;

  let leaf = field.trim();
  const lastDot = leaf.lastIndexOf(".");
  if (lastDot >= 0) leaf = leaf.slice(lastDot + 1);

  leaf = trimChars(leaf, "\"`[] ");

  // The profile's own delimiter, anywhere in what is left, is declined rather than
  // escaped by doubling: the doubling rule is not even the same in every engine, and a
  // name that needs escaping is a name we should refuse to emit.
  if (quoteChars(profile).some((ch) => leaf.includes(ch))) return undefined;

  return SAFE_IDENTIFIER_PATTERN.test(leaf) ? leaf : undefined;
}

/**
 * Quote an identifier already validated by {@link leafIdentifier}.
 *
 * Plain delimiting, with no escaping: {@link leafIdentifier} has already declined any
 * name carrying the profile's quote character, so there is nothing here to escape. That
 * is deliberate — doubling the quote is exactly what connector spec §5.1 rule 4
 * forbids.
 */
function quoteIdentifier(identifier: string, profile: DialectProfile): string {
  return profile.quoteOpen + identifier + profile.quoteClose;
}

/** Trim every character in `chars` from both ends, like .NET's `String.Trim(char[])`. */
function trimChars(value: string, chars: string): string {
  let start = 0;
  let end = value.length;
  while (start < end && chars.includes(value[start]!)) start++;
  while (end > start && chars.includes(value[end - 1]!)) end--;
  return value.slice(start, end);
}

/** A human-readable type name, for a decline message. */
function describeValueType(value: unknown): string {
  if (Array.isArray(value)) return "array";
  if (typeof value === "object") {
    const name = (value as object).constructor?.name;
    return name ? name : "object";
  }
  return typeof value;
}

// ---------------------------------------------------------------------------
// Field extraction (validateQuery)
// ---------------------------------------------------------------------------

/**
 * Every field name the query mentions in its SELECT, WHERE, ORDER BY, GROUP BY, or
 * HAVING clauses.
 */
function extractReferencedFields(query: string): Set<string> {
  const fields = new Set<string>();

  const span = findSelectListSpan(query);
  if (span !== undefined) {
    const selectList = query.slice(span.start, span.start + span.length);
    for (const entry of splitTopLevel(selectList)) {
      addField(fields, extractFieldName(entry));
    }
    // A field wrapped in an aggregate would otherwise be extracted as the whole
    // expression ("max(ssn)"), which matches no policy field and is then skipped by
    // the allow-list check for containing a parenthesis.
    addFieldsFromFunctionArguments(selectList, fields);
  }

  addFieldsFromConditionClause(query, WHERE_CLAUSE_PATTERN, fields);
  addFieldsFromOrderBy(query, fields);
  addFieldsFromCommaSeparatedClause(query, GROUP_BY_CLAUSE_PATTERN, fields);
  addFieldsFromConditionClause(query, HAVING_CLAUSE_PATTERN, fields);

  return fields;
}

/**
 * Record a field name, skipping keywords, numeric literals, and empty strings.
 *
 * The keyword and numeric checks are what keep `CAST(id AS text)` from being read as
 * a reference to a column called `text`, and `round(price, 2)` from being read as a
 * reference to a column called `2`. A prior implementation rejected both as non-allowed columns.
 */
function addField(fields: Set<string>, name: string): void {
  if (name === "") return;
  if (SQL_KEYWORDS.has(name.toUpperCase())) return;
  // A leading digit cannot start an identifier, so this is a literal.
  if (/^\d/.test(name)) return;
  fields.add(name);
}

/**
 * Add the field names on the left of a comparison in a WHERE or HAVING clause.
 */
function addFieldsFromConditionClause(
  query: string,
  clausePattern: RegExp,
  fields: Set<string>,
): void {
  const clauseMatch = clausePattern.exec(query);
  if (clauseMatch === null) return;

  // Group 1 is the clause body, always present when the clause pattern matches.
  const body = clauseMatch[1]!;

  for (const match of matchAll(body, QUALIFIED_COLUMN_COMPARISON_PATTERN)) {
    // Group 1 is the quoted form, group 2 the unquoted one.
    addField(fields, match.groups[1] ?? match.groups[2]!);
  }

  for (const match of matchAll(body, COLUMN_COMPARISON_PATTERN)) {
    addField(fields, match.groups[1]!);
  }

  addFieldsFromFunctionArguments(body, fields);
}

/**
 * Add the field names inside a function call's argument list.
 *
 * A field wrapped in an aggregate is not on the left of any comparison operator, so
 * the comparison patterns never see it: `HAVING max(ssn) > '1'` presents `)` as the
 * left operand. Left unextracted, a hidden field can be used to choose which rows
 * are returned — the aggregate's value is disclosed by the row set even though the
 * field is absent from the projection. This is a defect observed in a prior implementation, not a
 * hypothetical: `HAVING max(ssn) > '1'` passed validation in a prior implementation with `ssn` hidden.
 *
 * String literals are removed first so a value is not mistaken for a field name.
 */
function addFieldsFromFunctionArguments(body: string, fields: Set<string>): void {
  const withoutLiterals = body.replace(STRING_LITERAL_PATTERN, " ");

  for (const call of matchAll(withoutLiterals, FUNCTION_CALL_PATTERN)) {
    for (const word of matchAll(call.groups[2]!, WORD_PATTERN)) {
      addField(fields, word.groups[0]!);
    }
  }
}

/** Add the field names in an ORDER BY clause, discarding ASC/DESC and NULLS suffixes. */
function addFieldsFromOrderBy(query: string, fields: Set<string>): void {
  const clauseMatch = ORDER_BY_CLAUSE_PATTERN.exec(query);
  if (clauseMatch === null) return;

  for (const part of clauseMatch[1]!.split(",")) {
    const trimmed = part.trim().replace(ORDER_BY_SUFFIX_PATTERN, "").trim();
    if (trimmed === "") continue;
    addField(fields, extractFieldName(trimmed));
  }
}

/** Add the field names in a comma-separated clause whose entries are plain references. */
function addFieldsFromCommaSeparatedClause(
  query: string,
  clausePattern: RegExp,
  fields: Set<string>,
): void {
  const clauseMatch = clausePattern.exec(query);
  if (clauseMatch === null) return;

  for (const part of clauseMatch[1]!.split(",")) {
    const trimmed = part.trim();
    if (trimmed === "") continue;
    addField(fields, extractFieldName(trimmed));
  }
}

/**
 * The field name a select-list or clause entry refers to: alias and table qualifier
 * removed, quotes stripped.
 *
 * A call expression is returned whole. A prior implementation split on the last dot unconditionally,
 * so `round(1.5)` yielded `5)` — a nonsense "column" that matched no allow-list
 * entry and made a perfectly legal query fail validation. Returning the whole
 * expression lets the allow-list check skip it (it contains a parenthesis) while
 * {@link addFieldsFromFunctionArguments} extracts the real field references from
 * inside it.
 */
function extractFieldName(expression: string): string {
  let expr = expression.trim();

  const asIndex = expr.toUpperCase().indexOf(" AS ");
  if (asIndex > 0) expr = expr.slice(0, asIndex).trim();

  // Only strip a qualifier when the expression is a plain dotted reference. A dot
  // inside a call expression is part of a numeric literal or a nested reference,
  // not a table qualifier.
  if (!expr.includes("(")) {
    const dotIndex = expr.lastIndexOf(".");
    if (dotIndex > 0) expr = expr.slice(dotIndex + 1).trim();
  }

  return trimChars(expr, "\"'` ");
}

// ---------------------------------------------------------------------------
// Lightweight SQL structure scanning
// ---------------------------------------------------------------------------

interface ScanMatch {
  index: number;
  length: number;
  groups: Array<string | undefined>;
}

/**
 * Iterate every match of a pattern without leaking `lastIndex` state.
 *
 * Every pattern passed here is declared with `g` at module scope; the flag set is
 * normalised anyway so a caller cannot accidentally pass a non-global pattern and
 * get an infinite loop out of `exec`.
 */
function matchAll(input: string, pattern: RegExp): ScanMatch[] {
  // A fresh RegExp per call: the module-level patterns are shared, and a global
  // regex carries `lastIndex` between uses, so reusing one would make results depend
  // on call order. Deduplicating the flags keeps "gi" + "g" from becoming "ggi",
  // which RegExp rejects.
  const flags = [...new Set(`${pattern.flags}g`)].join("");
  const local = new RegExp(pattern.source, flags);
  const out: ScanMatch[] = [];
  let match: RegExpExecArray | null;
  while ((match = local.exec(input)) !== null) {
    out.push({ index: match.index, length: match[0].length, groups: [...match] });
    // Unreachable with the patterns in this module -- every one requires at least
    // one character -- but a zero-length match would otherwise spin forever, so the
    // guard stays rather than trusting every future pattern to be non-empty.
    /* c8 ignore next */
    if (match[0].length === 0) local.lastIndex++;
  }
  return out;
}

/**
 * The offset and length of the statement's select list — everything between its
 * top-level `SELECT` and its top-level `FROM`.
 */
function findSelectListSpan(
  query: string,
): { start: number; length: number } | undefined {
  const scan = new SqlScan(query);

  const select = scan.firstTopLevel(SELECT_KEYWORD);
  if (select === undefined) return undefined;

  const listStart = select.index + select.length;

  const from = scan.firstTopLevelAfter(FROM_KEYWORD, listStart);
  if (from === undefined) return undefined;

  // Keep the surrounding whitespace out of the span so a replacement does not have
  // to reproduce it.
  let start = listStart;
  while (start < from.index && /\s/.test(query[start]!)) start++;

  let end = from.index;
  while (end > start && /\s/.test(query[end - 1]!)) end--;

  return end <= start ? undefined : { start, length: end - start };
}

/**
 * Split a comma-separated list on the commas at parenthesis depth zero, so a
 * function call's own arguments are not split apart.
 */
function splitTopLevel(list: string): string[] {
  const entries: string[] = [];
  const scan = new SqlScan(list);
  let current = "";

  for (let i = 0; i < list.length; i++) {
    if (list[i] === "," && scan.isTopLevel(i)) {
      entries.push(current.trim());
      current = "";
      continue;
    }
    current += list[i];
  }

  if (current.length > 0) entries.push(current.trim());

  return entries;
}

/**
 * The offset at which a fresh `WHERE` clause belongs.
 *
 * The **earliest by index** top-level clause that must follow `WHERE`, or the end of
 * the statement with any trailing semicolon and whitespace excluded. Taking the
 * earliest rather than the first pattern to match is what keeps
 * `GROUP BY x ORDER BY y` from producing `GROUP BY x WHERE ... ORDER BY y`.
 */
function findWhereInsertPoint(query: string, scan: SqlScan): number {
  let earliest = Number.MAX_SAFE_INTEGER;
  for (const pattern of POST_FROM_CLAUSES) {
    const match = scan.firstTopLevel(pattern);
    if (match !== undefined && match.index < earliest) earliest = match.index;
  }

  if (earliest !== Number.MAX_SAFE_INTEGER) {
    // Back up over the whitespace before the clause. The injected text carries its
    // own leading space, so inserting at the clause's own offset would strand the
    // original separator on the left and leave none on the right:
    // "FROM patients  WHERE ...GROUP BY region".
    while (earliest > 0 && /\s/.test(query[earliest - 1]!)) earliest--;
    return earliest;
  }

  return query.trimEnd().replace(/;\s*$/, "").trimEnd().length;
}

/**
 * A per-character map of a query's parenthesis depth and literal spans, so keyword
 * matches can be restricted to the outermost statement.
 *
 * Without this a subquery donates the match that governs the outer statement: the
 * `WHERE` in `SELECT * FROM t WHERE id IN (SELECT id FROM u WHERE x = 1)` is found
 * twice, and a prior implementation replaced the FIRST one — which for
 * `SELECT * FROM t WHERE id IN (SELECT ...)` injected the security filter into the
 * *subquery* and left the outer result completely unrestricted. String literals and
 * quoted identifiers are skipped so a parenthesis or the word `where` inside a
 * literal changes nothing.
 */
class SqlScan {
  private readonly query: string;
  private readonly depth: Int32Array;
  private readonly inLiteral: Uint8Array;

  constructor(query: string) {
    this.query = query;
    this.depth = new Int32Array(query.length);
    this.inLiteral = new Uint8Array(query.length);

    let depth = 0;
    let inString = false;
    let inQuotedIdentifier = false;

    for (let i = 0; i < query.length; i++) {
      const ch = query[i];

      if (inString) {
        this.inLiteral[i] = 1;
        this.depth[i] = depth;
        if (ch === "'") {
          // '' is an escaped quote, not the end of the literal.
          if (i + 1 < query.length && query[i + 1] === "'") {
            i++;
            this.inLiteral[i] = 1;
            this.depth[i] = depth;
          } else {
            inString = false;
          }
        }
        continue;
      }

      if (inQuotedIdentifier) {
        this.inLiteral[i] = 1;
        this.depth[i] = depth;
        if (ch === '"') {
          if (i + 1 < query.length && query[i + 1] === '"') {
            i++;
            this.inLiteral[i] = 1;
            this.depth[i] = depth;
          } else {
            inQuotedIdentifier = false;
          }
        }
        continue;
      }

      if (ch === "'") {
        inString = true;
        this.inLiteral[i] = 1;
      } else if (ch === '"') {
        inQuotedIdentifier = true;
        this.inLiteral[i] = 1;
      } else if (ch === "(") {
        depth++;
      } else if (ch === ")") {
        // Guarded so an unbalanced query cannot drive the depth negative and make
        // an inner keyword look top-level.
        if (depth > 0) depth--;
      }

      this.depth[i] = depth;
    }
  }

  /** Whether the character at an offset is outside every paren and literal. */
  isTopLevel(index: number): boolean {
    return (
      index >= 0 &&
      index < this.depth.length &&
      this.depth[index] === 0 &&
      this.inLiteral[index] === 0
    );
  }

  /** The first match of a pattern at top level, or undefined. */
  firstTopLevel(pattern: RegExp): ScanMatch | undefined {
    return this.firstTopLevelAfter(pattern, 0);
  }

  /** The first match of a pattern at top level at or after an offset, or undefined. */
  firstTopLevelAfter(pattern: RegExp, startAt: number): ScanMatch | undefined {
    for (const match of matchAll(this.query, pattern)) {
      if (match.index < startAt) continue;
      if (this.isTopLevel(match.index)) return match;
    }
    return undefined;
  }

  /** The last match of a pattern at top level, or undefined. */
  lastTopLevel(pattern: RegExp): ScanMatch | undefined {
    let found: ScanMatch | undefined;
    for (const match of matchAll(this.query, pattern)) {
      if (this.isTopLevel(match.index)) found = match;
    }
    return found;
  }
}
