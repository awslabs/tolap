/**
 * Validate every table and column a SQL query references, before it runs.
 *
 * {@link validateQueryReferences} is one of the pre-execution checks
 * `prepareSqlQuery` runs. It resolves the tables a query reads -- `FROM` and
 * `JOIN` items, comma-joined tables and derived tables -- into an alias map,
 * checks each table with {@link validateAccess}, and resolves each column
 * reference through that map so the field rules apply to the table the column
 * actually belongs to.
 *
 * The check is deliberately conservative. It does not parse SQL in general; it
 * recognises a common subset of `SELECT` and refuses, with a reason, any construct
 * it cannot resolve (common table expressions, set operations, subqueries outside
 * `FROM`, `LATERAL`, table-valued functions and so on). Refusing is the safe
 * answer: a construct the check cannot see into is one whose tables it cannot
 * vouch for.
 *
 * A query that reads exactly one table still goes through the existing single-table
 * checks (the object check and `validateQuery`). This check adds to them: it
 * validates that table's access and checks every column the query references, so it
 * can refuse a query they allow but never allow one they refuse.
 *
 * Lexing differs between engines: a backslash escapes a quote in MySQL but not in
 * standard SQL, `#` starts a comment only in MySQL, and block comments nest only in
 * PostgreSQL. So the query is tokenized under each of those conventions and must
 * pass under every one of them.
 *
 * The Python (`sql_references.py`) and .NET (`SqlQueryReferences.cs`) counterparts
 * implement the same rules, pinned by `fixtures/enforcement/sql-multi-table.json`.
 */

import type { AccessResult, EffectivePolicy } from "./types.js";
import { allowedFieldMatches, fieldNameMatches, validateAccess } from "./enforcement.js";

/** The reason given when a column reference is refused, shared with `validateQuery`. */
export const FIELD_DENIAL_REASON =
  "query references fields you do not have permission to access";

/** Prefix of the reason given when the query uses a construct the check refuses. */
export const UNSUPPORTED_REASON_PREFIX =
  "query uses a construct the pre-execution check cannot resolve: ";

/** The reason given when a supplied object name and the query's one table differ. */
export const OBJECT_MISMATCH_REASON = "object name does not match the table the query reads";

// Derived tables nest; each level recurses once. Real queries stay far below this.
const MAX_NESTING = 32;

function asciiLower(text: string): string {
  return text.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32));
}

// Keywords are ASCII to every engine, so words are upper-cased ASCII-only: a
// Unicode case mapping would read "ſelect" (long s) as SELECT.
function asciiUpper(text: string): string {
  return text.replace(/[a-z]/g, (c) => String.fromCharCode(c.charCodeAt(0) - 32));
}

const WHITESPACE = new Set([" ", "\t", "\n", "\r", "\f", "\v"]);

// Unicode whitespace some engines accept as a separator. Treating one as part of a
// word would hide a keyword, so its presence outside a literal is refused.
const UNICODE_SPACES = new Set(
  "\u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008" +
    "\u2009\u200a\u200b\u2028\u2029\u202f\u205f\u3000\ufeff",
);

type Mode = "ansi" | "mysql" | "postgres";
const MODES: Mode[] = ["ansi", "mysql", "postgres"];

const words = (text: string): Set<string> => new Set(text.split(/\s+/).filter(Boolean));

// Words never taken for a column when bare. Deliberately narrow: an unrecognised
// word is checked as a column, which can refuse a query but never admits one.
const KEYWORDS = words(
  "ALL AND ANY ARRAY AS ASC AT BETWEEN BOTH BY CASE CAST COLLATE CROSS CURRENT " +
    "CURRENT_CATALOG CURRENT_DATE CURRENT_ROLE CURRENT_SCHEMA CURRENT_TIME " +
    "CURRENT_TIMESTAMP CURRENT_USER DEFAULT DESC DISTINCT DIV ELSE END ESCAPE " +
    "EVERY EXCLUDE EXISTS FALSE FETCH FILTER FIRST FOLLOWING FROM FULL GLOB " +
    "GROUP GROUPS HAVING ILIKE IN INNER INTERVAL IS ISNULL JOIN LAST LEADING " +
    "LEFT LIKE LIMIT LOCALTIME LOCALTIMESTAMP MOD NATURAL NEXT NO NOT NOTNULL " +
    "NULL NULLS OFFSET ON ONLY OR ORDER ORDINALITY OTHERS OUTER OVER PARTITION " +
    "PRECEDING PRECISION RANGE REGEXP RLIKE ROW ROWS SELECT SEPARATOR " +
    "SESSION_USER SIGNED SIMILAR SOME TABLE THEN TIES TO TRAILING TRUE UNBOUNDED " +
    "UNKNOWN UNSIGNED USING VALUES VARYING WHEN WHERE WITH WITHIN WITHOUT XOR ZONE " +
    "ROLLUP CUBE SETS",
);

// Units that may follow INTERVAL or precede FROM inside EXTRACT(...).
const DATE_PARTS = words(
  "CENTURY DAY DAYS DECADE DOW DOY EPOCH HOUR HOURS ISODOW ISOYEAR JULIAN " +
    "MICROSECOND MICROSECONDS MILLENNIUM MILLISECOND MILLISECONDS MINUTE MINUTES " +
    "MONTH MONTHS QUARTER SECOND SECONDS TIMEZONE TIMEZONE_HOUR TIMEZONE_MINUTE " +
    "WEEK WEEKS YEAR YEARS",
);

// Reserved words that end the FROM clause and start another clause.
const TAIL_CLAUSES = words("WHERE GROUP HAVING ORDER LIMIT OFFSET FETCH FOR WINDOW WITH");

// Tail clauses whose content is read for column references, and those skipped.
const CHECKED_TAIL = words("WHERE GROUP HAVING ORDER");
const SKIPPED_TAIL = words("LIMIT OFFSET FETCH FOR");

// The words a skipped tail clause may hold: LIMIT ALL, OFFSET 5 ROWS, FETCH FIRST 5
// ROWS WITH TIES, FOR NO KEY UPDATE SKIP LOCKED, LOCK IN SHARE MODE. Anything else
// means a column was taken for the clause keyword (MySQL's WHERE offset = 7), so the
// clause is refused rather than left unread.
const SKIPPED_TAIL_WORDS = words(
  "ALL FIRST NEXT ROW ROWS ONLY WITH TIES PERCENT UPDATE SHARE NO KEY NOWAIT " +
    "SKIP LOCKED LOCK IN MODE",
);

const JOIN_WORDS = words("JOIN INNER LEFT RIGHT FULL CROSS NATURAL OUTER STRAIGHT_JOIN");

// Words refused as a table alias. Beyond the join and clause words these are the
// engine-specific table modifiers (hints, sampling, pivots, partitions); taking
// one for an alias would let what follows it go unread, so it is refused instead.
const NOT_AN_ALIAS = new Set([
  ...JOIN_WORDS,
  ...TAIL_CLAUSES,
  ...words(
    "ON USING AS APPLY LATERAL USE FORCE IGNORE PARTITION QUALIFY CONNECT " +
      "START LOCK PIVOT UNPIVOT MODEL SAMPLE TABLESAMPLE RETURNING OPTION " +
      "PROCEDURE INTO UNION INTERSECT EXCEPT MINUS",
  ),
]);

const SET_OPERATIONS = words("UNION INTERSECT EXCEPT MINUS");

const SELECT_MODIFIERS = words(
  "ALL DISTINCTROW SQL_CALC_FOUND_ROWS STRAIGHT_JOIN HIGH_PRIORITY SQL_NO_CACHE " +
    "SQL_CACHE SQL_SMALL_RESULT SQL_BIG_RESULT SQL_BUFFER_RESULT",
);

// The value an operand can end with, before a bare alias.
const OPERAND_END_KEYWORDS = words("END NULL TRUE FALSE UNKNOWN");

// Words reserved on every modelled engine, so never a bare column: skipped wherever
// they appear in an expression. Every other word is a keyword only in a position
// (see Analysis.bare); anywhere else it is checked as a column. TRUE and FALSE are
// reserved everywhere but SQL Server, where a column so named is taken for the literal.
const RESERVED = words(
  "AND CASE CROSS CURRENT_DATE CURRENT_TIME CURRENT_TIMESTAMP CURRENT_USER " +
    "DISTINCT ELSE FALSE FOR FROM GROUP HAVING IN INNER IS JOIN LEFT LIKE NOT NULL " +
    "ON OR ORDER OUTER THEN TRUE WHEN WHERE WITH",
);

// Reserved words that are themselves a value, so a word after one is not an operand.
const RESERVED_VALUES = words(
  "CURRENT_DATE CURRENT_TIME CURRENT_TIMESTAMP CURRENT_USER NULL TRUE FALSE",
);

// Keywords that follow another keyword: ORDER BY, NULLS LAST, SIMILAR TO, WITH ROLLUP,
// AT TIME ZONE, a window frame's UNBOUNDED PRECEDING and CURRENT ROW. None of the
// first words is ever followed by an expression, so the second is never a column.
const KEYWORD_PAIRS = new Map<string, Set<string>>([
  ["ORDER", words("BY")],
  ["GROUP", words("BY")],
  ["PARTITION", words("BY")],
  ["ASC", words("NULLS SEPARATOR ROWS RANGE GROUPS")],
  ["DESC", words("NULLS SEPARATOR ROWS RANGE GROUPS")],
  ["FIRST", words("SEPARATOR ROWS RANGE GROUPS")],
  ["LAST", words("SEPARATOR ROWS RANGE GROUPS")],
  ["IGNORE", words("NULLS")],
  ["RESPECT", words("NULLS")],
  ["NULLS", words("FIRST LAST")],
  ["SIMILAR", words("TO")],
  ["WITH", words("ROLLUP CUBE TIME")],
  ["WITHOUT", words("TIME")],
  ["AT", words("TIME LOCAL")],
  ["ROWS", words("BETWEEN UNBOUNDED CURRENT")],
  ["RANGE", words("BETWEEN UNBOUNDED CURRENT")],
  ["GROUPS", words("BETWEEN UNBOUNDED CURRENT")],
  ["UNBOUNDED", words("PRECEDING FOLLOWING")],
  ["CURRENT", words("ROW")],
  ["EXCLUDE", words("CURRENT TIES NO")],
  ["NO", words("OTHERS")],
]);

// The words that may follow an operand: infix and postfix operators, a sort order, a
// unit after a number (MySQL's INTERVAL 7 DAY_HOUR), and the rest of a cast's type
// name. A select item's alias is removed before its expression is walked, so any other
// word after an operand is read as a column: MySQL's INTERVAL zone HOUR reads zone.
const AFTER_OPERAND = words(
  "ILIKE REGEXP RLIKE GLOB SIMILAR BETWEEN ESCAPE DIV MOD XOR SOUNDS OVERLAPS " +
    "ASC DESC NULLS AT FILTER WITHIN RESPECT IGNORE SEPARATOR PRECEDING FOLLOWING " +
    "ROWS RANGE GROUPS PRECISION VARYING INTEGER INT " +
    "SECOND_MICROSECOND MINUTE_MICROSECOND MINUTE_SECOND HOUR_MICROSECOND " +
    "HOUR_SECOND HOUR_MINUTE DAY_MICROSECOND DAY_SECOND DAY_MINUTE DAY_HOUR YEAR_MONTH",
);

// Operators written as a word after NOT: a NOT LIKE b, a NOT BETWEEN b AND c.
const NEGATED_OPERATORS = words("LIKE ILIKE REGEXP RLIKE GLOB SIMILAR BETWEEN IN");

// The words recognised directly before a string literal: national (N), escape (E),
// hex (X), bit or bytes (B), raw (R, RB, BR) and typed literals. A MySQL character
// set introducer (_utf8mb4) is recognised by its leading underscore. Any other word
// directly before a quote is a form the check does not model, so it is refused.
const LITERAL_PREFIXES = words("N E X B R RB BR DATE TIME TIMESTAMP");

// A numeric literal: digits (with PostgreSQL's digit separators), an optional
// fraction and exponent, or a hex or binary literal. A token that starts with a digit
// and is none of these is an identifier some engines accept (MySQL's 1abc), which
// would otherwise go unread as a column.
const NUMBER =
  /^(?:(?:[0-9][0-9_]*(?:\.[0-9_]*)?|\.[0-9][0-9_]*)(?:[eE][+-]?[0-9]+)?|0[xX][0-9a-fA-F]+|0[bB][01]+)$/;

class Unsupported extends Error {
  constructor(readonly construct: string) {
    super(construct);
  }
}

class FieldDenied extends Error {}

type TokKind = "word" | "qident" | "string" | "number" | "param" | "punct";

class Tok {
  constructor(
    readonly kind: TokKind,
    // The word, the unquoted identifier, or the punctuation character.
    readonly text: string,
  ) {}

  get fold(): string {
    return asciiLower(this.text);
  }

  get upper(): string {
    return this.kind === "word" ? asciiUpper(this.text) : "";
  }

  isWord(...candidates: string[]): boolean {
    return this.kind === "word" && candidates.includes(asciiUpper(this.text));
  }

  isPunct(char: string): boolean {
    return this.kind === "punct" && this.text === char;
  }

  get isIdent(): boolean {
    return this.kind === "word" || this.kind === "qident";
  }
}

// ---------------------------------------------------------------------------
// Lexing
// ---------------------------------------------------------------------------

function isWordStart(ch: string): boolean {
  return (
    (ch >= "a" && ch <= "z") || (ch >= "A" && ch <= "Z") || ch === "_" || ch.charCodeAt(0) >= 0x80
  );
}

function isDigit(ch: string): boolean {
  return ch >= "0" && ch <= "9";
}

function isWordChar(ch: string): boolean {
  return isWordStart(ch) || isDigit(ch) || ch === "$";
}

/** Refuse an identifier with a non-ASCII character; engines fold those differently. */
function identifier(text: string): string {
  for (let k = 0; k < text.length; k++) {
    if (text.charCodeAt(k) >= 0x80) throw new Unsupported("non-ASCII identifier");
  }
  return text;
}

function isLiteralPrefix(word: string): boolean {
  if (LITERAL_PREFIXES.has(asciiUpper(word))) return true;
  return word.length > 1 && word[0] === "_" && [...word.slice(1)].every(isWordChar);
}

function lex(sql: string, mode: Mode): Tok[] {
  const toks: Tok[] = [];
  const n = sql.length;
  let i = 0;
  let inExecutableComment = false;
  const last = (): Tok | undefined => toks[toks.length - 1];
  while (i < n) {
    const ch = sql[i]!;
    const nxt = i + 1 < n ? sql[i + 1]! : "";
    if (WHITESPACE.has(ch)) {
      i += 1;
      continue;
    }
    if (UNICODE_SPACES.has(ch)) throw new Unsupported("non-ASCII whitespace");
    // Comments.
    if (ch === "-" && nxt === "-") {
      const after = i + 2 < n ? sql[i + 2]! : "";
      if (mode !== "mysql" || mysqlDashCommentFollower(after)) {
        i = lineCommentEnd(sql, i);
        continue;
      }
    }
    if (ch === "#" && mode === "mysql") {
      i = lineCommentEnd(sql, i);
      continue;
    }
    if (ch === "/" && nxt === "*") {
      if (mode === "mysql" && i + 2 < n && sql[i + 2] === "!") {
        // Executable comment: its body is SQL to MySQL.
        i += 3;
        while (i < n && isDigit(sql[i]!)) i += 1;
        inExecutableComment = true;
        continue;
      }
      i = skipBlockComment(sql, i, mode === "postgres");
      continue;
    }
    if (ch === "*" && nxt === "/" && inExecutableComment) {
      inExecutableComment = false;
      i += 2;
      continue;
    }
    // Literals and quoted identifiers.
    if (ch === "&" && (nxt === "'" || nxt === '"') && i > 0 && isWordChar(sql[i - 1]!)) {
      throw new Unsupported("Unicode escape"); // U&'...' and U&"..."
    }
    if ((ch === "'" || ch === '"') && sql.startsWith(ch.repeat(3), i)) {
      throw new Unsupported("triple-quoted literal");
    }
    if (ch === "'") {
      const prev = last();
      const backslash =
        mode === "mysql" ||
        (mode === "postgres" &&
          prev !== undefined &&
          prev.kind === "word" &&
          (prev.text === "E" || prev.text === "e") &&
          adjacent(sql, i));
      if (prev !== undefined && prev.kind === "word" && adjacent(sql, i)) {
        // A literal prefix (N'', E'', X'', _utf8'') belongs to the literal.
        if (!isLiteralPrefix(prev.text)) throw new Unsupported("string literal prefix");
        toks.pop();
      }
      i = skipQuoted(sql, i, "'", backslash);
      toks.push(new Tok("string", ""));
      continue;
    }
    if (ch === '"') {
      if (mode === "mysql") {
        i = skipQuoted(sql, i, '"', true);
        toks.push(new Tok("string", ""));
      } else {
        const end = skipQuoted(sql, i, '"', false);
        toks.push(new Tok("qident", identifier(unquote(sql.slice(i + 1, end - 1), '"'))));
        i = end;
      }
      continue;
    }
    if (ch === "`") {
      const end = skipQuoted(sql, i, "`", false);
      toks.push(new Tok("qident", identifier(unquote(sql.slice(i + 1, end - 1), "`"))));
      i = end;
      continue;
    }
    if (ch === "[" && mode === "ansi") {
      const end = skipQuoted(sql, i, "]", false);
      toks.push(new Tok("qident", identifier(unquote(sql.slice(i + 1, end - 1), "]"))));
      i = end;
      continue;
    }
    if (ch === "$") {
      if (isDigit(nxt)) {
        let j = i + 1;
        while (j < n && isDigit(sql[j]!)) j += 1;
        toks.push(new Tok("param", sql.slice(i, j)));
        i = j;
        continue;
      }
      if (mode === "postgres") {
        let j = i + 1;
        while (j < n && (isWordStart(sql[j]!) || isDigit(sql[j]!))) j += 1;
        if (j < n && sql[j] === "$" && !isDigit(nxt)) {
          const tag = sql.slice(i, j + 1);
          const end = sql.indexOf(tag, j + 1);
          i = end < 0 ? n : end + tag.length;
          toks.push(new Tok("string", ""));
          continue;
        }
      }
    }
    // Numbers, words, parameters, punctuation.
    if (isDigit(ch) || (ch === "." && isDigit(nxt))) {
      let j = i + 1;
      while (j < n && (isWordChar(sql[j]!) || sql[j] === ".")) {
        if ((sql[j] === "e" || sql[j] === "E") && j + 1 < n && (sql[j + 1] === "+" || sql[j + 1] === "-")) {
          j += 1;
        }
        j += 1;
      }
      if (!NUMBER.test(sql.slice(i, j))) throw new Unsupported("identifier starting with a digit");
      toks.push(new Tok("number", sql.slice(i, j)));
      i = j;
      continue;
    }
    if (isWordStart(ch) || ch === "$") {
      let j = i + 1;
      while (j < n && isWordChar(sql[j]!)) {
        if (UNICODE_SPACES.has(sql[j]!)) throw new Unsupported("non-ASCII whitespace");
        j += 1;
      }
      toks.push(new Tok("word", identifier(sql.slice(i, j))));
      i = j;
      continue;
    }
    if (ch === "?") {
      toks.push(new Tok("param", "?"));
      i += 1;
      continue;
    }
    toks.push(new Tok("punct", ch));
    i += 1;
  }
  return toks;
}

/**
 * Whether MySQL starts a `--` comment given the next character: end of input, a
 * space or any control character (U+0000-U+0020 and U+007F).
 */
function mysqlDashCommentFollower(after: string): boolean {
  if (after === "") return true;
  const code = after.charCodeAt(0);
  return code <= 0x20 || code === 0x7f;
}

/**
 * Index just past a line comment, which ends at a line feed. Engines disagree on a
 * carriage return: PostgreSQL and Trino end the comment there, MySQL does not.
 * Either reading can hide SQL that the other executes, so a carriage return inside
 * a line comment is refused unless it is part of a CRLF.
 */
function lineCommentEnd(sql: string, start: number): number {
  const end = sql.indexOf("\n", start);
  const stop = end >= 0 ? end : sql.length;
  for (let k = start; k < stop; k++) {
    if (sql[k] === "\r" && k + 1 !== end) throw new Unsupported("carriage return in comment");
  }
  return end >= 0 ? end + 1 : sql.length;
}

/** Whether the character before the quote belongs to the preceding word. */
function adjacent(sql: string, quoteIndex: number): boolean {
  return quoteIndex > 0 && isWordChar(sql[quoteIndex - 1]!);
}

function skipBlockComment(sql: string, start: number, nested: boolean): number {
  let depth = 0;
  let i = start;
  const n = sql.length;
  while (i < n) {
    if (sql.startsWith("/*", i)) {
      depth += 1;
      i += 2;
      if (!nested && depth > 1) depth = 1;
      continue;
    }
    if (sql.startsWith("*/", i)) {
      depth -= 1;
      i += 2;
      if (depth === 0) return i;
      continue;
    }
    i += 1;
  }
  return n;
}

/** Index just past the literal or identifier opened at `start`. */
function skipQuoted(sql: string, start: number, close: string, backslash: boolean): number {
  let i = start + 1;
  const n = sql.length;
  while (i < n) {
    const ch = sql[i];
    if (backslash && ch === "\\") {
      i += 2;
      continue;
    }
    if (ch === close) {
      if (i + 1 < n && sql[i + 1] === close) {
        i += 2;
        continue;
      }
      return i + 1;
    }
    i += 1;
  }
  return n + 1;
}

function unquote(body: string, close: string): string {
  return body.split(close + close).join(close);
}

// ---------------------------------------------------------------------------
// Structure
// ---------------------------------------------------------------------------

/** A table or derived table in a FROM clause. */
interface Ref {
  // The base table's name, or null when it cannot be resolved.
  table: string | null;
  // The ASCII-folded names a column qualifier may use for it.
  names: Set<string>;
  derived: boolean;
  // A base table's ASCII-folded name, part by part.
  path: string[];
}

class Scope {
  readonly refs: Ref[] = [];
  readonly byName = new Map<string, Ref>();

  add(ref: Ref): void {
    for (const name of ref.names) {
      if (this.byName.has(name)) throw new Unsupported("duplicate table name");
      this.byName.set(name, ref);
    }
    this.refs.push(ref);
  }
}

/** What a FROM clause holds: its tables, derived-table bodies and join conditions. */
class FromClause {
  readonly scope = new Scope();
  readonly derived: Array<[number, number]> = [];
  readonly on: Array<[number, number]> = [];
  readonly using: Array<[string[], Ref[]]> = [];
  natural = false;
}

class Analysis {
  private readonly hidden: string[];
  private readonly allowed: string[] | undefined;
  private readonly match: Map<number, number>;

  constructor(
    private readonly toks: Tok[],
    private readonly policy: EffectivePolicy,
    private readonly objectName: string | undefined,
  ) {
    const rules = policy.objectRules?.fieldRules;
    this.hidden = [...(rules?.hiddenFields ?? [])];
    this.allowed = rules?.allowedFields;
    this.match = this.matchParens();
  }

  private matchParens(): Map<number, number> {
    const stack: number[] = [];
    const match = new Map<number, number>();
    this.toks.forEach((tok, idx) => {
      if (tok.isPunct("(")) {
        stack.push(idx);
      } else if (tok.isPunct(")")) {
        const open = stack.pop();
        if (open === undefined) throw new Unsupported("unbalanced parentheses");
        match.set(open, idx);
      }
    });
    if (stack.length > 0) throw new Unsupported("unbalanced parentheses");
    return match;
  }

  private close(open: number): number {
    return this.match.get(open)!;
  }

  /** Indices in [start, end) outside any parentheses opened in that range. */
  private *topLevel(start: number, end: number): Generator<number> {
    let i = start;
    while (i < end) {
      yield i;
      i = this.toks[i]!.isPunct("(") ? this.close(i) + 1 : i + 1;
    }
  }

  // -- statement ---------------------------------------------------------

  run(): AccessResult {
    const toks = this.toks;
    let end = toks.length;
    while (end > 0 && toks[end - 1]!.isPunct(";")) end -= 1;
    if (toks.slice(0, end).some((t) => t.isPunct(";"))) {
      throw new Unsupported("multiple statements");
    }
    if (end === 0) return { allowed: true };
    if (toks[0]!.isWord("WITH")) throw new Unsupported("WITH");
    if (!toks[0]!.isWord("SELECT")) throw new Unsupported("statement other than SELECT");
    return this.select(0, end, 0);
  }

  /** Check the SELECT spanning [start, end); `start` is the SELECT keyword. */
  private select(start: number, end: number, depth: number): AccessResult {
    if (depth > MAX_NESTING) throw new Unsupported("nesting depth");
    const toks = this.toks;
    const fromAt = this.findFrom(start, end);
    let selectEnd: number;
    let tailAt: number;
    let clause: FromClause;
    if (fromAt === undefined) {
      selectEnd = this.tailStart(start + 1, end);
      tailAt = selectEnd;
      clause = new FromClause();
    } else {
      selectEnd = fromAt;
      tailAt = this.tailStart(fromAt + 1, end);
      clause = this.parseFrom(fromAt + 1, tailAt);
    }
    const tails = this.splitTail(tailAt, end);
    const scope = clause.scope;

    if (depth === 0 && scope.refs.length <= 1 && clause.derived.length === 0) {
      // At most one table: check its access and refuse anything that reaches a further
      // table. Its columns are checked below as well as by the single-table checks, so
      // a column either check misses is still caught.
      for (let idx = start + 1; idx < end; idx++) {
        if (toks[idx]!.isWord("SELECT", "TABLE")) throw new Unsupported("subquery");
      }
      if (scope.refs.length === 0) return { allowed: true };
      const ref = scope.refs[0]!;
      const access = validateAccess(ref.table ?? "", this.policy);
      if (!access.allowed) return access;
      // A supplied object name must name the table the query reads; otherwise the
      // object checked is not the object read.
      if (this.objectName !== undefined && !sameObject(this.objectName, ref.path)) {
        return { allowed: false, reason: OBJECT_MISMATCH_REASON };
      }
    }

    for (const ref of scope.refs) {
      if (!ref.derived && ref.table !== null) {
        const access = validateAccess(ref.table, this.policy);
        if (!access.allowed) return access;
      }
    }
    for (const [innerStart, innerEnd] of clause.derived) {
      const inner = this.select(innerStart, innerEnd, depth + 1);
      if (!inner.allowed) return inner;
    }

    this.checkSelectList(start + 1, selectEnd, scope);
    for (const [a, b] of clause.on) this.walk(a, b, scope);
    for (const [cols, refs] of clause.using) {
      for (const col of cols) {
        for (const ref of refs) this.checkColumn(ref, col);
      }
    }
    if (
      clause.natural &&
      (this.hidden.length > 0 || (this.allowed !== undefined && !this.allowsEverything()))
    ) {
      throw new Unsupported("NATURAL JOIN");
    }
    const aliases = this.selectAliases(start + 1, selectEnd);
    for (const [word, a, b] of tails) {
      if (a >= b) throw new Unsupported(`empty ${word} clause`);
      if (SKIPPED_TAIL.has(word)) {
        this.checkSkippedTail(word, a, b);
      } else if (word === "ORDER") {
        this.checkOrderBy(a, b, scope, aliases);
      } else {
        this.walk(a, b, scope);
      }
    }
    return { allowed: true };
  }

  /**
   * Refuse a LIMIT, OFFSET, FETCH or FOR clause holding anything but its own words,
   * numbers and parameters (and, after FOR ... OF, table names).
   */
  private checkSkippedTail(word: string, start: number, end: number): void {
    const toks = this.toks;
    let names = false;
    for (let idx = start; idx < end; idx++) {
      const tok = toks[idx]!;
      if (tok.isWord("SELECT", "TABLE")) throw new Unsupported("subquery");
      if (word === "FOR" && tok.isWord("OF")) {
        names = true;
        continue;
      }
      if (tok.kind === "number" || tok.kind === "param") continue;
      if (tok.kind === "punct" && (tok.text === "," || tok.text === "(" || tok.text === ")")) {
        continue;
      }
      if (tok.kind === "word" && SKIPPED_TAIL_WORDS.has(tok.upper)) continue;
      if (names && (tok.isIdent || tok.isPunct("."))) continue;
      throw new Unsupported(`${word} clause`);
    }
  }

  /** The SELECT's own FROM keyword, refusing set operations and SELECT INTO. */
  private findFrom(start: number, end: number): number | undefined {
    let fromAt: number | undefined;
    for (const idx of this.topLevel(start + 1, end)) {
      const tok = this.toks[idx]!;
      if (tok.kind !== "word") continue;
      const word = tok.upper;
      if (SET_OPERATIONS.has(word)) throw new Unsupported("set operation");
      if (word === "INTO") throw new Unsupported("SELECT INTO");
      if (word === "FROM" && !this.isDistinctFrom(idx, start)) {
        if (fromAt !== undefined) throw new Unsupported("FROM clause");
        fromAt = idx;
      }
    }
    return fromAt;
  }

  private isDistinctFrom(idx: number, start: number): boolean {
    // "a IS [NOT] DISTINCT FROM b" is a comparison, not a FROM clause.
    return (
      idx - 2 > start &&
      this.toks[idx - 1]!.isWord("DISTINCT") &&
      this.toks[idx - 2]!.isWord("IS", "NOT")
    );
  }

  private isTailMark(idx: number): boolean {
    const tok = this.toks[idx]!;
    if (tok.kind !== "word" || !TAIL_CLAUSES.has(tok.upper)) return false;
    if (tok.upper === "WITH") {
      // TIME WITH TIME ZONE, FETCH ... ROWS WITH TIES, GROUP BY ... WITH ROLLUP.
      const before = idx > 0 ? this.toks[idx - 1] : undefined;
      const after = idx + 1 < this.toks.length ? this.toks[idx + 1] : undefined;
      if (before !== undefined && before.isWord("TIME", "TIMESTAMP", "ROW", "ROWS")) return false;
      if (after !== undefined && after.isWord("TIES", "ROLLUP", "CUBE")) return false;
    }
    return true;
  }

  private tailStart(start: number, end: number): number {
    for (const idx of this.topLevel(start, end)) {
      if (this.isTailMark(idx)) return idx;
    }
    return end;
  }

  /** The tail clauses as (keyword, content start, content end). */
  private splitTail(start: number, end: number): Array<[string, number, number]> {
    const marks = [...this.topLevel(start, end)].filter((idx) => this.isTailMark(idx));
    const tails: Array<[string, number, number]> = [];
    marks.forEach((idx, pos) => {
      const word = this.toks[idx]!.upper;
      if (!CHECKED_TAIL.has(word) && !SKIPPED_TAIL.has(word)) throw new Unsupported(word);
      let contentStart = idx + 1;
      if (
        (word === "GROUP" || word === "ORDER") &&
        contentStart < end &&
        this.toks[contentStart]!.isWord("BY")
      ) {
        contentStart += 1;
      }
      const contentEnd = pos + 1 < marks.length ? marks[pos + 1]! : end;
      tails.push([word, contentStart, contentEnd]);
    });
    return tails;
  }

  // -- FROM --------------------------------------------------------------

  private parseFrom(start: number, end: number): FromClause {
    const toks = this.toks;
    const clause = new FromClause();
    let i = this.parseItem(start, end, clause);
    while (i < end) {
      if (toks[i]!.isPunct(",")) {
        i = this.parseItem(i + 1, end, clause);
        continue;
      }
      if (toks[i]!.isWord("NATURAL")) {
        clause.natural = true;
        i += 1;
      }
      if (i + 1 < end && toks[i]!.isWord("CROSS", "OUTER") && toks[i + 1]!.isWord("APPLY")) {
        throw new Unsupported("APPLY");
      }
      if (i < end && toks[i]!.isWord("INNER", "CROSS")) {
        i += 1;
      } else if (i < end && toks[i]!.isWord("LEFT", "RIGHT", "FULL")) {
        i += 1;
        if (i < end && toks[i]!.isWord("OUTER")) i += 1;
      }
      if (!(i < end && toks[i]!.isWord("JOIN", "STRAIGHT_JOIN"))) {
        throw new Unsupported("FROM clause");
      }
      const left = [...clause.scope.refs];
      i = this.parseItem(i + 1, end, clause);
      const right = clause.scope.refs[clause.scope.refs.length - 1]!;
      if (i < end && toks[i]!.isWord("ON")) {
        let onEnd = end;
        for (const idx of this.topLevel(i + 1, end)) {
          if (toks[idx]!.isPunct(",") || this.isJoinWord(idx, end)) {
            onEnd = idx;
            break;
          }
        }
        clause.on.push([i + 1, onEnd]);
        i = onEnd;
      } else if (i < end && toks[i]!.isWord("USING")) {
        if (!(i + 1 < end && toks[i + 1]!.isPunct("("))) throw new Unsupported("FROM clause");
        const close = this.close(i + 1);
        const cols: string[] = [];
        for (let idx = i + 2; idx < close; idx++) {
          const tok = toks[idx]!;
          if (tok.isIdent) cols.push(tok.text);
          else if (!tok.isPunct(",")) throw new Unsupported("FROM clause");
        }
        clause.using.push([cols, [...left, right]]);
        i = close + 1;
      }
    }
    return clause;
  }

  private isJoinWord(idx: number, end: number): boolean {
    // LEFT(...) and RIGHT(...) in a join condition are functions, not joins.
    const tok = this.toks[idx]!;
    if (tok.kind !== "word" || !JOIN_WORDS.has(tok.upper)) return false;
    return !(idx + 1 < end && this.toks[idx + 1]!.isPunct("("));
  }

  private parseItem(start: number, end: number, clause: FromClause): number {
    const toks = this.toks;
    if (start >= end) throw new Unsupported("FROM clause");
    const tok = toks[start]!;
    if (tok.isWord("LATERAL")) throw new Unsupported("LATERAL");
    if (tok.isPunct("(")) {
      const close = this.close(start);
      if (!(start + 1 < close && toks[start + 1]!.isWord("SELECT"))) {
        throw new Unsupported("parenthesized join");
      }
      clause.derived.push([start + 1, close]);
      let [alias, i] = this.parseAlias(close + 1, end);
      if (i < end && toks[i]!.isPunct("(")) {
        i = this.close(i) + 1; // column aliases rename the derived table's outputs
      }
      const table = this.singleBaseTable(start + 1, close);
      clause.scope.add({
        table,
        names: alias ? new Set([alias.fold]) : new Set(),
        derived: true,
        path: [],
      });
      return i;
    }
    if (!tok.isIdent || (tok.kind === "word" && (KEYWORDS.has(tok.upper) || NOT_AN_ALIAS.has(tok.upper)))) {
      throw new Unsupported("FROM clause");
    }
    const parts = [tok];
    let i = start + 1;
    while (i + 1 < end && toks[i]!.isPunct(".") && toks[i + 1]!.isIdent) {
      parts.push(toks[i + 1]!);
      i += 2;
    }
    if (i < end && toks[i]!.isPunct("(")) throw new Unsupported("table-valued function");
    let alias: Tok | undefined;
    [alias, i] = this.parseAlias(i, end);
    if (i < end && toks[i]!.isPunct("(")) throw new Unsupported("column alias list");
    const leafTok = parts[parts.length - 1]!;
    let leaf = leafTok.text;
    if (leafTok.kind === "qident" && leaf.includes(".")) {
      leaf = leaf.slice(leaf.lastIndexOf(".") + 1);
    }
    let names: Set<string>;
    if (alias !== undefined) {
      names = new Set([alias.fold]);
    } else {
      const folded = parts.map((p) => p.fold);
      names = new Set(folded.map((_, k) => folded.slice(k).join(".")));
    }
    const path = parts.flatMap((p) =>
      (p.kind === "qident" ? p.text.split(".") : [p.text]).map(asciiLower),
    );
    clause.scope.add({ table: leaf, names, derived: false, path });
    return i;
  }

  private parseAlias(i: number, end: number): [Tok | undefined, number] {
    const toks = this.toks;
    if (i < end && toks[i]!.isWord("AS")) {
      if (i + 1 < end && Analysis.canAlias(toks[i + 1]!)) return [toks[i + 1]!, i + 2];
      throw new Unsupported("FROM clause");
    }
    if (i < end && Analysis.canAlias(toks[i]!)) return [toks[i]!, i + 1];
    return [undefined, i];
  }

  private static canAlias(tok: Tok): boolean {
    if (tok.kind === "qident") return true;
    return tok.kind === "word" && !NOT_AN_ALIAS.has(tok.upper) && !KEYWORDS.has(tok.upper);
  }

  /** The one base table a derived table reads, or null when there is not exactly one. */
  private singleBaseTable(start: number, end: number): string | null {
    const fromAt = this.findFrom(start, end);
    if (fromAt === undefined) return null;
    const inner = this.parseFrom(fromAt + 1, this.tailStart(fromAt + 1, end));
    if (inner.scope.refs.length === 1 && inner.derived.length === 0) {
      return inner.scope.refs[0]!.table;
    }
    return null;
  }

  // -- field rules -------------------------------------------------------

  private allowsEverything(): boolean {
    return this.allowed !== undefined && this.allowed.some((a) => a.trim() === "*");
  }

  /** Check a table-qualified column against both field rules. */
  private checkName(name: string): void {
    if (this.hidden.some((h) => fieldNameMatches(h, name))) throw new FieldDenied();
    if (this.allowed !== undefined && !this.allowed.some((a) => allowedFieldMatches(a, name))) {
      throw new FieldDenied();
    }
  }

  /** Check a column whose table is unknown: only an unqualified entry can allow it. */
  private checkUnresolved(col: string): void {
    if (this.hidden.some((h) => fieldNameMatches(h, col))) throw new FieldDenied();
    if (
      this.allowed !== undefined &&
      !this.allowed.some((a) => !a.includes(".") && fieldNameMatches(a, col))
    ) {
      throw new FieldDenied();
    }
  }

  private checkColumn(ref: Ref, col: string): void {
    if (ref.table === null) this.checkUnresolved(col);
    else this.checkName(`${ref.table}.${col}`);
  }

  private checkBare(col: string, scope: Scope): void {
    if (scope.refs.length === 1) this.checkColumn(scope.refs[0]!, col);
    else this.checkUnresolved(col);
  }

  /**
   * `t.*`: hidden fields are stripped after the fetch, but an allow-list must fit.
   *
   * The fetched keys are bare column names, so an entry qualified with another
   * table would admit this table's column of the same name. The star is allowed
   * only when every qualified entry names this table.
   */
  private checkStar(ref: Ref): void {
    if (this.allowed === undefined || this.allowsEverything()) return;
    const table = ref.table !== null ? asciiLower(ref.table) : null;
    for (const entry of this.allowed) {
      const dot = entry.lastIndexOf(".");
      if (dot >= 0 && (table === null || asciiLower(entry.slice(0, dot)) !== table)) {
        throw new FieldDenied();
      }
    }
  }

  // -- expressions -------------------------------------------------------

  /** Check every column reference in the expression tokens [start, end). */
  private walk(start: number, end: number, scope: Scope): void {
    const toks = this.toks;
    const ends = new Set<number>(); // words that end an operand
    const windows = new Set<number>(); // the "(" opening each OVER (...) window
    const brackets: number[] = [];
    let i = start;
    while (i < end) {
      const tok = toks[i]!;
      if (tok.kind === "punct") {
        if (tok.text === "(" || tok.text === "[") {
          brackets.push(i);
        } else if ((tok.text === ")" || tok.text === "]") && brackets.length > 0) {
          brackets.pop();
        } else if (tok.text === ":" && i + 2 < end && toks[i + 1]!.isPunct(":")) {
          if (toks[i + 2]!.isIdent) {
            ends.add(i + 2);
            i += 3; // a cast's target type
            continue;
          }
        } else if (
          tok.text === ":" &&
          i + 1 < end &&
          toks[i + 1]!.isIdent &&
          !(brackets.length > 0 && toks[brackets[brackets.length - 1]!]!.isPunct("["))
        ) {
          ends.add(i + 1);
          i += 2; // a named bind parameter; inside [...] it is a slice bound
          continue;
        }
        i += 1;
        continue;
      }
      if (!tok.isIdent) {
        i += 1;
        continue;
      }
      const parts = [tok];
      let j = i;
      while (
        j + 2 < end &&
        toks[j + 1]!.isPunct(".") &&
        (toks[j + 2]!.isIdent || toks[j + 2]!.isPunct("*"))
      ) {
        parts.push(toks[j + 2]!);
        j += 2;
        if (parts[parts.length - 1]!.isPunct("*")) break;
      }
      const lastPart = parts[parts.length - 1]!;
      if (j + 1 < end && toks[j + 1]!.isPunct("(") && !lastPart.isPunct("*")) {
        if (j === i && tok.isWord("OVER") && i > start && toks[i - 1]!.isPunct(")")) {
          windows.add(i + 1);
        }
        i = j + 1; // a function name; its arguments are walked
        continue;
      }
      if (parts.length === 1) {
        const inWindow = brackets.length > 0 && windows.has(brackets[brackets.length - 1]!);
        i = this.bare(i, start, end, scope, ends, inWindow);
        continue;
      }
      const qualifier = parts
        .slice(0, -1)
        .map((p) => p.fold)
        .join(".");
      const ref = scope.byName.get(qualifier);
      if (ref === undefined) throw new Unsupported("unresolved qualifier");
      if (lastPart.isPunct("*")) {
        this.checkStar(ref);
      } else {
        this.checkColumn(ref, lastPart.text);
        ends.add(j);
      }
      i = j + 1;
    }
  }

  /** Whether token `k` of the walk that began at `start` ends an operand. */
  private endsOperand(k: number, start: number, ends: Set<number>): boolean {
    if (k < start) return false;
    const tok = this.toks[k]!;
    return (
      tok.kind === "qident" ||
      tok.kind === "string" ||
      tok.kind === "number" ||
      tok.kind === "param" ||
      tok.isPunct(")") ||
      tok.isPunct("]") ||
      ends.has(k)
    );
  }

  /**
   * Handle a lone identifier at `i`; return the index to continue from.
   *
   * A word is skipped only where it cannot be a column: a reserved word, a word
   * directly after an operand (an operator, ASC, an alias), the second word of a
   * keyword pair, or a window's frame words. Anywhere else it is checked, so a
   * column named like a keyword (`zone`, `first`) is still read as one.
   */
  private bare(
    i: number,
    start: number,
    end: number,
    scope: Scope,
    ends: Set<number>,
    inWindow: boolean,
  ): number {
    const toks = this.toks;
    const tok = toks[i]!;
    const following = i + 1 < end ? toks[i + 1] : undefined;
    const prev = i - 1 >= start ? toks[i - 1] : undefined;
    const prev2 = i - 2 >= start ? toks[i - 2] : undefined;
    if (tok.kind === "word") {
      const word = tok.upper;
      if (word === "SELECT" || word === "TABLE") throw new Unsupported("subquery");
      if (word === "AS" || word === "COLLATE") {
        // An alias or cast type, or a collation.
        if (following !== undefined && following.isIdent) {
          ends.add(i + 1);
          return i + 2;
        }
        return i + 1;
      }
      if (RESERVED.has(word)) {
        if (RESERVED_VALUES.has(word)) ends.add(i);
        return i + 1;
      }
      if (word === "OVER" && prev !== undefined && prev.isPunct(")")) {
        if (following !== undefined && following.isIdent) {
          ends.add(i + 1);
          return i + 2; // a named window
        }
        return i + 1;
      }
      if (this.endsOperand(i - 1, start, ends)) {
        if (OPERAND_END_KEYWORDS.has(word) || word === "ISNULL" || word === "NOTNULL") {
          ends.add(i);
          return i + 1;
        }
        if (AFTER_OPERAND.has(word) || DATE_PARTS.has(word)) {
          return i + 1; // an operator or modifier: DIV, ASC, BETWEEN, AT
        }
      }
      if (prev !== undefined && prev.kind === "word") {
        const before = prev.upper;
        if (KEYWORD_PAIRS.get(before)?.has(word)) {
          // WITH TIME is only a keyword pair ahead of ZONE
          if (!(word === "TIME" && !(following !== undefined && following.isWord("ZONE")))) {
            return i + 1;
          }
        }
        if (
          word === "ZONE" &&
          before === "TIME" &&
          prev2 !== undefined &&
          prev2.isWord("WITH", "WITHOUT", "AT")
        ) {
          return i + 1;
        }
        if (before === "IS" || (before === "NOT" && prev2 !== undefined && prev2.isWord("IS"))) {
          ends.add(i);
          return i + 1; // IS [NOT] UNKNOWN, IS JSON, IS DISTINCT FROM
        }
        if (
          before === "NOT" &&
          NEGATED_OPERATORS.has(word) &&
          this.endsOperand(i - 2, start, ends)
        ) {
          return i + 1; // a NOT BETWEEN b; a prefix NOT is followed by a value
        }
      }
      if (inWindow && this.frameWord(i, following, prev)) return i + 1;
      if (prev !== undefined && prev.isPunct("(") && prev2 !== undefined) {
        if (DATE_PARTS.has(word) && prev2.isWord("EXTRACT")) {
          return i + 1; // EXTRACT(YEAR FROM ...)
        }
        if ((word === "BOTH" || word === "LEADING" || word === "TRAILING") && prev2.isWord("TRIM")) {
          return i + 1; // TRIM(LEADING 'x' FROM ...)
        }
      }
      if (word === "INTERVAL") {
        const k = this.intervalLiteralEnd(i, end);
        if (k !== undefined) {
          ends.add(k - 1);
          return k;
        }
        if (
          following !== undefined &&
          following.isIdent &&
          i + 2 < end &&
          toks[i + 2]!.kind === "word" &&
          DATE_PARTS.has(toks[i + 2]!.upper)
        ) {
          return i + 1; // MySQL's INTERVAL n DAY
        }
      }
      if (word === "DATE" || word === "TIME" || word === "TIMESTAMP") {
        if (following !== undefined && following.kind === "string") {
          return i + 1; // a typed literal: DATE '2024-01-01'
        }
        if (
          following !== undefined &&
          following.isWord("WITH", "WITHOUT") &&
          i + 3 < end &&
          toks[i + 2]!.isWord("TIME") &&
          toks[i + 3]!.isWord("ZONE")
        ) {
          return i + 4; // TIMESTAMP WITH TIME ZONE '...'
        }
      }
      if (word === "ARRAY" && following !== undefined && following.isPunct("[")) {
        return i + 1; // an array constructor: ARRAY[1, 2]
      }
      if (word === "GROUPING" && following !== undefined && following.isWord("SETS")) {
        return i + 1;
      }
    }
    this.checkBare(tok.text, scope);
    ends.add(i);
    return i + 1;
  }

  /** Whether the word at `i`, directly inside OVER (...), is a frame keyword. */
  private frameWord(i: number, following: Tok | undefined, prev: Tok | undefined): boolean {
    const word = this.toks[i]!.upper;
    const nxt = following !== undefined && following.kind === "word" ? following.upper : "";
    const opens = prev !== undefined && prev.isPunct("(");
    if (word === "PARTITION") return opens && nxt === "BY";
    if (word === "ROWS" || word === "RANGE" || word === "GROUPS") {
      return (
        opens &&
        (nxt === "BETWEEN" ||
          nxt === "UNBOUNDED" ||
          nxt === "CURRENT" ||
          (following !== undefined &&
            (following.kind === "number" ||
              following.kind === "param" ||
              following.kind === "string")))
      );
    }
    if (word === "UNBOUNDED") return nxt === "PRECEDING" || nxt === "FOLLOWING";
    if (word === "CURRENT") return nxt === "ROW";
    if (word === "EXCLUDE") {
      return nxt === "CURRENT" || nxt === "GROUP" || nxt === "TIES" || nxt === "NO";
    }
    return false;
  }

  /** The index past `INTERVAL [-]'1' [DAY [TO SECOND]]` at `i`, or undefined. */
  private intervalLiteralEnd(i: number, end: number): number | undefined {
    const toks = this.toks;
    let k = i + 1;
    if (k < end && (toks[k]!.isPunct("-") || toks[k]!.isPunct("+"))) k += 1;
    if (
      !(
        k < end &&
        (toks[k]!.kind === "string" || toks[k]!.kind === "number" || toks[k]!.kind === "param")
      )
    ) {
      return undefined;
    }
    k += 1;
    if (k < end && toks[k]!.kind === "word" && DATE_PARTS.has(toks[k]!.upper)) {
      k += 1;
      if (
        k + 1 < end &&
        toks[k]!.isWord("TO") &&
        toks[k + 1]!.kind === "word" &&
        DATE_PARTS.has(toks[k + 1]!.upper)
      ) {
        k += 2;
      }
    }
    return k;
  }

  // -- select list and ORDER BY -----------------------------------------

  private entries(start: number, end: number): Array<[number, number]> {
    const entries: Array<[number, number]> = [];
    let entryStart = start;
    for (const idx of this.topLevel(start, end)) {
      if (this.toks[idx]!.isPunct(",")) {
        entries.push([entryStart, idx]);
        entryStart = idx + 1;
      }
    }
    entries.push([entryStart, end]);
    return entries.filter(([a, b]) => a < b);
  }

  /** Step past DISTINCT [ON (...)], TOP n and the like, checking DISTINCT ON. */
  private skipModifiers(start: number, end: number, scope: Scope): number {
    const toks = this.toks;
    let i = start;
    while (i < end) {
      const tok = toks[i]!;
      if (tok.isWord("DISTINCT")) {
        i += 1;
        if (i + 1 < end && toks[i]!.isWord("ON") && toks[i + 1]!.isPunct("(")) {
          const close = this.close(i + 1);
          this.walk(i + 2, close, scope);
          i = close + 1;
        }
        continue;
      }
      if (tok.isWord("TOP")) {
        i += 1;
        if (i < end && toks[i]!.isPunct("(")) {
          i = this.close(i) + 1;
        } else if (i < end && (toks[i]!.kind === "number" || toks[i]!.kind === "param")) {
          i += 1;
        }
        if (i < end && toks[i]!.isWord("PERCENT")) i += 1;
        if (i + 1 < end && toks[i]!.isWord("WITH") && toks[i + 1]!.isWord("TIES")) i += 2;
        continue;
      }
      if (tok.kind === "word" && SELECT_MODIFIERS.has(tok.upper)) {
        i += 1;
        continue;
      }
      break;
    }
    return i;
  }

  /** Where an entry's expression ends, and its alias if it has one. */
  private entryAlias(a: number, b: number): [number, Tok | undefined] {
    const toks = this.toks;
    if (b - a >= 3 && toks[b - 2]!.isWord("AS") && toks[b - 1]!.isIdent) {
      return [b - 2, toks[b - 1]!];
    }
    if (b - a >= 2 && Analysis.canBeOutputAlias(toks[b - 1]!)) {
      const prev = toks[b - 2]!;
      const prevEndsOperand =
        prev.kind === "qident" ||
        prev.kind === "string" ||
        prev.kind === "number" ||
        prev.kind === "param" ||
        prev.isPunct(")") ||
        (prev.kind === "word" && (!KEYWORDS.has(prev.upper) || OPERAND_END_KEYWORDS.has(prev.upper)));
      if (prevEndsOperand) return [b - 1, toks[b - 1]!];
    }
    return [b, undefined];
  }

  private static canBeOutputAlias(tok: Tok): boolean {
    return tok.kind === "qident" || (tok.kind === "word" && !KEYWORDS.has(tok.upper));
  }

  private checkSelectList(start: number, end: number, scope: Scope): void {
    const body = this.skipModifiers(start, end, scope);
    for (const [a, b] of this.entries(body, end)) {
      if (b - a === 1 && this.toks[a]!.isPunct("*")) {
        for (const ref of scope.refs) this.checkStar(ref);
        continue;
      }
      const [exprEnd] = this.entryAlias(a, b);
      this.walk(a, exprEnd, scope);
    }
  }

  private selectAliases(start: number, end: number): Set<string> {
    const aliases = new Set<string>();
    for (const [a, b] of this.entries(start, end)) {
      const [, alias] = this.entryAlias(a, b);
      if (alias !== undefined) aliases.add(alias.fold);
    }
    return aliases;
  }

  private checkOrderBy(start: number, end: number, scope: Scope, aliases: Set<string>): void {
    for (const [a, b] of this.entries(start, end)) {
      let k = b;
      while (k > a && this.toks[k - 1]!.isWord("ASC", "DESC", "FIRST", "LAST", "NULLS")) k -= 1;
      if (k - a === 1 && this.toks[a]!.isIdent && aliases.has(this.toks[a]!.fold)) {
        continue; // an output column's alias, which ORDER BY resolves first
      }
      this.walk(a, b, scope);
    }
  }
}

function tokensKey(toks: Tok[]): string {
  return JSON.stringify(toks.map((t) => [t.kind, t.text]));
}

/**
 * Whether a supplied object name and a table's name can name the same object.
 *
 * Both are compared part by part, ASCII case-insensitively, from the right. A name
 * with fewer parts matches one qualified further (`patients` and
 * `public.patients`); names whose shared parts differ do not (`db1.patients` and
 * `db2.patients`).
 */
function sameObject(objectName: string, path: string[]): boolean {
  const given = objectName.split(".").map(asciiLower);
  const k = Math.min(given.length, path.length);
  if (k === 0) return false;
  for (let m = 1; m <= k; m++) {
    if (given[given.length - m] !== path[path.length - m]) return false;
  }
  return true;
}

/**
 * Check every table and column a query references against the policy.
 *
 * Every table the query reads must pass {@link validateAccess}, and every column
 * reference is resolved to its table and checked against `hiddenFields` and
 * `allowedFields`. A bare column in a query over several tables is allowed only by
 * an unqualified `allowedFields` entry (or `*`), because the table it belongs to
 * cannot be known without the schema. Constructs the check cannot resolve are
 * refused with a reason beginning with {@link UNSUPPORTED_REASON_PREFIX}.
 *
 * A query that reads a single table has its columns checked here as well as by
 * `validateQuery`. When the caller supplies `objectName` it is checked with
 * {@link validateAccess} as well, and a query over one table must read that
 * object: a different table is refused with {@link OBJECT_MISMATCH_REASON}. Every
 * table of a query is checked whether or not an object name is supplied.
 *
 * Identifier and literal forms the check does not model are refused rather than
 * guessed at: Unicode-escape forms (`U&"..."`, `U&'...'`), string literal prefixes
 * other than the recognised ones (such as Oracle's `q'[...]'`), triple-quoted
 * literals, identifiers with a non-ASCII character and identifiers that start with
 * a digit.
 */
export function validateQueryReferences(
  query: string,
  policy: EffectivePolicy,
  options: { objectName?: string } = {},
): AccessResult {
  if (options.objectName !== undefined) {
    const named = validateAccess(options.objectName, policy);
    if (!named.allowed) return named;
  }
  if (!query) return { allowed: true };
  const seen = new Set<string>();
  for (const mode of MODES) {
    let result: AccessResult;
    try {
      const toks = lex(query, mode);
      const key = tokensKey(toks);
      if (seen.has(key)) continue;
      seen.add(key);
      result = new Analysis(toks, policy, options.objectName).run();
    } catch (error) {
      if (error instanceof Unsupported) {
        return { allowed: false, reason: UNSUPPORTED_REASON_PREFIX + error.construct };
      }
      if (error instanceof FieldDenied) {
        return { allowed: false, reason: FIELD_DENIAL_REASON };
      }
      throw error;
    }
    if (!result.allowed) return result;
  }
  return { allowed: true };
}
