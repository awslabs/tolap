/**
 * Build a `db` manifest from SQL DDL or an `information_schema` dump.
 *
 * Administrators can already produce one of these -- `pg_dump --schema-only`,
 * `SHOW CREATE TABLE`, or a two-column query against `information_schema.columns`
 * -- which beats hand-typing every column into a form.
 *
 * This is a **deliberately shallow reader**, not a SQL parser. It finds table and
 * column names and ignores constraints, types, defaults and everything else. The
 * output only populates dropdowns, so a table it fails to recognize costs an author
 * one manual entry; there is no correctness cliff, and no reason to take on a real
 * grammar.
 */

import { ManifestError, parseManifest, type SourceManifest } from "./manifest.ts";

/**
 * Strip `-- line` and block comments so they cannot hide or fake a column.
 *
 * The block-comment pass is a hand-written scan rather than
 * `/\/\*[\s\S]*?\*\//g`, which is quadratic on input the *author controls*: for
 * `"a/*".repeat(n)` — many comment openings, none of them closed — the engine restarts a
 * lazy scan to end-of-input at every `/*`. Measured at ~1s for 150 KB and rising with the
 * square, so a body inside Fastify's 1 MB default could stall the event loop for tens of
 * seconds. One Fargate task serves both the admin API and `/v1/resolve`, so that is not
 * merely a slow import: it delays policy resolution for every install.
 *
 * `indexOf` makes it linear — each character is examined once — and an unterminated
 * comment drops the remainder, which is what the SQL engines do too.
 */
function stripComments(sql: string): string {
  let out = "";
  let index = 0;

  for (;;) {
    const open = sql.indexOf("/*", index);
    if (open === -1) {
      out += sql.slice(index);
      break;
    }
    out += sql.slice(index, open) + " ";

    const close = sql.indexOf("*/", open + 2);
    // Unterminated: everything after it is inside the comment.
    if (close === -1) break;
    index = close + 2;
  }

  // Linear already: the character class cannot backtrack across the newline.
  return out.replace(/--[^\n]*/g, " ");
}

/** Unquote an identifier: `"users"`, `` `users` ``, `[users]`, or bare. */
function unquote(identifier: string): string {
  const trimmed = identifier.trim();
  const quoted = /^(["`[])(.*)([\]"`])$/.exec(trimmed);
  const inner = quoted ? quoted[2]! : trimmed;
  // Schema-qualified names reduce to the table name: TOLAP object rules match on
  // the object name the wrapper is given, which is what a tool call passes.
  const parts = inner.split(".");
  return (parts[parts.length - 1] ?? inner).replace(/^["`[]|[\]"`]$/g, "");
}

/**
 * Split a `CREATE TABLE (...)` body on top-level commas.
 *
 * Needed because a column can carry parenthesized detail -- `NUMERIC(10,2)`,
 * `CHECK (x IN (1,2))` -- whose commas must not split a definition.
 */
function splitTopLevel(body: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let current = "";
  let quote: string | undefined;

  for (const char of body) {
    if (quote !== undefined) {
      current += char;
      if (char === quote) quote = undefined;
      continue;
    }
    if (char === "'" || char === '"' || char === "`") {
      quote = char;
      current += char;
      continue;
    }
    if (char === "(") depth += 1;
    if (char === ")") depth -= 1;
    if (char === "," && depth === 0) {
      parts.push(current);
      current = "";
      continue;
    }
    current += char;
  }
  if (current.trim() !== "") parts.push(current);
  return parts;
}

/** Table-level constraint keywords: these lines declare no column. */
const CONSTRAINT_KEYWORDS = new Set([
  "primary",
  "foreign",
  "unique",
  "check",
  "constraint",
  "key",
  "index",
  "exclude",
  "period",
]);

function parseCreateTables(sql: string): Map<string, string[]> {
  const tables = new Map<string, string[]>();

  // Walk `CREATE TABLE <name> (` occurrences, then take the balanced body. A
  // single regex cannot do this correctly because the body nests parentheses.
  const header =
    /create\s+(?:global\s+|local\s+)?(?:temp(?:orary)?\s+|unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?([^\s(]+)\s*\(/gi;

  let match: RegExpExecArray | null;
  while ((match = header.exec(sql)) !== null) {
    const table = unquote(match[1]!);
    let depth = 1;
    let index = header.lastIndex;
    while (index < sql.length && depth > 0) {
      if (sql[index] === "(") depth += 1;
      else if (sql[index] === ")") depth -= 1;
      index += 1;
    }
    const body = sql.slice(header.lastIndex, index - 1);

    const columns: string[] = [];
    for (const part of splitTopLevel(body)) {
      const trimmed = part.trim();
      if (trimmed === "") continue;
      const first = /^([^\s(]+)/.exec(trimmed);
      if (!first) continue;

      const name = unquote(first[1]!);
      if (CONSTRAINT_KEYWORDS.has(name.toLowerCase())) continue;
      if (name === "") continue;
      columns.push(name);
    }

    if (columns.length > 0) tables.set(table, columns);
    header.lastIndex = index;
  }

  return tables;
}

/**
 * Parse an `information_schema.columns` dump.
 *
 * Accepts psql's pipe-delimited output and plain CSV/TSV, expecting the first two
 * columns to be table name and column name.
 */
function parseColumnDump(sql: string): Map<string, string[]> {
  const tables = new Map<string, string[]>();

  for (const line of sql.split("\n")) {
    const trimmed = line.trim();
    if (trimmed === "") continue;
    // psql rules and totals lines.
    if (/^[-+|\s]+$/.test(trimmed)) continue;
    if (/^\(\d+ rows?\)$/.test(trimmed)) continue;

    const cells = trimmed
      .split(/\s*[|,\t]\s*/)
      .map((cell) => cell.trim())
      .filter((cell) => cell !== "");
    if (cells.length < 2) continue;

    const [table, column] = cells as [string, string];
    // Skip a header row.
    if (/^table[_ ]?name$/i.test(table)) continue;
    if (!/^[A-Za-z_][\w$]*$/.test(table) || !/^[A-Za-z_][\w$]*$/.test(column)) {
      continue;
    }

    const existing = tables.get(table) ?? [];
    if (!existing.includes(column)) existing.push(column);
    tables.set(table, existing);
  }

  return tables;
}

export function importSqlDdl(
  sourceConnectionId: string,
  ddl: string,
): SourceManifest {
  if (typeof ddl !== "string" || ddl.trim() === "") {
    throw new ManifestError("ddl must be a non-empty string");
  }

  const sql = stripComments(ddl);

  // Prefer CREATE TABLE, which is unambiguous, and fall back to a column dump.
  let tables = parseCreateTables(sql);
  if (tables.size === 0) {
    tables = parseColumnDump(sql);
  }

  if (tables.size === 0) {
    throw new ManifestError(
      "no tables found -- expected CREATE TABLE statements or an information_schema.columns dump",
    );
  }

  return parseManifest({
    sourceConnectionId,
    objects: [...tables.entries()]
      .map(([name, fields]) => ({ name, fields }))
      .sort((a, b) => a.name.localeCompare(b.name)),
  });
}
