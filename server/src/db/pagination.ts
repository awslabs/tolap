/**
 * Bounded, keyset pagination for the admin API's list endpoints.
 *
 * Why this exists at all: the admin API and `/v1/resolve` are two Fastify
 * instances in **one** Node process on one task. A list endpoint that reads a
 * whole table into memory and serializes it does not merely make that one request
 * slow -- it stalls the event loop and the connection pool that every install's
 * policy resolution depends on, and an install that cannot resolve gets *no*
 * access rather than no restrictions. The `TaskMemoryHigh` alarm at 85% exists
 * because these listings used to be unbounded. So the bound is a availability
 * control, not a nicety.
 *
 * Two decisions worth stating, because both have a defensible opposite:
 *
 * 1. **An out-of-range `limit` is REJECTED with 400, never clamped.** Clamping is
 *    tempting because it always returns something, but it returns *fewer rows than
 *    asked for with no signal that it did*. On the audit log that is a correctness
 *    problem, not a cosmetic one: a reviewer who asks for 100000 entries and
 *    silently receives 500 concludes there were only 500 events. A 400 tells the
 *    caller the truth -- page instead. Same rule on every endpoint, so a caller
 *    never has to remember which ones lie.
 *
 * 2. **Keyset, not OFFSET.** `OFFSET n` makes the database walk and discard n rows,
 *    so page 500 costs 500 pages of work, and any insert or delete between two
 *    requests shifts every subsequent row -- which silently skips or repeats
 *    entries. On the audit log, skipping is losing evidence. Every table paged here
 *    has a stable, unique sort key (a primary key, or a timestamp with the primary
 *    key as tiebreaker), so keyset is available everywhere and there is no fallback
 *    to explain.
 *
 * Cursors are opaque to the caller on purpose: their contents are the sort key of
 * the last row returned, which is an implementation detail we want to be free to
 * change without breaking a client that learned to parse it.
 */

/**
 * Rows returned when the caller asks for no particular number.
 *
 * 200 is what `/v1/audit` already defaulted to, so no existing caller changes
 * behavior, and it is a page a human or a console table can actually use.
 */
export const DEFAULT_PAGE_LIMIT = 200;

/**
 * Hard ceiling on any single page.
 *
 * 500 is the largest page a first-party caller legitimately asks for today (the
 * console's audit view requests 500), so the ceiling admits every real caller and
 * refuses everything above it. Raising this is not free: it is a direct multiplier
 * on the peak heap of a process that is also resolving policy.
 */
export const MAX_PAGE_LIMIT = 500;

/**
 * A pagination parameter the caller supplied that cannot be honored.
 *
 * Carries the status so the route layer does not have to re-derive it. 400 rather
 * than 422: this is a malformed request line, not a document that failed schema
 * validation, and the console distinguishes the two.
 */
export class PaginationError extends Error {
  readonly status: 400;

  // Not a constructor parameter property: the server runs its own sources under
  // strip-only type stripping, which cannot desugar those.
  constructor(message: string) {
    super(message);
    this.name = "PaginationError";
    this.status = 400;
  }
}

/** What a caller asks for. Both fields optional: no arguments means first page. */
export interface PageRequest {
  readonly limit?: number;
  readonly cursor?: string;
}

/**
 * One page of results.
 *
 * `nextCursor` is `null` -- present and null, not absent -- on the last page. A
 * caller loops until it is null, and an absent field would make "last page" and
 * "this endpoint does not paginate" indistinguishable.
 */
export interface Page<T> {
  readonly items: T[];
  readonly nextCursor: string | null;
}

/** Query parameters every paginated route accepts. */
export interface PageQuery {
  limit?: string;
  cursor?: string;
}

/**
 * Parse `?limit=` from a query string.
 *
 * Digits only, deliberately: `Number("1e3")` is 1000 and `Number(" 5")` is 5, and
 * accepting either means the server is guessing at a value that bounds its own
 * memory use. Absent stays absent so the default applies; everything else that is
 * not a plain in-range integer is refused.
 */
export function parseLimit(raw: string | undefined): number | undefined {
  if (raw === undefined) return undefined;
  if (!/^\d+$/.test(raw)) {
    throw new PaginationError(
      `limit must be an integer between 1 and ${MAX_PAGE_LIMIT}`,
    );
  }
  return checkLimit(Number(raw));
}

/**
 * Apply the default and enforce the ceiling.
 *
 * Called by the store as well as the route, so a server-side caller that passes a
 * number directly cannot bypass the bound the route enforces -- the route is the
 * control, this is the backstop, and they share one constant so they cannot drift.
 */
export function normalizeLimit(limit: number | undefined): number {
  if (limit === undefined) return DEFAULT_PAGE_LIMIT;
  return checkLimit(limit);
}

function checkLimit(limit: number): number {
  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_PAGE_LIMIT) {
    throw new PaginationError(
      `limit must be an integer between 1 and ${MAX_PAGE_LIMIT}`,
    );
  }
  return limit;
}

/**
 * Encode the sort key of the last returned row as an opaque cursor.
 *
 * base64url rather than base64 so the value survives a query string untouched; a
 * `+` in a cursor decodes as a space and the next page silently starts from the
 * wrong row.
 */
export function encodeCursor(parts: readonly string[]): string {
  return Buffer.from(JSON.stringify(parts), "utf8").toString("base64url");
}

/**
 * Decode a cursor, or `undefined` for the first page.
 *
 * `arity` is the number of key components the endpoint expects. A cursor minted
 * for a different endpoint would otherwise be interpolated into the wrong
 * comparison and page from nonsense; rejecting it is how the caller learns.
 */
export function decodeCursor(
  raw: string | undefined,
  arity: number,
): string[] | undefined {
  if (raw === undefined || raw === "") return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(raw, "base64url").toString("utf8"));
  } catch {
    throw new PaginationError("cursor is not a valid pagination cursor");
  }
  if (
    !Array.isArray(parsed) ||
    parsed.length !== arity ||
    !parsed.every((part) => typeof part === "string")
  ) {
    throw new PaginationError("cursor is not a valid pagination cursor");
  }
  return parsed as string[];
}

/**
 * SQL that renders a `timestamptz` as a cursor component without losing precision.
 *
 * Postgres keeps microseconds; a JS `Date` keeps milliseconds. Round-tripping the
 * value the driver hands back would truncate it, and two rows written inside the
 * same millisecond would then land on the wrong side of the keyset comparison --
 * one of them skipped or returned twice. `US` keeps all six digits.
 *
 * `column` is a literal from this file's callers, never caller input, so the
 * interpolation is not an injection site.
 */
export function timestampCursorSql(column: string): string {
  return `to_char(${column} AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;
}

const TIMESTAMP_CURSOR = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Validate a cursor component before it reaches a SQL cast.
 *
 * Not defense against injection -- these are bound parameters. It is so a hand-edited
 * cursor produces a 400 that names the problem instead of a Postgres cast error surfacing
 * as a 500, which would page an operator over a bad URL.
 *
 * That goal was initially unmet for one case: the integer validators checked shape but not
 * magnitude, so a long digit string reached the cast and Postgres raised 22003
 * (`numeric_value_out_of_range`) -- a real 500 from a URL an auditor could type. Shape
 * alone is not enough; each validator has to reject what its target COLUMN cannot hold.
 */
export function cursorTimestamp(value: string): string {
  if (!TIMESTAMP_CURSOR.test(value)) {
    throw new PaginationError("cursor is not a valid pagination cursor");
  }
  return value;
}

export function cursorInteger(value: string, max = MAX_BIGINT): string {
  // Shape AND magnitude. `/^\d+$/` alone let an arbitrarily long digit string through to
  // a `::bigint` cast, where Postgres raised 22003 and the route returned **500** -- which
  // is precisely the "page an operator over a bad URL" outcome the comment above says this
  // function exists to prevent. Verified: a 30-digit cursor returned
  // `500 {"error":"internal error"}` before this bound.
  if (!/^\d+$/.test(value) || BigInt(value) > max) {
    throw new PaginationError("cursor is not a valid pagination cursor");
  }
  return value;
}

/** Largest value a Postgres `bigint` column can hold. */
const MAX_BIGINT = 2n ** 63n - 1n;

/** Largest value a Postgres `integer` column can hold -- `version_no` is an int4. */
export const MAX_INT4 = 2147483647n;

export function cursorUuid(value: string): string {
  if (!UUID.test(value)) {
    throw new PaginationError("cursor is not a valid pagination cursor");
  }
  return value;
}

/**
 * Turn `limit + 1` fetched rows into a page.
 *
 * The extra row is why an exactly-full last page reports `nextCursor: null`.
 * Deciding "there is more" from `rows.length === limit` instead is the classic
 * off-by-one here: a table with exactly 200 rows would hand out a cursor to an
 * empty page forever, and a caller looping until the page is empty would make one
 * pointless query per poll.
 */
export function toPage<Row, Item>(
  rows: Row[],
  limit: number,
  map: (row: Row) => Item,
  cursorOf: (row: Row) => string,
): Page<Item> {
  const hasMore = rows.length > limit;
  const kept = hasMore ? rows.slice(0, limit) : rows;
  const last = kept[kept.length - 1];
  return {
    items: kept.map(map),
    nextCursor: hasMore && last !== undefined ? cursorOf(last) : null,
  };
}
