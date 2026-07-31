/**
 * "There is more than this" — the signal, and the button.
 *
 * The server now bounds every list endpoint. That was necessary (an unbounded read
 * stalls the one process that also serves policy resolution) but it moved the problem
 * rather than solving it: a page that fetches 200 rows and renders them looks exactly
 * like a page showing everything. Nobody misreads a list that says it is truncated.
 * Everybody misreads one that does not.
 *
 * Where that matters most is the audit log. A reviewer asking "did anyone change this
 * policy" reads a complete-looking list, sees nothing, and concludes nothing happened —
 * and the whole point of an audit trail is that this conclusion is trustworthy. The same
 * applies more quietly elsewhere: an install missing from a truncated list reads as an
 * install that was never registered.
 *
 * So the emphasis here is deliberately on the *state*, not the control. The count and the
 * warning render whether or not more pages are being fetched; the button is secondary.
 */

export interface MoreResultsProps {
  /** How many rows are currently loaded. */
  readonly loaded: number;
  /** Cursor for the next page. `null` or absent means this is everything. */
  readonly nextCursor?: string | null;
  /** What is being counted, plural: "entries", "policies", "installs". */
  readonly noun: string;
  /** True while the next page is in flight. */
  readonly loading?: boolean;
  readonly onLoadMore: () => void;
  /**
   * Set when a filter is applied client-side over only the loaded rows.
   *
   * This is the sharper half of the problem. A filter that searches the loaded page and
   * reports "no matches" is not merely incomplete — it is *wrong*, because the reader
   * asked a question about the whole log and got an answer about a slice of it. Saying so
   * is the minimum; the fix is to filter server-side, which these endpoints do not offer
   * yet.
   */
  readonly filtered?: boolean;
}

export function MoreResults({
  loaded,
  nextCursor,
  noun,
  loading = false,
  onLoadMore,
  filtered = false,
}: MoreResultsProps) {
  const complete = nextCursor === null || nextCursor === undefined;

  if (complete) {
    // Stated positively, and only once everything is in hand. "Showing all 12 policies"
    // is worth a line precisely because it licenses the reader to draw a conclusion from
    // an absence.
    return (
      <p className="more-results more-results--complete">
        Showing all {loaded} {noun}.
      </p>
    );
  }

  return (
    <div className="more-results" role="status">
      <p className="more-results__warning">
        <strong>
          Showing the first {loaded} {noun}. There are more.
        </strong>{" "}
        {filtered ? (
          <>
            The filter above searches only these {loaded} — a result of “no matches” does
            not mean there are none. Load more before concluding anything from an absence.
          </>
        ) : (
          <>An item you expect to see may be on a later page.</>
        )}
      </p>
      <button type="button" onClick={onLoadMore} disabled={loading}>
        {loading ? "Loading…" : `Load more ${noun}`}
      </button>
    </div>
  );
}
