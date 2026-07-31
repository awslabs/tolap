/**
 * `fetchAll`, and the two ways following a cursor can go wrong.
 *
 * Used for the lists that populate a **selector** rather than a browsable table — the
 * policy sidebar, the source dropdown, the policy `<select>` on the assignments page. A
 * truncated table is a visible annoyance and gets a "load more" control; a truncated
 * dropdown is a silent one, because the author looks for a policy that exists, does not
 * find it, and reasonably concludes it was never created. There is nowhere to put a
 * control inside a `<select>`.
 *
 * Which means this function must never quietly return a partial list — that is the exact
 * failure it exists to prevent, moved one level down. Both bounds below therefore throw
 * rather than returning what they have.
 */

import { describe, expect, it, vi } from "vitest";
import { fetchAll } from "./api.ts";

/** A paginated endpoint over a fixed set of rows. */
function pagedSource(rows: string[], pageSize: number) {
  return vi.fn(async (cursor?: string) => {
    const start = cursor === undefined ? 0 : Number(cursor);
    const slice = rows.slice(start, start + pageSize);
    const next = start + pageSize;
    return {
      items: slice,
      nextCursor: next < rows.length ? String(next) : null,
    };
  });
}

describe("fetchAll", () => {
  it("follows the cursor to the end and preserves order", async () => {
    const rows = Array.from({ length: 25 }, (_, i) => `row-${i}`);
    const fetchPage = pagedSource(rows, 10);

    expect(await fetchAll<string>(fetchPage, "items")).toEqual(rows);
    // 3 pages for 25 rows at 10 apiece -- the last one reports nextCursor: null.
    expect(fetchPage).toHaveBeenCalledTimes(3);
  });

  it("makes exactly one request when the first page is the last", async () => {
    const fetchPage = pagedSource(["only"], 10);
    expect(await fetchAll<string>(fetchPage, "items")).toEqual(["only"]);
    expect(fetchPage).toHaveBeenCalledTimes(1);
  });

  it("treats an absent cursor as the end, not as unknown", async () => {
    // An endpoint that does not paginate at all returns no `nextCursor` field.
    const fetchPage = vi.fn(async () => ({ items: ["a", "b"] }));
    expect(await fetchAll<string>(fetchPage, "items")).toEqual(["a", "b"]);
    expect(fetchPage).toHaveBeenCalledTimes(1);
  });

  it("handles an empty result", async () => {
    const fetchPage = vi.fn(async () => ({ items: [], nextCursor: null }));
    expect(await fetchAll<string>(fetchPage, "items")).toEqual([]);
  });

  it("tolerates a missing items key rather than crashing", async () => {
    // A shape change on the server should degrade to "nothing" here, not to a TypeError
    // inside a page load.
    const fetchPage = vi.fn(async () => ({ nextCursor: null }));
    expect(await fetchAll<string>(fetchPage, "items")).toEqual([]);
  });

  it("throws rather than spinning when the cursor does not advance", async () => {
    // A server bug that returns the same cursor forever would otherwise be an infinite
    // loop inside a page load -- a hung tab with no error, which is worse than a failure.
    const fetchPage = vi.fn(async () => ({ items: ["x"], nextCursor: "same" }));
    await expect(fetchAll<string>(fetchPage, "items")).rejects.toThrow(
      /did not advance/,
    );
    // Detected on the second response, not after exhausting the page cap.
    expect(fetchPage).toHaveBeenCalledTimes(2);
  });

  it("throws rather than returning a partial list at the page cap", async () => {
    // The important half. Returning 20 pages of a 40-page list would put the caller back
    // in the state this function exists to avoid: a short list that looks complete.
    const rows = Array.from({ length: 500 }, (_, i) => `row-${i}`);
    const fetchPage = pagedSource(rows, 10);

    await expect(fetchAll<string>(fetchPage, "items")).rejects.toThrow(
      /refusing to load a partial list silently/,
    );
  });

  it("names the list in its errors", async () => {
    // The message reaches a failure banner, where "policies" versus "sources" is the
    // difference between an actionable report and a shrug.
    const fetchPage = vi.fn(async () => ({ policies: ["p"], nextCursor: "stuck" }));
    await expect(fetchAll<string>(fetchPage, "policies")).rejects.toThrow(/policies/);
  });

  it("propagates a request failure instead of returning what it has", async () => {
    // Half a selector is indistinguishable from a small deployment.
    const fetchPage = vi
      .fn<(cursor?: string) => Promise<{ items: string[]; nextCursor: string | null }>>()
      .mockResolvedValueOnce({ items: ["a"], nextCursor: "1" })
      .mockRejectedValueOnce(new Error("gateway timeout"));

    await expect(fetchAll<string>(fetchPage, "items")).rejects.toThrow(/gateway timeout/);
  });
});
