/**
 * The truncation signal.
 *
 * These assertions are about a claim the UI makes rather than about a control. The server
 * bounds every listing, so a page can now render a complete-looking list that is not
 * complete — and the reader draws conclusions from absence. On the audit log that is the
 * whole point of the log: "nobody changed this policy" has to be trustworthy.
 *
 * So the tests below check that the component distinguishes three states an operator would
 * otherwise conflate: everything is here, more exists, and more exists *while a filter is
 * hiding rows the filter never searched*.
 */

import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MoreResults } from "./MoreResults.tsx";

describe("MoreResults", () => {
  it("licenses a conclusion from absence only when the list is complete", () => {
    // `null` means the server said this is the last page. Stated positively and counted,
    // because that is what makes "the install I expected is not here" a real finding
    // rather than a guess about pagination.
    render(
      <MoreResults loaded={12} nextCursor={null} noun="policies" onLoadMore={vi.fn()} />,
    );
    expect(screen.getByText(/Showing all 12 policies/)).toBeDefined();
    expect(screen.queryByRole("button")).toBeNull();
  });

  it("treats an absent cursor as complete, not as unknown", () => {
    // A caller that has not wired paging passes nothing. Rendering a truncation warning
    // there would cry wolf on every complete list and train the reader to ignore it.
    render(<MoreResults loaded={3} noun="installs" onLoadMore={vi.fn()} />);
    expect(screen.getByText(/Showing all 3 installs/)).toBeDefined();
  });

  it("says plainly that rows are missing when a cursor remains", () => {
    render(
      <MoreResults
        loaded={200}
        nextCursor="eyJhIjoxfQ"
        noun="entries"
        onLoadMore={vi.fn()}
      />,
    );
    const warning = screen.getByRole("status");
    expect(warning.textContent).toMatch(/first 200 entries/);
    expect(warning.textContent).toMatch(/There are more/);
    // The consequence, not just the count.
    expect(warning.textContent).toMatch(/may be on a later page/);
  });

  it("warns that a client-side filter searched only the loaded rows", () => {
    // The sharper failure. A filter over a truncated page reporting "no matches" is not
    // incomplete, it is wrong: the reader asked about the whole log and got an answer
    // about a slice. Until these endpoints filter server-side, saying so is the fix.
    render(
      <MoreResults
        loaded={200}
        nextCursor="eyJhIjoxfQ"
        noun="entries"
        filtered
        onLoadMore={vi.fn()}
      />,
    );
    const warning = screen.getByRole("status");
    expect(warning.textContent).toMatch(/searches only these 200/);
    expect(warning.textContent).toMatch(/does not mean there are none/);
  });

  it("does not claim the filter is partial when everything is loaded", () => {
    // With the full list in hand a client-side filter is perfectly accurate.
    render(
      <MoreResults
        loaded={40}
        nextCursor={null}
        noun="entries"
        filtered
        onLoadMore={vi.fn()}
      />,
    );
    expect(screen.queryByText(/does not mean there are none/)).toBeNull();
  });

  it("requests the next page", async () => {
    const onLoadMore = vi.fn();
    render(
      <MoreResults
        loaded={200}
        nextCursor="eyJhIjoxfQ"
        noun="entries"
        onLoadMore={onLoadMore}
      />,
    );
    await userEvent.click(screen.getByRole("button", { name: /Load more entries/ }));
    expect(onLoadMore).toHaveBeenCalledTimes(1);
  });

  it("keeps the warning visible while loading, and blocks a double request", () => {
    // The count and the warning are the load-bearing part, so they must not disappear
    // into a spinner -- and a second click mid-flight would append the same page twice.
    render(
      <MoreResults
        loaded={200}
        nextCursor="eyJhIjoxfQ"
        noun="entries"
        loading
        onLoadMore={vi.fn()}
      />,
    );
    expect(screen.getByRole("status").textContent).toMatch(/There are more/);
    expect(screen.getByRole("button")).toHaveProperty("disabled", true);
  });
});
