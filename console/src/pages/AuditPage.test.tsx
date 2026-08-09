/**
 * The audit log.
 *
 * A read-only view, so there is no state to corrupt -- which moves the risk to whether it
 * tells the truth about what it is showing:
 *
 * 1. **"Nothing recorded" and "nothing matched" are different facts.** Collapsing them into
 *    one empty state tells a reviewer their filter found nothing when the log is empty, or
 *    that the log is empty when their filter is simply too narrow. Either reading can end an
 *    investigation early.
 * 2. **The filter has to search what a reviewer types.** Actor, action and target -- the
 *    three fields they actually have in hand -- and case-insensitively, since an actor is a
 *    subject id or an email.
 * 3. **A failed fetch must not look like an empty log.** "Nothing recorded yet" is the worst
 *    possible thing to say when the request failed.
 *
 * There is no readOnly prop: an auditor reading the audit log is the point, and this page
 * has nothing to write.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { api as realApi, type AuditEntry } from "../api.ts";
import { AuditPage } from "./AuditPage.tsx";

vi.mock("../api.ts", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api.ts")>()),
  api: { listAudit: vi.fn() },
}));

const api = vi.mocked(realApi);

function entry(overrides: Partial<AuditEntry> = {}): AuditEntry {
  return {
    at: "2026-01-02T03:04:05.000Z",
    actor: "admin@example.test",
    actorKind: "admin",
    action: "policy.publish",
    targetKind: "policy",
    targetId: "patients-analyst",
    detail: null,
    ...overrides,
  };
}

const ENTRIES: AuditEntry[] = [
  entry(),
  entry({
    at: "2026-01-02T04:00:00.000Z",
    actor: "worker-one",
    actorKind: "install",
    action: "policy.resolve",
    targetId: "exports-reader",
  }),
  entry({
    at: "2026-01-02T05:00:00.000Z",
    actor: "auditor@example.test",
    actorKind: "auditor",
    action: "assignment.create",
    targetId: "analytics-team",
    detail: { reason: "Cohort analysis" },
  }),
];

async function renderPage(entries: AuditEntry[] = ENTRIES) {
  api.listAudit.mockResolvedValue({ entries });
  const view = render(<AuditPage />);
  await waitFor(() => expect(api.listAudit).toHaveBeenCalled());
  return view;
}

/** The actor cell of every visible row. */
function visibleActors(): string[] {
  const rows = screen.queryAllByRole("row").slice(1);
  return rows.map((row) => row.querySelector("code")!.textContent!);
}

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  cleanup();
});

describe("loading", () => {
  it("asks for a bounded page rather than the whole log", async () => {
    // The admin API and /v1/resolve share one process, so an unbounded read would stall
    // policy resolution for every install. 500 is the server's ceiling; asking for more is
    // a 400, not a silently truncated response.
    await renderPage();
    expect(api.listAudit).toHaveBeenCalledWith(500);
  });

  it("distinguishes an empty log from a filter that matched nothing", async () => {
    // The distinction that keeps a reviewer from concluding "no such event exists" when
    // their filter was simply too narrow.
    await renderPage([]);
    expect(screen.getByText("Nothing recorded yet.")).toBeDefined();

    cleanup();
    await renderPage();
    await userEvent.type(screen.getByLabelText("Filter"), "no-such-actor");
    expect(screen.getByText("No matching entries.")).toBeDefined();
    expect(screen.queryByText("Nothing recorded yet.")).toBeNull();
  });

  it("reports a failed fetch instead of claiming the log is empty", async () => {
    // "Nothing recorded yet" over a failed request would read as an assurance that nothing
    // happened -- the most misleading possible message on an audit page.
    api.listAudit.mockRejectedValue(new Error("audit unavailable"));
    render(<AuditPage />);

    expect((await screen.findByRole("alert")).textContent).toMatch(/audit unavailable/);
  });

  it("clears a stale error once a refresh succeeds", async () => {
    // A stuck banner would have a reviewer distrust rows that did load.
    api.listAudit.mockRejectedValue(new Error("audit unavailable"));
    render(<AuditPage />);
    await screen.findByRole("alert");

    api.listAudit.mockResolvedValue({ entries: ENTRIES });
    await userEvent.click(screen.getByRole("button", { name: "Refresh" }));

    await waitFor(() => expect(screen.queryByRole("alert")).toBeNull());
    expect(visibleActors()).toHaveLength(3);
  });

  it("refetches on demand", async () => {
    await renderPage();
    await userEvent.click(screen.getByRole("button", { name: "Refresh" }));
    await waitFor(() => expect(api.listAudit).toHaveBeenCalledTimes(2));
  });
});

describe("what each row shows", () => {
  it("shows the actor, what kind of actor it was, the action and the target", async () => {
    // The kind matters: `policy.resolve` by an install is routine, and the same action by a
    // human is not.
    await renderPage([ENTRIES[1]!]);

    const row = screen.getAllByRole("row")[1]!;
    expect(row.textContent).toMatch(/install/);
    expect(row.textContent).toMatch(/worker-one/);
    expect(row.textContent).toMatch(/policy\.resolve/);
    expect(row.textContent).toMatch(/exports-reader/);
  });

  it("renders the detail payload so the reason behind a change is visible", async () => {
    await renderPage([ENTRIES[2]!]);
    expect(screen.getByText(/"reason":"Cohort analysis"/)).toBeDefined();
  });

  it("renders a row with no target or detail without crashing", async () => {
    // Both are nullable in the API type, and a sign-in event has neither.
    await renderPage([
      entry({ action: "session.start", targetKind: null, targetId: null, detail: null }),
    ]);

    const row = screen.getAllByRole("row")[1]!;
    expect(row.textContent).toMatch(/session\.start/);
    expect(screen.getAllByRole("row")).toHaveLength(2);
  });
});

describe("filtering", () => {
  it("shows every entry when no filter is set", async () => {
    await renderPage();
    expect(visibleActors()).toEqual([
      "admin@example.test",
      "worker-one",
      "auditor@example.test",
    ]);
  });

  it("filters by actor", async () => {
    await renderPage();
    await userEvent.type(screen.getByLabelText("Filter"), "worker-one");
    expect(visibleActors()).toEqual(["worker-one"]);
  });

  it("filters by action", async () => {
    await renderPage();
    await userEvent.type(screen.getByLabelText("Filter"), "assignment.create");
    expect(visibleActors()).toEqual(["auditor@example.test"]);
  });

  it("filters by target", async () => {
    // The reviewer's usual question is "what happened to this policy", so the target has to
    // be searchable even though it is not the actor or the action.
    await renderPage();
    await userEvent.type(screen.getByLabelText("Filter"), "patients-analyst");
    expect(visibleActors()).toEqual(["admin@example.test"]);
  });

  it("matches regardless of case, in both directions", async () => {
    /*
     * Actors are subject ids and email addresses; requiring exact case would hide rows a
     * reviewer knows exist and teach them the filter is broken.
     *
     * Both directions are needed to pin this. A lowercase entry searched with an uppercase
     * needle is caught by lowering the *needle* alone, which the page would do anyway -- so
     * a mixed-case entry searched with a lowercase needle is the case that proves the
     * haystack is lowered too.
     */
    await renderPage([
      entry({ actor: "Admin.User@Example.Test", action: "Policy.Publish" }),
      ENTRIES[1]!,
    ]);
    const filter = screen.getByLabelText("Filter");

    // Uppercase needle against a lowercase entry.
    await userEvent.type(filter, "WORKER-ONE");
    expect(visibleActors()).toEqual(["worker-one"]);

    // Lowercase needle against a mixed-case entry.
    await userEvent.clear(filter);
    await userEvent.type(filter, "admin.user@example.test");
    expect(visibleActors()).toEqual(["Admin.User@Example.Test"]);

    // And on the action, which is stored mixed-case here too.
    await userEvent.clear(filter);
    await userEvent.type(filter, "policy.publish");
    expect(visibleActors()).toEqual(["Admin.User@Example.Test"]);
  });

  it("ignores surrounding whitespace, as a paste tends to carry", async () => {
    await renderPage();
    await userEvent.type(screen.getByLabelText("Filter"), "  worker-one  ");
    expect(visibleActors()).toEqual(["worker-one"]);
  });

  it("treats a whitespace-only filter as no filter", async () => {
    // Otherwise a stray space blanks the table and looks like an empty log.
    await renderPage();
    await userEvent.type(screen.getByLabelText("Filter"), "   ");
    expect(visibleActors()).toHaveLength(3);
    expect(screen.queryByText("No matching entries.")).toBeNull();
  });

  it("matches on a substring rather than requiring the whole value", async () => {
    await renderPage();
    await userEvent.type(screen.getByLabelText("Filter"), "policy.");
    expect(visibleActors()).toEqual(["admin@example.test", "worker-one"]);
  });

  it("does not filter on the detail payload", async () => {
    // Characterising the current scope rather than asserting it is ideal: the filter covers
    // actor, action and target. If detail search is added, this test should change with it
    // rather than silently start passing for the wrong reason.
    await renderPage();
    await userEvent.type(screen.getByLabelText("Filter"), "Cohort analysis");
    expect(screen.getByText("No matching entries.")).toBeDefined();
  });

  it("restores every row when the filter is cleared", async () => {
    await renderPage();
    const filter = screen.getByLabelText("Filter");
    await userEvent.type(filter, "worker-one");
    expect(visibleActors()).toEqual(["worker-one"]);

    await userEvent.clear(filter);
    expect(visibleActors()).toHaveLength(3);
  });

  it("filters the rows it already has without refetching", async () => {
    // A refetch per keystroke would put the shared API process under load from a text box.
    await renderPage();
    await userEvent.type(screen.getByLabelText("Filter"), "worker");
    expect(api.listAudit).toHaveBeenCalledTimes(1);
  });
});
