/**
 * Assignments: who a policy applies to.
 *
 * The reassuring property of this page is that it cannot escalate. Merge is
 * most-restrictive-wins, so adding an assignment only ever narrows access -- there is no
 * ordering to get right and no way to widen anything by adding a row. That removes the
 * usual authorization-UI hazards and leaves three that matter:
 *
 * 1. **The reason is the audit trail.** A grant with no stated reason is a grant nobody can
 *    review later, so the field is required rather than merely encouraged.
 * 2. **Scope keys are omitted, not blanked.** An empty `tenantId` means "every tenant"; a
 *    `tenantId: ""` is a tenant whose id is the empty string, which matches nothing. One is
 *    the intended broad grant, the other is a dead assignment.
 * 3. **An auditor cannot grant or revoke.** The server enforces this; the page not offering
 *    the controls is the courtesy.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import {
  api as realApi,
  type PolicyAssignment,
  type PolicyDefinition,
} from "../api.ts";
import { AssignmentsPage } from "./AssignmentsPage.tsx";

vi.mock("../api.ts", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api.ts")>()),
  api: {
    listAssignments: vi.fn(),
    listPolicies: vi.fn(),
    createAssignment: vi.fn(),
    revokeAssignment: vi.fn(),
  },
}));

const api = vi.mocked(realApi);

const POLICIES: PolicyDefinition[] = [
  { version: "1.0", name: "patients-analyst", permissions: { canQuery: true } },
  { version: "1.0", name: "exports-reader", permissions: { canQuery: true } },
];

function assignment(overrides: Partial<PolicyAssignment> = {}): PolicyAssignment {
  return {
    version: "1.0",
    policyName: "patients-analyst",
    assignee: { type: "group", identifier: "analytics-team" },
    scope: {},
    active: true,
    audit: {
      grantedBy: "admin@example.test",
      grantedAt: "2026-01-02T03:04:05.000Z",
      reason: "Cohort analysis",
    },
    ...overrides,
  };
}

async function renderPage(
  { assignments = [] as PolicyAssignment[], readOnly = false } = {},
) {
  api.listAssignments.mockResolvedValue({ assignments });
  api.listPolicies.mockResolvedValue({ policies: POLICIES });
  api.createAssignment.mockResolvedValue(assignment());
  api.revokeAssignment.mockResolvedValue(undefined);

  const view = render(<AssignmentsPage readOnly={readOnly} />);
  await waitFor(() => expect(api.listPolicies).toHaveBeenCalled());
  return view;
}

/** Fill the form the way an administrator does. Returns nothing; asserts nothing. */
async function fillForm({
  policy = "patients-analyst",
  type,
  identifier = "analyst@example.test",
  tenant,
  source,
  reason = "Quarterly review",
}: {
  policy?: string;
  type?: string;
  identifier?: string;
  tenant?: string;
  source?: string;
  reason?: string;
} = {}) {
  await userEvent.selectOptions(screen.getByLabelText("Policy"), policy);
  if (type !== undefined) {
    await userEvent.selectOptions(screen.getByLabelText("Assignee type"), type);
  }
  await userEvent.type(screen.getByLabelText("Assignee identifier"), identifier);
  if (tenant !== undefined) {
    await userEvent.type(screen.getByLabelText("Tenant (optional)"), tenant);
  }
  if (source !== undefined) {
    await userEvent.type(screen.getByLabelText("Source (optional)"), source);
  }
  await userEvent.type(screen.getByLabelText("Reason"), reason);
}

async function submit() {
  await userEvent.click(screen.getByRole("button", { name: "Assign" }));
}

/** The assignment as the server receives it, with `undefined` keys dropped as JSON drops them. */
function created(): PolicyAssignment {
  expect(api.createAssignment).toHaveBeenCalled();
  const [sent] = api.createAssignment.mock.calls.at(-1)!;
  return JSON.parse(JSON.stringify(sent)) as PolicyAssignment;
}

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  cleanup();
});

describe("the merge property, stated on the page", () => {
  it("tells the administrator that adding an assignment cannot widen access", async () => {
    // The reason this page needs no ordering controls and no confirmation step. Stating it
    // is what stops someone inventing a "priority" here that the merge does not have.
    await renderPage();
    const hint = screen.getByText(/most-restrictive-wins/);
    expect(hint.textContent).toMatch(/only narrow access, never widen it/i);
  });
});

describe("listing assignments", () => {
  it("distinguishes an unscoped grant from a scoped one", async () => {
    // "unscoped" means every tenant and every source the policy's patterns match, which is
    // the broadest an assignment gets. A blank cell would read as "not loaded".
    await renderPage({
      assignments: [
        assignment(),
        assignment({
          policyName: "exports-reader",
          assignee: { type: "user", identifier: "analyst@example.test" },
          scope: { tenantId: "tenant-a", sourceConnectionId: "db:analytics:patients" },
        }),
      ],
    });

    const rows = screen.getAllByRole("row").slice(1);
    expect(rows[0]!.textContent).toMatch(/unscoped/);
    expect(rows[1]!.textContent).toMatch(/tenant-a/);
    expect(rows[1]!.textContent).toMatch(/db:analytics:patients/);
    expect(rows[1]!.textContent).not.toMatch(/unscoped/);
  });

  it("says a grant never expires rather than leaving the cell blank", async () => {
    // A standing grant is the thing a reviewer most wants to notice, so it is spelled out.
    await renderPage({ assignments: [assignment()] });
    expect(screen.getByRole("row", { name: /analytics-team/ }).textContent).toMatch(
      /never/,
    );
  });

  it("shows who granted an assignment", async () => {
    await renderPage({ assignments: [assignment()] });
    expect(screen.getByText("admin@example.test")).toBeDefined();
  });

  it("says so when nothing is assigned", async () => {
    await renderPage();
    expect(screen.getByText("No live assignments.")).toBeDefined();
  });

  it("reports a failed load instead of showing an empty list", async () => {
    // "No live assignments" is a dangerous thing to believe when the truth is that the
    // server could not be reached.
    api.listAssignments.mockRejectedValue(new Error("assignments unavailable"));
    api.listPolicies.mockResolvedValue({ policies: [] });
    render(<AssignmentsPage readOnly={false} />);

    expect((await screen.findByRole("alert")).textContent).toMatch(
      /assignments unavailable/,
    );
    expect(screen.queryByText("No live assignments.")).toBeDefined();
  });
});

describe("creating an assignment", () => {
  it("omits an unset tenant and source rather than sending empty strings", async () => {
    // `scope: {}` means every tenant and every source. `scope: { tenantId: "" }` is a
    // tenant literally named "", which matches nothing -- an assignment that appears in
    // the list and grants nobody anything.
    await renderPage();
    await fillForm();
    await submit();

    const sent = created();
    expect(sent.scope).toEqual({});
    expect(Object.keys(sent.scope)).toHaveLength(0);
    // Likewise for an expiry never set: an `expiresAt` of "" or Invalid Date would be
    // worse than absent.
    expect(Object.keys(sent)).not.toContain("expiresAt");
  });

  it("sends the scope keys the administrator did fill in", async () => {
    await renderPage();
    await fillForm({ tenant: "tenant-a", source: "db:analytics:patients" });
    await submit();

    expect(created().scope).toEqual({
      tenantId: "tenant-a",
      sourceConnectionId: "db:analytics:patients",
    });
  });

  it("sends only the source when only the source is narrowed", async () => {
    await renderPage();
    await fillForm({ source: "kb:research:notes" });
    await submit();

    expect(created().scope).toEqual({ sourceConnectionId: "kb:research:notes" });
  });

  it("records the reason, because the reason is the audit trail", async () => {
    await renderPage();
    await fillForm({ reason: "Incident 42 investigation" });
    await submit();

    expect(created().audit.reason).toBe("Incident 42 investigation");
  });

  it("refuses to submit without a reason", async () => {
    // Required in the markup, so the browser blocks the submit. A grant with no stated
    // reason is one no reviewer can later evaluate.
    await renderPage();
    await userEvent.selectOptions(screen.getByLabelText("Policy"), "patients-analyst");
    await userEvent.type(
      screen.getByLabelText("Assignee identifier"),
      "analyst@example.test",
    );
    await submit();

    expect(api.createAssignment).not.toHaveBeenCalled();
    const reason = screen.getByLabelText("Reason") as HTMLInputElement;
    expect(reason.required).toBe(true);
    expect(reason.validity.valueMissing).toBe(true);
  });

  it("refuses to submit without a policy or an assignee", async () => {
    await renderPage();
    await userEvent.type(screen.getByLabelText("Reason"), "no target");
    await submit();

    expect(api.createAssignment).not.toHaveBeenCalled();
    expect((screen.getByLabelText("Policy") as HTMLSelectElement).required).toBe(true);
    expect(
      (screen.getByLabelText("Assignee identifier") as HTMLInputElement).required,
    ).toBe(true);
  });

  it("defaults the assignee type to user and can target a group", async () => {
    // A group grant reaches everyone in the group, so choosing the type deliberately
    // matters; `user` is the narrowest default.
    await renderPage();
    expect((screen.getByLabelText("Assignee type") as HTMLSelectElement).value).toBe(
      "user",
    );

    await fillForm({ type: "group", identifier: "analytics-team" });
    await submit();

    expect(created().assignee).toEqual({
      type: "group",
      identifier: "analytics-team",
    });
  });

  it("sends an expiry as a UTC instant, not the local string the picker shows", async () => {
    // The input is `datetime-local` and carries no zone. Sending its raw value would have
    // the server interpret a wall-clock time in its own zone, so a grant could expire
    // hours early or late.
    await renderPage();
    await fillForm();
    await userEvent.type(
      screen.getByLabelText("Expires (optional)"),
      "2026-12-31T23:59",
    );
    await submit();

    const sent = created();
    expect(sent.expiresAt).toBe(new Date("2026-12-31T23:59").toISOString());
    expect(sent.expiresAt).toMatch(/Z$/);
  });

  it("marks a new assignment active", async () => {
    await renderPage();
    await fillForm();
    await submit();
    expect(created().active).toBe(true);
  });

  it("confirms the grant and clears the fields that must not be reused", async () => {
    // Leaving the identifier and reason populated is how the next grant silently inherits
    // the previous one's justification.
    await renderPage();
    await fillForm({ identifier: "analyst@example.test", reason: "Quarterly review" });
    await submit();

    await waitFor(() =>
      expect(screen.getByRole("status").textContent).toMatch(
        /Assigned patients-analyst to analyst@example\.test/,
      ),
    );
    expect((screen.getByLabelText("Assignee identifier") as HTMLInputElement).value).toBe(
      "",
    );
    expect((screen.getByLabelText("Reason") as HTMLInputElement).value).toBe("");
  });

  it("reloads the list after a grant so the new row is visible", async () => {
    await renderPage();
    expect(api.listAssignments).toHaveBeenCalledTimes(1);

    await fillForm();
    await submit();

    await waitFor(() => expect(api.listAssignments).toHaveBeenCalledTimes(2));
  });

  it("reports a rejected grant and keeps the form filled in", async () => {
    // Losing the typed reason on a server error means retyping it, which is how a shorter
    // and less useful reason ends up in the audit log.
    await renderPage();
    api.createAssignment.mockRejectedValue(new Error("policy not found"));

    await fillForm({ identifier: "analyst@example.test", reason: "Quarterly review" });
    await submit();

    await waitFor(() =>
      expect(screen.getByRole("alert").textContent).toMatch(/policy not found/),
    );
    expect((screen.getByLabelText("Reason") as HTMLInputElement).value).toBe(
      "Quarterly review",
    );
  });

  it("offers every policy in the catalog", async () => {
    await renderPage();
    const options = [...screen.getByLabelText("Policy").querySelectorAll("option")].map(
      (option) => option.getAttribute("value"),
    );
    // "" is the unselected placeholder, which is why the field is `required`.
    expect(options).toEqual(["", "patients-analyst", "exports-reader"]);
  });
});

describe("revoking", () => {
  it("revokes the row the administrator pointed at", async () => {
    await renderPage({
      assignments: [
        assignment(),
        assignment({
          policyName: "exports-reader",
          assignee: { type: "user", identifier: "analyst@example.test" },
        }),
      ],
    });

    const row = screen.getByRole("row", { name: /exports-reader/ });
    await userEvent.click(
      await within(row).findByRole("button", { name: "Revoke" }),
    );

    await waitFor(() =>
      expect(api.revokeAssignment).toHaveBeenCalledWith(
        "exports-reader",
        "analyst@example.test",
      ),
    );
    expect(api.revokeAssignment).toHaveBeenCalledTimes(1);
  });

  it("reloads the list after a revoke", async () => {
    await renderPage({ assignments: [assignment()] });
    await userEvent.click(screen.getByRole("button", { name: "Revoke" }));
    await waitFor(() => expect(api.listAssignments).toHaveBeenCalledTimes(2));
  });

  it("reports a failed revoke rather than appearing to succeed", async () => {
    // The row stays on screen either way, so without a message the administrator would
    // reasonably believe the access was removed.
    await renderPage({ assignments: [assignment()] });
    api.revokeAssignment.mockRejectedValue(new Error("revoke failed"));

    await userEvent.click(screen.getByRole("button", { name: "Revoke" }));

    await waitFor(() =>
      expect(screen.getByRole("alert").textContent).toMatch(/revoke failed/),
    );
  });
});

describe("auditor access", () => {
  it("offers an auditor no way to grant or revoke", async () => {
    await renderPage({ assignments: [assignment()], readOnly: true });

    expect(screen.queryByRole("button", { name: "Assign" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Revoke" })).toBeNull();
    // The whole form, not just the button: a rendered form an auditor cannot submit is a
    // form that wastes their time and then 403s.
    expect(screen.queryByLabelText("Assignee identifier")).toBeNull();
    expect(screen.queryByLabelText("Reason")).toBeNull();
  });

  it("still shows an auditor who has access to what", async () => {
    // Reading assignments is the auditor's job.
    await renderPage({ assignments: [assignment()], readOnly: true });

    expect(screen.getByText("patients-analyst")).toBeDefined();
    expect(screen.getByRole("row", { name: /analytics-team/ })).toBeDefined();
    const headers = screen.getAllByRole("columnheader").map((h) => h.textContent);
    expect(headers).toEqual([
      "Policy",
      "Assignee",
      "Scope",
      "Expires",
      "Granted by",
    ]);
  });
});
