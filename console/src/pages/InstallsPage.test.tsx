/**
 * Registered remote installs.
 *
 * One behaviour dominates this page: the credential is shown **exactly once**, because the
 * server keeps only its hash. Everything worth testing follows from that.
 *
 * - The warning has to say the credential is unrecoverable *before* the admin dismisses it,
 *   not after. An admin who closes the panel believing they can find it later has to revoke
 *   the install and register a new one.
 * - It must not be re-displayed by an unrelated re-render, and it must not survive a
 *   dismissal, because a credential left on screen is a credential on a projector.
 * - Revoking one install must not disturb the others; that per-install isolation is the
 *   stated reason each install has its own credential.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { api as realApi, type Install } from "../api.ts";
import { InstallsPage } from "./InstallsPage.tsx";

vi.mock("../api.ts", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api.ts")>()),
  api: {
    listInstalls: vi.fn(),
    createInstall: vi.fn(),
    revokeInstall: vi.fn(),
  },
}));

const api = vi.mocked(realApi);

/** A neutral placeholder that is obviously not a real secret. */
const CREDENTIAL = "test-credential-value-not-a-real-secret";

function install(overrides: Partial<Install> = {}): Install {
  return {
    id: "worker-one",
    name: "Analytics worker",
    createdAt: "2026-01-02T03:04:05.000Z",
    revokedAt: null,
    lastSeenAt: "2026-01-03T04:05:06.000Z",
    ...overrides,
  };
}

async function renderPage({ installs = [] as Install[], readOnly = false } = {}) {
  api.listInstalls.mockResolvedValue({ installs });
  api.createInstall.mockResolvedValue({
    id: "worker-two",
    name: "Reporting worker",
    credential: CREDENTIAL,
    notice: "Store this now; it cannot be recovered.",
  });
  api.revokeInstall.mockResolvedValue(undefined);

  const view = render(<InstallsPage readOnly={readOnly} />);
  await waitFor(() => expect(api.listInstalls).toHaveBeenCalled());
  return view;
}

async function register(id = "worker-two", name = "Reporting worker") {
  await userEvent.type(screen.getByLabelText("ID"), id);
  await userEvent.type(screen.getByLabelText("Name"), name);
  await userEvent.click(screen.getByRole("button", { name: "Register" }));
}

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  cleanup();
});

describe("listing installs", () => {
  it("says so when nothing is registered", async () => {
    await renderPage();
    expect(screen.getByText("No installs registered.")).toBeDefined();
  });

  it("explains why each install has its own credential", async () => {
    // The reason revocation is per-install and the audit log can attribute a resolve.
    await renderPage();
    const hint = screen.getByText(/Each remote TOLAP install holds its own credential/);
    expect(hint.textContent).toMatch(/revoked without\s+disturbing the others/);
  });

  it("distinguishes an active install from a revoked one", async () => {
    await renderPage({
      installs: [
        install(),
        install({
          id: "worker-old",
          name: "Retired worker",
          revokedAt: "2026-02-01T00:00:00.000Z",
        }),
      ],
    });

    expect(screen.getByRole("row", { name: /worker-one/ }).textContent).toMatch(/active/);
    const revoked = screen.getByRole("row", { name: /worker-old/ });
    expect(revoked.textContent).toMatch(/revoked/);
    // A revoked install cannot be revoked again.
    expect(within(revoked).queryByRole("button", { name: "Revoke" })).toBeNull();
  });

  it("says an install has never resolved a policy rather than leaving the cell blank", async () => {
    // "never" on a registered install is the signal that a deployment never came up, or
    // that its credential is wrong. A blank cell reads as a loading state.
    await renderPage({ installs: [install({ lastSeenAt: null })] });
    expect(screen.getByRole("row", { name: /worker-one/ }).textContent).toMatch(/never/);
  });

  it("reports a failed load", async () => {
    api.listInstalls.mockRejectedValue(new Error("installs unavailable"));
    render(<InstallsPage readOnly={false} />);
    expect((await screen.findByRole("alert")).textContent).toMatch(
      /installs unavailable/,
    );
  });
});

describe("the credential, shown once", () => {
  it("shows the credential with a warning that it cannot be recovered", async () => {
    await renderPage();
    await register();

    const banner = await screen.findByRole("alert");
    expect(banner.textContent).toMatch(/shown once/i);
    // The consequence, stated before the admin dismisses the panel rather than after.
    expect(banner.textContent).toMatch(/cannot be recovered/i);
    expect(banner.textContent).toMatch(/revoke this install and register a new one/i);
    expect(screen.getByText(CREDENTIAL)).toBeDefined();
  });

  it("names the install the credential belongs to", async () => {
    // Registering two workers in a row and pasting the wrong secret into the wrong
    // deployment is the obvious mistake to prevent.
    await renderPage();
    await register();
    expect((await screen.findByRole("alert")).textContent).toMatch(
      /Credential for worker-two/,
    );
  });

  it("removes the credential from the page once it is acknowledged", async () => {
    await renderPage();
    await register();
    await screen.findByText(CREDENTIAL);

    await userEvent.click(screen.getByRole("button", { name: "I have stored it" }));

    expect(screen.queryByText(CREDENTIAL)).toBeNull();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("does not bring a dismissed credential back when the list reloads", async () => {
    // The credential lives in state that a later refresh must not resurrect -- a secret
    // reappearing after being dismissed is a secret on someone's shared screen.
    await renderPage({ installs: [install()] });
    await register();
    await screen.findByText(CREDENTIAL);
    await userEvent.click(screen.getByRole("button", { name: "I have stored it" }));

    // Any subsequent action that refreshes the list.
    await userEvent.click(screen.getByRole("button", { name: "Revoke" }));
    await waitFor(() => expect(api.revokeInstall).toHaveBeenCalled());

    expect(screen.queryByText(CREDENTIAL)).toBeNull();
  });

  it("shows no credential before anything is registered", async () => {
    await renderPage({ installs: [install()] });
    expect(screen.queryByText(/shown once/i)).toBeNull();
  });
});

describe("registering", () => {
  it("registers the id and name the admin typed", async () => {
    await renderPage();
    await register("worker-us-east-1", "East worker");

    await waitFor(() =>
      expect(api.createInstall).toHaveBeenCalledWith("worker-us-east-1", "East worker"),
    );
  });

  it("clears the form so the next install is not registered under the same name", async () => {
    await renderPage();
    await register();

    await waitFor(() =>
      expect((screen.getByLabelText("ID") as HTMLInputElement).value).toBe(""),
    );
    expect((screen.getByLabelText("Name") as HTMLInputElement).value).toBe("");
  });

  it("reloads the list so the new install appears", async () => {
    await renderPage();
    expect(api.listInstalls).toHaveBeenCalledTimes(1);

    await register();

    await waitFor(() => expect(api.listInstalls).toHaveBeenCalledTimes(2));
  });

  it("requires both an id and a name", async () => {
    await renderPage();
    await userEvent.click(screen.getByRole("button", { name: "Register" }));

    expect(api.createInstall).not.toHaveBeenCalled();
    expect((screen.getByLabelText("ID") as HTMLInputElement).validity.valueMissing).toBe(
      true,
    );
  });

  it("rejects an id the server's pattern would refuse", async () => {
    // Surfaced in the markup rather than discovered as a 400, and it matters because the
    // id is what the audit log attributes a resolve to.
    await renderPage();
    const id = screen.getByLabelText("ID") as HTMLInputElement;
    await userEvent.type(id, "Worker One");
    await userEvent.type(screen.getByLabelText("Name"), "Analytics worker");
    await userEvent.click(screen.getByRole("button", { name: "Register" }));

    expect(api.createInstall).not.toHaveBeenCalled();
    expect(id.validity.patternMismatch).toBe(true);
  });

  it("reports a rejected registration and issues no credential", async () => {
    // A failed registration that still showed a credential panel would hand out a secret
    // for an install that does not exist.
    await renderPage();
    api.createInstall.mockRejectedValue(new Error("id already registered"));

    await register();

    await waitFor(() =>
      expect(screen.getByRole("alert").textContent).toMatch(/id already registered/),
    );
    expect(screen.queryByText(CREDENTIAL)).toBeNull();
  });
});

describe("revoking", () => {
  it("revokes the install the admin pointed at", async () => {
    await renderPage({
      installs: [install(), install({ id: "worker-two", name: "Reporting worker" })],
    });

    const row = screen.getByRole("row", { name: /worker-two/ });
    await userEvent.click(within(row).getByRole("button", { name: "Revoke" }));

    await waitFor(() => expect(api.revokeInstall).toHaveBeenCalledWith("worker-two"));
    // Per-install isolation: exactly one call, for exactly that install.
    expect(api.revokeInstall).toHaveBeenCalledTimes(1);
  });

  it("reloads the list after a revoke", async () => {
    await renderPage({ installs: [install()] });
    await userEvent.click(screen.getByRole("button", { name: "Revoke" }));
    await waitFor(() => expect(api.listInstalls).toHaveBeenCalledTimes(2));
  });

  it("reports a failed revoke rather than appearing to succeed", async () => {
    // The row still says "active" either way, so silence would read as success on an
    // install that can still resolve policy.
    await renderPage({ installs: [install()] });
    api.revokeInstall.mockRejectedValue(new Error("revoke failed"));

    await userEvent.click(screen.getByRole("button", { name: "Revoke" }));

    await waitFor(() =>
      expect(screen.getByRole("alert").textContent).toMatch(/revoke failed/),
    );
  });
});

describe("auditor access", () => {
  it("offers an auditor no way to register or revoke", async () => {
    await renderPage({ installs: [install()], readOnly: true });

    expect(screen.queryByRole("button", { name: "Register" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Revoke" })).toBeNull();
    // No form at all: an auditor who could submit it would be issued a credential the
    // server would refuse to mint.
    expect(screen.queryByLabelText("ID")).toBeNull();
  });

  it("still shows an auditor which installs exist and their state", async () => {
    await renderPage({ installs: [install()], readOnly: true });

    expect(screen.getByText("worker-one")).toBeDefined();
    expect(screen.getAllByRole("columnheader").map((h) => h.textContent)).toEqual([
      "ID",
      "Name",
      "Registered",
      "Last resolve",
      "State",
    ]);
  });
});
