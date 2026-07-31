/**
 * The source catalog.
 *
 * The catalog is an *authoring aid* and never consulted at enforcement time, which sets
 * the stakes precisely: a wrong catalog cannot break enforcement, but a missing or stale
 * one lets a typo'd field name into a policy, where nothing can detect it. So the risks
 * here are about the import round-trip being honest:
 *
 * 1. The three import modes send genuinely different payloads to different endpoints -- a
 *    SQL DDL body is a raw string, an OpenAPI body is parsed JSON. Sending the wrong shape
 *    fails at the server, or worse, imports nothing and reports success.
 * 2. A JSON typo is the author's mistake, and saying so beats a server error that sends
 *    them to the logs.
 * 3. The confirmation counts objects and fields, because "imported 0 fields" is the signal
 *    that a DDL dialect was not understood -- and it looks like success otherwise.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { api as realApi, type SourceManifest } from "../api.ts";
import { CatalogPage } from "./CatalogPage.tsx";

vi.mock("../api.ts", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api.ts")>()),
  api: {
    listSources: vi.fn(),
    putSource: vi.fn(),
    importOpenApi: vi.fn(),
    importSql: vi.fn(),
    deleteSource: vi.fn(),
  },
}));

const api = vi.mocked(realApi);

const DB_SOURCE: SourceManifest = {
  sourceConnectionId: "db:analytics:patients",
  category: "db",
  objects: [
    { name: "patients", fields: ["patient_id", "ssn_number", "region"] },
    { name: "encounters", fields: ["id"] },
  ],
  endpoints: [],
  tags: [],
  prefixes: [],
};

const API_SOURCE: SourceManifest = {
  sourceConnectionId: "api:internal:clinical",
  category: "api",
  objects: [],
  endpoints: [{ path: "/patients", methods: ["GET"], responseFields: ["ssn"] }],
  tags: [],
  prefixes: [],
};

async function renderPage({ sources = [] as SourceManifest[], readOnly = false } = {}) {
  api.listSources.mockResolvedValue({ sources });
  api.putSource.mockResolvedValue(DB_SOURCE);
  api.importOpenApi.mockResolvedValue(API_SOURCE);
  api.importSql.mockResolvedValue(DB_SOURCE);
  api.deleteSource.mockResolvedValue(undefined);

  const view = render(<CatalogPage readOnly={readOnly} />);
  await waitFor(() => expect(api.listSources).toHaveBeenCalled());
  return view;
}

const chooseMode = (label: string) =>
  userEvent.click(screen.getByRole("radio", { name: label }));

/**
 * The import body, whichever mode is selected.
 *
 * The label text changes per mode, and the parenthesised forms are required to
 * disambiguate: a bare /Manifest/ also matches the "Manifest JSON" radio button.
 */
const bodyField = () =>
  screen.getByLabelText(
    /CREATE TABLE statements|OpenAPI document \(JSON\)|Manifest \(JSON\)/,
  );

/**
 * Put text in the import body.
 *
 * Pasted rather than typed: `userEvent.type` reads `{` as the start of a key descriptor,
 * so a JSON document typed character by character never arrives intact. Pasting is also
 * what an author actually does with an OpenAPI document.
 */
async function typeBody(text: string) {
  const field = bodyField();
  await userEvent.click(field);
  await userEvent.paste(text);
}

const importNow = () => userEvent.click(screen.getByRole("button", { name: "Import" }));

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  cleanup();
});

describe("what the catalog is for", () => {
  it("says the catalog is never consulted when a policy is enforced", async () => {
    // Load-bearing: an administrator who believes the catalog gates enforcement would
    // treat a missing source as a safety control. It is not one.
    await renderPage();
    const hint = screen.getByText(/Never consulted when a policy is enforced/);
    expect(hint.textContent).toMatch(/typo'd field name in a policy is invisible to TOLAP/);
  });

  it("says so when the catalog is empty", async () => {
    await renderPage();
    expect(screen.getByText("Nothing in the catalog yet.")).toBeDefined();
  });

  it("reports a failed load", async () => {
    api.listSources.mockRejectedValue(new Error("catalog unavailable"));
    render(<CatalogPage readOnly={false} />);
    expect((await screen.findByRole("alert")).textContent).toMatch(
      /catalog unavailable/,
    );
  });
});

describe("listing sources", () => {
  it("counts fields across every object, not objects alone", async () => {
    // The field count is the number that tells an author whether the import actually
    // understood the schema; summing only the first object would hide a partial import.
    await renderPage({ sources: [DB_SOURCE] });

    const row = screen.getByRole("row", { name: /db:analytics:patients/ });
    const cells = within(row)
      .getAllByRole("cell")
      .map((cell) => cell.textContent);
    // id, category, objects, fields, endpoints
    expect(cells.slice(0, 5)).toEqual([
      "db:analytics:patients",
      "db",
      "2",
      "4",
      "0",
    ]);
  });

  it("shows the category, which decides which policy sections apply", async () => {
    await renderPage({ sources: [DB_SOURCE, API_SOURCE] });
    const rows = screen.getAllByRole("row").slice(1);
    expect(rows[0]!.textContent).toMatch(/db/);
    expect(rows[1]!.textContent).toMatch(/api/);
    expect(
      within(rows[1]!).getAllByRole("cell")[4]!.textContent,
    ).toBe("1");
  });
});

describe("importing", () => {
  it("defaults to SQL DDL, the mode that needs no hand-written JSON", async () => {
    await renderPage();
    expect((screen.getByRole("radio", { name: "SQL DDL" }) as HTMLInputElement).checked).toBe(
      true,
    );
  });

  it("sends DDL as a raw string, not as JSON", async () => {
    // `importSql` takes the text verbatim. Parsing it here would throw on the first
    // `CREATE TABLE` and blame the author for valid input.
    await renderPage();
    await userEvent.type(screen.getByLabelText("Source connection ID"), "db:analytics:patients");
    await typeBody("CREATE TABLE patients (patient_id int, ssn_number text);");
    await importNow();

    await waitFor(() => expect(api.importSql).toHaveBeenCalled());
    const [id, ddl] = api.importSql.mock.calls.at(-1)!;
    expect(id).toBe("db:analytics:patients");
    expect(ddl).toBe("CREATE TABLE patients (patient_id int, ssn_number text);");
    expect(api.importOpenApi).not.toHaveBeenCalled();
    expect(api.putSource).not.toHaveBeenCalled();
  });

  it("sends an OpenAPI document as parsed JSON", async () => {
    await renderPage();
    await chooseMode("OpenAPI");
    await userEvent.type(screen.getByLabelText("Source connection ID"), "api:internal:clinical");
    await typeBody('{"openapi":"3.0.0"}');
    await importNow();

    await waitFor(() => expect(api.importOpenApi).toHaveBeenCalled());
    const [id, spec] = api.importOpenApi.mock.calls.at(-1)!;
    expect(id).toBe("api:internal:clinical");
    // Parsed, so the server receives an object rather than a string containing an object.
    expect(spec).toEqual({ openapi: "3.0.0" });
    expect(api.importSql).not.toHaveBeenCalled();
  });

  it("sends a manifest without asking for a separate id", async () => {
    // The manifest carries its own `sourceConnectionId`, so a second field for it would be
    // a chance for the two to disagree.
    await renderPage();
    await chooseMode("Manifest JSON");

    expect(screen.queryByLabelText("Source connection ID")).toBeNull();

    await typeBody('{"sourceConnectionId":"db:analytics:patients","category":"db"}');
    await importNow();

    await waitFor(() => expect(api.putSource).toHaveBeenCalled());
    expect(api.putSource.mock.calls.at(-1)![0]).toEqual({
      sourceConnectionId: "db:analytics:patients",
      category: "db",
    });
  });

  it("blames a JSON typo on the JSON rather than on the server", async () => {
    /*
     * Otherwise the author reads a parse error as a server fault and goes looking in the
     * logs for a mistake that is on screen.
     *
     * Asserted on the page's own prefix rather than on "not valid JSON", because V8's
     * `SyntaxError.message` happens to contain that phrase already -- a test matching only
     * the phrase passes even if the SyntaxError branch is deleted and the raw error is
     * shown. The prefix is the part the page contributes.
     */
    await renderPage();
    await chooseMode("Manifest JSON");
    await typeBody('{"category": }');
    await importNow();

    await waitFor(() =>
      expect(screen.getByRole("alert").textContent).toMatch(/^That is not valid JSON: /),
    );
    // Never reached the network.
    expect(api.putSource).not.toHaveBeenCalled();
  });

  it("reports the counts a successful import produced", async () => {
    // "0 field(s)" is how an author learns the DDL dialect was not understood. Without the
    // numbers, a no-op import is indistinguishable from a good one.
    await renderPage();
    await userEvent.type(screen.getByLabelText("Source connection ID"), "db:analytics:patients");
    await typeBody("CREATE TABLE patients (patient_id int);");
    await importNow();

    const status = await screen.findByRole("status");
    expect(status.textContent).toMatch(/Saved db:analytics:patients/);
    expect(status.textContent).toMatch(/2 object\(s\)/);
    expect(status.textContent).toMatch(/4 field\(s\)/);
    expect(status.textContent).toMatch(/0 endpoint\(s\)/);
  });

  it("reports an import that found nothing, without calling it a failure", async () => {
    // The honest outcome for an unrecognised dialect: the server accepted it and extracted
    // nothing. Reporting zero is the whole point.
    await renderPage();
    // After renderPage, which installs the default resolutions.
    api.importSql.mockResolvedValue({
      ...DB_SOURCE,
      objects: [],
      endpoints: [],
    });
    await userEvent.type(screen.getByLabelText("Source connection ID"), "db:analytics:patients");
    await typeBody("-- a dialect the importer does not know");
    await importNow();

    const status = await screen.findByRole("status");
    expect(status.textContent).toMatch(/0 object\(s\)/);
    expect(status.textContent).toMatch(/0 field\(s\)/);
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("clears the body but keeps the id, so a second import needs less retyping", async () => {
    await renderPage();
    const idInput = screen.getByLabelText("Source connection ID") as HTMLInputElement;
    await userEvent.type(idInput, "db:analytics:patients");
    const body = bodyField() as HTMLTextAreaElement;
    await userEvent.type(body, "CREATE TABLE patients (patient_id int);");
    await importNow();

    await waitFor(() => expect(body.value).toBe(""));
    expect(idInput.value).toBe("db:analytics:patients");
  });

  it("reloads the catalog after an import", async () => {
    await renderPage();
    expect(api.listSources).toHaveBeenCalledTimes(1);

    await userEvent.type(screen.getByLabelText("Source connection ID"), "db:analytics:patients");
    await typeBody("CREATE TABLE patients (patient_id int);");
    await importNow();

    await waitFor(() => expect(api.listSources).toHaveBeenCalledTimes(2));
  });

  it("keeps the body when the server rejects the import", async () => {
    // Retyping a pasted OpenAPI document because of a transient failure is a real cost.
    await renderPage();
    api.importSql.mockRejectedValue(new Error("unsupported dialect"));
    await userEvent.type(screen.getByLabelText("Source connection ID"), "db:analytics:patients");
    await typeBody("CREATE TABLE patients (patient_id int);");
    await importNow();

    await waitFor(() =>
      expect(screen.getByRole("alert").textContent).toMatch(/unsupported dialect/),
    );
    expect((bodyField() as HTMLTextAreaElement).value).not.toBe(
      "",
    );
  });

  it("will not import an empty or whitespace-only body", async () => {
    await renderPage();
    const button = screen.getByRole("button", { name: "Import" }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);

    await typeBody("   ");
    expect(button.disabled).toBe(true);

    await typeBody("CREATE TABLE t (a int);");
    expect(button.disabled).toBe(false);
  });

  it("requires a source id for the two modes that need one", async () => {
    await renderPage();
    await typeBody("CREATE TABLE patients (patient_id int);");
    await importNow();

    // Blocked by the browser, so nothing is sent under a blank id.
    expect(api.importSql).not.toHaveBeenCalled();
    expect(
      (screen.getByLabelText("Source connection ID") as HTMLInputElement).validity
        .valueMissing,
    ).toBe(true);
  });
});

describe("removing a source", () => {
  it("removes the source the administrator pointed at", async () => {
    await renderPage({ sources: [DB_SOURCE, API_SOURCE] });

    const row = screen.getByRole("row", { name: /api:internal:clinical/ });
    await userEvent.click(within(row).getByRole("button", { name: "Remove" }));

    await waitFor(() =>
      expect(api.deleteSource).toHaveBeenCalledWith("api:internal:clinical"),
    );
    expect(api.deleteSource).toHaveBeenCalledTimes(1);
  });

  it("reports a failed removal", async () => {
    await renderPage({ sources: [DB_SOURCE] });
    api.deleteSource.mockRejectedValue(new Error("still referenced"));

    await userEvent.click(screen.getByRole("button", { name: "Remove" }));

    await waitFor(() =>
      expect(screen.getByRole("alert").textContent).toMatch(/still referenced/),
    );
  });
});

describe("auditor access", () => {
  it("offers an auditor no import form and no remove button", async () => {
    await renderPage({ sources: [DB_SOURCE], readOnly: true });

    expect(screen.queryByRole("button", { name: "Import" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Remove" })).toBeNull();
    expect(screen.queryByLabelText(/CREATE TABLE statements/)).toBeNull();
  });

  it("still shows an auditor what is in the catalog", async () => {
    await renderPage({ sources: [DB_SOURCE], readOnly: true });

    expect(screen.getByText("db:analytics:patients")).toBeDefined();
    expect(screen.getAllByRole("columnheader").map((h) => h.textContent)).toEqual([
      "Source",
      "Category",
      "Objects",
      "Fields",
      "Endpoints",
    ]);
  });
});
