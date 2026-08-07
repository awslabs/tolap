/**
 * Endpoint and method rules for `api` sources.
 *
 * The endpoint picker is where the OpenAPI importer pays off: the importer has already
 * rewritten `/patients/{id}` to `/patients/*`, so an author picking from the list gets a
 * pattern that matches at enforcement time instead of a literal `{id}` that never matches.
 *
 * The method picker guards a distinction the schema makes and a checkbox grid cannot show
 * on its own: `allowedMethods` absent means the read-only default, while `allowedMethods:
 * []` denies every request. Both render as "nothing ticked".
 */

import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { EndpointPicker, MethodPicker, endpointOptions } from "./EndpointPicker.tsx";
import type { SourceManifest } from "../api.ts";

const MANIFEST: SourceManifest = {
  sourceConnectionId: "api:internal:clinical",
  category: "api",
  objects: [],
  endpoints: [
    { path: "/api/v1/patients", methods: ["GET", "POST"], responseFields: ["id", "ssn"] },
    { path: "/api/v1/patients/*/labs", methods: ["GET"], responseFields: ["result"] },
  ],
  tags: [],
  prefixes: [],
};

describe("endpointOptions", () => {
  it("lists paths with their methods, sorted", () => {
    expect(endpointOptions(MANIFEST)).toEqual([
      { path: "/api/v1/patients", methods: ["GET", "POST"] },
      { path: "/api/v1/patients/*/labs", methods: ["GET"] },
    ]);
  });

  it("returns nothing without a manifest", () => {
    expect(endpointOptions(undefined)).toEqual([]);
  });
});

describe("EndpointPicker", () => {
  it("explains that empty denies every endpoint but absent does not", () => {
    render(
      <EndpointPicker
        label="Allowed endpoints"
        selected={[]}
        manifest={MANIFEST}
        onChange={vi.fn()}
      />,
    );
    const note = screen.getByRole("note");
    expect(note.textContent).toMatch(/denies every endpoint/i);
    expect(note.textContent).toMatch(/unrestricted/i);
  });

  it("offers imported paths and shows the methods each one has", () => {
    const { container } = render(
      <EndpointPicker
        label="Allowed endpoints"
        selected={[]}
        manifest={MANIFEST}
        onChange={vi.fn()}
      />,
    );
    const values = [...container.querySelectorAll("datalist option")].map((option) =>
      option.getAttribute("value"),
    );
    // The glob form the importer produced, not the OpenAPI `{id}` template.
    expect(values).toEqual(["/api/v1/patients", "/api/v1/patients/*/labs"]);
    expect(screen.getByText(/2 endpoint\(s\) available/i)).toBeDefined();
  });

  it("shows the methods alongside a selected endpoint", () => {
    render(
      <EndpointPicker
        label="Allowed endpoints"
        selected={["/api/v1/patients"]}
        manifest={MANIFEST}
        onChange={vi.fn()}
      />,
    );
    // Allowing an endpoint that offers POST is worth seeing while allowing it.
    expect(screen.getByText("GET POST")).toBeDefined();
  });

  it("flags a path the imported document does not describe", () => {
    render(
      <EndpointPicker
        label="Allowed endpoints"
        selected={["/api/v1/patient"]}
        manifest={MANIFEST}
        onChange={vi.fn()}
      />,
    );
    expect(screen.getByText(/not in catalog/i)).toBeDefined();
  });

  it("does not flag a glob, since a pattern need not match a listed path", () => {
    render(
      <EndpointPicker
        label="Allowed endpoints"
        selected={["/api/v1/*"]}
        manifest={MANIFEST}
        onChange={vi.fn()}
      />,
    );
    expect(screen.queryByText(/not in catalog/i)).toBeNull();
  });

  it("does not flag anything before an OpenAPI import", () => {
    render(
      <EndpointPicker
        label="Allowed endpoints"
        selected={["/anything"]}
        onChange={vi.fn()}
      />,
    );
    expect(screen.queryByText(/not in catalog/i)).toBeNull();
    expect(screen.getByLabelText("Add to Allowed endpoints")).toHaveProperty(
      "placeholder",
      "Import an OpenAPI document to see suggestions",
    );
  });

  it("adds on Enter without submitting the surrounding form", async () => {
    const onChange = vi.fn();
    const onSubmit = vi.fn((event: React.FormEvent) => event.preventDefault());
    render(
      <form onSubmit={onSubmit}>
        <EndpointPicker
          label="Allowed endpoints"
          selected={[]}
          manifest={MANIFEST}
          onChange={onChange}
        />
      </form>,
    );

    await userEvent.type(
      screen.getByLabelText("Add to Allowed endpoints"),
      "/api/v1/patients{Enter}",
    );

    expect(onChange).toHaveBeenCalledWith(["/api/v1/patients"]);
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it("refuses duplicates and blanks, and trims", async () => {
    const onChange = vi.fn();
    render(
      <EndpointPicker
        label="Allowed endpoints"
        selected={["/api/v1/patients"]}
        manifest={MANIFEST}
        onChange={onChange}
      />,
    );

    const input = screen.getByLabelText("Add to Allowed endpoints");
    await userEvent.type(input, "/api/v1/patients{Enter}");
    expect(onChange).not.toHaveBeenCalled();

    await userEvent.clear(input);
    await userEvent.type(input, "  {Enter}");
    expect(onChange).not.toHaveBeenCalled();

    await userEvent.clear(input);
    await userEvent.type(input, "  /api/v1/patients/*/labs  {Enter}");
    expect(onChange).toHaveBeenCalledWith([
      "/api/v1/patients",
      "/api/v1/patients/*/labs",
    ]);
  });

  it("gives the allowed and hidden pickers separate dropdown ids", () => {
    // Both render side by side in the editor. A shared id would make one datalist win and
    // silently leave the other picker with no suggestions.
    const { container } = render(
      <>
        <EndpointPicker
          label="Allowed endpoints"
          selected={[]}
          manifest={MANIFEST}
          onChange={vi.fn()}
        />
        <EndpointPicker
          label="Hidden endpoints"
          selected={[]}
          manifest={MANIFEST}
          onChange={vi.fn()}
        />
      </>,
    );
    const ids = [...container.querySelectorAll("datalist")].map((list) => list.id);
    expect(ids).toHaveLength(2);
    expect(new Set(ids).size).toBe(2);

    // And each input must point at its own list, not merely exist alongside it.
    const inputs = [...container.querySelectorAll("input[list]")].map((input) =>
      input.getAttribute("list"),
    );
    expect(new Set(inputs)).toEqual(new Set(ids));
  });

  it("removes a selected endpoint", async () => {
    const onChange = vi.fn();
    render(
      <EndpointPicker
        label="Allowed endpoints"
        selected={["/api/v1/patients", "/api/v1/patients/*/labs"]}
        manifest={MANIFEST}
        onChange={onChange}
      />,
    );

    await userEvent.click(
      screen.getByRole("button", {
        name: "Remove /api/v1/patients from Allowed endpoints",
      }),
    );
    expect(onChange).toHaveBeenCalledWith(["/api/v1/patients/*/labs"]);
  });
});

describe("MethodPicker", () => {
  it("treats absent as the read-only default and says which methods that is", () => {
    render(<MethodPicker selected={undefined} manifest={MANIFEST} onChange={vi.fn()} />);

    const box = screen.getByRole("checkbox", { name: /Use the default/ });
    expect((box as HTMLInputElement).checked).toBe(true);
    // The grid is hidden while defaulted, so there is nothing to misread as "none".
    expect(screen.queryByRole("checkbox", { name: /^GET/ })).toBeNull();
  });

  it("emits undefined, not an empty list, when returning to the default", async () => {
    const onChange = vi.fn();
    render(<MethodPicker selected={["GET", "POST"]} manifest={MANIFEST} onChange={onChange} />);

    await userEvent.click(screen.getByRole("checkbox", { name: /Use the default/ }));

    // `[]` would deny every request; absent means read-only. Not interchangeable.
    expect(onChange).toHaveBeenCalledWith(undefined);
  });

  it("starts an explicit list at GET when leaving the default", async () => {
    const onChange = vi.fn();
    render(<MethodPicker selected={undefined} manifest={MANIFEST} onChange={onChange} />);

    await userEvent.click(screen.getByRole("checkbox", { name: /Use the default/ }));

    // Not `[]`: an explicit list that denies everything should be a deliberate act.
    expect(onChange).toHaveBeenCalledWith(["GET"]);
  });

  it("warns when an explicit list is empty and offers the way out", () => {
    render(<MethodPicker selected={[]} manifest={MANIFEST} onChange={vi.fn()} />);
    const warning = screen.getByText(/denies every request/i);
    expect(warning.textContent).toMatch(/read-only default/i);
  });

  it("marks a checked method that can change data", () => {
    render(<MethodPicker selected={["GET", "POST"]} manifest={MANIFEST} onChange={vi.fn()} />);
    // Only for methods actually granted -- flagging unchecked ones is noise.
    expect(screen.getAllByText("writes")).toHaveLength(1);
  });

  it("marks methods no imported endpoint offers", () => {
    render(<MethodPicker selected={["GET"]} manifest={MANIFEST} onChange={vi.fn()} />);
    // The manifest exposes GET and POST. The other five are unused, so allowing them
    // grants nothing today and would grant something if the API later added them.
    expect(screen.getAllByText("unused")).toHaveLength(5);
  });

  it("marks nothing unused when no source is imported", () => {
    render(<MethodPicker selected={["GET"]} onChange={vi.fn()} />);
    expect(screen.queryByText("unused")).toBeNull();
  });

  it("adds and removes individual methods", async () => {
    const onChange = vi.fn();
    render(<MethodPicker selected={["GET"]} manifest={MANIFEST} onChange={onChange} />);

    await userEvent.click(screen.getByRole("checkbox", { name: /^DELETE/ }));
    expect(onChange).toHaveBeenCalledWith(["GET", "DELETE"]);

    onChange.mockClear();
    await userEvent.click(screen.getByRole("checkbox", { name: /^GET/ }));
    expect(onChange).toHaveBeenCalledWith([]);
  });

  it("offers exactly the methods the policy schema enumerates", () => {
    render(<MethodPicker selected={["GET"]} manifest={MANIFEST} onChange={vi.fn()} />);
    const labels = screen
      .getAllByRole("checkbox")
      // Drop the "use the default" toggle; the rest are the grid.
      .slice(1)
      .map((box) => (box as HTMLInputElement).parentElement?.textContent);
    expect(labels).toHaveLength(7);
    expect(labels?.[0]).toMatch(/GET/);
  });
});
