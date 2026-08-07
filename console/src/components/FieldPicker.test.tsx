/**
 * The catalog-backed field picker.
 *
 * Two behaviors matter more than the rest:
 *
 * 1. A name that is not in the catalog is **flagged, not blocked**. The catalog is
 *    an authoring aid; if it could refuse a value it would become an authority on
 *    what a policy may say, and a stale manifest would start blocking legitimate
 *    policies.
 * 2. An empty selection is explained, because empty and absent are opposite
 *    policies (spec section 3) and a blank control looks identical either way.
 */

import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { FieldPicker, fieldOptions, objectOptions } from "./FieldPicker.tsx";
import type { SourceManifest } from "../api.ts";

const MANIFEST: SourceManifest = {
  sourceConnectionId: "db:analytics:patients",
  category: "db",
  objects: [
    { name: "patients", fields: ["patient_id", "ssn_number", "region"] },
    { name: "encounters", fields: ["id", "patient_id"] },
  ],
  endpoints: [],
  tags: [],
  prefixes: [],
};

describe("fieldOptions", () => {
  it("offers dotted and bare names, sorted and deduplicated", () => {
    // patient_id appears in two tables; the bare form must appear once.
    expect(fieldOptions(MANIFEST)).toEqual([
      "encounters.id",
      "encounters.patient_id",
      "id",
      "patient_id",
      "patients.patient_id",
      "patients.region",
      "patients.ssn_number",
      "region",
      "ssn_number",
    ]);
  });

  it("includes api response fields", () => {
    const api: SourceManifest = {
      sourceConnectionId: "api:internal:clinical",
      category: "api",
      objects: [],
      endpoints: [{ path: "/patients", methods: ["GET"], responseFields: ["ssn"] }],
      tags: [],
      prefixes: [],
    };
    expect(fieldOptions(api)).toEqual(["ssn"]);
  });

  it("returns nothing without a manifest", () => {
    expect(fieldOptions(undefined)).toEqual([]);
    expect(objectOptions(undefined)).toEqual([]);
  });
});

describe("objectOptions", () => {
  it("offers table names, endpoint paths and storage prefixes", () => {
    expect(objectOptions(MANIFEST)).toEqual(["encounters", "patients"]);

    const storage: SourceManifest = {
      sourceConnectionId: "storage:data:bucket",
      category: "storage",
      objects: [],
      endpoints: [{ path: "/x", methods: ["GET"], responseFields: [] }],
      tags: [],
      prefixes: ["reports/"],
    };
    expect(objectOptions(storage)).toEqual(["/x", "reports/"]);
  });
});

describe("FieldPicker", () => {
  it("explains that an empty selection is not the same as no rule", async () => {
    render(
      <FieldPicker label="Allowed fields" selected={[]} manifest={MANIFEST} onChange={vi.fn()} />,
    );
    // The section 3 distinction, stated where the author is looking.
    const note = screen.getByRole("note");
    expect(note.textContent).toMatch(/denies everything/i);
    expect(note.textContent).toMatch(/unrestricted/i);
  });

  it("adds a catalog value without flagging it", async () => {
    const onChange = vi.fn();
    render(
      <FieldPicker
        label="Hidden fields"
        selected={[]}
        manifest={MANIFEST}
        onChange={onChange}
      />,
    );

    await userEvent.type(
      screen.getByLabelText("Add to Hidden fields"),
      "patients.ssn_number",
    );
    await userEvent.click(screen.getByRole("button", { name: "Add" }));

    expect(onChange).toHaveBeenCalledWith(["patients.ssn_number"]);
  });

  it("flags a value the catalog does not know, but keeps it", async () => {
    // The whole point: `ssn` looks right and is wrong here, because the column is
    // `ssn_number`. TOLAP would enforce it faithfully and protect nothing.
    render(
      <FieldPicker
        label="Hidden fields"
        selected={["ssn"]}
        manifest={MANIFEST}
        onChange={vi.fn()}
      />,
    );

    expect(screen.getByText(/not in catalog/i)).toBeDefined();
    // Still present -- flagged, not rejected.
    expect(screen.getByText("ssn")).toBeDefined();
  });

  it("does not flag a glob pattern", () => {
    render(
      <FieldPicker
        label="Allowed objects"
        selected={["patient_*"]}
        manifest={MANIFEST}
        objects
        onChange={vi.fn()}
      />,
    );
    expect(screen.queryByText(/not in catalog/i)).toBeNull();
    expect(screen.getByText("pattern")).toBeDefined();
  });

  it("does not flag a name that differs only in case", () => {
    // Field matching is case-insensitive at enforcement (canonical spec section 4:
    // `matchForms` lower-cases both the rule and the record key), so `SSN_Number` does
    // hide the `ssn_number` column. A warning that fires on a rule that works is worse
    // than none -- it teaches the author to dismiss the warning that matters.
    render(
      <FieldPicker
        label="Hidden fields"
        selected={["SSN_Number", "PATIENTS.Region"]}
        manifest={MANIFEST}
        onChange={vi.fn()}
      />,
    );
    expect(screen.queryByText(/not in catalog/i)).toBeNull();
  });

  it("does not flag anything when no catalog is loaded", () => {
    // Without a manifest there is nothing to compare against, and warning on every
    // value would train the author to ignore the warning.
    render(
      <FieldPicker label="Hidden fields" selected={["anything"]} onChange={vi.fn()} />,
    );
    expect(screen.queryByText(/not in catalog/i)).toBeNull();
  });

  it("adds on Enter without submitting the surrounding form", async () => {
    const onChange = vi.fn();
    const onSubmit = vi.fn((event: React.FormEvent) => event.preventDefault());
    render(
      <form onSubmit={onSubmit}>
        <FieldPicker
          label="Hidden fields"
          selected={[]}
          manifest={MANIFEST}
          onChange={onChange}
        />
      </form>,
    );

    await userEvent.type(screen.getByLabelText("Add to Hidden fields"), "region{Enter}");

    expect(onChange).toHaveBeenCalledWith(["region"]);
    // A form submit here would discard the half-finished policy the author is editing.
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it("refuses duplicates and blank entries", async () => {
    const onChange = vi.fn();
    render(
      <FieldPicker
        label="Hidden fields"
        selected={["region"]}
        manifest={MANIFEST}
        onChange={onChange}
      />,
    );

    const input = screen.getByLabelText("Add to Hidden fields");
    await userEvent.type(input, "region{Enter}");
    expect(onChange).not.toHaveBeenCalled();

    await userEvent.clear(input);
    await userEvent.type(input, "   {Enter}");
    expect(onChange).not.toHaveBeenCalled();
  });

  it("trims surrounding whitespace", async () => {
    const onChange = vi.fn();
    render(
      <FieldPicker label="Hidden fields" selected={[]} manifest={MANIFEST} onChange={onChange} />,
    );
    await userEvent.type(screen.getByLabelText("Add to Hidden fields"), "  region  {Enter}");
    // A stored " region " would never match a field name at enforcement time.
    expect(onChange).toHaveBeenCalledWith(["region"]);
  });

  it("removes a selected value", async () => {
    const onChange = vi.fn();
    render(
      <FieldPicker
        label="Hidden fields"
        selected={["region", "ssn_number"]}
        manifest={MANIFEST}
        onChange={onChange}
      />,
    );

    await userEvent.click(
      screen.getByRole("button", { name: "Remove region from Hidden fields" }),
    );
    expect(onChange).toHaveBeenCalledWith(["ssn_number"]);
  });

  it("does not offer an already-selected value", () => {
    const { container } = render(
      <FieldPicker
        label="Hidden fields"
        selected={["region"]}
        manifest={MANIFEST}
        onChange={vi.fn()}
      />,
    );
    const values = [...container.querySelectorAll("datalist option")].map(
      (option) => option.getAttribute("value"),
    );
    expect(values).not.toContain("region");
    expect(values).toContain("patients.ssn_number");
  });
});
