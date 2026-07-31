/**
 * Masking rules.
 *
 * The two failure modes worth testing are the two the component exists to prevent: a
 * field name the source does not have (masks nothing, and nothing downstream can detect
 * it), and a mask type that discloses more than the author believes. Both are supposed to
 * be visible while authoring rather than discovered in an incident review.
 */

import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MaskedFieldEditor } from "./MaskedFieldEditor.tsx";
import type { SourceManifest } from "../api.ts";

const MANIFEST: SourceManifest = {
  sourceConnectionId: "db:analytics:patients",
  category: "db",
  objects: [{ name: "patients", fields: ["patient_id", "ssn_number", "region"] }],
  endpoints: [],
  tags: [],
  prefixes: [],
};

describe("MaskedFieldEditor", () => {
  it("says plainly that no rules means no masking", () => {
    render(<MaskedFieldEditor rules={[]} manifest={MANIFEST} onChange={vi.fn()} />);
    expect(screen.getByText(/returned as stored/i)).toBeDefined();
  });

  it("starts a new rule at redact rather than partial", async () => {
    const onChange = vi.fn();
    render(<MaskedFieldEditor rules={[]} manifest={MANIFEST} onChange={onChange} />);

    await userEvent.click(screen.getByRole("button", { name: "Add masking rule" }));

    // Forgetting to change the mask type should err toward disclosing less.
    expect(onChange).toHaveBeenCalledWith([{ field: "", maskType: "redact" }]);
  });

  it("offers catalog fields in the dropdown", () => {
    const { container } = render(
      <MaskedFieldEditor
        rules={[{ field: "", maskType: "redact" }]}
        manifest={MANIFEST}
        onChange={vi.fn()}
      />,
    );
    const values = [...container.querySelectorAll("datalist option")].map((option) =>
      option.getAttribute("value"),
    );
    expect(values).toContain("patients.ssn_number");
    expect(values).toContain("ssn_number");
  });

  it("flags a field the catalog does not have", () => {
    // `ssn` reads correctly and masks nothing here: the column is `ssn_number`.
    render(
      <MaskedFieldEditor
        rules={[{ field: "ssn", maskType: "redact" }]}
        manifest={MANIFEST}
        onChange={vi.fn()}
      />,
    );
    expect(screen.getByText(/masks nothing/i)).toBeDefined();
  });

  it("does not flag a known field or a glob", () => {
    render(
      <MaskedFieldEditor
        rules={[
          { field: "ssn_number", maskType: "redact" },
          { field: "ssn_*", maskType: "redact" },
        ]}
        manifest={MANIFEST}
        onChange={vi.fn()}
      />,
    );
    expect(screen.queryByText(/masks nothing/i)).toBeNull();
  });

  it("does not flag a field that differs only in case", () => {
    // Case-insensitive at enforcement, so this rule masks the real column.
    render(
      <MaskedFieldEditor
        rules={[{ field: "SSN_Number", maskType: "redact" }]}
        manifest={MANIFEST}
        onChange={vi.fn()}
      />,
    );
    expect(screen.queryByText(/masks nothing/i)).toBeNull();
  });

  it("does not flag anything before a catalog is loaded", () => {
    // Warning on every value with nothing to compare against would train the author to
    // ignore the warning that matters.
    render(
      <MaskedFieldEditor
        rules={[{ field: "whatever", maskType: "redact" }]}
        onChange={vi.fn()}
      />,
    );
    expect(screen.queryByText(/masks nothing/i)).toBeNull();
  });

  it("warns that hash is not a confidentiality control", async () => {
    const onChange = vi.fn();
    render(
      <MaskedFieldEditor
        rules={[{ field: "ssn_number", maskType: "hash" }]}
        manifest={MANIFEST}
        onChange={onChange}
      />,
    );

    // Stated where the author is choosing, not only in the schema docs: an unsalted
    // truncated digest of an SSN is brute-forceable.
    const note = screen.getByText(/NOT a confidentiality control/i);
    expect(note.textContent).toMatch(/brute-forceable/i);
  });

  it("says that partial reveals real characters", () => {
    render(
      <MaskedFieldEditor
        rules={[{ field: "ssn_number", maskType: "partial" }]}
        manifest={MANIFEST}
        onChange={vi.fn()}
      />,
    );
    expect(screen.getByText(/reveals real characters/i)).toBeDefined();
  });

  it("orders the mask types most- to least-restrictive", () => {
    const { container } = render(
      <MaskedFieldEditor
        rules={[{ field: "ssn_number", maskType: "redact" }]}
        manifest={MANIFEST}
        onChange={vi.fn()}
      />,
    );
    const options = [...container.querySelectorAll("select option")].map((option) =>
      option.getAttribute("value"),
    );
    // Same order the enforcement spec merges them in: least-revealing wins.
    expect(options).toEqual(["null", "redact", "full", "hash", "partial"]);
  });

  it("changes the mask type of one rule without touching the others", async () => {
    const onChange = vi.fn();
    render(
      <MaskedFieldEditor
        rules={[
          { field: "ssn_number", maskType: "redact" },
          { field: "region", maskType: "hash" },
        ]}
        manifest={MANIFEST}
        onChange={onChange}
      />,
    );

    await userEvent.selectOptions(
      screen.getByLabelText("Mask type for field 1"),
      "null",
    );

    expect(onChange).toHaveBeenCalledWith([
      { field: "ssn_number", maskType: "null" },
      { field: "region", maskType: "hash" },
    ]);
  });

  it("drops parameters the new mask type does not accept", async () => {
    // `parameters` is closed in the schema and each key names the type it belongs to, so
    // a `showLast` carried onto a `redact` rule is not ignored -- it fails validation on
    // save, pointing at a control that is no longer on screen.
    const onChange = vi.fn();
    render(
      <MaskedFieldEditor
        rules={[
          { field: "ssn_number", maskType: "partial", parameters: { showLast: 4 } },
        ]}
        manifest={MANIFEST}
        onChange={onChange}
      />,
    );

    await userEvent.selectOptions(
      screen.getByLabelText("Mask type for field 1"),
      "redact",
    );

    expect(onChange).toHaveBeenCalledWith([
      { field: "ssn_number", maskType: "redact" },
    ]);
  });

  it("keeps the parameters the new mask type still accepts", async () => {
    // maskChar is valid for both `partial` and `full`; discarding it would silently
    // change what the mask emits.
    const onChange = vi.fn();
    render(
      <MaskedFieldEditor
        rules={[
          {
            field: "ssn_number",
            maskType: "partial",
            parameters: { showLast: 4, maskChar: "#" },
          },
        ]}
        manifest={MANIFEST}
        onChange={onChange}
      />,
    );

    await userEvent.selectOptions(screen.getByLabelText("Mask type for field 1"), "full");

    expect(onChange).toHaveBeenCalledWith([
      { field: "ssn_number", maskType: "full", parameters: { maskChar: "#" } },
    ]);
  });

  it("lets an author reveal the last four characters", async () => {
    // The reason to choose `partial` at all. Without this control the mask silently
    // degrades to `full`, which is safe but not what the author asked for.
    const onChange = vi.fn();
    render(
      <MaskedFieldEditor
        rules={[{ field: "ssn_number", maskType: "partial" }]}
        manifest={MANIFEST}
        onChange={onChange}
      />,
    );

    await userEvent.type(screen.getByLabelText("Show last for field 1"), "4");

    expect(onChange).toHaveBeenCalledWith([
      { field: "ssn_number", maskType: "partial", parameters: { showLast: 4 } },
    ]);
  });

  it("warns that a partial mask revealing nothing is just a full mask", () => {
    render(
      <MaskedFieldEditor
        rules={[{ field: "ssn_number", maskType: "partial" }]}
        manifest={MANIFEST}
        onChange={vi.fn()}
      />,
    );
    expect(screen.getByText(/behaves as a/i).textContent).toMatch(/full/);
  });

  it("describes what a configured partial mask reveals", () => {
    render(
      <MaskedFieldEditor
        rules={[
          {
            field: "ssn_number",
            maskType: "partial",
            parameters: { showFirst: 1, showLast: 4 },
          },
        ]}
        manifest={MANIFEST}
        onChange={vi.fn()}
      />,
    );
    const note = screen.getByText(/Reveals the first 1 and the last 4/i);
    // The degrade-to-full rule is the surprising part, so it is stated here too.
    expect(note.textContent).toMatch(/masked completely instead/i);
  });

  it("offers only the hash algorithms every SDK agrees on", () => {
    render(
      <MaskedFieldEditor
        rules={[{ field: "ssn_number", maskType: "hash" }]}
        manifest={MANIFEST}
        onChange={vi.fn()}
      />,
    );
    const select = screen.getByLabelText("Hash algorithm for field 1");
    const values = [...select.querySelectorAll("option")].map((o) => o.getAttribute("value"));
    // "" is the leave-it-to-the-default choice. A value outside this set produces a
    // pseudonym that does not match across languages.
    expect(values).toEqual(["", "sha256", "sha512", "blake2b"]);
  });

  it("shows parameters only for the mask types that take them", () => {
    render(
      <MaskedFieldEditor
        rules={[
          { field: "a", maskType: "redact" },
          { field: "b", maskType: "null" },
        ]}
        manifest={MANIFEST}
        onChange={vi.fn()}
      />,
    );
    expect(screen.queryByLabelText(/Show last/)).toBeNull();
    expect(screen.queryByLabelText(/Mask character/)).toBeNull();
    expect(screen.queryByLabelText(/Hash algorithm/)).toBeNull();
  });

  it("removes a parameter rather than storing a blank", async () => {
    // An empty string fails the schema's integer and minLength constraints.
    const onChange = vi.fn();
    render(
      <MaskedFieldEditor
        rules={[
          { field: "ssn_number", maskType: "partial", parameters: { showLast: 4 } },
        ]}
        manifest={MANIFEST}
        onChange={onChange}
      />,
    );

    await userEvent.clear(screen.getByLabelText("Show last for field 1"));

    expect(onChange).toHaveBeenCalledWith([
      { field: "ssn_number", maskType: "partial" },
    ]);
  });

  it("scopes its dropdown to the instance", () => {
    // A hardcoded id would make the first editor's datalist capture the second's input,
    // leaving one of them silently without suggestions.
    const { container } = render(
      <>
        <MaskedFieldEditor
          rules={[{ field: "", maskType: "redact" }]}
          manifest={MANIFEST}
          onChange={vi.fn()}
        />
        <MaskedFieldEditor
          rules={[{ field: "", maskType: "redact" }]}
          manifest={MANIFEST}
          onChange={vi.fn()}
        />
      </>,
    );
    const ids = [...container.querySelectorAll("datalist")].map((list) => list.id);
    expect(new Set(ids).size).toBe(2);

    const linked = [...container.querySelectorAll("input[list]")].map((input) =>
      input.getAttribute("list"),
    );
    expect(new Set(linked)).toEqual(new Set(ids));
  });

  it("removes the rule the author pointed at", async () => {
    const onChange = vi.fn();
    render(
      <MaskedFieldEditor
        rules={[
          { field: "ssn_number", maskType: "redact" },
          { field: "region", maskType: "hash" },
        ]}
        manifest={MANIFEST}
        onChange={onChange}
      />,
    );

    await userEvent.click(
      screen.getByRole("button", { name: "Remove masking rule 2" }),
    );
    expect(onChange).toHaveBeenCalledWith([{ field: "ssn_number", maskType: "redact" }]);
  });
});
