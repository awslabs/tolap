/**
 * Row filters.
 *
 * A row filter is the only way TOLAP selects records — there is no record-id concept — so
 * the field name is load-bearing. A record missing the referenced field fails the filter
 * (fail closed), which means a typo'd column name silently drops *every* record. The
 * author sees "the agent returns nothing", not "the policy is wrong".
 *
 * The other thing tested here is operator shape: `in` takes a list, `equals` takes one
 * value, `isNull` takes none. Carrying a stale `value` across an operator change would
 * emit a filter the schema rejects.
 */

import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { RowFilterEditor } from "./RowFilterEditor.tsx";
import type { RowFilter, SourceManifest } from "../api.ts";

const MANIFEST: SourceManifest = {
  sourceConnectionId: "db:analytics:patients",
  category: "db",
  objects: [{ name: "patients", fields: ["patient_id", "region", "discharged_at"] }],
  endpoints: [],
  tags: [],
  prefixes: [],
};

describe("RowFilterEditor", () => {
  it("says that no filters passes every record through", () => {
    render(<RowFilterEditor filters={[]} manifest={MANIFEST} onChange={vi.fn()} />);
    expect(screen.getByText(/Every record .* is passed through/i)).toBeDefined();
  });

  it("states the AND and the fail-closed behavior once filters exist", () => {
    render(
      <RowFilterEditor
        filters={[{ field: "region", operator: "equals", value: "west" }]}
        manifest={MANIFEST}
        onChange={vi.fn()}
      />,
    );
    const hint = screen.getByText(/ANDed/i);
    expect(hint.textContent).toMatch(/misspelled field name denies everything/i);
  });

  it("adds a filter that defaults to a single-value operator", async () => {
    const onChange = vi.fn();
    render(<RowFilterEditor filters={[]} manifest={MANIFEST} onChange={onChange} />);

    await userEvent.click(screen.getByRole("button", { name: "Add row filter" }));

    expect(onChange).toHaveBeenCalledWith([
      { field: "", operator: "equals", value: "" },
    ]);
  });

  it("offers catalog fields in the dropdown", () => {
    const { container } = render(
      <RowFilterEditor
        filters={[{ field: "", operator: "equals", value: "" }]}
        manifest={MANIFEST}
        onChange={vi.fn()}
      />,
    );
    const values = [...container.querySelectorAll("datalist option")].map((option) =>
      option.getAttribute("value"),
    );
    expect(values).toContain("patients.region");
    expect(values).toContain("region");
  });

  it("warns that an unknown field drops every record", () => {
    render(
      <RowFilterEditor
        filters={[{ field: "regoin", operator: "equals", value: "west" }]}
        manifest={MANIFEST}
        onChange={vi.fn()}
      />,
    );
    // The consequence, not just "unknown field": this denies all access, quietly.
    expect(screen.getByText(/drops every record/i)).toBeDefined();
  });

  it("does not warn on a known field, a glob, or an empty new row", () => {
    render(
      <RowFilterEditor
        filters={[
          { field: "region", operator: "equals", value: "west" },
          { field: "patient_*", operator: "isNotNull" },
          { field: "", operator: "equals", value: "" },
        ]}
        manifest={MANIFEST}
        onChange={vi.fn()}
      />,
    );
    expect(screen.queryByText(/drops every record/i)).toBeNull();
  });

  it("does not warn on a field that differs only in case", () => {
    // Case-insensitive at enforcement, so this filter selects on the real column and a
    // warning here would be false.
    render(
      <RowFilterEditor
        filters={[{ field: "Region", operator: "equals", value: "west" }]}
        manifest={MANIFEST}
        onChange={vi.fn()}
      />,
    );
    expect(screen.queryByText(/drops every record/i)).toBeNull();
  });

  it("does not warn before a catalog is loaded", () => {
    render(
      <RowFilterEditor
        filters={[{ field: "anything", operator: "equals", value: "x" }]}
        onChange={vi.fn()}
      />,
    );
    expect(screen.queryByText(/drops every record/i)).toBeNull();
  });

  it("shows one value input for a single-value operator", () => {
    render(
      <RowFilterEditor
        filters={[{ field: "region", operator: "equals", value: "west" }]}
        manifest={MANIFEST}
        onChange={vi.fn()}
      />,
    );
    expect(screen.getByLabelText("Filter value 1")).toBeDefined();
    expect(screen.queryByLabelText("Filter values 1")).toBeNull();
  });

  it("shows a list input for a multi-value operator", () => {
    render(
      <RowFilterEditor
        filters={[{ field: "region", operator: "in", values: ["west", "east"] }]}
        manifest={MANIFEST}
        onChange={vi.fn()}
      />,
    );
    const textarea = screen.getByLabelText("Filter values 1") as HTMLTextAreaElement;
    expect(textarea.value).toBe("west\neast");
    expect(screen.queryByLabelText("Filter value 1")).toBeNull();
  });

  it("shows no value input at all for isNull", () => {
    render(
      <RowFilterEditor
        filters={[{ field: "discharged_at", operator: "isNull" }]}
        manifest={MANIFEST}
        onChange={vi.fn()}
      />,
    );
    expect(screen.queryByLabelText("Filter value 1")).toBeNull();
    expect(screen.queryByLabelText("Filter values 1")).toBeNull();
    expect(screen.getByText("Takes no value.")).toBeDefined();
  });

  it("drops the single value when switching to a list operator", async () => {
    const onChange = vi.fn();
    render(
      <RowFilterEditor
        filters={[{ field: "region", operator: "equals", value: "west" }]}
        manifest={MANIFEST}
        onChange={onChange}
      />,
    );

    await userEvent.selectOptions(screen.getByLabelText("Filter operator 1"), "in");

    // A leftover `value` alongside `values` is not what `in` means, and the schema
    // rejects the combination.
    expect(onChange).toHaveBeenCalledWith([
      { field: "region", operator: "in", values: [] },
    ]);
  });

  it("drops both values when switching to a no-value operator", async () => {
    const onChange = vi.fn();
    render(
      <RowFilterEditor
        filters={[{ field: "region", operator: "in", values: ["west"] }]}
        manifest={MANIFEST}
        onChange={onChange}
      />,
    );

    await userEvent.selectOptions(screen.getByLabelText("Filter operator 1"), "isNull");

    expect(onChange).toHaveBeenCalledWith([
      { field: "region", operator: "isNull" },
    ]);
  });

  it("keeps the field name across an operator change", async () => {
    const onChange = vi.fn();
    render(
      <RowFilterEditor
        filters={[{ field: "discharged_at", operator: "equals", value: "" }]}
        manifest={MANIFEST}
        onChange={onChange}
      />,
    );

    await userEvent.selectOptions(
      screen.getByLabelText("Filter operator 1"),
      "isNotNull",
    );

    expect(onChange).toHaveBeenCalledWith([
      { field: "discharged_at", operator: "isNotNull" },
    ]);
  });

  it("drops blank lines from a value list", async () => {
    const onChange = vi.fn();
    render(
      <RowFilterEditor
        filters={[{ field: "region", operator: "in", values: [] }]}
        manifest={MANIFEST}
        onChange={onChange}
      />,
    );

    const textarea = screen.getByLabelText("Filter values 1");
    await userEvent.type(textarea, "west\n\n  east  \n");

    // An empty-string entry matches nothing and is never what a trailing newline meant.
    expect(onChange).toHaveBeenLastCalledWith([
      { field: "region", operator: "in", values: ["west", "east"] },
    ]);
  });

  it("keeps the newline while a second value is being typed", async () => {
    // The regression this guards: stripping blank lines on every keystroke while also
    // deriving the textarea from the stored values deletes the newline as soon as Enter
    // is pressed, so a second value cannot be entered at all.
    function Harness() {
      const [filters, setFilters] = useState<RowFilter[]>([
        { field: "region", operator: "in", values: [] },
      ]);
      return (
        <RowFilterEditor
          filters={filters}
          manifest={MANIFEST}
          onChange={setFilters}
        />
      );
    }
    render(<Harness />);

    const textarea = screen.getByLabelText("Filter values 1") as HTMLTextAreaElement;
    await userEvent.type(textarea, "west\neast");

    expect(textarea.value).toBe("west\neast");
  });

  it("adopts values that changed outside the textarea", async () => {
    // Switching operator or loading a different policy must be reflected, even though
    // in-progress typing must not be.
    const { rerender } = render(
      <RowFilterEditor
        filters={[{ field: "region", operator: "in", values: ["west"] }]}
        manifest={MANIFEST}
        onChange={vi.fn()}
      />,
    );
    rerender(
      <RowFilterEditor
        filters={[{ field: "region", operator: "in", values: ["north", "south"] }]}
        manifest={MANIFEST}
        onChange={vi.fn()}
      />,
    );

    expect((screen.getByLabelText("Filter values 1") as HTMLTextAreaElement).value).toBe(
      "north\nsouth",
    );
  });

  it("explains the operators whose behavior is easy to get wrong", () => {
    render(
      <RowFilterEditor
        filters={[
          { field: "region", operator: "like", value: "we%" },
          { field: "patient_id", operator: "between", values: ["1", "9"] },
          { field: "region", operator: "matches", value: "^we" },
        ]}
        manifest={MANIFEST}
        onChange={vi.fn()}
      />,
    );
    expect(screen.getByText(/% for any sequence/i)).toBeDefined();
    expect(screen.getByText(/two values, ordered/i)).toBeDefined();
    // A regex that cannot be evaluated denies rather than passes; say so.
    expect(screen.getByText(/treated as a non-match, which denies/i)).toBeDefined();
  });

  it("edits one filter without disturbing the others", async () => {
    const onChange = vi.fn();
    render(
      <RowFilterEditor
        filters={[
          { field: "region", operator: "equals", value: "west" },
          { field: "patient_id", operator: "isNotNull" },
        ]}
        manifest={MANIFEST}
        onChange={onChange}
      />,
    );

    await userEvent.type(screen.getByLabelText("Filter value 1"), "!");

    expect(onChange).toHaveBeenLastCalledWith([
      { field: "region", operator: "equals", value: "west!" },
      { field: "patient_id", operator: "isNotNull" },
    ]);
  });

  it("removes the filter the author pointed at", async () => {
    const onChange = vi.fn();
    render(
      <RowFilterEditor
        filters={[
          { field: "region", operator: "equals", value: "west" },
          { field: "patient_id", operator: "isNotNull" },
        ]}
        manifest={MANIFEST}
        onChange={onChange}
      />,
    );

    await userEvent.click(screen.getByRole("button", { name: "Remove filter 1" }));
    expect(onChange).toHaveBeenCalledWith([
      { field: "patient_id", operator: "isNotNull" },
    ]);
  });

  it("scopes its dropdown to the instance", () => {
    const { container } = render(
      <>
        <RowFilterEditor
          filters={[{ field: "", operator: "equals", value: "" }]}
          manifest={MANIFEST}
          onChange={vi.fn()}
        />
        <RowFilterEditor
          filters={[{ field: "", operator: "equals", value: "" }]}
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

  it("offers every operator the enforcement spec defines", () => {
    const { container } = render(
      <RowFilterEditor
        filters={[{ field: "region", operator: "equals", value: "" }]}
        manifest={MANIFEST}
        onChange={vi.fn()}
      />,
    );
    const operators = [...container.querySelectorAll("select option")].map((option) =>
      option.getAttribute("value"),
    );
    // 16 operators. A missing one is only discoverable by hand-editing JSON.
    expect(operators).toHaveLength(16);
    expect(operators).toContain("notLike");
    expect(operators).toContain("between");
    expect(operators).toContain("isNotNull");
  });
});
