/**
 * Tag rules for `kb` sources.
 *
 * The asymmetry is the whole test surface. `deniedTags` takes precedence over
 * `allowedTags`, and a document passes the allow-list if it carries **one** allowed tag —
 * so an allow-list is narrower than it looks and a deny-list is absolute. An author who
 * has these backwards writes a policy that reads as restrictive and returns everything,
 * which is exactly the failure the inline text exists to prevent.
 */

import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { TagPicker, tagOptions } from "./TagPicker.tsx";
import type { SourceManifest } from "../api.ts";

const MANIFEST: SourceManifest = {
  sourceConnectionId: "kb:research:corpus",
  category: "kb",
  objects: [],
  endpoints: [],
  tags: ["phi", "public", "deidentified"],
  prefixes: [],
};

describe("tagOptions", () => {
  it("sorts the catalog tags", () => {
    expect(tagOptions(MANIFEST)).toEqual(["deidentified", "phi", "public"]);
  });

  it("returns nothing without a manifest", () => {
    expect(tagOptions(undefined)).toEqual([]);
  });
});

describe("TagPicker", () => {
  it("warns that an empty allow-list returns no documents", () => {
    render(
      <TagPicker
        label="Allowed tags"
        selected={[]}
        manifest={MANIFEST}
        semantics="allow"
        onChange={vi.fn()}
      />,
    );
    const note = screen.getByRole("note");
    expect(note.textContent).toMatch(/no documents at all/i);
    expect(note.textContent).toMatch(/unrestricted/i);
  });

  it("says an empty deny-list excludes nothing", () => {
    // The opposite of the allow case, and the reason the two share no empty-state text.
    render(
      <TagPicker
        label="Denied tags"
        selected={[]}
        manifest={MANIFEST}
        semantics="deny"
        onChange={vi.fn()}
      />,
    );
    const note = screen.getByRole("note");
    expect(note.textContent).toMatch(/No document is excluded/i);
    expect(note.textContent).not.toMatch(/no documents at all/i);
  });

  it("states that one allowed tag is enough", () => {
    render(
      <TagPicker
        label="Allowed tags"
        selected={["deidentified"]}
        manifest={MANIFEST}
        semantics="allow"
        onChange={vi.fn()}
      />,
    );
    // A document tagged both `deidentified` and `phi` passes this allow-list.
    expect(screen.getByText(/at least ONE of these tags/i)).toBeDefined();
  });

  it("states that deny wins over allow", () => {
    render(
      <TagPicker
        label="Denied tags"
        selected={["phi"]}
        manifest={MANIFEST}
        semantics="deny"
        onChange={vi.fn()}
      />,
    );
    expect(screen.getByText(/Takes precedence over the allow-list/i)).toBeDefined();
  });

  it("offers the catalog tags and not the already-selected ones", () => {
    const { container } = render(
      <TagPicker
        label="Allowed tags"
        selected={["phi"]}
        manifest={MANIFEST}
        semantics="allow"
        onChange={vi.fn()}
      />,
    );
    const values = [...container.querySelectorAll("datalist option")].map((option) =>
      option.getAttribute("value"),
    );
    expect(values).toEqual(["deidentified", "public"]);
  });

  it("gives allow and deny pickers separate dropdown ids", () => {
    // A shared id would make one datalist win and silently empty the other picker.
    const { container } = render(
      <>
        <TagPicker
          label="Allowed tags"
          selected={[]}
          manifest={MANIFEST}
          semantics="allow"
          onChange={vi.fn()}
        />
        <TagPicker
          label="Denied tags"
          selected={[]}
          manifest={MANIFEST}
          semantics="deny"
          onChange={vi.fn()}
        />
      </>,
    );
    const ids = [...container.querySelectorAll("datalist")].map((list) => list.id);
    expect(new Set(ids).size).toBe(2);
  });

  it("flags a tag no document in the catalog carries", () => {
    render(
      <TagPicker
        label="Denied tags"
        selected={["PHI"]}
        manifest={MANIFEST}
        semantics="deny"
        onChange={vi.fn()}
      />,
    );
    // Tag matching is exact, so a case difference denies nothing.
    expect(screen.getByText(/not in catalog/i)).toBeDefined();
    expect(screen.getByText("PHI")).toBeDefined();
  });

  it("does not flag anything before a catalog is loaded", () => {
    render(
      <TagPicker
        label="Denied tags"
        selected={["anything"]}
        semantics="deny"
        onChange={vi.fn()}
      />,
    );
    expect(screen.queryByText(/not in catalog/i)).toBeNull();
  });

  it("adds on Enter without submitting the surrounding form", async () => {
    const onChange = vi.fn();
    const onSubmit = vi.fn((event: React.FormEvent) => event.preventDefault());
    render(
      <form onSubmit={onSubmit}>
        <TagPicker
          label="Denied tags"
          selected={[]}
          manifest={MANIFEST}
          semantics="deny"
          onChange={onChange}
        />
      </form>,
    );

    await userEvent.type(screen.getByLabelText("Add to Denied tags"), "phi{Enter}");

    expect(onChange).toHaveBeenCalledWith(["phi"]);
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it("refuses duplicates and blanks, and trims", async () => {
    const onChange = vi.fn();
    render(
      <TagPicker
        label="Denied tags"
        selected={["phi"]}
        manifest={MANIFEST}
        semantics="deny"
        onChange={onChange}
      />,
    );

    const input = screen.getByLabelText("Add to Denied tags");
    await userEvent.type(input, "phi{Enter}");
    expect(onChange).not.toHaveBeenCalled();

    await userEvent.clear(input);
    await userEvent.type(input, "   {Enter}");
    expect(onChange).not.toHaveBeenCalled();

    await userEvent.clear(input);
    await userEvent.type(input, "  public  {Enter}");
    // A stored " public " would never match a tag at enforcement time.
    expect(onChange).toHaveBeenCalledWith(["phi", "public"]);
  });

  it("removes a selected tag", async () => {
    const onChange = vi.fn();
    render(
      <TagPicker
        label="Allowed tags"
        selected={["deidentified", "public"]}
        manifest={MANIFEST}
        semantics="allow"
        onChange={onChange}
      />,
    );

    await userEvent.click(
      screen.getByRole("button", { name: "Remove public from Allowed tags" }),
    );
    expect(onChange).toHaveBeenCalledWith(["deidentified"]);
  });
});
