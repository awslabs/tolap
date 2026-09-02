/**
 * Purpose binding.
 *
 * The tests here are weighted towards one distinction, because it is the one that is a
 * security bug rather than a usability wart: `allowedActions` **absent** means every
 * action is permitted, and `allowedActions: []` means every action is denied
 * (canonical-enforcement-spec section 15.2, following section 3). They are opposite
 * policies, an editor that collapses them into "no chips selected" silently picks one,
 * and `toEqual` cannot tell them apart -- `{ a: undefined }` and `{}` compare equal in
 * memory and do not on the wire. So the assertions that matter go through
 * `JSON.stringify`, which is what `api.ts` sends.
 *
 * The other reason this editor needs its own tests is that it is the only one whose
 * presence changes whether the policy applies at all. Adding a profile to a working
 * policy excludes it for every caller that does not declare that exact purpose, so the
 * on-screen statement of that consequence is asserted as a feature and not as decoration.
 */

import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { PurposeProfileEditor } from "./PurposeProfileEditor.tsx";
import type { PurposeProfile } from "../api.ts";

const FRAUD: PurposeProfile = { purposeId: "fraud-detection" };

/** The most recent emitted profile, or `undefined` if the profile was removed. */
function lastEmitted(onChange: ReturnType<typeof vi.fn>): PurposeProfile | undefined {
  expect(onChange).toHaveBeenCalled();
  return onChange.mock.calls.at(-1)![0] as PurposeProfile | undefined;
}

/**
 * The emitted profile as the server would receive it.
 *
 * `JSON.stringify` drops a key whose value is `undefined` and keeps a key whose value is
 * `[]`. That is exactly the section 3 distinction, so asserting the wire form is what
 * makes "absent" and "empty" different things to assert.
 */
function wireEmitted(onChange: ReturnType<typeof vi.fn>): Record<string, unknown> {
  const emitted = lastEmitted(onChange);
  expect(emitted).toBeDefined();
  return JSON.parse(JSON.stringify(emitted)) as Record<string, unknown>;
}

/** A live editor, for the cases where two edits have to build on each other. */
function Harness({ initial }: { readonly initial?: PurposeProfile }) {
  const [profile, setProfile] = useState<PurposeProfile | undefined>(initial);
  return <PurposeProfileEditor profile={profile} onChange={setProfile} />;
}

describe("PurposeProfileEditor without a profile", () => {
  it("says the policy is purpose-agnostic rather than showing an empty form", () => {
    render(<PurposeProfileEditor onChange={vi.fn()} />);

    expect(screen.getByText(/No purpose profile/)).toBeDefined();
    expect(screen.getByText(/whatever purpose is declared/)).toBeDefined();
    // No purpose id control until a profile exists: an empty one is not "no profile".
    expect(screen.queryByLabelText("Purpose id")).toBeNull();
  });

  it("adds a profile with an empty purpose id rather than inventing one", async () => {
    // Guessing a purpose id would be guessing which callers this policy still serves.
    const onChange = vi.fn();
    render(<PurposeProfileEditor onChange={onChange} />);

    await userEvent.click(screen.getByRole("button", { name: "Add purpose profile" }));

    expect(onChange).toHaveBeenCalledWith({ purposeId: "" });
  });
});

describe("the consequence of having a profile at all", () => {
  it("states that the policy now resolves only for that purpose, case-sensitively", () => {
    // The whole reason this editor is loud: an author reads a purpose profile as "one
    // more rule" and gets "this policy no longer applies to anyone else".
    render(<PurposeProfileEditor profile={FRAUD} onChange={vi.fn()} />);

    const warning = screen.getByText(/A purpose profile changes/);
    expect(warning.textContent).toMatch(/whether this policy applies/);
    expect(warning.textContent).toMatch(/only/);
    expect(warning.textContent).toMatch(/case-sensitively/);
    // And that declaring no purpose is not a way in.
    expect(warning.textContent).toMatch(/no purpose/);
    expect(warning.textContent).toMatch(/fraud-detection/);
  });

  it("removes the whole profile rather than blanking it", async () => {
    const onChange = vi.fn();
    render(
      <PurposeProfileEditor
        profile={{ ...FRAUD, allowedActions: [], judge: { enabled: true } }}
        onChange={onChange}
      />,
    );

    await userEvent.click(
      screen.getByRole("button", { name: "Remove purpose profile" }),
    );

    // Not `{}`, and not a profile with an empty id: either would keep filtering
    // resolution while looking removed.
    expect(lastEmitted(onChange)).toBeUndefined();
  });

  it("says a blank purpose id is required rather than warning about it", () => {
    // A freshly added profile is not yet a mistake, the way a freshly added row filter
    // with no field is not. It still cannot be saved, and the note says so.
    render(<PurposeProfileEditor profile={{ purposeId: "" }} onChange={vi.fn()} />);

    expect(screen.getByText(/Required\./)).toBeDefined();
    expect(screen.queryByText(/is not a valid purpose id/)).toBeNull();
  });
});

describe("purpose id validation", () => {
  it("surfaces an uppercase purpose id", () => {
    // Resolution compares case-sensitively, so `Fraud-Detection` would resolve for
    // nobody declaring `fraud-detection`. The schema rejects it outright.
    render(
      <PurposeProfileEditor profile={{ purposeId: "Fraud-Detection" }} onChange={vi.fn()} />,
    );

    expect(screen.getByText(/is not a valid purpose id/)).toBeDefined();
  });

  it("surfaces a leading hyphen", () => {
    render(
      <PurposeProfileEditor profile={{ purposeId: "-fraud" }} onChange={vi.fn()} />,
    );

    expect(screen.getByText(/is not a valid purpose id/)).toBeDefined();
  });

  it("surfaces a trailing hyphen and a single character", () => {
    // The schema's pattern anchors a final character class, so it needs at least two
    // characters and cannot end in a hyphen. Both are easy to type and neither is
    // obvious from the pattern.
    const { rerender } = render(
      <PurposeProfileEditor profile={{ purposeId: "fraud-" }} onChange={vi.fn()} />,
    );
    expect(screen.getByText(/is not a valid purpose id/)).toBeDefined();

    rerender(<PurposeProfileEditor profile={{ purposeId: "f" }} onChange={vi.fn()} />);
    expect(screen.getByText(/is not a valid purpose id/)).toBeDefined();
  });

  it("surfaces a purpose id longer than the schema's ceiling", () => {
    render(
      <PurposeProfileEditor
        profile={{ purposeId: "a".repeat(129) }}
        onChange={vi.fn()}
      />,
    );

    expect(screen.getByText(/Longer than 128 characters/)).toBeDefined();
  });

  it("does not warn about a valid purpose id", () => {
    render(
      <PurposeProfileEditor
        profile={{ purposeId: "campaign-x-overlap-2026" }}
        onChange={vi.fn()}
      />,
    );

    expect(screen.queryByText(/is not a valid purpose id/)).toBeNull();
    expect(screen.queryByText(/Required\./)).toBeNull();
  });

  it("carries the typed purpose id through without touching the rest", async () => {
    const onChange = vi.fn();
    render(
      <PurposeProfileEditor
        profile={{ purposeId: "fraud", prohibitedActions: ["export_pii"] }}
        onChange={onChange}
      />,
    );

    await userEvent.type(screen.getByLabelText("Purpose id"), "-");

    expect(lastEmitted(onChange)).toEqual({
      purposeId: "fraud-",
      prohibitedActions: ["export_pii"],
    });
  });
});

// -- The distinction that matters -----------------------------------------------

describe("allowedActions: absent versus empty", () => {
  it("renders an absent allow-list as unrestricted, with no deny-all warning", () => {
    render(<PurposeProfileEditor profile={FRAUD} onChange={vi.fn()} />);

    const box = screen.getByRole("checkbox", {
      name: /Permit every action category/,
    }) as HTMLInputElement;
    expect(box.checked).toBe(true);
    expect(screen.queryByText(/denies every action/)).toBeNull();
    // And no allow-list to edit, because there is no allow-list.
    expect(screen.queryByLabelText("Add to Allowed actions")).toBeNull();
  });

  it("renders an empty allow-list as deny-all, and says so", () => {
    render(
      <PurposeProfileEditor
        profile={{ ...FRAUD, allowedActions: [] }}
        onChange={vi.fn()}
      />,
    );

    const box = screen.getByRole("checkbox", {
      name: /Permit every action category/,
    }) as HTMLInputElement;
    expect(box.checked).toBe(false);
    expect(screen.getByText(/denies every action/)).toBeDefined();
    // The control is on screen, because `[]` is an authorable value that has to be
    // editable -- and reachable back to "no restriction".
    expect(screen.getByLabelText("Add to Allowed actions")).toBeDefined();
  });

  it("emits an empty array, not an absent key, when the restriction is switched on", async () => {
    // Direction one. Unchecking has to write `[]` and the wire form has to keep it:
    // this is the most restrictive value the form can express, and it is the fail-closed
    // starting point for building an allow-list.
    const onChange = vi.fn();
    render(<PurposeProfileEditor profile={FRAUD} onChange={onChange} />);

    await userEvent.click(
      screen.getByRole("checkbox", { name: /Permit every action category/ }),
    );

    const wire = wireEmitted(onChange);
    expect(wire.allowedActions).toEqual([]);
    // Present on the wire, not merely present in memory.
    expect(Object.keys(wire)).toContain("allowedActions");
  });

  it("emits no allowedActions key at all when the restriction is switched off", async () => {
    // Direction two, and the dangerous one: this widens the policy from deny-all to
    // unrestricted, so it must happen only because the author asked. `[]` left behind
    // here would keep denying every action while the box reads "permit every action".
    const onChange = vi.fn();
    render(
      <PurposeProfileEditor
        profile={{ ...FRAUD, allowedActions: ["aggregate_overlap"] }}
        onChange={onChange}
      />,
    );

    await userEvent.click(
      screen.getByRole("checkbox", { name: /Permit every action category/ }),
    );

    const wire = wireEmitted(onChange);
    expect(Object.keys(wire)).not.toContain("allowedActions");
    expect(wire).toEqual({ purposeId: "fraud-detection" });
  });

  it("survives a round trip through both directions", async () => {
    // Absent -> `[]` -> a category -> absent -> `[]`. A control that stores the previous
    // list and restores it, or that coerces `[]` on re-entry, breaks somewhere in here.
    render(<Harness initial={FRAUD} />);
    const box = () => screen.getByRole("checkbox", { name: /Permit every action category/ });

    await userEvent.click(box());
    expect(screen.getByText(/denies every action/)).toBeDefined();

    await userEvent.type(
      screen.getByLabelText("Add to Allowed actions"),
      "aggregate_overlap{Enter}",
    );
    expect(screen.queryByText(/denies every action/)).toBeNull();

    await userEvent.click(box());
    expect(screen.queryByLabelText("Add to Allowed actions")).toBeNull();

    await userEvent.click(box());
    // Back to empty, not back to the list that was there before -- the author asked for
    // "restrict", and reviving a forgotten allow-list would grant a category silently.
    expect(screen.getByText(/denies every action/)).toBeDefined();
    expect(screen.queryByText("aggregate_overlap")).toBeNull();
  });
});

// -- The chip lists --------------------------------------------------------------

describe("action categories", () => {
  it("adds an allowed action", async () => {
    const onChange = vi.fn();
    render(
      <PurposeProfileEditor
        profile={{ ...FRAUD, allowedActions: [] }}
        onChange={onChange}
      />,
    );

    await userEvent.type(
      screen.getByLabelText("Add to Allowed actions"),
      "aggregate_overlap{Enter}",
    );

    expect(lastEmitted(onChange)).toEqual({
      purposeId: "fraud-detection",
      allowedActions: ["aggregate_overlap"],
    });
  });

  it("removes an allowed action, leaving the empty list rather than the absent key", async () => {
    // Removing the last chip must not become "unrestricted". The two are opposite
    // policies and only the checkbox may switch between them.
    const onChange = vi.fn();
    render(
      <PurposeProfileEditor
        profile={{ ...FRAUD, allowedActions: ["aggregate_overlap"] }}
        onChange={onChange}
      />,
    );

    await userEvent.click(
      screen.getByRole("button", {
        name: "Remove aggregate_overlap from Allowed actions",
      }),
    );

    const wire = wireEmitted(onChange);
    expect(wire.allowedActions).toEqual([]);
    expect(Object.keys(wire)).toContain("allowedActions");
  });

  it("adds a prohibited action", async () => {
    const onChange = vi.fn();
    render(<PurposeProfileEditor profile={FRAUD} onChange={onChange} />);

    await userEvent.type(
      screen.getByLabelText("Add to Prohibited actions"),
      "export_pii{Enter}",
    );

    expect(lastEmitted(onChange)).toEqual({
      purposeId: "fraud-detection",
      prohibitedActions: ["export_pii"],
    });
  });

  it("drops the prohibited key when the last one is removed", async () => {
    // The deliberate asymmetry with the allow-list: a deny-list of nothing restricts
    // nothing, so absent and `[]` are the same policy and absent is the canonical
    // spelling. Doing this to `allowedActions` would be a security bug; here it is not.
    const onChange = vi.fn();
    render(
      <PurposeProfileEditor
        profile={{ ...FRAUD, prohibitedActions: ["export_pii"] }}
        onChange={onChange}
      />,
    );

    await userEvent.click(
      screen.getByRole("button", { name: "Remove export_pii from Prohibited actions" }),
    );

    const wire = wireEmitted(onChange);
    expect(Object.keys(wire)).not.toContain("prohibitedActions");
  });

  it("keeps the two lists independent", async () => {
    const onChange = vi.fn();
    render(
      <PurposeProfileEditor
        profile={{
          ...FRAUD,
          allowedActions: ["aggregate_overlap"],
          prohibitedActions: ["export_pii"],
        }}
        onChange={onChange}
      />,
    );

    await userEvent.type(
      screen.getByLabelText("Add to Prohibited actions"),
      "bulk_read{Enter}",
    );

    expect(lastEmitted(onChange)).toEqual({
      purposeId: "fraud-detection",
      allowedActions: ["aggregate_overlap"],
      prohibitedActions: ["export_pii", "bulk_read"],
    });
  });

  it("surfaces an action category the schema rejects", async () => {
    // Free text, so the schema's pattern is the only check available -- and an invalid
    // category is not a rule that fails open, it is a policy that will not save.
    render(<Harness initial={{ ...FRAUD, allowedActions: [] }} />);

    await userEvent.type(
      screen.getByLabelText("Add to Allowed actions"),
      "Export PII{Enter}",
    );

    expect(screen.getByText("⚠ invalid category")).toBeDefined();
  });

  it("surfaces an invalid category in the prohibited list too", () => {
    render(
      <PurposeProfileEditor
        profile={{ ...FRAUD, prohibitedActions: ["_leading_underscore"] }}
        onChange={vi.fn()}
      />,
    );

    expect(screen.getByText("⚠ invalid category")).toBeDefined();
  });

  it("surfaces a category longer than the schema's ceiling", () => {
    render(
      <PurposeProfileEditor
        profile={{ ...FRAUD, prohibitedActions: ["a".repeat(129)] }}
        onChange={vi.fn()}
      />,
    );

    const marker = screen.getByText("⚠ invalid category");
    expect(marker.getAttribute("title")).toMatch(/longer than 128/);
  });

  it("does not warn about the categories the schema permits", () => {
    // Hyphens, underscores, digits and a single character are all legal here, unlike in
    // a purpose id -- a shared validator would reject `export_pii`, the spec's own
    // example.
    render(
      <PurposeProfileEditor
        profile={{
          ...FRAUD,
          allowedActions: ["export_pii", "aggregate-overlap", "read2", "x"],
        }}
        onChange={vi.fn()}
      />,
    );

    expect(screen.queryByText("⚠ invalid category")).toBeNull();
  });

  it("marks a category that both lists name, because prohibited wins", () => {
    // Not an error -- the schema permits it and enforcement has a defined answer -- but
    // an allow-list entry that is silently denied is worth saying out loud.
    render(
      <PurposeProfileEditor
        profile={{
          ...FRAUD,
          allowedActions: ["aggregate_overlap", "export_pii"],
          prohibitedActions: ["export_pii"],
        }}
        onChange={vi.fn()}
      />,
    );

    const marker = screen.getByText("⚠ also prohibited");
    expect(marker.getAttribute("title")).toMatch(/prohibited wins/i);
    // Only the overlapping chip is marked.
    expect(screen.getAllByText("⚠ also prohibited")).toHaveLength(1);
    expect(screen.getByText(/a category in both lists is/).textContent).toMatch(
      /denied/,
    );
  });
});

describe("the unclassified-tool consequence", () => {
  it("warns once a non-null allow-list exists", () => {
    // Section 15.2 fails closed on a call the deployment's category map does not cover,
    // and the console cannot see that map. An author enabling this on a deployment with
    // no map configured denies every call.
    render(
      <PurposeProfileEditor
        profile={{ ...FRAUD, allowedActions: [] }}
        onChange={vi.fn()}
      />,
    );

    expect(screen.getByText(/has not mapped to a category is denied/)).toBeDefined();
  });

  it("warns once a non-empty deny-list exists", () => {
    // The less obvious half, and the one the spec calls out: "anything but exporting
    // PII" cannot mean "and anything unclassified".
    render(
      <PurposeProfileEditor
        profile={{ ...FRAUD, prohibitedActions: ["export_pii"] }}
        onChange={vi.fn()}
      />,
    );

    expect(screen.getByText(/has not mapped to a category is denied/)).toBeDefined();
  });

  it("does not warn for a profile that constrains no actions", () => {
    // An empty deny-list restricts nothing and so cannot make a call unclassifiable.
    // Warning here would train the author to ignore the warning that matters.
    render(
      <PurposeProfileEditor
        profile={{ ...FRAUD, prohibitedActions: [] }}
        onChange={vi.fn()}
      />,
    );

    expect(screen.queryByText(/has not mapped to a category is denied/)).toBeNull();
  });
});

// -- The judge -------------------------------------------------------------------

describe("the judge", () => {
  it("offers no judge settings until a judge is configured", () => {
    render(<PurposeProfileEditor profile={FRAUD} onChange={vi.fn()} />);

    expect(
      (screen.getByRole("checkbox", { name: /Configure a semantic judge/ }) as HTMLInputElement)
        .checked,
    ).toBe(false);
    expect(screen.queryByLabelText("Judge model")).toBeNull();
  });

  it("adds an enabled judge and removes the whole object again", async () => {
    const onChange = vi.fn();
    const { rerender } = render(
      <PurposeProfileEditor profile={FRAUD} onChange={onChange} />,
    );

    await userEvent.click(
      screen.getByRole("checkbox", { name: /Configure a semantic judge/ }),
    );
    expect(lastEmitted(onChange)).toEqual({
      purposeId: "fraud-detection",
      judge: { enabled: true },
    });

    rerender(
      <PurposeProfileEditor
        profile={{ ...FRAUD, judge: { enabled: true, model: "claude-sonnet" } }}
        onChange={onChange}
      />,
    );
    await userEvent.click(
      screen.getByRole("checkbox", { name: /Configure a semantic judge/ }),
    );

    // The whole object goes, not just `enabled`: a judge block with no `enabled` is a
    // third state, and leaving one behind would keep a model that nothing consults.
    const wire = wireEmitted(onChange);
    expect(Object.keys(wire)).not.toContain("judge");
  });

  it("keeps a disabled judge's settings visible and editable", async () => {
    // The gate is on the judge object existing, not on it being enabled. Hiding a
    // disabled judge's model makes it invisible, un-removable, and live again the
    // instant someone ticks the box.
    const onChange = vi.fn();
    render(
      <PurposeProfileEditor
        profile={{ ...FRAUD, judge: { enabled: false, model: "claude-sonnet" } }}
        onChange={onChange}
      />,
    );

    expect((screen.getByLabelText("Judge model") as HTMLInputElement).value).toBe(
      "claude-sonnet",
    );
    expect(
      (screen.getByRole("checkbox", { name: /Consult the judge/ }) as HTMLInputElement)
        .checked,
    ).toBe(false);

    await userEvent.click(screen.getByRole("checkbox", { name: /Consult the judge/ }));
    expect(lastEmitted(onChange)).toEqual({
      purposeId: "fraud-detection",
      judge: { enabled: true, model: "claude-sonnet" },
    });
  });

  it("stores a judge number and drops the key when it is cleared", async () => {
    // Cleared means "use the SDK default", which is an absent key -- the merger
    // materializes no defaults, so writing 0.85 into the policy would change the signed
    // bytes of every purpose-bound policy for no gain.
    const onChange = vi.fn();
    render(
      <PurposeProfileEditor
        profile={{ ...FRAUD, judge: { enabled: true, historyWindow: 25 } }}
        onChange={onChange}
      />,
    );

    await userEvent.clear(screen.getByLabelText("Judge history window"));

    const wire = wireEmitted(onChange);
    expect(Object.keys(wire.judge as object)).not.toContain("historyWindow");
    expect((wire.judge as Record<string, unknown>).enabled).toBe(true);
  });

  it("surfaces inverted thresholds", () => {
    // `getDisposition` checks the inversion before any verdict, so this does not merely
    // shift a boundary: every single call escalates, and escalation is a denial wherever
    // no review handler is wired.
    render(
      <PurposeProfileEditor
        profile={{
          ...FRAUD,
          judge: {
            enabled: true,
            confidenceThreshold: 0.5,
            escalationThreshold: 0.9,
          },
        }}
        onChange={vi.fn()}
      />,
    );

    const warning = screen.getByText(/An inverted pair is checked/);
    expect(warning.textContent).toMatch(/every call escalates/);
    expect(warning.textContent).toMatch(/denial/);
  });

  it("surfaces an inversion against the unset side's default", () => {
    // Only one threshold configured is the likelier mistake: an escalation of 0.9 with
    // no confidence set is inverted against the 0.85 default, and nothing in the policy
    // JSON shows it.
    render(
      <PurposeProfileEditor
        profile={{ ...FRAUD, judge: { enabled: true, escalationThreshold: 0.9 } }}
        onChange={vi.fn()}
      />,
    );

    expect(screen.getByText(/every call escalates/)).toBeDefined();
  });

  it("does not warn about a correctly ordered pair", () => {
    render(
      <PurposeProfileEditor
        profile={{
          ...FRAUD,
          judge: {
            enabled: true,
            confidenceThreshold: 0.9,
            escalationThreshold: 0.6,
          },
        }}
        onChange={vi.fn()}
      />,
    );

    expect(screen.queryByText(/every call escalates/)).toBeNull();
  });

  it("does not warn when the two are equal, which is not inverted", () => {
    // The disposition check is a strict `>`; equal thresholds have a coherent reading.
    render(
      <PurposeProfileEditor
        profile={{
          ...FRAUD,
          judge: {
            enabled: true,
            confidenceThreshold: 0.7,
            escalationThreshold: 0.7,
          },
        }}
        onChange={vi.fn()}
      />,
    );

    expect(screen.queryByText(/every call escalates/)).toBeNull();
  });

  it("says a differing model cannot be merged, and that a timeout escalates", () => {
    // Two facts an author cannot discover from the form: naming a model narrows what
    // may merge with this policy, and the latency budget is not a fail-open.
    render(
      <PurposeProfileEditor
        profile={{ ...FRAUD, judge: { enabled: true } }}
        onChange={vi.fn()}
      />,
    );

    expect(screen.getByText(/cannot be merged and resolve to deny-all/)).toBeDefined();
    expect(screen.getByText(/A timeout escalates; it never/)).toBeDefined();
  });
});
