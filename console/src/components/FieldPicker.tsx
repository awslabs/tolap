/**
 * Pick object and field names from the source catalog.
 *
 * This is the component the catalog exists for. `hiddenFields: ["ssn"]` protects
 * nothing when the column is actually `ssn_number`, and no part of TOLAP can
 * detect that: the policy validates, signs, resolves, and enforces perfectly
 * while guarding a column that does not exist. Picking from a list of real names
 * removes the typo entirely.
 *
 * Free text is still allowed, because a policy may legitimately name something the
 * catalog does not have -- a glob like `patients.*`, or a table added since the
 * manifest was imported. Such a value is **flagged, not blocked**: the catalog is
 * an authoring aid and must never become an authority on what a policy may say.
 */

import { useMemo, useState } from "react";
import type { SourceManifest } from "../api.ts";

export interface FieldPickerProps {
  readonly label: string;
  readonly selected: string[];
  readonly manifest?: SourceManifest;
  /** Offer object names (tables) rather than field names. */
  readonly objects?: boolean;
  readonly onChange: (next: string[]) => void;
  readonly describedBy?: string;
}

/** Every field name a policy could name for this source. */
export function fieldOptions(manifest: SourceManifest | undefined): string[] {
  if (!manifest) return [];
  const options = new Set<string>();
  for (const object of manifest.objects) {
    for (const field of object.fields) {
      // The dotted form scopes a column to one table for a `db` policy; the bare
      // form is what `api` and `kb` policies match on (connector-spec 3.2).
      options.add(`${object.name}.${field}`);
      options.add(field);
    }
  }
  for (const endpoint of manifest.endpoints) {
    for (const field of endpoint.responseFields) options.add(field);
  }
  return [...options].sort();
}

/** Object names: tables for `db`, endpoint paths for `api`, prefixes for `storage`. */
export function objectOptions(manifest: SourceManifest | undefined): string[] {
  if (!manifest) return [];
  const options = new Set<string>();
  for (const object of manifest.objects) options.add(object.name);
  for (const endpoint of manifest.endpoints) options.add(endpoint.path);
  for (const prefix of manifest.prefixes) options.add(prefix);
  return [...options].sort();
}

/** Does this value look like a glob rather than a literal name? */
function isPattern(value: string): boolean {
  return value.includes("*") || value.includes("?");
}

export function FieldPicker({
  label,
  selected,
  manifest,
  objects = false,
  onChange,
  describedBy,
}: FieldPickerProps) {
  const [draft, setDraft] = useState("");

  const options = useMemo(
    () => (objects ? objectOptions(manifest) : fieldOptions(manifest)),
    [manifest, objects],
  );

  const available = useMemo(
    () => options.filter((option) => !selected.includes(option)),
    [options, selected],
  );

  const add = (value: string) => {
    const trimmed = value.trim();
    if (trimmed === "" || selected.includes(trimmed)) return;
    onChange([...selected, trimmed]);
    setDraft("");
  };

  const remove = (value: string) => {
    onChange(selected.filter((entry) => entry !== value));
  };

  const listId = `${label.replace(/\W+/g, "-").toLowerCase()}-options`;

  return (
    <div className="field-picker">
      <span className="field-picker__label" id={`${listId}-label`}>
        {label}
      </span>

      {selected.length === 0 ? (
        <p className="field-picker__empty" role="note">
          {/*
            Empty and absent are different policies, and the difference is the
            most dangerous thing in the schema: for an allow-list, absent means
            unrestricted while an empty list denies everything (spec section 3).
            An author looking at a blank control needs to know which one they have.
          */}
          Nothing selected. An empty allow-list <strong>denies everything</strong>;
          removing the rule entirely leaves it unrestricted.
        </p>
      ) : (
        <ul className="field-picker__selected">
          {selected.map((value) => {
            const known = options.includes(value);
            const pattern = isPattern(value);
            return (
              <li key={value} className="field-picker__chip">
                <code>{value}</code>
                {!known && !pattern && manifest ? (
                  <span
                    className="field-picker__warning"
                    title="Not present in this source's catalog. It may be a typo, or the catalog may be out of date."
                  >
                    {/* Flagged, never blocked. */}
                    ⚠ not in catalog
                  </span>
                ) : null}
                {pattern ? (
                  <span className="field-picker__pattern" title="Glob pattern">
                    pattern
                  </span>
                ) : null}
                <button
                  type="button"
                  onClick={() => remove(value)}
                  aria-label={`Remove ${value} from ${label}`}
                >
                  ×
                </button>
              </li>
            );
          })}
        </ul>
      )}

      <div className="field-picker__add">
        <input
          type="text"
          list={listId}
          value={draft}
          placeholder={
            manifest
              ? objects
                ? "Select or type an object name"
                : "Select or type a field name"
              : "Select a source above to see suggestions"
          }
          aria-label={`Add to ${label}`}
          aria-describedby={describedBy}
          onChange={(event) => setDraft(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") {
              // Otherwise Enter submits the surrounding form, discarding the entry
              // the author was in the middle of typing.
              event.preventDefault();
              add(draft);
            }
          }}
        />
        <datalist id={listId}>
          {available.map((option) => (
            <option key={option} value={option} />
          ))}
        </datalist>
        <button type="button" onClick={() => add(draft)} disabled={draft.trim() === ""}>
          Add
        </button>
      </div>

      {manifest && available.length > 0 ? (
        <p className="field-picker__hint">
          {available.length} available from{" "}
          <code>{manifest.sourceConnectionId}</code>
        </p>
      ) : null}
    </div>
  );
}
