/**
 * Tag rules for `kb` sources, driven by the imported catalog.
 *
 * Knowledge bases express classification as tags, so this is how a policy says
 * "clinical researchers may read de-identified documents but not raw PHI".
 *
 * The direction is the thing to get right, and it is not symmetric: `deniedTags` takes
 * precedence over `allowedTags`, and a document needs only **one** allowed tag to pass.
 * So an allow-list is narrower than it looks and a deny-list is absolute. Both are
 * stated inline, because getting this backwards produces a policy that reads as
 * restrictive and returns everything.
 */

import { useMemo, useState } from "react";
import type { SourceManifest } from "../api.ts";

export interface TagPickerProps {
  readonly label: string;
  readonly selected: string[];
  readonly manifest?: SourceManifest;
  /** Shown under the control: allow and deny behave differently enough to say so. */
  readonly semantics: "allow" | "deny";
  readonly onChange: (next: string[]) => void;
}

export function tagOptions(manifest: SourceManifest | undefined): string[] {
  return manifest ? [...manifest.tags].sort() : [];
}

export function TagPicker({
  label,
  selected,
  manifest,
  semantics,
  onChange,
}: TagPickerProps) {
  const [draft, setDraft] = useState("");
  const options = useMemo(() => tagOptions(manifest), [manifest]);
  const available = options.filter((option) => !selected.includes(option));
  const known = new Set(options);

  const add = (value: string) => {
    const trimmed = value.trim();
    if (trimmed === "" || selected.includes(trimmed)) return;
    onChange([...selected, trimmed]);
    setDraft("");
  };

  const listId = `${label.replace(/\W+/g, "-").toLowerCase()}-tags`;

  return (
    <div className="field-picker">
      <span className="field-picker__label">{label}</span>

      {selected.length === 0 ? (
        <p className="field-picker__empty" role="note">
          {semantics === "allow" ? (
            <>
              Nothing selected. An empty allow-list returns{" "}
              <strong>no documents at all</strong>; removing the rule leaves them
              unrestricted.
            </>
          ) : (
            <>Nothing denied. No document is excluded on the basis of its tags.</>
          )}
        </p>
      ) : (
        <ul className="field-picker__selected">
          {selected.map((tag) => (
            <li key={tag} className="field-picker__chip">
              <code>{tag}</code>
              {manifest && !known.has(tag) ? (
                <span
                  className="field-picker__warning"
                  title="No document in this source's catalog carries this tag. It may be a typo, or the manifest may be out of date."
                >
                  ⚠ not in catalog
                </span>
              ) : null}
              <button
                type="button"
                onClick={() => onChange(selected.filter((t) => t !== tag))}
                aria-label={`Remove ${tag} from ${label}`}
              >
                ×
              </button>
            </li>
          ))}
        </ul>
      )}

      <p className="rule-editor__note">
        {semantics === "allow"
          ? "A document passes if it carries at least ONE of these tags."
          : "A document is excluded if it carries ANY of these tags. Takes precedence over the allow-list."}
      </p>

      <div className="field-picker__add">
        <input
          type="text"
          list={listId}
          value={draft}
          placeholder={
            manifest ? "Select or type a tag" : "Import a source to see suggestions"
          }
          aria-label={`Add to ${label}`}
          onChange={(event) => setDraft(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") {
              // Otherwise Enter submits the surrounding form.
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
    </div>
  );
}
