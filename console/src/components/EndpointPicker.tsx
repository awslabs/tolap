/**
 * Endpoint rules for `api` sources, driven by an imported OpenAPI document.
 *
 * This is where the OpenAPI importer pays off. It converts `/patients/{id}` into
 * `/patients/*` — the glob form TOLAP endpoint rules actually match — so an author
 * picking from the list gets a pattern that works at enforcement time rather than a
 * literal `{id}` that never matches anything.
 *
 * Methods are per-policy rather than per-endpoint, because that is what the schema
 * models: `allowedMethods` applies to the whole policy. The methods each endpoint
 * *offers* are shown next to it so an author can see when they are allowing a verb the
 * API does not expose, or forbidding one it does.
 */

import { useMemo, useState } from "react";
import type { SourceManifest } from "../api.ts";

/** The methods the policy schema's `allowedMethods` enum permits. */
const HTTP_METHODS = [
  "GET",
  "HEAD",
  "OPTIONS",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
] as const;

/** Methods that only read. Everything else can change data. */
const READ_ONLY_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

export interface EndpointPickerProps {
  readonly label: string;
  readonly selected: string[];
  readonly manifest?: SourceManifest;
  readonly onChange: (next: string[]) => void;
}

/** Endpoint paths this source exposes, plus the methods each offers. */
export function endpointOptions(
  manifest: SourceManifest | undefined,
): Array<{ path: string; methods: string[] }> {
  if (!manifest) return [];
  return [...manifest.endpoints]
    .map((endpoint) => ({ path: endpoint.path, methods: endpoint.methods }))
    .sort((a, b) => a.path.localeCompare(b.path));
}

export function EndpointPicker({
  label,
  selected,
  manifest,
  onChange,
}: EndpointPickerProps) {
  const [draft, setDraft] = useState("");
  const options = useMemo(() => endpointOptions(manifest), [manifest]);
  const available = options.filter((option) => !selected.includes(option.path));

  const add = (value: string) => {
    const trimmed = value.trim();
    if (trimmed === "" || selected.includes(trimmed)) return;
    onChange([...selected, trimmed]);
    setDraft("");
  };

  const listId = `${label.replace(/\W+/g, "-").toLowerCase()}-endpoints`;

  return (
    <div className="field-picker">
      <span className="field-picker__label">{label}</span>

      {selected.length === 0 ? (
        <p className="field-picker__empty" role="note">
          Nothing selected. An empty allow-list <strong>denies every endpoint</strong>;
          removing the rule entirely leaves them unrestricted.
        </p>
      ) : (
        <ul className="field-picker__selected">
          {selected.map((path) => {
            // Case-insensitive: the enforcement glob dialect is (canonical spec 3.1),
            // so `/API/v1/patients` really does match the imported `/api/v1/patients`
            // and flagging it would warn about a rule that works.
            const known = options.find(
              (option) => option.path.toLowerCase() === path.toLowerCase(),
            );
            const isPattern = path.includes("*");
            return (
              <li key={path} className="field-picker__chip">
                <code>{path}</code>
                {known ? (
                  <span className="field-picker__pattern">
                    {known.methods.join(" ")}
                  </span>
                ) : !isPattern && manifest ? (
                  <span
                    className="field-picker__warning"
                    title="Not in this source's catalog. It may be a typo, or the OpenAPI import may be out of date."
                  >
                    ⚠ not in catalog
                  </span>
                ) : null}
                <button
                  type="button"
                  onClick={() => onChange(selected.filter((p) => p !== path))}
                  aria-label={`Remove ${path} from ${label}`}
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
              ? "Select or type an endpoint path"
              : "Import an OpenAPI document to see suggestions"
          }
          aria-label={`Add to ${label}`}
          onChange={(event) => setDraft(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") {
              // Otherwise Enter submits the surrounding form, discarding the entry.
              event.preventDefault();
              add(draft);
            }
          }}
        />
        <datalist id={listId}>
          {available.map((option) => (
            <option key={option.path} value={option.path}>
              {option.methods.join(" ")}
            </option>
          ))}
        </datalist>
        <button type="button" onClick={() => add(draft)} disabled={draft.trim() === ""}>
          Add
        </button>
      </div>

      {manifest && available.length > 0 ? (
        <p className="field-picker__hint">
          {available.length} endpoint(s) available from{" "}
          <code>{manifest.sourceConnectionId}</code>
        </p>
      ) : null}
    </div>
  );
}

export interface MethodPickerProps {
  readonly selected: string[] | undefined;
  readonly manifest?: SourceManifest;
  readonly onChange: (next: string[] | undefined) => void;
}

/**
 * HTTP methods the policy permits.
 *
 * Absent means the schema default — read-only methods only — which is a different
 * policy from an empty list, so the two are distinguished explicitly rather than
 * collapsed into "nothing checked".
 */
export function MethodPicker({ selected, manifest, onChange }: MethodPickerProps) {
  // Which methods this source actually exposes anywhere, so allowing a verb the API
  // does not offer is visible rather than silent.
  const offered = useMemo(() => {
    const set = new Set<string>();
    for (const endpoint of manifest?.endpoints ?? []) {
      for (const method of endpoint.methods) set.add(method);
    }
    return set;
  }, [manifest]);

  const explicit = selected !== undefined;

  return (
    <div className="rule-editor">
      <span className="field-picker__label">Allowed methods</span>

      <label>
        <input
          type="checkbox"
          checked={!explicit}
          onChange={(event) => onChange(event.target.checked ? undefined : ["GET"])}
        />
        Use the default (<code>GET</code>, <code>HEAD</code>, <code>OPTIONS</code> — read
        only)
      </label>

      {explicit ? (
        <>
          <div className="method-grid">
            {HTTP_METHODS.map((method) => {
              const checked = selected.includes(method);
              return (
                <label key={method} className="method-grid__item">
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={(event) =>
                      onChange(
                        event.target.checked
                          ? [...selected, method]
                          : selected.filter((m) => m !== method),
                      )
                    }
                  />
                  <code>{method}</code>
                  {!READ_ONLY_METHODS.has(method) && checked ? (
                    <span className="field-picker__warning" title="This method can change data">
                      writes
                    </span>
                  ) : null}
                  {manifest && !offered.has(method) ? (
                    <span
                      className="field-picker__pattern"
                      title="No endpoint in this source's catalog offers this method"
                    >
                      unused
                    </span>
                  ) : null}
                </label>
              );
            })}
          </div>

          {selected.length === 0 ? (
            <p className="rule-editor__warning">
              ⚠ An empty method list denies every request. Uncheck the box above to fall
              back to the read-only default instead.
            </p>
          ) : null}
        </>
      ) : null}
    </div>
  );
}
