/**
 * Policy authoring: list, edit, validate, version, publish, roll back.
 *
 * TOLAP guarantees it enforces the policy you wrote; it does not guarantee the
 * policy is right. `docs/architecture.md` says so directly -- "if a policy is
 * overly permissive, TOLAP will faithfully enforce that permissiveness" -- so the
 * three features aimed at that risk are the ones this page is built around:
 * live validation, catalog-backed pickers, and a diff before anything is published.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  api,
  ApiError,
  fetchAll,
  type PolicyDefinition,
  type PolicyVersion,
  type SourceManifest,
  type ValidationError,
} from "../api.ts";
import { FieldPicker } from "../components/FieldPicker.tsx";
import { EndpointPicker, MethodPicker } from "../components/EndpointPicker.tsx";
import { MaskedFieldEditor } from "../components/MaskedFieldEditor.tsx";
import { RowFilterEditor } from "../components/RowFilterEditor.tsx";
import { TagPicker } from "../components/TagPicker.tsx";

/**
 * Page size for the selector fetches, set to the server's ceiling.
 *
 * `fetchAll` follows at most 20 pages before throwing rather than returning a partial
 * list, so this constant sets the real limit on how large a deployment these pages
 * support: 20 x 500 = 10,000. At the server's *default* of 200 it would be 4,000, and the
 * failure is not graceful -- the Policies tab renders only an error banner, and the policy
 * list is that page's own navigation, so the page becomes unusable rather than degraded.
 *
 * Asking for the ceiling also means 2.5x fewer round trips for every deployment, large or
 * small.
 */
const SELECTOR_PAGE = 500;

const BLANK: PolicyDefinition = {
  version: "1.0",
  name: "",
  // canQuery false and readOnly true: a new policy starts granting nothing and
  // permitting no writes. An author has to ask for access, rather than remember to
  // remove it.
  permissions: { canQuery: false, readOnly: true },
};

/** Stable, sorted JSON so two policies can be compared line by line. */
function stableJson(value: unknown): string {
  const sort = (node: unknown): unknown => {
    if (Array.isArray(node)) return node.map(sort);
    if (node && typeof node === "object") {
      return Object.fromEntries(
        Object.keys(node as Record<string, unknown>)
          .sort()
          .map((key) => [key, sort((node as Record<string, unknown>)[key])]),
      );
    }
    return node;
  };
  return JSON.stringify(sort(value), null, 2);
}

interface DiffLine {
  readonly kind: "same" | "added" | "removed";
  readonly text: string;
}

/**
 * Line diff between the published policy and the draft.
 *
 * Deliberately simple: a set-membership comparison, not a longest-common-
 * subsequence. It answers "what changed" for a JSON document whose keys are
 * sorted, which is the question before publishing, and it needs no dependency.
 */
function diffLines(before: string, after: string): DiffLine[] {
  const beforeLines = before.split("\n");
  const afterLines = after.split("\n");
  const beforeSet = new Set(beforeLines);
  const afterSet = new Set(afterLines);

  const lines: DiffLine[] = [];
  for (const line of beforeLines) {
    if (!afterSet.has(line)) lines.push({ kind: "removed", text: line });
  }
  for (const line of afterLines) {
    lines.push({ kind: afterSet.has(line) && beforeSet.has(line) ? "same" : "added", text: line });
  }
  return lines.filter((line) => line.kind !== "same");
}

export function PoliciesPage({ readOnly }: { readonly readOnly: boolean }) {
  const [policies, setPolicies] = useState<PolicyDefinition[]>([]);
  const [sources, setSources] = useState<SourceManifest[]>([]);
  const [draft, setDraft] = useState<PolicyDefinition | undefined>();
  const [published, setPublished] = useState<PolicyDefinition | undefined>();
  const [versions, setVersions] = useState<PolicyVersion[]>([]);
  const [errors, setErrors] = useState<ValidationError[]>([]);
  const [status, setStatus] = useState<string | undefined>();
  const [failure, setFailure] = useState<string | undefined>();
  const [catalogFor, setCatalogFor] = useState<string>("");
  const [showDiff, setShowDiff] = useState(false);

  const refresh = useCallback(async () => {
    try {
      // Every page of both, rather than the first. These are selectors, not browsable
      // tables: the policy list IS the navigation for this page, and the source list
      // populates the manifest dropdown that drives every catalog-backed picker. A
      // truncated selector hides a policy or a source that exists, and the author
      // reasonably concludes it was never created -- with no control to prove otherwise.
      const [list, catalog] = await Promise.all([
        fetchAll<PolicyDefinition>((cursor) => api.listPolicies({ cursor, limit: SELECTOR_PAGE }), "policies"),
        fetchAll<SourceManifest>((cursor) => api.listSources({ cursor, limit: SELECTOR_PAGE }), "sources"),
      ]);
      setPolicies(list);
      setSources(catalog);
      setFailure(undefined);
    } catch (caught) {
      setFailure((caught as Error).message);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const manifest = useMemo(
    () => sources.find((source) => source.sourceConnectionId === catalogFor),
    [sources, catalogFor],
  );

  /** Revalidate on every edit, in fragment mode so a partial draft is not noise. */
  useEffect(() => {
    if (!draft) {
      setErrors([]);
      return;
    }
    let cancelled = false;
    const timer = setTimeout(() => {
      void api
        .validatePolicy(draft, true)
        .then((result) => {
          if (!cancelled) setErrors(result.errors);
        })
        .catch(() => {
          // A validation request failing is not the author's problem to see on
          // every keystroke; the save path reports it authoritatively.
        });
    }, 250);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [draft]);

  const open = async (name: string) => {
    try {
      const policy = await api.getPolicy(name);
      setDraft(structuredClone(policy));
      setPublished(policy);
      setVersions((await api.listVersions(name)).versions);
      setShowDiff(false);
      setStatus(undefined);
      setFailure(undefined);
    } catch (caught) {
      setFailure((caught as Error).message);
    }
  };

  const startNew = () => {
    setDraft(structuredClone(BLANK));
    setPublished(undefined);
    setVersions([]);
    setShowDiff(false);
    setStatus(undefined);
  };

  const patch = (change: Partial<PolicyDefinition>) => {
    setDraft((current) => (current ? { ...current, ...change } : current));
  };

  const patchObjectRules = (
    change: Partial<NonNullable<PolicyDefinition["objectRules"]>>,
  ) => {
    setDraft((current) =>
      current
        ? { ...current, objectRules: { ...current.objectRules, ...change } }
        : current,
    );
  };

  const patchFieldRules = (
    change: Partial<
      NonNullable<NonNullable<PolicyDefinition["objectRules"]>["fieldRules"]>
    >,
  ) => {
    setDraft((current) =>
      current
        ? {
            ...current,
            objectRules: {
              ...current.objectRules,
              fieldRules: { ...current.objectRules?.fieldRules, ...change },
            },
          }
        : current,
    );
  };

  const patchEndpointRules = (
    change: Partial<
      NonNullable<NonNullable<PolicyDefinition["objectRules"]>["endpointRules"]>
    >,
  ) => {
    setDraft((current) =>
      current
        ? {
            ...current,
            objectRules: {
              ...current.objectRules,
              endpointRules: { ...current.objectRules?.endpointRules, ...change },
            },
          }
        : current,
    );
  };

  const patchTagRules = (
    change: Partial<
      NonNullable<NonNullable<PolicyDefinition["objectRules"]>["tagRules"]>
    >,
  ) => {
    setDraft((current) =>
      current
        ? {
            ...current,
            objectRules: {
              ...current.objectRules,
              tagRules: { ...current.objectRules?.tagRules, ...change },
            },
          }
        : current,
    );
  };

  /**
   * The selected source's category, which decides which sections are relevant.
   *
   * Taken from the manifest rather than guessed from the policy: the category is a
   * segment of the source id (`db:`, `api:`, `kb:`, `storage:`) and the connector spec
   * makes it the thing that decides which rules an enforcement wrapper even reads.
   * Showing endpoint rules for a database source would invite authoring a rule that is
   * silently ignored.
   */
  const category = manifest?.category;

  const act = async (label: string, action: () => Promise<unknown>) => {
    setStatus(undefined);
    setFailure(undefined);
    try {
      await action();
      setStatus(label);
      await refresh();
    } catch (caught) {
      if (caught instanceof ApiError && caught.errors.length > 0) {
        setErrors(caught.errors);
        setFailure(`${caught.message}: see the errors listed below.`);
        return;
      }
      setFailure((caught as Error).message);
    }
  };

  const saveDraft = () =>
    act("Draft saved. Review the diff, then publish.", async () => {
      const { versionNo } = await api.saveDraft(draft!);
      setVersions((await api.listVersions(draft!.name)).versions);
      return versionNo;
    });

  const publishLatest = async () => {
    const latest = versions.find((version) => version.state === "draft");
    if (!latest) {
      setFailure("Save a draft before publishing.");
      return;
    }
    await act(`Version ${latest.versionNo} published.`, async () => {
      await api.publish(draft!.name, latest.versionNo);
      const policy = await api.getPolicy(draft!.name);
      setPublished(policy);
      setVersions((await api.listVersions(draft!.name)).versions);
    });
  };

  const draftJson = draft ? stableJson(draft) : "";
  const publishedJson = published ? stableJson(published) : "";
  const changed = draftJson !== publishedJson;
  const diff = useMemo(
    () => (changed ? diffLines(publishedJson, draftJson) : []),
    [changed, publishedJson, draftJson],
  );

  return (
    <section className="page">
      <div className="page__list">
        <div className="page__list-header">
          <h2>Policies</h2>
          {!readOnly ? (
            <button type="button" onClick={startNew}>
              New
            </button>
          ) : null}
        </div>
        {policies.length === 0 ? (
          <p className="muted">No policies yet.</p>
        ) : (
          <ul className="policy-list">
            {policies.map((policy) => (
              <li key={policy.name}>
                <button type="button" onClick={() => void open(policy.name)}>
                  <code>{policy.name}</code>
                  {policy.permissions.canQuery ? null : (
                    <span className="badge badge--deny" title="canQuery is false">
                      no read
                    </span>
                  )}
                  {policy.permissions.readOnly === false ? (
                    <span className="badge badge--warn" title="Writes are permitted">
                      writes
                    </span>
                  ) : null}
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="page__detail">
        {failure ? (
          <p className="banner banner--error" role="alert">
            {failure}
          </p>
        ) : null}
        {status ? (
          <p className="banner banner--success" role="status">
            {status}
          </p>
        ) : null}

        {!draft ? (
          <p className="muted">Select a policy, or create one.</p>
        ) : (
          <form
            onSubmit={(event) => {
              event.preventDefault();
              void saveDraft();
            }}
          >
            <fieldset disabled={readOnly}>
              <legend>Identity</legend>
              <label htmlFor="policy-name">Name</label>
              <input
                id="policy-name"
                value={draft.name}
                onChange={(event) => patch({ name: event.target.value })}
                // The schema's pattern, surfaced here rather than discovered on save.
                pattern="[a-z0-9]([a-z0-9-]*[a-z0-9])?"
                title="Lowercase letters, digits and hyphens"
                required
              />

              <label htmlFor="policy-description">Description</label>
              <input
                id="policy-description"
                value={draft.description ?? ""}
                onChange={(event) =>
                  patch({ description: event.target.value || undefined })
                }
              />

              <label htmlFor="policy-priority">Priority</label>
              <input
                id="policy-priority"
                type="number"
                min={0}
                max={1000}
                value={draft.priority ?? 100}
                onChange={(event) => patch({ priority: Number(event.target.value) })}
              />
            </fieldset>

            <fieldset disabled={readOnly}>
              <legend>Scope</legend>
              <p className="hint">
                {/*
                  Section 10 is the one place an empty list does NOT mean deny-all,
                  and the asymmetry with section 3 has caused real bugs.
                */}
                Leave empty to apply to <strong>every</strong> source. This is the
                opposite of an allow-list, where empty denies everything.
              </p>
              <FieldPicker
                label="Source patterns"
                selected={draft.sourcePatterns ?? []}
                // Section 10, not section 3: absent and `[]` both mean "every source"
                // here, so the default allow-list message would say the opposite.
                emptyMeans="everySource"
                onChange={(next) =>
                  patch({ sourcePatterns: next.length > 0 ? next : undefined })
                }
              />
            </fieldset>

            <fieldset disabled={readOnly}>
              <legend>Permissions</legend>
              <label>
                <input
                  type="checkbox"
                  checked={draft.permissions.canQuery}
                  onChange={(event) =>
                    patch({
                      permissions: {
                        ...draft.permissions,
                        canQuery: event.target.checked,
                      },
                    })
                  }
                />
                Can read (<code>canQuery</code>)
              </label>
              <label>
                <input
                  type="checkbox"
                  checked={draft.permissions.readOnly !== false}
                  onChange={(event) =>
                    patch({
                      permissions: {
                        ...draft.permissions,
                        readOnly: event.target.checked,
                      },
                    })
                  }
                />
                Read-only (denies every write regardless of the flags below)
              </label>
              {draft.permissions.readOnly === false ? (
                <div className="nested">
                  {(["canInsert", "canUpdate", "canDelete"] as const).map((flag) => (
                    <label key={flag}>
                      <input
                        type="checkbox"
                        checked={draft.permissions[flag] === true}
                        onChange={(event) =>
                          patch({
                            permissions: {
                              ...draft.permissions,
                              [flag]: event.target.checked,
                            },
                          })
                        }
                      />
                      <code>{flag}</code>
                    </label>
                  ))}
                </div>
              ) : null}
            </fieldset>

            <fieldset disabled={readOnly}>
              <legend>Objects and fields</legend>
              <label htmlFor="catalog-source">Suggest names from</label>
              <select
                id="catalog-source"
                value={catalogFor}
                onChange={(event) => setCatalogFor(event.target.value)}
              >
                <option value="">— no source selected —</option>
                {sources.map((source) => (
                  <option
                    key={source.sourceConnectionId}
                    value={source.sourceConnectionId}
                  >
                    {source.displayName ?? source.sourceConnectionId}
                  </option>
                ))}
              </select>
              {sources.length === 0 ? (
                <p className="hint">
                  No sources in the catalog. Add one under <strong>Sources</strong> to
                  pick real object and field names instead of typing them.
                </p>
              ) : null}
              {manifest ? (
                <p className="hint">
                  <span className="badge">{manifest.category}</span>{" "}
                  {manifest.objects.length} object(s),{" "}
                  {manifest.objects.reduce((n, o) => n + o.fields.length, 0)} field(s)
                  {manifest.endpoints.length > 0
                    ? `, ${manifest.endpoints.length} endpoint(s)`
                    : ""}
                  {manifest.tags.length > 0 ? `, ${manifest.tags.length} tag(s)` : ""}
                  {". Sections below are filtered to this category."}
                </p>
              ) : null}

              <FieldPicker
                label="Allowed objects"
                objects
                manifest={manifest}
                selected={draft.objectRules?.allowedObjects ?? []}
                onChange={(next) =>
                  patchObjectRules({
                    allowedObjects: next.length > 0 ? next : undefined,
                  })
                }
              />
              <FieldPicker
                label="Hidden objects"
                objects
                manifest={manifest}
                selected={draft.objectRules?.hiddenObjects ?? []}
                onChange={(next) =>
                  patchObjectRules({
                    hiddenObjects: next.length > 0 ? next : undefined,
                  })
                }
              />
              <FieldPicker
                label="Allowed fields"
                manifest={manifest}
                selected={draft.objectRules?.fieldRules?.allowedFields ?? []}
                onChange={(next) =>
                  patchFieldRules({
                    allowedFields: next.length > 0 ? next : undefined,
                  })
                }
              />
              <FieldPicker
                label="Hidden fields"
                manifest={manifest}
                selected={draft.objectRules?.fieldRules?.hiddenFields ?? []}
                onChange={(next) =>
                  patchFieldRules({
                    hiddenFields: next.length > 0 ? next : undefined,
                  })
                }
              />

              <FieldPicker
                label="Read-only fields"
                manifest={manifest}
                selected={draft.objectRules?.fieldRules?.readOnlyFields ?? []}
                describedBy="readonly-fields-hint"
                onChange={(next) =>
                  patchFieldRules({
                    readOnlyFields: next.length > 0 ? next : undefined,
                  })
                }
              />
              <p className="hint" id="readonly-fields-hint">
                Readable but not writable. No effect on reads; a write whose payload
                contains one of these is rejected outright.
              </p>
            </fieldset>

            <fieldset disabled={readOnly}>
              <legend>Masking</legend>
              <MaskedFieldEditor
                rules={draft.objectRules?.fieldRules?.maskedFields ?? []}
                manifest={manifest}
                onChange={(next) =>
                  patchFieldRules({
                    maskedFields: next.length > 0 ? next : undefined,
                  })
                }
              />
            </fieldset>

            <fieldset disabled={readOnly}>
              <legend>Rows</legend>
              <RowFilterEditor
                filters={draft.objectRules?.rowFilters ?? []}
                manifest={manifest}
                onChange={(next) =>
                  patchObjectRules({ rowFilters: next.length > 0 ? next : undefined })
                }
              />
            </fieldset>

            {/*
              Category-gated sections. Endpoint rules do not constrain a SQL query and
              tag rules do not constrain an API call -- the connector spec has each
              wrapper read only the fields for its own category -- so authoring them
              against the wrong source type produces rules that are silently ignored.
              Shown when the selected source is that category, or when the policy
              already carries such rules (so an existing policy is never un-editable).
            */}
            {category === "api" ||
            draft.objectRules?.endpointRules !== undefined ? (
              <fieldset disabled={readOnly}>
                <legend>API endpoints</legend>
                <EndpointPicker
                  label="Allowed endpoints"
                  manifest={manifest}
                  selected={draft.objectRules?.endpointRules?.allowedEndpoints ?? []}
                  onChange={(next) =>
                    patchEndpointRules({
                      allowedEndpoints: next.length > 0 ? next : undefined,
                    })
                  }
                />
                <EndpointPicker
                  label="Hidden endpoints"
                  manifest={manifest}
                  selected={draft.objectRules?.endpointRules?.hiddenEndpoints ?? []}
                  onChange={(next) =>
                    patchEndpointRules({
                      hiddenEndpoints: next.length > 0 ? next : undefined,
                    })
                  }
                />
                <MethodPicker
                  manifest={manifest}
                  selected={draft.objectRules?.endpointRules?.allowedMethods}
                  onChange={(next) => patchEndpointRules({ allowedMethods: next })}
                />
              </fieldset>
            ) : null}

            {category === "kb" || draft.objectRules?.tagRules !== undefined ? (
              <fieldset disabled={readOnly}>
                <legend>Knowledge-base tags</legend>
                <TagPicker
                  label="Allowed tags"
                  semantics="allow"
                  manifest={manifest}
                  selected={draft.objectRules?.tagRules?.allowedTags ?? []}
                  onChange={(next) =>
                    patchTagRules({ allowedTags: next.length > 0 ? next : undefined })
                  }
                />
                <TagPicker
                  label="Denied tags"
                  semantics="deny"
                  manifest={manifest}
                  selected={draft.objectRules?.tagRules?.deniedTags ?? []}
                  onChange={(next) =>
                    patchTagRules({ deniedTags: next.length > 0 ? next : undefined })
                  }
                />
              </fieldset>
            ) : null}

            <fieldset disabled={readOnly}>
              <legend>Limits</legend>
              <label htmlFor="max-results">Max results per call</label>
              <input
                id="max-results"
                type="number"
                min={0}
                value={draft.limits?.maxResults ?? ""}
                placeholder="unlimited"
                onChange={(event) =>
                  patch({
                    limits: {
                      ...draft.limits,
                      maxResults:
                        event.target.value === ""
                          ? undefined
                          : Number(event.target.value),
                    },
                  })
                }
              />
              <p className="hint">
                {/* Zero is meaningful, which a minimum of 1 would forbid expressing. */}
                Empty means unlimited. <code>0</code> is valid and returns nothing.
              </p>

              {category === "kb" || draft.limits?.minSimilarityScore !== undefined ? (
                <>
                  <label htmlFor="min-similarity">Minimum similarity score</label>
                  <input
                    id="min-similarity"
                    type="number"
                    min={0}
                    max={1}
                    step={0.01}
                    value={draft.limits?.minSimilarityScore ?? ""}
                    placeholder="no threshold"
                    onChange={(event) =>
                      patch({
                        limits: {
                          ...draft.limits,
                          minSimilarityScore:
                            event.target.value === ""
                              ? undefined
                              : Number(event.target.value),
                        },
                      })
                    }
                  />
                  <p className="hint">
                    Vector-search floor, 0 to 1. Higher is more restrictive — it drops
                    weaker matches.
                  </p>
                </>
              ) : null}

              {category === "storage" ||
              draft.limits?.maxObjectSizeBytes !== undefined ? (
                <>
                  <label htmlFor="max-object-size">Max object size (bytes)</label>
                  <input
                    id="max-object-size"
                    type="number"
                    min={1}
                    value={draft.limits?.maxObjectSizeBytes ?? ""}
                    placeholder="unlimited"
                    onChange={(event) =>
                      patch({
                        limits: {
                          ...draft.limits,
                          maxObjectSizeBytes:
                            event.target.value === ""
                              ? undefined
                              : Number(event.target.value),
                        },
                      })
                    }
                  />
                </>
              ) : null}
            </fieldset>

            {errors.length > 0 ? (
              <div className="banner banner--warning" role="status">
                <strong>{errors.length} schema issue(s):</strong>
                <ul>
                  {errors.map((error) => (
                    <li key={`${error.path}-${error.message}`}>
                      <code>{error.path}</code> {error.message}
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}

            {!readOnly ? (
              <div className="actions">
                <button type="submit" disabled={errors.length > 0}>
                  Save draft
                </button>
                <button
                  type="button"
                  onClick={() => setShowDiff((shown) => !shown)}
                  disabled={!changed}
                >
                  {showDiff ? "Hide diff" : "Review diff"}
                </button>
                <button
                  type="button"
                  onClick={() => void publishLatest()}
                  disabled={!versions.some((version) => version.state === "draft")}
                >
                  Publish latest draft
                </button>
              </div>
            ) : null}

            {showDiff ? (
              <div className="diff">
                <h3>Change against the published policy</h3>
                {diff.length === 0 ? (
                  <p className="muted">No differences.</p>
                ) : (
                  <pre>
                    {diff.map((line, index) => (
                      <div key={index} className={`diff__${line.kind}`}>
                        {line.kind === "added" ? "+" : "-"} {line.text}
                      </div>
                    ))}
                  </pre>
                )}
              </div>
            ) : null}
          </form>
        )}

        {versions.length > 0 ? (
          <div className="versions">
            <h3>Versions</h3>
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>State</th>
                  <th>By</th>
                  <th>When</th>
                  <th>Note</th>
                  {!readOnly ? <th /> : null}
                </tr>
              </thead>
              <tbody>
                {versions.map((version) => (
                  <tr key={version.versionNo}>
                    <td>{version.versionNo}</td>
                    <td>
                      <span className={`badge badge--${version.state}`}>
                        {version.state}
                      </span>
                    </td>
                    <td>{version.createdBy}</td>
                    <td>{new Date(version.createdAt).toLocaleString()}</td>
                    <td>{version.note ?? ""}</td>
                    {!readOnly ? (
                      <td>
                        {version.state === "published" ? null : (
                          <button
                            type="button"
                            onClick={() =>
                              void act(
                                `Rolled back to version ${version.versionNo}.`,
                                async () => {
                                  await api.rollback(draft!.name, version.versionNo);
                                  const policy = await api.getPolicy(draft!.name);
                                  setDraft(structuredClone(policy));
                                  setPublished(policy);
                                  setVersions(
                                    (await api.listVersions(draft!.name)).versions,
                                  );
                                },
                              )
                            }
                          >
                            {version.state === "draft" ? "Publish" : "Roll back to"}
                          </button>
                        )}
                      </td>
                    ) : null}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </div>
    </section>
  );
}
