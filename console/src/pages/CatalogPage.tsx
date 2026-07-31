/**
 * Source catalog: upload a manifest or import from OpenAPI / SQL DDL.
 *
 * The server never connects to a data source to discover this. Holding read-only
 * source credentials would give the policy server a data-source secret store,
 * which is exactly what the SDKs avoid by never taking a connection.
 */

import { useCallback, useEffect, useState } from "react";
import { api, type SourceManifest } from "../api.ts";
import { MoreResults } from "../components/MoreResults.tsx";

type Mode = "manifest" | "openapi" | "sql";

export function CatalogPage({ readOnly }: { readonly readOnly: boolean }) {
  const [sources, setSources] = useState<SourceManifest[]>([]);
  const [mode, setMode] = useState<Mode>("sql");
  const [sourceId, setSourceId] = useState("");
  const [text, setText] = useState("");
  const [status, setStatus] = useState<string | undefined>();
  const [cursor, setCursor] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [failure, setFailure] = useState<string | undefined>();

  const refresh = useCallback(async () => {
    try {
      const page = await api.listSources();
      setSources(page.sources);
      setCursor(page.nextCursor ?? null);
    } catch (caught) {
      setFailure((caught as Error).message);
    }
  }, []);

  /**
   * Append the next page.
   *
   * The server bounds this listing, so without following the cursor the page shows the
   * first N sources and looks exactly like a page showing all of them -- and an item
   * missing from a truncated list reads as an item that does not exist. Failure keeps the
   * cursor, so a partial load reports itself rather than looking like the end.
   */
  const loadMore = useCallback(async () => {
    if (cursor === null) return;
    setLoadingMore(true);
    try {
      const page = await api.listSources({ cursor });
      setSources((current) => [...current, ...page.sources]);
      setCursor(page.nextCursor ?? null);
    } catch (caught) {
      setFailure((caught as Error).message);
    } finally {
      setLoadingMore(false);
    }
  }, [cursor]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const submit = async () => {
    setStatus(undefined);
    setFailure(undefined);
    try {
      let saved: SourceManifest;
      if (mode === "manifest") {
        saved = await api.putSource(JSON.parse(text));
      } else if (mode === "openapi") {
        saved = await api.importOpenApi(sourceId, JSON.parse(text));
      } else {
        saved = await api.importSql(sourceId, text);
      }
      const fields = saved.objects.reduce(
        (total, object) => total + object.fields.length,
        0,
      );
      setStatus(
        `Saved ${saved.sourceConnectionId}: ${saved.objects.length} object(s), ` +
          `${fields} field(s), ${saved.endpoints.length} endpoint(s).`,
      );
      setText("");
      await refresh();
    } catch (caught) {
      // A JSON.parse failure is the author's typo, not a server error, and saying
      // so saves them checking the server logs.
      setFailure(
        caught instanceof SyntaxError
          ? `That is not valid JSON: ${caught.message}`
          : (caught as Error).message,
      );
    }
  };

  return (
    <section className="page page--single">
      <h2>Sources</h2>
      <p className="hint">
        A source's structure, used to offer real object and field names when
        authoring. Never consulted when a policy is enforced — a typo'd field name
        in a policy is invisible to TOLAP, which is what this prevents.
      </p>

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

      {sources.length === 0 ? (
        <p className="muted">Nothing in the catalog yet.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Source</th>
              <th>Category</th>
              <th>Objects</th>
              <th>Fields</th>
              <th>Endpoints</th>
              {!readOnly ? <th /> : null}
            </tr>
          </thead>
          <tbody>
            {sources.map((source) => (
              <tr key={source.sourceConnectionId}>
                <td>
                  <code>{source.sourceConnectionId}</code>
                </td>
                <td>{source.category}</td>
                <td>{source.objects.length}</td>
                <td>
                  {source.objects.reduce((n, object) => n + object.fields.length, 0)}
                </td>
                <td>{source.endpoints.length}</td>
                {!readOnly ? (
                  <td>
                    <button
                      type="button"
                      onClick={() =>
                        void api
                          .deleteSource(source.sourceConnectionId)
                          .then(refresh)
                          .catch((caught: Error) => setFailure(caught.message))
                      }
                    >
                      Remove
                    </button>
                  </td>
                ) : null}
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {sources.length > 0 ? (
        <MoreResults
          loaded={sources.length}
          nextCursor={cursor}
          noun="sources"
          loading={loadingMore}
          onLoadMore={() => void loadMore()}
        />
      ) : null}

      {!readOnly ? (
        <form
          onSubmit={(event) => {
            event.preventDefault();
            void submit();
          }}
        >
          <h3>Add or update a source</h3>

          <div className="radio-row">
            {(
              [
                ["sql", "SQL DDL"],
                ["openapi", "OpenAPI"],
                ["manifest", "Manifest JSON"],
              ] as Array<[Mode, string]>
            ).map(([value, label]) => (
              <label key={value}>
                <input
                  type="radio"
                  name="import-mode"
                  checked={mode === value}
                  onChange={() => setMode(value)}
                />
                {label}
              </label>
            ))}
          </div>

          {mode !== "manifest" ? (
            <>
              <label htmlFor="catalog-id">Source connection ID</label>
              <input
                id="catalog-id"
                value={sourceId}
                onChange={(event) => setSourceId(event.target.value)}
                placeholder={
                  mode === "sql" ? "db:analytics:patients" : "api:internal:clinical"
                }
                required
              />
            </>
          ) : null}

          <label htmlFor="catalog-text">
            {mode === "sql"
              ? "CREATE TABLE statements, or an information_schema.columns dump"
              : mode === "openapi"
                ? "OpenAPI document (JSON)"
                : "Manifest (JSON)"}
          </label>
          <textarea
            id="catalog-text"
            value={text}
            onChange={(event) => setText(event.target.value)}
            rows={12}
            spellCheck={false}
            required
          />

          <button type="submit" disabled={text.trim() === ""}>
            Import
          </button>
        </form>
      ) : null}
    </section>
  );
}
