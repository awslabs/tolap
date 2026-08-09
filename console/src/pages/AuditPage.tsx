/**
 * The audit log.
 *
 * Answers two questions a compliance reviewer actually asks: who changed this
 * policy, and which remote install pulled it. Readable by an auditor, since reading
 * it is the auditor's job.
 */

import { useCallback, useEffect, useState } from "react";
import { api, type AuditEntry } from "../api.ts";
import { MoreResults } from "../components/MoreResults.tsx";

/**
 * Rows per request.
 *
 * The server's ceiling is 500 and this asks for it, because the alternative -- more
 * round trips -- costs an auditor more than one large response costs the server.
 */
const PAGE = 500;

export function AuditPage() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState("");
  const [failure, setFailure] = useState<string | undefined>();

  const refresh = useCallback(async () => {
    try {
      const page = await api.listAudit(PAGE);
      setEntries(page.entries);
      setCursor(page.nextCursor ?? null);
      setFailure(undefined);
    } catch (caught) {
      setFailure((caught as Error).message);
    }
  }, []);

  /**
   * Append the next page.
   *
   * Appends rather than replaces, so following the log backwards accumulates instead of
   * making the reader hold two screens in their head. The cursor is read from state at
   * call time and cleared on failure, so a partial load reports itself rather than
   * looking like the end of the log -- which is the same mistake this control exists to
   * prevent, one level down.
   */
  const loadMore = useCallback(async () => {
    if (cursor === null) return;
    setLoading(true);
    try {
      const page = await api.listAudit(PAGE, cursor);
      setEntries((current) => [...current, ...page.entries]);
      setCursor(page.nextCursor ?? null);
      setFailure(undefined);
    } catch (caught) {
      setFailure((caught as Error).message);
    } finally {
      setLoading(false);
    }
  }, [cursor]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const needle = filter.trim().toLowerCase();
  const shown =
    needle === ""
      ? entries
      : entries.filter((entry) =>
          [entry.actor, entry.action, entry.targetId ?? ""]
            .join(" ")
            .toLowerCase()
            .includes(needle),
        );

  return (
    <section className="page page--single">
      <div className="page__list-header">
        <h2>Audit</h2>
        <button type="button" onClick={() => void refresh()}>
          Refresh
        </button>
      </div>

      {failure ? (
        <p className="banner banner--error" role="alert">
          {failure}
        </p>
      ) : null}

      <label htmlFor="audit-filter">Filter</label>
      <input
        id="audit-filter"
        value={filter}
        onChange={(event) => setFilter(event.target.value)}
        placeholder="actor, action, or target"
      />

      {shown.length === 0 ? (
        <p className="muted">
          {entries.length === 0 ? "Nothing recorded yet." : "No matching entries."}
        </p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>When</th>
              <th>Actor</th>
              <th>Action</th>
              <th>Target</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((entry, index) => (
              <tr key={`${entry.at}-${index}`}>
                <td>{new Date(entry.at).toLocaleString()}</td>
                <td>
                  <span className={`badge badge--${entry.actorKind}`}>
                    {entry.actorKind}
                  </span>{" "}
                  <code>{entry.actor}</code>
                </td>
                <td>
                  <code>{entry.action}</code>
                </td>
                <td>{entry.targetId ? <code>{entry.targetId}</code> : ""}</td>
                <td>
                  {entry.detail ? (
                    <code className="detail">{JSON.stringify(entry.detail)}</code>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {entries.length > 0 ? (
        <MoreResults
          loaded={entries.length}
          nextCursor={cursor}
          noun="entries"
          loading={loading}
          onLoadMore={() => void loadMore()}
          // The filter below runs over the loaded rows only, so on a truncated log a
          // "no matching entries" result is an answer about a slice, not the log.
          filtered={needle !== ""}
        />
      ) : null}
    </section>
  );
}
