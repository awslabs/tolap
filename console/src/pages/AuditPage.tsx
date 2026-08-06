/**
 * The audit log.
 *
 * Answers two questions a compliance reviewer actually asks: who changed this
 * policy, and which remote install pulled it. Readable by an auditor, since reading
 * it is the auditor's job.
 */

import { useCallback, useEffect, useState } from "react";
import { api, type AuditEntry } from "../api.ts";

export function AuditPage() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [filter, setFilter] = useState("");
  const [failure, setFailure] = useState<string | undefined>();

  const refresh = useCallback(async () => {
    try {
      setEntries((await api.listAudit(500)).entries);
      setFailure(undefined);
    } catch (caught) {
      setFailure((caught as Error).message);
    }
  }, []);

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
    </section>
  );
}
