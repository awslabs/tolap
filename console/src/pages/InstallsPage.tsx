/**
 * Registered remote installs.
 *
 * A credential is shown exactly once, at registration: the server stores only its
 * hash. That is stated loudly in the UI, because an admin who closes the dialog
 * assuming they can find it later has to re-register the install instead.
 */

import { useCallback, useEffect, useState } from "react";
import { api, type Install } from "../api.ts";

export function InstallsPage({ readOnly }: { readonly readOnly: boolean }) {
  const [installs, setInstalls] = useState<Install[]>([]);
  const [id, setId] = useState("");
  const [name, setName] = useState("");
  const [issued, setIssued] = useState<{ id: string; credential: string } | undefined>();
  const [failure, setFailure] = useState<string | undefined>();

  const refresh = useCallback(async () => {
    try {
      setInstalls((await api.listInstalls()).installs);
    } catch (caught) {
      setFailure((caught as Error).message);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const register = async () => {
    setFailure(undefined);
    try {
      const created = await api.createInstall(id, name);
      setIssued({ id: created.id, credential: created.credential });
      setId("");
      setName("");
      await refresh();
    } catch (caught) {
      setFailure((caught as Error).message);
    }
  };

  return (
    <section className="page page--single">
      <h2>Installs</h2>
      <p className="hint">
        Each remote TOLAP install holds its own credential, so the audit log records
        which one resolved a policy and any single install can be revoked without
        disturbing the others.
      </p>

      {failure ? (
        <p className="banner banner--error" role="alert">
          {failure}
        </p>
      ) : null}

      {issued ? (
        <div className="banner banner--warning" role="alert">
          <p>
            <strong>Credential for {issued.id} — shown once.</strong> Only its hash
            is stored, so this cannot be recovered. Copy it now; if it is lost,
            revoke this install and register a new one.
          </p>
          <pre className="credential">{issued.credential}</pre>
          <button type="button" onClick={() => setIssued(undefined)}>
            I have stored it
          </button>
        </div>
      ) : null}

      {installs.length === 0 ? (
        <p className="muted">No installs registered.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Name</th>
              <th>Registered</th>
              <th>Last resolve</th>
              <th>State</th>
              {!readOnly ? <th /> : null}
            </tr>
          </thead>
          <tbody>
            {installs.map((install) => (
              <tr key={install.id}>
                <td>
                  <code>{install.id}</code>
                </td>
                <td>{install.name}</td>
                <td>{new Date(install.createdAt).toLocaleString()}</td>
                <td>
                  {install.lastSeenAt
                    ? new Date(install.lastSeenAt).toLocaleString()
                    : "never"}
                </td>
                <td>
                  {install.revokedAt ? (
                    <span className="badge badge--deny">revoked</span>
                  ) : (
                    <span className="badge badge--ok">active</span>
                  )}
                </td>
                {!readOnly ? (
                  <td>
                    {install.revokedAt ? null : (
                      <button
                        type="button"
                        onClick={() =>
                          void api
                            .revokeInstall(install.id)
                            .then(refresh)
                            .catch((caught: Error) => setFailure(caught.message))
                        }
                      >
                        Revoke
                      </button>
                    )}
                  </td>
                ) : null}
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {!readOnly ? (
        <form
          className="inline-form"
          onSubmit={(event) => {
            event.preventDefault();
            void register();
          }}
        >
          <h3>Register an install</h3>
          <label htmlFor="install-id">ID</label>
          <input
            id="install-id"
            value={id}
            onChange={(event) => setId(event.target.value)}
            pattern="[a-z0-9][a-z0-9-]{0,62}[a-z0-9]"
            title="Lowercase letters, digits and hyphens, 2-64 characters"
            placeholder="worker-us-east-1"
            required
          />
          <label htmlFor="install-name">Name</label>
          <input
            id="install-name"
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder="Analytics worker"
            required
          />
          <button type="submit">Register</button>
        </form>
      ) : null}
    </section>
  );
}
