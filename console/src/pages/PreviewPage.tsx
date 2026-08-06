/**
 * Resolve preview.
 *
 * The answer to the one thing TOLAP explicitly does not guarantee: that a policy
 * says what its author meant. Merge is most-restrictive-wins and the directions
 * differ per field -- an allow-list intersects while a hidden list unions -- so
 * reading three policies and predicting the result is genuinely hard. Asking the
 * server is not.
 *
 * The response is unsigned by design. Signing here would mint a usable credential
 * from a route an auditor can reach.
 */

import { useState } from "react";
import { api, type ResolvePreview } from "../api.ts";

export function PreviewPage() {
  const [userId, setUserId] = useState("");
  const [tenantId, setTenantId] = useState("");
  const [source, setSource] = useState("");
  const [result, setResult] = useState<ResolvePreview | undefined>();
  const [failure, setFailure] = useState<string | undefined>();

  const run = async () => {
    setFailure(undefined);
    setResult(undefined);
    try {
      setResult(await api.preview(userId, tenantId, source));
    } catch (caught) {
      setFailure((caught as Error).message);
    }
  };

  const policy = result?.effectivePolicy as
    | {
        permissions?: { canQuery?: boolean; readOnly?: boolean };
        objectRules?: Record<string, unknown>;
        limits?: Record<string, unknown>;
      }
    | undefined;

  return (
    <section className="page page--single">
      <h2>Resolve preview</h2>
      <p className="hint">
        Shows the effective policy a user would receive, merged from every
        assignment that reaches them. Nothing is signed and nothing is changed.
      </p>

      <form
        className="inline-form"
        onSubmit={(event) => {
          event.preventDefault();
          void run();
        }}
      >
        <label htmlFor="preview-user">User ID</label>
        <input
          id="preview-user"
          value={userId}
          onChange={(event) => setUserId(event.target.value)}
          required
        />

        <label htmlFor="preview-tenant">Tenant ID</label>
        <input
          id="preview-tenant"
          value={tenantId}
          onChange={(event) => setTenantId(event.target.value)}
          required
        />

        <label htmlFor="preview-source">Source connection ID</label>
        <input
          id="preview-source"
          value={source}
          onChange={(event) => setSource(event.target.value)}
          placeholder="db:analytics:patients"
          required
        />

        <button type="submit">Preview</button>
      </form>

      {failure ? (
        <p className="banner banner--error" role="alert">
          {failure}
        </p>
      ) : null}

      {result ? (
        <div className="preview">
          <h3>Effective policy</h3>

          {policy?.permissions?.canQuery ? (
            <p className="banner banner--success" role="status">
              This user <strong>can read</strong> this source.
            </p>
          ) : (
            <p className="banner banner--info" role="status">
              This user <strong>cannot read</strong> this source. Either nothing is
              assigned, or a policy denies it.
            </p>
          )}

          <h4>Contributing policies</h4>
          {result.contributingPolicies.length === 0 ? (
            <p className="muted">
              None. An empty merge is a deny-all policy, not a missing one.
            </p>
          ) : (
            <ul>
              {result.contributingPolicies.map((name) => (
                <li key={name}>
                  <code>{name}</code>
                </li>
              ))}
            </ul>
          )}

          <h4>Merged result</h4>
          {/*
            The raw document, because every field matters and summarizing it here
            would be a second implementation of the merge rules that could disagree
            with the real one.
          */}
          <pre>{JSON.stringify(result.effectivePolicy, null, 2)}</pre>
        </div>
      ) : null}
    </section>
  );
}
