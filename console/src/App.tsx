/**
 * The console shell.
 *
 * Tabs rather than a router: this is a single-screen admin tool, and a router
 * would be a dependency (and, at the time of writing, a high-severity CSRF
 * advisory in react-router's RSC mode) bought for nothing.
 *
 * Role awareness runs through everything. An auditor sees every read view and no
 * write control. That is a **convenience**, not the control -- the server enforces
 * it and returns 403 regardless of what this renders. Hiding a button an auditor
 * cannot use is better UX than letting them press it and read an error.
 */

import { useCallback, useEffect, useState } from "react";
import { api, ApiError, hasToken, setUnauthenticatedHandler, type Me } from "./api.ts";
import { PoliciesPage } from "./pages/PoliciesPage.tsx";
import { AssignmentsPage } from "./pages/AssignmentsPage.tsx";
import { CatalogPage } from "./pages/CatalogPage.tsx";
import { InstallsPage } from "./pages/InstallsPage.tsx";
import { AuditPage } from "./pages/AuditPage.tsx";
import { PreviewPage } from "./pages/PreviewPage.tsx";
import { SignIn } from "./SignIn.tsx";

type Tab = "policies" | "assignments" | "preview" | "catalog" | "installs" | "audit";

const TABS: Array<{ id: Tab; label: string }> = [
  { id: "policies", label: "Policies" },
  { id: "assignments", label: "Assignments" },
  { id: "preview", label: "Resolve preview" },
  { id: "catalog", label: "Sources" },
  { id: "installs", label: "Installs" },
  { id: "audit", label: "Audit" },
];

export function App() {
  const [me, setMe] = useState<Me | undefined>();
  const [tab, setTab] = useState<Tab>("policies");
  const [signedIn, setSignedIn] = useState(hasToken());
  const [error, setError] = useState<string | undefined>();
  /**
   * Whether a session has ended, as opposed to never having started.
   *
   * Without this the sign-in page told a first-time visitor "Your session ended",
   * because it inferred that from `signedIn` being false -- which is also the initial
   * state. Alarming and wrong.
   */
  const [sessionEnded, setSessionEnded] = useState(false);

  const loadMe = useCallback(async () => {
    try {
      setMe(await api.me());
      setError(undefined);
    } catch (caught) {
      if (caught instanceof ApiError && caught.isUnauthenticated) {
        setSignedIn(false);
        setMe(undefined);
        setSessionEnded(true);
        return;
      }
      setError((caught as Error).message);
    }
  }, []);

  // Stable identity. Passed to SignIn, where it is a dependency of the code-exchange
  // effect -- an inline arrow would be a new function every render and would restart
  // an exchange of a single-use authorization code.
  const handleSignedIn = useCallback(() => {
    setSignedIn(true);
    setSessionEnded(false);
  }, []);

  useEffect(() => {
    // The server rejecting the token is the authority on session state, not a
    // local timer: a token can be revoked in Cognito before it expires.
    setUnauthenticatedHandler(() => {
      setSignedIn(false);
      setMe(undefined);
      setSessionEnded(true);
    });
  }, []);

  useEffect(() => {
    if (signedIn) void loadMe();
  }, [signedIn, loadMe]);

  if (!signedIn || !me) {
    return (
      <SignIn
        onSignedIn={handleSignedIn}
        message={
          error ??
          (sessionEnded
            ? "Your session ended. Sign in again to continue."
            : undefined)
        }
      />
    );
  }

  const readOnly = me.role !== "admin";

  return (
    <div className="app">
      <header className="app__header">
        <h1>TOLAP Policy Console</h1>
        <div className="app__identity">
          <span>{me.email ?? me.subject}</span>
          <span className={`badge badge--${me.role}`}>{me.role}</span>
        </div>
      </header>

      {readOnly ? (
        <p className="banner banner--info" role="status">
          You have <strong>auditor</strong> access: policies, previews and the audit
          log are readable, and nothing here can be changed.
        </p>
      ) : null}

      <nav className="app__tabs" aria-label="Sections">
        {TABS.map(({ id, label }) => (
          <button
            key={id}
            type="button"
            className={tab === id ? "tab tab--active" : "tab"}
            aria-current={tab === id ? "page" : undefined}
            onClick={() => setTab(id)}
          >
            {label}
          </button>
        ))}
      </nav>

      <main className="app__main">
        {tab === "policies" ? <PoliciesPage readOnly={readOnly} /> : null}
        {tab === "assignments" ? <AssignmentsPage readOnly={readOnly} /> : null}
        {tab === "preview" ? <PreviewPage /> : null}
        {tab === "catalog" ? <CatalogPage readOnly={readOnly} /> : null}
        {tab === "installs" ? <InstallsPage readOnly={readOnly} /> : null}
        {tab === "audit" ? <AuditPage /> : null}
      </main>
    </div>
  );
}
