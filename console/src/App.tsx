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

  const loadMe = useCallback(async () => {
    try {
      setMe(await api.me());
      setError(undefined);
    } catch (caught) {
      if (caught instanceof ApiError && caught.isUnauthenticated) {
        setSignedIn(false);
        setMe(undefined);
        return;
      }
      setError((caught as Error).message);
    }
  }, []);

  useEffect(() => {
    // The server rejecting the token is the authority on session state, not a
    // local timer: a token can be revoked in Cognito before it expires.
    setUnauthenticatedHandler(() => {
      setSignedIn(false);
      setMe(undefined);
    });
  }, []);

  useEffect(() => {
    if (signedIn) void loadMe();
  }, [signedIn, loadMe]);

  if (!signedIn || !me) {
    return (
      <SignIn
        onSignedIn={() => setSignedIn(true)}
        message={
          error ??
          (signedIn ? undefined : "Your session ended. Sign in again to continue.")
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
