/**
 * Sign-in.
 *
 * The console authenticates against a Cognito user pool with the authorization-code
 * + PKCE flow. That flow is not optional here: the implicit flow returns tokens in
 * the URL fragment, where they land in browser history, referrer headers, and any
 * logging proxy in between -- and this token authorizes editing the policy that
 * governs regulated data.
 *
 * PKCE means the console holds no client secret, which is correct for a browser
 * app: a secret shipped to a browser is not a secret.
 *
 * A paste-a-token box is offered as well, because an operator bringing up a fresh
 * deployment needs to reach the API before the redirect URIs are configured, and
 * because the whole console is testable without a pool.
 */

import { useEffect, useMemo, useRef, useState } from "react";
import { setToken } from "./api.ts";

/** Cognito settings, injected at build time. */
interface OidcConfig {
  readonly domain: string;
  readonly clientId: string;
  readonly redirectUri: string;
}

function oidcConfig(): OidcConfig | undefined {
  const env = import.meta.env;
  const domain = env.VITE_COGNITO_DOMAIN as string | undefined;
  const clientId = env.VITE_COGNITO_CLIENT_ID as string | undefined;
  if (!domain || !clientId) return undefined;
  return {
    domain: domain.replace(/\/$/, ""),
    clientId,
    redirectUri:
      (env.VITE_REDIRECT_URI as string | undefined) ??
      `${window.location.origin}/`,
  };
}

const VERIFIER_KEY = "tolap.pkce.verifier";

function base64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function beginLogin(config: OidcConfig): Promise<void> {
  const verifier = base64Url(crypto.getRandomValues(new Uint8Array(32)));
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier),
  );
  const challenge = base64Url(new Uint8Array(digest));

  // sessionStorage, not localStorage: the verifier is single-use and scoped to
  // this tab's login attempt, and it must not outlive the tab.
  sessionStorage.setItem(VERIFIER_KEY, verifier);

  const url = new URL(`${config.domain}/oauth2/authorize`);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", config.clientId);
  url.searchParams.set("redirect_uri", config.redirectUri);
  url.searchParams.set("scope", "openid email profile");
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("code_challenge", challenge);
  window.location.assign(url.toString());
}

async function completeLogin(
  config: OidcConfig,
  code: string,
): Promise<string> {
  const verifier = sessionStorage.getItem(VERIFIER_KEY);
  if (!verifier) {
    throw new Error(
      "No PKCE verifier for this login. Start the sign-in again from this tab.",
    );
  }
  sessionStorage.removeItem(VERIFIER_KEY);

  const response = await fetch(`${config.domain}/oauth2/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      code,
      code_verifier: verifier,
    }),
  });

  if (!response.ok) {
    throw new Error(`Token exchange failed (${response.status}).`);
  }

  const payload = (await response.json()) as {
    id_token?: string;
    access_token?: string;
  };
  // Prefer the id token: it carries `email` and `cognito:groups`, which is what
  // the server maps to a role.
  const token = payload.id_token ?? payload.access_token;
  if (!token) throw new Error("Token response contained no usable token.");
  return token;
}

export interface SignInProps {
  readonly onSignedIn: () => void;
  readonly message?: string;
}

export function SignIn({ onSignedIn, message }: SignInProps) {
  // Memoized because it is a dependency of the exchange effect below. Calling
  // oidcConfig() in the render body returns a NEW object every render, which made the
  // effect re-run on every state change -- and the second run found the verifier
  // already consumed. The values come from build-time env, so there is nothing to
  // recompute.
  const config = useMemo(oidcConfig, []);
  const [manual, setManual] = useState("");
  const [error, setError] = useState<string | undefined>();
  const [exchanging, setExchanging] = useState(false);
  /**
   * Whether the code exchange has been started.
   *
   * A ref, not state: it must be set synchronously, before any await, so a second
   * effect invocation sees it. State would not update until the next render, which is
   * exactly the window that caused the bug.
   *
   * An OAuth authorization code is **single-use**. Exchanging it twice fails at
   * Cognito, and the local verifier is consumed on the first attempt -- so the second
   * attempt reported "No PKCE verifier" and the user was told to start over, from a
   * page that had in fact just signed them in successfully.
   */
  const exchangeStarted = useRef(false);

  useEffect(() => {
    if (!config) return;
    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");
    if (!code) return;

    // Guard before anything async. React 19's StrictMode double-invokes effects in
    // development, and each setState below re-renders -- either would otherwise start
    // a second exchange of a code that can only be used once.
    if (exchangeStarted.current) return;
    exchangeStarted.current = true;

    setExchanging(true);
    void completeLogin(config, code)
      .then((token) => {
        setToken(token);
        // Strip the code from the URL so a refresh cannot replay it and the
        // authorization code never sits in history.
        window.history.replaceState({}, "", window.location.pathname);
        onSignedIn();
      })
      .catch((caught: Error) => {
        // Allow a retry: the code is spent, but the user needs to be able to press
        // the button again rather than face a dead page.
        exchangeStarted.current = false;
        setError(caught.message);
      })
      .finally(() => setExchanging(false));
  }, [config, onSignedIn]);

  return (
    <div className="signin">
      <h1>TOLAP Policy Console</h1>

      {message ? (
        <p className="banner banner--info" role="status">
          {message}
        </p>
      ) : null}
      {error ? (
        <p className="banner banner--error" role="alert">
          {error}
        </p>
      ) : null}

      {config ? (
        <button
          type="button"
          className="signin__primary"
          disabled={exchanging}
          onClick={() => {
            void beginLogin(config).catch((caught: Error) =>
              setError(caught.message),
            );
          }}
        >
          {exchanging ? "Signing in…" : "Sign in with Cognito"}
        </button>
      ) : (
        <p className="banner banner--warning" role="note">
          Cognito is not configured for this build. Set{" "}
          <code>VITE_COGNITO_DOMAIN</code> and <code>VITE_COGNITO_CLIENT_ID</code>{" "}
          to enable single sign-on.
        </p>
      )}

      <details className="signin__manual">
        <summary>Use an existing token</summary>
        <p>
          For bringing up a deployment before redirect URIs are configured. Paste
          an id token from the user pool.
        </p>
        <form
          onSubmit={(event) => {
            event.preventDefault();
            const trimmed = manual.trim();
            if (trimmed === "") return;
            setToken(trimmed);
            onSignedIn();
          }}
        >
          <label htmlFor="manual-token">Bearer token</label>
          <textarea
            id="manual-token"
            value={manual}
            onChange={(event) => setManual(event.target.value)}
            rows={4}
            spellCheck={false}
            // A token is a credential; keep it out of form autofill stores.
            autoComplete="off"
          />
          <button type="submit" disabled={manual.trim() === ""}>
            Continue
          </button>
        </form>
      </details>
    </div>
  );
}
