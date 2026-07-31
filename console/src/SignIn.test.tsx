/**
 * Sign-in: the PKCE code exchange.
 *
 * These exist because of a real failure. The console showed, together:
 *
 *   "Your session ended. Sign in again to continue."
 *   "No PKCE verifier for this login. Start the sign-in again from this tab."
 *
 * Both were wrong. The sign-in had *succeeded*; the effect that exchanges the
 * authorization code ran twice, and the second run found the verifier already
 * consumed by the first. Two causes:
 *
 * 1. `oidcConfig()` was called in the render body, so `config` was a new object every
 *    render -- and it was a dependency of the exchange effect. Every `setState` in the
 *    effect therefore re-triggered the effect.
 * 2. `onSignedIn` was an inline arrow in the parent, so it too was a new reference
 *    every render.
 *
 * An OAuth authorization code is single-use, so "run the exchange more than once" is
 * never merely wasteful -- it fails, and it fails with a message that tells the user to
 * start over from a page that already signed them in.
 */

import { StrictMode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { SignIn } from "./SignIn.tsx";
import { hasToken, setToken } from "./api.ts";

const DOMAIN = "https://example.auth.us-east-1.amazoncognito.com";
const CLIENT_ID = "test-client-id";

/** The `state` the component stored when it started the flow. */
const STATE = "the-state";

/**
 * Put `?code=` and `?state=` in the URL, as Cognito does on redirect.
 *
 * Both, because the component now rejects a response whose `state` does not match the one
 * it stored -- a code arriving without it did not come from a flow started in this tab.
 * The default matches what `primeFlow` stores, so a test exercising the happy path does
 * not have to think about it; `state` is overridable for the tests that attack it.
 */
function arriveWithCode(
  code = "auth-code-123",
  state: string | null = STATE,
): void {
  const query = new URLSearchParams({ code });
  if (state !== null) query.set("state", state);
  window.history.replaceState({}, "", `/?${query.toString()}`);
}

/** Store what `beginLogin` would have stored before redirecting. */
function primeFlow(verifier = "the-verifier", state = STATE): void {
  sessionStorage.setItem("tolap.pkce.verifier", verifier);
  sessionStorage.setItem("tolap.pkce.state", state);
}

beforeEach(() => {
  vi.stubEnv("VITE_COGNITO_DOMAIN", DOMAIN);
  vi.stubEnv("VITE_COGNITO_CLIENT_ID", CLIENT_ID);
  vi.stubEnv("VITE_REDIRECT_URI", "http://localhost/");
  sessionStorage.clear();
  setToken(undefined);
  window.history.replaceState({}, "", "/");
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  // `restoreAllMocks` does NOT undo `stubGlobal`, so without this a test that stubs
  // `location` or `fetch` leaks it into every later test in the file. That is how the
  // state-parameter tests below first failed in a full run while passing in isolation:
  // they inherited a stubbed `location` whose `search` no longer matched the URL.
  vi.unstubAllGlobals();
  sessionStorage.clear();
  window.history.replaceState({}, "", "/");
  setToken(undefined);
});

describe("code exchange", () => {
  it("exchanges the code exactly once", async () => {
    // The regression. Before the fix this fired twice: the second call had no verifier
    // and surfaced "No PKCE verifier" over a successful login.
    primeFlow();
    arriveWithCode();

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ id_token: "an-id-token" }),
    });
    vi.stubGlobal("fetch", fetchMock);

    const onSignedIn = vi.fn();
    render(<SignIn onSignedIn={onSignedIn} />);

    await waitFor(() => expect(onSignedIn).toHaveBeenCalled());
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(onSignedIn).toHaveBeenCalledTimes(1);
    expect(hasToken()).toBe(true);
  });

  it("does not report a missing verifier after a successful exchange", async () => {
    // The user-visible symptom, asserted directly: no error banner at all.
    primeFlow();
    arriveWithCode();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ id_token: "an-id-token" }),
      }),
    );

    const onSignedIn = vi.fn();
    render(<SignIn onSignedIn={onSignedIn} />);

    await waitFor(() => expect(onSignedIn).toHaveBeenCalled());
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.queryByText(/No PKCE verifier/i)).toBeNull();
  });

  it("survives a parent that re-renders with a new callback", async () => {
    // The second cause. A parent passing an inline arrow gives SignIn a new
    // `onSignedIn` every render; the guard must hold regardless.
    primeFlow();
    arriveWithCode();
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ id_token: "an-id-token" }),
    });
    vi.stubGlobal("fetch", fetchMock);

    const calls: number[] = [];
    const { rerender } = render(
      <SignIn onSignedIn={() => calls.push(1)} />,
    );
    rerender(<SignIn onSignedIn={() => calls.push(2)} />);
    rerender(<SignIn onSignedIn={() => calls.push(3)} />);

    await waitFor(() => expect(calls.length).toBeGreaterThan(0));
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("strips the code from the URL so a refresh cannot replay it", async () => {
    primeFlow();
    arriveWithCode();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ id_token: "an-id-token" }),
      }),
    );

    const onSignedIn = vi.fn();
    render(<SignIn onSignedIn={onSignedIn} />);

    await waitFor(() => expect(onSignedIn).toHaveBeenCalled());
    // An authorization code in history is a credential in history.
    expect(window.location.search).toBe("");
  });

  it("sends the verifier, and prefers the id token", async () => {
    primeFlow();
    arriveWithCode("code-abc");
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      // The id token carries email and cognito:groups, which is what the server maps
      // to a role; an access token would authenticate but resolve no role.
      json: async () => ({ id_token: "id-tok", access_token: "access-tok" }),
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<SignIn onSignedIn={vi.fn()} />);
    await waitFor(() => expect(fetchMock).toHaveBeenCalled());

    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe(`${DOMAIN}/oauth2/token`);
    const body = new URLSearchParams(init.body as string);
    expect(body.get("code")).toBe("code-abc");
    expect(body.get("code_verifier")).toBe("the-verifier");
    expect(body.get("grant_type")).toBe("authorization_code");
    // PKCE means no client secret is sent.
    expect(body.get("client_secret")).toBeNull();
  });

  it("consumes the verifier so it cannot be reused", async () => {
    primeFlow();
    arriveWithCode();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ id_token: "id-tok" }),
      }),
    );

    const onSignedIn = vi.fn();
    render(<SignIn onSignedIn={onSignedIn} />);
    await waitFor(() => expect(onSignedIn).toHaveBeenCalled());

    expect(sessionStorage.getItem("tolap.pkce.verifier")).toBeNull();
  });
});

describe("failure handling", () => {
  it("reports a missing verifier when there genuinely is none", async () => {
    // The message is correct in this case -- arriving with a code in a tab that never
    // started the login. What was wrong before was reaching it after a success.
    arriveWithCode();
    vi.stubGlobal("fetch", vi.fn());

    render(<SignIn onSignedIn={vi.fn()} />);

    await waitFor(() =>
      expect(screen.getByRole("alert").textContent).toMatch(/No PKCE verifier/i),
    );
  });

  it("surfaces a failed token exchange and allows a retry", async () => {
    primeFlow();
    arriveWithCode();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({ ok: false, status: 400 }),
    );

    render(<SignIn onSignedIn={vi.fn()} />);

    await waitFor(() =>
      expect(screen.getByRole("alert").textContent).toMatch(/400/),
    );
    // Not a dead page: the sign-in button must still be usable. `toBeDisabled` needs
    // jest-dom, which this project does not install, so read the property directly.
    const button = screen.getByRole("button", {
      name: /sign in with cognito/i,
    }) as HTMLButtonElement;
    expect(button.disabled).toBe(false);
  });

  it("does nothing when there is no code in the URL", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    render(<SignIn onSignedIn={vi.fn()} />);

    expect(fetchMock).not.toHaveBeenCalled();
    expect(screen.queryByRole("alert")).toBeNull();
  });
});

describe("configuration", () => {
  it("explains itself when Cognito is not configured", () => {
    vi.stubEnv("VITE_COGNITO_DOMAIN", "");
    vi.stubEnv("VITE_COGNITO_CLIENT_ID", "");

    render(<SignIn onSignedIn={vi.fn()} />);

    expect(screen.getByRole("note").textContent).toMatch(/not configured/i);
    expect(
      screen.queryByRole("button", { name: /sign in with cognito/i }),
    ).toBeNull();
  });

  it("starts the authorize redirect with S256 and no secret", async () => {
    const assign = vi.fn();
    vi.stubGlobal("location", { ...window.location, origin: "http://localhost", assign });

    render(<SignIn onSignedIn={vi.fn()} />);
    await userEvent.click(
      screen.getByRole("button", { name: /sign in with cognito/i }),
    );

    await waitFor(() => expect(assign).toHaveBeenCalled());
    const url = new URL(assign.mock.calls[0]![0] as string);
    expect(url.searchParams.get("response_type")).toBe("code");
    // Never `token`: the implicit flow puts a policy-authoring credential in the URL
    // fragment, where it lands in history and referrer headers.
    expect(url.searchParams.get("response_type")).not.toBe("token");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("code_challenge")).toBeTruthy();
    // The verifier is stored for the redirect back, and never sent now.
    expect(sessionStorage.getItem("tolap.pkce.verifier")).toBeTruthy();
    expect(url.searchParams.get("code_verifier")).toBeNull();
  });

  it("accepts a pasted token for bring-up", async () => {
    const onSignedIn = vi.fn();
    render(<SignIn onSignedIn={onSignedIn} />);

    await userEvent.type(screen.getByLabelText(/bearer token/i), "pasted-token");
    await userEvent.click(screen.getByRole("button", { name: /continue/i }));

    expect(hasToken()).toBe(true);
    expect(onSignedIn).toHaveBeenCalled();
  });
});

describe("login CSRF (the state parameter)", () => {
  /*
   * PKCE and `state` answer different questions, which is why PKCE alone was not enough.
   * The verifier proves the code was requested by *a* flow this browser started; `state`
   * proves it was requested by *this* flow.
   *
   * Without it, anyone holding a valid authorization code of their own can feed it to a
   * victim as `?code=...` and sign that browser into the ATTACKER's account. On this
   * console the victim then authors policy under an identity they did not choose, and the
   * audit log records the attacker's subject as the actor -- so the trail points at the
   * wrong person.
   */

  it("sends a state parameter when starting the flow", async () => {
    const assign = vi.fn();
    vi.stubGlobal("location", { ...window.location, origin: "http://localhost", assign });

    render(<SignIn onSignedIn={vi.fn()} />);
    await userEvent.click(screen.getByRole("button", { name: /Sign in with Cognito/i }));
    await waitFor(() => expect(assign).toHaveBeenCalled());

    const target = new URL(assign.mock.calls[0]![0] as string);
    const state = target.searchParams.get("state");
    expect(state, "no state in the authorize URL").toBeTruthy();
    // Must be unguessable: a predictable state is no better than none, since the whole
    // point is that an attacker cannot produce it.
    expect(state!.length).toBeGreaterThanOrEqual(32);
    expect(sessionStorage.getItem("tolap.pkce.state")).toBe(state);
  });

  it("uses a fresh state for each attempt", async () => {
    // A reused state would let one intercepted authorize request be replayed against a
    // later login attempt in the same tab.
    const assign = vi.fn();
    vi.stubGlobal("location", { ...window.location, origin: "http://localhost", assign });

    render(<SignIn onSignedIn={vi.fn()} />);
    const button = screen.getByRole("button", { name: /Sign in with Cognito/i });

    await userEvent.click(button);
    await waitFor(() => expect(assign).toHaveBeenCalledTimes(1));
    await userEvent.click(button);
    await waitFor(() => expect(assign).toHaveBeenCalledTimes(2));

    const first = new URL(assign.mock.calls[0]![0] as string).searchParams.get("state");
    const second = new URL(assign.mock.calls[1]![0] as string).searchParams.get("state");
    expect(second).not.toBe(first);
  });

  it("refuses a code whose state does not match, without exchanging it", async () => {
    const exchange = vi.fn();
    vi.stubGlobal("fetch", exchange);
    primeFlow("the-verifier", "the-real-state");
    arriveWithCode("attacker-code", "a-different-state");

    render(<SignIn onSignedIn={vi.fn()} />);

    await waitFor(() =>
      expect(screen.getByRole("alert").textContent).toMatch(/did not start in this tab/i),
    );
    // The point is not merely to fail: an unsolicited code must never reach the token
    // endpoint at all.
    expect(exchange).not.toHaveBeenCalled();
    expect(hasToken()).toBe(false);
  });

  it("refuses a code that carries no state at all", async () => {
    // The bare force-feed: an attacker links the victim to `/?code=...`. An authorization
    // response with no state did not come from a flow started here.
    const exchange = vi.fn();
    vi.stubGlobal("fetch", exchange);
    primeFlow();
    arriveWithCode("attacker-code", null);

    render(<SignIn onSignedIn={vi.fn()} />);

    await waitFor(() =>
      expect(screen.getByRole("alert").textContent).toMatch(/did not start in this tab/i),
    );
    expect(exchange).not.toHaveBeenCalled();
  });

  it("refuses when nothing was stored, even if the URL carries a state", async () => {
    // The attacker controls the URL, so they can supply a state that matches itself.
    // Nothing was stored here, so there is no flow to match against.
    const exchange = vi.fn();
    vi.stubGlobal("fetch", exchange);
    sessionStorage.setItem("tolap.pkce.verifier", "the-verifier");
    arriveWithCode("attacker-code", "attacker-chosen-state");

    render(<SignIn onSignedIn={vi.fn()} />);

    await waitFor(() => expect(screen.getByRole("alert")).toBeDefined());
    expect(exchange).not.toHaveBeenCalled();
  });

  it("clears both stored values on a rejected attempt", async () => {
    // So a rejected attempt cannot be retried against the same verifier, and so a failure
    // leaves nothing behind for the next flow to pick up.
    vi.stubGlobal("fetch", vi.fn());
    primeFlow("the-verifier", "the-real-state");
    arriveWithCode("attacker-code", "wrong");

    render(<SignIn onSignedIn={vi.fn()} />);

    await waitFor(() => expect(screen.getByRole("alert")).toBeDefined());
    expect(sessionStorage.getItem("tolap.pkce.verifier")).toBeNull();
    expect(sessionStorage.getItem("tolap.pkce.state")).toBeNull();
  });
});

describe("under StrictMode, as the app actually renders", () => {
  /*
   * `main.tsx` wraps the app in StrictMode, which double-invokes effects. That is exactly
   * the condition the double-exchange guard exists for -- and none of the tests above
   * render inside it, so deleting the guard passed all 12 of them. The bug it fixes is
   * one that already shipped once, so it needs a test that would notice its return.
   */

  it("still exchanges the code exactly once", async () => {
    const exchange = vi.fn(async () => ({
      ok: true,
      json: async () => ({ id_token: "the-id-token" }),
    }));
    vi.stubGlobal("fetch", exchange);
    primeFlow();
    arriveWithCode();

    const onSignedIn = vi.fn();
    render(
      <StrictMode>
        <SignIn onSignedIn={onSignedIn} />
      </StrictMode>,
    );

    await waitFor(() => expect(hasToken()).toBe(true));
    // A second exchange of a single-use code fails, and the original symptom was that
    // failure surfacing as "No PKCE verifier" over a login that had already succeeded.
    expect(exchange).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("alert")).toBeNull();
  });
});
