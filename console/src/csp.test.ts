/**
 * The Content-Security-Policy shipped in the built page.
 *
 * Two real failures motivate this. Sign-in broke at the final step with:
 *
 *   "Connecting to '.../oauth2/token' violates the following Content Security Policy
 *    directive: connect-src 'self'. The action has been blocked."
 *
 * — because the policy was hardcoded with `connect-src 'self'` while the PKCE token
 * exchange is a cross-origin fetch to the Cognito domain. And:
 *
 *   "The CSP directive 'frame-ancestors' is ignored when delivered via a <meta>
 *    element."
 *
 * — so the clickjacking protection the policy appeared to provide did not exist. That
 * directive now comes from CloudFront as a response header instead.
 *
 * The policy is generated at build time from VITE_COGNITO_DOMAIN, so it is asserted by
 * building the page rather than by reading a literal.
 */

import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const DOMAIN = "https://pool-under-test.auth.us-east-1.amazoncognito.com";

/** Build the console and return the CSP from the emitted index.html. */
function builtPolicy(env: Record<string, string> = {}): string {
  const outDir = mkdtempSync(path.join(tmpdir(), "tolap-csp-"));
  try {
    execFileSync("npx", ["vite", "build", "--outDir", outDir, "--emptyOutDir"], {
      cwd: path.resolve(import.meta.dirname, ".."),
      env: {
        ...process.env,
        VITE_COGNITO_DOMAIN: DOMAIN,
        VITE_COGNITO_CLIENT_ID: "client-under-test",
        ...env,
      },
      stdio: "pipe",
    });

    const html = readFileSync(path.join(outDir, "index.html"), "utf8");
    const match = /http-equiv="Content-Security-Policy" content="([^"]*)"/.exec(html);
    if (!match) throw new Error(`no CSP meta tag in the built page:\n${html}`);
    // Browsers decode HTML entities when parsing an attribute value.
    return match[1]!.replace(/&#39;/g, "'").replace(/&amp;/g, "&");
  } finally {
    rmSync(outDir, { recursive: true, force: true });
  }
}

/**
 * The index.html a real `vite dev` server serves.
 *
 * Run in a child process: importing vite here would pull esbuild into the jsdom
 * environment, which fails its own `TextEncoder` invariant check.
 */
function devServedHtml(): string {
  const script = `
    const { createServer } = await import("vite");
    const server = await createServer({ configFile: ${JSON.stringify(
      path.resolve(import.meta.dirname, "../vite.config.ts"),
    )}, server: { port: 0, middlewareMode: false }, logLevel: "silent" });
    const { readFileSync } = await import("node:fs");
    const raw = readFileSync(${JSON.stringify(
      path.resolve(import.meta.dirname, "../index.html"),
    )}, "utf8");
    process.stdout.write(await server.transformIndexHtml("/index.html", raw));
    await server.close();
  `;
  return execFileSync("node", ["--input-type=module", "-e", script], {
    cwd: path.resolve(import.meta.dirname, ".."),
    env: { ...process.env, VITE_COGNITO_DOMAIN: DOMAIN },
    encoding: "utf8",
    stdio: ["pipe", "pipe", "pipe"],
  });
}

describe("generated Content-Security-Policy", () => {
  const policy = builtPolicy();

  it("allows the Cognito origin in connect-src", () => {
    // The regression. Without this the PKCE token exchange is blocked and sign-in
    // fails at the last step with a CSP violation rather than an auth error.
    expect(policy).toContain(`connect-src 'self' ${DOMAIN}`);
  });

  it("does not carry frame-ancestors, which a meta tag cannot enforce", () => {
    // Browsers ignore it here and say so in the console. It is set as a real response
    // header by CloudFront instead -- see infra/lib/edge-stack.ts.
    expect(policy).not.toContain("frame-ancestors");
  });

  it("allows the Cognito origin in form-action for the hosted-UI redirect", () => {
    // beginLogin performs a top-level navigation to the hosted UI.
    expect(policy).toContain(`form-action 'self' ${DOMAIN}`);
  });

  it("still refuses third-party scripts and objects", () => {
    // The page holds a token that can author policy governing regulated data, so a
    // foreign script origin would be able to read it.
    expect(policy).toContain("script-src 'self'");
    expect(policy).toContain("object-src 'none'");
    expect(policy).toContain("default-src 'self'");
    expect(policy).toContain("base-uri 'self'");
  });

  it("scopes connect-src to the one configured pool, not all of Cognito", () => {
    // A wildcard would let the page talk to any Cognito pool.
    expect(policy).not.toMatch(/connect-src[^;]*\*/);
    expect(policy).not.toMatch(/connect-src[^;]*amazoncognito\.com(?!\/)\s*;?\s*$/);
    // Origin only: a path in a CSP source is ignored and would read as tighter than
    // it is.
    expect(policy).not.toContain("/oauth2/token");
  });

  it("falls back to self-only when no pool is configured", () => {
    // A build without Cognito must not widen the policy to something permissive.
    const unconfigured = builtPolicy({ VITE_COGNITO_DOMAIN: "" });
    expect(unconfigured).toContain("connect-src 'self'");
    expect(unconfigured).not.toContain("amazoncognito.com");
  });

  it("is not injected during dev, where it blocks React from mounting", () => {
    // The regression this guards, found in a browser: `script-src 'self'` forbids inline
    // script and the React plugin's HMR preamble *is* inline, so with the meta injected
    // in dev the browser blocked it, React never mounted, and every page rendered blank
    // with only "@vitejs/plugin-react can't detect preamble" in the console.
    //
    // Asserted by asking a real dev server for the page it would serve, rather than by
    // inspecting config: what matters is the HTML the browser receives.
    const html = devServedHtml();

    // The meta tag specifically -- index.html also *mentions* the header in a comment.
    expect(html).not.toMatch(/http-equiv="Content-Security-Policy"/);

    // And the thing the policy was breaking is present, so this test would still fail if
    // the preamble stopped being inline and the assertion above became vacuous.
    expect(html).toContain("injectIntoGlobalHook");
  });
});
