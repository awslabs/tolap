// vitest/config rather than vite: it is the same defineConfig widened to accept
// the `test` block below, which vite's own types reject.
import { defineConfig, type Plugin } from "vitest/config";
import react from "@vitejs/plugin-react";

/**
 * Build the Content-Security-Policy from the configured Cognito domain.
 *
 * The policy has to name that origin explicitly: the PKCE token exchange is a
 * cross-origin `fetch` to `<domain>/oauth2/token`, and a bare `connect-src 'self'`
 * blocks it — which is exactly what happened, with sign-in failing at the final step
 * and reporting a CSP violation rather than an auth error.
 *
 * Generated rather than hardcoded so the allowed origin is *only* the pool this build
 * targets. Widening to `https:` or `*.amazoncognito.com` would let the page talk to any
 * Cognito pool, and this page holds a token that can author policy.
 *
 * `frame-ancestors` is deliberately absent here. It is **ignored** when delivered in a
 * `<meta>` element (the browser says so), so leaving it in was misleading: it looked
 * like clickjacking protection and provided none. The real control is the
 * `X-Frame-Options: DENY` header CloudFront sets, which is enforced — see
 * `infra/lib/edge-stack.ts`.
 */
function cspPlugin(cognitoDomain: string | undefined): Plugin {
  const connectSrc = ["'self'"];
  if (cognitoDomain) {
    try {
      // Origin only: a path in a CSP source is ignored, and passing one through would
      // read as tighter than it is.
      connectSrc.push(new URL(cognitoDomain).origin);
    } catch {
      throw new Error(
        `VITE_COGNITO_DOMAIN is not a valid URL: ${JSON.stringify(cognitoDomain)}`,
      );
    }
  }

  const policy = [
    "default-src 'self'",
    `connect-src ${connectSrc.join(" ")}`,
    "img-src 'self' data:",
    // Vite injects the stylesheet inline in dev and as a file in production; the
    // inline allowance covers the former. No external style origins.
    "style-src 'self' 'unsafe-inline'",
    // No third-party scripts at all. A script origin here could read the token.
    "script-src 'self'",
    // The console never embeds anything, and nothing embeds it.
    "frame-src 'none'",
    "object-src 'none'",
    "base-uri 'self'",
    // The sign-in redirect is a top-level navigation to the Cognito hosted UI, so it
    // must be permitted; nothing else may be navigated to.
    `form-action 'self'${cognitoDomain ? ` ${new URL(cognitoDomain).origin}` : ""}`,
  ].join("; ");

  return {
    name: "tolap-csp",
    transformIndexHtml() {
      return [
        {
          tag: "meta",
          attrs: { "http-equiv": "Content-Security-Policy", content: policy },
          injectTo: "head-prepend",
        },
      ];
    },
  };
}

export default defineConfig(({ mode }) => {
  // Read from process.env rather than loadEnv so the same value the app receives is
  // the one the policy is built from.
  const cognitoDomain = process.env.VITE_COGNITO_DOMAIN;
  void mode;

  return {
    plugins: [react(), cspPlugin(cognitoDomain)],
    server: {
      port: 5173,
      // The admin API runs on its own listener. Proxying in dev keeps the console's
      // fetch calls same-origin so no CORS configuration is needed here or there --
      // in production the console and API share one CloudFront distribution.
      proxy: {
        "/v1": {
          target: "http://127.0.0.1:8080",
          changeOrigin: true,
        },
      },
    },
    test: {
      environment: "jsdom",
      globals: true,
      include: ["src/**/*.test.tsx", "src/**/*.test.ts"],
      coverage: {
        provider: "v8",
        include: ["src/**"],
        reporter: ["text", "lcov"],
      },
    },
  };
});
