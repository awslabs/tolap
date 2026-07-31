/**
 * A local stand-in for a Cognito user pool, for development only.
 *
 * The server verifies admin tokens against a real user pool's JWKS, which is
 * correct and also means you cannot open the console until a pool exists. That is a
 * bad first ten minutes for someone evaluating this, so this script serves a JWKS
 * document and prints a signed admin and auditor token you can paste into the
 * console's "Use an existing token" box.
 *
 * It is genuinely the same code path as production: the tokens are RS256, signed by
 * a key this script publishes, and the server verifies signature, issuer, audience,
 * `token_use`, expiry and group claims exactly as it would for Cognito. Nothing is
 * stubbed or bypassed on the server side.
 *
 * **Never run this anywhere real.** It mints admin credentials for whoever can
 * reach it, and it prints a private key's worth of authority to stdout. It binds
 * loopback only and refuses to start when NODE_ENV is production.
 *
 *   node --experimental-strip-types tools/dev-idp.ts
 */

import { createServer } from "node:http";
import { createSign, generateKeyPairSync } from "node:crypto";

if (process.env.NODE_ENV === "production") {
  console.error(
    "dev-idp mints admin tokens for anyone who can reach it. Refusing to run with NODE_ENV=production.",
  );
  process.exit(1);
}

const PORT = Number(process.env.DEV_IDP_PORT ?? 8499);
const HOST = "127.0.0.1";
const ISSUER = `http://${HOST}:${PORT}`;
const AUDIENCE = process.env.DEV_IDP_AUDIENCE ?? "dev-client";
const ADMIN_GROUP = process.env.TOLAP_ADMIN_GROUP ?? "tolap-admin";
const AUDITOR_GROUP = process.env.TOLAP_AUDITOR_GROUP ?? "tolap-auditor";
/** Long enough to work through the console without re-minting. */
const TTL_SECONDS = 12 * 3600;

const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
});
const jwk = {
  ...(publicKey.export({ format: "jwk" }) as Record<string, unknown>),
  kid: "dev-idp",
  alg: "RS256",
  use: "sig",
};

const b64u = (value: unknown): string =>
  Buffer.from(JSON.stringify(value)).toString("base64url");

function mint(subject: string, email: string, groups: string[]): string {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", kid: "dev-idp", typ: "JWT" };
  const claims = {
    sub: subject,
    email,
    iss: ISSUER,
    aud: AUDIENCE,
    token_use: "id",
    "cognito:groups": groups,
    iat: now,
    exp: now + TTL_SECONDS,
  };
  const signingInput = `${b64u(header)}.${b64u(claims)}`;
  const signature = createSign("RSA-SHA256")
    .update(signingInput)
    .sign(privateKey)
    .toString("base64url");
  return `${signingInput}.${signature}`;
}

createServer((request, response) => {
  if (request.url?.startsWith("/.well-known/jwks.json")) {
    response.setHeader("content-type", "application/json");
    response.end(JSON.stringify({ keys: [jwk] }));
    return;
  }
  response.statusCode = 404;
  response.end();
}).listen(PORT, HOST, () => {
  const admin = mint("dev-admin", "admin@example.invalid", [ADMIN_GROUP]);
  const auditor = mint("dev-auditor", "auditor@example.invalid", [AUDITOR_GROUP]);

  console.log(`
Development identity provider on ${ISSUER}
NOT FOR ANY REAL DEPLOYMENT: this mints admin tokens for anyone who can reach it.

Start the server with:

  COGNITO_ISSUER=${ISSUER} \\
  COGNITO_AUDIENCE=${AUDIENCE} \\
  TOLAP_IDENTITY_SOURCE=static \\
  TOLAP_STATIC_GROUPS="alice=analysts" \\
    npm run dev

Admin token (paste into the console's "Use an existing token"):

${admin}

Auditor token (read-only, to see what a reviewer sees):

${auditor}

Valid for ${TTL_SECONDS / 3600} hours. Ctrl-C to stop.
`);
});
