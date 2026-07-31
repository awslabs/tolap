/**
 * Cognito admin authentication.
 *
 * These tests are written from the attacker's side: each one is a token someone
 * would forge to publish policy, and the assertion is that it is refused. The
 * happy path is a single test; the rest are refusals, because on this surface a
 * false accept is the whole compromise.
 *
 * Tokens are minted here with a locally generated RSA key and served through a
 * stub JWKS fetcher, so the suite needs no Cognito pool and no network.
 */

import { beforeAll, describe, expect, it } from "vitest";
import {
  createSign,
  generateKeyPairSync,
  type KeyObject,
} from "node:crypto";
import {
  AdminAuthError,
  CognitoVerifier,
  bearerToken,
  type CognitoConfig,
} from "../src/auth/cognito.ts";

const ISSUER = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_test";
const CONFIG: CognitoConfig = {
  issuer: ISSUER,
  audience: "test-client-id",
  adminGroup: "tolap-admin",
  auditorGroup: "tolap-auditor",
};

let privateKey: KeyObject;
let jwks: { keys: unknown[] };
/** A second key the verifier does not publish, for signature-mismatch cases. */
let foreignPrivateKey: KeyObject;

beforeAll(() => {
  const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
  privateKey = pair.privateKey;
  const jwk = pair.publicKey.export({ format: "jwk" }) as Record<string, unknown>;
  jwks = { keys: [{ ...jwk, kid: "test-kid", alg: "RS256", use: "sig" }] };

  foreignPrivateKey = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  }).privateKey;
});

const b64u = (value: unknown): string =>
  Buffer.from(JSON.stringify(value)).toString("base64url");

interface MintOptions {
  header?: Record<string, unknown>;
  claims?: Record<string, unknown>;
  signWith?: KeyObject;
  /** Replace the signature with this literal instead of signing. */
  signature?: string;
}

function mint(options: MintOptions = {}): string {
  const now = Math.floor(Date.now() / 1000);
  const header = {
    alg: "RS256",
    kid: "test-kid",
    typ: "JWT",
    ...options.header,
  };
  const claims = {
    sub: "user-sub-1",
    email: "admin@example.com",
    iss: ISSUER,
    aud: CONFIG.audience,
    token_use: "id",
    "cognito:groups": ["tolap-admin"],
    iat: now,
    exp: now + 900,
    ...options.claims,
  };

  const signingInput = `${b64u(header)}.${b64u(claims)}`;
  const signature =
    options.signature ??
    createSign("RSA-SHA256")
      .update(signingInput)
      .sign(options.signWith ?? privateKey)
      .toString("base64url");
  return `${signingInput}.${signature}`;
}

function verifier(): CognitoVerifier {
  return new CognitoVerifier(CONFIG, async () => jwks as { keys: never[] });
}

describe("bearerToken", () => {
  it("returns undefined when no credential is offered", () => {
    // Absent is not an error -- the route guard decides what to do with it.
    expect(bearerToken(undefined)).toBeUndefined();
    expect(bearerToken("")).toBeUndefined();
    expect(bearerToken("   ")).toBeUndefined();
  });

  it("throws on a header that is present but not a bearer token", () => {
    // Presented and unusable is a rejection, never a downgrade to anonymous
    // (canonical spec section 11).
    expect(() => bearerToken("Basic dXNlcjpwYXNz")).toThrow(AdminAuthError);
    expect(() => bearerToken("Bearer")).toThrow(AdminAuthError);
    expect(() => bearerToken("Bearer  two tokens")).toThrow(AdminAuthError);
  });

  it("accepts case-insensitive scheme and extra whitespace", () => {
    expect(bearerToken("bearer abc.def.ghi")).toBe("abc.def.ghi");
    expect(bearerToken("Bearer\tabc.def.ghi")).toBe("abc.def.ghi");
  });
});

describe("CognitoVerifier happy path", () => {
  it("maps an admin-group token to the admin role", async () => {
    const principal = await verifier().verify(mint());
    expect(principal).toEqual({
      subject: "user-sub-1",
      email: "admin@example.com",
      role: "admin",
    });
  });

  it("maps an auditor-group token to the auditor role", async () => {
    const token = mint({ claims: { "cognito:groups": ["tolap-auditor"] } });
    expect((await verifier().verify(token)).role).toBe("auditor");
  });

  it("grants admin when a user holds both groups", async () => {
    // The roles are nested, not exclusive: an admin can do everything an auditor
    // can, so the broader role wins rather than the first match.
    const token = mint({
      claims: { "cognito:groups": ["tolap-auditor", "tolap-admin"] },
    });
    expect((await verifier().verify(token)).role).toBe("admin");
  });

  it("accepts an access token that carries client_id instead of aud", async () => {
    const token = mint({
      claims: { aud: undefined, client_id: CONFIG.audience, token_use: "access" },
    });
    expect((await verifier().verify(token)).role).toBe("admin");
  });

  it("omits email when the token has none", async () => {
    const token = mint({ claims: { email: undefined } });
    const principal = await verifier().verify(token);
    expect(principal.email).toBeUndefined();
    expect(principal.subject).toBe("user-sub-1");
  });
});

describe("CognitoVerifier refusals", () => {
  const rejects = (token: string) =>
    expect(verifier().verify(token)).rejects.toThrow(AdminAuthError);

  it("refuses alg=none", async () => {
    // The classic unsigned-token forgery: strip the signature and claim there
    // was never meant to be one.
    await rejects(mint({ header: { alg: "none" }, signature: "" }));
  });

  it("refuses an HMAC algorithm", async () => {
    // Algorithm confusion: if the verifier honored `alg: HS256` it might use the
    // RSA public key -- which is public -- as an HMAC secret, letting anyone who
    // can read the JWKS mint valid tokens.
    await rejects(mint({ header: { alg: "HS256" } }));
  });

  it("refuses a signature from a key the issuer does not publish", async () => {
    await rejects(mint({ signWith: foreignPrivateKey }));
  });

  it("refuses a tampered payload", async () => {
    const token = mint({ claims: { "cognito:groups": ["tolap-auditor"] } });
    const [header, , signature] = token.split(".") as [string, string, string];
    // Swap in admin claims while keeping the signature over the auditor ones.
    const escalated = b64u({
      sub: "user-sub-1",
      iss: ISSUER,
      aud: CONFIG.audience,
      token_use: "id",
      "cognito:groups": ["tolap-admin"],
      exp: Math.floor(Date.now() / 1000) + 900,
    });
    await rejects(`${header}.${escalated}.${signature}`);
  });

  it("refuses an unknown key id", async () => {
    await rejects(mint({ header: { kid: "not-published" } }));
  });

  it("refuses a missing key id", async () => {
    await rejects(mint({ header: { kid: undefined } }));
  });

  it("refuses a foreign issuer", async () => {
    // Any Cognito pool in any AWS account would otherwise authenticate here.
    await rejects(
      mint({
        claims: {
          iss: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_attacker",
        },
      }),
    );
  });

  it("refuses a mismatched audience", async () => {
    await rejects(mint({ claims: { aud: "some-other-client" } }));
  });

  it("refuses a refresh token", async () => {
    await rejects(mint({ claims: { token_use: "refresh" } }));
  });

  it("refuses an expired token", async () => {
    const now = Math.floor(Date.now() / 1000);
    await rejects(mint({ claims: { exp: now - 3600 } }));
  });

  it("refuses a token with no expiry", async () => {
    // Absent expiry is never "never expires" -- same fail-closed rule the SDKs
    // apply to security-context expiry.
    await rejects(mint({ claims: { exp: undefined } }));
  });

  it("refuses a not-yet-valid token", async () => {
    const now = Math.floor(Date.now() / 1000);
    await rejects(mint({ claims: { nbf: now + 3600 } }));
  });

  it("refuses a token with no subject", async () => {
    await rejects(mint({ claims: { sub: undefined } }));
  });

  it("refuses a token whose groups grant no role", async () => {
    // Authenticated but unauthorized must not yield a role-less principal that a
    // caller might forget to check.
    await rejects(mint({ claims: { "cognito:groups": ["some-other-group"] } }));
    await rejects(mint({ claims: { "cognito:groups": undefined } }));
  });

  it("refuses structurally malformed tokens", async () => {
    await rejects("not-a-jwt");
    await rejects("only.two");
    await rejects("a.b.c.d");
    await rejects("!!!.###.$$$");
  });

  it("refuses when the issuer publishes no usable keys", async () => {
    const empty = new CognitoVerifier(CONFIG, async () => ({ keys: [] }));
    await expect(empty.verify(mint())).rejects.toThrow(AdminAuthError);
  });
});

describe("JWKS caching", () => {
  it("fetches once across many verifications", async () => {
    let fetches = 0;
    const cached = new CognitoVerifier(CONFIG, async () => {
      fetches += 1;
      return jwks as { keys: never[] };
    });

    await Promise.all([
      cached.verify(mint()),
      cached.verify(mint()),
      cached.verify(mint()),
    ]);
    await cached.verify(mint());

    // Concurrent first-use must collapse into one fetch, not one per request.
    expect(fetches).toBe(1);
  });

  it("refetches once when an unknown kid appears, then gives up", async () => {
    let fetches = 0;
    const rotating = new CognitoVerifier(CONFIG, async () => {
      fetches += 1;
      return jwks as { keys: never[] };
    });

    await rotating.verify(mint()); // primes the cache
    expect(fetches).toBe(1);

    await expect(
      rotating.verify(mint({ header: { kid: "rotated-in" } })),
    ).rejects.toThrow(AdminAuthError);

    // One retry for a genuine early rotation, then a refusal -- not a refetch
    // per request, which would make an unknown kid a way to hammer the JWKS
    // endpoint through this server.
    expect(fetches).toBe(2);
  });
});
