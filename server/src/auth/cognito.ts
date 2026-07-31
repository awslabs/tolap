/**
 * Amazon Cognito identity verification for the admin surface.
 *
 * The server owns no passwords and has no user table: Cognito is the identity
 * provider, and this module's only job is to turn a bearer token into a
 * trustworthy principal or refuse. Two roles come out of it -- `admin` (authors,
 * assigns, publishes) and `auditor` (reads policies, previews and the audit log,
 * writes nothing).
 *
 * ## Failure semantics
 *
 * Follows `docs/canonical-enforcement-spec.md` section 11, which the SDKs already
 * implement for data-plane identity and which applies just as much here:
 *
 * | Situation                                          | Behavior           |
 * | -------------------------------------------------- | ------------------ |
 * | No `Authorization` header at all                   | return `undefined` |
 * | Token present but malformed, wrong `alg`, `alg=none`, bad signature, expired, not-yet-valid, wrong issuer/audience, or missing claims | **throw** |
 *
 * Returning "no identity" for a token that was presented and rejected would let
 * a caller treat the request as anonymous, converting an authentication failure
 * into an authorization decision. On the admin surface that is the difference
 * between rejecting a forged token and letting it publish policy.
 *
 * ## Why no JWT library
 *
 * Node's `crypto` verifies RS256 directly from a JWK (`createPublicKey({ format:
 * "jwk" })`), which is all a Cognito JWKS document contains. Adding a JWT
 * dependency to a security-critical path would buy nothing except more supply
 * chain to audit, and this file deliberately implements only the algorithms
 * Cognito actually issues rather than a general-purpose verifier.
 *
 * `alg` is taken from an allow-list and never used to *select* the verification
 * strategy from the token's own header beyond that -- which is what defeats
 * algorithm-confusion attacks.
 */

import { createPublicKey, createVerify, type KeyObject } from "node:crypto";

/** The only algorithms Cognito signs with, and the only ones accepted. */
const ALLOWED_ALGORITHMS = new Set(["RS256"]);

/** Clock-skew allowance for `exp` and `nbf`, in seconds. */
const LEEWAY_SECONDS = 60;

/** How long a fetched JWKS is reused before refetching. */
const JWKS_TTL_MS = 3_600_000;

export type AdminRole = "admin" | "auditor";

export interface AdminPrincipal {
  /** Cognito `sub`. The stable identifier written to the audit log. */
  readonly subject: string;
  /** Email if the token carries one, for human-readable audit rows. */
  readonly email?: string;
  readonly role: AdminRole;
}

/**
 * Thrown when a credential is presented and rejected.
 *
 * The message is deliberately coarse. Section 11 requires that errors not
 * disclose whether a token merely expired versus failed verification beyond what
 * the operator logs, so callers map this to a flat 401 and the detail stays in
 * server-side logs.
 */
export class AdminAuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AdminAuthError";
  }
}

export interface CognitoConfig {
  /** e.g. `https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc123`. */
  readonly issuer: string;
  /** The app client id. Checked against `aud` (id tokens). */
  readonly audience: string;
  /** Cognito group granting the admin role. */
  readonly adminGroup: string;
  /** Cognito group granting the read-only auditor role. */
  readonly auditorGroup: string;
}

interface Jwk {
  readonly kid: string;
  readonly kty: string;
  readonly alg?: string;
  readonly n?: string;
  readonly e?: string;
}

type Fetcher = (url: string) => Promise<{ keys: Jwk[] }>;

const defaultFetcher: Fetcher = async (url) => {
  const response = await fetch(url);
  if (!response.ok) {
    throw new AdminAuthError(`JWKS fetch failed with status ${response.status}`);
  }
  return (await response.json()) as { keys: Jwk[] };
};

function decodeSegment(segment: string): unknown {
  // base64url with no padding. Buffer accepts base64url directly, but a segment
  // containing characters outside the alphabet decodes to garbage rather than
  // throwing, so validate the shape first.
  if (!/^[A-Za-z0-9_-]+$/.test(segment)) {
    throw new AdminAuthError("token segment is not base64url");
  }
  try {
    return JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
  } catch {
    throw new AdminAuthError("token segment is not JSON");
  }
}

function asRecord(value: unknown, what: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new AdminAuthError(`token ${what} is not an object`);
  }
  return value as Record<string, unknown>;
}

/**
 * Verifies Cognito-issued JWTs, caching the pool's public keys.
 */
export class CognitoVerifier {
  private keys = new Map<string, KeyObject>();
  private fetchedAt = 0;
  private inFlight: Promise<void> | undefined;
  private readonly config: CognitoConfig;
  private readonly fetcher: Fetcher;

  // Fields are assigned explicitly rather than declared as constructor parameter
  // properties: the server's sources run under `node --experimental-strip-types`,
  // which is strip-only and cannot desugar that syntax.
  constructor(config: CognitoConfig, fetcher: Fetcher = defaultFetcher) {
    this.config = config;
    this.fetcher = fetcher;
  }

  private get jwksUri(): string {
    return `${this.config.issuer.replace(/\/$/, "")}/.well-known/jwks.json`;
  }

  private async refreshKeys(): Promise<void> {
    // Collapse concurrent refreshes: a burst of requests after a key rotation
    // would otherwise each fetch the same document.
    this.inFlight ??= (async () => {
      try {
        const document = await this.fetcher(this.jwksUri);
        const next = new Map<string, KeyObject>();
        for (const jwk of document.keys ?? []) {
          if (jwk.kty !== "RSA" || !jwk.kid) continue;
          next.set(jwk.kid, createPublicKey({ key: jwk as never, format: "jwk" }));
        }
        if (next.size === 0) {
          throw new AdminAuthError("JWKS contained no usable RSA keys");
        }
        this.keys = next;
        this.fetchedAt = Date.now();
      } finally {
        this.inFlight = undefined;
      }
    })();
    await this.inFlight;
  }

  private async keyFor(kid: string): Promise<KeyObject> {
    const stale = Date.now() - this.fetchedAt > JWKS_TTL_MS;
    if (this.keys.size === 0 || stale) {
      await this.refreshKeys();
    }

    let key = this.keys.get(kid);
    if (!key && !stale) {
      // Unknown kid with a fresh cache means the pool rotated early. Refetch once
      // rather than rejecting a legitimate token.
      await this.refreshKeys();
      key = this.keys.get(kid);
    }

    if (!key) {
      throw new AdminAuthError("token key id is not published by the issuer");
    }
    return key;
  }

  /**
   * Verify a raw JWT and map it to a principal.
   *
   * @throws {AdminAuthError} if the token is present and not trustworthy.
   */
  async verify(token: string): Promise<AdminPrincipal> {
    const parts = token.split(".");
    if (parts.length !== 3) {
      throw new AdminAuthError("token is not a three-part JWT");
    }
    const [headerSegment, payloadSegment, signatureSegment] = parts as [
      string,
      string,
      string,
    ];

    const header = asRecord(decodeSegment(headerSegment), "header");
    const alg = header.alg;
    if (typeof alg !== "string" || !ALLOWED_ALGORITHMS.has(alg)) {
      // Covers `alg: "none"` and any HMAC algorithm, which an attacker would
      // choose precisely because the verifier might feed it a public key as a
      // shared secret.
      throw new AdminAuthError("token algorithm is not allowed");
    }
    if (typeof header.kid !== "string" || header.kid === "") {
      throw new AdminAuthError("token has no key id");
    }

    const key = await this.keyFor(header.kid);

    const verified = createVerify("RSA-SHA256")
      .update(`${headerSegment}.${payloadSegment}`)
      .verify(key, Buffer.from(signatureSegment, "base64url"));
    if (!verified) {
      throw new AdminAuthError("token signature is invalid");
    }

    const claims = asRecord(decodeSegment(payloadSegment), "payload");
    this.assertClaims(claims);

    const groups = Array.isArray(claims["cognito:groups"])
      ? (claims["cognito:groups"] as unknown[]).filter(
          (g): g is string => typeof g === "string",
        )
      : [];

    // Admin wins when a user is in both, because the roles are nested rather
    // than mutually exclusive -- an admin can do everything an auditor can.
    let role: AdminRole;
    if (groups.includes(this.config.adminGroup)) {
      role = "admin";
    } else if (groups.includes(this.config.auditorGroup)) {
      role = "auditor";
    } else {
      // Authenticated but unauthorized. Still an error rather than a principal
      // with no role: a caller holding a role-less principal has to remember to
      // check, and forgetting is a privilege escalation.
      throw new AdminAuthError("token carries no recognized admin group");
    }

    return {
      subject: claims.sub as string,
      ...(typeof claims.email === "string" ? { email: claims.email } : {}),
      role,
    };
  }

  private assertClaims(claims: Record<string, unknown>): void {
    if (typeof claims.sub !== "string" || claims.sub === "") {
      throw new AdminAuthError("token has no subject");
    }

    if (claims.iss !== this.config.issuer) {
      // Without this, a token minted by any Cognito pool in any AWS account
      // would verify here as long as its JWKS was reachable.
      throw new AdminAuthError("token issuer is not trusted");
    }

    // Cognito puts the client id in `aud` on id tokens and in `client_id` on
    // access tokens. Accept either, but require one to match.
    const audience = claims.aud ?? claims.client_id;
    const audienceMatches = Array.isArray(audience)
      ? audience.includes(this.config.audience)
      : audience === this.config.audience;
    if (!audienceMatches) {
      throw new AdminAuthError("token audience does not match");
    }

    // `token_use` distinguishes Cognito's id and access tokens. Anything else
    // (notably a refresh token) must not authenticate a request.
    const tokenUse = claims.token_use;
    if (tokenUse !== undefined && tokenUse !== "id" && tokenUse !== "access") {
      throw new AdminAuthError("token use is not id or access");
    }

    const now = Math.floor(Date.now() / 1000);

    const exp = claims.exp;
    if (typeof exp !== "number") {
      // A token with no expiry is never "does not expire" -- same fail-closed
      // reasoning as validateExpiry in the SDKs.
      throw new AdminAuthError("token has no expiry");
    }
    if (exp + LEEWAY_SECONDS <= now) {
      throw new AdminAuthError("token is expired");
    }

    const nbf = claims.nbf;
    if (typeof nbf === "number" && nbf - LEEWAY_SECONDS > now) {
      // Section 11: presented before nbf is invalid, not anonymous.
      throw new AdminAuthError("token is not yet valid");
    }
  }
}

/**
 * Pull a bearer token out of an `Authorization` header.
 *
 * Returns `undefined` only when no credential was offered at all. A header that
 * is present but not a usable bearer token is a rejection, not an anonymous
 * request.
 */
export function bearerToken(
  authorization: string | undefined,
): string | undefined {
  if (authorization === undefined || authorization.trim() === "") {
    return undefined;
  }
  const match = /^Bearer[ \t]+(\S+)$/i.exec(authorization.trim());
  if (!match) {
    throw new AdminAuthError("Authorization header is not a bearer token");
  }
  return match[1];
}
