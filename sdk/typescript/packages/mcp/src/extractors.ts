/**
 * TOLAP MCP Identity Extractors
 *
 * Implementations of RequestIdentityExtractor for common auth patterns.
 */

import { createHmac, timingSafeEqual } from "node:crypto";

import type { RequestIdentityExtractor, McpRequestContext } from "./types.js";

// ---------------------------------------------------------------------------
// Identity extraction failures
// ---------------------------------------------------------------------------

/**
 * Thrown when a credential is *presented and rejected*.
 *
 * Per canonical spec §11 an identity extractor either returns a trustworthy
 * principal or it fails. Returning `undefined` for a token that was presented and
 * rejected converts an authentication failure into an authorization decision: the
 * caller sees no identity, treats the request as anonymous, and resolves whatever
 * a default or anonymous assignment happens to grant. The same expired token then
 * succeeds here and fails on the .NET SDK, which throws.
 *
 * An *absent* credential is not an error -- it yields `undefined`, which the
 * integrator may legitimately choose to allow as an anonymous request.
 */
export class IdentityExtractionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "IdentityExtractionError";
  }
}

// ---------------------------------------------------------------------------
// Header-based extractor
// ---------------------------------------------------------------------------

/**
 * Extracts identity from custom HTTP headers.
 */
export class HeaderIdentityExtractor implements RequestIdentityExtractor {
  private userIdHeader: string;
  private tenantIdHeader: string;

  constructor(
    userIdHeader: string = "x-user-id",
    tenantIdHeader: string = "x-tenant-id",
  ) {
    this.userIdHeader = userIdHeader.toLowerCase();
    this.tenantIdHeader = tenantIdHeader.toLowerCase();
  }

  extractUserId(request: McpRequestContext): string | undefined {
    if (!request.headers) return undefined;
    // Headers may be case-insensitive -- normalize to lowercase
    const normalized = this.normalizeHeaders(request.headers);
    return normalized[this.userIdHeader];
  }

  extractTenantId(request: McpRequestContext): string | undefined {
    if (!request.headers) return undefined;
    const normalized = this.normalizeHeaders(request.headers);
    return normalized[this.tenantIdHeader];
  }

  private normalizeHeaders(
    headers: Record<string, string>,
  ): Record<string, string> {
    const result: Record<string, string> = {};
    for (const [key, value] of Object.entries(headers)) {
      result[key.toLowerCase()] = value;
    }
    return result;
  }
}

// ---------------------------------------------------------------------------
// JWT-based extractor
// ---------------------------------------------------------------------------

/** HMAC algorithms this SDK can verify with only the Node standard library. */
const HMAC_ALGORITHMS: Record<string, string> = {
  HS256: "sha256",
  HS384: "sha384",
  HS512: "sha512",
};

/**
 * Options controlling how {@link JwtIdentityExtractor} trusts a token.
 *
 * Provide `secret` to verify HMAC-signed JWTs (recommended), or set
 * `allowUnverified: true` only when a trusted upstream layer has already
 * verified the signature. Supplying neither is a construction error, so the
 * insecure path can never be selected by accident.
 */
export interface JwtExtractorOptions {
  userIdClaim?: string;
  tenantIdClaim?: string;
  /** Shared HMAC secret the issuer signed with. */
  secret?: string | Buffer;
  /** Accepted algorithms (allow-list). Defaults to `["HS256"]`. */
  algorithms?: string[];
  /** Trust an already-verified token without re-checking the signature. */
  allowUnverified?: boolean;
  /** Clock-skew allowance for `exp` and `nbf`, in seconds. */
  leewaySeconds?: number;
}

/**
 * Extracts identity from a JWT in the Authorization header **after verifying
 * its signature**.
 *
 * By default the signature (HMAC / HS256-384-512) and the `exp`/`nbf` claims are
 * verified before any claim is trusted. The `none` algorithm and any algorithm
 * outside the allow-list are rejected, defeating `alg`-confusion and
 * unsigned-token attacks.
 *
 * Failure semantics follow canonical spec §11 and are identical in all three SDKs:
 *
 * - **No credential presented** (absent/empty `Authorization` header, or no token
 *   after the scheme) -- returns `undefined`. A legitimate anonymous request the
 *   integrator may choose to allow.
 * - **Credential presented but invalid** -- malformed structure, non-allowlisted
 *   algorithm, `alg=none`, bad signature, expired (`exp`), not-yet-valid (`nbf`),
 *   or a missing required claim -- throws {@link IdentityExtractionError}.
 *
 * The distinction matters because returning `undefined` for a rejected token makes
 * an attacker's expired or forged credential indistinguishable from no credential
 * at all, and the request then resolves whatever an anonymous or default
 * assignment grants instead of being refused.
 */
export class JwtIdentityExtractor implements RequestIdentityExtractor {
  private userIdClaim: string;
  private tenantIdClaim: string;
  private secret?: Buffer;
  private algorithms: string[];
  private allowUnverified: boolean;
  private leewaySeconds: number;

  constructor(options: JwtExtractorOptions = {}) {
    if (options.secret === undefined && !options.allowUnverified) {
      throw new Error(
        "JwtIdentityExtractor requires a signing 'secret' to verify JWTs. " +
          "If (and only if) signatures are already verified by a trusted " +
          "upstream layer, pass allowUnverified: true explicitly.",
      );
    }
    this.userIdClaim = options.userIdClaim ?? "sub";
    this.tenantIdClaim = options.tenantIdClaim ?? "tenant_id";
    this.secret =
      options.secret === undefined
        ? undefined
        : Buffer.isBuffer(options.secret)
          ? options.secret
          : Buffer.from(options.secret, "utf8");
    this.algorithms = options.algorithms ?? ["HS256"];
    this.allowUnverified = options.allowUnverified ?? false;
    this.leewaySeconds = options.leewaySeconds ?? 0;
  }

  extractUserId(request: McpRequestContext): string | undefined {
    return this.claim(request, this.userIdClaim);
  }

  extractTenantId(request: McpRequestContext): string | undefined {
    return this.claim(request, this.tenantIdClaim);
  }

  /**
   * Resolve one claim: `undefined` when no credential was presented, the claim
   * value when the token verifies, and a throw for anything in between.
   */
  private claim(
    request: McpRequestContext,
    claimName: string,
  ): string | undefined {
    const token = this.presentedToken(request);
    if (token === undefined) return undefined;

    const claims = this.verifiedClaims(token);
    const value = claims[claimName];
    if (typeof value !== "string" || value.length === 0) {
      // A verified token missing a required claim is a misconfiguration, not an
      // anonymous request: the issuer authenticated someone the policy engine
      // cannot identify.
      throw new IdentityExtractionError(`Missing claim: ${claimName}`);
    }
    return value;
  }

  /**
   * Return the presented token, or `undefined` when no credential was sent.
   *
   * An absent header, an empty header, and a bare `Bearer` with no token are all
   * "no credential presented" -- the anonymous case. Anything else is a credential
   * whose validity is then decided by verification, so a malformed scheme throws
   * rather than silently degrading to anonymous.
   */
  private presentedToken(request: McpRequestContext): string | undefined {
    if (!request.headers) return undefined;
    const normalized: Record<string, string> = {};
    for (const [key, value] of Object.entries(request.headers)) {
      normalized[key.toLowerCase()] = value;
    }

    const authHeader = normalized["authorization"];
    if (!authHeader || authHeader.trim().length === 0) return undefined;

    const parts = authHeader.trim().split(/\s+/);
    // "Bearer" alone carries no credential to reject.
    if (parts.length === 1 && parts[0].toLowerCase() === "bearer") {
      return undefined;
    }
    if (parts.length !== 2 || parts[0].toLowerCase() !== "bearer") {
      throw new IdentityExtractionError(
        "Invalid Authorization header: expected 'Bearer <token>'",
      );
    }
    return parts[1];
  }

  /**
   * Verify a presented token and return its claims, throwing on every rejection.
   */
  private verifiedClaims(token: string): Record<string, unknown> {
    const segments = token.split(".");
    if (segments.length !== 3) {
      throw new IdentityExtractionError(
        "Invalid JWT format: expected 3 dot-separated parts",
      );
    }

    let header: Record<string, unknown>;
    let payload: Record<string, unknown>;
    try {
      header = JSON.parse(
        Buffer.from(segments[0], "base64url").toString("utf8"),
      ) as Record<string, unknown>;
      payload = JSON.parse(
        Buffer.from(segments[1], "base64url").toString("utf8"),
      ) as Record<string, unknown>;
    } catch {
      throw new IdentityExtractionError("Malformed JWT encoding");
    }
    if (
      header === null ||
      typeof header !== "object" ||
      Array.isArray(header) ||
      payload === null ||
      typeof payload !== "object" ||
      Array.isArray(payload)
    ) {
      throw new IdentityExtractionError(
        "Malformed JWT: header and payload must be objects",
      );
    }

    if (!this.allowUnverified) {
      const alg = header["alg"];
      // Reject "none" and any algorithm outside the caller's allow-list.
      if (
        typeof alg !== "string" ||
        !this.algorithms.includes(alg) ||
        !(alg in HMAC_ALGORITHMS)
      ) {
        throw new IdentityExtractionError(
          `JWT algorithm not allowed: ${typeof alg === "string" ? alg : "(none)"}`,
        );
      }
      /* c8 ignore next 5 -- unreachable defensive guard, deliberately retained.
         The constructor refuses to build an extractor with neither `secret` nor
         `allowUnverified: true`, and this block only runs when
         `allowUnverified` is false, so `secret` is always present here. Kept
         because it is the invariant that stops verification being skipped: if a
         future refactor loosens the constructor, this throws rather than
         silently trusting an unverified token. Asserting it would require
         defeating the constructor's own check, which would test the mock. */
      if (!this.secret) {
        throw new IdentityExtractionError(
          "No signing secret configured for JWT verification",
        );
      }
      const expected = createHmac(HMAC_ALGORITHMS[alg], this.secret)
        .update(`${segments[0]}.${segments[1]}`)
        .digest();
      let provided: Buffer;
      try {
        provided = Buffer.from(segments[2], "base64url");
        /* c8 ignore next 3 -- unreachable in Node: `Buffer.from(s, "base64url")`
           never throws, it silently ignores characters outside the alphabet (an
           undecodable signature therefore surfaces as a length mismatch or a
           timingSafeEqual failure below, both of which ARE covered). Retained
           because the surrounding contract is "a malformed signature is a clean
           IdentityExtractionError, never a raw decode error escaping into the
           caller", and that must hold if this ever runs on a runtime whose
           base64url decoder is stricter. */
      } catch {
        throw new IdentityExtractionError("Invalid JWT signature encoding");
      }
      if (
        expected.length !== provided.length ||
        !timingSafeEqual(expected, provided)
      ) {
        throw new IdentityExtractionError("Invalid JWT signature");
      }
    }

    // Temporal claims are checked in both modes when present.
    this.verifyTemporalClaims(payload);

    return payload;
  }

  /**
   * Enforce `exp` and `nbf` with the same leeway.
   *
   * `nbf` is validated because a token presented before it becomes valid is
   * invalid, not anonymous (spec §11). Leaving it unchecked let a post-dated token
   * -- one an issuer minted for a future window -- be used immediately.
   */
  private verifyTemporalClaims(payload: Record<string, unknown>): void {
    const now = Math.floor(Date.now() / 1000);

    const exp = payload["exp"];
    if (typeof exp === "number" && Number.isFinite(exp)) {
      if (now > exp + this.leewaySeconds) {
        throw new IdentityExtractionError("JWT has expired");
      }
    }

    const nbf = payload["nbf"];
    if (typeof nbf === "number" && Number.isFinite(nbf)) {
      if (now < nbf - this.leewaySeconds) {
        throw new IdentityExtractionError("JWT is not yet valid");
      }
    }
  }
}
