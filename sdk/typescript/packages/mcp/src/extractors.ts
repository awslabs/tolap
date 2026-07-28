/**
 * TOLAP MCP Identity Extractors
 *
 * Implementations of RequestIdentityExtractor for common auth patterns.
 */

import { createHmac, timingSafeEqual } from "node:crypto";

import type { RequestIdentityExtractor, McpRequestContext } from "./types.js";

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
  /** Clock-skew allowance for `exp`, in seconds. */
  leewaySeconds?: number;
}

/**
 * Extracts identity from a JWT in the Authorization header **after verifying
 * its signature**.
 *
 * By default the signature (HMAC / HS256-384-512) and the `exp` claim are
 * verified before any claim is trusted. A token that fails verification yields
 * `undefined`, so enforcement fails closed onto an empty/anonymous policy
 * rather than an attacker-supplied one. The `none` algorithm and any algorithm
 * outside the allow-list are rejected, defeating `alg`-confusion and
 * unsigned-token attacks.
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
    const claims = this.verifiedClaims(request);
    if (!claims) return undefined;
    const value = claims[this.userIdClaim];
    return typeof value === "string" ? value : undefined;
  }

  extractTenantId(request: McpRequestContext): string | undefined {
    const claims = this.verifiedClaims(request);
    if (!claims) return undefined;
    const value = claims[this.tenantIdClaim];
    return typeof value === "string" ? value : undefined;
  }

  private verifiedClaims(
    request: McpRequestContext,
  ): Record<string, unknown> | undefined {
    if (!request.headers) return undefined;
    const normalized: Record<string, string> = {};
    for (const [key, value] of Object.entries(request.headers)) {
      normalized[key.toLowerCase()] = value;
    }

    const authHeader = normalized["authorization"];
    if (!authHeader) return undefined;

    const parts = authHeader.split(" ");
    if (parts.length !== 2 || parts[0].toLowerCase() !== "bearer") {
      return undefined;
    }

    const token = parts[1];
    const segments = token.split(".");
    if (segments.length !== 3) return undefined;

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
      return undefined;
    }

    if (!this.allowUnverified) {
      const alg = header["alg"];
      // Reject "none" and any algorithm outside the caller's allow-list.
      if (
        typeof alg !== "string" ||
        !this.algorithms.includes(alg) ||
        !(alg in HMAC_ALGORITHMS) ||
        !this.secret
      ) {
        return undefined;
      }
      const expected = createHmac(HMAC_ALGORITHMS[alg], this.secret)
        .update(`${segments[0]}.${segments[1]}`)
        .digest();
      let provided: Buffer;
      try {
        provided = Buffer.from(segments[2], "base64url");
      } catch {
        return undefined;
      }
      if (
        expected.length !== provided.length ||
        !timingSafeEqual(expected, provided)
      ) {
        return undefined;
      }
    }

    // Expiry is checked in both modes when present.
    const exp = payload["exp"];
    if (typeof exp === "number") {
      const now = Math.floor(Date.now() / 1000);
      if (now > exp + this.leewaySeconds) return undefined;
    }

    return payload;
  }
}
