/**
 * Credentials issued to registered installs, used on the resolve port.
 *
 * A remote TOLAP install registers once, receives a credential, and presents it
 * on every `/v1/resolve` call. The credential exists so the audit log can name
 * *which* install pulled a policy and so one install can be revoked without
 * disturbing the others -- a shared secret across all installs would give up
 * both properties.
 *
 * The server stores only a hash. A leaked database gives an attacker no usable
 * credential, which matters because the resolve port is the surface remote
 * installs reach.
 */

import {
  createHash,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

/** Prefix so a leaked credential is recognizable in logs and scanners. */
const PREFIX = "tolap_ik_";

/** 32 bytes of CSPRNG output, base64url encoded. */
const SECRET_BYTES = 32;

export interface IssuedCredential {
  /** Public identifier, safe to log and store in plaintext. */
  readonly installId: string;
  /**
   * The full credential string. Returned **once** at registration and never
   * recoverable afterwards, because only its hash is persisted.
   */
  readonly secret: string;
  /** What goes in the database. */
  readonly hash: string;
}

/**
 * Mint a credential for a newly registered install.
 */
export function issueCredential(installId: string): IssuedCredential {
  const secret = `${PREFIX}${installId}.${randomBytes(SECRET_BYTES).toString("base64url")}`;
  return { installId, secret, hash: hashCredential(secret) };
}

/**
 * Hash a credential for storage or comparison.
 *
 * Plain SHA-256 rather than a password KDF, deliberately: this is a
 * 256-bit random value, not a human-chosen password, so there is no dictionary
 * to attack and the slow-hash property that protects weak passwords buys nothing
 * here. It would, however, cost a KDF's worth of CPU on every resolve call.
 */
export function hashCredential(secret: string): string {
  return createHash("sha256").update(secret, "utf8").digest("hex");
}

/**
 * Read the install id embedded in a credential, without trusting it.
 *
 * Used only to look up which hash to compare against. The credential is not
 * authenticated until {@link credentialMatches} succeeds, so nothing derived from
 * this may be treated as an identity on its own.
 */
export function installIdFromCredential(secret: string): string | undefined {
  if (!secret.startsWith(PREFIX)) return undefined;
  const rest = secret.slice(PREFIX.length);
  const dot = rest.indexOf(".");
  if (dot <= 0 || dot === rest.length - 1) return undefined;
  return rest.slice(0, dot);
}

/**
 * Constant-time comparison of a presented credential against a stored hash.
 */
export function credentialMatches(secret: string, storedHash: string): boolean {
  const presented = Buffer.from(hashCredential(secret), "hex");
  let stored: Buffer;
  try {
    stored = Buffer.from(storedHash, "hex");
  } catch {
    return false;
  }
  // timingSafeEqual throws on a length mismatch rather than returning false, and
  // a truncated or malformed stored hash must be a non-match, not a crash inside
  // an authentication check.
  if (presented.length !== stored.length) return false;
  return timingSafeEqual(presented, stored);
}

export { PREFIX as CREDENTIAL_PREFIX };
