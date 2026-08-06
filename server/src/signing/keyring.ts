/**
 * Signing keys, and rotating them without downtime.
 *
 * ## Why this is possible without touching the SDKs
 *
 * None of the three SDKs has a `kid` concept or a key-resolution hook: every
 * signing and verification API takes a bare `secretKey: string`. That looked like
 * it made rotation a cross-SDK change. It does not, for one reason worth stating
 * plainly: **the security-context envelope has no JSON Schema**, so an extra
 * top-level key is legal, and all three SDKs ignore members they do not model.
 *
 * Verified rather than assumed -- an artifact carrying `kid` alongside the
 * signature verifies in TypeScript (`validateContext` and `validatePolicy`),
 * deserializes and verifies in Python (`deserialize_context`), and verifies in
 * .NET (`SecurityContextSigner.Validate`). The `kid` is *outside* the signed
 * payload, which the canonical projection fixes to
 * `{version,userId,tenantId,issuedAt,expiresAt,policies[]}` (spec section 2), so
 * adding it cannot change the signed bytes.
 *
 * ## `kid` is a hint, never an authority
 *
 * It is unsigned, so an attacker can rewrite it freely. That is harmless because it
 * only selects *which key to try*: a wrong or forged `kid` leads to a key under
 * which the signature fails, which is a denial. What a consumer must never do is
 * treat `kid` as evidence of anything, or fall back to "try every key" on a
 * mismatch -- the second turns an unknown `kid` into an oracle for which keys a
 * server holds.
 *
 * ## Rotation
 *
 * Configure the new key as active and keep the old one verifiable. Both are valid
 * during the overlap, so installs update on their own schedule instead of a flag
 * day. Once every artifact signed with the old key has expired -- at most one TTL,
 * capped at an hour -- drop it.
 */

/** A key the server can sign or verify with. */
export interface SigningKey {
  /** Identifier stamped into the artifact. Opaque; conventionally dated. */
  readonly kid: string;
  readonly secret: string;
}

export class KeyringError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KeyringError";
  }
}

const MIN_SECRET_LENGTH = 32;

/** Conservative charset: `kid` travels in JSON and ends up in logs and metrics. */
const KID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}[A-Za-z0-9]$/;

export class Keyring {
  private readonly keys: Map<string, SigningKey>;
  private readonly activeKid: string;

  /**
   * @param keys     Every key that may still appear on an unexpired artifact.
   * @param activeKid The key new artifacts are signed with.
   */
  constructor(keys: readonly SigningKey[], activeKid: string) {
    if (keys.length === 0) {
      throw new KeyringError("at least one signing key is required");
    }

    const map = new Map<string, SigningKey>();
    for (const key of keys) {
      if (!KID_PATTERN.test(key.kid)) {
        throw new KeyringError(
          `invalid kid ${JSON.stringify(key.kid)}: use 2-64 characters of [A-Za-z0-9._-]`,
        );
      }
      if (key.secret.length < MIN_SECRET_LENGTH) {
        throw new KeyringError(
          `signing key '${key.kid}' must be at least ${MIN_SECRET_LENGTH} characters`,
        );
      }
      if (map.has(key.kid)) {
        // Two secrets under one kid makes verification order-dependent, which is
        // the one thing a kid exists to remove.
        throw new KeyringError(`duplicate kid '${key.kid}'`);
      }
      map.set(key.kid, key);
    }

    if (!map.has(activeKid)) {
      throw new KeyringError(
        `active kid '${activeKid}' is not among the configured keys (${[...map.keys()].join(", ")})`,
      );
    }

    this.keys = map;
    this.activeKid = activeKid;
  }

  /** The key new artifacts are signed with. */
  get active(): SigningKey {
    // Non-null: the constructor proved activeKid is present.
    return this.keys.get(this.activeKid)!;
  }

  /** Look up a key by identifier, or `undefined` if this server does not hold it. */
  find(kid: string): SigningKey | undefined {
    return this.keys.get(kid);
  }

  /** Every kid, for the operator-facing rotation status. */
  get kids(): string[] {
    return [...this.keys.keys()];
  }

  get size(): number {
    return this.keys.size;
  }

  /**
   * Parse the `TOLAP_SIGNING_KEYS` environment form.
   *
   * `kid:secret` pairs separated by commas, the first being active:
   *
   *     TOLAP_SIGNING_KEYS="2026-08:<secret>,2026-05:<older secret>"
   *
   * A single bare secret is also accepted and given the kid `default`, so an
   * existing `TOLAP_SIGNING_KEY` deployment keeps working: it produces exactly the
   * artifact it did before, plus `"kid":"default"`.
   */
  static parse(spec: string, activeKid?: string): Keyring {
    const entries = spec
      .split(",")
      .map((entry) => entry.trim())
      .filter((entry) => entry !== "");

    if (entries.length === 0) {
      throw new KeyringError("no signing keys configured");
    }

    const keys: SigningKey[] = entries.map((entry) => {
      // Split on the FIRST colon only: a secret may well contain one, and base64
      // padding or a URL-shaped secret must survive.
      const separator = entry.indexOf(":");
      if (separator <= 0) {
        return { kid: "default", secret: entry };
      }
      return {
        kid: entry.slice(0, separator),
        secret: entry.slice(separator + 1),
      };
    });

    if (keys.length > 1 && keys.some((key) => key.kid === "default")) {
      // With several keys, an unlabelled one cannot be told apart in an artifact.
      throw new KeyringError(
        "when configuring more than one signing key, every entry must be 'kid:secret'",
      );
    }

    return new Keyring(keys, activeKid ?? keys[0]!.kid);
  }
}
