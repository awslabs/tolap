import { Keyring } from "./signing/keyring.ts";

/**
 * Server configuration, read from the environment once at startup.
 *
 * Everything here is validated eagerly and the process refuses to start on a bad
 * value. A policy server that boots with a broken signing key or an unreachable
 * database is worse than one that does not boot: it answers `/v1/resolve` with
 * artifacts nobody can verify, and the failure surfaces at the enforcement
 * boundary in someone else's service.
 */

/** Minimum HMAC key length. */
const MIN_SIGNING_KEY_LENGTH = 32;

/** Default artifact lifetime. */
const DEFAULT_TTL_SECONDS = 900;

/**
 * The longest TTL the server will issue.
 *
 * A signed artifact is replayable for its entire lifetime -- there is no `jti`
 * and no single-use enforcement anywhere in TOLAP
 * (canonical-enforcement-spec.md section 13), so expiry is the only bound on a
 * captured artifact. A day-long TTL is therefore a day-long window, which is why
 * this is a hard ceiling rather than a documented recommendation.
 */
const MAX_TTL_SECONDS = 3600;

export interface ServerConfig {
  readonly databaseUrl: string;
  /** Every key that may still appear on an unexpired artifact. */
  readonly keyring: Keyring;
  readonly ttlSeconds: number;
  /** Admin API + console listener. */
  readonly port: number;
  readonly host: string;
  /** Resolve listener, separate so it can bind a different interface. */
  readonly resolvePort: number;
  readonly resolveHost: string;
  readonly cognitoIssuer: string;
  readonly cognitoAudience: string;
  readonly adminGroup: string;
  readonly auditorGroup: string;
  /** Where group and role membership comes from. */
  readonly identity: IdentityConfig;
}

/**
 * How the server learns a user's groups and roles.
 *
 * `none` is spelled out rather than being the silent default, because a deployment
 * that uses group-scoped assignments and forgets to configure this gets grants that
 * resolve to nothing -- and nothing about that looks like a misconfiguration.
 */
export type IdentityConfig =
  | { readonly kind: "cognito"; readonly userPoolId: string; readonly rolePrefix?: string; readonly cacheTtlSeconds: number }
  | { readonly kind: "static"; readonly spec: string }
  | { readonly kind: "none" };

function required(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name];
  if (value === undefined || value.trim() === "") {
    throw new Error(
      `${name} is required. Refusing to start without it -- see docs/policy-server.md.`,
    );
  }
  return value;
}

function integer(
  env: NodeJS.ProcessEnv,
  name: string,
  fallback: number,
): number {
  const raw = env[name];
  if (raw === undefined || raw.trim() === "") return fallback;

  // Number() accepts "1e3", " 12 " and "0x10"; parseInt accepts "12abc". Neither
  // is what a port or a TTL means, so require the whole string to be digits.
  if (!/^\d+$/.test(raw.trim())) {
    throw new Error(
      `${name} must be a non-negative integer, got ${JSON.stringify(raw)}.`,
    );
  }
  return Number.parseInt(raw.trim(), 10);
}

/**
 * Build the keyring.
 *
 * `TOLAP_SIGNING_KEYS` is the rotation form -- `kid:secret` pairs, first active.
 * `TOLAP_SIGNING_KEY` remains supported as a single bare secret, so an existing
 * deployment keeps working unchanged; it becomes the key `default`.
 *
 * No development fallback in either form. A default key would be shared by every
 * deployment that forgot to set one, making every artifact those servers issue
 * forgeable by anyone who has read this file.
 */
function loadKeyring(env: NodeJS.ProcessEnv): Keyring {
  const multi = env.TOLAP_SIGNING_KEYS;
  if (multi !== undefined && multi.trim() !== "") {
    return Keyring.parse(multi, env.TOLAP_ACTIVE_KID);
  }
  return Keyring.parse(required(env, "TOLAP_SIGNING_KEY"), env.TOLAP_ACTIVE_KID);
}

function loadIdentity(env: NodeJS.ProcessEnv): IdentityConfig {
  // Default to Cognito when a pool is configured: the server already
  // authenticates administrators against a pool, so the groups are almost always
  // there for the asking, and defaulting to "no membership" makes group-scoped
  // assignments fail silently.
  const kind =
    env.TOLAP_IDENTITY_SOURCE ??
    (env.COGNITO_USER_POOL_ID !== undefined ? "cognito" : "none");

  switch (kind) {
    case "cognito": {
      const cacheTtlSeconds = integer(env, "TOLAP_IDENTITY_CACHE_SECONDS", 300);
      if (cacheTtlSeconds < 0 || cacheTtlSeconds > 3600) {
        throw new Error(
          `TOLAP_IDENTITY_CACHE_SECONDS must be between 0 and 3600, got ${cacheTtlSeconds}. ` +
            "A long cache delays revoking someone's group membership.",
        );
      }
      return {
        kind: "cognito",
        userPoolId: required(env, "COGNITO_USER_POOL_ID"),
        ...(env.TOLAP_ROLE_PREFIX !== undefined
          ? { rolePrefix: env.TOLAP_ROLE_PREFIX }
          : {}),
        cacheTtlSeconds,
      };
    }
    case "static":
      return { kind: "static", spec: required(env, "TOLAP_STATIC_GROUPS") };
    case "none":
      return { kind: "none" };
    default:
      throw new Error(
        `TOLAP_IDENTITY_SOURCE must be 'cognito', 'static' or 'none', got ${JSON.stringify(kind)}.`,
      );
  }
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): ServerConfig {
  const keyring = loadKeyring(env);

  const ttlSeconds = integer(env, "TOLAP_TTL_SECONDS", DEFAULT_TTL_SECONDS);
  if (ttlSeconds < 1 || ttlSeconds > MAX_TTL_SECONDS) {
    throw new Error(
      `TOLAP_TTL_SECONDS must be between 1 and ${MAX_TTL_SECONDS}, got ${ttlSeconds}. ` +
        "A signed artifact is replayable until it expires (spec section 13).",
    );
  }

  const port = integer(env, "PORT", 8080);
  const resolvePort = integer(env, "RESOLVE_PORT", 8081);
  for (const [name, value] of [
    ["PORT", port],
    ["RESOLVE_PORT", resolvePort],
  ] as const) {
    if (value < 1 || value > 65535) {
      throw new Error(`${name} must be between 1 and 65535, got ${value}.`);
    }
  }
  if (port === resolvePort) {
    // Sharing a port would silently collapse the two-listener split, putting the
    // policy-authoring surface on whatever interface the resolve port was meant
    // to expose to remote installs.
    throw new Error(
      `PORT and RESOLVE_PORT must differ; both are ${port}. The admin and resolve ` +
        "listeners are separate so they can bind different interfaces.",
    );
  }

  return {
    databaseUrl: required(env, "DATABASE_URL"),
    keyring,
    ttlSeconds,
    port,
    // Loopback by default. A policy server that binds every interface the moment
    // it starts is reachable before an operator has decided it should be.
    host: env.HOST ?? "127.0.0.1",
    resolvePort,
    resolveHost: env.RESOLVE_HOST ?? env.HOST ?? "127.0.0.1",
    cognitoIssuer: required(env, "COGNITO_ISSUER"),
    cognitoAudience: required(env, "COGNITO_AUDIENCE"),
    adminGroup: env.TOLAP_ADMIN_GROUP ?? "tolap-admin",
    auditorGroup: env.TOLAP_AUDITOR_GROUP ?? "tolap-auditor",
    identity: loadIdentity(env),
  };
}

export { MIN_SIGNING_KEY_LENGTH, MAX_TTL_SECONDS, DEFAULT_TTL_SECONDS };
