import { isLogLevel, LOG_LEVELS, type LogLevel } from "./logging.ts";
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
 * Expiry is the only replay bound a consumer gets without opting in. Artifacts carry
 * a signed `jti` and every SDK accepts a `ReplayGuard` that makes them single-use
 * (canonical-enforcement-spec.md section 13.1), but this server cannot make a consumer
 * configure one -- so the ceiling assumes none is. A day-long TTL would then be a
 * day-long replay window, which is why this is a hard limit rather than a documented
 * recommendation.
 */
const MAX_TTL_SECONDS = 3600;

/**
 * Per-IP request ceilings per window, in-process.
 *
 * Set well above any legitimate use and below what a scripted abuse loop wants. The
 * console is the admin listener's only real client and makes a handful of calls per
 * screen; 300/minute leaves room for a reviewer clicking quickly through a large
 * catalog. An install polls `/v1/resolve` at most once per policy TTL -- 15 minutes
 * by default -- so 60/minute tolerates a fleet behind one NAT address while still
 * bounding a harvest loop.
 *
 * Deliberately not a defense against a distributed source: per-IP counting cannot be.
 * WAF at the edge is the outer bound, and neither is a substitute for the credential
 * checks that actually decide access.
 */
const DEFAULT_ADMIN_RATE_LIMIT = 300;
const DEFAULT_RESOLVE_RATE_LIMIT = 60;
const DEFAULT_RATE_LIMIT_WINDOW_SECONDS = 60;

export interface ServerConfig {
  /**
   * How to reach the database.
   *
   * Two forms, and the distinction is about rotation rather than convenience. A
   * `url` carries the password inline, which is fine locally and wrong in a
   * deployment: it is a snapshot that goes stale the moment the secret rotates. A
   * `secret` names a Secrets Manager secret the server reads per connection, so a
   * rotation is picked up without a restart.
   */
  readonly database: DatabaseConfig;
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
  /**
   * Request log verbosity.
   *
   * `info` by default, because the alternative was `logger: false` and a server that
   * cannot report its own latency. `silent` disables the request hooks entirely rather
   * than formatting lines and dropping them, which is what the test suite wants.
   */
  readonly logLevel: LogLevel;
  /**
   * Per-IP request ceilings, one per listener, applied in-process.
   *
   * These are the inner bound, not the only one: the reference deployment also runs a
   * WAF rate-based rule at the edge (`infra/lib/edge-stack.ts`). Both exist because
   * they fail differently. WAF sheds a flood before it reaches this process, which
   * in-process limiting cannot do -- by the time Fastify counts a request it has
   * already cost a connection and an event-loop turn. But WAF only protects a
   * deployment that has WAF, and this server is meant to be runnable behind any
   * ingress, on a laptop, or in a container with nothing in front of it. Without an
   * in-process bound those deployments have none at all.
   *
   * The resolve limit is the tighter of the two on purpose. That endpoint mints signed
   * artifacts, and one is replayable for its whole TTL unless the consuming SDK
   * configures a replay guard -- which this server cannot enforce and cannot verify.
   * So the rate at which a stolen install credential can harvest policy is bounded
   * here or nowhere.
   */
  readonly adminRateLimit: number;
  readonly resolveRateLimit: number;
  /** Window for both ceilings, in seconds. */
  readonly rateLimitWindowSeconds: number;
}

/**
 * Database connection configuration.
 *
 * `secret` is the deployed form: the password is fetched from Secrets Manager when a
 * connection is opened, so a rotated credential is picked up by the next connection.
 * `url` is for local development, where the password is in the connection string.
 */
export type DatabaseConfig =
  | { readonly kind: "url"; readonly url: string }
  | {
      readonly kind: "secret";
      /** Secret id or ARN holding {username, password}. */
      readonly secretId: string;
      readonly host: string;
      readonly port: number;
      readonly database: string;
      readonly sslMode: string;
      readonly sslRootCert?: string;
      readonly cacheTtlMs: number;
    };

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

/**
 * Read the database configuration.
 *
 * `DATABASE_SECRET_ID` wins when set, because a deployment that has gone to the
 * trouble of providing a secret should never silently fall back to a password baked
 * into an environment variable.
 */
export function loadDatabaseConfig(
  env: NodeJS.ProcessEnv = process.env,
): DatabaseConfig {
  const secretId = env.DATABASE_SECRET_ID;
  if (secretId !== undefined && secretId.trim() !== "") {
    const cacheTtlSeconds = integer(env, "DATABASE_SECRET_CACHE_SECONDS", 300);
    if (cacheTtlSeconds < 0 || cacheTtlSeconds > 3600) {
      throw new Error(
        `DATABASE_SECRET_CACHE_SECONDS must be between 0 and 3600, got ${cacheTtlSeconds}.`,
      );
    }
    return {
      kind: "secret",
      secretId,
      // The host may come from the secret itself (RDS-managed secrets include it),
      // so it is optional here and resolved at connect time.
      host: env.DATABASE_HOST ?? "",
      port: integer(env, "DATABASE_PORT", 5432),
      database: env.DATABASE_NAME ?? "tolap",
      // verify-full rather than require: current `pg` treats `require` as an alias
      // for verify-full but warns that a future major will make it encrypt without
      // verifying. Naming the strict mode means the upgrade cannot weaken it.
      sslMode: env.DATABASE_SSL_MODE ?? "verify-full",
      ...(env.DATABASE_SSL_ROOT_CERT !== undefined
        ? { sslRootCert: env.DATABASE_SSL_ROOT_CERT }
        : {}),
      cacheTtlMs: cacheTtlSeconds * 1000,
    };
  }

  return { kind: "url", url: required(env, "DATABASE_URL") };
}

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
        "A signed artifact is replayable until it expires unless the consumer " +
          "configures a replay guard (spec section 13.1).",
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

  // Refused rather than clamped when nonsensical, for the same reason an over-large
  // pagination limit is refused: a silently corrected security parameter reads as
  // applied. Zero is rejected explicitly because "no requests allowed" is never what
  // an operator meant, and it would take the server down in a way that looks like a
  // bug rather than a setting.
  const adminRateLimit = integer(env, "TOLAP_ADMIN_RATE_LIMIT", DEFAULT_ADMIN_RATE_LIMIT);
  const resolveRateLimit = integer(env, "TOLAP_RESOLVE_RATE_LIMIT", DEFAULT_RESOLVE_RATE_LIMIT);
  const rateLimitWindowSeconds = integer(
    env,
    "TOLAP_RATE_LIMIT_WINDOW_SECONDS",
    DEFAULT_RATE_LIMIT_WINDOW_SECONDS,
  );
  for (const [name, value] of [
    ["TOLAP_ADMIN_RATE_LIMIT", adminRateLimit],
    ["TOLAP_RESOLVE_RATE_LIMIT", resolveRateLimit],
    ["TOLAP_RATE_LIMIT_WINDOW_SECONDS", rateLimitWindowSeconds],
  ] as const) {
    if (value < 1) {
      throw new Error(`${name} must be at least 1, got ${value}.`);
    }
  }

  return {
    database: loadDatabaseConfig(env),
    keyring,
    ttlSeconds,
    adminRateLimit,
    resolveRateLimit,
    rateLimitWindowSeconds,
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
    logLevel: loadLogLevel(env),
  };
}

/**
 * Request log verbosity, `info` unless asked otherwise.
 *
 * Rejects an unrecognized value rather than falling back. A typo in `LOG_LEVEL` that
 * silently produced `info` would be harmless; one that silently produced `silent` would
 * mean an operator believing they had logs and having none, which is the state this whole
 * change exists to leave.
 */
function loadLogLevel(env: NodeJS.ProcessEnv): LogLevel {
  const raw = env.LOG_LEVEL;
  if (raw === undefined || raw === "") return "info";
  if (!isLogLevel(raw)) {
    throw new Error(
      `LOG_LEVEL must be one of ${LOG_LEVELS.join(", ")}, got ${JSON.stringify(raw)}`,
    );
  }
  return raw;
}

export { MIN_SIGNING_KEY_LENGTH, MAX_TTL_SECONDS, DEFAULT_TTL_SECONDS };
