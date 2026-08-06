/**
 * Database credentials read from AWS Secrets Manager at connection time.
 *
 * ## Why not an environment variable
 *
 * Injecting the password as an env var (ECS `secrets:`, a Kubernetes secret) is a
 * **point-in-time snapshot**. It is taken when the task starts and never changes, so
 * the moment the secret rotates the running task is holding a password the database
 * no longer accepts. Nothing fails at rotation — it fails at the next new
 * connection, minutes or hours later, as an authentication error that looks like a
 * misconfiguration rather than a rotation.
 *
 * Reading the secret when a connection is opened fixes that: `pg` accepts a
 * `password` **function** and calls it per client (`pg/lib/client.js:269`), so a
 * rotated secret is picked up by the next connection without a restart or a
 * deployment.
 *
 * A snapshot in the environment has a second cost: it sits in `/proc/<pid>/environ`
 * for the lifetime of the process, is inherited by anything the process spawns, and
 * shows up in a crash dump or a debug endpoint that prints `process.env`. A value
 * fetched on demand and held only in a short-lived cache is exposed for less.
 *
 * ## Rotation and the cache
 *
 * The value is cached briefly, because opening a pool connection per request would
 * otherwise mean a Secrets Manager call per request — both slow and rate-limited.
 * The cache is short, and more importantly an **authentication failure clears it**,
 * so a rotation is absorbed on the next attempt rather than waiting out a TTL.
 */

import {
  GetSecretValueCommand,
  SecretsManagerClient,
} from "@aws-sdk/client-secrets-manager";

/** How long a fetched secret is reused. */
const DEFAULT_CACHE_TTL_MS = 300_000;

/**
 * The shape RDS and Aurora write into a managed secret. Extra keys (`dbname`,
 * `engine`, `port`, `dbClusterIdentifier`) are present and ignored.
 */
export interface DatabaseSecret {
  readonly username: string;
  readonly password: string;
  readonly host?: string;
  readonly port?: number;
}

export class CredentialsError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "CredentialsError";
  }
}

export interface SecretsReaderOptions {
  readonly secretId: string;
  readonly cacheTtlMs?: number;
  /** Injectable for tests. */
  readonly client?: Pick<SecretsManagerClient, "send">;
}

/**
 * Reads and briefly caches a database secret.
 */
export class DatabaseSecretReader {
  private readonly client: Pick<SecretsManagerClient, "send">;
  private readonly secretId: string;
  private readonly ttlMs: number;
  private cached: { value: DatabaseSecret; at: number } | undefined;
  private inFlight: Promise<DatabaseSecret> | undefined;

  constructor(options: SecretsReaderOptions) {
    this.secretId = options.secretId;
    this.ttlMs = options.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS;
    this.client = options.client ?? new SecretsManagerClient({});
  }

  async read(): Promise<DatabaseSecret> {
    if (this.cached && Date.now() - this.cached.at < this.ttlMs) {
      return this.cached.value;
    }

    // Collapse concurrent reads. A pool filling several connections at startup
    // would otherwise issue one API call each and share the rate limit.
    this.inFlight ??= (async () => {
      try {
        const response = await this.client.send(
          new GetSecretValueCommand({ SecretId: this.secretId }),
        );
        if (!response.SecretString) {
          throw new CredentialsError(
            `secret ${this.secretId} has no string value`,
          );
        }

        let parsed: unknown;
        try {
          parsed = JSON.parse(response.SecretString);
        } catch (error) {
          throw new CredentialsError(
            `secret ${this.secretId} is not JSON`,
            { cause: error },
          );
        }

        const secret = parsed as Partial<DatabaseSecret>;
        if (
          typeof secret.username !== "string" ||
          typeof secret.password !== "string"
        ) {
          throw new CredentialsError(
            `secret ${this.secretId} must contain string 'username' and 'password'`,
          );
        }

        const value: DatabaseSecret = {
          username: secret.username,
          password: secret.password,
          ...(typeof secret.host === "string" ? { host: secret.host } : {}),
          ...(typeof secret.port === "number" ? { port: secret.port } : {}),
        };
        this.cached = { value, at: Date.now() };
        return value;
      } finally {
        this.inFlight = undefined;
      }
    })();

    return this.inFlight;
  }

  /**
   * Drop the cache so the next read goes to Secrets Manager.
   *
   * Called when the database rejects the credential: that is the signal a rotation
   * happened, and waiting out the TTL would keep failing for no reason.
   */
  invalidate(): void {
    this.cached = undefined;
  }
}

/**
 * Postgres authentication failure — the code that means "rotated behind us".
 *
 * 28P01 is `invalid_password`, 28000 is `invalid_authorization_specification`.
 */
function isAuthFailure(error: unknown): boolean {
  const code = (error as { code?: unknown }).code;
  return code === "28P01" || code === "28000";
}

/**
 * A `password` function for `pg`, backed by Secrets Manager.
 *
 * `pg` calls this per client and caches the resolved value on that client, so a
 * long-lived connection is unaffected and each *new* connection picks up the current
 * secret.
 */
export function secretPasswordProvider(
  reader: DatabaseSecretReader,
): () => Promise<string> {
  return async () => (await reader.read()).password;
}

/**
 * Wrap a pool so an authentication failure invalidates the cached secret.
 *
 * Without this, a rotation is absorbed only after the cache expires: every
 * connection in between fails with the stale password even though the new one is
 * already available.
 */
export function onAuthFailureInvalidate(
  pool: { on(event: "error", listener: (error: unknown) => void): unknown },
  reader: DatabaseSecretReader,
): void {
  pool.on("error", (error) => {
    if (isAuthFailure(error)) reader.invalidate();
  });
}

export { isAuthFailure };
