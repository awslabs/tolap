/**
 * Database credentials from Secrets Manager.
 *
 * The behaviour that justifies this module is rotation. An environment-injected
 * password is a snapshot taken at task start: the moment the secret rotates, the
 * running task holds a password the database no longer accepts, and the failure
 * appears at the next *new* connection as an authentication error that reads like a
 * misconfiguration. Reading per connection removes that, and the tests below are
 * mostly about proving the read actually happens again.
 */

import { describe, expect, it, vi } from "vitest";
import { GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";
import {
  CredentialsError,
  DatabaseSecretReader,
  isAuthFailure,
  onAuthFailureInvalidate,
  secretPasswordProvider,
} from "../src/db/credentials.ts";
import { buildPool } from "../src/db/pool.ts";

const SECRET = {
  username: "tolap_admin",
  password: "s3cret-value",
  host: "cluster.example.rds.amazonaws.com",
  port: 5432,
};

function reader(
  responses: Array<Record<string, unknown> | Error>,
  options: { cacheTtlMs?: number } = {},
) {
  const send = vi.fn();
  for (const response of responses) {
    if (response instanceof Error) send.mockRejectedValueOnce(response);
    else send.mockResolvedValueOnce({ SecretString: JSON.stringify(response) });
  }
  return {
    instance: new DatabaseSecretReader({
      secretId: "tolap/database",
      client: { send: send as never },
      ...options,
    }),
    send,
  };
}

describe("DatabaseSecretReader", () => {
  it("reads username, password, host and port", async () => {
    const { instance } = reader([SECRET]);
    expect(await instance.read()).toEqual(SECRET);
  });

  it("requests the configured secret", async () => {
    const { instance, send } = reader([SECRET]);
    await instance.read();
    const command = send.mock.calls[0]![0] as GetSecretValueCommand;
    expect(command).toBeInstanceOf(GetSecretValueCommand);
    expect(command.input.SecretId).toBe("tolap/database");
  });

  it("omits host and port when the secret does not carry them", async () => {
    const { instance } = reader([
      { username: "u", password: "p" },
    ]);
    const secret = await instance.read();
    expect(secret.host).toBeUndefined();
    expect(secret.port).toBeUndefined();
  });

  it("caches within the TTL", async () => {
    const { instance, send } = reader([SECRET]);
    await instance.read();
    await instance.read();
    await instance.read();
    // Opening several pool connections must not mean a Secrets Manager call each --
    // that is both slow and rate-limited.
    expect(send).toHaveBeenCalledTimes(1);
  });

  it("re-reads after the TTL expires", async () => {
    const rotated = { ...SECRET, password: "rotated-value" };
    const { instance, send } = reader([SECRET, rotated], { cacheTtlMs: 0 });
    expect((await instance.read()).password).toBe("s3cret-value");
    expect((await instance.read()).password).toBe("rotated-value");
    expect(send).toHaveBeenCalledTimes(2);
  });

  it("collapses concurrent reads", async () => {
    let release: (value: unknown) => void = () => {};
    const send = vi
      .fn()
      .mockImplementation(() => new Promise((resolve) => (release = resolve)));
    const instance = new DatabaseSecretReader({
      secretId: "tolap/database",
      client: { send: send as never },
    });

    const all = Promise.all([instance.read(), instance.read(), instance.read()]);
    release({ SecretString: JSON.stringify(SECRET) });
    await all;

    // A pool filling its minimum connections at startup issues one API call, not one
    // per connection.
    expect(send).toHaveBeenCalledTimes(1);
  });

  it("picks up a rotation immediately after invalidate", async () => {
    const rotated = { ...SECRET, password: "rotated-value" };
    const { instance } = reader([SECRET, rotated]);

    expect((await instance.read()).password).toBe("s3cret-value");
    instance.invalidate();
    // This is the path an authentication failure takes: without it a rotation is
    // absorbed only when the cache expires, and every connection until then fails
    // with a password that is already known to be wrong.
    expect((await instance.read()).password).toBe("rotated-value");
  });

  describe("failure handling", () => {
    it("throws when the secret has no string value", async () => {
      const send = vi.fn().mockResolvedValue({});
      const instance = new DatabaseSecretReader({
        secretId: "tolap/database",
        client: { send: send as never },
      });
      await expect(instance.read()).rejects.toThrow(CredentialsError);
    });

    it("throws when the secret is not JSON", async () => {
      const send = vi.fn().mockResolvedValue({ SecretString: "not json" });
      const instance = new DatabaseSecretReader({
        secretId: "tolap/database",
        client: { send: send as never },
      });
      await expect(instance.read()).rejects.toThrow(/not JSON/);
    });

    it.each([
      { username: "u" },
      { password: "p" },
      { username: 1, password: "p" },
      {},
    ])("throws when required fields are missing or wrong-typed: %o", async (body) => {
      const { instance } = reader([body as Record<string, unknown>]);
      await expect(instance.read()).rejects.toThrow(
        /must contain string 'username' and 'password'/,
      );
    });

    it("names the secret in the error", async () => {
      const { instance } = reader([{}]);
      await expect(instance.read()).rejects.toThrow(/tolap\/database/);
    });

    it("does not cache a failure", async () => {
      const { instance } = reader([
        new Error("ThrottlingException"),
        SECRET,
      ]);
      await expect(instance.read()).rejects.toThrow();
      // A throttle must not pin a failure for the cache lifetime.
      expect((await instance.read()).password).toBe("s3cret-value");
    });

    it("propagates the underlying AWS error", async () => {
      const cause = new Error("AccessDeniedException");
      const { instance } = reader([cause]);
      await expect(instance.read()).rejects.toThrow("AccessDeniedException");
    });
  });
});

describe("secretPasswordProvider", () => {
  it("returns the current password each time pg asks", async () => {
    const rotated = { ...SECRET, password: "rotated-value" };
    const { instance } = reader([SECRET, rotated]);
    const provider = secretPasswordProvider(instance);

    expect(await provider()).toBe("s3cret-value");
    instance.invalidate();
    // pg calls the password function per new client, so the next connection after a
    // rotation authenticates with the new value -- no restart, no redeploy.
    expect(await provider()).toBe("rotated-value");
  });

  it("propagates a read failure rather than returning an empty password", async () => {
    // An empty string would be offered to the database as a credential and rejected,
    // turning a Secrets Manager problem into a confusing authentication error.
    const { instance } = reader([new Error("AccessDeniedException")]);
    await expect(secretPasswordProvider(instance)()).rejects.toThrow();
  });
});

describe("isAuthFailure", () => {
  it.each(["28P01", "28000"])("recognizes Postgres code %s", (code) => {
    expect(isAuthFailure({ code })).toBe(true);
  });

  it.each(["57P01", "08006", undefined])(
    "does not treat %s as an auth failure",
    (code) => {
      // A dropped connection or a shutdown is not a rotation, and invalidating the
      // cache on every error would defeat the cache entirely.
      expect(isAuthFailure({ code })).toBe(false);
    },
  );
});

describe("onAuthFailureInvalidate", () => {
  function fakePool() {
    const listeners: Array<(error: unknown) => void> = [];
    return {
      on(_event: "error", listener: (error: unknown) => void) {
        listeners.push(listener);
        return this;
      },
      emit(error: unknown) {
        for (const listener of listeners) listener(error);
      },
    };
  }

  it("clears the cache when the database rejects the credential", async () => {
    const rotated = { ...SECRET, password: "rotated-value" };
    const { instance } = reader([SECRET, rotated]);
    const pool = fakePool();
    onAuthFailureInvalidate(pool, instance);

    expect((await instance.read()).password).toBe("s3cret-value");
    pool.emit({ code: "28P01" });
    expect((await instance.read()).password).toBe("rotated-value");
  });

  it("leaves the cache alone for unrelated errors", async () => {
    const { instance, send } = reader([SECRET]);
    const pool = fakePool();
    onAuthFailureInvalidate(pool, instance);

    await instance.read();
    pool.emit({ code: "57P01" }); // admin shutdown
    await instance.read();
    expect(send).toHaveBeenCalledTimes(1);
  });
});

describe("connection pool bounds", () => {
  /**
   * The pool is now multiplied by the task count.
   *
   * The service runs two tasks and autoscales to six, and every task opens its own pool.
   * So `pg`'s default of 10 clients is really "up to 10 per task" -- and Aurora Serverless
   * v2 at the 0.5 ACU floor this cluster starts from allows on the order of 90. Getting
   * this wrong trades a latency problem for connection exhaustion, which fails worse: a
   * task that cannot get a connection cannot resolve policy at all.
   *
   * `infra/test/infra.test.ts` asserts the other half -- that maxCapacity times this value
   * stays inside that budget.
   */
  const withEnv = async <T>(
    value: string | undefined,
    run: () => Promise<T> | T,
  ): Promise<T> => {
    const previous = process.env.DATABASE_POOL_MAX;
    if (value === undefined) delete process.env.DATABASE_POOL_MAX;
    else process.env.DATABASE_POOL_MAX = value;
    try {
      return await run();
    } finally {
      if (previous === undefined) delete process.env.DATABASE_POOL_MAX;
      else process.env.DATABASE_POOL_MAX = previous;
    }
  };

  it("bounds the pool and fails fast when it is saturated", async () => {
    const { pool } = await withEnv(undefined, () =>
      buildPool({ kind: "url", url: "postgres://u:p@127.0.0.1:5432/db" }),
    );
    try {
      const options = (pool as unknown as { options: Record<string, unknown> }).options;
      expect(options.max).toBe(10);
      // `pg` defaults to NO connection timeout, so a request arriving with the pool
      // saturated waits forever: it holds a socket and a Fastify handler and never
      // returns, which is how a busy service becomes an unresponsive one. Failing in
      // seconds gives the caller something it can retry and lets the 5xx alarm see it.
      expect(options.connectionTimeoutMillis).toBe(5_000);
      // Return connections between requests rather than a scaled-out fleet sitting on its
      // whole allocation at idle.
      expect(options.idleTimeoutMillis).toBe(30_000);
    } finally {
      await pool.end();
    }
  });

  it("honours an explicit pool ceiling", async () => {
    const { pool } = await withEnv("4", () =>
      buildPool({ kind: "url", url: "postgres://u:p@127.0.0.1:5432/db" }),
    );
    try {
      expect((pool as unknown as { options: { max: number } }).options.max).toBe(4);
    } finally {
      await pool.end();
    }
  });

  it("refuses a nonsensical pool ceiling rather than falling back", async () => {
    // A silent fallback to 10 on a typo is how a deployment that meant to lower its
    // footprint keeps the old one, and only finds out when Aurora starts refusing
    // connections under load.
    for (const bad of ["0", "-1", "abc", "2.5"]) {
      await expect(
        withEnv(bad, () =>
          buildPool({ kind: "url", url: "postgres://u:p@127.0.0.1:5432/db" }),
        ),
      ).rejects.toThrow(/DATABASE_POOL_MAX/);
    }
  });
});
