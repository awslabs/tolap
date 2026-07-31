/**
 * Request logging, and specifically what it must never write down.
 *
 * Enabling logs on this server is not free: the `Authorization` header is a live
 * credential on every route (a Cognito ID token on the admin port, an install credential
 * that mints signed artifacts on the resolve port), and the resolve query string names the
 * user and tenant being resolved for.
 *
 * So these tests are less about "does it log" than about the two things that would make
 * logging a downgrade: a credential in CloudWatch, and a second uncontrolled copy of the
 * data the audit log already records under access control. Both are asserted against a
 * real Fastify instance with the real logger, capturing what pino actually emits, rather
 * than against the options object — the options are the mechanism, the emitted line is the
 * property.
 */

import { describe, expect, it } from "vitest";
import Fastify from "fastify";
import { isLogLevel, loggerOptions, pathOnly, LOG_LEVELS } from "../src/logging.ts";

/** Run a request against a Fastify app wired to the real logger, capturing its output. */
async function captureLog(
  level: Parameters<typeof loggerOptions>[0]["level"],
  run: (app: ReturnType<typeof Fastify>) => Promise<unknown>,
): Promise<string[]> {
  const lines: string[] = [];
  const options = loggerOptions({ level, app: "admin" });

  const app = Fastify({
    logger:
      options === false
        ? false
        : {
            ...options,
            // A pino destination that keeps the raw text, so assertions see exactly what
            // would reach stdout and therefore CloudWatch.
            stream: {
              write(chunk: string) {
                lines.push(chunk);
              },
            },
          },
  });

  app.get("/v1/resolve", async () => ({ ok: true }));
  app.get("/v1/policies/:name", async () => ({ ok: true }));
  app.get("/boom", async () => {
    throw new Error("intentional");
  });

  try {
    await run(app);
    // Pino writes asynchronously; yield so the lines land before assertions.
    await new Promise((resolve) => setTimeout(resolve, 10));
  } finally {
    await app.close();
  }
  return lines;
}

describe("pathOnly", () => {
  it("drops the query string and keeps the path", () => {
    expect(pathOnly("/v1/resolve?userId=alice&tenantId=acme")).toBe("/v1/resolve");
  });

  it("leaves a bare path alone", () => {
    expect(pathOnly("/v1/policies")).toBe("/v1/policies");
  });

  it("handles an empty query string", () => {
    expect(pathOnly("/v1/resolve?")).toBe("/v1/resolve");
  });
});

describe("isLogLevel", () => {
  it("accepts every level it advertises", () => {
    for (const level of LOG_LEVELS) expect(isLogLevel(level)).toBe(true);
  });

  it("rejects anything else", () => {
    // A typo that fell back to a default would be fine; one that fell back to `silent`
    // would leave an operator believing they had logs.
    expect(isLogLevel("verbose")).toBe(false);
    expect(isLogLevel("INFO")).toBe(false);
    expect(isLogLevel("")).toBe(false);
  });
});

describe("loggerOptions", () => {
  it("disables logging entirely at silent rather than formatting and discarding", () => {
    // `false` removes Fastify's request/response hooks. A silent-level logger would still
    // build every line, which is real cost in a suite that issues hundreds of requests.
    expect(loggerOptions({ level: "silent", app: "admin" })).toBe(false);
  });

  it("names the app, so two listeners in one process stay distinguishable", async () => {
    const lines = await captureLog("info", async (app) => {
      await app.inject({ method: "GET", url: "/v1/policies/x" });
    });
    expect(lines.length).toBeGreaterThan(0);
    for (const line of lines) {
      expect(JSON.parse(line).app).toBe("admin");
    }
  });
});

describe("what the log must not contain", () => {
  it("never writes the Authorization header", async () => {
    const token = "Bearer eyJhbGciOiJSUzI1NiJ9.THIS-IS-A-LIVE-CREDENTIAL.sig";
    const lines = await captureLog("info", async (app) => {
      await app.inject({
        method: "GET",
        url: "/v1/policies/x",
        headers: { authorization: token },
      });
    });

    const all = lines.join("\n");
    expect(all).not.toContain("THIS-IS-A-LIVE-CREDENTIAL");
    expect(all).not.toContain(token);
    // And not merely absent because nothing was logged at all.
    expect(all).toContain("/v1/policies/x");
  });

  it("never writes the resolve query string", async () => {
    // The path is useful for operations and carries no identifiers; the query string is
    // who the policy was resolved for. The audit log records that deliberately, with
    // access control on it -- a log line is a second copy with weaker controls and a
    // different retention.
    const lines = await captureLog("info", async (app) => {
      await app.inject({
        method: "GET",
        url: "/v1/resolve?userId=alice@example.com&tenantId=acme&sourceConnectionId=db:analytics:patients",
      });
    });

    const all = lines.join("\n");
    expect(all).not.toContain("alice@example.com");
    expect(all).not.toContain("acme");
    expect(all).not.toContain("db:analytics:patients");
    expect(all).toContain("/v1/resolve");
  });

  it("still records status and latency, which is the point of enabling it", async () => {
    // The ReDoS stalled the event loop for ~15s with nothing recorded. A response line
    // needs a status code and a duration or this change bought nothing.
    const lines = await captureLog("info", async (app) => {
      await app.inject({ method: "GET", url: "/v1/policies/x" });
    });

    const response = lines
      .map((line) => JSON.parse(line))
      .find((entry) => entry.res !== undefined);

    expect(response, `no response line in:\n${lines.join("")}`).toBeDefined();
    expect(response.res.statusCode).toBe(200);
    expect(typeof response.responseTime).toBe("number");
  });

  it("logs the route pattern so latency aggregates per route", async () => {
    // `/v1/policies/:name` rather than `/v1/policies/some-specific-policy`: the concrete
    // path splinters the metric across every policy name that was ever fetched.
    const lines = await captureLog("info", async (app) => {
      await app.inject({ method: "GET", url: "/v1/policies/payroll-read-only" });
    });

    const request = lines
      .map((line) => JSON.parse(line))
      .find((entry) => entry.req !== undefined);

    expect(request.req.route).toBe("/v1/policies/:name");
  });

  it("records a failing request", async () => {
    const lines = await captureLog("info", async (app) => {
      await app.inject({ method: "GET", url: "/boom" });
    });

    const all = lines.join("\n");
    expect(all).toContain("/boom");
    // A 500 that leaves no trace is the case that makes an incident unexplainable.
    expect(all).toMatch(/"statusCode":500/);
  });
});
