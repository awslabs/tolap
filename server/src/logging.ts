/**
 * Request logging, and the redaction it has to do to be safe to enable.
 *
 * Both apps ran with `logger: false`, which meant the server could not report that it was
 * degraded. That was not a theoretical gap: a quadratic regex in the SQL importer stalled
 * the event loop for ~15 seconds per request and nothing recorded it — no latency, no
 * request line, no error. The first symptom available to an operator was somebody saying
 * the agent seemed slow. A policy server that cannot say "resolve is taking 8 seconds" is
 * hard to operate and harder to trust.
 *
 * Logging this particular server is not a free action, though, which is why this is a
 * module rather than `logger: true`:
 *
 * 1. **The `Authorization` header is a credential on every route.** On the admin port it
 *    is a Cognito ID token; on the resolve port it is an install credential that mints
 *    signed policy artifacts. Pino's default request serializer does not log headers, but
 *    that is a default, and a default is one config change from being wrong. `redact`
 *    makes it explicit and survives someone enabling header logging later.
 *
 * 2. **The resolve query string is the whole request.** `?userId=&tenantId=&
 *    sourceConnectionId=` is who is being resolved for — personal identifiers and the
 *    data source involved. That is exactly what the audit log records deliberately, with
 *    access control on it; a log line is a second copy in a place with different (usually
 *    weaker) access control and a different retention. So the path is logged and the query
 *    string is dropped: correlation stays possible through the audit trail, which is the
 *    surface built for it.
 *
 * The result is a log that answers "is it slow, is it erroring, and on which route" and
 * deliberately cannot answer "for whom" — the audit log answers that one.
 */

import type { FastifyServerOptions } from "fastify";

/**
 * Header names never written to a log, matched case-insensitively.
 *
 * `cookie` and `set-cookie` are not used by either app today. They are listed because the
 * cost of listing them is nothing and the cost of a future session cookie landing in
 * CloudWatch is a credential in a log group.
 */
const REDACTED_HEADERS = [
  "authorization",
  "cookie",
  "set-cookie",
  "x-api-key",
  "proxy-authorization",
] as const;

export type LogLevel = "fatal" | "error" | "warn" | "info" | "debug" | "trace" | "silent";

export const LOG_LEVELS: readonly LogLevel[] = [
  "fatal",
  "error",
  "warn",
  "info",
  "debug",
  "trace",
  "silent",
];

export function isLogLevel(value: string): value is LogLevel {
  return (LOG_LEVELS as readonly string[]).includes(value);
}

/**
 * Strip the query string from a URL, keeping the path.
 *
 * The path is the useful half for operations — it identifies the route and groups the
 * latency — and it is the half that carries no identifiers. Returned as-is if there is no
 * `?`, so a bare path costs nothing.
 */
export function pathOnly(url: string): string {
  const query = url.indexOf("?");
  return query === -1 ? url : url.slice(0, query);
}

export interface LoggerOptions {
  readonly level: LogLevel;
  /** Names the port in every line, so two apps in one process stay distinguishable. */
  readonly app: "admin" | "resolve";
}

/**
 * The `logger` value for a Fastify instance.
 *
 * `silent` returns `false` rather than a silent logger: it disables the request/response
 * hooks entirely instead of formatting lines and discarding them, which is what a test
 * suite running hundreds of requests wants.
 */
export function loggerOptions(
  options: LoggerOptions,
): FastifyServerOptions["logger"] {
  if (options.level === "silent") return false;

  return {
    level: options.level,
    base: { app: options.app },

    // Belt and braces. Pino's default serializers already omit headers, so this is
    // insurance against a later change that adds them -- with `censor` rather than
    // `remove` so a redacted line still shows that a credential was present, which is
    // the difference between "unauthenticated call" and "call whose token we hid".
    redact: {
      paths: [
        ...REDACTED_HEADERS.flatMap((header) => [
          `req.headers.${header}`,
          `req.headers["${header}"]`,
          `request.headers.${header}`,
        ]),
        // The signing secret and DB password should never reach a log line, but if a
        // config object is ever logged wholesale, these are the keys that matter.
        "*.secret",
        "*.password",
        "*.credential",
      ],
      censor: "[redacted]",
    },

    serializers: {
      req(request: {
        method: string;
        url: string;
        routeOptions?: { url?: string };
      }) {
        return {
          method: request.method,
          // Path only: the resolve query string names the user and tenant being
          // resolved for, which belongs in the audit log rather than in two places.
          url: pathOnly(request.url),
          // The route pattern (`/v1/policies/:name`) rather than the concrete path, so
          // latency aggregates per route instead of splintering per policy name.
          ...(request.routeOptions?.url !== undefined
            ? { route: request.routeOptions.url }
            : {}),
        };
      },
      res(reply: { statusCode: number }) {
        return { statusCode: reply.statusCode };
      },
    },
  };
}
