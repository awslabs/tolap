/**
 * The `declaredPurpose` query parameter, shared by every route that resolves a policy.
 *
 * Shared rather than duplicated because the two routes drifting is exactly how the gap this
 * closes came about: `GET /v1/resolve` learned about purposes and `GET /v1/resolve/preview`
 * did not, so the console could author a purpose profile it could never preview — the
 * preview resolved without a purpose, which for a purpose-scoped policy set means deny-all,
 * and a deny-all preview looks like a policy that grants nothing rather than like a route
 * that cannot see it.
 *
 * A route that resolves a policy and does not accept a purpose is not neutral about
 * purposes; it silently resolves as though none was declared.
 */

/**
 * Purpose identifiers are the `name` pattern from `schema/v1.0/policy-definition.schema.json`:
 * lowercase alphanumeric with interior hyphens, at least two characters.
 */
export const PURPOSE_ID_PATTERN = /^[a-z0-9][a-z0-9-]*[a-z0-9]$/;

/**
 * An upper bound, so an unbounded string never reaches the regex or the audit row. The
 * schema sets none; this is the server's own limit and is deliberately generous.
 */
export const PURPOSE_ID_MAX_LENGTH = 128;

/** The 400 body, identical on both routes so a client can branch on one string. */
export const PURPOSE_ID_ERROR =
  "declaredPurpose must be lowercase alphanumeric with hyphens, " +
  `at most ${PURPOSE_ID_MAX_LENGTH} characters`;

/**
 * Normalizes and validates a `declaredPurpose` query value.
 *
 * An empty or whitespace-only string normalizes to **absent**, matching how all three SDKs
 * normalize it for the signature: `""` and omitted must not behave as two different
 * declarations, or one context would have two valid signed forms.
 *
 * A malformed purpose is **rejected**, not ignored. Ignoring it would resolve without a
 * purpose — deny-all against a purpose-scoped policy set — which reads as a request that
 * worked and simply granted nothing, the hardest kind to debug.
 *
 * @returns `{ purpose }` on success, where `purpose` is `undefined` when none was declared,
 * or `{ error }` with the message to send as a 400.
 */
export function normalizeDeclaredPurpose(
  declaredPurpose: string | undefined,
): { purpose: string | undefined; error?: undefined } | { purpose?: undefined; error: string } {
  if (declaredPurpose === undefined || declaredPurpose.trim() === "") {
    return { purpose: undefined };
  }

  if (
    declaredPurpose.length > PURPOSE_ID_MAX_LENGTH ||
    !PURPOSE_ID_PATTERN.test(declaredPurpose)
  ) {
    return { error: PURPOSE_ID_ERROR };
  }

  return { purpose: declaredPurpose };
}

/**
 * Whether a thrown value is a Fastify schema-validation failure.
 *
 * Needed because a `setErrorHandler` replaces Fastify's default error response entirely, so a
 * validation error that would have been a 400 falls through to the catch-all and becomes a
 * 500 instead. Both `GET /v1/resolve` and `GET /v1/resolve/preview` declare a querystring
 * schema and both had this hole: the schemas rejected a repeated parameter correctly and the
 * response reported it as a server fault. A comment on the resolve route asserted the 400
 * outright, and nothing tested it.
 *
 * Narrowed rather than cast, matching the 429 check beside it: the handler's `error` is
 * `unknown`, and reaching into it without a check is how a non-error throw becomes a crash
 * inside the handler that exists to prevent crashes.
 */
export function isValidationError(
  error: unknown,
): error is { validation: unknown[]; message: string } {
  return (
    typeof error === "object" &&
    error !== null &&
    Array.isArray((error as { validation?: unknown }).validation)
  );
}

/**
 * The 400 body for a schema-validation failure.
 *
 * Includes Fastify's message, which describes the *caller's own query string* and so
 * discloses nothing about the server — unlike the catch-all's deliberate silence, which
 * exists because a database error or a stack trace would.
 */
export function validationErrorBody(error: { message: string }): { error: string } {
  return { error: `malformed query parameters: ${error.message}` };
}
