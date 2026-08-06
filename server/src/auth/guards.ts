/**
 * Authorization decisions for the two listeners.
 *
 * The server runs two ports on purpose (see `index.ts`): the admin API and
 * console on one, `/v1/resolve` on the other. That lets an operator bind the
 * policy-authoring surface to a private interface while remote installs reach
 * only the resolve port -- defense in depth for the surface
 * `docs/canonical-enforcement-spec.md` section 13 says must stay restricted to
 * trusted administrators.
 *
 * Port separation is not the authorization control, though; these guards are.
 * A deployment that puts both on one interface must still be safe.
 */

import {
  AdminAuthError,
  bearerToken,
  type AdminPrincipal,
  type AdminRole,
} from "./cognito.ts";
import {
  credentialMatches,
  installIdFromCredential,
} from "./install-credential.ts";

/**
 * Refusal carrying the status the route should return.
 *
 * `401` means "authenticate"; `403` means "authenticated, not permitted". The
 * distinction matters to a console that must decide between re-running the OIDC
 * flow and telling the user they lack the role.
 */
export class AuthorizationError extends Error {
  readonly status: 401 | 403;

  // Not a constructor parameter property: strip-only type stripping (which is
  // how the server runs) cannot desugar those.
  constructor(status: 401 | 403, message: string) {
    super(message);
    this.name = "AuthorizationError";
    this.status = status;
  }
}

/** What a verifier must provide. Narrowed so tests can substitute a stub. */
export interface TokenVerifier {
  verify(token: string): Promise<AdminPrincipal>;
}

/** Roles that satisfy a requirement. `admin` satisfies everything. */
const SATISFIES: Record<AdminRole, ReadonlySet<AdminRole>> = {
  admin: new Set<AdminRole>(["admin", "auditor"]),
  auditor: new Set<AdminRole>(["auditor"]),
};

/**
 * Authenticate an admin request and require a role.
 *
 * @param required `admin` for anything that writes; `auditor` for read-only
 *                 routes, which an admin also satisfies.
 * @throws {AuthorizationError} always, rather than returning a nullable
 *                 principal. A guard that can return "no one" puts the burden on
 *                 every caller to check, and one forgotten check is an
 *                 unauthenticated write.
 */
export async function requireAdmin(
  authorization: string | undefined,
  verifier: TokenVerifier,
  required: AdminRole = "admin",
): Promise<AdminPrincipal> {
  let token: string | undefined;
  try {
    token = bearerToken(authorization);
  } catch (error) {
    // Presented but unusable. Section 11: never downgrade this to anonymous.
    throw new AuthorizationError(401, (error as Error).message);
  }

  if (token === undefined) {
    // Absent credential. On the admin surface there is no anonymous role to fall
    // back to, so this is still a refusal -- just a differently-worded one.
    throw new AuthorizationError(401, "authentication required");
  }

  let principal: AdminPrincipal;
  try {
    principal = await verifier.verify(token);
  } catch (error) {
    if (error instanceof AdminAuthError) {
      throw new AuthorizationError(401, error.message);
    }
    // A JWKS fetch failure is not an authentication decision. Surfacing it as a
    // 401 would tell an operator their token is bad when the real problem is that
    // the server cannot reach Cognito.
    throw error;
  }

  if (!SATISFIES[principal.role].has(required)) {
    throw new AuthorizationError(
      403,
      `role '${principal.role}' cannot perform this action`,
    );
  }

  return principal;
}

/** A registered install, as the store returns it. */
export interface InstallRecord {
  readonly id: string;
  readonly credentialHash: string;
  readonly revokedAt: Date | null;
}

/** Lookup the guard needs. Implemented by the Postgres store. */
export interface InstallLookup {
  getInstall(id: string): Promise<InstallRecord | undefined>;
}

/**
 * Authenticate a remote install on the resolve port.
 *
 * Every failure is a flat 401 with no detail about which stage failed: whether an
 * install id exists, whether it was revoked, and whether the secret was wrong are
 * all things an unauthenticated caller must not be able to probe.
 */
export async function requireInstall(
  authorization: string | undefined,
  lookup: InstallLookup,
): Promise<InstallRecord> {
  const unauthorized = () =>
    new AuthorizationError(401, "invalid install credential");

  let secret: string | undefined;
  try {
    secret = bearerToken(authorization);
  } catch {
    throw unauthorized();
  }
  if (secret === undefined) throw unauthorized();

  const installId = installIdFromCredential(secret);
  if (installId === undefined) throw unauthorized();

  const install = await lookup.getInstall(installId);

  // Compare even when the install is missing or revoked, so the response time
  // does not reveal which installs exist. `credentialMatches` is constant-time;
  // returning early here would not be.
  const referenceHash = install?.credentialHash ?? "0".repeat(64);
  const secretOk = credentialMatches(secret, referenceHash);

  if (!install || install.revokedAt !== null || !secretOk) {
    // Revocation must actually deny, not merely be recorded -- the same rule
    // section 12 states for assignments. A revoked install presenting a valid
    // secret is refused here.
    throw unauthorized();
  }

  return install;
}
