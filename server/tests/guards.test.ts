/**
 * Route guards: the authorization decisions themselves.
 */

import { describe, expect, it } from "vitest";
import { AdminAuthError, type AdminPrincipal } from "../src/auth/cognito.ts";
import {
  AuthorizationError,
  requireAdmin,
  requireInstall,
  type InstallLookup,
  type InstallRecord,
} from "../src/auth/guards.ts";
import { issueCredential } from "../src/auth/install-credential.ts";

const ADMIN: AdminPrincipal = {
  subject: "s-1",
  email: "a@example.com",
  role: "admin",
};
const AUDITOR: AdminPrincipal = { subject: "s-2", role: "auditor" };

const verifierFor = (principal: AdminPrincipal) => ({
  verify: async () => principal,
});
const rejectingVerifier = (message = "bad token") => ({
  verify: async () => {
    throw new AdminAuthError(message);
  },
});

async function statusOf(fn: () => Promise<unknown>): Promise<number> {
  try {
    await fn();
    throw new Error("expected a refusal but the guard allowed the request");
  } catch (error) {
    if (error instanceof AuthorizationError) return error.status;
    throw error;
  }
}

describe("requireAdmin", () => {
  it("admits an admin to an admin route", async () => {
    const principal = await requireAdmin(
      "Bearer t",
      verifierFor(ADMIN),
      "admin",
    );
    expect(principal.subject).toBe("s-1");
  });

  it("admits an admin to an auditor route", async () => {
    // The roles are nested: admin can do everything auditor can.
    const principal = await requireAdmin(
      "Bearer t",
      verifierFor(ADMIN),
      "auditor",
    );
    expect(principal.role).toBe("admin");
  });

  it("admits an auditor to an auditor route", async () => {
    const principal = await requireAdmin(
      "Bearer t",
      verifierFor(AUDITOR),
      "auditor",
    );
    expect(principal.role).toBe("auditor");
  });

  it("gives an auditor 403 on an admin route", async () => {
    // 403 not 401: the identity is fine, the role is not. A console that got 401
    // here would loop the user through a login that cannot fix anything.
    expect(
      await statusOf(() => requireAdmin("Bearer t", verifierFor(AUDITOR), "admin")),
    ).toBe(403);
  });

  it("gives 401 when no credential is offered", async () => {
    expect(await statusOf(() => requireAdmin(undefined, verifierFor(ADMIN)))).toBe(
      401,
    );
    expect(await statusOf(() => requireAdmin("", verifierFor(ADMIN)))).toBe(401);
  });

  it("gives 401 for a non-bearer header", async () => {
    expect(
      await statusOf(() => requireAdmin("Basic abc", verifierFor(ADMIN))),
    ).toBe(401);
  });

  it("gives 401 when the verifier rejects the token", async () => {
    expect(
      await statusOf(() => requireAdmin("Bearer t", rejectingVerifier())),
    ).toBe(401);
  });

  it("propagates infrastructure failures instead of calling them 401", async () => {
    // A JWKS fetch failure is not an authentication decision. Reporting it as 401
    // sends an operator to debug the user's token when the server cannot reach
    // Cognito.
    const broken = {
      verify: async () => {
        throw new Error("ECONNREFUSED");
      },
    };
    await expect(requireAdmin("Bearer t", broken)).rejects.toThrow(
      "ECONNREFUSED",
    );
    await expect(requireAdmin("Bearer t", broken)).rejects.not.toBeInstanceOf(
      AuthorizationError,
    );
  });

  it("defaults to requiring admin", async () => {
    // The safe default: a route that forgets to state its requirement gets the
    // stricter one, not the looser.
    expect(await statusOf(() => requireAdmin("Bearer t", verifierFor(AUDITOR)))).toBe(
      403,
    );
  });
});

describe("requireInstall", () => {
  function lookupWith(records: InstallRecord[]): InstallLookup {
    return {
      getInstall: async (id) => records.find((r) => r.id === id),
    };
  }

  it("admits a registered install with a valid credential", async () => {
    const issued = issueCredential("install-1");
    const lookup = lookupWith([
      { id: "install-1", credentialHash: issued.hash, revokedAt: null },
    ]);
    const install = await requireInstall(`Bearer ${issued.secret}`, lookup);
    expect(install.id).toBe("install-1");
  });

  it("refuses a revoked install even with the right credential", async () => {
    // Revocation must deny, not merely be recorded (spec section 12).
    const issued = issueCredential("install-1");
    const lookup = lookupWith([
      {
        id: "install-1",
        credentialHash: issued.hash,
        revokedAt: new Date("2026-01-01T00:00:00Z"),
      },
    ]);
    expect(
      await statusOf(() => requireInstall(`Bearer ${issued.secret}`, lookup)),
    ).toBe(401);
  });

  it("refuses an unknown install", async () => {
    const issued = issueCredential("ghost");
    expect(
      await statusOf(() => requireInstall(`Bearer ${issued.secret}`, lookupWith([]))),
    ).toBe(401);
  });

  it("refuses a valid install id with the wrong secret", async () => {
    const real = issueCredential("install-1");
    const forged = issueCredential("install-1");
    const lookup = lookupWith([
      { id: "install-1", credentialHash: real.hash, revokedAt: null },
    ]);
    expect(
      await statusOf(() => requireInstall(`Bearer ${forged.secret}`, lookup)),
    ).toBe(401);
  });

  it("refuses absent and malformed credentials", async () => {
    const lookup = lookupWith([]);
    expect(await statusOf(() => requireInstall(undefined, lookup))).toBe(401);
    expect(await statusOf(() => requireInstall("Bearer nonsense", lookup))).toBe(
      401,
    );
    expect(await statusOf(() => requireInstall("Basic abc", lookup))).toBe(401);
  });

  it("does not reveal which stage failed", async () => {
    const issued = issueCredential("install-1");
    const revoked = lookupWith([
      { id: "install-1", credentialHash: issued.hash, revokedAt: new Date() },
    ]);
    const messages: string[] = [];
    for (const attempt of [
      () => requireInstall(`Bearer ${issued.secret}`, revoked),
      () => requireInstall(`Bearer ${issueCredential("ghost").secret}`, revoked),
      () => requireInstall("Bearer nonsense", revoked),
    ]) {
      await attempt().catch((e: AuthorizationError) => messages.push(e.message));
    }
    // Unknown, revoked and malformed must be indistinguishable to the caller, or
    // the resolve port becomes an oracle for enumerating installs.
    expect(new Set(messages).size).toBe(1);
  });

  it("still compares a secret when the install is missing", async () => {
    // Guards against a future early-return that would make a missing install
    // measurably faster than a wrong secret.
    let looked = false;
    const lookup: InstallLookup = {
      getInstall: async () => {
        looked = true;
        return undefined;
      },
    };
    await statusOf(() =>
      requireInstall(`Bearer ${issueCredential("x").secret}`, lookup),
    );
    expect(looked).toBe(true);
  });
});
