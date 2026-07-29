/**
 * Regression tests for identity-extraction failure semantics
 * (docs/canonical-enforcement-spec.md §9).
 *
 * An extractor either returns a trustworthy principal or it fails. Returning
 * `undefined` for a token that was presented and rejected converts an
 * authentication failure into an authorization decision: the caller treats the
 * request as anonymous and resolves whatever a default assignment grants. Before
 * this change .NET threw while Python and TypeScript returned no identity on the
 * very same token -- the same expired credential, opposite outcomes.
 */

import { createHmac } from "node:crypto";
import { describe, it, expect } from "vitest";
import {
  IdentityExtractionError,
  JwtIdentityExtractor,
} from "../src/extractors.js";
import type { McpRequestContext } from "../src/types.js";

const SECRET = "test-signing-secret-value";

function signJwt(
  payload: Record<string, unknown>,
  secret: string = SECRET,
  alg = "HS256",
): string {
  const algMap: Record<string, string> = {
    HS256: "sha256",
    HS384: "sha384",
    HS512: "sha512",
  };
  const header = Buffer.from(JSON.stringify({ alg, typ: "JWT" })).toString(
    "base64url",
  );
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = createHmac(algMap[alg], secret)
    .update(`${header}.${body}`)
    .digest("base64url");
  return `${header}.${body}.${signature}`;
}

function request(headers: Record<string, string>): McpRequestContext {
  return { toolName: "test", headers };
}

function bearer(token: string): McpRequestContext {
  return request({ Authorization: `Bearer ${token}` });
}

// ---------------------------------------------------------------------------
// Absent credential: anonymous, not an error
// ---------------------------------------------------------------------------

describe("§9: no credential presented returns no identity", () => {
  const extractor = new JwtIdentityExtractor({ secret: SECRET });

  const absent: Array<[label: string, headers: Record<string, string>]> = [
    ["no Authorization header", {}],
    ["empty header", { Authorization: "" }],
    ["whitespace header", { Authorization: "   " }],
    ["scheme with no token", { Authorization: "Bearer" }],
    ["scheme with empty token", { Authorization: "Bearer " }],
  ];

  for (const [label, headers] of absent) {
    it(`treats ${label} as a legitimate anonymous request`, () => {
      expect(extractor.extractUserId(request(headers))).toBeUndefined();
      expect(extractor.extractTenantId(request(headers))).toBeUndefined();
    });
  }

  it("treats a request with no headers at all as anonymous", () => {
    expect(extractor.extractUserId({ toolName: "test" })).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Presented but invalid: throw
// ---------------------------------------------------------------------------

describe("§9: a presented-and-rejected credential throws", () => {
  const extractor = new JwtIdentityExtractor({ secret: SECRET });

  it("throws on a malformed structure", () => {
    expect(() => extractor.extractUserId(bearer("only.two"))).toThrow(
      IdentityExtractionError,
    );
  });

  it("throws on unparseable segments", () => {
    expect(() => extractor.extractUserId(bearer("aaa.bbb.ccc"))).toThrow(
      IdentityExtractionError,
    );
  });

  it("throws on a non-Bearer scheme rather than degrading to anonymous", () => {
    // A credential was presented -- just not one this extractor understands.
    expect(() =>
      extractor.extractUserId(request({ Authorization: "Basic dXNlcjpwYXNz" })),
    ).toThrow(/Bearer/);
  });

  it("throws on an algorithm outside the allow-list", () => {
    // HS512 is a real algorithm but outside the caller's allow-list, so accepting
    // it would defeat the point of pinning one.
    const pinned = new JwtIdentityExtractor({
      secret: SECRET,
      algorithms: ["HS256"],
    });
    const token = signJwt({ sub: "u", tenant_id: "t" }, SECRET, "HS512");

    expect(() => pinned.extractUserId(bearer(token))).toThrow(
      /algorithm not allowed/,
    );
  });

  it("throws when a required claim is missing", () => {
    // A verified token the policy engine cannot identify is not anonymous: the
    // issuer authenticated someone, so proceeding would resolve the wrong policy.
    const token = signJwt({ sub: "user-001" }); // no tenant_id

    expect(() => extractor.extractTenantId(bearer(token))).toThrow(
      /Missing claim: tenant_id/,
    );
  });

  it("throws when a required claim is not a string", () => {
    const token = signJwt({ sub: 12345, tenant_id: "t" });

    expect(() => extractor.extractUserId(bearer(token))).toThrow(
      /Missing claim: sub/,
    );
  });

  it("throws an IdentityExtractionError, so callers can catch the type", () => {
    const token = signJwt({ sub: "a", tenant_id: "b" }, "wrong-secret");

    expect(() => extractor.extractUserId(bearer(token))).toThrow(
      IdentityExtractionError,
    );
    try {
      extractor.extractUserId(bearer(token));
      expect.unreachable("extraction should have thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).name).toBe("IdentityExtractionError");
    }
  });
});

// ---------------------------------------------------------------------------
// nbf (not-before), spec §9
// ---------------------------------------------------------------------------

describe("§9: nbf is validated with the same leeway as exp", () => {
  const nowSeconds = () => Math.floor(Date.now() / 1000);

  it("throws for a token presented before its nbf", () => {
    // A token presented before its nbf is INVALID, not anonymous. nbf was
    // previously unchecked in every SDK, so a post-dated token -- one an issuer
    // minted for a future window -- was usable immediately.
    const extractor = new JwtIdentityExtractor({ secret: SECRET });
    const token = signJwt({
      sub: "user-001",
      tenant_id: "tenant-001",
      nbf: nowSeconds() + 600,
    });

    expect(() => extractor.extractUserId(bearer(token))).toThrow(
      /not yet valid/,
    );
  });

  it("accepts a token whose nbf has already passed", () => {
    const extractor = new JwtIdentityExtractor({ secret: SECRET });
    const token = signJwt({
      sub: "user-001",
      tenant_id: "tenant-001",
      nbf: nowSeconds() - 600,
    });

    expect(extractor.extractUserId(bearer(token))).toBe("user-001");
  });

  it("accepts an nbf inside the configured leeway", () => {
    // Ordinary clock skew must not reject a token the issuer considers valid.
    const extractor = new JwtIdentityExtractor({
      secret: SECRET,
      leewaySeconds: 120,
    });
    const token = signJwt({
      sub: "user-001",
      tenant_id: "tenant-001",
      nbf: nowSeconds() + 30,
    });

    expect(extractor.extractUserId(bearer(token))).toBe("user-001");
  });

  it("enforces nbf in unverified mode too", () => {
    const extractor = new JwtIdentityExtractor({ allowUnverified: true });
    const token = signJwt(
      { sub: "user-001", tenant_id: "tenant-001", nbf: nowSeconds() + 600 },
      "any-key",
    );

    expect(() => extractor.extractUserId(bearer(token))).toThrow(
      /not yet valid/,
    );
  });
});
