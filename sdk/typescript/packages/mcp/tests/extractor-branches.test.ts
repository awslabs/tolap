/**
 * Branch coverage for extractors.ts.
 *
 * Spec §10 draws one line: a credential that was NOT presented yields no identity,
 * and a credential that WAS presented and rejected must throw. Every branch below is
 * driven from both sides of that line, because the failure mode is silent — a caller
 * treating a null principal as anonymous converts an authentication failure into an
 * authorization decision.
 */

import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  HeaderIdentityExtractor,
  IdentityExtractionError,
  JwtIdentityExtractor,
} from "../src/extractors.js";
import type { McpRequestContext } from "../src/types.js";

const SECRET = "extractor-branch-secret";
const HASH: Record<string, string> = {
  HS256: "sha256",
  HS384: "sha384",
  HS512: "sha512",
};

function jwt(
  payload: Record<string, unknown>,
  { secret = SECRET, alg = "HS256", header }: {
    secret?: string;
    alg?: string;
    header?: Record<string, unknown>;
  } = {},
): string {
  const head = Buffer.from(
    JSON.stringify(header ?? { alg, typ: "JWT" }),
  ).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = createHmac(HASH[alg] ?? "sha256", secret)
    .update(`${head}.${body}`)
    .digest("base64url");
  return `${head}.${body}.${signature}`;
}

const bearer = (token: string): McpRequestContext => ({
  toolName: "t",
  headers: { Authorization: `Bearer ${token}` },
});

const nowSeconds = () => Math.floor(Date.now() / 1000);

// ---------------------------------------------------------------------------
// HeaderIdentityExtractor
// ---------------------------------------------------------------------------

describe("HeaderIdentityExtractor: both sides of each guard", () => {
  it("reads the default headers case-insensitively", () => {
    const extractor = new HeaderIdentityExtractor();
    const req: McpRequestContext = {
      toolName: "t",
      headers: { "X-User-Id": "u1", "x-TENANT-id": "t1" },
    };

    expect(extractor.extractUserId(req)).toBe("u1");
    expect(extractor.extractTenantId(req)).toBe("t1");
  });

  it("reads custom header names, normalized to lower case", () => {
    const extractor = new HeaderIdentityExtractor("X-Custom-User", "X-Custom-Tenant");
    const req: McpRequestContext = {
      toolName: "t",
      headers: { "x-custom-user": "u2", "X-CUSTOM-TENANT": "t2" },
    };

    expect(extractor.extractUserId(req)).toBe("u2");
    expect(extractor.extractTenantId(req)).toBe("t2");
  });

  it("returns undefined with no headers object and with an empty one", () => {
    const extractor = new HeaderIdentityExtractor();
    expect(extractor.extractUserId({ toolName: "t" })).toBeUndefined();
    expect(extractor.extractTenantId({ toolName: "t" })).toBeUndefined();
    expect(extractor.extractUserId({ toolName: "t", headers: {} })).toBeUndefined();
  });

  it("returns undefined when only the other header is present", () => {
    const extractor = new HeaderIdentityExtractor();
    const req: McpRequestContext = { toolName: "t", headers: { "x-user-id": "u1" } };

    expect(extractor.extractUserId(req)).toBe("u1");
    expect(extractor.extractTenantId(req)).toBeUndefined();
  });

  it("does not throw on any input -- headers carry no credential to reject", () => {
    // A header extractor is a trust-the-transport shim, so absent means anonymous.
    const extractor = new HeaderIdentityExtractor();
    expect(() => extractor.extractUserId({ toolName: "t", headers: {} })).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

describe("JwtIdentityExtractor construction", () => {
  it("refuses to construct with neither a secret nor an explicit opt-out", () => {
    // The insecure path must never be selectable by accident.
    expect(() => new JwtIdentityExtractor()).toThrow(/requires a signing 'secret'/);
    expect(() => new JwtIdentityExtractor({})).toThrow(/allowUnverified/);
    expect(() => new JwtIdentityExtractor({ allowUnverified: false })).toThrow(/secret/);
  });

  it("accepts a string secret and a Buffer secret equivalently", () => {
    const token = jwt({ sub: "u", tenant_id: "t" });
    const fromString = new JwtIdentityExtractor({ secret: SECRET });
    const fromBuffer = new JwtIdentityExtractor({ secret: Buffer.from(SECRET, "utf8") });

    expect(fromString.extractUserId(bearer(token))).toBe("u");
    expect(fromBuffer.extractUserId(bearer(token))).toBe("u");
  });

  it("accepts allowUnverified: true with no secret", () => {
    expect(() => new JwtIdentityExtractor({ allowUnverified: true })).not.toThrow();
  });

  it("uses the default claim names and honours overrides", () => {
    const token = jwt({ sub: "s", tenant_id: "t", uid: "custom-u", org: "custom-t" });

    const defaults = new JwtIdentityExtractor({ secret: SECRET });
    expect(defaults.extractUserId(bearer(token))).toBe("s");
    expect(defaults.extractTenantId(bearer(token))).toBe("t");

    const custom = new JwtIdentityExtractor({
      secret: SECRET,
      userIdClaim: "uid",
      tenantIdClaim: "org",
    });
    expect(custom.extractUserId(bearer(token))).toBe("custom-u");
    expect(custom.extractTenantId(bearer(token))).toBe("custom-t");
  });
});

// ---------------------------------------------------------------------------
// Presented vs absent (spec §10)
// ---------------------------------------------------------------------------

describe("§10: absent credential yields no identity", () => {
  const extractor = new JwtIdentityExtractor({ secret: SECRET });

  const absent: Array<[string, McpRequestContext]> = [
    ["no headers object", { toolName: "t" }],
    ["empty headers", { toolName: "t", headers: {} }],
    ["empty Authorization", { toolName: "t", headers: { Authorization: "" } }],
    ["whitespace Authorization", { toolName: "t", headers: { Authorization: "   " } }],
    ["bare Bearer", { toolName: "t", headers: { Authorization: "Bearer" } }],
    ["bare bearer, lower case", { toolName: "t", headers: { Authorization: "bearer" } }],
    ["Bearer with trailing space only", { toolName: "t", headers: { Authorization: "Bearer " } }],
  ];

  for (const [label, req] of absent) {
    it(`${label} is anonymous, not an error`, () => {
      expect(extractor.extractUserId(req)).toBeUndefined();
      expect(extractor.extractTenantId(req)).toBeUndefined();
    });
  }

  it("the authorization header is found case-insensitively", () => {
    const token = jwt({ sub: "u", tenant_id: "t" });
    expect(
      extractor.extractUserId({ toolName: "t", headers: { AUTHORIZATION: `Bearer ${token}` } }),
    ).toBe("u");
  });

  it("extra whitespace around a real token is tolerated", () => {
    const token = jwt({ sub: "u", tenant_id: "t" });
    expect(
      extractor.extractUserId({
        toolName: "t",
        headers: { Authorization: `  Bearer   ${token}  ` },
      }),
    ).toBe("u");
  });
});

describe("§10: a presented-and-rejected credential throws", () => {
  const extractor = new JwtIdentityExtractor({ secret: SECRET });

  it("a non-Bearer scheme throws rather than degrading to anonymous", () => {
    for (const header of ["Basic dXNlcjpwYXNz", "Token abc", "abc"]) {
      expect(() =>
        extractor.extractUserId({ toolName: "t", headers: { Authorization: header } }),
      ).toThrow(/expected 'Bearer <token>'/);
    }
  });

  it("a Bearer header with too many parts throws", () => {
    expect(() =>
      extractor.extractUserId({
        toolName: "t",
        headers: { Authorization: "Bearer a b" },
      }),
    ).toThrow(/expected 'Bearer <token>'/);
  });

  it("the Bearer scheme itself is matched case-insensitively", () => {
    const token = jwt({ sub: "u", tenant_id: "t" });
    expect(extractor.extractUserId({ toolName: "t", headers: { Authorization: `bEaReR ${token}` } })).toBe(
      "u",
    );
  });

  it("a token with the wrong number of segments throws", () => {
    for (const bad of ["onlyone", "only.two", "a.b.c.d"]) {
      expect(() => extractor.extractUserId(bearer(bad))).toThrow(
        /expected 3 dot-separated parts/,
      );
    }
  });

  it("undecodable or non-JSON segments throw", () => {
    expect(() => extractor.extractUserId(bearer("!!!.!!!.sig"))).toThrow(
      IdentityExtractionError,
    );
    const notJson = `${Buffer.from("notjson").toString("base64url")}.${Buffer.from(
      "notjson",
    ).toString("base64url")}.sig`;
    expect(() => extractor.extractUserId(bearer(notJson))).toThrow(/Malformed JWT encoding/);
  });

  it("a header or payload that is not an OBJECT throws", () => {
    // `JSON.parse("null")`, `"[]"`, and `"1"` all parse successfully, so the shape
    // check is what catches them. Without it, claim lookup on a non-object would
    // silently yield undefined and look like a missing claim.
    const cases: Array<[string, string]> = [
      ["null header", "null"],
      ["array header", "[]"],
      ["scalar header", "1"],
      ["string header", '"a"'],
    ];

    for (const [label, raw] of cases) {
      const head = Buffer.from(raw).toString("base64url");
      const body = Buffer.from(JSON.stringify({ sub: "u" })).toString("base64url");
      expect(() => extractor.extractUserId(bearer(`${head}.${body}.sig`)), label).toThrow(
        IdentityExtractionError,
      );
    }

    for (const [label, raw] of cases) {
      const head = Buffer.from(JSON.stringify({ alg: "HS256" })).toString("base64url");
      const body = Buffer.from(raw).toString("base64url");
      expect(
        () => extractor.extractUserId(bearer(`${head}.${body}.sig`)),
        `payload: ${label}`,
      ).toThrow(IdentityExtractionError);
    }
  });

  it("alg=none is rejected", () => {
    const head = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString(
      "base64url",
    );
    const body = Buffer.from(JSON.stringify({ sub: "attacker", tenant_id: "victim" })).toString(
      "base64url",
    );

    expect(() => extractor.extractUserId(bearer(`${head}.${body}.`))).toThrow(
      /algorithm not allowed: none/,
    );
  });

  it("a MISSING or non-string alg is rejected and reported as (none)", () => {
    for (const header of [{ typ: "JWT" }, { alg: 256 }, { alg: null }, { alg: ["HS256"] }]) {
      const head = Buffer.from(JSON.stringify(header)).toString("base64url");
      const body = Buffer.from(JSON.stringify({ sub: "u" })).toString("base64url");
      expect(
        () => extractor.extractUserId(bearer(`${head}.${body}.sig`)),
        JSON.stringify(header),
      ).toThrow(/algorithm not allowed: \(none\)/);
    }
  });

  it("an algorithm outside the allow-list is rejected even though it is real", () => {
    const pinned = new JwtIdentityExtractor({ secret: SECRET, algorithms: ["HS256"] });
    expect(() =>
      pinned.extractUserId(bearer(jwt({ sub: "u" }, { alg: "HS512" }))),
    ).toThrow(/algorithm not allowed: HS512/);
  });

  it("an allow-listed but NON-HMAC algorithm is rejected, not silently trusted", () => {
    // RS256 is in the caller's allow-list but this SDK has no asymmetric verifier,
    // so accepting it would mean skipping verification entirely -- the alg-confusion
    // attack. Both conditions must hold, which is why the check is an AND.
    const permissive = new JwtIdentityExtractor({
      secret: SECRET,
      algorithms: ["HS256", "RS256"],
    });
    const head = Buffer.from(JSON.stringify({ alg: "RS256" })).toString("base64url");
    const body = Buffer.from(JSON.stringify({ sub: "u" })).toString("base64url");

    expect(() => permissive.extractUserId(bearer(`${head}.${body}.sig`))).toThrow(
      /algorithm not allowed: RS256/,
    );
  });

  it("each allow-listed HMAC algorithm verifies when it is the one used", () => {
    for (const alg of ["HS256", "HS384", "HS512"]) {
      const e = new JwtIdentityExtractor({ secret: SECRET, algorithms: [alg] });
      expect(e.extractUserId(bearer(jwt({ sub: "u", tenant_id: "t" }, { alg })))).toBe("u");
    }
  });

  it("a wrong-key signature is rejected", () => {
    expect(() =>
      extractor.extractUserId(bearer(jwt({ sub: "a" }, { secret: "wrong-secret" }))),
    ).toThrow(/Invalid JWT signature/);
  });

  it("a signature of the wrong LENGTH is rejected without throwing from timingSafeEqual", () => {
    // timingSafeEqual throws on a length mismatch, so the length pre-check is what
    // turns a truncated signature into a clean IdentityExtractionError.
    const token = jwt({ sub: "u", tenant_id: "t" });
    const [head, body] = token.split(".");

    for (const sig of ["", "AA", "A".repeat(200)]) {
      let error: unknown;
      try {
        extractor.extractUserId(bearer(`${head}.${body}.${sig}`));
      } catch (e) {
        error = e;
      }
      expect(error, `signature ${sig.length} chars`).toBeInstanceOf(
        IdentityExtractionError,
      );
    }
  });

  it("an empty-string claim is treated as missing", () => {
    expect(() => extractor.extractUserId(bearer(jwt({ sub: "", tenant_id: "t" })))).toThrow(
      /Missing claim: sub/,
    );
  });

  it("an absent or non-string claim throws rather than resolving as anonymous", () => {
    // A verified token the policy engine cannot identify is not anonymous: the
    // issuer authenticated someone, so proceeding would resolve the wrong policy.
    expect(() => extractor.extractTenantId(bearer(jwt({ sub: "u" })))).toThrow(
      /Missing claim: tenant_id/,
    );
    for (const sub of [12345, null, true, { a: 1 }, ["u"]]) {
      expect(() =>
        extractor.extractUserId(bearer(jwt({ sub, tenant_id: "t" } as Record<string, unknown>))),
      ).toThrow(/Missing claim: sub/);
    }
  });

  it("every rejection is an IdentityExtractionError by name and type", () => {
    try {
      extractor.extractUserId(bearer("garbage"));
      expect.unreachable("should have thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(IdentityExtractionError);
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).name).toBe("IdentityExtractionError");
    }
  });
});

// ---------------------------------------------------------------------------
// allowUnverified
// ---------------------------------------------------------------------------

describe("allowUnverified skips signature checks only", () => {
  const unverified = new JwtIdentityExtractor({ allowUnverified: true });

  it("accepts any signature, including a bogus one", () => {
    expect(
      unverified.extractUserId(bearer(jwt({ sub: "u", tenant_id: "t" }, { secret: "anything" }))),
    ).toBe("u");
  });

  it("accepts alg=none, since the algorithm check is part of verification", () => {
    const head = Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url");
    const body = Buffer.from(JSON.stringify({ sub: "u", tenant_id: "t" })).toString("base64url");
    expect(unverified.extractUserId(bearer(`${head}.${body}.`))).toBe("u");
  });

  it("STILL enforces structure, claim presence, and the temporal claims", () => {
    // The opt-out is about the signature, not about trusting anything at all.
    expect(() => unverified.extractUserId(bearer("only.two"))).toThrow(
      /expected 3 dot-separated parts/,
    );
    expect(() => unverified.extractUserId(bearer(jwt({ tenant_id: "t" })))).toThrow(
      /Missing claim: sub/,
    );
    expect(() =>
      unverified.extractUserId(bearer(jwt({ sub: "u", tenant_id: "t", exp: 1 }))),
    ).toThrow(/expired/);
    expect(() =>
      unverified.extractUserId(
        bearer(jwt({ sub: "u", tenant_id: "t", nbf: nowSeconds() + 600 })),
      ),
    ).toThrow(/not yet valid/);
  });

  it("a secret supplied alongside allowUnverified is simply unused", () => {
    const both = new JwtIdentityExtractor({ secret: SECRET, allowUnverified: true });
    expect(both.extractUserId(bearer(jwt({ sub: "u", tenant_id: "t" }, { secret: "other" })))).toBe(
      "u",
    );
  });
});

// ---------------------------------------------------------------------------
// Temporal claims -- every type guard and both sides of each comparison
// ---------------------------------------------------------------------------

describe("temporal claims: exp and nbf", () => {
  const extractor = new JwtIdentityExtractor({ secret: SECRET });

  it("an expired exp throws and a future exp is accepted", () => {
    expect(() =>
      extractor.extractUserId(bearer(jwt({ sub: "u", tenant_id: "t", exp: 1 }))),
    ).toThrow(/expired/);
    expect(
      extractor.extractUserId(bearer(jwt({ sub: "u", tenant_id: "t", exp: nowSeconds() + 600 }))),
    ).toBe("u");
  });

  it("an exp exactly at now is still valid (the comparison is strict)", () => {
    expect(
      extractor.extractUserId(bearer(jwt({ sub: "u", tenant_id: "t", exp: nowSeconds() }))),
    ).toBe("u");
  });

  it("an absent exp means no expiry bound", () => {
    expect(extractor.extractUserId(bearer(jwt({ sub: "u", tenant_id: "t" })))).toBe("u");
  });

  it("a NON-NUMERIC or non-finite exp is ignored rather than crashing", () => {
    // Ignoring is the pre-existing cross-SDK behavior (Python checks isinstance the
    // same way). It is not a bypass of any check this SDK claims to make -- the
    // signature already proved the issuer wrote these bytes.
    for (const exp of ["1", null, true, Number.NaN, Number.POSITIVE_INFINITY, {}]) {
      expect(
        extractor.extractUserId(
          bearer(jwt({ sub: "u", tenant_id: "t", exp } as Record<string, unknown>)),
        ),
        `exp=${String(exp)}`,
      ).toBe("u");
    }
  });

  it("a future nbf throws and a past nbf is accepted", () => {
    expect(() =>
      extractor.extractUserId(bearer(jwt({ sub: "u", tenant_id: "t", nbf: nowSeconds() + 600 }))),
    ).toThrow(/not yet valid/);
    expect(
      extractor.extractUserId(bearer(jwt({ sub: "u", tenant_id: "t", nbf: nowSeconds() - 600 }))),
    ).toBe("u");
  });

  it("an nbf exactly at now is valid", () => {
    expect(
      extractor.extractUserId(bearer(jwt({ sub: "u", tenant_id: "t", nbf: nowSeconds() }))),
    ).toBe("u");
  });

  it("an absent or non-numeric nbf is ignored", () => {
    expect(extractor.extractUserId(bearer(jwt({ sub: "u", tenant_id: "t" })))).toBe("u");
    for (const nbf of ["soon", null, Number.NaN]) {
      expect(
        extractor.extractUserId(
          bearer(jwt({ sub: "u", tenant_id: "t", nbf } as Record<string, unknown>)),
        ),
      ).toBe("u");
    }
  });

  it("leeway widens both bounds by the same amount", () => {
    const lenient = new JwtIdentityExtractor({ secret: SECRET, leewaySeconds: 120 });

    // Just-expired and not-quite-valid both fall inside the leeway.
    expect(
      lenient.extractUserId(bearer(jwt({ sub: "u", tenant_id: "t", exp: nowSeconds() - 30 }))),
    ).toBe("u");
    expect(
      lenient.extractUserId(bearer(jwt({ sub: "u", tenant_id: "t", nbf: nowSeconds() + 30 }))),
    ).toBe("u");

    // Outside the leeway they are still rejected -- leeway is not "no check".
    expect(() =>
      lenient.extractUserId(bearer(jwt({ sub: "u", tenant_id: "t", exp: nowSeconds() - 600 }))),
    ).toThrow(/expired/);
    expect(() =>
      lenient.extractUserId(bearer(jwt({ sub: "u", tenant_id: "t", nbf: nowSeconds() + 600 }))),
    ).toThrow(/not yet valid/);
  });

  it("the default leeway is zero", () => {
    expect(() =>
      extractor.extractUserId(bearer(jwt({ sub: "u", tenant_id: "t", exp: nowSeconds() - 5 }))),
    ).toThrow(/expired/);
  });

  it("exp is checked before nbf when a token violates both", () => {
    // Deterministic error selection, so a caller's log does not vary run to run.
    expect(() =>
      extractor.extractUserId(
        bearer(jwt({ sub: "u", tenant_id: "t", exp: 1, nbf: nowSeconds() + 600 })),
      ),
    ).toThrow(/expired/);
  });
});
