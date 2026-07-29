/**
 * Branch coverage for resolution.ts: the glob compiler, assignment filtering, and
 * the assignee-type switch.
 *
 * Resolution decides which policies apply at all, so a wrong branch here is not a
 * masking bug — it silently swaps the whole effective policy. Each case asserts the
 * resolved outcome, not just that the line ran.
 */

import { describe, expect, it } from "vitest";
import { globMatch, globToRegex, resolve } from "../src/resolution.js";
import type { PolicyAssignment, PolicyDefinition } from "../src/types.js";

function definition(name = "p", extra: Partial<PolicyDefinition> = {}): PolicyDefinition {
  return {
    version: "1.0",
    name,
    permissions: { canQuery: true, canExport: false, readOnly: true },
    ...extra,
  };
}

function assignment(extra: Partial<PolicyAssignment> = {}): PolicyAssignment {
  return {
    version: "1.0",
    policyName: "p",
    assignee: { type: "user", identifier: "user-001" },
    scope: {},
    active: true,
    audit: { grantedBy: "admin", grantedAt: "2026-01-01T00:00:00Z", reason: "test" },
    ...extra,
  };
}

async function resolveWith(
  assignments: PolicyAssignment[],
  definitions: PolicyDefinition[] = [definition()],
  opts: {
    userId?: string;
    tenantId?: string;
    sourceConnectionId?: string;
    groups?: string[];
    roles?: string[];
  } = {},
) {
  return resolve(
    opts.userId ?? "user-001",
    opts.tenantId ?? "tenant-001",
    opts.sourceConnectionId ?? "db:production:x",
    assignments,
    new Map(definitions.map((d) => [d.name, d])),
    () => opts.groups ?? [],
    () => opts.roles ?? [],
  );
}

// ---------------------------------------------------------------------------
// globToRegex -- every character class
// ---------------------------------------------------------------------------

describe("globToRegex: every character class", () => {
  it("`*` matches within a path segment but not across `/`", () => {
    expect(globMatch("/api/*", "/api/patients")).toBe(true);
    expect(globMatch("/api/*", "/api/v1/patients")).toBe(false);
  });

  it("`**` crosses `/`", () => {
    expect(globMatch("/api/**", "/api/v1/patients")).toBe(true);
    expect(globMatch("/api/**", "/api/")).toBe(true);
  });

  it("`**/` consumes the separator, so `**` also matches an empty prefix", () => {
    // The trailing-slash consumption is what lets "**/x" match a bare "x".
    expect(globMatch("**/patients", "patients")).toBe(true);
    expect(globMatch("**/patients", "db/prod/patients")).toBe(true);
  });

  it("a trailing `**` with no slash still matches the rest", () => {
    expect(globMatch("/api/v1**", "/api/v1/patients/123")).toBe(true);
  });

  it("`?` matches exactly one non-separator character", () => {
    expect(globMatch("patient?", "patients")).toBe(true);
    expect(globMatch("patient?", "patient")).toBe(false);
    expect(globMatch("patient?", "patientss")).toBe(false);
    expect(globMatch("a?c", "a/c")).toBe(false);
  });

  it("regex metacharacters are escaped, so they match literally", () => {
    // A pattern is a glob, not a regex: `.` must not match any character, or an
    // allow-pattern would match strings the administrator never listed.
    const literals: Array<[string, string, string]> = [
      [".", "a.b", "axb"],
      ["+", "a+b", "aab"],
      ["^", "a^b", "ab"],
      ["$", "a$b", "ab"],
      ["{", "a{b", "ab"],
      ["}", "a}b", "ab"],
      ["(", "a(b", "ab"],
      [")", "a)b", "ab"],
      ["|", "a|b", "a"],
      ["[", "a[b", "ab"],
      ["]", "a]b", "ab"],
    ];

    for (const [label, pattern, shouldNotMatch] of literals) {
      expect(globMatch(pattern, pattern), `${label} matches itself`).toBe(true);
      expect(globMatch(pattern, shouldNotMatch), `${label} is literal`).toBe(false);
    }
  });

  it("a backslash is escaped rather than starting an escape sequence", () => {
    expect(globMatch("a\\b", "a\\b")).toBe(true);
    expect(globMatch("a\\b", "ab")).toBe(false);
  });

  it("the produced regex is fully anchored", () => {
    const regex = globToRegex("patients");
    expect(regex.source).toBe("^patients$");
    expect(regex.test("xpatientsx")).toBe(false);
  });

  it("an empty pattern matches only the empty string", () => {
    expect(globMatch("", "")).toBe(true);
    expect(globMatch("", "x")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Assignment activity and scope
// ---------------------------------------------------------------------------

describe("assignment filtering: active flag and expiry", () => {
  it("an inactive assignment does not resolve", async () => {
    const result = await resolveWith([assignment({ active: false })]);
    expect(result.sourceProfiles).toEqual([]);
    expect(result.permissions.canQuery).toBe(false);
  });

  it("an active assignment with no expiry resolves", async () => {
    expect((await resolveWith([assignment()])).sourceProfiles).toEqual(["p"]);
  });

  it("a future expiry resolves; empty, unparseable, now, and past do not", async () => {
    // Fail closed on every non-future value (spec §2): an assignment carries no
    // signature, so its expiry string is whatever the store hands back.
    const future = new Date(Date.now() + 86_400_000).toISOString();
    expect(
      (await resolveWith([assignment({ expiresAt: future })])).sourceProfiles,
    ).toEqual(["p"]);

    for (const bad of ["", "never", "2026-13-45T99:99:99Z", "2020-01-01T00:00:00Z"]) {
      const result = await resolveWith([assignment({ expiresAt: bad })]);
      expect(result.sourceProfiles, `expiresAt=${bad}`).toEqual([]);
    }

    const atNow = await resolveWith([assignment({ expiresAt: new Date().toISOString() })]);
    expect(atNow.sourceProfiles).toEqual([]);
  });
});

describe("assignment filtering: scope", () => {
  it("an empty scope matches any tenant and any source", async () => {
    const result = await resolveWith([assignment({ scope: {} })], [definition()], {
      tenantId: "any-tenant",
      sourceConnectionId: "kb:any:thing",
    });
    expect(result.sourceProfiles).toEqual(["p"]);
  });

  it("a scoped tenantId matches its own tenant and excludes another", async () => {
    expect(
      (
        await resolveWith([assignment({ scope: { tenantId: "tenant-001" } })], [definition()], {
          tenantId: "tenant-001",
        })
      ).sourceProfiles,
    ).toEqual(["p"]);
    expect(
      (
        await resolveWith([assignment({ scope: { tenantId: "tenant-001" } })], [definition()], {
          tenantId: "tenant-002",
        })
      ).sourceProfiles,
    ).toEqual([]);
  });

  it("a scoped sourceConnectionId matches exactly, not by glob", async () => {
    // Assignment scope is an exact-match check; only a definition's
    // sourcePatterns are globs (spec §9).
    const scoped = assignment({ scope: { sourceConnectionId: "db:production:x" } });
    expect(
      (await resolveWith([scoped], [definition()], { sourceConnectionId: "db:production:x" }))
        .sourceProfiles,
    ).toEqual(["p"]);
    expect(
      (await resolveWith([scoped], [definition()], { sourceConnectionId: "db:production:y" }))
        .sourceProfiles,
    ).toEqual([]);
  });

  it("both scope fields must match when both are set", async () => {
    const both = assignment({
      scope: { tenantId: "tenant-001", sourceConnectionId: "db:production:x" },
    });
    expect(
      (
        await resolveWith([both], [definition()], {
          tenantId: "tenant-001",
          sourceConnectionId: "db:production:x",
        })
      ).sourceProfiles,
    ).toEqual(["p"]);
    expect(
      (
        await resolveWith([both], [definition()], {
          tenantId: "tenant-001",
          sourceConnectionId: "db:production:OTHER",
        })
      ).sourceProfiles,
    ).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Assignee-type switch -- every arm, matching and not
// ---------------------------------------------------------------------------

describe("assignee matching: every type arm", () => {
  it("`user` matches the resolved user id only", async () => {
    const a = assignment({ assignee: { type: "user", identifier: "user-001" } });
    expect((await resolveWith([a], [definition()], { userId: "user-001" })).sourceProfiles).toEqual(
      ["p"],
    );
    expect((await resolveWith([a], [definition()], { userId: "user-002" })).sourceProfiles).toEqual(
      [],
    );
  });

  it("`serviceAccount` also matches on the user id", async () => {
    const a = assignment({ assignee: { type: "serviceAccount", identifier: "svc-001" } });
    expect((await resolveWith([a], [definition()], { userId: "svc-001" })).sourceProfiles).toEqual(
      ["p"],
    );
    expect((await resolveWith([a], [definition()], { userId: "svc-002" })).sourceProfiles).toEqual(
      [],
    );
  });

  it("`group` matches only a group the user is in", async () => {
    const a = assignment({ assignee: { type: "group", identifier: "analysts" } });
    expect(
      (await resolveWith([a], [definition()], { groups: ["analysts"] })).sourceProfiles,
    ).toEqual(["p"]);
    expect((await resolveWith([a], [definition()], { groups: ["other"] })).sourceProfiles).toEqual(
      [],
    );
    expect((await resolveWith([a], [definition()], { groups: [] })).sourceProfiles).toEqual([]);
  });

  it("`role` matches only a role the user holds", async () => {
    const a = assignment({ assignee: { type: "role", identifier: "data-analyst" } });
    expect(
      (await resolveWith([a], [definition()], { roles: ["data-analyst"] })).sourceProfiles,
    ).toEqual(["p"]);
    expect((await resolveWith([a], [definition()], { roles: ["other"] })).sourceProfiles).toEqual(
      [],
    );
  });

  it("an UNKNOWN assignee type never matches (fail closed)", async () => {
    // A type from a newer schema version, or a typo, must not grant access. A
    // permissive default here would hand the policy to every caller.
    for (const type of ["User", "serviceaccount", "device", "", "everyone"]) {
      const a = assignment({ assignee: { type, identifier: "user-001" } });
      const result = await resolveWith([a], [definition()], { userId: "user-001" });
      expect(result.sourceProfiles, `assignee type ${type}`).toEqual([]);
      expect(result.permissions.canQuery).toBe(false);
    }
  });

  it("a group identifier is not honoured as a user id, or vice versa", async () => {
    const groupAssignment = assignment({
      assignee: { type: "group", identifier: "user-001" },
    });
    // The identifier happens to equal the user id, but the TYPE says group and the
    // user is in no groups, so it must not match.
    expect(
      (await resolveWith([groupAssignment], [definition()], { userId: "user-001" }))
        .sourceProfiles,
    ).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Definition lookup and the resolved envelope
// ---------------------------------------------------------------------------

describe("definition lookup and the resolved envelope", () => {
  it("an assignment naming a missing definition contributes nothing", async () => {
    const result = await resolveWith([assignment({ policyName: "does-not-exist" })]);
    expect(result.sourceProfiles).toEqual([]);
    expect(result.permissions.canQuery).toBe(false);
  });

  it("a present definition is merged and a missing sibling is skipped", async () => {
    const result = await resolveWith(
      [assignment({ policyName: "p" }), assignment({ policyName: "ghost" })],
      [definition("p")],
    );
    expect(result.sourceProfiles).toEqual(["p"]);
  });

  it("definitions may be supplied as a plain object as well as a Map", async () => {
    const viaObject = await resolve(
      "user-001",
      "tenant-001",
      "db:production:x",
      [assignment()],
      { p: definition() },
    );
    expect(viaObject.sourceProfiles).toEqual(["p"]);
  });

  it("the default group/role resolvers yield no groups or roles", async () => {
    // Omitting them must not accidentally grant a group- or role-scoped policy.
    const groupScoped = await resolve(
      "user-001",
      "tenant-001",
      "db:production:x",
      [assignment({ assignee: { type: "group", identifier: "analysts" } })],
      { p: definition() },
    );
    expect(groupScoped.sourceProfiles).toEqual([]);
  });

  it("async group/role resolvers are awaited", async () => {
    const result = await resolve(
      "user-001",
      "tenant-001",
      "db:production:x",
      [assignment({ assignee: { type: "group", identifier: "analysts" } })],
      { p: definition() },
      async () => ["analysts"],
      async () => [],
    );
    expect(result.sourceProfiles).toEqual(["p"]);
  });

  it("the envelope carries the resolved identity and a ttl-derived expiry", async () => {
    const before = Date.now();
    const result = await resolve(
      "user-001",
      "tenant-001",
      "db:production:x",
      [assignment()],
      { p: definition() },
      () => [],
      () => [],
      60_000,
    );

    expect(result.version).toBe("1.0");
    expect(result.userId).toBe("user-001");
    expect(result.tenantId).toBe("tenant-001");
    expect(result.sourceConnectionId).toBe("db:production:x");
    expect(result.integrity).toEqual({ algorithm: "none", signature: "" });

    const expires = new Date(result.expiresAt).getTime();
    expect(expires).toBeGreaterThanOrEqual(before + 60_000);
    expect(expires).toBeLessThan(before + 60_000 + 5_000);
  });

  it("objectRules and limits are omitted when the merge produces none", async () => {
    const result = await resolveWith([assignment()], [definition()]);
    expect(result.objectRules).toBeUndefined();
    expect(result.limits).toBeUndefined();
  });

  it("objectRules and limits are present when the merge produces them", async () => {
    const result = await resolveWith(
      [assignment()],
      [
        definition("p", {
          objectRules: { allowedObjects: ["patients"] },
          limits: { maxResults: 10 },
        }),
      ],
    );
    expect(result.objectRules?.allowedObjects).toEqual(["patients"]);
    expect(result.limits?.maxResults).toBe(10);
  });

  it("no assignments at all resolves to deny-all", async () => {
    const result = await resolveWith([]);
    expect(result.permissions).toEqual({
      canQuery: false,
      canExport: false,
      readOnly: true,
    });
    expect(result.sourceProfiles).toEqual([]);
  });
});
