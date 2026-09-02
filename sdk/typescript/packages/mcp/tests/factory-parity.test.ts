/**
 * The factory must forward **every** option the wrappers accept.
 *
 * The factory is the documented composition root, so an option it does not declare, or
 * declares and drops, is an option that does nothing for anyone following the
 * recommended path. Two such bugs shipped:
 *
 * - `hashSalt` was declared nowhere on the factory and forwarded to neither wrapper, so
 *   a factory-built wrapper hashed **unsalted** even where the deployment had configured
 *   a salt. A deliberate confidentiality control degraded to a plain digest with nothing
 *   in the output to indicate it — the dangerous kind, because it fails *open* and
 *   silently.
 * - `toolActionCategories` / `httpActionCategories` were likewise absent, so a
 *   factory-built wrapper classified nothing and denied **every** call under a purpose
 *   that constrains actions. Fail-closed and loud, but it made purpose binding
 *   unreachable through the recommended path.
 *
 * Both are the same shape, so this file checks the shape rather than the two instances:
 *
 * 1. **Compile-time exhaustiveness.** `Record<keyof Required<T>, true>` requires every
 *    key and forbids any other, so adding an option to a wrapper without adding it to
 *    the table below fails to compile.
 * 2. **Runtime key-set parity.** The factory's declared keys must cover the union of
 *    both wrappers' keys, and the only extra it may own is `fetchFn`.
 * 3. **Runtime value forwarding.** Declaring an option is not forwarding one. A fully
 *    populated factory is built and each produced wrapper's own options are compared,
 *    so a newly-added-but-unforwarded option fails without anyone writing a case for it.
 * 4. **Behavioural pairs** for the three options that were missing, each with an allow
 *    *before* the denial — without the allow, a factory forwarding nothing still
 *    satisfies a denial assertion via the unclassified-tool rule, for the wrong reason.
 */

import { describe, expect, it } from "vitest";

import {
  UNDECLARED_CATEGORY_REASON,
  applyMask,
  buildSecurityContext,
  signContext,
  type ActionCategoryMap,
  type EffectivePolicy,
  type PurposeProfile,
  type SecurityContext,
} from "@aws/tolap-core";
import {
  SecureToolFactory,
  type SecureToolFactoryOptions,
} from "../src/factory.js";
import type { SecureContextWrapperOptions } from "../src/context-wrapper.js";
import type { FetchLike, SecureHttpWrapperOptions } from "../src/http-wrapper.js";

const KEY = "factory-parity-key";
const SALT = "deployment-salt-not-a-policy-field";

// ---------------------------------------------------------------------------
// (1) Compile-time exhaustive key tables
// ---------------------------------------------------------------------------
//
// `Record<keyof Required<T>, true>` is total in both directions: a missing key is a
// compile error and an unknown key is a compile error. So these three tables cannot
// drift from the types they mirror without breaking the build -- which is the point.
// A hand-written string array would silently go stale, which is how the two bugs above
// survived.

const CONTEXT_WRAPPER_KEYS: Record<keyof Required<SecureContextWrapperOptions>, true> = {
  signingKey: true,
  enforceSignatures: true,
  enforceExpiry: true,
  allowedTools: true,
  hashSalt: true,
  allowUnenforceableShapes: true,
  toolActionCategories: true,
};

const HTTP_WRAPPER_KEYS: Record<keyof Required<SecureHttpWrapperOptions>, true> = {
  signingKey: true,
  enforceSignatures: true,
  enforceExpiry: true,
  baseUrl: true,
  hashSalt: true,
  httpActionCategories: true,
};

const FACTORY_KEYS: Record<keyof Required<SecureToolFactoryOptions>, true> = {
  signingKey: true,
  enforceSignatures: true,
  enforceExpiry: true,
  fetchFn: true,
  baseUrl: true,
  allowedTools: true,
  allowUnenforceableShapes: true,
  hashSalt: true,
  toolActionCategories: true,
  httpActionCategories: true,
};

/**
 * The one option the factory owns that no wrapper accepts.
 *
 * `fetchFn` is a *constructor argument* to `SecureHttpToolWrapper`, not an option on
 * it, so the factory has to carry it separately. Naming the exception here is what
 * keeps the parity assertion below strict: any other extra key is a finding.
 */
const FACTORY_ONLY_KEYS = ["fetchFn"];

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const CONSTRAINED: PurposeProfile = {
  purposeId: "campaign-x-overlap",
  description: "Aggregate segment overlap only.",
  allowedActions: ["aggregate_overlap", "count_segments"],
  prohibitedActions: ["export_pii"],
};

const TOOL_MAP: ActionCategoryMap = {
  segment_overlap: "aggregate_overlap",
  export_csv: "export_pii",
};

const HTTP_MAP: ActionCategoryMap = {
  "GET /segments/*": "aggregate_overlap",
  "GET /export/*": "export_pii",
};

function policy(
  sourceConnectionId: string,
  profile?: PurposeProfile,
  objectRules?: EffectivePolicy["objectRules"],
): EffectivePolicy {
  const now = new Date();
  return {
    version: "1.0",
    userId: "factory-user",
    tenantId: "factory-tenant",
    sourceConnectionId,
    resolvedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 3_600_000).toISOString(),
    sourceProfiles: ["factory-parity"],
    permissions: { canQuery: true, readOnly: true },
    ...(objectRules === undefined ? {} : { objectRules }),
    ...(profile === undefined ? {} : { purposeProfile: profile }),
    integrity: { algorithm: "none", signature: "" },
  };
}

function signed(p: EffectivePolicy): SecurityContext {
  return signContext(
    buildSecurityContext(
      p.userId,
      p.tenantId,
      p,
      3_600_000,
      undefined,
      p.purposeProfile?.purposeId,
    ),
    KEY,
  );
}

const okFetch: FetchLike = async () => ({
  ok: true,
  status: 200,
  json: async () => ({ email: "alice@example.com" }),
});

/** Every path reachable by GET, so the endpoint rules never do the denying. */
const ALL_GET: EffectivePolicy["objectRules"] = {
  endpointRules: { allowedEndpoints: ["/*", "/**"], allowedMethods: ["GET"] },
};

/** A factory with every option populated, for the forwarding comparison. */
function fullyConfiguredFactory(): {
  factory: SecureToolFactory;
  options: Required<SecureToolFactoryOptions>;
} {
  const options: Required<SecureToolFactoryOptions> = {
    signingKey: KEY,
    enforceSignatures: true,
    enforceExpiry: true,
    fetchFn: okFetch,
    baseUrl: "https://factory.test",
    allowedTools: ["segment_overlap"],
    allowUnenforceableShapes: true,
    hashSalt: SALT,
    toolActionCategories: TOOL_MAP,
    httpActionCategories: HTTP_MAP,
  };
  return { factory: new SecureToolFactory(options), options };
}

/** A produced wrapper's own options, for comparison. Test-only reach-in. */
function optionsOf(wrapper: unknown): Record<string, unknown> {
  return (wrapper as { options: Record<string, unknown> }).options;
}

// ---------------------------------------------------------------------------
// (2) Key-set parity
// ---------------------------------------------------------------------------

describe("the factory declares every option the wrappers accept", () => {
  it("the key tables are non-empty, so the comparisons below are not vacuous", () => {
    expect(Object.keys(CONTEXT_WRAPPER_KEYS).length).toBeGreaterThan(0);
    expect(Object.keys(HTTP_WRAPPER_KEYS).length).toBeGreaterThan(0);
    expect(Object.keys(FACTORY_KEYS).length).toBeGreaterThan(0);
  });

  it("covers every SecureContextWrapperOptions key", () => {
    const missing = Object.keys(CONTEXT_WRAPPER_KEYS).filter(
      (key) => !Object.prototype.hasOwnProperty.call(FACTORY_KEYS, key),
    );

    expect(
      missing,
      `SecureToolFactoryOptions is missing ${missing.join(", ")}; a factory-produced ` +
        "context wrapper cannot be configured with them",
    ).toEqual([]);
  });

  it("covers every SecureHttpWrapperOptions key", () => {
    const missing = Object.keys(HTTP_WRAPPER_KEYS).filter(
      (key) => !Object.prototype.hasOwnProperty.call(FACTORY_KEYS, key),
    );

    expect(
      missing,
      `SecureToolFactoryOptions is missing ${missing.join(", ")}; a factory-produced ` +
        "HTTP wrapper cannot be configured with them",
    ).toEqual([]);
  });

  it("declares nothing beyond the two wrappers except fetchFn", () => {
    // The other direction. An option only the factory understands is either dead
    // configuration or a control the wrappers were supposed to gain and did not.
    const wrapperKeys = new Set([
      ...Object.keys(CONTEXT_WRAPPER_KEYS),
      ...Object.keys(HTTP_WRAPPER_KEYS),
    ]);
    const extra = Object.keys(FACTORY_KEYS).filter(
      (key) => !wrapperKeys.has(key) && !FACTORY_ONLY_KEYS.includes(key),
    );

    expect(extra, `SecureToolFactoryOptions declares unforwardable ${extra.join(", ")}`)
      .toEqual([]);
  });

  it("names the three options whose absence was the bug", () => {
    // Pinned individually as well as covered by the sweep, so a regression names itself
    // rather than appearing as an anonymous key-set difference.
    for (const key of ["hashSalt", "toolActionCategories", "httpActionCategories"]) {
      expect(Object.prototype.hasOwnProperty.call(FACTORY_KEYS, key), key).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// (3) Value forwarding -- declaring is not forwarding
// ---------------------------------------------------------------------------

describe("the factory forwards every option it declares", () => {
  it("forwards every SecureContextWrapperOptions key to the context wrapper", () => {
    // The generic assertion: a future option added to the factory and the wrapper but
    // not to `createContextTool` fails here without anyone writing a case for it. That
    // is exactly the gap `hashSalt` fell into.
    const { factory, options } = fullyConfiguredFactory();
    const forwarded = optionsOf(factory.createContextTool());

    for (const key of Object.keys(CONTEXT_WRAPPER_KEYS)) {
      expect(
        forwarded[key],
        `createContextTool dropped '${key}'`,
      ).toEqual((options as Record<string, unknown>)[key]);
    }
  });

  it("forwards every SecureHttpWrapperOptions key to the HTTP wrapper", () => {
    const { factory, options } = fullyConfiguredFactory();
    const forwarded = optionsOf(factory.createHttpTool());

    for (const key of Object.keys(HTTP_WRAPPER_KEYS)) {
      expect(
        forwarded[key],
        `createHttpTool dropped '${key}'`,
      ).toEqual((options as Record<string, unknown>)[key]);
    }
  });

  it("forwards nothing that was not configured", () => {
    // The other direction, and it matters for the same reason absent-versus-empty does
    // elsewhere: a factory that materialized `hashSalt: undefined` would be harmless,
    // but one that materialized `toolActionCategories: {}` would turn "unconfigured"
    // into "configured to classify nothing" -- which reads the same and is a different
    // statement about what the deployment intended.
    const minimal = new SecureToolFactory({ signingKey: KEY, fetchFn: okFetch });

    // `enforceSignatures`, `enforceExpiry` and `allowUnenforceableShapes` are excluded
    // because each wrapper materializes its own documented default for them in its
    // constructor — they are always present regardless of what the factory sent, and
    // that is the wrappers' behaviour rather than a forwarding artifact. The remaining
    // options have no default, so absent has to stay absent.
    const context = optionsOf(minimal.createContextTool());
    for (const key of ["hashSalt", "toolActionCategories", "allowedTools"]) {
      expect(key in context, `createContextTool materialized '${key}'`).toBe(false);
    }
    // And the wrapper's own defaults ARE present, so the exclusion above is a real
    // distinction rather than a way of not checking anything.
    expect(context.allowUnenforceableShapes).toBe(false);

    const http = optionsOf(minimal.createHttpTool());
    for (const key of ["hashSalt", "httpActionCategories", "baseUrl"]) {
      expect(key in http, `createHttpTool materialized '${key}'`).toBe(false);
    }
  });

  it("createTool dispatches to a wrapper carrying the same options", () => {
    // `createTool` is the documented entry point; the two `create*Tool` methods are the
    // ones the tests above drive, so this checks the dispatch path forwards as well.
    const { factory, options } = fullyConfiguredFactory();

    const dbTool = factory.createTool(
      signed(policy("db:marketing:customer_segments", CONSTRAINED)),
    );
    expect(optionsOf(dbTool).toolActionCategories).toEqual(options.toolActionCategories);
    expect(optionsOf(dbTool).hashSalt).toBe(SALT);

    const apiTool = factory.createTool(
      signed(policy("api:purpose:test", CONSTRAINED, ALL_GET)),
    );
    expect(optionsOf(apiTool).httpActionCategories).toEqual(options.httpActionCategories);
    expect(optionsOf(apiTool).hashSalt).toBe(SALT);
  });
});

// ---------------------------------------------------------------------------
// (4) Behaviour -- allow FIRST, then the denial
// ---------------------------------------------------------------------------

describe("a factory-built context tool enforces the purpose", () => {
  const factory = (): SecureToolFactory =>
    new SecureToolFactory({
      signingKey: KEY,
      fetchFn: okFetch,
      toolActionCategories: TOOL_MAP,
      httpActionCategories: HTTP_MAP,
    });

  it("ALLOWS a permitted tool -- so the denial below is not a blanket refusal", () => {
    // Stated first and deliberately: without it, a factory forwarding nothing still
    // satisfies the denial assertion, because an unclassified tool is denied too. The
    // allow is the only assertion that can distinguish "the map arrived" from "the map
    // is missing and everything is refused".
    const tool = factory().createContextTool();

    expect(
      tool.preExecute(signed(policy("db:marketing:customer_segments", CONSTRAINED)), {
        toolName: "segment_overlap",
      }),
    ).toEqual({ allowed: true });
  });

  it("denies a prohibited tool with the prohibition reason, not the undeclared one", () => {
    // The reason distinguishes the two failure modes: `export_pii is prohibited` proves
    // the map was consulted, whereas `action category not declared for tool` would prove
    // the opposite while still being a denial.
    const tool = factory().createContextTool();

    const result = tool.preExecute(
      signed(policy("db:marketing:customer_segments", CONSTRAINED)),
      { toolName: "export_csv" },
    );

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe(
      "action 'export_pii' is prohibited under purpose 'campaign-x-overlap'",
    );
  });

  it("still fails closed when a map genuinely is not configured", () => {
    // Correct behaviour worth keeping: a purpose that constrains actions plus a wrapper
    // that classifies nothing is a denial, and the reason names the configuration gap
    // rather than the policy.
    const tool = new SecureToolFactory({ signingKey: KEY }).createContextTool();

    expect(
      tool.preExecute(signed(policy("db:marketing:customer_segments", CONSTRAINED)), {
        toolName: "segment_overlap",
      }).reason,
    ).toBe(UNDECLARED_CATEGORY_REASON);
  });

  it("a purpose-agnostic policy is unaffected either way", () => {
    const withMap = factory().createContextTool();
    const withoutMap = new SecureToolFactory({ signingKey: KEY }).createContextTool();
    const context = signed(policy("db:marketing:customer_segments"));

    expect(withMap.preExecute(context, { toolName: "export_csv" })).toEqual({
      allowed: true,
    });
    expect(withoutMap.preExecute(context, { toolName: "export_csv" })).toEqual({
      allowed: true,
    });
  });
});

describe("a factory-built HTTP tool enforces the purpose", () => {
  const factory = (): SecureToolFactory =>
    new SecureToolFactory({
      signingKey: KEY,
      fetchFn: okFetch,
      httpActionCategories: HTTP_MAP,
    });

  it("ALLOWS a permitted path first", async () => {
    const tool = factory().createHttpTool();

    expect(
      await tool.request(signed(policy("api:purpose:test", CONSTRAINED, ALL_GET)), {
        method: "GET",
        path: "/segments/overlap",
      }),
    ).toEqual({ email: "alice@example.com" });
  });

  it("denies a prohibited path with the prohibition reason", async () => {
    const tool = factory().createHttpTool();

    await expect(
      tool.request(signed(policy("api:purpose:test", CONSTRAINED, ALL_GET)), {
        method: "GET",
        path: "/export/all.csv",
      }),
    ).rejects.toThrow(
      /action 'export_pii' is prohibited under purpose 'campaign-x-overlap'/,
    );
  });

  it("still fails closed when no map is configured", async () => {
    const tool = new SecureToolFactory({ signingKey: KEY, fetchFn: okFetch }).createHttpTool();

    await expect(
      tool.request(signed(policy("api:purpose:test", CONSTRAINED, ALL_GET)), {
        method: "GET",
        path: "/segments/overlap",
      }),
    ).rejects.toThrow(UNDECLARED_CATEGORY_REASON);
  });
});

describe("a factory-built tool masks with the configured salt", () => {
  const MASKED: EffectivePolicy["objectRules"] = {
    fieldRules: {
      maskedFields: [{ field: "email", maskType: "hash", parameters: { algorithm: "sha256" } }],
    },
  };

  it("the salted pseudonym differs from the unsalted one", async () => {
    // The reference values come from `applyMask`, the control that actually computes the
    // digest, so this compares the factory's output against the SDK's own arithmetic
    // rather than against a hardcoded hash that could be regenerated to match a bug.
    const unsaltedPseudonym = applyMask("alice@example.com", {
      field: "email",
      maskType: "hash",
      parameters: { algorithm: "sha256" },
    });
    const saltedPseudonym = applyMask(
      "alice@example.com",
      { field: "email", maskType: "hash", parameters: { algorithm: "sha256" } },
      SALT,
    );

    // The premise: salting changes the value. Without this the two assertions below
    // could both hold while the salt did nothing.
    expect(saltedPseudonym).not.toBe(unsaltedPseudonym);

    const salted = new SecureToolFactory({ signingKey: KEY, hashSalt: SALT });
    const unsalted = new SecureToolFactory({ signingKey: KEY });
    const context = signed(policy("db:marketing:customer_segments", undefined, MASKED));

    expect(
      salted.createContextTool().postExecute(context, [{ email: "alice@example.com" }]),
    ).toEqual([{ email: saltedPseudonym }]);
    // Paired control: the same factory without a salt reproduces the plain digest, so
    // existing join keys survive an upgrade.
    expect(
      unsalted.createContextTool().postExecute(context, [{ email: "alice@example.com" }]),
    ).toEqual([{ email: unsaltedPseudonym }]);
  });

  it("the HTTP tool salts identically, so the transport does not change the pseudonym", async () => {
    // The bug the shared salt exists to prevent: the same field masking to two different
    // pseudonyms depending on which wrapper served the request would break every
    // cross-service join on that column while both sides looked correct alone.
    const factory = new SecureToolFactory({
      signingKey: KEY,
      fetchFn: okFetch,
      hashSalt: SALT,
      httpActionCategories: HTTP_MAP,
    });
    const dbContext = signed(policy("db:marketing:customer_segments", undefined, MASKED));
    const apiContext = signed(
      policy("api:purpose:test", undefined, {
        ...MASKED,
        endpointRules: ALL_GET.endpointRules,
      }),
    );

    const viaContext = factory
      .createContextTool()
      .postExecute(dbContext, [{ email: "alice@example.com" }]);
    const viaHttp = await factory
      .createHttpTool()
      .request(apiContext, { method: "GET", path: "/segments/overlap" });

    expect(viaHttp).toEqual({ email: (viaContext as Array<{ email: string }>)[0].email });
  });
});
