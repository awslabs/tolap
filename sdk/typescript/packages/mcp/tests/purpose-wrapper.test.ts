/**
 * Purpose-bound action validation inside the two wrappers (canonical spec §15.2).
 *
 * The category comes from administrator-supplied wrapper configuration, never from the
 * caller, so these tests are as much about *where* the check sits as about what it
 * decides:
 *
 * - In the context wrapper, **after** the `canQuery` gate and **before** the object
 *   rules. After `canQuery`, because a policy granting no reads should say so rather
 *   than complain about a category; before the object rules, because "this action does
 *   not serve the declared purpose" is the more specific answer when both would deny.
 * - In the HTTP wrapper, inside `validateHop`, so it applies to **redirect targets**
 *   as well as to the original request — a 307 to `/export/all.csv` is a different
 *   action from the `GET` that started the chain.
 *
 * Every denial is paired with a case proving the same call succeeds when permitted.
 */

import { describe, expect, it } from "vitest";

import {
  PrincipalType,
  UNDECLARED_CATEGORY_REASON,
  buildSecurityContext,
  signContext,
  type ActionCategoryMap,
  type DelegationHop,
  type EffectivePolicy,
  type PurposeProfile,
  type SecurityContext,
} from "@aws/tolap-core";
import { SecureContextToolWrapper } from "../src/context-wrapper.js";
import { SecureHttpToolWrapper, type FetchLike } from "../src/http-wrapper.js";

const KEY = "purpose-wrapper-key";
const BASE = "https://purpose.test";

/** A purpose that constrains actions in both directions. */
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

/** Every path reachable by GET, so the endpoint rules never do the denying. */
const ALL_GET: EffectivePolicy["objectRules"] = {
  endpointRules: { allowedEndpoints: ["/*", "/**"], allowedMethods: ["GET"] },
};

function policyWith(
  profile?: PurposeProfile,
  objectRules?: EffectivePolicy["objectRules"],
  permissions: EffectivePolicy["permissions"] = { canQuery: true, readOnly: true },
): EffectivePolicy {
  const now = new Date();
  return {
    version: "1.0",
    userId: "purpose-user",
    tenantId: "purpose-tenant",
    sourceConnectionId: "api:purpose:test",
    resolvedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 3_600_000).toISOString(),
    sourceProfiles: ["purpose-wrapper"],
    permissions,
    ...(objectRules === undefined ? {} : { objectRules }),
    ...(profile === undefined ? {} : { purposeProfile: profile }),
    integrity: { algorithm: "none", signature: "" },
  };
}

/** A signed context recording the purpose that produced the policy. */
function signedContext(policy: EffectivePolicy): SecurityContext {
  return signContext(
    buildSecurityContext(
      policy.userId,
      policy.tenantId,
      policy,
      3_600_000,
      undefined,
      policy.purposeProfile?.purposeId,
    ),
    KEY,
  );
}

function contextWrapper(
  toolActionCategories: ActionCategoryMap | undefined,
): SecureContextToolWrapper {
  return new SecureContextToolWrapper({
    signingKey: KEY,
    ...(toolActionCategories === undefined ? {} : { toolActionCategories }),
  });
}

/** A transport returning `{"count": 3}` on every hop. */
function okFetch(): { fetchFn: FetchLike; calls: Array<{ url: string }> } {
  const calls: Array<{ url: string }> = [];
  const fetchFn: FetchLike = async (input) => {
    calls.push({ url: input.url });
    return { ok: true, status: 200, json: async () => ({ count: 3 }) };
  };
  return { fetchFn, calls };
}

/** A transport that 307s once to `location`, then succeeds. */
function oneRedirectFetch(location: string): {
  fetchFn: FetchLike;
  calls: Array<{ url: string }>;
} {
  const calls: Array<{ url: string }> = [];
  let redirected = false;
  const fetchFn: FetchLike = async (input) => {
    calls.push({ url: input.url });
    if (!redirected) {
      redirected = true;
      return {
        ok: false,
        status: 307,
        headers: { get: (name: string) => (name.toLowerCase() === "location" ? location : null) },
        json: async () => ({}),
      };
    }
    return { ok: true, status: 200, json: async () => ({ count: 3 }) };
  };
  return { fetchFn, calls };
}

function httpWrapper(
  fetchFn: FetchLike,
  httpActionCategories: ActionCategoryMap | undefined,
): SecureHttpToolWrapper {
  return new SecureHttpToolWrapper(
    {
      signingKey: KEY,
      baseUrl: BASE,
      ...(httpActionCategories === undefined ? {} : { httpActionCategories }),
    },
    fetchFn,
  );
}

// ---------------------------------------------------------------------------
// The context wrapper
// ---------------------------------------------------------------------------

describe("SecureContextToolWrapper: purpose-bound action validation", () => {
  it("denies a prohibited tool", () => {
    const result = contextWrapper(TOOL_MAP).preExecute(
      signedContext(policyWith(CONSTRAINED)),
      { toolName: "export_csv" },
    );

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe(
      "action 'export_pii' is prohibited under purpose 'campaign-x-overlap'",
    );
  });

  it("allows a permitted tool", () => {
    // The paired control. Without it, a wrapper that denied every purpose-bound call
    // would pass the test above.
    expect(
      contextWrapper(TOOL_MAP).preExecute(signedContext(policyWith(CONSTRAINED)), {
        toolName: "segment_overlap",
      }),
    ).toEqual({ allowed: true });
  });

  it("denies an unmapped tool under a constraining purpose", () => {
    expect(
      contextWrapper(TOOL_MAP).preExecute(signedContext(policyWith(CONSTRAINED)), {
        toolName: "some_other_tool",
      }).reason,
    ).toBe(UNDECLARED_CATEGORY_REASON);
  });

  it("denies every call when no map is configured", () => {
    // The state an integrator is in the moment they add a `purposeProfile` and forget
    // the map. Fail-closed and named as a configuration problem, so the fix is obvious.
    expect(
      contextWrapper(undefined).preExecute(signedContext(policyWith(CONSTRAINED)), {
        toolName: "segment_overlap",
      }).reason,
    ).toBe(UNDECLARED_CATEGORY_REASON);
  });

  it("a purpose-agnostic policy is unaffected, with or without a map", () => {
    // The backward-compatibility half: every existing deployment resolves policies with
    // no profile, and configuring a map must not start denying their calls.
    const agnostic = signedContext(policyWith());

    expect(
      contextWrapper(undefined).preExecute(agnostic, { toolName: "export_csv" }),
    ).toEqual({ allowed: true });
    expect(
      contextWrapper(TOOL_MAP).preExecute(agnostic, { toolName: "export_csv" }),
    ).toEqual({ allowed: true });
  });

  it("an unconstrained purpose is unaffected by an unmapped tool", () => {
    const unconstrained = signedContext(
      policyWith({ purposeId: "campaign-x-overlap", description: "anything goes" }),
    );

    expect(
      contextWrapper(TOOL_MAP).preExecute(unconstrained, { toolName: "unmapped" }),
    ).toEqual({ allowed: true });
  });

  it("also gates executeWithEnforcement, not only the bare preExecute", () => {
    // The check has to sit on the path an integrator actually calls. A pre-flight
    // helper nobody invokes is the "gate that silently does not exist" shape.
    const wrapper = contextWrapper(TOOL_MAP);
    const context = signedContext(policyWith(CONSTRAINED));
    let ran = false;

    return expect(
      wrapper.executeWithEnforcement(context, { toolName: "export_csv" }, () => {
        ran = true;
        return [];
      }),
    )
      .rejects.toThrow(/is prohibited under purpose 'campaign-x-overlap'/)
      .then(() => {
        // The tool never ran: the denial is pre-execution, so no data was fetched.
        expect(ran).toBe(false);
      });
  });

  it("a permitted tool does reach executeWithEnforcement's callback", async () => {
    const wrapper = contextWrapper(TOOL_MAP);
    const context = signedContext(policyWith(CONSTRAINED));

    const rows = await wrapper.executeWithEnforcement(
      context,
      { toolName: "segment_overlap" },
      () => [{ segment: "a" }],
    );

    expect(rows).toEqual([{ segment: "a" }]);
  });
});

describe("SecureContextToolWrapper: check ordering", () => {
  it("the action is checked BEFORE the object rules", () => {
    // Both would deny. The purpose answer is the more specific one, and it is the one
    // that tells an operator what actually went wrong.
    const policy = policyWith(CONSTRAINED, { hiddenObjects: ["customer_segments"] });

    expect(
      contextWrapper(TOOL_MAP).preExecute(signedContext(policy), {
        toolName: "export_csv",
        objectName: "customer_segments",
      }).reason,
    ).toBe("action 'export_pii' is prohibited under purpose 'campaign-x-overlap'");
  });

  it("the object rules still apply to a permitted action", () => {
    // Paired with the above: ordering first is not ordering instead.
    const policy = policyWith(CONSTRAINED, { hiddenObjects: ["customer_segments"] });

    expect(
      contextWrapper(TOOL_MAP).preExecute(signedContext(policy), {
        toolName: "segment_overlap",
        objectName: "customer_segments",
      }).reason,
    ).toBe("object is hidden");
  });

  it("canQuery is checked BEFORE the action", () => {
    // A policy that grants no reads at all should say so rather than complain about a
    // category the caller could not have got right either way.
    const policy = policyWith(CONSTRAINED, undefined, { canQuery: false, readOnly: true });

    expect(
      contextWrapper(TOOL_MAP).preExecute(signedContext(policy), {
        toolName: "export_csv",
      }).reason,
    ).toBe("query not permitted");
  });

  it("the allowedTools list is checked BEFORE the action", () => {
    // A tool the deployment never exposed is not a purpose problem.
    const wrapper = new SecureContextToolWrapper({
      signingKey: KEY,
      allowedTools: ["segment_overlap"],
      toolActionCategories: TOOL_MAP,
    });

    expect(
      wrapper.preExecute(signedContext(policyWith(CONSTRAINED)), {
        toolName: "export_csv",
      }).reason,
    ).toBe("tool not in allowed list");
  });

  it("the context signature is checked BEFORE the action", () => {
    // The purpose is inside the signed bytes, so a context whose purpose was swapped
    // must fail on the signature rather than be evaluated against the swapped value.
    const tampered = signedContext(policyWith(CONSTRAINED));
    tampered.declaredPurpose = "fraud-detection";

    expect(
      contextWrapper(TOOL_MAP).preExecute(tampered, { toolName: "segment_overlap" })
        .reason,
    ).toBe("invalid signature");
  });

  it("the field checks still run after a permitted action", () => {
    const policy = policyWith(CONSTRAINED, {
      fieldRules: { hiddenFields: ["ssn"] },
    });

    expect(
      contextWrapper(TOOL_MAP).preExecute(signedContext(policy), {
        toolName: "segment_overlap",
        fields: ["ssn"],
      }).reason,
    ).toBe("denied fields: ssn");
  });
});

// ---------------------------------------------------------------------------
// The HTTP wrapper
// ---------------------------------------------------------------------------

describe("SecureHttpToolWrapper: purpose-bound action validation", () => {
  it("denies a prohibited path", async () => {
    const { fetchFn, calls } = okFetch();
    const wrapper = httpWrapper(fetchFn, HTTP_MAP);
    const context = signedContext(policyWith(CONSTRAINED, ALL_GET));

    await expect(
      wrapper.request(context, { method: "GET", path: "/export/all.csv" }),
    ).rejects.toThrow(
      /action 'export_pii' is prohibited under purpose 'campaign-x-overlap'/,
    );
    // Pre-request: the transport was never reached, so nothing left the process.
    expect(calls).toHaveLength(0);
  });

  it("allows a permitted path and returns the enforced body", async () => {
    const { fetchFn, calls } = okFetch();
    const wrapper = httpWrapper(fetchFn, HTTP_MAP);
    const context = signedContext(policyWith(CONSTRAINED, ALL_GET));

    expect(
      await wrapper.request(context, { method: "GET", path: "/segments/overlap" }),
    ).toEqual({ count: 3 });
    expect(calls).toHaveLength(1);
  });

  it("denies an unmapped path under a constraining purpose", async () => {
    const { fetchFn } = okFetch();
    const wrapper = httpWrapper(fetchFn, HTTP_MAP);

    await expect(
      wrapper.request(signedContext(policyWith(CONSTRAINED, ALL_GET)), {
        method: "GET",
        path: "/reports/monthly",
      }),
    ).rejects.toThrow(UNDECLARED_CATEGORY_REASON);
  });

  it("denies every request when no map is configured", async () => {
    const { fetchFn } = okFetch();
    const wrapper = httpWrapper(fetchFn, undefined);

    await expect(
      wrapper.request(signedContext(policyWith(CONSTRAINED, ALL_GET)), {
        method: "GET",
        path: "/segments/overlap",
      }),
    ).rejects.toThrow(UNDECLARED_CATEGORY_REASON);
  });

  it("a purpose-agnostic policy is unaffected", async () => {
    const { fetchFn } = okFetch();
    const wrapper = httpWrapper(fetchFn, HTTP_MAP);

    expect(
      await wrapper.request(signedContext(policyWith(undefined, ALL_GET)), {
        method: "GET",
        path: "/export/all.csv",
      }),
    ).toEqual({ count: 3 });
  });

  it("matches the category with the query string stripped", async () => {
    // A category cannot be dodged by appending a query: policy patterns are written
    // against paths, not URLs.
    const { fetchFn } = okFetch();
    const wrapper = httpWrapper(fetchFn, HTTP_MAP);

    await expect(
      wrapper.request(signedContext(policyWith(CONSTRAINED, ALL_GET)), {
        method: "GET",
        path: "/export/all.csv?format=json",
      }),
    ).rejects.toThrow(/action 'export_pii' is prohibited/);
  });

  it("checks the action BEFORE the endpoint rules", async () => {
    // Both would deny; the purpose reason is the more actionable one.
    const { fetchFn } = okFetch();
    const wrapper = httpWrapper(fetchFn, HTTP_MAP);
    const policy = policyWith(CONSTRAINED, {
      endpointRules: {
        allowedEndpoints: ["/*", "/**"],
        hiddenEndpoints: ["/export/*"],
        allowedMethods: ["GET"],
      },
    });

    await expect(
      wrapper.request(signedContext(policy), { method: "GET", path: "/export/all.csv" }),
    ).rejects.toThrow(/action 'export_pii' is prohibited/);
  });

  it("the endpoint rules still apply to a permitted action", async () => {
    // Paired: ordering first is not ordering instead.
    const { fetchFn } = okFetch();
    const wrapper = httpWrapper(fetchFn, HTTP_MAP);
    const policy = policyWith(CONSTRAINED, {
      endpointRules: {
        allowedEndpoints: ["/*", "/**"],
        hiddenEndpoints: ["/segments/*"],
        allowedMethods: ["GET"],
      },
    });

    await expect(
      wrapper.request(signedContext(policy), { method: "GET", path: "/segments/overlap" }),
    ).rejects.toThrow(/endpoint/);
  });

  it("the path shape check still runs first", async () => {
    // A protocol-relative target is not a path at all, so it is refused before any glob
    // — including the category globs — is consulted.
    const { fetchFn } = okFetch();
    const wrapper = httpWrapper(fetchFn, HTTP_MAP);

    await expect(
      wrapper.request(signedContext(policyWith(CONSTRAINED, ALL_GET)), {
        method: "GET",
        path: "//evil.example/segments/overlap",
      }),
    ).rejects.toThrow(/protocol-relative/);
  });
});

describe("SecureHttpToolWrapper: redirects are re-categorized", () => {
  it("a redirect to a prohibited path is denied", async () => {
    // The reason the check lives in `validateHop` rather than at the entry point: a
    // permitted `GET /segments/overlap` that 307s to `/export/all.csv` is a different
    // action, and the wrapper is the only thing that sees the second one.
    const { fetchFn, calls } = oneRedirectFetch("/export/all.csv");
    const wrapper = httpWrapper(fetchFn, HTTP_MAP);

    await expect(
      wrapper.request(signedContext(policyWith(CONSTRAINED, ALL_GET)), {
        method: "GET",
        path: "/segments/overlap",
      }),
    ).rejects.toThrow(
      /action 'export_pii' is prohibited under purpose 'campaign-x-overlap'/,
    );
    // The first hop was fetched, the redirect target was not.
    expect(calls).toHaveLength(1);
  });

  it("a redirect to a permitted path still succeeds", async () => {
    // Paired: the redirect check narrows, it does not refuse redirects wholesale.
    const map: ActionCategoryMap = {
      ...HTTP_MAP,
      "GET /segments/count": "count_segments",
    };
    const { fetchFn, calls } = oneRedirectFetch("/segments/count");
    const wrapper = httpWrapper(fetchFn, map);

    expect(
      await wrapper.request(signedContext(policyWith(CONSTRAINED, ALL_GET)), {
        method: "GET",
        path: "/segments/overlap",
      }),
    ).toEqual({ count: 3 });
    expect(calls).toHaveLength(2);
  });

  it("a redirect to an UNMAPPED path is denied", async () => {
    // The fail-closed arm on the redirect path specifically: an unclassified target is
    // no more acceptable than an unclassified original request.
    const { fetchFn } = oneRedirectFetch("/reports/monthly");
    const wrapper = httpWrapper(fetchFn, HTTP_MAP);

    await expect(
      wrapper.request(signedContext(policyWith(CONSTRAINED, ALL_GET)), {
        method: "GET",
        path: "/segments/overlap",
      }),
    ).rejects.toThrow(UNDECLARED_CATEGORY_REASON);
  });

  it("a redirect carrying a query string is categorized on the path alone", async () => {
    const { fetchFn } = oneRedirectFetch("/export/all.csv?format=json");
    const wrapper = httpWrapper(fetchFn, HTTP_MAP);

    await expect(
      wrapper.request(signedContext(policyWith(CONSTRAINED, ALL_GET)), {
        method: "GET",
        path: "/segments/overlap",
      }),
    ).rejects.toThrow(/action 'export_pii' is prohibited/);
  });
});

// ---------------------------------------------------------------------------
// The two wrappers must agree
// ---------------------------------------------------------------------------

describe("the two wrappers reach the same decision for the same category", () => {
  it("both deny a prohibited category with the identical reason", async () => {
    // Two controls acting on one shared rule through two different lookups. Pinning
    // each alone cannot see a divergence between them, and the outlier would be what an
    // integrator trips over.
    const contextResult = contextWrapper(TOOL_MAP).preExecute(
      signedContext(policyWith(CONSTRAINED)),
      { toolName: "export_csv" },
    );

    const { fetchFn } = okFetch();
    let httpReason = "";
    try {
      await httpWrapper(fetchFn, HTTP_MAP).request(
        signedContext(policyWith(CONSTRAINED, ALL_GET)),
        { method: "GET", path: "/export/all.csv" },
      );
    } catch (error) {
      httpReason = (error as Error).message.replace("Access denied: ", "");
    }

    expect(contextResult.reason).toBe(httpReason);
  });

  it("both deny an unclassified call with the identical reason", async () => {
    const contextResult = contextWrapper(TOOL_MAP).preExecute(
      signedContext(policyWith(CONSTRAINED)),
      { toolName: "nope" },
    );

    const { fetchFn } = okFetch();
    let httpReason = "";
    try {
      await httpWrapper(fetchFn, HTTP_MAP).request(
        signedContext(policyWith(CONSTRAINED, ALL_GET)),
        { method: "GET", path: "/nope" },
      );
    } catch (error) {
      httpReason = (error as Error).message.replace("Access denied: ", "");
    }

    expect(contextResult.reason).toBe(UNDECLARED_CATEGORY_REASON);
    expect(httpReason).toBe(UNDECLARED_CATEGORY_REASON);
  });
});

// ---------------------------------------------------------------------------
// The delegation chain is checked, not merely carried (§15.3)
// ---------------------------------------------------------------------------

/**
 * Through the wrappers, not the validator: a validator nobody calls passes all of its own
 * tests while enforcing nothing (testing-antipatterns.md §4). What is asserted here is that a
 * context carrying a widened hop is actually refused at the point a call is made.
 */
const WIDENING: DelegationHop[] = [
  { principalId: "analyst@example.test", principalType: PrincipalType.User, declaredPurpose: "campaign-x" },
  { principalId: "agent-1", principalType: PrincipalType.Agent, declaredPurpose: "campaign-xyz-evil" },
];

const NARROWING: DelegationHop[] = [
  { principalId: "analyst@example.test", principalType: PrincipalType.User, declaredPurpose: "campaign-x" },
  { principalId: "agent-1", principalType: PrincipalType.Agent, declaredPurpose: "campaign-x-overlap" },
];

function chainContext(
  chain: DelegationHop[] | undefined,
  objectRules?: EffectivePolicy["objectRules"],
): SecurityContext {
  const policy = policyWith(undefined, objectRules);
  return signContext(
    buildSecurityContext(
      policy.userId,
      policy.tenantId,
      policy,
      3_600_000,
      undefined,
      undefined,
      chain,
    ),
    KEY,
  );
}

describe("SecureContextToolWrapper: delegation-chain validation", () => {
  it("denies a chain whose child hop widens its parent's purpose", () => {
    const result = contextWrapper(undefined).validateSecurityContext(chainContext(WIDENING));

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe(
      "delegation hop 1 purpose 'campaign-xyz-evil' is not within parent scope 'campaign-x'",
    );
  });

  it("allows a chain that narrows on a segment boundary", () => {
    // The paired control: a wrapper that rejected every chain would satisfy the case above.
    expect(
      contextWrapper(undefined).validateSecurityContext(chainContext(NARROWING)).allowed,
    ).toBe(true);
  });

  it("allows a context carrying no chain at all", () => {
    // Backward compatibility as a test rather than a comment: every context issued before
    // this feature carries no chain, and none of them may start failing.
    expect(
      contextWrapper(undefined).validateSecurityContext(chainContext(undefined)).allowed,
    ).toBe(true);
  });

  it("denies a widening chain through preExecute, not just through the validator", () => {
    expect(
      contextWrapper(TOOL_MAP).preExecute(chainContext(WIDENING), {
        toolName: "segment_overlap",
      }).allowed,
    ).toBe(false);
  });

  it("checks the signature before the chain", () => {
    // The ordering is the whole reason chain validation is worth doing. Validating an
    // unsigned chain checks the attacker's own arithmetic: anyone who can rewrite a hop can
    // rewrite it into something consistent. So a context with both a bad signature and a
    // widening chain must report the signature.
    const tampered: SecurityContext = { ...chainContext(NARROWING), delegationChain: WIDENING };

    expect(contextWrapper(undefined).validateSecurityContext(tampered).reason).toBe(
      "invalid signature",
    );
  });
});

describe("SecureHttpToolWrapper: delegation-chain validation", () => {
  it("denies a widening chain", async () => {
    // The HTTP wrapper validates contexts through its own path, so a fix applied only to the
    // context wrapper would leave `api` sources unguarded.
    const { fetchFn } = okFetch();

    await expect(
      httpWrapper(fetchFn, undefined).request(chainContext(WIDENING, ALL_GET), {
        method: "GET",
        path: "/segments/overlap",
      }),
    ).rejects.toThrow(/is not within parent scope/);
  });

  it("allows a narrowing chain", async () => {
    const { fetchFn } = okFetch();

    await expect(
      httpWrapper(fetchFn, undefined).request(chainContext(NARROWING, ALL_GET), {
        method: "GET",
        path: "/segments/overlap",
      }),
    ).resolves.toEqual({ count: 3 });
  });
});
