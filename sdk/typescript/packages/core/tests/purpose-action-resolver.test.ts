/**
 * `validateToolAction` / `validateHttpRequestAction` — resolving a call's action
 * category from administrator configuration (canonical spec §15.2).
 *
 * The category never comes from the caller: an agent that can name its own action
 * category can name a permitted one, which reduces the check to a formality. So there
 * are two maps, one per wrapper family, and the interesting behaviour is what happens
 * when **neither** classifies the call. That path is fail-closed, and it is the one an
 * integrator hits first — a map they have not filled in yet.
 *
 * Every denial below is paired with a case proving the same call succeeds when
 * classified and permitted.
 */

import { describe, expect, it } from "vitest";
import {
  UNDECLARED_CATEGORY_REASON,
  validateHttpRequestAction,
  validateToolAction,
  type ActionCategoryMap,
} from "../src/purpose-action.js";
import type { EffectivePolicy, PurposeProfile } from "../src/types.js";

const NOW = "2026-09-01T10:00:00Z";

function policyWith(profile?: PurposeProfile): EffectivePolicy {
  return {
    version: "1.0",
    userId: "user-1",
    tenantId: "tenant-1",
    sourceConnectionId: "db:marketing:customer_segments",
    resolvedAt: NOW,
    expiresAt: "2026-09-01T11:00:00Z",
    sourceProfiles: ["p"],
    permissions: { canQuery: true, readOnly: true },
    ...(profile === undefined ? {} : { purposeProfile: profile }),
    integrity: { algorithm: "none", signature: "" },
  };
}

/** A purpose that constrains actions in both directions. */
const CONSTRAINED: PurposeProfile = {
  purposeId: "campaign-x-overlap",
  allowedActions: ["aggregate_overlap", "count_segments"],
  prohibitedActions: ["export_pii"],
};

const TOOL_MAP: ActionCategoryMap = {
  segment_overlap: "aggregate_overlap",
  segment_count: "count_segments",
  export_csv: "export_pii",
};

const HTTP_MAP: ActionCategoryMap = {
  "GET /segments/overlap": "aggregate_overlap",
  "GET /segments/count": "count_segments",
  "POST /export/*": "export_pii",
};

// ---------------------------------------------------------------------------
// A purpose-agnostic policy is untouched by this feature
// ---------------------------------------------------------------------------

describe("a policy with no purpose profile always allows", () => {
  it("allows a tool call whether or not a map is configured", () => {
    // The backward-compatibility half. Every policy authored before purpose binding
    // has no profile, so this path must not consult the map at all -- including when a
    // map exists and would have classified the tool as prohibited.
    expect(validateToolAction(policyWith(), "anything", undefined).allowed).toBe(true);
    expect(validateToolAction(policyWith(), "export_csv", TOOL_MAP).allowed).toBe(true);
  });

  it("allows an HTTP request whether or not a map is configured", () => {
    expect(
      validateHttpRequestAction(policyWith(), "POST", "/export/all.csv", undefined)
        .allowed,
    ).toBe(true);
    expect(
      validateHttpRequestAction(policyWith(), "POST", "/export/all.csv", HTTP_MAP)
        .allowed,
    ).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Tool-name lookup
// ---------------------------------------------------------------------------

describe("validateToolAction", () => {
  it("allows a mapped, permitted tool", () => {
    expect(
      validateToolAction(policyWith(CONSTRAINED), "segment_overlap", TOOL_MAP).allowed,
    ).toBe(true);
  });

  it("denies a mapped, prohibited tool with the category's own reason", () => {
    // The reason names the CATEGORY, not the tool: the prohibition is written against
    // categories, and an operator needs to see the rule that fired.
    const result = validateToolAction(policyWith(CONSTRAINED), "export_csv", TOOL_MAP);

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe(
      "action 'export_pii' is prohibited under purpose 'campaign-x-overlap'",
    );
  });

  it("denies a mapped tool whose category is outside the allow-list", () => {
    const map: ActionCategoryMap = { train: "train_model" };

    const result = validateToolAction(policyWith(CONSTRAINED), "train", map);
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe(
      "action 'train_model' not in allowed actions for purpose 'campaign-x-overlap'",
    );
  });

  it("denies an unmapped tool under a constraining purpose", () => {
    const result = validateToolAction(
      policyWith(CONSTRAINED),
      "unmapped_tool",
      TOOL_MAP,
    );

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe(UNDECLARED_CATEGORY_REASON);
  });

  it("denies every call when NO map is configured", () => {
    // The state an integrator is in before they have written the map: a purpose-bound
    // policy that constrains actions denies everything, because a tool nothing
    // classifies cannot be shown to serve the purpose. Loud and fixable, rather than a
    // control that quietly does nothing.
    const result = validateToolAction(policyWith(CONSTRAINED), "segment_overlap", undefined);

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe(UNDECLARED_CATEGORY_REASON);
  });

  it("treats an EMPTY map as classifying nothing, not as unrestricted", () => {
    // The `undefined`-versus-`{}` distinction. A truthiness check on the map would
    // read `{}` as absent and reach the same answer, so this is asserted alongside the
    // `undefined` case rather than instead of it.
    const empty: ActionCategoryMap = {};

    expect(validateToolAction(policyWith(CONSTRAINED), "x", empty).reason).toBe(
      UNDECLARED_CATEGORY_REASON,
    );
    expect(
      validateHttpRequestAction(policyWith(CONSTRAINED), "GET", "/x", empty).reason,
    ).toBe(UNDECLARED_CATEGORY_REASON);
  });

  it("matches the tool name case-sensitively, as allowedTools does", () => {
    // A tool name is an identifier the deployment controls on both sides, so exactness
    // is achievable — and the fail direction of getting it wrong is a denial.
    expect(
      validateToolAction(policyWith(CONSTRAINED), "Segment_Overlap", TOOL_MAP).reason,
    ).toBe(UNDECLARED_CATEGORY_REASON);
    expect(
      validateToolAction(policyWith(CONSTRAINED), "segment_overlap", TOOL_MAP).allowed,
    ).toBe(true);
  });

  it("does not pick a category up off the prototype chain", () => {
    // `toString` and `constructor` exist on every object literal's prototype. A
    // truthy `map[toolName]` lookup would hand `validateAction` a function for a tool
    // named `toString`, which is a category nobody wrote.
    const result = validateToolAction(policyWith(CONSTRAINED), "toString", TOOL_MAP);

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe(UNDECLARED_CATEGORY_REASON);
  });
});

// ---------------------------------------------------------------------------
// What "constrains actions" means -- the fail-closed condition
// ---------------------------------------------------------------------------

describe("an unclassified call is denied only when the purpose constrains actions", () => {
  it("an unconstrained purpose allows an unclassified tool", () => {
    // A purpose may legitimately constrain nothing but the resolution scope. Denying
    // here would make every purpose-bound policy need a full category map before it
    // could do anything at all.
    const unconstrained: PurposeProfile = { purposeId: "campaign-x-overlap" };

    expect(
      validateToolAction(policyWith(unconstrained), "unmapped_tool", TOOL_MAP).allowed,
    ).toBe(true);
    expect(
      validateHttpRequestAction(policyWith(unconstrained), "GET", "/anything", HTTP_MAP)
        .allowed,
    ).toBe(true);
  });

  it("an ALLOW-list, however permissive, makes an unclassified tool a denial", () => {
    const allowOnly: PurposeProfile = {
      purposeId: "campaign-x-overlap",
      allowedActions: ["aggregate_overlap"],
    };

    expect(
      validateToolAction(policyWith(allowOnly), "unmapped_tool", TOOL_MAP).reason,
    ).toBe(UNDECLARED_CATEGORY_REASON);
  });

  it("an EMPTY allow-list also makes an unclassified tool a denial", () => {
    // `[]` is the most restrictive allow-list, so it must constrain at least as much
    // as a populated one. A truthiness check would read it as absent and allow.
    const denyAll: PurposeProfile = {
      purposeId: "campaign-x-overlap",
      allowedActions: [],
    };

    expect(
      validateToolAction(policyWith(denyAll), "unmapped_tool", TOOL_MAP).reason,
    ).toBe(UNDECLARED_CATEGORY_REASON);
  });

  it("a prohibition-only purpose still denies an unclassified tool", () => {
    // The less obvious half and the more important one: "anything but exporting PII"
    // cannot mean "and also anything unclassified", because an unclassified tool might
    // be an exporter. Permitting the unclassified while forbidding the classified
    // cannot be what the author meant.
    const prohibitionOnly: PurposeProfile = {
      purposeId: "campaign-x-overlap",
      prohibitedActions: ["export_pii"],
    };

    expect(
      validateToolAction(policyWith(prohibitionOnly), "unmapped_tool", TOOL_MAP).reason,
    ).toBe(UNDECLARED_CATEGORY_REASON);
    // Paired: a classified, non-prohibited tool under the same purpose is allowed.
    expect(
      validateToolAction(policyWith(prohibitionOnly), "segment_overlap", TOOL_MAP)
        .allowed,
    ).toBe(true);
  });

  it("an EMPTY prohibition list restricts nothing, so it does not deny", () => {
    // Mirrors spec §3, where the two arrays read in opposite directions: an empty
    // deny-list forbids nothing.
    const emptyProhibition: PurposeProfile = {
      purposeId: "campaign-x-overlap",
      prohibitedActions: [],
    };

    expect(
      validateToolAction(policyWith(emptyProhibition), "unmapped_tool", TOOL_MAP).allowed,
    ).toBe(true);
  });

  it("an empty allow-list denies even a MAPPED tool", () => {
    // The map resolves a category and `validateAction` refuses it. Distinct from the
    // unclassified path, and reported with the allow-list reason rather than the
    // configuration one.
    const denyAll: PurposeProfile = {
      purposeId: "campaign-x-overlap",
      allowedActions: [],
    };

    const result = validateToolAction(policyWith(denyAll), "segment_overlap", TOOL_MAP);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("not in allowed actions");
  });
});

// ---------------------------------------------------------------------------
// HTTP "METHOD path-glob" lookup
// ---------------------------------------------------------------------------

describe("validateHttpRequestAction", () => {
  it("allows a mapped, permitted path", () => {
    expect(
      validateHttpRequestAction(
        policyWith(CONSTRAINED),
        "GET",
        "/segments/overlap",
        HTTP_MAP,
      ).allowed,
    ).toBe(true);
  });

  it("denies a mapped, prohibited path", () => {
    const result = validateHttpRequestAction(
      policyWith(CONSTRAINED),
      "POST",
      "/export/all.csv",
      HTTP_MAP,
    );

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe(
      "action 'export_pii' is prohibited under purpose 'campaign-x-overlap'",
    );
  });

  for (const method of ["get", "GET", "Get", "gEt"]) {
    it(`matches the method case-insensitively ('${method}')`, () => {
      // Matching how `allowedMethods` is compared. An HTTP method is a protocol
      // constant whose canonical spelling a transport may or may not preserve, unlike a
      // tool name.
      expect(
        validateHttpRequestAction(
          policyWith(CONSTRAINED),
          method,
          "/segments/overlap",
          HTTP_MAP,
        ).allowed,
      ).toBe(true);
    });
  }

  it("the method is part of the key, so a different verb is unclassified", () => {
    // `POST /export/*` must not classify a `GET` to the same path: a read and a write
    // of one route are different actions, which is the whole reason the method is in
    // the key.
    expect(
      validateHttpRequestAction(policyWith(CONSTRAINED), "GET", "/export/all.csv", HTTP_MAP)
        .reason,
    ).toBe(UNDECLARED_CATEGORY_REASON);
  });

  for (const path of ["/export/all.csv", "/export/nested/deep.csv"]) {
    it(`the path glob uses the endpoint dialect, so '*' crosses '/' ('${path}')`, () => {
      // Same dialect as `allowedEndpoints`, so a deployment writes one kind of endpoint
      // pattern. If `*` stopped at `/`, `POST /export/*` would classify the flat path
      // and leave the nested one unclassified — a category dodged by adding a segment.
      expect(
        validateHttpRequestAction(policyWith(CONSTRAINED), "POST", path, HTTP_MAP).allowed,
      ).toBe(false);
    });
  }

  it("denies an unmapped path under a constraining purpose", () => {
    expect(
      validateHttpRequestAction(
        policyWith(CONSTRAINED),
        "GET",
        "/segments/unmapped",
        HTTP_MAP,
      ).reason,
    ).toBe(UNDECLARED_CATEGORY_REASON);
  });

  it("denies every request when NO map is configured", () => {
    expect(
      validateHttpRequestAction(
        policyWith(CONSTRAINED),
        "GET",
        "/segments/overlap",
        undefined,
      ).reason,
    ).toBe(UNDECLARED_CATEGORY_REASON);
  });

  it("validates EVERY matching entry, not a single best match", () => {
    // A specificity rule can be gamed by adding a broader entry. Evaluating every
    // match makes the outcome independent of how the map happens to be written.
    const overlapping: ActionCategoryMap = {
      "GET /segments/*": "aggregate_overlap",
      "GET /segments/individuals": "enumerate_individuals",
    };
    const profile: PurposeProfile = {
      purposeId: "campaign-x-overlap",
      prohibitedActions: ["enumerate_individuals"],
    };

    const denied = validateHttpRequestAction(
      policyWith(profile),
      "GET",
      "/segments/individuals",
      overlapping,
    );
    expect(denied.allowed).toBe(false);
    expect(denied.reason).toBe(
      "action 'enumerate_individuals' is prohibited under purpose 'campaign-x-overlap'",
    );

    // Paired: a path matched only by the broad entry is still allowed, so the denial
    // above is the specific entry firing rather than the broad one being refused.
    expect(
      validateHttpRequestAction(
        policyWith(profile),
        "GET",
        "/segments/overlap",
        overlapping,
      ).allowed,
    ).toBe(true);
  });

  it("the decision is independent of map insertion order", () => {
    const profile: PurposeProfile = {
      purposeId: "campaign-x-overlap",
      prohibitedActions: ["enumerate_individuals"],
    };
    const forward: ActionCategoryMap = {
      "GET /segments/*": "aggregate_overlap",
      "GET /segments/individuals": "enumerate_individuals",
    };
    const reverse: ActionCategoryMap = {
      "GET /segments/individuals": "enumerate_individuals",
      "GET /segments/*": "aggregate_overlap",
    };

    expect(
      validateHttpRequestAction(policyWith(profile), "GET", "/segments/individuals", forward),
    ).toEqual(
      validateHttpRequestAction(policyWith(profile), "GET", "/segments/individuals", reverse),
    );
  });

  it("the reason string is stable when two entries would both deny", () => {
    // Keys are considered in sorted order, so the reported reason does not depend on
    // object property order — which is what makes the reason usable as a contract.
    const profile: PurposeProfile = {
      purposeId: "campaign-x-overlap",
      prohibitedActions: ["export_pii", "enumerate_individuals"],
    };
    const forward: ActionCategoryMap = {
      "GET /a/*": "export_pii",
      "GET /a/b": "enumerate_individuals",
    };
    const reverse: ActionCategoryMap = {
      "GET /a/b": "enumerate_individuals",
      "GET /a/*": "export_pii",
    };

    const first = validateHttpRequestAction(policyWith(profile), "GET", "/a/b", forward);
    const second = validateHttpRequestAction(policyWith(profile), "GET", "/a/b", reverse);

    expect(first.reason).toBe(second.reason);
    // Sorted ordinally, `GET /a/*` precedes `GET /a/b` ('*' is 0x2A, 'b' is 0x62).
    expect(first.reason).toContain("export_pii");
  });

  for (const key of ["GET", "GET ", " /segments/overlap", "", " "]) {
    it(`a malformed key '${key}' matches nothing`, () => {
      // A key with no space, an empty method, or an empty pattern is a
      // misconfiguration. A key that silently matched everything would be the worst
      // possible reading of one — the map exists to narrow.
      const map: ActionCategoryMap = { [key]: "aggregate_overlap" };

      expect(
        validateHttpRequestAction(
          policyWith(CONSTRAINED),
          "GET",
          "/segments/overlap",
          map,
        ).reason,
      ).toBe(UNDECLARED_CATEGORY_REASON);
    });
  }

  it("a well-formed key beside a malformed one still classifies", () => {
    // Paired with the block above: one bad key does not disable the map.
    const map: ActionCategoryMap = {
      GET: "export_pii",
      "GET /segments/overlap": "aggregate_overlap",
    };

    expect(
      validateHttpRequestAction(policyWith(CONSTRAINED), "GET", "/segments/overlap", map)
        .allowed,
    ).toBe(true);
  });

  it("the path is matched as given -- the caller strips the query", () => {
    // This function is handed a path with the query already removed (the HTTP wrapper
    // does that before calling), so a `?` here is literal and does not match. Asserted
    // so the division of responsibility is pinned rather than assumed.
    expect(
      validateHttpRequestAction(
        policyWith(CONSTRAINED),
        "POST",
        "/export/all.csv?format=json",
        { "POST /export/all.csv": "export_pii" },
      ).reason,
    ).toBe(UNDECLARED_CATEGORY_REASON);
  });
});

// ---------------------------------------------------------------------------
// The two maps must agree about the same purpose
// ---------------------------------------------------------------------------

describe("the tool and HTTP paths agree", () => {
  it("the same category reaches the same decision through either map", () => {
    // Two controls, one shared rule. Testing each in isolation cannot see a
    // divergence between them, and the outlier is what an integrator would trip over
    // (antipattern #2).
    const viaTool = validateToolAction(policyWith(CONSTRAINED), "export_csv", TOOL_MAP);
    const viaHttp = validateHttpRequestAction(
      policyWith(CONSTRAINED),
      "POST",
      "/export/all.csv",
      HTTP_MAP,
    );

    expect(viaTool).toEqual(viaHttp);
  });

  it("both report the identical reason for an unclassified call", () => {
    expect(
      validateToolAction(policyWith(CONSTRAINED), "nope", TOOL_MAP),
    ).toEqual(
      validateHttpRequestAction(policyWith(CONSTRAINED), "GET", "/nope", HTTP_MAP),
    );
  });

  it("the undeclared reason names the configuration, not the access", () => {
    // The fix is to add the tool to the map, not to widen the policy, and the string
    // is what tells an operator which.
    expect(UNDECLARED_CATEGORY_REASON).toBe("action category not declared for tool");
  });
});
