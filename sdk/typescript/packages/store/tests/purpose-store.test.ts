/**
 * `declaredPurpose` threaded through the store's resolution convenience
 * (canonical spec §15.1).
 *
 * The parameter has to reach `resolve` rather than be applied by the caller afterwards,
 * because purpose filtering happens **before** the merge: a policy scoped to a purpose
 * the caller did not declare must not fold its rules into the effective policy at all,
 * and there is no later point at which to undo that. A store that accepted the argument
 * and dropped it would resolve a policy nobody asked for — and would look correct, since
 * a purpose-agnostic result is indistinguishable from a filtered one unless you check
 * the rules.
 *
 * Built on the shared policy/assignment fixture pairs, so the scenarios match the ones
 * the core suite and the other two SDKs resolve.
 */

import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { InMemoryPolicyStore } from "../src/in-memory-store.js";
import type { PolicyAuditEvent, PolicyStore } from "../src/types.js";
import type { PolicyAssignment, PolicyDefinition } from "@aws/tolap-core";

const policiesDir = path.resolve(__dirname, "../../../../../fixtures/policies");
const assignmentsDir = path.resolve(__dirname, "../../../../../fixtures/assignments");

const TENANT = "tenant-acme-retail";
const USER = "user-marketing-001";
const SOURCE = "db:marketing:customer_segments";
const CAMPAIGN_PURPOSE = "campaign-x-overlap";

function loadPolicy(name: string): PolicyDefinition {
  return JSON.parse(
    fs.readFileSync(path.join(policiesDir, `${name}.json`), "utf-8"),
  ) as PolicyDefinition;
}

function loadAssignment(name: string): PolicyAssignment {
  return JSON.parse(
    fs.readFileSync(path.join(assignmentsDir, `${name}.json`), "utf-8"),
  ) as PolicyAssignment;
}

const SCOPED = loadPolicy("purpose-campaign-overlap");
const FRAUD = loadPolicy("purpose-fraud-detection");
const AGNOSTIC = loadPolicy("purpose-agnostic-baseline");

/** A store loaded with the named fixture pairs. */
async function storeWith(
  pairs: Array<[PolicyDefinition, PolicyAssignment]>,
): Promise<InMemoryPolicyStore> {
  const store = new InMemoryPolicyStore();
  for (const [definition, assignment] of pairs) {
    await store.putDefinition(definition);
    await store.putAssignment(assignment);
  }
  return store;
}

const SCOPED_PAIR: [PolicyDefinition, PolicyAssignment] = [
  SCOPED,
  loadAssignment("purpose-campaign-overlap"),
];
const FRAUD_PAIR: [PolicyDefinition, PolicyAssignment] = [
  FRAUD,
  loadAssignment("purpose-fraud-detection"),
];
const AGNOSTIC_PAIR: [PolicyDefinition, PolicyAssignment] = [
  AGNOSTIC,
  loadAssignment("purpose-agnostic-baseline"),
];

// ---------------------------------------------------------------------------
// The parameter reaches the resolver
// ---------------------------------------------------------------------------

describe("resolvePolicy threads declaredPurpose through", () => {
  it("a matching purpose resolves the scoped policy", async () => {
    const store = await storeWith([SCOPED_PAIR, AGNOSTIC_PAIR]);

    const result = await store.resolvePolicy(USER, TENANT, SOURCE, CAMPAIGN_PURPOSE);

    expect(result.sourceProfiles).toEqual([
      "campaign-x-overlap-agent",
      "marketing-baseline",
    ]);
    expect(result.purposeProfile?.purposeId).toBe(CAMPAIGN_PURPOSE);
  });

  it("no purpose resolves only the purpose-agnostic policy", async () => {
    const store = await storeWith([SCOPED_PAIR, AGNOSTIC_PAIR]);

    const result = await store.resolvePolicy(USER, TENANT, SOURCE);

    expect(result.sourceProfiles).toEqual(["marketing-baseline"]);
    expect(result.purposeProfile).toBeUndefined();
  });

  it("the scoped policy's RULES are absent, not just its name", async () => {
    // The assertion that distinguishes a store which threads the parameter from one
    // which drops it: a dropped parameter resolves the scoped policy, so its row filter
    // and masked field would be present in both results.
    const store = await storeWith([SCOPED_PAIR, AGNOSTIC_PAIR]);

    const withPurpose = await store.resolvePolicy(USER, TENANT, SOURCE, CAMPAIGN_PURPOSE);
    const without = await store.resolvePolicy(USER, TENANT, SOURCE);

    expect(withPurpose.objectRules?.rowFilters).toHaveLength(1);
    expect(without.objectRules?.rowFilters).toBeUndefined();
    expect(withPurpose.objectRules?.fieldRules?.maskedFields).toHaveLength(1);
    expect(without.objectRules?.fieldRules?.maskedFields).toBeUndefined();
  });

  it("a non-matching purpose is deny-all when every policy is scoped", async () => {
    const store = await storeWith([SCOPED_PAIR, FRAUD_PAIR]);

    const result = await store.resolvePolicy(USER, TENANT, SOURCE, "some-other-purpose");

    expect(result.permissions.canQuery).toBe(false);
    expect(result.sourceProfiles).toEqual([]);
  });

  it("declaring the other purpose resolves the other policy", async () => {
    // The paired control. Without it, a store that refused every purpose would pass the
    // test above.
    const store = await storeWith([SCOPED_PAIR, FRAUD_PAIR]);

    const result = await store.resolvePolicy(USER, TENANT, SOURCE, "fraud-detection");

    expect(result.sourceProfiles).toEqual(["fraud-detection-agent"]);
    expect(result.limits?.maxResults).toBe(500);
  });

  it("an empty purpose string behaves as no purpose", async () => {
    const store = await storeWith([SCOPED_PAIR, AGNOSTIC_PAIR]);

    expect((await store.resolvePolicy(USER, TENANT, SOURCE, "")).sourceProfiles).toEqual([
      "marketing-baseline",
    ]);
  });

  it("the comparison is case-sensitive here too", async () => {
    const store = await storeWith([SCOPED_PAIR]);

    expect(
      (await store.resolvePolicy(USER, TENANT, SOURCE, "Campaign-X-Overlap")).permissions
        .canQuery,
    ).toBe(false);
    expect(
      (await store.resolvePolicy(USER, TENANT, SOURCE, CAMPAIGN_PURPOSE)).permissions
        .canQuery,
    ).toBe(true);
  });

  it("the three-argument call keeps working unchanged", async () => {
    // The trailing-parameter guarantee, exercised through the call every existing
    // integrator makes rather than reasoned about.
    const store = await storeWith([AGNOSTIC_PAIR]);

    const result = await store.resolvePolicy(USER, TENANT, SOURCE);

    expect(result.permissions.canQuery).toBe(true);
    expect(result.sourceProfiles).toEqual(["marketing-baseline"]);
  });

  it("the TTL default survives the extra positional argument", async () => {
    // `declaredPurpose` follows `ttlMs` positionally in `resolve`, so a store that
    // passed it in the wrong slot would silently set a one-purpose-long TTL. The window
    // is checked rather than the exact value, since the clock moves between the two
    // reads.
    const store = await storeWith([AGNOSTIC_PAIR]);

    const result = await store.resolvePolicy(USER, TENANT, SOURCE, undefined);
    const lifetimeMs =
      new Date(result.expiresAt).getTime() - new Date(result.resolvedAt).getTime();

    expect(lifetimeMs).toBe(3_600_000);
  });

  it("the TTL is the same with a purpose declared", async () => {
    const store = await storeWith([SCOPED_PAIR]);

    const result = await store.resolvePolicy(USER, TENANT, SOURCE, CAMPAIGN_PURPOSE);
    const lifetimeMs =
      new Date(result.expiresAt).getTime() - new Date(result.resolvedAt).getTime();

    expect(lifetimeMs).toBe(3_600_000);
  });

  it("the interface's optional parameter is satisfied by the implementation", async () => {
    // Typed through `PolicyStore`, so a signature change on either side would fail to
    // compile here rather than only inside the concrete class.
    const store: PolicyStore = await storeWith([SCOPED_PAIR]);

    expect(
      (await store.resolvePolicy(USER, TENANT, SOURCE, CAMPAIGN_PURPOSE)).purposeProfile
        ?.purposeId,
    ).toBe(CAMPAIGN_PURPOSE);
  });
});

// ---------------------------------------------------------------------------
// The audit trail
// ---------------------------------------------------------------------------

describe("the audit event records the purpose", () => {
  it("includes declaredPurpose when one was declared", async () => {
    // "Which purpose was this resolved for" is the question a reviewer asks of a
    // purpose-bound grant, and the resolved policy alone cannot answer it: a
    // purpose-agnostic result looks identical whether no purpose was declared or a
    // non-matching one was.
    const store = await storeWith([SCOPED_PAIR]);
    const events: PolicyAuditEvent[] = [];
    store.onAudit((event) => events.push(event));

    await store.resolvePolicy(USER, TENANT, SOURCE, CAMPAIGN_PURPOSE);

    const resolveEvent = events.find((e) => e.action === "policy.resolve");
    expect(resolveEvent?.details).toEqual({
      userId: USER,
      tenantId: TENANT,
      sourceConnectionId: SOURCE,
      declaredPurpose: CAMPAIGN_PURPOSE,
    });
  });

  it("omits the key entirely when no purpose was declared", async () => {
    // A pre-purpose event's details are unchanged, so a consumer comparing details
    // objects does not see a new empty field appear.
    const store = await storeWith([AGNOSTIC_PAIR]);
    const events: PolicyAuditEvent[] = [];
    store.onAudit((event) => events.push(event));

    await store.resolvePolicy(USER, TENANT, SOURCE);

    const resolveEvent = events.find((e) => e.action === "policy.resolve");
    expect(resolveEvent?.details).toEqual({
      userId: USER,
      tenantId: TENANT,
      sourceConnectionId: SOURCE,
    });
    expect("declaredPurpose" in (resolveEvent?.details ?? {})).toBe(false);
  });

  it("records an empty declared purpose as the empty string it was given", async () => {
    // `""` resolves as "no purpose", but the audit trail records what the CALLER said
    // rather than what the resolver made of it — the two are different facts and a
    // reviewer needs the first.
    const store = await storeWith([AGNOSTIC_PAIR]);
    const events: PolicyAuditEvent[] = [];
    store.onAudit((event) => events.push(event));

    await store.resolvePolicy(USER, TENANT, SOURCE, "");

    expect(events.find((e) => e.action === "policy.resolve")?.details.declaredPurpose).toBe(
      "",
    );
  });

  it("records a purpose that resolved nothing", async () => {
    // The most important audit case: a deny-all is exactly when someone asks why, and
    // the declared purpose is the answer.
    const store = await storeWith([SCOPED_PAIR]);
    const events: PolicyAuditEvent[] = [];
    store.onAudit((event) => events.push(event));

    const result = await store.resolvePolicy(USER, TENANT, SOURCE, "fraud-detection");

    expect(result.permissions.canQuery).toBe(false);
    expect(events.find((e) => e.action === "policy.resolve")?.details.declaredPurpose).toBe(
      "fraud-detection",
    );
  });
});

// ---------------------------------------------------------------------------
// Purpose-bound definitions survive a store round trip
// ---------------------------------------------------------------------------

describe("a purpose-bound definition round-trips through the store", () => {
  it("getDefinition returns the profile intact", async () => {
    const store = await storeWith([SCOPED_PAIR]);

    const stored = await store.getDefinition(SCOPED.name);

    expect(stored?.purposeProfile).toEqual(SCOPED.purposeProfile);
  });

  it("listDefinitions includes it", async () => {
    const store = await storeWith([SCOPED_PAIR, AGNOSTIC_PAIR]);

    const listed = await store.listDefinitions();

    expect(listed.map((d) => d.name).sort()).toEqual([
      "campaign-x-overlap-agent",
      "marketing-baseline",
    ]);
    expect(
      listed.find((d) => d.name === "campaign-x-overlap-agent")?.purposeProfile?.judge,
    ).toBeUndefined();
  });

  it("a judge block survives too", async () => {
    const judged = loadPolicy("purpose-judge-enabled");
    const store = await storeWith([[judged, loadAssignment("purpose-judged")]]);

    const stored = await store.getDefinition(judged.name);

    expect(stored?.purposeProfile?.judge).toEqual({
      enabled: true,
      model: "claude-sonnet",
      historyWindow: 5,
      confidenceThreshold: 0.9,
      escalationThreshold: 0.7,
      maxLatencyMs: 1500,
    });
  });

  it("deleting a purpose-bound definition stops it resolving", async () => {
    // The store-level counterpart to the revocation rule: removing the definition must
    // remove the access, not merely the listing.
    const store = await storeWith([SCOPED_PAIR]);
    expect(
      (await store.resolvePolicy(USER, TENANT, SOURCE, CAMPAIGN_PURPOSE)).permissions
        .canQuery,
    ).toBe(true);

    expect(await store.deleteDefinition(SCOPED.name)).toBe(true);

    expect(
      (await store.resolvePolicy(USER, TENANT, SOURCE, CAMPAIGN_PURPOSE)).permissions
        .canQuery,
    ).toBe(false);
  });
});
