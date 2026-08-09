/**
 * The policy authoring page.
 *
 * The five rule editors have their own tests. This file tests the thing that wires them
 * together, which is where a different class of bug lives: the page holds the draft and
 * merges every editor's partial update into it. Three risks, in order:
 *
 * 1. **Absent is not empty.** For an allow-list, absent/`null` means *unrestricted* and
 *    `[]` means *deny everything* (canonical-enforcement-spec section 3). The patch
 *    helpers merge partial updates into a nested object, so one that coerces `[]` to
 *    `undefined`, or forgets to spread a sibling key, silently rewrites a rule the author
 *    never touched -- and rewrites it in the permissive direction.
 * 2. **Category gating.** Endpoint rules do not constrain a SQL query and tag rules do not
 *    constrain an API call, so sections are shown per source category. Gating too
 *    aggressively is the worse failure: a rule that exists but has no editor cannot be
 *    removed, and the author cannot see what the policy says.
 * 3. **Read-only.** An auditor gets no write controls. The server is the real control and
 *    returns 403 regardless, but a page that renders an editable form for a role that
 *    cannot save is a page that loses work.
 *
 * `sourcePatterns` is deliberately tested the *other* way round: it is the one list where
 * absent and `[]` both mean "applies to every source" (spec section 10), and asserting the
 * allow-list reading here would encode the exact confusion the rest of this file guards.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import {
  api as realApi,
  ApiError,
  type PolicyDefinition,
  type PolicyVersion,
  type SourceManifest,
  type ValidationError,
} from "../api.ts";
import { PoliciesPage } from "./PoliciesPage.tsx";

/**
 * The page must never reach the network.
 *
 * Only the `api` object is replaced. `ApiError` stays real, because the save path branches
 * on `instanceof ApiError` to decide whether a failure carries schema errors worth listing
 * -- mocking the whole module would make that branch untestable.
 */
vi.mock("../api.ts", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api.ts")>()),
  api: {
    listPolicies: vi.fn(),
    listSources: vi.fn(),
    getPolicy: vi.fn(),
    listVersions: vi.fn(),
    validatePolicy: vi.fn(),
    saveDraft: vi.fn(),
    publish: vi.fn(),
    rollback: vi.fn(),
  },
}));

const api = vi.mocked(realApi);

// -- Fixtures ---------------------------------------------------------------

const DB_SOURCE: SourceManifest = {
  sourceConnectionId: "db:analytics:patients",
  category: "db",
  displayName: "Analytics patients",
  objects: [{ name: "patients", fields: ["patient_id", "ssn_number", "region"] }],
  endpoints: [],
  tags: [],
  prefixes: [],
};

const API_SOURCE: SourceManifest = {
  sourceConnectionId: "api:internal:clinical",
  category: "api",
  displayName: "Clinical API",
  objects: [],
  endpoints: [
    { path: "/patients", methods: ["GET", "POST"], responseFields: ["ssn"] },
    { path: "/reports", methods: ["GET"], responseFields: ["total"] },
  ],
  tags: [],
  prefixes: [],
};

const KB_SOURCE: SourceManifest = {
  sourceConnectionId: "kb:research:notes",
  category: "kb",
  displayName: "Research notes",
  objects: [],
  endpoints: [],
  tags: ["phi", "deidentified"],
  prefixes: [],
};

const STORAGE_SOURCE: SourceManifest = {
  sourceConnectionId: "storage:analytics:exports",
  category: "storage",
  displayName: "Analytics exports",
  objects: [],
  endpoints: [],
  tags: [],
  prefixes: ["reports/"],
};

const ALL_SOURCES = [DB_SOURCE, API_SOURCE, KB_SOURCE, STORAGE_SOURCE];

const ANALYST: PolicyDefinition = {
  version: "1.0",
  name: "patients-analyst",
  permissions: { canQuery: true, readOnly: true },
  objectRules: {
    allowedObjects: ["patients"],
    fieldRules: { hiddenFields: ["ssn_number"] },
  },
};

function version(overrides: Partial<PolicyVersion> = {}): PolicyVersion {
  return {
    name: "patients-analyst",
    versionNo: 1,
    policy: ANALYST,
    state: "published",
    note: null,
    createdBy: "admin@example.test",
    createdAt: "2026-01-02T03:04:05.000Z",
    ...overrides,
  };
}

// -- Harness ----------------------------------------------------------------

interface Scenario {
  readonly policies?: PolicyDefinition[];
  readonly sources?: SourceManifest[];
  readonly policy?: PolicyDefinition;
  readonly versions?: PolicyVersion[];
  readonly errors?: ValidationError[];
  readonly readOnly?: boolean;
}

async function renderPage(scenario: Scenario = {}) {
  const policy = scenario.policy ?? ANALYST;
  api.listPolicies.mockResolvedValue({ policies: scenario.policies ?? [policy] });
  api.listSources.mockResolvedValue({ sources: scenario.sources ?? ALL_SOURCES });
  // A fresh clone per call: the page keeps the object it is handed as `published`, and a
  // shared fixture would let one test's edits leak into the next.
  api.getPolicy.mockImplementation(async () => structuredClone(policy));
  api.listVersions.mockResolvedValue({ versions: scenario.versions ?? [version()] });
  api.validatePolicy.mockResolvedValue({
    valid: (scenario.errors ?? []).length === 0,
    errors: scenario.errors ?? [],
  });
  api.saveDraft.mockResolvedValue({ name: policy.name, versionNo: 2 });
  api.publish.mockResolvedValue({ published: policy });
  api.rollback.mockResolvedValue({ newVersionNo: 3 });

  const view = render(<PoliciesPage readOnly={scenario.readOnly ?? false} />);
  // Rendered from the list fetch, so its arrival is the signal the page is ready.
  await waitFor(() => expect(api.listSources).toHaveBeenCalled());
  return view;
}

/**
 * Open a policy for editing, the way an author does: click it in the list.
 *
 * A substring predicate rather than `new RegExp(name)`. Testing Library accepts a matcher
 * function, so the regex bought nothing -- and building one from a variable is the pattern
 * Semgrep flags for ReDoS. Harmless in a test with literal names, but this repository's
 * subject is access control and a blocking finding that has to be explained every scan is
 * worse than one line of code that does not produce it. It also sidesteps a real bug: a
 * policy name containing a regex metacharacter would not have matched itself.
 */
async function openPolicy(name = ANALYST.name) {
  await userEvent.click(
    screen.getByRole("button", {
      name: (accessibleName) => accessibleName.includes(name),
    }),
  );
  await screen.findByLabelText("Name");
}

async function selectSource(manifest: SourceManifest) {
  await userEvent.selectOptions(
    screen.getByLabelText("Suggest names from"),
    manifest.sourceConnectionId,
  );
}

/**
 * The draft as the server receives it.
 *
 * `api.ts` sends the body through `JSON.stringify`, which **drops a key whose value is
 * `undefined`** and **keeps a key whose value is `[]`**. That is precisely the section 3
 * distinction, so asserting the wire form rather than the in-memory object is what makes
 * these assertions mean anything: `toEqual` treats `{ a: undefined }` and `{}` as equal,
 * and the server does not.
 */
function savedPolicy(): PolicyDefinition {
  expect(api.saveDraft).toHaveBeenCalled();
  const [sent] = api.saveDraft.mock.calls.at(-1)!;
  return JSON.parse(JSON.stringify(sent)) as PolicyDefinition;
}

async function save() {
  await userEvent.click(screen.getByRole("button", { name: "Save draft" }));
  await waitFor(() => expect(api.saveDraft).toHaveBeenCalled());
}

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  cleanup();
});

// -- The list ---------------------------------------------------------------

describe("policy list", () => {
  it("flags a policy that cannot read and one that permits writes", async () => {
    // Both badges answer a question an administrator scanning the list asks: which of
    // these grants nothing, and which of these can change data.
    await renderPage({
      policies: [
        { version: "1.0", name: "no-access", permissions: { canQuery: false } },
        {
          version: "1.0",
          name: "writer",
          permissions: { canQuery: true, readOnly: false },
        },
      ],
    });

    const noAccess = await screen.findByRole("button", { name: /no-access/ });
    expect(noAccess.textContent).toMatch(/no read/);
    const writer = screen.getByRole("button", { name: /writer/ });
    expect(writer.textContent).toMatch(/writes/);
    // The reverse: a read-only reader carries neither badge.
    expect(noAccess.textContent).not.toMatch(/writes/);
  });

  it("reports a failed load instead of rendering an empty catalog", async () => {
    // An empty list and a broken server look identical otherwise, and "no policies yet"
    // is a dangerous thing to believe when the truth is "could not ask".
    api.listPolicies.mockRejectedValue(new Error("network down"));
    api.listSources.mockResolvedValue({ sources: [] });
    render(<PoliciesPage readOnly={false} />);

    expect((await screen.findByRole("alert")).textContent).toMatch(/network down/);
  });
});

// -- The patch helpers: absent vs empty ------------------------------------

describe("merging edits into the draft", () => {
  it("keeps an existing empty allow-list while a sibling endpoint rule is edited", async () => {
    // The section 3 case, in the helper most likely to get it wrong. `allowedEndpoints: []`
    // is deny-every-endpoint. The author here edits `hiddenEndpoints`, which must merge
    // *into* the existing endpointRules; a helper that rebuilt the object, or that treated
    // `[]` as "nothing to keep", would turn deny-all into unrestricted without the author
    // touching that control.
    await renderPage({
      policy: {
        ...ANALYST,
        objectRules: {
          endpointRules: { allowedEndpoints: [], hiddenEndpoints: ["/reports"] },
        },
      },
      sources: [API_SOURCE],
    });
    await openPolicy();

    await userEvent.type(
      screen.getByLabelText("Add to Hidden endpoints"),
      "/patients{Enter}",
    );
    await save();

    const sent = savedPolicy();
    expect(sent.objectRules?.endpointRules?.allowedEndpoints).toEqual([]);
    expect(sent.objectRules?.endpointRules?.hiddenEndpoints).toEqual([
      "/reports",
      "/patients",
    ]);
    // Present on the wire, not merely present in memory: `undefined` would vanish here.
    expect(
      Object.keys(sent.objectRules!.endpointRules!),
    ).toContain("allowedEndpoints");
  });

  it("keeps an existing empty allow-list of tags while the deny-list is edited", async () => {
    // Same hazard in patchTagRules. `allowedTags: []` returns no documents at all;
    // dropping the key returns every document.
    await renderPage({
      policy: {
        ...ANALYST,
        objectRules: { tagRules: { allowedTags: [], deniedTags: [] } },
      },
      sources: [KB_SOURCE],
    });
    await openPolicy();

    await userEvent.type(screen.getByLabelText("Add to Denied tags"), "phi{Enter}");
    await save();

    const sent = savedPolicy();
    expect(sent.objectRules?.tagRules?.allowedTags).toEqual([]);
    expect(sent.objectRules?.tagRules?.deniedTags).toEqual(["phi"]);
  });

  it("keeps an empty allowed-methods list, which denies every request", async () => {
    // `allowedMethods: []` and an absent `allowedMethods` are opposite policies: empty
    // denies every method (spec section 9), absent falls back to the read-only default.
    // The method picker is the one control that can express `[]`, and the page must carry
    // it through rather than normalising it away.
    await renderPage({
      policy: {
        ...ANALYST,
        objectRules: { endpointRules: { allowedMethods: ["GET"] } },
      },
      sources: [API_SOURCE],
    });
    await openPolicy();

    // Unchecking the last method leaves the explicit empty list.
    await userEvent.click(screen.getByRole("checkbox", { name: /^GET/ }));
    await save();

    expect(savedPolicy().objectRules?.endpointRules?.allowedMethods).toEqual([]);
  });

  it("removes allowed-methods entirely when the author asks for the default", async () => {
    // The other half of the same distinction: choosing the default must produce an
    // *absent* key, not `[]`, or the policy denies every request instead of allowing
    // the read-only verbs.
    await renderPage({
      policy: {
        ...ANALYST,
        objectRules: { endpointRules: { allowedMethods: ["GET", "POST"] } },
      },
      sources: [API_SOURCE],
    });
    await openPolicy();

    await userEvent.click(screen.getByRole("checkbox", { name: /Use the default/ }));
    await save();

    const endpointRules = savedPolicy().objectRules?.endpointRules ?? {};
    expect(Object.keys(endpointRules)).not.toContain("allowedMethods");
  });

  it("does not disturb unrelated object rules when an endpoint rule changes", async () => {
    // patchEndpointRules writes one key of objectRules. Rebuilding objectRules instead of
    // spreading it would silently delete every other rule in the policy -- field rules,
    // row filters, hidden objects -- and the author would see a green save.
    await renderPage({
      policy: {
        ...ANALYST,
        objectRules: {
          allowedObjects: ["patients"],
          hiddenObjects: ["audit_log"],
          fieldRules: { hiddenFields: ["ssn_number"], allowedFields: [] },
          rowFilters: [{ field: "region", operator: "equals", value: "west" }],
          tagRules: { deniedTags: ["phi"] },
          endpointRules: { allowedEndpoints: ["/reports"] },
        },
      },
      sources: [API_SOURCE],
    });
    await openPolicy();

    await userEvent.type(
      screen.getByLabelText("Add to Allowed endpoints"),
      "/patients{Enter}",
    );
    await save();

    const rules = savedPolicy().objectRules!;
    expect(rules.allowedObjects).toEqual(["patients"]);
    expect(rules.hiddenObjects).toEqual(["audit_log"]);
    expect(rules.fieldRules?.hiddenFields).toEqual(["ssn_number"]);
    // The empty allow-list is a deny-all rule and survives an unrelated edit too.
    expect(rules.fieldRules?.allowedFields).toEqual([]);
    expect(rules.rowFilters).toEqual([
      { field: "region", operator: "equals", value: "west" },
    ]);
    expect(rules.tagRules).toEqual({ deniedTags: ["phi"] });
    expect(rules.endpointRules?.allowedEndpoints).toEqual(["/reports", "/patients"]);
  });

  it("does not disturb unrelated object rules when an allowed object changes", async () => {
    // patchObjectRules is the shallowest helper and governs the two object pickers and the
    // row filters, so it is the one an author touches first. Rebuilding objectRules here
    // rather than spreading it would delete the field, tag and endpoint rules -- including
    // an empty allow-list, which is the most restrictive rule the schema can express.
    await renderPage({
      policy: {
        ...ANALYST,
        objectRules: {
          allowedObjects: ["patients"],
          fieldRules: { allowedFields: [], hiddenFields: ["ssn_number"] },
          tagRules: { deniedTags: ["phi"] },
          endpointRules: { allowedEndpoints: [] },
          rowFilters: [{ field: "region", operator: "equals", value: "west" }],
        },
      },
      sources: [DB_SOURCE],
    });
    await openPolicy();

    await userEvent.type(
      screen.getByLabelText("Add to Allowed objects"),
      "encounters{Enter}",
    );
    await save();

    const rules = savedPolicy().objectRules!;
    expect(rules.allowedObjects).toEqual(["patients", "encounters"]);
    expect(rules.fieldRules).toEqual({
      allowedFields: [],
      hiddenFields: ["ssn_number"],
    });
    expect(rules.tagRules).toEqual({ deniedTags: ["phi"] });
    expect(rules.endpointRules).toEqual({ allowedEndpoints: [] });
    expect(rules.rowFilters).toEqual([
      { field: "region", operator: "equals", value: "west" },
    ]);
  });

  it("does not disturb unrelated object rules when a row filter changes", async () => {
    // Same helper, the other caller. A row filter edit must not widen the field rules.
    await renderPage({
      policy: {
        ...ANALYST,
        objectRules: {
          fieldRules: { allowedFields: [] },
          rowFilters: [
            { field: "region", operator: "equals", value: "west" },
            { field: "cohort", operator: "equals", value: "a" },
          ],
        },
      },
      sources: [DB_SOURCE],
    });
    await openPolicy();

    await userEvent.click(screen.getByRole("button", { name: "Remove filter 2" }));
    await save();

    const rules = savedPolicy().objectRules!;
    expect(rules.rowFilters).toEqual([
      { field: "region", operator: "equals", value: "west" },
    ]);
    expect(rules.fieldRules?.allowedFields).toEqual([]);
  });

  it("does not disturb unrelated object rules when a tag rule changes", async () => {
    await renderPage({
      policy: {
        ...ANALYST,
        objectRules: {
          fieldRules: { maskedFields: [{ field: "ssn_number", maskType: "redact" }] },
          endpointRules: { allowedMethods: [] },
          tagRules: { allowedTags: ["deidentified"] },
        },
      },
      sources: [KB_SOURCE],
    });
    await openPolicy();

    await userEvent.click(
      screen.getByRole("button", { name: "Remove deidentified from Allowed tags" }),
    );
    await save();

    const rules = savedPolicy().objectRules!;
    expect(rules.fieldRules?.maskedFields).toEqual([
      { field: "ssn_number", maskType: "redact" },
    ]);
    // The deny-every-method rule is still there, still empty.
    expect(rules.endpointRules?.allowedMethods).toEqual([]);
  });

  it("does not disturb sibling field rules when one field rule changes", async () => {
    // patchFieldRules nests one level deeper than the others, so it has two objects to
    // spread rather than one and two chances to drop a key.
    await renderPage({
      policy: {
        ...ANALYST,
        objectRules: {
          allowedObjects: ["patients"],
          fieldRules: {
            allowedFields: [],
            hiddenFields: ["ssn_number"],
            readOnlyFields: ["patient_id"],
            maskedFields: [{ field: "region", maskType: "hash" }],
          },
        },
        sourcePatterns: ["db:analytics:*"],
      },
      sources: [DB_SOURCE],
    });
    await openPolicy();

    await userEvent.type(
      screen.getByLabelText("Add to Hidden fields"),
      "region{Enter}",
    );
    await save();

    const sent = savedPolicy();
    expect(sent.objectRules?.fieldRules).toEqual({
      allowedFields: [],
      hiddenFields: ["ssn_number", "region"],
      readOnlyFields: ["patient_id"],
      maskedFields: [{ field: "region", maskType: "hash" }],
    });
    expect(sent.objectRules?.allowedObjects).toEqual(["patients"]);
    expect(sent.sourcePatterns).toEqual(["db:analytics:*"]);
  });

  it("leaves a policy with no rules alone when nothing is edited", async () => {
    // A save that adds `objectRules: {}` or `limits: {}` to a policy the author only
    // renamed makes every diff and every version comparison noisy.
    await renderPage({
      policy: { version: "1.0", name: "reader", permissions: { canQuery: true } },
    });
    await openPolicy("reader");

    await save();

    expect(savedPolicy()).toEqual({
      version: "1.0",
      name: "reader",
      permissions: { canQuery: true },
    });
  });
});

// -- sourcePatterns: the one list where empty is not deny-all --------------

describe("scope (sourcePatterns)", () => {
  it("says that an empty scope applies to every source", async () => {
    // Section 10 inverts section 3 here, and the asymmetry has caused real bugs, so the
    // page states it next to the control rather than leaving the author to infer the
    // allow-list reading that applies everywhere else on this form.
    await renderPage();
    await openPolicy();

    const hint = screen.getByText(/Leave empty to apply to/);
    expect(hint.textContent).toMatch(/every/);
    // Explicitly *not* the deny-all reading.
    expect(hint.textContent).toMatch(/opposite of an allow-list/i);
  });

  it("omits sourcePatterns once the last pattern is removed", async () => {
    // Correct **because** this is section 10 and not section 3: absent means "applies to
    // every source", which is what an author who cleared the list asked for. The same
    // coercion on an allow-list would be a bug; here storing `[]` would merely be a
    // second spelling of the same thing, and absent is the canonical one.
    await renderPage({ policy: { ...ANALYST, sourcePatterns: ["db:analytics:*"] } });
    await openPolicy();

    await userEvent.click(
      screen.getByRole("button", {
        name: "Remove db:analytics:* from Source patterns",
      }),
    );
    await save();

    const sent = savedPolicy();
    expect(Object.keys(sent)).not.toContain("sourcePatterns");
  });

  it("scopes a policy to the patterns the author typed", async () => {
    await renderPage();
    await openPolicy();

    const input = screen.getByLabelText("Add to Source patterns");
    await userEvent.type(input, "db:analytics:*{Enter}");
    await userEvent.type(input, "kb:research:*{Enter}");
    await save();

    expect(savedPolicy().sourcePatterns).toEqual([
      "db:analytics:*",
      "kb:research:*",
    ]);
  });
});

// -- Category gating -------------------------------------------------------

/** Which of the category-gated sections are on screen. */
function sectionsOnScreen() {
  return {
    endpoints: screen.queryByText("API endpoints") !== null,
    tags: screen.queryByText("Knowledge-base tags") !== null,
    similarity: screen.queryByLabelText("Minimum similarity score") !== null,
    objectSize: screen.queryByLabelText("Max object size (bytes)") !== null,
  };
}

describe("category gating", () => {
  it("shows a database source no endpoint, tag, similarity or object-size controls", async () => {
    // None of those rules are read by a db wrapper, so authoring one produces a rule that
    // is silently ignored -- the worst possible outcome for a security control.
    await renderPage();
    await openPolicy();
    await selectSource(DB_SOURCE);

    expect(sectionsOnScreen()).toEqual({
      endpoints: false,
      tags: false,
      similarity: false,
      objectSize: false,
    });
    // The category-agnostic sections are still there.
    expect(screen.getByLabelText("Add to Hidden fields")).toBeDefined();
    expect(screen.getByLabelText("Max results per call")).toBeDefined();
  });

  it("shows an api source its endpoint rules and nothing else", async () => {
    await renderPage();
    await openPolicy();
    await selectSource(API_SOURCE);

    expect(sectionsOnScreen()).toEqual({
      endpoints: true,
      tags: false,
      similarity: false,
      objectSize: false,
    });
    expect(screen.getByLabelText("Add to Allowed endpoints")).toBeDefined();
    expect(screen.getByLabelText("Add to Hidden endpoints")).toBeDefined();
  });

  it("shows a kb source its tag rules and the similarity floor", async () => {
    await renderPage();
    await openPolicy();
    await selectSource(KB_SOURCE);

    expect(sectionsOnScreen()).toEqual({
      endpoints: false,
      tags: true,
      similarity: true,
      objectSize: false,
    });
    expect(screen.getByLabelText("Add to Allowed tags")).toBeDefined();
    expect(screen.getByLabelText("Add to Denied tags")).toBeDefined();
  });

  it("shows a storage source the object-size ceiling", async () => {
    await renderPage();
    await openPolicy();
    await selectSource(STORAGE_SOURCE);

    expect(sectionsOnScreen()).toEqual({
      endpoints: false,
      tags: false,
      similarity: false,
      objectSize: true,
    });
  });

  it("shows every category-agnostic section before a source is chosen", async () => {
    // A policy can be authored without a catalog at all -- the catalog is an aid, not a
    // gate -- so the sections that apply to every category must not wait for one.
    await renderPage({ sources: [] });
    await openPolicy();

    expect(screen.getByLabelText("Add to Allowed objects")).toBeDefined();
    expect(screen.getByLabelText("Add to Allowed fields")).toBeDefined();
    expect(sectionsOnScreen().endpoints).toBe(false);
    // And it says why there are no suggestions rather than looking broken.
    expect(screen.getByText(/No sources in the catalog/)).toBeDefined();
  });

  it("keeps an existing endpoint rule editable under a database source", async () => {
    // The gate is about what to *offer*, never about what to hide. A policy carrying
    // endpoint rules while a db source is selected must still show them: otherwise the
    // rule is invisible, un-removable, and enforced anyway.
    await renderPage({
      policy: {
        ...ANALYST,
        objectRules: { endpointRules: { allowedEndpoints: ["/patients"] } },
      },
    });
    await openPolicy();
    await selectSource(DB_SOURCE);

    expect(sectionsOnScreen().endpoints).toBe(true);
    expect(screen.getByText("/patients")).toBeDefined();
    // And it can actually be removed, which is the point.
    await userEvent.click(
      screen.getByRole("button", { name: "Remove /patients from Allowed endpoints" }),
    );
    await save();
    const endpointRules = savedPolicy().objectRules?.endpointRules ?? {};
    expect(Object.keys(endpointRules)).not.toContain("allowedEndpoints");
  });

  it("keeps an existing tag rule editable under an api source", async () => {
    await renderPage({
      policy: {
        ...ANALYST,
        objectRules: { tagRules: { deniedTags: ["phi"] } },
      },
    });
    await openPolicy();
    await selectSource(API_SOURCE);

    expect(sectionsOnScreen().tags).toBe(true);
    expect(screen.getByText("phi")).toBeDefined();
  });

  it("keeps an empty endpoint allow-list visible, because it denies everything", async () => {
    // The gating rule keys off `endpointRules !== undefined`, not on the rules being
    // non-empty. A truthiness check here would hide the single most restrictive policy
    // this form can express.
    await renderPage({
      policy: { ...ANALYST, objectRules: { endpointRules: { allowedEndpoints: [] } } },
    });
    await openPolicy();
    await selectSource(DB_SOURCE);

    expect(sectionsOnScreen().endpoints).toBe(true);
    expect(
      within(screen.getByLabelText("Add to Allowed endpoints").closest("div")!)
        .queryAllByRole("button").length,
    ).toBeGreaterThan(0);
  });

  it("keeps an existing similarity floor and object-size ceiling visible", async () => {
    await renderPage({
      policy: {
        ...ANALYST,
        limits: { minSimilarityScore: 0.8, maxObjectSizeBytes: 1024 },
      },
    });
    await openPolicy();
    await selectSource(DB_SOURCE);

    expect(sectionsOnScreen().similarity).toBe(true);
    expect(sectionsOnScreen().objectSize).toBe(true);
    expect(
      (screen.getByLabelText("Minimum similarity score") as HTMLInputElement).value,
    ).toBe("0.8");
  });

  it("summarises the selected source so the author can see the catalog is stale", async () => {
    await renderPage();
    await openPolicy();
    await selectSource(DB_SOURCE);

    const hint = screen.getByText(/object\(s\)/);
    expect(hint.textContent).toMatch(/1 object\(s\)/);
    expect(hint.textContent).toMatch(/3 field\(s\)/);
    expect(hint.textContent).toMatch(/filtered to this category/);
  });
});

// -- Permissions -----------------------------------------------------------

describe("permissions", () => {
  it("starts a new policy granting nothing and permitting no writes", async () => {
    // The default has to fail closed. An author must ask for read access rather than
    // remember to remove it.
    await renderPage();
    await userEvent.click(screen.getByRole("button", { name: "New" }));

    const canRead = screen.getByRole("checkbox", { name: /Can read/ }) as HTMLInputElement;
    const readOnly = screen.getByRole("checkbox", {
      name: /Read-only/,
    }) as HTMLInputElement;
    expect(canRead.checked).toBe(false);
    expect(readOnly.checked).toBe(true);

    await userEvent.type(screen.getByLabelText("Name"), "new-policy");
    await save();

    expect(savedPolicy().permissions).toEqual({ canQuery: false, readOnly: true });
  });

  it("hides the write flags until read-only is lifted", async () => {
    // readOnly is a ceiling, not a peer: while it is true the three write flags cannot
    // grant anything, and showing checkboxes that do nothing invites the belief they do.
    await renderPage();
    await openPolicy();

    expect(screen.queryByRole("checkbox", { name: "canInsert" })).toBeNull();

    await userEvent.click(screen.getByRole("checkbox", { name: /Read-only/ }));

    expect(screen.getByRole("checkbox", { name: "canInsert" })).toBeDefined();
    expect(screen.getByRole("checkbox", { name: "canUpdate" })).toBeDefined();
    expect(screen.getByRole("checkbox", { name: "canDelete" })).toBeDefined();
  });

  it("treats an absent readOnly as read-only, matching the schema default", async () => {
    // The schema defaults readOnly to true, so a policy that omits it denies writes. A
    // checkbox bound to `draft.permissions.readOnly` alone would render unchecked and
    // tell the author writes are permitted.
    await renderPage({
      policy: { version: "1.0", name: "reader", permissions: { canQuery: true } },
    });
    await openPolicy("reader");

    const readOnly = screen.getByRole("checkbox", {
      name: /Read-only/,
    }) as HTMLInputElement;
    expect(readOnly.checked).toBe(true);
    expect(screen.queryByRole("checkbox", { name: "canInsert" })).toBeNull();
  });

  it("grants one write verb without granting the others", async () => {
    await renderPage({
      policy: { ...ANALYST, permissions: { canQuery: true, readOnly: false } },
    });
    await openPolicy();

    await userEvent.click(screen.getByRole("checkbox", { name: "canUpdate" }));
    await save();

    expect(savedPolicy().permissions).toEqual({
      canQuery: true,
      readOnly: false,
      canUpdate: true,
    });
  });
});

// -- Limits ----------------------------------------------------------------

describe("limits", () => {
  it("keeps a zero max-results, which returns nothing", async () => {
    // Zero is a meaningful limit and it is falsy. A `Number(value) || undefined` here
    // would read as "unlimited" -- the widest possible policy from the narrowest input.
    await renderPage();
    await openPolicy();

    await userEvent.type(screen.getByLabelText("Max results per call"), "0");
    await save();

    expect(savedPolicy().limits?.maxResults).toBe(0);
    expect(screen.getByText(/is valid and returns nothing/)).toBeDefined();
  });

  it("removes the limit when the field is cleared rather than storing zero", async () => {
    // The inverse mistake: an empty box means unlimited, and coercing it to 0 would deny
    // every result.
    await renderPage({ policy: { ...ANALYST, limits: { maxResults: 50 } } });
    await openPolicy();

    await userEvent.clear(screen.getByLabelText("Max results per call"));
    await save();

    const limits = savedPolicy().limits ?? {};
    expect(Object.keys(limits)).not.toContain("maxResults");
  });

  it("keeps a similarity floor that an author lowers to zero", async () => {
    // Zero is falsy and meaningful here too: it is the loosest threshold, so coercing it
    // to undefined would be harmless, but coercing it the other way would not be. Pinned
    // because the same `=== "" ? undefined : Number(...)` shape appears three times.
    await renderPage({
      policy: { ...ANALYST, limits: { minSimilarityScore: 0.8 } },
      sources: [KB_SOURCE],
    });
    await openPolicy();
    await selectSource(KB_SOURCE);

    const input = screen.getByLabelText("Minimum similarity score");
    await userEvent.clear(input);
    await userEvent.type(input, "0");
    await save();

    expect(savedPolicy().limits?.minSimilarityScore).toBe(0);
  });

  it("removes the object-size ceiling when it is cleared", async () => {
    await renderPage({
      policy: { ...ANALYST, limits: { maxObjectSizeBytes: 1024, maxResults: 10 } },
      sources: [STORAGE_SOURCE],
    });
    await openPolicy();
    await selectSource(STORAGE_SOURCE);

    await userEvent.clear(screen.getByLabelText("Max object size (bytes)"));
    await save();

    const limits = savedPolicy().limits!;
    expect(Object.keys(limits)).not.toContain("maxObjectSizeBytes");
    // The sibling limit is untouched -- `patch` replaces the whole `limits` object, so it
    // has to spread the current one.
    expect(limits.maxResults).toBe(10);
  });

  it("is documented to hide a cleared kb/storage limit when the category does not match", async () => {
    /*
     * A characterisation test, not an endorsement.
     *
     * These two controls render when `category === "kb"` (or `"storage"`) OR the value is
     * already set. Clearing the value while a *different* category is selected therefore
     * satisfies neither arm and the input unmounts under the cursor -- the author cannot
     * retype a value without re-selecting a matching source. Nothing is enforced wrongly
     * (an absent limit is the correct reading of a cleared box), so this is a usability
     * wart rather than a policy bug, but it is surprising enough to pin: if the gating is
     * reworked, this test should be deleted rather than worked around.
     */
    await renderPage({
      policy: { ...ANALYST, limits: { minSimilarityScore: 0.8 } },
      sources: [DB_SOURCE],
    });
    await openPolicy();
    await selectSource(DB_SOURCE);

    await userEvent.clear(screen.getByLabelText("Minimum similarity score"));

    expect(screen.queryByLabelText("Minimum similarity score")).toBeNull();
    await save();
    // The saved policy is still correct, which is why this is only a wart.
    expect(Object.keys(savedPolicy().limits ?? {})).not.toContain("minSimilarityScore");
  });
});

// -- Validation, saving, publishing ---------------------------------------

describe("validation", () => {
  it("lists the schema issues the server reports and blocks the save", async () => {
    await renderPage({
      errors: [{ path: "/permissions/canQuery", message: "must be boolean" }],
    });
    await openPolicy();

    await waitFor(() => expect(screen.getByText(/1 schema issue/)).toBeDefined());
    expect(screen.getByText("must be boolean")).toBeDefined();
    // Saving a draft the server has already rejected wastes a round trip and teaches the
    // author that the error list is advisory.
    const submit = screen.getByRole("button", {
      name: "Save draft",
    }) as HTMLButtonElement;
    expect(submit.disabled).toBe(true);
  });

  it("validates in fragment mode so a half-finished draft is not an error list", async () => {
    // A new policy has an empty name, which the full schema rejects. Reporting that on the
    // first keystroke trains the author to ignore the panel.
    await renderPage();
    await userEvent.click(screen.getByRole("button", { name: "New" }));

    await waitFor(() => expect(api.validatePolicy).toHaveBeenCalled());
    expect(api.validatePolicy.mock.calls.at(-1)![1]).toBe(true);
  });

  it("stays usable when the validation request itself fails", async () => {
    // Validation is a convenience. Losing it must not cost the author their draft or put
    // an unexplained error over the form.
    api.validatePolicy.mockRejectedValue(new Error("validator unavailable"));
    await renderPage();
    await openPolicy();

    await userEvent.type(screen.getByLabelText("Description"), "hello");
    await waitFor(() => expect(api.validatePolicy).toHaveBeenCalled());

    expect(screen.queryByText(/validator unavailable/)).toBeNull();
    const submit = screen.getByRole("button", {
      name: "Save draft",
    }) as HTMLButtonElement;
    expect(submit.disabled).toBe(false);
  });

  it("surfaces the schema errors a rejected save carries", async () => {
    await renderPage();
    await openPolicy();
    api.saveDraft.mockRejectedValue(
      new ApiError(400, "policy is invalid", [
        { path: "/sourcePatterns/0", message: "must match pattern" },
      ]),
    );

    await userEvent.click(screen.getByRole("button", { name: "Save draft" }));

    await waitFor(() =>
      expect(screen.getByRole("alert").textContent).toMatch(/policy is invalid/),
    );
    // Pointed at, not just announced.
    expect(screen.getByText("must match pattern")).toBeDefined();
    expect(screen.getByText("/sourcePatterns/0")).toBeDefined();
  });
});

describe("saving and publishing", () => {
  it("saves rather than reloads when Enter is pressed in a text field", async () => {
    // The form's submit handler must preventDefault; a real navigation would discard the
    // draft entirely.
    await renderPage();
    await openPolicy();

    await userEvent.type(screen.getByLabelText("Description"), "regional analyst{Enter}");

    await waitFor(() => expect(api.saveDraft).toHaveBeenCalled());
    expect(savedPolicy().description).toBe("regional analyst");
  });

  it("publishes the draft version, not whichever row happens to be first", async () => {
    /*
     * The draft is deliberately NOT the highest-numbered version here, because that is the
     * arrangement in which the two candidate implementations differ.
     *
     * The server lists versions newest-first, and a rollback re-publishes an old body as a
     * *new* version -- so a draft saved at 3 and then overtaken by a rollback that minted
     * 4 and 5 leaves the draft in the middle of the list. Publishing `versions[0]` there
     * would re-publish an already-live version and silently discard the draft the author
     * is looking at.
     */
    await renderPage({
      versions: [
        version({ versionNo: 5, state: "published", note: "rollback to version 2" }),
        version({ versionNo: 4, state: "superseded" }),
        version({ versionNo: 3, state: "draft" }),
      ],
    });
    await openPolicy();

    await userEvent.click(screen.getByRole("button", { name: "Publish latest draft" }));

    await waitFor(() => expect(api.publish).toHaveBeenCalled());
    expect(api.publish).toHaveBeenCalledWith(ANALYST.name, 3);
  });

  it("offers no publish button when there is no draft to publish", async () => {
    await renderPage({ versions: [version({ versionNo: 1, state: "published" })] });
    await openPolicy();

    const publish = screen.getByRole("button", {
      name: "Publish latest draft",
    }) as HTMLButtonElement;
    expect(publish.disabled).toBe(true);
  });

  it("shows the diff between the draft and what is published", async () => {
    // The last chance to notice that a policy says something other than what was meant.
    await renderPage();
    await openPolicy();

    const review = screen.getByRole("button", {
      name: "Review diff",
    }) as HTMLButtonElement;
    // Nothing changed yet, so there is nothing to review.
    expect(review.disabled).toBe(true);

    await userEvent.type(screen.getByLabelText("Add to Hidden fields"), "region{Enter}");
    expect(review.disabled).toBe(false);
    await userEvent.click(review);

    const diff = screen.getByText(/Change against the published policy/).parentElement!;
    // The added field appears as an addition, and the shorter old array as a removal.
    expect(diff.textContent).toMatch(/\+.*"region"/s);
    expect(diff.textContent).toMatch(/-/);
  });

  it("does not offer a diff for a policy that was never published", async () => {
    await renderPage();
    await userEvent.click(screen.getByRole("button", { name: "New" }));

    // A brand-new draft differs from nothing, so there is a diff to show; what matters is
    // that it does not claim the whole document was removed from something.
    await userEvent.type(screen.getByLabelText("Name"), "new-policy");
    await userEvent.click(screen.getByRole("button", { name: "Review diff" }));

    const diff = screen.getByText(/Change against the published policy/).parentElement!;
    expect(diff.textContent).not.toMatch(/^-/m);
  });

  it("lists versions with who made them", async () => {
    await renderPage({
      versions: [
        version({ versionNo: 2, state: "draft", note: "widen region filter" }),
        version({ versionNo: 1, state: "published" }),
      ],
    });
    await openPolicy();

    const table = screen.getByRole("table");
    expect(table.textContent).toMatch(/widen region filter/);
    expect(table.textContent).toMatch(/admin@example\.test/);
    expect(table.textContent).toMatch(/draft/);
    expect(table.textContent).toMatch(/published/);
  });

  it("rolls back to a superseded version and reloads the draft from it", async () => {
    // Rollback re-publishes the old body as a new version server-side. The page has to
    // refetch, or the author keeps editing the body that was just replaced.
    const rolledBack: PolicyDefinition = {
      ...ANALYST,
      description: "the version we rolled back to",
    };
    await renderPage({
      versions: [
        version({ versionNo: 2, state: "published" }),
        version({ versionNo: 1, state: "superseded" }),
      ],
    });
    await openPolicy();
    api.getPolicy.mockResolvedValue(rolledBack);

    await userEvent.click(screen.getByRole("button", { name: "Roll back to" }));

    await waitFor(() => expect(api.rollback).toHaveBeenCalledWith(ANALYST.name, 1));
    await waitFor(() =>
      expect((screen.getByLabelText("Description") as HTMLInputElement).value).toBe(
        "the version we rolled back to",
      ),
    );
    expect(screen.getByRole("status").textContent).toMatch(/Rolled back to version 1/);
  });

  it("offers no rollback control for the version already published", async () => {
    await renderPage({ versions: [version({ versionNo: 2, state: "published" })] });
    await openPolicy();

    expect(screen.queryByRole("button", { name: "Roll back to" })).toBeNull();
  });
});

// -- Read-only (auditor) --------------------------------------------------

describe("auditor access", () => {
  it("offers an auditor no way to create, save, publish or roll back", async () => {
    await renderPage({
      readOnly: true,
      versions: [
        version({ versionNo: 2, state: "draft" }),
        version({ versionNo: 1, state: "published" }),
      ],
    });
    await openPolicy();

    for (const name of [
      "New",
      "Save draft",
      "Review diff",
      "Publish latest draft",
      "Publish",
      "Roll back to",
    ]) {
      expect(screen.queryByRole("button", { name })).toBeNull();
    }
  });

  it("lets an auditor read a policy but not change it", async () => {
    // Reading is the auditor's job, so the form is rendered rather than replaced by a
    // permission notice. Every fieldset is disabled instead.
    await renderPage({ readOnly: true });
    await openPolicy();

    const name = screen.getByLabelText("Name") as HTMLInputElement;
    expect(name.value).toBe(ANALYST.name);

    await userEvent.type(name, "-tampered");
    expect(name.value).toBe(ANALYST.name);

    // Every fieldset, not just the identity one -- one missed `disabled` is one editable
    // section, and the rule editors are where the damage would be.
    const fieldsets = [...document.querySelectorAll("fieldset")];
    expect(fieldsets.length).toBeGreaterThan(5);
    for (const fieldset of fieldsets) {
      expect(fieldset.hasAttribute("disabled")).toBe(true);
    }
  });

  it("does not let an auditor edit a rule editor's chips or checkboxes", async () => {
    // The controls inside the rule editors are the ones that change what is enforced, and
    // they are only protected by the enclosing fieldset.
    await renderPage({
      readOnly: true,
      policy: {
        ...ANALYST,
        permissions: { canQuery: true, readOnly: false },
        objectRules: {
          ...ANALYST.objectRules,
          endpointRules: { allowedEndpoints: ["/patients"] },
        },
      },
    });
    await openPolicy();

    await userEvent.click(
      screen.getByRole("button", { name: "Remove ssn_number from Hidden fields" }),
    );
    expect(screen.getByText("ssn_number")).toBeDefined();

    await userEvent.click(
      screen.getByRole("button", { name: "Remove /patients from Allowed endpoints" }),
    );
    expect(screen.getByText("/patients")).toBeDefined();

    const canRead = screen.getByRole("checkbox", { name: /Can read/ }) as HTMLInputElement;
    await userEvent.click(canRead);
    expect(canRead.checked).toBe(true);
  });

  it("shows an auditor the version history without the action column", async () => {
    await renderPage({
      readOnly: true,
      versions: [version({ versionNo: 1, state: "published" })],
    });
    await openPolicy();

    const headers = screen.getAllByRole("columnheader");
    expect(headers.map((header) => header.textContent)).toEqual([
      "#",
      "State",
      "By",
      "When",
      "Note",
    ]);
  });
});
