/**
 * Provider renderers for `kb` metadata filters (connector-spec §7).
 *
 * {@link buildKbFilter} produces provider-neutral clauses; these render them into each
 * provider's own filter syntax. Splitting the two is what keeps the semantics in one place:
 * the decision about *what* is safe to push (see `kb-filter.ts`) is made once, and a
 * renderer only translates. A renderer that cannot express a clause returns `null` for it,
 * which surfaces as an unpushed rule rather than a silently weakened filter.
 *
 * **Every renderer here is a pushdown, and the post-retrieval pass remains normative.**
 * None of them can reproduce TOLAP's tag extraction — recursive, case-insensitive, across
 * five key shapes — so a filter matching nothing is expected and harmless. See the header
 * of `kb-filter.ts` for why that direction is the safe one.
 *
 * Only the Bedrock shape is exercised against a real service in the reference
 * implementation; the other five are written from each provider's published filter grammar.
 * They are marked accordingly, because "compiles and looks right" is not the same evidence
 * as "observed to filter", and an integrator deserves to know which they are relying on.
 */

import {
  KbFilterOp,
  type KbFilterClause,
  type KbFilterResult,
} from "./kb-filter.js";

/** The providers a filter can be rendered for. */
export enum KbProvider {
  /** Amazon Bedrock Knowledge Bases `retrievalConfiguration.filter`. */
  Bedrock = "bedrock",
  /** OpenSearch / Elasticsearch bool query filter clauses. */
  OpenSearch = "opensearch",
  /** Elasticsearch — same DSL as OpenSearch; kept distinct for intent. */
  Elasticsearch = "elasticsearch",
  /** Azure AI Search OData `$filter`. */
  AzureAiSearch = "azureAiSearch",
  /** Vertex AI Search / Discovery Engine filter expression. */
  VertexAiSearch = "vertexAiSearch",
  /** pgvector — a SQL `WHERE` fragment over a metadata column. */
  Pgvector = "pgvector",
}

/**
 * Whether a provider's filter has been exercised against the live service, or written
 * from its published grammar only. Carried into {@link RenderedKbFilter} so the
 * distinction reaches the integrator rather than living only in a comment here.
 */
export enum KbFilterConfidence {
  /** Exercised against the real service. */
  Verified = "verified",
  /** Written from published filter grammar; not exercised here. */
  FromGrammar = "fromGrammar",
}

const CONFIDENCE: Record<KbProvider, KbFilterConfidence> = {
  [KbProvider.Bedrock]: KbFilterConfidence.Verified,
  [KbProvider.OpenSearch]: KbFilterConfidence.FromGrammar,
  [KbProvider.Elasticsearch]: KbFilterConfidence.FromGrammar,
  [KbProvider.AzureAiSearch]: KbFilterConfidence.FromGrammar,
  [KbProvider.VertexAiSearch]: KbFilterConfidence.FromGrammar,
  [KbProvider.Pgvector]: KbFilterConfidence.FromGrammar,
};

/** A filter rendered for one provider. */
export interface RenderedKbFilter {
  provider: KbProvider;
  /**
   * The provider-native filter: a JSON-shaped object for Bedrock/OpenSearch/Vertex, a
   * string for OData and SQL. `null` when nothing could be rendered — retrieve unfiltered
   * and rely on the post pass.
   */
  filter: unknown;
  /** True when the policy denies every chunk; the caller MUST skip retrieval. */
  deniesEverything: boolean;
  /**
   * Rules not represented in {@link filter} — carried through from
   * {@link KbFilterResult.unpushedRules} plus anything this provider could not express.
   */
  unpushedRules: KbFilterResult["unpushedRules"];
  confidence: KbFilterConfidence;
}

// ---------------------------------------------------------------------------
// Bedrock
// ---------------------------------------------------------------------------

/**
 * Bedrock Knowledge Bases: `{ in: { key, value: [...] } }` /
 * `{ notIn: ... }`, combined with `andAll`.
 *
 * A single clause is emitted bare rather than wrapped in a one-element `andAll`, because
 * Bedrock rejects an `andAll` with fewer than two members.
 */
function renderBedrock(clauses: KbFilterClause[]): unknown {
  if (clauses.length === 0) return null;

  const rendered = clauses.map((clause) => ({
    [clause.op === KbFilterOp.In ? "in" : "notIn"]: {
      key: clause.key,
      value: clause.values,
    },
  }));

  return rendered.length === 1 ? rendered[0] : { andAll: rendered };
}

// ---------------------------------------------------------------------------
// OpenSearch / Elasticsearch
// ---------------------------------------------------------------------------

/**
 * A `bool` query: `terms` under `filter` for a positive match, under `must_not` for a
 * negated one. `filter` rather than `must` because scoring is irrelevant to an access
 * decision.
 *
 * Note `.keyword`: a `text`-mapped field is analyzed, and `terms` against an analyzed
 * field matches unpredictably. The suffix assumes the conventional keyword sub-field. If a
 * deployment maps its metadata differently the filter matches nothing — the usual harmless
 * miss.
 */
function renderOpenSearch(clauses: KbFilterClause[]): unknown {
  if (clauses.length === 0) return null;

  const filter: unknown[] = [];
  const mustNot: unknown[] = [];

  for (const clause of clauses) {
    const terms = { terms: { [`${clause.key}.keyword`]: clause.values } };
    if (clause.op === KbFilterOp.In) filter.push(terms);
    else mustNot.push(terms);
  }

  const bool: Record<string, unknown> = {};
  if (filter.length > 0) bool["filter"] = filter;
  if (mustNot.length > 0) bool["must_not"] = mustNot;
  return { bool };
}

// ---------------------------------------------------------------------------
// Azure AI Search
// ---------------------------------------------------------------------------

/** OData string literal: single quotes, with embedded quotes doubled. */
function odataLiteral(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

/**
 * OData `$filter` over a collection field: `tags/any(t: search.in(t, '...'))`.
 *
 * `search.in` takes a comma-delimited list, so a tag containing a comma would corrupt the
 * predicate. Rather than emit something that silently matches the wrong set, such a clause
 * is refused — `null` here becomes an unpushed rule.
 */
function renderAzure(clauses: KbFilterClause[]): unknown {
  if (clauses.length === 0) return null;

  const parts: string[] = [];
  for (const clause of clauses) {
    if (clause.values.some((v) => v.includes(","))) return null;

    const list = odataLiteral(clause.values.join(","));
    const any = `${clause.key}/any(t: search.in(t, ${list}))`;
    parts.push(clause.op === KbFilterOp.In ? any : `not ${any}`);
  }

  return parts.join(" and ");
}

// ---------------------------------------------------------------------------
// Vertex AI Search
// ---------------------------------------------------------------------------

/**
 * Discovery Engine filter expression: `ANY("a", "b")` / `NOT ANY(...)`.
 *
 * A double quote inside a value would break the expression and the grammar offers no
 * escape, so such a clause is refused rather than mangled.
 */
function renderVertex(clauses: KbFilterClause[]): unknown {
  if (clauses.length === 0) return null;

  const parts: string[] = [];
  for (const clause of clauses) {
    if (clause.values.some((v) => v.includes('"'))) return null;

    const any = `${clause.key}: ANY(${clause.values.map((v) => `"${v}"`).join(", ")})`;
    parts.push(clause.op === KbFilterOp.In ? any : `NOT ${any}`);
  }

  return parts.join(" AND ");
}

// ---------------------------------------------------------------------------
// pgvector
// ---------------------------------------------------------------------------

/** Single-quoted SQL literal with quotes doubled. */
function sqlLiteral(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

/**
 * A `WHERE` fragment over a `jsonb` metadata column, using the containment operator:
 * `metadata->'tags' ?| array[...]`.
 *
 * Rendered with literals rather than placeholders because the caller appends this to a
 * query it owns; every value is a tag from a **signed** policy and is quote-escaped here,
 * so it cannot introduce SQL the policy author did not write. Identifiers are validated
 * below rather than escaped, since a metadata key is deployment configuration and an
 * unexpected one should be refused, not quoted into existence.
 */
function renderPgvector(clauses: KbFilterClause[], column: string): unknown {
  if (clauses.length === 0) return null;

  const parts: string[] = [];
  for (const clause of clauses) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(clause.key)) return null;

    const array = `array[${clause.values.map(sqlLiteral).join(", ")}]`;
    const contains = `${column}->'${clause.key}' ?| ${array}`;
    // NOT (...) alone would also drop a row whose key is absent, because the operator
    // yields NULL there and NOT NULL is not true — that would discard untagged chunks the
    // policy permits. The IS NULL arm restores them.
    parts.push(
      clause.op === KbFilterOp.In
        ? contains
        : `(NOT (${contains}) OR ${column}->'${clause.key}' IS NULL)`,
    );
  }

  return parts.join(" AND ");
}

/** Options for {@link renderKbFilter}. */
export interface RenderKbFilterOptions {
  /** The `jsonb` metadata column for {@link KbProvider.Pgvector}. Defaults to `metadata`. */
  pgvectorColumn?: string;
}

/**
 * Render a provider-neutral filter for one provider.
 *
 * A rule this provider cannot express is added to {@link RenderedKbFilter.unpushedRules}
 * rather than approximated, so the returned filter is never broader than the policy.
 */
export function renderKbFilter(
  result: KbFilterResult,
  provider: KbProvider,
  options: RenderKbFilterOptions = {},
): RenderedKbFilter {
  const base = {
    provider,
    deniesEverything: result.deniesEverything,
    confidence: CONFIDENCE[provider],
  };

  // Deny-all short-circuits: there is nothing to render, and the caller must skip
  // retrieval rather than read an absent filter as "unrestricted".
  if (result.deniesEverything) {
    return { ...base, filter: null, unpushedRules: result.unpushedRules };
  }

  const column = options.pgvectorColumn ?? "metadata";

  const filter = (() => {
    switch (provider) {
      case KbProvider.Bedrock:
        return renderBedrock(result.clauses);
      case KbProvider.OpenSearch:
      case KbProvider.Elasticsearch:
        return renderOpenSearch(result.clauses);
      case KbProvider.AzureAiSearch:
        return renderAzure(result.clauses);
      case KbProvider.VertexAiSearch:
        return renderVertex(result.clauses);
      case KbProvider.Pgvector:
        return renderPgvector(result.clauses, column);
    }
  })();

  // A renderer that refused the clauses reports every rule it was given as unpushed: the
  // provider will return chunks the post pass has to discard, and saying so is the
  // difference between a missed optimization and a false sense of enforcement.
  const unpushedRules =
    filter === null && result.clauses.length > 0
      ? [
          ...result.unpushedRules,
          {
            rule: "deniedTags" as const,
            reason: `${provider} cannot express these tag values; left to the post pass`,
          },
        ]
      : result.unpushedRules;

  return { ...base, filter, unpushedRules };
}
