/**
 * Provider-side metadata filters for `kb` sources (connector-spec §7).
 *
 * ## What this is for
 *
 * `tagRules` is the whole knowledge-base confidentiality control — a classification level
 * *is* a tag (§7). Post-retrieval, {@link filterByTags} enforces it on returned chunks.
 * This module additionally emits a **provider-native filter** so denied chunks are never
 * retrieved in the first place, which §7 puts "on the same footing as SQL rewriting, never
 * a replacement for the post pass".
 *
 * That framing is the entire safety argument, so it is worth being explicit about why the
 * pushdown is *structurally* weaker than the post pass rather than merely redundant:
 *
 * - Post-retrieval extraction reads tags from `tags`, `Tags`, `labels`, `classification`
 *   and `metadata.tags` — **at any depth**, matched with the same bidirectional
 *   case-insensitive glob matcher masking uses. A provider filter cannot express that. It
 *   filters on one concrete indexed metadata field, named up front.
 * - A chunk tagged `secret` under a key the provider does not index, or nested where the
 *   provider cannot reach, is invisible to the filter and caught only by the post pass.
 *
 * So a filter that matches nothing is **useless, not unsafe** — the post pass still runs
 * and still drops the chunk. The failure this module must avoid is the opposite one:
 * emitting a filter that causes the provider to return *more* than it should while
 * something downstream mistakenly treats the pushdown as sufficient. Two rules follow, and
 * every renderer below obeys them:
 *
 *  1. **Never emit a filter that is broader than the rule it came from.** When a rule
 *     cannot be expressed exactly, it is reported as unpushed instead of approximated.
 *  2. **Always report what was not pushed** ({@link KbFilterResult.unpushedRules}), so a
 *     caller can never conclude "the provider filtered everything" from a partial filter.
 *
 * ## Semantics preserved from `filterByTags`
 *
 * | Rule | Meaning | Pushed? |
 * | --- | --- | --- |
 * | `deniedTags: [a, b]` | drop chunks carrying any of them; **keep untagged** | yes — a negated match |
 * | `deniedTags: []` | denies nothing | nothing to push (no filter needed) |
 * | `allowedTags: [a, b]` | keep only chunks carrying one of them; **drop untagged** | yes — a positive match |
 * | `allowedTags: []` | denies **everything** | not pushable as a filter; reported unpushed |
 * | both | denied wins | both pushed, combined with AND |
 *
 * The `allowedTags: []` case is the one that most invites a mistake. It means deny-all, and
 * there is no metadata predicate meaning "match no document" that is portable across these
 * six providers — an empty `in` list is variously an error, a no-op, or a match-nothing
 * depending on the engine. Rendering it as a no-op would be a fail-open, so it is refused:
 * {@link buildKbFilter} returns `deniesEverything: true` and no filter, and the caller
 * should skip the retrieval altogether.
 */

import type { EffectivePolicy, TagRules } from "./types.js";

/**
 * The metadata keys a provider filter may be built against.
 *
 * Deliberately **not** the same list as post-retrieval extraction's, and deliberately
 * caller-supplied. Extraction's key set is fixed and unconfigurable because it decides
 * what counts as security metadata, and an unsigned knob must not influence a
 * confidentiality decision. This one is different in kind: it names which field the
 * *provider* happens to index, which is deployment knowledge the SDK cannot infer, and
 * getting it wrong makes the filter match nothing — costing efficiency, never access.
 *
 * The default covers the shapes §7 names. Override per source when the provider indexes
 * something else.
 */
export const DEFAULT_KB_METADATA_KEYS: readonly string[] = [
  "tags",
  "labels",
  "classification",
];

/** How a rule is combined into the provider filter. */
export enum KbFilterOp {
  /** Metadata value equals one of the listed values. */
  In = "in",
  /** Metadata value equals none of the listed values. */
  NotIn = "notIn",
}

/**
 * One clause of a provider-neutral filter: a metadata key tested against tag values.
 *
 * Values are lower-cased, matching the case-insensitive comparison `filterByTags`
 * performs. Note the limitation this implies: a provider whose own matching is
 * case-*sensitive* will fail to exclude a chunk tagged `Secret` when the clause says
 * `secret`. That is a pushdown miss, caught by the post pass — and it is why
 * {@link KbFilterResult.caseSensitivityCaveat} says so out loud rather than leaving an
 * integrator to assume the provider did the whole job.
 */
export interface KbFilterClause {
  key: string;
  op: KbFilterOp;
  values: string[];
}

/** A rule that could not be expressed as a provider filter, and why. */
export interface UnpushedRule {
  rule: "allowedTags" | "deniedTags";
  reason: string;
}

/**
 * A provider-neutral filter plus an honest account of its limits.
 */
export interface KbFilterResult {
  /**
   * Clauses to combine with AND. Empty means nothing could be pushed — retrieve
   * unfiltered and let the post pass do the work.
   */
  clauses: KbFilterClause[];
  /**
   * True when the policy denies every chunk (`allowedTags: []`). No filter can express
   * this portably, so the caller MUST skip retrieval rather than treat an empty
   * {@link clauses} as "no restriction".
   */
  deniesEverything: boolean;
  /**
   * Rules not represented in {@link clauses}. Non-empty means the provider will return
   * chunks the post pass still has to discard. Never let a non-empty list be read as
   * "filtered at the source".
   */
  unpushedRules: UnpushedRule[];
  /**
   * True whenever clauses were emitted, as a standing reminder that tag comparison is
   * case-insensitive in TOLAP but may not be in the provider, and that the provider sees
   * only the keys in {@link DEFAULT_KB_METADATA_KEYS} (or the override) at the depth it
   * indexes them. The post pass remains normative.
   */
  caseSensitivityCaveat: boolean;
}

/** Options for {@link buildKbFilter}. */
export interface KbFilterOptions {
  /**
   * Metadata keys the provider indexes. Defaults to {@link DEFAULT_KB_METADATA_KEYS}.
   * Supplying a key the provider does not index yields a filter that matches nothing,
   * which loses the optimization but never grants access.
   */
  metadataKeys?: readonly string[];
}

function normalize(values: readonly string[]): string[] {
  // Lower-cased and de-duplicated, matching filterByTags' comparison. Sorted so the same
  // policy renders byte-identically in all three SDKs — the shared fixtures compare
  // rendered output, and an unstable order would make them fail for the wrong reason.
  return [...new Set(values.map((v) => v.toLowerCase()))].sort();
}

/**
 * Build a provider-neutral metadata filter from a policy's `tagRules` (§7).
 *
 * Returns clauses to AND together, plus what could not be pushed. A caller that ignores
 * {@link KbFilterResult.unpushedRules} still gets correct enforcement — the post pass is
 * unconditional — but loses the ability to tell whether the provider did any of the work.
 */
export function buildKbFilter(
  policy: EffectivePolicy,
  options: KbFilterOptions = {},
): KbFilterResult {
  const empty: KbFilterResult = {
    clauses: [],
    deniesEverything: false,
    unpushedRules: [],
    caseSensitivityCaveat: false,
  };

  const tagRules: TagRules | undefined = policy.objectRules?.tagRules;
  if (tagRules === undefined) return empty;

  const keys = options.metadataKeys ?? DEFAULT_KB_METADATA_KEYS;
  if (keys.length === 0) {
    // No key to filter on. Reported rather than silently returning "no restriction".
    return {
      ...empty,
      unpushedRules: unpushedFor(tagRules, "no metadata keys were supplied to filter on"),
    };
  }

  const clauses: KbFilterClause[] = [];
  const unpushedRules: UnpushedRule[] = [];

  // Denied first, mirroring filterByTags' precedence. A denylist is the well-behaved case:
  // "value not in [...]" excludes exactly the denied tags and leaves an untagged chunk
  // alone, which is what the post pass does.
  if (tagRules.deniedTags !== undefined && tagRules.deniedTags.length > 0) {
    for (const key of keys) {
      clauses.push({ key, op: KbFilterOp.NotIn, values: normalize(tagRules.deniedTags) });
    }
  }
  // An empty deniedTags denies nothing, so there is nothing to push and nothing unpushed.

  if (tagRules.allowedTags !== undefined) {
    if (tagRules.allowedTags.length === 0) {
      // Deny-all. Not expressible portably (see the module comment), and rendering it as a
      // no-op would be a fail-open, so it is refused loudly instead.
      return {
        clauses: [],
        deniesEverything: true,
        unpushedRules: [
          {
            rule: "allowedTags",
            reason:
              "an empty allowedTags denies every chunk; no portable metadata filter " +
              "expresses match-nothing, so skip retrieval entirely",
          },
        ],
        caseSensitivityCaveat: false,
      };
    }

    // A positive match on ONE key only. This is the constraint that makes multi-key
    // allow-lists unpushable: the post pass admits a chunk tagged `public` under EITHER
    // `tags` OR `classification`, which is a disjunction across keys. ANDing a positive
    // clause per key would instead demand the tag be present under *every* key and drop
    // chunks the policy allows — narrower than the policy, which is a correctness bug even
    // though it errs "safe". Emitting a single-key clause is exact when there is one key;
    // with several, the rule is reported unpushed rather than approximated in either
    // direction.
    if (keys.length === 1) {
      clauses.push({
        key: keys[0],
        op: KbFilterOp.In,
        values: normalize(tagRules.allowedTags),
      });
    } else {
      unpushedRules.push({
        rule: "allowedTags",
        reason:
          "an allow-list spans multiple metadata keys as a disjunction; ANDing per key " +
          "would drop permitted chunks, so it is left to the post pass",
      });
    }
  }

  return {
    clauses,
    deniesEverything: false,
    unpushedRules,
    caseSensitivityCaveat: clauses.length > 0,
  };
}

function unpushedFor(tagRules: TagRules, reason: string): UnpushedRule[] {
  const out: UnpushedRule[] = [];
  if (tagRules.deniedTags !== undefined && tagRules.deniedTags.length > 0) {
    out.push({ rule: "deniedTags", reason });
  }
  if (tagRules.allowedTags !== undefined) {
    out.push({ rule: "allowedTags", reason });
  }
  return out;
}
