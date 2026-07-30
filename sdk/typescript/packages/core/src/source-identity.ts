/**
 * Source identity — parsing `category:namespace:name` (connector-spec §1).
 *
 * Every data source is identified by exactly three colon-separated segments. The
 * first is a fixed-set category; the other two are opaque to TOLAP.
 *
 * The category matters beyond documentation: it decides which wrapper enforces a
 * source, and it is read from the **signed** `sourceConnectionId` rather than from a
 * separate registry field. That is deliberate — a category taken from unsigned
 * configuration could disagree with the policy the context carries, and an attacker
 * who could flip `db` to `api` would pick the wrapper that enforces the *other*
 * category's rules on their request. Inside the signed bytes, changing it
 * invalidates the signature.
 */

/**
 * The four connector categories (connector-spec §1). Fixed set; adding one is a
 * breaking change (§10).
 */
export enum SourceCategory {
  /** Relational and query-engine sources (§5). */
  Db = "db",
  /** HTTP-shaped services (§6). */
  Api = "api",
  /** Knowledge bases and vector stores (§7). */
  Kb = "kb",
  /** Object stores (§8). */
  Storage = "storage",
}

const CATEGORIES: ReadonlySet<string> = new Set<string>([
  SourceCategory.Db,
  SourceCategory.Api,
  SourceCategory.Kb,
  SourceCategory.Storage,
]);

/** The three parts of a source connection identifier. */
export interface SourceIdentity {
  category: SourceCategory;
  namespace: string;
  name: string;
}

/**
 * Parse a `category:namespace:name` identifier, or return `undefined` if it is not
 * one.
 *
 * Returns `undefined` rather than throwing so a caller can decide whether an
 * unparseable identifier is a denial or a configuration error; every caller in this
 * SDK treats it as a denial. Rejected: a wrong segment count (`db:production` and
 * `db:a:b:c` both), an unknown category, and an empty segment — an empty namespace or
 * name would let `db::` match a `db:*:*` pattern while naming no actual source.
 *
 * The category is compared case-insensitively and returned lower-cased, matching the
 * case-insensitive `sourcePatterns` matching of enforcement spec §10. The namespace
 * and name are returned verbatim: they are opaque, and folding their case here would
 * make this function lie about what the identifier says.
 */
export function parseSourceIdentity(
  sourceConnectionId: string | undefined,
): SourceIdentity | undefined {
  if (sourceConnectionId === undefined) return undefined;

  const segments = sourceConnectionId.split(":");
  if (segments.length !== 3) return undefined;
  if (segments.some((segment) => segment.length === 0)) return undefined;

  const category = segments[0].toLowerCase();
  if (!CATEGORIES.has(category)) return undefined;

  return {
    category: category as SourceCategory,
    namespace: segments[1],
    name: segments[2],
  };
}

/**
 * The category of a source connection identifier, or `undefined` if unparseable.
 *
 * Convenience over {@link parseSourceIdentity} for the common case: the wrapper a
 * source needs depends only on its category.
 */
export function sourceCategory(
  sourceConnectionId: string | undefined,
): SourceCategory | undefined {
  return parseSourceIdentity(sourceConnectionId)?.category;
}
